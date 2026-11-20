//! The node's side of webhook intake (#578 step 4; docs/explanation/trigger-intake.md).
//!
//! `wicket node intake`, a small process of its own beside this `serve`, terminates the deliveries.
//! This `serve` keeps what it needs and what it hands over:
//! - the table of triggers it serves, as the control host last sent it ([`Msg::IntakeSync`]), in
//!   memory only (it holds their verify secrets), and whether it has had one since it started;
//! - the spool of verified events, on disk, bounded, until the control host acks them;
//! - the counts of what intake refused, until the next sync.
//!
//! Intake reaches it over the intake socket: `node.json`'s `intake_socket`, or `ctl/intake.sock`.
//! Every connection's peer is checked (`SO_PEERCRED`): only `node.json`'s `intake_uid` (intake run
//! as its own user, the hardened setup), or this process's own uid when there is none, is served.
//! A connection is one JSON request a line, bounded, and one answer each.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use wicket_chan::chan::{Frame, Msg};
use wicket_core::intake::{IntakeEvent, IntakeRefused, IntakeTrigger};

/// The most events the spool holds …
pub const SPOOL_MAX_EVENTS: usize = 10_000;
/// … and bytes.
pub const SPOOL_MAX_BYTES: u64 = 64 << 20;
/// An event older than this (s) is dropped from the spool, counted.
pub const SPOOL_MAX_AGE_SECS: i64 = 86_400;
/// The most events one [`Msg::IntakeEvents`] carries …
pub const SYNC_MAX_EVENTS: usize = 500;
/// … and bytes of them.
pub const SYNC_MAX_BYTES: usize = 4 << 20;
/// The most intake connections served at once.
pub const SOCKET_CONNECTIONS: usize = 16;
/// How long a connection waits for one of the [`SOCKET_CONNECTIONS`] slots.
pub const SOCKET_SLOT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// How long intake may take to send one request line.
pub const SOCKET_LINE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Where intake reaches this node, and which uid may: `node.json`'s `intake_socket` and
/// `intake_uid`, else `ctl/intake.sock` beside the control socket and this process's own uid.
pub fn endpoint(root: &Path, ctl: &Path) -> (PathBuf, u32) {
    let info = std::fs::read(root.join("node.json")).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    let sock =
        info.as_ref().and_then(|v| v["intake_socket"].as_str()).map(PathBuf::from).unwrap_or_else(|| ctl.with_file_name("intake.sock"));
    // SAFETY: a plain getter.
    let uid = info.as_ref().and_then(|v| v["intake_uid"].as_u64()).map(|u| u as u32).unwrap_or_else(|| unsafe { libc::geteuid() });
    (sock, uid)
}

#[derive(Default)]
pub(super) struct Intake {
    table: Mutex<Vec<IntakeTrigger>>,
    /// Whether the control host has sent a table since this `serve` started: until then, intake
    /// answers 503 (try later), not 404.
    ready: AtomicBool,
    refused: Mutex<IntakeRefused>,
    /// The spool's count and bytes, kept as it changes (read from the disk once, lazily); the lock
    /// is also one writer or reader of the spool at a time.
    spool: Mutex<Option<(usize, u64)>>,
}

/// One request from `wicket node intake`.
#[derive(serde::Deserialize, serde::Serialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// The triggers served now.
    Table,
    /// A verified delivery, to spool.
    Deliver { event: IntakeEvent },
    /// What it refused since it last said.
    Refused { counts: IntakeRefused },
}

fn dir(root: &Path) -> PathBuf {
    root.join("intake").join("spool")
}

/// The spool's files, oldest first (their names sort by when), with their sizes.
fn listing(root: &Path) -> Vec<(PathBuf, u64)> {
    let Ok(rd) = std::fs::read_dir(dir(root)) else { return vec![] };
    let mut v: Vec<(PathBuf, u64)> = rd
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| (e.path(), e.metadata().map(|m| m.len()).unwrap_or(0)))
        .collect();
    v.sort();
    v
}

impl Intake {
    /// Spools `e`, atomically and synced. Err if the spool is full, or the event isn't for a trigger
    /// served here.
    pub(super) fn deliver(&self, root: &Path, mut e: IntakeEvent, now: i64) -> anyhow::Result<()> {
        if !self.table.lock().expect("table").iter().any(|t| t.trigger == e.trigger) {
            anyhow::bail!("not served here");
        }
        let mut g = self.spool.lock().expect("spool");
        let c = g.get_or_insert_with(|| {
            let l = listing(root);
            (l.len(), l.iter().map(|(_, n)| n).sum())
        });
        if c.0 >= SPOOL_MAX_EVENTS || c.1 >= SPOOL_MAX_BYTES {
            anyhow::bail!("full");
        }
        let d = dir(root);
        std::fs::create_dir_all(&d)?;
        // Sorts by when, then is unique: a timestamp and part of a fresh token.
        let r = wicket_core::intake::new_token().map_err(|err| anyhow::anyhow!(err))?;
        let r: String = r.chars().filter(char::is_ascii_alphanumeric).take(16).collect();
        e.id = format!("{:020}-{r}", now.max(0));
        let body = serde_json::to_vec(&e)?;
        let tmp = d.join(format!(".{}.tmp", e.id));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, d.join(format!("{}.json", e.id)))?;
        if let Ok(f) = std::fs::File::open(&d) {
            let _ = f.sync_all();
        }
        c.0 += 1;
        c.1 += body.len() as u64;
        Ok(())
    }

    /// A sync: the new table, the acked events deleted, events of triggers no longer assigned here
    /// (in neither the table nor `serving`) deleted, then what to send (oldest first, bounded: only
    /// as many files are read as are sent) and the refusals counted since the last one. An event of
    /// a trigger assigned here but left out of this table (its secret didn't read) is kept, unsent.
    pub(super) fn sync(
        &self,
        root: &Path,
        triggers: Vec<IntakeTrigger>,
        ack: &[String],
        serving: &[String],
        hold: &[String],
        now: i64,
    ) -> (Vec<IntakeEvent>, IntakeRefused) {
        let mut keep: Vec<String> = serving.to_vec();
        keep.extend(triggers.iter().map(|t| t.trigger.clone()));
        // Held triggers' events are kept and not sent this time.
        let send: Vec<String> = triggers.iter().map(|t| t.trigger.clone()).filter(|t| !hold.contains(t)).collect();
        *self.table.lock().expect("table") = triggers;
        self.ready.store(true, Ordering::Relaxed);
        let mut g = self.spool.lock().expect("spool");
        let d = dir(root);
        for id in ack {
            // Only a spool id's shape: an ack never names another file.
            if !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                let _ = std::fs::remove_file(d.join(format!("{id}.json")));
            }
        }
        let (mut out, mut size) = (vec![], 0usize);
        let (mut count, mut bytes) = (0usize, 0u64);
        for (p, n) in listing(root) {
            if out.len() >= SYNC_MAX_EVENTS || size + n as usize > SYNC_MAX_BYTES {
                // Not read: counted as held.
                count += 1;
                bytes += n;
                continue;
            }
            match std::fs::read(&p).ok().and_then(|b| serde_json::from_slice::<IntakeEvent>(&b).ok()) {
                Some(e) if now - e.received_at > SPOOL_MAX_AGE_SECS => {
                    let _ = std::fs::remove_file(&p);
                    self.refused.lock().expect("refused").other += 1;
                }
                // A trigger no longer assigned here (deleted, moved): its events go.
                Some(e) if !keep.contains(&e.trigger) => {
                    let _ = std::fs::remove_file(&p);
                }
                Some(e) => {
                    count += 1;
                    bytes += n;
                    if send.contains(&e.trigger) {
                        size += n as usize;
                        out.push(e);
                    }
                }
                None => {
                    let _ = std::fs::remove_file(&p);
                    self.refused.lock().expect("refused").other += 1;
                }
            }
        }
        *g = Some((count, bytes));
        let refused = std::mem::take(&mut *self.refused.lock().expect("refused"));
        (out, refused)
    }

    /// Answers one request from intake.
    pub(super) fn answer(&self, root: &Path, req: Request, now: i64) -> serde_json::Value {
        match req {
            Request::Table => {
                serde_json::json!({ "triggers": *self.table.lock().expect("table"), "ready": self.ready.load(Ordering::Relaxed) })
            }
            Request::Deliver { event } => match self.deliver(root, event, now) {
                Ok(()) => serde_json::json!({ "ok": true }),
                Err(e) => {
                    self.refused.lock().expect("refused").other += 1;
                    serde_json::json!({ "error": format!("{e:#}") })
                }
            },
            Request::Refused { counts } => {
                let mut r = self.refused.lock().expect("refused");
                r.token += counts.token;
                r.signature += counts.signature;
                r.rate += counts.rate;
                r.other += counts.other;
                serde_json::json!({ "ok": true })
            }
        }
    }
}

/// Handles the control host's [`Msg::IntakeSync`] on connection `gen`: the spool's work is blocking
/// file work, so it runs off the runtime.
#[allow(clippy::too_many_arguments)]
pub(super) fn sync(
    node: Arc<super::Node>,
    gen: u64,
    id: u64,
    triggers: Vec<IntakeTrigger>,
    ack: Vec<String>,
    serving: Vec<String>,
    hold: Vec<String>,
) {
    tokio::task::spawn_blocking(move || {
        let now = (node.clock)() / 1000;
        let (events, refused) = node.intake.sync(&node.paths.root, triggers, &ack, &serving, &hold, now);
        node.send_to(gen, Frame::Msg(Msg::IntakeEvents { id, events, refused, error: None }));
    });
}

/// Serves `wicket node intake` on `sock`, only to peers of uid `uid`: one JSON request a line, one
/// answer a line.
pub(super) fn serve_socket(node: Arc<super::Node>, sock: PathBuf, uid: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::remove_file(&sock);
    let listener = wicket_proxy::sockpath::bind(&sock)?;
    // The intake user reaches it through the socket's directory and group (the node's setup makes
    // them); the peer check below is what decides.
    let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o660));
    // A few connections at a time, each line read within a deadline: a compromised intake can't use
    // up this process's file descriptors or hold connections open (#714 review F8).
    let slots = Arc::new(tokio::sync::Semaphore::new(SOCKET_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            let Ok((c, _)) = listener.accept().await else {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            };
            // Only intake's uid: anyone else who can reach the socket gets nothing.
            if c.peer_cred().map(|p| p.uid()).ok() != Some(uid) {
                continue;
            }
            let n = node.clone();
            let slots = slots.clone();
            tokio::spawn(async move {
                // A busy moment waits for a slot (a dropped deliver is a 503 the sender may not
                // retry), up to a deadline: only a stuck intake is shut out (#714 review F8).
                let Ok(Ok(_permit)) = tokio::time::timeout(SOCKET_SLOT_WAIT, slots.acquire_owned()).await else { return };
                let (rd, mut wr) = c.into_split();
                let mut lines = tokio::io::BufReader::new(rd.take(2 * wicket_core::intake::MAX_BODY as u64 + 4096)).lines();
                while let Ok(Ok(Some(l))) = tokio::time::timeout(SOCKET_LINE_TIMEOUT, lines.next_line()).await {
                    let n2 = n.clone();
                    let a = match serde_json::from_str::<Request>(&l) {
                        Ok(req) => tokio::task::spawn_blocking(move || n2.intake.answer(&n2.paths.root, req, (n2.clock)() / 1000))
                            .await
                            .unwrap_or_else(|e| serde_json::json!({ "error": format!("{e}") })),
                        Err(e) => serde_json::json!({ "error": format!("{e}") }),
                    };
                    let mut out = serde_json::to_vec(&a).unwrap_or_default();
                    out.push(b'\n');
                    if wr.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(trigger: &str, at: i64) -> IntakeEvent {
        IntakeEvent {
            id: String::new(),
            trigger: trigger.into(),
            kind: "webhook".into(),
            delivery: format!("d-{at}"),
            received_at: at,
            fields: serde_json::json!({ "a": 1 }),
            raw_sha256: "00".into(),
            bytes: 2,
        }
    }

    fn t(id: &str) -> IntakeTrigger {
        IntakeTrigger {
            trigger: id.into(),
            kind: "webhook".into(),
            token_sha256: "x".into(),
            secret: "s".into(),
            repo: None,
            events: vec![],
            unavailable: false,
        }
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Only served triggers' events are spooled; a sync hands them over oldest first, acks delete
    /// them, stale and unassigned ones go, one assigned but left out of the table (its secret didn't
    /// read) is kept, and the refusals are counted once. Not ready until the first sync.
    #[test]
    fn the_spool_holds_what_the_control_host_hasnt_acked() {
        let root = std::env::temp_dir().join(format!("wicket-intake-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let i = Intake::default();
        assert_eq!(i.answer(&root, Request::Table, 1)["ready"], false, "not ready before a sync");
        assert!(i.deliver(&root, ev("trg_a", 100), 100).is_err(), "nothing served yet");
        i.sync(&root, vec![t("trg_a"), t("trg_b")], &[], &[], &[], 100);
        assert_eq!(i.answer(&root, Request::Table, 1)["ready"], true);
        i.deliver(&root, ev("trg_a", 100), 100).unwrap();
        i.deliver(&root, ev("trg_b", 101), 101).unwrap();
        i.answer(&root, Request::Refused { counts: IntakeRefused { signature: 2, ..Default::default() } }, 101);
        let (got, refused) = i.sync(&root, vec![t("trg_a"), t("trg_b")], &[], &[], &[], 102);
        assert_eq!(got.iter().map(|e| e.trigger.as_str()).collect::<Vec<_>>(), ["trg_a", "trg_b"]);
        assert_eq!(refused.signature, 2);
        assert_eq!(i.sync(&root, vec![t("trg_a"), t("trg_b")], &[], &[], &[], 102).1.total(), 0, "counted once");
        // Acked: gone. trg_b still assigned but out of the table this time: kept, not sent.
        let (got2, _) = i.sync(&root, vec![t("trg_a")], &[got[0].id.clone()], &ids(&["trg_a", "trg_b"]), &[], 103);
        assert!(got2.is_empty(), "{got2:?}");
        let (got3, _) = i.sync(&root, vec![t("trg_a"), t("trg_b")], &[], &[], &[], 103);
        assert_eq!(got3.len(), 1, "trg_b's event was kept");
        // No longer assigned at all: its events go.
        let (got4, _) = i.sync(&root, vec![t("trg_a")], &[], &ids(&["trg_a"]), &[], 103);
        assert!(got4.is_empty());
        let (got5, _) = i.sync(&root, vec![t("trg_a"), t("trg_b")], &[], &[], &[], 103);
        assert!(got5.is_empty(), "trg_b's event went");
        // Stale: dropped, counted.
        i.deliver(&root, ev("trg_a", 200), 200).unwrap();
        let (got, refused) = i.sync(&root, vec![t("trg_a")], &[], &[], &[], 200 + SPOOL_MAX_AGE_SECS + 1);
        assert!(got.is_empty());
        assert_eq!(refused.other, 1);
        // A held trigger's events are kept and not sent; once it isn't held, they are.
        i.deliver(&root, ev("trg_a", 210), 210).unwrap();
        let (held, _) = i.sync(&root, vec![t("trg_a")], &[], &[], &ids(&["trg_a"]), 211);
        assert!(held.is_empty(), "held");
        let (back, _) = i.sync(&root, vec![t("trg_a")], &[], &[], &[], 211);
        assert_eq!(back.len(), 1, "kept for when it isn't");
        i.sync(&root, vec![t("trg_a")], &[back[0].id.clone()], &[], &[], 211);
        // An ack can't name another file.
        std::fs::write(root.join("intake").join("keep.json"), b"x").unwrap();
        i.sync(&root, vec![], &["../keep".into()], &[], &[], 300);
        assert!(root.join("intake").join("keep.json").exists());
        // The counts are kept in memory: a full spool refuses without reading the disk.
        i.sync(&root, vec![t("trg_a")], &[], &[], &[], 301);
        *i.spool.lock().unwrap() = Some((SPOOL_MAX_EVENTS, 0));
        assert!(i.deliver(&root, ev("trg_a", 301), 301).unwrap_err().to_string().contains("full"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// #714 review H4: the socket and the uid allowed come from `node.json`, else the defaults.
    #[test]
    fn intakes_endpoint_is_the_nodes_to_say() {
        let root = std::env::temp_dir().join(format!("wicket-intake-endpoint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let ctl = root.join("ctl").join("ctl.sock");
        // SAFETY: a plain getter.
        let me = unsafe { libc::geteuid() };
        assert_eq!(endpoint(&root, &ctl), (root.join("ctl").join("intake.sock"), me));
        std::fs::write(root.join("node.json"), br#"{"intake_socket": "/run/wicket-intake/intake.sock", "intake_uid": 4242}"#).unwrap();
        assert_eq!(endpoint(&root, &ctl), (PathBuf::from("/run/wicket-intake/intake.sock"), 4242));
        let _ = std::fs::remove_dir_all(&root);
    }
}
