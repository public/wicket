//! The node's side of webhook intake (#578 step 4; docs/explanation/trigger-intake.md).
//!
//! `wicket intake serve`, a small process of its own beside this `serve`, terminates the deliveries.
//! This `serve` keeps what it needs and what it hands over:
//! - the table of triggers it serves, as the control host last sent it ([`Msg::IntakeSync`]), in
//!   memory only (it holds their verify secrets);
//! - the spool of verified events, on disk, bounded, until the control host acks them;
//! - the counts of what intake refused, until the next sync.
//!
//! Intake reaches it over `<node dir>/ctl/intake.sock`, in the 0700 control directory: a connection
//! per request, one JSON line each way (bounded).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
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

/// The intake socket, beside the control socket.
pub fn socket(ctl: &Path) -> PathBuf {
    ctl.with_file_name("intake.sock")
}

#[derive(Default)]
pub(super) struct Intake {
    table: Mutex<Vec<IntakeTrigger>>,
    refused: Mutex<IntakeRefused>,
    /// One writer or reader of the spool at a time.
    spool: Mutex<()>,
}

/// One request from `wicket intake serve`.
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

impl Intake {
    fn dir(root: &Path) -> PathBuf {
        root.join("intake").join("spool")
    }

    /// The spool's events, oldest first, with their files and sizes. Unreadable or stale files are
    /// removed (counted as refused: they never reach the control host).
    fn spooled(&self, root: &Path, now: i64) -> Vec<(PathBuf, u64, IntakeEvent)> {
        let dir = Intake::dir(root);
        let Ok(rd) = std::fs::read_dir(&dir) else { return vec![] };
        let mut names: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
        names.sort();
        let mut out = vec![];
        for p in names {
            let Ok(b) = std::fs::read(&p) else { continue };
            match serde_json::from_slice::<IntakeEvent>(&b) {
                Ok(e) if now - e.received_at <= SPOOL_MAX_AGE_SECS => out.push((p, b.len() as u64, e)),
                _ => {
                    let _ = std::fs::remove_file(&p);
                    self.refused.lock().expect("refused").other += 1;
                }
            }
        }
        out
    }

    /// Spools `e`, atomically and synced. Err if the spool is full, or the event isn't for a trigger
    /// served here.
    pub(super) fn deliver(&self, root: &Path, mut e: IntakeEvent, now: i64) -> anyhow::Result<()> {
        if !self.table.lock().expect("table").iter().any(|t| t.trigger == e.trigger) {
            anyhow::bail!("not served here");
        }
        let _g = self.spool.lock().expect("spool");
        let held = self.spooled(root, now);
        let bytes: u64 = held.iter().map(|(_, n, _)| n).sum();
        if held.len() >= SPOOL_MAX_EVENTS || bytes >= SPOOL_MAX_BYTES {
            anyhow::bail!("full");
        }
        let dir = Intake::dir(root);
        std::fs::create_dir_all(&dir)?;
        // Sorts by when, then is unique: a timestamp and part of a fresh token.
        let r = wicket_core::intake::new_token().map_err(|err| anyhow::anyhow!(err))?;
        let r: String = r.chars().filter(char::is_ascii_alphanumeric).take(16).collect();
        e.id = format!("{:020}-{r}", now.max(0));
        let body = serde_json::to_vec(&e)?;
        let tmp = dir.join(format!(".{}.tmp", e.id));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, dir.join(format!("{}.json", e.id)))?;
        if let Ok(d) = std::fs::File::open(&dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// A sync: the new table, the acked events deleted, then what to send (oldest first, bounded)
    /// and the refusals counted since the last one.
    pub(super) fn sync(&self, root: &Path, triggers: Vec<IntakeTrigger>, ack: &[String], now: i64) -> (Vec<IntakeEvent>, IntakeRefused) {
        *self.table.lock().expect("table") = triggers;
        let _g = self.spool.lock().expect("spool");
        let dir = Intake::dir(root);
        for id in ack {
            // Only a spool id's shape: an ack never names another file.
            if !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                let _ = std::fs::remove_file(dir.join(format!("{id}.json")));
            }
        }
        let served: Vec<String> = self.table.lock().expect("table").iter().map(|t| t.trigger.clone()).collect();
        let (mut out, mut size) = (vec![], 0usize);
        for (p, n, e) in self.spooled(root, now) {
            // A trigger no longer served (deleted, moved to another node): its events go.
            if !served.contains(&e.trigger) {
                let _ = std::fs::remove_file(&p);
                continue;
            }
            if out.len() >= SYNC_MAX_EVENTS || size + n as usize > SYNC_MAX_BYTES {
                break;
            }
            size += n as usize;
            out.push(e);
        }
        let refused = std::mem::take(&mut *self.refused.lock().expect("refused"));
        (out, refused)
    }

    /// Answers one request from intake.
    pub(super) fn answer(&self, root: &Path, req: Request, now: i64) -> serde_json::Value {
        match req {
            Request::Table => serde_json::json!({ "triggers": *self.table.lock().expect("table") }),
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

/// Handles the control host's [`Msg::IntakeSync`] on connection `gen`.
pub(super) fn sync(node: &super::Node, gen: u64, id: u64, triggers: Vec<IntakeTrigger>, ack: Vec<String>) {
    let now = (node.clock)() / 1000;
    let (events, refused) = node.intake.sync(&node.paths.root, triggers, &ack, now);
    node.send_to(gen, Frame::Msg(Msg::IntakeEvents { id, events, refused, error: None }));
}

/// Serves `wicket intake serve` on `sock`: one JSON request a line, one answer a line.
pub(super) fn serve_socket(node: std::sync::Arc<super::Node>, sock: PathBuf) -> anyhow::Result<()> {
    let _ = std::fs::remove_file(&sock);
    let listener = wicket_proxy::sockpath::bind(&sock)?;
    tokio::spawn(async move {
        loop {
            let Ok((c, _)) = listener.accept().await else {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            };
            let n = node.clone();
            tokio::spawn(async move {
                let (rd, mut wr) = c.into_split();
                let mut lines = tokio::io::BufReader::new(rd.take(2 * wicket_core::intake::MAX_BODY as u64 + 4096)).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    let a = match serde_json::from_str::<Request>(&l) {
                        Ok(req) => n.intake.answer(&n.paths.root, req, (n.clock)() / 1000),
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
        }
    }

    /// Only served triggers' events are spooled; a sync hands them over oldest first, acks delete
    /// them, stale and unserved ones go, and the refusals are counted once.
    #[test]
    fn the_spool_holds_what_the_control_host_hasnt_acked() {
        let root = std::env::temp_dir().join(format!("wicket-intake-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let i = Intake::default();
        assert!(i.deliver(&root, ev("trg_a", 100), 100).is_err(), "nothing served yet");
        i.sync(&root, vec![t("trg_a"), t("trg_b")], &[], 100);
        i.deliver(&root, ev("trg_a", 100), 100).unwrap();
        i.deliver(&root, ev("trg_b", 101), 101).unwrap();
        i.answer(&root, Request::Refused { counts: IntakeRefused { signature: 2, ..Default::default() } }, 101);
        let (got, refused) = i.sync(&root, vec![t("trg_a"), t("trg_b")], &[], 102);
        assert_eq!(got.iter().map(|e| e.trigger.as_str()).collect::<Vec<_>>(), ["trg_a", "trg_b"]);
        assert_eq!(refused.signature, 2);
        assert_eq!(i.sync(&root, vec![t("trg_a"), t("trg_b")], &[], 102).1.total(), 0, "counted once");
        // Acked: gone. A trigger no longer served: its events go too.
        let (got, _) = i.sync(&root, vec![t("trg_b")], &[got[0].id.clone()], 103);
        assert_eq!(got.len(), 1);
        let (got, _) = i.sync(&root, vec![t("trg_a")], &[], 103);
        assert!(got.is_empty(), "trg_b's event went with it");
        // Stale: dropped, counted.
        i.deliver(&root, ev("trg_a", 200), 200).unwrap();
        let (got, refused) = i.sync(&root, vec![t("trg_a")], &[], 200 + SPOOL_MAX_AGE_SECS + 1);
        assert!(got.is_empty());
        assert_eq!(refused.other, 1);
        // An ack can't name another file.
        std::fs::write(root.join("intake").join("keep.json"), b"x").unwrap();
        i.sync(&root, vec![], &["../keep".into()], 300);
        assert!(root.join("intake").join("keep.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
