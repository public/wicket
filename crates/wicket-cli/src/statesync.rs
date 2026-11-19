//! Where the ledger's stream to the state store is (#635): what `wicket state check`, the console's
//! health section and `wicket top` show, and what the console alerts on.
//!
//! The position is Litestream's own. `wicket state replicate` runs it with its control socket on,
//! beside the ledger (`<data dir>/litestream.sock`), and asks nothing of it; this module asks the
//! socket's `GET /list` for the ledger's state and the time of its last successful upload to the
//! store. Litestream records that time after every sync that leaves the store current, including on
//! an idle ledger every `sync_interval`, so how long ago it was is how far behind the store is.
//!
//! Litestream reports replication errors only in its log. `wicket state replicate` reads that log
//! (it is Litestream's parent) and keeps the last error, with when it started Litestream, in
//! `<data dir>/state-stream.json`, which this module reads too. A `replicate` that can't start
//! (another host took over the store, say) records why there.

use crate::statestore::StateStore;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Behind by more than this (or 10 sync intervals, if longer), the stream is lagging.
pub const LAG_SECS: i64 = 60;

/// Litestream's control socket, beside the ledger.
pub fn socket_path(db: &Path) -> PathBuf {
    db.with_file_name("litestream.sock")
}

/// What `wicket state replicate` saw, beside the ledger.
fn log_path(db: &Path) -> PathBuf {
    db.with_file_name("state-stream.json")
}

/// `<data dir>/state-stream.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamLog {
    /// When `wicket state replicate` last started Litestream (Unix ms).
    #[serde(default)]
    pub started_ms: i64,
    #[serde(default)]
    pub lineage: Option<String>,
    /// The last error: Litestream's, or why it isn't running.
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_ms: i64,
}

impl StreamLog {
    pub fn read(db: &Path) -> StreamLog {
        std::fs::read(log_path(db)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    /// Written whole (a temporary file renamed over it): readers never see half of it.
    pub fn write(&self, db: &Path) -> Result<()> {
        let p = log_path(db);
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    /// Records `error` at `at_ms`, keeping the rest.
    pub fn record_error(db: &Path, error: &str, at_ms: i64) {
        let mut l = StreamLog::read(db);
        l.error = Some(wicket_core::text::clip(&wicket_core::text::redact_urls(error), 500));
        l.error_ms = at_ms;
        if let Err(e) = l.write(db) {
            eprintln!("[wicket] recording the stream's error: {e:#}");
        }
    }
}

/// The error a Litestream log line reports, if it is one: its message and its `error` attribute.
/// Litestream logs with Go's slog text handler: `time=… level=ERROR msg="monitor error" error="…" …`.
pub fn log_error(line: &str) -> Option<String> {
    let attrs = slog_attrs(line);
    let level = attrs.iter().find(|(k, _)| k == "level")?;
    if level.1 != "ERROR" {
        return None;
    }
    let msg = attrs.iter().find(|(k, _)| k == "msg").map(|(_, v)| v.as_str()).unwrap_or("error");
    match attrs.iter().find(|(k, _)| k == "error" || k == "err") {
        Some((_, e)) => Some(format!("{msg}: {e}")),
        None => Some(msg.to_string()),
    }
}

/// `key=value` pairs, values bare or Go-quoted (`"a \"b\""`).
fn slog_attrs(line: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let mut it = line.chars().peekable();
    loop {
        while it.peek() == Some(&' ') {
            it.next();
        }
        let key: String = std::iter::from_fn(|| it.next_if(|c| *c != '=' && *c != ' ')).collect();
        if key.is_empty() {
            break;
        }
        if it.next_if_eq(&'=').is_none() {
            continue;
        }
        let mut val = String::new();
        if it.next_if_eq(&'"').is_some() {
            while let Some(c) = it.next() {
                match c {
                    '"' => break,
                    '\\' => match it.next() {
                        Some('n') => val.push('\n'),
                        Some('t') => val.push('\t'),
                        Some(c) => val.push(c),
                        None => break,
                    },
                    c => val.push(c),
                }
            }
        } else {
            val = std::iter::from_fn(|| it.next_if(|c| *c != ' ')).collect();
        }
        out.push((key, val));
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    /// Litestream started and hasn't synced yet.
    Starting,
    /// The store is at most the lag threshold behind.
    Streaming,
    /// Litestream runs, but hasn't brought the store up to date for longer.
    Lagging,
    /// Litestream isn't running, or isn't replicating the ledger.
    Stopped,
}

impl StreamState {
    pub fn as_str(self) -> &'static str {
        match self {
            StreamState::Starting => "starting",
            StreamState::Streaming => "streaming",
            StreamState::Lagging => "lagging",
            StreamState::Stopped => "stopped",
        }
    }
}

/// The ledger stream's state, for the CLI, the console and its alerts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StreamStatus {
    /// The store's endpoint and bucket.
    pub endpoint: String,
    pub bucket: String,
    pub lineage: Option<String>,
    pub state: StreamState,
    /// When Litestream last brought the store up to date (Unix ms), while it runs.
    pub last_sync_ms: Option<i64>,
    /// How far behind the store is (seconds): since the last sync, or since Litestream started if
    /// it hasn't synced. None while it isn't running (how much changed since is unknown).
    pub behind_secs: Option<i64>,
    /// Behind by more than this, it is lagging.
    pub lag_secs: i64,
    /// The last error and when (Unix ms).
    pub error: Option<String>,
    pub error_ms: Option<i64>,
}

/// The ledger stream's state at `now_ms`, for `state-store.yaml` `s` and the ledger at `db`.
pub fn status_of(s: &StateStore, db: &Path, now_ms: i64) -> Result<StreamStatus> {
    let c = s.s3()?;
    let l = s.ledger.as_ref().context("state-store.yaml has no ledger: section")?;
    let interval = wicket_core::time::parse_duration(&l.sync_interval).context("ledger.sync_interval")?.as_secs() as i64;
    let lag_secs = LAG_SECS.max(10 * interval);
    let log = StreamLog::read(db);
    let mut st = StreamStatus {
        endpoint: c.shown_endpoint(),
        bucket: c.bucket.clone(),
        lineage: log.lineage.clone(),
        state: StreamState::Stopped,
        last_sync_ms: None,
        behind_secs: None,
        lag_secs,
        error: log.error.clone(),
        error_ms: log.error.as_ref().map(|_| log.error_ms),
    };
    let list = match ask(&socket_path(db), "/list") {
        Ok(v) => v,
        Err(e) => {
            if st.error.is_none() || log.error_ms < log.started_ms {
                st.error = Some(wicket_core::text::redact_urls(&format!("Litestream isn't running (its control socket: {e:#})")));
                st.error_ms = None;
            }
            return Ok(st);
        }
    };
    let dbs = list["databases"].as_array().cloned().unwrap_or_default();
    let mine = dbs.iter().find(|d| d["path"].as_str().map(Path::new) == Some(db)).or(dbs.first());
    let Some(d) = mine else {
        st.error.get_or_insert_with(|| "Litestream runs but doesn't replicate the ledger".into());
        return Ok(st);
    };
    if d["status"].as_str() == Some("stopped") {
        return Ok(st);
    }
    st.last_sync_ms = d["last_sync_at"].as_str().and_then(go_time_ms);
    let since = st.last_sync_ms.unwrap_or(log.started_ms);
    let behind = ((now_ms - since) / 1000).max(0);
    st.behind_secs = Some(behind);
    st.state = match (st.last_sync_ms, behind <= lag_secs) {
        (_, false) => StreamState::Lagging,
        (Some(_), true) => StreamState::Streaming,
        (None, true) => StreamState::Starting,
    };
    Ok(st)
}

/// A Go `time.Time` as JSON writes it (RFC 3339, nanoseconds, `Z` or an offset) in Unix ms.
fn go_time_ms(s: &str) -> Option<i64> {
    let base = wicket_core::time::parse_rfc3339_weak(s.get(..19)?).ok()?;
    let mut ms = base.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as i64;
    let rest = &s[19..];
    let (frac, zone) = match rest.find(['Z', '+', '-']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    if let Some(f) = frac.strip_prefix('.') {
        let digits: String = f.chars().chain(std::iter::repeat('0')).take(3).collect();
        ms += digits.parse::<i64>().ok()?;
    }
    if zone.len() == 6 {
        let sign = if zone.starts_with('-') { -1 } else { 1 };
        let off = zone[1..3].parse::<i64>().ok()? * 3600 + zone[4..6].parse::<i64>().ok()? * 60;
        ms -= sign * off * 1000;
    }
    Some(ms)
}

/// How long a question to Litestream's socket may take, connecting included.
const ASK_DEADLINE: Duration = Duration::from_secs(3);

/// A GET on Litestream's control socket (HTTP over a unix socket), its JSON body, within
/// [`ASK_DEADLINE`]. std has no connect timeout for unix sockets (a listener with a full backlog
/// blocks it), so the question runs on a thread of its own, left behind if it doesn't answer.
fn ask(sock: &Path, path: &str) -> Result<serde_json::Value> {
    ask_within(sock, path, ASK_DEADLINE)
}

fn ask_within(sock: &Path, path: &str, deadline: Duration) -> Result<serde_json::Value> {
    let (tx, rx) = std::sync::mpsc::channel();
    let (sock, path) = (sock.to_path_buf(), path.to_string());
    std::thread::Builder::new().name("litestream-ask".into()).spawn(move || {
        let _ = tx.send(ask_now(&sock, &path));
    })?;
    rx.recv_timeout(deadline).unwrap_or_else(|_| bail!("Litestream didn't answer on its control socket within {} s", deadline.as_secs()))
}

fn ask_now(sock: &Path, path: &str) -> Result<serde_json::Value> {
    let mut s = std::os::unix::net::UnixStream::connect(sock).with_context(|| format!("{}", sock.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.set_write_timeout(Some(Duration::from_secs(2)))?;
    // HTTP/1.0: the reply is the whole body, then the connection closes (no chunking).
    write!(s, "GET {path} HTTP/1.0\r\nHost: litestream\r\n\r\n")?;
    let mut resp = Vec::new();
    s.take(1 << 20).read_to_end(&mut resp)?;
    let resp = String::from_utf8_lossy(&resp);
    let (head, body) = resp.split_once("\r\n\r\n").context("Litestream's reply has no body")?;
    let status = head.lines().next().unwrap_or("");
    if status.split_whitespace().nth(1) != Some("200") {
        // Shown in the console: cut, and any URL in it without its user info or query.
        let body = wicket_core::text::redact_urls(&wicket_core::text::clip(body.trim(), 200));
        bail!("Litestream said {:?}: {body}", wicket_core::text::clip(status, 60));
    }
    serde_json::from_str(body).context("Litestream's reply")
}

/// The state store's sync and the audit export's progress together: what the console's health
/// section and `wicket top` show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Progress {
    /// The ledger stream, if `state-store.yaml` has a `ledger:` section.
    pub stream: Option<StreamStatus>,
    /// Every audit sink against the chain head.
    pub audit: Vec<crate::audit_export::SinkStatus>,
    /// What couldn't be read. These name the file and the command that says more, never the
    /// file's values (an error can quote one, and these reach the console and its pushes).
    pub errors: Vec<String>,
}

/// The progress at `now_ms` from the given configs (as `StateStore::load` and `SinksConfig::load`
/// return them) and the ledger `l` at `ledger`. None with neither a state store nor sinks.
pub fn progress(
    l: &wicket_store::Ledger,
    ledger: &Path,
    store: Result<Option<StateStore>>,
    sinks: Result<Option<crate::audit_export::SinksConfig>>,
    now_ms: i64,
) -> Option<Progress> {
    let mut errors = Vec::new();
    let stream = match store {
        Ok(Some(s)) if s.ledger.is_some() => status_of(&s, ledger, now_ms)
            .map_err(|_| errors.push("the ledger stream can't be read: `wicket state check` says why".into()))
            .ok(),
        Ok(_) => None,
        Err(_) => {
            errors.push("state-store.yaml can't be read: `wicket state check` says why".into());
            None
        }
    };
    let audit = match sinks {
        Ok(Some(c)) => crate::audit_export::status(l, &c, now_ms / 1000).unwrap_or_else(|_| {
            errors.push("the audit export's cursors can't be read: `wicket audit export --status` says why".into());
            vec![]
        }),
        Ok(None) => vec![],
        Err(_) => {
            errors.push("audit-sinks.yaml can't be read: `wicket audit export --status` says why".into());
            vec![]
        }
    };
    (stream.is_some() || !audit.is_empty() || !errors.is_empty()).then_some(Progress { stream, audit, errors })
}

/// The ledger stream not current for longer than this is an alert (and a push).
pub const STREAM_ALERT_SECS: i64 = 300;
/// An audit sink whose oldest unacknowledged record has waited longer than this is an alert.
pub const AUDIT_ALERT_SECS: i64 = 300;
/// So is one behind by more records than this, however recent.
pub const AUDIT_ALERT_RECORDS: i64 = 10_000;

/// A config that can't be read for longer than this is an alert: nothing is streamed or exported
/// as configured meanwhile.
pub const CONFIG_ALERT_SECS: i64 = 300;

/// What the alerts remember between reads of the progress: when the ledger's stream was last
/// current (a stopped or restarting Litestream doesn't say), and since when a config can't be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watch {
    /// The last sync seen while the stream was streaming, or when watching started.
    pub stream_current_ms: i64,
    /// Since when [`Progress::errors`] has been non-empty, without a break.
    pub errors_since_ms: Option<i64>,
}

impl Watch {
    pub fn new(now_ms: i64) -> Watch {
        Watch { stream_current_ms: now_ms, errors_since_ms: None }
    }

    /// Notes one read at `now_ms`.
    pub fn observe(&mut self, p: Option<&Progress>, now_ms: i64) {
        if let Some(st) = p.and_then(|p| p.stream.as_ref()).filter(|s| s.state == StreamState::Streaming) {
            self.stream_current_ms = self.stream_current_ms.max(st.last_sync_ms.unwrap_or(now_ms));
        }
        self.errors_since_ms = match p.is_some_and(|p| !p.errors.is_empty()) {
            true => Some(self.errors_since_ms.unwrap_or(now_ms)),
            false => None,
        };
    }
}

/// The health alerts `p` raises at `now_ms` (#635), which the console shows and pushes as it does a
/// node's: once each until it clears.
/// - The ledger stream, in any state but streaming, not current for [`STREAM_ALERT_SECS`] (or its
///   lag threshold, 10 sync intervals, if longer): since
///   Litestream's last sync if it reports one, else since `w` last saw one.
/// - An audit sink (not a manual one) whose oldest unacknowledged record has waited
///   [`AUDIT_ALERT_SECS`], or that is [`AUDIT_ALERT_RECORDS`] behind.
/// - A config that couldn't be read for [`CONFIG_ALERT_SECS`].
///
/// Keys start `control:`, which a node's name can't. Texts carry no error: they reach lock
/// screens, and an error can quote a collector's reply. The console's rows have the errors.
pub fn alerts(p: &Progress, w: &Watch, now_ms: i64) -> Vec<crate::health::Alert> {
    let ago = |ms: i64| crate::audit_export::ago(ms / 1000);
    let mut out = Vec::new();
    if let Some(st) = p.stream.as_ref().filter(|s| s.state != StreamState::Streaming) {
        let current = st.last_sync_ms.unwrap_or(w.stream_current_ms);
        // Never sooner than the stream counts as lagging: 10 sync intervals, if that is longer.
        if now_ms - current > STREAM_ALERT_SECS.max(st.lag_secs) * 1000 {
            let since = match st.last_sync_ms {
                Some(t) => format!("last sync {} ago", ago(now_ms - t)),
                None => format!("not current for {}", ago(now_ms - current)),
            };
            out.push(crate::health::Alert {
                key: "control:state-store/stream".into(),
                text: format!("the state store: the ledger stream is {} ({since})", st.state.as_str()),
            });
        }
    }
    for s in p.audit.iter().filter(|s| !s.manual) {
        if s.behind_secs > AUDIT_ALERT_SECS || s.behind > AUDIT_ALERT_RECORDS {
            out.push(crate::health::Alert {
                key: format!("control:audit/{}", s.sink),
                text: format!("audit sink {}: {} records behind (oldest {})", s.sink, s.behind, crate::audit_export::ago(s.behind_secs)),
            });
        }
    }
    if let Some(since) = w.errors_since_ms.filter(|t| !p.errors.is_empty() && now_ms - t > CONFIG_ALERT_SECS * 1000) {
        out.push(crate::health::Alert {
            key: "control:state-store/config".into(),
            // The errors name the file and the command that says why, never a value.
            text: format!("{} (for {})", p.errors.join("; "), ago(now_ms - since)),
        });
    }
    out
}

/// A read of the progress older than this is stale: the console marks its rows so, as they may no
/// longer say what is true (the ledger couldn't be opened, or a read hung).
pub const STALE_SECS: i64 = 30;

/// Whether a read made at `read_ms` is stale at `now_ms`, and the alert once it has been for
/// [`STREAM_ALERT_SECS`]: then nothing about the stream or the sinks is being checked.
pub fn staleness(read_ms: i64, now_ms: i64) -> (bool, Option<crate::health::Alert>) {
    let age = (now_ms - read_ms) / 1000;
    let alert = (age > STREAM_ALERT_SECS).then(|| crate::health::Alert {
        key: "control:state-store/unread".into(),
        text: format!(
            "the state store and audit export haven't been checked for {}: the console's reads fail or hang (its log says why)",
            crate::audit_export::ago(age)
        ),
    });
    (age > STALE_SECS, alert)
}

/// [`progress`] with this installation's configs, at the ledger `l` opened from `ledger`.
pub fn installed_progress(l: &wicket_store::Ledger, ledger: &Path, now_ms: i64) -> Option<Progress> {
    progress(l, ledger, StateStore::load(), crate::audit_export::SinksConfig::load(), now_ms)
}

/// The stream on one line: `wicket state check`.
pub fn line(st: &StreamStatus, now_ms: i64) -> String {
    let ago = |ms: i64| crate::audit_export::ago((now_ms - ms) / 1000);
    let mut out = format!("ledger stream to {} ({}): {}", st.endpoint, st.bucket, st.state.as_str());
    match (st.last_sync_ms, st.behind_secs) {
        (Some(t), _) => out += &format!(", last sync {} ago", ago(t)),
        (None, Some(b)) => out += &format!(", no sync yet ({} since it started)", crate::audit_export::ago(b)),
        (None, None) => {}
    }
    if let Some(e) = &st.error {
        let when = st.error_ms.map(|t| format!(" {} ago", ago(t))).unwrap_or_default();
        out += &format!("  last error{when}: {e}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> StateStore {
        StateStore::parse("s3: { endpoint: 'https://s3.example.com', bucket: b-1, access_key_id: k, secret: s3 }\nledger: {}\n").unwrap()
    }

    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Dir {
            // Short: a unix socket's path is at most 107 bytes.
            let d = std::env::temp_dir().join(format!("ss-{}", &wicket_core::new_ulid().to_string()[16..]));
            std::fs::create_dir_all(&d).unwrap();
            Dir(d)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A stand-in for Litestream's control socket: answers each connection with `body` (v0.5.18's
    /// `GET /list` shape) until dropped.
    fn litestream(db: &Path, body: String) -> std::thread::JoinHandle<()> {
        let l = std::os::unix::net::UnixListener::bind(socket_path(db)).unwrap();
        std::thread::spawn(move || {
            if let Ok((mut c, _)) = l.accept() {
                let mut req = [0u8; 512];
                let n = c.read(&mut req).unwrap();
                assert!(String::from_utf8_lossy(&req[..n]).starts_with("GET /list HTTP/1.0\r\n"));
                write!(c, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{body}").unwrap();
            }
        })
    }

    #[test]
    fn litestreams_times_are_read_with_their_zone() {
        let t = go_time_ms("2026-11-19T18:57:00.123456789Z").unwrap();
        assert_eq!(t % 1000, 123);
        assert_eq!(go_time_ms("2026-11-19T19:57:00.123+01:00").unwrap(), t);
        assert_eq!(go_time_ms("2026-11-19T13:57:00.1-05:00").unwrap(), t - 23);
        assert_eq!(go_time_ms("2026-11-19T18:57:00Z").unwrap(), t - 123);
        assert_eq!(go_time_ms("nope"), None);
    }

    #[test]
    fn the_stream_is_streaming_lagging_or_stopped() {
        let d = Dir::new();
        let db = d.0.join("ledger.db");
        let s = store();
        let synced = go_time_ms("2026-11-19T18:57:00Z").unwrap();

        // No Litestream: stopped, saying so.
        let st = status_of(&s, &db, synced).unwrap();
        assert_eq!((st.state, st.behind_secs), (StreamState::Stopped, None));
        assert!(st.error.as_deref().unwrap().starts_with("Litestream isn't running"), "{st:?}");

        // Synced 5 s ago: streaming.
        let list = |at: &str| format!(r#"{{"databases":[{{"path":"{}","status":"replicating","last_sync_at":"{at}"}}]}}"#, db.display());
        let t = litestream(&db, list("2026-11-19T18:57:00.000000001Z"));
        let st = status_of(&s, &db, synced + 5_000).unwrap();
        t.join().unwrap();
        assert_eq!((st.state, st.last_sync_ms, st.behind_secs, st.error.as_deref()), (StreamState::Streaming, Some(synced), Some(5), None));
        assert!(line(&st, synced + 5_000).ends_with(": streaming, last sync 5 s ago"), "{}", line(&st, synced + 5_000));

        // An upload failing since: Litestream logged it, and the store is 2 min behind.
        std::fs::remove_file(socket_path(&db)).unwrap();
        StreamLog { started_ms: synced - 60_000, lineage: Some("l1".into()), ..Default::default() }.write(&db).unwrap();
        StreamLog::record_error(&db, "monitor error: calc pos: connection refused", synced + 3_000);
        let t = litestream(&db, list("2026-11-19T18:57:00Z"));
        let st = status_of(&s, &db, synced + 120_000).unwrap();
        t.join().unwrap();
        assert_eq!((st.state, st.behind_secs, st.lineage.as_deref()), (StreamState::Lagging, Some(120), Some("l1")));
        assert_eq!((st.error.as_deref(), st.error_ms), (Some("monitor error: calc pos: connection refused"), Some(synced + 3_000)));
        let l = line(&st, synced + 120_000);
        assert!(l.contains(": lagging, last sync 2 min ago  last error 117 s ago: monitor error"), "{l}");

        // Started, nothing synced yet.
        std::fs::remove_file(socket_path(&db)).unwrap();
        let t = litestream(&db, format!(r#"{{"databases":[{{"path":"{}","status":"replicating"}}]}}"#, db.display()));
        let st = status_of(&s, &db, synced - 50_000).unwrap();
        t.join().unwrap();
        assert_eq!((st.state, st.behind_secs), (StreamState::Starting, Some(10)));

        // Litestream gone again: the error it logged is kept (it is newer than its start).
        std::fs::remove_file(socket_path(&db)).unwrap();
        let st = status_of(&s, &db, synced + 200_000).unwrap();
        assert_eq!((st.state, st.error.as_deref()), (StreamState::Stopped, Some("monitor error: calc pos: connection refused")));
    }

    fn stream(state: StreamState, last_sync_ms: Option<i64>, now: i64) -> StreamStatus {
        StreamStatus {
            endpoint: "https://s3.example.com".into(),
            bucket: "b-1".into(),
            lineage: None,
            state,
            last_sync_ms,
            behind_secs: last_sync_ms.map(|t| (now - t) / 1000),
            lag_secs: 60,
            error: Some("calc pos: connection refused".into()),
            error_ms: Some(now - 1000),
        }
    }

    fn sink(name: &str, behind: i64, behind_secs: i64, manual: bool) -> crate::audit_export::SinkStatus {
        crate::audit_export::SinkStatus {
            sink: name.into(),
            kind: if manual { "jsonl" } else { "store" },
            seq: 1,
            head: 1 + behind,
            behind,
            behind_secs,
            checkpoint_at: 0,
            holder: None,
            error: Some("PUT https://c.example/v1/logs: 401: token rejected".into()),
            manual,
        }
    }

    fn progress_of(s: Option<StreamStatus>, audit: Vec<crate::audit_export::SinkStatus>, errors: &[&str]) -> Progress {
        Progress { stream: s, audit, errors: errors.iter().map(|e| e.to_string()).collect() }
    }

    fn keys(p: &Progress, w: &Watch, now: i64) -> Vec<String> {
        alerts(p, w, now).into_iter().map(|a| a.key).collect()
    }

    const NOW: i64 = 1_763_200_000_000;

    #[test]
    fn a_stream_behind_past_five_minutes_of_its_last_sync_is_an_alert() {
        // Watching for an hour, and the stream current all along until it lagged.
        let mut w = Watch::new(NOW - 3_600_000);
        w.observe(Some(&progress_of(Some(stream(StreamState::Streaming, Some(NOW - 330_000), NOW - 329_000)), vec![], &[])), NOW - 329_000);
        assert_eq!(w.stream_current_ms, NOW - 330_000, "the sync it saw, not the poll's time");
        // Lagging, last sync 4 min 59 s ago: no alert; 5 min 1 s: one, saying when, no error text.
        let lag = |since| progress_of(Some(stream(StreamState::Lagging, Some(NOW - since), NOW)), vec![], &[]);
        assert!(keys(&lag(299_000), &w, NOW).is_empty());
        let a = alerts(&lag(301_000), &w, NOW);
        assert_eq!(a[0].key, "control:state-store/stream");
        assert_eq!(a[0].text, "the state store: the ledger stream is lagging (last sync 5 min ago)");
        // Streaming again: cleared.
        assert!(keys(&progress_of(Some(stream(StreamState::Streaming, Some(NOW - 1_000), NOW)), vec![], &[]), &w, NOW).is_empty());
    }

    /// Litestream crash-looping (restarted every few seconds, never syncing): polls see it stopped
    /// and starting in turn, and it is alerted 5 min after its last sync, not never.
    #[test]
    fn a_crash_looping_litestream_is_alerted() {
        let start = NOW - 600_000;
        let mut w = Watch::new(start - 60_000);
        let last_sync = start - 10_000;
        w.observe(Some(&progress_of(Some(stream(StreamState::Streaming, Some(last_sync), start)), vec![], &[])), start);
        let mut first_alert = None;
        for i in 0..200 {
            let now = start + i * 3_000;
            let state = if i % 2 == 0 { StreamState::Stopped } else { StreamState::Starting };
            let p = progress_of(Some(stream(state, None, now)), vec![], &[]);
            w.observe(Some(&p), now);
            if !keys(&p, &w, now).is_empty() && first_alert.is_none() {
                first_alert = Some(now);
            }
        }
        let at = first_alert.expect("alerted within 10 minutes");
        assert!(at - last_sync > 300_000 && at - last_sync <= 303_000, "5 min after the last sync: {}", at - last_sync);
        let p = progress_of(Some(stream(StreamState::Stopped, None, start + 600_000)), vec![], &[]);
        assert!(alerts(&p, &w, start + 600_000)[0].text.contains("stopped (not current for 10 min)"));
    }

    #[test]
    fn a_sink_behind_is_an_alert_unless_it_is_fed_by_hand() {
        let w = Watch::new(NOW);
        assert!(keys(&progress_of(None, vec![sink("store", 24, 299, false)], &[]), &w, NOW).is_empty());
        let a = alerts(&progress_of(None, vec![sink("store", 24, 301, false)], &[]), &w, NOW);
        assert_eq!((a[0].key.as_str(), a[0].text.as_str()), ("control:audit/store", "audit sink store: 24 records behind (oldest 5 min)"));
        assert!(!a[0].text.contains("token"), "no error in a push");
        assert_eq!(keys(&progress_of(None, vec![sink("store", 10_001, 2, false)], &[]), &w, NOW), ["control:audit/store"]);
        assert!(keys(&progress_of(None, vec![sink("stdout", 50_000, 86_400, true)], &[]), &w, NOW).is_empty(), "manual: never");
    }

    #[test]
    fn a_config_that_cant_be_read_is_an_alert_after_five_minutes_and_clears() {
        let mut w = Watch::new(NOW - 3_600_000);
        let bad = progress_of(None, vec![], &["state-store.yaml can't be read: `wicket state check` says why"]);
        w.observe(Some(&bad), NOW - 299_000);
        assert!(keys(&bad, &w, NOW).is_empty());
        w.observe(Some(&bad), NOW + 2_000);
        assert_eq!(keys(&bad, &w, NOW + 2_000), ["control:state-store/config"]);
        let sinks_bad = progress_of(None, vec![], &["audit-sinks.yaml can't be read: `wicket audit export --status` says why"]);
        assert_eq!(
            alerts(&sinks_bad, &w, NOW + 2_000)[0].text,
            "audit-sinks.yaml can't be read: `wicket audit export --status` says why (for 5 min)",
            "names the file that is broken"
        );
        let good = progress_of(None, vec![sink("store", 0, 0, false)], &[]);
        w.observe(Some(&good), NOW + 5_000);
        assert_eq!(w.errors_since_ms, None);
        assert!(keys(&good, &w, NOW + 5_000).is_empty(), "cleared");
        w.observe(Some(&bad), NOW + 8_000);
        assert!(keys(&bad, &w, NOW + 9_000).is_empty(), "back: the delay starts again");
    }

    #[test]
    fn a_slow_sync_interval_alerts_no_sooner_than_it_lags() {
        let w = Watch::new(NOW - 3_600_000);
        let mut st = stream(StreamState::Starting, Some(NOW - 400_000), NOW);
        st.lag_secs = 600; // sync_interval: 60s
        assert!(keys(&progress_of(Some(st.clone()), vec![], &[]), &w, NOW).is_empty());
        st.last_sync_ms = Some(NOW - 601_000);
        assert_eq!(keys(&progress_of(Some(st), vec![], &[]), &w, NOW), ["control:state-store/stream"]);
    }

    #[test]
    fn a_read_goes_stale_then_alerts() {
        assert_eq!(staleness(NOW - 30_000, NOW), (false, None));
        assert!(staleness(NOW - 31_000, NOW).0);
        assert_eq!(staleness(NOW - 299_000, NOW).1, None);
        assert_eq!(staleness(NOW - 301_000, NOW).1.unwrap().key, "control:state-store/unread");
    }

    /// A socket that accepts nothing (its backlog full, or a process that never reads) doesn't hold a
    /// read past the deadline; and a refusal's body is cut and its URLs redacted.
    #[test]
    fn litestreams_socket_is_asked_within_a_deadline() {
        let d = Dir::new();
        let db = d.0.join("ledger.db");
        let _held = std::os::unix::net::UnixListener::bind(socket_path(&db)).unwrap(); // never accepted, never answered
        let t = std::time::Instant::now();
        let e = ask_within(&socket_path(&db), "/list", Duration::from_millis(300)).unwrap_err().to_string();
        assert!(t.elapsed() < Duration::from_secs(2) && e.contains("didn't answer"), "{e}");
        drop(_held);
        std::fs::remove_file(socket_path(&db)).unwrap();
        let l = std::os::unix::net::UnixListener::bind(socket_path(&db)).unwrap();
        let h = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut req = [0u8; 512];
            let _ = c.read(&mut req).unwrap();
            write!(c, "HTTP/1.0 500 Internal Server Error\r\n\r\nfailed: https://k:s3cr3t@s3.example.com/b?sig=abc").unwrap();
        });
        let e = ask(&socket_path(&db), "/list").unwrap_err().to_string();
        h.join().unwrap();
        assert!(e.contains("https://s3.example.com/b?…") && !e.contains("s3cr3t") && !e.contains("sig=abc"), "{e}");
    }

    #[test]
    fn errors_are_read_from_litestreams_log() {
        let l = r#"time=2026-11-19T18:57:00.000Z level=ERROR msg="monitor error" error="calc pos: operation error S3: ListObjectsV2, dial tcp: \"connect\" refused" consecutive_errors=3 backoff=4s"#;
        assert_eq!(log_error(l).unwrap(), r#"monitor error: calc pos: operation error S3: ListObjectsV2, dial tcp: "connect" refused"#);
        assert_eq!(log_error("time=x level=ERROR msg=boom").unwrap(), "boom");
        assert_eq!(log_error(r#"time=x level=INFO msg="replica sync" db=/x"#), None);
        assert_eq!(log_error("[wicket] streaming"), None);
    }
}
