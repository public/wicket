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
                st.error = Some(format!("Litestream isn't running (its control socket: {e:#})"));
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

/// A GET on Litestream's control socket (HTTP over a unix socket), its JSON body.
fn ask(sock: &Path, path: &str) -> Result<serde_json::Value> {
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
        bail!("Litestream said {status:?}: {}", body.trim());
    }
    serde_json::from_str(body).context("Litestream's reply")
}

/// The state store's sync and the audit export's progress together: what the console's health
/// section shows (and, later, `wicket top`).
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

    #[test]
    fn errors_are_read_from_litestreams_log() {
        let l = r#"time=2026-11-19T18:57:00.000Z level=ERROR msg="monitor error" error="calc pos: operation error S3: ListObjectsV2, dial tcp: \"connect\" refused" consecutive_errors=3 backoff=4s"#;
        assert_eq!(log_error(l).unwrap(), r#"monitor error: calc pos: operation error S3: ListObjectsV2, dial tcp: "connect" refused"#);
        assert_eq!(log_error("time=x level=ERROR msg=boom").unwrap(), "boom");
        assert_eq!(log_error(r#"time=x level=INFO msg="replica sync" db=/x"#), None);
        assert_eq!(log_error("[wicket] streaming"), None);
    }
}
