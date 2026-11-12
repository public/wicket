//! The batched audit writer (#62): one background thread per process that appends audit records
//! to the ledger file in group commits, so no request waits for its own fsync.
//!
//! - **Deferred** records ([`AuditWriter::submit`]) are queued and the caller moves on; the
//!   egress proxy's per-request `op` rows go this way. They are durable once their batch commits,
//!   a few milliseconds later.
//! - **Durable** records ([`AuditWriter::append`]) wait for their batch's commit and return its
//!   sequence number. Decisions, approvals and everything else that must be on disk before it takes
//!   effect go this way. Waiting is a shared flush: every record in the batch rides the same fsync.
//!
//! A batch is one `BEGIN IMMEDIATE` transaction: the head is read and every record chained and
//! inserted under SQLite's write lock, so other processes appending to the same ledger (a run, its
//! children, the console) interleave whole batches and the hash chain stays a single chain. The
//! ledger is in WAL mode with `synchronous = FULL`, so a committed batch survives a crash or a power
//! cut, and an acknowledged record (`append` returned, or a [`AuditWriter::flush`] after `submit`)
//! is never lost.
//!
//! Batching: the thread takes whatever is queued (at most `max_batch`). If nothing in the batch is
//! waited on, it lingers up to `linger` for more, to save fsyncs; a waited-on record commits at once.

use crate::{chain_hash_v2, now, ChainFields, Result, StoreError, CHAIN_ZERO};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use wicket_core::{RunId, TenantId};

/// How the writer batches.
#[derive(Debug, Clone, Copy)]
pub struct WriterConfig {
    /// The most records in one commit.
    pub max_batch: usize,
    /// How long a batch of deferred records waits for company before committing.
    pub linger: Duration,
    /// How many times a failed commit is retried (backing off from 50 ms) before its records fail.
    pub retries: u32,
}

impl Default for WriterConfig {
    fn default() -> Self {
        WriterConfig { max_batch: 512, linger: Duration::from_millis(2), retries: 5 }
    }
}

type Reply = SyncSender<std::result::Result<i64, String>>;

struct Pending {
    /// When it was queued (a retried batch commits later; the record keeps its own time).
    ts: i64,
    tenant: String,
    run: Option<String>,
    kind: String,
    body: String,
    reply: Option<Reply>,
}

enum Msg {
    Rec(Pending),
    /// Replies once everything queued before it has committed.
    Flush(SyncSender<std::result::Result<(), String>>),
}

struct Inner {
    tx: Mutex<Option<Sender<Msg>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Closing the channel makes the thread commit what is queued and exit.
        self.tx.lock().map(|mut t| t.take()).ok();
        if let Some(h) = self.thread.lock().ok().and_then(|mut t| t.take()) {
            let _ = h.join();
        }
    }
}

/// A handle to the process's audit writer. Clones share one thread; the last one dropped commits
/// whatever is still queued and stops it.
#[derive(Clone)]
pub struct AuditWriter {
    inner: Arc<Inner>,
    path: PathBuf,
}

/// A queued record's commit, to wait for.
pub struct Ticket(Receiver<std::result::Result<i64, String>>);

impl Ticket {
    /// Blocks until the record's batch has committed; returns its sequence number.
    pub fn wait(self) -> Result<i64> {
        match self.0.recv() {
            Ok(Ok(seq)) => Ok(seq),
            Ok(Err(e)) => Err(StoreError::Writer(e)),
            Err(_) => Err(StoreError::Writer("the audit writer stopped".into())),
        }
    }
}

impl AuditWriter {
    /// Starts the writer for the ledger at `path` (the file must be a ledger, or creatable as one).
    pub fn start(path: &Path, cfg: WriterConfig) -> Result<AuditWriter> {
        let conn = crate::Ledger::open(path)?.conn;
        conn.execute_batch("PRAGMA synchronous = FULL;")?;
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("wicket-audit".into())
            .spawn(move || writer_loop(conn, rx, cfg))
            .map_err(|e| StoreError::Writer(e.to_string()))?;
        Ok(AuditWriter { inner: Arc::new(Inner { tx: Mutex::new(Some(tx)), thread: Mutex::new(Some(thread)) }), path: path.to_path_buf() })
    }

    /// The ledger file this writer appends to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn send(&self, m: Msg) -> Result<()> {
        let g = self.inner.tx.lock().map_err(|_| StoreError::Writer("lock".into()))?;
        g.as_ref()
            .ok_or_else(|| StoreError::Writer("the audit writer stopped".into()))?
            .send(m)
            .map_err(|_| StoreError::Writer("the audit writer stopped".into()))
    }

    fn queue(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: String, reply: Option<Reply>) -> Result<()> {
        self.send(Msg::Rec(Pending { ts: now(), tenant: tenant.0.clone(), run: run.map(|r| r.0.clone()), kind: kind.into(), body, reply }))
    }

    /// Queues a record without waiting: durable within a batch interval, or at the next
    /// [`flush`](Self::flush).
    pub fn submit(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: &serde_json::Value) -> Result<()> {
        self.queue(tenant, run, kind, serde_json::to_string(body)?, None)
    }

    /// Queues a record and returns a ticket for its commit.
    pub fn enqueue(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: &serde_json::Value) -> Result<Ticket> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.queue(tenant, run, kind, serde_json::to_string(body)?, Some(tx))?;
        Ok(Ticket(rx))
    }

    /// Appends a record and waits for its commit. Returns its sequence number.
    pub fn append(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: &serde_json::Value) -> Result<i64> {
        self.enqueue(tenant, run, kind, body)?.wait()
    }

    pub(crate) fn append_str(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: String) -> Result<i64> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.queue(tenant, run, kind, body, Some(tx))?;
        Ticket(rx).wait()
    }

    /// Waits until every record queued before this call has committed.
    pub fn flush(&self) -> Result<()> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.send(Msg::Flush(tx))?;
        match rx.recv() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(StoreError::Writer(e)),
            Err(_) => Err(StoreError::Writer("the audit writer stopped".into())),
        }
    }
}

fn writer_loop(mut conn: Connection, rx: Receiver<Msg>, cfg: WriterConfig) {
    let mut recs: Vec<Pending> = Vec::new();
    let mut flushes: Vec<SyncSender<std::result::Result<(), String>>> = Vec::new();
    let mut open = true;
    while open {
        // Block for the first message of a batch.
        match rx.recv() {
            Ok(m) => take(m, &mut recs, &mut flushes),
            Err(_) => break,
        }
        // Then whatever else is already queued.
        let started = Instant::now();
        loop {
            if recs.len() >= cfg.max_batch {
                break;
            }
            match rx.try_recv() {
                Ok(m) => {
                    take(m, &mut recs, &mut flushes);
                    continue;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    open = false;
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            // Nothing queued: linger for deferred-only batches, commit at once if anyone waits.
            let waited = !flushes.is_empty() || recs.iter().any(|r| r.reply.is_some());
            let left = cfg.linger.saturating_sub(started.elapsed());
            if waited || left.is_zero() {
                break;
            }
            match rx.recv_timeout(left) {
                Ok(m) => take(m, &mut recs, &mut flushes),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    open = false;
                    break;
                }
            }
        }
        let outcome = commit_with_retry(&mut conn, &recs, cfg.retries);
        match &outcome {
            Ok(seqs) => {
                for (r, seq) in recs.drain(..).zip(seqs) {
                    if let Some(tx) = r.reply {
                        let _ = tx.send(Ok(*seq));
                    }
                }
            }
            Err(e) => {
                let lost = recs.iter().filter(|r| r.reply.is_none()).count();
                if lost > 0 {
                    eprintln!("wicket: audit writer: {lost} record(s) not written: {e}");
                }
                for r in recs.drain(..) {
                    if let Some(tx) = r.reply {
                        let _ = tx.send(Err(e.clone()));
                    }
                }
            }
        }
        for f in flushes.drain(..) {
            let _ = f.send(outcome.as_ref().map(|_| ()).map_err(|e| e.clone()));
        }
    }
}

fn take(m: Msg, recs: &mut Vec<Pending>, flushes: &mut Vec<SyncSender<std::result::Result<(), String>>>) {
    match m {
        Msg::Rec(p) => recs.push(p),
        Msg::Flush(f) => flushes.push(f),
    }
}

/// Commits a batch, retrying while another process holds the write lock past the busy timeout.
fn commit_with_retry(conn: &mut Connection, recs: &[Pending], retries: u32) -> std::result::Result<Vec<i64>, String> {
    if recs.is_empty() {
        return Ok(Vec::new());
    }
    let mut delay = Duration::from_millis(50);
    for attempt in 0.. {
        match commit(conn, recs) {
            Ok(s) => return Ok(s),
            Err(_) if attempt < retries => {
                std::thread::sleep(delay);
                delay *= 2;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    unreachable!()
}

/// One batch: read the head and chain every record under one write lock.
fn commit(conn: &mut Connection, recs: &[Pending]) -> rusqlite::Result<Vec<i64>> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let (mut seq, mut prev): (i64, String) = tx
        .query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .unwrap_or_else(|| (0, CHAIN_ZERO.to_string()));
    let mut seqs = Vec::with_capacity(recs.len());
    {
        let mut st =
            tx.prepare_cached("INSERT INTO audit (seq, ts, tenant, run, kind, body, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")?;
        for r in recs {
            seq += 1;
            let f = ChainFields { seq, ts: r.ts, tenant: &r.tenant, run: r.run.as_deref(), kind: &r.kind, body: &r.body };
            let hash = chain_hash_v2(&prev, &f);
            st.execute(params![seq, r.ts, r.tenant, r.run, r.kind, r.body, prev, hash])?;
            seqs.push(seq);
            prev = hash;
        }
    }
    tx.commit()?;
    Ok(seqs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ledger;

    /// A temp dir, removed when the test ends (passed or failed).
    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    impl std::ops::Deref for Tmp {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }
    fn tmp(name: &str) -> Tmp {
        let d = std::env::temp_dir().join(format!("wicket-writer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }

    #[test]
    fn batches_commit_in_order_and_chain() {
        let d = tmp("order");
        let p = d.join("ledger.db");
        let w = AuditWriter::start(&p, WriterConfig { max_batch: 7, linger: Duration::from_millis(5), retries: 5 }).unwrap();
        let t = TenantId::single();
        for i in 0..100 {
            w.submit(&t, None, "op", &serde_json::json!({ "i": i })).unwrap();
        }
        let seq = w.append(&t, None, "decision", &serde_json::json!({ "last": true })).unwrap();
        assert_eq!(seq, 101);
        let l = Ledger::open(&p).unwrap();
        assert_eq!(l.verify_audit().unwrap(), 101);
        let tail = l.audit_tail(200).unwrap();
        for (k, row) in tail.iter().take(100).enumerate() {
            assert_eq!(row.4, format!("{{\"i\":{k}}}"), "records commit in the order they were queued");
        }
        drop(w);
    }

    #[test]
    fn drop_commits_what_is_queued() {
        let d = tmp("drop");
        let p = d.join("ledger.db");
        let w = AuditWriter::start(&p, WriterConfig { max_batch: 512, linger: Duration::from_millis(50), retries: 5 }).unwrap();
        for i in 0..50 {
            w.submit(&TenantId::single(), None, "op", &serde_json::json!({ "i": i })).unwrap();
        }
        drop(w);
        assert_eq!(Ledger::open(&p).unwrap().verify_audit().unwrap(), 50);
    }

    #[test]
    fn concurrent_writers_keep_one_chain() {
        // Several writers (as several processes would have) and plain ledger appends on one file.
        let d = tmp("concurrent");
        let p = d.join("ledger.db");
        Ledger::open(&p).unwrap();
        let mut hs = Vec::new();
        for k in 0..4 {
            let p = p.clone();
            hs.push(std::thread::spawn(move || {
                let w = AuditWriter::start(&p, WriterConfig::default()).unwrap();
                let t = TenantId::single();
                for i in 0..200 {
                    if i % 50 == 49 {
                        w.append(&t, None, "decision", &serde_json::json!({ "w": k, "i": i })).unwrap();
                    } else {
                        w.submit(&t, None, "op", &serde_json::json!({ "w": k, "i": i })).unwrap();
                    }
                }
                w.flush().unwrap();
            }));
        }
        let p2 = p.clone();
        hs.push(std::thread::spawn(move || {
            let l = Ledger::open(&p2).unwrap();
            for i in 0..100 {
                l.audit(&TenantId::single(), None, "plain", &serde_json::json!({ "i": i })).unwrap();
            }
        }));
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(Ledger::open(&p).unwrap().verify_audit().unwrap(), 900);
    }

    /// The child half of `a_crash_loses_nothing_acknowledged`: appends until killed.
    #[test]
    #[ignore = "run by a_crash_loses_nothing_acknowledged in a child process"]
    fn crash_child() {
        let Some(p) = std::env::var_os("WICKET_WRITER_CRASH_LEDGER") else { return };
        let w = AuditWriter::start(Path::new(&p), WriterConfig { max_batch: 16, linger: Duration::from_millis(3), retries: 5 }).unwrap();
        let t = TenantId::single();
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        for i in 0u64.. {
            if i % 10 == 9 {
                let seq = w.append(&t, None, "decision", &serde_json::json!({ "i": i })).unwrap();
                writeln!(out, "ACK {seq}").unwrap();
                out.flush().unwrap();
            } else {
                w.submit(&t, None, "op", &serde_json::json!({ "i": i })).unwrap();
            }
            if i == 3000 {
                // Die mid-stream, without any destructor: queued records are lost, acknowledged ones not.
                std::process::abort();
            }
        }
    }

    #[test]
    fn a_crash_loses_nothing_acknowledged() {
        let d = tmp("crash");
        let p = d.join("ledger.db");
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "writer::tests::crash_child", "--ignored", "--nocapture", "--test-threads=1"])
            .env("WICKET_WRITER_CRASH_LEDGER", &p)
            .output()
            .unwrap();
        assert!(!out.status.success(), "the child aborts");
        let acked: Vec<i64> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.strip_prefix("ACK ").and_then(|s| s.trim().parse().ok()))
            .collect();
        assert!(acked.len() > 100, "the child acknowledged records before it died ({})", acked.len());
        let l = Ledger::open(&p).unwrap();
        let n = l.verify_audit().unwrap();
        let max = *acked.iter().max().unwrap();
        assert!(n >= max, "every acknowledged record survived: {n} records, last acknowledged {max}");
        let tail = l.audit_tail(usize::MAX >> 2).unwrap();
        for seq in &acked {
            assert_eq!(tail[(*seq - 1) as usize].2, "decision");
        }
        drop(l);
    }
}
