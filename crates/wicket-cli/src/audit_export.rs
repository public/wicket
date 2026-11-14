//! Audit export (#91): the ledger's audit records, and signed checkpoints of its chain head, streamed
//! to the sinks an installation configures (`audit-sinks.yaml`, see `docs/reference/audit.md`).
//!
//! - The ledger is the source of truth and the buffer. Each sink has a cursor in the ledger (the
//!   last sequence number it acknowledged); delivery reads past it. A sink that is down holds its
//!   cursor and catches up when it's back: nothing is dropped, and delivery is at least once.
//! - Delivery runs on its own thread with its own ledger connection, never on a request's path.
//!   Each sink is fed by one process at a time (a lease in the ledger), so the processes sharing a
//!   ledger don't send everything several times.
//! - Every `checkpoint_every`, each sink also gets a checkpoint: the sequence number and hash of the
//!   last record it has, and the time, signed by the installation's issuer key. A copy held outside
//!   the control host lets `wicket audit --verify --against <file>` catch a rewritten local chain,
//!   which the chain alone can't (whoever controls the host can recompute every hash).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wicket_store::{AuditRecord, Ledger, EXPORT_LEASE_SECS};

/// Opens the ledger with this process's batched audit writer started (#62).
pub fn open_batched(path: &Path) -> Result<Ledger> {
    let mut l = Ledger::open(path)?;
    l.start_audit_writer(None)?;
    Ok(l)
}

/// Commits the audit records still queued when it is dropped (the end of a run, on any path), then
/// lets the background exporter deliver them and hand its sinks over.
pub struct FlushOnDrop(pub Arc<Mutex<Ledger>>);

impl Drop for FlushOnDrop {
    fn drop(&mut self) {
        if let Ok(l) = self.0.lock() {
            if let Err(e) = l.flush_audit() {
                eprintln!("wicket: committing the last audit records failed: {e}");
            }
        }
        stop_background(Duration::from_secs(10));
    }
}

/// Until it is aborted: on SIGTERM or SIGINT, commits the audit records still queued (and lets the
/// background exporter deliver them), runs `then`, and exits (143 or 130). For a process's phases
/// that have no signal handling of their own, so only a SIGKILL can lose the last unwaited batch.
pub fn flush_on_signal(ledger: Arc<Mutex<Ledger>>, then: impl FnOnce() + Send + 'static) -> tokio::task::JoinHandle<()> {
    use tokio::signal::unix::{signal, SignalKind};
    // Registered now, not when the task first runs, so no signal slips past.
    let term = signal(SignalKind::terminate());
    let int = signal(SignalKind::interrupt());
    tokio::spawn(async move {
        let (Ok(mut term), Ok(mut int)) = (term, int) else { return };
        let code = tokio::select! {
            _ = term.recv() => 143,
            _ = int.recv() => 130,
        };
        let _ = tokio::task::spawn_blocking(move || {
            if let Ok(l) = ledger.lock() {
                if let Err(e) = l.flush_audit() {
                    eprintln!("wicket: committing the last audit records failed: {e}");
                }
            }
            stop_background(Duration::from_secs(5));
            then();
        })
        .await;
        std::process::exit(code);
    })
}

// ---- configuration ----

/// The installation's sinks file: `$WICKET_AUDIT_SINKS`, else `audit-sinks.yaml` in the data dir.
pub fn sinks_path() -> PathBuf {
    match std::env::var_os("WICKET_AUDIT_SINKS") {
        Some(p) => PathBuf::from(p),
        None => crate::data_dir().join("audit-sinks.yaml"),
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinksConfig {
    /// How often each sink gets a signed checkpoint (humantime, e.g. `5m`).
    #[serde(default = "default_every", with = "humantime_serde_compat")]
    pub checkpoint_every: Duration,
    /// The most records per delivery.
    #[serde(default = "default_batch")]
    pub batch: usize,
    pub sinks: Vec<SinkSpec>,
}

fn default_every() -> Duration {
    Duration::from_secs(300)
}
fn default_batch() -> usize {
    500
}

mod humantime_serde_compat {
    use serde::{Deserialize, Deserializer};
    use std::time::Duration;
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        humantime::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SinkSpec {
    /// The sink's name: its cursor in the ledger. Renaming a sink starts it from the beginning.
    pub name: String,
    #[serde(flatten)]
    pub kind: SinkKind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkKind {
    /// JSON lines appended to `path` (`-`: standard output, only from `wicket audit export`).
    Jsonl { path: String },
    /// OTLP/HTTP logs (JSON encoding) to an OpenTelemetry Collector: `endpoint` is its base URL;
    /// records are POSTed to `<endpoint>/v1/logs`.
    Otlp {
        endpoint: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        /// Extra resource attributes (`service.name` is `wicket`).
        #[serde(default)]
        resource: BTreeMap<String, String>,
    },
    /// Objects in the installation's state store (`state-store.yaml`, #154): one JSON-lines object
    /// per delivered batch, `audit/<sink>/<first seq>-<last seq>-<hash>.jsonl` (a checkpoint's is
    /// `<seq>-cp-<time>-<hash>.jsonl`). Never overwritten: what a lost control host exported stays,
    /// and is what `audit --verify --against store:<sink>` compares a restored chain with.
    Store {},
}

/// The state store's key prefix of a `store` sink's objects.
pub fn store_prefix(sink: &str) -> String {
    format!("audit/{sink}/")
}

/// Every object a `store` sink has written, as exported objects (records and checkpoints).
pub fn stored_objects(sink: &str) -> Result<Vec<Value>> {
    use wicket_store::objects::ObjectStore;
    let st = crate::statestore::StateStore::load()?.context("no state-store.yaml: there is no state store")?.open_s3()?;
    let mut out = vec![];
    for k in st.list_prefix(&store_prefix(sink))? {
        let mut text = String::new();
        if let Some(mut r) = st.get(&k)? {
            std::io::Read::read_to_string(&mut r, &mut text)?;
        }
        out.extend(exported_objects(&text));
    }
    Ok(out)
}

impl SinksConfig {
    pub fn parse(text: &str) -> Result<SinksConfig> {
        let c: SinksConfig = serde_yaml::from_str(text)?;
        let mut seen = std::collections::BTreeSet::new();
        for s in &c.sinks {
            if s.name.is_empty() || !seen.insert(s.name.clone()) {
                bail!("audit sink names must be present and distinct ({:?})", s.name);
            }
            if matches!(s.kind, SinkKind::Store {}) && !wicket_store::objects::valid_key(&s.name) {
                bail!("a store sink's name is part of its objects' keys: lowercase letters, digits, '_', '.' and '-' ({:?})", s.name);
            }
        }
        if c.batch == 0 {
            bail!("batch must be at least 1");
        }
        Ok(c)
    }

    /// The installation's sinks, if it has a sinks file.
    pub fn load() -> Result<Option<SinksConfig>> {
        let p = sinks_path();
        match std::fs::read_to_string(&p) {
            Ok(t) => Ok(Some(SinksConfig::parse(&t).with_context(|| format!("{}", p.display()))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("{}", p.display())),
        }
    }
}

// ---- what is sent ----

/// One audit record as exported: a JSON object, one line.
pub fn record_json(r: &AuditRecord) -> Value {
    json!({
        "type": "wicket.audit.record",
        "seq": r.seq, "ts": r.ts, "tenant": r.tenant, "run": r.run, "kind": r.kind,
        "body": serde_json::from_str::<Value>(&r.body).unwrap_or_else(|_| Value::String(r.body.clone())),
        "prev": r.prev, "hash": r.hash,
    })
}

/// A signed checkpoint of the chain at `seq` (whose record's hash is `head`).
pub fn checkpoint_json(issuer: &wicket_identity::Issuer, seq: i64, head: &str, ts: i64) -> Value {
    let payload = json!({ "seq": seq, "head": head, "ts": ts, "iss": issuer.issuer_id() });
    json!({
        "type": "wicket.audit.checkpoint",
        "seq": seq, "head": head, "ts": ts, "iss": issuer.issuer_id(),
        "kid": wicket_identity::key_id(&issuer.verifying_key()),
        "jws": issuer.sign_checkpoint(&payload),
    })
}

/// OTLP/HTTP JSON for a batch of exported objects (records or checkpoints): one log record each,
/// whose body is the object's JSON line.
pub fn otlp_body(items: &[Value], resource: &BTreeMap<String, String>) -> Value {
    let s = |v: &str| json!({ "stringValue": v });
    let observed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0).to_string();
    let mut res = vec![json!({ "key": "service.name", "value": s("wicket") })];
    res.extend(resource.iter().map(|(k, v)| json!({ "key": k, "value": s(v) })));
    let logs: Vec<Value> = items
        .iter()
        .map(|it| {
            let ty = it["type"].as_str().unwrap_or("");
            let mut attrs = vec![
                json!({ "key": "wicket.audit.type", "value": s(ty) }),
                json!({ "key": "wicket.audit.seq", "value": { "intValue": it["seq"].as_i64().unwrap_or(0).to_string() } }),
            ];
            for (k, f) in [
                ("wicket.audit.kind", "kind"),
                ("wicket.audit.hash", "hash"),
                ("wicket.audit.head", "head"),
                ("wicket.run", "run"),
                ("wicket.tenant", "tenant"),
            ] {
                if let Some(v) = it[f].as_str() {
                    attrs.push(json!({ "key": k, "value": s(v) }));
                }
            }
            json!({
                "timeUnixNano": (it["ts"].as_i64().unwrap_or(0) as i128 * 1_000_000_000).to_string(),
                "observedTimeUnixNano": observed,
                "severityNumber": 9,
                "severityText": "INFO",
                "body": s(&it.to_string()),
                "attributes": attrs,
            })
        })
        .collect();
    json!({
        "resourceLogs": [{
            "resource": { "attributes": res },
            "scopeLogs": [{ "scope": { "name": "wicket.audit" }, "logRecords": logs }],
        }]
    })
}

// ---- sinks ----

struct Sink {
    spec: SinkSpec,
    /// Not before this instant (backoff after a failure).
    next_try: Instant,
    backoff: Duration,
    held: bool,
    renewed: Option<Instant>,
}

/// Feeds the configured sinks from the ledger.
pub struct Exporter {
    ledger: Ledger,
    cfg: SinksConfig,
    sinks: Vec<Sink>,
    holder: String,
    issuer: Option<wicket_identity::Issuer>,
    http: reqwest::Client,
    rt: tokio::runtime::Runtime,
    /// The state store, opened on first use by a `store` sink.
    store: Option<crate::s3::S3Store>,
    /// Whether this process may write to standard output (only `wicket audit export`).
    pub stdout: bool,
}

/// What one pass delivered.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pass {
    pub records: usize,
    pub checkpoints: usize,
    pub failures: Vec<(String, String)>,
    /// Sinks another process is feeding (this pass left them alone).
    pub busy: Vec<String>,
}

impl Exporter {
    /// `issuer`: the key checkpoints are signed with (none: records only, and a warning).
    pub fn new(ledger_path: &Path, cfg: SinksConfig, issuer: Option<wicket_identity::Issuer>) -> Result<Exporter> {
        let mut nonce = [0u8; 6];
        getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("random: {e}"))?;
        let sinks = cfg
            .sinks
            .iter()
            .map(|s| Sink { spec: s.clone(), next_try: Instant::now(), backoff: Duration::from_secs(1), held: false, renewed: None })
            .collect();
        Ok(Exporter {
            ledger: Ledger::open(ledger_path)?,
            cfg,
            sinks,
            holder: format!("{}-{}", std::process::id(), hex::encode(nonce)),
            issuer,
            http: reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?,
            rt: tokio::runtime::Builder::new_current_thread().enable_all().build()?,
            store: None,
            stdout: false,
        })
    }

    /// One pass over every sink: deliver what each is missing, and a checkpoint if one is due
    /// (`force_checkpoint`: due now).
    pub fn pass(&mut self, force_checkpoint: bool) -> Pass {
        let mut out = Pass::default();
        let now = Instant::now();
        let at = wicket_store::now();
        for i in 0..self.sinks.len() {
            let name = self.sinks[i].spec.name.clone();
            if matches!(&self.sinks[i].spec.kind, SinkKind::Jsonl { path } if path == "-") && !self.stdout {
                continue;
            }
            // Renew the lease about three times per lease period; take it when it lapses.
            let s = &self.sinks[i];
            if !s.held || s.renewed.is_none_or(|r| now.duration_since(r) >= Duration::from_secs((EXPORT_LEASE_SECS / 3) as u64)) {
                let held = self.ledger.lease_export(&name, &self.holder, at).unwrap_or(false);
                let s = &mut self.sinks[i];
                s.held = held;
                s.renewed = held.then_some(now);
            }
            if !self.sinks[i].held {
                out.busy.push(name);
                continue;
            }
            if now < self.sinks[i].next_try {
                continue;
            }
            match self.feed(i, force_checkpoint) {
                Ok((r, c)) => {
                    out.records += r;
                    out.checkpoints += c;
                    let s = &mut self.sinks[i];
                    s.backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    let _ = self.ledger.export_failed(&name, &msg);
                    let s = &mut self.sinks[i];
                    s.next_try = now + s.backoff;
                    s.backoff = (s.backoff * 2).min(Duration::from_secs(60));
                    out.failures.push((name, msg));
                }
            }
        }
        out
    }

    /// Clears backoff, so the next pass retries every sink at once.
    #[cfg(test)]
    pub fn retry_now(&mut self) {
        for s in &mut self.sinks {
            s.next_try = Instant::now();
        }
    }

    fn feed(&mut self, i: usize, force_checkpoint: bool) -> Result<(usize, usize)> {
        let name = self.sinks[i].spec.name.clone();
        let mut cur = self.ledger.export_cursor(&name)?;
        let mut sent = 0;
        loop {
            let recs = self.ledger.audit_records_after(cur.seq, self.cfg.batch)?;
            let Some(last) = recs.last().map(|r| r.seq) else { break };
            let items: Vec<Value> = recs.iter().map(record_json).collect();
            self.deliver(i, &items)?;
            // One cursor write per delivered batch.
            self.ledger.advance_export(&name, last)?;
            cur.seq = last;
            sent += recs.len();
            if recs.len() < self.cfg.batch {
                break;
            }
        }
        let at = wicket_store::now();
        let due = force_checkpoint || at - cur.checkpoint_at >= self.cfg.checkpoint_every.as_secs() as i64;
        let mut cps = 0;
        if due && cur.seq > 0 && self.issuer.is_some() {
            let head = self.ledger.audit_hash_at(cur.seq)?.context("the sink's cursor is past the local chain")?;
            let cp = checkpoint_json(self.issuer.as_ref().expect("checked"), cur.seq, &head, at);
            self.deliver(i, &[cp])?;
            self.ledger.export_checkpointed(&name, at)?;
            cps = 1;
        }
        Ok((sent, cps))
    }

    fn deliver(&mut self, i: usize, items: &[Value]) -> Result<()> {
        match &self.sinks[i].spec.kind {
            SinkKind::Store {} => {
                use wicket_store::objects::ObjectStore;
                if self.store.is_none() {
                    let s = crate::statestore::StateStore::load()?.context("an audit sink of type store needs state-store.yaml")?;
                    self.store = Some(s.open_s3()?);
                }
                let (Some(first), Some(last)) = (items.first(), items.last()) else { return Ok(()) };
                let h = |v: &Value| {
                    v["hash"].as_str().or(v["head"].as_str()).unwrap_or("").trim_start_matches("v2:").chars().take(16).collect::<String>()
                };
                let name = match first["type"].as_str() {
                    Some("wicket.audit.checkpoint") => {
                        format!("{:020}-cp-{}-{}", first["seq"].as_i64().unwrap_or(0), first["ts"].as_i64().unwrap_or(0), h(first))
                    }
                    _ => format!("{:020}-{:020}-{}", first["seq"].as_i64().unwrap_or(0), last["seq"].as_i64().unwrap_or(0), h(last)),
                };
                let mut buf = String::new();
                for it in items {
                    buf.push_str(&it.to_string());
                    buf.push('\n');
                }
                let key = format!("{}{name}.jsonl", store_prefix(&self.sinks[i].spec.name));
                // Already there (a batch delivered before its cursor was saved): the same records.
                self.store.as_ref().expect("opened").put_if_absent(&key, &mut buf.as_bytes())?;
                Ok(())
            }
            SinkKind::Jsonl { path } => {
                let mut buf = String::new();
                for it in items {
                    buf.push_str(&it.to_string());
                    buf.push('\n');
                }
                if path == "-" {
                    let mut o = std::io::stdout().lock();
                    o.write_all(buf.as_bytes())?;
                    o.flush()?;
                } else {
                    let p = Path::new(path);
                    if let Some(d) = p.parent() {
                        std::fs::create_dir_all(d)?;
                    }
                    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p).with_context(|| path.clone())?;
                    f.write_all(buf.as_bytes())?;
                    f.sync_data()?;
                }
                Ok(())
            }
            SinkKind::Otlp { endpoint, headers, resource } => {
                let url = format!("{}/v1/logs", endpoint.trim_end_matches('/'));
                let mut req = self.http.post(&url).json(&otlp_body(items, resource));
                for (k, v) in headers {
                    req = req.header(k, v);
                }
                self.rt.block_on(async {
                    let resp = req.send().await.with_context(|| url.clone())?;
                    let status = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    if !status.is_success() {
                        bail!("{url}: {status}: {}", text.chars().take(200).collect::<String>());
                    }
                    // A 2xx can still reject some records (OTLP partial success): hold the cursor.
                    let rejected = serde_json::from_str::<Value>(&text)
                        .ok()
                        .and_then(|v| {
                            v["partialSuccess"]["rejectedLogRecords"]
                                .as_str()
                                .map(String::from)
                                .or_else(|| v["partialSuccess"]["rejectedLogRecords"].as_i64().map(|n| n.to_string()))
                        })
                        .and_then(|n| n.parse::<i64>().ok())
                        .unwrap_or(0);
                    if rejected > 0 {
                        bail!("{url}: the collector rejected {rejected} record(s): {}", text.chars().take(200).collect::<String>());
                    }
                    Ok(())
                })
            }
        }
    }

    /// Gives up this process's leases (so another process takes over at once).
    pub fn release(&mut self) {
        for s in &mut self.sinks {
            if s.held {
                let _ = self.ledger.release_export(&s.spec.name, &self.holder);
                s.held = false;
            }
        }
    }
}

impl Drop for Exporter {
    fn drop(&mut self) {
        self.release();
    }
}

/// Starts this process's background exporter if the installation has sinks configured: a thread
/// that feeds them every second until the process exits. Once per process.
pub fn spawn_background() {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let cfg = match SinksConfig::load() {
        Ok(Some(c)) if !c.sinks.is_empty() => c,
        Ok(_) => return,
        Err(e) => {
            eprintln!("wicket: audit export is off: {e:#}");
            return;
        }
    };
    let issuer = crate::issuer().map_err(|e| eprintln!("wicket: audit checkpoints are off (no issuer key: {e})")).ok();
    let path = crate::ledger_path();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<std::sync::mpsc::SyncSender<()>>();
    let _ = std::thread::Builder::new().name("wicket-audit-export".into()).spawn(move || {
        let mut x = match Exporter::new(&path, cfg, issuer) {
            Ok(x) => x,
            Err(e) => return eprintln!("wicket: audit export is off: {e:#}"),
        };
        loop {
            x.pass(false);
            match stop_rx.recv_timeout(Duration::from_secs(1)) {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Ok(done) => {
                    // A last pass for what the process wrote at the end, then hand the sinks over.
                    x.pass(false);
                    x.release();
                    let _ = done.send(());
                    return;
                }
                Err(_) => return,
            }
        }
    });
    if let Ok(mut s) = BACKGROUND.lock() {
        *s = Some(stop_tx);
    }
}

static BACKGROUND: Mutex<Option<std::sync::mpsc::Sender<std::sync::mpsc::SyncSender<()>>>> = Mutex::new(None);

/// Stops the background exporter, if this process runs one: one last pass, then its sinks' leases
/// are given up so the next process takes over at once. Waits at most `wait`.
pub fn stop_background(wait: Duration) {
    let Some(tx) = BACKGROUND.lock().ok().and_then(|mut s| s.take()) else { return };
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    if tx.send(done_tx).is_ok() {
        let _ = done_rx.recv_timeout(wait);
    }
}

// ---- verification against exported copies ----

/// What `--against` found.
#[derive(Debug, Default)]
pub struct Against {
    pub checkpoints: usize,
    pub records: usize,
    /// Exported before a restore that went back to an earlier point (`state.restored` with
    /// `rolled_back_after`): history the restore declared discarded, not compared (#154).
    pub superseded: usize,
    pub problems: Vec<String>,
}

/// The exported objects in a file: JSON lines of records and checkpoints as wicket writes them, or
/// OTLP/HTTP JSON lines (as a Collector's file exporter writes them) whose log bodies are those.
pub fn exported_objects(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        if let Some(rls) = v["resourceLogs"].as_array() {
            for rl in rls {
                for sl in rl["scopeLogs"].as_array().into_iter().flatten() {
                    for lr in sl["logRecords"].as_array().into_iter().flatten() {
                        if let Some(b) = lr["body"]["stringValue"].as_str().and_then(|b| serde_json::from_str::<Value>(b).ok()) {
                            out.push(b);
                        }
                    }
                }
            }
        } else {
            out.push(v);
        }
    }
    out
}

/// Checks the local ledger against exported records and checkpoints: every signed checkpoint's
/// head and every exported record's hash must be the local chain's at that sequence number, and the
/// local chain must reach the newest checkpoint. A rewritten (even consistently re-chained) or
/// truncated local chain fails.
pub fn verify_against(l: &Ledger, objects: &[Value], issuer: &wicket_identity::VerifyingKey) -> Result<Against> {
    let mut a = Against::default();
    let head = l.audit_head()?.map(|h| h.0).unwrap_or(0);
    let mut newest = 0;
    // Restores that went back to an earlier point: (the last record kept, when the restore was).
    let rollbacks: Vec<(i64, i64)> = l
        .audit_of_kind("state.restored")?
        .iter()
        .filter_map(|r| Some((serde_json::from_str::<Value>(&r.body).ok()?["rolled_back_after"].as_i64()?, r.ts)))
        .collect();
    // An exported copy that doesn't match is discarded history if a restore went back before it and
    // it was made before that restore (the same second counts: records carry whole seconds).
    let discarded = |seq: i64, ts: i64| rollbacks.iter().any(|&(after, at)| seq > after && ts <= at);
    for o in objects {
        match o["type"].as_str() {
            Some("wicket.audit.checkpoint") => {
                let Some(jws) = o["jws"].as_str() else {
                    a.problems.push("a checkpoint without a signature".into());
                    continue;
                };
                let p = match wicket_identity::verify_checkpoint(jws, issuer) {
                    Ok(p) => p,
                    Err(e) => {
                        a.problems.push(format!("a checkpoint (seq {}) does not verify: {e}", o["seq"]));
                        continue;
                    }
                };
                let (Some(seq), Some(want)) = (p["seq"].as_i64(), p["head"].as_str()) else {
                    a.problems.push("a signed checkpoint without seq and head".into());
                    continue;
                };
                let local = l.audit_hash_at(seq)?;
                if local.as_deref() != Some(want) && discarded(seq, p["ts"].as_i64().unwrap_or(i64::MAX)) {
                    a.superseded += 1;
                    continue;
                }
                newest = newest.max(seq);
                match local {
                    Some(h) if h == want => a.checkpoints += 1,
                    Some(h) => a.problems.push(format!("checkpoint at seq {seq} (signed at {}): exported head {want}, local {h}", p["ts"])),
                    None => a.problems.push(format!("checkpoint at seq {seq}: the local chain ends at {head}")),
                }
            }
            Some("wicket.audit.record") => {
                let Some(seq) = o["seq"].as_i64() else { continue };
                let gone = discarded(seq, o["ts"].as_i64().unwrap_or(i64::MAX));
                // Every exported field, not only the hash: a v1 hash covers neither ts, tenant nor
                // run, so a record moved to another run must be caught here (#120).
                match l.audit_record_at(seq)? {
                    Some(r) => {
                        let local = record_json(&r);
                        let differ: Vec<&str> = ["ts", "tenant", "run", "kind", "body", "prev", "hash"]
                            .into_iter()
                            .filter(|k| o.get(*k).unwrap_or(&Value::Null) != &local[*k])
                            .collect();
                        if differ.is_empty() {
                            a.records += 1;
                        } else if gone {
                            a.superseded += 1;
                        } else {
                            a.problems.push(format!("record {seq}: the exported copy's {} differs from the local one", differ.join(", ")));
                        }
                    }
                    None if gone => a.superseded += 1,
                    None => a.problems.push(format!("record {seq}: exported, but missing locally")),
                }
            }
            _ => {}
        }
    }
    if a.checkpoints + a.records == 0 && a.problems.is_empty() {
        a.problems.push("the exported copies hold no wicket audit records or checkpoints: nothing was compared".into());
    }
    if newest > head {
        a.problems.push(format!("the local chain ends at seq {head}, before the newest checkpoint ({newest})"));
    }
    a.problems.dedup();
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::{RunId, TenantId};

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(name: &str) -> TmpDir {
            let mut n = [0u8; 4];
            getrandom::getrandom(&mut n).unwrap();
            let d = std::env::temp_dir().join(format!("wicket-export-{name}-{}-{}", std::process::id(), hex::encode(n)));
            std::fs::create_dir_all(&d).unwrap();
            TmpDir(d)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_records(l: &Ledger, from: usize, n: usize) {
        for i in from..from + n {
            l.audit(&TenantId::single(), Some(&RunId("run_a".into())), "op", &json!({ "i": i })).unwrap();
        }
    }

    fn jsonl_cfg(path: &Path) -> SinksConfig {
        SinksConfig::parse(&format!(
            "checkpoint_every: 1h\nbatch: 7\nsinks:\n  - name: file\n    type: jsonl\n    path: {}\n",
            path.display()
        ))
        .unwrap()
    }

    #[test]
    fn the_sinks_file_parses_and_rejects_duplicates() {
        let c = SinksConfig::parse(
            "checkpoint_every: 2m\nsinks:\n  - {name: a, type: jsonl, path: '-'}\n  - {name: b, type: otlp, endpoint: 'http://127.0.0.1:4318', headers: {x-tenant: t}}\n",
        )
        .unwrap();
        assert_eq!(c.checkpoint_every, Duration::from_secs(120));
        assert_eq!(c.batch, 500);
        assert!(matches!(&c.sinks[1].kind, SinkKind::Otlp { headers, .. } if headers["x-tenant"] == "t"));
        assert!(SinksConfig::parse("sinks:\n  - {name: a, type: jsonl, path: x}\n  - {name: a, type: jsonl, path: y}\n").is_err());
        assert!(SinksConfig::parse("sinks:\n  - {name: a, type: kafka}\n").is_err());
    }

    /// Rewrites record `seq`'s body and re-chains every record after it: a consistent forgery that
    /// the chain alone can't catch.
    fn rewrite_and_rechain(path: &Path, seq: i64) {
        let c = rusqlite_conn(path);
        c.execute("UPDATE audit SET body = '{\"i\":\"forged\"}' WHERE seq = ?1", [seq]).unwrap();
        type Row = (i64, i64, String, Option<String>, String, String);
        let rows: Vec<Row> = {
            let mut st = c.prepare("SELECT seq, ts, tenant, run, kind, body FROM audit ORDER BY seq").unwrap();
            let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))).unwrap();
            r.map(|x| x.unwrap()).collect()
        };
        let mut prev = wicket_store::CHAIN_ZERO.to_string();
        for (s, ts, tenant, run, kind, body) in rows {
            let f = wicket_store::ChainFields { seq: s, ts, tenant: &tenant, run: run.as_deref(), kind: &kind, body: &body };
            let h = wicket_store::chain_hash_v2(&prev, &f);
            c.execute("UPDATE audit SET prev = ?2, hash = ?3 WHERE seq = ?1", rusqlite::params![s, prev, h]).unwrap();
            prev = h;
        }
    }

    fn rusqlite_conn(path: &Path) -> rusqlite::Connection {
        rusqlite::Connection::open(path).unwrap()
    }

    #[test]
    fn exported_copies_a_restore_discarded_are_not_mismatches_and_others_still_are() {
        let d = TmpDir::new("rollback");
        let (lp, out) = (d.0.join("ledger.db"), d.0.join("out/audit.jsonl"));
        let issuer = wicket_identity::Issuer::generate("test.local");
        let key = issuer.verifying_key();
        let l = open_batched(&lp).unwrap();
        write_records(&l, 0, 10);
        let mut x = Exporter::new(&lp, jsonl_cfg(&out), Some(issuer)).unwrap();
        x.pass(true);
        drop(x);
        let objs = exported_objects(&std::fs::read_to_string(&out).unwrap());
        // The restored ledger has the first 6 records, then goes on differently.
        let all = l.audit_records_after(0, 100).unwrap();
        let r = Ledger::open_in_memory().unwrap();
        assert_eq!(r.import_exported_audit(&all[..6]).unwrap(), 6);
        write_records(&r, 100, 3);
        let mismatched = verify_against(&r, &objs, &key).unwrap();
        assert!(!mismatched.problems.is_empty(), "without a restore record the divergence is a mismatch");
        // Declared by the restore: the copies of 7.. and the checkpoint at 10 are discarded history.
        let r = Ledger::open_in_memory().unwrap();
        r.import_exported_audit(&all[..6]).unwrap();
        r.audit(&TenantId::single(), None, "state.restored", &json!({ "rolled_back_after": 6 })).unwrap();
        write_records(&r, 100, 3);
        let a = verify_against(&r, &objs, &key).unwrap();
        assert!(a.problems.is_empty(), "{:?}", a.problems);
        assert_eq!((a.records, a.superseded), (6, 5), "{a:?}");
        // A copy of a record the restore kept must still match.
        let mut forged = objs.clone();
        let i = forged.iter().position(|o| o["seq"] == 3 && o["type"] == "wicket.audit.record").unwrap();
        forged[i]["kind"] = json!("forged");
        assert!(verify_against(&r, &forged, &key).unwrap().problems.iter().any(|p| p.starts_with("record 3:")));
    }

    #[test]
    fn a_rewritten_or_truncated_chain_fails_against_exported_checkpoints() {
        let d = TmpDir::new("against");
        let lp = d.0.join("ledger.db");
        let out = d.0.join("out/audit.jsonl");
        let issuer = wicket_identity::Issuer::generate("test.local");
        let key = issuer.verifying_key();
        let l = open_batched(&lp).unwrap();
        write_records(&l, 0, 20);
        let mut x = Exporter::new(&lp, jsonl_cfg(&out), Some(issuer)).unwrap();
        let p = x.pass(true);
        assert_eq!((p.records, p.checkpoints), (20, 1), "{p:?}");
        write_records(&l, 20, 5);
        let p = x.pass(true);
        assert_eq!((p.records, p.checkpoints), (5, 1));
        let objs = exported_objects(&std::fs::read_to_string(&out).unwrap());
        assert_eq!(objs.len(), 27);
        let a = verify_against(&l, &objs, &key).unwrap();
        assert!(a.problems.is_empty(), "{:?}", a.problems);
        assert_eq!((a.checkpoints, a.records), (2, 25));

        // Only checkpoints exported (e.g. to a write-once bucket): still caught.
        let cps: Vec<Value> = objs.iter().filter(|o| o["type"] == "wicket.audit.checkpoint").cloned().collect();
        rewrite_and_rechain(&lp, 3);
        assert_eq!(l.verify_audit().unwrap(), 25, "the forgery is internally consistent");
        let a = verify_against(&l, &cps, &key).unwrap();
        assert_eq!(a.problems.len(), 2, "both checkpoints disagree: {:?}", a.problems);
        let a = verify_against(&l, &objs, &key).unwrap();
        assert!(a.problems.iter().any(|p| p.starts_with("record 3:")), "{:?}", a.problems);

        // An empty or unrelated file proves nothing either: it fails rather than passing vacuously.
        assert!(!verify_against(&l, &exported_objects("{\"hello\":1}\nnot json\n"), &key).unwrap().problems.is_empty());

        // A checkpoint signed by another key proves nothing.
        let other = wicket_identity::Issuer::generate("test.local").verifying_key();
        let a = verify_against(&l, &cps, &other).unwrap();
        assert_eq!(a.checkpoints, 0);
        assert!(a.problems.iter().all(|p| p.contains("does not verify")));
        drop(x);
        drop(l);

        // Truncation: the local chain no longer reaches the newest checkpoint.
        let d2 = TmpDir::new("truncate");
        let lp2 = d2.0.join("ledger.db");
        let out2 = d2.0.join("audit.jsonl");
        let issuer = wicket_identity::Issuer::generate("test.local");
        let key = issuer.verifying_key();
        let l = Ledger::open(&lp2).unwrap();
        write_records(&l, 0, 10);
        let mut x = Exporter::new(&lp2, jsonl_cfg(&out2), Some(issuer)).unwrap();
        x.pass(true);
        rusqlite_conn(&lp2).execute("DELETE FROM audit WHERE seq > 6", []).unwrap();
        assert_eq!(l.verify_audit().unwrap(), 6);
        let cps: Vec<Value> = exported_objects(&std::fs::read_to_string(&out2).unwrap())
            .into_iter()
            .filter(|o| o["type"] == "wicket.audit.checkpoint")
            .collect();
        let a = verify_against(&l, &cps, &key).unwrap();
        assert!(a.problems.iter().any(|p| p.contains("ends at seq 6")), "{:?}", a.problems);
    }

    #[test]
    fn one_process_feeds_a_sink_at_a_time() {
        let d = TmpDir::new("lease");
        let lp = d.0.join("ledger.db");
        let out = d.0.join("audit.jsonl");
        let l = Ledger::open(&lp).unwrap();
        write_records(&l, 0, 10);
        let mut a = Exporter::new(&lp, jsonl_cfg(&out), None).unwrap();
        let mut b = Exporter::new(&lp, jsonl_cfg(&out), None).unwrap();
        assert_eq!(a.pass(false).records, 10);
        write_records(&l, 10, 3);
        assert_eq!(b.pass(false).records, 0, "a holds the lease");
        a.release();
        assert_eq!(b.pass(false).records, 3, "b takes over where a left off");
        assert_eq!(exported_objects(&std::fs::read_to_string(&out).unwrap()).len(), 13);
    }

    /// The child half of `sigterm_commits_what_is_queued`: queues records, then waits for SIGTERM.
    #[test]
    #[ignore = "run by sigterm_commits_what_is_queued in a child process"]
    fn sigterm_child() {
        let Some(p) = std::env::var_os("WICKET_SIGTERM_LEDGER") else { return };
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        rt.block_on(async {
            let mut l = Ledger::open(Path::new(&p)).unwrap();
            // A linger far past the test: only the signal path can commit these.
            let w = wicket_store::AuditWriter::start(
                Path::new(&p),
                wicket_store::WriterConfig { linger: Duration::from_secs(600), ..Default::default() },
            )
            .unwrap();
            l.start_audit_writer(Some(w)).unwrap();
            for i in 0..25 {
                l.audit_deferred(&TenantId::single(), None, "op", &json!({ "i": i })).unwrap();
            }
            let _g = flush_on_signal(Arc::new(Mutex::new(l)), || {});
            println!("READY");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
    }

    #[test]
    fn sigterm_commits_what_is_queued() {
        use std::io::BufRead;
        let d = TmpDir::new("sigterm");
        let lp = d.0.join("ledger.db");
        Ledger::open(&lp).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "audit_export::tests::sigterm_child", "--ignored", "--nocapture", "--test-threads=1"])
            .env("WICKET_SIGTERM_LEDGER", &lp)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while out.read_line(&mut line).unwrap() > 0 && !line.contains("READY") {}
        assert_eq!(Ledger::open(&lp).unwrap().audit_head().unwrap(), None, "still queued");
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        let st = child.wait().unwrap();
        assert_eq!(st.code(), Some(143));
        assert_eq!(Ledger::open(&lp).unwrap().verify_audit().unwrap(), 25, "SIGTERM committed every queued record");
    }

    // ---- a local OTLP/HTTP receiver ----

    #[derive(Default)]
    struct Stub {
        up: AtomicBool,
        bodies: Mutex<Vec<Value>>,
    }

    fn start_stub(rt: &tokio::runtime::Runtime) -> (Arc<Stub>, String) {
        use http_body_util::BodyExt;
        let stub = Arc::new(Stub::default());
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let addr = listener.local_addr().unwrap();
        let s2 = stub.clone();
        rt.spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let s3 = s2.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let s4 = s3.clone();
                        async move {
                            let path = req.uri().path().to_string();
                            let ct = req.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                            let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                            let (status, text) = if !s4.up.load(Ordering::SeqCst) {
                                (503, "{}".to_string())
                            } else if path != "/v1/logs" || !ct.starts_with("application/json") {
                                (404, "{}".to_string())
                            } else {
                                s4.bodies.lock().unwrap().push(serde_json::from_slice(&body).unwrap());
                                (200, "{}".to_string())
                            };
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(status)
                                    .header("content-type", "application/json")
                                    .body(http_body_util::Full::new(bytes::Bytes::from(text)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).await;
                });
            }
        });
        (stub, format!("http://{addr}"))
    }

    #[test]
    fn an_otlp_receiver_gets_every_record_after_being_down() {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let (stub, endpoint) = start_stub(&rt);
        let d = TmpDir::new("otlp");
        let lp = d.0.join("ledger.db");
        let issuer = wicket_identity::Issuer::generate("test.local");
        let key = issuer.verifying_key();
        let cfg = SinksConfig::parse(&format!(
            "checkpoint_every: 1h\nbatch: 16\nsinks:\n  - {{name: otel, type: otlp, endpoint: '{endpoint}'}}\n"
        ))
        .unwrap();
        let l = open_batched(&lp).unwrap();
        write_records(&l, 0, 40);

        // Down: nothing advances, the failure is recorded, and more records arrive meanwhile.
        let mut x = Exporter::new(&lp, cfg, Some(issuer)).unwrap();
        let p = x.pass(true);
        assert_eq!(p.records, 0);
        assert_eq!(p.failures.len(), 1, "{p:?}");
        assert!(l.export_cursor("otel").unwrap().error.unwrap().contains("503"));
        write_records(&l, 40, 60);
        x.retry_now();
        assert_eq!(x.pass(false).records, 0);

        // Back: everything arrives, then a checkpoint.
        stub.up.store(true, Ordering::SeqCst);
        x.retry_now();
        let p = x.pass(true);
        assert_eq!((p.records, p.checkpoints), (100, 1), "{p:?}");
        assert_eq!(l.export_cursor("otel").unwrap().seq, 100);

        let bodies = stub.bodies.lock().unwrap().clone();
        let lines: Vec<String> = bodies.iter().map(|b| b.to_string()).collect();
        let objs = exported_objects(&lines.join("\n"));
        let mut seqs: Vec<i64> = objs.iter().filter(|o| o["type"] == "wicket.audit.record").map(|o| o["seq"].as_i64().unwrap()).collect();
        seqs.sort();
        seqs.dedup();
        assert_eq!(seqs, (1..=100).collect::<Vec<_>>(), "every record, by sequence number");
        let first = &bodies[0]["resourceLogs"][0];
        assert_eq!(first["resource"]["attributes"][0]["value"]["stringValue"], "wicket");
        let lr = &first["scopeLogs"][0]["logRecords"][0];
        assert_eq!(lr["attributes"][1]["key"], "wicket.audit.seq");
        assert!(lr["attributes"][1]["value"]["intValue"].is_string(), "OTLP JSON carries int64 as a string");
        assert!(lr["timeUnixNano"].is_string());
        let a = verify_against(&l, &objs, &key).unwrap();
        assert!(a.problems.is_empty(), "{:?}", a.problems);
        assert_eq!((a.records, a.checkpoints), (100, 1));
        drop(x);
        drop(l);
    }

    #[test]
    fn a_partial_success_holds_the_cursor() {
        // The collector answers 200 but rejects records: nothing is skipped.
        use http_body_util::BodyExt;
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let addr = listener.local_addr().unwrap();
        rt.spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                        let _ = req.into_body().collect().await;
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from(
                            r#"{"partialSuccess":{"rejectedLogRecords":"2","errorMessage":"bad"}}"#,
                        ))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).await;
                });
            }
        });
        let d = TmpDir::new("partial");
        let lp = d.0.join("ledger.db");
        let l = Ledger::open(&lp).unwrap();
        write_records(&l, 0, 5);
        let cfg = SinksConfig::parse(&format!("sinks:\n  - {{name: otel, type: otlp, endpoint: 'http://{addr}'}}\n")).unwrap();
        let mut x = Exporter::new(&lp, cfg, None).unwrap();
        let p = x.pass(false);
        assert_eq!(p.records, 0);
        assert!(p.failures[0].1.contains("rejected 2"), "{p:?}");
        assert_eq!(l.export_cursor("otel").unwrap().seq, 0);
    }
}
