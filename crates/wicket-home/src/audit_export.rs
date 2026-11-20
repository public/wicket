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
    /// How often each sink gets a signed checkpoint (a duration, e.g. `5m`).
    #[serde(default = "default_every", with = "duration_serde")]
    pub checkpoint_every: Duration,
    /// The most records per delivery.
    #[serde(default = "default_batch")]
    pub batch: usize,
    /// How big the audit table on this host may grow, in GB, before its oldest records (ones
    /// every sink has, behind a checkpoint one acknowledged) are pruned (#582). Only with a sink
    /// and the state store configured; otherwise nothing is ever pruned.
    #[serde(default = "default_host_gb")]
    pub host_gb: f64,
    pub sinks: Vec<SinkSpec>,
}

/// The audit table's default limit on the host, in GB (see the docs for why).
pub const DEFAULT_HOST_GB: f64 = 2.0;

fn default_host_gb() -> f64 {
    DEFAULT_HOST_GB
}

fn forever() -> String {
    "forever".into()
}

fn sink_retention<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if s != "forever" {
        return Err(serde::de::Error::custom(format!(
            "retention {s:?}: a sink keeps everything (`forever`); expire old records in the sink itself (a bucket lifecycle rule, a Collector's own retention)"
        )));
    }
    Ok(s)
}

fn default_every() -> Duration {
    Duration::from_secs(300)
}
fn default_batch() -> usize {
    500
}

mod duration_serde {
    use serde::{Deserialize, Deserializer};
    use std::time::Duration;
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        wicket_core::time::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SinkSpec {
    /// The sink's name: its cursor in the ledger. Renaming a sink starts it from the beginning.
    pub name: String,
    /// How long the sink keeps what it was sent: `forever`, the default and (for now) the only
    /// value. A separate setting from the host's `host_gb` (#582): pruning the host never prunes
    /// a sink.
    #[serde(default = "forever", deserialize_with = "sink_retention")]
    pub retention: String,
    /// Whether this sink keeps records durably off the host, so retention may prune the host's
    /// copy once it has them (#582). A `store` sink always does; a file or a Collector does only
    /// if you say so (a Collector's 2xx, or a local file, isn't by itself a copy that survives the
    /// host). Standard output never does.
    #[serde(default)]
    pub durable: bool,
    #[serde(flatten)]
    pub kind: SinkKind,
}

impl SinkSpec {
    /// Whether retention may count on this sink (see [`SinkSpec::durable`]).
    pub fn is_durable(&self) -> bool {
        match &self.kind {
            SinkKind::Store {} => true,
            SinkKind::Jsonl { path } if path == "-" => false,
            _ => self.durable,
        }
    }

    /// What the sink's cursor is for: its path, endpoint, or the state store's bucket. A sink
    /// whose target changes starts again from the first record (`Ledger::sink_target`). Err when
    /// it can't be told (the state store's file doesn't read): then nothing is reset, and nothing
    /// is pruned on that sink's word.
    pub fn target(&self) -> Result<String> {
        match &self.kind {
            SinkKind::Store {} => self.target_in(crate::statestore::StateStore::load()?.as_ref()),
            _ => self.target_in(None),
        }
    }

    /// [`SinkSpec::target`], a `store` sink's from `store` (the state store's configuration its
    /// exporter delivers through): the endpoint, bucket and prefix its objects go under. An OTLP
    /// sink's includes a hash of its headers, which may choose where a Collector puts what it gets.
    pub fn target_in(&self, store: Option<&crate::statestore::StateStore>) -> Result<String> {
        Ok(match &self.kind {
            SinkKind::Jsonl { path } => format!("jsonl:{path}"),
            SinkKind::Otlp { endpoint, headers, .. } if headers.is_empty() => format!("otlp:{endpoint}"),
            SinkKind::Otlp { endpoint, headers, .. } => {
                use sha2::Digest;
                let h = sha2::Sha256::digest(serde_json::to_string(headers)?.as_bytes());
                format!("otlp:{endpoint}#headers:{}", &hex::encode(h)[..16])
            }
            SinkKind::Store {} => match store {
                Some(crate::statestore::StateStore { s3: Some(c), .. }) => format!("store:{}/{}/{}", c.endpoint, c.bucket, c.prefix),
                _ => bail!("sink {}: state-store.yaml names no store", self.name),
            },
        })
    }
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
        #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
        headers: BTreeMap<String, String>,
        /// Extra resource attributes (`service.name` is `wicket`).
        #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
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
        let c: SinksConfig = wicket_core::yaml::from_str(text)?;
        let mut seen = std::collections::BTreeSet::new();
        for s in &c.sinks {
            if s.name.is_empty() || !seen.insert(s.name.clone()) {
                bail!("audit sink names must be present and distinct ({:?})", s.name);
            }
            if matches!(s.kind, SinkKind::Store {}) && !wicket_store::objects::valid_key(&s.name) {
                bail!("a store sink's name is part of its objects' keys: lowercase letters, digits, '_', '.' and '-' ({:?})", s.name);
            }
            if s.durable && matches!(&s.kind, SinkKind::Jsonl { path } if path == "-") {
                bail!("sink {:?}: standard output isn't durable (nothing keeps what it prints)", s.name);
            }
            // Processes in different working directories would write two files under one cursor.
            if let SinkKind::Jsonl { path } = &s.kind {
                if path != "-" && !Path::new(path).is_absolute() {
                    bail!(
                        "sink {:?}: a jsonl path must be absolute ({path:?}): every wicket process exporting it shares one cursor",
                        s.name
                    );
                }
            }
        }
        if c.batch == 0 {
            bail!("batch must be at least 1");
        }
        if !(c.host_gb.is_finite() && c.host_gb > 0.0) {
            bail!("host_gb must be a positive number of GB, not {}", c.host_gb);
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

// ---- retention on the host (#582) ----

/// What retention did, or would do, and where it stands: for reconcile's report, `wicket top`
/// and the console.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Retention {
    /// Whether pruning is on: a durable sink configured and the state store streaming the ledger.
    /// Why not, if not.
    pub enabled: bool,
    pub why_not: Option<String>,
    /// The limit, the table's estimated size and the file's, and the anchor (the prune checkpoint).
    pub limit_bytes: i64,
    pub usage: wicket_store::AuditUsage,
    pub file_bytes: i64,
    pub anchor: Option<wicket_store::AuditAnchor>,
    /// Records pruned by this pass (0 for a status).
    pub pruned: i64,
    /// Over the limit with nothing to prune to yet: why (a checkpoint was asked for, a sink is
    /// behind, the state store hasn't synced).
    pub waiting: Option<String>,
    /// The file doesn't give pruned space back (`auto_vacuum` isn't incremental): `wicket audit
    /// compact`, with wicket's services stopped, switches it once.
    pub compact_needed: bool,
}

/// The fraction of the limit a prune cuts the table back to, so it isn't pruning every pass.
const PRUNE_TO: f64 = 0.9;
/// Records deleted per transaction, so a prune never holds the write lock long.
const PRUNE_ROWS: i64 = 10_000;
/// Chunks per pass (500,000 records at most).
const PRUNE_CHUNKS: usize = 50;
/// Free pages given back per transaction, and at most per pass.
const VACUUM_PAGES: i64 = 2000;
const VACUUM_STEPS: usize = 500;

/// Whether this installation may prune: at least one durable sink (a store sink, or one marked
/// `durable: true`), and the state store set up to stream the ledger off the host. The sinks, or
/// why not. (That the stream is live, and synced past the checkpoint, is the caller's to give:
/// `synced_ms` in [`retention_with`].)
pub fn retention_config() -> Result<std::result::Result<SinksConfig, String>> {
    let sinks = match SinksConfig::load()? {
        Some(c) if c.sinks.iter().any(SinkSpec::is_durable) => c,
        Some(c) if !c.sinks.is_empty() => {
            return Ok(Err("no durable audit sink is configured (a store sink, or one marked durable: true)".into()));
        }
        _ => return Ok(Err(format!("no audit sink is configured ({})", sinks_path().display()))),
    };
    match crate::statestore::StateStore::load()? {
        Some(s) if s.ledger.is_some() => Ok(Ok(sinks)),
        _ => Ok(Err("the state store doesn't stream the ledger off the host (wicket state replicate)".into())),
    }
}

/// One retention pass, or (`prune` false) where retention stands. `synced_ms`: until when the
/// state store has the ledger (its last sync while streaming), None if it isn't streaming. If
/// pruning is on and the audit table is over its limit, its oldest records are pruned back towards
/// [`PRUNE_TO`] of it, to a checkpoint a durable sink acknowledged that every durable sink has
/// exported past and the store had synced; with none at or before the cut, a checkpoint there is
/// asked of the exporter, and the next pass prunes to it.
pub fn retention_with(l: &Ledger, cfg: std::result::Result<&SinksConfig, &str>, synced_ms: Option<i64>, prune: bool) -> Result<Retention> {
    let limit_bytes = (cfg.as_ref().map(|c| c.host_gb).unwrap_or(DEFAULT_HOST_GB) * 1e9) as i64;
    let why_not = match (&cfg, synced_ms) {
        (Err(e), _) => Some(e.to_string()),
        (Ok(c), _) if !c.sinks.iter().any(SinkSpec::is_durable) => {
            Some("no durable audit sink is configured (a store sink, or one marked durable: true)".into())
        }
        (Ok(_), None) => Some("the state store isn't streaming the ledger now (wicket state status)".into()),
        _ => None,
    };
    let mut r = Retention {
        enabled: why_not.is_none(),
        why_not,
        limit_bytes,
        usage: l.audit_usage()?,
        file_bytes: l.file_bytes()?,
        anchor: l.audit_anchor()?,
        pruned: 0,
        waiting: None,
        compact_needed: !l.auto_vacuum_incremental()?,
    };
    let (Ok(cfg), Some(synced)) = (cfg, synced_ms) else { return Ok(r) };
    // At most PRUNE_CHUNKS deletes a pass, what an earlier pass left of its prune and a new one
    // together: a long backlog goes over several passes, the chain verifying from the anchor
    // throughout.
    let mut chunks = PRUNE_CHUNKS;
    if prune {
        // What an earlier pass left of its prune, first.
        prune_chunks(l, &mut chunks, &mut r)?;
    }
    if r.usage.bytes <= limit_bytes || r.usage.rows == 0 || chunks == 0 {
        return settle(l, r);
    }
    let per_row = (r.usage.bytes / r.usage.rows).max(1);
    let keep = ((limit_bytes as f64 * PRUNE_TO) as i64 / per_row).max(1);
    let target = r.usage.head - keep + 1;
    let mut targets = vec![];
    for s in cfg.sinks.iter().filter(|s| s.is_durable()) {
        match s.target() {
            Ok(t) => targets.push((s.name.as_str(), t)),
            Err(e) => {
                // Nothing new pruned; what an earlier prune left was resumed above, so settle it.
                r.waiting = Some(format!("over its limit, but where sink {} points can't be told ({e:#}): nothing new pruned", s.name));
                return settle(l, r);
            }
        }
    }
    let durable: Vec<&str> = targets.iter().map(|(n, _)| *n).collect();
    let pairs: Vec<(&str, &str)> = targets.iter().map(|(n, t)| (*n, t.as_str())).collect();
    let Some(cp) = l.prune_point(&pairs, target, synced)? else {
        if prune && target > r.usage.first {
            l.want_checkpoint(target)?;
        }
        r.waiting = Some(format!(
            "over its limit: waiting for a checkpoint at or before seq {target} that every durable sink ({}) has exported past and the state store has synced",
            durable.join(", ")
        ));
        return settle(l, r);
    };
    if !prune {
        r.waiting = Some(format!("over its limit: the records before seq {} are due to be pruned", cp.seq));
        return Ok(r);
    }
    // Chosen again and begun in one transaction: nothing it read (cursors, targets) changes in
    // between.
    let Some(cp) = l.begin_prune_at(&pairs, target, synced)? else { return settle(l, r) };
    if cp.seq < target {
        // Short of the cut: this prune goes as far as it may, and the next goes the rest.
        l.want_checkpoint(target)?;
    }
    prune_chunks(l, &mut chunks, &mut r)?;
    settle(l, r)
}

/// Deletes pruned records a chunk at a time while `chunks` lasts (taking from it).
fn prune_chunks(l: &Ledger, chunks: &mut usize, r: &mut Retention) -> Result<()> {
    while *chunks > 0 {
        *chunks -= 1;
        let n = l.prune_chunk(PRUNE_ROWS)?;
        if n == 0 {
            break;
        }
        r.pruned += n;
    }
    Ok(())
}

/// After a pass's deletes, whether it resumed an earlier prune or began one: freed pages back to
/// the file system (a bounded number), and the figures read again.
fn settle(l: &Ledger, mut r: Retention) -> Result<Retention> {
    if r.pruned == 0 {
        return Ok(r);
    }
    for _ in 0..VACUUM_STEPS {
        if l.vacuum_step(VACUUM_PAGES)? == 0 {
            break;
        }
    }
    r.usage = l.audit_usage()?;
    r.file_bytes = l.file_bytes()?;
    r.anchor = l.audit_anchor()?;
    Ok(r)
}

/// Checks the anchor's signature against `issuer`, and that it signed the record kept there: what
/// `verify_audit` leaves to whoever has the key. The anchor's seq, if there is one.
pub fn verify_anchor(l: &Ledger, issuer: &wicket_identity::VerifyingKey) -> Result<Option<i64>> {
    let Some(a) = l.audit_anchor()? else { return Ok(None) };
    let p = wicket_identity::verify_checkpoint(&a.jws, issuer).context("the audit chain's anchor checkpoint doesn't verify")?;
    if p["seq"].as_i64() != Some(a.seq) || p["head"].as_str() != Some(a.hash.as_str()) {
        bail!("the audit chain's anchor checkpoint signs seq {} head {}, not the record kept at seq {}", p["seq"], p["head"], a.seq);
    }
    Ok(Some(a.seq))
}

/// [`verify_anchor`] with this installation's issuer key.
pub fn verify_local_anchor(l: &Ledger) -> Result<Option<i64>> {
    if l.audit_anchor()?.is_none() {
        return Ok(None);
    }
    let key = crate::issuer().context("checking the audit chain's anchor needs the issuer key")?;
    verify_anchor(l, &key.verifying_key())
}

/// Retention in a line: the table against its limit, the anchor, and what it waits for.
pub fn retention_line(r: &Retention) -> String {
    let gb = |b: i64| format!("{:.2} GB", b as f64 / 1e9);
    let mut out = format!("audit {} of {} (ledger file {})", gb(r.usage.bytes), gb(r.limit_bytes), gb(r.file_bytes));
    match &r.anchor {
        Some(a) => out.push_str(&format!(", pruned to seq {} ({} records, kept in sink {})", a.seq, a.pruned, a.sink)),
        None => out.push_str(", nothing pruned"),
    }
    if let Some(w) = &r.why_not {
        out.push_str(&format!("; never pruned: {w}"));
    } else if let Some(w) = &r.waiting {
        out.push_str(&format!("; {w}"));
    }
    if r.compact_needed && r.anchor.is_some() {
        out.push_str("; the file keeps the space until `wicket audit compact`");
    }
    out
}

// ---- where each sink is ----

/// One sink's progress against the chain head (#635): what `wicket audit export --status`, the
/// console's health section and `wicket top` show.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SinkStatus {
    pub sink: String,
    /// `jsonl`, `otlp` or `store`.
    pub kind: &'static str,
    /// The last sequence number it acknowledged.
    pub seq: i64,
    /// The chain head's sequence number.
    pub head: i64,
    /// Records it hasn't acknowledged yet.
    pub behind: i64,
    /// How long the oldest of those has waited (seconds), 0 when caught up.
    pub behind_secs: i64,
    /// When it last acknowledged a signed checkpoint (Unix seconds), 0 if never.
    pub checkpoint_at: i64,
    /// Who feeds it, while its lease lasts.
    pub holder: Option<String>,
    /// The last delivery error, cleared on success.
    pub error: Option<String>,
    /// A `jsonl` sink to standard output (`path: "-"`): only a `wicket audit export` in the
    /// foreground feeds it, so being behind is expected, not a fault.
    pub manual: bool,
}

impl SinkKind {
    pub fn name(&self) -> &'static str {
        match self {
            SinkKind::Jsonl { .. } => "jsonl",
            SinkKind::Otlp { .. } => "otlp",
            SinkKind::Store {} => "store",
        }
    }
}

/// Every configured sink's progress at `now` (Unix seconds), from the ledger's cursors.
pub fn status(l: &Ledger, cfg: &SinksConfig, now: i64) -> Result<Vec<SinkStatus>> {
    let head = l.audit_head()?.map(|h| h.0).unwrap_or(0);
    cfg.sinks
        .iter()
        .map(|s| {
            let c = l.peek_export_cursor(&s.name)?;
            let oldest = if c.seq < head { l.audit_ts_after(c.seq)? } else { None };
            Ok(SinkStatus {
                sink: s.name.clone(),
                kind: s.kind.name(),
                seq: c.seq,
                head,
                behind: (head - c.seq).max(0),
                behind_secs: oldest.map(|ts| (now - ts).max(0)).unwrap_or(0),
                checkpoint_at: c.checkpoint_at,
                holder: c.holder.filter(|_| c.lease_until >= now),
                error: c.error,
                manual: matches!(&s.kind, SinkKind::Jsonl { path } if path == "-"),
            })
        })
        .collect()
}

/// A sink's status on one line: `wicket audit export --status` and `wicket top`.
pub fn status_line(s: &SinkStatus, now: i64) -> String {
    let behind = match s.behind {
        0 => "caught up".to_string(),
        n => format!("{n} behind (oldest {})", ago(s.behind_secs)),
    };
    let cp = match s.checkpoint_at {
        0 => "never".to_string(),
        at => format!("{} ago", ago(now - at)),
    };
    let behind = if s.manual { format!("{behind} (manual: fed only by `wicket audit export`)") } else { behind };
    format!(
        "{:<16} {:<5} at {} of {}, {behind}  last checkpoint {cp}  fed by {}{}",
        s.sink,
        s.kind,
        s.seq,
        s.head,
        s.holder.as_deref().unwrap_or("-"),
        s.error.as_ref().map(|e| format!("  error: {e}")).unwrap_or_default()
    )
}

/// A span of seconds, short: `40 s`, `12 min`, `3 h`, `2 d`.
pub fn ago(secs: i64) -> String {
    match secs.max(0) {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} d", s / 86_400),
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

/// What an exported object is as an OpenTelemetry event (#368): its event name, severity, and the
/// standard attributes its record carries, beside wicket's own. The hash chain is the object
/// itself (the log record's body), unchanged; these only make it readable by a collector without
/// knowing wicket's bodies.
///
/// - an egress decision (`op` of kind `egress`) is `wicket.egress.decision`, with HTTP semantic
///   conventions (`http.request.method`, `server.address`, `url.path`), the outcome, the risk class
///   and the reason; a refusal is `WARN`, with `error.type` its outcome;
/// - a model call (`op` of kind `llm`) is `gen_ai.client.inference.operation.details`, with the
///   GenAI conventions (`gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`,
///   `gen_ai.usage.input_tokens` and `.output_tokens`) and `http.response.status_code`;
/// - a tool call (`op` of kind `tool`) is `wicket.tool.call`, with `gen_ai.operation.name`
///   `execute_tool` and `gen_ai.tool.name`;
/// - a human's or an agent's decision on a request (`decision`) is `wicket.approval.decision`;
/// - anything else is `wicket.audit.<kind>`, and a checkpoint `wicket.audit.checkpoint`.
pub fn otlp_event(it: &Value) -> (String, u8, Vec<Value>) {
    let s = |v: &str| json!({ "stringValue": v });
    let int = |v: u64| json!({ "intValue": v.to_string() });
    let attr = |k: &str, v: Value| json!({ "key": k, "value": v });
    let body = &it["body"];
    let text = |f: &str| body[f].as_str().filter(|v| !v.is_empty());
    let mut a = Vec::new();
    if it["type"] == "wicket.audit.checkpoint" {
        return ("wicket.audit.checkpoint".into(), 9, a);
    }
    let kind = it["kind"].as_str().unwrap_or("");
    let op = if kind == "op" { body["kind"].as_str().unwrap_or("") } else { "" };
    let (name, mut sev) = match (kind, op) {
        ("op", "egress") => {
            for (k, f) in [("http.request.method", "method"), ("server.address", "host"), ("url.path", "path")] {
                if let Some(v) = text(f) {
                    a.push(attr(k, s(v)));
                }
            }
            ("wicket.egress.decision".to_string(), 9)
        }
        ("op", "llm") => {
            a.push(attr("gen_ai.operation.name", s("chat")));
            if let Some(p) = text("provider") {
                a.push(attr("gen_ai.provider.name", s(p)));
            }
            if let Some(m) = text("model") {
                a.push(attr("gen_ai.request.model", s(m)));
            }
            let (input, cached, output) = (
                body["input_tokens"].as_u64().unwrap_or(0),
                body["cached_tokens"].as_u64().unwrap_or(0),
                body["output_tokens"].as_u64().unwrap_or(0),
            );
            // GenAI's input tokens are the whole prompt's, cached ones included.
            a.push(attr("gen_ai.usage.input_tokens", int(input + cached)));
            a.push(attr("gen_ai.usage.output_tokens", int(output)));
            a.push(attr("wicket.llm.cached_tokens", int(cached)));
            if let Some(st) = body["status"].as_u64().filter(|s| *s > 0) {
                a.push(attr("http.response.status_code", int(st)));
            }
            ("gen_ai.client.inference.operation.details".to_string(), 9)
        }
        ("op", "tool") => {
            a.push(attr("gen_ai.operation.name", s("execute_tool")));
            if let Some(n) = text("name") {
                a.push(attr("gen_ai.tool.name", s(n)));
            }
            ("wicket.tool.call".to_string(), 9)
        }
        ("decision", _) => {
            for (k, f) in [
                ("wicket.decision", "decision"),
                ("wicket.request.id", "request"),
                ("wicket.grant.id", "grant"),
                ("wicket.decision.by", "by"),
                ("http.request.method", "method"),
                ("server.address", "host"),
                ("url.path", "path"),
            ] {
                if let Some(v) = text(f) {
                    a.push(attr(k, s(v)));
                }
            }
            ("wicket.approval.decision".to_string(), 9)
        }
        ("op", other) if !other.is_empty() => (format!("wicket.audit.op.{other}"), 9),
        _ => (format!("wicket.audit.{}", if kind.is_empty() { "record" } else { kind }), 9),
    };
    if kind == "op" {
        if let Some(o) = text("outcome") {
            a.push(attr("wicket.decision.outcome", s(&wicket_core::text::clip(o, 256))));
        }
        // A refusal of the box's request is a warning, its type the outcome; a model call's (whose
        // outcome is a note) is its HTTP status.
        let failed = match op {
            "llm" => body["status"].as_u64().filter(|st| *st >= 400).map(|st| st.to_string()),
            "egress" => text("outcome").filter(|o| !matches!(*o, "allow" | "spliced")).map(String::from),
            _ => None,
        };
        if let Some(t) = failed {
            a.push(attr("error.type", s(&t)));
            sev = 13;
        }
        if let Some(r) = text("risk").filter(|r| *r != "-") {
            a.push(attr("wicket.decision.risk", s(r)));
        }
        if let Some(d) = text("detail") {
            a.push(attr("wicket.decision.reason", s(&wicket_core::text::clip(d, 1024))));
        }
    }
    (name, sev, a)
}

/// OTLP/HTTP JSON for a batch of exported objects (records or checkpoints): one log record each,
/// whose body is the object's JSON line, with its event name and standard attributes
/// ([`otlp_event`]).
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
            let (event, sev, extra) = otlp_event(it);
            attrs.extend(extra);
            json!({
                "timeUnixNano": (it["ts"].as_i64().unwrap_or(0) as i128 * 1_000_000_000).to_string(),
                "observedTimeUnixNano": observed,
                "severityNumber": sev,
                "severityText": if sev >= 13 { "WARN" } else { "INFO" },
                "eventName": event,
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
    /// Where this exporter's configuration points it ([`SinkSpec::target_in`]); None until it can
    /// be told. Its cursor, lease and checkpoints are written only while the ledger's target for
    /// the sink is this one (#582).
    target: Option<String>,
    /// Another process has pointed the sink elsewhere since this one read its configuration: this
    /// exporter no longer feeds it.
    stale: bool,
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
    /// The state store, opened on first use by a `store` sink, from `store_cfg`.
    store: Option<crate::s3::S3Store>,
    /// The state store's configuration as this exporter read it: what a `store` sink's target is
    /// told from, and what its objects are delivered through.
    store_cfg: Option<crate::statestore::StateStore>,
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
        getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("random: {e}"))?;
        let store_cfg = match cfg.sinks.iter().any(|s| matches!(s.kind, SinkKind::Store {})) {
            true => crate::statestore::StateStore::load().ok().flatten(),
            false => None,
        };
        let ledger = Ledger::open(ledger_path)?;
        let mut sinks = vec![];
        for s in &cfg.sinks {
            // A sink whose target changed starts again (#582): its cursor was for records another
            // target got. Can't tell (the state store's file doesn't read): the cursor is kept,
            // and the sink isn't fed (nor retention counting on it) until it can.
            let target = s.target_in(store_cfg.as_ref()).ok();
            if let Some(t) = &target {
                ledger.sink_target(&s.name, t)?;
            }
            sinks.push(Sink {
                spec: s.clone(),
                target,
                stale: false,
                next_try: Instant::now(),
                backoff: Duration::from_secs(1),
                held: false,
                renewed: None,
            });
        }
        Ok(Exporter {
            ledger,
            cfg,
            sinks,
            store_cfg,
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
            if self.sinks[i].stale {
                continue;
            }
            let target = match self.target(i) {
                Ok(t) => t,
                Err(e) => {
                    out.failures.push((name, format!("{e:#}")));
                    continue;
                }
            };
            // Renew the lease about three times per lease period; take it when it lapses.
            let s = &self.sinks[i];
            if !s.held || s.renewed.is_none_or(|r| now.duration_since(r) >= Duration::from_secs((EXPORT_LEASE_SECS / 3) as u64)) {
                let held = self.ledger.lease_export(&name, &target, &self.holder, at).unwrap_or(false);
                let s = &mut self.sinks[i];
                s.held = held;
                s.renewed = held.then_some(now);
            }
            if !self.sinks[i].held {
                if self.stale_now(i, &target) {
                    out.failures.push((name, self.stale_message(i)));
                } else {
                    out.busy.push(name);
                }
                continue;
            }
            if now < self.sinks[i].next_try {
                continue;
            }
            match self.feed(i, &target, force_checkpoint) {
                Ok((r, c)) => {
                    out.records += r;
                    out.checkpoints += c;
                    let s = &mut self.sinks[i];
                    s.backoff = Duration::from_secs(1);
                }
                Err(_) if self.stale_now(i, &target) => {
                    self.sinks[i].held = false;
                    out.failures.push((name, self.stale_message(i)));
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    // Stored and shown: a URL's user info and query (tokens) dropped.
                    let _ = self.ledger.export_failed(&name, &wicket_core::text::redact_urls(&msg));
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

    /// Sink `i`'s target, told now if it couldn't be before (the state store's file read again).
    fn target(&mut self, i: usize) -> Result<String> {
        if let Some(t) = &self.sinks[i].target {
            return Ok(t.clone());
        }
        if matches!(self.sinks[i].spec.kind, SinkKind::Store {}) && self.store.is_none() {
            self.store_cfg = crate::statestore::StateStore::load()?;
        }
        let t = self.sinks[i].spec.target_in(self.store_cfg.as_ref())?;
        self.ledger.sink_target(&self.sinks[i].spec.name, &t)?;
        self.sinks[i].target = Some(t.clone());
        Ok(t)
    }

    /// Whether the ledger now points sink `i` somewhere other than `target` (another process,
    /// with a newer configuration): then this exporter stops feeding it for good.
    fn stale_now(&mut self, i: usize, target: &str) -> bool {
        let now = self.ledger.sink_target_of(&self.sinks[i].spec.name).ok().flatten();
        let stale = now.is_some_and(|t| t != target);
        self.sinks[i].stale |= stale;
        stale
    }

    fn stale_message(&self, i: usize) -> String {
        let s = &self.sinks[i];
        let now = self.ledger.sink_target_of(&s.spec.name).ok().flatten().unwrap_or_default();
        format!(
            "sink {} now points at {now} (another process read a newer configuration), not {}: this process no longer feeds it (restart it to read the new one)",
            s.spec.name,
            s.target.as_deref().unwrap_or("")
        )
    }

    fn feed(&mut self, i: usize, target: &str, force_checkpoint: bool) -> Result<(usize, usize)> {
        let name = self.sinks[i].spec.name.clone();
        let mut cur = self.ledger.export_cursor(&name)?;
        let mut sent = 0;
        loop {
            // Not to a target the sink has left (the cursor write below would be refused anyway).
            if self.ledger.sink_target_of(&name)?.as_deref() != Some(target) {
                bail!("sink {name}'s target changed under this process");
            }
            let recs = self.ledger.audit_records_after(cur.seq, self.cfg.batch)?;
            let Some(last) = recs.last().map(|r| r.seq) else { break };
            let items: Vec<Value> = recs.iter().map(record_json).collect();
            self.deliver(i, &items)?;
            // One cursor write per delivered batch, only while the sink still points here.
            if !self.ledger.advance_export(&name, target, last)? {
                bail!("sink {name}'s target changed under this process");
            }
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
            let jws = cp["jws"].as_str().unwrap_or_default().to_string();
            self.deliver(i, &[cp])?;
            // What retention may prune back to (#582): kept with what it signed, and where it went
            // (the target it was delivered through).
            if !self.ledger.export_checkpointed(&name, target, at)?
                || !self.ledger.record_checkpoint(&name, target, cur.seq, &head, at, &jws)?
            {
                bail!("sink {name}'s target changed under this process");
            }
            cps = 1;
        }
        // Checkpoints retention asked for, where it wants to cut (#582): signed once each sink is
        // past them, at that seq.
        if self.issuer.is_some() {
            for seq in self.ledger.checkpoint_wants()? {
                if seq > cur.seq || seq <= 0 || self.ledger.has_checkpoint(&name, target, seq)? {
                    continue;
                }
                let Some(head) = self.ledger.audit_hash_at(seq)? else { continue };
                let cp = checkpoint_json(self.issuer.as_ref().expect("checked"), seq, &head, at);
                let jws = cp["jws"].as_str().unwrap_or_default().to_string();
                self.deliver(i, &[cp])?;
                if !self.ledger.record_checkpoint(&name, target, seq, &head, at, &jws)? {
                    bail!("sink {name}'s target changed under this process");
                }
                cps += 1;
            }
        }
        Ok((sent, cps))
    }

    fn deliver(&mut self, i: usize, items: &[Value]) -> Result<()> {
        match &self.sinks[i].spec.kind {
            SinkKind::Store {} => {
                use wicket_store::objects::ObjectStore;
                if self.store.is_none() {
                    // Through the configuration its target was told from (`store_cfg`).
                    let s = self.store_cfg.as_ref().context("an audit sink of type store needs state-store.yaml")?;
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
    // Checked (and said) once; loaded again for each try below (an issuer isn't `Clone`).
    let signs = crate::issuer().map_err(|e| eprintln!("wicket: audit checkpoints are off (no issuer key: {e})")).is_ok();
    let path = crate::ledger_path();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<std::sync::mpsc::SyncSender<()>>();
    let _ = std::thread::Builder::new().name("wicket-audit-export".into()).spawn(move || {
        // A ledger busy at the start (a migration, a long write elsewhere) is waited out, not taken
        // as export being off for the life of the process; a stop still ends it meanwhile.
        let mut wait = Duration::from_secs(1);
        let mut x = loop {
            let issuer = if signs { crate::issuer().ok() } else { None };
            match Exporter::new(&path, cfg.clone(), issuer) {
                Ok(x) => break x,
                Err(e) if is_busy(&e) => {
                    eprintln!("wicket: audit export waits for the ledger ({e:#}); trying again in {} s", wait.as_secs());
                    match stop_rx.recv_timeout(wait) {
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => wait = (wait * 2).min(Duration::from_secs(60)),
                        Ok(done) => {
                            let _ = done.send(());
                            return;
                        }
                        Err(_) => return,
                    }
                }
                Err(e) => return eprintln!("wicket: audit export is off: {e:#}"),
            }
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

/// Whether `e` is SQLite saying another connection holds the database (busy or locked): worth
/// trying again.
fn is_busy(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        let sql = c.downcast_ref::<rusqlite::Error>().or_else(|| match c.downcast_ref::<wicket_store::StoreError>() {
            Some(wicket_store::StoreError::Sql(s)) => Some(s),
            _ => None,
        });
        matches!(
            sql.and_then(rusqlite::Error::sqlite_error_code),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        )
    })
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
    /// Exported records and checkpoints from before the local chain's anchor: pruned here by
    /// retention (#582), so kept only in the sinks, not compared.
    pub pruned: usize,
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
    // Only those the chain vouches for: one forged below the anchor, where nothing chains it,
    // doesn't excuse a mismatch.
    let rollbacks: Vec<(i64, i64)> = l
        .trusted_restores()?
        .iter()
        .filter_map(|r| Some((serde_json::from_str::<Value>(&r.body).ok()?["rolled_back_after"].as_i64()?, r.ts)))
        .collect();
    // An exported copy that doesn't match is discarded history if a restore went back before it and
    // it was made before that restore (the same second counts: records carry whole seconds).
    let discarded = |seq: i64, ts: i64| rollbacks.iter().any(|&(after, at)| seq > after && ts <= at);
    // Before the anchor: deleted here by retention, after every sink had it (#582).
    let anchor = l.audit_anchor()?.map(|x| x.seq).unwrap_or(0);
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
                if seq < anchor && local.is_none() {
                    a.pruned += 1;
                    continue;
                }
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
                    None if seq < anchor => a.pruned += 1,
                    None => a.problems.push(format!("record {seq}: exported, but missing locally")),
                }
            }
            _ => {}
        }
    }
    if a.checkpoints + a.records + a.pruned == 0 && a.problems.is_empty() {
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
            getrandom::fill(&mut n).unwrap();
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
        // #677 follow-up: a relative path would be another file in each working directory.
        let e = SinksConfig::parse("sinks:\n  - {name: a, type: jsonl, path: audit.jsonl}\n").unwrap_err().to_string();
        assert!(e.contains("must be absolute"), "{e}");
        assert!(SinksConfig::parse("sinks:\n  - {name: a, type: jsonl, path: /var/log/a.jsonl}\n").is_ok());
        assert!(SinksConfig::parse("sinks:\n  - {name: a, type: jsonl, path: '-'}\n").is_ok());
    }

    /// #677 follow-up: a busy or locked ledger at the exporter's start is tried again, anything
    /// else isn't.
    #[test]
    fn a_busy_ledger_is_worth_trying_again() {
        let sql = |code| rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
        let busy = anyhow::Error::from(wicket_store::StoreError::Sql(sql(rusqlite::ffi::SQLITE_BUSY))).context("opening the ledger");
        assert!(is_busy(&busy));
        assert!(is_busy(&anyhow::Error::from(sql(rusqlite::ffi::SQLITE_LOCKED))));
        assert!(!is_busy(&anyhow::Error::from(sql(rusqlite::ffi::SQLITE_CORRUPT))));
        assert!(!is_busy(&anyhow::anyhow!("database is busy, said someone")));
    }

    #[test]
    fn a_sinks_status_counts_what_it_has_not_acknowledged() {
        let l = Ledger::open_in_memory().unwrap();
        let cfg = SinksConfig::parse("sinks:\n  - {name: a, type: jsonl, path: '-'}\n  - {name: s, type: store}\n").unwrap();
        write_records(&l, 0, 5);
        let (head, _) = l.audit_head().unwrap().unwrap();
        let first = l.audit_record_at(1).unwrap().unwrap();
        l.sink_target("a", "jsonl:-").unwrap();
        l.advance_export("a", "jsonl:-", head).unwrap();
        l.export_checkpointed("a", "jsonl:-", 77).unwrap();
        l.lease_export("a", "jsonl:-", "serve-1", first.ts + 80).unwrap();
        l.export_failed("s", "connection refused").unwrap();
        let st = status(&l, &cfg, first.ts + 90).unwrap();
        let a = &st[0];
        assert_eq!((a.kind, a.seq, a.head, a.behind, a.behind_secs, a.checkpoint_at), ("jsonl", head, head, 0, 0, 77));
        assert_eq!(a.holder.as_deref(), Some("serve-1"));
        assert!(a.manual, "a jsonl sink to stdout is fed by hand");
        assert!(status_line(a, first.ts + 90).contains("(manual: fed only by `wicket audit export`)"));
        let s = &st[1];
        assert_eq!(
            (s.kind, s.seq, s.behind, s.behind_secs, s.manual),
            ("store", 0, head, 90, false),
            "behind by every record, the first 90 s old"
        );
        assert_eq!(s.error.as_deref(), Some("connection refused"));
        let later = status(&l, &cfg, first.ts + 3600).unwrap();
        assert_eq!(later[0].holder, None, "a lapsed lease feeds nothing");
        let now = first.ts + 90;
        assert!(status_line(a, now).contains(&format!("at {head} of {head}, caught up")), "{}", status_line(a, now));
        let line = status_line(s, now);
        assert!(
            line.contains("5 behind (oldest 90 s)")
                && line.contains("last checkpoint never")
                && line.ends_with("error: connection refused"),
            "{line}"
        );
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

    /// #582: with a durable sink and the state store streaming, a ledger over its limit is pruned
    /// back under it, but not much further: to a checkpoint retention asked the exporter for at the
    /// cut, never one near the head. The chain, its anchor's signature and the exported copy still
    /// verify, across prunes and after more records. Without a durable sink, or with the state
    /// store not streaming, nothing is ever pruned.
    #[test]
    fn retention_keeps_the_ledger_within_its_limit_and_verifiable() {
        let d = TmpDir::new("retention");
        let lp = d.0.join("ledger.db");
        let out = d.0.join("out/audit.jsonl");
        let issuer = wicket_identity::Issuer::generate("test.local");
        let key = issuer.verifying_key();
        let l = open_batched(&lp).unwrap();
        let mut cfg = SinksConfig::parse(&format!(
            "host_gb: 0.00002\nsinks:\n  - name: file\n    type: jsonl\n    durable: true\n    path: {}\n",
            out.display()
        ))
        .unwrap();
        let limit = (cfg.host_gb * 1e9) as i64;
        let far = Some(i64::MAX);
        let mut x = Exporter::new(&lp, cfg.clone(), Some(issuer)).unwrap();
        write_records(&l, 0, 300);
        x.pass(true);
        // No sink, a sink that isn't durable, or no stream: never pruned.
        assert!(!retention_with(&l, Err("no audit sink is configured"), far, true).unwrap().enabled);
        let mut stdout = cfg.clone();
        stdout.sinks[0].kind = SinkKind::Jsonl { path: "-".into() };
        stdout.sinks[0].durable = false;
        let r = retention_with(&l, Ok(&stdout), far, true).unwrap();
        assert!(!r.enabled && r.why_not.as_deref().unwrap_or("").contains("durable"), "{r:?}");
        cfg.sinks[0].durable = false;
        assert!(!retention_with(&l, Ok(&cfg), far, true).unwrap().enabled, "a file isn't durable unless marked");
        cfg.sinks[0].durable = true;
        assert!(!retention_with(&l, Ok(&cfg), None, true).unwrap().enabled, "the state store isn't streaming");
        assert_eq!(l.audit_usage().unwrap().rows, 300, "nothing pruned yet");
        // The only checkpoint is at the head: retention asks for one at its cut, and waits.
        let r = retention_with(&l, Ok(&cfg), far, true).unwrap();
        assert!(r.pruned == 0 && r.waiting.is_some(), "{r:?}");
        for round in 0..3 {
            // Prune, sign what retention asked for, prune again: within a few passes it is under.
            let mut r = retention_with(&l, Ok(&cfg), far, true).unwrap();
            for _ in 0..3 {
                if r.usage.bytes <= limit {
                    break;
                }
                x.pass(false);
                r = retention_with(&l, Ok(&cfg), far, true).unwrap();
            }
            assert!(l.audit_anchor().unwrap().is_some(), "round {round}: {r:?}");
            assert!(r.usage.bytes <= limit, "round {round}: within the limit: {} of {limit}", r.usage.bytes);
            assert!(r.usage.bytes >= limit / 2, "round {round}: not emptied: {} of {limit}", r.usage.bytes);
            assert!(l.verify_audit().unwrap() > 0);
            assert!(l.verify_node_audit().is_ok());
            assert!(verify_anchor(&l, &key).unwrap().is_some());
            write_records(&l, 300 + round * 300, 300);
            x.pass(true);
        }
        let a = verify_against(&l, &exported_objects(&std::fs::read_to_string(&out).unwrap()), &key).unwrap();
        assert!(a.problems.is_empty(), "{:?}", a.problems);
        assert!(a.pruned > 0 && a.records > 0, "{a:?}");
        assert!(!retention_line(&retention_with(&l, Ok(&cfg), far, false).unwrap()).contains("dry run"));
        // A forged anchor is caught by its signature.
        let other = wicket_identity::Issuer::generate("test.local").verifying_key();
        assert!(verify_anchor(&l, &other).is_err());
    }

    /// A second durable sink that is behind holds pruning back to what it has; settings retention
    /// can't honour are refused.
    #[test]
    fn retention_waits_for_every_durable_sink() {
        let d = TmpDir::new("retention2");
        let lp = d.0.join("ledger.db");
        let (a, b) = (d.0.join("a.jsonl"), d.0.join("b.jsonl"));
        let issuer = wicket_identity::Issuer::generate("test.local");
        let l = open_batched(&lp).unwrap();
        write_records(&l, 0, 300);
        let one = format!("host_gb: 0.00001\nsinks:\n  - name: file\n    type: jsonl\n    durable: true\n    path: {}\n", a.display());
        let mut x = Exporter::new(&lp, SinksConfig::parse(&one).unwrap(), Some(issuer)).unwrap();
        x.pass(true);
        let both =
            SinksConfig::parse(&format!("{one}  - name: slow\n    type: jsonl\n    durable: true\n    path: {}\n", b.display())).unwrap();
        let far = Some(i64::MAX);
        retention_with(&l, Ok(&both), far, true).unwrap();
        x.pass(false);
        assert_eq!(retention_with(&l, Ok(&both), far, true).unwrap().pruned, 0, "slow has nothing yet");
        assert!(retention_with(&l, Ok(&SinksConfig::parse(&one).unwrap()), far, true).unwrap().pruned > 0);
        for bad in [
            "sinks:\n  - name: x\n    type: jsonl\n    path: /tmp/x\n    retention: 30d\n",
            "sinks:\n  - name: x\n    type: jsonl\n    path: \"-\"\n    durable: true\n",
            "host_gb: 0\nsinks: []\n",
            "host_gb: -1\nsinks: []\n",
        ] {
            assert!(SinksConfig::parse(bad).is_err(), "{bad}");
        }
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

    /// #677 third check (N2): a sink moved from a.jsonl to b.jsonl while a process started with
    /// the old configuration still holds its lease. That process feeds a.jsonl no further and moves
    /// nothing; the new one feeds b.jsonl from the start, and only its checkpoints, at what b.jsonl
    /// got, count for retention.
    #[test]
    fn a_stale_exporter_in_another_process_moves_nothing() {
        let d = TmpDir::new("stale");
        let lp = d.0.join("ledger.db");
        let (a_out, b_out) = (d.0.join("a.jsonl"), d.0.join("b.jsonl"));
        let l = Ledger::open(&lp).unwrap();
        write_records(&l, 0, 20);
        let issuer = || Some(wicket_identity::Issuer::generate("test.local"));
        let mut old = Exporter::new(&lp, jsonl_cfg(&a_out), issuer()).unwrap();
        assert_eq!(old.pass(true).records, 20);
        write_records(&l, 20, 10);
        // The configuration moves the sink; a new process reads it.
        let mut new = Exporter::new(&lp, jsonl_cfg(&b_out), issuer()).unwrap();
        assert_eq!(l.peek_export_cursor("file").unwrap().seq, 0, "started again for b.jsonl");
        // The old process goes on with its lease and its configuration: it feeds nothing more.
        let p = old.pass(true);
        assert_eq!((p.records, p.checkpoints), (0, 0), "{p:?}");
        assert!(p.failures.iter().any(|(_, m)| m.contains("no longer feeds it")), "{p:?}");
        assert_eq!(exported_objects(&std::fs::read_to_string(&a_out).unwrap()).len(), 21, "a.jsonl as it was: 20 and a checkpoint");
        assert_eq!(l.peek_export_cursor("file").unwrap().seq, 0, "the cursor not pushed back to the head");
        // The new one has the sink at once, from the start.
        let p = new.pass(true);
        assert_eq!((p.records, p.checkpoints), (30, 1), "{p:?}");
        let b_objects = exported_objects(&std::fs::read_to_string(&b_out).unwrap());
        assert_eq!(b_objects.len(), 31);
        let target = format!("jsonl:{}", b_out.display());
        let cps = l.checkpoints().unwrap();
        assert!(!cps.is_empty() && cps.iter().all(|c| c.target == target), "{cps:?}");
        assert_eq!(l.prune_point(&[("file", target.as_str())], 30, i64::MAX).unwrap().map(|c| c.seq), Some(30));
        // And later passes of the old one still move nothing.
        write_records(&l, 30, 2);
        assert_eq!(old.pass(true).records, 0);
        assert_eq!(new.pass(false).records, 2);
        assert_eq!(l.peek_export_cursor("file").unwrap().seq, l.audit_head().unwrap().unwrap().0);
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

    /// #368: each record is an OpenTelemetry event with standard attributes beside wicket's own:
    /// HTTP conventions for an egress decision, GenAI conventions for a model call, and the record
    /// itself (the chain) still the body.
    #[test]
    fn records_carry_event_names_and_standard_attributes() {
        let rec = |kind: &str, body: Value| json!({ "type": "wicket.audit.record", "seq": 7, "ts": 1, "tenant": "t", "run": "run_a", "kind": kind, "body": body, "prev": "p", "hash": "h" });
        let attrs = |v: &Value| -> BTreeMap<String, Value> {
            v["attributes"].as_array().unwrap().iter().map(|a| (a["key"].as_str().unwrap().to_string(), a["value"].clone())).collect()
        };
        let items = vec![
            rec(
                "op",
                json!({ "kind": "egress", "method": "POST", "host": "api.github.com", "path": "/repos/a/b/issues", "risk": "R3ExternalOrIrreversible", "outcome": "pending", "detail": "req_1 (new): outside reach" }),
            ),
            rec(
                "op",
                json!({ "kind": "egress", "method": "GET", "host": "crates.io", "path": "/api/v1/crates", "risk": "R1ReadScoped", "outcome": "allow", "detail": "reach rule 0" }),
            ),
            rec(
                "op",
                json!({ "kind": "llm", "provider": "anthropic", "model": "claude-sonnet-5-5", "status": 200, "input_tokens": 10, "cached_tokens": 90, "output_tokens": 5, "requests": 1, "outcome": "ok" }),
            ),
            rec(
                "op",
                json!({ "kind": "llm", "model": null, "status": 429, "input_tokens": 0, "cached_tokens": 0, "output_tokens": 0, "requests": 9, "outcome": "budget: request cap reached" }),
            ),
            rec("op", json!({ "kind": "tool", "name": "spawn", "detail": "x" })),
            rec(
                "decision",
                json!({ "decision": "approve", "request": "req_1", "grant": "gr_1", "by": "alex", "method": "POST", "host": "api.github.com", "path": "/repos/a/b/issues" }),
            ),
            rec("agent.hibernate", json!({ "agent": "agt_x" })),
            json!({ "type": "wicket.audit.checkpoint", "seq": 7, "head": "h", "ts": 1 }),
        ];
        let body = otlp_body(&items, &BTreeMap::new());
        let logs = body["resourceLogs"][0]["scopeLogs"][0]["logRecords"].as_array().unwrap().clone();
        let names: Vec<&str> = logs.iter().map(|l| l["eventName"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "wicket.egress.decision",
                "wicket.egress.decision",
                "gen_ai.client.inference.operation.details",
                "gen_ai.client.inference.operation.details",
                "wicket.tool.call",
                "wicket.approval.decision",
                "wicket.audit.agent.hibernate",
                "wicket.audit.checkpoint"
            ]
        );
        let pending = attrs(&logs[0]);
        assert_eq!(pending["http.request.method"]["stringValue"], "POST");
        assert_eq!(pending["server.address"]["stringValue"], "api.github.com");
        assert_eq!(pending["url.path"]["stringValue"], "/repos/a/b/issues");
        assert_eq!(pending["wicket.decision.outcome"]["stringValue"], "pending");
        assert_eq!(pending["error.type"]["stringValue"], "pending");
        assert_eq!(pending["wicket.decision.risk"]["stringValue"], "R3ExternalOrIrreversible");
        assert_eq!((logs[0]["severityNumber"].as_u64(), logs[0]["severityText"].as_str()), (Some(13), Some("WARN")));
        let allowed = attrs(&logs[1]);
        assert!(!allowed.contains_key("error.type"));
        assert_eq!(logs[1]["severityText"], "INFO");
        let llm = attrs(&logs[2]);
        assert_eq!(llm["gen_ai.operation.name"]["stringValue"], "chat");
        assert_eq!(llm["gen_ai.provider.name"]["stringValue"], "anthropic");
        assert_eq!(llm["gen_ai.request.model"]["stringValue"], "claude-sonnet-5-5");
        assert_eq!(llm["gen_ai.usage.input_tokens"]["intValue"], "100", "the whole prompt, cached tokens included");
        assert_eq!(llm["gen_ai.usage.output_tokens"]["intValue"], "5");
        assert_eq!(llm["http.response.status_code"]["intValue"], "200");
        assert!(!llm.contains_key("error.type"));
        let capped = attrs(&logs[3]);
        assert_eq!(capped["error.type"]["stringValue"], "429");
        assert!(!capped.contains_key("gen_ai.request.model") && !capped.contains_key("gen_ai.provider.name"));
        assert_eq!(attrs(&logs[4])["gen_ai.tool.name"]["stringValue"], "spawn");
        let d = attrs(&logs[5]);
        assert_eq!(
            (d["wicket.decision"]["stringValue"].as_str(), d["wicket.decision.by"]["stringValue"].as_str()),
            (Some("approve"), Some("alex"))
        );
        // The chain is untouched: every body is the exported object's JSON line.
        for (l, it) in logs.iter().zip(&items) {
            assert_eq!(serde_json::from_str::<Value>(l["body"]["stringValue"].as_str().unwrap()).unwrap(), *it);
        }
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
