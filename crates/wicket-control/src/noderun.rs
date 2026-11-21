//! The control host's side of a run on a node (#57, #146): every `wicket run` talks to a node's
//! `wicket node serve`, an enrolled node's (`--node <name>`) or this host's own (`localnode.rs`).
//!
//! - **Feed.** One [`Publisher`] per node, under `<data dir>/nodes/<name>/feed`: the node's online feed
//!   key (made here) and its certificate, signed by the installation's feed root. The run publishes
//!   its box's authority as a Biscuit token (`wicket_feed::token`): block 0 minted here with the
//!   authority root key from the zone's ceiling, until the run's timeout. Each grant a human approves
//!   for its requests is a third-party block signed here with the approver key; the token is rebuilt
//!   from its base with the live grants and published whole (bound to its box; the node counts their
//!   uses, and the ledger hands them over so it never consumes them too). Revocations of those grants
//!   go by grant id, and a run revocation also revokes the token's block 0 by its revocation id. A
//!   freshness statement goes out every refresh, from whichever run's connection signs it first. Many
//!   runs share a node's feed ([`SharedFeed`], one publisher per node in a process): each commit or
//!   statement holds the feed's lock and first applies the deltas other processes appended.
//! - **Channel.** `ssh <pinned> <target> wicket node attach` joins the ssh session to the node's
//!   control socket (for this host's own node, the socket itself: [`Via`]). The connection is the
//!   run's own (its scope is the run id). When it drops, the run keeps going: reconnects back off from 0.5 s to 5 s, and on
//!   each reconnect the node is caught up (deltas or a snapshot, and a statement signed for the
//!   occasion), stdout and stderr resume where they left off, unsent stdin is resent, and the node
//!   ships the audit records it made meanwhile.
//! - **Calls.** The node asks this run's gateway for the tools it doesn't answer itself
//!   (`Msg::Call`, #257 slice 4b), answered by the run's `Gateway` in this process. No socket of this
//!   run's is a tunnel target: the model, egress and gateway proxies are the node's (#257).
//! - **Asks.** A request the node can't allow is raised here as an ordinary pending request.
//! - **Identity.** Every connection starts with the mutual authentication in `nodeauth.rs`; at half
//!   its life the node's certificate is renewed over the channel, and a node revoked meanwhile (from
//!   another process: `wicket node revoke`) is dropped within a second and not reconnected.
//!
//! Test hooks: `WICKET_FEED_TTL_MS` and `WICKET_FEED_REFRESH_MS` override the feed's timings (within the certificate's caps, which follow them); `WICKET_FEED_COMPACT_BYTES` the
//! delta log size past which an idle feed starts a new generation.

use crate::chan::{self, accept_at, BoxStart, ControlTool, Frame, Msg, OutBuf};
use crate::nodeauth::HsError;
use crate::nodecall::{Calls, Via};
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use wicket_core::timing::Timings;
use wicket_core::{Op, RunId, TenantId, ZoneSpec};
use wicket_feed::{BoxAuthority, Change, KeyCert, LiveGrant, Publisher, PublisherConfig, Refreshed, RevokeKind};
use wicket_identity::node::NodeCertClaims;
use wicket_node::AGENT_ASKS;
use wicket_store::Ledger;

/// The feed's timings for this control host: the defaults, or the test overrides.
pub fn feed_config() -> PublisherConfig {
    let env = |k: &str, d: i64| std::env::var(k).ok().and_then(|v| v.parse().ok()).filter(|v: &i64| *v > 0).unwrap_or(d);
    PublisherConfig {
        ttl_ms: env("WICKET_FEED_TTL_MS", wicket_feed::DEFAULT_TTL_MS),
        refresh_ms: env("WICKET_FEED_REFRESH_MS", wicket_feed::DEFAULT_REFRESH_MS),
        ..PublisherConfig::default()
    }
}

/// A node's delta log past this size starts a new feed generation when no box holds authority from it.
const COMPACT_BYTES: u64 = 1 << 20;

/// The supervisor's loops do their ledger work at least this often, whether or not the change
/// counters moved (#582 step 2): what a counter can't see (a grant's end, a due renewal) is caught.
const FULL_EVERY: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether `topic` changed since this connection last looked (true if the ledger can't say).
fn changed(sh: &Shared, p: &mut Progress, topic: wicket_store::Topic) -> bool {
    let l = sh.ledger.lock().expect("ledger");
    p.watch.changed(&l, topic).unwrap_or(true)
}

/// A node's health is written to the ledger at most this often (ms), whichever of its runs'
/// connections has it first: each reports the same, every 30 s.
const HEALTH_WRITE_MS: i64 = 20_000;

/// A node feed's directory holds this file when its feed must start a new generation the next time
/// it is opened (after a restore, #154: its delta log stayed behind).
pub const REGENESIS: &str = "regenesis";

/// [`open_feed`] under the node feed's lock (`<data dir>/nodes/<name>/feed.lock`), as every
/// publisher on it holds it: for a caller outside [`SharedFeed`], such as `wicket keys certify`
/// starting a new generation, which renames the log.
pub fn open_feed_locked(name: &str, cfg: PublisherConfig) -> Result<Publisher<BoxAuthority>> {
    let _lock = feed_lock(&crate::data_dir().join("nodes").join(name))?;
    open_feed(name, cfg)
}

/// Opens node `name`'s feed: its key (created here on first use, 0600) and a certificate for it from
/// the installation's feed root. A delta log that doesn't read is an error, not set aside.
pub fn open_feed(name: &str, cfg: PublisherConfig) -> Result<Publisher<BoxAuthority>> {
    let dir = crate::data_dir().join("nodes").join(name).join("feed");
    if dir.join(REGENESIS).exists() {
        let log = dir.join("deltas.jsonl");
        if log.exists() {
            std::fs::rename(&log, dir.join("deltas.jsonl.restored")).context("setting aside the old delta log")?;
        }
        let p = open_feed_inner(name, &cfg, true, true).context("starting the feed's new generation after a restore")?;
        std::fs::remove_file(dir.join(REGENESIS))?;
        say!("[wicket] node {name}'s feed starts a new generation (restored)");
        return Ok(p);
    }
    open_feed_inner(name, &cfg, false, false)
}

/// `restored`: the kit's certificate may be older than versions the node has seen since (the lost
/// host's feed may have compacted after the kit was made), so the new version is at least the time
/// in seconds, which no version counted up from 1 reaches.
fn open_feed_inner(name: &str, cfg: &PublisherConfig, new_generation: bool, restored: bool) -> Result<Publisher<BoxAuthority>> {
    let dir = crate::data_dir().join("nodes").join(name).join("feed");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let key_path = dir.join("feed.key");
    let key = match std::fs::read_to_string(&key_path) {
        Ok(s) => {
            let seed: [u8; 32] = hex::decode(s.trim()).ok().and_then(|b| b.try_into().ok()).context("feed.key")?;
            wicket_identity::SigningKey::from_bytes(&seed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("random: {e}"))?;
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&key_path)?;
            std::io::Write::write_all(&mut f, hex::encode(seed).as_bytes())?;
            wicket_identity::SigningKey::from_bytes(&seed)
        }
        Err(e) => return Err(e.into()),
    };
    let now = wicket_feed::now_ms();
    let cert_path = dir.join("cert.jws");
    let old = std::fs::read_to_string(&cert_path).ok().and_then(|j| wicket_feed::jws::payload_unverified::<KeyCert>(&j).map(|c| (c, j)));
    let want_ttl = cfg.ttl_ms.max(wicket_feed::DEFAULT_TTL_MS);
    let kid = wicket_feed::kid(&key.verifying_key());
    // With the roots offline (#154) a certificate is used to its end (`wicket keys certify` renews it);
    // with them here, renewed when under a day is left.
    let offline = crate::roots::offline();
    let margin = renew_margin().unwrap_or(0);
    let cert_jws = match old {
        Some((c, j)) if !new_generation && c.kid == kid && c.not_after > now + margin && c.max_ttl_ms >= cfg.ttl_ms => {
            if offline && c.not_after < now + 7 * 86_400_000 {
                say_err!(
                    "[wicket] node {name}'s feed certificate ends in under a week: renew it with `WICKET_ROOTS=<dir> wicket keys certify`"
                );
            }
            j
        }
        old => {
            let root = crate::roots::feed_root_signing().with_context(|| format!("node {name}'s feed needs a certificate"))?;
            // Same key: same version (a renewal). A new key needs a new version (a re-genesis).
            let version = match &old {
                Some((c, _)) if restored => (c.version + 1).max(u64::try_from(now / 1000).unwrap_or(0)),
                Some((c, _)) if new_generation => c.version + 1,
                Some((c, _)) if c.kid == kid => c.version,
                Some((c, _)) => c.version + 1,
                None => 1,
            };
            let c = KeyCert::new(&key.verifying_key(), version, now + crate::roots::cert_ms(), want_ttl);
            let j = wicket_feed::sign(&root, wicket_feed::TYP_KEY, &c);
            std::fs::write(&cert_path, &j)?;
            j
        }
    };
    let authz_root = crate::roots::authz_root_public()?;
    Ok(Publisher::open_with(&dir, name, &crate::roots::feed_root_public()?, key, &cert_jws, cfg.clone(), authz_root)?)
}

/// A node's feed, shared by every process that publishes to it (each run on the node, and each
/// link relay), and within a process by every run on the node ([`SharedFeed::open`] hands them the
/// same one: one publisher per node per process). Every use holds `<data dir>/nodes/<name>/feed.lock`
/// for its duration, and first applies the deltas other processes appended since
/// ([`Publisher::refresh`]), so each delta extends the one true head.
pub struct SharedFeed {
    name: String,
    cfg: PublisherConfig,
    dir: PathBuf,
    /// The publisher, and when its certificate was last compared with the one on disk (Unix ms).
    inner: Mutex<(Publisher<BoxAuthority>, i64)>,
}

/// How long before its end a feed's certificate is renewed when the feed is opened: a day, with the
/// roots on this host; none without them (`wicket keys certify` renews it then).
fn renew_margin() -> Option<i64> {
    (!crate::roots::offline()).then_some(86_400_000)
}

/// Whether a publisher whose certificate couldn't be renewed may go on publishing with the one it
/// holds: only while that is valid at `now` (Unix ms), and the certificate on disk (`cert.jws`) is
/// of the same version. One on disk that is missing or doesn't read isn't the same version.
fn keep_after_failed_renewal(held: &KeyCert, on_disk: Option<&str>, now: i64) -> bool {
    let disk_version = on_disk.and_then(wicket_feed::jws::payload_unverified::<KeyCert>).map(|c| c.version);
    held.not_after > now && disk_version == Some(held.version)
}

/// How often a feed's certificate is checked for nearing its end, to be renewed.
const CERT_CHECK_MS: i64 = 3_600_000;

/// The node feeds this process publishes to, by directory.
static FEEDS: std::sync::LazyLock<Mutex<std::collections::HashMap<PathBuf, std::sync::Weak<SharedFeed>>>> =
    std::sync::LazyLock::new(Default::default);

/// A held feed: the publisher, current, with the feed's lock taken.
pub struct FeedGuard<'a> {
    g: std::sync::MutexGuard<'a, (Publisher<BoxAuthority>, i64)>,
    name: &'a str,
    dir: &'a Path,
    /// The last statement time when the lock was taken.
    issued: i64,
    _lock: std::fs::File,
}

impl std::ops::Deref for FeedGuard<'_> {
    type Target = Publisher<BoxAuthority>;
    fn deref(&self) -> &Publisher<BoxAuthority> {
        &self.g.0
    }
}

impl std::ops::DerefMut for FeedGuard<'_> {
    fn deref_mut(&mut self) -> &mut Publisher<BoxAuthority> {
        &mut self.g.0
    }
}

impl Drop for FeedGuard<'_> {
    fn drop(&mut self) {
        if let Some(e) = self.g.0.take_checkpoint_error() {
            // Only the next open is slower: tried again at the next interval.
            say_err!("[wicket] could not write node {}'s feed checkpoint: {e}", self.name);
        }
        if self.g.0.last_issued() != self.issued {
            let _ = std::fs::write(self.dir.join("feed/issued"), self.g.0.last_issued().to_string());
        }
    }
}

fn feed_lock(dir: &Path) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    std::fs::create_dir_all(dir)?;
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("feed.lock"))?;
    // SAFETY: flock on a file descriptor this function owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error()).context("locking the node's feed");
    }
    Ok(f)
}

/// The protocol node `name` last talked to this control host (`<data dir>/nodes/<name>/protocol`,
/// written at each connection's welcome, and cleared when a connection drops or is refused), if
/// known: with [`live_protocols`], what decides, before anything is published to its feed or it is
/// chosen for a box, whether it can read a record (#664, #691).
pub fn known_protocol(name: &str) -> Option<u32> {
    let dir = crate::data_dir().join("nodes").join(name);
    std::fs::read_to_string(dir.join("protocol")).ok()?.trim().parse().ok()
}

/// Notes the protocol a connection to node `name` talks (see [`known_protocol`]). Best effort: a
/// note that can't be written leaves the last one (or none, which refuses what needs a newer node).
pub fn note_protocol(name: &str, proto: u32) {
    if known_protocol(name) == Some(proto) {
        return;
    }
    let dir = crate::data_dir().join("nodes").join(name);
    let tmp = dir.join(format!("protocol.{}", std::process::id()));
    let ok = std::fs::create_dir_all(&dir).is_ok() && std::fs::write(&tmp, proto.to_string()).is_ok();
    if !ok || std::fs::rename(&tmp, dir.join("protocol")).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Forgets node `name`'s protocol: a connection to it dropped, or was refused, so what it talks
/// now isn't known until one connects again (a node restarted on an older build, #691).
pub fn forget_protocol(name: &str) {
    let _ = std::fs::remove_file(crate::data_dir().join("nodes").join(name).join("protocol"));
}

/// One live connection to a node, noted while it lasts (`<data dir>/nodes/<name>/sessions/<pid>-<n>`,
/// holding its protocol; removed when dropped): what [`live_protocols`] reads, in every process.
pub struct LiveSession(PathBuf);

impl Drop for LiveSession {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Notes a connection to node `name` that talks `proto`: the node's protocol, and this live session.
pub fn note_session(name: &str, proto: u32) -> LiveSession {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    note_protocol(name, proto);
    let dir = crate::data_dir().join("nodes").join(name).join("sessions");
    let path = dir.join(format!("{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&path, proto.to_string()));
    LiveSession(path)
}

/// The protocols node `name`'s live connections talk, from every process on this host (the notes
/// of processes no longer running are removed).
pub fn live_protocols(name: &str) -> Vec<u32> {
    let dir = crate::data_dir().join("nodes").join(name).join("sessions");
    let Ok(rd) = std::fs::read_dir(&dir) else { return vec![] };
    let mut out = vec![];
    for e in rd.flatten() {
        let file = e.file_name().to_string_lossy().into_owned();
        let pid = file.split('-').next().and_then(|p| p.parse::<u32>().ok());
        if pid.is_none_or(|p| !Path::new(&format!("/proc/{p}")).exists()) {
            let _ = std::fs::remove_file(e.path());
            continue;
        }
        if let Some(v) = std::fs::read_to_string(e.path()).ok().and_then(|v| v.trim().parse().ok()) {
            out.push(v);
        }
    }
    out
}

/// What node `name` is known to talk now: the lowest of its live connections' protocols, or with
/// none live its note.
fn node_protocol_now(name: &str) -> Option<u32> {
    live_protocols(name).into_iter().min().or_else(|| known_protocol(name))
}

/// The protocol a node must talk to be sent `zone`'s record: [`wicket_chan::chan::DECODE_SLASH`]
/// if it decides an encoded slash (a node before it parses the record strictly and refuses it,
/// stalling its whole feed), otherwise any.
pub fn protocol_needed(zone: &wicket_core::ZoneSpec) -> u32 {
    if zone.reach.iter().any(|r| !r.decode_slash.is_empty()) {
        wicket_chan::chan::DECODE_SLASH
    } else {
        0
    }
}

/// Readies `zone` for a node talking `proto` (None: not known), given which secrets `is_set` (#415).
/// At [`wicket_chan::chan::LIVE_SECRETS`] or later every rule goes. Otherwise, a node whose protocol
/// isn't known included (a re-attach whose note was lost: what the node's feed holds can't tell a
/// node at 23 from one below that had every secret set), it is taken as older: its optional
/// `inject` rules whose secrets aren't set now are dropped, and returned. That fails narrow: such a
/// host's requests go without the secret for the run's life, and the session is never ended for
/// it. Also whether the zone goes out with optional rules whatever their secrets, which only a node
/// at that protocol may then carry.
pub fn zone_for_node(
    zone: &mut ZoneSpec,
    proto: Option<u32>,
    is_set: impl Fn(&str) -> bool,
) -> (Vec<wicket_core::manifest::InjectRule>, bool) {
    match proto.is_some_and(|p| p >= wicket_chan::chan::LIVE_SECRETS) {
        true => (vec![], zone.inject.iter().any(|i| i.optional)),
        false => (zone.drop_unset_optional_injections(is_set), false),
    }
}

/// Refuses to publish `zone`'s record to node `name` unless the node is known to read it: decided
/// before the record goes in the node's feed, which every session to the node carries (#664).
pub fn check_protocol(name: &str, zone: &wicket_core::ZoneSpec) -> Result<()> {
    let need = protocol_needed(zone);
    if need == 0 {
        return Ok(());
    }
    match node_protocol_now(name) {
        Some(p) if p >= need => Ok(()),
        known => bail!(
            "zone {} decides an encoded slash (decode_slash), which needs a node at protocol {need}, and node {name} {}: \
             update the node (wicket self update --nodes), or place the box elsewhere",
            zone.name,
            match known {
                Some(p) => format!("talks {p}"),
                None if name == crate::localnode::NAME => {
                    "is running a build whose protocol isn't known yet (it is noted at its next connection: run a box without decode_slash there, or restart it with this build)".to_string()
                }
                None => "hasn't connected since it was last cut off (its protocol isn't known)".to_string(),
            }
        ),
    }
}

fn last_issued(feed_dir: &Path) -> i64 {
    std::fs::read_to_string(feed_dir.join("issued")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(i64::MIN)
}

impl SharedFeed {
    /// Node `name`'s feed for this process: the one its other runs on the node use, or opened now.
    pub fn open(name: &str, cfg: PublisherConfig) -> Result<Arc<SharedFeed>> {
        let dir = crate::data_dir().join("nodes").join(name);
        // The map only holds handles, each insert or removal whole: one a panic left poisoned is
        // still sound. It isn't held while a feed opens (the node's lock, the log read), so nodes
        // open in parallel; two runs opening the same node at once keep the first one in.
        let feeds = || FEEDS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(f) = feeds().get(&dir).and_then(std::sync::Weak::upgrade) {
            return Ok(f);
        }
        let f = Arc::new(SharedFeed::open_new(name, cfg)?);
        let mut feeds = feeds();
        if let Some(first) = feeds.get(&dir).and_then(std::sync::Weak::upgrade) {
            return Ok(first);
        }
        feeds.retain(|_, w| w.strong_count() > 0);
        feeds.insert(dir, Arc::downgrade(&f));
        Ok(f)
    }

    fn open_new(name: &str, cfg: PublisherConfig) -> Result<SharedFeed> {
        let dir = crate::data_dir().join("nodes").join(name);
        let _lock = feed_lock(&dir)?;
        let mut p = open_feed(name, cfg.clone())?;
        // Every run adds a few deltas: once the log is large and no box holds authority from it
        // (each run drops its token at exit), the feed starts a new generation, which nodes take as
        // a snapshot. (Opening doesn't replay it, from its checkpoint; this bounds its size.)
        let log = p.log_path().to_path_buf();
        let cap = std::env::var("WICKET_FEED_COMPACT_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(COMPACT_BYTES);
        // (Only with the feed root at hand: a new generation needs it.)
        if std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0) > cap
            && p.state().zones.is_empty()
            && crate::roots::feed_root_signing().is_ok()
        {
            std::fs::rename(&log, log.with_extension("jsonl.old")).context("setting the old delta log aside")?;
            p = open_feed_inner(name, &cfg, true, false)?;
        }
        p.note_issued(last_issued(&dir.join("feed")));
        Ok(SharedFeed { name: name.into(), cfg, dir, inner: Mutex::new((p, wicket_feed::now_ms())) })
    }

    /// The feed, locked and current.
    pub fn lock(&self) -> Result<FeedGuard<'_>> {
        let lock = feed_lock(&self.dir)?;
        // A run that panicked holding the feed may have left the publisher half-updated (a commit
        // that wrote its delta but didn't apply it): it is opened again from the files, and the
        // other runs on the node carry on. The poison is cleared only once that worked, so a
        // reopen that fails leaves it for the next lock to try again, never trusting the old one.
        let (mut g, poisoned) = match self.inner.lock() {
            Ok(g) => (g, false),
            Err(e) => (e.into_inner(), true),
        };
        let reopen = |g: &mut (Publisher<BoxAuthority>, i64)| -> Result<()> {
            let issued = g.0.last_issued();
            g.0 = open_feed(&self.name, self.cfg.clone())?;
            g.0.note_issued(issued);
            Ok(())
        };
        // What other processes appended first: a publisher that can't follow the log must be
        // opened again, or nothing may be published.
        if poisoned || !matches!(g.0.refresh(), Ok(Refreshed::Current | Refreshed::Applied(_))) {
            reopen(&mut g)?;
            self.inner.clear_poison();
        } else {
            let now = wicket_feed::now_ms();
            // Another process (or `wicket keys certify`) renewed the certificate, or it nears its
            // end (`open_feed` renews it in the same window, with the roots at hand; checked
            // hourly, as without them it can't).
            let on_disk = std::fs::read_to_string(self.dir.join("feed/cert.jws")).ok();
            let mut cert_due = on_disk.as_deref() != Some(g.0.key_frame().jws.as_str());
            if now >= g.1.saturating_add(CERT_CHECK_MS) {
                g.1 = now;
                cert_due |= renew_margin().is_some_and(|m| g.0.cert().not_after <= now + m);
            }
            // A renewal that fails keeps the publisher as it is, current, so the commit or
            // revocation this lock is for still goes out; but only while its certificate is still
            // valid and the one on disk is of the same version. A higher version on disk is a new
            // generation: publishing under the old one would be refused by the node, and hide it.
            if cert_due {
                if let Err(e) = reopen(&mut g) {
                    if !keep_after_failed_renewal(g.0.cert(), on_disk.as_deref(), now) {
                        return Err(e.context(format!(
                            "node {}'s feed certificate can't be renewed, and the one held is past its end or of another version than the one on disk",
                            self.name
                        )));
                    }
                    say_err!("[wicket] could not renew node {}'s feed certificate ({e:#}); publishing with the current one", self.name);
                }
            }
        }
        g.0.note_issued(last_issued(&self.dir.join("feed")));
        let issued = g.0.last_issued();
        Ok(FeedGuard { g, name: &self.name, dir: &self.dir, issued, _lock: lock })
    }
}

/// What the run loop gets: the box's stdio as streams, its exit, and a handle to stop it.
/// What the node said when it started the box: the image's digest it started (#192) and where the
/// start's time went there (#287), or why not.
type StartedAs = std::result::Result<(Option<String>, Vec<wicket_core::timing::Span>), String>;

pub struct NodeBox {
    /// The image's digest as the node started it (#192); None when this host didn't start it now
    /// (re-attached, or taken over).
    pub image_digest: Option<String>,
    pub stdin: Option<tokio::io::DuplexStream>,
    pub stdout: tokio::io::DuplexStream,
    pub stderr: tokio::io::DuplexStream,
    pub exit: oneshot::Receiver<i32>,
    pub ctl: Arc<NodeCtl>,
}

/// What a supervisor gives the box again when it hears from its node (#445, #453): on its first
/// resume of a run it took over, the messages and prompts the supervisor before it took and the
/// box never had; on every later resume (a reconnect), the messages it gave on the link that
/// dropped and the node never said the box had. Its own prompts are in its stdin buffer, sent
/// again from the node's count. How many messages, and prompts.
fn requeue_on_resume(l: &wicket_store::Ledger, run: &str, first: bool, took_over: bool, stdin_received: u64) -> (usize, usize) {
    match (first, took_over) {
        (true, true) => (l.requeue_in_flight(run).unwrap_or(0), l.requeue_prompts(run, stdin_received).map(|v| v.len()).unwrap_or(0)),
        (true, false) => (0, 0),
        (false, _) => (l.requeue_in_flight(run).unwrap_or(0), 0),
    }
}

/// Stops and revokes a run's box on its node, connected or not (sent on the next connect).
pub struct NodeCtl {
    node: String,
    pub run: String,
    link: Mutex<Option<chan::Out>>,
    publisher: Arc<SharedFeed>,
    /// The box's tokens' block 0 revocation ids (hex), and until when each matters (Unix ms): one
    /// per mint, the first at the box's start and one more for each renewal of its authority (#56).
    /// The last is the token the node holds now.
    token_roots: Mutex<Vec<(String, i64)>>,
    killed: AtomicBool,
    /// Calls on the box (pause, processes, exec, link sockets) over the run's connection.
    pub calls: Arc<Calls>,
    keep: bool,
    forgotten: AtomicBool,
    done: tokio::sync::Notify,
    /// How far into the box's stdout and stderr this supervisor got.
    next: [std::sync::atomic::AtomicU64; 2],
    /// The protocol version the current connection talks (0: none yet).
    proto: std::sync::atomic::AtomicU32,
    /// Why the box ended, as its node reported with its exit (#185).
    exit_cause: Mutex<Option<String>>,
    /// Where in the box's stdin (bytes since the run's start) what this supervisor writes begins:
    /// 0 for a box it started, its node's count for one it re-attached to, once the node said
    /// (#445). Operator prompts are recorded by where they are in it.
    pub stdin_base: std::sync::OnceLock<u64>,
}

impl NodeCtl {
    /// When the box's authority ends now (Unix ms): its current token's block 0.
    fn authority_until(&self) -> i64 {
        self.token_roots.lock().expect("token roots").last().map_or(0, |r| r.1)
    }

    fn send(&self, f: Frame) -> bool {
        self.link.lock().expect("link").as_ref().is_some_and(|l| l.send(f).is_ok())
    }

    /// Why the box ended, if its node said (#185): wicket's own stop, out of memory, a signal.
    pub fn exit_cause(&self) -> Option<String> {
        self.exit_cause.lock().expect("exit cause").clone()
    }

    /// How far into the box's stdout and stderr this supervisor got.
    pub fn offsets(&self) -> (u64, u64) {
        (self.next[0].load(Ordering::SeqCst), self.next[1].load(Ordering::SeqCst))
    }

    /// Whether the box's files are still kept on the node (after its exit, until forgotten).
    fn kept(&self) -> bool {
        self.keep && !self.forgotten.load(Ordering::SeqCst)
    }

    /// The node may delete the box's files now (its state was fetched); the connection then ends.
    pub fn forget(&self) {
        if self.keep && !self.forgotten.swap(true, Ordering::SeqCst) {
            self.calls.forget(&self.run);
            self.done.notify_one();
        }
    }

    /// Stops the box (now if connected, else as soon as the node is reachable again).
    pub fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        self.send(Frame::Msg(Msg::Kill { run: self.run.clone() }));
    }

    /// Revokes the run on the node (every op refused from the moment the delta applies), then stops it.
    pub fn revoke(&self) {
        let now = wicket_feed::now_ms();
        // Every block 0 the box was minted with: a child derived from an earlier one goes too.
        let mut changes = vec![Change::Revoke { kind: RevokeKind::Run, id: self.run.clone(), until: now + 86_400_000 }];
        for (id, until) in self.token_roots.lock().expect("token roots").iter() {
            changes.push(Change::Revoke { kind: RevokeKind::Token, id: id.clone(), until: (*until).max(now + 86_400_000) });
        }
        let frame = self.publisher.lock().and_then(|mut p| p.commit(changes, now).map_err(Into::into));
        match frame {
            Ok(f) => {
                self.send(Frame::Feed(f.to_line().trim_end().as_bytes().to_vec()));
            }
            Err(e) => say_err!("[wicket] could not publish the revocation of {} to {}: {e}", self.run, self.node),
        }
        self.kill();
    }
}

/// Everything about the run the connection manager needs.
/// A child the node started for this run's box (#164), as it reports it.
#[derive(Clone, Debug)]
pub struct Spawned {
    pub child: String,
    pub manifest: String,
    pub image: String,
    pub session: String,
    pub started_ms: i64,
    /// Its image's digest as the node started it (#192).
    pub digest: Option<String>,
}

/// Takes over a child its node started for this run's box (#164): checks it again as `spawn` here
/// would, records it, and supervises it as a run of its own. Err: refused, and the node stops it.
pub type Adopter = Arc<dyn Fn(Spawned) -> std::result::Result<(), String> + Send + Sync>;

pub struct Start {
    /// The node's name, and how to reach it.
    pub node: String,
    pub via: Via,
    pub tenant: TenantId,
    /// The installation's org policy, compiled for this box (#51): block 0's org layer.
    pub org: Option<Arc<wicket_authz::OrgLayer>>,
    pub run: RunId,
    pub zone: ZoneSpec,
    pub dir: PathBuf,
    pub ledger: Arc<Mutex<Ledger>>,
    pub events: mpsc::UnboundedSender<wicket_proxy::Event>,
    pub start: BoxStart,
    /// How long the box's authority has left from now (#153): its token's block 0 ends then, and
    /// its node stops the box. Counted from the run's start, so a re-attach doesn't extend it.
    pub authority_secs: u64,
    /// The latest a renewal may take the box's authority to, from now (#56): its run's hard end.
    pub authority_cap_secs: u64,
    /// What the run's agent may grant ends no later than this (Unix seconds): kept at the box's
    /// authority as it is renewed.
    pub authority_until: Option<Arc<std::sync::atomic::AtomicI64>>,
    /// Calls on boxes over this run's connection (made before the run's proxies, which use them).
    pub calls: Arc<Calls>,
    /// Trees sent to the node before the box starts: (tree, local directory, top-level names left out).
    pub trees: Vec<(String, PathBuf, Vec<String>)>,
    /// Who in the box made a request (the run's own reading of the agent's events).
    pub attribute: Option<wicket_proxy::Attributor>,
    /// Re-attach to a box already on the node (#151): no start; its output resumes from
    /// `resume_from` (stdout, stderr), what the last supervisor had.
    pub attach: bool,
    pub resume_from: [u64; 2],
    /// Keep the box's files on the node after it exits, until [`NodeCtl::forget`] (its state is
    /// fetched first).
    pub keep: bool,
    /// The run's own model proxy: it sends the node budget slices and takes the node's spend
    /// (#152). None: no model route.
    pub llm: Option<Arc<wicket_proxy::llm::Budget>>,
    /// Where the secrets the node fetches come from (#152).
    pub vault: wicket_proxy::vault::Vault,
    /// The run's credential swaps, with their real sources (#257): `start.swaps` names them for the
    /// node, which fetches each on first use.
    pub swaps: Vec<wicket_proxy::CredentialSwap>,
    /// A re-attached long-lived agent: its earlier spend, this activation's included, is already in
    /// the model proxy's `prior` counters, so the node's first report is the base its later ones
    /// count from (#152).
    pub spent_counted: bool,
    /// The control host's half of the box's gateway (#257 slice 4b): it answers the node's
    /// [`Msg::Call`]s.
    pub gateway: Arc<crate::gateway::Gateway>,
    /// What answers the box's `spawn` calls (#257 slice 4c): its children's supervisors run in this
    /// process. None: it may start none.
    pub spawn: Option<Arc<crate::spawn::SpawnCtx>>,
    /// Takes over children the node starts for the box (#164): None, it may start none.
    pub adopt: Option<Adopter>,
    /// Where the box start's time goes (#287): this host's steps, the node's (`node.start.*`), and
    /// the box's first output and first model request when they come.
    pub timings: Arc<Timings>,
    /// The installation's `names:` settings as the run read them when it started (#575): the host
    /// ports its public names are published on come from them. None: no public names.
    pub names: Option<Arc<wicket_names::NamesConfig>>,
}

struct Shared {
    /// The zone was published with its optional `inject` rules whatever their secrets (#415): only a
    /// node at protocol 23 may carry its record.
    optional_rules: bool,
    node: String,
    tenant: TenantId,
    run: RunId,
    zone: ZoneSpec,
    dir: PathBuf,
    ledger: Arc<Mutex<Ledger>>,
    events: mpsc::UnboundedSender<wicket_proxy::Event>,
    streams: [u64; 3],
    via: Via,
    ctl: Arc<NodeCtl>,
    cfg: PublisherConfig,
    issuer: Arc<wicket_identity::Issuer>,
    /// The installation CA, which signs the node's renewed CA (#416), if this host has one.
    installation_ca: Option<Arc<wicket_proxy::ca::InstallationCa>>,
    /// The box's base token (block 0), and the key that signs its grant blocks. Re-minted when its
    /// authority is renewed (#56).
    token_issuer: Mutex<wicket_feed::Issuer>,
    approver: wicket_authz::SigningKey,
    /// What block 0 is minted from, for a renewal's re-mint: the box's image and org layer.
    image: String,
    org: Option<Arc<wicket_authz::OrgLayer>>,
    authority_until: Option<Arc<std::sync::atomic::AtomicI64>>,
    /// Re-attaching to a box already on the node (#151), and the grants its token carries already.
    attach: bool,
    carried: Vec<LiveGrant>,
    /// The host ports the box's first record carried (#575 step 4c).
    ports_at_start: Vec<wicket_feed::PublishedPort>,
    /// Who in the box made a request, as the run reads the agent's event stream (for asks the node
    /// didn't attribute).
    attribute: Option<wicket_proxy::Attributor>,
    llm: Option<Arc<wicket_proxy::llm::Budget>>,
    vault: wicket_proxy::vault::Vault,
    /// What the node had counted when this supervisor took over, if that was already counted.
    spent_base: Mutex<Option<Option<wicket_proxy::llm::Spent>>>,
    /// Answers the node's [`Msg::Call`]s for the box's gateway (#257).
    gateway: Arc<crate::gateway::Gateway>,
    /// Answers the box's `spawn` calls (#257 slice 4c).
    spawn: Option<Arc<crate::spawn::SpawnCtx>>,
    /// The run's credential swaps, which its node makes (#257): what this host releases to it for
    /// them ([`fetch_secret`]).
    swaps: Vec<wicket_proxy::CredentialSwap>,
    adopt: Option<Adopter>,
    /// Where the node may pull the box's pinned image from (#191), and the registry's secret, which
    /// it may fetch for that pull only.
    pull: Option<crate::registry::Source>,
    /// Set while the node pulls the box's image: the only time it may fetch the registry's secret.
    pulling: AtomicBool,
    timings: Arc<Timings>,
    /// The box's first output has been seen (#287: `box.first_output`).
    first_output: AtomicBool,
    /// The installation's `names:` settings (#575 step 4c).
    names: Option<Arc<wicket_names::NamesConfig>>,
}

/// Mints box `run`'s block 0, until `not_after` (Unix seconds): by the authority root, or by its
/// certified issuing key while the roots are offline (#154), compiled from Cedar (#51): the zone's
/// policy and, if the installation has one, the org policy, for this box as it is now (its zone's
/// groups, its principal, its spawn depth). At the box's start, and again when its authority is
/// renewed (#56): the same block 0 with a later end.
#[allow(clippy::too_many_arguments)]
fn mint_token(
    tenant: &TenantId,
    run: &RunId,
    zone: &ZoneSpec,
    image: &str,
    org: Option<&wicket_authz::OrgLayer>,
    approver: &wicket_authz::SigningKey,
    not_after: u64,
    t: Option<&Timings>,
) -> Result<wicket_feed::Issuer> {
    let until_ms = i64::try_from(not_after).unwrap_or(i64::MAX / 1000).saturating_mul(1000);
    let (minter, issuer_cert) = crate::roots::minting_key(until_ms)?;
    let compiled = t.map(|t| t.span("token.policy"));
    let ceiling = wicket_policy::ceiling(zone, &run.0, not_after, vec![approver.public()], &[image.to_string()], org.cloned())
        .context("compiling the box's policy")?;
    drop(compiled);
    let _minted = t.map(|t| t.span("token.mint"));
    let mut token_issuer = wicket_feed::Issuer::from_ceiling(&minter, &tenant.0, &format!("run:{run}"), &run.0, 0, zone, &ceiling)
        .context("minting the box's token")?;
    token_issuer.issuer_cert = issuer_cert;
    Ok(token_issuer)
}

/// Connects to the node, publishes the run's zone, starts the box there, and returns its stdio.
pub async fn start(s: Start) -> Result<NodeBox> {
    let mut s = s;
    let t = s.timings.clone();
    let keys = t.span("token.keys");
    let name = s.node.clone();
    // A node below protocol 23 would take an optional rule whose secret isn't set as no credential
    // for its host until a fetch, letting plain HTTP to it through (#415). It gets the zone as
    // before: without such rules, whose hosts then go without them for the run's whole life.
    // Before anything is minted or published: the record goes in the node's feed, which every
    // session to it carries, so a node that can't read it is never sent it (#664).
    check_protocol(&name, &s.zone)?;
    let issuer = Arc::new(crate::issuer()?);
    let cfg = feed_config();
    let feed = SharedFeed::open(&name, cfg.clone())?;
    let (dropped, optional_rules) = zone_for_node(&mut s.zone, node_protocol_now(&name), |n| s.vault.has(n));
    for i in dropped {
        say!(
            "[wicket] node {name} doesn't take secrets set later (protocol 23): requests to {} go without {:?} for this run",
            i.host,
            i.secret
        );
    }
    let now = wicket_feed::now_ms();
    let paths = crate::enrol::Paths::installation();
    // Every grant has a lifetime (#153), block 0 included: the zone's `limits.authority` (default
    // the run's timeout), counted from the run's start. The node works for the box until then and
    // stops it at that time, whether or not it can reach this host. A renewal (#56) moves it, never
    // past the run's hard end; a re-attach keeps a renewal made before it.
    let now_s = now / 1000;
    let cap = now_s.saturating_add(i64::try_from(s.authority_cap_secs.max(s.authority_secs)).unwrap_or(i64::MAX / 2));
    let mut until_s = now_s.saturating_add(i64::try_from(s.authority_secs.max(1)).unwrap_or(i64::MAX / 2));
    if s.attach {
        if let Some((renewed, _)) = s.ledger.lock().expect("ledger").run_authority(&s.run.0)? {
            until_s = until_s.max(renewed.min(cap));
        }
    }
    let not_after = u64::try_from(until_s).unwrap_or(0);
    let approver = crate::enrol::token_key(&paths.approver_key)?;
    keys.end();
    let token_issuer = mint_token(&s.tenant, &s.run, &s.zone, &s.start.image, s.org.as_deref(), &approver, not_after, Some(t.as_ref()))?;
    s.ledger.lock().expect("ledger").set_run_authority(&s.run.0, until_s, cap)?;
    if let Some(a) = &s.authority_until {
        a.store(until_s, Ordering::SeqCst);
    }
    s.ledger.lock().expect("ledger").set_run_policy(&s.run.0, s.org.as_ref().map(|o| o.version.as_str()))?;
    // A re-attached run's token carries the grants the ledger already handed this node for it, so
    // nothing a human approved is lost with the supervisor that published them.
    let carried: Vec<LiveGrant> = match s.attach {
        false => vec![],
        true => {
            let now_s = wicket_store::now();
            let gs = s.ledger.lock().expect("ledger").grants_for_run(&s.run.0).unwrap_or_default();
            gs.into_iter()
                .filter(|g| g.node.as_deref() == Some(name.as_str()) && !g.revoked && g.expires_at > now_s)
                // Before a connection says the node's protocol: each for its own path (#257 4a).
                .map(|g| live_grant(&s.tenant, &s.run, &s.zone.name, &token_issuer, &g, false))
                .collect()
        }
    };
    let mut authority = token_issuer.publish(&approver, &carried).context("the box's token")?;
    // And, for a node that reads them, the host ports its public names have already (#575 step 4c):
    // a re-attach's token without them would close the node's listeners until the first sync.
    authority.ports = match (s.names.as_ref().and_then(|n| n.public.as_ref()), reads_ports(&name)) {
        (Some(public), true) => ports_for(&s.ledger.lock().expect("ledger"), public, &s.run, &name, wicket_store::now()),
        _ => vec![],
    };
    // What the node attenuates a child's token from, deciding its spawns (#164).
    if let Some(sp) = s.start.edge.as_mut().and_then(|e| e.spawn.as_mut()) {
        use base64::Engine;
        sp.base = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_issuer.base.to_bytes()?);
        sp.grant_keys = vec![approver.public()];
    }
    // Several runs share the node's feed. Tokens of runs that have ended (whose own exit didn't
    // drop them: a run killed hard) go in the same delta, so the feed and the node's snapshot don't
    // grow with every run.
    let published = t.span("feed.publish");
    let (target_epoch, ports_at_start) = {
        let mut publisher = feed.lock()?;
        let ended: Vec<String> = {
            let l = s.ledger.lock().expect("ledger");
            publisher
                .state()
                .zones
                .keys()
                .filter(|k| **k != s.run.0 && l.run_status(k).ok().flatten().as_deref() != Some("running"))
                .cloned()
                .collect()
        };
        let mut changes: Vec<Change<BoxAuthority>> = ended.into_iter().map(|name| Change::DropZone { name }).collect();
        changes.push(Change::PutZone { zone: authority });
        // Again under the feed's lock, just before the record goes in: the node's live sessions
        // (any process's) may have connected at an older protocol since the check above (#691).
        check_protocol(&name, &s.zone)?;
        gate_ports(&mut changes, node_protocol_now(&name));
        // What the node's record carries, as committed (#796 review, L2).
        let carried_ports = changes
            .iter()
            .find_map(|c| match c {
                Change::PutZone { zone } => Some(zone.ports.clone()),
                _ => None,
            })
            .unwrap_or_default();
        publisher.commit(changes, now).context("publishing the box's token")?;
        (publisher.epoch(), carried_ports)
    };
    // That token carries grants only: a re-attached run's standing rules aren't in it until its
    // first sync puts them back, so none reads as on the node meanwhile (#752 review, F1).
    s.ledger.lock().expect("ledger").standing_requeued(&s.run.0).context("recording the box's standing rules")?;
    published.end();
    let recording = t.span("authority.record");
    let token_root = (token_issuer.block_ids()[0].clone(), until_s.saturating_mul(1000));
    // What fences a wake of the agent elsewhere while this box may still run (#153).
    record_authority(&s.dir, &name, token_root.1 + 1000).context("recording the box's authority")?;
    // Records the node ships are filed under this run only once the ledger says it runs there (#120).
    s.ledger.lock().expect("ledger").set_run_node(&s.run.0, &name).context("recording the run's node")?;
    recording.end();
    let ctl = Arc::new(NodeCtl {
        node: name.clone(),
        run: s.run.0.clone(),
        link: Mutex::new(None),
        publisher: feed,
        token_roots: Mutex::new(vec![token_root]),
        killed: AtomicBool::new(false),
        calls: s.calls.clone(),
        keep: s.keep,
        forgotten: AtomicBool::new(false),
        done: tokio::sync::Notify::new(),
        next: [std::sync::atomic::AtomicU64::new(s.resume_from[0]), std::sync::atomic::AtomicU64::new(s.resume_from[1])],
        proto: std::sync::atomic::AtomicU32::new(0),
        exit_cause: Mutex::new(None),
        stdin_base: std::sync::OnceLock::new(),
    });
    let shared = Arc::new(Shared {
        optional_rules,
        node: name.clone(),
        tenant: s.tenant,
        run: s.run,
        zone: s.zone,
        dir: s.dir,
        ledger: s.ledger,
        events: s.events,
        streams: s.start.streams,
        via: s.via,
        ctl: ctl.clone(),
        cfg,
        issuer,
        token_issuer: Mutex::new(token_issuer),
        installation_ca: installation_ca().map(Arc::new),
        approver,
        image: s.start.image.clone(),
        org: s.org.clone(),
        authority_until: s.authority_until.clone(),
        attribute: s.attribute.clone(),
        llm: s.llm.clone(),
        vault: s.vault.clone(),
        spent_base: Mutex::new(s.spent_counted.then_some(None)),
        gateway: s.gateway.clone(),
        spawn: s.spawn.clone(),
        swaps: s.swaps.clone(),
        adopt: s.adopt.clone(),
        attach: s.attach,
        carried,
        ports_at_start,
        pull: match &s.start.image_pin {
            Some(_) => crate::images_policy::load()?.registry_for(&s.start.image).map(|(r, repository)| crate::registry::Source {
                host: r.host,
                repository,
                auth_hosts: r.auth_hosts,
                blob_hosts: r.blob_hosts,
                secret: r.secret,
            }),
            None => None,
        },
        pulling: AtomicBool::new(false),
        timings: t.clone(),
        first_output: AtomicBool::new(false),
        names: s.names.clone(),
    });
    let (stdin_ours, stdin_theirs) = tokio::io::duplex(256 * 1024);
    let (stdout_theirs, stdout_ours) = tokio::io::duplex(1 << 20);
    let (stderr_theirs, stderr_ours) = tokio::io::duplex(1 << 20);
    let (exit_tx, exit_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (started_tx, started_rx) = oneshot::channel();
    let interactive = s.start.interactive;
    let ready_span = t.span("node.ready");
    tokio::spawn(manage(
        shared.clone(),
        Io { stdin: stdin_theirs, stdout: Some(stdout_theirs), stderr: Some(stderr_theirs), exit: Some(exit_tx) },
        Some(ready_tx),
        Some(started_tx),
        target_epoch,
    ));
    match tokio::time::timeout(std::time::Duration::from_secs(60), ready_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => return Err(e),
        _ => bail!("node {name} did not come up fresh on the feed within 60 s"),
    }
    ready_span.end();
    let mut image_digest = None;
    if !s.attach {
        let trees = t.span("trees");
        for (tree, src, exclude) in &s.trees {
            let x: Vec<&str> = exclude.iter().map(String::as_str).collect();
            ctl.calls.put_tree(&ctl.run, tree, src, &x).await.with_context(|| format!("sending the box's {tree} to node {name}"))?;
        }
        trees.end();
        let start = s.start;
        ca_current(&shared, ctl.proto.load(Ordering::SeqCst)).await;
        // A remote node gets a pinned image it lacks from here, verified there before it imports it
        // (#191); the control host's own node shares its runtime.
        if let (Some(pin), crate::nodecall::Via::Ssh(_)) = (&start.image_pin, &shared.via) {
            let pull = shared.pull.as_ref();
            shared.pulling.store(pull.is_some(), Ordering::SeqCst);
            let _delivering = t.span("image.deliver");
            let got = deliver_image(&ctl.calls, &name, &ctl.run, &start.image, pin, pull).await;
            shared.pulling.store(false, Ordering::SeqCst);
            got.with_context(|| format!("getting image {pin} to node {name}"))?;
        }
        let sent = std::time::Instant::now();
        if !ctl.send(Frame::Msg(Msg::Start(Box::new(start)))) {
            bail!("lost node {name} while starting the box");
        }
        image_digest = match tokio::time::timeout(std::time::Duration::from_secs(120), started_rx).await {
            Ok(Ok(Ok((d, spans)))) => {
                // BoxStart → Started, and the node's own steps within it, placed from when it was
                // sent (they start up to the channel's one-way latency later).
                t.since("node.start", sent);
                t.nest("node.start.", sent, &spans);
                d
            }
            Ok(Ok(Err(e))) => bail!("node {name} could not start the box: {e}"),
            _ => bail!("node {name} did not start the box within 120 s"),
        };
    }
    Ok(NodeBox { image_digest, stdin: interactive.then_some(stdin_ours), stdout: stdout_ours, stderr: stderr_ours, exit: exit_rx, ctl })
}

/// A node back after its CA expired (#416) has it renewed by the connection (`nodeca.rs`) as soon
/// as it is up, and a CA that doesn't cover what the box needs is widened if its policy allows
/// (#573): the box's start waits for either (up to 60 s, one renewal step), since the node refuses
/// a box whose hosts need the CA while it is expired. Not renewed by then, the start goes ahead and
/// the node says why it refuses.
async fn ca_current(sh: &Shared, proto: u32) {
    // 0: not negotiated yet. Every version a connection can talk renews (#416).
    if proto == 0 || sh.node == crate::localnode::NAME {
        return;
    }
    let expired =
        || wicket_node::controlca::active(&sh.ledger.lock().expect("ledger"), &sh.node).is_some_and(|c| c.not_after <= wicket_store::now());
    // What the box needs of the CA that it doesn't cover (#573), wanted of it if the node allows.
    let wanted = want_ca_hosts(sh);
    let missing = || {
        wicket_node::controlca::active(&sh.ledger.lock().expect("ledger"), &sh.node)
            .map(|c| wicket_core::splice::uncovered(&c.hosts, &wanted))
            .unwrap_or_default()
    };
    if !expired() && missing().is_empty() {
        return;
    }
    if expired() {
        say!("[wicket] node {}'s CA has expired: renewing it before the box starts", sh.node);
    } else {
        say!("[wicket] widening node {}'s CA for {}, which the box's reach needs", sh.node, missing().join(", "));
    }
    for _ in 0..240 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if !expired() && missing().is_empty() {
            return;
        }
    }
    let left = missing();
    if !left.is_empty() {
        say!("[wicket] node {}'s CA still doesn't cover {}: the box's requests to them are refused there", sh.node, left.join(", "));
    }
}

/// What became of a grant's host as a want of its node's CA (#573).
#[derive(Debug, PartialEq, Eq)]
enum GrantWant {
    /// Nothing needed: spliced, not something a node CA carries, or the operator's hosts cover it.
    Needless,
    Wanted(String),
    /// The node's CA policy keeps it out: the approval can't be used on the node.
    Refused(String),
}

/// A grant's host, wanted of the node's CA when the operator's hosts don't cover it and the policy
/// allows (#573): the grant holds from when it is published, and takes effect once the CA covers
/// its host. A host the box's zone splices, or no node CA may carry, needs nothing. A host the
/// policy keeps out (it may have changed since the box started, when the node asked under the old
/// one) is audited, since the approval can't be used on this node.
fn want_grant_host_in(l: &Ledger, node: &str, tenant: &TenantId, run: &RunId, zone: &ZoneSpec, g: &wicket_store::GrantRow) -> GrantWant {
    let Some(need) = wicket_core::splice::ca_need(zone, &g.host) else { return GrantWant::Needless };
    let base = l.node(node).ok().flatten().map(|n| n.hosts).unwrap_or_default();
    if wicket_core::splice::uncovered(&base, std::slice::from_ref(&need)).is_empty() {
        return GrantWant::Needless;
    }
    if !l.node_ca_policy(node).unwrap_or(wicket_store::CaHosts::Fixed).allows(&need) {
        let body = serde_json::json!({ "name": node, "host": need, "grant": g.id });
        let _ = l.audit(tenant, Some(run), "node.ca_want_refused", &body);
        return GrantWant::Refused(need);
    }
    let _ = l.want_node_ca_hosts(node, std::slice::from_ref(&need), &run.0, &format!("grant {}", g.id), wicket_store::now());
    GrantWant::Wanted(need)
}

fn want_grant_host(sh: &Shared, g: &wicket_store::GrantRow) {
    if sh.node == crate::localnode::NAME {
        return;
    }
    let w = want_grant_host_in(&sh.ledger.lock().expect("ledger"), &sh.node, &sh.tenant, &sh.run, &sh.zone, g);
    if let GrantWant::Refused(h) = w {
        say!(
            "[wicket] grant {} is for {h}, which node {}'s CA doesn't cover and its CA policy keeps out: it can't be used there (wicket node set {} --ca-hosts …)",
            g.id,
            sh.node,
            sh.node
        );
    }
}

/// What a box needs of its node's CA beyond the operator's hosts (#573): its zone's inspected
/// hosts, its credential swaps' (`swaps`) and its live grants' (so a box restarted or woken wants
/// them again). Recorded as wants by `run` when the node's CA policy allows them, whether or not
/// the CA covers them now: another run may have widened it, and its wants end with it. Returns
/// (wanted, kept out by the policy).
fn want_ca_hosts_in(l: &Ledger, node: &str, run: &RunId, zone: &ZoneSpec, swaps: &[String]) -> (Vec<String>, Vec<String>) {
    let Some(n) = l.node(node).ok().flatten() else { return (vec![], vec![]) };
    let policy = l.node_ca_policy(node).unwrap_or(wicket_store::CaHosts::Fixed);
    let now = wicket_store::now();
    let grants = l.grants_for_run(&run.0).unwrap_or_default().into_iter().filter(|g| !g.revoked && g.expires_at > now).map(|g| g.host);
    let extra: Vec<String> = swaps.iter().cloned().chain(grants).collect();
    let missing = wicket_core::splice::uncovered(&n.hosts, &wicket_core::splice::ca_hosts(zone, &extra));
    let (allowed, kept_out): (Vec<String>, Vec<String>) = missing.into_iter().partition(|h| policy.allows(h));
    if !allowed.is_empty() {
        if let Err(e) = l.want_node_ca_hosts(node, &allowed, &run.0, "the box's reach", now) {
            say!("[wicket] could not record what {run} needs of node {node}'s CA: {e}");
            return (vec![], kept_out);
        }
    }
    (allowed, kept_out)
}

fn want_ca_hosts(sh: &Shared) -> Vec<String> {
    let l = sh.ledger.lock().expect("ledger");
    let swaps: Vec<String> = sh.swaps.iter().map(|s| s.host.clone()).collect();
    let (wanted, kept_out) = want_ca_hosts_in(&l, &sh.node, &sh.run, &sh.zone, &swaps);
    // Said only if the CA doesn't cover them now either (an operator's renew-ca may have).
    let uncovered =
        wicket_node::controlca::active(&l, &sh.node).map(|c| wicket_core::splice::uncovered(&c.hosts, &kept_out)).unwrap_or_default();
    if !uncovered.is_empty() {
        say!(
            "[wicket] node {}'s CA doesn't cover {}, and its CA policy keeps them out (wicket node set {} --ca-hosts …)",
            sh.node,
            uncovered.join(", "),
            sh.node
        );
    }
    wanted
}

/// Makes sure node `node` has image `pin` (#191): if it hasn't, this host's runtime exports it as an
/// OCI image layout, and the node verifies it against the pin before importing it. If this host
/// hasn't it either, it fails saying so: the image can't reach the node (it may have removed it
/// once unused, #191).
///
/// With `pull` (the image's registry is allowed in `images.yaml`), the node pulls it from there
/// itself first, host-side; if that fails, this host sends it if it can.
pub async fn deliver_image(
    calls: &crate::nodecall::Calls,
    node: &str,
    run: &str,
    image: &str,
    pin: &str,
    pull: Option<&crate::registry::Source>,
) -> Result<()> {
    if calls.has_image(pin).await? {
        return Ok(());
    }
    let name = crate::oci::import_name(image, pin);
    let mut pulled = None;
    if let Some(src) = pull {
        say!("[wicket] node {node} pulling image {pin} from {}", src.host);
        let t0 = std::time::Instant::now();
        match calls.pull_image(run, pin, name.as_deref(), src).await {
            Ok(()) => {
                say!("[wicket] node {node} pulled, verified and imported image {pin} in {:.1} s", t0.elapsed().as_secs_f64());
                return Ok(());
            }
            Err(e) => {
                say!("[wicket] node {node} could not pull image {pin} from {}: {e:#}", src.host);
                pulled = Some(e);
            }
        }
    }
    let here = wicket_sandbox::Docker::from_env();
    if !here.image_identity(pin).await?.is_some_and(|i| i.is(pin)) {
        if let Some(e) = pulled {
            return Err(
                e.context(format!("pulling it from {}, and this host hasn't it to send", pull.map(|p| p.host.as_str()).unwrap_or("")))
            );
        }
        // Not here either (a node may have removed an image it was given once unused, #191): said
        // plainly, rather than the node's refusal later.
        bail!(
            "node {node} hasn't image {image} ({pin}), and this host hasn't it to send: load it here (docker pull {image}), or list its registry in images.yaml so the node pulls it"
        );
    }
    say!("[wicket] sending image {image} ({pin}) to node {node}");
    let t0 = std::time::Instant::now();
    let mut save = here.export_image(pin)?;
    let out = save.stdout.take().context("the export's output")?;
    let mut err = save.stderr.take().context("the export's errors")?;
    let errs = tokio::spawn(async move {
        let mut s = String::new();
        let _ = tokio::io::AsyncReadExt::read_to_string(&mut err, &mut s).await;
        s
    });
    let sent = calls.put_image(pin, name.as_deref(), out).await;
    if sent.is_err() {
        let _ = save.start_kill();
    }
    let st = save.wait().await?;
    let sent = sent?;
    if !st.success() {
        bail!("exporting the image failed: {}", errs.await.unwrap_or_default().trim());
    }
    say!(
        "[wicket] node {node} verified and imported image {pin} ({:.1} MiB in {:.1} s)",
        sent as f64 / f64::from(1u32 << 20),
        t0.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The run loop's side of the box's stdio, held by the connection manager across reconnects.
struct Io {
    stdin: tokio::io::DuplexStream,
    stdout: Option<tokio::io::DuplexStream>,
    stderr: Option<tokio::io::DuplexStream>,
    exit: Option<oneshot::Sender<i32>>,
}

/// Per-run progress that survives reconnects.
struct Progress {
    stdin: OutBuf,
    stdin_closed: bool,
    next: [u64; 2],
    published: HashSet<String>,
    revoked: HashSet<String>,
    /// Grants waiting for room in the box's token (at most `MAX_GRANTS` live), each noted once.
    waiting: HashSet<String>,
    /// The grants the box's token carries now.
    live: Vec<LiveGrant>,
    /// The node has listed the run at least once (a re-attached run that it doesn't list is gone).
    ever_resumed: bool,
    ever: bool,
    exited: bool,
    /// The node's certificate, as last authenticated or renewed.
    cert: Option<NodeCertClaims>,
    /// A renewal sent and not yet answered.
    renewing: Option<NodeCertClaims>,
    /// No renewal attempt before this (after a failed one).
    renew_after: i64,
    /// The node CA's renewal on this connection (#416).
    ca: wicket_node::controlca::CaRenewal,
    /// The protocol version this connection talks (#162); 0 until it has negotiated one.
    proto: u32,
    /// Whether a budget slice went on this connection, and the last one sent (#152).
    slice_sent: bool,
    slice: Option<wicket_proxy::llm::Slice>,
    /// The secrets released to the node for this run, and what each was (to tell a change).
    fetched: std::collections::HashMap<String, String>,
    /// The secrets the run's zone uses that were refused to its node (an optional one not set yet,
    /// #415): the node is told when one can be released, and a refusal is audited once while it lasts.
    refused: HashSet<String>,
    /// A renewed authority end (Unix seconds) whose re-mint failed: not tried again (#56).
    remint_failed: i64,
    /// What changed in the ledger since this connection's loops last looked (#582 step 2), and when
    /// each last did its work regardless (the fallback every [`FULL_EVERY`]).
    watch: wicket_store::ChangeWatch,
    grants_full: std::time::Instant,
    ident_full: std::time::Instant,
    /// What `wicket top` reads of this run's node (`ctl/link.json`).
    link: wicket_node::status::LinkRecord,
    /// The standing rules (#572) the box's token carries now, by id, with the end each was
    /// published with.
    standing: std::collections::HashMap<String, u64>,
    /// The host ports the box's token carries now (#575 step 4c).
    ports: Vec<wicket_feed::PublishedPort>,
}

async fn manage(
    sh: Arc<Shared>,
    mut io: Io,
    mut ready: Option<oneshot::Sender<Result<()>>>,
    mut started: Option<oneshot::Sender<StartedAs>>,
    target_epoch: u64,
) {
    let mut p = Progress {
        stdin: OutBuf::new(crate::nodesrv::OUTPUT_CAP),
        stdin_closed: false,
        next: [sh.ctl.next[0].load(Ordering::SeqCst), sh.ctl.next[1].load(Ordering::SeqCst)],
        published: sh.carried.iter().map(|g| g.grant.gid.clone()).collect(),
        revoked: HashSet::new(),
        waiting: HashSet::new(),
        live: sh.carried.clone(),
        ever: false,
        ever_resumed: false,
        exited: false,
        cert: None,
        renewing: None,
        renew_after: 0,
        ca: Default::default(),
        proto: 0,
        slice_sent: false,
        slice: None,
        // What an earlier supervisor of the run released to its node, with the digest each went with
        // (#415, #818): the first connection revokes what changed since, or may be stale, and leaves
        // the rest with the node.
        fetched: released_before(&sh.dir),
        refused: HashSet::new(),
        remint_failed: 0,
        watch: wicket_store::ChangeWatch::new(),
        grants_full: std::time::Instant::now(),
        ident_full: std::time::Instant::now(),
        link: wicket_node::status::LinkRecord { node: sh.node.clone(), ..Default::default() },
        standing: std::collections::HashMap::new(),
        ports: sh.ports_at_start.clone(),
    };
    let mut backoff = std::time::Duration::from_millis(500);
    loop {
        let r = session(&sh, &mut io, &mut p, &mut ready, &mut started, target_epoch).await;
        *sh.ctl.link.lock().expect("link") = None;
        // Cut off (not the box's end): the node may come back on another build, so its protocol is
        // known again only from a new connection's welcome (#691).
        // The local node whose serve is still this build's (checked, not assumed) is known still.
        if !p.exited && !(sh.node == crate::localnode::NAME && crate::localnode::serve_is_this_build()) {
            forget_protocol(&sh.node);
        }
        // Cut off: since now, or since it was (a retry that fails again keeps the time).
        if p.link.connected || p.link.since_ms == 0 {
            let now = wicket_feed::now_ms();
            p.link = wicket_node::status::LinkRecord { connected: false, since_ms: now, updated_ms: now, ..p.link.clone() };
            p.link.save(&sh.dir);
        }
        sh.ctl.calls.set_out(None);
        if p.exited && !sh.ctl.kept() {
            return;
        }
        match r {
            Err(e) if !p.ever => {
                // Never connected, or refused (protocols too far apart): give up. The run sees the box end.
                match ready.take() {
                    Some(t) => {
                        let _ = t.send(Err(e));
                    }
                    None => say!("[wicket] giving up on node {}: {e:#}", sh.node),
                }
                return;
            }
            Err(e) => say!("[wicket] node {} unreachable ({e:#}); retrying in {}", sh.node, wicket_core::time::format_duration(backoff)),
            Ok(()) => {
                say!("[wicket] node {} channel closed; reconnecting in {}", sh.node, wicket_core::time::format_duration(backoff));
                backoff = std::time::Duration::from_millis(500);
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(5));
    }
}

/// One connection, until it drops. `Ok` if it got as far as the node's welcome.
async fn session(
    sh: &Arc<Shared>,
    io: &mut Io,
    p: &mut Progress,
    ready: &mut Option<oneshot::Sender<Result<()>>>,
    started: &mut Option<oneshot::Sender<StartedAs>>,
    target_epoch: u64,
) -> Result<()> {
    // Revoked while the channel was down: its pinned host key is gone too, so ssh would fail with
    // a host key error that looks like an outage. Give up instead of retrying.
    if let Some(why) = crate::nodeauth::untrusted(&sh.ledger.lock().expect("ledger"), &sh.node, None, wicket_store::now()) {
        p.ever = false;
        bail!("{why}: not reconnecting");
    }
    // Only the first connection's steps are part of the box's start (#287).
    let first = ready.is_some() && !sh.timings.has("node.dial");
    let dialing = std::time::Instant::now();
    let mut fresh = false;
    let (mut from, mut to, mut child, authed, shaking) = loop {
        let d = match sh.via.dial().await {
            Ok(d) => d,
            // This host's own node's `serve` is gone (killed, or exited): start it again, and it adopts
            // its boxes, this run's among them (#151).
            Err(e) if sh.node == crate::localnode::NAME => {
                crate::localnode::ensure(&sh.ledger).await.map_err(|e2| e.context(format!("restarting this host's node: {e2:#}")))?;
                sh.via.dial().await?
            }
            Err(e) => return Err(e),
        };
        let (mut from, mut to, mut child, errlog) = (d.rd, d.wr, d.child, d.errlog);
        let shaking = std::time::Instant::now();
        if first {
            sh.timings.record("node.dial", dialing, shaking);
        }
        let build = crate::nodesrv::build_id()?;
        let hello = |nonce| Msg::Hello {
            node: sh.node.clone(),
            version: env!("CARGO_PKG_VERSION").into(),
            build,
            proto: crate::chan::PROTOCOL,
            observer: false,
            nonce,
            scope: sh.run.0.clone(),
        };
        let authed = match crate::nodeauth::control(&mut from, &mut to, &sh.node, &sh.ledger, &sh.issuer, hello).await {
            Ok(a) => a,
            // Over a shared ssh connection that has gone stale (a network change, #287): close it and
            // dial again, once, over a fresh one, before counting this as no answer.
            Err(HsError::NoAnswer | HsError::Timeout(_)) if !fresh && matches!(sh.via, crate::nodecall::Via::Ssh(_)) => {
                if let Some(c) = child.as_mut() {
                    let _ = c.start_kill();
                }
                crate::enrol::close_master_of(&sh.ledger.lock().expect("ledger"), &crate::enrol::Paths::installation().nodes_dir, &sh.node);
                fresh = true;
                continue;
            }
            Err(HsError::NoAnswer) => {
                if let Some(c) = child.as_mut() {
                    let _ = c.start_kill();
                }
                let err = match errlog {
                    Some(e) => e.await.unwrap_or_default(),
                    None => String::new(),
                };
                let err = err.trim().lines().last().unwrap_or("no error output").to_string();
                bail!("no answer from `wicket node serve` ({err}): is it installed and running? (`wicket node install {}`)", sh.node);
            }
            Err(e @ HsError::Timeout(_)) => return Err(e.into()),
            Err(HsError::Refused(why)) => {
                // Refused either way (identity, revocation, protocol): not worth retrying. What it
                // talks isn't known now.
                forget_protocol(&sh.node);
                p.ever = false;
                bail!("{why}")
            }
        };
        break (from, to, child, authed, shaking);
    };
    // `_live` notes this connection's protocol until it drops (#691).
    let (feed, runs, _live) = match authed.welcome {
        Msg::Welcome { feed, runs, proto, capacity, .. } => {
            let now = wicket_feed::now_ms();
            p.link = wicket_node::status::LinkRecord { connected: true, since_ms: now, updated_ms: now, capacity, ..p.link.clone() };
            p.link.save(&sh.dir);
            p.proto = proto;
            sh.ctl.proto.store(proto, Ordering::SeqCst);
            (feed, runs, note_session(&sh.node, proto))
        }
        _ => unreachable!("nodeauth::control returns a welcome"),
    };
    if first {
        sh.timings.since("node.handshake", shaking);
    }
    p.ever = true;
    p.cert = Some(authed.cert);
    p.renewing = None;
    p.ca.reset();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Frame>();
    let writer = tokio::spawn(async move {
        while let Some(f) = out_rx.recv().await {
            if to.write_all(&f.encode()).await.is_err() {
                break;
            }
        }
    });
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Frame>();
    let reader = tokio::spawn(async move {
        while let Ok(Some(f)) = chan::read_frame(&mut from).await {
            if in_tx.send(f).is_err() {
                break;
            }
        }
    });
    let send = |f: Frame| {
        let _ = out_tx.send(f);
    };
    let feed_frame = |f: wicket_feed::Frame| Frame::Feed(f.to_line().trim_end().as_bytes().to_vec());
    // A node below protocol 19 can't read a record whose zone decodes a slash (#664). `start`
    // refuses to publish one to a node not known to talk 19; this is for one that has gone back
    // since (its feed may already carry it): this run's session ends rather than send it.
    if p.proto < protocol_needed(&sh.zone) {
        p.ever = false;
        bail!(
            "node {} talks protocol {}, and zone {} decides an encoded slash (decode_slash), which needs {}: update the node (wicket self update --nodes)",
            sh.node,
            p.proto,
            sh.zone.name,
            wicket_chan::chan::DECODE_SLASH
        );
    }
    // The same for a node that has gone back below protocol 23 since its zone went out with its
    // optional rules whatever their secrets (#415): it would let plain HTTP to such a host through.
    if p.proto < wicket_chan::chan::LIVE_SECRETS && sh.optional_rules {
        p.ever = false;
        bail!(
            "node {} talks protocol {}, and run {}'s zone went out with optional secrets read per request, which needs {}: update the node (wicket self update --nodes)",
            sh.node,
            p.proto,
            sh.run,
            wicket_chan::chan::LIVE_SECRETS
        );
    }
    let now = wicket_feed::now_ms();
    let catching = std::time::Instant::now();
    for f in sh.ctl.publisher.lock()?.catch_up(&feed, now)? {
        send(feed_frame(f));
    }
    let slicing = std::time::Instant::now();
    if first {
        sh.timings.record("feed.catch_up", catching, slicing);
    }
    // The run's secrets and budget slice, sealed to the node (#152), before anything the box does.
    p.slice_sent = false;
    if let Some(f) = slice_due(sh, p) {
        send(f);
    }
    // A revoke sent on a link that died may never have arrived (#415): those are sent again, with
    // every refusal. A secret the node holds as released stays (#818: after a self-update its new
    // process has it, handed over), unless it changed meanwhile, which is told now.
    let release = |name: &str| {
        crate::nodesecrets::release_run(&sh.zone, &sh.swaps, &sh.vault, name, sh.ctl.authority_until())
            .ok()
            .map(|f| crate::nodesecrets::digest(&f))
    };
    let revokes = connect_revokes(&mut p.fetched, &mut p.refused, release);
    if revokes.iter().any(|(_, resend)| !resend) {
        save_holdings(sh, p);
    }
    for (name, resend) in revokes {
        if !resend {
            say!("[wicket] secret {name} changed on this host: node {} fetches it again for {}", sh.node, sh.run);
        }
        send(Frame::Msg(Msg::SecretRevoke { run: sh.run.0.clone(), name, resend }));
    }
    if first {
        sh.timings.since("budget.slice", slicing);
    }
    if sh.attach && !p.ever_resumed && !runs.iter().any(|r| r.run == sh.run.0) {
        p.ever = false;
        bail!("node {} has no box for run {}: it is gone", sh.node, sh.run);
    }
    if let Some(r) = runs.iter().find(|r| r.run == sh.run.0) {
        p.ever_resumed = true;
        // Pick the streams up where the node is: stdin from what it has taken (a new supervisor's
        // buffer starts there), stdout and stderr no earlier than what it still holds.
        if p.stdin.end() < r.stdin_received {
            p.stdin = OutBuf::starting_at(crate::nodesrv::OUTPUT_CAP, r.stdin_received);
        }
        p.next[0] = p.next[0].max(r.stdout_start);
        p.next[1] = p.next[1].max(r.stderr_start);
        // The first time this supervisor hears how far the node got (#445): a re-attached one gives
        // again what the supervisor before it took and its box never had, before this connection
        // answers anything.
        // And on every reconnect after that (#453): what it gave on the link that dropped and its
        // node never said the box had. The node drops a repeat its box has had.
        let first = sh.ctl.stdin_base.set(p.stdin.end()).is_ok();
        let (messages, prompts) = requeue_on_resume(&sh.ledger.lock().expect("ledger"), &sh.run.0, first, sh.attach, r.stdin_received);
        if messages + prompts > 0 {
            let when = if first { "before this supervisor took over" } else { "before the link to its node dropped" };
            say!("[wicket] giving the box again what it never had {when}: {messages} message(s), {prompts} prompt(s)");
        }
        say!("[wicket] node {} reconnected; resuming the box's output", sh.node);
        send(Frame::Msg(Msg::Resume { run: r.run.clone(), stdout_from: p.next[0], stderr_from: p.next[1] }));
        p.stdin.ack(r.stdin_received);
        let (at, bytes) = p.stdin.since(r.stdin_received);
        if !bytes.is_empty() {
            send(Frame::Data { stream: sh.streams[0], offset: at, bytes });
        }
        if p.stdin_closed {
            send(Frame::Msg(Msg::StdinClose { run: r.run.clone() }));
        }
        if sh.ctl.killed.load(Ordering::SeqCst) {
            send(Frame::Msg(Msg::Kill { run: r.run.clone() }));
        }
    }
    let head = sh.ledger.lock().expect("ledger").node_audit_head(&sh.node)?.map(|h| h.0).unwrap_or(0);
    send(Frame::Msg(Msg::AuditFrom { seq: head }));
    *sh.ctl.link.lock().expect("link") = Some(out_tx.clone());
    sh.ctl.calls.set_out(Some(out_tx.clone()));

    let mut tick = tokio::time::interval(std::time::Duration::from_millis((sh.cfg.refresh_ms / 2).clamp(50, 1000) as u64));
    // When the statement tick last logged that it couldn't take the feed: at most once a minute,
    // as it ticks up to twenty times a second.
    let mut tick_failed_logged: Option<std::time::Instant> = None;
    let mut grants = tokio::time::interval(std::time::Duration::from_millis(250));
    let mut ident = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut leases = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut buf = vec![0u8; 32 * 1024];
    let result = loop {
        tokio::select! {
            _ = sh.ctl.done.notified(), if p.exited => break Ok(()),
            f = in_rx.recv() => match f {
                Some(f) => {
                    if let Err(e) = on_frame(sh, io, p, f, &out_tx, ready, started, target_epoch).await {
                        break Err(e);
                    }
                    if p.exited && !sh.ctl.kept() {
                        break Ok(());
                    }
                }
                None => break Ok(()),
            },
            n = io.stdin.read(&mut buf), if !p.stdin_closed => match n {
                Ok(0) | Err(_) => {
                    p.stdin_closed = true;
                    send(Frame::Msg(Msg::StdinClose { run: sh.run.0.clone() }));
                }
                Ok(n) => {
                    let at = p.stdin.write(&buf[..n]);
                    send(Frame::Data { stream: sh.streams[0], offset: at, bytes: buf[..n].to_vec() });
                }
            },
            _ = tick.tick() => {
                let f = match sh.ctl.publisher.lock() {
                    Ok(mut p) => p.tick(wicket_feed::now_ms()),
                    Err(e) => {
                        // No statement this tick: the node goes offline at its last one's end
                        // unless a later lock works.
                        if tick_failed_logged.is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(60)) {
                            tick_failed_logged = Some(std::time::Instant::now());
                            say_err!("[wicket] could not take node {}'s feed for a statement: {e:#}", sh.node);
                        }
                        None
                    }
                };
                if let Some(f) = f {
                    send(feed_frame(f));
                }
            }
            _ = leases.tick() => {
                if let Some(f) = slice_due(sh, p) {
                    send(f);
                }
                for f in secrets_changed(sh, p) {
                    send(f);
                }
            }
            _ = grants.tick() => {
                // Only when the grants changed (#582 step 2), or every FULL_EVERY regardless.
                if changed(sh, p, wicket_store::Topic::Grants) || p.grants_full.elapsed() >= FULL_EVERY {
                    p.grants_full = std::time::Instant::now();
                    for f in sync_grants(sh, p) {
                        send(feed_frame(f));
                    }
                }
            }
            _ = ident.tick() => {
                // Revocations and the node's status when they changed, or every FULL_EVERY, or as
                // the node's certificate (held here) reaches its end.
                let now = wicket_store::now();
                let ending = p.cert.as_ref().is_some_and(|c| c.exp <= now + 1);
                let check = changed(sh, p, wicket_store::Topic::Revocations) || ending || p.ident_full.elapsed() >= FULL_EVERY;
                let ca_check = changed(sh, p, wicket_store::Topic::NodeCa) || check || p.ca.busy();
                if check {
                    p.ident_full = std::time::Instant::now();
                }
                if let Some(why) = check.then(|| revoked(sh, p)).flatten() {
                    // Stop the box (in case the node still obeys), then drop the node for good.
                    send(Frame::Msg(Msg::Kill { run: sh.run.0.clone() }));
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    p.ever = false;
                    break Err(anyhow::anyhow!("{why}: dropping the channel"));
                }
                if let Some(f) = renewal(sh, p) {
                    send(f);
                }
                if let Some(m) = ca_check.then(|| p.ca.tick(&sh.ledger, &sh.node, p.proto, wicket_store::now())).flatten() {
                    send(Frame::Msg(m));
                }
            }
        }
    };
    writer.abort();
    reader.abort();
    if let Some(c) = child.as_mut() {
        let _ = c.start_kill();
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn on_frame(
    sh: &Arc<Shared>,
    io: &mut Io,
    p: &mut Progress,
    f: Frame,
    out: &chan::Out,
    ready: &mut Option<oneshot::Sender<Result<()>>>,
    started: &mut Option<oneshot::Sender<StartedAs>>,
    target_epoch: u64,
) -> Result<()> {
    let send = |f: Frame| {
        let _ = out.send(f);
    };
    // Tunnel bytes, and the answers to calls on boxes (pause, exec, link sockets).
    let Some(f) = sh.ctl.calls.handle(f) else { return Ok(()) };
    match f {
        Frame::Data { stream, offset, bytes } => {
            let Some(i) = [1usize, 2].into_iter().find(|&i| sh.streams[i] == stream) else { return Ok(()) };
            let (fresh, gap) = accept_at(&mut p.next[i - 1], offset, &bytes);
            sh.ctl.next[i - 1].store(p.next[i - 1], Ordering::SeqCst);
            if gap {
                say!(
                    "[wicket] some of the box's {} was lost while node {} was unreachable (it keeps {} MiB per stream)",
                    if i == 1 { "stdout" } else { "stderr" },
                    sh.node,
                    crate::nodesrv::OUTPUT_CAP >> 20
                );
            }
            if !fresh.is_empty() && !sh.first_output.swap(true, Ordering::SeqCst) {
                sh.timings.mark("box.first_output");
            }
            let w = if i == 1 { io.stdout.as_mut() } else { io.stderr.as_mut() };
            if let (Some(w), false) = (w, fresh.is_empty()) {
                let _ = w.write_all(&fresh).await;
            }
            send(Frame::Msg(Msg::Ack { stream, upto: p.next[i - 1] }));
        }
        Frame::Feed(_) => bail!("the node sent a feed frame"),
        Frame::Msg(m) => match m {
            Msg::FeedStatus { mode, epoch, refused, catch_up } => {
                if let Some(e) = epoch {
                    let _ = sh.ledger.lock().expect("ledger").node_feed_at(&sh.node, e as i64);
                }
                if let Some(r) = refused {
                    say!("[wicket] node {} refused a feed frame: {r}", sh.node);
                }
                if let Some(h) = catch_up {
                    for f in sh.ctl.publisher.lock()?.catch_up(&h, wicket_feed::now_ms())? {
                        send(Frame::Feed(f.to_line().trim_end().as_bytes().to_vec()));
                    }
                }
                if mode == wicket_feed::Mode::Fresh && epoch.is_some_and(|e| e >= target_epoch) {
                    if let Some(t) = ready.take() {
                        sh.timings.mark("feed.fresh");
                        let _ = t.send(Ok(()));
                    }
                }
            }
            Msg::Started { run, error, digest, timings } if run == sh.run.0 => {
                if let Some(t) = started.take() {
                    let _ = t.send(match error {
                        Some(e) => Err(e),
                        None => Ok((digest, timings)),
                    });
                }
            }
            Msg::Exited { run, code, result, reason, timings } if run == sh.run.0 => {
                // The box's own start and its end on the node (#287), where they happened.
                sh.timings.nest_wall(&timings);
                sh.timings.mark("box.exited");
                // The node says the box has stopped: nothing fences a wake of its agent any more.
                confirm_stopped(&sh.dir);
                // Nor does it need its node's CA any more (#573): the next due renewal prunes it.
                let _ = sh.ledger.lock().expect("ledger").drop_node_ca_wants(&sh.run.0);
                if let Some(why) = &reason {
                    say!("[wicket] the box ended (exit status {code}): {why}");
                    let _ = sh.ledger.lock().expect("ledger").audit(
                        &sh.tenant,
                        Some(&sh.run),
                        "run.exit_cause",
                        &serde_json::json!({ "node": sh.node, "code": code, "cause": why }),
                    );
                    *sh.ctl.exit_cause.lock().expect("exit cause") = Some(why.clone());
                }
                if let Some(r) = result {
                    let out = sh.dir.join("workspace/out");
                    let _ = std::fs::create_dir_all(&out);
                    // The outbox taken is the run's work collected (#377), once it is here.
                    if std::fs::write(out.join("result.json"), r).is_ok() {
                        let _ = sh.ledger.lock().expect("ledger").record_collected(&sh.run.0, "outbox");
                    }
                }
                // End of output: the run loop's readers see EOF, then the exit.
                io.stdout.take();
                io.stderr.take();
                if let Some(t) = io.exit.take() {
                    let _ = t.send(code);
                }
                // The node may delete the run's files once its work is collected (#377): this host's own
                // node keeps them anyway (they are the run's directory here); a remote node's
                // workspace, with nothing of it collected, stays until an operator forces it.
                if !sh.ctl.keep {
                    // Decided first: a guard in the match's scrutinee would be held into its arms,
                    // which lock the ledger again (a deadlock).
                    let refused = forget_refused(&sh.ledger.lock().expect("ledger"), &sh.node, &sh.run.0, true);
                    match refused {
                        None => send(Frame::Msg(Msg::Forget { run })),
                        Some(why) => {
                            say!("[wicket] {why}");
                            let _ = sh.ledger.lock().expect("ledger").audit(
                                &sh.tenant,
                                Some(&sh.run),
                                "run.cleanup_refused",
                                &serde_json::json!({ "node": sh.node, "why": why }),
                            );
                        }
                    }
                }
                // The box is gone: its token leaves the feed (the node no longer needs it).
                let dropped = sh.ctl.publisher.lock().and_then(|mut f| {
                    f.commit(vec![Change::DropZone { name: sh.run.0.clone() }], wicket_feed::now_ms()).map_err(Into::into)
                });
                if let Ok(f) = dropped {
                    send(Frame::Feed(f.to_line().trim_end().as_bytes().to_vec()));
                }
                // The node drops what it held for the run with its box: no digest of a secret is
                // kept in the run's directory past it (#818). A secret revoked for a change keeps
                // that mark, so a revoke of it still goes as a change.
                for d in p.fetched.values_mut().filter(|d| d.as_str() != CHANGED) {
                    *d = REVOKED.into();
                }
                save_holdings(sh, p);
                p.exited = true;
            }
            Msg::Event { run, event } if run == sh.run.0 => {
                if let Ok(ev) = serde_json::from_value::<wicket_proxy::Event>(event) {
                    // Near its memory limit (#185): the agent is told, as a message from wicket, so it
                    // can scale down before the kernel kills the box.
                    if let wicket_proxy::Event::Box { what, detail } = &ev {
                        if what == "memory_pressure" {
                            let _ = sh.ledger.lock().expect("ledger").add_notice(&sh.run.0, detail);
                        }
                    }
                    let _ = sh.events.send(ev);
                }
            }
            Msg::Ask { id, run, op, why, who, queued, prefix } => {
                send(Frame::Msg(ask(sh, id, &run, &op, &why, who.as_ref(), queued.as_ref(), prefix)))
            }
            Msg::AskStanding { id, run, rule, why } => {
                let reply = ask_standing(&sh.ledger.lock().expect("ledger"), &sh.tenant, &sh.run, &sh.zone, id, &run, &rule, &why);
                send(Frame::Msg(reply))
            }
            Msg::SecretFetch { id, run, name } => {
                // Only for this run, over its own connection: another run's ask is refused.
                let reply = match run == sh.run.0 {
                    true => fetch_secret(sh, p, id, &name),
                    false => Msg::SecretFetched { id, secret: None, error: Some(format!("not run {}'s connection", run)) },
                };
                send(Frame::Msg(reply));
            }
            // A child the node started for the box (#164): taken over (or refused) off this loop,
            // since that starts its supervisor.
            Msg::Spawned { run, child, manifest, image, session, started_ms, digest } if run == sh.run.0 => {
                let (adopt, out) = (sh.adopt.clone(), out.clone());
                let s = Spawned { child: child.clone(), manifest, image, session, started_ms, digest };
                tokio::task::spawn_blocking(move || {
                    let error = match adopt {
                        Some(a) => a(s).err(),
                        None => Some("this run may not start boxes".into()),
                    };
                    if let Some(e) = &error {
                        say!("[wicket] refused child {child} its node started: {e}");
                    }
                    let _ = out.send(Frame::Msg(Msg::Adopted { child, error }));
                });
            }
            // The node's health (#377): its latest, per node, for `wicket top`, the console and its
            // alerts (each run's connection to the node reports it; the latest wins).
            //
            // Every run's connection to the node gets the same report: one written per node every
            // 20 s is enough (#582), and the rest are a read, not the ledger's write lock. Placement
            // reads the row as its capacity index (#579).
            Msg::Health { health } => {
                let now = wicket_feed::now_ms();
                let l = sh.ledger.lock().expect("ledger");
                let fresh = l.node_health_at(&sh.node).ok().flatten().is_some_and(|at| now - at < HEALTH_WRITE_MS);
                if !fresh {
                    if let Ok(j) = serde_json::to_string(&health) {
                        let _ = l.set_node_health(&sh.node, now, &j);
                    }
                }
            }
            Msg::Spent { run, spent, first_request_ms } if run == sh.run.0 => {
                if p.link.spent != spent {
                    p.link.spent = spent;
                    p.link.updated_ms = wicket_feed::now_ms();
                    p.link.save(&sh.dir);
                }
                // The box's first model request (#287), on the node's clock: only as good as the
                // two hosts' clocks agree.
                if let Some(ms) = first_request_ms.filter(|_| !sh.timings.has("agent.first_model_request")) {
                    sh.timings.mark_unix_ms("agent.first_model_request", ms);
                    if wicket_core::timing::enabled() {
                        let at = sh.timings.spans().into_iter().find(|s| s.name == "agent.first_model_request").map_or(0.0, |s| s.at_ms);
                        say!("[wicket] timings: the agent's first model request reached node {} at {at:.1} ms", sh.node);
                    }
                }
                // The node calls the model itself and is the counter of record (#152).
                if let Some(l) = &sh.llm {
                    let base = {
                        let mut b = sh.spent_base.lock().expect("spent base");
                        match &mut *b {
                            Some(slot) => *slot.get_or_insert(spent),
                            None => wicket_proxy::llm::Spent::default(),
                        }
                    };
                    l.merge_spent(spent.since(base));
                }
            }
            // A tool of the box's gateway its node doesn't answer itself (#257 slice 4b): answered
            // by the run's own gateway here, on a task of its own (a wait may last minutes).
            Msg::Call { id, run, tool, args } => {
                let (gw, spawn, out) = (sh.gateway.clone(), sh.spawn.clone(), out.clone());
                let mine = run == sh.run.0;
                // A node that says when its box has had a message (#445) gets it in flight.
                let read_by_node = p.proto >= wicket_chan::chan::MESSAGE_READ;
                tokio::spawn(async move {
                    let (text, is_error) = match (mine, tool, gw.superseded()) {
                        (false, ..) => (format!("no gateway for run {run} here"), true),
                        (true, ControlTool::Spawn, Some(why)) => (why, true),
                        // A spawn its node doesn't start: its child's supervisor starts here, in
                        // this process (#257 slice 4c).
                        (true, ControlTool::Spawn, None) => match spawn {
                            Some(c) => tokio::task::spawn_blocking(move || crate::spawn::tool(&c, &args))
                                .await
                                .unwrap_or_else(|e| (format!("not started: {e}"), true)),
                            None => ("this agent may not start other boxes (max_children is 0)".into(), true),
                        },
                        // Its node says when the box has had a message it carries (`MessageRead`).
                        (true, ..) if read_by_node => {
                            let (text, is_error, in_flight) = gw.call_tool_read(&tool.name(), args).await;
                            // An answer that can't go (its link dropped while it waited) gives its
                            // message again (#453): the reconnect's re-send may have come first.
                            if out.send(Frame::Msg(Msg::Called { id, text, is_error })).is_err() {
                                if let Some(m) = in_flight {
                                    gw.message_not_read(&m);
                                }
                            }
                            return;
                        }
                        (true, ..) => gw.call_tool(&tool.name(), args).await,
                    };
                    let _ = out.send(Frame::Msg(Msg::Called { id, text, is_error }));
                });
            }
            // The box has had a message the gateway gave it (#445): read.
            Msg::MessageRead { run, id } if run == sh.run.0 => {
                sh.gateway.message_read(&id);
            }
            Msg::TunnelOpen { stream, run, target } => {
                // No socket of the control host's is a tunnel target any more (#257).
                send(Frame::Msg(Msg::TunnelOpened { stream, error: Some(format!("no tunnel to {target} for run {run}")) }));
            }
            Msg::Audit { records } => {
                let n = records.len();
                if let Err(e) = sh.ledger.lock().expect("ledger").append_node_audit(&sh.node, &sh.tenant, &records) {
                    say!("[wicket] node {}'s audit records were refused ({e}); they stay on the node", sh.node);
                } else {
                    tracing::debug!(node = %sh.node, n, "node audit records appended");
                }
            }
            Msg::Refused { why } => bail!("node {} refused: {why}", sh.node),
            Msg::AuditAsk {} => {
                let head = sh.ledger.lock().expect("ledger").node_audit_head(&sh.node)?.map(|h| h.0).unwrap_or(0);
                send(Frame::Msg(Msg::AuditFrom { seq: head }));
            }
            Msg::CaCsr { csr, error } => {
                if let Some(m) = p.ca.on_csr(&sh.ledger, sh.installation_ca.as_deref(), &sh.node, csr, error, wicket_store::now()) {
                    send(Frame::Msg(m));
                }
            }
            Msg::NodeCaInstalled { serial, error } => {
                p.ca.on_installed(&sh.ledger, &sh.node, &serial, error, wicket_store::now());
            }
            Msg::NodeCertInstalled { serial, error } => match (p.renewing.take(), error) {
                (Some(c), None) if c.jti == serial => {
                    say!("[wicket] node {}'s identity certificate renewed until {}", sh.node, c.exp);
                    p.cert = Some(c);
                }
                (_, e) => {
                    say!("[wicket] node {} did not take its renewed certificate ({}); retrying in a minute", sh.node, e.unwrap_or(serial));
                    p.renew_after = wicket_store::now() + 60;
                }
            },
            _ => {}
        },
    }
    Ok(())
}

/// Why the node must be dropped now, if it must (`nodeauth::untrusted`).
fn revoked(sh: &Shared, p: &Progress) -> Option<String> {
    crate::nodeauth::untrusted(&sh.ledger.lock().expect("ledger"), &sh.node, p.cert.as_ref(), wicket_store::now())
}

/// A renewed certificate for the node, when its current one is past half its life.
fn renewal(sh: &Shared, p: &mut Progress) -> Option<Frame> {
    let now = wicket_store::now();
    if p.renewing.is_some() || now < p.renew_after {
        return None;
    }
    let issued = crate::nodeauth::renew_if_due(&sh.ledger.lock().expect("ledger"), &sh.issuer, &sh.node, p.cert.as_ref()?, now)?;
    match issued {
        Ok((jws, claims)) => {
            p.renewing = Some(claims);
            Some(Frame::Msg(Msg::NodeCert { cert: jws }))
        }
        Err(e) => {
            say!("[wicket] could not renew node {}'s certificate: {e:#}", sh.node);
            p.renew_after = now + 60;
            None
        }
    }
}

/// Raises (or finds) the pending request for an op the node asks about, if it is this run's.
///
/// The node is not trusted with what the human sees (#121): the op is rebuilt here from its method,
/// host and canonical path, its risk is the control host's own classification (raised, never
/// lowered, by the node's, which saw the query), only egress asks outside wicket's own approval
/// namespace are taken (#117), and the reason on the card is this zone's own verdict, never the
/// node's text. The node's attribution is kept, shown as reported by the agent.
#[allow(clippy::too_many_arguments)]
fn ask(
    sh: &Shared,
    id: u64,
    run: &str,
    op: &Op,
    why_node: &str,
    who: Option<&serde_json::Value>,
    queued: Option<&(String, i64)>,
    prefix: bool,
) -> Msg {
    let reply = |pending, denied, error| Msg::Asked { id, pending, denied, error, hint: None };
    // An agent asking ahead (`request_access`, decided on its node, #164) gives its own reason.
    let agent = why_node.strip_prefix(AGENT_ASKS).map(|r| wicket_core::text::clip(r, 300));
    let (op, mut why) = match check_node_ask(&sh.tenant, &sh.run, &sh.zone, run, op, prefix && agent.is_some()) {
        Ok(x) => x,
        Err(e) => return reply(None, None, Some(e)),
    };
    // Raised while this host was unreachable (#153): the human sees that it is old.
    if let Some((q, at)) = queued {
        let secs = (wicket_feed::now_ms() - at).max(0) / 1000;
        why = format!("{why} (asked {secs}s ago, queued on node {} as {q} while the control host was unreachable)", sh.node);
    }
    let op = &op;
    // The node reports who asked if it knows; else the run's own attribution, read from the agent's
    // event stream outside the box (reported, not proven, either way).
    let ours = match who {
        Some(_) => None,
        None => sh.attribute.as_ref().and_then(|a| a(&op.host, &op.path)).map(|(v, _)| v),
    };
    let who = who.or(ours.as_ref());
    let l = sh.ledger.lock().expect("ledger");
    if let Ok(Some(rid)) = l.denied_recently(op) {
        return reply(None, Some(rid), None);
    }
    // As this host's gateway asks for it: in the agent's words, and for a prefix, every path
    // under the op's directory.
    let asked = match &agent {
        Some(reason) => {
            let old = why.split_once(" (asked ").map(|(_, q)| format!(" (asked {q}")).unwrap_or_default();
            l.ask(op, &format!("{AGENT_ASKS}{reason}{old}"), prefix, who)
        }
        None => l.pending_for(op, &why, who),
    };
    match asked {
        Ok((rid, fresh)) => {
            let hint = if agent.is_some() { repeat_hint(&l, &sh.tenant, run, op) } else { None };
            Msg::Asked { id, pending: Some((rid, fresh)), denied: None, error: None, hint }
        }
        Err(e) => reply(None, None, Some(e.to_string())),
    }
}

/// How many asks, in [`REPEAT_SECS`], make an agent's ask a repeat worth a hint (#572).
const REPEATS: u64 = 3;
const REPEAT_SECS: i64 = 7 * 24 * 3600;

/// When `run`'s agent has asked for `op`'s method on its host [`REPEATS`] times or more in the
/// last week (this ask included, in any of its runs): what to say so it asks once for standing
/// reach instead of again and again. By host and method, not path: the paths of one need (job
/// logs) differ ask by ask.
fn repeat_hint(l: &wicket_store::Ledger, tenant: &TenantId, run: &str, op: &Op) -> Option<String> {
    let who = l.identity(run).ok().flatten().filter(|i| i.parent_run.is_none())?;
    let (n, first) = l.asked_before(tenant, &who.spiffe_id, &op.method, &op.host, "/", wicket_store::now() - REPEAT_SECS).ok()?;
    (n >= REPEATS).then(|| {
        format!(
            "You have asked for {} on {} {n} times since {} (in this run and earlier ones). If this is part of your workload, ask once for standing reach instead: request_access with scope \"standing\" (and `methods` and `paths` for what you need); an operator approves it once, and your later runs don't ask again.",
            op.method,
            op.host,
            first.map(wicket_core::time::unix_rfc3339).unwrap_or_default()
        )
    })
}

/// A box's ask for standing reach (#572), from `request_access` on its node: for the agent's
/// principal, filed with the ledger's evidence for a human. Only the agent's own ask (in its
/// words), from its own connection; a spawned child has no principal of its own to bind it to.
#[allow(clippy::too_many_arguments)]
fn ask_standing(
    l: &wicket_store::Ledger,
    tenant: &TenantId,
    own: &RunId,
    zone: &ZoneSpec,
    id: u64,
    run: &str,
    rule: &wicket_core::manifest::ReachRule,
    why: &str,
) -> Msg {
    let reply = |pending, denied, error: Option<String>| Msg::Asked { id, pending, denied, error, hint: None };
    if run != own.0 {
        return reply(None, None, Some(format!("not run {run}'s connection")));
    }
    let Some(reason) = why.strip_prefix(AGENT_ASKS) else {
        return reply(None, None, Some("not requested: standing reach is the agent's own ask (request_access)".into()));
    };
    if !zone.escalation.request {
        return reply(None, None, Some(format!("not requested: {}.", wicket_proxy::NEVER_ASKS)));
    }
    let who = match l.identity(run) {
        Ok(Some(i)) if i.parent_run.is_none() => i,
        Ok(Some(_)) => {
            return reply(
                None,
                None,
                Some("not requested: a spawned child has no principal of its own to bind standing reach to (its zone names its parent's run); ask your parent to ask for it".into()),
            )
        }
        _ => return reply(None, None, Some("not requested: this run has no identity to bind standing reach to".into())),
    };
    // Denied in the last day, or one covering it was: not asked again. By coverage, not the JSON as
    // sent, so the same ask reordered, or a part of it, isn't a new one (#572 review, L4).
    let asked = rule.canonical();
    let day = wicket_store::now() - 24 * 3600;
    let covers = |d: &wicket_core::manifest::ReachRule| {
        d.host == asked.host
            && asked.methods.iter().all(|m| d.methods.contains(m))
            && asked.paths.iter().all(|p| d.paths.contains(p))
            && (d.allow_dangerous || !asked.allow_dangerous)
    };
    if let Ok(denied) = l.standing_with_status(tenant, "denied") {
        if let Some(d) =
            denied.iter().find(|d| d.principal == who.spiffe_id && covers(&d.rule.canonical()) && d.decided_at.unwrap_or(0) >= day)
        {
            return reply(None, Some(d.id.clone()), None);
        }
    }
    let digest = wicket_store::zone_digest(zone);
    match l.ask_standing(
        tenant,
        own,
        &zone.name,
        &digest,
        &who.spiffe_id,
        &asked,
        &format!("{AGENT_ASKS}{}", wicket_core::text::clip(reason, 300)),
    ) {
        Ok((sid, fresh)) => reply(Some((sid, fresh)), None, None),
        Err(e) => reply(None, None, Some(e.to_string())),
    }
}

/// A run's authority on its node, kept beside the run (`ctl/authority.json`, #153): until when the
/// node may keep its box running without this host (its token's block 0), and whether the node has
/// confirmed the box stopped. While it is live and unconfirmed, the run's agent is not woken
/// anywhere else, and a run on a node that can't be asked isn't ended as lost: two copies of an
/// agent would otherwise act at once, with separate budget slices and writes.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AuthorityRecord {
    pub node: String,
    /// Unix ms.
    pub until_ms: i64,
    #[serde(default)]
    pub stopped: bool,
    /// An operator released the fence without the node (#676): who, and why. The box may still
    /// run; the operator took that on, audited as `run.fence_released`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_by: Option<String>,
}

/// How far past a box's authority a wake still waits: clock skew between this host and the node.
/// The ledger's fence on a lapsed claim allows the same (#446).
pub const WAKE_SKEW_MS: i64 = wicket_store::WAKE_SKEW_SECS * 1000;

fn authority_file(run_dir: &Path) -> PathBuf {
    run_dir.join("ctl").join("authority.json")
}

/// Records a box's authority beside its run (a re-attach keeps what the node confirmed).
/// Durably, before the box starts: on disk (file and directory synced) before the node is asked to
/// start anything, so a crash can't leave a running box with no fence.
pub fn record_authority(run_dir: &Path, node: &str, until_ms: i64) -> Result<()> {
    let stopped = read_authority(run_dir).is_some_and(|a| a.stopped && a.until_ms == until_ms);
    write_authority(run_dir, &AuthorityRecord { node: node.into(), until_ms, stopped, released_by: None })
}

pub(crate) fn write_authority(run_dir: &Path, rec: &AuthorityRecord) -> Result<()> {
    use std::io::Write;
    let p = authority_file(run_dir);
    let dir = p.parent().expect("ctl");
    std::fs::create_dir_all(dir)?;
    let tmp = p.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec(rec)?)?;
    f.sync_all()?;
    std::fs::rename(&tmp, &p)?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

pub fn read_authority(run_dir: &Path) -> Option<AuthorityRecord> {
    serde_json::from_slice(&std::fs::read(authority_file(run_dir)).ok()?).ok()
}

/// The node has confirmed the box stopped (its exit, or it says it has no box for the run).
pub fn confirm_stopped(run_dir: &Path) {
    // A run whose record was lost gets one: confirmed, nothing left to fence.
    let mut a = read_authority(run_dir).unwrap_or_default();
    if !a.stopped {
        a.stopped = true;
        if let Err(e) = write_authority(run_dir, &a) {
            say_err!("[wicket] recording that {}'s box stopped: {e:#}", run_dir.display());
        }
    }
}

/// An operator releases run `run_dir`'s fence without its node (#676): for a run its node can't
/// confirm stopped (unreachable or revoked) whose fence wouldn't otherwise end. Marked as if the
/// node had confirmed, with who did it; the caller audits it (`run.fence_released`).
///
/// `expected` is the authority record the decision was made on: its node and `until_ms`, or None
/// if the run had none (#708). Refused if the record is no longer that (renewed, confirmed, or
/// written since), so a renewal between the decision and this write isn't overwritten.
pub fn release_fence(run_dir: &Path, by: &str, expected: Option<(&str, i64)>) -> Result<()> {
    let now = read_authority(run_dir);
    let current = now.as_ref().filter(|a| !a.stopped).map(|a| (a.node.as_str(), a.until_ms));
    if now.as_ref().is_some_and(|a| a.stopped) || current != expected {
        anyhow::bail!(
            "{}'s authority record changed since the fence was shown (renewed, or its node confirmed the box stopped): look again",
            run_dir.display()
        );
    }
    let mut a = now.unwrap_or_else(|| AuthorityRecord { node: "its node".into(), ..Default::default() });
    a.stopped = true;
    a.released_by = Some(by.to_string());
    write_authority(run_dir, &a)
}

/// Whether run `run`'s box may still be running on its node at `now_ms`: its node, and when that
/// ends for certain (its authority's end plus [`WAKE_SKEW_MS`]). None once the node confirmed the
/// box stopped (or an operator released it, [`release_fence`]), or the authority has ended, or for
/// a run without a record. The ledger's record of its authority's hard end (`runs.authority_cap`,
/// written before its box starts) bounds a fence its run's own records can't (#676).
pub fn fenced_until(l: &wicket_store::Ledger, run: &str, now_ms: i64) -> Option<(String, i64)> {
    crate::run::check_run_id(run).ok()?;
    let cap_ms = l.run_authority(run).ok().flatten().map(|(_, cap)| cap.saturating_mul(1000));
    fenced_in(&crate::data_dir().join("runs").join(run), now_ms, cap_ms)
}

/// [`fenced_until`] for the run in `run_dir`, with the ledger's hard end of its authority (Unix ms),
/// if recorded.
///
/// A run whose authority record is missing (lost) fences until its timeout, from its run record:
/// its box may run that long on its node, and no longer. If the run record is there but that can't
/// be read from it (#676), until the ledger's hard end; and with neither, until its node confirms the
/// box stopped ([`UNKNOWN_END`]), or an operator releases it. A run with no record of either kind
/// never started a box from this host's files: on a standby restored from the state store (#154),
/// the ledger's fence on the agent (`Ledger::agent_fenced_until`) holds instead.
pub fn fenced_in(run_dir: &Path, now_ms: i64, cap_ms: Option<i64>) -> Option<(String, i64)> {
    let a = match read_authority(run_dir) {
        Some(a) => a,
        None => {
            // No run record: no box was started from this host's files (or, on a standby restored
            // from the state store, #154, the lost host's files are gone and the ledger's own fence
            // on the agent holds instead). A record whose end can't be read: the ledger's hard end,
            // else until the node confirms.
            let until_ms = match (timeout_end(run_dir)?, cap_ms) {
                (UNKNOWN_END, Some(cap)) => cap,
                (t, _) => t,
            };
            AuthorityRecord { node: "its node".into(), until_ms, ..Default::default() }
        }
    };
    let until = a.until_ms.saturating_add(WAKE_SKEW_MS);
    (!a.stopped && now_ms < until).then_some((a.node, until))
}

/// Whether this host has the run record (`ctl/run.json`) of the run in `run_dir`.
pub fn has_run_record(run_dir: &Path) -> bool {
    run_dir.join("ctl/run.json").exists()
}

/// Why a run's box may still be running on its node: its node, until when (Unix ms), and whether
/// the ledger holds it rather than this host's records ([`held_until`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub node: String,
    pub until_ms: i64,
    pub by_ledger: bool,
}

/// Whether run `run`'s box may still be running on its node at `now_ms` (#153, #676): the one rule
/// the reconciler and a failed takeover share, so neither ends a run whose box may still run.
/// `fenced` is its fence from this host's records ([`fenced_until`]). With none, and no run record
/// here (`has_record`: a standby restored from the state store has none of the lost host's, #154),
/// the ledger's hard end of its box's authority holds it, plus 1 s and the skew, as
/// `Ledger::agent_fenced_until` has it. The cap rather than the latest renewal: a renewal the
/// standby's copy hasn't caught up with may have moved the box's end on.
///
/// A ledger that can't be read is an error, never "not held": the caller doesn't end a run whose
/// box it couldn't rule out.
pub fn held_until(
    l: &wicket_store::Ledger,
    run: &str,
    now_ms: i64,
    fenced: Option<(String, i64)>,
    has_record: bool,
) -> anyhow::Result<Option<Held>> {
    if let Some((node, until_ms)) = fenced {
        return Ok(Some(Held { node, until_ms, by_ledger: false }));
    }
    if has_record {
        return Ok(None);
    }
    let Some((_, cap)) = l.run_authority(run)? else { return Ok(None) };
    let until_ms = cap.saturating_add(1 + wicket_store::WAKE_SKEW_SECS).saturating_mul(1000);
    // Only the hold's words: a node that can't be read is "its node".
    let node = l.run_node(run).ok().flatten().unwrap_or_else(|| "its node".into());
    Ok((now_ms < until_ms).then_some(Held { node, until_ms, by_ledger: true }))
}

/// How long a hold lasts, in words: its end, or, for a fence this host can't bound, until its node
/// confirms the box stopped.
pub fn held_for(until_ms: i64) -> String {
    match until_ms {
        UNKNOWN_END => "until the node confirms the box stopped".to_string(),
        u => fmt_ms(u),
    }
}

/// Why a run's agent isn't woken while run `run`'s box may still run on `node` until `until` (Unix
/// ms, from [`fenced_until`]): when it can be, and how, the same words wherever it is said.
pub fn fence_refusal(run: &str, node: &str, until: i64) -> String {
    if until == UNKNOWN_END {
        format!(
            "its last activation (run {run}) may still be running on node {node}, and when its authority there ends can't be read from its records: it can be woken once node {node} reports the box stopped, or after an operator releases the fence (`wicket node release-fence {run}`, root, audited)"
        )
    } else {
        format!(
            "its last activation (run {run}) may still be running on node {node}, which this host can't confirm stopped, until its authority ends: it can be woken from {}, or as soon as node {node} reports the box stopped",
            fmt_ms(until)
        )
    }
}

/// When a run's box must have stopped by its timeout (Unix ms), from its run record (`ctl/run.json`):
/// its start, its zone's timeout, and a long-lived agent's node backstop (120 s). None if there is no
/// run record (no box was started). If the record is there but its start or timeout can't be read
/// (a stored manifest a later version no longer loads is read leniently, `stored_timeout`; one that
/// doesn't parse at all isn't), [`UNKNOWN_END`]: the box may run for as long as it was given, which
/// this host can't tell, so it is fenced until its node confirms it stopped (#676: fail closed).
fn timeout_end(run_dir: &Path) -> Option<i64> {
    let bytes = std::fs::read(run_dir.join("ctl/run.json")).ok()?;
    Some(read_timeout_end(&bytes).unwrap_or(UNKNOWN_END))
}

fn read_timeout_end(run_json: &[u8]) -> Option<i64> {
    let v: serde_json::Value = serde_json::from_slice(run_json).ok()?;
    let secs = i64::try_from(wicket_core::manifest::stored_timeout(v["manifest"].as_str()?)?.as_secs()).ok()?;
    v["started_ms"].as_i64()?.checked_add(secs.checked_mul(1000)?)?.checked_add(120_000)
}

/// A fence's end when this host can't tell when a box's authority ends (#676): never, until its node
/// confirms the box stopped.
pub const UNKNOWN_END: i64 = i64::MAX;

/// What this host has released to a run's node, secrets and budget slices (#152), kept beside the run
/// (`ctl/holdings.json`) for `wicket node list`: the secrets the node fetched for the run (by name,
/// never values) and its budget slice. An upper bound: the node may have dropped some already, never
/// holds more.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Holdings {
    pub secrets: Vec<String>,
    /// What each secret was when released (#818: [`crate::nodesecrets::digest`], a SHA-256 over the
    /// value and its binding, never the value), so a supervisor that takes the run over tells a
    /// secret that changed from one the node still holds as released, and doesn't make the node
    /// fetch again what a self-update handed to its new process. A secret revoked and not fetched
    /// since has none, or `changed` for one revoked because it changed (sent again as a change, #415).
    /// In the run's own directory, private to wicket's user, as the vault is.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub digests: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice: Option<wicket_proxy::llm::Slice>,
    /// When this was last written (Unix ms).
    pub updated_ms: i64,
}

fn save_holdings(sh: &Shared, p: &Progress) {
    let h = holdings_of(&p.fetched, p.slice, wicket_feed::now_ms());
    let f = sh.dir.join("ctl").join("holdings.json");
    if let Err(e) = wicket_chan::files::replace(&f, "tmp", &serde_json::to_vec(&h).unwrap_or_default()) {
        say_err!(
            "[wicket] run {}'s holdings on node {} can't be written ({e:#}): a supervisor that takes it over revokes all it released",
            sh.run,
            sh.node
        );
    }
}

/// What a run's holdings record (#152, #818): the secrets released to its node, and the digest each
/// went with; for one revoked for a change and not fetched since, [`CHANGED`] in its place, and for
/// one revoked otherwise none ([`REVOKED`]): a supervisor that takes the run over revokes either
/// again, as it was revoked.
fn holdings_of(fetched: &std::collections::HashMap<String, String>, slice: Option<wicket_proxy::llm::Slice>, now_ms: i64) -> Holdings {
    let mut secrets: Vec<String> = fetched.keys().cloned().collect();
    secrets.sort();
    let digests = fetched.iter().filter(|(_, d)| d.as_str() != REVOKED).map(|(n, d)| (n.clone(), d.clone())).collect();
    Holdings { secrets, digests, slice, updated_ms: now_ms }
}

pub fn read_holdings(run_dir: &Path) -> Option<Holdings> {
    serde_json::from_slice(&std::fs::read(run_dir.join("ctl").join("holdings.json")).ok()?).ok()
}

/// What node `node` holds for the runs this host supervises there, as far as this host knows: each
/// running run's authority, the secrets released to it and its budget slice.
pub fn node_holdings(l: &Ledger, node: &str) -> Result<Vec<(String, Option<AuthorityRecord>, Holdings)>> {
    let mut v = vec![];
    for (run, _) in l.running_runs()? {
        if l.run_node(&run)?.as_deref() != Some(node) || crate::run::check_run_id(&run).is_err() {
            continue;
        }
        let dir = crate::data_dir().join("runs").join(&run);
        v.push((run, read_authority(&dir), read_holdings(&dir).unwrap_or_default()));
    }
    Ok(v)
}

/// One line of a run's holdings on its node.
pub fn holdings_line(run: &str, a: Option<&AuthorityRecord>, h: &Holdings, now_ms: i64) -> String {
    let auth = match a {
        Some(a) if a.stopped => "box stopped (confirmed by the node)".to_string(),
        Some(a) if a.until_ms <= now_ms => format!("authority ended {}", fmt_ms(a.until_ms)),
        Some(a) => format!("authority until {}", fmt_ms(a.until_ms)),
        None => "authority: no record".to_string(),
    };
    let secrets = match h.secrets.is_empty() {
        true => "no secrets".to_string(),
        false => format!("secrets {}", h.secrets.join(",")),
    };
    let slice = match &h.slice {
        Some(s) => format!(
            "budget slice up to {} requests, {} output tokens{}",
            s.requests,
            s.output_tokens,
            s.input_tokens.map(|i| format!(", {i} input tokens")).unwrap_or_default()
        ),
        None => "no budget slice".to_string(),
    };
    format!("  {run}  {auth}  {secrets}  {slice}")
}

/// When (Unix ms) as a readable UTC time.
pub fn fmt_ms(ms: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ms / 1000)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_else(|| format!("{ms} ms"))
}

/// The fraction of a run's model budget sent to its node as a slice at a time (#152):
/// `WICKET_NODE_BUDGET_SLICE` on the control host, default 0.25. Offline, the node can spend what is
/// left of its slice and nothing more; connected, it is renewed before half of it is gone.
fn slice_fraction() -> f64 {
    std::env::var("WICKET_NODE_BUDGET_SLICE").ok().and_then(|v| v.parse::<f64>().ok()).filter(|f| *f > 0.0 && *f <= 1.0).unwrap_or(0.25)
}

/// The run's budget slice for its node (#152), if it differs from the last one sent on this
/// connection: renewed once less than half a slice is left, and lowered at once if what is
/// left of the budget shrinks below it (a spawn's carve-out).
fn slice_due(sh: &Shared, p: &mut Progress) -> Option<Frame> {
    let l = sh.llm.as_ref()?;
    let next = l.next_slice(slice_fraction())?;
    // A re-attached supervisor counts the node's spend from its first report (#422): the slice goes
    // out in the node's own counts, or a node that had spent the first report's amount would hold a
    // slice that much short, and none at all once that passed a slice (its calls all refused).
    let base = sh.spent_base.lock().expect("spent base").flatten().unwrap_or_default();
    let slice = wicket_proxy::llm::Slice::renewed_from(p.slice, next, l.spent(), l.input_total(), base);
    if p.slice_sent && p.slice == Some(slice) {
        return None;
    }
    if !p.slice_sent {
        say!("[wicket] sending node {} a budget slice for {}: {slice:?}", sh.node, sh.run);
    }
    p.slice_sent = true;
    p.slice = Some(slice);
    save_holdings(sh, p);
    Some(Frame::Msg(Msg::BudgetSlice { run: sh.run.0.clone(), slice }))
}

/// Releases secret `name` to this run's node, on its first use there (#152): only if the run's zone
/// (or one of its credential swaps, #257) uses it and the vault's binding covers the hosts it uses
/// it for. Audited either way.
fn fetch_secret(sh: &Shared, p: &mut Progress, id: u64, name: &str) -> Msg {
    // The registry's credential, for the pull of the box's image only (#191): bound to its host
    // and its token service's, and only while that pull is under way. The node holds it for the
    // pull alone, so it isn't among the secrets it keeps for the run.
    let for_pull = sh.pull.as_ref().filter(|s| s.secret.as_deref() == Some(name) && sh.pulling.load(Ordering::SeqCst));
    let r = match for_pull {
        Some(src) => {
            let hosts: Vec<String> = std::iter::once(src.host.clone()).chain(src.auth_hosts.iter().cloned()).collect();
            crate::nodesecrets::release_for_hosts(&sh.vault, name, &hosts, sh.ctl.authority_until())
        }
        None => crate::nodesecrets::release_run(&sh.zone, &sh.swaps, &sh.vault, name, sh.ctl.authority_until()),
    };
    let (ok, why) = match &r {
        Ok(_) => (true, None),
        Err(e) => (false, Some(e.clone())),
    };
    if for_pull.is_none() {
        let digest = r.as_ref().ok().map(crate::nodesecrets::digest);
        let uses = crate::nodesecrets::zone_uses(&sh.zone, &sh.swaps, name);
        let audit = record_answer(&mut p.fetched, &mut p.refused, name, digest, uses);
        if ok {
            save_holdings(sh, p);
        }
        if !audit {
            return Msg::SecretFetched { id, secret: None, error: why };
        }
    }
    let _ = sh.ledger.lock().expect("ledger").audit(
        &sh.tenant,
        Some(&sh.run),
        "node.secret_fetch",
        &serde_json::json!({ "node": sh.node, "secret": name, "released": ok, "why": why, "image_pull": for_pull.is_some() }),
    );
    match r {
        Ok(f) => Msg::SecretFetched { id, secret: Some(Box::new(f)), error: None },
        Err(e) => Msg::SecretFetched { id, secret: None, error: Some(e) },
    }
}

/// Records the answer to a node's fetch of `name` for the run: `released`'s digest, or None if it was
/// refused, of a name the run's zone or swaps `uses` or not. Whether to audit it: a release always;
/// a refusal of a name the zone uses only when first refused (#415: an optional rule's secret not
/// set yet is asked about again after a while, and is tracked so the node can be told when it's set).
fn record_answer(
    fetched: &mut std::collections::HashMap<String, String>,
    refused: &mut HashSet<String>,
    name: &str,
    released: Option<String>,
    uses: bool,
) -> bool {
    match released {
        Some(d) => {
            refused.remove(name);
            fetched.insert(name.to_string(), d);
            true
        }
        None if uses => refused.insert(name.to_string()),
        None => true,
    }
}

/// What an earlier supervisor of the run in `run_dir` released to its node, from its holdings (#415):
/// each with the digest it was released with, so the first check revokes only what changed since
/// (#818), or marked [`REVOKED`] if none was kept (revoked since, or holdings from before digests),
/// so the first connection revokes it.
fn released_before(run_dir: &Path) -> std::collections::HashMap<String, String> {
    let Some(h) = read_holdings(run_dir) else { return Default::default() };
    h.secrets
        .into_iter()
        .map(|n| {
            let d = h.digests.get(&n).cloned().unwrap_or_else(|| REVOKED.to_string());
            (n, d)
        })
        .collect()
}

/// What a new connection revokes, given what `release` would release now (#415, #818): first again
/// each revoke that may have been lost ([`revoke_lost`], `resend`), then each secret that changed
/// meanwhile, or refused one now released ([`changed_secrets`], not `resend`: it cascades to the
/// children the node shared it with). Not a secret the node holds as released and unchanged.
fn connect_revokes(
    fetched: &mut std::collections::HashMap<String, String>,
    refused: &mut HashSet<String>,
    release: impl Fn(&str) -> Option<String>,
) -> Vec<(String, bool)> {
    let lost = revoke_lost(fetched, refused);
    let changed = changed_secrets(fetched, refused, release);
    // A refusal now released is in both: once, as resent (the node only forgets the refusal).
    let changed: Vec<String> = changed.into_iter().filter(|n| !lost.iter().any(|(l, _)| l == n)).collect();
    lost.into_iter().chain(changed.into_iter().map(|n| (n, false))).collect()
}

/// What [`Progress::fetched`] holds for a secret revoked and not fetched since (#415): no release's
/// digest, so it is never taken for one, and the name is revoked again on the next connection, as a
/// resend (it leaves the uses the node shared with children it started while cut off). For a box that
/// exited, and for holdings with no digest for it.
const REVOKED: &str = "revoked";

/// [`REVOKED`], for a secret revoked because it changed (rotated, rebound, removed): sent again on
/// the next connection as the change it was, not a resend, so it still ends the uses shared with
/// children if the first one was lost. Kept in the run's holdings as such.
const CHANGED: &str = "changed";

/// Whether `d` marks a secret revoked rather than a release's digest.
fn marked(d: &str) -> bool {
    d == REVOKED || d == CHANGED
}

/// Secrets this run's node fetched that have since changed, been rebound or removed on this host,
/// and secrets refused to it that can now be released (#415): the node is told to drop what it holds
/// of each, or knows of it, and the next use fetches it again (#152).
fn secrets_changed(sh: &Shared, p: &mut Progress) -> Vec<Frame> {
    let release = |name: &str| {
        crate::nodesecrets::release_run(&sh.zone, &sh.swaps, &sh.vault, name, sh.ctl.authority_until())
            .ok()
            .map(|f| crate::nodesecrets::digest(&f))
    };
    let changed = changed_secrets(&mut p.fetched, &mut p.refused, release);
    if !changed.is_empty() {
        // Marked revoked: a supervisor that takes over revokes them again rather than trust them.
        save_holdings(sh, p);
    }
    changed
        .into_iter()
        .map(|name| {
            say!("[wicket] secret {name} changed on this host: node {} fetches it again for {}", sh.node, sh.run);
            Frame::Msg(Msg::SecretRevoke { run: sh.run.0.clone(), name, resend: false })
        })
        .collect()
}

/// The names to tell a node changed, given what `release` would release now (its digest, or None if
/// refused): each fetched one whose digest differs (then marked [`CHANGED`] until fetched again), and
/// each refused one now released (forgotten, so its next refusal is recorded again).
fn changed_secrets(
    fetched: &mut std::collections::HashMap<String, String>,
    refused: &mut HashSet<String>,
    release: impl Fn(&str) -> Option<String>,
) -> Vec<String> {
    let mut out: Vec<String> =
        fetched.iter().filter(|(n, d)| !marked(d) && release(n).as_deref() != Some(d.as_str())).map(|(n, _)| n.clone()).collect();
    out.sort();
    for n in &out {
        fetched.insert(n.clone(), CHANGED.into());
    }
    let mut now_set: Vec<String> = refused.iter().filter(|n| release(n).is_some()).cloned().collect();
    now_set.sort();
    for n in &now_set {
        refused.remove(n);
    }
    out.extend(now_set);
    out
}

/// What a new connection revokes again (#415), as one sent on a link that died may never have
/// arrived, each with whether it goes as a resend: a secret revoked for a change ([`CHANGED`]) as the
/// change it was (not a resend, so it ends uses shared with children), one revoked otherwise
/// ([`REVOKED`]) and every refusal (which the node then asks about again) as resends. Not a secret the
/// node holds as released and unchanged (#818: a self-update hands the node's cache to its new
/// process, which keeps using it); one that changed meanwhile is found by [`changed_secrets`], run on
/// the connection right after.
fn revoke_lost(fetched: &std::collections::HashMap<String, String>, refused: &HashSet<String>) -> Vec<(String, bool)> {
    let mut out: std::collections::BTreeMap<String, bool> = refused.iter().map(|n| (n.clone(), true)).collect();
    for (n, d) in fetched {
        match d.as_str() {
            CHANGED => {
                out.insert(n.clone(), false);
            }
            REVOKED => {
                out.entry(n.clone()).or_insert(true);
            }
            _ => {}
        }
    }
    out.into_iter().collect()
}

/// The op a node asks about, as the control host classifies it, and why it needs a grant, as this
/// zone decides it; refused if it isn't this run's, isn't egress, isn't canonical, is in wicket's
/// own namespace, or doesn't need a grant (forbidden, or already allowed).
#[cfg(test)]
fn check_node_op(tenant: &TenantId, own: &RunId, zone_spec: &ZoneSpec, run: &str, op: &Op) -> Result<(Op, String), String> {
    check_node_ask(tenant, own, zone_spec, run, op, false)
}

/// [`check_node_op`], and with `prefix` (an agent asking ahead for every path under a directory,
/// #164) a path the zone already allows may be the one asked about, as on this host's gateway.
fn check_node_ask(tenant: &TenantId, own: &RunId, zone_spec: &ZoneSpec, run: &str, op: &Op, prefix: bool) -> Result<(Op, String), String> {
    let zone = zone_spec.name.as_str();
    if run != own.0 || op.run != *own || op.tenant != *tenant || op.zone != zone {
        return Err(format!("not an op of run {own}"));
    }
    if op.surface != wicket_core::Surface::Egress {
        return Err("a node asks only about egress".into());
    }
    // A zone that may not ask (#50): nothing it asks for is raised, whoever relays it.
    if !zone_spec.escalation.request {
        return Err(format!("not requested: {}", wicket_proxy::NEVER_ASKS));
    }
    match wicket_core::canonical_path(&op.path) {
        Ok(p) if p == op.path => {}
        _ => return Err("not requested: the path is not canonical".into()),
    }
    let mut fresh = Op::egress(tenant, own, zone, &op.method, &op.host, &op.path);
    if fresh.method != op.method || fresh.host != op.host {
        return Err("not requested: the method or host is not canonical".into());
    }
    if let Some(why) = fresh.refused_for_agents() {
        return Err(format!("not requested: {why}"));
    }
    if op.risk > fresh.risk {
        fresh.risk = op.risk;
        fresh.effects.extend(op.effects.iter().map(|e| wicket_core::text::clip(e, 120)));
    }
    match wicket_core::evaluate(zone_spec, &fresh) {
        wicket_core::Verdict::NeedsGrant(why) => {
            let why = wicket_core::git::ask_reason(&fresh, &why);
            Ok((fresh, why))
        }
        wicket_core::Verdict::Forbidden(why) => Err(format!("not requested: {why}")),
        wicket_core::Verdict::AllowByReach(i) if prefix => {
            Ok((fresh, format!("reach rule {i} allows this path; asked for every path under it")))
        }
        wicket_core::Verdict::AllowByReach(_) => Err("not requested: this zone already allows it".into()),
    }
}

/// Publishes grants approved for this run's requests to its node, and revocations of grants it
/// published. It only publishes: since #257's slice 3 the node alone decides a box's egress and
/// counts a grant's uses, and the ledger records issuance (the grant, its renewals and its
/// revocation, and that it was handed to the node). No egress grant is kept back for the control
/// host to decide: one the node can't honour as approved is never published, and the box's request
/// is asked about again.
///
/// A grant reaches the node as a block of the box's token: whenever the live grants change, the
/// token is rebuilt from its base with one block per live grant (signed with the approver key) and
/// published whole, in the same delta as any grant revocations. At most
/// [`wicket_feed::token::MAX_GRANTS`] are live at once; more wait in the ledger until some expire.
///
/// Renewals (#56) go out the same way: a renewed grant's block is rebuilt with its new end, and a
/// renewed authority re-mints block 0 with its new end (the same ceiling, minted again), so the
/// node holds the box past its old end. Nothing new on the feed: one `PutZone`, as for any grant.
fn sync_grants(sh: &Shared, p: &mut Progress) -> Vec<wicket_feed::Frame> {
    let (grants, authority) = {
        let l = sh.ledger.lock().expect("ledger");
        let g = l.grants_for_run(&sh.run.0).unwrap_or_default();
        (g, l.run_authority(&sh.run.0).ok().flatten())
    };
    let now_s = wicket_store::now();
    let mut changes = vec![];
    let Ok(ctx) = sh.ctl.publisher.lock().map(|p| p.state().ctx) else { return vec![] };
    // The box's authority, renewed past what its token says: block 0 minted again until then.
    let held = sh.ctl.authority_until() / 1000;
    let reminted = match authority {
        Some((until, _)) if until > held && until > now_s && until != p.remint_failed => {
            match mint_token(
                &sh.tenant,
                &sh.run,
                &sh.zone,
                &sh.image,
                sh.org.as_deref(),
                &sh.approver,
                u64::try_from(until).unwrap_or(0),
                None,
            ) {
                Ok(i) => Some((i, until)),
                Err(e) => {
                    p.remint_failed = until;
                    say!("[wicket] could not re-mint {}'s token for its renewed authority: {e:#}; the box stops at its old end", sh.run);
                    None
                }
            }
        }
        _ => None,
    };
    let issuer = match &reminted {
        Some((i, _)) => i.clone(),
        None => sh.token_issuer.lock().expect("token issuer").clone(),
    };
    // Whether the token with these grants would load on a node (the publisher refuses it otherwise).
    let loads = |live: &[LiveGrant]| -> Result<(), String> {
        let a = issuer.publish(&sh.approver, live).map_err(|e| e.to_string())?;
        wicket_feed::Policy::compile(&a, &ctx, &|_, _| false).map(|_| ())
    };
    let before = p.live.len();
    // Live while `now < expires_at`, published as `not_after = expires_at - 1` (#342).
    p.live.retain(|g| g.grant.not_after >= u64::try_from(now_s).unwrap_or(0));
    let mut rebuild = p.live.len() != before || reminted.is_some();
    rebuild |= renew_live(&mut p.live, &grants, &sh.node, now_s);
    let mut handed: Vec<String> = vec![];
    for g in grants {
        let mine = g.node.as_deref() == Some(sh.node.as_str());
        if g.revoked && mine && p.published.contains(&g.id) && p.revoked.insert(g.id.clone()) {
            changes.push(Change::Revoke { kind: RevokeKind::Grant, id: g.id.clone(), until: g.expires_at * 1000 });
            p.live.retain(|l| l.grant.gid != g.id);
            rebuild = true;
            continue;
        }
        if g.revoked || g.node.is_some() || g.expires_at <= now_s || p.published.contains(&g.id) {
            continue;
        }
        // Grants in wicket's own namespace (spawn, capacity, links) are the control host's to use:
        // it is wicket that asks for them, never a box's egress.
        if Op::egress(&sh.tenant, &sh.run, &sh.zone.name, &g.method, &g.host, &g.path).refused_for_agents().is_some() {
            continue;
        }
        // Every egress grant goes to the node, whatever its host (#257): one on a host the node's
        // CA can't cover is held there too, and allows nothing, since that host is spliced (when the
        // token allows it wholesale) or refused before any request to it is decided.
        if p.live.len() >= wicket_feed::token::MAX_GRANTS {
            if p.waiting.insert(g.id.clone()) {
                say!("[wicket] node {} holds {} live grants for {}: grant {} waits until one ends", sh.node, p.live.len(), sh.run, g.id);
            }
            continue;
        }
        // A node's grant covers its path whatever the query, and carries no risk bound: hand it over
        // only if no query makes that path riskier than the human approved (#119; a fetch's ref
        // discovery approved at R1 is a push's at R4). Otherwise it is never published: nothing else
        // decides egress, so the box's request is asked about again.
        let worst = Op::egress_with_query(&sh.tenant, &sh.run, &sh.zone.name, &g.method, &g.host, &g.path, "any=query");
        if worst.risk.rank() > g.max_risk.unwrap_or(0) {
            if p.published.insert(g.id.clone()) {
                say!(
                    "[wicket] grant {} is bounded below what {} {}{} can be, which a node can't honour: it isn't published",
                    g.id,
                    g.method,
                    g.host,
                    g.path
                );
            }
            continue;
        }
        // A prefix grant as the prefix it is, on a node that admits one (#257 4a, protocol 16).
        let as_prefix = publish_as_prefix(g.prefix, p.proto);
        let live = live_grant(&sh.tenant, &sh.run, &sh.zone.name, &issuer, &g, as_prefix);
        let mut trial = p.live.clone();
        trial.push(live.clone());
        if let Err(e) = loads(&trial) {
            // Never handed over, and nothing else decides it.
            if p.published.insert(g.id.clone()) {
                say!("[wicket] grant {} can't go in {}'s token ({e}): it isn't published", g.id, sh.run);
            }
            continue;
        }
        if !sh.ledger.lock().expect("ledger").hand_grant_to_node(&g.id, &sh.node).unwrap_or(false) {
            continue;
        }
        want_grant_host(sh, &g);
        if g.prefix && !as_prefix {
            say!(
                "[wicket] grant {} is for a path prefix; node {} (protocol {}) honours it for {} exactly: update it (wicket node install)",
                g.id,
                sh.node,
                p.proto,
                g.path
            );
        }
        p.live.push(live);
        handed.push(g.id.clone());
        p.published.insert(g.id);
        rebuild = true;
    }
    // Standing reach (#572): the live standing rules bound to this run's agent or zone, as blocks of
    // its token ([`sync_standing`]).
    let top_level = issuer.box_path == sh.run.0;
    let rules = match p.proto >= wicket_chan::chan::STANDING && top_level {
        true => sh
            .ledger
            .lock()
            .expect("ledger")
            .standing_for_run(&sh.tenant, &sh.run, &sh.zone.name, &wicket_store::zone_digest(&sh.zone))
            .map_err(|e| e.to_string()),
        false => Ok(vec![]),
    };
    let (node, run) = (sh.node.clone(), sh.run.0.clone());
    let before = p.standing.clone();
    let (more, changed) =
        sync_standing(&mut p.standing, &mut p.live, &mut p.waiting, rules, p.proto, top_level, now_s, &issuer, &loads, &mut |m| {
            say!("[wicket] {run} on node {node}: {m}")
        });
    changes.extend(more);
    rebuild |= changed;
    // The host ports of the box's public names (#575 step 4c), for a node that reads them.
    let ports = if p.proto >= wicket_chan::chan::PORTS && reads_ports(&sh.node) { wanted_ports(sh, now_s) } else { vec![] };
    rebuild |= ports != p.ports;
    // Where each rule is on its way to the node (#572), for `await_grant` on it: the ones put in
    // (or renewed) are handed now and published with this delta; the ones taken out are gone.
    let (handed_rules, gone_rules) = standing_moves(&before, &p.standing);
    {
        let l = sh.ledger.lock().expect("ledger");
        if p.standing.is_empty() {
            // None in its token (none bind it, or its node is below protocol 17): none is on its
            // way, whatever an earlier supervisor recorded (#752 review, F2).
            let _ = l.standing_none(&sh.run.0);
        } else {
            let _ = l.standing_withdrawn(&sh.run.0, &gone_rules);
            let _ = l.standing_handed(&sh.run.0, &sh.node, &handed_rules);
        }
    }
    if !rebuild {
        return vec![];
    }
    let renewing = match issuer.publish(&sh.approver, &p.live) {
        Ok(mut a) => {
            a.ports = ports.clone();
            changes.push(Change::PutZone { zone: a });
            reminted
        }
        Err(e) => {
            say!("[wicket] could not rebuild the token of {} for node {}: {e}", sh.run, sh.node);
            None
        }
    };
    if changes.is_empty() {
        return vec![];
    }
    let n = p.live.len();
    let revokes: Vec<Change<BoxAuthority>> = changes.iter().filter(|c| matches!(c, Change::Revoke { .. })).cloned().collect();
    // Whether the rebuilt token went out (not only its revocations): a renewal counts only then.
    let has_token = changes.iter().any(|c| matches!(c, Change::PutZone { .. }));
    let token_out;
    let ports_out;
    let committed = {
        let Ok(mut p) = sh.ctl.publisher.lock() else { return vec![] };
        // Again under the feed's lock (#691): every live session to the node reads ports, or none
        // go (an older node's strict parse would refuse the record, and its whole feed with it).
        let mut changes = changes;
        gate_ports(&mut changes, node_protocol_now(&sh.node));
        ports_out = changes.iter().find_map(|c| match c {
            Change::PutZone { zone } => Some(zone.ports.clone()),
            _ => None,
        });
        let mut r = p.commit(changes, wicket_feed::now_ms());
        token_out = r.is_ok() && has_token;
        if r.is_err() && !revokes.is_empty() {
            // The rebuilt token was refused: the revocations must still go out.
            say!(
                "[wicket] could not publish {}'s rebuilt token ({}); publishing its grant revocations alone",
                sh.run,
                r.as_ref().err().map(|e| e.to_string()).unwrap_or_default()
            );
            r = p.commit(revokes, wicket_feed::now_ms());
        }
        r.map(|f| (f, p.epoch()))
    };
    if let Ok((_, epoch)) = &committed {
        let l = sh.ledger.lock().expect("ledger");
        let _ = l.grants_published(&handed, *epoch as i64);
        // Every rule handed and not yet published went with the token, this tick's or one whose
        // commit failed before (#752 review, F2).
        if token_out {
            let _ = l.standing_published(&sh.run.0, *epoch as i64);
        }
        drop(l);
        // What the node's record carries now: the ports, or none if they were held back.
        if let (true, Some(out)) = (token_out, ports_out) {
            p.ports = out;
        }
        if let Some((i, until)) = renewing.filter(|_| token_out) {
            renewed(sh, i, until);
        }
    }
    match committed {
        Ok((f, epoch)) => {
            say!(
                "[wicket] published {}'s token with {n} live grant(s) to node {}, epoch {epoch} (at {} ms)",
                sh.run,
                sh.node,
                wicket_feed::now_ms()
            );
            vec![f]
        }
        Err(e) => {
            say!("[wicket] could not publish grants to node {}: {e}", sh.node);
            vec![]
        }
    }
}

/// Gives each grant the box's token carries the end the ledger has for it now: a renewed grant
/// (#56) is published with its new end. Whether any changed.
fn renew_live(live: &mut [LiveGrant], grants: &[wicket_store::GrantRow], node: &str, now_s: i64) -> bool {
    let mut changed = false;
    for g in grants.iter().filter(|g| g.node.as_deref() == Some(node) && !g.revoked && g.expires_at > now_s) {
        let end = wicket_authz::Grant::not_after_for(g.expires_at);
        if let Some(l) = live.iter_mut().find(|l| l.grant.gid == g.id && l.grant.not_after != end) {
            l.grant.not_after = end;
            changed = true;
        }
    }
    changed
}

/// The box's re-minted token, until `until` (Unix seconds), is on the feed: it is the one revoked
/// with the box, the one secrets are released until, what fences a wake elsewhere, and what the
/// run's agent may grant within (#56).
fn renewed(sh: &Shared, issuer: wicket_feed::Issuer, until: i64) {
    let until_ms = until.saturating_mul(1000);
    sh.ctl.token_roots.lock().expect("token roots").push((issuer.block_ids()[0].clone(), until_ms));
    *sh.token_issuer.lock().expect("token issuer") = issuer;
    if let Some(a) = &sh.authority_until {
        a.store(until, Ordering::SeqCst);
    }
    if let Err(e) = record_authority(&sh.dir, &sh.node, until_ms + 1000) {
        say!("[wicket] could not record {}'s renewed authority: {e:#}", sh.run);
    }
    say!("[wicket] {}'s authority on node {} renewed until {until}", sh.run, sh.node);
    let _ = sh.ledger.lock().expect("ledger").audit(
        &sh.tenant,
        Some(&sh.run),
        "node.authority_renewed",
        &serde_json::json!({ "node": sh.node, "until": until }),
    );
}

/// A ledger grant as a block of the box's token. Its use count is the ledger's at handover: a
/// re-minted token (a re-attached run) gives the node that count again.
/// Whether a ledger grant is published to a node as a path-prefix grant (#257 4a): a prefix grant,
/// to a node at protocol 16 or later. An older node's structural check refuses the block, and with
/// it the box's whole token, so it is sent the grant for its own path exactly, as before.
fn publish_as_prefix(prefix: bool, proto: u32) -> bool {
    prefix && proto >= wicket_chan::chan::PREFIX_GRANTS
}

/// `prefix`: published as the path-prefix grant it is (#257 4a), for a node at protocol 16 or later;
/// otherwise (`false`) for its own path exactly.
fn live_grant(
    tenant: &TenantId,
    run: &RunId,
    zone: &str,
    issuer: &wicket_feed::Issuer,
    g: &wicket_store::GrantRow,
    prefix: bool,
) -> LiveGrant {
    let op = Op::egress(tenant, run, zone, &g.method, &g.host, &g.path);
    let path = if prefix { wicket_core::prefix_dir(&op.path) } else { op.path.clone() };
    LiveGrant {
        grant: wicket_authz::Grant {
            gid: g.id.clone(),
            box_id: issuer.box_path.clone(),
            epoch: issuer.epoch,
            host: op.host.clone(),
            method: op.method.clone(),
            path,
            // The ledger's end, as the token's inclusive whole-second check reads it (#342).
            not_after: wicket_authz::Grant::not_after_for(g.expires_at),
            approver: g.request_id.as_deref().map_or_else(|| "operator".to_string(), |r| format!("request:{r}")),
            digest: hex::decode(op.digest()).unwrap_or_default(),
        },
        uses: g.uses_left.map(|u| u.clamp(0, i64::from(u32::MAX)) as u32),
        prefix,
        standing: None,
    }
}

/// The end a standing rule approved until revoked is published with: 9999-12-31, the latest date
/// the token's check reads.
const STANDING_FOREVER: u64 = 253_402_300_799;

/// An approved standing rule (#572) as a block of the box's token: its host, methods and path
/// globs, until it lapses (or [`STANDING_FOREVER`]), with no use count (the node gives it all the
/// uses it asks for). Approved by the human whose decision it records.
fn standing_live(issuer: &wicket_feed::Issuer, s: &wicket_store::Standing) -> LiveGrant {
    LiveGrant {
        grant: wicket_authz::Grant {
            gid: s.id.clone(),
            box_id: issuer.box_path.clone(),
            epoch: issuer.epoch,
            host: s.rule.host.to_ascii_lowercase(),
            method: s.rule.methods.first().cloned().unwrap_or_default(),
            path: String::new(),
            not_after: s.expires_at.map_or(STANDING_FOREVER, wicket_authz::Grant::not_after_for),
            approver: format!("standing:{}", s.decided_by.as_deref().unwrap_or("operator")),
            digest: s.effect_sha256.as_deref().and_then(|e| hex::decode(e).ok()).unwrap_or_default(),
        },
        uses: None,
        prefix: false,
        standing: Some(wicket_authz::StandingRule {
            methods: s.rule.methods.clone(),
            paths: s.rule.paths.clone(),
            allow_dangerous: s.rule.allow_dangerous,
        }),
    }
}

/// The standing part of a token sync (#572), apart from the ledger and the feed so it can be
/// tested: `rules` are the live standing rules the ledger binds to the run now (or why they
/// couldn't be read), `published` what the box's token carries (by id, with the end each was
/// published with). The feed changes to make, and whether the token must be rebuilt.
///
/// - On a node below protocol 17, or for a spawned child's box, none is published; any published
///   before (a node rolled back to 16) come out of the token, which that node couldn't load with
///   them (#572 review, L6).
/// - Rules that can't be read this tick change nothing: a read error isn't "no rules", which would
///   revoke every published one on the node for a year (M4).
/// - One no longer live (revoked, lapsed, unbound) is revoked on the node, as a grant is.
/// - One whose end changed (renewed, or shortened) is published again with its new end (M3).
/// - A new one goes in if the token has room and loads with it.
#[allow(clippy::too_many_arguments)]
fn sync_standing(
    published: &mut std::collections::HashMap<String, u64>,
    live: &mut Vec<LiveGrant>,
    waiting: &mut HashSet<String>,
    rules: std::result::Result<Vec<wicket_store::Standing>, String>,
    proto: u32,
    top_level: bool,
    now_s: i64,
    issuer: &wicket_feed::Issuer,
    loads: &dyn Fn(&[LiveGrant]) -> std::result::Result<(), String>,
    log: &mut dyn FnMut(String),
) -> (Vec<Change<BoxAuthority>>, bool) {
    let mut changes = vec![];
    let mut rebuild = false;
    if proto < wicket_chan::chan::STANDING || !top_level {
        if !published.is_empty() {
            live.retain(|l| !published.contains_key(&l.grant.gid));
            published.clear();
            rebuild = true;
        }
        return (changes, rebuild);
    }
    let rules = match rules {
        Ok(r) => r,
        Err(e) => {
            log(format!("could not read its standing rules ({e}); its token keeps the ones it has until the next sync"));
            return (changes, false);
        }
    };
    let ids: HashSet<&str> = rules.iter().map(|s| s.id.as_str()).collect();
    for id in published.keys().filter(|id| !ids.contains(id.as_str())).cloned().collect::<Vec<_>>() {
        let until = now_s.saturating_add(366 * 24 * 3600).saturating_mul(1000);
        changes.push(Change::Revoke { kind: RevokeKind::Grant, id: id.clone(), until });
        live.retain(|l| l.grant.gid != id);
        published.remove(&id);
        rebuild = true;
    }
    for s in &rules {
        let block = standing_live(issuer, s);
        match published.get(&s.id) {
            Some(end) if *end == block.grant.not_after => continue,
            // Renewed or shortened: the same block with its new end. Put back if the sweep of
            // ended blocks took it this tick (a renewal that lands right at the old end, #572
            // re-review, N2).
            Some(_) => {
                match live.iter_mut().find(|l| l.grant.gid == s.id) {
                    Some(l) => l.grant.not_after = block.grant.not_after,
                    None => live.push(block.clone()),
                }
                published.insert(s.id.clone(), block.grant.not_after);
                rebuild = true;
                continue;
            }
            None => {}
        }
        if live.len() >= wicket_feed::token::MAX_GRANTS {
            if waiting.insert(s.id.clone()) {
                log(format!("standing rule {} waits for room in the token ({} live grants)", s.id, live.len()));
            }
            continue;
        }
        let mut trial = live.clone();
        trial.push(block.clone());
        if let Err(e) = loads(&trial) {
            if waiting.insert(s.id.clone()) {
                log(format!("standing rule {} can't go in the token ({e}): it isn't published", s.id));
            }
            continue;
        }
        log(format!("standing rule {} published", s.id));
        published.insert(s.id.clone(), block.grant.not_after);
        live.push(block);
        rebuild = true;
    }
    (changes, rebuild)
}

/// The nodes whose feed a control-host build before protocol 21 couldn't open (#575 step 4c): its
/// checkpoint, or a record after it, carries host ports, which that build's strict parse of a box's
/// record refuses (#475: rows an older build mishandles block going back to it). Such a build loads
/// the checkpoint and parses in full only the records after it; the ones before it it reads for
/// their chain alone.
pub fn feeds_holding_ports() -> Result<Vec<String>> {
    let mut out = vec![];
    for e in std::fs::read_dir(crate::data_dir().join("nodes")).into_iter().flatten().flatten() {
        let dir = e.path().join("feed");
        if dir.join("deltas.jsonl").exists() && feed_holds_ports(&dir)? {
            out.push(e.file_name().to_string_lossy().to_string());
        }
    }
    out.sort();
    Ok(out)
}

/// Writes a checkpoint of node `name`'s feed now, under its lock (#575 step 4c): the state as it is,
/// so records with host ports that no box's record holds any more are behind it. Its epoch.
pub fn checkpoint_feed(name: &str) -> Result<u64> {
    let _lock = feed_lock(&crate::data_dir().join("nodes").join(name))?;
    let mut p = open_feed(name, feed_config())?;
    p.checkpoint(wicket_feed::now_ms()).map_err(|e| anyhow::anyhow!("checkpointing node {name}'s feed: {e}"))?;
    Ok(p.epoch())
}

/// Whether node `name`'s feed holds a box record with host ports where a build before protocol 21
/// parses it (see [`feeds_holding_ports`]): for a node going back to such a build.
pub fn node_feed_holds_ports(name: &str) -> Result<bool> {
    let dir = crate::data_dir().join("nodes").join(name).join("feed");
    Ok(dir.join("deltas.jsonl").exists() && feed_holds_ports(&dir)?)
}

/// Whether the feed in `dir` holds a box record with host ports where an older build parses it.
fn feed_holds_ports(dir: &Path) -> Result<bool> {
    use base64::Engine;
    let with_ports = |v: &serde_json::Value| v.get("ports").and_then(|p| p.as_array()).is_some_and(|a| !a.is_empty());
    // The checkpoint's state, and where the records it doesn't cover start.
    let mut from = 0u64;
    if let Ok(text) = std::fs::read_to_string(dir.join(wicket_feed::CHECKPOINT)) {
        if let Ok(c) = serde_json::from_str::<serde_json::Value>(&text) {
            let snap: Option<serde_json::Value> = c.get("snap").and_then(|s| s.as_str()).and_then(|s| serde_json::from_str(s).ok());
            if let (Some(snap), Some(end)) = (snap, c.get("end").and_then(|e| e.as_u64())) {
                if snap.get("zones").and_then(|z| z.as_array()).is_some_and(|zs| zs.iter().any(with_ports)) {
                    return Ok(true);
                }
                from = end;
            }
        }
    }
    let log = std::fs::read(dir.join("deltas.jsonl")).with_context(|| format!("reading {}", dir.display()))?;
    let rest = log.get(usize::try_from(from).unwrap_or(usize::MAX)..).unwrap_or_default();
    for line in rest.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let Some(payload) = line.split(|b| *b == b'.').nth(1) else { continue };
        let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else { continue };
        let Ok(d) = serde_json::from_slice::<serde_json::Value>(&bytes) else { continue };
        let puts = d.get("changes").and_then(|c| c.as_array()).into_iter().flatten();
        if puts.filter(|c| c.get("op").and_then(|o| o.as_str()) == Some("put_zone")).any(|c| c.get("zone").is_some_and(with_ports)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// While this file is in the data directory (written by `wicket self update` for an update of the
/// control host from a build before protocol 21, removed once its health gate has ended), no
/// supervisor puts ports in a box's record (#796 review, M3); in a node's directory
/// (`nodes/<node>/update-gating`, for that node's update), none for boxes on that node. The build
/// a failed gate would roll back to couldn't read a feed holding them. The file holds when it stops
/// holding ports back (Unix seconds: the gate's window and a margin), so an update that died
/// mid-gate doesn't hold them for ever; one that can't be read counts for [`GATING_MAX_SECS`] from
/// its writing.
pub const UPDATE_GATING: &str = "update-gating";
/// How long an [`UPDATE_GATING`] file whose end can't be read holds ports back.
pub const GATING_MAX_SECS: u64 = 30 * 60;

/// Whether the [`UPDATE_GATING`] file at `p` holds ports back now.
pub fn gating_at(p: &Path) -> bool {
    if let Some(until) = std::fs::read_to_string(p).ok().and_then(|t| t.trim().parse::<i64>().ok()) {
        return wicket_store::now() < until;
    }
    std::fs::metadata(p).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|age| age.as_secs() < GATING_MAX_SECS)
}

/// Whether an update's health gate holds back ports for boxes on `node` now: the control host's or
/// that node's ([`UPDATE_GATING`]).
fn update_gating(node: &str) -> bool {
    let data = crate::data_dir();
    gating_at(&data.join(UPDATE_GATING)) || gating_at(&data.join("nodes").join(node).join(UPDATE_GATING))
}

/// Whether node `node` reads published ports (#575 step 4c): every live session to it talks
/// [`wicket_chan::chan::PORTS`] or later (or, with none live, the one last noted did), and no
/// update's health gate holds them back ([`UPDATE_GATING`]).
fn reads_ports(node: &str) -> bool {
    node_protocol_now(node).is_some_and(|p| p >= wicket_chan::chan::PORTS) && !update_gating(node)
}

/// Holds back the host ports of the records in `changes` unless the node talks
/// [`wicket_chan::chan::PORTS`] (`node_proto`, as [`node_protocol_now`] says now): an older node's
/// strict parse would refuse the record, and its whole feed with it. Whether it held any back.
fn gate_ports(changes: &mut [Change<BoxAuthority>], node_proto: Option<u32>) -> bool {
    if node_proto.is_some_and(|p| p >= wicket_chan::chan::PORTS) {
        return false;
    }
    let mut held = false;
    for c in changes.iter_mut() {
        if let Change::PutZone { zone } = c {
            held |= !zone.ports.is_empty();
            zone.ports.clear();
        }
    }
    held
}

/// The host ports the box's public names are published on now (#575 step 4c): each live public
/// name it holds that may be published on its node ([`crate::namesync::may_publish`], as the
/// names reconciler decides it), with the port allocated to it there (the one it had on another
/// node if that is free here; its rows on other nodes released). None without `names.public`.
fn wanted_ports(sh: &Shared, now_s: i64) -> Vec<wicket_feed::PublishedPort> {
    let Some(public) = sh.names.as_ref().and_then(|n| n.public.as_ref()) else { return vec![] };
    let l = sh.ledger.lock().expect("ledger");
    ports_for(&l, public, &sh.run, &sh.node, now_s)
}

/// [`wanted_ports`] for run `run` on node `node`, under `public`.
fn ports_for(l: &Ledger, public: &wicket_names::PublicConfig, run: &RunId, node: &str, now_s: i64) -> Vec<wicket_feed::PublishedPort> {
    let held = match l.names_held_by(run) {
        Ok(h) => h,
        Err(e) => {
            say!("[wicket] {run}: could not read its names ({e}); its token keeps no ports");
            return vec![];
        }
    };
    let mut out = vec![];
    for n in held.into_iter().filter(|n| n.kind == wicket_store::NameKind::Public) {
        match crate::namesync::may_publish(l, public, &n, now_s) {
            Ok(crate::namesync::Publish::On { node: on, .. }) if on == node => {}
            Ok(_) => continue,
            Err(e) => {
                say!("[wicket] {}: could not tell whether {} may be published ({e:#})", run, n.label);
                continue;
            }
        }
        let proto = crate::namesync::PROTO;
        let prefer = l.port_elsewhere(&n.id, node, proto).ok().flatten();
        let port = match l.allocate_port(node, proto, &n.id, public.ports.range(), prefer) {
            Ok(p) => p,
            Err(e) => {
                say!("[wicket] {}: no host port for {} on node {}: {e}", run, n.label, node);
                continue;
            }
        };
        let _ = l.release_ports_elsewhere(&n.id, node);
        out.push(wicket_feed::PublishedPort {
            name: n.id.clone(),
            label: n.label.clone(),
            host_port: port,
            box_port: n.port,
            until_ms: n.expires_at.map(|e| e.saturating_mul(1000)).unwrap_or(i64::MAX),
        });
    }
    out.sort_by_key(|p| p.host_port);
    out
}

/// The standing rules a sync put into a run's token or changed (renewed), and the ones it took
/// out: from the published rules (id → end) before and after it.
fn standing_moves(
    before: &std::collections::HashMap<String, u64>,
    after: &std::collections::HashMap<String, u64>,
) -> (Vec<String>, Vec<String>) {
    let mut handed: Vec<String> = after.iter().filter(|(id, end)| before.get(*id) != Some(end)).map(|(id, _)| id.clone()).collect();
    let mut gone: Vec<String> = before.keys().filter(|id| !after.contains_key(*id)).cloned().collect();
    handed.sort();
    gone.sort();
    (handed, gone)
}

/// The installation CA, for renewing nodes' CAs over their channels (#416, wicket-node's
/// `controlca`), if this control host has one (never created here).
fn installation_ca() -> Option<wicket_proxy::ca::InstallationCa> {
    let key = crate::enrol::Paths::installation().ca_key;
    key.exists()
        .then(|| wicket_proxy::ca::InstallationCa::load_or_create(&key))
        .and_then(|r| r.map_err(|e| say_err!("[wicket] installation CA: {e:#}")).ok())
}

#[cfg(test)]
mod tests {
    /// #415: the control host tells a run's node of a secret it fetched that changed or went, and of
    /// one it was refused that can now be released; each once, until the node fetches it again.
    #[test]
    fn a_node_is_told_of_secrets_changed_removed_or_newly_set() {
        let vault = std::cell::RefCell::new(std::collections::HashMap::from([("held".to_string(), "d1".to_string())]));
        let release = |n: &str| vault.borrow().get(n).cloned();
        let mut fetched = std::collections::HashMap::from([("held".to_string(), "d1".to_string())]);
        let mut refused = HashSet::from(["later".to_string()]);
        assert!(changed_secrets(&mut fetched, &mut refused, release).is_empty(), "nothing changed");
        vault.borrow_mut().insert("later".into(), "d2".into());
        assert_eq!(changed_secrets(&mut fetched, &mut refused, release), ["later"], "set since it was refused");
        assert!(refused.is_empty());
        vault.borrow_mut().insert("held".into(), "d3".into());
        assert_eq!(changed_secrets(&mut fetched, &mut refused, release), ["held"], "rotated");
        assert_eq!(fetched["held"], CHANGED, "kept, marked as changed, until fetched again");
        assert!(changed_secrets(&mut fetched, &mut refused, release).is_empty(), "told once per connection");
        fetched.insert("held".into(), "d3".into());
        vault.borrow_mut().remove("held");
        assert_eq!(changed_secrets(&mut fetched, &mut refused, release), ["held"], "removed");
    }

    /// #415: a refusal of a secret the zone uses is audited once while it lasts and tracked; one of
    /// a name it doesn't use is audited each time and never tracked (a node can't grow the set); a
    /// release is always audited, and ends the refusal.
    #[test]
    fn a_refusal_is_recorded_once_and_a_release_ends_it() {
        let (mut fetched, mut refused) = (std::collections::HashMap::new(), HashSet::new());
        assert!(record_answer(&mut fetched, &mut refused, "late", None, true), "first refusal: audited");
        assert!(!record_answer(&mut fetched, &mut refused, "late", None, true), "again: not");
        assert!(record_answer(&mut fetched, &mut refused, "other", None, false));
        assert!(record_answer(&mut fetched, &mut refused, "other", None, false), "not the zone's: each time");
        assert_eq!(refused, HashSet::from(["late".to_string()]));
        assert!(record_answer(&mut fetched, &mut refused, "late", Some("d".into()), true));
        assert!(refused.is_empty() && fetched["late"] == "d");
        assert!(record_answer(&mut fetched, &mut refused, "late", None, true), "refused again after a release: audited");
    }

    /// #415, skew: a node below protocol 23, or one whose protocol isn't known yet, gets the zone
    /// without an optional rule whose secret isn't set (it would take the host as having no
    /// credential, and let plain HTTP through); a node at 23 gets every rule, and its session then
    /// needs 23.
    #[test]
    fn an_older_node_gets_no_optional_rule_whose_secret_is_unset() {
        let zone = || -> ZoneSpec {
            wicket_core::yaml::from_str(
                "name: z\ninject:\n  - { host: a.example, header: Authorization, secret: unset, optional: true }\n  - { host: b.example, header: Authorization, secret: set, optional: true }\n  - { host: c.example, header: X-Key, secret: required }\n",
            )
            .unwrap()
        };
        let is_set = |n: &str| n != "unset";
        for proto in [None, Some(wicket_chan::chan::LIVE_SECRETS - 1)] {
            let mut z = zone();
            let (dropped, optional_rules) = zone_for_node(&mut z, proto, is_set);
            assert_eq!(dropped.iter().map(|i| i.secret.as_str()).collect::<Vec<_>>(), ["unset"], "{proto:?}");
            assert_eq!(z.inject.iter().map(|i| i.secret.as_str()).collect::<Vec<_>>(), ["set", "required"]);
            assert!(!optional_rules);
        }
        let mut z = zone();
        let (dropped, optional_rules) = zone_for_node(&mut z, Some(wicket_chan::chan::LIVE_SECRETS), is_set);
        assert!(dropped.is_empty() && z.inject.len() == 3 && optional_rules);
        // Re-attached with the node's protocol note lost: taken as older, whatever the feed holds,
        // so the session is never ended for it, and a rule whose secret isn't set now stays out.
        let mut z = zone();
        let (dropped, optional_rules) = zone_for_node(&mut z, None, |_| true);
        assert!(dropped.is_empty() && z.inject.len() == 3 && !optional_rules, "every secret set: nothing dropped, no 23 needed");
    }

    /// #415 with #818: a re-attached supervisor starts from what an earlier one recorded it released
    /// (`ctl/holdings.json`), with the digest each was released with. One unchanged is left with the
    /// node (a self-update handed it to the node's new process, which isn't made to fetch it again);
    /// one changed since is revoked by the first check; one with no digest (revoked since, or from
    /// before digests) is revoked again on the first connection. A run with no holdings starts from
    /// nothing.
    #[test]
    fn a_reattached_supervisor_revokes_only_what_changed_or_may_be_stale() {
        let dir = std::env::temp_dir().join(format!("wicket-holdings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(released_before(&dir).is_empty());
        std::fs::create_dir_all(dir.join("ctl")).unwrap();
        let h = Holdings {
            secrets: vec!["gh".into(), "model".into(), "old".into()],
            digests: [("gh".to_string(), "d-gh".to_string()), ("model".to_string(), "d-model".to_string())].into(),
            slice: None,
            updated_ms: 1,
        };
        std::fs::write(dir.join("ctl").join("holdings.json"), serde_json::to_vec(&h).unwrap()).unwrap();
        let mut fetched = released_before(&dir);
        assert_eq!(fetched.len(), 3);
        assert_eq!(fetched["old"], REVOKED);
        assert_eq!(revoke_lost(&fetched, &HashSet::new()), [("old".to_string(), true)], "only the one that may be stale");
        // The first check: model unchanged (left with the node), gh rotated since.
        let release = |n: &str| match n {
            "gh" => Some("d-gh-rotated".to_string()),
            "model" => Some("d-model".to_string()),
            _ => None,
        };
        assert_eq!(changed_secrets(&mut fetched, &mut HashSet::new(), release), ["gh"]);
        assert_eq!(fetched["model"], "d-model");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #818, the lost-revoke path end to end: a secret that changes is revoked and marked as changed,
    /// in its holdings too, so a supervisor that takes the run over (from those holdings) revokes it
    /// again on its first connection as the change it was: on the node that also ends the uses shared
    /// with a child it started while cut off, which a resend wouldn't. One unchanged is left with the
    /// node; one changed while cut off is revoked at connect as a change; a refusal is resent once;
    /// a box's exit leaves no digest, and its names go as resends.
    #[test]
    fn a_revoke_lost_with_its_supervisor_is_sent_again_by_the_next() {
        let vault = std::cell::RefCell::new(std::collections::HashMap::from([
            ("gh".to_string(), "d1".to_string()),
            ("model".to_string(), "m1".to_string()),
        ]));
        let release = |n: &str| vault.borrow().get(n).cloned();
        let mut fetched = std::collections::HashMap::from([("gh".to_string(), "d1".to_string()), ("model".to_string(), "m1".to_string())]);
        let mut refused = HashSet::new();
        // gh rotates: the check revokes it (that revoke may die with the link) and marks it changed.
        vault.borrow_mut().insert("gh".into(), "d2".into());
        assert_eq!(changed_secrets(&mut fetched, &mut refused, release), ["gh"]);
        let h = holdings_of(&fetched, None, 1);
        assert_eq!(h.secrets, ["gh", "model"]);
        assert_eq!(h.digests, [("gh".to_string(), CHANGED.to_string()), ("model".to_string(), "m1".to_string())].into());
        // The next supervisor reads those holdings.
        let dir = std::env::temp_dir().join(format!("wicket-lost-revoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ctl")).unwrap();
        std::fs::write(dir.join("ctl").join("holdings.json"), serde_json::to_vec(&h).unwrap()).unwrap();
        let mut fetched = released_before(&dir);
        assert_eq!(fetched["gh"], CHANGED);
        // Meanwhile model was rebound, and an optional secret refused earlier got set.
        vault.borrow_mut().insert("model".into(), "m2".into());
        vault.borrow_mut().insert("late".into(), "l1".into());
        let mut refused = HashSet::from(["late".to_string()]);
        let revokes = connect_revokes(&mut fetched, &mut refused, release);
        assert_eq!(revokes, [("gh".to_string(), false), ("late".to_string(), true), ("model".to_string(), false)]);
        // On the node: the run held gh and shared it with a child it started while cut off. The
        // revoke, as a change, ends the child's use too.
        const RUN: &str = "run_pppppppppppppppppppppppppp";
        const CHILD: &str = "run_cccccccccccccccccccccccccc";
        let cache = crate::nodesecrets::Cache::new(std::sync::Arc::new(|| 1_000));
        let f = crate::nodesecrets::Fetched {
            name: "gh".into(),
            value: "v1".into(),
            hosts: vec!["h".into()],
            not_after: 5_000,
            upstream_expiry: None,
        };
        cache.put(RUN, &f);
        cache.share(RUN, CHILD, &["gh".into()], 5_000);
        let none: crate::nodesecrets::Fetcher =
            std::sync::Arc::new(|_, _| Box::pin(async { Err(crate::nodesecrets::Unfetched::Unreachable("cut off".into())) }));
        let child = cache.source(CHILD, none);
        assert!(child.has("gh"), "the child holds the parent's copy, shared");
        for (name, resend) in &revokes {
            match resend {
                true => cache.revoke_resent(RUN, name),
                false => cache.revoke(RUN, name),
            }
        }
        assert!(!child.has("gh"), "the child's shared use of the rotated secret ended");
        // Each connection says the marked ones again, as they were revoked; an unchanged secret never.
        assert_eq!(connect_revokes(&mut fetched, &mut refused, release), [("gh".to_string(), false), ("model".to_string(), false)]);
        let mut fresh = std::collections::HashMap::from([("model".to_string(), "m2".to_string())]);
        assert!(connect_revokes(&mut fresh, &mut HashSet::new(), release).is_empty(), "left with the node");
        // The box exits: no digest is kept, and a takeover's revokes go as resends.
        for d in fresh.values_mut() {
            *d = REVOKED.into();
        }
        let h = holdings_of(&fresh, None, 2);
        assert!(h.digests.is_empty());
        std::fs::write(dir.join("ctl").join("holdings.json"), serde_json::to_vec(&h).unwrap()).unwrap();
        assert_eq!(revoke_lost(&released_before(&dir), &HashSet::new()), [("model".to_string(), true)]);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #415 with #818: a new connection sends again the revokes that may have been lost (each secret
    /// marked revoked) and every refusal, but not a secret the node holds as released and unchanged:
    /// after a self-update the node's new process holds it, handed over through a memfd.
    #[test]
    fn a_new_connection_resends_only_revokes_that_may_be_lost() {
        let fetched = std::collections::HashMap::from([("live".to_string(), "d1".to_string()), ("lost".to_string(), REVOKED.to_string())]);
        let refused = HashSet::from(["later".to_string(), "lost".to_string()]);
        assert_eq!(revoke_lost(&fetched, &refused), [("later".to_string(), true), ("lost".to_string(), true)]);
        assert_eq!(fetched["live"], "d1", "left as released");
        // Marked revoked, a name isn't taken as changed again on the same connection.
        let mut fetched = fetched;
        assert!(changed_secrets(&mut fetched, &mut HashSet::new(), |_| Some("d1".into())).is_empty());
    }

    /// #575 step 4c: a run's published ports are its public names that may be published on its
    /// node, each with a port from the range, kept when asked again, the same port on a node the
    /// box moves to (the old node's released), and none once the name is revoked.
    #[test]
    fn a_runs_public_names_get_host_ports_on_its_node() {
        use wicket_store::{AddressChange, NameAsk, NameScope, NameTerms, StandingBound};
        let l = Ledger::open_in_memory().unwrap();
        let public: wicket_names::PublicConfig = serde_json::from_value(serde_json::json!({
            "provider": "noop", "zone": "boxes.example.com", "owner": "a1b2c3d4", "ports": "20000-20009"
        }))
        .unwrap();
        for (n, ip) in [("n1", [8, 8, 4, 4]), ("n2", [8, 8, 8, 8])] {
            l.enrol_builtin_node(&wicket_store::NodeRow {
                name: n.into(),
                tenant: "t0".into(),
                target: "unix:/x/ctl.sock".into(),
                host_key: String::new(),
                host_key_fp: String::new(),
                node_key: "00".into(),
                ssh_key: None,
                hosts: vec![],
                enrolled_at: 1,
                status: "active".into(),
                revoked_at: None,
            })
            .unwrap();
            l.set_node_addresses(n, AddressChange::Set(std::net::Ipv4Addr::from(ip)), AddressChange::Keep, "op").unwrap();
        }
        let t = TenantId::single();
        let run = RunId("run_web".into());
        l.run_started(&t, &run, "web", "demo").unwrap();
        l.set_run_node(&run.0, "n1").unwrap();
        let ask = NameAsk {
            tenant: &t,
            run: &run,
            zone: "web",
            zone_digest: "zd",
            principal: "spiffe://t/z/web/a/demo",
            label: "demo",
            port: 3000,
            service: Some("http"),
            reason: "the demo",
            scope: NameScope::Run,
        };
        let (id, _) = l.ask_public(&ask).unwrap();
        let terms = NameTerms { bound: StandingBound::Agent, ttl_secs: None };
        let effect = wicket_store::name_effect(&l.name(&id).unwrap(), &terms, "boxes.example.com");
        l.approve_name(&id, &terms, "op", Some(&effect), &public).unwrap();
        let now = wicket_store::now();
        let ports = ports_for(&l, &public, &run, "n1", now);
        assert_eq!(ports.len(), 1);
        let p = ports[0].clone();
        assert!((20000..=20009).contains(&p.host_port) && p.box_port == 3000 && p.label == "demo" && p.until_ms == i64::MAX, "{p:?}");
        assert_eq!(ports_for(&l, &public, &run, "n1", now), ports, "kept");
        // Not on a node it isn't on.
        assert!(ports_for(&l, &public, &run, "n2", now).is_empty());
        // The box moves to n2: the same port there, n1's released (quarantined).
        l.set_run_node(&run.0, "n2").unwrap();
        let moved = ports_for(&l, &public, &run, "n2", now);
        assert_eq!(moved[0].host_port, p.host_port);
        assert!(l.quarantined_ports().unwrap().iter().any(|(n, _, port, _)| n == "n1" && *port == p.host_port));
        // Revoked: none.
        l.revoke_name(&id, "op").unwrap();
        assert!(ports_for(&l, &public, &run, "n2", now).is_empty());
    }

    /// #575 step 4c, #475: a feed whose checkpoint, or a record after it, carries host ports is
    /// one an older control-host build couldn't open; once a checkpoint covers a state without
    /// them, it can.
    #[test]
    fn a_feed_holding_ports_blocks_going_back() {
        use wicket_feed::{Issuer, KeyCert, Publisher, PublisherConfig};
        let dir = std::env::temp_dir().join(format!("wicket-feed-ports-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = wicket_identity::SigningKey::from_bytes(&[7; 32]);
        let key = wicket_identity::SigningKey::from_bytes(&[8; 32]);
        let authz_root = wicket_authz::SigningKey::from_bytes(&[9; 32]).unwrap();
        let approver = wicket_authz::SigningKey::from_bytes(&[10; 32]).unwrap();
        let cert = KeyCert::new(&key.verifying_key(), 1, i64::MAX / 2, 30_000);
        let cert_jws = wicket_feed::sign(&root, wicket_feed::TYP_KEY, &cert);
        let cfg = PublisherConfig { ttl_ms: 30_000, refresh_ms: 100, retain: 100 };
        let mut p = Publisher::open_with(&dir, "n1", &root.verifying_key(), key, &cert_jws, cfg, authz_root.public()).unwrap();
        let z: wicket_core::ZoneSpec = wicket_core::yaml::from_str("{ name: web }").unwrap();
        let issuer = Issuer::root(&authz_root, "t0", "run:r", "r", 0, &z, &[], 4_000_000_000, vec![approver.public()]).unwrap();
        let plain = issuer.publish(&approver, &[]).unwrap();
        let mut with = plain.clone();
        with.ports =
            vec![wicket_feed::PublishedPort { name: "n-1".into(), label: "demo".into(), host_port: 20001, box_port: 3000, until_ms: 9 }];
        let now = 1_000;
        p.commit(vec![Change::PutZone { zone: plain.clone() }], now).unwrap();
        assert!(!feed_holds_ports(&dir).unwrap());
        let with2 = with.clone();
        p.commit(vec![Change::PutZone { zone: with }], now + 1).unwrap();
        assert!(feed_holds_ports(&dir).unwrap(), "a record with ports after the checkpoint");
        // Its name revoked: the record without them, and a checkpoint covering that state.
        p.set_checkpoint_every(1);
        p.commit(vec![Change::PutZone { zone: plain }], now + 2).unwrap();
        assert!(!feed_holds_ports(&dir).unwrap(), "the checkpoint covers a state without ports");
        // A checkpoint whose state holds ports (a box published with them as it was written).
        p.commit(vec![Change::PutZone { zone: with2 }], now + 3).unwrap();
        assert!(feed_holds_ports(&dir).unwrap(), "the checkpoint's state holds ports");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #575 step 4c: ports go in a record only for a node every live session of which talks 21;
    /// otherwise they are held back (an older node would refuse the record, and its whole feed),
    /// and a record without any is untouched.
    #[test]
    fn ports_are_held_back_from_a_node_that_cant_read_them() {
        let z: wicket_core::ZoneSpec = wicket_core::yaml::from_str("{ name: web }").unwrap();
        let root = wicket_authz::SigningKey::from_bytes(&[9; 32]).unwrap();
        let approver = wicket_authz::SigningKey::from_bytes(&[10; 32]).unwrap();
        let issuer = wicket_feed::Issuer::root(&root, "t0", "run:r", "r", 0, &z, &[], 4_000_000_000, vec![approver.public()]).unwrap();
        let mut a = issuer.publish(&approver, &[]).unwrap();
        a.ports =
            vec![wicket_feed::PublishedPort { name: "n-1".into(), label: "demo".into(), host_port: 20001, box_port: 3000, until_ms: 9 }];
        let record = |a: &BoxAuthority| vec![Change::DropZone { name: "old".into() }, Change::PutZone { zone: a.clone() }];
        let ports_of = |c: &[Change<BoxAuthority>]| match &c[1] {
            Change::PutZone { zone } => zone.ports.len(),
            _ => unreachable!(),
        };
        for (proto, kept) in
            [(Some(wicket_chan::chan::PORTS), true), (Some(wicket_chan::chan::PORTS + 1), true), (Some(20), false), (None, false)]
        {
            let mut c = record(&a);
            assert_eq!(gate_ports(&mut c, proto), !kept, "{proto:?}");
            assert_eq!(ports_of(&c), usize::from(kept), "{proto:?}");
        }
        let mut none = a.clone();
        none.ports.clear();
        let mut c = record(&none);
        assert!(!gate_ports(&mut c, Some(19)), "nothing to hold back");
    }

    /// #572: what a sync put into a run's token or renewed, and what it took out.
    #[test]
    fn standing_moves_are_what_a_sync_changed() {
        let m = |v: &[(&str, u64)]| v.iter().map(|(k, e)| (k.to_string(), *e)).collect::<std::collections::HashMap<_, _>>();
        let (handed, gone) = super::standing_moves(&m(&[("s-a", 1), ("s-b", 1), ("s-c", 1)]), &m(&[("s-a", 1), ("s-b", 2), ("s-d", 1)]));
        assert_eq!(handed, vec!["s-b".to_string(), "s-d".to_string()]);
        assert_eq!(gone, vec!["s-c".to_string()]);
    }

    /// A failed renewal keeps the publisher only on a valid certificate of the version on disk.
    #[test]
    fn a_failed_renewal_keeps_the_publisher_only_on_a_valid_same_version_certificate() {
        let key = wicket_identity::SigningKey::from_bytes(&[7; 32]);
        let held = KeyCert::new(&key.verifying_key(), 3, 10_000, 30_000);
        let on_disk =
            |version: u64| wicket_feed::sign(&key, wicket_feed::TYP_KEY, &KeyCert::new(&key.verifying_key(), version, 20_000, 30_000));
        assert!(keep_after_failed_renewal(&held, Some(&on_disk(3)), 9_999));
        assert!(!keep_after_failed_renewal(&held, Some(&on_disk(3)), 10_000), "the held certificate is at its end");
        assert!(!keep_after_failed_renewal(&held, Some(&on_disk(4)), 9_999), "a new generation on disk");
        assert!(!keep_after_failed_renewal(&held, Some("not a certificate"), 9_999), "one that doesn't read");
        assert!(!keep_after_failed_renewal(&held, None, 9_999), "none on disk");
    }
    use super::*;

    /// #572: an approved standing rule goes in the box's token as its rule: its host, methods and
    /// globs, no use count, approved by the human who decided it, until revoked or its lapse.
    #[test]
    fn a_standing_rule_is_a_token_block_with_its_rule_and_end() {
        let tenant = TenantId::single();
        let run = RunId("run_s".into());
        let zone: ZoneSpec = wicket_core::yaml::from_str("name: z\nreach: []\n").unwrap();
        let key = wicket_authz::SigningKey::generate();
        let issuer = wicket_feed::Issuer::root(&key, &tenant.0, "run:run_s", &run.0, 0, &zone, &[], 2_000_000_000, vec![]).unwrap();
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        let rule: wicket_core::manifest::ReachRule =
            wicket_core::yaml::from_str("{ host: CI.example, methods: [GET], paths: ['/jobs/*/logs'] }").unwrap();
        let rule = wicket_core::manifest::ReachRule { host: "ci.example".into(), ..rule };
        let (id, _) = l.ask_standing(&tenant, &run, "z", "d", "spiffe://w/t/t0/z/z/a/a", &rule, "logs").unwrap();
        let terms = wicket_store::StandingTerms { bound: wicket_store::StandingBound::Agent, ttl_secs: None };
        l.approve_standing(&id, &rule, &terms, "ann", None).unwrap();
        let s = l.standing(&id).unwrap();
        let live = standing_live(&issuer, &s);
        assert_eq!((live.grant.gid.as_str(), live.grant.host.as_str(), live.uses, live.prefix), (id.as_str(), "ci.example", None, false));
        assert_eq!(live.grant.not_after, STANDING_FOREVER, "until revoked");
        assert_eq!(live.grant.approver, "standing:ann");
        assert_eq!(live.standing.as_ref().map(|r| r.paths.clone()), Some(vec!["/jobs/*/logs".to_string()]));
        // With a lapse, the block ends as a grant's does.
        let lapsing = wicket_store::Standing { expires_at: Some(1_900_000_000), ..s };
        assert_eq!(standing_live(&issuer, &lapsing).grant.not_after, 1_899_999_999);
    }

    /// #572 review (M3, M4, L6, and the branch's own tests): what a sync does with standing rules.
    /// A new one is published; an unchanged sync changes nothing; a renewal or a shortening is
    /// published again with its new end; a revoked (or lapsed, or unbound) one is revoked on the
    /// node; a read error changes nothing; a child's box, or a node below protocol 17, gets none,
    /// and loses any it had.
    #[test]
    fn a_sync_publishes_renews_and_revokes_standing_rules() {
        let tenant = TenantId::single();
        let run = RunId("run_s".into());
        let zone: ZoneSpec = wicket_core::yaml::from_str("name: z\nreach: []\n").unwrap();
        let key = wicket_authz::SigningKey::generate();
        let issuer = wicket_feed::Issuer::root(&key, &tenant.0, "run:run_s", &run.0, 0, &zone, &[], 2_000_000_000, vec![]).unwrap();
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        let rule: wicket_core::manifest::ReachRule =
            wicket_core::yaml::from_str("{ host: ci.example, methods: [GET], paths: ['/jobs/*/logs'] }").unwrap();
        let (id, _) = l.ask_standing(&tenant, &run, "z", "d", "spiffe://w/t/t0/z/z/a/a", &rule, "logs").unwrap();
        let terms = wicket_store::StandingTerms { bound: wicket_store::StandingBound::Agent, ttl_secs: Some(3600) };
        l.approve_standing(&id, &rule, &terms, "ann", None).unwrap();
        let rule_row = l.standing(&id).unwrap();
        let (mut published, mut live, mut waiting) = (std::collections::HashMap::new(), vec![], HashSet::new());
        let ok = |_: &[LiveGrant]| Ok(());
        let mut logs = vec![];
        let mut sync = |published: &mut std::collections::HashMap<String, u64>,
                        live: &mut Vec<LiveGrant>,
                        rules: std::result::Result<Vec<wicket_store::Standing>, String>,
                        proto: u32,
                        top: bool| {
            sync_standing(published, live, &mut waiting, rules, proto, top, 1_000, &issuer, &ok, &mut |m| logs.push(m))
        };
        let p17 = wicket_chan::chan::STANDING;
        // Published.
        let (c, r) = sync(&mut published, &mut live, Ok(vec![rule_row.clone()]), p17, true);
        assert!(c.is_empty() && r && live.len() == 1 && published.contains_key(&id));
        // Unchanged: nothing.
        let (c, r) = sync(&mut published, &mut live, Ok(vec![rule_row.clone()]), p17, true);
        assert!(c.is_empty() && !r);
        // Renewed, then shortened: published again with its new end, both ways.
        for end in [rule_row.expires_at.unwrap() + 86_400, rule_row.expires_at.unwrap() - 600] {
            let moved = wicket_store::Standing { expires_at: Some(end), ..rule_row.clone() };
            let (c, r) = sync(&mut published, &mut live, Ok(vec![moved]), p17, true);
            assert!(c.is_empty() && r, "{end}");
            assert_eq!(live[0].grant.not_after, wicket_authz::Grant::not_after_for(end));
            assert_eq!(published[&id], wicket_authz::Grant::not_after_for(end));
        }
        // Swept at its old end in the same tick its renewal lands: put back with the new end (N2).
        live.clear();
        let renewed = wicket_store::Standing { expires_at: Some(rule_row.expires_at.unwrap() + 7 * 86_400), ..rule_row.clone() };
        let (c, r) = sync(&mut published, &mut live, Ok(vec![renewed.clone()]), p17, true);
        assert!(c.is_empty() && r && live.len() == 1, "put back");
        assert_eq!(live[0].grant.not_after, wicket_authz::Grant::not_after_for(renewed.expires_at.unwrap()));
        // A read error: nothing changes (not "no rules", which would revoke it on the node).
        let (c, r) = sync(&mut published, &mut live, Err("database is locked".into()), p17, true);
        assert!(c.is_empty() && !r && live.len() == 1);
        // Gone from the ledger's live rules: revoked on the node, and out of the token.
        let (c, r) = sync(&mut published, &mut live, Ok(vec![]), p17, true);
        assert!(r && live.is_empty() && published.is_empty());
        assert!(matches!(&c[..], [Change::Revoke { kind: RevokeKind::Grant, id: g, .. }] if *g == id));
        // A child's box gets none; a node that drops to 16 loses what it had, with no revocation.
        let (c, r) = sync(&mut published, &mut live, Ok(vec![rule_row.clone()]), p17, false);
        assert!(c.is_empty() && !r && live.is_empty());
        sync(&mut published, &mut live, Ok(vec![rule_row.clone()]), p17, true);
        assert_eq!(live.len(), 1);
        let (c, r) = sync(&mut published, &mut live, Ok(vec![rule_row.clone()]), p17 - 1, true);
        assert!(c.is_empty() && r && live.is_empty() && published.is_empty());
        drop(sync);
        assert!(logs.iter().any(|m| m.contains("could not read")), "{logs:?}");
    }

    /// A ledger with node n1 enrolled for `api.example.com`, under `policy`.
    fn enrolled(policy: wicket_store::CaHosts) -> Ledger {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = l.create_node_token(&TenantId::single(), "n1", 3600).unwrap();
        let now = wicket_store::now();
        let node = wicket_store::NodeRow {
            name: "n1".into(),
            tenant: "t0".into(),
            target: "wicket@203.0.113.7".into(),
            host_key: "ssh-ed25519 AAAA".into(),
            host_key_fp: "SHA256:x".into(),
            node_key: "00".repeat(32),
            ssh_key: None,
            hosts: vec!["api.example.com".into()],
            enrolled_at: now,
            status: "active".into(),
            revoked_at: None,
        };
        let ca = wicket_store::NodeCaRow {
            serial: "01".into(),
            node: "n1".into(),
            issued_at: now,
            not_after: now + 3600,
            hosts: vec!["api.example.com".into()],
            status: "active".into(),
        };
        l.enrol_node(&t, &node, &ca).unwrap();
        l.set_node_ca_policy("n1", &policy).unwrap();
        l
    }

    fn zone(reach: &[&str]) -> ZoneSpec {
        let rules: String = reach.iter().map(|h| format!("  - {{ host: '{h}', methods: [GET], paths: ['/x'] }}\n")).collect();
        wicket_core::yaml::from_str(&format!("name: z\nreach:\n{rules}")).unwrap()
    }

    /// #573's review, 2 and 5: a box wants every host it needs beyond the operator's, even one the
    /// CA covers now (another run widened it, and that run's wants end with it); its live grants'
    /// hosts are wanted at its start too (a restarted or woken box), and not what can't be signed.
    #[test]
    fn a_box_wants_what_the_operators_hosts_leave_out_and_its_grants() {
        let mut l = enrolled(wicket_store::CaHosts::Auto);
        let z = zone(&["api.example.com", "x.example.com", "*", "8.8.8.8"]);
        for r in ["run_a", "run_b"] {
            l.run_started(&TenantId::single(), &RunId(r.into()), "z", "a").unwrap();
        }
        let (a, _) = want_ca_hosts_in(&l, "n1", &RunId("run_a".into()), &z, &[]);
        assert_eq!(a, ["x.example.com"]);
        // run_a's renewal covers x now; run_b needs it all the same.
        l.replace_node_ca(&wicket_store::NodeCaRow {
            serial: "02".into(),
            node: "n1".into(),
            issued_at: wicket_store::now(),
            not_after: wicket_store::now() + 3600,
            hosts: vec!["api.example.com".into(), "x.example.com".into()],
            status: "active".into(),
        })
        .unwrap();
        let (b, _) = want_ca_hosts_in(&l, "n1", &RunId("run_b".into()), &z, &["swap.example.com".into()]);
        assert_eq!(b, ["swap.example.com", "x.example.com"]);
        l.run_ended(&RunId("run_a".into()), "done", "").unwrap();
        let wants: Vec<_> = l.node_ca_wants("n1").unwrap().into_iter().map(|w| (w.host, w.run)).collect();
        assert!(wants.contains(&("x.example.com".into(), "run_b".into())), "{wants:?}");
        // A live grant of the run: wanted at its (re)start.
        let op = wicket_core::Op::egress(&TenantId::single(), &RunId("run_b".into()), "z", "GET", "granted.example.com", "/y");
        let (rid, _) = l.pending_for(&op, "out of reach", None).unwrap();
        let a = wicket_store::Approval { uses: None, ttl: std::time::Duration::from_secs(600), path_prefix: None, decided_by: "t".into() };
        l.approve(&rid, &a).unwrap();
        let (b, _) = want_ca_hosts_in(&l, "n1", &RunId("run_b".into()), &z, &[]);
        assert!(b.contains(&"granted.example.com".to_string()), "{b:?}");
        // Under fixed, nothing is wanted: kept out.
        l.set_node_ca_policy("n1", &wicket_store::CaHosts::Fixed).unwrap();
        let (b, out) = want_ca_hosts_in(&l, "n1", &RunId("run_b".into()), &z, &[]);
        assert!(b.is_empty() && out.contains(&"x.example.com".to_string()), "{b:?} {out:?}");
    }

    /// #573's review, 5 and 7: a grant's host is wanted only if a node CA must and may serve it; one
    /// the policy keeps out is audited, as the approval can't be used on the node.
    #[test]
    fn a_grants_host_is_wanted_only_if_it_needs_and_may_have_the_ca() {
        let l = enrolled(wicket_store::CaHosts::parse("*.example.org").unwrap());
        let (t, run) = (TenantId::single(), RunId("run_a".into()));
        l.run_started(&t, &run, "z", "a").unwrap();
        let whole = "{ host: whole.example.org, methods: [GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE], paths: ['/**'] }";
        let z: ZoneSpec = wicket_core::yaml::from_str(&format!("name: z\nreach: [{whole}]\n")).unwrap();
        let g = |host: &str| wicket_store::GrantRow {
            id: format!("g-{host}"),
            tenant: "t0".into(),
            zone: "z".into(),
            method: "GET".into(),
            host: host.into(),
            path: "/".into(),
            prefix: false,
            uses_left: None,
            expires_at: wicket_store::now() + 60,
            request_id: None,
            revoked: false,
            node: Some("n1".into()),
            max_risk: None,
            run: None,
            amount: None,
        };
        let w = |host: &str| want_grant_host_in(&l, "n1", &t, &run, &z, &g(host));
        assert_eq!(w("api.example.com"), GrantWant::Needless, "the operator's hosts cover it");
        assert_eq!(w("whole.example.org"), GrantWant::Needless, "spliced: no certificate");
        assert_eq!(w("*"), GrantWant::Needless, "never signed");
        assert_eq!(w("8.8.8.8"), GrantWant::Needless);
        assert_eq!(w("a.example.org"), GrantWant::Wanted("a.example.org".into()));
        assert_eq!(w("other.test"), GrantWant::Refused("other.test".into()));
        assert!(l.audit_tail(5).unwrap().iter().any(|a| a.2 == "node.ca_want_refused" && a.4.contains("other.test")));
        assert_eq!(l.node_ca_wants("n1").unwrap().iter().map(|w| w.host.as_str()).collect::<Vec<_>>(), ["a.example.org"]);
    }

    /// #56: a renewed grant the box's token carries is published with its new end; one the token
    /// doesn't carry (not handed to this node, revoked or expired) changes nothing.
    #[test]
    fn a_renewed_grant_is_republished_with_its_new_end() {
        let tenant = TenantId::single();
        let run = RunId("run_r".into());
        let zone: ZoneSpec = wicket_core::yaml::from_str("name: z\nreach: []\n").unwrap();
        let key = wicket_authz::SigningKey::generate();
        let issuer = wicket_feed::Issuer::root(&key, &tenant.0, "run:run_r", &run.0, 0, &zone, &[], 2_000_000_000, vec![]).unwrap();
        let row = |id: &str, node: Option<&str>, expires_at: i64| wicket_store::GrantRow {
            id: id.into(),
            tenant: tenant.0.clone(),
            zone: "z".into(),
            method: "GET".into(),
            host: "api.example.com".into(),
            path: "/v1/x".into(),
            prefix: false,
            uses_left: Some(2),
            expires_at,
            request_id: Some("r-1".into()),
            revoked: false,
            node: node.map(String::from),
            max_risk: Some(1),
            run: Some(run.0.clone()),
            amount: None,
        };
        let now = 1_000_000;
        let mut live = vec![live_grant(&tenant, &run, "z", &issuer, &row("g-1", Some("n1"), now + 60), false)];
        assert!(!renew_live(&mut live, &[row("g-1", Some("n1"), now + 60)], "n1", now), "unchanged");
        let renewed = [row("g-1", Some("n1"), now + 3600), row("g-2", None, now + 3600)];
        assert!(renew_live(&mut live, &renewed, "n1", now));
        assert_eq!(
            (live.len(), live[0].grant.not_after, live[0].uses),
            (1, (now + 3600 - 1) as u64, Some(2)),
            "published as expires_at - 1 (#342)"
        );
        let revoked = wicket_store::GrantRow { revoked: true, ..row("g-1", Some("n1"), now + 7200) };
        assert!(!renew_live(&mut live, &[revoked, row("g-1", Some("n2"), now + 7200)], "n1", now));
        assert_eq!(live[0].grant.not_after, (now + 3600 - 1) as u64);
    }

    /// #257 4a: a prefix grant goes to a node at protocol 16 as its prefix (the ledger's path as a
    /// canonical directory), and its token loads; to an older node, or as an exact grant, as before.
    #[test]
    fn a_prefix_grant_is_published_as_a_prefix_from_protocol_16() {
        assert!(publish_as_prefix(true, wicket_chan::chan::PREFIX_GRANTS));
        assert!(!publish_as_prefix(true, wicket_chan::chan::PREFIX_GRANTS - 1), "a node at 15: exactly, as before");
        assert!(!publish_as_prefix(false, wicket_chan::chan::PROTOCOL));
        let tenant = TenantId::single();
        let run = RunId("run_r".into());
        let zone: ZoneSpec = wicket_core::yaml::from_str("name: z\nreach: []\n").unwrap();
        let (root, approver) = (wicket_authz::SigningKey::generate(), wicket_authz::SigningKey::generate());
        let issuer =
            wicket_feed::Issuer::root(&root, &tenant.0, "run:run_r", &run.0, 0, &zone, &[], 2_000_000_000, vec![approver.public()])
                .unwrap();
        let row = wicket_store::GrantRow {
            id: "g-p".into(),
            tenant: tenant.0.clone(),
            zone: "z".into(),
            method: "PUT".into(),
            host: "api.example.com".into(),
            path: "/repos/acme/app".into(),
            prefix: true,
            uses_left: None,
            expires_at: 1_900_000_000,
            request_id: Some("r-1".into()),
            revoked: false,
            node: Some("n1".into()),
            max_risk: Some(4),
            run: Some(run.0.clone()),
            amount: None,
        };
        let live = live_grant(&tenant, &run, "z", &issuer, &row, true);
        assert_eq!((live.grant.path.as_str(), live.prefix), ("/repos/acme/app/", true));
        let a = issuer.publish(&approver, std::slice::from_ref(&live)).unwrap();
        assert!(a.grants[0].prefix);
        let exact = live_grant(&tenant, &run, "z", &issuer, &row, false);
        assert_eq!((exact.grant.path.as_str(), exact.prefix), ("/repos/acme/app", false));
    }

    /// #152: `wicket node list` shows, per run on a node, its authority, the secrets released to it
    /// (by name) and its budget slice.
    #[test]
    fn a_runs_holdings_read_as_one_line() {
        let h = Holdings {
            secrets: vec!["claude-oauth".into(), "gh".into()],
            digests: Default::default(),
            slice: Some(wicket_proxy::llm::Slice { requests: 75, output_tokens: 100_000, input_tokens: None }),
            updated_ms: 0,
        };
        let a = AuthorityRecord { node: "n1".into(), until_ms: 1_794_500_000_000, stopped: false, released_by: None };
        let line = holdings_line("run_x", Some(&a), &h, 1_794_400_000_000);
        assert!(line.contains("authority until 2026-"), "{line}");
        assert!(line.contains("secrets claude-oauth,gh"), "{line}");
        assert!(line.contains("budget slice up to 75 requests, 100000 output tokens"), "{line}");
        assert!(holdings_line("run_x", Some(&a), &h, 1_794_600_000_000).contains("authority ended"));
        let stopped = AuthorityRecord { stopped: true, ..a };
        assert!(holdings_line("run_x", Some(&stopped), &Holdings::default(), 0).contains("box stopped"));
        assert!(holdings_line("run_x", None, &Holdings::default(), 0).contains("no secrets  no budget slice"));
    }

    /// #153, the wake fence: while a box's authority is live on a node this host can't hear, its
    /// agent isn't woken elsewhere; it can be once the authority (plus skew) has ended, or as soon
    /// as the node confirms the box stopped; a re-attach doesn't lose that confirmation.
    #[test]
    fn a_box_fences_its_agent_until_its_authority_ends_or_its_node_confirms_it_stopped() {
        let d = std::env::temp_dir().join(format!("wicket-fence-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert!(fenced_in(&d, 0, None).is_none(), "neither record: no box was started");
        // A run record, but no authority record: fenced until its timeout (5m) and the backstop.
        std::fs::create_dir_all(d.join("ctl")).unwrap();
        let manifest = "task: t\nprogram: { name: p, command: [x] }\nzone: { name: z, limits: { timeout: 5m } }\n";
        std::fs::write(
            d.join("ctl/run.json"),
            serde_json::to_vec(&serde_json::json!({ "manifest": manifest, "started_ms": 1_000 })).unwrap(),
        )
        .unwrap();
        let end = 1_000 + 300_000 + 120_000 + WAKE_SKEW_MS;
        assert_eq!(fenced_in(&d, 2_000, None).map(|f| f.1), Some(end), "a missing record fences, not opens");
        assert!(fenced_in(&d, end, None).is_none());
        confirm_stopped(&d);
        assert!(fenced_in(&d, 2_000, None).is_none(), "confirmed even without a record");
        std::fs::remove_file(d.join("ctl/authority.json")).unwrap();
        record_authority(&d, "n1", 100_000).unwrap();
        assert_eq!(fenced_in(&d, 50_000, None), Some(("n1".to_string(), 100_000 + WAKE_SKEW_MS)));
        assert!(fenced_in(&d, 100_000 + WAKE_SKEW_MS - 1, None).is_some(), "skew past the authority");
        assert!(fenced_in(&d, 100_000 + WAKE_SKEW_MS, None).is_none(), "ended");
        confirm_stopped(&d);
        assert!(fenced_in(&d, 50_000, None).is_none(), "the node confirmed the box stopped");
        record_authority(&d, "n1", 100_000).unwrap();
        assert!(fenced_in(&d, 50_000, None).is_none(), "a re-attach keeps the confirmation");
        record_authority(&d, "n1", 200_000).unwrap();
        assert!(fenced_in(&d, 50_000, None).is_some(), "a new authority is fenced again");
        let _ = std::fs::remove_dir_all(d);
    }

    /// #676: what wake says of a fence it can't see the end of, and of one bounded by the ledger:
    /// the first names the operator's release, never a date at the end of time.
    #[test]
    fn wake_says_how_an_unbounded_fence_ends() {
        let d = std::env::temp_dir().join(format!("wicket-fence-wake-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("ctl")).unwrap();
        std::fs::write(d.join("ctl/run.json"), b"{ truncated").unwrap();
        let (node, until) = fenced_in(&d, 2_000, None).expect("fenced");
        let why = fence_refusal("run_x", &node, until);
        assert!(why.contains("can't be read from its records") && why.contains("wicket node release-fence run_x"), "{why}");
        assert!(!why.contains("9223372036854775807"), "{why}");
        let (node, until) = fenced_in(&d, 2_000, Some(1_800_000_000_000)).expect("fenced");
        let why = fence_refusal("run_x", &node, until);
        assert!(why.contains("it can be woken from 2027-"), "{why}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// #676: a run record whose manifest a later version no longer loads still fences until its
    /// timeout (read leniently); one whose timeout can't be read at all fences until its node
    /// confirms the box stopped, never not at all.
    #[test]
    fn a_run_record_that_no_longer_loads_still_fences() {
        let d = std::env::temp_dir().join(format!("wicket-fence-676-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("ctl")).unwrap();
        let write = |manifest: &str| {
            std::fs::write(
                d.join("ctl/run.json"),
                serde_json::to_vec(&serde_json::json!({ "manifest": manifest, "started_ms": 1_000 })).unwrap(),
            )
            .unwrap()
        };
        // A forbid glob without its leading `/`: refused since #674, accepted when the run started.
        let old = "task: t\nprogram: { name: p, command: [x] }\nzone: { name: z, limits: { timeout: 5m }, forbid: [{ host: a.test, paths: ['**/x'] }] }\n";
        assert!(wicket_agent::load(old).is_err(), "the manifest no longer loads");
        write(old);
        let end = 1_000 + 300_000 + 120_000 + WAKE_SKEW_MS;
        assert_eq!(fenced_in(&d, 2_000, None).map(|f| f.1), Some(end), "fenced until its timeout, read leniently");
        assert!(fenced_in(&d, end, None).is_none());
        // Not even YAML: when its authority ends can't be told, so the fence holds at any time.
        write("{ not: [yaml");
        assert_eq!(fenced_in(&d, i64::MAX - 1, None).map(|f| f.1), Some(UNKNOWN_END));
        std::fs::write(d.join("ctl/run.json"), b"not json").unwrap();
        assert_eq!(fenced_in(&d, 2_000, None).map(|f| f.1), Some(UNKNOWN_END), "an unreadable record fences too");
        // With the ledger's hard end of its authority: fenced until that, not forever.
        assert_eq!(fenced_in(&d, 2_000, Some(900_000)).map(|f| f.1), Some(900_000 + WAKE_SKEW_MS));
        assert!(fenced_in(&d, 900_000 + WAKE_SKEW_MS, Some(900_000)).is_none(), "and no longer");
        // No run record at all: not fenced by this host's files, whatever the ledger says (a standby
        // restored from the state store has the ledger's fence on the agent instead, #154).
        std::fs::remove_file(d.join("ctl/run.json")).unwrap();
        assert!(fenced_in(&d, 2_000, Some(900_000)).is_none(), "no run record: the ledger's fence holds instead");
        assert!(fenced_in(&d, 2_000, None).is_none(), "no record of either kind: no box was started");
        std::fs::write(d.join("ctl/run.json"), b"not json").unwrap();
        // An operator releases it (#676): the fence lifts, the record says who.
        release_fence(&d, "root@cli", None).unwrap();
        assert!(fenced_in(&d, 2_000, None).is_none(), "released");
        assert_eq!(read_authority(&d).unwrap().released_by.as_deref(), Some("root@cli"));
        std::fs::remove_file(d.join("ctl/authority.json")).unwrap();
        confirm_stopped(&d);
        assert!(fenced_in(&d, 2_000, None).is_none(), "until the node confirms the box stopped");
        let _ = std::fs::remove_dir_all(&d);
    }
    use wicket_core::RiskClass;

    /// #572: a box's standing ask is filed for its agent's principal, in the agent's words, from
    /// its own connection; a spawned child's, a zone that may not ask, and another run's aren't; one
    /// denied today is answered as denied. An agent asking for the same method on a host a third
    /// time in a week is told about standing reach.
    #[test]
    fn a_standing_ask_is_the_agents_own_and_a_repeated_ask_is_hinted() {
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let identity = |run: &str, parent: Option<&str>| {
            l.run_started(&t, &RunId(run.into()), "z", "a").unwrap();
            l.put_identity(&wicket_store::IdentityRow {
                run: run.into(),
                tenant: t.0.clone(),
                spiffe_id: format!("spiffe://w.test/t/{}/z/z/a/a{}", t.0, parent.map(|_| "-child").unwrap_or_default()),
                zone: "z".into(),
                agent: "a".into(),
                parent_run: parent.map(String::from),
                accept_from: vec![],
                jws: "j".into(),
                issued_at: 1,
            })
            .unwrap();
        };
        identity("run_s", None);
        identity("run_c", Some("run_s"));
        let zone = wicket_agent::load("task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n").unwrap().zone;
        let rule: wicket_core::manifest::ReachRule = wicket_core::yaml::from_str("{ host: ci.example, paths: ['/jobs/**'] }").unwrap();
        let why = format!("{AGENT_ASKS}CI logs");
        let own = RunId("run_s".into());
        let ask = |zone: &ZoneSpec, own: &RunId, run: &str, why: &str| ask_standing(&l, &t, own, zone, 1, run, &rule, why);
        let Msg::Asked { pending: Some((sid, true)), .. } = ask(&zone, &own, "run_s", &why) else { panic!("not filed") };
        assert!(sid.starts_with("s-"));
        assert_eq!(l.standing(&sid).unwrap().principal, "spiffe://w.test/t/t0/z/z/a/a");
        let refused = |m: Msg| match m {
            Msg::Asked { error: Some(e), .. } => e,
            m => panic!("not refused: {m:?}"),
        };
        assert!(refused(ask(&zone, &own, "run_s", "blocked request")).contains("agent's own ask"));
        assert!(refused(ask(&zone, &own, "run_x", &why)).contains("not run run_x's connection"));
        assert!(refused(ask(&zone, &RunId("run_c".into()), "run_c", &why)).contains("spawned child"));
        let quiet = wicket_agent::load("task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  escalation: { request: false }\n")
            .unwrap()
            .zone;
        assert!(refused(ask(&quiet, &own, "run_s", &why)).contains("escalation.request: false"));
        l.deny_standing(&sid, "op").unwrap();
        assert!(matches!(ask(&zone, &own, "run_s", &why), Msg::Asked { denied: Some(d), .. } if d == sid));
        // The same ask reordered, or a part of it, is denied too (L4).
        for r in
            ["{ host: ci.example, methods: [HEAD, GET], paths: ['/jobs/**'] }", "{ host: ci.example, methods: [GET], paths: ['/jobs/**'] }"]
        {
            let r: wicket_core::manifest::ReachRule = wicket_core::yaml::from_str(r).unwrap();
            let m = ask_standing(&l, &t, &own, &zone, 1, "run_s", &r, &why);
            assert!(matches!(&m, Msg::Asked { denied: Some(d), .. } if *d == sid), "{m:?}");
        }

        // The hint: by method and host, from the third ask in a week, in any of the agent's runs.
        let get = |job: u32| Op::egress(&t, &own, "z", "GET", "ci.example", &format!("/jobs/{job}/logs"));
        l.ask(&get(1), "logs", false, None).unwrap();
        l.ask(&get(2), "logs", false, None).unwrap();
        assert_eq!(repeat_hint(&l, &t, "run_s", &get(2)), None, "twice is not yet a pattern");
        l.ask(&get(3), "logs", false, None).unwrap();
        let hint = repeat_hint(&l, &t, "run_s", &get(3)).unwrap();
        assert!(hint.starts_with("You have asked for GET on ci.example 3 times since") && hint.contains("scope \"standing\""), "{hint}");
        assert_eq!(repeat_hint(&l, &t, "run_c", &get(3)), None, "a child is not hinted: it can't ask");
    }

    /// #121, #117: what a node asks about is rebuilt and classified on the control host.
    #[test]
    fn a_node_cannot_choose_what_its_ask_shows() {
        let (t, run) = (TenantId::single(), RunId("run_a".into()));
        let zone = wicket_agent::load(
            "task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  reach:\n    - { host: api.example.com, methods: [GET], paths: [\"/ok\"] }\n  forbid:\n    - { host: secret.example.com }\n",
        )
        .unwrap()
        .zone;
        let check = |op: &Op| check_node_op(&t, &run, &zone, "run_a", op).map(|(op, _)| op);
        let egress = |m: &str, h: &str, p: &str| Op::egress(&t, &run, "z", m, h, p);

        // An R4 push labelled R1 by the node is shown as R4.
        let mut push = egress("POST", "github.com", "/acme/app.git/git-receive-pack");
        assert_eq!(push.risk, RiskClass::R4ExecOrPrivilege);
        push.risk = RiskClass::R1ReadScoped;
        push.effects.clear();
        assert_eq!(check(&push).unwrap().risk, RiskClass::R4ExecOrPrivilege);
        // A node can raise the risk (it saw the query), never lower it.
        let mut read = egress("GET", "api.example.com", "/x");
        read.risk = RiskClass::R3ExternalOrIrreversible;
        assert_eq!(check(&read).unwrap().risk, RiskClass::R3ExternalOrIrreversible);
        // Not this run's, not egress, not canonical, or in wicket's own namespace: refused.
        assert!(check(&Op { run: RunId("run_b".into()), ..egress("GET", "api.example.com", "/x") }).is_err());
        assert!(check(&Op { surface: wicket_core::Surface::Llm, ..egress("GET", "api.example.com", "/x") }).is_err());
        assert!(check(&egress("GET", "api.example.com", "/a/../admin")).is_err());
        assert!(check(&Op { method: "get\u{1b}[2K".into(), ..egress("GET", "api.example.com", "/x") }).is_err());
        assert!(check(&egress("SPAWN", "wicket.internal", "/zones/z.x/0123")).is_err());
        assert!(check(&egress("CAPACITY", "api.example.com", "/capacity/l-1")).is_err());
        assert!(check(&egress("PROPFIND", "api.example.com", "/x")).is_err());
        assert!(check(&egress("GET", "x.wicket.internal", "/")).is_err());
        // Forbidden or already allowed in this zone: nothing to ask.
        assert!(check(&egress("GET", "secret.example.com", "/x")).is_err());
        assert!(check(&egress("GET", "api.example.com", "/ok")).is_err());
        // The reason on the card is this zone's own verdict (ask() never stores the node's text).
        let o = egress("GET", "api.example.com", "/x");
        let (_, why) = check_node_op(&t, &run, &zone, "run_a", &o).unwrap();
        assert_eq!(wicket_core::evaluate(&zone, &o), wicket_core::Verdict::NeedsGrant(why));
    }
}

/// Why `run`'s files on `node` aren't deleted yet (#377): its work hasn't been collected, and it is
/// a remote node's (this host's own node keeps a run's files as its run directory). None: they may be.
///
/// Collected means its files came here (fetched or bundled) or a push of them was allowed (#590
/// review), as the node hold and the simulation's invariant count it: a taken result alone
/// (`outbox`) leaves a workspace that was to be fetched on the node. Unless `no_files`: a box whose
/// workspace isn't kept to be fetched (`ctl.keep` off), where the result is all there is.
pub fn forget_refused(l: &wicket_store::Ledger, node: &str, run: &str, no_files: bool) -> Option<String> {
    let collected = |l: &wicket_store::Ledger| -> wicket_store::Result<bool> {
        let how = l.collected(run)?;
        Ok(l.files_collected(run)? || how.iter().any(|(h, _)| h == "pushed" || (no_files && h == "outbox")))
    };
    if node == crate::localnode::NAME || collected(l).unwrap_or(false) {
        return None;
    }
    Some(format!(
        "run {run}'s work hasn't been collected (no fetch, push or bundle is recorded): node {node} keeps its workspace; `wicket node forget {run} --force` deletes it"
    ))
}

/// `wicket node release-fence <run>` (#676): root releases a run's fence without its node, for a
/// run its node can't confirm stopped (unreachable or revoked) whose fence wouldn't otherwise end.
/// Refused to anyone but root, and for a run that isn't fenced. Audited as `run.fence_released`
/// with who, why and the fence it lifted; its agent can then be woken, and the reconciler ends the
/// run on its next pass if its node is gone. The box may still be running there: whoever releases
/// it takes that on.
pub fn release_fence_command(run: &str, reason: &str, by: &str, root: bool) -> anyhow::Result<()> {
    crate::run::check_run_id(run)?;
    anyhow::ensure!(root, "only root releases a run's fence (its box may still be running on its node)");
    anyhow::ensure!(!reason.trim().is_empty(), "say why with --reason: it goes on the audit record");
    let l = wicket_store::Ledger::open(&crate::ledger_path())?;
    let runs = crate::data_dir().join("runs");
    let now = wicket_feed::now_ms();
    let Some(f) = crate::fence::fence_of(&l, &runs, run, now)? else {
        anyhow::bail!("run {run} isn't fenced: its node confirmed its box stopped, or its authority has ended");
    };
    // The same decision and record as the console's (#690), as root: any fence, whatever its node says.
    let identity = crate::operators::Operator::cli(&f.tenant).ok().map(|o| o.id);
    let by = crate::fence::Decider::Root { label: by.to_string(), identity };
    let r = crate::fence::Release { run, reason, shown: &f.effect_sha256, now_ms: now, extra: serde_json::json!({ "via": "cli" }) };
    let f = crate::fence::release(&l, &runs, &by, r)?;
    say!("released run {run}'s fence on node {}; its box may still be running there", f.node);
    Ok(())
}

/// `wicket node forget <run>`: lets the run's node delete its files, its workspace among them
/// (#377). Refused while the run's work isn't collected, unless `force`; a forced delete is audited.
pub async fn forget_command(run: &str, force: bool, by: &str) -> anyhow::Result<()> {
    crate::run::check_run_id(run)?;
    let ledger = Arc::new(Mutex::new(wicket_store::Ledger::open(&crate::ledger_path())?));
    let (node, refused) = {
        let l = ledger.lock().expect("ledger");
        let node = l.run_node(run)?.with_context(|| format!("run {run} wasn't placed on a node"))?;
        let refused = forget_refused(&l, &node, run, false);
        (node, refused)
    };
    match (&refused, force) {
        (Some(why), false) => anyhow::bail!("{why}"),
        (Some(_), true) => {
            ledger.lock().expect("ledger").audit(
                &wicket_core::TenantId::single(),
                Some(&wicket_core::RunId(run.into())),
                "run.cleanup_forced",
                &serde_json::json!({ "node": node, "by": by, "why": "its work was never collected" }),
            )?;
        }
        (None, _) => {}
    }
    let link = crate::nodecall::Link::connect(&node, &format!("forget:{}", std::process::id()), &ledger).await?;
    // A run the node has no box record for may still have its directory there (#449): the node
    // finds it by its path, and deletes it the same way.
    let orphan = link.orphaned.iter().find(|o| o.run == run);
    if !link.runs.iter().any(|r| r.run == run) && orphan.is_none() {
        say!("node {node} has no files for run {run}");
        return Ok(());
    }
    if let Some(o) = orphan {
        say!("node {node} has no box record for run {run}, but keeps its directory ({} MiB)", o.bytes >> 20);
    }
    link.calls.forget(run);
    // A round trip after it: the node has handled the forget once this is answered.
    let _ = link.calls.has_image("sha256:0000000000000000000000000000000000000000000000000000000000000000").await;
    say!("node {node} deletes run {run}'s files{}", if refused.is_some() { " (forced: its work was never collected)" } else { "" });
    Ok(())
}

#[cfg(test)]
mod forget_tests {
    /// #377: a remote node's files for a run whose work was never collected stay; fetched,
    /// bundled or pushed, or on this host's own node, they may go. A taken result alone leaves a
    /// workspace that was to be fetched (#590 review), but is all a box without one has.
    #[test]
    fn an_uncollected_workspace_is_not_forgotten() {
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        let why = super::forget_refused(&l, "n1", "run_a", false).expect("refused");
        assert!(why.contains("hasn't been collected") && why.contains("--force"), "{why}");
        assert!(super::forget_refused(&l, crate::localnode::NAME, "run_a", false).is_none(), "this host's own node keeps them anyway");
        l.record_collected("run_a", "outbox").unwrap();
        assert!(super::forget_refused(&l, "n1", "run_a", false).is_some(), "an outbox alone: the workspace is still to fetch");
        assert!(super::forget_refused(&l, "n1", "run_a", true).is_none(), "an outbox is all a box without a kept workspace has");
        for how in ["pushed", "fetched", "bundled"] {
            let run = format!("run_{how}");
            l.record_collected(&run, how).unwrap();
            assert!(super::forget_refused(&l, "n1", &run, false).is_none(), "{how}");
        }
    }

    /// #453: a message the gateway gave on a link that dropped before its node said the box had
    /// it is given again when the link comes back, once, by the same supervisor; one the box had
    /// isn't. A supervisor that started the box has nothing to give again on its first resume.
    #[test]
    fn a_message_in_flight_when_the_link_drops_is_given_again_on_the_reconnect() {
        let mut l = wicket_store::Ledger::open_in_memory().unwrap();
        let t = wicket_core::TenantId("t".into());
        l.add_message("m1", &t, "run_p", "run_a", "{}").unwrap();
        l.add_message("m2", &t, "run_p", "run_a", "{}").unwrap();
        // The box's first connection: nothing to give again.
        assert_eq!(super::requeue_on_resume(&l, "run_a", true, false, 0), (0, 0));
        // await_message gives m1 and m2; the node says the box had m2; the link drops before m1's.
        let m1 = l.take_message_in_flight("run_a").unwrap().unwrap().id;
        let m2 = l.take_message_in_flight("run_a").unwrap().unwrap().id;
        assert!(l.message_read("run_a", &m2).unwrap());
        assert!(l.take_message_in_flight("run_a").unwrap().is_none(), "m1 is in flight, not waiting");
        // The link comes back, the same supervisor: m1 is given again, once.
        assert_eq!(super::requeue_on_resume(&l, "run_a", false, false, 0), (1, 0));
        assert_eq!(l.take_message_in_flight("run_a").unwrap().unwrap().id, m1);
        assert!(l.take_message_in_flight("run_a").unwrap().is_none(), "once, and never m2");
        assert!(l.message_read("run_a", &m1).unwrap());
        assert_eq!(super::requeue_on_resume(&l, "run_a", false, true, 0), (0, 0), "a reconnect with nothing in flight");
    }

    /// #253, #445: prompts share the inbox with peers' messages but keep their own guarantee. A
    /// supervisor that takes the run over gives again the prompts whose bytes the node never had
    /// (and the peers' messages in flight), never one it had; a plain reconnect gives no prompt
    /// again (the supervisor's own stdin buffer resends from the node's count).
    #[test]
    fn a_takeover_gives_again_the_prompts_and_messages_the_box_never_had() {
        let mut l = wicket_store::Ledger::open_in_memory().unwrap();
        let t = wicket_core::TenantId("t".into());
        let op = "spiffe://test.local/t/t/op/unix/alice";
        let had = l.add_prompt("run_a", "had", "alice", op).unwrap();
        let lost = l.add_prompt("run_a", "lost", "alice", op).unwrap();
        l.add_message("m1", &t, "run_p", "run_a", "{}").unwrap();
        let taken: Vec<String> = l.take_prompts("run_a").unwrap().into_iter().map(|p| p.id).collect();
        assert_eq!(taken, [had.clone(), lost.clone()]);
        l.set_prompt_stdin(&had, 0, 40).unwrap();
        l.set_prompt_stdin(&lost, 40, 80).unwrap();
        assert_eq!(l.take_message_in_flight("run_a").unwrap().unwrap().id, "m1");
        // A reconnect of the same supervisor: the message again, no prompt.
        assert_eq!(super::requeue_on_resume(&l, "run_a", false, false, 40), (1, 0));
        assert_eq!(l.take_message_in_flight("run_a").unwrap().unwrap().id, "m1");
        // The control host restarts; the new supervisor's node had 40 bytes: "lost" and m1 again.
        assert_eq!(super::requeue_on_resume(&l, "run_a", true, true, 40), (1, 1));
        assert_eq!(l.take_prompts("run_a").unwrap().into_iter().map(|p| p.text).collect::<Vec<_>>(), ["lost"]);
        assert!(l.take_prompts("run_a").unwrap().is_empty(), "never twice");
        assert_eq!(l.prompt_taken(&had).unwrap(), Some(true));
    }
}
