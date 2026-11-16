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
//!   go by grant id, and a run revocation also revokes the token's block 0 by its revocation id. Freshness statements go out every refresh. Many runs share a
//!   node's feed ([`SharedFeed`]): each commit or statement holds the feed's lock and first reloads the
//!   delta log if another process appended to it.
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
use wicket_feed::{BoxAuthority, Change, KeyCert, LiveGrant, Publisher, PublisherConfig, RevokeKind};
use wicket_identity::node::NodeCertClaims;
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

/// A node feed's directory holds this file when its feed must start a new generation the next time
/// it is opened (after a restore, #154: its delta log stayed behind).
pub const REGENESIS: &str = "regenesis";

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
            f.write_all_sync(hex::encode(seed).as_bytes())?;
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
    let margin = if offline { 0 } else { 86_400_000 };
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

trait WriteSync {
    fn write_all_sync(&mut self, b: &[u8]) -> std::io::Result<()>;
}
impl WriteSync for std::fs::File {
    fn write_all_sync(&mut self, b: &[u8]) -> std::io::Result<()> {
        std::io::Write::write_all(self, b)
    }
}

/// A node's feed, shared by every process that publishes to it (each run on the node, and each
/// link relay). Every use holds `<data dir>/nodes/<name>/feed.lock` for its duration, and first reloads
/// the delta log if another process appended to it since, so each delta extends the one true head.
pub struct SharedFeed {
    name: String,
    cfg: PublisherConfig,
    dir: PathBuf,
    /// The publisher, and the delta log's length when it was last loaded or written.
    inner: Mutex<(Publisher<BoxAuthority>, u64)>,
}

/// A held feed: the publisher, current, with the feed's lock taken.
pub struct FeedGuard<'a> {
    g: std::sync::MutexGuard<'a, (Publisher<BoxAuthority>, u64)>,
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
        self.g.1 = std::fs::metadata(self.g.0.log_path()).map(|m| m.len()).unwrap_or(0);
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

fn last_issued(feed_dir: &Path) -> i64 {
    std::fs::read_to_string(feed_dir.join("issued")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(i64::MIN)
}

impl SharedFeed {
    pub fn open(name: &str, cfg: PublisherConfig) -> Result<SharedFeed> {
        let dir = crate::data_dir().join("nodes").join(name);
        let _lock = feed_lock(&dir)?;
        let mut p = open_feed(name, cfg.clone())?;
        // Every run adds a few deltas and the log is replayed on every open: once it is large and no
        // box holds authority from it (each run drops its token at exit), the feed starts a new
        // generation, which nodes take as a snapshot.
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
        let len = std::fs::metadata(p.log_path()).map(|m| m.len()).unwrap_or(0);
        Ok(SharedFeed { name: name.into(), cfg, dir, inner: Mutex::new((p, len)) })
    }

    /// The feed, locked and current.
    pub fn lock(&self) -> Result<FeedGuard<'_>> {
        let lock = feed_lock(&self.dir)?;
        let mut g = self.inner.lock().expect("feed");
        let len = std::fs::metadata(g.0.log_path()).map(|m| m.len()).unwrap_or(0);
        if len != g.1 {
            g.0 = open_feed(&self.name, self.cfg.clone())?;
            g.1 = len;
        }
        g.0.note_issued(last_issued(&self.dir.join("feed")));
        let issued = g.0.last_issued();
        Ok(FeedGuard { g, dir: &self.dir, issued, _lock: lock })
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
    pub llm: Option<Arc<wicket_proxy::llm::Llm>>,
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
    pub gateway: Arc<wicket_proxy::gateway::Gateway>,
    /// What answers the box's `spawn` calls (#257 slice 4c): its children's supervisors run in this
    /// process. None: it may start none.
    pub spawn: Option<Arc<crate::spawn::SpawnCtx>>,
    /// Takes over children the node starts for the box (#164): None, it may start none.
    pub adopt: Option<Adopter>,
    /// Where the box start's time goes (#287): this host's steps, the node's (`node.start.*`), and
    /// the box's first output and first model request when they come.
    pub timings: Arc<Timings>,
}

struct Shared {
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
    /// Who in the box made a request, as the run reads the agent's event stream (for asks the node
    /// didn't attribute).
    attribute: Option<wicket_proxy::Attributor>,
    llm: Option<Arc<wicket_proxy::llm::Llm>>,
    vault: wicket_proxy::vault::Vault,
    /// What the node had counted when this supervisor took over, if that was already counted.
    spent_base: Mutex<Option<Option<wicket_proxy::llm::Spent>>>,
    /// Answers the node's [`Msg::Call`]s for the box's gateway (#257).
    gateway: Arc<wicket_proxy::gateway::Gateway>,
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
    let t = s.timings.clone();
    let keys = t.span("token.keys");
    let name = s.node.clone();
    let issuer = Arc::new(crate::issuer()?);
    let cfg = feed_config();
    let feed = Arc::new(SharedFeed::open(&name, cfg.clone())?);
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
                .map(|g| live_grant(&s.tenant, &s.run, &s.zone.name, &token_issuer, &g))
                .collect()
        }
    };
    let authority = token_issuer.publish(&approver, &carried).context("the box's token")?;
    // What the node attenuates a child's token from, deciding its spawns (#164).
    let mut s = s;
    if let Some(sp) = s.start.edge.as_mut().and_then(|e| e.spawn.as_mut()) {
        use base64::Engine;
        sp.base = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_issuer.base.to_bytes()?);
        sp.grant_keys = vec![approver.public()];
    }
    // Several runs share the node's feed. Tokens of runs that have ended (whose own exit didn't
    // drop them: a run killed hard) go in the same delta, so the feed and the node's snapshot don't
    // grow with every run.
    let published = t.span("feed.publish");
    let target_epoch = {
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
        publisher.commit(changes, now).context("publishing the box's token")?;
        publisher.epoch()
    };
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
    });
    let shared = Arc::new(Shared {
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
        installation_ca: crate::nodeca::installation_ca().map(Arc::new),
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
        refuse_older_node(&name, ctl.proto.load(Ordering::SeqCst))?;
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
/// as it is up: the box's start waits for that (up to 30 s), since the node refuses a box whose
/// hosts need the CA while it is expired. Not renewed by then, the start goes ahead and the node
/// says why it refuses.
async fn ca_current(sh: &Shared, proto: u32) {
    if proto < crate::chan::CA_RENEWAL || sh.node == crate::localnode::NAME {
        return;
    }
    let expired =
        || crate::nodeca::active(&sh.ledger.lock().expect("ledger"), &sh.node).is_some_and(|c| c.not_after <= wicket_store::now());
    if !expired() {
        return;
    }
    println!("[wicket] node {}'s CA has expired: renewing it before the box starts", sh.node);
    for _ in 0..120 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if !expired() {
            return;
        }
    }
}

/// Makes sure node `node` has image `pin` (#191): if it hasn't, this host's runtime exports it as an
/// OCI image layout, and the node verifies it against the pin before importing it. If this host
/// hasn't it either, nothing is sent, and the node refuses the box as before.
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
        say!("[wicket] node {node} hasn't image {pin}, and this host hasn't it to send");
        return Ok(());
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
    ca: crate::nodeca::CaRenewal,
    /// The protocol version this connection talks (#162): version-2 messages go only at 2 or later.
    proto: u32,
    /// Whether a budget slice went on this connection, and the last one sent (#152).
    slice_sent: bool,
    slice: Option<wicket_proxy::llm::Slice>,
    /// The secrets released to the node for this run, and what each was (to tell a change).
    fetched: std::collections::HashMap<String, String>,
    /// A renewed authority end (Unix seconds) whose re-mint failed: not tried again (#56).
    remint_failed: i64,
    /// What `wicket top` reads of this run's node (`ctl/link.json`).
    link: crate::top::LinkRecord,
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
        fetched: std::collections::HashMap::new(),
        remint_failed: 0,
        link: crate::top::LinkRecord { node: sh.node.clone(), ..Default::default() },
    };
    let mut backoff = std::time::Duration::from_millis(500);
    loop {
        let r = session(&sh, &mut io, &mut p, &mut ready, &mut started, target_epoch).await;
        *sh.ctl.link.lock().expect("link") = None;
        // Cut off: since now, or since it was (a retry that fails again keeps the time).
        if p.link.connected || p.link.since_ms == 0 {
            let now = wicket_feed::now_ms();
            p.link = crate::top::LinkRecord { connected: false, since_ms: now, updated_ms: now, ..p.link.clone() };
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
            Err(e) => say!("[wicket] node {} unreachable ({e:#}); retrying in {}", sh.node, humantime::format_duration(backoff)),
            Ok(()) => {
                say!("[wicket] node {} channel closed; reconnecting in {}", sh.node, humantime::format_duration(backoff));
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
            // Refused either way (identity, revocation, protocol): not worth retrying.
            p.ever = false;
            bail!("{why}")
        }
    };
    let (feed, runs) = match authed.welcome {
        Msg::Welcome { feed, runs, proto, capacity, .. } => {
            let now = wicket_feed::now_ms();
            p.link = crate::top::LinkRecord { connected: true, since_ms: now, updated_ms: now, capacity, ..p.link.clone() };
            p.link.save(&sh.dir);
            p.proto = proto;
            sh.ctl.proto.store(proto, Ordering::SeqCst);
            (feed, runs)
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
                let f = sh.ctl.publisher.lock().ok().and_then(|mut p| p.tick(wicket_feed::now_ms()));
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
                for f in sync_grants(sh, p) {
                    send(feed_frame(f));
                }
            }
            _ = ident.tick() => {
                if let Some(why) = revoked(sh, p) {
                    // Stop the box (in case the node still obeys), then drop the node for good.
                    send(Frame::Msg(Msg::Kill { run: sh.run.0.clone() }));
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    p.ever = false;
                    break Err(anyhow::anyhow!("{why}: dropping the channel"));
                }
                if let Some(f) = renewal(sh, p) {
                    send(f);
                }
                if let Some(m) = p.ca.tick(&sh.ledger, &sh.node, p.proto, wicket_store::now()) {
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
                    let refused = forget_refused(&sh.ledger.lock().expect("ledger"), &sh.node, &sh.run.0);
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
                p.exited = true;
            }
            Msg::Event { run, event } if run == sh.run.0 => {
                if let Ok(ev) = serde_json::from_value::<wicket_proxy::Event>(event) {
                    // Near its memory limit (#185): the agent is told, as a message from wicket, so it
                    // can scale down before the kernel kills the box.
                    if let wicket_proxy::Event::Box { what, detail } = &ev {
                        if what == "memory_pressure" {
                            let _ = sh.ledger.lock().expect("ledger").add_operator_message(&sh.run.0, detail, "wicket");
                        }
                    }
                    let _ = sh.events.send(ev);
                }
            }
            Msg::Ask { id, run, op, why, who, queued, prefix } => {
                send(Frame::Msg(ask(sh, id, &run, &op, &why, who.as_ref(), queued.as_ref(), prefix)))
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
            Msg::Health { health } => {
                if let Ok(j) = serde_json::to_string(&health) {
                    let _ = sh.ledger.lock().expect("ledger").set_node_health(&sh.node, wicket_feed::now_ms(), &j);
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
                        (true, ..) => gw.call_tool(&tool.name(), args).await,
                    };
                    let _ = out.send(Frame::Msg(Msg::Called { id, text, is_error }));
                });
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
    let reply = |pending, denied, error| Msg::Asked { id, pending, denied, error };
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
    let asked = match agent {
        Some(reason) => {
            let old = why.split_once(" (asked ").map(|(_, q)| format!(" (asked {q}")).unwrap_or_default();
            l.ask(op, &format!("{AGENT_ASKS}{reason}{old}"), prefix, who)
        }
        None => l.pending_for(op, &why, who),
    };
    match asked {
        Ok((rid, fresh)) => reply(Some((rid, fresh)), None, None),
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
}

/// How far past a box's authority a wake still waits: clock skew between this host and the node.
pub const WAKE_SKEW_MS: i64 = 30_000;

fn authority_file(run_dir: &Path) -> PathBuf {
    run_dir.join("ctl").join("authority.json")
}

/// Records a box's authority beside its run (a re-attach keeps what the node confirmed).
/// Durably, before the box starts: on disk (file and directory synced) before the node is asked to
/// start anything, so a crash can't leave a running box with no fence.
pub fn record_authority(run_dir: &Path, node: &str, until_ms: i64) -> Result<()> {
    let stopped = read_authority(run_dir).is_some_and(|a| a.stopped && a.until_ms == until_ms);
    write_authority(run_dir, &AuthorityRecord { node: node.into(), until_ms, stopped })
}

fn write_authority(run_dir: &Path, rec: &AuthorityRecord) -> Result<()> {
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

/// Whether run `run`'s box may still be running on its node at `now_ms`: its node, and when that
/// ends for certain (its authority's end plus [`WAKE_SKEW_MS`]). None once the node confirmed the
/// box stopped, or the authority has ended, or for a run without a record.
pub fn fenced_until(run: &str, now_ms: i64) -> Option<(String, i64)> {
    crate::run::check_run_id(run).ok()?;
    fenced_in(&crate::data_dir().join("runs").join(run), now_ms)
}

/// [`fenced_until`] for the run in `run_dir`.
///
/// A run whose record is missing (lost) fences until its timeout, from its run
/// record: its box may run that long on its node, and no longer. A run with neither record never
/// started a box.
pub fn fenced_in(run_dir: &Path, now_ms: i64) -> Option<(String, i64)> {
    let a = match read_authority(run_dir) {
        Some(a) => a,
        None => AuthorityRecord { node: "its node".into(), until_ms: timeout_end(run_dir)?, stopped: false },
    };
    let until = a.until_ms.saturating_add(WAKE_SKEW_MS);
    (!a.stopped && now_ms < until).then_some((a.node, until))
}

/// When a run's box must have stopped by its timeout (Unix ms), from its run record (`ctl/run.json`):
/// its start, its zone's timeout, and a long-lived agent's node backstop (120 s).
fn timeout_end(run_dir: &Path) -> Option<i64> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(run_dir.join("ctl/run.json")).ok()?).ok()?;
    let m = wicket_agent::load(v["manifest"].as_str()?).ok()?;
    let secs = i64::try_from(m.zone.limits.timeout().ok()?.as_secs()).ok()?;
    Some(v["started_ms"].as_i64()? + secs * 1000 + 120_000)
}

/// What this host has released to a run's node, secrets and budget slices (#152), kept beside the run
/// (`ctl/holdings.json`) for `wicket node list`: the secrets the node fetched for the run (by name,
/// never values) and its budget slice. An upper bound: the node may have dropped some already, never
/// holds more.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Holdings {
    pub secrets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice: Option<wicket_proxy::llm::Slice>,
    /// When this was last written (Unix ms).
    pub updated_ms: i64,
}

fn save_holdings(sh: &Shared, p: &Progress) {
    let mut secrets: Vec<String> = p.fetched.keys().cloned().collect();
    secrets.sort();
    let h = Holdings { secrets, slice: p.slice, updated_ms: wicket_feed::now_ms() };
    let f = sh.dir.join("ctl").join("holdings.json");
    let tmp = f.with_extension("tmp");
    if std::fs::write(&tmp, serde_json::to_vec(&h).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, &f);
    }
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
    let slice = wicket_proxy::llm::Slice::renewed(p.slice, next, l.spent(), l.input_total());
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

/// Why a box can't start on node `name` talking `proto` (#257 slice 4b): before protocol 13 the node
/// would relay the box's gateway tools through a tunnel this host no longer serves. Every older
/// feature floor (pins, budget slices, swaps, no forwarded egress) is below it.
pub(crate) fn refuse_older_node(name: &str, proto: u32) -> Result<()> {
    if proto < crate::chan::ONE_GATEWAY {
        bail!(
            "node {name} talks protocol {proto}, and this host answers a box's gateway tools only as typed calls, from protocol {}: update the node (`wicket node install {name}`)",
            crate::chan::ONE_GATEWAY
        );
    }
    Ok(())
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
        Ok(f) => {
            if for_pull.is_none() {
                p.fetched.insert(name.to_string(), crate::nodesecrets::digest(f));
                save_holdings(sh, p);
            }
            (true, None)
        }
        Err(e) => (false, Some(e.clone())),
    };
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

/// Secrets this run's node fetched that have since changed, been rebound or removed on this host:
/// the node is told to drop them (#152).
fn secrets_changed(sh: &Shared, p: &mut Progress) -> Vec<Frame> {
    let mut out = vec![];
    let names: Vec<String> = p.fetched.keys().cloned().collect();
    for name in names {
        let now = crate::nodesecrets::release_run(&sh.zone, &sh.swaps, &sh.vault, &name, sh.ctl.authority_until())
            .ok()
            .map(|f| crate::nodesecrets::digest(&f));
        if now.as_deref() != p.fetched.get(&name).map(String::as_str) {
            p.fetched.remove(&name);
            save_holdings(sh, p);
            say!("[wicket] secret {name} changed on this host: node {} drops its copy for {}", sh.node, sh.run);
            out.push(Frame::Msg(Msg::SecretRevoke { run: sh.run.0.clone(), name }));
        }
    }
    out
}

/// How a node marks an ask the agent made itself (`request_access`), its reason following.
pub(crate) const AGENT_ASKS: &str = "asked by the agent: ";

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
        let live = live_grant(&sh.tenant, &sh.run, &sh.zone.name, &issuer, &g);
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
        if g.prefix {
            say!("[wicket] grant {} is for a path prefix; node {} honours it for {} exactly", g.id, sh.node, g.path);
        }
        p.live.push(live);
        handed.push(g.id.clone());
        p.published.insert(g.id);
        rebuild = true;
    }
    if !rebuild {
        return vec![];
    }
    let renewing = match issuer.publish(&sh.approver, &p.live) {
        Ok(a) => {
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
    let token_out;
    let committed = {
        let Ok(mut p) = sh.ctl.publisher.lock() else { return vec![] };
        let mut r = p.commit(changes, wicket_feed::now_ms());
        token_out = r.is_ok();
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
        let _ = sh.ledger.lock().expect("ledger").grants_published(&handed, *epoch as i64);
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
fn live_grant(tenant: &TenantId, run: &RunId, zone: &str, issuer: &wicket_feed::Issuer, g: &wicket_store::GrantRow) -> LiveGrant {
    let op = Op::egress(tenant, run, zone, &g.method, &g.host, &g.path);
    LiveGrant {
        grant: wicket_authz::Grant {
            gid: g.id.clone(),
            box_id: issuer.box_path.clone(),
            epoch: issuer.epoch,
            host: op.host.clone(),
            method: op.method.clone(),
            path: op.path.clone(),
            // The ledger's end, as the token's inclusive whole-second check reads it (#342).
            not_after: wicket_authz::Grant::not_after_for(g.expires_at),
            approver: g.request_id.as_deref().map_or_else(|| "operator".to_string(), |r| format!("request:{r}")),
            digest: hex::decode(op.digest()).unwrap_or_default(),
        },
        uses: g.uses_left.map(|u| u.clamp(0, i64::from(u32::MAX)) as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut live = vec![live_grant(&tenant, &run, "z", &issuer, &row("g-1", Some("n1"), now + 60))];
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

    /// #152: `wicket node list` shows, per run on a node, its authority, the secrets released to it
    /// (by name) and its budget slice.
    #[test]
    fn a_runs_holdings_read_as_one_line() {
        let h = Holdings {
            secrets: vec!["claude-oauth".into(), "gh".into()],
            slice: Some(wicket_proxy::llm::Slice { requests: 75, output_tokens: 100_000, input_tokens: None }),
            updated_ms: 0,
        };
        let a = AuthorityRecord { node: "n1".into(), until_ms: 1_794_500_000_000, stopped: false };
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
        assert!(fenced_in(&d, 0).is_none(), "neither record: no box was started");
        // A run record, but no authority record: fenced until its timeout (5m) and the backstop.
        std::fs::create_dir_all(d.join("ctl")).unwrap();
        let manifest = "task: t\nprogram: { name: p, command: [x] }\nzone: { name: z, limits: { timeout: 5m } }\n";
        std::fs::write(
            d.join("ctl/run.json"),
            serde_json::to_vec(&serde_json::json!({ "manifest": manifest, "started_ms": 1_000 })).unwrap(),
        )
        .unwrap();
        let end = 1_000 + 300_000 + 120_000 + WAKE_SKEW_MS;
        assert_eq!(fenced_in(&d, 2_000).map(|f| f.1), Some(end), "a missing record fences, not opens");
        assert!(fenced_in(&d, end).is_none());
        confirm_stopped(&d);
        assert!(fenced_in(&d, 2_000).is_none(), "confirmed even without a record");
        std::fs::remove_file(d.join("ctl/authority.json")).unwrap();
        record_authority(&d, "n1", 100_000).unwrap();
        assert_eq!(fenced_in(&d, 50_000), Some(("n1".to_string(), 100_000 + WAKE_SKEW_MS)));
        assert!(fenced_in(&d, 100_000 + WAKE_SKEW_MS - 1).is_some(), "skew past the authority");
        assert!(fenced_in(&d, 100_000 + WAKE_SKEW_MS).is_none(), "ended");
        confirm_stopped(&d);
        assert!(fenced_in(&d, 50_000).is_none(), "the node confirmed the box stopped");
        record_authority(&d, "n1", 100_000).unwrap();
        assert!(fenced_in(&d, 50_000).is_none(), "a re-attach keeps the confirmation");
        record_authority(&d, "n1", 200_000).unwrap();
        assert!(fenced_in(&d, 50_000).is_some(), "a new authority is fenced again");
        let _ = std::fs::remove_dir_all(d);
    }
    use wicket_core::RiskClass;

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
pub fn forget_refused(l: &wicket_store::Ledger, node: &str, run: &str) -> Option<String> {
    if node == crate::localnode::NAME || l.collected(run).is_ok_and(|c| !c.is_empty()) {
        return None;
    }
    Some(format!(
        "run {run}'s work hasn't been collected (no fetch, outbox, push or bundle is recorded): node {node} keeps its workspace; `wicket node forget {run} --force` deletes it"
    ))
}

/// `wicket node forget <run>`: lets the run's node delete its files, its workspace among them
/// (#377). Refused while the run's work isn't collected, unless `force`; a forced delete is audited.
pub async fn forget_command(run: &str, force: bool, by: &str) -> anyhow::Result<()> {
    crate::run::check_run_id(run)?;
    let ledger = Arc::new(Mutex::new(wicket_store::Ledger::open(&crate::ledger_path())?));
    let (node, refused) = {
        let l = ledger.lock().expect("ledger");
        let node = l.run_node(run)?.with_context(|| format!("run {run} wasn't placed on a node"))?;
        let refused = forget_refused(&l, &node, run);
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
    if !link.runs.iter().any(|r| r.run == run) {
        say!("node {node} has no files for run {run}");
        return Ok(());
    }
    link.calls.forget(run);
    // A round trip after it: the node has handled the forget once this is answered.
    let _ = link.calls.has_image("sha256:0000000000000000000000000000000000000000000000000000000000000000").await;
    say!("node {node} deletes run {run}'s files{}", if refused.is_some() { " (forced: its work was never collected)" } else { "" });
    Ok(())
}

#[cfg(test)]
mod forget_tests {
    /// #377: a remote node's files for a run whose work was never collected stay; collected any
    /// way, or on this host's own node, they may go.
    #[test]
    fn an_uncollected_workspace_is_not_forgotten() {
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        let why = super::forget_refused(&l, "n1", "run_a").expect("refused");
        assert!(why.contains("hasn't been collected") && why.contains("--force"), "{why}");
        assert!(super::forget_refused(&l, crate::localnode::NAME, "run_a").is_none(), "this host's own node keeps them anyway");
        l.record_collected("run_a", "outbox").unwrap();
        assert!(super::forget_refused(&l, "n1", "run_a").is_none());
    }
}
