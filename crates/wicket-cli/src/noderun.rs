//! The control host's side of a run on an enrolled node (#57): `wicket run --node <name>` talks to
//! the node's `wicket node serve` instead of running docker over ssh.
//!
//! - **Feed.** One [`Publisher`] per node, under `<data dir>/nodes/<name>/feed`: the node's online feed
//!   key (made here) and its certificate, signed by the installation's feed root. The run publishes
//!   its box's authority as a Biscuit token (`wicket_feed::token`): block 0 minted here with the
//!   authority root key from the zone's ceiling, until the run's timeout. Each grant a human approves
//!   for its requests is a third-party block signed here with the approver key; the token is rebuilt
//!   from its base with the live grants and published whole (bound to its box; the node counts their
//!   uses, and the ledger hands them over so it never consumes them too). Revocations of those grants
//!   go by grant id, and a run revocation also revokes the token's block 0 by its revocation id. Freshness statements go out every refresh. While a run holds the
//!   feed (an exclusive lock), no other run can use the node: one run per node until the reconciler
//!   (#38) owns the feed.
//! - **Channel.** `ssh <pinned> <target> wicket node attach` joins the ssh session to the node's
//!   control socket. When it drops, the run keeps going: reconnects back off from 0.5 s to 5 s, and on
//!   each reconnect the node is caught up (deltas or a snapshot, and a statement signed for the
//!   occasion), stdout and stderr resume where they left off, unsent stdin is resent, and the node
//!   ships the audit records it made meanwhile.
//! - **Tunnels.** The node opens tunnels to this run's LLM and MCP gateway sockets, and to its egress
//!   proxy for hosts the node must not terminate; they are connected here.
//! - **Asks.** A request the node can't allow is raised here as an ordinary pending request.
//! - **Identity.** Every connection starts with the mutual authentication in `nodeauth.rs`; at half
//!   its life the node's certificate is renewed over the channel, and a node revoked meanwhile (from
//!   another process: `wicket node revoke`) is dropped within a second and not reconnected.
//!
//! Test hooks: `WICKET_FEED_TTL_MS`, `WICKET_FEED_REFRESH_MS` and `WICKET_FEED_NARROW_MS` override the
//! feed's timings (within the certificate's caps, which follow them).

use crate::chan::{self, accept_at, BoxStart, Frame, Msg, OutBuf, Tunnels, TUNNEL_BIT};
use crate::node::Node;
use crate::nodeauth::HsError;
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use wicket_core::{Op, RunId, TenantId, ZoneSpec};
use wicket_feed::{BoxAuthority, Change, KeyCert, LiveGrant, PublishError, Publisher, PublisherConfig, RevokeKind};
use wicket_identity::node::NodeCertClaims;
use wicket_store::Ledger;

/// The feed's timings for this control host: the defaults, or the test overrides.
pub fn feed_config() -> PublisherConfig {
    let env = |k: &str, d: i64| std::env::var(k).ok().and_then(|v| v.parse().ok()).filter(|v: &i64| *v > 0).unwrap_or(d);
    PublisherConfig {
        ttl_ms: env("WICKET_FEED_TTL_MS", wicket_feed::DEFAULT_TTL_MS),
        refresh_ms: env("WICKET_FEED_REFRESH_MS", wicket_feed::DEFAULT_REFRESH_MS),
        narrow_ms: env("WICKET_FEED_NARROW_MS", wicket_feed::DEFAULT_NARROW_MS),
        ..PublisherConfig::default()
    }
}

/// How long a node feed key's certificate lasts; it is renewed (same key and version) when a run
/// starts with less than a day left.
const CERT_DAYS: i64 = 7;

/// Opens node `name`'s feed: its key (created here on first use, 0600) and a certificate for it from
/// the installation's feed root. A delta log from before boxes' authority moved to tokens (zone
/// entries, which don't parse as box records) is set aside as `deltas.jsonl.zones`, and the feed
/// starts again under a new certificate version: a re-genesis, so the node takes the new snapshot.
pub fn open_feed(name: &str, cfg: PublisherConfig) -> Result<Publisher<BoxAuthority>> {
    let dir = crate::data_dir().join("nodes").join(name).join("feed");
    match open_feed_once(name, &cfg, false) {
        Err(e) if e.downcast_ref::<PublishError>().is_some_and(|e| e.to_string().contains("unreadable")) => {
            let log = dir.join("deltas.jsonl");
            std::fs::rename(&log, dir.join("deltas.jsonl.zones")).context("setting aside the old delta log")?;
            println!("[wicket] node {name}'s feed log predates token authority: set aside, starting a new feed generation");
            open_feed_once(name, &cfg, true)
        }
        r => r,
    }
}

fn open_feed_once(name: &str, cfg: &PublisherConfig, new_generation: bool) -> Result<Publisher<BoxAuthority>> {
    let dir = crate::data_dir().join("nodes").join(name).join("feed");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let root = wicket_identity::load_or_create_feed_root_signing(&crate::enrol::Paths::installation().feed_root_key)?;
    let key_path = dir.join("feed.key");
    let key = match std::fs::read_to_string(&key_path) {
        Ok(s) => {
            let seed: [u8; 32] = hex::decode(s.trim()).ok().and_then(|b| b.try_into().ok()).context("feed.key")?;
            wicket_identity::SigningKey::from_bytes(&seed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("random: {e}"))?;
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
    let want_narrow = cfg.narrow_ms.max(wicket_feed::DEFAULT_NARROW_MS);
    let kid = wicket_feed::kid(&key.verifying_key());
    let cert_jws = match old {
        Some((c, j))
            if !new_generation
                && c.kid == kid
                && c.not_after > now + 86_400_000
                && c.max_ttl_ms >= cfg.ttl_ms
                && c.max_narrow_ms >= cfg.narrow_ms =>
        {
            j
        }
        old => {
            // Same key: same version (a renewal). A new key needs a new version (a re-genesis).
            let version = match &old {
                Some((c, _)) if new_generation => c.version + 1,
                Some((c, _)) if c.kid == kid => c.version,
                Some((c, _)) => c.version + 1,
                None => 1,
            };
            let c = KeyCert::new(&key.verifying_key(), version, now + CERT_DAYS * 86_400_000, want_ttl, want_narrow);
            let j = wicket_feed::sign(&root, wicket_feed::TYP_KEY, &c);
            std::fs::write(&cert_path, &j)?;
            j
        }
    };
    let authz_root = crate::enrol::token_key(&crate::enrol::Paths::installation().authz_root_key)?.public();
    Ok(Publisher::open_with(&dir, name, &root.verifying_key(), key, &cert_jws, cfg.clone(), authz_root)?)
}

trait WriteSync {
    fn write_all_sync(&mut self, b: &[u8]) -> std::io::Result<()>;
}
impl WriteSync for std::fs::File {
    fn write_all_sync(&mut self, b: &[u8]) -> std::io::Result<()> {
        std::io::Write::write_all(self, b)
    }
}

/// An exclusive hold on a node's feed for the life of a run.
struct FeedLock(#[allow(dead_code)] std::fs::File);

fn lock_feed(name: &str) -> Result<FeedLock> {
    use std::os::fd::AsRawFd;
    let dir = crate::data_dir().join("nodes").join(name);
    std::fs::create_dir_all(&dir)?;
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("feed.lock"))?;
    // SAFETY: flock on a file descriptor this process owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another run is using node {name}: one run per node for now (#38)");
    }
    Ok(FeedLock(f))
}

/// What the run loop gets: the box's stdio as streams, its exit, and a handle to stop it.
pub struct NodeBox {
    pub stdin: Option<tokio::io::DuplexStream>,
    pub stdout: tokio::io::DuplexStream,
    pub stderr: tokio::io::DuplexStream,
    pub exit: oneshot::Receiver<i32>,
    pub ctl: Arc<NodeCtl>,
}

/// Stops and revokes a run's box on its node, connected or not (sent on the next connect).
pub struct NodeCtl {
    node: String,
    run: String,
    link: Mutex<Option<chan::Out>>,
    publisher: Arc<Mutex<Publisher<BoxAuthority>>>,
    /// The box's token's block 0 revocation id (hex), and until when it matters (Unix ms).
    token_root: (String, i64),
    killed: AtomicBool,
    _lock: FeedLock,
}

impl NodeCtl {
    fn send(&self, f: Frame) -> bool {
        self.link.lock().expect("link").as_ref().is_some_and(|l| l.send(f).is_ok())
    }

    /// Stops the box (now if connected, else as soon as the node is reachable again).
    pub fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        self.send(Frame::Msg(Msg::Kill { run: self.run.clone() }));
    }

    /// Revokes the run on the node (every op refused from the moment the delta applies), then stops it.
    pub fn revoke(&self) {
        let now = wicket_feed::now_ms();
        let frame = self.publisher.lock().expect("publisher").commit(
            vec![
                Change::Revoke { kind: RevokeKind::Run, id: self.run.clone(), until: now + 86_400_000 },
                Change::Revoke { kind: RevokeKind::Token, id: self.token_root.0.clone(), until: self.token_root.1.max(now + 86_400_000) },
            ],
            now,
        );
        match frame {
            Ok(f) => {
                self.send(Frame::Feed(f.to_line().trim_end().as_bytes().to_vec()));
            }
            Err(e) => eprintln!("[wicket] could not publish the revocation of {} to {}: {e}", self.run, self.node),
        }
        self.kill();
    }
}

/// Everything about the run the connection manager needs.
pub struct Start<'a> {
    pub node: &'a Node,
    pub tenant: TenantId,
    pub run: RunId,
    pub zone: ZoneSpec,
    pub dir: PathBuf,
    pub ledger: Arc<Mutex<Ledger>>,
    pub events: mpsc::UnboundedSender<wicket_proxy::Event>,
    pub start: BoxStart,
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
    argv: Vec<String>,
    ctl: Arc<NodeCtl>,
    tunnels: Tunnels,
    cfg: PublisherConfig,
    issuer: Arc<wicket_identity::Issuer>,
    /// The box's base token (block 0), and the key that signs its grant blocks.
    token_issuer: wicket_feed::Issuer,
    approver: wicket_authz::SigningKey,
}

/// Connects to the node, publishes the run's zone, starts the box there, and returns its stdio.
pub async fn start(s: Start<'_>) -> Result<NodeBox> {
    let name = s.node.name.clone().context("only enrolled nodes run `wicket node serve`")?;
    let issuer = Arc::new(crate::issuer()?);
    let lock = lock_feed(&name)?;
    let cfg = feed_config();
    let mut publisher = open_feed(&name, cfg.clone())?;
    let now = wicket_feed::now_ms();
    let paths = crate::enrol::Paths::installation();
    let (authz_root, approver) = (crate::enrol::token_key(&paths.authz_root_key)?, crate::enrol::token_key(&paths.approver_key)?);
    // Until the run's own deadline (the node kills the box then), with an hour's margin.
    let not_after = u64::try_from(now / 1000).unwrap_or(0) + s.start.timeout_secs + 3600;
    let token_issuer = wicket_feed::Issuer::root(
        &authz_root,
        &s.tenant.0,
        &format!("run:{}", s.run),
        &s.run.0,
        0,
        &s.zone,
        std::slice::from_ref(&s.start.image),
        not_after,
        vec![approver.public()],
    )
    .context("minting the box's token")?;
    let authority = token_issuer.publish(&approver, &[]).context("the box's token")?;
    // One run per node holds the feed (the lock above): earlier runs' tokens go in the same delta, so
    // the feed and the node's snapshot don't grow with every run.
    let mut changes: Vec<Change<BoxAuthority>> =
        publisher.state().zones.keys().filter(|k| **k != s.run.0).map(|k| Change::DropZone { name: k.clone() }).collect();
    changes.push(Change::PutZone { zone: authority });
    publisher.commit(changes, now).context("publishing the box's token")?;
    let token_root = (token_issuer.block_ids()[0].clone(), i64::try_from(not_after).unwrap_or(i64::MAX / 1000) * 1000);
    let target_epoch = publisher.epoch();
    let ctl = Arc::new(NodeCtl {
        node: name.clone(),
        run: s.run.0.clone(),
        link: Mutex::new(None),
        publisher: Arc::new(Mutex::new(publisher)),
        token_root,
        killed: AtomicBool::new(false),
        _lock: lock,
    });
    let mut argv = s.node.ssh_prefix();
    if argv[0] == "ssh" {
        // Notice a dead link in about 15 s rather than minutes (ssh takes an option's first value, so
        // these go before the defaults).
        argv.splice(1..1, ["-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"].map(String::from));
    }
    argv.push("\"$HOME/.local/bin/wicket\" node attach".into());
    let shared = Arc::new(Shared {
        node: name.clone(),
        tenant: s.tenant,
        run: s.run,
        zone: s.zone,
        dir: s.dir,
        ledger: s.ledger,
        events: s.events,
        streams: s.start.streams,
        argv,
        ctl: ctl.clone(),
        tunnels: Tunnels::default(),
        cfg,
        issuer,
        token_issuer,
        approver,
    });
    let (stdin_ours, stdin_theirs) = tokio::io::duplex(256 * 1024);
    let (stdout_theirs, stdout_ours) = tokio::io::duplex(1 << 20);
    let (stderr_theirs, stderr_ours) = tokio::io::duplex(1 << 20);
    let (exit_tx, exit_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (started_tx, started_rx) = oneshot::channel();
    let interactive = s.start.interactive;
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
    if !ctl.send(Frame::Msg(Msg::Start(Box::new(s.start)))) {
        bail!("lost node {name} while starting the box");
    }
    match tokio::time::timeout(std::time::Duration::from_secs(120), started_rx).await {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(e))) => bail!("node {name} could not start the box: {e}"),
        _ => bail!("node {name} did not start the box within 120 s"),
    }
    Ok(NodeBox { stdin: interactive.then_some(stdin_ours), stdout: stdout_ours, stderr: stderr_ours, exit: exit_rx, ctl })
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
    /// The grants the box's token carries now.
    live: Vec<LiveGrant>,
    ever: bool,
    exited: bool,
    /// The node's certificate, as last authenticated or renewed.
    cert: Option<NodeCertClaims>,
    /// A renewal sent and not yet answered.
    renewing: Option<NodeCertClaims>,
    /// No renewal attempt before this (after a failed one).
    renew_after: i64,
}

async fn manage(
    sh: Arc<Shared>,
    mut io: Io,
    mut ready: Option<oneshot::Sender<Result<()>>>,
    mut started: Option<oneshot::Sender<Option<String>>>,
    target_epoch: u64,
) {
    let mut p = Progress {
        stdin: OutBuf::new(crate::nodesrv::OUTPUT_CAP),
        stdin_closed: false,
        next: [0, 0],
        published: HashSet::new(),
        revoked: HashSet::new(),
        live: vec![],
        ever: false,
        exited: false,
        cert: None,
        renewing: None,
        renew_after: 0,
    };
    let mut backoff = std::time::Duration::from_millis(500);
    loop {
        let r = session(&sh, &mut io, &mut p, &mut ready, &mut started, target_epoch).await;
        *sh.ctl.link.lock().expect("link") = None;
        sh.tunnels.clear();
        if p.exited {
            return;
        }
        match r {
            Err(e) if !p.ever => {
                // Never connected, or refused (another build): give up. The run sees the box end.
                match ready.take() {
                    Some(t) => {
                        let _ = t.send(Err(e));
                    }
                    None => println!("[wicket] giving up on node {}: {e:#}", sh.node),
                }
                return;
            }
            Err(e) => println!("[wicket] node {} unreachable ({e:#}); retrying in {}", sh.node, humantime::format_duration(backoff)),
            Ok(()) => {
                println!("[wicket] node {} channel closed; reconnecting in {}", sh.node, humantime::format_duration(backoff));
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
    started: &mut Option<oneshot::Sender<Option<String>>>,
    target_epoch: u64,
) -> Result<()> {
    // Revoked while the channel was down: its pinned host key is gone too, so ssh would fail with
    // a host key error that looks like an outage. Give up instead of retrying.
    if let Some(why) = crate::nodeauth::untrusted(&sh.ledger.lock().expect("ledger"), &sh.node, None, wicket_store::now()) {
        p.ever = false;
        bail!("{why}: not reconnecting");
    }
    let mut child = tokio::process::Command::new(&sh.argv[0])
        .args(&sh.argv[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("starting the node channel (ssh)")?;
    let mut to = child.stdin.take().expect("stdin");
    let mut from = child.stdout.take().expect("stdout");
    let errlog = {
        let mut e = child.stderr.take().expect("stderr");
        tokio::spawn(async move {
            let mut s = String::new();
            let _ = e.read_to_string(&mut s).await;
            s
        })
    };
    let build = crate::nodesrv::build_id()?;
    let hello = |nonce| Msg::Hello { node: sh.node.clone(), version: env!("CARGO_PKG_VERSION").into(), build, observer: false, nonce };
    let authed = match crate::nodeauth::control(&mut from, &mut to, &sh.node, &sh.ledger, &sh.issuer, hello).await {
        Ok(a) => a,
        Err(HsError::NoAnswer) => {
            let _ = child.start_kill();
            let err = errlog.await.unwrap_or_default();
            let err = err.trim().lines().last().unwrap_or("no error output").to_string();
            bail!("no answer from `wicket node serve` ({err}): is it installed and running? (`wicket node install {}`)", sh.node);
        }
        Err(e @ HsError::Timeout(_)) => return Err(e.into()),
        Err(HsError::Refused(why)) => {
            // Refused either way (identity, revocation, another build): not worth retrying.
            p.ever = false;
            bail!("{why}")
        }
    };
    let (feed, runs) = match authed.welcome {
        Msg::Welcome { feed, runs, .. } => (feed, runs),
        _ => unreachable!("nodeauth::control returns a welcome"),
    };
    p.ever = true;
    p.cert = Some(authed.cert);
    p.renewing = None;
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
    for f in sh.ctl.publisher.lock().expect("publisher").catch_up(&feed, now)? {
        send(feed_frame(f));
    }
    if let Some(r) = runs.iter().find(|r| r.run == sh.run.0) {
        println!("[wicket] node {} reconnected; resuming the box's output", sh.node);
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

    let mut tick = tokio::time::interval(std::time::Duration::from_millis((sh.cfg.refresh_ms / 2).clamp(50, 1000) as u64));
    let mut grants = tokio::time::interval(std::time::Duration::from_millis(250));
    let mut ident = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut buf = vec![0u8; 32 * 1024];
    let result = loop {
        tokio::select! {
            f = in_rx.recv() => match f {
                Some(f) => {
                    if let Err(e) = on_frame(sh, io, p, f, &out_tx, ready, started, target_epoch).await {
                        break Err(e);
                    }
                    if p.exited {
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
                let f = sh.ctl.publisher.lock().expect("publisher").tick(wicket_feed::now_ms());
                if let Some(f) = f {
                    send(feed_frame(f));
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
            }
        }
    };
    writer.abort();
    reader.abort();
    let _ = child.start_kill();
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
    started: &mut Option<oneshot::Sender<Option<String>>>,
    target_epoch: u64,
) -> Result<()> {
    let send = |f: Frame| {
        let _ = out.send(f);
    };
    match f {
        Frame::Data { stream, bytes, .. } if stream & TUNNEL_BIT != 0 => {
            sh.tunnels.data(stream, bytes);
        }
        Frame::Data { stream, offset, bytes } => {
            let Some(i) = [1usize, 2].into_iter().find(|&i| sh.streams[i] == stream) else { return Ok(()) };
            let (fresh, gap) = accept_at(&mut p.next[i - 1], offset, &bytes);
            if gap {
                println!(
                    "[wicket] some of the box's {} was lost while node {} was unreachable (it keeps {} MiB per stream)",
                    if i == 1 { "stdout" } else { "stderr" },
                    sh.node,
                    crate::nodesrv::OUTPUT_CAP >> 20
                );
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
                if let Some(r) = refused {
                    println!("[wicket] node {} refused a feed frame: {r}", sh.node);
                }
                if let Some(h) = catch_up {
                    for f in sh.ctl.publisher.lock().expect("publisher").catch_up(&h, wicket_feed::now_ms())? {
                        send(Frame::Feed(f.to_line().trim_end().as_bytes().to_vec()));
                    }
                }
                if mode == wicket_feed::Mode::Fresh && epoch.is_some_and(|e| e >= target_epoch) {
                    if let Some(t) = ready.take() {
                        let _ = t.send(Ok(()));
                    }
                }
            }
            Msg::Started { run, error } if run == sh.run.0 => {
                if let Some(t) = started.take() {
                    let _ = t.send(error);
                }
            }
            Msg::Exited { run, code, result } if run == sh.run.0 => {
                if let Some(r) = result {
                    let out = sh.dir.join("workspace/out");
                    let _ = std::fs::create_dir_all(&out);
                    let _ = std::fs::write(out.join("result.json"), r);
                }
                // End of output: the run loop's readers see EOF, then the exit.
                io.stdout.take();
                io.stderr.take();
                if let Some(t) = io.exit.take() {
                    let _ = t.send(code);
                }
                send(Frame::Msg(Msg::Forget { run }));
                p.exited = true;
            }
            Msg::Event { run, event } if run == sh.run.0 => {
                if let Ok(ev) = serde_json::from_value::<wicket_proxy::Event>(event) {
                    let _ = sh.events.send(ev);
                }
            }
            Msg::Ask { id, run, op, why, who } => send(Frame::Msg(ask(sh, id, &run, &op, &why, who.as_ref()))),
            Msg::TunnelOpen { stream, run, target } => {
                let ok_target = ["egress", "llm", "gateway"].contains(&target.as_str());
                let conn = match (run == sh.run.0, ok_target) {
                    (true, true) => {
                        tokio::net::UnixStream::connect(sh.dir.join("sock").join(format!("{target}.sock"))).await.map_err(|e| e.to_string())
                    }
                    _ => Err(format!("no tunnel to {target} for run {run}")),
                };
                match conn {
                    Ok(c) => {
                        send(Frame::Msg(Msg::TunnelOpened { stream, error: None }));
                        sh.tunnels.attach(stream, c, out.clone());
                    }
                    Err(e) => send(Frame::Msg(Msg::TunnelOpened { stream, error: Some(e) })),
                }
            }
            Msg::Close { stream } => sh.tunnels.close(stream),
            Msg::Audit { records } => {
                let n = records.len();
                if let Err(e) = sh.ledger.lock().expect("ledger").append_node_audit(&sh.node, &records) {
                    println!("[wicket] node {}'s audit records were refused ({e}); they stay on the node", sh.node);
                } else {
                    tracing::debug!(node = %sh.node, n, "node audit records appended");
                }
            }
            Msg::Refused { why } => bail!("node {} refused: {why}", sh.node),
            Msg::NodeCertInstalled { serial, error } => match (p.renewing.take(), error) {
                (Some(c), None) if c.jti == serial => {
                    println!("[wicket] node {}'s identity certificate renewed until {}", sh.node, c.exp);
                    p.cert = Some(c);
                }
                (_, e) => {
                    println!(
                        "[wicket] node {} did not take its renewed certificate ({}); retrying in a minute",
                        sh.node,
                        e.unwrap_or(serial)
                    );
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
            println!("[wicket] could not renew node {}'s certificate: {e:#}", sh.node);
            p.renew_after = now + 60;
            None
        }
    }
}

/// Raises (or finds) the pending request for an op the node asks about, if it is this run's.
fn ask(sh: &Shared, id: u64, run: &str, op: &Op, why: &str, who: Option<&serde_json::Value>) -> Msg {
    let reply = |pending, denied, error| Msg::Asked { id, pending, denied, error };
    if run != sh.run.0 || op.run != sh.run || op.tenant != sh.tenant || op.zone != sh.zone.name {
        return reply(None, None, Some(format!("not an op of run {}", sh.run)));
    }
    let l = sh.ledger.lock().expect("ledger");
    if let Ok(Some(rid)) = l.denied_recently(op) {
        return reply(None, Some(rid), None);
    }
    match l.pending_for(op, why, who) {
        Ok((rid, fresh)) => reply(Some((rid, fresh)), None, None),
        Err(e) => reply(None, None, Some(e.to_string())),
    }
}

/// Publishes grants approved for this run's requests to hosts the node terminates (and hands them
/// over, so the ledger stops consuming them), and revocations of grants it published. Grants for
/// hosts the node forwards stay in the ledger: the control host's egress proxy decides those.
///
/// A grant reaches the node as a block of the box's token: whenever the live grants change, the
/// token is rebuilt from its base with one block per live grant (signed with the approver key) and
/// published whole, in the same delta as any grant revocations. At most
/// [`wicket_feed::token::MAX_GRANTS`] are live at once; more stay in the ledger until some expire.
fn sync_grants(sh: &Shared, p: &mut Progress) -> Vec<wicket_feed::Frame> {
    let (grants, ca) = {
        let l = sh.ledger.lock().expect("ledger");
        let g = l.grants_for_run(&sh.run.0).unwrap_or_default();
        let now = wicket_store::now();
        let ca = l.node_cas(&sh.node).ok().and_then(|cs| cs.into_iter().find(|c| c.status == "active" && c.not_after > now));
        (g, ca)
    };
    let now_s = wicket_store::now();
    let mut changes = vec![];
    let ctx = sh.ctl.publisher.lock().expect("publisher").state().ctx;
    // Whether the token with these grants would load on a node (the publisher refuses it otherwise).
    let loads = |live: &[LiveGrant]| -> Result<(), String> {
        let a = sh.token_issuer.publish(&sh.approver, live).map_err(|e| e.to_string())?;
        wicket_feed::Policy::compile(&a, &ctx, &|_, _| false).map(|_| ())
    };
    let before = p.live.len();
    p.live.retain(|g| g.grant.not_after > u64::try_from(now_s).unwrap_or(0));
    let mut rebuild = p.live.len() != before;
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
        let route = wicket_proxy::decide::route(&g.host, &sh.zone, &[], ca.as_ref().map(|c| (&c.hosts[..], c.not_after)), now_s);
        if route != wicket_proxy::decide::Route::Terminate {
            continue;
        }
        if p.live.len() >= wicket_feed::token::MAX_GRANTS {
            println!(
                "[wicket] node {} holds {} live grants for {}: grant {} stays with the control host for now",
                sh.node,
                p.live.len(),
                sh.run,
                g.id
            );
            continue;
        }
        let op = Op::egress(&sh.tenant, &sh.run, &sh.zone.name, &g.method, &g.host, &g.path);
        // A node's grant covers its path whatever the query, and carries no risk bound: hand it over
        // only if no query makes that path riskier than the human approved (#119; a fetch's ref
        // discovery approved at R1 is a push's at R4). Otherwise the control host keeps deciding it.
        let worst = Op::egress_with_query(&sh.tenant, &sh.run, &sh.zone.name, &g.method, &g.host, &g.path, "any=query");
        if worst.risk.rank() > g.max_risk.unwrap_or(0) {
            if p.published.insert(g.id.clone()) {
                println!("[wicket] grant {} is bounded below what {} {}{} can be; it stays with the control host", g.id, g.method, g.host, g.path);
            }
            continue;
        }
        let live = LiveGrant {
            grant: wicket_authz::Grant {
                gid: g.id.clone(),
                box_id: sh.token_issuer.box_path.clone(),
                epoch: sh.token_issuer.epoch,
                host: op.host.clone(),
                method: op.method.clone(),
                path: op.path.clone(),
                not_after: u64::try_from(g.expires_at).unwrap_or(0),
                approver: g.request_id.as_deref().map_or_else(|| "operator".to_string(), |r| format!("request:{r}")),
                digest: hex::decode(op.digest()).unwrap_or_default(),
            },
            uses: g.uses_left.map(|u| u.clamp(0, i64::from(u32::MAX)) as u32),
        };
        let mut trial = p.live.clone();
        trial.push(live.clone());
        if let Err(e) = loads(&trial) {
            // Never handed over: the control host keeps deciding it.
            if p.published.insert(g.id.clone()) {
                println!("[wicket] grant {} can't go in {}'s token ({e}); it stays with the control host", g.id, sh.run);
            }
            continue;
        }
        if !sh.ledger.lock().expect("ledger").hand_grant_to_node(&g.id, &sh.node).unwrap_or(false) {
            continue;
        }
        if g.prefix {
            println!("[wicket] grant {} is for a path prefix; node {} honours it for {} exactly", g.id, sh.node, g.path);
        }
        p.live.push(live);
        p.published.insert(g.id);
        rebuild = true;
    }
    if !rebuild {
        return vec![];
    }
    match sh.token_issuer.publish(&sh.approver, &p.live) {
        Ok(a) => changes.push(Change::PutZone { zone: a }),
        Err(e) => println!("[wicket] could not rebuild the token of {} for node {}: {e}", sh.run, sh.node),
    }
    if changes.is_empty() {
        return vec![];
    }
    let n = p.live.len();
    let revokes: Vec<Change<BoxAuthority>> = changes.iter().filter(|c| matches!(c, Change::Revoke { .. })).cloned().collect();
    let committed = {
        let mut p = sh.ctl.publisher.lock().expect("publisher");
        let mut r = p.commit(changes, wicket_feed::now_ms());
        if r.is_err() && !revokes.is_empty() {
            // The rebuilt token was refused: the revocations must still go out.
            println!(
                "[wicket] could not publish {}'s rebuilt token ({}); publishing its grant revocations alone",
                sh.run,
                r.as_ref().err().map(|e| e.to_string()).unwrap_or_default()
            );
            r = p.commit(revokes, wicket_feed::now_ms());
        }
        r.map(|f| (f, p.epoch()))
    };
    match committed {
        Ok((f, epoch)) => {
            println!(
                "[wicket] published {}'s token with {n} live grant(s) to node {}, epoch {epoch} (at {} ms)",
                sh.run,
                sh.node,
                wicket_feed::now_ms()
            );
            vec![f]
        }
        Err(e) => {
            println!("[wicket] could not publish grants to node {}: {e}", sh.node);
            vec![]
        }
    }
}

/// The workspace directory as a tar archive (for [`BoxStart::workspace_tar`]).
pub fn tar_dir(dir: &Path) -> Result<Vec<u8>> {
    let out = std::process::Command::new("tar").arg("-C").arg(dir).args(["-cf", "-", "."]).output()?;
    if !out.status.success() {
        bail!("archiving {} failed", dir.display());
    }
    if out.stdout.len() > crate::chan::MAX_FRAME / 2 {
        bail!("the workspace is too large to send to a node ({} bytes)", out.stdout.len());
    }
    Ok(out.stdout)
}
