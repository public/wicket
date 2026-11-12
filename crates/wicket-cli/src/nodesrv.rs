//! `wicket node serve` (#57, step 3): the node process that owns its boxes and decides their egress
//! locally, so a box keeps working (for allowed requests) while the control host is unreachable.
//!
//! - **It owns the box.** The control host asks it to start a box ([`Msg::Start`]); it runs `docker run`
//!   here and relays the box's stdin, stdout and stderr over the control channel. When the channel
//!   drops, the box keeps running and its output is kept (up to [`OUTPUT_CAP`] bytes per stream, oldest
//!   dropped first; the control host reports a gap) and replayed when the control host reconnects. The
//!   node also enforces the run's timeout itself.
//! - **It decides egress.** Each box gets its own egress proxy on a unix socket, deciding from the
//!   node's verified feed replica (`wicket_proxy::decide::NodeDecider`) and terminating TLS with the
//!   node's name-constrained CA. Hosts the node must not terminate (an `inject` rule, a credential
//!   swap, outside the CA's constraints, or an expired CA) are tunnelled to the control host's egress
//!   proxy for the run. The LLM proxy and the MCP gateway stay on the control host too: the box's
//!   `llm.sock` and `gateway.sock` here are tunnels to them.
//! - **It keeps an audit log.** A ledger of its own (`audit.db`), hash-chained like the control host's,
//!   records its decisions; it ships records past the control host's watermark on every connect.
//! - **One control connection at a time**, on a unix socket in a 0700 directory, reached over ssh
//!   (`wicket node attach`). A newer connection replaces an older one, but only once it has proved
//!   this installation's issuer key and accepted the node's certificate (`nodeauth.rs`). The control
//!   host must also run the same wicket build (sha256 of the binary): anything else is refused.
//! - **Clock.** Feed decisions use the wall clock read once at start, advanced by a monotonic clock, so
//!   a wall-clock step while serving can't stretch a freshness statement (wicket-feed's README).

use crate::chan::{self, accept_at, BoxStart, Frame, Msg, OutBuf, RunState, Tunnels, TUNNEL_BIT};
use anyhow::{bail, Context, Result};
use base64::Engine;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use wicket_feed::{BoxAuthority, Replica, ReplicaConfig};
use wicket_proxy::ca::{Minter, NodeCa};
use wicket_proxy::decide::{Asked, Clock, ControlLink, NodeDecider, Route};
use wicket_proxy::egress::{Egress, Relay, RelayStream};
use wicket_sandbox::{Docker, Mount, SandboxSpec};
use wicket_store::Ledger;

/// Output kept per stream (stdout, stderr) while the control host is unreachable.
pub const OUTPUT_CAP: usize = 4 << 20;

/// The node's files: what enrolment installed, and what `serve` keeps.
pub struct NodePaths {
    pub root: PathBuf,
}

impl NodePaths {
    /// `$WICKET_NODE_HOME`, else `~/.local/share/wicket-node` (where enrolment put the node's keys).
    pub fn default_root() -> PathBuf {
        if let Some(d) = std::env::var_os("WICKET_NODE_HOME") {
            return PathBuf::from(d);
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        home.join(crate::enrol::NODE_DIR)
    }
    pub fn new(root: Option<PathBuf>) -> NodePaths {
        NodePaths { root: root.unwrap_or_else(NodePaths::default_root) }
    }
    pub fn socket(&self) -> PathBuf {
        self.root.join("ctl/ctl.sock")
    }
    /// Whether this node shares the control host's filesystem (the built-in local node, #146):
    /// `node.json` says `"shares_host": true`, which only the control host writes, for its own node.
    pub fn shares_host(&self) -> bool {
        std::fs::read(self.root.join("node.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .is_some_and(|v| v["shares_host"] == serde_json::Value::Bool(true))
    }
    fn feed(&self) -> PathBuf {
        self.root.join("feed")
    }
    fn runs(&self) -> PathBuf {
        self.root.join("runs")
    }
    pub fn name(&self) -> Result<String> {
        let info: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.root.join("node.json"))
                .with_context(|| format!("{} (is this node enrolled?)", self.root.join("node.json").display()))?,
        )?;
        info["name"].as_str().map(String::from).context("node.json has no name")
    }
}

/// The running binary's sha256: control host and node must run the same build. Hashed once per
/// process (a release binary is large, and every run connects to a node).
pub fn build_id() -> Result<String> {
    use sha2::Digest;
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(id) = ID.get() {
        return Ok(id.clone());
    }
    let exe = std::env::current_exe().context("finding this binary")?;
    // Hashing the binary takes a while (a release build is ~200 MB); every run would pay it. The id
    // is a compatibility check (the handshake authenticates), so a hash cached in the data directory,
    // keyed by the file's identity and modification time, is enough.
    let key = std::fs::metadata(&exe).ok().map(|m| {
        use std::os::unix::fs::MetadataExt;
        format!("{}:{}:{}:{}.{}", m.dev(), m.ino(), m.size(), m.mtime(), m.mtime_nsec())
    });
    let cache = crate::data_dir().join("build-id");
    let cached = std::fs::read_to_string(&cache).ok().and_then(|c| {
        let (k, id) = c.trim().split_once(' ')?;
        (Some(k) == key.as_deref() && id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())).then(|| id.to_string())
    });
    let id = match cached {
        Some(id) => id,
        None => {
            let id = hex::encode(sha2::Sha256::digest(std::fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?));
            if let Some(k) = &key {
                let tmp = cache.with_extension(format!("{}.new", std::process::id()));
                if std::fs::write(&tmp, format!("{k} {id}\n")).is_ok() {
                    let _ = std::fs::rename(&tmp, &cache);
                }
            }
            id
        }
    };
    Ok(ID.get_or_init(|| id).clone())
}

/// Wall time read once, advanced by the monotonic clock (Unix ms).
pub fn node_clock() -> Clock {
    let wall0 = wicket_feed::now_ms();
    let t0 = std::time::Instant::now();
    Arc::new(move || wall0 + t0.elapsed().as_millis() as i64)
}

struct BoxState {
    streams: [u64; 3],
    name: String,
    dir: PathBuf,
    stdin: Option<mpsc::UnboundedSender<Vec<u8>>>,
    stdin_next: u64,
    out: [OutBuf; 2],
    exited: Option<(i32, Option<String>)>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// uid:gid the box runs as (execs in it run as this, unless asked otherwise).
    user: String,
    /// Link relay sockets listened on in its socket directory, by name.
    listeners: HashMap<String, tokio::task::JoinHandle<()>>,
    /// The control connection that started or last resumed it: its stdio, events, asks and
    /// tunnels go there.
    owner: Option<u64>,
}

struct Link {
    out: chan::Out,
    /// What the connection is for (a run's id, or a link relay's): a newer connection with the same
    /// scope replaces it, others stay.
    scope: String,
    /// Ends the connection's reader (a newer connection took over).
    kill: Option<oneshot::Sender<()>>,
    /// Tunnels opened for the boxes this connection owns; they die with it.
    tunnels: Arc<Tunnels>,
}

struct Node {
    name: String,
    paths: NodePaths,
    ident: crate::nodeauth::NodeIdentity,
    build: String,
    clock: Clock,
    replica: Arc<Mutex<Replica<BoxAuthority>>>,
    audit: Arc<Mutex<Ledger>>,
    root_pem: String,
    docker: Docker,
    /// Authenticated control connections, by generation.
    links: Mutex<HashMap<u64, Link>>,
    boxes: Mutex<HashMap<String, BoxState>>,
    asks: Mutex<HashMap<u64, oneshot::Sender<Msg>>>,
    opens: Mutex<HashMap<u64, oneshot::Sender<Option<String>>>>,
    next: AtomicU64,
    /// The connection audit records are shipped on (the last to send `AuditFrom`), and how far.
    audit_link: Mutex<Option<u64>>,
    shipped: AtomicI64,
    /// One audit shipment at a time (the timer and a reconnect's watermark would send the same batch).
    shipping: Mutex<()>,
}

impl Node {
    /// Sends on connection `gen`.
    fn send_to(&self, gen: u64, f: Frame) -> bool {
        self.links.lock().expect("links").get(&gen).is_some_and(|l| l.out.send(f).is_ok())
    }

    /// The connection that owns `run`'s box, if it is up.
    fn owner(&self, run: &str) -> Option<u64> {
        let owner = self.boxes.lock().expect("boxes").get(run).and_then(|b| b.owner)?;
        self.links.lock().expect("links").contains_key(&owner).then_some(owner)
    }

    /// Sends to the connection that owns `run`'s box.
    fn send_run(&self, run: &str, f: Frame) -> bool {
        self.owner(run).is_some_and(|g| self.send_to(g, f))
    }

    #[cfg(test)]
    fn connected(&self) -> bool {
        !self.links.lock().expect("links").is_empty()
    }

    fn id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn ca(&self) -> Option<Arc<NodeCa>> {
        let cert = std::fs::read_to_string(self.paths.root.join("ca.pem")).ok()?;
        let key = std::fs::read_to_string(self.paths.root.join("ca.key")).ok()?;
        match NodeCa::load(&cert, &key) {
            Ok(c) => Some(Arc::new(c)),
            Err(e) => {
                eprintln!("[node] the node CA is unusable ({e:#}); every host is forwarded to the control host");
                None
            }
        }
    }

    /// Opens a tunnel to the run's `target` socket on the control host.
    async fn open_tunnel(self: &Arc<Self>, run: &str, target: &str) -> std::io::Result<tokio::io::DuplexStream> {
        let unreachable = || std::io::Error::new(std::io::ErrorKind::NotConnected, "the control host is unreachable");
        let (out, tunnels) = {
            let gen = self.owner(run).ok_or_else(unreachable)?;
            let links = self.links.lock().expect("links");
            let l = links.get(&gen).ok_or_else(unreachable)?;
            (l.out.clone(), l.tunnels.clone())
        };
        let id = TUNNEL_BIT | self.id();
        let (tx, rx) = oneshot::channel();
        self.opens.lock().expect("opens").insert(id, tx);
        if out.send(Frame::Msg(Msg::TunnelOpen { stream: id, run: run.into(), target: target.into() })).is_err() {
            return Err(unreachable());
        }
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(None)) => {}
            Ok(Ok(Some(e))) => return Err(std::io::Error::other(e)),
            _ => {
                self.opens.lock().expect("opens").remove(&id);
                return Err(unreachable());
            }
        }
        let (ours, theirs) = tokio::io::duplex(256 * 1024);
        tunnels.attach(id, theirs, out);
        Ok(ours)
    }

    fn feed_status(&self, refused: Option<&wicket_feed::Refusal>) -> Frame {
        let r = self.replica.lock().expect("replica");
        let mode = r.mode((self.clock)());
        let catch_up = refused.filter(|e| e.wants_catch_up()).map(|_| r.hello());
        Frame::Msg(Msg::FeedStatus {
            mode,
            epoch: r.state().map(|s| s.epoch),
            refused: refused.map(|e| format!("{}: {e}", e.kind())),
            catch_up,
        })
    }

    fn ship_audit(&self) {
        let _one = self.shipping.lock().expect("shipping");
        let from = self.shipped.load(Ordering::SeqCst);
        let Some(gen) = *self.audit_link.lock().expect("audit link") else { return };
        if from < 0 {
            return;
        }
        let recs = self.audit.lock().expect("audit").audit_records_after(from, 500).unwrap_or_default();
        if let Some(last) = recs.last().map(|r| r.seq) {
            if self.send_to(gen, Frame::Msg(Msg::Audit { records: recs })) {
                self.shipped.store(last, Ordering::SeqCst);
            }
        }
    }
}

/// The decider's way to the control host.
struct Control(Arc<Node>, String);

impl ControlLink for Control {
    fn connected(&self) -> bool {
        self.0.owner(&self.1).is_some()
    }

    fn ask<'a>(
        &'a self,
        op: &'a wicket_core::Op,
        why: &'a str,
        who: Option<&'a serde_json::Value>,
    ) -> futures_util::future::BoxFuture<'a, std::result::Result<Asked, String>> {
        Box::pin(async move {
            let id = self.0.id();
            let (tx, rx) = oneshot::channel();
            self.0.asks.lock().expect("asks").insert(id, tx);
            let sent = self.0.send_run(
                &self.1,
                Frame::Msg(Msg::Ask { id, run: self.1.clone(), op: Box::new(op.clone()), why: why.into(), who: who.cloned() }),
            );
            let reply = match sent {
                true => tokio::time::timeout(std::time::Duration::from_secs(10), rx).await.ok().and_then(|r| r.ok()),
                false => None,
            };
            self.0.asks.lock().expect("asks").remove(&id);
            match reply {
                Some(Msg::Asked { pending: Some((request, fresh)), .. }) => Ok(Asked::Pending { request, fresh }),
                Some(Msg::Asked { denied: Some(request), .. }) => Ok(Asked::Denied { request }),
                Some(Msg::Asked { error: Some(e), .. }) => Err(e),
                _ => Err("the control host did not answer".into()),
            }
        })
    }
}

/// Where a run's CONNECTs go, and the way to the control host's egress proxy for it.
struct NodeRelay {
    node: Arc<Node>,
    run: String,
    zone: Arc<wicket_core::CompiledZone>,
    ca: Option<Arc<NodeCa>>,
}

impl Relay for NodeRelay {
    fn route(&self, host: &str) -> Route {
        // The zone as the feed has it now (inject rules may have changed since the box started).
        let spec = {
            let r = self.node.replica.lock().expect("replica");
            r.zone_of(&self.run).filter(|z| z.name == self.zone.name).cloned()
        };
        let spec = spec.unwrap_or_else(|| (*self.zone).clone());
        let now = (self.node.clock)() / 1000;
        wicket_proxy::decide::route(host, &spec, &[], self.ca.as_ref().map(|c| (&c.permitted[..], c.not_after)), now)
    }

    fn open(&self) -> futures_util::future::BoxFuture<'_, std::io::Result<Box<dyn RelayStream>>> {
        Box::pin(async move { self.node.open_tunnel(&self.run, "egress").await.map(|s| Box::new(s) as Box<dyn RelayStream>) })
    }
}

/// A minter for a node without a usable CA: every host is forwarded, so it is never asked.
struct NoCa;

impl Minter for NoCa {
    fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        bail!("this node has no usable CA: {host} must be forwarded")
    }
}

pub async fn serve(dir: Option<PathBuf>, idle_exit: Option<u64>) -> Result<()> {
    let paths = NodePaths::new(dir);
    let name = paths.name()?;
    // One `serve` per node directory: a second one would take the socket from the first.
    let _one = {
        use std::os::fd::AsRawFd;
        let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(paths.root.join("serve.lock"))?;
        // SAFETY: flock on a file descriptor this function owns.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            eprintln!("[node] another `wicket node serve` is serving {}", paths.root.display());
            return Ok(());
        }
        f
    };
    let root_hex = std::fs::read_to_string(paths.root.join("feed-root.pub")).context("feed-root.pub (is this node enrolled?)")?;
    let root_key: [u8; 32] = hex::decode(root_hex.trim()).ok().and_then(|b| b.try_into().ok()).context("feed-root.pub is not a key")?;
    let root_key = wicket_identity::VerifyingKey::from_bytes(&root_key).context("feed-root.pub is not a key")?;
    let root_pem = std::fs::read_to_string(paths.root.join("root.pem")).context("root.pem (is this node enrolled?)")?;
    let authz_hex = std::fs::read_to_string(paths.root.join("authz-root.pub")).context(
        "authz-root.pub (enrolled before boxes' authority moved to tokens? run `wicket node renew-ca` for this node on the control host)",
    )?;
    let authz_root: [u8; 32] = hex::decode(authz_hex.trim()).ok().and_then(|b| b.try_into().ok()).context("authz-root.pub is not a key")?;
    let authz_root = wicket_authz::PublicKey(authz_root);
    let replica = match Replica::open_with(&paths.feed(), &name, root_key, ReplicaConfig::default(), authz_root) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[node] the persisted feed does not verify ({e}); starting closed until the control host sends a fresh one");
            Replica::reset_with(&paths.feed(), &name, root_key, ReplicaConfig::default(), authz_root)?
        }
    };
    let ident = crate::nodeauth::NodeIdentity::load(&paths.root, &name, wicket_feed::now_ms() / 1000)?;
    let audit = crate::audit_export::open_batched(&paths.root.join("audit.db"))?;
    std::fs::create_dir_all(paths.runs())?;
    let ctl = paths.socket();
    let ctl_dir = ctl.parent().expect("socket dir");
    std::fs::create_dir_all(ctl_dir)?;
    std::fs::set_permissions(ctl_dir, std::fs::Permissions::from_mode(0o700))?;
    let _ = std::fs::remove_file(&ctl);
    let listener = UnixListener::bind(&ctl).with_context(|| format!("listening on {}", ctl.display()))?;
    let node = Arc::new(Node {
        name: name.clone(),
        paths,
        ident,
        build: build_id()?,
        clock: node_clock(),
        replica: Arc::new(Mutex::new(replica)),
        audit: Arc::new(Mutex::new(audit)),
        root_pem,
        docker: Docker::from_env(),
        links: Mutex::new(HashMap::new()),
        boxes: Mutex::new(HashMap::new()),
        asks: Mutex::new(HashMap::new()),
        opens: Mutex::new(HashMap::new()),
        next: AtomicU64::new(0),
        audit_link: Mutex::new(None),
        shipped: AtomicI64::new(-1),
        shipping: Mutex::new(()),
    });
    // Queued audit records are committed (and shipped, if the control host is connected) on a
    // normal exit, SIGTERM or ^C: only a SIGKILL can lose the last unwaited batch.
    let _flush = crate::audit_export::FlushOnDrop(node.audit.clone());
    {
        let n = node.clone();
        crate::audit_export::flush_on_signal(node.audit.clone(), move || n.ship_audit());
    }
    reap_previous(&node.docker, &node.paths.runs()).await;
    let mode = node.replica.lock().expect("replica").mode((node.clock)());
    eprintln!("[node] {name}: serving on {} (build {}, feed {mode:?})", ctl.display(), &node.build[..12]);
    {
        let n = node.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                t.tick().await;
                n.ship_audit();
            }
        });
    }
    if let Some(secs) = idle_exit {
        // Exits once it has had no boxes and no connections for `secs` (or its directory is gone).
        let n = node.clone();
        let root = n.paths.root.clone();
        tokio::spawn(async move {
            let mut idle_since = std::time::Instant::now();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let busy = !n.links.lock().expect("links").is_empty()
                    || n.boxes
                        .lock()
                        .expect("boxes")
                        .values()
                        .any(|b| b.exited.is_none() || b.owner.is_some_and(|g| n.links.lock().expect("links").contains_key(&g)));
                if busy {
                    idle_since = std::time::Instant::now();
                }
                if !root.join("node.json").exists() || idle_since.elapsed().as_secs() >= secs {
                    eprintln!("[node] idle for {secs} s: exiting");
                    if let Ok(l) = n.audit.lock() {
                        let _ = l.flush_audit();
                    }
                    std::process::exit(0);
                }
            }
        });
    }
    let mut gen = 0u64;
    loop {
        let (stream, _) = listener.accept().await?;
        gen += 1;
        let n = node.clone();
        tokio::spawn(async move {
            if let Err(e) = connection(n, stream, gen).await {
                eprintln!("[node] control connection ended: {e:#}");
            }
        });
    }
}

/// Stops boxes a previous `node serve` from this directory started (their run directory is under its
/// `runs/`): their owner is gone, so nobody holds their stdio or decides their egress. Any other
/// container, wicket's or not, is left alone.
async fn reap_previous(docker: &Docker, runs: &std::path::Path) {
    let Ok(boxes) = docker.boxes().await else { return };
    for b in boxes {
        let ours = b.run.as_deref().is_some_and(|r| crate::run::check_run_id(r).is_ok() && runs.join(r).is_dir());
        if !ours {
            continue;
        }
        if let crate::reap::Verdict::Orphan(why) = crate::reap::judge(&b, None) {
            eprintln!("[node] stopping {} ({why})", b.name);
            let _ = docker.kill(&b.name).await;
        }
    }
}

async fn connection(node: Arc<Node>, stream: UnixStream, gen: u64) -> Result<()> {
    let (mut rd, mut wr) = stream.into_split();
    let hello = tokio::time::timeout(std::time::Duration::from_secs(15), chan::read_frame(&mut rd)).await.context("no hello")??;
    if hello.is_none() {
        // Connected and closed: a check that the node is up (`localnode::ensure`).
        return Ok(());
    }
    let refuse = |why: String| Frame::Msg(Msg::Refused { why }).encode();
    let (observer, scope) = match hello {
        Some(Frame::Msg(Msg::Hello { node: n, build, version, observer, nonce, scope })) => {
            let why = if n != node.name {
                Some(format!("this is node {}, not {n}", node.name))
            } else if build != node.build {
                Some(format!(
                    "the control host runs wicket {version} build {}…, this node runs build {}…: run `wicket node install {}` from the control host",
                    &build[..12.min(build.len())],
                    &node.build[..12],
                    node.name
                ))
            } else {
                None
            };
            if let Some(why) = why {
                wr.write_all(&refuse(why.clone())).await?;
                bail!("refused a control host: {why}");
            }
            if !observer {
                // Nothing changes here (the current connection keeps the link) until it has proved
                // this installation's issuer key.
                if let Err(e) = crate::nodeauth::node(&mut rd, &mut wr, &node.ident, &node.paths.root, &node.name, &nonce).await {
                    let why = format!("{e:#}");
                    wr.write_all(&refuse(why.clone())).await?;
                    bail!("refused a control host: {why}");
                }
            }
            (observer, scope)
        }
        _ => {
            wr.write_all(&refuse("expected a hello".into())).await?;
            bail!("no hello");
        }
    };
    if observer {
        // Feed frames only, answered on this connection; the control connection is left alone.
        while let Some(f) = chan::read_frame(&mut rd).await? {
            if let Frame::Feed(bytes) = f {
                let r = node.replica.lock().expect("replica").accept_bytes(&bytes, (node.clock)());
                if let Err(e) = &r {
                    eprintln!("[node] feed frame refused (observer): {} ({e})", e.kind());
                }
                wr.write_all(&node.feed_status(r.as_ref().err()).encode()).await?;
            }
        }
        return Ok(());
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();
    let (kill_tx, mut kill_rx) = oneshot::channel();
    let tunnels = Arc::new(Tunnels::default());
    {
        // A newer connection with the same scope (the same run reconnecting) replaces the older one;
        // connections for other runs stay.
        let mut links = node.links.lock().expect("links");
        let older: Vec<u64> = links.iter().filter(|(_, l)| l.scope == scope).map(|(g, _)| *g).collect();
        for g in older {
            if let Some(mut old) = links.remove(&g) {
                old.tunnels.clear();
                if let Some(k) = old.kill.take() {
                    let _ = k.send(());
                }
            }
        }
        links.insert(gen, Link { out: tx.clone(), scope: scope.clone(), kill: Some(kill_tx), tunnels: tunnels.clone() });
    }
    let writer = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            if wr.write_all(&f.encode()).await.is_err() {
                break;
            }
        }
    });
    let runs: Vec<RunState> = node
        .boxes
        .lock()
        .expect("boxes")
        .iter()
        .map(|(run, b)| RunState {
            run: run.clone(),
            streams: b.streams,
            stdin_received: b.stdin_next,
            stdout_total: b.out[0].end(),
            stderr_total: b.out[1].end(),
            exited: b.exited.clone(),
        })
        .collect();
    let feed = node.replica.lock().expect("replica").hello();
    let _ = tx.send(Frame::Msg(Msg::Welcome { node: node.name.clone(), build: node.build.clone(), feed, runs }));
    eprintln!("[node] control host connected{}", if scope.is_empty() { String::new() } else { format!(" ({scope})") });
    let result = loop {
        tokio::select! {
            _ = &mut kill_rx => break Ok(()),
            f = chan::read_frame(&mut rd) => match f {
                Ok(Some(f)) => {
                    if let Err(e) = handle(&node, gen, &tunnels, f).await {
                        break Err(e);
                    }
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e.into()),
            }
        }
    };
    let gone = node.links.lock().expect("links").remove(&gen);
    if let Some(l) = gone {
        l.tunnels.clear();
        let mut a = node.audit_link.lock().expect("audit link");
        if *a == Some(gen) {
            *a = None;
            node.shipped.store(-1, Ordering::SeqCst);
            // Another connection, if any, takes over the audit shipping from its own watermark.
            let next = node.links.lock().expect("links").iter().filter(|(_, l)| l.scope.starts_with("run_")).map(|(g, _)| *g).max();
            if let Some(g) = next {
                node.send_to(g, Frame::Msg(Msg::AuditAsk {}));
            }
        }
        eprintln!(
            "[node] control host disconnected{}; its boxes keep running on the feed held",
            if scope.is_empty() { String::new() } else { format!(" ({scope})") }
        );
    }
    writer.abort();
    result
}

async fn handle(node: &Arc<Node>, gen: u64, tunnels: &Tunnels, f: Frame) -> Result<()> {
    match f {
        Frame::Feed(bytes) => {
            let now = (node.clock)();
            let r = node.replica.lock().expect("replica").accept_bytes(&bytes, now);
            if let Err(e) = &r {
                eprintln!("[node] feed frame refused: {} ({e})", e.kind());
                let _ = node.audit.lock().expect("audit").audit(
                    &wicket_core::TenantId::single(),
                    None,
                    "feed.refused",
                    &serde_json::json!({ "kind": e.kind(), "why": e.to_string() }),
                );
            }
            if r.is_ok() {
                if let Ok(f) = wicket_feed::Frame::parse(&bytes) {
                    if matches!(f.kind, wicket_feed::FrameKind::Delta | wicket_feed::FrameKind::Snap) {
                        let epoch = node.replica.lock().expect("replica").state().map(|s| s.epoch);
                        eprintln!(
                            "[node] feed {} applied, epoch {} (at {} ms)",
                            f.kind.as_str(),
                            epoch.unwrap_or(0),
                            wicket_feed::now_ms()
                        );
                    }
                }
            }
            node.send_to(gen, node.feed_status(r.as_ref().err()));
        }
        Frame::Data { stream, offset, bytes } if stream & TUNNEL_BIT != 0 => {
            tunnels.data(stream, bytes);
            let _ = offset;
        }
        Frame::Data { stream, offset, bytes } => {
            let mut boxes = node.boxes.lock().expect("boxes");
            if let Some(b) = boxes.values_mut().find(|b| b.owner == Some(gen) && b.streams[0] == stream) {
                let (fresh, _) = accept_at(&mut b.stdin_next, offset, &bytes);
                if let (Some(s), false) = (&b.stdin, fresh.is_empty()) {
                    let _ = s.send(fresh);
                }
            }
        }
        Frame::Msg(m) => match m {
            Msg::Start(bs) => {
                let n = node.clone();
                tokio::spawn(async move {
                    let run = bs.run.clone();
                    let error = start_box(&n, gen, *bs).await.err().map(|e| format!("{e:#}"));
                    if let Some(e) = &error {
                        eprintln!("[node] starting {run} failed: {e}");
                    }
                    n.send_to(gen, Frame::Msg(Msg::Started { run, error }));
                });
            }
            Msg::Resume { run, stdout_from, stderr_from } => {
                let (frames, exited) = {
                    let mut boxes = node.boxes.lock().expect("boxes");
                    let Some(b) = boxes.get_mut(&run) else { return Ok(()) };
                    // The resuming connection owns the box from now on.
                    b.owner = Some(gen);
                    let mut v = vec![];
                    for (i, from) in [(0usize, stdout_from), (1, stderr_from)] {
                        let (at, bytes) = b.out[i].since(from);
                        for (k, c) in bytes.chunks(32 * 1024).enumerate() {
                            v.push(Frame::Data { stream: b.streams[i + 1], offset: at + (k * 32 * 1024) as u64, bytes: c.to_vec() });
                        }
                    }
                    (v, b.exited.clone())
                };
                for f in frames {
                    node.send_to(gen, f);
                }
                if let Some((code, result)) = exited {
                    node.send_to(gen, Frame::Msg(Msg::Exited { run, code, result }));
                }
            }
            Msg::Ack { stream, upto } => {
                let mut boxes = node.boxes.lock().expect("boxes");
                for b in boxes.values_mut().filter(|b| b.owner == Some(gen)) {
                    for i in 0..2 {
                        if b.streams[i + 1] == stream {
                            b.out[i].ack(upto);
                        }
                    }
                }
            }
            Msg::StdinClose { run } => {
                if let Some(b) = node.boxes.lock().expect("boxes").get_mut(&run) {
                    b.stdin = None;
                }
            }
            Msg::Kill { run } => {
                let name = node.boxes.lock().expect("boxes").get(&run).map(|b| b.name.clone());
                if let Some(name) = name {
                    // A paused (idle) box is unpaused first, so it can be killed.
                    let _ = node.docker.unpause(&name).await;
                    let _ = node.docker.kill(&name).await;
                }
            }
            Msg::Forget { run } => {
                let b = node.boxes.lock().expect("boxes").remove(&run);
                if let Some(b) = b {
                    b.tasks.iter().for_each(|t| t.abort());
                    // Only what the node laid out itself: a shared-filesystem box's directory is the run's.
                    if b.dir.starts_with(node.paths.runs()) {
                        let _ = std::fs::remove_dir_all(&b.dir);
                    }
                }
            }
            m @ Msg::Asked { .. } => {
                let Msg::Asked { id, .. } = &m else { unreachable!() };
                if let Some(tx) = node.asks.lock().expect("asks").remove(id) {
                    let _ = tx.send(m);
                }
            }
            Msg::AuditFrom { seq } => {
                {
                    let _one = node.shipping.lock().expect("shipping");
                    *node.audit_link.lock().expect("audit link") = Some(gen);
                    node.shipped.store(seq, Ordering::SeqCst);
                }
                node.ship_audit();
            }
            Msg::TunnelOpened { stream, error } => {
                if let Some(tx) = node.opens.lock().expect("opens").remove(&stream) {
                    let _ = tx.send(error);
                }
            }
            Msg::Close { stream } => tunnels.close(stream),
            Msg::BoxCtl { id, run, what, user, arg } => {
                let n = node.clone();
                tokio::spawn(async move {
                    let (out, error) = match box_ctl(&n, &run, &what, &user, &arg).await {
                        Ok(o) => (o, None),
                        Err(e) => (None, Some(format!("{e:#}"))),
                    };
                    n.send_to(gen, Frame::Msg(Msg::BoxCtlDone { id, out, error }));
                });
            }
            Msg::Exec { stream, run, user, argv, stdin } => {
                let out = node.links.lock().expect("links").get(&gen).map(|l| l.out.clone());
                let (Some(out), true) = (out, stream & TUNNEL_BIT != 0 && stream & chan::CONTROL_TUNNEL_BIT != 0) else {
                    return Ok(());
                };
                let found = node
                    .boxes
                    .lock()
                    .expect("boxes")
                    .get(&run)
                    .filter(|b| b.exited.is_none())
                    .map(|b| (b.name.clone(), if user.is_empty() { b.user.clone() } else { user.clone() }));
                let spawned = match found {
                    None => Err(format!("run {run} has no running box on this node")),
                    Some((name, user)) => node
                        .docker
                        .exec(&name, &user, if stdin { &["-i"] } else { &[] }, &argv)
                        .stdin(if stdin { std::process::Stdio::piped() } else { std::process::Stdio::null() })
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .kill_on_drop(true)
                        .spawn()
                        .map_err(|e| format!("docker exec: {e}")),
                };
                match spawned {
                    Err(e) => {
                        node.send_to(gen, Frame::Msg(Msg::TunnelOpened { stream, error: Some(e) }));
                    }
                    Ok(mut c) => {
                        let rd = c.stdout.take().expect("stdout");
                        let wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = match c.stdin.take() {
                            Some(w) => Box::new(w),
                            None => Box::new(tokio::io::sink()),
                        };
                        node.send_to(gen, Frame::Msg(Msg::TunnelOpened { stream, error: None }));
                        tunnels.attach(stream, tokio::io::join(rd, wr), out);
                        let n = node.clone();
                        tokio::spawn(async move {
                            let code = c.wait().await.ok().and_then(|s| s.code()).unwrap_or(-1);
                            n.send_to(gen, Frame::Msg(Msg::ExecDone { stream, code }));
                        });
                    }
                }
            }
            Msg::Listen { id, run, sock } => {
                let error = listen(node, gen, &run, &sock).err().map(|e| format!("{e:#}"));
                node.send_to(gen, Frame::Msg(Msg::BoxCtlDone { id, out: None, error }));
            }
            Msg::Unlisten { run, sock } => {
                if let Some(b) = node.boxes.lock().expect("boxes").get_mut(&run) {
                    if let Some(t) = b.listeners.remove(&sock) {
                        t.abort();
                    }
                    let _ = std::fs::remove_file(b.dir.join("sock").join(&sock));
                }
            }
            Msg::NodeCert { cert } => {
                let now = (node.clock)() / 1000;
                let (serial, error) = match node.ident.install_cert(&node.paths.root, cert.trim(), &node.name, now) {
                    Ok(c) => {
                        eprintln!("[node] identity certificate renewed: {}… until {}", &c.jti[..12], c.exp);
                        (c.jti, None)
                    }
                    Err(e) => {
                        eprintln!("[node] refused a renewed identity certificate: {e:#}");
                        (String::new(), Some(format!("{e:#}")))
                    }
                };
                node.send_to(gen, Frame::Msg(Msg::NodeCertInstalled { serial, error }));
            }
            other => bail!("unexpected message from the control host: {other:?}"),
        },
    }
    Ok(())
}

/// `Msg::BoxCtl`: pause, unpause, list processes, or rewrite the hosts file of a run's box.
async fn box_ctl(node: &Node, run: &str, what: &str, user: &str, arg: &str) -> Result<Option<String>> {
    let (name, dir, box_user) = node
        .boxes
        .lock()
        .expect("boxes")
        .get(run)
        .filter(|b| b.exited.is_none())
        .map(|b| (b.name.clone(), b.dir.clone(), b.user.clone()))
        .with_context(|| format!("run {run} has no running box on this node"))?;
    let user = if user.is_empty() { box_user.as_str() } else { user };
    match what {
        "status" => Ok(None),
        "pause" => node.docker.pause(&name).await.map(|()| None),
        "unpause" => node.docker.unpause(&name).await.map(|()| None),
        "processes" => Ok(Some(serde_json::to_string(&node.docker.processes(&name, user).await?)?)),
        "hosts" => {
            if arg.len() > 64 * 1024 {
                bail!("hosts file too large");
            }
            // Rewritten in place: it is bind-mounted by inode.
            let mut f = std::fs::OpenOptions::new().write(true).truncate(true).open(dir.join("hosts"))?;
            std::io::Write::write_all(&mut f, arg.as_bytes())?;
            Ok(None)
        }
        w => bail!("unknown box operation {w:?}"),
    }
}

/// `Msg::Listen`: a link's relay socket in a run's socket directory; each connection to it is offered
/// to connection `gen` as a tunnel.
fn listen(node: &Arc<Node>, gen: u64, run: &str, sock: &str) -> Result<()> {
    let ok = sock
        .strip_prefix("link-")
        .and_then(|s| s.strip_suffix(".sock"))
        .is_some_and(|id| !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    if !ok {
        bail!("bad link socket name {sock:?}");
    }
    let mut boxes = node.boxes.lock().expect("boxes");
    let b = boxes.get_mut(run).filter(|b| b.exited.is_none()).with_context(|| format!("run {run} has no running box on this node"))?;
    let path = b.dir.join("sock").join(sock);
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path).with_context(|| format!("listening on {sock}"))?;
    let (n, run2, target) = (node.clone(), run.to_string(), format!("link:{sock}"));
    let task = tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            let (n, run, target) = (n.clone(), run2.clone(), target.clone());
            tokio::spawn(async move {
                let out = n.links.lock().expect("links").get(&gen).map(|l| (l.out.clone(), l.tunnels.clone()));
                let Some((out, tunnels)) = out else { return };
                let id = TUNNEL_BIT | n.id();
                let (tx, rx) = oneshot::channel();
                n.opens.lock().expect("opens").insert(id, tx);
                if out.send(Frame::Msg(Msg::TunnelOpen { stream: id, run, target })).is_err() {
                    return;
                }
                match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
                    Ok(Ok(None)) => tunnels.attach(id, c, out),
                    _ => {
                        n.opens.lock().expect("opens").remove(&id);
                    }
                }
            });
        }
    });
    if let Some(old) = b.listeners.insert(sock.to_string(), task) {
        old.abort();
    }
    Ok(())
}

fn ids() -> String {
    // SAFETY: getuid and getgid can't fail.
    unsafe { format!("{}:{}", libc::getuid(), libc::getgid()) }
}

async fn start_box(node: &Arc<Node>, gen: u64, bs: BoxStart) -> Result<()> {
    crate::run::check_run_id(&bs.run)?;
    if node.boxes.lock().expect("boxes").contains_key(&bs.run) {
        bail!("run {} is already on this node", bs.run);
    }
    // The box's authority (its token) must be in the feed, for the zone the box is started in.
    let zone = {
        let r = node.replica.lock().expect("replica");
        r.zone_of(&bs.run).cloned()
    };
    let zone = zone.with_context(|| format!("run {} has no authority in this node's feed", bs.run))?;
    if zone.name != bs.zone {
        bail!("run {}'s authority is for zone {}, not {}", bs.run, zone.name, bs.zone);
    }
    if !node.docker.image_exists(&bs.image).await? {
        bail!("image {} not found on node {} (run: wicket image there)", bs.image, node.name);
    }
    let (dir, spec, mut tasks) = match &bs.host {
        Some(h) => host_layout(node, &bs, h)?,
        None => {
            let dir = node.paths.runs().join(&bs.run);
            for sub in ["sock", "ca", "state/home", "state/claude", "workspace/out"] {
                std::fs::create_dir_all(dir.join(sub))?;
            }
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            std::fs::write(dir.join("ca/ca.pem"), format!("{}{}", node.root_pem, bs.ca_pem))?;
            std::fs::write(dir.join("hosts"), wicket_core::link::hosts_file(&[]))?;
            let b64 = base64::engine::general_purpose::STANDARD;
            let tar = b64.decode(&bs.workspace_tar).context("workspace archive")?;
            if !tar.is_empty() {
                let mut c = tokio::process::Command::new("tar")
                    .arg("-C")
                    .arg(dir.join("workspace"))
                    .args(["--no-same-owner", "-xf", "-"])
                    .stdin(std::process::Stdio::piped())
                    .spawn()?;
                c.stdin.take().expect("stdin").write_all(&tar).await?;
                if !c.wait().await?.success() {
                    bail!("unpacking the workspace failed");
                }
            }
            for (rel, body) in &bs.state_files {
                if rel.split('/').any(|p| p.is_empty() || p == "..") {
                    bail!("bad state file name {rel:?}");
                }
                let p = dir.join("state").join(rel);
                if let Some(d) = p.parent() {
                    std::fs::create_dir_all(d)?;
                }
                std::fs::write(&p, b64.decode(body)?)?;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
            }
            let mut volume_mounts = vec![];
            for (name, target) in &bs.volumes {
                let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) && s != "..";
                if !ok(name) || !ok(&bs.tenant) || !ok(&bs.zone) {
                    bail!("bad volume name {name:?}");
                }
                let d = node.paths.root.join("volumes").join(&bs.tenant).join(&bs.zone).join(name);
                std::fs::create_dir_all(&d)?;
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
                volume_mounts.push(Mount { host: d, target: target.clone(), read_only: false });
            }

            // The box's enforcement points: egress decided here; LLM and MCP gateway tunnelled to the control host.
            let compiled = Arc::new(wicket_core::CompiledZone::new(zone)?);
            let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<wicket_proxy::Event>();
            let ctx = wicket_proxy::RunCtx {
                tenant: wicket_core::TenantId(bs.tenant.clone()),
                run: wicket_core::RunId(bs.run.clone()),
                zone: compiled.clone(),
                ledger: node.audit.clone(),
                // Secrets never reach a node: hosts that need one are forwarded, so this vault stays empty.
                vault: wicket_proxy::vault::Vault::new(node.paths.root.join("no-secrets")),
                events: ev_tx,
                escalate: bs.escalate,
                attribute: None,
                identity: None,
                spawner: None,
                swaps: vec![],
                boxes: None,
                capacity: None,
                fence: None,
                waker: None,
            };
            let ca = node.ca();
            let minter: Arc<dyn Minter> = match &ca {
                Some(c) => c.clone(),
                None => Arc::new(NoCa),
            };
            let decider = Arc::new(NodeDecider {
                replica: node.replica.clone(),
                clock: node.clock.clone(),
                control: Arc::new(Control(node.clone(), bs.run.clone())),
            });
            let relay = Arc::new(NodeRelay { node: node.clone(), run: bs.run.clone(), zone: compiled, ca });
            let egress = Egress::with(ctx, minter, decider, Some(relay))?;
            // DNS and HTTP/3 for the box (#92), decided here like CONNECT: by the node's policy, with the
            // node's CA; hosts the node forwards to the control host get a 403 over HTTP/3 that points at
            // the proxy, which forwards them.
            let h3 = wicket_proxy::h3::H3::new(egress.clone(), wicket_proxy::h3::Options::from_env())?;
            let sock = dir.join("sock");
            let mut tasks = vec![];
            tasks.push(tokio::spawn({
                let us = sock.join("udp.sock");
                async move {
                    if let Err(e) = h3.serve(&us).await {
                        eprintln!("[node] HTTP/3 and DNS ended: {e:#}");
                    }
                }
            }));
            let es = sock.join("egress.sock");
            tasks.push(tokio::spawn({
                let es = es.clone();
                async move {
                    if let Err(e) = egress.serve(&es).await {
                        eprintln!("[node] egress proxy ended: {e:#}");
                    }
                }
            }));
            for target in ["llm", "gateway"] {
                let _ = std::fs::remove_file(sock.join(format!("{target}.sock")));
                let l = UnixListener::bind(sock.join(format!("{target}.sock")))?;
                let (n, run) = (node.clone(), bs.run.clone());
                tasks.push(tokio::spawn(async move {
                    while let Ok((mut c, _)) = l.accept().await {
                        let (n, run) = (n.clone(), run.clone());
                        tokio::spawn(async move {
                            if let Ok(mut t) = n.open_tunnel(&run, target).await {
                                let _ = tokio::io::copy_bidirectional(&mut c, &mut t).await;
                            }
                        });
                    }
                }));
            }
            {
                let (n, run) = (node.clone(), bs.run.clone());
                tasks.push(tokio::spawn(async move {
                    while let Some(ev) = ev_rx.recv().await {
                        if let Ok(event) = serde_json::to_value(&ev) {
                            n.send_run(&run, Frame::Msg(Msg::Event { run: run.clone(), event }));
                        }
                    }
                }));
            }
            for _ in 0..50 {
                if es.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }

            let spec = SandboxSpec {
                name: format!("wicket-{}", bs.run.replace('_', "-")),
                image: bs.image.clone(),
                isolation: bs.isolation,
                mounts: vec![
                    Mount { host: sock, target: wicket_agent::SOCK_DIR.into(), read_only: false },
                    Mount { host: dir.join("ca"), target: wicket_agent::CA_DIR.into(), read_only: true },
                    Mount { host: dir.join("state"), target: wicket_agent::STATE_DIR.into(), read_only: false },
                    Mount { host: dir.join("workspace"), target: wicket_agent::WORKSPACE.into(), read_only: false },
                    // wicket's own hosts file, which links add names to (`BoxCtl` "hosts").
                    Mount { host: dir.join("hosts"), target: "/etc/hosts".into(), read_only: true },
                ]
                .into_iter()
                .chain(volume_mounts)
                .collect(),
                env: bs.env.clone(),
                argv: bs.argv.clone(),
                memory: bs.memory.clone(),
                cpus: bs.cpus,
                pids: bs.pids,
                user: ids(),
                workdir: wicket_agent::WORKSPACE.into(),
                interactive: bs.interactive,
                labels: vec![("wicket.run".into(), bs.run.clone()), ("wicket.owner".into(), crate::reap::owner_label())],
            };
            (dir, spec, tasks)
        }
    };
    let name = spec.name.clone();
    let mut child = node.docker.spawn(&spec)?;
    let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    if let Some(mut si) = child.stdin.take() {
        tasks.push(tokio::spawn(async move {
            while let Some(b) = stdin_rx.recv().await {
                if si.write_all(&b).await.is_err() {
                    break;
                }
            }
        }));
    }
    node.boxes.lock().expect("boxes").insert(
        bs.run.clone(),
        BoxState {
            streams: bs.streams,
            name: name.clone(),
            dir: dir.clone(),
            stdin: bs.interactive.then_some(stdin_tx),
            stdin_next: 0,
            out: [OutBuf::new(OUTPUT_CAP), OutBuf::new(OUTPUT_CAP)],
            exited: None,
            tasks,
            user: spec.user.clone(),
            listeners: HashMap::new(),
            owner: Some(gen),
        },
    );
    let readers: Vec<_> = [
        child.stdout.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        child.stderr.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(i, r)| r.map(|r| (i, r)))
    .map(|(i, mut r)| {
        let (n, run) = (node.clone(), bs.run.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            while let Ok(k) = r.read(&mut buf).await {
                if k == 0 {
                    break;
                }
                let frame = {
                    let mut boxes = n.boxes.lock().expect("boxes");
                    let Some(b) = boxes.get_mut(&run) else { break };
                    let at = b.out[i].write(&buf[..k]);
                    Frame::Data { stream: b.streams[i + 1], offset: at, bytes: buf[..k].to_vec() }
                };
                n.send_run(&run, frame);
            }
        })
    })
    .collect();
    // The node enforces the run's timeout itself, connected or not.
    let (n, run, timeout, box_name) = (node.clone(), bs.run.clone(), bs.timeout_secs, name.clone());
    tokio::spawn(async move {
        let deadline = tokio::time::sleep(std::time::Duration::from_secs(timeout.max(1)));
        tokio::pin!(deadline);
        let status = tokio::select! {
            s = child.wait() => s.ok(),
            _ = &mut deadline => {
                eprintln!("[node] {run}: past its timeout; stopping the box");
                let _ = n.docker.unpause(&box_name).await;
                let _ = n.docker.kill(&box_name).await;
                child.wait().await.ok()
            }
        };
        for r in readers {
            let _ = r.await;
        }
        let code = status.and_then(|s| s.code()).unwrap_or(-1);
        let result = crate::hibernate::read_outbox(&dir, 64 * 1024).and_then(|b| String::from_utf8(b).ok());
        if let Some(b) = n.boxes.lock().expect("boxes").get_mut(&run) {
            b.exited = Some((code, result.clone()));
            b.stdin = None;
        }
        eprintln!("[node] {run}: box exited ({code})");
        n.send_run(&run.clone(), Frame::Msg(Msg::Exited { run, code, result }));
    });
    eprintln!("[node] {}: box {name} started", bs.run);
    Ok(())
}

/// A box the control host laid out (a node sharing its filesystem, #146): its mounts as given, in
/// the run's own directory, and its sockets the run's own proxies. Only a node made for that (the
/// built-in local node) takes one.
type Layout = (PathBuf, SandboxSpec, Vec<tokio::task::JoinHandle<()>>);

fn host_layout(node: &Node, bs: &BoxStart, h: &crate::chan::HostBox) -> Result<Layout> {
    if !node.paths.shares_host() {
        bail!("this node doesn't share the control host's filesystem: it lays out its boxes itself");
    }
    let ok_name =
        h.name.len() <= 100 && h.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && h.name.ends_with(&bs.run.replace('_', "-"));
    if !ok_name {
        bail!("bad box name {:?}", h.name);
    }
    let sock = h.mounts.iter().find(|(_, t, _)| t == wicket_agent::SOCK_DIR).map(|(p, _, _)| PathBuf::from(p));
    let dir = sock.and_then(|s| s.parent().map(PathBuf::from)).context("the box has no socket directory")?;
    let spec = SandboxSpec {
        name: h.name.clone(),
        image: bs.image.clone(),
        isolation: bs.isolation,
        mounts: h.mounts.iter().map(|(p, t, ro)| Mount { host: PathBuf::from(p), target: t.clone(), read_only: *ro }).collect(),
        env: bs.env.clone(),
        argv: bs.argv.clone(),
        memory: bs.memory.clone(),
        cpus: bs.cpus,
        pids: bs.pids,
        user: h.user.clone(),
        workdir: h.workdir.clone(),
        interactive: bs.interactive,
        labels: h.labels.clone(),
    };
    Ok((dir, spec, vec![]))
}

/// `wicket node attach`: what the control host runs over ssh. It joins its stdin and stdout to the
/// node's control socket, so the ssh session *is* the control channel.
pub async fn attach(dir: Option<PathBuf>) -> Result<()> {
    let sock = NodePaths::new(dir).socket();
    let s = UnixStream::connect(&sock).await.with_context(|| format!("wicket node serve is not listening on {}", sock.display()))?;
    let (mut rd, mut wr) = s.into_split();
    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut wr).await;
        let _ = wr.shutdown().await;
    });
    let mut out = tokio::io::stdout();
    let _ = tokio::io::copy(&mut rd, &mut out).await;
    let _ = out.flush().await;
    up.abort();
    Ok(())
}

/// `wicket dev node-feed-probe`: connects to a node's control socket as the control host would and
/// sends it its own last freshness statement twice, tampered and then as is, to show both are refused
/// (bad signature, replay). It connects as an observer, so the real control connection stays up.
pub async fn probe_tamper(dir: Option<PathBuf>) -> Result<Vec<String>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    let paths = NodePaths::new(dir);
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(paths.feed().join("statements.json")).context("no statement held yet")?)?;
    let jws = stored["fresh"]["jws"].as_str().or(stored["vouched"]["jws"].as_str()).context("no statement held yet")?.to_string();
    let mut parts: Vec<String> = jws.split('.').map(String::from).collect();
    let mut payload: serde_json::Value = serde_json::from_slice(&B64.decode(&parts[1])?)?;
    payload["fresh_until"] = serde_json::json!(payload["fresh_until"].as_i64().unwrap_or(0) + 3_600_000);
    payload["issued_at"] = serde_json::json!(payload["issued_at"].as_i64().unwrap_or(0) + 1);
    parts[1] = B64.encode(serde_json::to_vec(&payload)?);
    let tampered = parts.join(".");
    let mut s = UnixStream::connect(paths.socket()).await?;
    s.write_all(
        &Frame::Msg(Msg::Hello {
            node: paths.name()?,
            version: env!("CARGO_PKG_VERSION").into(),
            build: build_id()?,
            observer: true,
            nonce: String::new(),
            scope: String::new(),
        })
        .encode(),
    )
    .await?;
    let mut out = vec![];
    for j in [tampered, jws] {
        let line = wicket_feed::Frame::new(wicket_feed::FrameKind::Fresh, j).to_line();
        s.write_all(&Frame::Feed(line.trim_end().as_bytes().to_vec()).encode()).await?;
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(5), chan::read_frame(&mut s)).await {
                Ok(Ok(Some(Frame::Msg(Msg::FeedStatus { refused, mode, .. })))) => {
                    out.push(refused.unwrap_or_else(|| format!("accepted ({mode:?})")));
                    break;
                }
                Ok(Ok(Some(Frame::Msg(Msg::Refused { why })))) => bail!("{why}"),
                Ok(Ok(Some(_))) => continue,
                _ => bail!("no answer from the node"),
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::nodeauth::testkit::Install;
    use crate::nodeauth::HsError;

    fn test_node(i: &Install) -> Arc<Node> {
        let root = wicket_identity::SigningKey::from_bytes(&[3; 32]).verifying_key();
        Arc::new(Node {
            name: "n1".into(),
            paths: NodePaths::new(Some(i.dir.clone())),
            ident: i.identity(),
            build: build_id().unwrap(),
            clock: node_clock(),
            replica: Arc::new(Mutex::new(Replica::new_with("n1", root, ReplicaConfig::default(), wicket_authz::PublicKey([5; 32])))),
            audit: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            root_pem: String::new(),
            docker: Docker::from_env(),
            links: Mutex::new(HashMap::new()),
            boxes: Mutex::new(HashMap::new()),
            asks: Mutex::new(HashMap::new()),
            opens: Mutex::new(HashMap::new()),
            next: AtomicU64::new(0),
            audit_link: Mutex::new(None),
            shipped: AtomicI64::new(-1),
            shipping: Mutex::new(()),
        })
    }

    async fn next_msg(s: &mut UnixStream) -> Frame {
        tokio::time::timeout(std::time::Duration::from_secs(5), chan::read_frame(s)).await.unwrap().unwrap().unwrap()
    }

    fn hello(build: &str) -> impl FnOnce(String) -> Msg + '_ {
        move |nonce| Msg::Hello {
            node: "n1".into(),
            version: "t".into(),
            build: build.into(),
            observer: false,
            nonce,
            scope: String::new(),
        }
    }

    /// A control host's connection, authenticated both ways: the stream, and the result of the
    /// handshake (with the welcome, or why one side refused the other).
    async fn handshake(
        node: &Arc<Node>,
        gen: u64,
        build: &str,
        i: &Install,
        issuer: &wicket_identity::Issuer,
    ) -> (UnixStream, Result<Msg, HsError>) {
        let (mut a, b) = UnixStream::pair().unwrap();
        tokio::spawn(connection(node.clone(), b, gen));
        let (mut rd, mut wr) = a.split();
        let r = crate::nodeauth::control(&mut rd, &mut wr, "n1", &i.ledger, issuer, hello(build)).await.map(|a| a.welcome);
        (a, r)
    }

    /// A control connection for one run (its scope), as `wicket run` makes.
    async fn connect_run(node: &Arc<Node>, gen: u64, i: &Install, run: &str) -> UnixStream {
        let (mut a, b) = UnixStream::pair().unwrap();
        tokio::spawn(connection(node.clone(), b, gen));
        let (mut rd, mut wr) = a.split();
        let build = node.build.clone();
        let hello = move |nonce| Msg::Hello { node: "n1".into(), version: "t".into(), build, observer: false, nonce, scope: run.into() };
        let r = crate::nodeauth::control(&mut rd, &mut wr, "n1", &i.ledger, &i.issuer, hello).await.map(|a| a.welcome);
        assert!(matches!(r, Ok(Msg::Welcome { .. })), "{:?}", r.err());
        a
    }

    async fn connect(node: &Arc<Node>, gen: u64, i: &Install) -> UnixStream {
        let (a, r) = handshake(node, gen, &node.build, i, &i.issuer).await;
        assert!(matches!(r, Ok(Msg::Welcome { .. })), "{:?}", r.err());
        a
    }

    /// The node's id state for a connection that never finished the handshake.
    async fn wait_link(node: &Node, gen: Option<u64>) {
        for _ in 0..100 {
            let ok = {
                let links = node.links.lock().unwrap();
                links.keys().copied().max() == gen && links.len() <= 1
            };
            if ok {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("link is not {gen:?}");
    }

    /// Writes box output as the stdout reader task does.
    fn box_output(node: &Node, bytes: &[u8]) {
        let f = {
            let mut boxes = node.boxes.lock().unwrap();
            let b = boxes.get_mut("run_a").unwrap();
            let at = b.out[0].write(bytes);
            Frame::Data { stream: b.streams[1], offset: at, bytes: bytes.to_vec() }
        };
        node.send_run("run_a", f);
    }

    #[tokio::test]
    async fn a_reconnecting_control_host_gets_the_output_it_missed_and_its_stdin_is_not_doubled() {
        let inst = Install::new("nodesrv-reconnect");
        let dir = inst.dir.clone();
        let node = test_node(&inst);
        let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel();
        node.boxes.lock().unwrap().insert(
            "run_a".into(),
            BoxState {
                streams: [1, 2, 3],
                name: "wicket-run-a".into(),
                dir: dir.join("runs/run_a"),
                stdin: Some(stdin_tx),
                stdin_next: 0,
                out: [OutBuf::new(OUTPUT_CAP), OutBuf::new(OUTPUT_CAP)],
                exited: None,
                tasks: vec![],
                user: String::new(),
                listeners: HashMap::new(),
                owner: Some(2),
            },
        );
        // Another build is refused.
        let (_, r) = handshake(&node, 1, "not-this-build", &inst, &inst.issuer).await;
        assert!(matches!(r, Err(HsError::Refused(why)) if why.contains("wicket node install n1")));

        // Connected: output flows, and is acknowledged.
        let (mut c, r) = handshake(&node, 2, &node.build, &inst, &inst.issuer).await;
        assert!(matches!(r, Ok(Msg::Welcome { runs, .. }) if runs[0].stdout_total == 0));
        box_output(&node, b"hello\n");
        assert_eq!(next_msg(&mut c).await, Frame::Data { stream: 2, offset: 0, bytes: b"hello\n".to_vec() });
        c.write_all(&Frame::Msg(Msg::Ack { stream: 2, upto: 6 }).encode()).await.unwrap();
        // Stdin, with a resent overlap: the box gets each byte once.
        for (off, b) in [(0, &b"ab"[..]), (1, &b"bc"[..])] {
            c.write_all(&Frame::Data { stream: 1, offset: off, bytes: b.to_vec() }.encode()).await.unwrap();
        }
        assert_eq!(stdin_rx.recv().await.unwrap(), b"ab");
        assert_eq!(stdin_rx.recv().await.unwrap(), b"c");

        // The channel drops; the box keeps writing.
        drop(c);
        for _ in 0..100 {
            if !node.connected() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!node.connected());
        box_output(&node, b"while you were away\n");
        assert_eq!(node.boxes.lock().unwrap()["run_a"].out[0].start(), 6, "acknowledged output was dropped");

        // Reconnect: the welcome says how far stdin and stdout got; a resume replays what was missed.
        let (mut c, r) = handshake(&node, 3, &node.build, &inst, &inst.issuer).await;
        match r {
            Ok(Msg::Welcome { runs, .. }) => {
                assert_eq!((runs[0].stdin_received, runs[0].stdout_total), (3, 26));
            }
            other => panic!("{:?}", other.err()),
        }
        c.write_all(&Frame::Msg(Msg::Resume { run: "run_a".into(), stdout_from: 6, stderr_from: 0 }).encode()).await.unwrap();
        assert_eq!(next_msg(&mut c).await, Frame::Data { stream: 2, offset: 6, bytes: b"while you were away\n".to_vec() });
        // A newer connection replaces this one.
        let _c2 = connect(&node, 4, &inst).await;
        assert!(tokio::time::timeout(std::time::Duration::from_secs(5), chan::read_frame(&mut c)).await.unwrap().unwrap().is_none());
    }

    /// Done-when for #16: a node with an unexpected certificate is refused (wrong installation, wrong
    /// key, expired, unrecorded, revoked), and so is a control host that isn't this installation's.
    /// A refused or unfinished handshake never takes the link from the authenticated connection.
    #[tokio::test]
    async fn both_ends_refuse_an_unexpected_identity_and_impostors_never_take_the_link() {
        let inst = Install::new("nodesrv-auth");
        let node = test_node(&inst);
        let cert_path = inst.dir.join(crate::nodeauth::CERT_FILE);
        let good = std::fs::read_to_string(&cert_path).unwrap();
        let mut real = connect(&node, 1, &inst).await;
        wait_link(&node, Some(1)).await;
        let refused = |r: Result<Msg, HsError>| match r {
            Err(HsError::Refused(why)) => why,
            other => panic!("not refused: {:?}", other.ok()),
        };

        // A control host with another installation's issuer: it can't verify this node's certificate
        // (so it refuses the node), and the node never sees a proof it accepts.
        let impostor = wicket_identity::Issuer::generate("test.wicket.example");
        let why = refused(handshake(&node, 2, &node.build, &inst, &impostor).await.1);
        assert!(why.contains("not signed by this installation"), "{why}");
        // One that skips checking the node and just signs with its own key: the node refuses it.
        let (mut a, b) = UnixStream::pair().unwrap();
        tokio::spawn(connection(node.clone(), b, 3));
        let mut hs = wicket_identity::node::ControlHandshake::new("n1", b"");
        a.write_all(&Frame::Msg(hello(&node.build)(hs.nonce().into())).encode()).await.unwrap();
        let Frame::Msg(Msg::Challenge { proof }) = next_msg(&mut a).await else { panic!("no challenge") };
        hs.verify_node(&proof, &inst.issuer.verifying_key(), &inst.key.verifying_key(), wicket_store::now()).unwrap();
        a.write_all(&Frame::Msg(Msg::Prove { proof: hs.prove(&impostor).unwrap() }).encode()).await.unwrap();
        assert!(matches!(next_msg(&mut a).await, Frame::Msg(Msg::Refused { why }) if why.contains("issuer key")));
        // A peer that says hello and then nothing useful.
        let (mut a, b) = UnixStream::pair().unwrap();
        tokio::spawn(connection(node.clone(), b, 4));
        a.write_all(&Frame::Msg(hello(&node.build)(wicket_identity::node::nonce())).encode()).await.unwrap();
        let _ = next_msg(&mut a).await;
        a.write_all(&Frame::Msg(Msg::Kill { run: "run_a".into() }).encode()).await.unwrap();
        assert!(matches!(next_msg(&mut a).await, Frame::Msg(Msg::Refused { .. })));
        wait_link(&node, Some(1)).await;

        // The node's certificate from another installation (same key and name).
        let (foreign, _) = impostor.issue_node_cert("n1", &inst.key.verifying_key(), wicket_store::now(), 3600);
        std::fs::write(&cert_path, &foreign).unwrap();
        let why = refused(handshake(&node, 5, &node.build, &inst, &inst.issuer).await.1);
        assert!(why.contains("not signed by this installation"), "{why}");
        // Expired (by the control host's clock).
        let (expired, _) = inst.issuer.issue_node_cert("n1", &inst.key.verifying_key(), wicket_store::now() - 7200, 3600);
        std::fs::write(&cert_path, &expired).unwrap();
        let why = refused(handshake(&node, 6, &node.build, &inst, &inst.issuer).await.1);
        assert!(why.contains("expired"), "{why}");
        // Signed by this issuer, but never recorded (not issued through enrolment or renewal).
        let (unrecorded, _) = inst.issuer.issue_node_cert("n1", &inst.key.verifying_key(), wicket_store::now(), 3600);
        std::fs::write(&cert_path, &unrecorded).unwrap();
        let why = refused(handshake(&node, 7, &node.build, &inst, &inst.issuer).await.1);
        assert!(why.contains("never recorded"), "{why}");
        // No certificate at all.
        std::fs::remove_file(&cert_path).unwrap();
        let why = refused(handshake(&node, 8, &node.build, &inst, &inst.issuer).await.1);
        assert!(why.contains("no identity certificate"), "{why}");
        // A node whose key isn't the enrolled one (re-keyed or replaced), with a certificate for it.
        let other = wicket_identity::SigningKey::generate(&mut rand_core::OsRng);
        let (theirs, _) = inst.issuer.issue_node_cert("n1", &other.verifying_key(), wicket_store::now(), 3600);
        std::fs::write(&cert_path, &theirs).unwrap();
        let why = refused(handshake(&node, 9, &node.build, &inst, &inst.issuer).await.1);
        assert!(why.contains("enrolled key"), "{why}");
        // Through all of that, the authenticated connection kept the link.
        wait_link(&node, Some(1)).await;
        real.write_all(&Frame::Msg(Msg::AuditFrom { seq: 0 }).encode()).await.unwrap();

        // Renewal over the channel: the node checks the certificate and swaps it in.
        std::fs::write(&cert_path, &good).unwrap();
        let (renewed, rc) =
            crate::nodeauth::issue(&inst.ledger.lock().unwrap(), &inst.issuer, "n1", &inst.key.verifying_key(), wicket_store::now(), 3600)
                .unwrap();
        real.write_all(&Frame::Msg(Msg::NodeCert { cert: renewed.clone() }).encode()).await.unwrap();
        loop {
            match next_msg(&mut real).await {
                Frame::Msg(Msg::NodeCertInstalled { serial, error }) => {
                    assert_eq!((serial, error), (rc.jti.clone(), None));
                    break;
                }
                _ => continue,
            }
        }
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap().trim(), renewed);
        real.write_all(&Frame::Msg(Msg::NodeCert { cert: theirs.clone() }).encode()).await.unwrap();
        loop {
            match next_msg(&mut real).await {
                Frame::Msg(Msg::NodeCertInstalled { error, .. }) => {
                    assert!(error.unwrap().contains("another key"));
                    break;
                }
                _ => continue,
            }
        }
        // The renewed certificate authenticates the next connection; the earlier one still would.
        let _c = connect(&node, 10, &inst).await;
        std::fs::write(&cert_path, &good).unwrap();
        let _c = connect(&node, 11, &inst).await;

        // Revoked: refused at once, whatever certificate it holds.
        inst.ledger.lock().unwrap().revoke_node("n1").unwrap();
        let why = refused(handshake(&node, 12, &node.build, &inst, &inst.issuer).await.1);
        assert!(why.contains("revoked"), "{why}");
    }

    /// #146: one node serves many runs at once, each over its own control connection. A box's
    /// output goes to the connection that owns it, stdin from another run's connection doesn't reach
    /// it, and a run reconnecting replaces only its own older connection.
    #[tokio::test]
    async fn runs_on_one_node_each_keep_their_own_connection() {
        let inst = Install::new("nodesrv-many");
        let node = test_node(&inst);
        let mut stdins = HashMap::new();
        for (run, gen) in [("run_a", 1), ("run_b", 2)] {
            let (tx, rx) = mpsc::unbounded_channel();
            stdins.insert(run, rx);
            node.boxes.lock().unwrap().insert(
                run.into(),
                BoxState {
                    streams: [1, 2, 3],
                    name: format!("wicket-{run}"),
                    dir: inst.dir.join("runs").join(run),
                    stdin: Some(tx),
                    stdin_next: 0,
                    out: [OutBuf::new(OUTPUT_CAP), OutBuf::new(OUTPUT_CAP)],
                    exited: None,
                    tasks: vec![],
                    user: String::new(),
                    listeners: HashMap::new(),
                    owner: Some(gen),
                },
            );
        }
        let mut a = connect_run(&node, 1, &inst, "run_a").await;
        let mut b = connect_run(&node, 2, &inst, "run_b").await;
        let out = |run: &str, bytes: &[u8]| {
            let f = {
                let mut boxes = node.boxes.lock().unwrap();
                let bx = boxes.get_mut(run).unwrap();
                let at = bx.out[0].write(bytes);
                Frame::Data { stream: bx.streams[1], offset: at, bytes: bytes.to_vec() }
            };
            node.send_run(run, f)
        };
        assert!(out("run_a", b"for a\n"));
        assert!(out("run_b", b"for b\n"));
        assert_eq!(next_msg(&mut a).await, Frame::Data { stream: 2, offset: 0, bytes: b"for a\n".to_vec() });
        assert_eq!(next_msg(&mut b).await, Frame::Data { stream: 2, offset: 0, bytes: b"for b\n".to_vec() });
        // The same stream ids on two connections: each reaches its own box only.
        a.write_all(&Frame::Data { stream: 1, offset: 0, bytes: b"x".to_vec() }.encode()).await.unwrap();
        assert_eq!(stdins.get_mut("run_a").unwrap().recv().await.unwrap(), b"x");
        assert!(stdins.get_mut("run_b").unwrap().try_recv().is_err());
        // run_b reconnects: its old connection ends, run_a's stays.
        let _b2 = connect_run(&node, 3, &inst, "run_b").await;
        assert!(tokio::time::timeout(std::time::Duration::from_secs(5), chan::read_frame(&mut b)).await.unwrap().unwrap().is_none());
        assert!(out("run_a", b"still a\n"));
        assert_eq!(next_msg(&mut a).await, Frame::Data { stream: 2, offset: 6, bytes: b"still a\n".to_vec() });
        // Until it resumes, run_b's output waits on the node.
        assert!(!out("run_b", b"later\n"));
    }
}
