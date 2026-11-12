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

/// The running binary's sha256: control host and node must run the same build.
pub fn build_id() -> Result<String> {
    use sha2::Digest;
    let exe = std::env::current_exe().context("finding this binary")?;
    Ok(hex::encode(sha2::Sha256::digest(std::fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?)))
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
}

struct Link {
    out: chan::Out,
    gen: u64,
    /// Ends the connection's reader (a newer connection took over).
    kill: Option<oneshot::Sender<()>>,
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
    link: Mutex<Option<Link>>,
    boxes: Mutex<HashMap<String, BoxState>>,
    asks: Mutex<HashMap<u64, oneshot::Sender<Msg>>>,
    opens: Mutex<HashMap<u64, oneshot::Sender<Option<String>>>>,
    tunnels: Tunnels,
    next: AtomicU64,
    shipped: AtomicI64,
    /// One audit shipment at a time (the timer and a reconnect's watermark would send the same batch).
    shipping: Mutex<()>,
}

impl Node {
    fn send(&self, f: Frame) -> bool {
        self.link.lock().expect("link").as_ref().is_some_and(|l| l.out.send(f).is_ok())
    }

    fn connected(&self) -> bool {
        self.link.lock().expect("link").is_some()
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
        let out = self.link.lock().expect("link").as_ref().map(|l| l.out.clone()).ok_or_else(unreachable)?;
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
        self.tunnels.attach(id, theirs, out);
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
        if from < 0 || !self.connected() {
            return;
        }
        let recs = self.audit.lock().expect("audit").audit_records_after(from, 500).unwrap_or_default();
        if let Some(last) = recs.last().map(|r| r.seq) {
            if self.send(Frame::Msg(Msg::Audit { records: recs })) {
                self.shipped.store(last, Ordering::SeqCst);
            }
        }
    }
}

/// The decider's way to the control host.
struct Control(Arc<Node>, String);

impl ControlLink for Control {
    fn connected(&self) -> bool {
        self.0.connected()
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
            let sent =
                self.0.send(Frame::Msg(Msg::Ask { id, run: self.1.clone(), op: Box::new(op.clone()), why: why.into(), who: who.cloned() }));
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

pub async fn serve(dir: Option<PathBuf>) -> Result<()> {
    let paths = NodePaths::new(dir);
    let name = paths.name()?;
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
        link: Mutex::new(None),
        boxes: Mutex::new(HashMap::new()),
        asks: Mutex::new(HashMap::new()),
        opens: Mutex::new(HashMap::new()),
        tunnels: Tunnels::default(),
        next: AtomicU64::new(0),
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
    let refuse = |why: String| Frame::Msg(Msg::Refused { why }).encode();
    let observer = match hello {
        Some(Frame::Msg(Msg::Hello { node: n, build, version, observer, nonce })) => {
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
            observer
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
    {
        let mut l = node.link.lock().expect("link");
        if let Some(mut old) = l.take() {
            if let Some(k) = old.kill.take() {
                let _ = k.send(());
            }
        }
        *l = Some(Link { out: tx.clone(), gen, kill: Some(kill_tx) });
    }
    node.tunnels.clear();
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
    eprintln!("[node] control host connected");
    let result = loop {
        tokio::select! {
            _ = &mut kill_rx => break Ok(()),
            f = chan::read_frame(&mut rd) => match f {
                Ok(Some(f)) => {
                    if let Err(e) = handle(&node, f).await {
                        break Err(e);
                    }
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e.into()),
            }
        }
    };
    {
        let mut l = node.link.lock().expect("link");
        if l.as_ref().is_some_and(|l| l.gen == gen) {
            *l = None;
            node.tunnels.clear();
            node.asks.lock().expect("asks").clear();
            node.opens.lock().expect("opens").clear();
            node.shipped.store(-1, Ordering::SeqCst);
            eprintln!("[node] control host disconnected; boxes keep running on the feed held");
        }
    }
    writer.abort();
    result
}

async fn handle(node: &Arc<Node>, f: Frame) -> Result<()> {
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
            node.send(node.feed_status(r.as_ref().err()));
        }
        Frame::Data { stream, offset, bytes } if stream & TUNNEL_BIT != 0 => {
            node.tunnels.data(stream, bytes);
            let _ = offset;
        }
        Frame::Data { stream, offset, bytes } => {
            let mut boxes = node.boxes.lock().expect("boxes");
            if let Some(b) = boxes.values_mut().find(|b| b.streams[0] == stream) {
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
                    let error = start_box(&n, *bs).await.err().map(|e| format!("{e:#}"));
                    if let Some(e) = &error {
                        eprintln!("[node] starting {run} failed: {e}");
                    }
                    n.send(Frame::Msg(Msg::Started { run, error }));
                });
            }
            Msg::Resume { run, stdout_from, stderr_from } => {
                let (frames, exited) = {
                    let boxes = node.boxes.lock().expect("boxes");
                    let Some(b) = boxes.get(&run) else { return Ok(()) };
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
                    node.send(f);
                }
                if let Some((code, result)) = exited {
                    node.send(Frame::Msg(Msg::Exited { run, code, result }));
                }
            }
            Msg::Ack { stream, upto } => {
                let mut boxes = node.boxes.lock().expect("boxes");
                for b in boxes.values_mut() {
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
                    let _ = node.docker.kill(&name).await;
                }
            }
            Msg::Forget { run } => {
                let b = node.boxes.lock().expect("boxes").remove(&run);
                if let Some(b) = b {
                    b.tasks.iter().for_each(|t| t.abort());
                    let _ = std::fs::remove_dir_all(&b.dir);
                }
            }
            m @ Msg::Asked { .. } => {
                let Msg::Asked { id, .. } = &m else { unreachable!() };
                if let Some(tx) = node.asks.lock().expect("asks").remove(id) {
                    let _ = tx.send(m);
                }
            }
            Msg::AuditFrom { seq } => {
                node.shipped.store(seq, Ordering::SeqCst);
                node.ship_audit();
            }
            Msg::TunnelOpened { stream, error } => {
                if let Some(tx) = node.opens.lock().expect("opens").remove(&stream) {
                    let _ = tx.send(error);
                }
            }
            Msg::Close { stream } => node.tunnels.close(stream),
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
                node.send(Frame::Msg(Msg::NodeCertInstalled { serial, error }));
            }
            other => bail!("unexpected message from the control host: {other:?}"),
        },
    }
    Ok(())
}

fn ids() -> String {
    // SAFETY: getuid and getgid can't fail.
    unsafe { format!("{}:{}", libc::getuid(), libc::getgid()) }
}

async fn start_box(node: &Arc<Node>, bs: BoxStart) -> Result<()> {
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
    let dir = node.paths.runs().join(&bs.run);
    for sub in ["sock", "ca", "state/home", "state/claude", "workspace/out"] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(dir.join("ca/ca.pem"), format!("{}{}", node.root_pem, bs.ca_pem))?;
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
    let sock = dir.join("sock");
    let mut tasks = vec![];
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
                    n.send(Frame::Msg(Msg::Event { run: run.clone(), event }));
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

    let name = format!("wicket-{}", bs.run.replace('_', "-"));
    let spec = SandboxSpec {
        name: name.clone(),
        image: bs.image.clone(),
        isolation: bs.isolation,
        mounts: vec![
            Mount { host: sock, target: wicket_agent::SOCK_DIR.into(), read_only: false },
            Mount { host: dir.join("ca"), target: wicket_agent::CA_DIR.into(), read_only: true },
            Mount { host: dir.join("state"), target: wicket_agent::STATE_DIR.into(), read_only: false },
            Mount { host: dir.join("workspace"), target: wicket_agent::WORKSPACE.into(), read_only: false },
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
                n.send(frame);
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
                let _ = n.docker.kill(&box_name).await;
                child.wait().await.ok()
            }
        };
        for r in readers {
            let _ = r.await;
        }
        let code = status.and_then(|s| s.code()).unwrap_or(-1);
        let result = std::fs::read(dir.join("workspace/out/result.json"))
            .ok()
            .filter(|b| b.len() <= 64 * 1024)
            .and_then(|b| String::from_utf8(b).ok());
        if let Some(b) = n.boxes.lock().expect("boxes").get_mut(&run) {
            b.exited = Some((code, result.clone()));
            b.stdin = None;
        }
        eprintln!("[node] {run}: box exited ({code})");
        n.send(Frame::Msg(Msg::Exited { run, code, result }));
    });
    eprintln!("[node] {}: box {name} started", bs.run);
    Ok(())
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
            link: Mutex::new(None),
            boxes: Mutex::new(HashMap::new()),
            asks: Mutex::new(HashMap::new()),
            opens: Mutex::new(HashMap::new()),
            tunnels: Tunnels::default(),
            next: AtomicU64::new(0),
            shipped: AtomicI64::new(-1),
            shipping: Mutex::new(()),
        })
    }

    async fn next_msg(s: &mut UnixStream) -> Frame {
        tokio::time::timeout(std::time::Duration::from_secs(5), chan::read_frame(s)).await.unwrap().unwrap().unwrap()
    }

    fn hello(build: &str) -> impl FnOnce(String) -> Msg + '_ {
        move |nonce| Msg::Hello { node: "n1".into(), version: "t".into(), build: build.into(), observer: false, nonce }
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

    async fn connect(node: &Arc<Node>, gen: u64, i: &Install) -> UnixStream {
        let (a, r) = handshake(node, gen, &node.build, i, &i.issuer).await;
        assert!(matches!(r, Ok(Msg::Welcome { .. })), "{:?}", r.err());
        a
    }

    /// The node's id state for a connection that never finished the handshake.
    async fn wait_link(node: &Node, gen: Option<u64>) {
        for _ in 0..100 {
            if node.link.lock().unwrap().as_ref().map(|l| l.gen) == gen {
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
        node.send(f);
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
}
