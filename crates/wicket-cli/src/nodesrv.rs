//! `wicket node serve` (#57, step 3): the node process that owns its boxes and decides their egress
//! locally, so a box keeps working (for allowed requests) while the control host is unreachable.
//!
//! - **It owns the box.** The control host asks it to start a box ([`Msg::Start`]); it starts it
//!   detached (`docker run -d`) and relays its stdin (over the box's `sock/stdin.sock`, which
//!   `wicket-fwd --stdin-from` reads), stdout and stderr (from `docker logs`) over the control channel.
//!   When the channel drops, the box keeps running and its output is kept (up to [`OUTPUT_CAP`] bytes
//!   per stream, oldest dropped first; the control host reports a gap) and replayed when the control
//!   host reconnects. The node also enforces the run's timeout itself, and stops the box when its
//!   authority (its token's block 0) expires, connected or not (#153).
//! - **Its boxes outlive it** (#151). A record of each box (`node-box.json`) lets a restarted `serve`
//!   adopt the boxes the last one started (`adopt_previous`).
//! - **It decides egress.** Each box gets its own egress proxy on a unix socket, deciding from the
//!   node's verified feed replica (`wicket_proxy::decide::NodeDecider`) and terminating TLS with the
//!   node's name-constrained CA. Hosts the node must not terminate (an `inject` rule, a credential
//!   swap, outside the CA's constraints, or an expired CA) are tunnelled to the control host's egress
//!   proxy for the run.
//! - **It runs the box's model proxy and MCP gateway** (#151). The model proxy checks each call and
//!   relays it to the run's own on the control host, which holds the credential and checks it again;
//!   the gateway relays each call to the run's, which decides every tool, and answers MCP's own
//!   handshake itself while the control host can't be reached.
//! - **It keeps an audit log.** A ledger of its own (`audit.db`), hash-chained like the control host's,
//!   records its decisions; it ships records past the control host's watermark on every connect.
//! - **One control connection per run** (its scope; #146), on a unix socket in a 0700 directory,
//!   reached over ssh (`wicket node attach`), or directly by this host's own node's control host. A
//!   box's stdio, events, asks and tunnels go to the connection that started or last resumed it. A
//!   newer connection with the same scope replaces the older one, but only once it has proved this
//!   installation's issuer key and accepted the node's certificate (`nodeauth.rs`). The control
//!   host's protocol version must be within [`chan::PROTOCOL_SKEW`] of this node's (#162; any build
//!   that speaks it will do, so the two can be updated one at a time).
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
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use wicket_feed::{BoxAuthority, Replica, ReplicaConfig};
use wicket_proxy::ca::{Minter, NodeCa};
use wicket_proxy::decide::{Asked, Clock, ControlLink, NodeDecider, Route};
use wicket_proxy::egress::{Egress, Relay, RelayStream};
use wicket_sandbox::{Docker, Mount, SandboxSpec};
use wicket_store::Ledger;

mod conn;
mod gateway;
#[path = "nodegw.rs"]
mod gw;
mod images;
mod links;
use conn::*;
use gateway::*;
use links::*;

/// Output kept per stream (stdout, stderr) while the control host is unreachable.
pub const OUTPUT_CAP: usize = 4 << 20;

/// The node's files: what enrolment installed, and what `serve` keeps.
pub struct NodePaths {
    pub root: PathBuf,
    /// For the control host's own node (#146): the control host's data directory, which this node
    /// shares (`node.json`'s `shares_host`). Its boxes live in the runs' own directories there.
    shared: Option<PathBuf>,
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
        let root = root.unwrap_or_else(NodePaths::default_root);
        let info = std::fs::read(root.join("node.json")).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
        let shared =
            info.filter(|v| v["shares_host"] == serde_json::Value::Bool(true)).and_then(|v| v["data_dir"].as_str().map(PathBuf::from));
        NodePaths { root, shared }
    }
    pub fn socket(&self) -> PathBuf {
        self.root.join("ctl/ctl.sock")
    }
    /// Whether this node shares the control host's filesystem (the built-in local node, #146):
    /// `node.json` says `"shares_host": true`, which only the control host writes, for its own node.
    pub fn shares_host(&self) -> bool {
        self.shared.is_some()
    }
    /// Where zone volumes are kept: the control host's own for its own node, so they outlive a build.
    fn volumes(&self) -> PathBuf {
        match &self.shared {
            Some(d) => d.join("volumes"),
            None => self.root.join("volumes"),
        }
    }
    fn feed(&self) -> PathBuf {
        self.root.join("feed")
    }
    /// Where boxes are laid out: for the control host's own node, the runs' own directories (the
    /// control host's), so their files needn't move between the two.
    fn runs(&self) -> PathBuf {
        match &self.shared {
            Some(d) => d.join("runs"),
            None => self.root.join("runs"),
        }
    }
    pub fn name(&self) -> Result<String> {
        let info: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.root.join("node.json"))
                .with_context(|| format!("{} (is this node enrolled?)", self.root.join("node.json").display()))?,
        )?;
        info["name"].as_str().map(String::from).context("node.json has no name")
    }
}

/// The running binary's sha256: what `wicket self` names versions by, and what the channel's hello
/// reports (for the logs). Hashed once per process (a release binary is large, and every run
/// connects to a node).
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
    stdin: Option<Arc<StdinFeed>>,
    stdin_next: u64,
    out: [OutBuf; 2],
    exited: Option<(i32, Option<String>)>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// uid:gid the box runs as (execs in it run as this, unless asked otherwise).
    user: String,
    /// Its limits, for the node's reported use.
    cpus: f32,
    memory_mib: u64,
    /// Link relay sockets listened on in its socket directory, by name.
    listeners: HashMap<String, tokio::task::JoinHandle<()>>,
    /// What a restarted `serve` adopts it from.
    record: BoxRecord,
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
    /// The protocol version it talks ([`chan::negotiate`]): a message newer than this isn't sent on it.
    #[allow(dead_code)]
    proto: u32,
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
    /// The secrets this node's runs have used, in memory only (#152), and their budget slices.
    secrets: Arc<crate::nodesecrets::Cache>,
    slices: crate::nodesecrets::Slices,
    /// Asks raised while a run's control host was unreachable (#153), and the resent ones awaiting
    /// an answer (by message id).
    queue: crate::nodesecrets::Asks,
    requeued: Mutex<HashMap<u64, String>>,
    /// Gateway tool calls queued while a run's control host was unreachable, and queued asks it has
    /// since raised (#164).
    edge: gw::EdgeQueue,
    /// Why this node stopped a box itself, by run (#153), for its exit.
    stopped: Mutex<HashMap<String, String>>,
    /// Why each box that has exited ended (#185), for its exit (and a resumed connection's).
    causes: Mutex<HashMap<String, String>>,
    /// Each running box's cgroup, memory as sampled, and whether its agent was warned (#185).
    mem: Mutex<HashMap<String, BoxMem>>,
    /// Each box's model proxy, for its budget slice and spend reports (#152).
    llms: Mutex<HashMap<String, Arc<wicket_proxy::llm::Llm>>>,
    /// Images being received (#191), by stream.
    images: images::Incoming,
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

    /// This machine's size, and what its running boxes are given.
    fn capacity(&self) -> chan::NodeCapacity {
        let mem = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("MemTotal:")).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok()))
            .unwrap_or(0)
            >> 10;
        let mut c = chan::NodeCapacity {
            vcpus: std::thread::available_parallelism().map(|n| n.get() as f32).unwrap_or(1.0),
            memory_mib: mem,
            ..Default::default()
        };
        for b in self.boxes.lock().expect("boxes").values().filter(|b| b.exited.is_none()) {
            c.used_vcpus += b.cpus;
            c.used_memory_mib += b.memory_mib;
            c.boxes += 1;
        }
        c
    }

    /// What this node decides `run`'s gateway tools from (#164): None, they are all relayed (a
    /// control host before protocol 5 started it, or one of those is connected now).
    fn edge_start(&self, run: &str) -> Option<chan::EdgeStart> {
        let e = self.boxes.lock().expect("boxes").get(run).and_then(|b| b.record.start.edge.clone())?;
        match self.proto_of(run) {
            p if (1..chan::EDGE_DECISIONS).contains(&p) => None,
            _ => Some(*e),
        }
    }

    /// The tenant `run`'s box runs for, and the zone its token holds.
    fn tenant_zone(&self, run: &str) -> Option<(wicket_core::TenantId, String)> {
        let tenant = self.boxes.lock().expect("boxes").get(run).map(|b| b.record.start.tenant.clone())?;
        let zone = self.replica.lock().expect("replica").zone_of(run).map(|z| z.name.clone())?;
        Some((wicket_core::TenantId(tenant), zone))
    }

    /// Asks `run`'s control host to raise (or find) the pending request for `op`; `prefix`: for
    /// every path under its directory (an agent asking ahead, #164).
    async fn ask_control(
        &self,
        run: &str,
        op: &wicket_core::Op,
        why: &str,
        who: Option<&serde_json::Value>,
        prefix: bool,
    ) -> std::result::Result<Asked, String> {
        let id = self.id();
        let (tx, rx) = oneshot::channel();
        self.asks.lock().expect("asks").insert(id, tx);
        let ask = Msg::Ask { id, run: run.into(), op: Box::new(op.clone()), why: why.into(), who: who.cloned(), queued: None, prefix };
        let reply = match self.send_run(run, Frame::Msg(ask)) {
            true => tokio::time::timeout(std::time::Duration::from_secs(10), rx).await.ok().and_then(|r| r.ok()),
            false => None,
        };
        self.asks.lock().expect("asks").remove(&id);
        match reply {
            Some(Msg::Asked { pending: Some((request, fresh)), .. }) => Ok(Asked::Pending { request, fresh }),
            Some(Msg::Asked { denied: Some(request), .. }) => Ok(Asked::Denied { request }),
            Some(Msg::Asked { error: Some(e), .. }) => Err(e),
            _ => Err(NO_ANSWER.into()),
        }
    }

    /// The protocol version of the connection that owns `run`'s box (0: none up).
    fn proto_of(&self, run: &str) -> u32 {
        let Some(g) = self.owner(run) else { return 0 };
        self.links.lock().expect("links").get(&g).map_or(0, |l| l.proto)
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
        let loaded = if self.paths.shares_host() { NodeCa::load_any(&cert, &key) } else { NodeCa::load(&cert, &key) };
        match loaded {
            Ok(c) => Some(Arc::new(c)),
            Err(e) => {
                eprintln!("[node] the node CA is unusable ({e:#}); every host is forwarded to the control host");
                None
            }
        }
    }

    /// Opens a tunnel to the run's `target` socket on the control host: over the control channel, or
    /// for the control host's own node, the socket itself (the run's `ctl/` directory, on this host).
    async fn open_tunnel(self: &Arc<Self>, run: &str, target: &str) -> std::io::Result<Box<dyn RelayStream>> {
        if self.paths.shares_host() && ["egress", "llm", "gateway"].contains(&target) {
            crate::run::check_run_id(run).map_err(std::io::Error::other)?;
            let s = UnixStream::connect(self.paths.runs().join(run).join("ctl").join(format!("{target}.sock"))).await?;
            return Ok(Box::new(s));
        }
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
        Ok(Box::new(ours))
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

    /// How this node fetches a secret for a run (#152): over the run's own connection, when it is
    /// up; else it fails clearly, and the miss is audited.
    fn fetcher(self: &Arc<Self>) -> crate::nodesecrets::Fetcher {
        let n = self.clone();
        Arc::new(move |run: String, name: String| {
            let n = n.clone();
            Box::pin(async move {
                // A control host before protocol 3 doesn't release secrets: its node relays instead.
                if (1..chan::NODE_LEASES).contains(&n.proto_of(&run)) {
                    return Err(format!("{OLD_CONTROL}: credential {name} stays on the control host"));
                }
                let id = n.id();
                let (tx, rx) = oneshot::channel();
                n.asks.lock().expect("asks").insert(id, tx);
                let sent = n.send_run(&run, Frame::Msg(Msg::SecretFetch { id, run: run.clone(), name: name.clone() }));
                let reply = match sent {
                    true => tokio::time::timeout(std::time::Duration::from_secs(10), rx).await.ok().and_then(|r| r.ok()),
                    false => None,
                };
                n.asks.lock().expect("asks").remove(&id);
                let why = match reply {
                    Some(Msg::SecretFetched { secret: Some(f), .. }) => {
                        n.audit_note(&run, "node.secret_fetched", serde_json::json!({ "secret": name }));
                        return Ok(*f);
                    }
                    Some(Msg::SecretFetched { error: Some(e), .. }) => format!("credential {name} refused by the control host: {e}"),
                    _ => format!("credential {name} not cached on this node; control host unreachable"),
                };
                n.audit_note(&run, "node.secret_unavailable", serde_json::json!({ "secret": name, "why": why }));
                Err(why)
            })
        })
    }

    /// Records `kind` for `run`'s box in this node's audit log (under the box's tenant), and ships it.
    fn audit_note(&self, run: &str, kind: &str, body: serde_json::Value) {
        let tenant = self.boxes.lock().expect("boxes").get(run).map(|b| b.record.start.tenant.clone());
        let tenant = tenant.map(wicket_core::TenantId).unwrap_or_else(wicket_core::TenantId::single);
        let _ = self.audit.lock().expect("audit").audit(&tenant, Some(&wicket_core::RunId(run.to_string())), kind, &body);
        self.ship_audit();
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
        Box::pin(self.0.ask_control(&self.1, op, why, who, false))
    }

    /// Queued on this node's disk (#153) and raised, with its original time, when the run's
    /// control connection is back.
    fn queue(&self, op: &wicket_core::Op, why: &str, who: Option<&serde_json::Value>) -> std::result::Result<String, String> {
        let (id, new) = self.0.queue.push(&self.1, op, why, who, (self.0.clock)(), false);
        if new {
            self.0.audit_note(
                &self.1,
                "node.ask_queued",
                serde_json::json!({ "id": id, "host": op.host, "method": op.method, "path": op.path }),
            );
        }
        Ok(id)
    }
}

/// Where a run's CONNECTs go, and the way to the control host's egress proxy for it.
struct NodeRelay {
    node: Arc<Node>,
    run: String,
    zone: Arc<wicket_core::CompiledZone>,
    ca: Option<Arc<NodeCa>>,
    /// Hosts the control host swaps a credential in for (routing only): always forwarded.
    swaps: Vec<wicket_proxy::CredentialSwap>,
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
        // Injected hosts are decided here too, their secret fetched on first use (#152); with a
        // control host before protocol 3 they are forwarded to it, as before. Hosts the control host
        // swaps a credential in for (#169) are always forwarded: swaps stay there.
        let v1 = (1..chan::NODE_LEASES).contains(&self.node.proto_of(&self.run));
        wicket_proxy::decide::route_sealed(
            host,
            &spec,
            &self.swaps,
            self.ca.as_ref().map(|c| (&c.permitted[..], c.not_after)),
            now,
            &|_| !v1,
        )
    }

    fn open(&self) -> futures_util::future::BoxFuture<'_, std::io::Result<Box<dyn RelayStream>>> {
        Box::pin(async move { self.node.open_tunnel(&self.run, "egress").await })
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
    // Images a previous `serve` was receiving when it ended (#191) are incomplete.
    images::clear_spool(&paths.root);
    let ctl = paths.socket();
    let ctl_dir = ctl.parent().expect("socket dir");
    std::fs::create_dir_all(ctl_dir)?;
    std::fs::set_permissions(ctl_dir, std::fs::Permissions::from_mode(0o700))?;
    let _ = std::fs::remove_file(&ctl);
    let listener = wicket_proxy::sockpath::bind(&ctl).with_context(|| format!("listening on {}", ctl.display()))?;
    let clock = node_clock();
    let node_root = paths.root.clone();
    // Secrets live in this process's memory only (#152): keep it out of core dumps and others' ptrace,
    // and take the cache a self-update's re-exec handed over, if any.
    crate::nodesecrets::Cache::harden_process();
    let secrets = crate::nodesecrets::Cache::new(clock.clone());
    match secrets.import_handover() {
        Ok(0) => {}
        Ok(n) => eprintln!("[node] {n} cached secret(s) handed over from the previous process"),
        Err(e) => eprintln!("[node] the secret cache handed over is refused: {e:#}"),
    }
    let slices = crate::nodesecrets::Slices::new(&node_root)?;
    let node = Arc::new(Node {
        name: name.clone(),
        paths,
        ident,
        build: build_id()?,
        clock,
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
        secrets,
        slices,
        queue: crate::nodesecrets::Asks::open(&node_root),
        edge: gw::EdgeQueue::open(&node_root),
        requeued: Mutex::new(HashMap::new()),
        stopped: Mutex::new(HashMap::new()),
        causes: Mutex::new(HashMap::new()),
        mem: Mutex::new(HashMap::new()),
        llms: Mutex::new(HashMap::new()),
        images: Default::default(),
    });
    // Queued audit records are committed (and shipped, if the control host is connected) on a
    // normal exit, SIGTERM or ^C: only a SIGKILL can lose the last unwaited batch.
    let _flush = crate::audit_export::FlushOnDrop(node.audit.clone());
    {
        let n = node.clone();
        crate::audit_export::flush_on_signal(node.audit.clone(), move || n.ship_audit());
    }
    adopt_previous(&node).await;
    {
        // `wicket self update` moves a node to a new build with SIGHUP: it saves where each box's
        // output got to, commits its audit, and re-executes itself from the new version, which
        // adopts the boxes as a restarted `serve` does (#151). Its boxes never stop.
        let n = node.clone();
        // This host's own node runs the control host's versions; another node its own.
        let versions = match n.paths.shares_host() {
            true => crate::update::Versions::control().root,
            false => n.paths.root.join("versions"),
        };
        crate::update::reexec_on_hangup(n.paths.root.join("serve.pid"), versions, move || {
            for b in n.boxes.lock().expect("boxes").values_mut() {
                save_output(b);
            }
            if let Ok(l) = n.audit.lock() {
                let _ = l.flush_audit();
            }
            n.ship_audit();
            // The secret cache goes to the new process in a sealed memfd, never a file (#152): the
            // descriptor is left open across the exec only, and named in the environment.
            match n.secrets.export() {
                Ok(fd) => {
                    use std::os::fd::IntoRawFd;
                    std::env::set_var(crate::nodesecrets::HANDOVER_ENV, fd.into_raw_fd().to_string());
                }
                Err(e) => eprintln!("[node] the secret cache can't be handed over ({e:#}); it is fetched again"),
            }
        });
    }
    {
        // A box whose authority has expired (#153): its token's block 0 ends at the run's
        // `limits.authority` (default its timeout). The workload's grants decide, not this node:
        // connected or not, the box is stopped then. One with no authority on this node at all
        // (its run dropped from the feed) is left to its run, or to adoption's own check.
        let n = node.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(1));
            // Stopped once each: the kill is in flight until the box's exit is read.
            let mut stopped: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut tick5 = 0u64;
            loop {
                t.tick().await;
                let now = (n.clock)();
                let running: Vec<(String, String)> = n
                    .boxes
                    .lock()
                    .expect("boxes")
                    .iter()
                    .filter(|(_, b)| b.exited.is_none())
                    .map(|(r, b)| (r.clone(), b.name.clone()))
                    .collect();
                let expired: Vec<(String, String, i64)> = {
                    let r = n.replica.lock().expect("replica");
                    running
                        .into_iter()
                        .filter_map(|(run, name)| r.authority_until(&run).filter(|u| *u <= now).map(|u| (run, name, u)))
                        .collect()
                };
                // Each box's memory, every 5 s (#185): its peak for an out-of-memory cause, and a
                // warning to its agent near the limit.
                tick5 = tick5.wrapping_add(1);
                if tick5.is_multiple_of(5) {
                    sample_memory(&n).await;
                }
                // Secrets past their expiry are dropped (#152); their use already ended.
                n.secrets.sweep();
                stopped.retain(|r| n.boxes.lock().expect("boxes").get(r).is_some_and(|b| b.exited.is_none()));
                for (run, name, until) in expired {
                    if !stopped.insert(run.clone()) {
                        continue;
                    }
                    eprintln!("[node] {run}: its authority expired at {until} ms; stopping the box");
                    n.audit_note(&run, "node.authority_expired", serde_json::json!({ "until_ms": until }));
                    n.stopped.lock().expect("stopped").insert(run.clone(), format!("its authority expired at {until} ms"));
                    let _ = n.docker.unpause(&name).await;
                    let _ = n.docker.kill(&name).await;
                }
            }
        });
    }
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

/// Takes over the boxes a previous `node serve` from this directory started (#151): each running box
/// with its record (`node-box.json`) is adopted (its proxies started again, its output read from the
/// start, its stdin fed, its timeout kept) and waits for its control host to resume it. A box whose
/// run has no authority in the feed any more is stopped, and so is one from before records (as
/// before: nobody can supervise it). Any other container, wicket's or not, is left alone.
async fn adopt_previous(node: &Arc<Node>) {
    let runs = node.paths.runs();
    let Ok(boxes) = node.docker.boxes().await else { return };
    for b in boxes {
        let Some(run) = b.run.as_deref().filter(|r| crate::run::check_run_id(r).is_ok() && runs.join(r).is_dir()) else { continue };
        let dir = runs.join(run);
        match BoxRecord::load(&dir).filter(|r| r.name == b.name && r.start.run == run) {
            Some(rec) => {
                // A child this node started (#164) holds the authority it derived for it, until the
                // feed holds the child's own.
                load_derived(node, &dir, run);
                let zone = node.replica.lock().expect("replica").zone_of(run).cloned();
                match zone {
                    Some(z) if z.name == rec.start.zone => match serve_box(node, &rec.start, &dir, z).await {
                        Ok(tasks) => {
                            eprintln!("[node] {run}: adopted box {} from a previous serve", b.name);
                            wire(node, None, rec, dir, tasks, ids());
                        }
                        Err(e) => {
                            eprintln!("[node] {run}: could not adopt box {} ({e:#}); stopping it", b.name);
                            let _ = node.docker.kill(&b.name).await;
                        }
                    },
                    _ => {
                        eprintln!("[node] {run}: box {} has no authority in this node's feed; stopping it", b.name);
                        let _ = node.docker.kill(&b.name).await;
                    }
                }
            }
            // This host's own node shares the run directories with every other node on this Docker:
            // a box without its record isn't its to judge (it is another node's, or the reconciler's).
            None if node.paths.shares_host() => {}
            None => {
                if let crate::owner::Verdict::Orphan(why) = crate::owner::judge(&b, None) {
                    eprintln!("[node] stopping {} ({why})", b.name);
                    let _ = node.docker.kill(&b.name).await;
                }
            }
        }
    }
    // Boxes that exited while no `serve` ran: their exit is kept for the control host.
    for (name, run) in node.docker.exited_boxes().await.unwrap_or_default() {
        let dir = runs.join(&run);
        let Some(rec) = BoxRecord::load(&dir).filter(|r| r.name == name && crate::run::check_run_id(&run).is_ok()) else { continue };
        load_derived(node, &dir, &run);
        let code = node.docker.state(&name).await.ok().flatten().map(|s| s.1).unwrap_or(-1);
        wire_exited(node, rec, dir, code).await;
    }
}

/// A box that exited while no `serve` ran: kept as exited (with its output from the logs), so a
/// resuming control host gets it all and its exit.
async fn wire_exited(node: &Arc<Node>, rec: BoxRecord, dir: PathBuf, code: i32) {
    let _ = code;
    wire(node, None, rec, dir, vec![], ids());
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
        "usage" => {
            let d = tree_dir(&node.paths, run, arg)?;
            Ok(Some(tokio::task::spawn_blocking(move || crate::hibernate::used_bytes(&d)).await?.to_string()))
        }
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

type GwBody = http_body_util::Full<bytes::Bytes>;

fn ids() -> String {
    // SAFETY: getuid and getgid can't fail.
    unsafe { format!("{}:{}", libc::getuid(), libc::getgid()) }
}

/// [`start_box`], boxed with a named type: a box's gateway starting a box (#164) is a cycle of
/// futures whose types the compiler can't otherwise see through.
fn start_box_boxed(
    node: &Arc<Node>,
    owner: Option<u64>,
    bs: BoxStart,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + '_>> {
    Box::pin(start_box(node, owner, bs))
}

/// Starts a box: for the control connection `owner`, or (a child this node started, #164) for
/// none until its control host takes it over.
async fn start_box(node: &Arc<Node>, owner: Option<u64>, bs: BoxStart) -> Result<String> {
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
    // What the image is here (#192). Pinned, the box is exactly that digest: by its pinned
    // reference, or the digest alone; a tag moved to another image since changes nothing, and a
    // node without it refuses. Either way the box is started by the image's id, so nothing swaps it.
    let ident = match &bs.image_pin {
        Some(pin) => {
            let by_ref = node.docker.image_identity(&bs.image).await?.filter(|i| i.is(pin));
            let by_digest = match by_ref {
                Some(i) => Some(i),
                None => node.docker.image_identity(pin).await?.filter(|i| i.is(pin)),
            };
            by_digest.with_context(|| format!("image {} (pinned to {pin}) is not on node {}", bs.image, node.name))?
        }
        None => node
            .docker
            .image_identity(&bs.image)
            .await?
            .with_context(|| format!("image {} not found on node {} (run: wicket image there)", bs.image, node.name))?,
    };
    if !bs.binds.is_empty() && !node.paths.shares_host() {
        bail!("this node doesn't share the control host's filesystem: it can't mount the control host's directories");
    }
    for (host, target, _) in &bs.binds {
        let reserved = [wicket_agent::SOCK_DIR, wicket_agent::CA_DIR, wicket_agent::STATE_DIR, "/etc/hosts", "/tmp"];
        if !host.starts_with('/')
            || !target.starts_with('/')
            || reserved.iter().any(|r| target == r || target.starts_with(&format!("{r}/")))
        {
            bail!("bad bind {host:?} on {target:?}");
        }
    }
    let dir = node.paths.runs().join(&bs.run);
    if bs.long_lived {
        std::fs::create_dir_all(dir.join("tmp"))?;
        std::fs::set_permissions(dir.join("tmp"), std::fs::Permissions::from_mode(0o1777))?;
    }
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
        // A long-lived agent's durable volume is its own, kept with its state in the run's
        // directory (and moved when it hibernates); any other is the zone's.
        let d = match bs.long_lived && bs.durable.iter().any(|(n, _)| n == name) {
            true => dir.join("volumes").join(name),
            false => node.paths.volumes().join(&bs.tenant).join(&bs.zone).join(name),
        };
        std::fs::create_dir_all(&d)?;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
        volume_mounts.push(Mount { host: d, target: target.clone(), read_only: false });
    }

    let tasks = serve_box(node, &bs, &dir, zone).await?;
    let sock = dir.join("sock");

    let spec = SandboxSpec {
        // The name the control host gives it (its box prefix), else wicket's own.
        name: bs.name.clone().filter(|n| box_name_ok(n, &bs.run)).unwrap_or_else(|| format!("wicket-{}", bs.run.replace('_', "-"))),
        image: ident.id.clone(),
        isolation: bs.isolation,
        mounts: vec![
            Mount { host: sock, target: wicket_agent::SOCK_DIR.into(), read_only: false },
            Mount { host: dir.join("ca"), target: wicket_agent::CA_DIR.into(), read_only: true },
            Mount { host: dir.join("state"), target: wicket_agent::STATE_DIR.into(), read_only: false },
            // wicket's own hosts file, which links add names to (`BoxCtl` "hosts").
            Mount { host: dir.join("hosts"), target: "/etc/hosts".into(), read_only: true },
        ]
        .into_iter()
        // The workspace: the run's, or (on the control host's own node) a directory of the control
        // host's own, mounted in place, as the binds say.
        .chain((!bs.binds.iter().any(|(_, t, _)| t == wicket_agent::WORKSPACE)).then(|| Mount {
            host: dir.join("workspace"),
            target: wicket_agent::WORKSPACE.into(),
            read_only: false,
        }))
        .chain(bs.binds.iter().map(|(h, t, ro)| Mount { host: PathBuf::from(h), target: t.clone(), read_only: *ro }))
        .chain(volume_mounts)
        // A long-lived agent's /tmp is a directory here, kept with the rest of its state.
        .chain(bs.long_lived.then(|| Mount { host: dir.join("tmp"), target: "/tmp".into(), read_only: false }))
        .collect(),
        // An interactive box's stdin comes over `sock/stdin.sock` (see `wire`), not Docker's.
        env: bs
            .env
            .iter()
            .cloned()
            .chain(bs.interactive.then(|| ("WICKET_STDIN_SOCK".to_string(), format!("{}/stdin.sock", wicket_agent::SOCK_DIR))))
            .collect(),
        argv: bs.argv.clone(),
        memory: bs.memory.clone(),
        cpus: bs.cpus,
        pids: bs.pids,
        user: ids(),
        workdir: bs
            .workdir
            .clone()
            .filter(|w| w.starts_with('/') && node.paths.shares_host())
            .unwrap_or_else(|| wicket_agent::WORKSPACE.into()),
        interactive: false,
        // Its owner: on the control host's own node, the run's process (what the reconciler there
        // judges); elsewhere this `serve` (what the next `serve` judges, `reap_previous`).
        labels: vec![
            ("wicket.run".into(), bs.run.clone()),
            (
                "wicket.owner".into(),
                bs.owner
                    .clone()
                    .filter(|o| node.paths.shares_host() && o.len() <= 200 && !o.contains(['\n', '=']))
                    .unwrap_or_else(crate::owner::owner_label),
            ),
        ],
    };
    let name = spec.name.clone();
    let cap = bs.output_cap.max(64 << 10);
    // Detached, so the box outlives this `serve` (a restarted one adopts it, `adopt_previous`).
    node.docker.start_detached(&spec, cap).await?;
    let rec = BoxRecord {
        start: bs,
        image_digest: Some(ident.id.clone()),
        name: name.clone(),
        started_ms: wicket_feed::now_ms(),
        stdin_received: 0,
        stdin_closed: false,
        out_end: [0, 0],
        out_tail: [String::new(), String::new()],
        out_saved_ms: 0,
    };
    rec.save(&dir)?;
    wire(node, owner, rec, dir, tasks, spec.user.clone());
    eprintln!("[node] box {name} started ({})", ident.id);
    Ok(ident.id)
}

/// The authority this node derived for a child it started (#164), kept beside it so a restarted
/// `serve` holds it again (`derived.json`).
const DERIVED_FILE: &str = "derived.json";

fn save_derived(dir: &std::path::Path, a: &BoxAuthority) -> Result<()> {
    crate::nodesecrets::write_atomic(&dir.join(DERIVED_FILE), &serde_json::to_vec(a)?)
}

/// Holds a child's derived authority again (a restarted `serve`), unless the feed holds its own.
fn load_derived(node: &Node, dir: &std::path::Path, run: &str) {
    let Some(a) = std::fs::read(dir.join(DERIVED_FILE)).ok().and_then(|b| serde_json::from_slice::<BoxAuthority>(&b).ok()) else { return };
    if a.run != run {
        return;
    }
    let mut r = node.replica.lock().expect("replica");
    if r.state().is_some_and(|s| s.zones.contains_key(run)) {
        return;
    }
    if let Err(e) = r.put_local(a) {
        eprintln!("[node] {run}: the authority this node derived for it no longer holds ({e})");
    }
}

/// A child's box (#164), as its control host would start it: its parent's start with the child's
/// own manifest, adapter plan, limits and name. A fresh workspace; no volumes, binds or swaps.
fn child_start(
    parent: &BoxStart,
    plan: &crate::spawn::ChildPlan,
    child: &wicket_core::RunId,
    session: &wicket_agent::AgentSession,
    who: serde_json::Value,
    until_ms: i64,
) -> Result<BoxStart> {
    let m = &plan.cm;
    if m.agent.as_ref().is_some_and(|a| a.kind == "acp") {
        // wicket is an ACP agent's client from the control host (#66); a node doesn't drive one.
        bail!("an ACP agent's child starts from wicket's control host, which this node can't reach now");
    }
    let launch = match wicket_agent::program_plan(m, child) {
        Some(p) => p,
        None => wicket_agent::claude_code_plan(m, child, session),
    };
    let mut state_files = vec![];
    if wicket_agent::uses_claude_settings(m) {
        let json = serde_json::to_vec_pretty(&wicket_agent::claude_settings(m))?;
        state_files.push(("claude/settings.json".into(), base64::engine::general_purpose::STANDARD.encode(&json)));
    }
    let suffix = format!("-{}", parent.run.replace('_', "-"));
    let name = parent.name.as_deref().and_then(|n| n.strip_suffix(&suffix)).map(|p| format!("{p}-{}", child.0.replace('_', "-")));
    let timeout = m.zone.limits.timeout()?.as_secs();
    let left = u64::try_from((until_ms - wicket_feed::now_ms()) / 1000).unwrap_or(0);
    Ok(BoxStart {
        run: child.0.clone(),
        tenant: parent.tenant.clone(),
        zone: m.zone.name.clone(),
        image: plan.image.clone(),
        isolation: m.zone.isolation,
        env: launch.env,
        argv: launch.argv,
        memory: m.zone.limits.memory_bytes().context("limits.memory is unreadable")?.to_string(),
        cpus: m.zone.limits.cpus,
        pids: m.zone.limits.pids,
        interactive: launch.stdin_task.is_some(),
        timeout_secs: timeout.min(left),
        escalate: m.program.as_ref().is_none_or(|p| p.on_pending != wicket_core::OnPending::Fail),
        ca_pem: parent.ca_pem.clone(),
        workspace_tar: String::new(),
        state_files,
        volumes: vec![],
        streams: [1, 2, 3],
        binds: vec![],
        workdir: None,
        owner: parent.owner.clone(),
        long_lived: false,
        durable: vec![],
        name,
        llm_prior: (0, 0, 0),
        output_cap: m.zone.limits.output_bytes().unwrap_or(64 << 20),
        output_stop: m.zone.limits.on_output_full == wicket_core::manifest::OnOutputFull::Stop,
        swap_hosts: vec![],
        edge: Some(Box::new(chan::EdgeStart { who, spawn: None })),
        image_pin: plan.image_pin.clone(),
    })
}

/// Writes `bytes` to a box's stdin as its control host would (a child's task, #164): at the
/// stdin offset reached, so the same bytes from its control host later are dropped as a replay.
fn feed_stdin(node: &Node, run: &str, bytes: &[u8]) {
    let mut boxes = node.boxes.lock().expect("boxes");
    if let Some(b) = boxes.get_mut(run) {
        let at = b.stdin_next;
        let (fresh, _) = accept_at(&mut b.stdin_next, at, bytes);
        if let (Some(s), false) = (&b.stdin, fresh.is_empty()) {
            s.push(&fresh);
            b.record.stdin_received = b.stdin_next;
            let _ = b.record.save(&b.dir);
        }
    }
}

/// What a node keeps of a box it started, in its run directory (`node-box.json`): enough for a
/// restarted `serve` to adopt it.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct BoxRecord {
    start: BoxStart,
    /// The image's digest as this node started it (#192).
    #[serde(default)]
    image_digest: Option<String>,
    name: String,
    started_ms: i64,
    /// Bytes of stdin taken from the control host, and whether it closed it.
    stdin_received: u64,
    #[serde(default)]
    stdin_closed: bool,
    /// How far into its stdout and stderr this node has read (bytes read, whatever Docker has rotated
    /// away since), the last bytes read of each (base64; to line a replay up again), and when.
    #[serde(default)]
    out_end: [u64; 2],
    #[serde(default)]
    out_tail: [String; 2],
    #[serde(default)]
    out_saved_ms: i64,
}

/// How many of a stream's last bytes a box's record keeps, to find its place in a replay.
const TAIL: usize = 1024;

impl BoxRecord {
    const FILE: &'static str = "node-box.json";

    fn save(&self, dir: &std::path::Path) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = dir.join(format!("{}.new", Self::FILE));
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all_sync(&serde_json::to_vec(self)?)?;
        std::fs::rename(&tmp, dir.join(Self::FILE))?;
        Ok(())
    }

    fn load(dir: &std::path::Path) -> Option<BoxRecord> {
        serde_json::from_slice(&std::fs::read(dir.join(Self::FILE)).ok()?).ok()
    }
}

/// An interactive box's stdin, kept (up to [`OUTPUT_CAP`]) so the box's forwarder gets every byte
/// once, however often it reconnects.
struct StdinFeed {
    buf: std::sync::Mutex<(OutBuf, bool)>,
    more: tokio::sync::Notify,
    /// The box's forwarder has connected at least once.
    seen: std::sync::atomic::AtomicBool,
}

impl StdinFeed {
    fn new(at: u64, closed: bool) -> StdinFeed {
        StdinFeed {
            buf: std::sync::Mutex::new((OutBuf::starting_at(OUTPUT_CAP, at), closed)),
            more: tokio::sync::Notify::new(),
            seen: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn push(&self, b: &[u8]) {
        self.buf.lock().expect("stdin").0.write(b);
        self.more.notify_waiters();
    }

    fn close(&self) {
        self.buf.lock().expect("stdin").1 = true;
        self.more.notify_waiters();
    }

    /// Serves the box's forwarder (`wicket-fwd --stdin-from`) on `path`.
    fn serve(self: Arc<Self>, path: &std::path::Path) -> Result<tokio::task::JoinHandle<()>> {
        let _ = std::fs::remove_file(path);
        let l = wicket_proxy::sockpath::bind(path)?;
        Ok(tokio::spawn(async move {
            while let Ok((c, _)) = l.accept().await {
                let me = self.clone();
                tokio::spawn(async move {
                    let _ = me.feed(c).await;
                });
            }
        }))
    }

    async fn feed(&self, mut c: UnixStream) -> std::io::Result<()> {
        let mut off = [0u8; 8];
        c.read_exact(&mut off).await?;
        self.seen.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut at = u64::from_be_bytes(off);
        loop {
            let more = self.more.notified();
            tokio::pin!(more);
            more.as_mut().enable();
            let (from, bytes, closed) = {
                let g = self.buf.lock().expect("stdin");
                let (from, bytes) = g.0.since(at);
                (from, bytes, g.1)
            };
            for chunk in bytes.chunks(64 * 1024) {
                c.write_all(&(chunk.len() as u32).to_be_bytes()).await?;
                c.write_all(chunk).await?;
            }
            at = from + bytes.len() as u64;
            if closed {
                c.write_all(&0u32.to_be_bytes()).await?;
                // Held open until the forwarder hangs up, so it never reconnects for more.
                let mut sink = [0u8; 1];
                let _ = c.read(&mut sink).await;
                return Ok(());
            }
            more.await;
        }
    }
}

trait WriteSync {
    fn write_all_sync(&mut self, b: &[u8]) -> std::io::Result<()>;
}
impl WriteSync for std::fs::File {
    fn write_all_sync(&mut self, b: &[u8]) -> std::io::Result<()> {
        std::io::Write::write_all(self, b)
    }
}

/// Connects a running box to this `serve`: its stdin (`docker attach`), its output from the start
/// (`docker logs`, so a restarted `serve` replays it and the control host drops what it already has),
/// its exit, and its timeout, counted from when it started.
fn wire(node: &Arc<Node>, owner: Option<u64>, rec: BoxRecord, dir: PathBuf, tasks: Vec<tokio::task::JoinHandle<()>>, user: String) {
    let bs = &rec.start;
    let name = rec.name.clone();
    let mut tasks = tasks;
    // An interactive box's stdin: a feed the box's forwarder reads over `sock/stdin.sock`
    // (`wicket-fwd --stdin-from`), reconnecting if this `serve` goes away.
    let feed = bs.interactive.then(|| Arc::new(StdinFeed::new(rec.stdin_received, rec.stdin_closed)));
    if let Some(f) = &feed {
        match f.clone().serve(&dir.join("sock/stdin.sock")) {
            Ok(t) => tasks.push(t),
            Err(e) => eprintln!("[node] {}: the box's stdin socket failed: {e:#}", bs.run),
        }
        // An image from before stdin came over a socket never asks for it, and its agent would wait
        // for ever: stopped, saying why (on the box's stderr, which the control host shows).
        let (n, f, run, name) = (node.clone(), f.clone(), bs.run.clone(), name.clone());
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            if f.seen.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let why =
                "[wicket] the box never read its stdin: its image predates wicket's stdin socket (#151); rebuild it with `wicket image`\n";
            eprintln!("[node] {run}: {}", why.trim());
            let frame = {
                let mut boxes = n.boxes.lock().expect("boxes");
                boxes.get_mut(&run).filter(|b| b.exited.is_none()).map(|b| {
                    let at = b.out[1].write(why.as_bytes());
                    Frame::Data { stream: b.streams[2], offset: at, bytes: why.as_bytes().to_vec() }
                })
            };
            if let Some(fr) = frame {
                n.send_run(&run, fr);
                n.stopped.lock().expect("stopped").entry(run.clone()).or_insert_with(|| "its image predates wicket's stdin socket".into());
                let _ = n.docker.kill(&name).await;
            }
        }));
    }
    node.boxes.lock().expect("boxes").insert(
        bs.run.clone(),
        BoxState {
            streams: bs.streams,
            name: name.clone(),
            dir: dir.clone(),
            stdin: feed,
            stdin_next: rec.stdin_received,
            out: [OutBuf::starting_at(OUTPUT_CAP, rec.out_end[0]), OutBuf::starting_at(OUTPUT_CAP, rec.out_end[1])],
            exited: None,
            tasks,
            user,
            cpus: bs.cpus,
            memory_mib: bs.memory.parse::<u64>().map(|b| b >> 20).unwrap_or(0),
            listeners: HashMap::new(),
            owner,
            record: rec.clone(),
        },
    );
    // A box read before (adopted): Docker's logs since a little before the last save, lined up on
    // the last bytes read (rotation may have dropped their start).
    let since = (rec.out_saved_ms > 0).then(|| {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_millis((rec.out_saved_ms - 10_000).max(0) as u64);
        humantime::format_rfc3339_millis(t).to_string()
    });
    let logs = node.docker.logs(&name, since.as_deref()).spawn();
    let readers: Vec<_> = match logs {
        Err(e) => {
            eprintln!("[node] {}: reading the box's output failed: {e}", bs.run);
            vec![]
        }
        Ok(mut child) => {
            let rs: Vec<_> = [
                child.stdout.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
                child.stderr.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
            ]
            .into_iter()
            .enumerate()
            .filter_map(|(i, r)| r.map(|r| (i, r)))
            .map(|(i, r)| {
                use base64::Engine;
                let tail = base64::engine::general_purpose::STANDARD.decode(&rec.out_tail[i]).unwrap_or_default();
                tokio::spawn(read_output(node.clone(), bs.run.clone(), name.clone(), i, r, tail, bs.output_cap, bs.output_stop))
            })
            .collect();
            // The log reader lives as long as its readers.
            let mut rs = rs;
            rs.push(tokio::spawn(async move {
                let _ = child.wait().await;
            }));
            rs
        }
    };
    // The node enforces the run's timeout itself, connected or not, from when the box started.
    let (n, run, box_name) = (node.clone(), bs.run.clone(), name.clone());
    let left = (rec.started_ms + (bs.timeout_secs.max(1) as i64) * 1000 - wicket_feed::now_ms()).max(1000);
    tokio::spawn(async move {
        let deadline = tokio::time::sleep(std::time::Duration::from_millis(left as u64));
        tokio::pin!(deadline);
        let code = tokio::select! {
            c = n.docker.wait(&box_name) => c.unwrap_or(-1),
            _ = &mut deadline => {
                eprintln!("[node] {run}: past its timeout; stopping the box");
                n.stopped.lock().expect("stopped").entry(run.clone()).or_insert_with(|| "past its timeout (the node's backstop)".into());
                let _ = n.docker.unpause(&box_name).await;
                let _ = n.docker.kill(&box_name).await;
                n.docker.wait(&box_name).await.unwrap_or(-1)
            }
        };
        for r in readers {
            let _ = r.await;
        }
        finish(&n, &run, &box_name, code).await;
    });
}

/// Lines an adopted box's replayed output up on the last bytes its node read of it before (#151).
struct Aligner {
    tail: Vec<u8>,
    pending: Vec<u8>,
}

impl Aligner {
    /// Takes replayed bytes: once the whole tail has been seen, what follows it.
    fn feed(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        self.pending.extend_from_slice(data);
        let t = self.tail.as_slice();
        let p = self.pending.windows(t.len()).position(|w| w == t)?;
        Some(self.pending.split_off(p + t.len()))
    }

    /// No whole tail in the replay: if it starts inside the tail (at least 64 bytes of its end, or
    /// all of a shorter one), what follows; otherwise all of it (the replay starts after the tail, or
    /// Docker rotated part of it away). The flag says whether it was lined up.
    fn give_up(&mut self) -> (Vec<u8>, bool) {
        let p = std::mem::take(&mut self.pending);
        let t = &self.tail;
        for k in (t.len().min(64)..t.len()).rev() {
            if p.starts_with(&t[t.len() - k..]) {
                return (p[k..].to_vec(), true);
            }
        }
        (p, false)
    }
}

/// Reads one of a box's streams from Docker's logs into the node's buffer. Offsets count the bytes
/// this node has read: what Docker rotated away before it was read is never seen, nor counted.
///
/// - **Lining a replay up** (an adopted box): until the stream's last recorded bytes (`tail`) are
///   found in what Docker replays, nothing is passed on; what follows them continues at the recorded
///   offset. If they aren't found within 3 s (`Aligner::give_up`), the replay continues at the
///   recorded offset, and a gap that can't be lined up is put in the node's audit (`box.output.gap`).
///   Output that repeats itself exactly can line up on an earlier copy of the tail.
/// - **The cap**: Docker keeps at most `cap` bytes on the host, so the oldest are rotated away
///   (`box.output` records at exit how many at least), or with `stop` the box is stopped once it has
///   written more, saying why on its stderr.
#[allow(clippy::too_many_arguments)]
async fn read_output<R: tokio::io::AsyncRead + Unpin>(
    n: Arc<Node>,
    run: String,
    name: String,
    i: usize,
    mut r: R,
    tail: Vec<u8>,
    cap: u64,
    stop: bool,
) {
    let mut buf = vec![0u8; 32 * 1024];
    let mut aligner = (!tail.is_empty()).then(|| Aligner { tail, pending: Vec::new() });
    let t0 = std::time::Instant::now();
    let mut last_save = std::time::Instant::now();
    let mut stopped = false;
    loop {
        // While lining up, a quiet box's replay mustn't be held back: reads time out at 3 s.
        let read = match aligner {
            Some(_) => tokio::time::timeout(std::time::Duration::from_secs(3).saturating_sub(t0.elapsed()), r.read(&mut buf)).await.ok(),
            None => Some(r.read(&mut buf).await),
        };
        let timed_out = read.is_none();
        let (k, eof) = match read {
            Some(Ok(0)) | Some(Err(_)) => (0, true),
            Some(Ok(k)) => (k, false),
            None => (0, false),
        };
        let data = match aligner.as_mut() {
            None => buf[..k].to_vec(),
            Some(a) => match a.feed(&buf[..k]) {
                Some(d) => {
                    aligner = None;
                    d
                }
                None if eof || timed_out || a.pending.len() > (8 << 20) => {
                    let (d, lined) = a.give_up();
                    aligner = None;
                    if !lined {
                        let at = n.boxes.lock().expect("boxes").get(&run).map(|b| b.out[i].end()).unwrap_or(0);
                        eprintln!("[node] {run}: its output's replay couldn't be lined up: resuming at offset {at}");
                        let _ = n.audit.lock().expect("audit").audit(
                            &wicket_core::TenantId::single(),
                            Some(&wicket_core::RunId(run.clone())),
                            "box.output.gap",
                            &serde_json::json!({ "stream": if i == 0 { "stdout" } else { "stderr" }, "offset": at }),
                        );
                    }
                    d
                }
                None => continue,
            },
        };
        if data.is_empty() {
            if eof {
                break;
            }
            continue;
        }
        let (frame, over) = {
            let mut boxes = n.boxes.lock().expect("boxes");
            let Some(b) = boxes.get_mut(&run) else { break };
            let at = b.out[i].write(&data);
            b.record.out_end[i] = b.out[i].end();
            if last_save.elapsed() > std::time::Duration::from_secs(2) {
                save_output(b);
                last_save = std::time::Instant::now();
            }
            let over = stop && !stopped && b.record.out_end[0] + b.record.out_end[1] > cap;
            (Frame::Data { stream: b.streams[i + 1], offset: at, bytes: data }, over)
        };
        n.send_run(&run, frame);
        if over {
            stopped = true;
            let why =
                format!("[wicket] the box's output passed its zone's limits.output ({cap} bytes): stopping it (on_output_full: stop)\n");
            eprintln!("[node] {run}: {}", why.trim());
            let frame = {
                let mut boxes = n.boxes.lock().expect("boxes");
                boxes.get_mut(&run).map(|b| {
                    let at = b.out[1].write(why.as_bytes());
                    Frame::Data { stream: b.streams[2], offset: at, bytes: why.as_bytes().to_vec() }
                })
            };
            if let Some(f) = frame {
                n.send_run(&run, f);
            }
            n.stopped
                .lock()
                .expect("stopped")
                .entry(run.clone())
                .or_insert_with(|| format!("its output passed limits.output ({cap} bytes; on_output_full: stop)"));
            let _ = n.docker.kill(&name).await;
        }
        if eof {
            break;
        }
    }
    // The tail as of the end of this read, for a `serve` that comes after.
    if let Some(b) = n.boxes.lock().expect("boxes").get_mut(&run) {
        save_output(b);
    }
}

/// Saves how far into each of a box's streams this node has read, with the bytes that end there.
fn save_output(b: &mut BoxState) {
    use base64::Engine;
    for i in 0..2 {
        let end = b.out[i].end();
        let (_, s) = b.out[i].since(end.saturating_sub(TAIL as u64));
        b.record.out_end[i] = end;
        b.record.out_tail[i] = base64::engine::general_purpose::STANDARD.encode(&s[s.len().saturating_sub(TAIL)..]);
    }
    b.record.out_saved_ms = wicket_feed::now_ms();
    let _ = b.record.save(&b.dir);
}

/// A box exited: its exit and result are kept for the control host, and its container removed.
async fn finish(n: &Arc<Node>, run: &str, box_name: &str, code: i32) {
    let dir = n.boxes.lock().expect("boxes").get(run).map(|b| b.dir.clone());
    let result = dir.as_ref().and_then(|d| crate::hibernate::read_outbox(d, 64 * 1024)).and_then(|b| String::from_utf8(b).ok());
    let output = n.boxes.lock().expect("boxes").get_mut(run).map(|b| {
        b.exited = Some((code, result.clone()));
        if let Some(f) = b.stdin.take() {
            f.close();
        }
        (b.record.out_end, b.record.start.output_cap, b.record.start.tenant.clone())
    });
    // What the box wrote, against what its node keeps of it (#151): counted from what this node read,
    // so what Docker rotated away unread isn't in it, and the drop is a lower bound.
    if let Some(([o, e], cap, tenant)) = output {
        let dropped = (o + e).saturating_sub(cap);
        let _ = n.audit.lock().expect("audit").audit(
            &wicket_core::TenantId(tenant),
            Some(&wicket_core::RunId(run.to_string())),
            "box.output",
            &serde_json::json!({ "stdout_read": o, "stderr_read": e, "cap": cap, "dropped_from_host_at_least": dropped }),
        );
        n.ship_audit();
    }
    // Why it ended (#185): wicket's own stop, the OOM killer, the runtime, or a signal; read before
    // the box is removed.
    let info = n.docker.exit_info(box_name).await.ok().flatten();
    let mem = n.mem.lock().expect("mem").remove(run).map(|(_, m, _)| m);
    let limit = n.boxes.lock().expect("boxes").get(run).map(|b| b.memory_mib << 20).filter(|l| *l > 0);
    let stopped = n.stopped.lock().expect("stopped").get(run).cloned();
    let cause = crate::exitcause::describe(code, stopped.as_deref(), info.as_ref(), mem.as_ref(), limit);
    if let Some(c) = &cause {
        eprintln!("[node] {run}: {c}");
        n.audit_note(
            run,
            "box.exit_cause",
            serde_json::json!({ "code": code, "cause": c, "oom_killed": info.as_ref().is_some_and(|i| i.oom_killed),
                "memory_peak": mem.map(|m| m.peak), "memory_limit": mem.and_then(|m| m.max).or(limit) }),
        );
        n.causes.lock().expect("causes").insert(run.to_string(), c.clone());
    }
    let _ = n.docker.remove(box_name).await;
    if let Some(d) = &dir {
        let _ = std::fs::remove_file(d.join(BoxRecord::FILE));
    }
    // What was leased to the run goes with its box (#152, #153).
    n.secrets.release(run);
    n.slices.drop_run(run);
    n.queue.drop_run(run);
    n.edge.drop_run(run);
    n.replica.lock().expect("replica").drop_local(run);
    n.llms.lock().expect("llms").remove(run);
    eprintln!("[node] {run}: box exited ({code})");
    n.send_run(run, Frame::Msg(Msg::Exited { run: run.to_string(), code, result, reason: cause }));
}

/// The box's enforcement points: egress decided here; the model proxy and the MCP gateway reached
/// on the control host. Started for a new box, and again for one a restarted `serve` adopts.
async fn serve_box(
    node: &Arc<Node>,
    bs: &BoxStart,
    dir: &std::path::Path,
    zone: wicket_core::ZoneSpec,
) -> Result<Vec<tokio::task::JoinHandle<()>>> {
    let compiled = Arc::new(wicket_core::CompiledZone::new(zone)?);
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<wicket_proxy::Event>();
    let ctx = wicket_proxy::RunCtx {
        tenant: wicket_core::TenantId(bs.tenant.clone()),
        run: wicket_core::RunId(bs.run.clone()),
        zone: compiled.clone(),
        org: None,
        ledger: node.audit.clone(),
        // The secrets the run uses, fetched from the control host on first use and kept in memory
        // only (#152).
        vault: wicket_proxy::vault::Vault::from_source(node.secrets.source(&bs.run, node.fetcher())),
        events: ev_tx,
        escalate: bs.escalate,
        attribute: None,
        identity: None,
        spawner: None,
        // Routing only: hosts the control host swaps a credential in for are forwarded to it (no
        // placeholder or value here, so nothing is ever swapped on the node).
        swaps: bs
            .swap_hosts
            .iter()
            .map(|h| wicket_proxy::CredentialSwap {
                box_bearers: false,
                name: "the control host's".into(),
                host: h.clone(),
                placeholder: String::new(),
                real: wicket_proxy::SwapSource::Value(String::new()),
            })
            .collect(),
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
    let relay = Arc::new(NodeRelay { node: node.clone(), run: bs.run.clone(), zone: compiled, ca, swaps: ctx.swaps.clone() });
    let mut tasks = vec![];
    // The model proxy (#151, #152): the run's checks here (allowed routes and models, server tools,
    // the budget and this node's slice of it). With the model credential in this node's cache, it
    // calls the model itself, the control host isn't asked, and this node is the counter of record
    // (its spend persisted beside the box, and reported). Otherwise the call is relayed to the
    // run's own proxy on the control host, which adds the credential and counts it there too.
    let llm = {
        let (quiet_tx, mut quiet_rx) = mpsc::unbounded_channel::<wicket_proxy::Event>();
        let mut c = ctx.clone();
        c.events = quiet_tx;
        let (n, run) = (node.clone(), bs.run.clone());
        let relay: wicket_proxy::llm::LlmRelay = Arc::new(move || {
            let (n, run) = (n.clone(), run.clone());
            Box::pin(async move { n.open_tunnel(&run, "llm").await })
        });
        let l = wicket_proxy::llm::Llm::relayed(c, relay)?;
        l.spent_before(bs.llm_prior.0, bs.llm_prior.1, bs.llm_prior.2);
        // What this node already counted for the box, before a restart of `serve`.
        if let Some(sp) = std::fs::read(dir.join(SPEND_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
            l.merge_spent(sp);
        }
        l.set_slice(node.slices.get(&bs.run));
        node.llms.lock().expect("llms").insert(bs.run.clone(), l.clone());
        // Its events are the console's only when the call went from here (else the control host's
        // proxy shows the same call).
        let (vault, secret, fwd) = (ctx.vault.clone(), ctx.zone.llm.as_ref().map(|x| x.secret.clone()), ctx.events.clone());
        tasks.push(tokio::spawn(async move {
            while let Some(ev) = quiet_rx.recv().await {
                if secret.as_deref().is_some_and(|s| vault.has(s)) {
                    let _ = fwd.send(ev);
                }
            }
        }));
        // Spend: persisted and reported when it moves, and every 10 s anyway (a new connection
        // learns it without waiting for the next call).
        let (n, run, l2, path) = (node.clone(), bs.run.clone(), l.clone(), dir.join(SPEND_FILE));
        tasks.push(tokio::spawn(async move {
            let mut last = wicket_proxy::llm::Spent::default();
            let mut t = tokio::time::interval(std::time::Duration::from_secs(1));
            let mut i = 0u64;
            loop {
                t.tick().await;
                i += 1;
                let now = l2.spent();
                if now != last {
                    let _ = std::fs::write(&path, serde_json::to_vec(&now).unwrap_or_default());
                }
                if (now != last || i.is_multiple_of(10)) && n.proto_of(&run) >= chan::NODE_LEASES {
                    n.send_run(&run, Frame::Msg(Msg::Spent { run: run.clone(), spent: now }));
                }
                last = now;
            }
        }));
        l
    };
    let egress = Egress::with(ctx, minter, decider, Some(relay))?;
    // DNS and HTTP/3 for the box (#92), decided here like CONNECT: by the node's policy, with the
    // node's CA; hosts the node forwards to the control host get a 403 over HTTP/3 that points at
    // the proxy, which forwards them.
    let h3 = wicket_proxy::h3::H3::new(egress.clone(), wicket_proxy::h3::Options::from_env())?;
    let sock = dir.join("sock");
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
    tasks.push(tokio::spawn({
        let ls = sock.join("llm.sock");
        async move {
            if let Err(e) = llm.serve(&ls).await {
                eprintln!("[node] model proxy ended: {e:#}");
            }
        }
    }));
    // The MCP gateway (#151): served here, each call relayed to the run's gateway on the control
    // host, which decides every tool (they read or write the ledger). While it can't be reached, the
    // node answers MCP's own handshake itself and refuses tool calls clearly.
    {
        let gs = sock.join("gateway.sock");
        let _ = std::fs::remove_file(&gs);
        let l = wicket_proxy::sockpath::bind(&gs)?;
        let (n, run) = (node.clone(), bs.run.clone());
        tasks.push(tokio::spawn(async move {
            while let Ok((c, _)) = l.accept().await {
                let (n, run) = (n.clone(), run.clone());
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let (n, run) = (n.clone(), run.clone());
                        async move { Ok::<_, hyper::Error>(gateway_call(&n, &run, req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(c), svc).await;
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

    Ok(tasks)
}

/// How a fetch for a version-1 control host fails: the model proxy relays on it.
pub const OLD_CONTROL: &str = wicket_proxy::llm::RELAY_INSTEAD;
/// An ask the control host didn't answer (cut off mid-ask).
const NO_ANSWER: &str = "the control host did not answer";

/// A box's cgroup directory (once found), its memory as sampled, and whether its agent was warned.
type BoxMem = (Option<std::path::PathBuf>, crate::exitcause::Mem, bool);

/// Samples every running box's memory from its cgroup (#185), keeping its peak, and warns its agent
/// once it nears its limit (an event to its run, which tells the agent).
async fn sample_memory(n: &Arc<Node>) {
    let running: Vec<(String, String)> =
        n.boxes.lock().expect("boxes").iter().filter(|(_, b)| b.exited.is_none()).map(|(r, b)| (r.clone(), b.name.clone())).collect();
    for (run, name) in running {
        let known = n.mem.lock().expect("mem").get(&run).and_then(|e| e.0.clone());
        let dir = match known {
            Some(d) => Some(d),
            None => match n.docker.pid(&name).await {
                Ok(pid) if pid > 0 => crate::exitcause::cgroup_of(pid),
                _ => None,
            },
        };
        let Some(dir) = dir else { continue };
        let (prev, warned) = n.mem.lock().expect("mem").get(&run).map(|e| (e.1, e.2)).unwrap_or_default();
        let Some(m) = crate::exitcause::sample(&dir, prev) else { continue };
        let (warned2, text) = crate::exitcause::pressure(&m, warned);
        n.mem.lock().expect("mem").insert(run.clone(), (Some(dir), m, warned2));
        if let Some(text) = text {
            eprintln!("[node] {run}: memory at {} of {}", crate::exitcause::human(m.current), crate::exitcause::human(m.max.unwrap_or(0)));
            n.audit_note(&run, "box.memory_pressure", serde_json::json!({ "current": m.current, "max": m.max, "peak": m.peak }));
            let ev = wicket_proxy::Event::Box { what: "memory_pressure".into(), detail: text };
            if let Ok(event) = serde_json::to_value(&ev) {
                n.send_run(&run, Frame::Msg(Msg::Event { run: run.clone(), event }));
            }
        }
    }
}

/// A box's model spend as its node counted it (#152), beside its record.
const SPEND_FILE: &str = "node-spend.json";

/// A box name a control host may choose: a prefix and the run (`<prefix>-run-…`).
fn box_name_ok(name: &str, run: &str) -> bool {
    name.len() <= 100
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && name.ends_with(&format!("-{}", run.replace('_', "-")))
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
            proto: chan::PROTOCOL,
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

    pub(super) fn test_node(i: &Install) -> Arc<Node> {
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
            secrets: crate::nodesecrets::Cache::new(node_clock()),
            slices: crate::nodesecrets::Slices::new(&i.dir).unwrap(),
            queue: crate::nodesecrets::Asks::open(&i.dir),
            edge: gw::EdgeQueue::open(&i.dir),
            requeued: Mutex::new(HashMap::new()),
            stopped: Mutex::new(HashMap::new()),
            causes: Mutex::new(HashMap::new()),
            mem: Mutex::new(HashMap::new()),
            llms: Mutex::new(HashMap::new()),
            images: Default::default(),
        })
    }

    /// The stdin a box's feed holds, once it holds `n` bytes.
    async fn fed(f: &StdinFeed, n: usize) -> Vec<u8> {
        for _ in 0..200 {
            let b = f.buf.lock().unwrap().0.since(0).1;
            if b.len() >= n {
                return b;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the feed never got {n} bytes");
    }

    /// #151: an adopted box's replay is lined up on the last bytes read before, wherever it starts.
    #[test]
    fn a_replay_lines_up_on_the_last_bytes_read() {
        let tail: Vec<u8> = (0..100).map(|k| b"abcdefghij"[k % 10] ^ (k as u8)).collect();
        // The whole tail in the replay, after older bytes: only what follows it, in pieces.
        let mut a = Aligner { tail: tail.clone(), pending: vec![] };
        let mut replay = b"older output\n".to_vec();
        replay.extend_from_slice(&tail);
        assert_eq!(a.feed(&replay[..50]), None);
        assert_eq!(a.feed(&[&replay[50..], b"fresh"].concat()), Some(b"fresh".to_vec()));
        // The replay starts inside the tail (Docker's entries since the save start mid-way).
        let mut a = Aligner { tail: tail.clone(), pending: vec![] };
        assert_eq!(a.feed(&[&tail[30..], b"fresh"].concat()), None);
        assert_eq!(a.give_up(), (b"fresh".to_vec(), true));
        // Nothing of the tail (the replay starts after it): all of it, not lined up.
        let mut a = Aligner { tail: tail.clone(), pending: vec![] };
        assert_eq!(a.feed(b"after"), None);
        assert_eq!(a.give_up(), (b"after".to_vec(), false));
        // A quiet stream: nothing replayed, nothing passed on.
        let mut a = Aligner { tail: tail.clone(), pending: vec![] };
        assert_eq!(a.give_up(), (vec![], false));
        // Output that repeats itself: lined up on the first copy of the tail.
        let mut a = Aligner { tail: b"yy\n".to_vec(), pending: vec![] };
        assert_eq!(a.feed(b"yy\nyy\nz"), Some(b"yy\nz".to_vec()));
    }

    fn fake_record(run: &str) -> BoxRecord {
        BoxRecord {
            start: BoxStart {
                run: run.into(),
                tenant: "t0".into(),
                zone: "z".into(),
                image: "img".into(),
                isolation: wicket_core::Isolation::Gvisor,
                env: vec![],
                argv: vec![],
                memory: "1".into(),
                cpus: 1.0,
                pids: 1,
                interactive: true,
                timeout_secs: 60,
                escalate: true,
                ca_pem: String::new(),
                workspace_tar: String::new(),
                state_files: vec![],
                volumes: vec![],
                streams: [1, 2, 3],
                binds: vec![],
                workdir: None,
                owner: None,
                long_lived: false,
                durable: vec![],
                name: None,
                llm_prior: (0, 0, 0),
                output_cap: 64 << 20,
                output_stop: false,
                swap_hosts: vec![],
                edge: None,
                image_pin: None,
            },
            image_digest: None,
            name: format!("wicket-{run}"),
            started_ms: 0,
            stdin_received: 0,
            stdin_closed: false,
            out_end: [0, 0],
            out_tail: [String::new(), String::new()],
            out_saved_ms: 0,
        }
    }

    async fn next_msg(s: &mut UnixStream) -> Frame {
        tokio::time::timeout(std::time::Duration::from_secs(5), chan::read_frame(s)).await.unwrap().unwrap().unwrap()
    }

    fn hello(proto: u32) -> impl FnOnce(String) -> Msg {
        move |nonce| Msg::Hello {
            node: "n1".into(),
            version: "t".into(),
            build: "any build".into(),
            proto,
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
        proto: u32,
        i: &Install,
        issuer: &wicket_identity::Issuer,
    ) -> (UnixStream, Result<Msg, HsError>) {
        let (mut a, b) = UnixStream::pair().unwrap();
        tokio::spawn(connection(node.clone(), b, gen));
        let (mut rd, mut wr) = a.split();
        let r = crate::nodeauth::control(&mut rd, &mut wr, "n1", &i.ledger, issuer, hello(proto)).await.map(|a| a.welcome);
        (a, r)
    }

    /// A control connection for one run (its scope), as `wicket run` makes.
    async fn connect_run(node: &Arc<Node>, gen: u64, i: &Install, run: &str) -> UnixStream {
        let (mut a, b) = UnixStream::pair().unwrap();
        tokio::spawn(connection(node.clone(), b, gen));
        let (mut rd, mut wr) = a.split();
        let build = node.build.clone();
        let hello = move |nonce| Msg::Hello {
            node: "n1".into(),
            version: "t".into(),
            build,
            proto: chan::PROTOCOL,
            observer: false,
            nonce,
            scope: run.into(),
        };
        let r = crate::nodeauth::control(&mut rd, &mut wr, "n1", &i.ledger, &i.issuer, hello).await.map(|a| a.welcome);
        assert!(matches!(r, Ok(Msg::Welcome { .. })), "{:?}", r.err());
        a
    }

    pub(super) async fn connect(node: &Arc<Node>, gen: u64, i: &Install) -> UnixStream {
        let (a, r) = handshake(node, gen, chan::PROTOCOL, i, &i.issuer).await;
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
        let feed = Arc::new(StdinFeed::new(0, false));
        node.boxes.lock().unwrap().insert(
            "run_a".into(),
            BoxState {
                streams: [1, 2, 3],
                name: "wicket-run-a".into(),
                dir: dir.join("runs/run_a"),
                stdin: Some(feed.clone()),
                stdin_next: 0,
                out: [OutBuf::new(OUTPUT_CAP), OutBuf::new(OUTPUT_CAP)],
                exited: None,
                tasks: vec![],
                user: String::new(),
                cpus: 0.0,
                memory_mib: 0,
                listeners: HashMap::new(),
                owner: Some(2),
                record: fake_record("run_a"),
            },
        );
        // A control host from before protocol versions, or two versions apart, is refused.
        let (_, r) = handshake(&node, 1, 0, &inst, &inst.issuer).await;
        assert!(
            matches!(&r, Err(HsError::Refused(why)) if why.contains("before protocol versions") && why.contains("self update --nodes n1")),
            "{r:?}"
        );
        let (_, r) = handshake(&node, 1, chan::PROTOCOL + 2, &inst, &inst.issuer).await;
        assert!(matches!(&r, Err(HsError::Refused(why)) if why.contains("at most 1 apart")), "{r:?}");
        // One apart either way is accepted, at the lower version (`connect` below is at this build's).
        let (_, r) = handshake(&node, 1, chan::PROTOCOL + 1, &inst, &inst.issuer).await;
        assert!(matches!(r, Ok(Msg::Welcome { proto, .. }) if proto == chan::PROTOCOL), "{r:?}");

        // Connected: output flows, and is acknowledged.
        let (mut c, r) = handshake(&node, 2, chan::PROTOCOL, &inst, &inst.issuer).await;
        assert!(matches!(r, Ok(Msg::Welcome { runs, .. }) if runs[0].stdout_total == 0));
        box_output(&node, b"hello\n");
        assert_eq!(next_msg(&mut c).await, Frame::Data { stream: 2, offset: 0, bytes: b"hello\n".to_vec() });
        c.write_all(&Frame::Msg(Msg::Ack { stream: 2, upto: 6 }).encode()).await.unwrap();
        // Stdin, with a resent overlap: the box gets each byte once.
        for (off, b) in [(0, &b"ab"[..]), (1, &b"bc"[..])] {
            c.write_all(&Frame::Data { stream: 1, offset: off, bytes: b.to_vec() }.encode()).await.unwrap();
        }
        assert_eq!(fed(&feed, 3).await, b"abc");

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
        let (mut c, r) = handshake(&node, 3, chan::PROTOCOL, &inst, &inst.issuer).await;
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

    /// #152, #153: an ask queued while the run's control host was away is raised when it resumes the
    /// box, with its node-local id and time, and leaves the queue once answered; a lease's budget
    /// slice is kept on disk; a protocol-1 control host gets none of the version-2 messages.
    #[tokio::test]
    async fn a_queued_ask_is_raised_on_resume_and_a_lease_keeps_its_slice() {
        const RUN: &str = "run_qqqqqqqqqqqqqqqqqqqqqqqqqq";
        let inst = Install::new("nodesrv-queued");
        let node = test_node(&inst);
        let mut st = BoxState {
            streams: [1, 2, 3],
            name: format!("wicket-{RUN}"),
            dir: inst.dir.join("runs").join(RUN),
            stdin: None,
            stdin_next: 0,
            out: [OutBuf::new(OUTPUT_CAP), OutBuf::new(OUTPUT_CAP)],
            exited: None,
            tasks: vec![],
            user: String::new(),
            cpus: 0.0,
            memory_mib: 0,
            listeners: HashMap::new(),
            owner: None,
            record: fake_record(RUN),
        };
        st.record.start.run = RUN.into();
        node.boxes.lock().unwrap().insert(RUN.into(), st);
        let op =
            wicket_core::Op::egress(&wicket_core::TenantId("t0".into()), &wicket_core::RunId(RUN.into()), "z", "GET", "x.example", "/a");
        // Cut off: the decider's ask is queued, once.
        let ctl = Control(node.clone(), RUN.into());
        let id = ctl.queue(&op, "out of reach", None).unwrap();
        assert_eq!(ctl.queue(&op, "out of reach", None).unwrap(), id);
        let (mut c, r) = handshake(&node, 2, chan::PROTOCOL, &inst, &inst.issuer).await;
        assert!(r.is_ok(), "{:?}", r.err());
        c.write_all(&Frame::Msg(Msg::Resume { run: RUN.into(), stdout_from: 0, stderr_from: 0 }).encode()).await.unwrap();
        let (mid, queued) = match next_msg(&mut c).await {
            Frame::Msg(Msg::Ask { id, run, op: o, queued, .. }) if run == RUN && *o == op => (id, queued),
            other => panic!("{other:?}"),
        };
        assert_eq!(queued.as_ref().map(|q| q.0.as_str()), Some(id.as_str()));
        assert_eq!(node.queue.of(RUN).len(), 1, "kept until answered");
        c.write_all(&Frame::Msg(Msg::Asked { id: mid, pending: Some(("r-1".into(), true)), denied: None, error: None }).encode())
            .await
            .unwrap();
        // A lease's slice: kept on disk for a restarted `serve`.
        let slice = wicket_proxy::llm::Slice { requests: 3, output_tokens: 300, input_tokens: None };
        c.write_all(
            &Frame::Msg(Msg::Lease { run: RUN.into(), lease: Box::new(crate::nodesecrets::Lease { slice: Some(slice) }) }).encode(),
        )
        .await
        .unwrap();
        for _ in 0..200 {
            if node.queue.of(RUN).is_empty() && node.slices.get(RUN).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(node.queue.of(RUN).is_empty(), "answered: off the queue");
        assert_eq!(node.slices.get(RUN), Some(slice));
        assert!(crate::nodesecrets::Asks::open(&inst.dir).of(RUN).is_empty(), "and off the disk");
        assert_eq!(node.proto_of(RUN), chan::PROTOCOL);
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
        let why = refused(handshake(&node, 2, chan::PROTOCOL, &inst, &impostor).await.1);
        assert!(why.contains("not signed by this installation"), "{why}");
        // One that skips checking the node and just signs with its own key: the node refuses it.
        let (mut a, b) = UnixStream::pair().unwrap();
        tokio::spawn(connection(node.clone(), b, 3));
        let mut hs = wicket_identity::node::ControlHandshake::new("n1", b"");
        a.write_all(&Frame::Msg(hello(chan::PROTOCOL)(hs.nonce().into())).encode()).await.unwrap();
        let Frame::Msg(Msg::Challenge { proof }) = next_msg(&mut a).await else { panic!("no challenge") };
        hs.verify_node(&proof, &inst.issuer.verifying_key(), &inst.key.verifying_key(), wicket_store::now()).unwrap();
        a.write_all(&Frame::Msg(Msg::Prove { proof: hs.prove(&impostor).unwrap() }).encode()).await.unwrap();
        assert!(matches!(next_msg(&mut a).await, Frame::Msg(Msg::Refused { why }) if why.contains("issuer key")));
        // A peer that says hello and then nothing useful.
        let (mut a, b) = UnixStream::pair().unwrap();
        tokio::spawn(connection(node.clone(), b, 4));
        a.write_all(&Frame::Msg(hello(chan::PROTOCOL)(wicket_identity::node::nonce())).encode()).await.unwrap();
        let _ = next_msg(&mut a).await;
        a.write_all(&Frame::Msg(Msg::Kill { run: "run_a".into() }).encode()).await.unwrap();
        assert!(matches!(next_msg(&mut a).await, Frame::Msg(Msg::Refused { .. })));
        wait_link(&node, Some(1)).await;

        // The node's certificate from another installation (same key and name).
        let (foreign, _) = impostor.issue_node_cert("n1", &inst.key.verifying_key(), wicket_store::now(), 3600);
        std::fs::write(&cert_path, &foreign).unwrap();
        let why = refused(handshake(&node, 5, chan::PROTOCOL, &inst, &inst.issuer).await.1);
        assert!(why.contains("not signed by this installation"), "{why}");
        // Expired (by the control host's clock).
        let (expired, _) = inst.issuer.issue_node_cert("n1", &inst.key.verifying_key(), wicket_store::now() - 7200, 3600);
        std::fs::write(&cert_path, &expired).unwrap();
        let why = refused(handshake(&node, 6, chan::PROTOCOL, &inst, &inst.issuer).await.1);
        assert!(why.contains("expired"), "{why}");
        // Signed by this issuer, but never recorded (not issued through enrolment or renewal).
        let (unrecorded, _) = inst.issuer.issue_node_cert("n1", &inst.key.verifying_key(), wicket_store::now(), 3600);
        std::fs::write(&cert_path, &unrecorded).unwrap();
        let why = refused(handshake(&node, 7, chan::PROTOCOL, &inst, &inst.issuer).await.1);
        assert!(why.contains("never recorded"), "{why}");
        // No certificate at all.
        std::fs::remove_file(&cert_path).unwrap();
        let why = refused(handshake(&node, 8, chan::PROTOCOL, &inst, &inst.issuer).await.1);
        assert!(why.contains("no identity certificate"), "{why}");
        // A node whose key isn't the enrolled one (re-keyed or replaced), with a certificate for it.
        let other = wicket_identity::SigningKey::generate(&mut rand_core::OsRng);
        let (theirs, _) = inst.issuer.issue_node_cert("n1", &other.verifying_key(), wicket_store::now(), 3600);
        std::fs::write(&cert_path, &theirs).unwrap();
        let why = refused(handshake(&node, 9, chan::PROTOCOL, &inst, &inst.issuer).await.1);
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
        let why = refused(handshake(&node, 12, chan::PROTOCOL, &inst, &inst.issuer).await.1);
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
            let f = Arc::new(StdinFeed::new(0, false));
            stdins.insert(run, f.clone());
            node.boxes.lock().unwrap().insert(
                run.into(),
                BoxState {
                    streams: [1, 2, 3],
                    name: format!("wicket-{run}"),
                    dir: inst.dir.join("runs").join(run),
                    stdin: Some(f),
                    stdin_next: 0,
                    out: [OutBuf::new(OUTPUT_CAP), OutBuf::new(OUTPUT_CAP)],
                    exited: None,
                    tasks: vec![],
                    user: String::new(),
                    cpus: 0.0,
                    memory_mib: 0,
                    listeners: HashMap::new(),
                    owner: Some(gen),
                    record: fake_record(run),
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
        assert_eq!(fed(&stdins["run_a"], 1).await, b"x");
        assert!(stdins["run_b"].buf.lock().unwrap().0.since(0).1.is_empty());
        // run_b reconnects: its old connection ends, run_a's stays.
        let _b2 = connect_run(&node, 3, &inst, "run_b").await;
        assert!(tokio::time::timeout(std::time::Duration::from_secs(5), chan::read_frame(&mut b)).await.unwrap().unwrap().is_none());
        assert!(out("run_a", b"still a\n"));
        assert_eq!(next_msg(&mut a).await, Frame::Data { stream: 2, offset: 6, bytes: b"still a\n".to_vec() });
        // Until it resumes, run_b's output waits on the node.
        assert!(!out("run_b", b"later\n"));
    }

    /// A box on this node whose token the replica holds: `zone` (YAML), minted for `run` until an
    /// hour from now, with the node's #164 edge start.
    fn fed_box(node: &Arc<Node>, inst: &Install, run: &str, zone: &str) {
        fed_boxes(node, inst, &[(run, zone)]);
    }

    /// [`fed_box`] for several boxes on this node.
    fn fed_boxes(node: &Arc<Node>, inst: &Install, boxes: &[(&str, &str)]) {
        use wicket_feed::{Change, Issuer, KeyCert, Publisher, PublisherConfig};
        let root = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let authz_root = wicket_authz::SigningKey::from_bytes(&[9; 32]).unwrap();
        let approver = wicket_authz::SigningKey::from_bytes(&[10; 32]).unwrap();
        let cert = KeyCert::new(&key.verifying_key(), 1, i64::MAX / 2, 30_000);
        let cert_jws = wicket_feed::sign(&root, wicket_feed::TYP_KEY, &cert);
        let cfg = PublisherConfig { ttl_ms: 30_000, refresh_ms: 100, retain: 100 };
        let mut p =
            Publisher::open_with(&inst.dir.join("pub"), "n1", &root.verifying_key(), key, &cert_jws, cfg, authz_root.public()).unwrap();
        let mut r = Replica::new_with("n1", root.verifying_key(), ReplicaConfig::default(), authz_root.public());
        let now = (node.clock)();
        let not_after = u64::try_from(now / 1000 + 3600).unwrap();
        let mut changes = vec![];
        for (run, zone) in boxes {
            let z: wicket_core::ZoneSpec = serde_yaml::from_str(zone).unwrap();
            let issuer =
                Issuer::root(&authz_root, "t0", &format!("run:{run}"), run, 0, &z, &[], not_after, vec![approver.public()]).unwrap();
            changes.push(Change::PutZone { zone: issuer.publish(&approver, &[]).unwrap() });
        }
        p.commit(changes, now).unwrap();
        for f in p.catch_up(&r.hello(), now).unwrap() {
            r.accept(&f, now).unwrap();
        }
        *node.replica.lock().unwrap() = r;
        for (run, zone) in boxes {
            add_box(node, inst, run, zone);
        }
    }

    fn add_box(node: &Arc<Node>, inst: &Install, run: &str, zone: &str) {
        let z: wicket_core::ZoneSpec = serde_yaml::from_str(zone).unwrap();
        let mut rec = fake_record(run);
        rec.start.zone = z.name.clone();
        rec.start.edge = Some(Box::new(chan::EdgeStart {
            who: serde_json::json!({ "id": format!("spiffe://wicket.test/t0/{run}"), "run": run, "zone": z.name }),
            spawn: None,
        }));
        let st = BoxState {
            streams: [1, 2, 3],
            name: format!("wicket-{run}"),
            dir: inst.dir.join("runs").join(run),
            stdin: None,
            stdin_next: 0,
            out: [OutBuf::new(OUTPUT_CAP), OutBuf::new(OUTPUT_CAP)],
            exited: None,
            tasks: vec![],
            user: String::new(),
            cpus: 0.0,
            memory_mib: 0,
            listeners: HashMap::new(),
            owner: None,
            record: rec,
        };
        node.boxes.lock().unwrap().insert(run.into(), st);
    }

    /// Plays the run's gateway on the control host for one tunnelled tool call: answers the
    /// tunnel's open, reads the HTTP request off its data frames, and answers `text`. Returns the
    /// tool call's name and arguments.
    async fn answer_tool(c: &mut UnixStream, stream: u64, text: &str) -> (String, serde_json::Value) {
        c.write_all(&Frame::Msg(Msg::TunnelOpened { stream, error: None }).encode()).await.unwrap();
        let mut req = vec![];
        let call = loop {
            match next_msg(c).await {
                Frame::Data { stream: s, bytes, .. } if s == stream => req.extend_from_slice(&bytes),
                _ => continue,
            }
            let text = String::from_utf8_lossy(&req).to_string();
            if let Some((_, body)) = text.split_once("\r\n\r\n") {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                    break v;
                }
            }
        };
        let body = serde_json::json!({ "jsonrpc": "2.0", "id": call["id"], "result": { "content": [{ "type": "text", "text": text }], "isError": false } })
            .to_string();
        let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}", body.len());
        c.write_all(&Frame::Data { stream, offset: 0, bytes: resp.into_bytes() }.encode()).await.unwrap();
        (call["params"]["name"].as_str().unwrap_or("").to_string(), call["params"]["arguments"].clone())
    }

    /// #164: with its control host unreachable, the node decides the box's gateway tools from its
    /// token: who it is, what it may already do and what it never may, and queues what needs a
    /// human (an ask, a prefix ask, a capacity request) under node-local ids, spending no grant.
    /// When the control host is back, the queued asks are raised and the queued call made, and
    /// await_grant on a node-local id follows the request it became.
    #[tokio::test]
    async fn the_node_decides_gateway_tools_and_queues_what_needs_a_human() {
        const RUN: &str = "run_eeeeeeeeeeeeeeeeeeeeeeeeee";
        let inst = Install::new("nodesrv-edge");
        let node = test_node(&inst);
        fed_box(
            &node,
            &inst,
            RUN,
            "name: z\nreach: [{ host: api.example, methods: [GET], paths: ['/ok/**'] }]\nforbid: [{ host: api.example, paths: ['/secret/**'] }]\n",
        );
        let call = |name: &str, args: serde_json::Value| {
            let (node, name) = (node.clone(), name.to_string());
            async move { gw::tool(&node, RUN, &name, &args).await.expect("decided on the node") }
        };
        let (who, err) = call("whoami", serde_json::json!({})).await;
        assert!(!err && who.contains(&format!("spiffe://wicket.test/t0/{RUN}")) && who.contains("node n1"), "{who}");
        let access = |path: &str, scope: &str| serde_json::json!({ "url": format!("https://api.example{path}"), "reason": "to read the docs", "scope": scope });
        let (t, _) = call("request_access", access("/ok/a", "exact")).await;
        assert!(t.contains("already allowed"), "{t}");
        let (t, _) = call("request_access", access("/secret/x", "exact")).await;
        assert!(t.starts_with("not requested") && t.contains("never be allowed"), "{t}");
        let (t, _) = call("request_access", access("/other/a", "exact")).await;
        let exact = t.split_whitespace().nth(1).unwrap().trim_end_matches(':').to_string();
        assert!(t.starts_with("queued: q-"), "{t}");
        let (t, _) = call("request_access", access("/ok/a", "prefix")).await;
        let prefix = t.split_whitespace().nth(1).unwrap().trim_end_matches(':').to_string();
        assert!(t.starts_with("queued: q-") && prefix != exact, "a prefix ask is its own request: {t}");
        assert!(node.queue.get(&prefix).unwrap().prefix);
        let (t, _) = call("request_capacity", serde_json::json!({ "vcpus": 2 })).await;
        let cap = t.split(" as ").nth(1).unwrap().split(' ').next().unwrap().trim_end_matches(';').to_string();
        assert!(cap.starts_with("q-"), "{t}");
        let (t, _) = call("await_grant", serde_json::json!({ "request_id": exact, "timeout_seconds": 5 })).await;
        assert!(t.starts_with("pending:") && t.contains("unreachable"), "{t}");
        let (t, _) = call("pending_requests", serde_json::json!({})).await;
        assert!(t.contains(&exact) && t.contains(&prefix) && t.contains(&cap), "{t}");
        // Back: the asks are raised (the prefix one as such, in the agent's words), and the call made.
        let mut c = connect_run(&node, 2, &inst, RUN).await;
        c.write_all(&Frame::Msg(Msg::Resume { run: RUN.into(), stdout_from: 0, stderr_from: 0 }).encode()).await.unwrap();
        let (mut asks, mut made) = (vec![], None);
        while asks.len() < 2 || made.is_none() {
            match next_msg(&mut c).await {
                Frame::Msg(Msg::Ask { id, queued: Some((q, _)), prefix: p, why, .. }) => {
                    assert!(why.starts_with(crate::noderun::AGENT_ASKS), "{why}");
                    assert_eq!(p, q == prefix);
                    let rid = format!("r-{}", asks.len() + 1);
                    c.write_all(&Frame::Msg(Msg::Asked { id, pending: Some((rid.clone(), true)), denied: None, error: None }).encode())
                        .await
                        .unwrap();
                    asks.push((q, rid));
                }
                Frame::Msg(Msg::TunnelOpen { stream, target, .. }) if target == "gateway" => {
                    made = Some(answer_tool(&mut c, stream, "requested: r-cap for 2 vcpus").await);
                }
                _ => {}
            }
        }
        assert_eq!(made.unwrap().0, "request_capacity");
        let rid = asks.iter().find(|(q, _)| *q == exact).unwrap().1.clone();
        // await_grant on the node-local id follows the request it became, read on the control host.
        let waiting = tokio::spawn(call("await_grant", serde_json::json!({ "request_id": exact, "timeout_seconds": 5 })));
        let (name, args) = loop {
            if let Frame::Msg(Msg::TunnelOpen { stream, .. }) = next_msg(&mut c).await {
                break answer_tool(&mut c, stream, "granted: it was approved").await;
            }
        };
        assert_eq!((name.as_str(), args["request_id"].as_str()), ("await_grant", Some(rid.as_str())));
        let (t, _) = waiting.await.unwrap();
        assert!(t.contains(&format!("{exact} became {rid}")) && t.contains("granted"), "{t}");
        let (t, _) = call("await_grant", serde_json::json!({ "request_id": cap, "timeout_seconds": 5 })).await;
        assert!(t.contains("r-cap"), "{t}");
        assert!(node.queue.of(RUN).is_empty());
        // Tools the node doesn't decide are the control host's.
        assert!(gw::tool(&node, RUN, "send_message", &serde_json::json!({})).await.is_none());
    }

    /// #164: cut off, a message between two boxes on one node is decided there from both tokens
    /// (a zone that accepts the sender's, else refused), delivered there, attested by the node, and
    /// recorded in its audit log; one to a box elsewhere waits for the control host.
    #[tokio::test]
    async fn the_node_delivers_messages_between_its_boxes_while_cut_off() {
        const A: &str = "run_aaaaaaaaaaaaaaaaaaaaaaaaaa";
        const B: &str = "run_bbbbbbbbbbbbbbbbbbbbbbbbbb";
        const C: &str = "run_cccccccccccccccccccccccccc";
        let inst = Install::new("nodesrv-msg");
        let node = test_node(&inst);
        fed_boxes(&node, &inst, &[(A, "name: za\n"), (B, "name: zb\naccept_from: [za]\n"), (C, "name: zc\n")]);
        let call = |run: &'static str, name: &'static str, args: serde_json::Value| {
            let node = node.clone();
            async move { gw::tool(&node, run, name, &args).await.expect("decided on the node") }
        };
        let (t, err) = call(A, "send_message", serde_json::json!({ "to": B, "body": { "hello": 1 } })).await;
        assert!(!err && t.starts_with("sent m-node-") && t.contains("attested by the node"), "{t}");
        let (t, err) = call(A, "send_message", serde_json::json!({ "to": C, "body": {} })).await;
        assert!(err && t.contains("does not accept messages from zone za"), "{t}");
        let (t, err) = call(A, "send_message", serde_json::json!({ "to": "run_zzzzzzzzzzzzzzzzzzzzzzzzzz", "body": {} })).await;
        assert!(err && t.contains("isn't on your node"), "{t}");
        let (t, _) = call(B, "await_message", serde_json::json!({ "timeout_seconds": 1 })).await;
        let v: serde_json::Value = serde_json::from_str(&t).unwrap();
        assert_eq!((v["from"]["run"].as_str(), v["body"]["hello"].as_i64()), (Some(A), Some(1)), "{t}");
        assert_eq!(v["from"]["verified_by"], "node n1");
        let (t, _) = call(B, "await_message", serde_json::json!({ "timeout_seconds": 1 })).await;
        assert!(t.starts_with("no message"), "taken once: {t}");
        let audit = node.audit.lock().unwrap().audit_tail(50).unwrap();
        assert!(audit.iter().any(|r| r.2 == "node.message"), "{audit:?}");
    }
}
