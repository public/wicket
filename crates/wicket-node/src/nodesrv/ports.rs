//! Published host ports (#575 step 4c; design in `docs/explanation/box-dns.md`, "Host ports"):
//! the node listens on the host ports its boxes' public names were given, and copies each
//! connection's bytes into the box's own port.
//!
//! **Layer 4 only.** A byte relay, as a link's far end is: no TLS is terminated, no protocol is
//! read, nothing is routed by name, and nothing passes through the control host. What the node
//! decides is only whether to take a connection, and whether to keep it.
//!
//! **Decided here, from the feed.** Every [`TICK`] the node reads its replica: a port is open while
//! the box's authority holds on this node (the replica fresh or offline, as every decision the
//! node makes needs; unexpired, unrevoked), the port's own end hasn't passed, it is in this node's
//! range ([`PUBLISH_FILE`]), and exactly one box claims it. Otherwise it is closed, its connections
//! with it. So a port closes within a tick of the node's feed dropping it or revoking the box, and
//! when the box's authority or the port's own end passes: the latter also while the control host
//! is out of reach (a node cut off from it can't hear of a revocation). Without the file the node
//! publishes nothing.
//!
//! **What is recorded,** as node audit records shipped to the control host:
//! `name.port.opened`, `name.port.closed` (with why), `name.port.failed` (a port it couldn't bind,
//! once until it binds, filed under each claiming run), and `name.conn` per connection (the peer,
//! bytes each way, how long, whether the port's end cut it), or one aggregate `name.conn` per tick
//! when more than [`CONN_RECORDS`] ended in it. Connections let go without a relay (over a limit,
//! silent past [`FIRST_BYTE`], or a relay that couldn't start) are counted in `name.conn.refused`.
//!
//! **Limits** (#796 review, H2): per port ([`MAX_CONNS`], [`MAX_NEW_PER_TICK`]), per peer address
//! on a port ([`MAX_PER_PEER`]), and over the node ([`MAX_NODE_EXECS`], [`MAX_NODE_NEW_PER_TICK`]),
//! all checked before anything costs more; no exec is spawned before a connection's first byte, and
//! one idle for [`IDLE`] is closed.

use super::*;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

/// The file, in the node's directory, that says which host ports it may publish:
/// `{"ports": "20000-20999"}`. Written by `wicket node install` from `names.public.ports` for a
/// node with the `names.public.nodes` labels; the node's firewall admits the same range.
pub const PUBLISH_FILE: &str = "publish.json";
/// How often the node looks again at what it publishes.
pub const TICK: Duration = Duration::from_secs(2);
/// The most connections one name's port holds at once.
pub const MAX_CONNS: usize = 64;
/// The most new connections one name's port takes per [`TICK`]: each costs a `docker exec` and an
/// audit record, and the internet can make them as fast as it likes.
pub const MAX_NEW_PER_TICK: u64 = 128;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishSettings {
    ports: String,
}

/// The host ports this node may publish, from [`PUBLISH_FILE`] in `dir`: none without it, or with
/// one it can't read (said once by the caller).
pub fn publish_range(dir: &std::path::Path) -> Result<Option<std::ops::RangeInclusive<u16>>, String> {
    let p = dir.join(PUBLISH_FILE);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", p.display())),
    };
    let s: PublishSettings = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
    let bad = || format!("{}: ports {:?} is not low-high, from 1024", p.display(), s.ports);
    let (a, b) = s.ports.split_once('-').ok_or_else(bad)?;
    let (a, b) = (a.trim().parse::<u16>().map_err(|_| bad())?, b.trim().parse::<u16>().map_err(|_| bad())?);
    if a < 1024 || a > b {
        return Err(bad());
    }
    // Never one of wicket's own ports (#796 review, M2): a box's name would take it from wicket.
    if let Some(w) = wicket_names::WICKET_PORTS.iter().find(|w| (a..=b).contains(*w)) {
        return Err(format!("{}: ports {:?} holds {w}, one of wicket's own ports", p.display(), s.ports));
    }
    Ok(Some(a..=b))
}

/// What one port, and the node over all its ports, takes (#796 review, H2): the internet can open
/// connections as fast as it likes, from as few addresses as it likes, and each one that gets as far
/// as the box costs a `docker exec` and an audit record. Cheap checks come first: nothing here
/// spawns anything, or takes the replica's lock, for a connection a limit already refuses.
#[derive(Clone, Debug)]
pub(super) struct Limits {
    /// The most connections one port holds at once ([`MAX_CONNS`]).
    pub max_conns: usize,
    /// The most new connections one port takes per [`TICK`] ([`MAX_NEW_PER_TICK`]).
    pub max_new_per_tick: u64,
    /// The most connections one peer address holds at once on one port.
    pub per_peer: usize,
    /// How long a connection may send nothing before it is closed, with no exec spawned for it.
    pub first_byte: Duration,
    /// How long a connection may carry no bytes either way before it is closed.
    pub idle: Duration,
    /// The most `docker exec` relays the node runs at once, over all its ports.
    pub node_execs: usize,
    /// The most new `docker exec` relays the node starts per [`TICK`], over all its ports.
    pub node_new_per_tick: u64,
    /// The most `name.conn` records one port writes per [`TICK`]: past it, that tick's connections
    /// are recorded as one aggregate record instead.
    pub conn_records: usize,
}

/// The most connections one peer address holds at once on one port.
pub const MAX_PER_PEER: usize = 8;
/// How long a connection may send nothing before it is closed (no exec is spawned until it does).
pub const FIRST_BYTE: Duration = Duration::from_secs(10);
/// How long a connection may carry no bytes either way before it is closed.
pub const IDLE: Duration = Duration::from_secs(5 * 60);
/// The most relays (`docker exec`s) the node runs at once, over all its ports.
pub const MAX_NODE_EXECS: usize = 256;
/// The most new relays the node starts per [`TICK`], over all its ports.
pub const MAX_NODE_NEW_PER_TICK: u64 = 256;
/// The most `name.conn` records one port writes per [`TICK`] before it aggregates.
pub const CONN_RECORDS: usize = 20;

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_conns: MAX_CONNS,
            max_new_per_tick: MAX_NEW_PER_TICK,
            per_peer: MAX_PER_PEER,
            first_byte: FIRST_BYTE,
            idle: IDLE,
            node_execs: MAX_NODE_EXECS,
            node_new_per_tick: MAX_NODE_NEW_PER_TICK,
            conn_records: CONN_RECORDS,
        }
    }
}

/// The node's relays over all its ports (#796 review, H2): one per [`Published`], which is one per
/// node.
#[derive(Default)]
struct Execs {
    live: AtomicUsize,
    /// Started since the last [`tick`].
    new: AtomicU64,
}

impl Execs {
    fn full(&self, l: &Limits) -> bool {
        self.live.load(Ordering::SeqCst) >= l.node_execs || self.new.load(Ordering::SeqCst) >= l.node_new_per_tick
    }

    /// A relay's place, if the node has one: given back when the returned guard drops.
    fn take(self: &Arc<Self>, l: &Limits) -> Option<ExecSlot> {
        self.live.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < l.node_execs).then_some(n + 1)).ok()?;
        if self.new.fetch_add(1, Ordering::SeqCst) >= l.node_new_per_tick {
            self.live.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ExecSlot(self.clone()))
    }
}

struct ExecSlot(Arc<Execs>);

impl Drop for ExecSlot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One port a box claims, as its record in the feed has it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Claim {
    run: String,
    name: String,
    label: String,
    box_port: u16,
    until_ms: i64,
}

/// One open port: its claim, its task, and what its connections record.
struct Open {
    claim: Claim,
    task: tokio::task::JoinHandle<()>,
    log: Arc<PortLog>,
}

/// What the node publishes now: a task per open port.
#[derive(Default)]
pub struct Published {
    open: HashMap<u16, Open>,
    /// Ports just closed, until their task has let go of the listener: not opened again before.
    closing: HashMap<u16, tokio::task::JoinHandle<()>>,
    /// Ports whose bind failed, with the claim: recorded once until it binds or goes.
    failed: HashSet<(u16, String)>,
    /// Ports more than one box claims, with each claiming run: recorded once for each.
    contested: HashSet<(u16, String)>,
    /// Claims this node won't publish (outside its range, or no range at all), recorded once.
    skipped: HashSet<(u16, String)>,
    /// Whether the node has said it listens on IPv4 alone (L4: said once, recorded per port).
    said_v4_only: bool,
    execs: Arc<Execs>,
    pub(super) limits: Arc<Limits>,
}

/// Whether box `run`'s authority holds in `r` at `now`, as every decision the node makes requires
/// (`Replica::gate` and the token's own checks; #796 review, M1): the replica fresh or offline (not
/// lagging, not closed), the run not revoked, its token valid (a revoked block makes it invalid),
/// the issuing key that minted it still certified, and the token unexpired.
fn authority_holds(r: &Replica<BoxAuthority>, run: &str, now: i64) -> bool {
    if !matches!(r.mode(now), wicket_feed::Mode::Fresh | wicket_feed::Mode::Offline) {
        return false;
    }
    let Some(st) = r.state() else { return false };
    if st.is_revoked(wicket_feed::RevokeKind::Run, run) {
        return false;
    }
    let Some(Ok(c)) = st.zones.get(run).map(|z| &z.compiled) else { return false };
    if c.issuer_until.is_some_and(|u| now >= u) {
        return false;
    }
    r.authority_until(run).is_some_and(|u| u > now)
}

/// The ports the replica says to publish now, by host port, and those more than one box claims.
fn wanted(node: &Node, range: Option<&std::ops::RangeInclusive<u16>>) -> Wanted {
    let now = (node.clock)();
    let r = node.replica.lock().expect("replica");
    let mut by_port: HashMap<u16, Vec<Claim>> = HashMap::new();
    // No state yet (a node not yet fed): nothing published.
    let Some(state) = r.state() else { return Wanted::default() };
    let mut skipped = vec![];
    for (run, a) in &state.zones {
        if a.spec.ports.is_empty() || !authority_holds(&r, run, now) {
            continue;
        }
        for p in &a.spec.ports {
            let sound = p.until_ms > now && p.host_port >= 1024 && p.box_port != 0 && wicket_names::check_shape(&p.label, true).is_ok();
            if !sound {
                continue;
            }
            let why = match range {
                None => Some(format!("this node publishes no host ports (no {PUBLISH_FILE} in its directory)")),
                Some(r) if !r.contains(&p.host_port) => Some(format!("outside this node's range {}-{}", r.start(), r.end())),
                Some(_) => None,
            };
            if let Some(why) = why {
                skipped.push((run.clone(), p.host_port, p.name.clone(), p.label.clone(), why));
                continue;
            }
            by_port.entry(p.host_port).or_default().push(Claim {
                run: run.clone(),
                name: p.name.clone(),
                label: p.label.clone(),
                box_port: p.box_port,
                until_ms: p.until_ms,
            });
        }
    }
    let contested = by_port.iter().filter(|(_, c)| c.len() > 1).map(|(p, c)| (*p, c.clone())).collect();
    let one = by_port.into_iter().filter(|(_, c)| c.len() == 1).map(|(p, mut c)| (p, c.remove(0))).collect();
    Wanted { one, contested, skipped }
}

/// What the replica says to publish now.
#[derive(Default)]
struct Wanted {
    /// By host port, the ports one box claims.
    one: HashMap<u16, Claim>,
    /// Ports more than one box claims, with the claims.
    contested: HashMap<u16, Vec<Claim>>,
    /// Claims this node won't publish: `(run, port, name, label, why)`.
    skipped: Vec<(String, u16, String, String, String)>,
}

/// One look (see the module's documentation): closes what shouldn't be open, opens what should.
pub fn tick(node: &Arc<Node>, range: Option<&std::ops::RangeInclusive<u16>>, st: &mut Published) {
    // The node-wide count of new relays is per tick (H2).
    st.execs.new.store(0, Ordering::SeqCst);
    let Wanted { one: want, contested, skipped } = wanted(node, range);
    let now_skipped: HashSet<(u16, String)> = skipped.iter().map(|(run, p, ..)| (*p, run.clone())).collect();
    for (run, port, name, label, why) in &skipped {
        if !st.skipped.contains(&(*port, run.clone())) {
            node.audit_note(run, "name.port.failed", serde_json::json!({ "name": name, "label": label, "port": port, "why": why }));
        }
    }
    st.skipped = now_skipped;
    // A contested port is filed under each run that claims it, so each tenant sees why its name
    // has no port (#796 review, M4).
    let mut now_contested = HashSet::new();
    for (port, claims) in &contested {
        let runs: Vec<&str> = claims.iter().map(|c| c.run.as_str()).collect();
        for c in claims {
            let key = (*port, c.run.clone());
            if !st.contested.contains(&key) && !now_contested.contains(&key) {
                let body = serde_json::json!({ "name": c.name, "label": c.label, "port": port, "runs": runs, "why": "more than one box claims it: none gets it" });
                node.audit_note(&c.run, "name.port.failed", body);
            }
            now_contested.insert(key);
        }
    }
    st.contested = now_contested;
    let close: Vec<u16> = st
        .open
        .iter()
        .filter(|(port, o)| {
            let c = &o.claim;
            o.task.is_finished() || want.get(port).is_none_or(|w| w.run != c.run || w.name != c.name || w.box_port != c.box_port)
        })
        .map(|(p, _)| *p)
        .collect();
    for port in close {
        if let Some(o) = st.open.remove(&port) {
            // Its live connections are recorded as cut before the task (and they) go (M4): an
            // aborted task runs no more code of its own.
            o.log.close();
            o.task.abort();
            let c = &o.claim;
            let why = match want.get(&port) {
                Some(_) => "its claim changed",
                None => "its name or its box's authority ended here",
            };
            node.audit_note(&c.run, "name.port.closed", serde_json::json!({ "name": c.name, "label": c.label, "port": port, "why": why }));
            st.closing.insert(port, o.task);
        }
    }
    st.closing.retain(|_, h| !h.is_finished());
    st.failed.retain(|(p, run)| want.get(p).is_some_and(|w| &w.run == run));
    for (port, c) in want {
        if st.open.contains_key(&port) || st.closing.contains_key(&port) {
            continue;
        }
        match bind(port) {
            Ok((l, v4_only)) => {
                st.failed.remove(&(port, c.run.clone()));
                let mut body = serde_json::json!({ "name": c.name, "label": c.label, "port": port, "box_port": c.box_port });
                if v4_only {
                    // L4: a node without IPv6 publishes on IPv4 alone; said once, recorded per port.
                    if !st.said_v4_only {
                        st.said_v4_only = true;
                        say_err!("[node] can't listen on IPv6 (turned off?): host ports for public names listen on IPv4 alone");
                    }
                    body["ipv4_only"] = true.into();
                }
                node.audit_note(&c.run, "name.port.opened", body);
                let log = Arc::new(PortLog::new(node.clone(), c.clone(), port, st.limits.clone()));
                let task = tokio::spawn(serve(node.clone(), l, c.clone(), log.clone(), st.execs.clone()));
                st.open.insert(port, Open { claim: c, task, log });
            }
            Err(e) => {
                if st.failed.insert((port, c.run.clone())) {
                    say_err!("[node] {}: can't listen on host port {port} for {}: {e}", c.run, c.label);
                    node.audit_note(
                        &c.run,
                        "name.port.failed",
                        serde_json::json!({ "name": c.name, "label": c.label, "port": port, "why": e.to_string() }),
                    );
                }
            }
        }
    }
}

/// Whether a failed dual-stack bind should be tried again on IPv4 alone: not when the port is
/// taken (IPv4 would be too), only when IPv6 itself is the trouble (turned off, no such family).
fn falls_back_to_v4(e: &std::io::Error) -> bool {
    e.kind() != std::io::ErrorKind::AddrInUse
}

/// A listener on every address of the node at `port`: one IPv6 socket that takes IPv4 too.
/// On a node with IPv6 turned off, an IPv4 socket (and true: said by the caller, L4).
fn bind(port: u16) -> std::io::Result<(tokio::net::TcpListener, bool)> {
    let dual = || -> std::io::Result<socket2::Socket> {
        let s = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        s.set_only_v6(false)?;
        s.set_reuse_address(true)?;
        s.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
        Ok(s)
    };
    let v4 = || -> std::io::Result<socket2::Socket> {
        let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        s.set_reuse_address(true)?;
        s.bind(&SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)).into())?;
        Ok(s)
    };
    let (s, v4_only) = match dual() {
        Ok(s) => (s, false),
        Err(e) if !falls_back_to_v4(&e) => return Err(e),
        Err(_) => (v4()?, true),
    };
    s.set_nonblocking(true)?;
    s.listen(128)?;
    Ok((tokio::net::TcpListener::from_std(s.into())?, v4_only))
}

/// A peer's address without its IPv6 mapping: the address limits count by, and records name.
fn canonical(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, a.port())),
            None => a,
        },
        _ => a,
    }
}

/// A peer's address as recorded: an IPv4 one without its IPv6 mapping.
fn peer(a: SocketAddr) -> String {
    canonical(a).to_string()
}

/// Whether `c` may still be published: its box's authority holds here ([`authority_holds`]), and
/// the box's record as the replica has it now still carries the port, unexpired (a renewed name's
/// new end counts).
fn held(node: &Node, c: &Claim) -> bool {
    let now = (node.clock)();
    let r = node.replica.lock().expect("replica");
    let listed = r
        .state()
        .and_then(|s| s.zones.get(&c.run))
        .is_some_and(|z| z.spec.ports.iter().any(|p| p.name == c.name && p.box_port == c.box_port && p.until_ms > now));
    listed && authority_holds(&r, &c.run, now)
}

/// A live connection's counts, read when it ends, however it ends.
struct ConnStats {
    peer: SocketAddr,
    started: std::time::Instant,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// When bytes last moved either way, in ms since `started`.
    last_ms: AtomicU64,
}

impl ConnStats {
    fn moved(&self, n: &AtomicU64, k: usize) {
        n.fetch_add(k as u64, Ordering::SeqCst);
        self.last_ms.store(self.started.elapsed().as_millis() as u64, Ordering::SeqCst);
    }
}

/// Why a connection was let go without a relay.
#[derive(Debug)]
enum Dropped {
    /// Over the port's own limits.
    Port,
    /// Over its peer's limit.
    Peer,
    /// Over the node's relays.
    Node,
    /// It sent nothing within [`Limits::first_byte`] (or closed first).
    Silent,
    /// Its relay couldn't start (no running box, or `docker exec` failed to spawn).
    Failed,
}

#[derive(Default)]
struct Counts {
    port: u64,
    peer: u64,
    node: u64,
    silent: u64,
    failed: u64,
}

/// One ended connection, for its `name.conn` record.
struct Ended {
    ip: std::net::IpAddr,
    peer: String,
    bytes_in: u64,
    bytes_out: u64,
    ms: u64,
    cut: bool,
}

/// This tick's ended connections past [`Limits::conn_records`], as totals.
#[derive(Default)]
struct Folded {
    conns: u64,
    cut: u64,
    bytes_in: u64,
    bytes_out: u64,
    peers: HashSet<std::net::IpAddr>,
}

#[derive(Default)]
struct LogState {
    next: u64,
    live: HashMap<u64, Arc<ConnStats>>,
    peers: HashMap<std::net::IpAddr, usize>,
    /// This tick's ended connections, one by one while there are few.
    ended: Vec<Ended>,
    /// Or, once there are more, all of them as totals (H2).
    folded: Folded,
    dropped: Counts,
    /// Closed: its live connections are recorded as cut, and nothing more is taken.
    closed: bool,
}

/// What one port's connections record, shared by its task, its connections and [`tick`]. Whoever
/// takes a connection out of `live`, under the lock, records it: the connection as it ends, or
/// [`PortLog::close`] for those still live (cut), so each is recorded once however the port ends
/// (#796 review, M4).
struct PortLog {
    node: Arc<Node>,
    claim: Claim,
    port: u16,
    limits: Arc<Limits>,
    st: Mutex<LogState>,
}

impl PortLog {
    fn new(node: Arc<Node>, claim: Claim, port: u16, limits: Arc<Limits>) -> Self {
        PortLog { node, claim, port, limits, st: Mutex::new(LogState::default()) }
    }

    /// Counts a connection let go before it was taken.
    fn refuse(&self, why: Dropped) {
        let mut st = self.st.lock().expect("port log");
        let d = &mut st.dropped;
        match why {
            Dropped::Port => d.port += 1,
            Dropped::Peer => d.peer += 1,
            Dropped::Node => d.node += 1,
            Dropped::Silent => d.silent += 1,
            Dropped::Failed => d.failed += 1,
        }
    }

    /// Takes a connection from `from`, if its peer is under its limit (checked with the port's
    /// own, before anything costs more): its id and counts.
    fn take(&self, from: SocketAddr) -> Result<(u64, Arc<ConnStats>), Dropped> {
        let mut st = self.st.lock().expect("port log");
        if st.closed || st.live.len() >= self.limits.max_conns {
            return Err(Dropped::Port);
        }
        let ip = from.ip();
        if st.peers.get(&ip).copied().unwrap_or(0) >= self.limits.per_peer {
            return Err(Dropped::Peer);
        }
        *st.peers.entry(ip).or_default() += 1;
        st.next += 1;
        let id = st.next;
        let stats = Arc::new(ConnStats {
            peer: from,
            started: std::time::Instant::now(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            last_ms: AtomicU64::new(0),
        });
        st.live.insert(id, stats.clone());
        Ok((id, stats))
    }

    /// Lets go of a taken connection that never got a relay: counted, not recorded one by one.
    fn let_go(&self, id: u64, why: Dropped) {
        let mut st = self.st.lock().expect("port log");
        if let Some(s) = st.live.remove(&id) {
            Self::unpeer(&mut st, s.peer.ip());
            drop(st);
            self.refuse(why);
        }
    }

    /// A relayed connection's end: recorded, unless [`PortLog::close`] recorded it already.
    fn end(&self, id: u64) {
        let mut st = self.st.lock().expect("port log");
        if let Some(s) = st.live.remove(&id) {
            Self::unpeer(&mut st, s.peer.ip());
            self.ended(&mut st, &s, false);
        }
    }

    fn unpeer(st: &mut LogState, ip: std::net::IpAddr) {
        if let Some(n) = st.peers.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                st.peers.remove(&ip);
            }
        }
    }

    fn ended(&self, st: &mut LogState, s: &ConnStats, cut: bool) {
        let e = Ended {
            ip: s.peer.ip(),
            peer: peer(s.peer),
            bytes_in: s.bytes_in.load(Ordering::SeqCst),
            bytes_out: s.bytes_out.load(Ordering::SeqCst),
            ms: s.started.elapsed().as_millis() as u64,
            cut,
        };
        let fold = |f: &mut Folded, e: &Ended| {
            f.conns += 1;
            f.cut += u64::from(e.cut);
            f.bytes_in += e.bytes_in;
            f.bytes_out += e.bytes_out;
            f.peers.insert(e.ip);
        };
        if st.folded.conns == 0 && st.ended.len() < self.limits.conn_records {
            st.ended.push(e);
            return;
        }
        // Past the per-tick records: this tick's connections become one aggregate (H2).
        for old in std::mem::take(&mut st.ended) {
            fold(&mut st.folded, &old);
        }
        fold(&mut st.folded, &e);
    }

    /// Writes this tick's records: each ended connection (`name.conn`), or one aggregate of them
    /// when there were more than [`Limits::conn_records`], and what was let go
    /// (`name.conn.refused`).
    fn flush(&self) {
        let (ended, folded, d) = {
            let mut st = self.st.lock().expect("port log");
            (std::mem::take(&mut st.ended), std::mem::take(&mut st.folded), std::mem::take(&mut st.dropped))
        };
        let c = &self.claim;
        for e in ended {
            let mut body = serde_json::json!({
                "name": c.name, "label": c.label, "port": self.port, "peer": e.peer,
                "bytes_in": e.bytes_in, "bytes_out": e.bytes_out, "ms": e.ms,
            });
            if e.cut {
                body["cut"] = true.into();
            }
            self.node.audit_note(&c.run, "name.conn", body);
        }
        if folded.conns > 0 {
            self.node.audit_note(
                &c.run,
                "name.conn",
                serde_json::json!({
                    "name": c.name, "label": c.label, "port": self.port, "aggregate": true,
                    "conns": folded.conns, "cut": folded.cut, "bytes_in": folded.bytes_in, "bytes_out": folded.bytes_out,
                    "peers": folded.peers.len(),
                }),
            );
        }
        let refused = d.port + d.peer + d.node;
        if refused + d.silent + d.failed > 0 {
            let l = &self.limits;
            self.node.audit_note(
                &c.run,
                "name.conn.refused",
                serde_json::json!({
                    "name": c.name, "label": c.label, "port": self.port,
                    "refused": refused, "over_port": d.port, "over_peer": d.peer, "over_node": d.node,
                    "silent": d.silent, "failed": d.failed,
                    "max_conns": l.max_conns, "max_new_per_tick": l.max_new_per_tick, "max_per_peer": l.per_peer,
                }),
            );
        }
    }

    /// The port's end: its live connections recorded as cut, and everything written.
    fn close(&self) {
        {
            let mut st = self.st.lock().expect("port log");
            if st.closed {
                return;
            }
            st.closed = true;
            st.peers.clear();
            let live: Vec<Arc<ConnStats>> = std::mem::take(&mut st.live).into_values().collect();
            for s in live {
                self.ended(&mut st, &s, true);
            }
        }
        self.flush();
    }
}

/// A taken connection, given back to its port's log however its task ends (an abort included).
struct Taken(Arc<PortLog>, u64);

impl Drop for Taken {
    fn drop(&mut self) {
        self.0.end(self.1);
    }
}

/// Copies `r` to `w` until `r` ends, counting into `n` (and when bytes last moved).
async fn pump<R, W>(r: &mut R, w: &mut W, s: &ConnStats, n: &AtomicU64) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let k = r.read(&mut buf).await?;
        if k == 0 {
            return Ok(());
        }
        w.write_all(&buf[..k]).await?;
        s.moved(n, k);
    }
}

/// Takes connections on `l` for claim `c` until it no longer holds (checked every [`TICK`]): each is
/// dialed into the box at its port and the bytes copied both ways. Ends, aborting its
/// connections (recorded as cut, M4), when it no longer holds or the manager aborts it.
async fn serve(node: Arc<Node>, l: tokio::net::TcpListener, c: Claim, log: Arc<PortLog>, execs: Arc<Execs>) {
    let mut conns = tokio::task::JoinSet::new();
    let mut taken_this_tick = 0u64;
    let mut tick = tokio::time::interval(TICK);
    loop {
        tokio::select! {
            a = l.accept() => {
                // A failed accept (a peer gone mid-handshake, out of descriptors) isn't the port's
                // end: the next one may work.
                let Ok((s, from)) = a else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let from = canonical(from);
                // The cheap limits first, before the replica's lock (H2).
                if taken_this_tick >= log.limits.max_new_per_tick {
                    log.refuse(Dropped::Port);
                    continue;
                }
                if execs.full(&log.limits) {
                    log.refuse(Dropped::Node);
                    continue;
                }
                let (id, stats) = match log.take(from) {
                    Ok(t) => t,
                    Err(why) => {
                        log.refuse(why);
                        continue;
                    }
                };
                let taken = Taken(log.clone(), id);
                if !held(&node, &c) {
                    log.let_go(id, Dropped::Port);
                    drop(taken);
                    break;
                }
                taken_this_tick += 1;
                conns.spawn(relay(node.clone(), s, c.box_port, taken, stats, execs.clone()));
            }
            _ = tick.tick() => {
                taken_this_tick = 0;
                if !held(&node, &c) {
                    break;
                }
                log.flush();
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    log.close();
    conns.abort_all();
}

/// One connection: once its first byte arrives, a `docker exec -i <box> wicket-fwd --dial
/// 127.0.0.1:<box_port>`, and the bytes copied both ways until either side ends or none move for
/// [`Limits::idle`].
///
/// Killing the `docker exec` client (kill_on_drop, or at the idle bound) ends the relay here, but
/// not necessarily the `wicket-fwd` in the box: Docker doesn't kill an exec's process when its
/// client goes. What should end it (inferred from `wicket-fwd`'s source, not measured, and maybe
/// otherwise under gVisor) is its stdin closing with the attach, which half-closes its connection
/// to the box's port; `--dial` then exits once the box's service closes its side. It has no idle
/// bound of its own, so a service that never closes keeps that one process in the box (within the
/// box's own limits, not the node's) until it does (#796 review, H2: a gap, to be bounded in
/// wicket-fwd itself).
async fn relay(node: Arc<Node>, s: tokio::net::TcpStream, box_port: u16, taken: Taken, stats: Arc<ConnStats>, execs: Arc<Execs>) {
    let log = taken.0.clone();
    let limits = log.limits.clone();
    // No exec until the peer has said something: one that sends nothing costs only its socket.
    let mut b = [0u8; 1];
    match tokio::time::timeout(limits.first_byte, s.peek(&mut b)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return log.let_go(taken.1, Dropped::Silent),
    }
    let Some(_slot) = execs.take(&limits) else { return log.let_go(taken.1, Dropped::Node) };
    let found =
        node.boxes.lock().expect("boxes").get(&log.claim.run).filter(|b| b.exited.is_none()).map(|b| (b.name.clone(), b.user.clone()));
    let Some((name, user)) = found else { return log.let_go(taken.1, Dropped::Failed) };
    let child = node
        .docker
        .exec(&name, &user, &["-i"], &["wicket-fwd".to_string(), "--dial".into(), format!("127.0.0.1:{box_port}")])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = child else { return log.let_go(taken.1, Dropped::Failed) };
    if let (Some(mut w), Some(mut r)) = (child.stdin.take(), child.stdout.take()) {
        let (mut cr, mut cw) = s.into_split();
        let st = &stats;
        let up = async {
            let _ = pump(&mut cr, &mut w, st, &st.bytes_in).await;
            drop(w);
        };
        let down = async {
            let _ = pump(&mut r, &mut cw, st, &st.bytes_out).await;
            let _ = cw.shutdown().await;
        };
        let idle = async {
            loop {
                let since = st.started.elapsed().saturating_sub(Duration::from_millis(st.last_ms.load(Ordering::SeqCst)));
                if since >= limits.idle {
                    return;
                }
                tokio::time::sleep(limits.idle - since).await;
            }
        };
        tokio::select! {
            _ = async { tokio::join!(up, down) } => {}
            _ = idle => {}
        }
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
    drop(taken);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_publish_file_says_the_range_or_nothing() {
        let d = std::env::temp_dir().join(format!("wicket-publish-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(publish_range(&d), Ok(None), "no file: nothing published");
        std::fs::write(d.join(PUBLISH_FILE), r#"{"ports":"20000-20999"}"#).unwrap();
        assert_eq!(publish_range(&d), Ok(Some(20000..=20999)));
        for bad in [
            r#"{"ports":"8000-9000"}"#,
            r#"{"ports":"80-443"}"#,
            r#"{"ports":"21000-20000"}"#,
            r#"{"ports":"x"}"#,
            r#"{"ports":"1-2","extra":1}"#,
        ] {
            std::fs::write(d.join(PUBLISH_FILE), bad).unwrap();
            assert!(publish_range(&d).is_err(), "{bad}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_peer_is_recorded_without_its_ipv6_mapping() {
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:5000".parse().unwrap();
        assert_eq!(peer(mapped), "192.0.2.7:5000");
        let v6: SocketAddr = "[2001:db8::1]:5000".parse().unwrap();
        assert_eq!(peer(v6), "[2001:db8::1]:5000");
        // Limits count the mapped and plain forms as one address (H2).
        assert_eq!(canonical(mapped).ip(), "192.0.2.7".parse::<std::net::IpAddr>().unwrap());
    }

    /// H2, M4: whoever takes a connection out records it once; more ended in a tick than
    /// `conn_records` are one aggregate record, and those cut by the port's end are counted.
    #[test]
    fn many_ends_in_a_tick_are_one_aggregate_record() {
        let inst = crate::nodeauth::testkit::Install::new("ports-aggregate");
        let node = super::super::tests::test_node(&inst);
        let claim = Claim { run: "run_agg".into(), name: "n-0".into(), label: "demo".into(), box_port: 3000, until_ms: i64::MAX };
        let limits = Arc::new(Limits { conn_records: 2, per_peer: 3, ..Limits::default() });
        let log = PortLog::new(node.clone(), claim, 20999, limits);
        let kinds = || -> Vec<(String, serde_json::Value)> {
            let rows = node.audit.lock().unwrap().audit_tail(100).unwrap();
            rows.into_iter().filter(|r| r.2.starts_with("name.conn")).map(|r| (r.2, serde_json::from_str(&r.4).unwrap())).collect()
        };
        let from = |n: u8| -> SocketAddr { format!("192.0.2.{n}:4000").parse().unwrap() };
        // Two ends: one record each.
        for n in [1, 2] {
            let (id, s) = log.take(from(n)).unwrap();
            s.moved(&s.bytes_in, 3);
            log.end(id);
        }
        log.flush();
        assert_eq!(kinds().len(), 2, "{:?}", kinds());
        // Three ends, two from one address: one aggregate.
        for n in [1, 1, 2] {
            let (id, s) = log.take(from(n)).unwrap();
            s.moved(&s.bytes_out, 5);
            log.end(id);
            log.end(id); // a second end of the same connection records nothing
        }
        log.flush();
        let k = kinds();
        assert_eq!(k.len(), 3, "{k:?}");
        let agg = &k[2].1;
        assert_eq!(
            (agg["aggregate"].clone(), agg["conns"].clone(), agg["peers"].clone(), agg["bytes_out"].clone()),
            (true.into(), 3.into(), 2.into(), 15.into()),
            "{agg}"
        );
        // The per-peer cap, and the port's end recording what it cuts (and taking no more).
        let held: Vec<_> = (0..3).map(|_| log.take(from(9)).unwrap()).collect();
        assert!(matches!(log.take(from(9)), Err(Dropped::Peer)));
        log.refuse(Dropped::Peer);
        log.close();
        for (id, _) in &held {
            log.end(*id);
        }
        assert!(matches!(log.take(from(8)), Err(Dropped::Port)), "closed");
        let k = kinds();
        // Three cut, past the two records: one aggregate of them.
        let cut = k.iter().find(|(kind, b)| kind == "name.conn" && b["cut"] == 3).expect("cut");
        assert_eq!((cut.1["conns"].clone(), cut.1["peers"].clone()), (3.into(), 1.into()), "{k:?}");
        let refused = k.iter().find(|(kind, _)| kind == "name.conn.refused").expect("refused");
        assert_eq!(refused.1["over_peer"], 1, "{k:?}");
    }

    /// L4: a port another listener holds is not tried on IPv4 alone (it is taken there too); IPv6
    /// itself failing is.
    #[test]
    fn only_ipv6_trouble_falls_back_to_ipv4() {
        use std::io::{Error, ErrorKind};
        assert!(!falls_back_to_v4(&Error::from(ErrorKind::AddrInUse)));
        assert!(falls_back_to_v4(&Error::from(ErrorKind::AddrNotAvailable)));
        assert!(falls_back_to_v4(&Error::from_raw_os_error(97))); // EAFNOSUPPORT
    }

    /// H2: the node's relays are capped at once and per tick, and a slot is given back on drop.
    #[test]
    fn the_nodes_relays_are_capped() {
        let l = Limits { node_execs: 2, node_new_per_tick: 3, ..Limits::default() };
        let e = Arc::new(Execs::default());
        let (a, b) = (e.take(&l).unwrap(), e.take(&l).unwrap());
        assert!(e.full(&l) && e.take(&l).is_none(), "two at once");
        drop(a);
        let _c = e.take(&l).unwrap();
        drop(b);
        assert!(e.take(&l).is_none(), "three new this tick");
        e.new.store(0, Ordering::SeqCst);
        assert!(e.take(&l).is_some());
    }
}
