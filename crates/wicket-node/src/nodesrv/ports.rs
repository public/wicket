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
//! once until it binds, filed under each claiming run), and `name.conn` twice per connection
//! (#796 re-review, M4): `"phase": "start"` once its relay is running (the peer and a connection id
//! unique across the node's restarts), and `"phase": "end"` with the same id, bytes each way, how
//! long, and `"cut": true` with why when the node ended it (its port closed, [`LIFETIME`], [`IDLE`],
//! [`AFTER_CLOSE`]; #796 review, N2), no `cut` when either side closed. So a connection the node
//! never recorded the end of (it restarted) is still on record, and a long one is visible while it
//! lasts. Records are written each [`TICK`]; past [`CONN_RECORDS`] in one tick, that tick's
//! starts and ends are one aggregate `name.conn` instead. Connections let go without a relay (over
//! a limit, silent past [`FIRST_BYTE`], evicted while waiting for it, or a relay that couldn't
//! start) are counted in `name.conn.refused`.
//!
//! **Limits** (#796 review and re-review, H2): per port ([`MAX_CONNS`], and at most a
//! [`PORT_SHARE`]th of the node's relays; [`MAX_NEW_PER_TICK`]), per peer on a port
//! ([`MAX_PER_PEER`], an IPv6 peer counted by its /64), per peer over the node
//! ([`MAX_NODE_PER_PEER`]), and over the node ([`MAX_NODE_EXECS`], [`MAX_NODE_NEW_PER_TICK`]), all
//! checked before anything costs more. No exec is spawned before a connection's first byte, and
//! connections still waiting for it have their own small caps ([`MAX_WAITING`],
//! [`MAX_WAITING_PER_PEER`]): a newcomer to a full pool evicts its oldest waiter rather than being
//! refused. A relay ends when it carries nothing for [`IDLE`], [`AFTER_CLOSE`] after its peer's
//! half-close with nothing sent to the peer since, and at [`LIFETIME`] whatever it carries; the
//! `wicket-fwd` in the box is given the first two too, so it ends on its own.

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
/// The most connections one name's port holds at once: at most a [`PORT_SHARE`]th of the node's
/// relays ([`Limits::port_cap`]), so no few names hold them all (#796 re-review, H2).
pub const MAX_CONNS: usize = 32;
/// A port holds at most this fraction (1/n) of the node's relays at once: it takes this many names,
/// each at its cap, to fill the node.
pub const PORT_SHARE: usize = 8;
const _: () = assert!(MAX_CONNS <= MAX_NODE_EXECS / PORT_SHARE);
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
    if let Some(w) = wicket_names::own_ports().iter().find(|w| (a..=b).contains(*w)) {
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
    /// The most connections one port holds at once ([`MAX_CONNS`]; see [`Limits::port_cap`]).
    pub max_conns: usize,
    /// The most new connections one port takes per [`TICK`] ([`MAX_NEW_PER_TICK`]).
    pub max_new_per_tick: u64,
    /// The most connections one peer (an IPv4 address, an IPv6 /64) holds at once on one port.
    pub per_peer: usize,
    /// The most relays one peer holds at once over all the node's ports ([`MAX_NODE_PER_PEER`]).
    pub node_per_peer: usize,
    /// How long a connection may send nothing before it is closed, with no exec spawned for it.
    pub first_byte: Duration,
    /// The most connections on one port still waiting for their first byte.
    pub waiting: usize,
    /// The most of those from one peer.
    pub waiting_per_peer: usize,
    /// How long a connection may carry no bytes either way before it is closed.
    pub idle: Duration,
    /// How long a relay may go on after its peer's half-close with nothing sent to the peer.
    pub after_close: Duration,
    /// How long a relay may last, whatever it carries.
    pub lifetime: Duration,
    /// The most `docker exec` relays the node runs at once, over all its ports.
    pub node_execs: usize,
    /// The most new `docker exec` relays the node starts per [`TICK`], over all its ports.
    pub node_new_per_tick: u64,
    /// The most `name.conn` records one port writes per [`TICK`]: past it, that tick's connections
    /// are recorded as one aggregate record instead.
    pub conn_records: usize,
}

/// The most connections one peer holds at once on one port.
pub const MAX_PER_PEER: usize = 8;
/// The most relays one peer holds at once over all the node's ports (#796 review, R1): the per-port
/// cap alone let four addresses hold eight ports' worth, all [`MAX_NODE_EXECS`], for an hour. With
/// this, it takes `MAX_NODE_EXECS / MAX_NODE_PER_PEER` (8) peers to fill the node, while one client
/// still has four ports' worth of [`MAX_PER_PEER`].
pub const MAX_NODE_PER_PEER: usize = 32;
const _: () = assert!(MAX_PER_PEER <= MAX_NODE_PER_PEER && MAX_NODE_PER_PEER <= MAX_NODE_EXECS / PORT_SHARE);
/// How long a connection may send nothing before it is closed (no exec is spawned until it does).
pub const FIRST_BYTE: Duration = Duration::from_secs(10);
/// The most connections on one port waiting for their first byte at once (#796 re-review, H2):
/// half the port's [`MAX_CONNS`], so silent ones never hold the rest, which only connections that
/// spoke can. A client's first bytes follow its handshake at once, so a speaking connection waits
/// here for moments, not seconds. A newcomer to a full pool evicts its oldest waiter (#796 review,
/// R1): refusing it instead let a few peers reconnecting about twice a second keep the pool full
/// and shut the port to everyone, while a speaking connection, gone from the pool within moments,
/// is never the oldest for long.
pub const MAX_WAITING: usize = 16;
const _: () = assert!(MAX_WAITING < MAX_CONNS && MAX_WAITING_PER_PEER <= MAX_WAITING);
/// The most of those from one peer: a browser's burst to one host (six connections at once) must
/// fit, since a burst's connections are all accepted before any is read from. 1 or 2 refused four
/// of six such connections in a local test.
pub const MAX_WAITING_PER_PEER: usize = 6;
/// How long a connection may carry no bytes either way before it is closed.
pub const IDLE: Duration = Duration::from_secs(5 * 60);
/// How long a relay goes on after its peer's half-close, for the box's answer (#796 re-review, H2):
/// a peer that sends a byte and closes doesn't hold a relay for as long as the service ignores it.
/// Counted from the half-close or the last byte sent to the peer since, whichever is later (#796
/// review, N1): a half-closed peer still downloading is not cut while its download flows.
pub const AFTER_CLOSE: Duration = Duration::from_secs(30);
/// How long a relay may last at all (#796 re-review, H2): one byte every few minutes doesn't hold
/// a slot for good. A connection cut here is recorded `cut`, why `lifetime`.
pub const LIFETIME: Duration = Duration::from_secs(60 * 60);
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
            node_per_peer: MAX_NODE_PER_PEER,
            first_byte: FIRST_BYTE,
            waiting: MAX_WAITING,
            waiting_per_peer: MAX_WAITING_PER_PEER,
            idle: IDLE,
            after_close: AFTER_CLOSE,
            lifetime: LIFETIME,
            node_execs: MAX_NODE_EXECS,
            node_new_per_tick: MAX_NODE_NEW_PER_TICK,
            conn_records: CONN_RECORDS,
        }
    }
}

impl Limits {
    /// The most connections one port holds at once (#796 re-review, H2): its own cap, and no more
    /// than a [`PORT_SHARE`]th of the node's relays, so no fewer than that many names fill the node
    /// (at least one, for a node with very few).
    pub fn port_cap(&self) -> usize {
        self.max_conns.min(self.node_execs / PORT_SHARE).max(1)
    }
}

/// The node's relays over all its ports (#796 review, H2): one per [`Published`], which is one per
/// node.
#[derive(Default)]
struct Execs {
    live: AtomicUsize,
    /// Started since the last [`tick`].
    new: AtomicU64,
    /// By [`peer_key`], the relays each peer holds over all the node's ports (#796 review, R1).
    peers: Mutex<HashMap<std::net::IpAddr, usize>>,
}

impl Execs {
    fn full(&self, l: &Limits) -> bool {
        self.live.load(Ordering::SeqCst) >= l.node_execs || self.new.load(Ordering::SeqCst) >= l.node_new_per_tick
    }

    /// Whether peer `key` holds all the relays one peer may over the node (R1): a cheap check
    /// before anything else, as [`Execs::full`]; [`Execs::take`] decides.
    fn peer_full(&self, key: std::net::IpAddr, l: &Limits) -> bool {
        self.peers.lock().expect("execs").get(&key).copied().unwrap_or(0) >= l.node_per_peer
    }

    /// A relay's place for peer `key`, if the node and the peer have one: given back when the
    /// returned guard drops. Otherwise why not.
    fn take(self: &Arc<Self>, l: &Limits, key: std::net::IpAddr) -> Result<ExecSlot, Dropped> {
        // Held throughout, so two relays of one peer can't both take its last place.
        let mut peers = self.peers.lock().expect("execs");
        if peers.get(&key).copied().unwrap_or(0) >= l.node_per_peer {
            return Err(Dropped::NodePeer);
        }
        self.live.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < l.node_execs).then_some(n + 1)).map_err(|_| Dropped::Node)?;
        if self.new.fetch_add(1, Ordering::SeqCst) >= l.node_new_per_tick {
            self.live.fetch_sub(1, Ordering::SeqCst);
            return Err(Dropped::Node);
        }
        *peers.entry(key).or_default() += 1;
        Ok(ExecSlot(self.clone(), key))
    }
}

struct ExecSlot(Arc<Execs>, std::net::IpAddr);

impl Drop for ExecSlot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
        dec(&mut self.0.peers.lock().expect("execs"), self.1);
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

/// A peer's address without its IPv6 mapping: the address records name.
fn canonical(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, a.port())),
            None => a,
        },
        _ => a,
    }
}

/// The peer limits count by (#796 re-review, H2): an IPv4 address (a v4-mapped one as IPv4), or
/// an IPv6 address's /64, the least a site is given: one host holds a whole /64 as easily as one
/// address in it.
fn peer_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.into(),
            None => std::net::Ipv6Addr::from(u128::from(v6) & !(u128::from(u64::MAX))).into(),
        },
        v4 => v4,
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
    /// What the peer limits count it under ([`peer_key`]).
    key: std::net::IpAddr,
    started: std::time::Instant,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// When bytes last moved either way, in ms since `started`.
    last_ms: AtomicU64,
    /// When bytes last went to the peer (box to peer), in ms since `started` (#796 review, N1).
    last_out_ms: AtomicU64,
    /// Told when the connection is evicted while it waits for its first byte (#796 review, R1):
    /// its task, waiting on the peer, lets it go at once. One permit (`notify_one`), so an eviction
    /// before the task waits is not lost.
    evict: tokio::sync::Notify,
}

impl ConnStats {
    fn moved(&self, n: &AtomicU64, k: usize) {
        n.fetch_add(k as u64, Ordering::SeqCst);
        let ms = self.started.elapsed().as_millis() as u64;
        self.last_ms.store(ms, Ordering::SeqCst);
        // Bytes to the peer also reset the after-close timer (N1).
        if std::ptr::eq(n, &self.bytes_out) {
            self.last_out_ms.store(ms, Ordering::SeqCst);
        }
    }

    fn new(peer: SocketAddr, key: std::net::IpAddr) -> Self {
        ConnStats {
            peer,
            key,
            started: std::time::Instant::now(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            last_ms: AtomicU64::new(0),
            last_out_ms: AtomicU64::new(0),
            evict: tokio::sync::Notify::new(),
        }
    }
}

/// Why a connection was let go without a relay.
#[derive(Debug)]
enum Dropped {
    /// Over the port's own limits.
    Port,
    /// Over its peer's limit.
    Peer,
    /// Over its peer's connections waiting for their first byte (or a port that takes none).
    Waiting,
    /// Evicted while it waited for its first byte, by a newcomer to a full pool (#796 review, R1).
    Evicted,
    /// Over the node's relays.
    Node,
    /// Over its peer's relays over the node ([`Limits::node_per_peer`]; #796 review, R1).
    NodePeer,
    /// It sent nothing within [`Limits::first_byte`] (or closed first).
    Silent,
    /// Its relay couldn't start (no running box, or `docker exec` failed to spawn).
    Failed,
    /// The port closed before its relay started.
    Closed,
}

#[derive(Default)]
struct Counts {
    port: u64,
    peer: u64,
    waiting: u64,
    evicted: u64,
    node: u64,
    node_peer: u64,
    silent: u64,
    failed: u64,
    closed: u64,
}

/// How a relayed connection ended: either side closing ([`Why::Done`]), or the node ending it
/// (every other: recorded `"cut": true` with why, #796 review, N2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
    /// Either side closed: nothing to say.
    Done,
    /// No bytes either way for [`Limits::idle`].
    Idle,
    /// [`Limits::after_close`] after its peer's half-close, or the last byte sent to it since.
    AfterClose,
    /// It reached [`Limits::lifetime`]: cut.
    Lifetime,
    /// Its port closed: cut.
    PortClosed,
}

impl Why {
    /// Whether the node ended it: every end but either side closing (#796 review, N2).
    fn cut(self) -> bool {
        self != Why::Done
    }

    fn says(self) -> Option<&'static str> {
        match self {
            Why::Done => None,
            Why::Idle => Some("idle"),
            Why::AfterClose => Some("after close"),
            Why::Lifetime => Some("lifetime"),
            Why::PortClosed => Some("port closed"),
        }
    }
}

/// One record of this tick: a relay started, or one ended.
enum Event {
    Start { id: u64, key: std::net::IpAddr, peer: String },
    End(Ended),
}

/// One ended connection, for its `name.conn` record.
struct Ended {
    id: u64,
    key: std::net::IpAddr,
    peer: String,
    bytes_in: u64,
    bytes_out: u64,
    ms: u64,
    why: Why,
}

/// This tick's records past [`Limits::conn_records`], as totals.
#[derive(Default)]
struct Folded {
    started: u64,
    conns: u64,
    cut: u64,
    bytes_in: u64,
    bytes_out: u64,
    peers: HashSet<std::net::IpAddr>,
}

impl Folded {
    fn add(&mut self, e: &Event) {
        match e {
            Event::Start { key, .. } => {
                self.started += 1;
                self.peers.insert(*key);
            }
            Event::End(e) => {
                self.conns += 1;
                self.cut += u64::from(e.why.cut());
                self.bytes_in += e.bytes_in;
                self.bytes_out += e.bytes_out;
                self.peers.insert(e.key);
            }
        }
    }

    fn any(&self) -> bool {
        self.started + self.conns > 0
    }
}

/// A taken connection, as the port's log holds it.
struct Live {
    stats: Arc<ConnStats>,
    /// Not yet sent its first byte: counted against [`Limits::waiting`].
    waiting: bool,
    /// Its relay is running, and its start is on record: its end will be.
    started: bool,
}

#[derive(Default)]
struct LogState {
    next: u64,
    live: HashMap<u64, Live>,
    /// By [`peer_key`], the port's connections, and those of them still waiting.
    peers: HashMap<std::net::IpAddr, usize>,
    waiting_peers: HashMap<std::net::IpAddr, usize>,
    /// The ids of those still waiting, oldest (lowest) first: whom a newcomer evicts (R1).
    waiters: std::collections::BTreeSet<u64>,
    /// This tick's records in order, one by one while there are few (a start before its end).
    events: Vec<Event>,
    /// Or, once there are more, all of them as totals (H2).
    folded: Folded,
    dropped: Counts,
    /// Closed: its live connections are recorded as cut, and nothing more is taken.
    closed: bool,
}

fn dec(m: &mut HashMap<std::net::IpAddr, usize>, k: std::net::IpAddr) {
    if let Some(n) = m.get_mut(&k) {
        *n -= 1;
        if *n == 0 {
            m.remove(&k);
        }
    }
}

impl LogState {
    /// No longer waiting for its first byte.
    fn unwait(&mut self, id: u64, l: &mut Live) {
        if std::mem::take(&mut l.waiting) {
            self.waiters.remove(&id);
            dec(&mut self.waiting_peers, l.stats.key);
        }
    }

    /// Takes `id` out, with what it counted for: the caller records it.
    fn remove(&mut self, id: u64) -> Option<Live> {
        let mut l = self.live.remove(&id)?;
        self.unwait(id, &mut l);
        dec(&mut self.peers, l.stats.key);
        Some(l)
    }

    /// Evicts waiter `id` (R1): taken out and counted here, and its task told, which closes its
    /// socket at once.
    fn evict(&mut self, id: u64) {
        if let Some(l) = self.remove(id) {
            l.stats.evict.notify_one();
            PortLog::count(self, Dropped::Evicted);
        }
    }
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
    /// When the port opened (node clock, ms): connection ids are `<opened>.<n>`, so they don't
    /// repeat when the node restarts and opens the port again (#796 re-review, M4).
    opened: i64,
    st: Mutex<LogState>,
}

impl PortLog {
    fn new(node: Arc<Node>, claim: Claim, port: u16, limits: Arc<Limits>) -> Self {
        let opened = (node.clock)();
        PortLog { node, claim, port, limits, opened, st: Mutex::new(LogState::default()) }
    }

    fn conn_id(&self, n: u64) -> String {
        format!("{}.{n}", self.opened)
    }

    /// Counts a connection let go before it was taken.
    fn refuse(&self, why: Dropped) {
        Self::count(&mut self.st.lock().expect("port log"), why);
    }

    fn count(st: &mut LogState, why: Dropped) {
        let d = &mut st.dropped;
        match why {
            Dropped::Port => d.port += 1,
            Dropped::Peer => d.peer += 1,
            Dropped::Waiting => d.waiting += 1,
            Dropped::Evicted => d.evicted += 1,
            Dropped::Node => d.node += 1,
            Dropped::NodePeer => d.node_peer += 1,
            Dropped::Silent => d.silent += 1,
            Dropped::Failed => d.failed += 1,
            Dropped::Closed => d.closed += 1,
        }
    }

    /// Takes a connection from `from`, if its port and its peer are under their limits (checked
    /// before anything costs more): its id and counts. It waits for its first byte until
    /// [`PortLog::spoke`]. Every refusal is decided before anything is evicted.
    fn take(&self, from: SocketAddr) -> Result<(u64, Arc<ConnStats>), Dropped> {
        let l = &self.limits;
        let mut st = self.st.lock().expect("port log");
        if st.closed {
            return Err(Dropped::Port);
        }
        let key = peer_key(from.ip());
        if st.peers.get(&key).copied().unwrap_or(0) >= l.per_peer {
            return Err(Dropped::Peer);
        }
        // A peer at its own waiting cap is refused, not let evict its own oldest waiter (#796
        // review, R1). Either way it evicts no other peer's (checked before the pool's eviction
        // below, which it never reaches); refusing also means a peer at its cap evicts nothing at
        // all, and can't keep its waiters the pool's youngest by replacing them, so they age into
        // the ones other newcomers evict. What it costs: silent sockets from one shared address (a
        // NAT) refuse that address's other connections until they speak or time out.
        if st.waiting_peers.get(&key).copied().unwrap_or(0) >= l.waiting_per_peer {
            return Err(Dropped::Waiting);
        }
        // Silent sockets can't fill the port (#796 re-review, H2), nor shut it (R1): a newcomer to
        // a full pool, or to a port at its cap while some of it still waits, evicts the oldest
        // waiter instead of being refused. Only a port full of relays refuses it.
        let pool_full = st.waiters.len() >= l.waiting;
        if pool_full || st.live.len() >= l.port_cap() {
            match st.waiters.first().copied() {
                Some(oldest) => st.evict(oldest),
                None if pool_full => return Err(Dropped::Waiting),
                None => return Err(Dropped::Port),
            }
        }
        *st.peers.entry(key).or_default() += 1;
        *st.waiting_peers.entry(key).or_default() += 1;
        st.next += 1;
        let id = st.next;
        st.waiters.insert(id);
        let stats = Arc::new(ConnStats::new(from, key));
        st.live.insert(id, Live { stats: stats.clone(), waiting: true, started: false });
        Ok((id, stats))
    }

    /// A taken connection's first byte arrived: no longer counted as waiting. False if it is gone
    /// (evicted, or the port closed): the caller lets it go, with no exec spawned.
    fn spoke(&self, id: u64) -> bool {
        let mut st = self.st.lock().expect("port log");
        let Some(mut l) = st.live.remove(&id) else { return false };
        st.unwait(id, &mut l);
        st.live.insert(id, l);
        true
    }

    /// Its relay is running: its start goes on record (M4). False if the port closed meanwhile
    /// (the connection is gone: the caller stops its relay).
    fn start(&self, id: u64) -> bool {
        let mut st = self.st.lock().expect("port log");
        let Some(l) = st.live.get_mut(&id) else { return false };
        l.started = true;
        let ev = Event::Start { id, key: l.stats.key, peer: peer(l.stats.peer) };
        self.record(&mut st, ev);
        true
    }

    /// Lets go of a taken connection that never got a relay: counted, not recorded one by one.
    fn let_go(&self, id: u64, why: Dropped) {
        let mut st = self.st.lock().expect("port log");
        if st.remove(id).is_some() {
            Self::count(&mut st, why);
        }
    }

    /// A connection's end: recorded if its start was, unless [`PortLog::close`] recorded it
    /// already; one that never started is counted as let go.
    fn end(&self, id: u64, why: Why) {
        let mut st = self.st.lock().expect("port log");
        if let Some(l) = st.remove(id) {
            self.ended(&mut st, id, &l, why);
        }
    }

    fn ended(&self, st: &mut LogState, id: u64, l: &Live, why: Why) {
        if !l.started {
            return Self::count(st, if why == Why::PortClosed { Dropped::Closed } else { Dropped::Failed });
        }
        let s = &l.stats;
        let e = Ended {
            id,
            key: s.key,
            peer: peer(s.peer),
            bytes_in: s.bytes_in.load(Ordering::SeqCst),
            bytes_out: s.bytes_out.load(Ordering::SeqCst),
            ms: s.started.elapsed().as_millis() as u64,
            why,
        };
        self.record(st, Event::End(e));
    }

    fn record(&self, st: &mut LogState, ev: Event) {
        if !st.folded.any() && st.events.len() < self.limits.conn_records {
            st.events.push(ev);
            return;
        }
        // Past the per-tick records: this tick's starts and ends become one aggregate (H2).
        for old in std::mem::take(&mut st.events) {
            st.folded.add(&old);
        }
        st.folded.add(&ev);
    }

    /// Writes this tick's records: each start and end (`name.conn`), or one aggregate of them when
    /// there were more than [`Limits::conn_records`], and what was let go (`name.conn.refused`).
    fn flush(&self) {
        let (events, folded, d) = {
            let mut st = self.st.lock().expect("port log");
            (std::mem::take(&mut st.events), std::mem::take(&mut st.folded), std::mem::take(&mut st.dropped))
        };
        let c = &self.claim;
        for ev in events {
            let body = match ev {
                Event::Start { id, peer, .. } => serde_json::json!({
                    "name": c.name, "label": c.label, "port": self.port, "phase": "start",
                    "conn": self.conn_id(id), "peer": peer,
                }),
                Event::End(e) => {
                    let mut body = serde_json::json!({
                        "name": c.name, "label": c.label, "port": self.port, "phase": "end",
                        "conn": self.conn_id(e.id), "peer": e.peer,
                        "bytes_in": e.bytes_in, "bytes_out": e.bytes_out, "ms": e.ms,
                    });
                    if e.why.cut() {
                        body["cut"] = true.into();
                    }
                    if let Some(w) = e.why.says() {
                        body["why"] = w.into();
                    }
                    body
                }
            };
            self.node.audit_note(&c.run, "name.conn", body);
        }
        if folded.any() {
            self.node.audit_note(
                &c.run,
                "name.conn",
                serde_json::json!({
                    "name": c.name, "label": c.label, "port": self.port, "aggregate": true,
                    "started": folded.started, "conns": folded.conns, "cut": folded.cut,
                    "bytes_in": folded.bytes_in, "bytes_out": folded.bytes_out, "peers": folded.peers.len(),
                }),
            );
        }
        let refused = d.port + d.peer + d.waiting + d.node + d.node_peer;
        if refused + d.evicted + d.silent + d.failed + d.closed > 0 {
            let l = &self.limits;
            self.node.audit_note(
                &c.run,
                "name.conn.refused",
                serde_json::json!({
                    "name": c.name, "label": c.label, "port": self.port,
                    "refused": refused, "over_port": d.port, "over_peer": d.peer, "waiting": d.waiting, "over_node": d.node,
                    "node_peer": d.node_peer, "evicted": d.evicted, "silent": d.silent, "failed": d.failed, "closed": d.closed,
                    "max_conns": l.port_cap(), "max_new_per_tick": l.max_new_per_tick, "max_per_peer": l.per_peer,
                    "max_node_per_peer": l.node_per_peer, "max_waiting": l.waiting, "max_waiting_per_peer": l.waiting_per_peer,
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
            let ids: Vec<u64> = st.live.keys().copied().collect();
            for id in ids {
                if let Some(l) = st.remove(id) {
                    self.ended(&mut st, id, &l, Why::PortClosed);
                }
            }
        }
        self.flush();
    }
}

/// A taken connection, given back to its port's log however its task ends (an abort included):
/// with how it ended, if its relay said.
struct Taken(Arc<PortLog>, u64, Why);

impl Drop for Taken {
    fn drop(&mut self) {
        self.0.end(self.1, self.2);
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
                if execs.peer_full(peer_key(from.ip()), &log.limits) {
                    log.refuse(Dropped::NodePeer);
                    continue;
                }
                let (id, stats) = match log.take(from) {
                    Ok(t) => t,
                    Err(why) => {
                        log.refuse(why);
                        continue;
                    }
                };
                let taken = Taken(log.clone(), id, Why::Done);
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

/// Seconds for a `wicket-fwd` flag.
fn secs(d: Duration) -> String {
    d.as_secs_f64().to_string()
}

/// The command run in the box for one connection: `wicket-fwd --dial` to the box's port.
fn dial_argv(box_port: u16) -> Vec<String> {
    vec!["wicket-fwd".into(), "--dial".into(), format!("127.0.0.1:{box_port}")]
}

/// The `docker exec` options for one connection (#796 re-review, H2): the node's idle and
/// after-close limits for the box's `wicket-fwd`, so it ends by itself even when the box's service
/// never closes its side (Docker doesn't end an exec's process when its client goes). As
/// environment variables, not flags: a `wicket-fwd` in a box image from before them ignores them
/// and still relays, unbounded, where it would refuse a flag it doesn't know.
fn exec_opts(l: &Limits) -> Vec<String> {
    vec![
        "-i".into(),
        "-e".into(),
        format!("WICKET_FWD_IDLE_SECS={}", secs(l.idle)),
        "-e".into(),
        format!("WICKET_FWD_AFTER_CLOSE_SECS={}", secs(l.after_close)),
    ]
}

/// One connection: once its first byte arrives, a `docker exec -i <box>` of [`dial_argv`], and the
/// bytes copied both ways until either side ends, none move for [`Limits::idle`],
/// [`Limits::after_close`] passes after the peer's half-close, or [`Limits::lifetime`] passes.
///
/// Killing the `docker exec` client (kill_on_drop, or at a limit) ends the relay here, but not
/// necessarily the `wicket-fwd` in the box: Docker doesn't kill an exec's process when its client
/// goes. That one has its own limits (`WICKET_FWD_IDLE_SECS`, `WICKET_FWD_AFTER_CLOSE_SECS`, #796 re-review, H2): a
/// service that ignores half-close no longer keeps it, once its stdin ends or nothing moves. What
/// is still inferred, not measured (and maybe otherwise under gVisor): that its stdin ends when the
/// client is killed. If it didn't, a service that keeps sending would keep it past a node-side cut
/// (lifetime, the port's end) until its writes to the gone client fail.
async fn relay(node: Arc<Node>, s: tokio::net::TcpStream, box_port: u16, mut taken: Taken, stats: Arc<ConnStats>, execs: Arc<Execs>) {
    let log = taken.0.clone();
    let limits = log.limits.clone();
    // No exec until the peer has said something: one that sends nothing costs only its socket.
    // Evicted meanwhile (R1): gone at once, its socket with it (counted by the evictor).
    let mut b = [0u8; 1];
    let spoke = tokio::select! {
        r = tokio::time::timeout(limits.first_byte, s.peek(&mut b)) => matches!(r, Ok(Ok(n)) if n > 0),
        _ = stats.evict.notified() => return,
    };
    // Evicted (or the port closed) just as its byte arrived: still no exec.
    if !spoke || !log.spoke(taken.1) {
        return log.let_go(taken.1, Dropped::Silent);
    }
    let _slot = match execs.take(&limits, stats.key) {
        Ok(s) => s,
        Err(why) => return log.let_go(taken.1, why),
    };
    let found =
        node.boxes.lock().expect("boxes").get(&log.claim.run).filter(|b| b.exited.is_none()).map(|b| (b.name.clone(), b.user.clone()));
    let Some((name, user)) = found else { return log.let_go(taken.1, Dropped::Failed) };
    let child = node
        .docker
        .exec(&name, &user, &exec_opts(&limits).iter().map(String::as_str).collect::<Vec<_>>(), &dial_argv(box_port))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = child else { return log.let_go(taken.1, Dropped::Failed) };
    if !log.start(taken.1) {
        // The port closed meanwhile.
        let _ = child.start_kill();
        let _ = child.wait().await;
        return;
    }
    if let (Some(mut w), Some(mut r)) = (child.stdin.take(), child.stdout.take()) {
        let (mut cr, mut cw) = s.into_split();
        let st = &stats;
        let half_closed = tokio::sync::Notify::new();
        let up = async {
            let _ = pump(&mut cr, &mut w, st, &st.bytes_in).await;
            drop(w);
            half_closed.notify_one();
        };
        let down = async {
            let _ = pump(&mut r, &mut cw, st, &st.bytes_out).await;
            let _ = cw.shutdown().await;
        };
        let bounds = async {
            let lifetime = tokio::time::sleep_until(tokio::time::Instant::from_std(st.started + limits.lifetime));
            // An idle timer from the half-close, reset by each byte sent to the peer since (#796
            // review, N1): a half-closed peer still downloading isn't cut while bytes flow to it.
            let after_close = async {
                half_closed.notified().await;
                let closed_ms = st.started.elapsed().as_millis() as u64;
                loop {
                    let from = Duration::from_millis(closed_ms.max(st.last_out_ms.load(Ordering::SeqCst)));
                    let since = st.started.elapsed().saturating_sub(from);
                    if since >= limits.after_close {
                        return;
                    }
                    tokio::time::sleep(limits.after_close - since).await;
                }
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
                _ = lifetime => Why::Lifetime,
                _ = after_close => Why::AfterClose,
                _ = idle => Why::Idle,
            }
        };
        taken.2 = tokio::select! {
            _ = async { tokio::join!(up, down) } => Why::Done,
            why = bounds => why,
        };
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

    /// A connection taken, spoken and started, as a relay does.
    fn go(log: &PortLog, from: SocketAddr) -> (u64, Arc<ConnStats>) {
        let (id, s) = log.take(from).unwrap();
        assert!(log.spoke(id));
        assert!(log.start(id));
        (id, s)
    }

    fn conn_records(node: &Node) -> Vec<(String, serde_json::Value)> {
        let rows = node.audit.lock().unwrap().audit_tail(200).unwrap();
        rows.into_iter().filter(|r| r.2.starts_with("name.conn")).map(|r| (r.2, serde_json::from_str(&r.4).unwrap())).collect()
    }

    /// H2, M4: whoever takes a connection out records it once; more starts and ends in a tick than
    /// `conn_records` are one aggregate record, and those cut by the port's end are counted.
    #[test]
    fn many_ends_in_a_tick_are_one_aggregate_record() {
        let inst = crate::nodeauth::testkit::Install::new("ports-aggregate");
        let node = super::super::tests::test_node(&inst);
        let claim = Claim { run: "run_agg".into(), name: "n-0".into(), label: "demo".into(), box_port: 3000, until_ms: i64::MAX };
        let limits = Arc::new(Limits { conn_records: 4, per_peer: 3, waiting_per_peer: 3, ..Limits::default() });
        let log = PortLog::new(node.clone(), claim, 20999, limits);
        let kinds = || conn_records(&node);
        let from = |n: u8| -> SocketAddr { format!("192.0.2.{n}:4000").parse().unwrap() };
        // Two connections: a start and an end record each.
        for n in [1, 2] {
            let (id, s) = go(&log, from(n));
            s.moved(&s.bytes_in, 3);
            log.end(id, Why::Done);
        }
        log.flush();
        assert_eq!(kinds().len(), 4, "{:?}", kinds());
        // Three more, two from one address: six records, past four, so one aggregate.
        for n in [1, 1, 2] {
            let (id, s) = go(&log, from(n));
            s.moved(&s.bytes_out, 5);
            log.end(id, Why::Done);
            log.end(id, Why::Done); // a second end of the same connection records nothing
        }
        log.flush();
        let k = kinds();
        assert_eq!(k.len(), 5, "{k:?}");
        let agg = &k[4].1;
        assert_eq!(
            (agg["aggregate"].clone(), agg["started"].clone(), agg["conns"].clone(), agg["peers"].clone(), agg["bytes_out"].clone()),
            (true.into(), 3.into(), 3.into(), 2.into(), 15.into()),
            "{agg}"
        );
        // The per-peer cap, and the port's end recording what it cuts (and taking no more).
        let held: Vec<_> = (0..3).map(|_| go(&log, from(9))).collect();
        assert!(matches!(log.take(from(9)), Err(Dropped::Peer)));
        log.refuse(Dropped::Peer);
        log.flush(); // the three starts
        log.close();
        for (id, _) in &held {
            log.end(*id, Why::Done);
        }
        assert!(matches!(log.take(from(8)), Err(Dropped::Port)), "closed");
        let k = kinds();
        let cut: Vec<_> = k.iter().filter(|(kind, b)| kind == "name.conn" && b["cut"] == true).collect();
        assert_eq!(cut.len(), 3, "{k:?}");
        assert!(cut.iter().all(|(_, b)| b["why"] == "port closed" && b["phase"] == "end"), "{cut:?}");
        let refused = k.iter().find(|(kind, _)| kind == "name.conn.refused").expect("refused");
        assert_eq!(refused.1["over_peer"], 1, "{k:?}");
    }

    /// M4 (#796 re-review): a relay's start is on record (with its id) before its end, and each
    /// end carries its start's id; a connection that never started is counted, not recorded.
    #[test]
    fn a_start_is_recorded_before_its_end_with_the_same_id() {
        let inst = crate::nodeauth::testkit::Install::new("ports-start");
        let node = super::super::tests::test_node(&inst);
        let claim = Claim { run: "run_st".into(), name: "n-0".into(), label: "demo".into(), box_port: 3000, until_ms: i64::MAX };
        let log = PortLog::new(node.clone(), claim, 20998, Arc::new(Limits::default()));
        let from: SocketAddr = "192.0.2.5:4000".parse().unwrap();
        let (a, _) = go(&log, from);
        log.flush();
        let k = conn_records(&node);
        assert_eq!(k.len(), 1, "the live one's start: {k:?}");
        assert_eq!((k[0].1["phase"].clone(), k[0].1["peer"].clone()), ("start".into(), "192.0.2.5:4000".into()));
        let id = k[0].1["conn"].as_str().unwrap().to_string();
        assert!(id.starts_with(&format!("{}.", log.opened)), "{id}");
        // One started and ended in the same tick: start, then end.
        let (b, _) = go(&log, from);
        log.end(b, Why::Lifetime);
        log.end(a, Why::Done);
        // And one taken that never got a relay.
        let (c, _) = log.take(from).unwrap();
        log.end(c, Why::Done);
        log.flush();
        let k = conn_records(&node);
        let phases: Vec<(String, String)> = k[1..]
            .iter()
            .filter(|(kind, _)| kind == "name.conn")
            .map(|(_, b)| (b["phase"].as_str().unwrap().into(), b["conn"].as_str().unwrap().into()))
            .collect();
        let bid = log.conn_id(b);
        assert_eq!(phases, [("start".into(), bid.clone()), ("end".into(), bid), ("end".into(), id)], "{k:?}");
        let life = k.iter().find(|(_, b)| b["why"] == "lifetime").expect("lifetime");
        assert_eq!(life.1["cut"], true);
        let refused = k.iter().find(|(kind, _)| kind == "name.conn.refused").expect("refused");
        assert_eq!(refused.1["failed"], 1, "{k:?}");
    }

    /// H2 (#796 re-review): peers are counted by IPv4 address (a v4-mapped one as IPv4) and by
    /// IPv6 /64.
    #[test]
    fn peers_are_counted_by_address_or_ipv6_64() {
        let k = |s: &str| peer_key(s.parse().unwrap());
        assert_eq!(k("192.0.2.7"), k("::ffff:192.0.2.7"));
        assert_ne!(k("192.0.2.7"), k("192.0.2.8"));
        assert_eq!(k("2001:db8:1:2::1"), k("2001:db8:1:2:ffff:ffff:ffff:ffff"));
        assert_eq!(k("2001:db8:1:2::1"), "2001:db8:1:2::".parse::<std::net::IpAddr>().unwrap());
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
    }

    /// H2 (#796 re-review): a port holds at most a `PORT_SHARE`th of the node's relays, at least one.
    #[test]
    fn a_ports_share_of_the_node_is_bounded() {
        let d = Limits::default();
        assert_eq!(d.port_cap(), MAX_CONNS);
        assert!(d.port_cap() * PORT_SHARE <= d.node_execs, "{PORT_SHARE} names at their cap fit the node");
        assert_eq!(Limits { node_execs: 80, ..Limits::default() }.port_cap(), 10);
        assert_eq!(Limits { max_conns: 4, ..Limits::default() }.port_cap(), 4);
        assert_eq!(Limits { node_execs: 2, ..Limits::default() }.port_cap(), 1);
    }

    /// Whether `s`'s task has been told it is evicted (the permit `notify_one` leaves).
    async fn evicted(s: &ConnStats) -> bool {
        tokio::time::timeout(Duration::from_millis(10), s.evict.notified()).await.is_ok()
    }

    /// H2 (#796 re-review), R1 (#796 review): connections waiting for their first byte are capped
    /// per peer (past it the newcomer is refused, evicting nothing) and per port, where a newcomer
    /// to a full pool evicts the oldest waiter, whichever peer's, and is taken; one that speaks
    /// frees its place.
    #[tokio::test]
    async fn waiting_connections_are_capped_and_the_oldest_evicted() {
        let inst = crate::nodeauth::testkit::Install::new("ports-waiting");
        let node = super::super::tests::test_node(&inst);
        let claim = Claim { run: "run_w".into(), name: "n-0".into(), label: "demo".into(), box_port: 3000, until_ms: i64::MAX };
        let log = PortLog::new(node.clone(), claim, 20997, Arc::new(Limits { waiting: 3, waiting_per_peer: 2, ..Limits::default() }));
        let v6 = |n: u8| -> SocketAddr { format!("[2001:db8::{n}]:4000").parse().unwrap() };
        let v4 = |n: u8| -> SocketAddr { format!("192.0.2.{n}:4000").parse().unwrap() };
        let (a, sa) = log.take(v6(1)).unwrap();
        let (b, sb) = log.take(v6(2)).unwrap();
        assert!(matches!(log.take(v6(3)), Err(Dropped::Waiting)), "two waiting from one /64");
        assert!(!evicted(&sa).await && !evicted(&sb).await, "a peer over its own cap evicts nothing");
        let (c, sc) = log.take(v4(1)).unwrap();
        // The pool is full (three): the next evicts the oldest, the first from the /64.
        let (d, _) = log.take(v4(2)).expect("taken, not refused, into a full pool");
        assert!(evicted(&sa).await, "the oldest is told");
        assert!(!evicted(&sb).await && !evicted(&sc).await, "only the oldest");
        assert!(!log.spoke(a), "an evicted one is gone: no exec for it");
        log.let_go(a, Dropped::Silent); // as its task does: nothing more is counted
        assert!(log.spoke(c));
        log.take(v6(4)).expect("a place freed by one speaking: nothing evicted");
        assert!(!evicted(&sb).await);
        for id in [b, c, d] {
            log.let_go(id, Dropped::Failed);
        }
        log.flush();
        let k = conn_records(&node);
        let refused = &k.iter().find(|(kind, _)| kind == "name.conn.refused").expect("refused").1;
        assert_eq!(
            (refused["evicted"].clone(), refused["waiting"].clone(), refused["silent"].clone()),
            (1.into(), 0.into(), 0.into()),
            "the eviction counted by the evictor (a refusal is by `serve`), the evicted one not again as silent: {refused}"
        );
    }

    /// R1 (#796 review): a port at its cap while some of it still waits evicts the oldest waiter
    /// for a newcomer; one full of relays refuses it.
    #[tokio::test]
    async fn a_full_port_evicts_a_waiter_but_not_a_relay() {
        let inst = crate::nodeauth::testkit::Install::new("ports-full");
        let node = super::super::tests::test_node(&inst);
        let claim = Claim { run: "run_f".into(), name: "n-0".into(), label: "demo".into(), box_port: 3000, until_ms: i64::MAX };
        let log = PortLog::new(node, claim, 20996, Arc::new(Limits { max_conns: 2, ..Limits::default() }));
        let v4 = |n: u8| -> SocketAddr { format!("192.0.2.{n}:4000").parse().unwrap() };
        let _relay = go(&log, v4(1));
        let (_, sb) = log.take(v4(2)).unwrap();
        let (c, _) = log.take(v4(3)).expect("evicts the waiter");
        assert!(evicted(&sb).await);
        assert!(log.spoke(c));
        assert!(matches!(log.take(v4(4)), Err(Dropped::Port)), "two relays: full");
    }

    /// H2 (#796 re-review): the box's `wicket-fwd` is given the node's idle and after-close limits.
    #[test]
    fn the_dial_carries_the_limits() {
        let l = Limits { idle: Duration::from_millis(1500), ..Limits::default() };
        assert_eq!(dial_argv(3000), ["wicket-fwd", "--dial", "127.0.0.1:3000"]);
        assert_eq!(exec_opts(&l), ["-i", "-e", "WICKET_FWD_IDLE_SECS=1.5", "-e", "WICKET_FWD_AFTER_CLOSE_SECS=30"]);
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
        let k = |s: &str| peer_key(s.parse().unwrap());
        let (a, b) = (e.take(&l, k("192.0.2.1")).unwrap(), e.take(&l, k("192.0.2.2")).unwrap());
        assert!(e.full(&l) && matches!(e.take(&l, k("192.0.2.3")), Err(Dropped::Node)), "two at once");
        drop(a);
        let _c = e.take(&l, k("192.0.2.3")).unwrap();
        drop(b);
        assert!(matches!(e.take(&l, k("192.0.2.4")), Err(Dropped::Node)), "three new this tick");
        e.new.store(0, Ordering::SeqCst);
        assert!(e.take(&l, k("192.0.2.4")).is_ok());
    }

    /// R1 (#796 review): one peer (an IPv6 /64 as one) holds at most `node_per_peer` of the node's
    /// relays, over all its ports; a refused take leaves nothing held, and a slot dropped frees it.
    #[test]
    fn a_peers_relays_over_the_node_are_capped() {
        let l = Limits { node_per_peer: 2, ..Limits::default() };
        let e = Arc::new(Execs::default());
        let k = |s: &str| peer_key(s.parse().unwrap());
        let a = e.take(&l, k("2001:db8::1")).unwrap();
        let _b = e.take(&l, k("2001:db8::2")).unwrap();
        assert!(e.peer_full(k("2001:db8::3"), &l));
        assert!(matches!(e.take(&l, k("2001:db8::3")), Err(Dropped::NodePeer)), "two from one /64");
        assert_eq!(e.live.load(Ordering::SeqCst), 2, "the refused one holds no relay");
        let _c = e.take(&l, k("192.0.2.1")).expect("another peer");
        drop(a);
        assert!(!e.peer_full(k("2001:db8::3"), &l));
        let _d = e.take(&l, k("2001:db8::3")).unwrap();
        drop((_b, _c, _d));
        assert!(e.peers.lock().unwrap().is_empty(), "every slot given back");
    }
}
