//! Published host ports (#575 step 4c; design in `docs/explanation/box-dns.md`, "Host ports"):
//! the node listens on the host ports its boxes' public names were given, and copies each
//! connection's bytes into the box's own port.
//!
//! **Layer 4 only.** A byte relay, as a link's far end is: no TLS is terminated, no protocol is
//! read, nothing is routed by name, and nothing passes through the control host. What the node
//! decides is only whether to take a connection, and whether to keep it.
//!
//! **Decided here, from the feed.** Every [`TICK`] the node reads its replica: a port is open while
//! the box's authority holds on this node (unexpired, unrevoked), the port's own end hasn't passed,
//! it is in this node's range ([`PUBLISH_FILE`]), and exactly one box claims it. Otherwise it is
//! closed, its connections with it. So a revoked name, or a box whose authority ends, closes here
//! even while the control host is out of reach. Without the file the node publishes nothing.
//!
//! **What is recorded,** as node audit records shipped to the control host:
//! `name.port.opened`, `name.port.closed` (with why), `name.port.failed` (a port it couldn't bind,
//! once until it binds), and `name.conn` per connection (the peer, bytes each way, how long). A
//! connection over the per-name limit is refused and counted, not recorded one by one.

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
    Ok(Some(a..=b))
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

/// What the node publishes now: a task per open port.
#[derive(Default)]
pub struct Published {
    open: HashMap<u16, (Claim, tokio::task::JoinHandle<()>)>,
    /// Ports whose bind failed, with the claim: recorded once until it binds or goes.
    failed: HashSet<(u16, String)>,
    /// Ports more than one box claims, recorded once.
    contested: HashSet<u16>,
    /// Claims this node won't publish (outside its range, or no range at all), recorded once.
    skipped: HashSet<(u16, String)>,
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
        if a.spec.ports.is_empty() || !r.authority_until(run).is_some_and(|u| u > now) {
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
            {
                by_port.entry(p.host_port).or_default().push(Claim {
                    run: run.clone(),
                    name: p.name.clone(),
                    label: p.label.clone(),
                    box_port: p.box_port,
                    until_ms: p.until_ms,
                });
            }
        }
    }
    let contested = by_port.iter().filter(|(_, c)| c.len() > 1).map(|(p, _)| *p).collect();
    let one = by_port.into_iter().filter(|(_, c)| c.len() == 1).map(|(p, mut c)| (p, c.remove(0))).collect();
    Wanted { one, contested, skipped }
}

/// What the replica says to publish now.
#[derive(Default)]
struct Wanted {
    /// By host port, the ports one box claims.
    one: HashMap<u16, Claim>,
    /// Ports more than one box claims.
    contested: HashSet<u16>,
    /// Claims this node won't publish: `(run, port, name, label, why)`.
    skipped: Vec<(String, u16, String, String, String)>,
}

/// One look (see the module's documentation): closes what shouldn't be open, opens what should.
pub fn tick(node: &Arc<Node>, range: Option<&std::ops::RangeInclusive<u16>>, st: &mut Published) {
    let Wanted { one: want, contested, skipped } = wanted(node, range);
    let now_skipped: HashSet<(u16, String)> = skipped.iter().map(|(run, p, ..)| (*p, run.clone())).collect();
    for (run, port, name, label, why) in &skipped {
        if !st.skipped.contains(&(*port, run.clone())) {
            node.audit_note(run, "name.port.failed", serde_json::json!({ "name": name, "label": label, "port": port, "why": why }));
        }
    }
    st.skipped = now_skipped;
    for p in contested.difference(&st.contested.clone()) {
        let body = serde_json::json!({ "port": p, "why": "more than one box claims it: none gets it" });
        let _ = node.audit.lock().expect("audit").audit(&wicket_core::TenantId::single(), None, "name.port.failed", &body);
    }
    st.contested = contested;
    let close: Vec<u16> = st
        .open
        .iter()
        .filter(|(port, (c, h))| {
            h.is_finished() || want.get(port).is_none_or(|w| w.run != c.run || w.name != c.name || w.box_port != c.box_port)
        })
        .map(|(p, _)| *p)
        .collect();
    for port in close {
        if let Some((c, h)) = st.open.remove(&port) {
            h.abort();
            let why = match want.get(&port) {
                Some(_) => "its claim changed",
                None => "its name or its box's authority ended here",
            };
            node.audit_note(&c.run, "name.port.closed", serde_json::json!({ "name": c.name, "label": c.label, "port": port, "why": why }));
        }
    }
    st.failed.retain(|(p, run)| want.get(p).is_some_and(|w| &w.run == run));
    for (port, c) in want {
        if st.open.contains_key(&port) {
            continue;
        }
        match bind(port) {
            Ok(l) => {
                st.failed.remove(&(port, c.run.clone()));
                node.audit_note(
                    &c.run,
                    "name.port.opened",
                    serde_json::json!({ "name": c.name, "label": c.label, "port": port, "box_port": c.box_port }),
                );
                let h = tokio::spawn(serve(node.clone(), l, port, c.clone()));
                st.open.insert(port, (c, h));
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

/// A listener on every address of the node at `port`: one IPv6 socket that takes IPv4 too.
/// On a node with IPv6 turned off, an IPv4 socket.
fn bind(port: u16) -> std::io::Result<tokio::net::TcpListener> {
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
    let s = match dual() {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return Err(e),
        Err(_) => v4()?,
    };
    s.set_nonblocking(true)?;
    s.listen(128)?;
    tokio::net::TcpListener::from_std(s.into())
}

/// A peer's address as recorded: an IPv4 one without its IPv6 mapping.
fn peer(a: SocketAddr) -> String {
    match a.ip() {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, a.port())).to_string(),
            None => a.to_string(),
        },
        _ => a.to_string(),
    }
}

/// Whether `c` may still be published: its box's authority holds here, and the box's record as
/// the replica has it now still carries the port, unexpired (a renewed name's new end counts).
fn held(node: &Node, c: &Claim) -> bool {
    let now = (node.clock)();
    let r = node.replica.lock().expect("replica");
    let listed = r
        .state()
        .and_then(|s| s.zones.get(&c.run))
        .is_some_and(|z| z.spec.ports.iter().any(|p| p.name == c.name && p.box_port == c.box_port && p.until_ms > now));
    listed && r.authority_until(&c.run).is_some_and(|u| u > now)
}

/// Takes connections on `l` for claim `c` until it no longer holds (checked every [`TICK`]): each is
/// dialed into the box at its port and the bytes copied both ways. Ends, aborting its
/// connections, when it no longer holds or the manager aborts it.
async fn serve(node: Arc<Node>, l: tokio::net::TcpListener, port: u16, c: Claim) {
    let mut conns = tokio::task::JoinSet::new();
    let live = Arc::new(AtomicUsize::new(0));
    let refused = Arc::new(AtomicU64::new(0));
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
                if !held(&node, &c) {
                    break;
                }
                if live.load(Ordering::SeqCst) >= MAX_CONNS || taken_this_tick >= MAX_NEW_PER_TICK {
                    refused.fetch_add(1, Ordering::SeqCst);
                    drop(s);
                    continue;
                }
                taken_this_tick += 1;
                let found = node.boxes.lock().expect("boxes").get(&c.run).filter(|b| b.exited.is_none()).map(|b| (b.name.clone(), b.user.clone()));
                let Some((name, user)) = found else { continue };
                let child = node
                    .docker
                    .exec(&name, &user, &["-i"], &["wicket-fwd".to_string(), "--dial".into(), format!("127.0.0.1:{}", c.box_port)])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .spawn();
                let Ok(mut child) = child else { continue };
                live.fetch_add(1, Ordering::SeqCst);
                let (n, c2, live2) = (node.clone(), c.clone(), live.clone());
                conns.spawn(async move {
                    let started = std::time::Instant::now();
                    let (mut up_n, mut down_n) = (0u64, 0u64);
                    if let (Some(mut w), Some(mut r)) = (child.stdin.take(), child.stdout.take()) {
                        let (mut cr, mut cw) = s.into_split();
                        let up = async {
                            up_n = tokio::io::copy(&mut cr, &mut w).await.unwrap_or(0);
                            drop(w);
                        };
                        let down = async {
                            down_n = tokio::io::copy(&mut r, &mut cw).await.unwrap_or(0);
                            let _ = cw.shutdown().await;
                        };
                        tokio::join!(up, down);
                    }
                    let _ = child.wait().await;
                    live2.fetch_sub(1, Ordering::SeqCst);
                    n.audit_note(&c2.run, "name.conn", serde_json::json!({
                        "name": c2.name, "label": c2.label, "port": port, "peer": peer(from),
                        "bytes_in": up_n, "bytes_out": down_n, "ms": started.elapsed().as_millis() as u64,
                    }));
                });
            }
            _ = tick.tick() => {
                taken_this_tick = 0;
                if !held(&node, &c) {
                    break;
                }
                let r = refused.swap(0, Ordering::SeqCst);
                if r > 0 {
                    node.audit_note(&c.run, "name.conn.refused", serde_json::json!({ "name": c.name, "label": c.label, "port": port, "refused": r, "max_conns": MAX_CONNS, "max_new_per_tick": MAX_NEW_PER_TICK }));
                }
            }
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    conns.abort_all();
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
        for bad in [r#"{"ports":"80-443"}"#, r#"{"ports":"21000-20000"}"#, r#"{"ports":"x"}"#, r#"{"ports":"1-2","extra":1}"#] {
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
    }
}
