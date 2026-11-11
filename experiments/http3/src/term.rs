//! Host side: accepts the box's SOCK_SEQPACKET relay connection, answers its DNS, and terminates
//! its QUIC with quinn driven through a custom `AsyncUdpSocket` over that same unix socket (no host
//! UDP socket at all). Each HTTP/3 request is decided with `CompiledZone::evaluate` and either
//! re-originated upstream or answered with wicket's 403, and audited as one JSON line.

use crate::certs::{self, Ca, SniMinter};
use crate::dns::{self, Names};
use crate::upstream::{Down, Upstream};
use crate::wire::{self, Head, HDR, KIND_DNS, KIND_QUIC};
use anyhow::{Context as _, Result};
use bytes::{Buf, Bytes, BytesMut};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use wicket_core::{CompiledZone, HostVerdict, Op, RunId, TenantId, Verdict, ZoneSpec};


pub struct Opts {
    pub sock: String,
    pub zone: ZoneSpec,
    pub ca_out: String,
    pub origin_ca: String,
    pub upstreams: HashMap<String, SocketAddr>,
    pub audit: String,
    pub https_records: bool,
    pub migration: bool,
    pub mtu_upper: Option<u16>,
    pub idle_secs: u64,
}

struct Shared {
    zone: CompiledZone,
    names: Names,
    up: Upstream,
    audit: Mutex<std::fs::File>,
    https_records: bool,
    run: RunId,
    t0: Instant,
    ca: Arc<Ca>,
    transport: Arc<quinn::TransportConfig>,
    migration: bool,
    /// One QUIC server config per name: its certificate resolver mints for that name only.
    per_name: Mutex<HashMap<String, quinn::ServerConfig>>,
}

impl Shared {
    /// The server config for a connection to `name`'s synthetic address: a ClientHello naming
    /// anything else gets no certificate, so the handshake fails before any request.
    fn server_config(&self, name: &str) -> Result<quinn::ServerConfig> {
        if let Some(c) = self.per_name.lock().unwrap().get(name) {
            return Ok(c.clone());
        }
        let want = name.to_string();
        let minter = Arc::new(SniMinter { ca: self.ca.clone(), allow: Box::new(move |sni| sni.eq_ignore_ascii_case(&want)) });
        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(certs::h3_server_config(minter)?)?;
        let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qsc));
        sc.transport_config(self.transport.clone());
        sc.migration(self.migration);
        self.per_name.lock().unwrap().insert(name.to_string(), sc.clone());
        Ok(sc)
    }

    fn audit(&self, v: serde_json::Value) {
        let mut v = v;
        v["t_ms"] = (self.t0.elapsed().as_secs_f64() * 1000.0).round().into();
        let mut f = self.audit.lock().unwrap();
        let _ = writeln!(f, "{v}");
        let _ = f.flush();
    }
}

pub async fn run(o: Opts) -> Result<()> {
    let ca = Arc::new(Ca::generate("wicket run CA (h3 spike)")?);
    std::fs::write(&o.ca_out, ca.cert_pem())?;
    let zone = CompiledZone::new(o.zone.clone())?;
    let zone_for_names = CompiledZone::new(o.zone.clone())?;
    let names = Names::new(Box::new(move |h| zone_for_names.host_verdict(h) == HostVerdict::Open));
    let roots = std::fs::read_to_string(&o.origin_ca).context("origin CA")?;
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(o.idle_secs).try_into()?));
    if let Some(up) = o.mtu_upper {
        let mut m = quinn::MtuDiscoveryConfig::default();
        m.upper_bound(up);
        t.mtu_discovery_config(Some(m));
    }
    t.stream_receive_window((8u32 << 20).into());
    t.receive_window((16u32 << 20).into());
    t.send_window(16 << 20);
    let shared = Arc::new(Shared {
        zone,
        names,
        up: Upstream::new(o.upstreams.clone(), &roots)?,
        audit: Mutex::new(std::fs::OpenOptions::new().create(true).append(true).open(&o.audit)?),
        https_records: o.https_records,
        run: RunId("run_h3spike".into()),
        t0: Instant::now(),
        ca: ca.clone(),
        transport: Arc::new(t),
        migration: o.migration,
        per_name: Default::default(),
    });
    // The endpoint's default config is never used: every Incoming is accepted with its name's config.
    let sc = shared.server_config("unused.invalid")?;

    // SAFETY: the fd is owned by the AsyncFd and lives as long as it.
    let listener = unsafe { AsyncFd::register(wire::listen(&o.sock)?)? };
    std::fs::set_permissions(&o.sock, std::os::unix::fs::PermissionsExt::from_mode(0o777))?;
    eprintln!("term: listening on {} (migration {}, https records {})", o.sock, o.migration, o.https_records);
    loop {
        let mut g = listener.readable().await?;
        let fd = match g.try_io(|l| wire::accept(l.as_raw_fd())) {
            Ok(Ok(fd)) => fd,
            Ok(Err(e)) => {
                eprintln!("term: accept: {e}");
                continue;
            }
            Err(_) => continue,
        };
        eprintln!("term: box connected");
        let relay = Arc::new(Relay { fd: unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE | Interest::WRITABLE)? }, shared: shared.clone(), stats: Default::default() });
        let ep = quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), Some(sc.clone()), relay.clone(), Arc::new(quinn::TokioRuntime))?;
        let shared = shared.clone();
        tokio::spawn(async move {
            while let Some(inc) = ep.accept().await {
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = conn(shared, inc).await {
                        eprintln!("term: connection: {e:#}");
                    }
                });
            }
        });
    }
}

async fn conn(shared: Arc<Shared>, inc: quinn::Incoming) -> Result<()> {
    let remote = inc.remote_address();
    let local = inc.local_ip();
    // The decision binds to the name the synthetic address stands for, and the SNI must be that name:
    // otherwise a client could send to a hidden host's address with an allowed host's SNI, or the reverse.
    let mapped = match local {
        Some(IpAddr::V4(ip)) => shared.names.name_of(ip),
        _ => None,
    };
    let Some(host) = mapped else {
        shared.audit(serde_json::json!({"event": "quic-refused", "why": "address maps to no name", "remote": remote.to_string(), "local": format!("{local:?}")}));
        inc.refuse();
        return Ok(());
    };
    let c = match inc.accept_with(Arc::new(shared.server_config(&host)?))?.await {
        Ok(c) => c,
        Err(e) => {
            shared.audit(serde_json::json!({"event": "quic-refused", "why": format!("handshake: {e}"), "host": host, "remote": remote.to_string()}));
            return Ok(());
        }
    };
    let sni = c.handshake_data().and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok()).and_then(|h| h.server_name);
    if !sni.as_deref().is_some_and(|s| s.eq_ignore_ascii_case(&host)) {
        c.close(0x0101u32.into(), b"wicket: SNI does not match the address");
        return Ok(());
    }
    shared.audit(serde_json::json!({"event": "quic-open", "host": host, "remote": remote.to_string(), "local": format!("{local:?}")}));
    let mut h3c: h3::server::Connection<h3_quinn::Connection, Bytes> = h3::server::Connection::new(h3_quinn::Connection::new(c.clone())).await?;
    loop {
        match h3c.accept().await {
            Ok(Some(resolver)) => {
                let (shared, host) = (shared.clone(), host.clone());
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = request(shared, host, req, stream).await {
                                eprintln!("term: request: {e:#}");
                            }
                        }
                        Err(e) => eprintln!("term: resolve: {e}"),
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                if !e.is_h3_no_error() {
                    eprintln!("term: h3 accept: {e}");
                }
                break;
            }
        }
    }
    let s = c.stats();
    shared.audit(serde_json::json!({"event": "quic-close", "host": host, "rtt_us": s.path.rtt.as_micros() as u64,
        "mtu": s.path.current_mtu, "lost": s.path.lost_packets, "sent_pkts": s.path.sent_packets,
        "udp_tx": s.udp_tx.datagrams, "udp_rx": s.udp_rx.datagrams, "udp_tx_bytes": s.udp_tx.bytes, "migrations": format!("{:?}", c.remote_address())}));
    Ok(())
}

async fn request(shared: Arc<Shared>, host: String, req: http::Request<()>, mut down: Down) -> Result<()> {
    let t = Instant::now();
    let method = req.method().as_str().to_string();
    let authority = req.uri().authority().map(|a| a.host().to_ascii_lowercase());
    let pq = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let (path, query) = match pq.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (pq.clone(), String::new()),
    };
    // A connection serves one host (RFC 9114 coalescing would let a client ask this connection for another).
    if authority.as_deref() != Some(host.as_str()) {
        shared.audit(serde_json::json!({"event": "request", "host": host, "authority": authority, "method": method, "path": path, "status": 421}));
        return refuse(&mut down, 421, "misdirected", "Blocked by wicket sandbox: wrong host for this connection", "This connection serves one host only.").await;
    }
    let canon = match wicket_core::canonical_path(&pq) {
        Ok(p) => p.to_string(),
        Err(e) => {
            shared.audit(serde_json::json!({"event": "request", "host": host, "method": method, "path": path, "status": 403, "verdict": format!("malformed: {e}")}));
            return refuse(&mut down, 403, "forbidden", "Blocked by wicket sandbox: malformed request", &e.to_string()).await;
        }
    };
    let op = Op::egress_with_query(&TenantId::single(), &shared.run, &shared.zone.name, &method, &host, &canon, &query);
    let verdict = shared.zone.evaluate(&op);
    match &verdict {
        Verdict::AllowByReach(i) => {
            // Read the request body (bounded) before deciding is done; the spike forwards it whole.
            let mut body = BytesMut::new();
            while let Some(mut c) = down.recv_data().await? {
                body.extend_from_slice(&c.copy_to_bytes(c.remaining()));
                if body.len() > 16 << 20 {
                    return refuse(&mut down, 413, "too-large", "Blocked by wicket sandbox: request body too large", "").await;
                }
            }
            let decided_us = t.elapsed().as_micros() as u64;
            let out = shared.up.forward(&host, req, body.freeze(), &mut down).await;
            match out {
                Ok(o) => shared.audit(serde_json::json!({"event": "request", "host": host, "method": method, "path": canon,
                    "verdict": format!("allow (reach rule {i})"), "risk": format!("{:?}", op.risk), "upstream": o.proto, "status": o.status,
                    "bytes": o.bytes, "decide_us": decided_us, "ms": t.elapsed().as_secs_f64() * 1000.0})),
                Err(e) => {
                    shared.audit(serde_json::json!({"event": "request", "host": host, "method": method, "path": canon, "verdict": "allow", "status": 502, "error": format!("{e:#}")}));
                    let _ = refuse(&mut down, 502, "upstream", "wicket: upstream failed", &format!("{e:#}")).await;
                }
            }
        }
        Verdict::Forbidden(why) => {
            shared.audit(serde_json::json!({"event": "request", "host": host, "method": method, "path": canon, "verdict": "forbidden", "why": why, "status": 403}));
            refuse(&mut down, 403, "forbidden", "Blocked by wicket sandbox: never allowed", why).await?;
        }
        Verdict::NeedsGrant(why) => {
            // The real proxy files a pending request here; the spike refuses as a zone without grants would.
            shared.audit(serde_json::json!({"event": "request", "host": host, "method": method, "path": canon, "verdict": "needs-grant", "why": why, "status": 403}));
            refuse(&mut down, 403, "out-of-reach", "Blocked by wicket sandbox: outside this zone's reach", why).await?;
        }
    }
    Ok(())
}

/// wicket's problem+json refusal, over HTTP/3.
async fn refuse(down: &mut Down, status: u16, kind: &str, title: &str, detail: &str) -> Result<()> {
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "type": format!("https://wicket.dev/e/{kind}"), "title": title, "status": status, "detail": detail,
    }))?;
    let resp = http::Response::builder().status(status).header("content-type", "application/problem+json").header("x-wicket", kind).body(())?;
    down.send_response(resp).await?;
    down.send_data(Bytes::from(body)).await?;
    down.finish().await?;
    Ok(())
}

// ---- the custom quinn socket over the box's SOCK_SEQPACKET relay ----

#[derive(Default)]
struct Stats {
    rx: u64,
    tx: u64,
    dns: u64,
}

pub struct Relay {
    fd: AsyncFd<OwnedFd>,
    shared: Arc<Shared>,
    stats: Mutex<Stats>,
}

impl fmt::Debug for Relay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Relay")
    }
}

impl Relay {
    fn dns(&self, h: Head, q: &[u8]) {
        let Some((r, what)) = dns::answer(&self.shared.names, q, self.shared.https_records) else { return };
        self.stats.lock().unwrap().dns += 1;
        self.shared.audit(serde_json::json!({"event": "dns", "q": what}));
        let mut hdr = [0u8; HDR];
        wire::put_head(&mut hdr, &Head { kind: KIND_DNS, ..h });
        let _ = self.fd.try_io(Interest::WRITABLE, |fd| wire::send(fd.as_raw_fd(), &[&hdr, &r]));
    }
}

impl AsyncUdpSocket for Relay {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller { relay: self })
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        let (SocketAddr::V4(to), Some(IpAddr::V4(from))) = (t.destination, t.src_ip) else {
            return Ok(()); // nothing else exists in the box: drop
        };
        let mut hdr = [0u8; HDR];
        wire::put_head(&mut hdr, &Head { kind: KIND_QUIC, src: to, dst: SocketAddrV4::new(from, 443) });
        self.fd.try_io(Interest::WRITABLE, |fd| wire::send(fd.as_raw_fd(), &[&hdr, t.contents]))?;
        self.stats.lock().unwrap().tx += 1;
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let mut n = 0;
        let mut hdr = [0u8; HDR];
        while n < bufs.len() {
            let mut g = if n == 0 {
                ready!(self.fd.poll_read_ready(cx))?
            } else {
                match self.fd.poll_read_ready(cx) {
                    Poll::Ready(g) => g?,
                    Poll::Pending => break,
                }
            };
            let res = g.try_io(|fd| recv2(fd.as_raw_fd(), &mut hdr, &mut bufs[n]));
            let len = match res {
                Ok(Ok(0)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "box relay closed"))),
                Ok(Ok(len)) => len,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => {
                    if n == 0 {
                        continue;
                    }
                    break;
                }
            };
            let Some(h) = wire::get_head(&hdr) else { continue };
            let plen = len.saturating_sub(HDR);
            if h.kind == KIND_DNS {
                let q = bufs[n][..plen].to_vec();
                self.dns(h, &q);
                continue;
            }
            meta[n] = RecvMeta { addr: SocketAddr::V4(h.src), len: plen, stride: plen, ecn: None, dst_ip: Some(IpAddr::V4(*h.dst.ip())) };
            n += 1;
        }
        self.stats.lock().unwrap().rx += n as u64;
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443))
    }

    /// Unix datagrams never fragment: lets quinn run path-MTU discovery up to its upper bound.
    fn may_fragment(&self) -> bool {
        false
    }
}

/// recvmsg into [header, payload] so the payload lands straight in quinn's buffer.
fn recv2(fd: i32, hdr: &mut [u8; HDR], buf: &mut [u8]) -> io::Result<usize> {
    let mut iov = [libc::iovec { iov_base: hdr.as_mut_ptr() as *mut _, iov_len: HDR }, libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() }];
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = iov.as_mut_ptr();
    m.msg_iovlen = 2;
    let n = unsafe { libc::recvmsg(fd, &mut m, 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

struct Poller {
    relay: Arc<Relay>,
}

impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Poller")
    }
}

impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // Keep the readiness: try_send's try_io clears it on EAGAIN.
        let _g = ready!(self.relay.fd.poll_write_ready(cx))?;
        Poll::Ready(Ok(()))
    }
}
