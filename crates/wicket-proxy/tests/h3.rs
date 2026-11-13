//! HTTP/3 through wicket (#92), end to end on the host: a quinn + h3 client, a stand-in for the box's
//! forwarder (a UDP socket that frames each datagram to the run's `udp.sock` with the synthetic
//! destination, as `wicket-fwd` does from `IP_PKTINFO`), wicket's DNS and QUIC termination, the
//! egress proxy's decisions, and local origins (HTTP/3 + HTTP/1.1, and HTTP/1.1 only) with their own CA.

use bytes::{Buf, Bytes};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use wicket_core::{RunId, TenantId, ZoneSpec};
use wicket_fwd::frame::{self, Head, HDR, MAX_FRAME};
use wicket_proxy::ca::RunCa;
use wicket_proxy::decide::Central;
use wicket_proxy::egress::{Egress, Upstream};
use wicket_proxy::h3::{Options, H3};
use wicket_proxy::{Event, RunCtx};

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("h3-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn zone() -> ZoneSpec {
    serde_json::from_value(serde_json::json!({
        "name": "h3zone",
        "unlisted_hosts": "hide",
        "reach": [
            {"host": "h3.test", "methods": ["GET", "POST"], "paths": ["/allowed/**"]},
            {"host": "h1only.test", "paths": ["/**"]}
        ],
        "forbid": [{"host": "h3.test", "paths": ["/admin/**"]}]
    }))
    .unwrap()
}

/// The origins: `h3.test` speaks HTTP/3 (UDP) and HTTP/1.1 (TCP) on one port, `h1only.test`
/// HTTP/1.1 only. Each answers with how it was reached.
/// `/allowed/bytes/N` asks an origin for N bytes.
fn bytes_of(path: &str) -> Option<usize> {
    path.strip_prefix("/allowed/bytes/")?.parse().ok()
}

async fn origins(ca: &RunCa) -> HashMap<String, SocketAddr> {
    // One port number for UDP and TCP: a free UDP port whose TCP twin may be taken, so try a few.
    let mut pair = None;
    for _ in 0..50 {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        if let Ok(tcp) = tokio::net::TcpListener::bind(udp.local_addr().unwrap()).await {
            pair = Some((udp, tcp));
            break;
        }
    }
    let (udp, tcp) = pair.expect("a port free for both UDP and TCP");
    let both = udp.local_addr().unwrap();
    let h1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let h1_addr = h1.local_addr().unwrap();
    // HTTP/3
    let mut tls = (*ca.server_config("h3.test").unwrap()).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let sc = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap()));
    let ep = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(sc), udp, Arc::new(quinn::TokioRuntime)).unwrap();
    tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            tokio::spawn(async move {
                let Ok(c) = inc.await else { return };
                let Ok(mut h) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(c)).await else { return };
                while let Ok(Some(r)) = h.accept().await {
                    tokio::spawn(async move {
                        let Ok((req, mut s)) = r.resolve_request().await else { return };
                        let mut n = 0;
                        while let Ok(Some(b)) = s.recv_data().await {
                            n += b.remaining();
                        }
                        let auth = req.headers().get("authorization").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                        let _ = s.send_response(http::Response::builder().status(200).body(()).unwrap()).await;
                        if let Some(size) = bytes_of(req.uri().path()) {
                            let block = Bytes::from(vec![b'x'; 64 * 1024]);
                            let mut left = size;
                            while left > 0 {
                                let k = left.min(block.len());
                                if s.send_data(block.slice(..k)).await.is_err() {
                                    return;
                                }
                                left -= k;
                            }
                        } else {
                            let body = format!("h3 {} {} body={n} auth={auth}", req.method(), req.uri().path());
                            let _ = s.send_data(Bytes::from(body)).await;
                        }
                        let _ = s.finish().await;
                    });
                }
            });
        }
    });
    // HTTP/1.1 over TLS, for both names.
    for (l, name) in [(tcp, "h3.test"), (h1, "h1only.test")] {
        let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config(name).unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(s).await else { return };
                    let svc = hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
                        use http_body_util::BodyExt;
                        let m = req.method().clone();
                        let p = req.uri().path().to_string();
                        let n = req.into_body().collect().await.map(|b| b.to_bytes().len()).unwrap_or(0);
                        let body = match bytes_of(&p) {
                            Some(size) => Bytes::from(vec![b'x'; size]),
                            None => Bytes::from(format!("h1 {m} {p} body={n}")),
                        };
                        Ok::<_, std::convert::Infallible>(http::Response::new(http_body_util::Full::new(body)))
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), svc).await;
                });
            }
        });
    }
    HashMap::from([("h3.test".to_string(), both), ("h1only.test".to_string(), h1_addr)])
}

struct World {
    run_ca: Arc<RunCa>,
    names: Arc<wicket_proxy::dns::Names>,
    sock: PathBuf,
    events: Mutex<UnboundedReceiver<Event>>,
    dir: PathBuf,
}

impl World {
    async fn new(stream: bool, opts: Options) -> World {
        World::with_relay(stream, opts, None).await
    }

    async fn with_relay(stream: bool, opts: Options, relay: Option<Arc<dyn wicket_proxy::egress::Relay>>) -> World {
        World::build(stream, opts, relay, false).await
    }

    /// `stale`: this run is an activation of an agent that has since been woken again (#70).
    async fn build(stream: bool, opts: Options, relay: Option<Arc<dyn wicket_proxy::egress::Relay>>, stale: bool) -> World {
        let dir = tmpdir();
        let origin_ca = RunCa::generate("origin").unwrap();
        let resolve = origins(&origin_ca).await;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut ledger = wicket_store::Ledger::open_in_memory().unwrap();
        let agent = wicket_store::new_agent_id();
        ledger
            .create_agent(&wicket_store::NewAgent {
                id: &agent,
                tenant: "t0",
                zone: "h3zone",
                name: "a",
                run: "run_h3",
                session_id: "s",
                manifest: "m",
                image: "i",
                workspace: None,
                lease_until: 0,
            })
            .unwrap();
        assert!(ledger.commit_agent_push(&agent, 1, 0, 1, "h", 1).unwrap());
        if stale {
            assert_eq!(ledger.claim_wake(&agent, "run_new", 0).unwrap(), Some(2));
        }
        let ctx = RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_h3".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(zone()).unwrap()),
            org: None,
            ledger: Arc::new(Mutex::new(ledger)),
            vault: wicket_proxy::vault::Vault::new(dir.join("vault")),
            events: tx,
            escalate: true,
            attribute: None,
            identity: None,
            spawner: None,
            swaps: vec![],
            boxes: None,
            capacity: None,
            fence: Some(wicket_proxy::Fence { agent, generation: 1 }),
            waker: None,
        };
        let run_ca = Arc::new(RunCa::generate("run_h3").unwrap());
        let up = Upstream { resolve, roots_pem: Some(origin_ca.cert_pem()), no_h3: false, ..Default::default() };
        let egress = Egress::with_upstream(ctx, run_ca.clone(), Arc::new(Central), relay, up).unwrap();
        let h3 = H3::new(egress, opts).unwrap();
        let names = h3.names().clone();
        let sock = dir.join("udp.sock");
        let s2 = sock.clone();
        tokio::spawn(async move {
            if stream {
                h3.serve_stream(&s2).await
            } else {
                h3.serve(&s2).await
            }
        });
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        World { run_ca, names, sock, events: Mutex::new(rx), dir }
    }

    fn events(&self) -> Vec<Event> {
        let mut v = vec![];
        while let Ok(e) = self.events.lock().unwrap().try_recv() {
            v.push(e);
        }
        v
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The box's forwarder, as far as one client goes: datagrams from the client on a local UDP socket
/// are framed to `udp.sock` as if sent to `dst`, and replies come back from that local socket.
struct FakeBox {
    udp: Arc<UdpSocket>,
    link: Arc<Link>,
}

enum Link {
    Seq(OwnedFd),
    Stream(Mutex<std::os::unix::net::UnixStream>, std::os::unix::net::UnixStream),
}

impl Link {
    fn send(&self, f: &[u8]) {
        match self {
            Link::Seq(fd) => {
                // SAFETY: a live buffer and descriptor.
                unsafe { libc::send(fd.as_raw_fd(), f.as_ptr() as *const _, f.len(), libc::MSG_NOSIGNAL) };
            }
            Link::Stream(w, _) => {
                use std::io::Write;
                let mut w = w.lock().unwrap();
                let _ = w.write_all(&(f.len() as u32).to_be_bytes());
                let _ = w.write_all(f);
            }
        }
    }

    fn recv(&self, buf: &mut [u8]) -> usize {
        match self {
            // SAFETY: a live buffer and descriptor.
            Link::Seq(fd) => unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len(), 0) }.max(0) as usize,
            Link::Stream(_, r) => {
                use std::io::Read;
                let mut r = r;
                let mut len = [0u8; 4];
                if r.read_exact(&mut len).is_err() {
                    return 0;
                }
                let n = u32::from_be_bytes(len) as usize;
                r.read_exact(&mut buf[..n]).map(|_| n).unwrap_or(0)
            }
        }
    }
}

impl FakeBox {
    fn connect(w: &World, stream: bool) -> FakeBox {
        let link = if stream {
            let s = std::os::unix::net::UnixStream::connect(&w.sock).unwrap();
            Link::Stream(Mutex::new(s.try_clone().unwrap()), s)
        } else {
            // SAFETY: plain socket(2) and connect(2) with a valid sockaddr_un.
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0);
                assert!(fd >= 0);
                let mut a: libc::sockaddr_un = std::mem::zeroed();
                a.sun_family = libc::AF_UNIX as _;
                for (d, s) in a.sun_path.iter_mut().zip(w.sock.as_os_str().as_encoded_bytes()) {
                    *d = *s as _;
                }
                assert_eq!(libc::connect(fd, &a as *const _ as *const _, std::mem::size_of::<libc::sockaddr_un>() as _), 0);
                Link::Seq(OwnedFd::from_raw_fd(fd))
            }
        };
        FakeBox { udp: Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap()), link: Arc::new(link) }
    }

    /// One DNS query (type `t`) through the relay; the raw answer.
    fn dns(&self, name: &str, t: u16) -> Vec<u8> {
        let mut q = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, (t >> 8) as u8, t as u8, 0, 1]);
        let h = Head { seg: 0, src: "198.19.0.1:5353".parse().unwrap(), dst: "198.18.0.1:53".parse().unwrap() };
        let mut f = h.encode().to_vec();
        f.extend_from_slice(&q);
        self.link.send(&f);
        let mut buf = vec![0u8; MAX_FRAME];
        let n = self.link.recv(&mut buf);
        assert_eq!(Head::decode(&buf[..n]).unwrap(), h);
        buf[HDR..n].to_vec()
    }

    /// The A record for `name`, or None for NXDOMAIN.
    fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let a = self.dns(name, 1);
        if a[3] & 0x0f == 3 {
            return None;
        }
        Some(Ipv4Addr::new(a[a.len() - 4], a[a.len() - 3], a[a.len() - 2], a[a.len() - 1]))
    }

    /// Starts relaying the client's QUIC as if sent to `dst`:443. Returns where the client sends.
    fn relay_to(&self, dst: Ipv4Addr) -> SocketAddr {
        let (udp, link) = (self.udp.clone(), self.link.clone());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, SocketAddr::V4(src))) = udp.recv_from(&mut buf) else { return };
                let mut f = Head { seg: 0, src, dst: SocketAddrV4::new(dst, 443) }.encode().to_vec();
                f.extend_from_slice(&buf[..n]);
                link.send(&f);
            }
        });
        let (udp, link) = (self.udp.clone(), self.link.clone());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_FRAME];
            loop {
                let n = link.recv(&mut buf);
                if n == 0 {
                    return;
                }
                let h = Head::decode(&buf[..n]).unwrap();
                assert_eq!(*h.dst.ip(), dst, "replies come from the address the client used");
                for d in frame::segments(h.seg, &buf[HDR..n]) {
                    let _ = udp.send_to(d, h.src);
                }
            }
        });
        self.udp.local_addr().unwrap()
    }
}

fn client(w: &World) -> quinn::Endpoint {
    client_with(w, None, false)
}

/// A server certificate verifier that accepts anything (to test what wicket refuses by itself).
#[derive(Debug)]
struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// A client endpoint: `mtu` raises its MTU bound (and advertised datagram size) as the box would
/// for `WICKET_H3_BOX_MTU`; `any_cert` skips certificate verification.
fn client_with(w: &World, mtu: Option<u16>, any_cert: bool) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::pem::PemObject::pem_slice_iter(w.run_ca.cert_pem().as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = true;
    if any_cert {
        tls.dangerous().set_certificate_verifier(Arc::new(AnyCert));
    }
    let mut ep_cfg = quinn::EndpointConfig::default();
    let mut t = quinn::TransportConfig::default();
    if let Some(m) = mtu {
        ep_cfg.max_udp_payload_size(m).unwrap();
        let mut d = quinn::MtuDiscoveryConfig::default();
        d.upper_bound(m);
        t.mtu_discovery_config(Some(d));
    }
    t.stream_receive_window((8u32 << 20).into());
    t.receive_window((16u32 << 20).into());
    let mut cc = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap()));
    cc.transport_config(Arc::new(t));
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut ep = quinn::Endpoint::new(ep_cfg, None, sock, Arc::new(quinn::TokioRuntime)).unwrap();
    ep.set_default_client_config(cc);
    ep
}

/// One request over a fresh connection to `to` as `sni`: (status, body, x-wicket).
async fn get(ep: &quinn::Endpoint, to: SocketAddr, sni: &str, method: &str, url: &str) -> anyhow::Result<(u16, String, Option<String>)> {
    let conn = tokio::time::timeout(Duration::from_secs(10), ep.connect(to, sni)?).await??;
    request(&conn, method, url).await
}

async fn request(conn: &quinn::Connection, method: &str, url: &str) -> anyhow::Result<(u16, String, Option<String>)> {
    let (st, body, xw) = request_body(conn, method, url, if method == "POST" { 12 } else { 0 }).await?;
    Ok((st, String::from_utf8_lossy(&body).into(), xw))
}

/// One request with `upload` bytes of body; (status, body, x-wicket).
async fn request_body(conn: &quinn::Connection, method: &str, url: &str, upload: usize) -> anyhow::Result<(u16, Vec<u8>, Option<String>)> {
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await?;
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut s = send.send_request(http::Request::builder().method(method).uri(url).body(())?).await?;
    if upload == 12 {
        s.send_data(Bytes::from_static(b"twelve bytes")).await?;
    } else if upload > 0 {
        let block = Bytes::from(vec![b'u'; 64 * 1024]);
        let mut left = upload;
        while left > 0 {
            let k = left.min(block.len());
            s.send_data(block.slice(..k)).await?;
            left -= k;
        }
    }
    s.finish().await?;
    let r = tokio::time::timeout(Duration::from_secs(30), s.recv_response()).await??;
    let mut body = Vec::new();
    while let Some(mut b) = s.recv_data().await? {
        body.extend_from_slice(&b.copy_to_bytes(b.remaining()));
    }
    let xw = r.headers().get("x-wicket").map(|v| v.to_str().unwrap().to_string());
    Ok((r.status().as_u16(), body, xw))
}

fn egress_events(w: &World) -> Vec<(String, String, String, String)> {
    w.events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Egress { method, host, outcome, detail, .. } => Some((method, host, outcome, detail)),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_resolves_reachable_hosts_and_hides_the_rest() {
    let w = World::new(false, Options::default()).await;
    let b = FakeBox::connect(&w, false);
    let ip = tokio::task::spawn_blocking(move || {
        let ip = b.resolve("h3.test").unwrap();
        assert_eq!(b.resolve("H3.Test"), Some(ip), "stable, case-insensitive");
        assert_ne!(b.resolve("h1only.test"), Some(ip));
        assert_eq!(b.resolve("hidden.test"), None);
        assert_eq!(b.resolve("example.com"), None);
        let aaaa = b.dns("h3.test", 28);
        assert_eq!((aaaa[3] & 0x0f, aaaa[7]), (0, 0), "AAAA: NODATA");
        let https = b.dns("h3.test", 65);
        assert_eq!(https[7], 1, "an HTTPS record");
        assert!(https.windows(3).any(|x| x == [2, b'h', b'3']));
        ip
    })
    .await
    .unwrap();
    assert!(wicket_proxy::dns::is_synthetic(ip));
    let ev = egress_events(&w);
    assert!(ev.iter().any(|(m, h, o, _)| m == "DNS" && h == "h3.test" && o == "allow"));
    assert!(ev.iter().any(|(m, h, o, _)| m == "DNS" && h == "hidden.test" && o == "hidden"));
    assert_eq!(ev.iter().filter(|(_, h, _, _)| h == "h3.test").count(), 1, "audited once, not per lookup");
}

async fn decisions(stream: bool) {
    let w = World::new(stream, Options::default()).await;
    let b = FakeBox::connect(&w, stream);
    let (b, ip, ip1) = tokio::task::spawn_blocking(move || {
        let ip = b.resolve("h3.test").unwrap();
        let ip1 = b.resolve("h1only.test").unwrap();
        (b, ip, ip1)
    })
    .await
    .unwrap();
    let to = b.relay_to(ip);
    let ep = client(&w);

    // Allowed: 200 from the origin, re-originated over HTTP/3 (the first request may race to
    // HTTP/1.1 while HTTP/3 comes up; the next ones go over HTTP/3).
    let (st, body, _) = get(&ep, to, "h3.test", "GET", "https://h3.test/allowed/a").await.unwrap();
    assert_eq!(st, 200, "{body}");
    assert!(body.ends_with("GET /allowed/a body=0 auth=") || body == "h1 GET /allowed/a body=0", "{body}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (st, body, _) = get(&ep, to, "h3.test", "POST", "https://h3.test/allowed/form").await.unwrap();
    assert_eq!((st, body.as_str()), (200, "h3 POST /allowed/form body=12 auth="));
    // Out of reach: wicket's 403 over HTTP/3 (and a pending request, this run escalates).
    let (st, body, xw) = get(&ep, to, "h3.test", "GET", "https://h3.test/secret").await.unwrap();
    assert_eq!((st, xw.as_deref()), (403, Some("pending-approval")), "{body}");
    // Forbidden.
    let (st, _, xw) = get(&ep, to, "h3.test", "GET", "https://h3.test/admin/users").await.unwrap();
    assert_eq!((st, xw.as_deref()), (403, Some("forbidden")));
    // Another host on this connection: 421.
    let conn = ep.connect(to, "h3.test").unwrap().await.unwrap();
    let (st, _, xw) = request(&conn, "GET", "https://h1only.test/x").await.unwrap();
    assert_eq!((st, xw.as_deref()), (421, Some("misdirected")));
    // A server name that isn't the address's host: no connection (the client can't verify a leaf
    // for it, and wicket refuses it even if it didn't check).
    assert!(get(&ep, to, "h1only.test", "GET", "https://h1only.test/x").await.is_err());
    let ev = egress_events(&w);
    assert!(ev.iter().any(|(m, h, o, d)| m == "GET" && h == "h3.test" && o == "allow" && !d.is_empty()), "{ev:?}");
    assert!(ev.iter().any(|(m, _, o, _)| m == "GET" && o == "pending"), "{ev:?}");
    assert!(ev.iter().any(|(m, _, o, d)| m == "GET" && o == "forbidden" && d.contains("h1only.test on h3.test")), "{ev:?}");

    // An HTTP/1.1-only upstream, through its own address.
    let b1 = FakeBox::connect(&w, stream);
    let to1 = b1.relay_to(ip1);
    let (st, body, _) = get(&ep, to1, "h1only.test", "GET", "https://h1only.test/x").await.unwrap();
    assert_eq!((st, body.as_str()), (200, "h1 GET /x body=0"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_are_decided_like_http1_over_seqpacket() {
    decisions(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_are_decided_like_http1_over_a_stream_socket() {
    decisions(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_rtt_is_never_accepted() {
    let w = World::new(false, Options::default()).await;
    let b = FakeBox::connect(&w, false);
    let (b, ip) = tokio::task::spawn_blocking(move || {
        let ip = b.resolve("h3.test").unwrap();
        (b, ip)
    })
    .await
    .unwrap();
    let to = b.relay_to(ip);
    let ep = client(&w);
    for _ in 0..2 {
        let conn = ep.connect(to, "h3.test").unwrap().await.unwrap();
        let (st, _, _) = request(&conn, "GET", "https://h3.test/allowed/z").await.unwrap();
        assert_eq!(st, 200);
        conn.close(0u32.into(), b"");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // With session tickets from two connections, a third still can't send early data.
    match ep.connect(to, "h3.test").unwrap().into_0rtt() {
        Ok(_) => panic!("0-RTT was offered: wicket issued a ticket allowing early data"),
        Err(c) => assert!(c.await.is_ok(), "a full handshake still works"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_to_an_address_wicket_never_handed_out_is_refused() {
    let w = World::new(false, Options::default()).await;
    let b = FakeBox::connect(&w, false);
    let to = b.relay_to(Ipv4Addr::new(198, 19, 200, 1));
    let ep = client(&w);
    assert!(get(&ep, to, "h3.test", "GET", "https://h3.test/allowed/a").await.is_err());
}

/// Several MB each way, so quinn's batches (GSO frames to the box) and the stream link's framing
/// carry real traffic; with the box MTU raised, the path MTU climbs past 1452 and nothing is lost.
async fn bulk(stream: bool, mtu: Option<u16>) {
    let w = World::new(stream, Options { box_mtu: mtu, ..Options::default() }).await;
    let b = FakeBox::connect(&w, stream);
    let (b, ip) = tokio::task::spawn_blocking(move || {
        let ip = b.resolve("h3.test").unwrap();
        (b, ip)
    })
    .await
    .unwrap();
    let to = b.relay_to(ip);
    let ep = client_with(&w, mtu, false);
    // One connection per request: `request_body` opens an HTTP/3 session and ends it.
    let size = 6 << 20;
    for _ in 0..2 {
        let conn = ep.connect(to, "h3.test").unwrap().await.unwrap();
        let (st, body, _) = request_body(&conn, "GET", &format!("https://h3.test/allowed/bytes/{size}"), 0).await.unwrap();
        assert_eq!(st, 200);
        assert_eq!(body.len(), size, "the whole download arrives");
        assert!(body.iter().all(|&c| c == b'x'));
    }
    let up = 3 << 20;
    let conn = ep.connect(to, "h3.test").unwrap().await.unwrap();
    let (st, body, _) = request_body(&conn, "POST", "https://h3.test/allowed/up", up).await.unwrap();
    assert_eq!(st, 200);
    let body = String::from_utf8_lossy(&body).to_string();
    assert!(body.contains(&format!("POST /allowed/up body={up}")), "{body}");
    // The path MTU, read while a connection is open (a closed one reports the initial 1200): one
    // more download, with the HTTP/3 session kept until after the reading.
    let conn = ep.connect(to, "h3.test").unwrap().await.unwrap();
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await.unwrap();
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut s = send.send_request(http::Request::get(format!("https://h3.test/allowed/bytes/{size}")).body(()).unwrap()).await.unwrap();
    s.finish().await.unwrap();
    s.recv_response().await.unwrap();
    let mut got = 0;
    while let Some(b) = s.recv_data().await.unwrap() {
        got += b.remaining();
    }
    assert_eq!(got, size);
    let mtu_now = conn.stats().path.current_mtu;
    match mtu {
        Some(m) => assert!(mtu_now > 1452 && mtu_now <= m, "path MTU {mtu_now} with a {m} bound"),
        None => assert!(mtu_now <= 1452, "path MTU {mtu_now}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn megabytes_each_way_over_seqpacket() {
    bulk(false, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn megabytes_each_way_over_a_stream_socket() {
    bulk(true, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn megabytes_each_way_with_the_box_mtu_raised() {
    bulk(false, Some(16000)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_name_other_than_the_addresss_host_is_refused_even_unverified() {
    let w = World::new(false, Options::default()).await;
    let b = FakeBox::connect(&w, false);
    let (b, ip) = tokio::task::spawn_blocking(move || {
        let ip = b.resolve("h3.test").unwrap();
        let _ = b.resolve("h1only.test").unwrap();
        (b, ip)
    })
    .await
    .unwrap();
    let to = b.relay_to(ip);
    let ep = client_with(&w, None, true);
    // Without wicket's check this would reach the request stage (and get a 421); with it, the
    // connection is closed before any request.
    assert!(get(&ep, to, "h1only.test", "GET", "https://h1only.test/x").await.is_err());
    let ev = egress_events(&w);
    assert!(ev.iter().any(|(m, h, _, d)| m == "QUIC" && h == "h3.test" && d.contains("server name (h1only.test)")), "{ev:?}");
    // The right name still works with the same unverifying client.
    assert_eq!(get(&ep, to, "h3.test", "GET", "https://h3.test/allowed/a").await.unwrap().0, 200);
}

/// A node's relay that forwards `h1only.test` to the control host and terminates the rest.
struct NodeRelay;

impl wicket_proxy::egress::Relay for NodeRelay {
    fn route(&self, host: &str) -> wicket_proxy::decide::Route {
        if host == "h1only.test" {
            wicket_proxy::decide::Route::Forward("the zone injects a credential for this host".into())
        } else {
            wicket_proxy::decide::Route::Terminate
        }
    }
    fn open(&self) -> futures_util::future::BoxFuture<'_, std::io::Result<Box<dyn wicket_proxy::egress::RelayStream>>> {
        Box::pin(async { Err(std::io::Error::other("no control host in this test")) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_a_node_forwarded_hosts_refuse_http3_and_say_why() {
    let w = World::with_relay(false, Options::default(), Some(Arc::new(NodeRelay))).await;
    let b = FakeBox::connect(&w, false);
    let b1 = FakeBox::connect(&w, false);
    let (b, b1, ip, ip1) = tokio::task::spawn_blocking(move || {
        let ip = b.resolve("h3.test").unwrap();
        let ip1 = b.resolve("h1only.test").expect("forwarded hosts still resolve (TCP through the proxy reaches them)");
        (b, b1, ip, ip1)
    })
    .await
    .unwrap();
    let to = b.relay_to(ip);
    let to1 = b1.relay_to(ip1);
    let ep = client(&w);
    assert_eq!(get(&ep, to, "h3.test", "GET", "https://h3.test/allowed/a").await.unwrap().0, 200);
    assert!(get(&ep, to1, "h1only.test", "GET", "https://h1only.test/x").await.is_err());
    let ev = egress_events(&w);
    assert!(
        ev.iter().any(|(m, h, o, d)| m == "QUIC" && h == "h1only.test" && o == "forbidden" && d.contains("isn't served on this node")),
        "{ev:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_superseded_activation_resolves_nothing_and_connects_nowhere() {
    // The same world, current then stale: only the fence differs.
    let live = World::build(false, Options::default(), None, false).await;
    let lb = FakeBox::connect(&live, false);
    let ip = tokio::task::spawn_blocking(move || lb.resolve("h3.test")).await.unwrap();
    assert!(ip.is_some(), "a current activation resolves");

    let w = World::build(false, Options::default(), None, true).await;
    let b = FakeBox::connect(&w, false);
    let b = tokio::task::spawn_blocking(move || {
        assert_eq!(b.resolve("h3.test"), None, "no answers for a stale activation");
        b
    })
    .await
    .unwrap();
    // Even at an address minted earlier (here: forced into the map), QUIC is refused.
    let ip = w.names.mint("h3.test").unwrap().0;
    let to = b.relay_to(ip);
    assert!(get(&client(&w), to, "h3.test", "GET", "https://h3.test/allowed/a").await.is_err());
    let ev = egress_events(&w);
    assert!(ev.iter().any(|(m, _, _, d)| m == "QUIC" && d.contains("stale")), "{ev:?}");
}
