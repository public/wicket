//! The intercepting egress path's bodies and upstream connections (#142), end to end on the host: a
//! box-side client speaking CONNECT and TLS to the egress proxy's unix socket, against local origins
//! with their own CA, one offering HTTP/2 (ALPN) and one HTTP/1.1 only.
//!
//! - Request bodies stream upstream as they arrive: an upload larger than the old 64 MiB cap gets
//!   through, the origin sees its first bytes before the box has sent the rest, and while the origin
//!   stops reading, the box's writes stop too (memory stays bounded by buffers, not the body).
//! - The request's `content-length` goes upstream as sent; the response's comes back to the box.
//! - Requests from several box connections share one pooled HTTP/2 upstream connection.

use bytes::Bytes;
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use wicket_core::{RunId, TenantId, ZoneSpec};
use wicket_proxy::ca::RunCa;
use wicket_proxy::decide::Central;
use wicket_proxy::egress::{Egress, Upstream};
use wicket_proxy::RunCtx;

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("stream-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Inspected hosts (not every method), so every request goes through the intercepting path.
fn zone() -> ZoneSpec {
    serde_json::from_value(serde_json::json!({
        "name": "streamzone",
        "reach": [
            {"host": "h1.test", "methods": ["GET", "POST", "PUT"]},
            {"host": "h2.test", "methods": ["GET", "POST", "PUT"]}
        ]
    }))
    .unwrap()
}

/// One request an origin saw: HTTP version, `content-length`, `transfer-encoding`.
type Request = (http::Version, Option<String>, Option<String>);

/// What an origin saw.
#[derive(Default)]
struct Seen {
    /// TCP connections accepted.
    conns: AtomicUsize,
    /// Per request: HTTP version, `content-length`, `transfer-encoding`.
    requests: Mutex<Vec<Request>>,
    /// Body bytes received so far, over all uploads.
    got: AtomicU64,
}

/// Controls for an upload: the origin reads the first chunk, says so, then waits for `go`.
struct Gate {
    first: tokio::sync::Notify,
    go: tokio::sync::watch::Sender<bool>,
}

/// One TLS origin for `name`, signed by `ca`, speaking HTTP/2 if `h2` (ALPN) and HTTP/1.1 otherwise.
/// `/up` reads the request body (pausing after the first chunk until the gate opens) and answers
/// `got N`; anything else answers 100,000 bytes.
async fn origin(ca: &RunCa, name: &str, h2: bool, seen: Arc<Seen>, gate: Arc<Gate>) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let mut cfg = (*ca.server_config(name).unwrap()).clone();
    cfg.alpn_protocols = if h2 { vec![b"h2".to_vec(), b"http/1.1".to_vec()] } else { vec![b"http/1.1".to_vec()] };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            seen.conns.fetch_add(1, Ordering::SeqCst);
            let (acceptor, seen, gate) = (acceptor.clone(), seen.clone(), gate.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(s).await else { return };
                let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let (seen, gate) = (seen.clone(), gate.clone());
                    async move {
                        let h = |n: &str| req.headers().get(n).map(|v| v.to_str().unwrap().to_string());
                        seen.requests.lock().unwrap().push((req.version(), h("content-length"), h("transfer-encoding")));
                        if req.uri().path() != "/up" {
                            return Ok::<_, hyper::Error>(http::Response::new(http_body_util::Full::new(Bytes::from(vec![b'x'; 100_000]))));
                        }
                        let mut body = req.into_body();
                        let mut n = 0u64;
                        let mut go = gate.go.subscribe();
                        while let Some(f) = body.frame().await {
                            if let Ok(d) = f?.into_data() {
                                n += d.len() as u64;
                                seen.got.fetch_add(d.len() as u64, Ordering::SeqCst);
                                gate.first.notify_one();
                                let _ = go.wait_for(|g| *g).await;
                            }
                        }
                        Ok(http::Response::new(http_body_util::Full::new(Bytes::from(format!("got {n}")))))
                    }
                });
                let io = hyper_util::rt::TokioIo::new(tls);
                if is_h2 {
                    let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(io, svc).await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await;
                }
            });
        }
    });
    addr
}

struct World {
    sock: PathBuf,
    seen: HashMap<&'static str, Arc<Seen>>,
    gate: Arc<Gate>,
    dir: PathBuf,
}

impl World {
    async fn new() -> World {
        let dir = tmpdir();
        let origin_ca = RunCa::generate("origin").unwrap();
        let (go, _) = tokio::sync::watch::channel(false);
        let gate = Arc::new(Gate { first: tokio::sync::Notify::new(), go });
        let mut seen = HashMap::new();
        let mut resolve = HashMap::new();
        for (name, h2) in [("h1.test", false), ("h2.test", true)] {
            let s = Arc::new(Seen::default());
            resolve.insert(name.to_string(), origin(&origin_ca, name, h2, s.clone(), gate.clone()).await);
            seen.insert(name, s);
        }
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        // Keep the event channel open (and drained) for the proxy's audit rows.
        tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
        });
        let ctx = RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_stream".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(zone()).unwrap()),
            org: None,
            ledger: Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().unwrap())),
            vault: wicket_proxy::vault::Vault::new(dir.join("vault")),
            events: tx,
            escalate: true,
            attribute: None,
            identity: None,
            spawner: None,
            swaps: vec![],
            boxes: None,
            capacity: None,
            fence: None,
            waker: None,
        };
        let up = Upstream { resolve, roots_pem: Some(origin_ca.cert_pem()), ..Default::default() };
        let egress = Egress::with_upstream(ctx, Arc::new(RunCa::generate("run_stream").unwrap()), Arc::new(Central), None, up).unwrap();
        let sock = dir.join("egress.sock");
        let s2 = sock.clone();
        tokio::spawn(async move { egress.serve(&s2).await });
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        World { sock, seen, gate, dir }
    }

    /// CONNECT and TLS (any certificate) to `host` through the proxy.
    async fn tls(&self, host: &str) -> tokio_rustls::client::TlsStream<UnixStream> {
        let mut s = UnixStream::connect(&self.sock).await.unwrap();
        s.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(s.read(&mut b).await.unwrap(), 1);
            head.push(b[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.unwrap()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Reads one HTTP/1.1 response with a `content-length` (the proxy keeps it): head and body.
async fn response<S: AsyncRead + Unpin>(s: &mut S) -> (String, Vec<u8>) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).await.unwrap(), 1, "closed in the response head: {}", String::from_utf8_lossy(&head));
        head.push(b[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
        .unwrap_or_else(|| panic!("no content-length: {head}"));
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).await.unwrap();
    (head, body)
}

/// Writes `n` bytes of body in 64 KiB chunks, counting what the socket has taken.
async fn write_body<S: AsyncWrite + Unpin>(s: &mut S, n: u64, sent: &AtomicU64) {
    let chunk = vec![b'u'; 64 * 1024];
    let mut left = n;
    while left > 0 {
        let k = left.min(chunk.len() as u64) as usize;
        s.write_all(&chunk[..k]).await.unwrap();
        sent.fetch_add(k as u64, Ordering::SeqCst);
        left -= k as u64;
    }
    s.flush().await.unwrap();
}

/// An upload larger than the old 64 MiB cap streams through with bounded memory, over HTTP/1.1 and
/// HTTP/2 upstreams, and its `content-length` reaches the origin as sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_upload_streams_upstream_with_bounded_memory() {
    const N: u64 = 80 * 1024 * 1024;
    for (host, version) in [("h1.test", http::Version::HTTP_11), ("h2.test", http::Version::HTTP_2)] {
        let w = World::new().await;
        let tls = w.tls(host).await;
        let (mut rd, mut wr) = tokio::io::split(tls);
        let sent = Arc::new(AtomicU64::new(0));
        let writer = tokio::spawn({
            let sent = sent.clone();
            async move {
                wr.write_all(format!("PUT /up HTTP/1.1\r\nHost: {host}\r\nContent-Length: {N}\r\n\r\n").as_bytes()).await.unwrap();
                write_body(&mut wr, N, &sent).await;
                wr
            }
        });
        // The origin has the first bytes while the box is still sending: nothing waited for the whole body.
        tokio::time::timeout(Duration::from_secs(20), w.gate.first.notified()).await.expect("the origin saw no body bytes");
        assert!(sent.load(Ordering::SeqCst) < N, "{host}: the box had already sent everything");
        // The origin stops reading: the box's writes stop too, after what the buffers on the way hold.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let stalled = sent.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let later = sent.load(Ordering::SeqCst);
        assert_eq!(stalled, later, "{host}: the box kept writing while the origin read nothing");
        assert!(stalled < 32 * 1024 * 1024, "{host}: {stalled} bytes accepted while the origin stalled");
        // The origin reads on: the whole body arrives, and the box gets the answer.
        w.gate.go.send_replace(true);
        let _wr = tokio::time::timeout(Duration::from_secs(120), writer).await.expect("upload finished").unwrap();
        let (head, body) = tokio::time::timeout(Duration::from_secs(30), response(&mut rd)).await.unwrap();
        assert!(head.starts_with("HTTP/1.1 200"), "{host}: {head}");
        assert_eq!(String::from_utf8(body).unwrap(), format!("got {N}"), "{host}");
        let seen = &w.seen[host];
        let reqs = seen.requests.lock().unwrap().clone();
        assert_eq!(reqs, vec![(version, Some(N.to_string()), None)], "{host}: the length as sent, not chunked");
    }
}

/// A body sent without a length streams through too (chunked upstream over HTTP/1.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chunked_upload_streams_through() {
    let w = World::new().await;
    w.gate.go.send_replace(true);
    let mut tls = w.tls("h1.test").await;
    tls.write_all(b"POST /up HTTP/1.1\r\nHost: h1.test\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
    let chunk = vec![b'c'; 100_000];
    for _ in 0..30 {
        tls.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await.unwrap();
        tls.write_all(&chunk).await.unwrap();
        tls.write_all(b"\r\n").await.unwrap();
    }
    tls.write_all(b"0\r\n\r\n").await.unwrap();
    // TLS may hold records the socket didn't take yet: send them before waiting for the answer.
    tls.flush().await.unwrap();
    let (head, body) = response(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"got 3000000");
    let reqs = w.seen["h1.test"].requests.lock().unwrap().clone();
    assert_eq!(reqs, vec![(http::Version::HTTP_11, None, Some("chunked".to_string()))]);
}

/// Requests from several box connections share one pooled HTTP/2 upstream connection, and each
/// response keeps its `content-length`. An HTTP/1.1-only origin is still served (one request at a
/// time per pooled connection).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_http2_upstream_is_reused_across_box_connections() {
    let w = World::new().await;
    for host in ["h2.test", "h1.test"] {
        let mut boxes = vec![];
        for _ in 0..4 {
            boxes.push(w.tls(host).await);
        }
        for round in 0..2 {
            for (i, tls) in boxes.iter_mut().enumerate() {
                tls.write_all(format!("GET /x/{round}/{i} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
                tls.flush().await.unwrap();
                let (head, body) = response(tls).await;
                assert!(head.starts_with("HTTP/1.1 200"), "{host}: {head}");
                assert!(head.to_ascii_lowercase().contains("content-length: 100000"), "{host}: {head}");
                assert_eq!(body.len(), 100_000);
            }
        }
    }
    let h2 = &w.seen["h2.test"];
    assert_eq!(h2.conns.load(Ordering::SeqCst), 1, "one upstream connection for 4 box connections");
    let reqs = h2.requests.lock().unwrap().clone();
    assert_eq!(reqs.len(), 8);
    assert!(reqs.iter().all(|r| r.0 == http::Version::HTTP_2), "{reqs:?}");
    let h1 = &w.seen["h1.test"];
    assert!(h1.requests.lock().unwrap().iter().all(|r| r.0 == http::Version::HTTP_11));
}

/// Accepts any server certificate.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

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
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
