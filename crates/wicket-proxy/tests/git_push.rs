//! One approval per git push (#26), end to end on the host: a box-side client speaking CONNECT and
//! TLS to the egress proxy, against a local `github.com` origin with its own CA.
//!
//! - A push's ref discovery and its upload are one request: the push asks once, and both requests
//!   (and a retry) pass on one approval.
//! - That approval covers the push for a short window, which ends: then the push is asked about again.
//! - The request bodies aren't read or judged: which refs a push may update is the forge's to enforce
//!   (a scoped token, branch rules); the body goes upstream byte for byte.
//! - A fetch is unaffected: still reads, allowed by reach, never asked about (#179).

use bytes::Bytes;
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use wicket_core::{RunId, TenantId, ZoneSpec};
use wicket_proxy::ca::RunCa;
use wicket_proxy::decide::Central;
use wicket_proxy::egress::{Egress, Upstream};
use wicket_proxy::RunCtx;
use wicket_store::{Approval, Ledger};

const OLD: &str = "1111111111111111111111111111111111111111";
const NEW: &str = "2222222222222222222222222222222222222222";

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("gitpush-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Fetches of acme/app are in reach; pushes are not.
fn zone() -> ZoneSpec {
    serde_json::from_value(serde_json::json!({
        "name": "pushzone",
        "reach": [
            {"host": "github.com", "methods": ["GET", "POST"], "paths": ["/acme/app.git/info/refs", "/acme/app.git/git-upload-pack"]}
        ]
    }))
    .unwrap()
}

/// What the origin saw: per request, its method, path and query, and its body.
type Seen = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

async fn origin(ca: &RunCa, seen: Seen) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let mut cfg = (*ca.server_config("github.com").unwrap()).clone();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let (acceptor, seen) = (acceptor.clone(), seen.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(s).await else { return };
                let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let seen = seen.clone();
                    async move {
                        let (m, pq) = (req.method().to_string(), req.uri().path_and_query().unwrap().to_string());
                        let body = req.into_body().collect().await?.to_bytes().to_vec();
                        let n = body.len();
                        seen.lock().unwrap().push((m, pq, body));
                        Ok::<_, hyper::Error>(http::Response::new(http_body_util::Full::new(Bytes::from(format!("origin got {n}")))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), svc).await;
            });
        }
    });
    addr
}

struct World {
    sock: PathBuf,
    seen: Seen,
    ledger: Arc<Mutex<Ledger>>,
    dir: PathBuf,
}

impl World {
    async fn new() -> World {
        let dir = tmpdir();
        let origin_ca = RunCa::generate("origin").unwrap();
        let seen: Seen = Arc::default();
        let resolve = [("github.com".to_string(), origin(&origin_ca, seen.clone()).await)].into_iter().collect();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let ctx = RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_push".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(zone()).unwrap()),
            org: None,
            ledger: ledger.clone(),
            vault: wicket_proxy::vault::Vault::new(dir.join("vault")),
            events: tx,
            escalate: true,
            attribute: None,
            identity: None,
            spawner: None,
            swaps: vec![],
            boxes: None,
            capacity: None,
            decisions: None,
            fence: None,
            waker: None,
            lifecycle: None,
        };
        let up = Upstream { resolve, roots_pem: Some(origin_ca.cert_pem()), ..Default::default() };
        let egress = Egress::with_upstream(ctx, Arc::new(RunCa::generate("run_push").unwrap()), Arc::new(Central), None, up).unwrap();
        let sock = dir.join("egress.sock");
        let s2 = sock.clone();
        tokio::spawn(async move { egress.serve(&s2).await });
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        World { sock, seen, ledger, dir }
    }

    /// One request on its own connection: (status, body).
    async fn send(&self, method: &str, pq: &str, body: &[u8]) -> (u16, String) {
        let mut s = UnixStream::connect(&self.sock).await.unwrap();
        s.write_all(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n").await.unwrap();
        let head = read_head(&mut s).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from("github.com").unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.unwrap();
        let ct = if method == "POST" { "Content-Type: application/x-git-receive-pack-request\r\n" } else { "" };
        let len = if method == "POST" { format!("Content-Length: {}\r\n", body.len()) } else { String::new() };
        tls.write_all(format!("{method} {pq} HTTP/1.1\r\nHost: github.com\r\n{ct}{len}\r\n").as_bytes()).await.unwrap();
        tls.write_all(body).await.unwrap();
        tls.flush().await.unwrap();
        let head = read_head(&mut tls).await;
        let status: u16 = head[9..12].parse().unwrap();
        let n: usize = head
            .lines()
            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
            .unwrap_or_else(|| panic!("no content-length: {head}"));
        let mut b = vec![0u8; n];
        tls.read_exact(&mut b).await.unwrap();
        (status, String::from_utf8_lossy(&b).into_owned())
    }

    async fn discover(&self, repo: &str) -> (u16, String) {
        self.send("GET", &format!("{repo}/info/refs?service=git-receive-pack"), b"").await
    }

    async fn upload(&self, repo: &str, refs: &[&str]) -> (u16, String) {
        self.send("POST", &format!("{repo}/git-receive-pack"), &push_body(refs)).await
    }

    fn pending(&self) -> Vec<wicket_store::Request> {
        self.ledger.lock().unwrap().pending(&TenantId::single()).unwrap()
    }

    fn approve(&self, id: &str, ttl: Duration) {
        let a = Approval { uses: Some(1), ttl, path_prefix: None, decided_by: "human:test".into() };
        self.ledger.lock().unwrap().approve(id, &a).unwrap();
    }

    fn origin_saw(&self) -> Vec<(String, String)> {
        self.seen.lock().unwrap().iter().map(|(m, p, _)| (m.clone(), p.clone())).collect()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).await.unwrap(), 1, "closed in the head: {}", String::from_utf8_lossy(&head));
        head.push(b[0]);
    }
    String::from_utf8(head).unwrap()
}

fn pkt(s: &str) -> Vec<u8> {
    let mut v = format!("{:04x}", s.len() + 4).into_bytes();
    v.extend_from_slice(s.as_bytes());
    v
}

/// A receive-pack body: one command per ref, a flush, then pack bytes.
fn push_body(refs: &[&str]) -> Vec<u8> {
    let mut b = Vec::new();
    for (i, r) in refs.iter().enumerate() {
        let caps = if i == 0 { "\0report-status side-band-64k" } else { "" };
        b.extend(pkt(&format!("{OLD} {NEW} {r}{caps}\n")));
    }
    b.extend(b"0000PACK\0\0\0\x02\0\0\0\0");
    b.extend(std::iter::repeat_n(b'p', 100_000));
    b
}

const REPO: &str = "/acme/app.git";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_asks_once_and_both_requests_pass_on_one_approval() {
    let w = World::new().await;
    let (st, body) = w.discover(REPO).await;
    assert_eq!(st, 403, "{body}");
    assert!(body.contains("needs human approval") || body.contains("await_grant"), "{body}");
    let p = w.pending();
    assert_eq!(p.len(), 1);
    let rid = p[0].id.clone();
    // One typed request: the push of the repository, at push risk.
    assert_eq!((p[0].method.as_str(), p[0].host.as_str(), p[0].path.as_str()), ("POST", "github.com", "/acme/app.git/git-receive-pack"));
    assert_eq!(p[0].risk, "R4ExecOrPrivilege");
    assert!(p[0].reason.starts_with("git push to github.com/acme/app.git"), "{}", p[0].reason);
    assert!(body.contains(&rid), "{body}");
    // The upload, unapproved, is the same request.
    let (st, body) = w.upload(REPO, &["refs/heads/feat"]).await;
    assert_eq!(st, 403, "{body}");
    assert!(body.contains(&rid), "{body}");
    assert_eq!(w.pending().len(), 1, "asked once");
    assert!(w.origin_saw().is_empty());

    // One approval (a single use, as the human picked; a push gets its window instead).
    w.approve(&rid, Duration::from_secs(3600));
    let (st, body) = w.discover(REPO).await;
    assert_eq!((st, body.as_str()), (200, "origin got 0"));
    let sent = push_body(&["refs/heads/feat", "refs/tags/v1"]);
    let (st, body) = w.upload(REPO, &["refs/heads/feat", "refs/tags/v1"]).await;
    assert_eq!((st, body), (200, format!("origin got {}", sent.len())), "the whole body, commands and pack, went upstream");
    assert_eq!(w.seen.lock().unwrap()[1].2, sent, "byte for byte");
    // git's retry: still nothing new to ask.
    assert_eq!(w.upload(REPO, &["refs/heads/feat"]).await.0, 200);
    assert!(w.pending().is_empty(), "nothing else was asked");
    assert_eq!(
        w.origin_saw(),
        [
            ("GET".to_string(), "/acme/app.git/info/refs?service=git-receive-pack".to_string()),
            ("POST".into(), "/acme/app.git/git-receive-pack".into()),
            ("POST".into(), "/acme/app.git/git-receive-pack".into())
        ]
    );
    // Another repository is another push: it is asked about on its own.
    assert_eq!(w.discover("/acme/other.git").await.0, 403);
    assert_eq!(w.pending().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_push_window_expires() {
    let w = World::new().await;
    assert_eq!(w.discover(REPO).await.0, 403);
    let rid = w.pending()[0].id.clone();
    w.approve(&rid, Duration::from_secs(2));
    assert_eq!(w.discover(REPO).await.0, 200);
    assert_eq!(w.upload(REPO, &["refs/heads/feat"]).await.0, 200);
    tokio::time::sleep(Duration::from_millis(3100)).await;
    // The window has passed: the next push is a new request for a human.
    let (st, body) = w.discover(REPO).await;
    assert_eq!(st, 403, "{body}");
    let p = w.pending();
    assert_eq!(p.len(), 1);
    assert_ne!(p[0].id, rid);
    assert_eq!(w.upload(REPO, &["refs/heads/feat"]).await.0, 403);
    assert_eq!(w.origin_saw().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fetch_is_unaffected() {
    let w = World::new().await;
    let (st, body) = w.send("GET", "/acme/app.git/info/refs?service=git-upload-pack", b"").await;
    assert_eq!((st, body.as_str()), (200, "origin got 0"));
    let (st, _) =
        w.send("POST", "/acme/app.git/git-upload-pack", b"0032want 1111111111111111111111111111111111111111\n00000009done\n").await;
    assert_eq!(st, 200);
    assert!(w.pending().is_empty(), "a fetch is never asked about");
    // Still a read (#179), and not a push.
    let op =
        |m: &str, p: &str, q: &str| wicket_core::Op::egress_with_query(&TenantId::single(), &RunId("r".into()), "z", m, "github.com", p, q);
    assert_eq!(op("POST", "/acme/app.git/git-upload-pack", "").risk, wicket_core::RiskClass::R1ReadScoped);
    assert_eq!(op("GET", "/acme/app.git/info/refs", "service=git-upload-pack").risk, wicket_core::RiskClass::R1ReadScoped);
    assert_eq!(wicket_core::git::push_repo("GET", "/acme/app.git/info/refs", "service=git-upload-pack"), None);
    assert_eq!(wicket_core::git::push_repo("POST", "/acme/app.git/git-upload-pack", ""), None);
}

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
