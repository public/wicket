//! Placeholders as canaries, and the reflected-secret guard (#362), end to end through the egress
//! proxy against an origin that echoes back what it was sent. The box holds a placeholder for
//! `echo.test`'s credential. Checked:
//! - a reply that reflects the credential (raw, base64, hex) reaches the box with it masked, and
//!   the reflection is audited;
//! - the placeholder sent to another host, in the body, in the URL or in another header is refused
//!   before anything reaches the origin, audited as an anomaly, and counted as a strike;
//! - another run's placeholder is refused the same way;
//! - a compressed reply from the credentialed host is refused, and the request asked for none;
//! - a bearer on the host that isn't the placeholder is dropped, and audited.

use base64::Engine;
use bytes::Bytes;
use std::collections::HashMap;
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
use wicket_proxy::{CredentialSwap, RunCtx, SwapSource};

const HOST: &str = "echo.test";
const OTHER: &str = "other.test";
const SECRET: &str = "real-echo-credential-5e1f9a";
const PLACEHOLDER: &str = "sk-ant-oat01-wicket-placeholder-run-01jcanary0000000000000000aa";
const FOREIGN: &str = "sk-ant-oat01-wicket-placeholder-run-01jother00000000000000000zz";

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("canary-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn zone() -> ZoneSpec {
    serde_json::from_value(serde_json::json!({
        "name": "canary",
        "reach": [
            {"host": HOST, "methods": ["GET", "POST"]},
            {"host": OTHER, "methods": ["GET", "POST"]}
        ]
    }))
    .unwrap()
}

/// Everything an origin saw, as text: request lines, headers and bodies.
type Seen = Arc<Mutex<String>>;

/// The echoing origin: answers with what it was sent. `/forms` answers with the Authorization's
/// token in base64 (inside a longer value, as Basic credentials hold one) and hex; `/gzip` claims a
/// gzip-encoded body.
async fn origin(ca: &RunCa, name: &str, seen: Seen) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let mut cfg = (*ca.server_config(name).unwrap()).clone();
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
                        use http_body_util::BodyExt;
                        let mut text = format!("{} {}\n", req.method(), req.uri());
                        for (k, v) in req.headers() {
                            text.push_str(&format!("{k}: {}\n", String::from_utf8_lossy(v.as_bytes())));
                        }
                        let path = req.uri().path().to_string();
                        let token = req
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.strip_prefix("Bearer "))
                            .unwrap_or("")
                            .to_string();
                        let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                        text.push('\n');
                        text.push_str(&String::from_utf8_lossy(&body));
                        seen.lock().unwrap().push_str(&format!("{text}\n----\n"));
                        let mut r = http::Response::builder().header("x-echo", "yes");
                        let out = match path.as_str() {
                            "/forms" => {
                                let b64 = base64::engine::general_purpose::STANDARD.encode(format!("git:{token}"));
                                format!("{{\"basic\":\"{b64}\",\"hex\":\"{}\",\"raw\":\"{token}\"}}", hex::encode(&token))
                            }
                            "/gzip" => {
                                r = r.header("content-encoding", "gzip");
                                "\u{1f}\u{8b}not really gzip".to_string()
                            }
                            _ => text,
                        };
                        Ok::<_, hyper::Error>(r.body(http_body_util::Full::new(Bytes::from(out))).unwrap())
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
    seen: HashMap<&'static str, Seen>,
    ledger: Arc<Mutex<wicket_store::Ledger>>,
    dir: PathBuf,
}

impl World {
    async fn new() -> World {
        let dir = tmpdir();
        let origin_ca = RunCa::generate("origin").unwrap();
        let mut resolve = HashMap::new();
        let mut seen = HashMap::new();
        for name in [HOST, OTHER] {
            let s: Seen = Arc::default();
            resolve.insert(name.to_string(), origin(&origin_ca, name, s.clone()).await);
            seen.insert(name, s);
        }
        let vault = wicket_proxy::vault::Vault::new(dir.join("vault"));
        vault.set("echo", SECRET).unwrap();
        vault.set_hosts("echo", &[HOST.into()]).unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
        });
        let ledger = Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().unwrap()));
        let ctx = RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_01jcanary0000000000000000aa".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(zone()).unwrap()),
            org: None,
            ledger: ledger.clone(),
            vault,
            events: tx,
            escalate: true,
            attribute: None,
            identity: None,
            spawner: None,
            swaps: vec![CredentialSwap {
                name: "echo login".into(),
                host: HOST.into(),
                placeholder: PLACEHOLDER.into(),
                real: SwapSource::Vault("echo".into()),
                box_bearers: false,
            }],
            boxes: None,
            capacity: None,
            decisions: None,
            fence: None,
            waker: None,
            lifecycle: None,
        };
        let up = Upstream { resolve, roots_pem: Some(origin_ca.cert_pem()), ..Default::default() };
        let egress = Egress::with_upstream(ctx, Arc::new(RunCa::generate("run_canary").unwrap()), Arc::new(Central), None, up).unwrap();
        let sock = dir.join("egress.sock");
        let s2 = sock.clone();
        tokio::spawn(async move { egress.serve(&s2).await });
        for _ in 0..3000 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(sock.exists(), "the proxy's socket {} never appeared", sock.display());
        World { sock, seen, ledger, dir }
    }

    /// One request from the box to `host`, with these extra header lines and body (sent with its
    /// length, so it streams upstream). Returns the status line and body the box got.
    async fn call(&self, host: &str, method: &str, path: &str, headers: &str, body: &str) -> (String, String) {
        let mut s = UnixStream::connect(&self.sock).await.unwrap();
        s.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes()).await.unwrap();
        let head = read_head(&mut s).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.unwrap();
        let length = if method == "GET" { String::new() } else { format!("Content-Length: {}\r\n", body.len()) };
        tls.write_all(format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n{headers}{length}Connection: close\r\n\r\n{body}").as_bytes())
            .await
            .unwrap();
        tls.flush().await.unwrap();
        let head = read_head(&mut tls).await;
        let len: Option<usize> =
            head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()));
        let mut body = Vec::new();
        match len {
            Some(len) => {
                while body.len() < len {
                    let mut b = vec![0u8; len - body.len()];
                    match tls.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&b[..n]),
                    }
                }
            }
            None => {
                let _ = tls.read_to_end(&mut body).await;
            }
        }
        (head, String::from_utf8_lossy(&body).into_owned())
    }

    fn seen(&self, host: &str) -> String {
        self.seen[host].lock().unwrap().clone()
    }

    /// The audit records of `kind`, as JSON text.
    fn audits(&self, kind: &str) -> Vec<String> {
        self.ledger.lock().unwrap().audit_tail(1000).unwrap().into_iter().filter(|r| r.2 == kind).map(|r| r.4).collect()
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

fn bearer(token: &str) -> String {
    format!("Authorization: Bearer {token}\r\n")
}

/// Every form of the secret the guard masks.
fn leaks(text: &str) -> bool {
    let b64 = base64::engine::general_purpose::STANDARD.encode(format!("git:{SECRET}"));
    text.contains(SECRET) || text.contains(&hex::encode(SECRET)) || text.contains(&b64[8..b64.len() - 4])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_echoed_credential_reaches_the_box_masked() {
    let w = World::new().await;
    // The origin echoes the whole request back, the swapped-in credential with it.
    let (head, body) = w.call(HOST, "GET", "/echo", &bearer(PLACEHOLDER), "").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(w.seen(HOST).contains(&format!("authorization: Bearer {SECRET}")), "the origin got the real credential");
    assert!(body.contains("authorization: Bearer ****"), "{body}");
    assert!(!leaks(&body) && !leaks(&head), "{head}{body}");
    // It was asked for an unencoded reply, whatever the box asked for.
    assert!(w.seen(HOST).contains("accept-encoding: identity"), "{}", w.seen(HOST));
    // Raw, in base64 inside a longer value, and in hex: all masked.
    let (head, body) = w.call(HOST, "GET", "/forms", &format!("{}Accept-Encoding: gzip\r\n", bearer(PLACEHOLDER)), "").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(!leaks(&body), "{body}");
    assert!(body.contains("\"raw\":\"****"), "{body}");
    let reflected = w.audits("anomaly");
    assert!(reflected.len() == 2 && reflected.iter().all(|a| a.contains("secret.reflected")), "{reflected:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_placeholder_out_of_its_slot_is_refused_audited_and_struck() {
    let w = World::new().await;
    let cases: Vec<(&str, &str, String, String, &str)> = vec![
        // To the wrong host, in its slot there.
        (OTHER, "/x", bearer(PLACEHOLDER), String::new(), "sent to other.test"),
        // In the body, to its own host and to another.
        (HOST, "/x", String::new(), format!("{{\"token\":\"{PLACEHOLDER}\"}}"), "body"),
        (OTHER, "/x", String::new(), format!("{{\"token\":\"{PLACEHOLDER}\"}}"), "body"),
        // In the URL, plain and percent-encoded.
        (HOST, "/x?token=PH", String::new(), String::new(), "URL"),
        (OTHER, "/x?t=%73k-ant-oat01-wicket-placeholder-run-01jcanary0000000000000000aa", String::new(), String::new(), "URL"),
        // In another header, on its own host.
        (HOST, "/x", format!("X-Api-Key: {PLACEHOLDER}\r\n"), String::new(), "x-api-key header"),
        // Another run's, even in the slot on this one's host.
        (HOST, "/x", bearer(FOREIGN), String::new(), "another run's"),
        (OTHER, "/x", format!("Cookie: s={FOREIGN}\r\n"), String::new(), "another run's"),
    ];
    for (i, (host, path, headers, body, why)) in cases.iter().enumerate() {
        let path = path.replace("PH", PLACEHOLDER);
        let method = if body.is_empty() { "GET" } else { "POST" };
        let (head, answer) = w.call(host, method, &path, headers, body).await;
        assert!(head.starts_with("HTTP/1.1 403"), "case {i}: {head}{answer}");
        assert!(answer.contains("never allowed") && answer.contains(why), "case {i}: {answer}");
    }
    // Nothing of either placeholder (or the credential) reached either origin.
    for host in [HOST, OTHER] {
        let seen = w.seen(host);
        assert!(!seen.contains("wicket-placeholder") && !seen.contains(SECRET), "{host} saw: {seen}");
    }
    let moved = w.audits("anomaly");
    assert_eq!(moved.len(), cases.len(), "{moved:?}");
    assert!(moved.iter().all(|a| a.contains("placeholder.moved")), "{moved:?}");
    // Counted as strikes: the agent is told to stop.
    let (_, answer) = w.call(OTHER, "GET", "/x", &bearer(PLACEHOLDER), "").await;
    assert!(answer.contains("stop retrying it"), "{answer}");
    // The slot itself still works.
    let (head, _) = w.call(HOST, "GET", "/echo", &bearer(PLACEHOLDER), "").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_compressed_reply_from_a_credentialed_host_is_refused() {
    let w = World::new().await;
    let (head, body) = w.call(HOST, "GET", "/gzip", &format!("{}Accept-Encoding: gzip, br\r\n", bearer(PLACEHOLDER)), "").await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}{body}");
    assert!(body.contains("gzip-encoded"), "{body}");
    assert!(w.seen(HOST).contains("accept-encoding: identity") && !w.seen(HOST).contains("accept-encoding: gzip"), "{}", w.seen(HOST));
    assert!(w.audits("anomaly").iter().any(|a| a.contains("response.encoded")));
    // A host no credential goes to keeps its encoding.
    let (head, _) = w.call(OTHER, "GET", "/gzip", "Accept-Encoding: gzip\r\n", "").await;
    assert!(head.starts_with("HTTP/1.1 200") && head.to_ascii_lowercase().contains("content-encoding: gzip"), "{head}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_bearer_on_a_placeholder_host_is_dropped_and_audited() {
    let w = World::new().await;
    for _ in 0..2 {
        let (head, _) = w.call(HOST, "GET", "/echo", &bearer("stale-or-forged-token"), "").await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    }
    assert!(!w.seen(HOST).contains("stale-or-forged-token") && !w.seen(HOST).contains("authorization"), "{}", w.seen(HOST));
    assert_eq!(w.audits("placeholder.unknown").len(), 1, "once per host per run");
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
