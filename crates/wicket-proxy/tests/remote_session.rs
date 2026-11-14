//! A remote session's login, end to end through the egress proxy (#169), against a stub of a
//! vendor's remote-session API (shaped like Claude Code's Remote Control: register an environment,
//! poll it for work, then the session's worker channel with a per-session token the API handed out).
//! The box holds only the login's placeholder. Checked:
//! - the origin gets the real login, swapped in for the placeholder, on the login's paths;
//! - the per-session token the box got from the API goes up as the box sent it (`box_bearers`), and
//!   without `box_bearers` it is dropped;
//! - a forbidden path never reaches the origin, and one outside reach waits for a human;
//! - nothing that comes back to the box holds the login.

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

const HOST: &str = "rc.api.test";
const LOGIN: &str = "real-login-token-0f9d";
const PLACEHOLDER: &str = "login-placeholder-run-rc";
const SESSION_TOKEN: &str = "per-session-token-77";

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("remote-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn zone() -> ZoneSpec {
    serde_json::from_value(serde_json::json!({
        "name": "remote",
        "reach": [
            {"host": HOST, "methods": ["POST"], "paths": ["/v1/environments/bridge"]},
            {"host": HOST, "methods": ["GET", "POST"], "paths": ["/v1/environments/*/work/**"]},
            {"host": HOST, "methods": ["GET", "POST", "PUT"], "paths": ["/v1/code/sessions/*/worker/**"]}
        ],
        "forbid": [{"host": HOST, "paths": ["/v1/mcp_servers", "/v1/mcp_servers/**"]}]
    }))
    .unwrap()
}

/// What the stub API saw: (method, path, Authorization).
type Seen = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

/// The stub: registration and work polls answer only to the real login; the worker channel only to
/// the per-session token it handed out.
async fn stub(ca: &RunCa, seen: Seen) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let mut cfg = (*ca.server_config(HOST).unwrap()).clone();
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
                        let auth = req.headers().get("authorization").map(|v| v.to_str().unwrap().to_string());
                        let path = req.uri().path().to_string();
                        seen.lock().unwrap().push((req.method().to_string(), path.clone(), auth.clone()));
                        let login_ok = auth.as_deref() == Some(&format!("Bearer {LOGIN}"));
                        let (status, body) = match path.as_str() {
                            "/v1/environments/bridge" if login_ok => (200, r#"{"environment_id":"env_1"}"#.to_string()),
                            "/v1/environments/env_1/work/poll" if login_ok => {
                                (200, format!(r#"{{"id":"work_1","data":{{"type":"session","id":"cse_1"}},"secret":"{SESSION_TOKEN}"}}"#))
                            }
                            "/v1/code/sessions/cse_1/worker/events" if auth.as_deref() == Some(&format!("Bearer {SESSION_TOKEN}")) => {
                                (200, r#"{"ok":true}"#.to_string())
                            }
                            _ => (401, r#"{"error":"unauthorized"}"#.to_string()),
                        };
                        let mut r = http::Response::new(http_body_util::Full::new(Bytes::from(body)));
                        *r.status_mut() = http::StatusCode::from_u16(status).unwrap();
                        Ok::<_, hyper::Error>(r)
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
    ledger: Arc<Mutex<wicket_store::Ledger>>,
    dir: PathBuf,
}

impl World {
    async fn new(box_bearers: bool) -> World {
        let dir = tmpdir();
        let origin_ca = RunCa::generate("origin").unwrap();
        let seen: Seen = Arc::default();
        let mut resolve = HashMap::new();
        resolve.insert(HOST.to_string(), stub(&origin_ca, seen.clone()).await);
        let vault = wicket_proxy::vault::Vault::new(dir.join("vault"));
        vault.set("login", LOGIN).unwrap();
        vault.set_hosts("login", &[HOST.into()]).unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
        });
        let ledger = Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().unwrap()));
        let ctx = RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_rc".into()),
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
                name: "account login".into(),
                host: HOST.into(),
                placeholder: PLACEHOLDER.into(),
                real: SwapSource::Vault("login".into()),
                box_bearers,
            }],
            boxes: None,
            capacity: None,
            fence: None,
            waker: None,
        };
        let up = Upstream { resolve, roots_pem: Some(origin_ca.cert_pem()), ..Default::default() };
        let egress = Egress::with_upstream(ctx, Arc::new(RunCa::generate("run_rc").unwrap()), Arc::new(Central), None, up).unwrap();
        let sock = dir.join("egress.sock");
        let s2 = sock.clone();
        tokio::spawn(async move { egress.serve(&s2).await });
        // Ready once its socket exists (bound and listening): on a loaded host that can take seconds.
        for _ in 0..3000 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(sock.exists(), "the proxy's socket {} never appeared", sock.display());
        World { sock, seen, ledger, dir }
    }

    /// One request from the box: CONNECT, TLS (any certificate), and an HTTP/1.1 request with this
    /// bearer. Returns the status line and body the box got.
    async fn call(&self, method: &str, path: &str, bearer: &str) -> (String, String) {
        let mut s = UnixStream::connect(&self.sock).await.unwrap();
        s.write_all(format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes()).await.unwrap();
        let (head, _) = read_head(&mut s).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(HOST.to_string()).unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.unwrap();
        let body = if method == "GET" { "" } else { "{}" };
        tls.write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        tls.flush().await.unwrap();
        let (head, rest) = read_head(&mut tls).await;
        let len: usize = head
            .lines()
            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
            .unwrap_or(rest.len());
        let mut body = rest;
        while body.len() < len {
            let mut b = vec![0u8; len - body.len()];
            let n = tls.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            body.extend_from_slice(&b[..n]);
        }
        (head.lines().next().unwrap_or("").to_string(), String::from_utf8_lossy(&body).into_owned())
    }

    fn seen_at(&self, path: &str) -> Vec<Option<String>> {
        self.seen.lock().unwrap().iter().filter(|(_, p, _)| p == path).map(|(_, _, a)| a.clone()).collect()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> (String, Vec<u8>) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).await.unwrap(), 1, "closed in the head: {}", String::from_utf8_lossy(&head));
        head.push(b[0]);
    }
    (String::from_utf8(head).unwrap(), vec![])
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remote_session_registers_and_works_with_only_a_placeholder_in_the_box() {
    let w = World::new(true).await;
    let mut back = String::new();
    // Registration and the work poll: the real login reaches the API, swapped for the placeholder.
    let (st, body) = w.call("POST", "/v1/environments/bridge", PLACEHOLDER).await;
    assert!(st.contains(" 200"), "{st} {body}");
    back.push_str(&body);
    let (st, body) = w.call("GET", "/v1/environments/env_1/work/poll", PLACEHOLDER).await;
    assert!(st.contains(" 200") && body.contains(SESSION_TOKEN), "{st} {body}");
    back.push_str(&body);
    assert_eq!(w.seen_at("/v1/environments/bridge"), [Some(format!("Bearer {LOGIN}"))]);
    assert_eq!(w.seen_at("/v1/environments/env_1/work/poll"), [Some(format!("Bearer {LOGIN}"))]);
    // The worker channel, with the per-session token the API handed the box: up as the box sent it.
    let (st, body) = w.call("POST", "/v1/code/sessions/cse_1/worker/events", SESSION_TOKEN).await;
    assert!(st.contains(" 200"), "{st} {body}");
    back.push_str(&body);
    assert_eq!(w.seen_at("/v1/code/sessions/cse_1/worker/events"), [Some(format!("Bearer {SESSION_TOKEN}"))]);
    // A forbidden path never reaches the API.
    let (st, body) = w.call("GET", "/v1/mcp_servers", PLACEHOLDER).await;
    assert!(st.contains(" 403") && body.contains("never allowed"), "{st} {body}");
    back.push_str(&body);
    assert!(w.seen_at("/v1/mcp_servers").is_empty());
    // One outside reach waits for a human, and doesn't reach the API either.
    let (st, body) = w.call("GET", "/v1/sessions", PLACEHOLDER).await;
    assert!(st.contains(" 403") && body.contains("request_id"), "{st} {body}");
    back.push_str(&body);
    assert!(w.seen_at("/v1/sessions").is_empty());
    let pending = w.ledger.lock().unwrap().pending(&TenantId::single()).unwrap();
    assert!(pending.iter().any(|r| r.host == HOST && r.path == "/v1/sessions"), "{pending:?}");
    // Nothing that came back to the box holds the login.
    assert!(!back.contains(LOGIN), "{back}");
    // The login went up only where it was swapped in.
    let with_login: Vec<String> = w
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, a)| a.as_deref().is_some_and(|a| a.contains(LOGIN)))
        .map(|(_, p, _)| p.clone())
        .collect();
    assert_eq!(with_login, ["/v1/environments/bridge", "/v1/environments/env_1/work/poll"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_box_bearers_a_token_the_box_holds_is_dropped() {
    let w = World::new(false).await;
    let (st, _) = w.call("POST", "/v1/code/sessions/cse_1/worker/events", SESSION_TOKEN).await;
    assert!(st.contains(" 401"), "{st}");
    assert_eq!(w.seen_at("/v1/code/sessions/cse_1/worker/events"), [None]);
    // The placeholder is still swapped.
    let (st, _) = w.call("POST", "/v1/environments/bridge", PLACEHOLDER).await;
    assert!(st.contains(" 200"), "{st}");
}
