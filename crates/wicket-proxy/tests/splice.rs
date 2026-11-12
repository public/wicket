//! Splice-through (#62), end to end on the host: a box-side client speaking CONNECT to the egress
//! proxy's unix socket, then TLS, against local origins with their own CA. A host the zone allows
//! wholesale is spliced (the box sees the origin's own certificate); any other host is intercepted
//! (the box sees a leaf from the run's CA).

use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use wicket_core::{RunId, TenantId, ZoneSpec};
use wicket_proxy::ca::RunCa;
use wicket_proxy::decide::{Central, NodeDecider};
use wicket_proxy::egress::{Egress, Upstream};
use wicket_proxy::{Event, RunCtx};

const ALL: [&str; 7] = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("splice-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn zone() -> ZoneSpec {
    serde_json::from_value(serde_json::json!({
        "name": "splicezone",
        "reach": [
            {"host": "open.test", "methods": ALL},
            {"host": "checked.test", "methods": ["GET"]},
            {"host": "fenced.test", "methods": ALL},
            {"host": "private.test", "methods": ALL},
            {"host": "registry.test", "methods": ["GET"]}
        ],
        "forbid": [
            {"host": "fenced.test", "paths": ["/admin/**"]},
            {"host": "registry.test", "paths": ["/@evil/**"]}
        ]
    }))
    .unwrap()
}

/// One TLS origin per name, all signed by `ca`; each answers `origin <path>`, or N bytes for `/bytes/N`.
async fn origins(ca: &RunCa, names: &[&str]) -> HashMap<String, SocketAddr> {
    let mut out = HashMap::new();
    for name in names {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        out.insert(name.to_string(), l.local_addr().unwrap());
        let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config(name).unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(s).await else { return };
                    let svc = hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
                        // The path exactly as it arrived, escapes and all.
                        let p = req.uri().path().to_string();
                        let body = match p.strip_prefix("/bytes/").and_then(|n| n.parse::<usize>().ok()) {
                            Some(n) => Bytes::from(vec![b'x'; n]),
                            None => Bytes::from(format!("origin {p}")),
                        };
                        Ok::<_, std::convert::Infallible>(http::Response::new(http_body_util::Full::new(body)))
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), svc).await;
                });
            }
        });
    }
    out
}

struct World {
    sock: PathBuf,
    ledger: Arc<Mutex<wicket_store::Ledger>>,
    agent: String,
    events: Mutex<tokio::sync::mpsc::UnboundedReceiver<Event>>,
    dir: PathBuf,
}

impl World {
    async fn new() -> World {
        World::with(None).await
    }

    /// The proxy as the control host runs it, or (with a node decider) as a node does: the node's
    /// feed decides, there is no activation fence, and interception uses the node's own CA.
    async fn with(node: Option<Arc<NodeDecider>>) -> World {
        let dir = tmpdir();
        let origin_ca = RunCa::generate("origin").unwrap();
        let resolve = origins(&origin_ca, &["open.test", "checked.test", "fenced.test", "registry.test"]).await;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        // This run is generation 1 of a long-lived agent, so a later wake supersedes it (#70).
        let mut ledger = wicket_store::Ledger::open_in_memory().unwrap();
        let agent = wicket_store::new_agent_id();
        ledger
            .create_agent(&wicket_store::NewAgent {
                id: &agent,
                tenant: "t0",
                zone: "splicezone",
                name: "a",
                run: "run_splice",
                session_id: "s",
                manifest: "m",
                image: "i",
                workspace: None,
                lease_until: 0,
            })
            .unwrap();
        assert!(ledger.commit_agent_push(&agent, 1, 0, 1, "h", 1).unwrap());
        let ledger = Arc::new(Mutex::new(ledger));
        let ctx = RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_splice".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(zone()).unwrap()),
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
            fence: node.is_none().then(|| wicket_proxy::Fence { agent: agent.clone(), generation: 1 }),
            waker: None,
        };
        let mut up = Upstream { resolve, roots_pem: Some(origin_ca.cert_pem()), ..Default::default() };
        // Not pinned: checked like a real DNS answer (#116), and refused.
        up.dns.insert("private.test".into(), vec!["127.0.0.1".parse().unwrap()]);
        let egress = match node {
            None => Egress::with_upstream(ctx, Arc::new(RunCa::generate("run_splice").unwrap()), Arc::new(Central), None, up),
            Some(d) => Egress::with_upstream(ctx, Arc::new(RunCa::generate("node").unwrap()), d, None, up),
        }
        .unwrap();
        let sock = dir.join("egress.sock");
        let s2 = sock.clone();
        tokio::spawn(async move { egress.serve(&s2).await });
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        World { sock, ledger, agent, events: Mutex::new(rx), dir }
    }

    fn events(&self) -> Vec<(String, String, String)> {
        let mut v = vec![];
        while let Ok(e) = self.events.lock().unwrap().try_recv() {
            if let Event::Egress { host, outcome, detail, .. } = e {
                v.push((host, outcome, detail));
            }
        }
        v
    }

    /// CONNECTs to `host`, returning the proxy's status line and the stream after it.
    async fn connect(&self, host: &str) -> (String, UnixStream) {
        let mut s = UnixStream::connect(&self.sock).await.unwrap();
        s.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(s.read(&mut b).await.unwrap(), 1, "proxy closed during the CONNECT answer");
            head.push(b[0]);
        }
        let text = String::from_utf8(head).unwrap();
        // A refusal carries a body; read it so the status line can say why.
        if !text.starts_with("HTTP/1.1 200") {
            let mut rest = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut rest)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
            return (format!("{text}{}", String::from_utf8_lossy(&rest[..n])), s);
        }
        (text, s)
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Accepts any server certificate (the test inspects which one it was).
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

/// TLS over `s` with SNI `sni`, then `GET path`: the leaf's issuer CN and the response body.
async fn get(s: UnixStream, sni: &str, path: &str) -> (String, Vec<u8>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.unwrap();
    let leaf = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    let (_, cert) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    let issuer = cert.issuer().iter_common_name().next().unwrap().as_str().unwrap().to_string();
    tls.write_all(format!("GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;
    let body = match resp.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => resp[i + 4..].to_vec(),
        None => resp,
    };
    (issuer, body)
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wholesale_host_is_spliced_and_others_are_inspected() {
    let w = World::new().await;

    // Spliced: the origin's own certificate, end to end, and one audit row for the connection.
    let (status, s) = w.connect("open.test").await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let (issuer, body) = get(s, "open.test", "/hello").await;
    assert_eq!(issuer, "wicket run CA origin", "the box sees the origin's certificate");
    assert_eq!(body, b"origin /hello");
    settle().await;
    let ev = w.events();
    assert_eq!(ev.len(), 1, "{ev:?}");
    assert_eq!((ev[0].0.as_str(), ev[0].1.as_str()), ("open.test", "spliced"));
    assert!(ev[0].2.contains("reach rule 0") && ev[0].2.contains("bytes up") && !ev[0].2.contains(" 0 bytes up"), "{}", ev[0].2);

    // A large body through splice(2) arrives whole, and the row counts it.
    let (_, s) = w.connect("open.test").await;
    let (_, body) = get(s, "open.test", "/bytes/5000000").await;
    assert_eq!(body.len(), 5_000_000);
    settle().await;
    let ev = w.events();
    let down: u64 = ev[0].2.split(" bytes up, ").nth(1).unwrap().split(" down").next().unwrap().parse().unwrap();
    assert!(down > 5_000_000, "{}", ev[0].2);

    // Inspected (reach limits methods; a forbid rule names the host): the run CA's leaf, and a
    // decision per request.
    for host in ["checked.test", "fenced.test"] {
        let (status, s) = w.connect(host).await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let (issuer, body) = get(s, host, "/hello").await;
        assert_eq!(issuer, "wicket run CA run_splice", "{host} is intercepted");
        assert!(String::from_utf8_lossy(&body).contains("origin /hello"), "{host}");
        settle().await;
        let ev = w.events();
        assert!(ev.iter().any(|e| e.0 == host && e.1 == "allow"), "{host}: {ev:?}");
        assert!(!ev.iter().any(|e| e.1 == "spliced"), "{host}: {ev:?}");
    }
    // The forbid rule still applies to the intercepted host.
    let (_, s) = w.connect("fenced.test").await;
    let (_, body) = get(s, "fenced.test", "/admin/x").await;
    assert!(String::from_utf8_lossy(&body).contains("forbidden"), "{}", String::from_utf8_lossy(&body));
    w.events();
}

/// A ClientHello that names another host than the CONNECT is not spliced: it is intercepted, as any
/// other host is, so the box gets the run CA's leaf for the CONNECT host and its requests are
/// decided one by one (and Host pinning refuses the other name).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_sni_that_differs_from_the_connect_host_is_intercepted() {
    let w = World::new().await;
    let (status, s) = w.connect("open.test").await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let (issuer, body) = get(s, "checked.test", "/hello").await;
    assert_eq!(issuer, "wicket run CA run_splice");
    assert!(String::from_utf8_lossy(&body).contains("does not match the tunnel target"), "{}", String::from_utf8_lossy(&body));
    settle().await;
    let ev = w.events();
    assert!(!ev.iter().any(|e| e.1 == "spliced"), "{ev:?}");
    assert!(ev.iter().any(|e| e.0 == "open.test" && e.1 == "forbidden"), "{ev:?}");
}

/// The dial-time address check (#116) applies to spliced hosts: refused before the CONNECT is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spliced_host_resolving_to_a_private_address_is_not_dialled() {
    let w = World::new().await;
    let (status, _) = w.connect("private.test").await;
    assert!(status.starts_with("HTTP/1.1 502"), "{status}");
    assert!(status.contains("non-public"), "{status}");
    let ev = w.events();
    assert!(ev.iter().any(|e| e.0 == "private.test" && e.1 == "forbidden" && e.2.contains("non-public")), "{ev:?}");
}

/// A spliced connection is cut once its activation is superseded (#70): a newer wake of the agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spliced_connection_is_cut_when_its_activation_is_superseded() {
    let w = World::new().await;
    let (status, s) = w.connect("open.test").await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("open.test").unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.unwrap();
    // Kept alive: one request works, then the agent is woken again elsewhere.
    tls.write_all(b"GET /a HTTP/1.1\r\nHost: open.test\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tls.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("origin /a"));
    assert_eq!(w.ledger.lock().unwrap().claim_wake(&w.agent, "run_new", 0).unwrap(), Some(2));
    // Within a fence check or two, the connection is closed under the client.
    let closed = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the spliced connection outlived its activation");
    settle().await;
    let ev = w.events();
    assert!(ev.iter().any(|e| e.1 == "spliced" && e.2.contains("cut:") && e.2.contains("generation 2")), "{ev:?}");
}

/// #143: npm asks an inspected registry for a scoped package as `GET /@scope%2fname`. It is decided
/// as `/@scope/name` (so the forbid on `/@evil/**` holds) and sent upstream as written; any other
/// encoded separator is still refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn npm_scoped_packages_pass_an_inspected_registry() {
    let w = World::new().await;
    for (path, want) in [
        ("/@types%2fnode", "origin /@types%2fnode"),
        ("/@eslint-community%2Feslint-utils", "origin /@eslint-community%2Feslint-utils"),
        ("/@babel%2fcore/7.26.0", "origin /@babel%2fcore/7.26.0"),
        ("/@types/node", "origin /@types/node"),
    ] {
        let (status, s) = w.connect("registry.test").await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let (issuer, body) = get(s, "registry.test", path).await;
        assert_eq!(issuer, "wicket run CA run_splice", "the registry is inspected, not spliced");
        let body = String::from_utf8_lossy(&body);
        assert!(body.lines().any(|l| l == want), "{path}: {body}");
    }
    settle().await;
    let ev = w.events();
    assert_eq!(ev.iter().filter(|e| e.0 == "registry.test" && e.1 == "allow").count(), 4, "{ev:?}");
    for (path, refusal) in [
        ("/@evil%2fpkg", "never allowed"),
        ("/@evil/pkg", "never allowed"),
        ("/x%2fy", "malformed request"),
        ("/@types%2fnode%2fx", "malformed request"),
        ("/-/package/@types%2fnode/dist-tags", "malformed request"),
    ] {
        let (_, s) = w.connect("registry.test").await;
        let (_, body) = get(s, "registry.test", path).await;
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains(refusal) && !body.contains("origin"), "{path}: {body}");
    }
    settle().await;
    let ev = w.events();
    assert_eq!(ev.iter().filter(|e| e.1 == "forbidden").count(), 5, "{ev:?}");
}

/// A node's link to the control host that is never up (nothing in these tests escalates).
struct Offline;

impl wicket_proxy::decide::ControlLink for Offline {
    fn connected(&self) -> bool {
        false
    }
    fn ask<'a>(
        &'a self,
        _: &'a wicket_core::Op,
        _: &'a str,
        _: Option<&'a serde_json::Value>,
    ) -> futures_util::future::BoxFuture<'a, Result<wicket_proxy::decide::Asked, String>> {
        Box::pin(async { Err("offline".to_string()) })
    }
}

/// A node's feed for run_splice: its token minted from [`zone`], fresh for 1 s of the test's clock,
/// then narrow for 2 s, then closed. Returns the decider, the clock and the feed's directory.
fn node_feed(zone: &ZoneSpec, box_run: &str) -> (Arc<NodeDecider>, Arc<std::sync::atomic::AtomicI64>, PathBuf) {
    use ed25519_dalek::SigningKey;
    use wicket_feed::{Change, Issuer, KeyCert, Publisher, PublisherConfig, Replica, ReplicaConfig};
    let dir = tmpdir();
    let root = SigningKey::from_bytes(&[7; 32]);
    let key = SigningKey::from_bytes(&[8; 32]);
    let authz_root = wicket_authz::SigningKey::from_bytes(&[9; 32]).unwrap();
    let approver = wicket_authz::SigningKey::from_bytes(&[10; 32]).unwrap();
    let cert = KeyCert::new(&key.verifying_key(), 1, i64::MAX / 2, 30_000, 120_000);
    let cert_jws = wicket_feed::sign(&root, wicket_feed::TYP_KEY, &cert);
    let cfg = PublisherConfig { ttl_ms: 1_000, refresh_ms: 100, narrow_ms: 2_000, retain: 100 };
    let mut p = Publisher::open_with(&dir.join("pub"), "n1", &root.verifying_key(), key, &cert_jws, cfg, authz_root.public()).unwrap();
    let mut r = Replica::new_with("n1", root.verifying_key(), ReplicaConfig::default(), authz_root.public());
    let t0 = 1_000_000;
    let tenant = TenantId::single().0;
    let mut issuer =
        Issuer::root(&authz_root, &tenant, "run:run_splice", "run_splice", 0, zone, &[], 3_600, vec![approver.public()]).unwrap();
    if box_run != "run_splice" {
        // A child of run_splice, in the same zone.
        let c = wicket_authz::Ceiling::from_zone(zone, &format!("run_splice/{box_run}"), 3_600, vec![approver.public()]).unwrap();
        issuer = issuer.child(box_run, 0, zone, &c).unwrap();
    }
    p.commit(vec![Change::PutZone { zone: issuer.publish(&approver, &[]).unwrap() }], t0).unwrap();
    let hello = r.hello();
    for f in p.catch_up(&hello, t0).unwrap() {
        r.accept(&f, t0).unwrap();
    }
    let now = Arc::new(std::sync::atomic::AtomicI64::new(t0));
    let clock: wicket_proxy::decide::Clock = {
        let now = now.clone();
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    let d = Arc::new(NodeDecider { replica: Arc::new(Mutex::new(r)), clock, control: Arc::new(Offline) });
    (d, now, dir)
}

/// #141: a node splices a host its box's token allows wholesale while its feed is fresh. When the
/// feed narrows, the spliced connection is cut at the next check, and new connections are
/// intercepted with the node's CA and decided per request (plain reads only).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_splices_while_its_feed_is_fresh_and_stops_when_it_narrows() {
    let (d, now, feed_dir) = node_feed(&zone(), "run_splice");
    let w = World::with(Some(d)).await;
    // Fresh: spliced, the origin's own certificate; inspected hosts still get the node's leaf.
    let (status, s) = w.connect("checked.test").await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let (issuer, body) = get(s, "checked.test", "/hello").await;
    assert_eq!(issuer, "wicket run CA node", "checked.test is intercepted on the node");
    assert!(String::from_utf8_lossy(&body).contains("origin /hello"));
    let (status, s) = w.connect("open.test").await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from("open.test").unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.unwrap();
    let leaf = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    let (_, cert) = x509_parser::parse_x509_certificate(&leaf).unwrap();
    assert_eq!(cert.issuer().iter_common_name().next().unwrap().as_str().unwrap(), "wicket run CA origin", "spliced on the node");
    tls.write_all(b"POST /a HTTP/1.1\r\nHost: open.test\r\nContent-Length: 0\r\n\r\n").await.unwrap();
    tls.flush().await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tls.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("origin /a"));
    // The feed narrows (the control host has been unreachable past the lease): the spliced
    // connection is cut within a check or two.
    now.fetch_add(1_500, Ordering::SeqCst);
    let closed = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the spliced connection outlived the node's fresh policy");
    settle().await;
    let ev = w.events();
    let row = ev.iter().find(|e| e.0 == "open.test" && e.1 == "spliced").expect("a row for the spliced connection");
    assert!(row.2.contains("on the node") && row.2.contains("cut:") && row.2.contains("no longer fresh"), "{}", row.2);
    // Narrow: a new connection is intercepted with the node's CA; reads go, writes are refused.
    let (status, s) = w.connect("open.test").await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let (issuer, body) = get(s, "open.test", "/read").await;
    assert_eq!(issuer, "wicket run CA node", "inspected once narrow");
    assert!(String::from_utf8_lossy(&body).contains("origin /read"));
    let (_, s) = w.connect("open.test").await;
    let body = request(s, "open.test", "POST /write HTTP/1.1\r\nHost: open.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
    assert!(body.contains("plain reads") && !body.contains("origin"), "{body}");
    settle().await;
    let ev = w.events();
    assert!(!ev.iter().any(|e| e.1 == "spliced"), "{ev:?}");
    // Closed: refused outright.
    now.fetch_add(2_000, Ordering::SeqCst);
    let (_, s) = w.connect("open.test").await;
    let (_, body) = get(s, "open.test", "/read").await;
    assert!(String::from_utf8_lossy(&body).contains("allows nothing"), "{}", String::from_utf8_lossy(&body));
    let _ = std::fs::remove_dir_all(feed_dir);
}

/// #141: a child box is never spliced on a node, even in a zone that allows the host wholesale: its
/// token is narrowed by its ancestors' ceilings, which the node can't read back from the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_splices_only_top_level_boxes_and_only_wholesale_hosts() {
    let (d, _, child_dir) = node_feed(&zone(), "run_child");
    {
        let r = d.replica.lock().unwrap();
        assert_eq!(r.splice(&TenantId::single(), "run_child", "open.test", 1_000_000), None, "a child box");
        assert_eq!(r.splice(&TenantId::single(), "run_child", "checked.test", 1_000_000), None);
    }
    let (d, _, top_dir) = node_feed(&zone(), "run_splice");
    {
        let r = d.replica.lock().unwrap();
        assert_eq!(r.splice(&TenantId::single(), "run_splice", "open.test", 1_000_000), Some(0), "fresh, top-level");
        assert_eq!(r.splice(&TenantId::single(), "run_splice", "fenced.test", 1_000_000), None, "a forbid rule");
        assert_eq!(r.splice(&TenantId::single(), "run_splice", "checked.test", 1_000_000), None, "GET only");
        assert_eq!(r.splice(&TenantId::single(), "run_other", "open.test", 1_000_000), None, "no authority for the box");
        assert_eq!(r.splice(&TenantId::single(), "run_splice", "open.test", 1_001_000), None, "narrow");
    }
    for d in [child_dir, top_dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// TLS over `s` (any certificate), one raw request, and the response as text.
async fn request(s: UnixStream, sni: &str, raw: &str) -> String {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.unwrap();
    tls.write_all(raw.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    let mut resp = Vec::new();
    let _ = tls.read_to_end(&mut resp).await;
    String::from_utf8_lossy(&resp).into_owned()
}
