//! The egress conformance pack (#361): bypasses other egress proxies and sandboxes have had, or that
//! vendors document, each run against wicket's egress proxy through the box's socket. A test fails
//! if the defence it names regresses.
//!
//! Two origins sit behind the proxy, both resolvable by it: `echo.test`, which the zone reaches
//! (except `/forbidden/**`, which it forbids) and which records every request it gets, and
//! `evil.test`, which the zone doesn't name. A case passes when what the box sent is refused (or
//! goes only where it was decided to go) and nothing it shouldn't reach was reached: `evil.test` sees
//! nothing, ever, and `echo.test` never sees a request for `/forbidden/`.
//!
//! - **Upgrades and smuggling**: WebSocket and h2c upgrades (never passed upstream, and a refused or
//!   unasked-for 101 leaves no raw pipe), conflicting or duplicate `Content-Length` and
//!   `Transfer-Encoding`, obs-fold, CR, LF and NUL in headers, an absolute-form URL and a CONNECT
//!   inside a tunnel.
//! - **Addresses**: IP literals in every spelling, ports other than 443 (and 80 for plain HTTP), a
//!   `Host` header with a port, a trailing dot, userinfo or a second value.
//! - **Vendors' documented bypasses**: SNI/Host domain fronting, raw addresses (even ones a zone
//!   names), relayed CONNECT, SOCKS greetings and null bytes in the target.
//!
//! The reflection guard's own pack is `canary.rs` (an echoing origin with a credential bound to it).

use crate::zone_decider::ZoneDecider;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use wicket_core::{RunId, TenantId, ZoneSpec};
use wicket_proxy::ca::RunCa;
use wicket_proxy::egress::{Egress, Upstream};
use wicket_proxy::RunCtx;

const ECHO: &str = "echo.test";
const EVIL: &str = "evil.test";

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("conform-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `extra_reach`: more reach rules, as JSON (for the raw-address case).
fn zone(extra_reach: &[serde_json::Value]) -> ZoneSpec {
    let mut reach = vec![serde_json::json!({ "host": ECHO, "methods": ["GET", "POST"] })];
    reach.extend(extra_reach.iter().cloned());
    serde_json::from_value(serde_json::json!({
        "name": "conform",
        "reach": reach,
        "forbid": [{ "host": ECHO, "paths": ["/forbidden/**"] }],
    }))
    .unwrap()
}

/// One request an origin got: its request line, and its headers and body as text.
#[derive(Clone, Debug)]
struct Got {
    line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Got {
    fn body(&self) -> &str {
        &self.body
    }

    fn header(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
    }
}

type Seen = Arc<Mutex<Vec<Got>>>;

/// An origin that records each request and answers with its request line. `/upgrade` answers
/// `101 Switching Protocols` to a request that asks for an upgrade, as a WebSocket server would;
/// `/sneaky-101` answers 101 whatever was asked; `/refuse-upgrade` answers 400 to everything.
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
                        let line = format!("{} {}", req.method(), req.uri());
                        let headers: Vec<(String, String)> = req
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
                            .collect();
                        let path = req.uri().path().to_string();
                        let asks_upgrade = req.headers().contains_key("upgrade");
                        let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                        let body = String::from_utf8_lossy(&body).into_owned();
                        seen.lock().unwrap().push(Got { line: line.clone(), headers, body });
                        let switch = (path == "/upgrade" && asks_upgrade) || path == "/sneaky-101";
                        let r = if switch {
                            http::Response::builder()
                                .status(101)
                                .header("connection", "upgrade")
                                .header("upgrade", "websocket")
                                .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                                .body(http_body_util::Full::new(Bytes::new()))
                                .unwrap()
                        } else if path == "/refuse-upgrade" {
                            http::Response::builder().status(400).body(http_body_util::Full::new(Bytes::from("no upgrade here"))).unwrap()
                        } else {
                            http::Response::builder().body(http_body_util::Full::new(Bytes::from(format!("origin got: {line}")))).unwrap()
                        };
                        Ok::<_, hyper::Error>(r)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });
    addr
}

struct World {
    sock: PathBuf,
    seen: HashMap<&'static str, Seen>,
    dir: PathBuf,
}

impl World {
    async fn new() -> World {
        World::with_reach(&[]).await
    }

    async fn with_reach(extra_reach: &[serde_json::Value]) -> World {
        let dir = tmpdir();
        let origin_ca = RunCa::generate("origin").unwrap();
        let mut resolve = HashMap::new();
        let mut seen = HashMap::new();
        for name in [ECHO, EVIL] {
            let s: Seen = Arc::default();
            resolve.insert(name.to_string(), origin(&origin_ca, name, s.clone()).await);
            seen.insert(name, s);
        }
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
        });
        let ctx = RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_01jconform000000000000000aa".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(zone(extra_reach)).unwrap()),
            org: None,
            ledger: Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().unwrap())),
            vault: wicket_proxy::vault::Vault::new(dir.join("vault")),
            events: tx,
            // Nothing outside the zone is asked for: what isn't reached is refused outright.
            escalate: false,
            attribute: None,
            identity: None,
            swaps: vec![],
            boxes: None,
            capacity: None,
            decisions: None,
            fence: None,
            waker: None,
            lifecycle: None,
            names: None,
        };
        let up = Upstream { resolve, roots_pem: Some(origin_ca.cert_pem()), ..Default::default() };
        let egress =
            Egress::with_upstream(ctx, Arc::new(RunCa::generate("run_conform").unwrap()), Arc::new(ZoneDecider), None, up).unwrap();
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
        World { sock, seen, dir }
    }

    fn got(&self, host: &str) -> Vec<Got> {
        self.seen[host].lock().unwrap().clone()
    }

    /// What every case ends on: `evil.test` was never reached, and `echo.test` never got a request
    /// for a forbidden path.
    fn nothing_leaked(&self, case: &str) {
        assert!(self.got(EVIL).is_empty(), "{case}: evil.test was reached: {:?}", self.got(EVIL));
        let forbidden: Vec<_> = self.got(ECHO).into_iter().filter(|g| g.line.contains("/forbidden")).collect();
        assert!(forbidden.is_empty(), "{case}: echo.test got a forbidden request: {forbidden:?}");
    }

    /// Raw bytes on the box's socket (no CONNECT): what the proxy answered, until it closed or went
    /// quiet.
    async fn raw(&self, bytes: &[u8]) -> String {
        let mut s = UnixStream::connect(&self.sock).await.unwrap();
        s.write_all(bytes).await.unwrap();
        read_all(&mut s).await
    }

    /// CONNECT to `target` (as written), and the proxy's answer's head.
    async fn connect(&self, target: &str) -> (UnixStream, String) {
        let mut s = UnixStream::connect(&self.sock).await.unwrap();
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
        let head = read_head(&mut s).await;
        (s, head)
    }

    /// A tunnel to `host` with TLS for `sni`: writes `bytes` inside it, and returns everything the
    /// proxy answered there until it closed or went quiet.
    async fn tunnel(&self, host: &str, sni: &str, bytes: &[u8]) -> String {
        let (s, head) = self.connect(&format!("{host}:443")).await;
        assert!(head.starts_with("HTTP/1.1 200"), "CONNECT {host}: {head}");
        let mut tls = tls(s, sni).await;
        tls.write_all(bytes).await.unwrap();
        tls.flush().await.unwrap();
        read_all(&mut tls).await
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn tls(s: UnixStream, sni: &str) -> tokio_rustls::client::TlsStream<UnixStream> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, s).await.unwrap()
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(Duration::from_secs(10), s.read(&mut b)).await {
            Ok(Ok(1)) => head.push(b[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Everything until the peer closes, or nothing more comes for a while.
async fn read_all<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> String {
    let mut out = Vec::new();
    let mut b = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_millis(1500), s.read(&mut b)).await {
            Ok(Ok(n)) if n > 0 => out.extend_from_slice(&b[..n]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The status codes of the responses in what the proxy answered.
fn statuses(answer: &str) -> Vec<u16> {
    answer.match_indices("HTTP/1.1 ").filter_map(|(i, _)| answer.get(i + 9..i + 12)?.parse().ok()).collect()
}

fn get(path: &str, host_line: &str) -> String {
    format!("GET {path} HTTP/1.1\r\n{host_line}\r\n")
}

// ---- upgrades and request smuggling ----

/// A WebSocket or h2c upgrade is never passed upstream: the upgrade headers are dropped (the origin
/// sees a plain GET and answers it), the box gets no 101, and what it sends after the request is
/// read as the next HTTP request, and decided, never piped through raw.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upgrades_are_never_passed_upstream_and_leave_no_raw_pipe() {
    let w = World::new().await;
    let ws = "GET /upgrade HTTP/1.1\r\nHost: echo.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\r\n";
    let h2c = "GET /upgrade HTTP/1.1\r\nHost: echo.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n";
    // An upstream that refuses the upgrade: what follows must still be a request, not a pipe.
    let refused = "GET /refuse-upgrade HTTP/1.1\r\nHost: echo.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    // An upstream that answers 101 to a request that didn't ask for an upgrade.
    let sneaky = "GET /sneaky-101 HTTP/1.1\r\nHost: echo.test\r\n\r\n";
    for (case, first, first_status) in
        [("websocket", ws, 200), ("h2c", h2c, 200), ("refused upgrade", refused, 400), ("unasked 101", sneaky, 0)]
    {
        let after = format!("{}{}", get("/forbidden/x", "Host: echo.test\r\n"), get("/after", "Host: echo.test\r\nConnection: close\r\n"));
        let answer = w.tunnel(ECHO, ECHO, format!("{first}{after}").as_bytes()).await;
        let st = statuses(&answer);
        assert!(!st.contains(&101), "{case}: the box got a 101: {answer}");
        if first_status != 0 {
            assert_eq!(st.first(), Some(&first_status), "{case}: {answer}");
        }
        // Whatever the first answer was, the bytes after it were requests, each decided.
        if first_status != 0 {
            assert_eq!(&st[1..], [403, 200], "{case}: {answer}");
        }
        assert!(!answer.contains("GET /forbidden"), "{case}: the request came back raw: {answer}");
        w.nothing_leaked(case);
    }
    for g in w.got(ECHO) {
        for h in ["upgrade", "connection", "http2-settings", "sec-websocket-key", "sec-websocket-version"] {
            assert!(g.header(h).is_empty(), "{h} reached the origin: {g:?}");
        }
    }
}

/// Framing a front end and a back end could read differently is refused at the box's edge, or read
/// one way only, and a request hidden in a body never reaches the origin as a request:
/// - `Content-Length` with `Transfer-Encoding` is read as chunked (RFC 9112 §6.3: the length is
///   dropped, so it isn't what goes upstream), and the connection closes after its answer, so
///   nothing after the body is read as another request;
/// - two lengths, a list of them, a coding that doesn't end in `chunked`, obs-fold, and CR or NUL in
///   a header are refused (400) before anything is decided;
/// - a GET with a body is refused (403) before it is decided.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ambiguous_framing_is_refused_and_smuggles_nothing() {
    let w = World::new().await;
    let hidden = get("/forbidden/smuggled", "Host: echo.test\r\n");
    let n = hidden.len();
    // (case, bytes, what the box gets: the statuses of its answers).
    let cases: Vec<(&str, String, &[u16])> = vec![
        ("CL.TE", format!("POST /a HTTP/1.1\r\nHost: echo.test\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n{hidden}"), &[200]),
        ("TE.CL", format!("POST /b HTTP/1.1\r\nHost: echo.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n{n:x}\r\n{hidden}\r\n0\r\n\r\n"), &[200]),
        ("two lengths", format!("POST /a HTTP/1.1\r\nHost: echo.test\r\nContent-Length: 0\r\nContent-Length: {n}\r\n\r\n{hidden}"), &[400]),
        ("a list of lengths", format!("POST /a HTTP/1.1\r\nHost: echo.test\r\nContent-Length: 0, {n}\r\n\r\n{hidden}"), &[400]),
        ("TE not chunked last", format!("POST /a HTTP/1.1\r\nHost: echo.test\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n{hidden}"), &[400]),
        ("TE misspelt", format!("POST /a HTTP/1.1\r\nHost: echo.test\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n{hidden}"), &[400]),
        ("TE with a space", format!("POST /a HTTP/1.1\r\nHost: echo.test\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n{hidden}"), &[400]),
        ("obs-fold", format!("GET /a HTTP/1.1\r\nHost: echo.test\r\nX-A: a\r\n Transfer-Encoding: chunked\r\n\r\n{hidden}"), &[400]),
        ("NUL in a value", format!("GET /a HTTP/1.1\r\nHost: echo.test\r\nUser-Agent: a\0b\r\n\r\n{hidden}"), &[400]),
        ("bare CR in a value", format!("GET /a HTTP/1.1\r\nHost: echo.test\r\nUser-Agent: a\rHost: evil.test\r\n\r\n{hidden}"), &[400]),
        ("a GET with a body", format!("GET /a HTTP/1.1\r\nHost: echo.test\r\nContent-Length: {n}\r\n\r\n{hidden}"), &[403]),
        ("a chunked GET", format!("GET /a HTTP/1.1\r\nHost: echo.test\r\nTransfer-Encoding: chunked\r\n\r\n{n:x}\r\n{hidden}\r\n0\r\n\r\n"), &[403]),
    ];
    for (case, bytes, want) in &cases {
        let answer = w.tunnel(ECHO, ECHO, bytes.as_bytes()).await;
        assert_eq!(statuses(&answer), *want, "{case}: {answer}");
        w.nothing_leaked(case);
    }
    // Only the two read as chunked reached the origin, each with the body chunked framing gives it,
    // and with no length of the box's.
    let got = w.got(ECHO);
    assert_eq!(got.iter().map(|g| (g.line.as_str(), g.body())).collect::<Vec<_>>(), [("POST /a", ""), ("POST /b", hidden.as_str())]);
    for g in &got {
        assert!(g.header("content-length").iter().all(|l| *l == g.body().len().to_string()), "{g:?}");
    }
    // A well-framed request on the same terms goes, with the body it framed.
    let ok = w.tunnel(ECHO, ECHO, b"POST /c HTTP/1.1\r\nHost: echo.test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi").await;
    assert_eq!(statuses(&ok), [200], "{ok}");
    assert_eq!(w.got(ECHO).last().map(|g| (g.line.clone(), g.body.clone())), Some(("POST /c".into(), "hi".into())));
}

/// Inside a tunnel the target is the tunnel's: an absolute-form URL naming another host, or a
/// CONNECT to one, is refused, and reaches nobody.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tunnel_reaches_only_its_own_host() {
    let w = World::new().await;
    for (case, req) in [
        ("absolute https URL", "GET https://evil.test/x HTTP/1.1\r\nHost: echo.test\r\n\r\n"),
        ("absolute http URL", "GET http://evil.test/x HTTP/1.1\r\nHost: echo.test\r\n\r\n"),
        ("absolute URL and Host", "GET https://evil.test/x HTTP/1.1\r\nHost: evil.test\r\n\r\n"),
        ("absolute URL with another port", "GET https://echo.test:8443/x HTTP/1.1\r\nHost: echo.test\r\n\r\n"),
        ("relayed CONNECT", "CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n"),
        ("relayed CONNECT, the tunnel's Host", "CONNECT evil.test:443 HTTP/1.1\r\nHost: echo.test\r\n\r\n"),
        ("relayed CONNECT to itself", "CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test\r\n\r\n"),
        ("TRACE", "TRACE /x HTTP/1.1\r\nHost: echo.test\r\n\r\n"),
    ] {
        let answer = w.tunnel(ECHO, ECHO, req.as_bytes()).await;
        let st = statuses(&answer);
        assert!(st.first().is_some_and(|s| *s == 400 || *s == 403), "{case}: {answer}");
        assert!(!st.contains(&200), "{case}: {answer}");
        w.nothing_leaked(case);
    }
    assert!(w.got(ECHO).is_empty(), "{:?}", w.got(ECHO));
    // Its own host, absolute or origin-form, goes.
    let ok = w.tunnel(ECHO, ECHO, b"GET https://echo.test/abs HTTP/1.1\r\nHost: echo.test\r\nConnection: close\r\n\r\n").await;
    assert_eq!(statuses(&ok), [200], "{ok}");
    assert_eq!(w.got(ECHO).len(), 1);
}

// ---- addresses ----

/// An IP address is refused in every spelling a URL parser accepts, at CONNECT and in plain HTTP,
/// even one the zone names; and so is a port other than 443 (80 for plain HTTP).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn addresses_and_ports_have_one_spelling_and_ips_none() {
    // A zone that names an address, as a manifest might: still no IP literal gets through.
    let w = World::with_reach(&[serde_json::json!({ "host": "127.0.0.1", "methods": ["GET"] })]).await;
    for target in [
        "127.0.0.1:443",
        "127.1:443",
        "2130706433:443",
        "0177.0.0.1:443",
        "0x7f.0.0.1:443",
        "0x7f000001:443",
        "[::1]:443",
        "[::ffff:127.0.0.1]:443",
        "[::ffff:7f00:1]:443",
        "[0:0:0:0:0:ffff:127.0.0.1]:443",
        "169.254.169.254:443",
        "[fe80::1]:443",
    ] {
        let (_, head) = w.connect(target).await;
        assert!(head.starts_with("HTTP/1.1 403") || head.starts_with("HTTP/1.1 400"), "CONNECT {target}: {head}");
    }
    for url in ["http://127.0.0.1/", "http://2130706433/", "http://0x7f.1/", "http://[::ffff:127.0.0.1]/"] {
        let answer = w.raw(format!("GET {url} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await;
        assert!(answer.starts_with("HTTP/1.1 403") || answer.starts_with("HTTP/1.1 400"), "{url}: {answer}");
    }
    for target in ["echo.test:80", "echo.test:8443", "echo.test:22", "echo.test:0", "echo.test:65535"] {
        let (_, head) = w.connect(target).await;
        assert!(head.starts_with("HTTP/1.1 403"), "CONNECT {target}: {head}");
    }
    let (_, head) = w.connect("echo.test:8443").await;
    let mut s = UnixStream::connect(&w.sock).await.unwrap();
    s.write_all(b"CONNECT echo.test:8443 HTTP/1.1\r\nHost: echo.test:8443\r\n\r\n").await.unwrap();
    let body = read_all(&mut s).await;
    assert!(head.starts_with("HTTP/1.1 403") && body.contains("only port 443"), "{body}");
    let answer = w.raw(b"GET http://echo.test:8080/ HTTP/1.1\r\nHost: echo.test:8080\r\n\r\n").await;
    assert!(answer.starts_with("HTTP/1.1 403") && answer.contains("port 80 only"), "{answer}");
    w.nothing_leaked("addresses");
    assert!(w.got(ECHO).is_empty());
}

/// The Host header is pinned to the tunnel's target: a port, a trailing dot or another case are the
/// same host; another host, userinfo, or a host smuggled after it are refused; and upstream the
/// Host is always wicket's own, never the box's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_header_names_the_tunnel_target_or_is_refused() {
    let w = World::new().await;
    for host in ["echo.test", "echo.test:443", "echo.test.", "ECHO.test", "echo.test.:443"] {
        let answer = w.tunnel(ECHO, ECHO, get("/same", &format!("Host: {host}\r\nConnection: close\r\n")).as_bytes()).await;
        assert_eq!(statuses(&answer), [200], "Host: {host}: {answer}");
    }
    for host in [
        "evil.test",
        "evil.test.",
        "evil.test:443",
        "echo.test@evil.test",
        "evil.test#echo.test",
        "echo.test.evil.test",
        "echo.test\tevil.test",
    ] {
        let answer = w.tunnel(ECHO, ECHO, get("/other", &format!("Host: {host}\r\nConnection: close\r\n")).as_bytes()).await;
        let st = statuses(&answer);
        assert!(st.first().is_some_and(|s| *s == 400 || *s == 403), "Host: {host}: {answer}");
    }
    // Two Host headers: refused before anything is decided.
    let answer = w.tunnel(ECHO, ECHO, b"GET /two HTTP/1.1\r\nHost: echo.test\r\nHost: evil.test\r\nConnection: close\r\n\r\n").await;
    assert!(statuses(&answer).first().is_some_and(|s| *s == 400 || *s == 403), "{answer}");
    w.nothing_leaked("host headers");
    let got = w.got(ECHO);
    assert_eq!(got.len(), 5, "{got:?}");
    for g in &got {
        assert_eq!(g.header("host"), ["echo.test"], "{g:?}");
    }
}

// ---- vendors' documented bypasses ----

/// Domain fronting: the TLS server name inside a tunnel doesn't choose the upstream (the CONNECT
/// target does, and the Host header must agree with it), and fronting an unreachable host behind a
/// reachable one's CONNECT reaches nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_fronting_reaches_only_the_decided_host() {
    let w = World::new().await;
    // SNI evil.test inside echo.test's tunnel, Host echo.test: decided and sent as echo.test.
    let answer = w.tunnel(ECHO, EVIL, get("/fronted", "Host: echo.test\r\nConnection: close\r\n").as_bytes()).await;
    assert_eq!(statuses(&answer), [200], "{answer}");
    // SNI and Host evil.test inside echo.test's tunnel: refused.
    let answer = w.tunnel(ECHO, EVIL, get("/fronted", "Host: evil.test\r\nConnection: close\r\n").as_bytes()).await;
    assert!(statuses(&answer).first().is_some_and(|s| *s == 403), "{answer}");
    // CONNECT to evil.test (which the zone doesn't name: its tunnel opens, and each request in it is
    // decided), SNI echo.test: whatever the Host, nothing goes.
    for host in ["evil.test", "echo.test"] {
        let answer = w.tunnel(EVIL, ECHO, get("/fronted", &format!("Host: {host}\r\nConnection: close\r\n")).as_bytes()).await;
        assert!(statuses(&answer).first().is_some_and(|s| *s == 403), "Host {host}: {answer}");
    }
    w.nothing_leaked("fronting");
    assert_eq!(w.got(ECHO).len(), 1);
    assert_eq!(w.got(ECHO)[0].line, "GET /fronted");
}

/// What isn't an HTTP proxy request is answered as a bad request, never as a SOCKS server would,
/// and null bytes in the target are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks_and_null_bytes_get_no_tunnel() {
    let w = World::new().await;
    let socks: [&[u8]; 4] = [
        b"\x05\x01\x00",
        b"\x05\x01\x00\x05\x01\x00\x03\x09evil.test\x01\xbb",
        b"\x04\x01\x01\xbb\x7f\x00\x00\x01user\x00",
        // SOCKS4a: a host name after the user's null byte.
        b"\x04\x01\x01\xbb\x00\x00\x00\x01\x00evil.test\x00",
    ];
    for (i, greeting) in socks.iter().enumerate() {
        let answer = w.raw(greeting).await;
        assert!(!answer.as_bytes().starts_with(b"\x05") && !answer.as_bytes().starts_with(b"\x00"), "case {i}: a SOCKS reply: {answer:?}");
        assert!(answer.is_empty() || answer.starts_with("HTTP/1.1 400"), "case {i}: {answer:?}");
    }
    for target in [
        "echo.test\0.evil.test:443",
        "evil.test\0echo.test:443",
        "echo.test:443\0",
        "echo.test%00.evil.test:443",
        "echo.test%2eevil.test:443",
    ] {
        let mut s = UnixStream::connect(&w.sock).await.unwrap();
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: echo.test:443\r\n\r\n").as_bytes()).await.unwrap();
        let answer = read_all(&mut s).await;
        assert!(!answer.starts_with("HTTP/1.1 200"), "CONNECT {target:?}: {answer}");
    }
    w.nothing_leaked("socks");
    assert!(w.got(ECHO).is_empty());
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
