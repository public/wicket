//! The model proxy's two routes, held to each other (#552): a model call reaches the model host
//! either through the model proxy's own socket (`Llm::handle`) or, from a wrapped session, through
//! the egress proxy's gate (`Egress::handle` → `Llm::through_egress`). #360's 401 retry was once
//! written on the first only, and #552 was the other; both now make one `Llm::call`, which differs
//! by route only in `ModelRoute` (where the call goes, how its credential is attached). Every behaviour of a model call is
//! run here through both routes against one mock model host (the same handler, over plain HTTP for
//! the model proxy's upstream and over TLS as `api.anthropic.com` for the egress proxy), and each
//! route must answer, record and charge alike.
//!
//! Two lists say where they differ, each entry with why:
//!
//! - [`INTENDED`]: differences by design, which stay (the destination and transport, where a stale
//!   activation is refused, a zone without a model route, an upstream error's wording);
//! - [`KNOWN`]: differences that are drift, found by the audit (`out/one-route/proposal.md`'s
//!   rows), each to be deleted from the list as the routes are made one (`Llm::call`).
//!
//! A case whose routes differ and that is in neither list fails; so does a [`KNOWN`] entry whose
//! routes no longer differ (delete it). [`INTENDED_UNTESTED`] names what no single call can show.
//! `PARITY_SHOW=1` prints what each case saw on each route.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::BodyExt;

/// Access tokens as long as real ones: the egress proxy masks only credentials long enough to tell
/// apart from ordinary text (`canary::MIN_FORM`).
const T1: &str = "test-access-token-first-0123456789abcdef";
const T2: &str = "test-access-token-refreshed-0123456789abcdef";
const TNEVER: &str = "test-access-token-never-given-0123456789";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// The model proxy's own socket.
    Direct,
    /// A wrapped session's call, through the egress proxy's gate.
    Egress,
}

/// What a case saw on one route.
#[derive(Debug, Clone)]
struct Seen {
    status: u16,
    body: String,
    /// The `llm` op records' outcomes (their notes), in order.
    notes: Vec<String>,
    /// Model requests counted.
    requests: u64,
    /// The bearers the mock model host saw.
    bearers: Vec<String>,
    /// Whether a request header the provider's profile forwards (`anthropic-beta`) reached it.
    beta_header: bool,
    /// Output tokens charged (settled or reserved).
    charged: u64,
    /// Whether the run's first model request was recorded (a node reports it, #152).
    first_request: bool,
}

impl Seen {
    fn note(&self, s: &str) -> bool {
        self.notes.iter().any(|n| n.contains(s))
    }
}

// ---- the mock model host ----

/// How the mock model host answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// `200`, a JSON body with usage (1 in, 2 out); `401` for any bearer but the accepted one.
    Ok,
    /// As `Ok`, the body echoing the bearer it was sent (#362).
    Echo,
    /// As `Ok`, `Content-Encoding: gzip` though identity was asked for.
    Gzip,
}

#[derive(Default)]
struct MockState {
    accept: Mutex<String>,
    answer: Mutex<Option<Answer>>,
    delay_ms: AtomicU64,
    seen: Mutex<Vec<(String, bool)>>,
    /// Called on each refusal (a login refreshed by its owner, #360/#552).
    on_reject: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

struct Mock {
    state: Arc<MockState>,
    plain: SocketAddr,
    tls: SocketAddr,
    origin_pem: String,
}

impl Mock {
    async fn start() -> Mock {
        let state = Arc::new(MockState::default());
        *state.accept.lock().unwrap() = T1.into();
        *state.answer.lock().unwrap() = Some(Answer::Ok);
        let origin = crate::ca::RunCa::generate("origin").unwrap();
        let mut cfg = (*origin.server_config("api.anthropic.com").unwrap()).clone();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let plain_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (plain, tls) = (plain_l.local_addr().unwrap(), tls_l.local_addr().unwrap());
        let st = state.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = plain_l.accept().await {
                let st = st.clone();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(s), hyper::service::service_fn(move |r| answer(st.clone(), r)))
                        .await;
                });
            }
        });
        let st = state.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = tls_l.accept().await {
                let (st, acceptor) = (st.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let Ok(t) = acceptor.accept(s).await else { return };
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(t), hyper::service::service_fn(move |r| answer(st.clone(), r)))
                        .await;
                });
            }
        });
        Mock { state, plain, tls, origin_pem: origin.cert_pem() }
    }
}

type MockBody = http_body_util::Full<bytes::Bytes>;

async fn answer(st: Arc<MockState>, req: http::Request<hyper::body::Incoming>) -> Result<http::Response<MockBody>, hyper::Error> {
    let bearer = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").trim_start_matches("Bearer ").to_string();
    let beta = req.headers().contains_key("anthropic-beta");
    let _ = req.into_body().collect().await?;
    st.seen.lock().unwrap().push((bearer.clone(), beta));
    let delay = st.delay_ms.load(SeqCst);
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    let usage = r#""usage":{"input_tokens":1,"output_tokens":2}"#;
    let accepted = bearer == *st.accept.lock().unwrap();
    let kind = st.answer.lock().unwrap().unwrap_or(Answer::Ok);
    let r = if !accepted {
        if let Some(f) = st.on_reject.lock().unwrap().as_ref() {
            f();
        }
        http::Response::builder()
            .status(401)
            .header("content-type", "application/json")
            .body(MockBody::from(r#"{"type":"error","error":{"type":"authentication_error","message":"OAuth token revoked"}}"#))
    } else {
        match kind {
            Answer::Ok => http::Response::builder().header("content-type", "application/json").body(MockBody::from(format!("{{{usage}}}"))),
            Answer::Echo => http::Response::builder()
                .header("content-type", "application/json")
                .body(MockBody::from(format!(r#"{{"echo":"{bearer}",{usage}}}"#))),
            Answer::Gzip => http::Response::builder()
                .header("content-type", "application/json")
                .header("content-encoding", "gzip")
                .body(MockBody::from(&b"\x1f\x8b\x08\x00compressed"[..])),
        }
    };
    Ok(r.unwrap())
}

// ---- one call, on one route ----

/// How a case sets up the run and the call.
struct Setup {
    /// More of the zone's `llm` section (budgets, models).
    llm: &'static str,
    /// The zone has no model route at all.
    no_model_route: bool,
    /// The model secret: a value, a linked file (rewritten by the case), a node's source, or none.
    secret: Secret,
    /// A stale activation (#70).
    stale: bool,
    path: &'static str,
    body: String,
    headers: Vec<(&'static str, &'static str)>,
    /// Calls made first, whose answers are not looked at.
    before: usize,
    /// The model host is down (its address refuses connections).
    upstream_down: bool,
    /// The box gives up on the call after this long (#422).
    give_up_after: Option<Duration>,
}

enum Secret {
    Value(&'static str),
    /// A linked login, `tok-1` at first; the mock writes `tok-2` into it `after` its first refusal.
    Linked {
        refreshed_after: Option<Duration>,
    },
    /// A linked login whose file is gone when the call comes and written `after` (its owner
    /// rewriting it, #350).
    Rewritten {
        after: Duration,
    },
    /// A linked login whose file never appears: its read gives up (#350).
    Missing,
    /// A node's copy that its source can't fetch (#152).
    NodeUnfetchable,
}

fn messages(max_tokens: u64, extra: &str) -> String {
    format!(r#"{{"model":"claude-x","max_tokens":{max_tokens},"messages":[{{"role":"user","content":"hi"}}]{extra}}}"#)
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            llm: "",
            no_model_route: false,
            secret: Secret::Value(T1),
            stale: false,
            path: "/v1/messages",
            body: messages(50, ""),
            headers: vec![],
            before: 0,
            upstream_down: false,
            give_up_after: None,
        }
    }
}

struct NodeSource;
impl crate::vault::SecretSource for NodeSource {
    fn get(&self, name: &str) -> anyhow::Result<String> {
        anyhow::bail!("{name}: not on this node")
    }
    fn hosts(&self, _: &str) -> Vec<String> {
        vec!["127.0.0.1".into(), "api.anthropic.com".into()]
    }
    fn has(&self, _: &str) -> bool {
        false
    }
    fn fetch<'a>(&'a self, name: &'a str) -> futures_util::future::BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move { anyhow::bail!("the control host is unreachable: {name} can't be fetched") })
    }
}

/// Writes a login file as its owner does (a new file, renamed in). From a case's background thread
/// the directory may be gone by then (the case is over): nothing to do.
fn write_login(p: &std::path::Path, t: &str) {
    use std::os::unix::fs::PermissionsExt;
    let tmp = p.with_extension("tmp");
    let _ = std::fs::write(&tmp, format!(r#"{{"o":{{"accessToken":"{t}"}}}}"#))
        .and_then(|()| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)))
        .and_then(|()| std::fs::rename(&tmp, p));
}

/// Runs a case's call on `route`, against a fresh mock model host, run context and proxies.
async fn run(route: Route, s: Setup, tag: &str, answer: Answer, delay: u64) -> Seen {
    let mock = Mock::start().await;
    *mock.state.answer.lock().unwrap() = Some(answer);
    mock.state.delay_ms.store(delay, SeqCst);
    let dir = std::env::temp_dir().join(format!("wicket-parity-{tag}-{route:?}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // The model proxy's upstream: the mock over plain HTTP (or an address that refuses).
    let down = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let plain = if s.upstream_down { down } else { mock.plain };
    let llm = if s.no_model_route { String::new() } else { format!("llm: {{secret: model, upstream: 'http://{plain}'{}}}, ", s.llm) };
    let mut m = wicket_core::Manifest::from_yaml(&format!(
        "task: t\nagent: {{name: a}}\nzone: {{name: z, {llm}reach: [{{host: api.anthropic.com, methods: [GET, POST]}}]}}"
    ))
    .unwrap();
    crate::provider::fill_test_route(&mut m);
    // The secret, in a vault both proxies read.
    let vault = match &s.secret {
        Secret::NodeUnfetchable => crate::vault::Vault::from_source(Arc::new(NodeSource)),
        _ => crate::vault::Vault::new(dir.join("vault")),
    };
    let login = dir.join("login.json");
    match &s.secret {
        Secret::Value(v) => vault.set("model", v).unwrap(),
        Secret::Linked { refreshed_after } => {
            write_login(&login, T1);
            vault.link("model", login.to_str().unwrap(), Some("/o/accessToken"), None, None).unwrap();
            if let Some(after) = *refreshed_after {
                let (l, done) = (login.clone(), Arc::new(AtomicBool::new(false)));
                *mock.state.accept.lock().unwrap() = T2.into();
                *mock.state.on_reject.lock().unwrap() = Some(Box::new(move || {
                    if !done.swap(true, SeqCst) {
                        let l = l.clone();
                        std::thread::spawn(move || {
                            std::thread::sleep(after);
                            write_login(&l, T2);
                        });
                    }
                }));
            } else {
                // Never refreshed: the host has revoked `tok-1` for good.
                *mock.state.accept.lock().unwrap() = TNEVER.into();
            }
        }
        Secret::Rewritten { after } => {
            write_login(&login, T1);
            vault.link("model", login.to_str().unwrap(), Some("/o/accessToken"), None, None).unwrap();
            std::fs::remove_file(&login).unwrap();
            let (l, after) = (login.clone(), *after);
            std::thread::spawn(move || {
                std::thread::sleep(after);
                write_login(&l, T1);
            });
        }
        Secret::Missing => {
            write_login(&login, T1);
            vault.link("model", login.to_str().unwrap(), Some("/o/accessToken"), None, None).unwrap();
            std::fs::remove_file(&login).unwrap();
        }
        Secret::NodeUnfetchable => {}
    }
    if !matches!(s.secret, Secret::NodeUnfetchable) {
        vault.set_hosts("model", &["127.0.0.1".into(), "api.anthropic.com".into()]).unwrap();
    }
    let ledger = Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().unwrap()));
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let swap = crate::CredentialSwap {
        name: "model".into(),
        host: "api.anthropic.com".into(),
        placeholder: "ph-run".into(),
        real: crate::SwapSource::Vault("model".into()),
        box_bearers: false,
    };
    let c = crate::RunCtx {
        tenant: wicket_core::TenantId::single(),
        run: wicket_core::RunId("run_x".into()),
        zone: Arc::new(wicket_core::CompiledZone::new(m.zone.clone()).unwrap()),
        org: None,
        ledger: ledger.clone(),
        vault,
        events: tx,
        escalate: true,
        attribute: None,
        identity: None,
        swaps: vec![swap],
        boxes: None,
        capacity: None,
        decisions: None,
        fence: s.stale.then(|| crate::Fence { agent: "agent-gone".into(), generation: 1 }),
        waker: None,
        lifecycle: None,
    };
    let llm = crate::llm::Llm::new(c.clone()).unwrap();
    let mut out = None;
    for i in 0..=s.before {
        let looked = i == s.before;
        let r = match route {
            Route::Direct => call_direct(&llm, &s, &dir, looked).await,
            Route::Egress => call_egress(&llm, &c, &mock, &s, down, looked).await,
        };
        out = Some(r);
    }
    let (status, body) = out.unwrap();
    // Let the call settle: its accounting runs on a task, and a box that gave up leaves it running.
    tokio::time::sleep(Duration::from_millis(if s.give_up_after.is_some() { 900 } else { 100 })).await;
    let notes = ledger
        .lock()
        .unwrap()
        .audit_of_kind("op")
        .unwrap()
        .into_iter()
        .map(|r| r.body)
        .filter(|b| b.contains("\"kind\":\"llm\""))
        .map(|b| {
            serde_json::from_str::<serde_json::Value>(&b).ok().and_then(|v| v["outcome"].as_str().map(String::from)).unwrap_or_default()
        })
        .collect();
    let seen = mock.state.seen.lock().unwrap().clone();
    let counts = llm.count.counts();
    let r = Seen {
        status,
        body,
        notes,
        requests: counts.requests,
        bearers: seen.iter().map(|(b, _)| b.clone()).collect(),
        beta_header: seen.iter().any(|(_, beta)| *beta),
        charged: counts.output_tokens,
        first_request: llm.first_request_ms().is_some(),
    };
    let _ = std::fs::remove_dir_all(&dir);
    r
}

/// The model proxy's own socket: the box's harness configured with wicket's model URL.
async fn call_direct(llm: &Arc<crate::llm::Llm>, s: &Setup, dir: &std::path::Path, looked: bool) -> (u16, String) {
    let sock = dir.join("llm.sock");
    let _ = std::fs::remove_file(&sock);
    let server = tokio::spawn({
        let (llm, sock) = (llm.clone(), sock.clone());
        async move { llm.serve(&sock).await }
    });
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let mut b = http::Request::post(s.path).header("host", "localhost").header("content-type", "application/json");
    for (k, v) in &s.headers {
        b = b.header(*k, *v);
    }
    let req = b.body(http_body_util::Full::new(bytes::Bytes::from(s.body.clone()))).unwrap();
    let call = async move {
        let r = send.send_request(req).await.unwrap();
        let st = r.status().as_u16();
        (st, String::from_utf8_lossy(&r.into_body().collect().await.unwrap().to_bytes()).into_owned())
    };
    let r = match (looked, s.give_up_after) {
        (true, Some(t)) => tokio::time::timeout(t, call).await.unwrap_or((0, "the box gave up".into())),
        _ => call.await,
    };
    server.abort();
    r
}

/// A wrapped session's call: to the model host, through the egress proxy, with the run's placeholder.
async fn call_egress(
    llm: &Arc<crate::llm::Llm>,
    c: &crate::RunCtx,
    mock: &Mock,
    s: &Setup,
    down: SocketAddr,
    looked: bool,
) -> (u16, String) {
    let to = if s.upstream_down { down } else { mock.tls };
    let up = crate::egress::Upstream {
        resolve: [("api.anthropic.com".to_string(), to)].into(),
        roots_pem: Some(mock.origin_pem.clone()),
        ..Default::default()
    };
    let ca = Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
    let e = crate::egress::Egress::with_upstream(c.clone(), ca, Arc::new(crate::zone_decider::ZoneDecider), None, up).unwrap();
    e.set_model_gate(llm.clone());
    let mut b = http::Request::post(s.path)
        .header("host", "api.anthropic.com")
        .header("content-type", "application/json")
        .header("authorization", "Bearer ph-run")
        .header("content-length", s.body.len());
    for (k, v) in &s.headers {
        b = b.header(*k, *v);
    }
    let req = b.body(http_body_util::Full::new(bytes::Bytes::from(s.body.clone()))).unwrap();
    let call = async move {
        let r = e.handle(req, "api.anthropic.com".into(), "https", crate::egress::Via::Tcp).await;
        let st = r.status().as_u16();
        (st, String::from_utf8_lossy(&r.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default()).into_owned())
    };
    match (looked, s.give_up_after) {
        (true, Some(t)) => tokio::time::timeout(t, call).await.unwrap_or((0, "the box gave up".into())),
        _ => call.await,
    }
}

// ---- the cases ----

/// What both routes must show, as a check on one route's [`Seen`].
type Check = fn(&Seen) -> bool;

struct Case {
    name: &'static str,
    setup: fn() -> Setup,
    /// What each route must show; a case whose routes differ must be in [`KNOWN`] or [`INTENDED`].
    both: Check,
}

/// A difference between the routes: the case, the audit's row, why, and what each route shows now.
struct Differs {
    case: &'static str,
    row: u8,
    why: &'static str,
    direct: Check,
    egress: Check,
}

/// Differences by design: they stay, and are named here.
const INTENDED: &[Differs] = &[
    Differs {
        case: "stale activation",
        row: 3,
        why: "the egress proxy refuses a stale activation for the whole tunnel, before the model gate, with its own wording; the model proxy refuses the call (409)",
        direct: |s| s.status == 409 && s.requests == 0,
        egress: |s| s.status != 200 && s.requests == 0 && s.bearers.is_empty(),
    },
    Differs {
        case: "the model host down",
        row: 18,
        why: "both answer 502; the error is worded by each route's own client (reqwest's, or the egress dialer's chain)",
        direct: |s| s.status == 502 && s.note("upstream error"),
        egress: |s| s.status == 502 && s.note("upstream error"),
    },
    Differs {
        case: "zone without a model route",
        row: 4,
        why: "a wrapped session's zone may have no model route: its calls are ordinary egress (not a model call, not counted); the model proxy has nothing to serve (404)",
        direct: |s| s.status == 404 && s.bearers.is_empty(),
        egress: |s| s.status != 404 && s.requests == 0,
    },
];

/// Intended differences no single call can show, named here so they are decided in one place.
const INTENDED_UNTESTED: &[(u8, &str)] = &[(
    12,
    "the destination and transport: the model proxy calls its route's upstream with its own client; a wrapped session's call goes to the host the box named, on the egress dialer (DNS pinning, dial-time address checks, HTTP/3)",
)];

/// Drift the audit found (`out/one-route/proposal.md`), deleted from this list as the two routes
/// became one call (`Llm::call`, rows 2, 6, 8, 9, 10, 13, 14, 15, 16 and 17). A new difference is a
/// regression: make the routes alike rather than list it here.
const KNOWN: &[Differs] = &[];

const CASES: &[Case] = &[
    Case { name: "an ordinary call", setup: Setup::default, both: |s| s.status == 200 && s.requests == 1 && s.bearers == [T1] },
    Case {
        name: "a provider header",
        setup: || Setup { headers: vec![("anthropic-beta", "x")], ..Setup::default() },
        both: |s| s.status == 200 && s.beta_header,
    },
    Case {
        name: "the request budget spent",
        setup: || Setup { llm: ", max_requests: 1", before: 1, ..Setup::default() },
        both: |s| s.status == 429 && s.body.contains("request budget") && s.bearers.len() == 1,
    },
    Case {
        name: "a model the zone doesn't allow",
        setup: || Setup { llm: ", models: [claude-other]", ..Setup::default() },
        both: |s| s.status == 403 && s.bearers.is_empty(),
    },
    Case {
        name: "max_tokens over what is left",
        setup: || Setup { llm: ", max_output_tokens: 20", ..Setup::default() },
        both: |s| s.status == 200 && s.note("max_tokens 50 lowered to the 20"),
    },
    Case {
        name: "a stripped field",
        setup: || Setup { body: messages(50, r#","some_future_field":{"x":1}"#), ..Setup::default() },
        both: |s| s.status == 200 && s.note("stripped 1 request field(s): some_future_field"),
    },
    Case {
        name: "an encoded body",
        setup: || Setup { headers: vec![("content-encoding", "gzip")], ..Setup::default() },
        both: |s| s.status == 415 && s.bearers.is_empty(),
    },
    Case {
        name: "a path that isn't a model route",
        setup: || Setup { path: "/v1/messages/batches", ..Setup::default() },
        both: |s| s.bearers.is_empty() && s.status >= 400,
    },
    Case {
        name: "an oversized body",
        setup: || Setup { body: messages(50, &format!(r#","pad":"{}""#, "a".repeat(32 * 1024 * 1024))), ..Setup::default() },
        both: |s| s.bearers.is_empty() && s.status >= 400,
    },
    Case {
        name: "a login refreshed while the call is out",
        setup: || Setup { secret: Secret::Linked { refreshed_after: Some(Duration::from_millis(300)) }, ..Setup::default() },
        both: |s| s.status == 200 && s.bearers == [T1, T2] && s.note("retried once after a 401"),
    },
    Case {
        name: "a revoked login",
        setup: || Setup { secret: Secret::Linked { refreshed_after: None }, ..Setup::default() },
        both: |s| s.status == 401 && s.bearers == [T1] && s.note("is unchanged: not retried"),
    },
    Case {
        name: "a login being rewritten",
        setup: || Setup { secret: Secret::Rewritten { after: Duration::from_millis(500) }, ..Setup::default() },
        both: |s| s.status == 200,
    },
    Case {
        name: "a login that can't be read",
        setup: || Setup { secret: Secret::Missing, ..Setup::default() },
        both: |s| s.status == 503 && s.body.contains("secret-unavailable") && s.bearers.is_empty(),
    },
    Case {
        name: "a node without the credential",
        setup: || Setup { secret: Secret::NodeUnfetchable, ..Setup::default() },
        both: |s| s.status >= 500 && s.bearers.is_empty(),
    },
    Case {
        name: "the run's placeholder in another header",
        setup: || Setup { headers: vec![("anthropic-beta", "ph-run")], ..Setup::default() },
        both: |s| s.status == 403 && s.bearers.is_empty(),
    },
    Case {
        name: "an upstream that echoes the credential",
        setup: || Setup { ..Setup::default() },
        both: |s| s.status == 200 && !s.body.contains(T1),
    },
    Case { name: "an upstream that encodes anyway", setup: Setup::default, both: |s| s.status == 502 && s.body.contains("gzip-encoded") },
    Case { name: "the model host down", setup: || Setup { upstream_down: true, ..Setup::default() }, both: |s| s.status == 502 },
    Case {
        name: "the box gives up while the call is out",
        setup: || Setup { give_up_after: Some(Duration::from_millis(100)), ..Setup::default() },
        both: |s| s.charged == 2,
    },
    Case { name: "stale activation", setup: || Setup { stale: true, ..Setup::default() }, both: |s| s.status == 409 },
    Case { name: "zone without a model route", setup: || Setup { no_model_route: true, ..Setup::default() }, both: |s| s.status == 404 },
];

/// What a case's mock answers, beyond its setup.
fn answer_for(case: &str) -> (Answer, u64) {
    match case {
        "an upstream that echoes the credential" => (Answer::Echo, 0),
        "an upstream that encodes anyway" => (Answer::Gzip, 0),
        "the box gives up while the call is out" => (Answer::Ok, 400),
        _ => (Answer::Ok, 0),
    }
}

/// Every behaviour of a model call, through both routes: alike, or listed with why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_model_call_behaves_alike_on_both_routes() {
    let mut failures = vec![];
    let mut known_now_alike = vec![];
    for case in CASES {
        let mut seen = vec![];
        for route in [Route::Direct, Route::Egress] {
            let (answer, delay) = answer_for(case.name);
            seen.push(run(route, (case.setup)(), &case.name.replace(' ', "-"), answer, delay).await);
        }
        let (d, e) = (&seen[0], &seen[1]);
        if std::env::var_os("PARITY_SHOW").is_some() {
            for (r, x) in [("direct", d), ("egress", e)] {
                eprintln!(
                    "SHOW {} [{r}] status={} req={} bearers={:?} charged={} first={} beta={} notes={:?} body={}",
                    case.name,
                    x.status,
                    x.requests,
                    x.bearers,
                    x.charged,
                    x.first_request,
                    x.beta_header,
                    x.notes,
                    x.body.chars().take(160).collect::<String>()
                );
            }
        }
        let listed = INTENDED.iter().chain(KNOWN).find(|x| x.case == case.name);
        match listed {
            Some(x) => {
                if !(x.direct)(d) || !(x.egress)(e) {
                    let in_known = KNOWN.iter().any(|k| k.case == case.name);
                    if in_known && (case.both)(d) && (case.both)(e) {
                        known_now_alike.push(format!("{} (row {})", case.name, x.row));
                    } else {
                        failures
                            .push(format!("{}: not as listed (row {}: {})\n    direct: {d:?}\n    egress: {e:?}", case.name, x.row, x.why));
                    }
                }
            }
            None => {
                for (route, s) in [("direct", d), ("egress", e)] {
                    if !(case.both)(s) {
                        failures.push(format!("{}: the {route} route differs, and isn't listed\n    {s:?}", case.name));
                    }
                }
            }
        }
    }
    assert!(known_now_alike.is_empty(), "now alike on both routes: delete from KNOWN: {known_now_alike:?}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every case is listed once, and every listed difference names a case.
#[test]
fn the_lists_name_cases() {
    let names: Vec<&str> = CASES.iter().map(|c| c.name).collect();
    for x in INTENDED.iter().chain(KNOWN) {
        assert!(names.contains(&x.case), "{} names no case", x.case);
    }
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "a case is listed twice");
    assert!(INTENDED_UNTESTED.iter().all(|(row, why)| *row > 0 && !why.is_empty()));
}
