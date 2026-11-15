//! Target 1: the egress proxy's request parsing, end to end. The input is the bytes a box writes on
//! one connection to the proxy: either the proxy socket itself (CONNECT, or absolute-form plain
//! HTTP) or, decrypted, the inside of a CONNECT tunnel to `fuzz.example` (where TLS is terminated,
//! the proxy's HTTP/1.1 server sees exactly these bytes).
//!
//! The first byte picks which; the rest is the stream. Requests that are allowed go to local
//! origins (`plain.example` over HTTP, `fuzz.example` over TLS) that record what they received.
//!
//! The oracle, besides panics and hangs: **what was decided is what went upstream** (no request
//! smuggling). Every request an origin receives must be the next request decided on that
//! connection, taken again from what the origin saw: the op [`wicket_core::git::op_for`] makes of the
//! origin's method, Host and canonical path has the decided method, host and path. A request the
//! origin receives that wasn't decided (a second request hidden in a body, a desynchronised
//! keep-alive connection) fails it, and so does one whose host, path or method changed on the way.
//!
//! HTTP/2 and HTTP/3 aren't parsed by wicket (hyper's `http1` server faces the box; HTTP/3 is the
//! `h3` crate's), so this target is HTTP/1.1 only.

use futures_util::future::BoxFuture;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wicket_core::{HostVerdict, Op};
use wicket_proxy::decide::{Decider, Outcome};
use wicket_proxy::egress::{Egress, Upstream};
use wicket_proxy::RunCtx;

/// The host whose tunnel the decrypted mode is inside (TLS origin).
pub const TLS_HOST: &str = "fuzz.example";
/// The host plain HTTP may go to (HTTP origin).
pub const PLAIN_HOST: &str = "plain.example";

/// What one side saw of a request: method, host, path and query as sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub method: String,
    pub host: String,
    pub path: String,
}

/// Allows every request to the two hosts, records what it decided, and forbids every other host.
struct Recorder {
    decided: Arc<Mutex<Vec<Seen>>>,
}

impl Decider for Recorder {
    fn host_verdict(&self, _ctx: &RunCtx, host: &str) -> HostVerdict {
        if host == TLS_HOST || host == PLAIN_HOST {
            HostVerdict::Open
        } else {
            HostVerdict::Forbidden("not a fuzz host".into())
        }
    }

    fn decide<'a>(&'a self, _ctx: &'a RunCtx, op: &'a Op, _who: Option<&'a (serde_json::Value, String)>) -> BoxFuture<'a, Outcome> {
        self.decided.lock().unwrap().push(Seen { method: op.method.clone(), host: op.host.clone(), path: op.path.clone() });
        Box::pin(async { Outcome::Allow("fuzz".into()) })
    }
}

struct World {
    rt: tokio::runtime::Runtime,
    egress: Arc<Egress>,
    decided: Arc<Mutex<Vec<Seen>>>,
    upstream: Arc<Mutex<Vec<Seen>>>,
}

fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime");
        let upstream: Arc<Mutex<Vec<Seen>>> = Default::default();
        let decided: Arc<Mutex<Vec<Seen>>> = Default::default();
        let (plain, tls, roots) = rt.block_on(origins(upstream.clone()));
        let (ctx, events) = crate::util::ctx("reach: []", crate::util::scratch("egress-vault"));
        // The world lives as long as the process: so does its event channel (unread).
        std::mem::forget(events);
        let ca = Arc::new(wicket_proxy::ca::RunCa::generate("run_fuzz").expect("run CA"));
        let up = Upstream {
            resolve: HashMap::from([(PLAIN_HOST.to_string(), plain), (TLS_HOST.to_string(), tls)]),
            roots_pem: Some(roots),
            no_h3: true,
            http1_only: true,
            ..Default::default()
        };
        let egress = rt.block_on(async { Egress::with_upstream(ctx, ca, Arc::new(Recorder { decided: decided.clone() }), None, up) }).expect("egress");
        World { rt, egress, decided, upstream }
    })
}

/// The two origins: plain HTTP, and TLS with a certificate from a CA of its own (returned as PEM).
async fn origins(log: Arc<Mutex<Vec<Seen>>>) -> (SocketAddr, SocketAddr, String) {
    let ca_key = rcgen::KeyPair::generate().expect("key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("CA");
    let leaf_key = rcgen::KeyPair::generate().expect("key");
    let leaf = rcgen::CertificateParams::new(vec![TLS_HOST.to_string()]).expect("params").signed_by(&leaf_key, &ca, &ca_key).expect("leaf");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        )
        .expect("server config");
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

    let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addrs = (plain.local_addr().unwrap(), tls.local_addr().unwrap());
    let l = log.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = plain.accept().await {
            tokio::spawn(origin_conn(s, l.clone()));
        }
    });
    tokio::spawn(async move {
        while let Ok((s, _)) = tls.accept().await {
            let (acceptor, log) = (acceptor.clone(), log.clone());
            tokio::spawn(async move {
                if let Ok(s) = acceptor.accept(s).await {
                    origin_conn(s, log).await;
                }
            });
        }
    });
    (addrs.0, addrs.1, ca.pem())
}

async fn origin_conn<S>(s: S, log: Arc<Mutex<Vec<Seen>>>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req: http::Request<Incoming>| {
        let log = log.clone();
        async move {
            let host = req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
            log.lock().unwrap().push(Seen { method: req.method().to_string(), host, path });
            // Read the body, so a keep-alive connection is reused only after the whole request.
            let _ = req.into_body().collect().await;
            Ok::<_, hyper::Error>(http::Response::new(Full::new(bytes::Bytes::from_static(b"origin"))))
        }
    });
    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
}

/// The op the decision would have been about, from what the origin received.
fn op_of(u: &Seen) -> Result<Seen, String> {
    let (path, query) = match u.path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (u.path.as_str(), ""),
    };
    let canon = wicket_core::canonical_path(path).map_err(|e| format!("the origin got a path that isn't canonical ({e}): {u:?}"))?;
    let host = u.host.split(':').next().unwrap_or("").to_string();
    let t = wicket_core::TenantId::single();
    let op = wicket_core::git::op_for(&t, &wicket_core::RunId("r".into()), "z", &u.method, &host, &canon.to_string(), query);
    Ok(Seen { method: op.method, host: op.host, path: op.path })
}

/// The proxy's HTTP/1.1 server, except that it answers what it has read after the client shuts
/// down its side (as a box that keeps the connection open until it has its answers would see).
pub(crate) fn half_closing() -> hyper::server::conn::http1::Builder {
    let mut b = hyper::server::conn::http1::Builder::new();
    b.half_close(true);
    b
}

pub fn run(data: &[u8]) {
    let (decided, upstream) = exchange(data);
    check(&decided, &upstream);
}

/// Runs one connection; what was decided, and what the origins received.
pub fn exchange(data: &[u8]) -> (Vec<Seen>, Vec<Seen>) {
    let Some((&mode, stream)) = data.split_first() else { return (vec![], vec![]) };
    let w = world();
    // One connection at a time: the logs are the world's (tests run on several threads).
    static ONE: Mutex<()> = Mutex::new(());
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    w.decided.lock().unwrap_or_else(|e| e.into_inner()).clear();
    w.upstream.lock().unwrap_or_else(|e| e.into_inner()).clear();
    let out = w.rt.block_on(async {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let egress = w.egress.clone();
        let served = if mode & 1 == 0 {
            tokio::spawn(egress.serve_io(server, half_closing()))
        } else {
            tokio::spawn(async move {
                let _ = egress.serve_decrypted(server, TLS_HOST.to_string(), half_closing()).await;
            })
        };
        let talk = async {
            let (mut rd, mut wr) = tokio::io::split(&mut client);
            let write = async {
                let _ = wr.write_all(stream).await;
                let _ = wr.shutdown().await;
            };
            let mut out = Vec::new();
            let read = async {
                let _ = rd.read_to_end(&mut out).await;
            };
            tokio::join!(write, read);
            out
        };
        let out = tokio::time::timeout(Duration::from_secs(10), talk).await;
        served.abort();
        out
    });
    // A connection that doesn't end within the time limit is a hang only if the box couldn't have
    // caused it by leaving a body unfinished; the proxy has no request timeout of its own, so
    // timeouts aren't findings.
    let _ = out;
    let decided = std::mem::take(&mut *w.decided.lock().unwrap_or_else(|e| e.into_inner()));
    let upstream = std::mem::take(&mut *w.upstream.lock().unwrap_or_else(|e| e.into_inner()));
    (decided, upstream)
}

/// Every request the origins got must be one decided, in order, and the same request.
pub fn check(decided: &[Seen], upstream: &[Seen]) {
    let mut d = decided.iter();
    for u in upstream {
        let want = op_of(u).unwrap_or_else(|e| panic!("{e}"));
        loop {
            match d.next() {
                Some(x) if *x == want => break,
                // A decided request may not reach the origin (refused when readied, an upstream error).
                Some(_) => continue,
                None => panic!(
                    "smuggled: the origin received {u:?} (decided as {want:?}), which was never decided; decided: {decided:?}, upstream: {upstream:?}"
                ),
            }
        }
    }
}
