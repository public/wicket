//! A replica of wicket's egress proxy data path (`crates/wicket-proxy/src/egress.rs` at 727e50f), for
//! the allowed-by-reach path. Same crates and calls: hyper HTTP/1.1 on a unix socket, CONNECT and
//! upgrade, `RunCa::server_config` (the real one) and a rustls accept, hyper HTTP/1.1 inside the tunnel,
//! `canonical_path`, `Op::egress_with_query` and `CompiledZone::evaluate`, the audit row written to a
//! `wicket_store::Ledger` under its mutex plus the event channel, and a shared `reqwest::Client` that
//! buffers the request body and streams the response.
//!
//! Changes, all for the harness:
//! - the upstream URL carries the origin's port (`https://origin.test:PORT/...`) and the reqwest
//!   client resolves `origin.test` to 127.0.0.1 and trusts the origin's CA (`add_root_certificate`);
//! - grants, approvals, credential swaps and the strike counter are left out (the bench only sends
//!   allowed requests, and the zone injects nothing);
//! - stage timings are recorded (a few `Instant::now()` calls per request).

use crate::stamps;
use anyhow::Result;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::UnixListener;
use tokio::sync::mpsc::UnboundedSender;
use wicket_core::{canonical_path, CompiledZone, Op, RunId, TenantId, Verdict};
use wicket_proxy::ca::RunCa;
use wicket_store::Ledger;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;
const STRIP_REQUEST: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "authorization",
    "x-api-key",
    "cookie",
];
const STRIP_RESPONSE: &[&str] = &["connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "content-length"];

pub struct Mitm {
    tenant: TenantId,
    run: RunId,
    zone: Arc<CompiledZone>,
    ca: Arc<RunCa>,
    client: reqwest::Client,
    ledger: Arc<Mutex<Ledger>>,
    events: UnboundedSender<serde_json::Value>,
    upstream_port: u16,
}

fn full(b: impl Into<Bytes>) -> BoxBody {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

fn problem(status: u16, detail: &str) -> Response<BoxBody> {
    let body = serde_json::json!({ "status": status, "detail": detail });
    Response::builder().status(status).header("content-type", "application/problem+json").body(full(body.to_string())).unwrap()
}

pub async fn run() -> Result<()> {
    let listen = match crate::Endpoint::parse(&crate::need("--listen")?)? {
        crate::Endpoint::Unix(p) => p,
        _ => anyhow::bail!("mitm listens on a unix socket"),
    };
    let dir = std::path::PathBuf::from(crate::need("--dir")?);
    let upstream_port: u16 = crate::need("--upstream-port")?.parse()?;
    let origin_ca = std::fs::read(dir.join("origin-ca.der"))?;
    let run = RunId("run_netbench".into());
    let ca = Arc::new(RunCa::generate(&run.0)?);
    std::fs::write(dir.join("run-ca.pem"), ca.cert_pem())?;
    let mut cb = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(15))
        // Harness only: route and trust the local origin.
        .add_root_certificate(reqwest::Certificate::from_der(&origin_ca)?)
        .resolve(crate::ORIGIN_HOST, ([127, 0, 0, 1], upstream_port).into());
    if crate::flag("--no-pool") {
        cb = cb.pool_max_idle_per_host(0);
    }
    let client = cb.build()?;
    let mut ledger = match crate::need("--ledger")?.as_str() {
        ":memory:" => Ledger::open_in_memory()?,
        p => Ledger::open(std::path::Path::new(p))?,
    };
    if crate::flag("--batched") {
        // As `wicket run` opens it since #62's fix: the process's batched audit writer.
        ledger.start_audit_writer(None)?;
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // The run drains events to its console; here they are dropped.
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let me = Arc::new(Mitm {
        tenant: TenantId::single(),
        run,
        zone: crate::zone()?,
        ca,
        client,
        ledger: Arc::new(Mutex::new(ledger)),
        events: tx,
        upstream_port,
    });
    stamps::dump_on_sigterm();
    let _ = std::fs::remove_file(&listen);
    let listener = UnixListener::bind(&listen)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let me = me.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| me.clone().outer(req));
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).with_upgrades().await;
        });
    }
}

impl Mitm {
    fn emit(&self, ev: serde_json::Value) {
        // As `RunCtx::emit`: with a writer, the lock is held only to clone it, and an allowed-by-reach
        // row is queued without waiting; without one, the row is written (and fsynced) here.
        let writer = self.ledger.lock().ok().and_then(|l| match l.audit_writer() {
            Some(w) => Some(w),
            None => {
                let _ = l.audit(&self.tenant, Some(&self.run), "op", &ev);
                None
            }
        });
        if let Some(w) = writer {
            let _ = w.submit(&self.tenant, Some(&self.run), "op", &ev);
        }
        let _ = self.events.send(ev);
    }

    async fn outer(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<BoxBody>, hyper::Error> {
        if req.method() != Method::CONNECT {
            return Ok(problem(400, "use CONNECT"));
        }
        let t0 = Instant::now();
        let Some(auth) = req.uri().authority().cloned() else { return Ok(problem(400, "CONNECT needs host:port")) };
        let host = auth.host().trim_end_matches('.').to_ascii_lowercase();
        let port = auth.port_u16().unwrap_or(443);
        if port != 443 || host.parse::<std::net::IpAddr>().is_ok() {
            return Ok(problem(403, "only hostnames on port 443"));
        }
        if !matches!(self.zone.host_verdict(&host), wicket_core::HostVerdict::Open) {
            return Ok(problem(403, "host"));
        }
        stamps::add("connect_judge_host", t0.elapsed());
        let me = self.clone();
        tokio::spawn(async move {
            if let Ok(upgraded) = hyper::upgrade::on(req).await {
                let _ = me.tunnel(upgraded, host).await;
            }
        });
        Ok(Response::new(full(Bytes::new())))
    }

    async fn tunnel(self: Arc<Self>, upgraded: hyper::upgrade::Upgraded, host: String) -> Result<()> {
        let t0 = Instant::now();
        let cfg = self.ca.server_config(&host)?;
        stamps::add("leaf_server_config", t0.elapsed());
        let t1 = Instant::now();
        let tls = tokio_rustls::TlsAcceptor::from(cfg).accept(TokioIo::new(upgraded)).await?;
        stamps::add("box_tls_accept", t1.elapsed());
        let me = self.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let host = host.clone();
            async move { Ok::<_, hyper::Error>(me.handle(req, host, "https").await) }
        });
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await?;
        Ok(())
    }

    async fn handle(self: Arc<Self>, req: Request<Incoming>, host: String, scheme: &str) -> Response<BoxBody> {
        let t0 = Instant::now();
        let method = req.method().as_str().to_string();
        if let Some(h) = req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()) {
            let h = h.split(':').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
            if !h.is_empty() && h != host {
                return problem(403, "Host header does not match the tunnel target");
            }
        }
        let pq = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        let path = match canonical_path(&pq) {
            Ok(p) => p.to_string(),
            Err(e) => return problem(403, &format!("ambiguous path: {e}")),
        };
        let query = pq.split_once('?').map(|(_, q)| q).unwrap_or("");
        let op = Op::egress_with_query(&self.tenant, &self.run, &self.zone.name, &method, &host, &path, query);
        let risk = format!("{:?}", op.risk);
        let verdict = self.zone.evaluate(&op);
        stamps::add("decide", t0.elapsed());
        let t1 = Instant::now();
        let ev = |outcome: &str, detail: String| {
            serde_json::json!({
                "kind": "egress", "method": method, "host": host, "path": path, "risk": risk,
                "outcome": outcome, "detail": detail,
            })
        };
        match verdict {
            Verdict::AllowByReach(i) => self.emit(ev("allow", format!("reach rule {i}"))),
            other => {
                self.emit(ev("forbidden", format!("{other:?}")));
                return problem(403, &format!("{other:?}"));
            }
        }
        stamps::add("audit_emit", t1.elapsed());
        match self.forward(req, &host, scheme, &pq).await {
            Ok(r) => r,
            Err(e) => problem(502, &e.to_string()),
        }
    }

    async fn forward(&self, req: Request<Incoming>, host: &str, scheme: &str, pq: &str) -> Result<Response<BoxBody>> {
        let t0 = Instant::now();
        let (parts, body) = req.into_parts();
        let body = Limited::new(body, MAX_REQUEST_BODY).collect().await.map_err(|e| anyhow::anyhow!("request body: {e}"))?.to_bytes();
        stamps::add("request_body_buffered", t0.elapsed());
        let url = format!("{scheme}://{host}:{}{pq}", self.upstream_port);
        let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?;
        let mut rb = self.client.request(method, &url);
        for (name, value) in parts.headers.iter() {
            if !STRIP_REQUEST.contains(&name.as_str()) {
                rb = rb.header(name.as_str(), value.as_bytes());
            }
        }
        // The zone injects nothing here; the real proxy scans its inject rules and swaps (none match).
        let injected: Vec<String> = Vec::new();
        let t1 = Instant::now();
        let resp = rb.body(body).send().await?;
        stamps::add("upstream_response_headers", t1.elapsed());
        let status = StatusCode::from_u16(resp.status().as_u16())?;
        let mut out = Response::builder().status(status);
        for (name, value) in resp.headers().iter() {
            if STRIP_RESPONSE.contains(&name.as_str()) {
                continue;
            }
            if injected.iter().any(|s| value.as_bytes().windows(s.len()).any(|w| w == s.as_bytes())) {
                continue;
            }
            out = out.header(name.as_str(), value.as_bytes());
        }
        let stream = resp.bytes_stream().map_ok(Frame::data).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        Ok(out.body(BodyExt::boxed(StreamBody::new(stream)))?)
    }
}
