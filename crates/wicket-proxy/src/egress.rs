//! The egress proxy (design §9.1): CONNECT, terminate TLS with the run's CA, canonicalize-or-reject,
//! decide, then forward with client credentials stripped and the zone's credential injected into
//! its one declared header slot.
//!
//! The same proxy runs on a remote node (`wicket node serve`, #57) with a different [`Decider`]
//! (the node's feed replica), a different [`Minter`] (the node's name-constrained CA), and a
//! [`Relay`] to the control host: CONNECTs the node must not terminate (see [`crate::decide::route`])
//! are tunnelled, raw, to the control host's own egress proxy for the run, which decides and
//! terminates them there.

use crate::ca::{Minter, RunCa};
use crate::decide::{Central, Decider, Outcome, Route};
use crate::{full, problem, BoxBody, Event, RunCtx, FORWARD_METHODS, FORWARD_REQUEST, HOP_BY_HOP, REFUSE_REQUEST};
use anyhow::Result;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited, StreamBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use wicket_core::{canonical_path, manifest::host_matches, Op};

/// The largest request body read whole: GET and HEAD (which must have none), and requests that
/// arrived over HTTP/3, which are re-sent upstream from memory.
const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;
/// HTTP/2 upstream flow control (#142): what one response may have in flight, per stream and per
/// connection, and the largest frame the upstream may send.
const H2_STREAM_WINDOW: u32 = 8 * 1024 * 1024;
const H2_CONN_WINDOW: u32 = 16 * 1024 * 1024;
const H2_MAX_FRAME: u32 = 1024 * 1024;
/// The largest request body streamed upstream (#142): enforced as the bytes pass, and up front when
/// the request says its length. Large enough for a release upload or a big `git push`.
pub(crate) const MAX_STREAMED_BODY: u64 = 4 * 1024 * 1024 * 1024;

pub struct Egress {
    pub(crate) ctx: RunCtx,
    pub(crate) ca: Arc<dyn Minter>,
    pub(crate) decider: Arc<dyn Decider>,
    pub(crate) relay: Option<Arc<dyn Relay>>,
    client: reqwest::Client,
    /// Where upstream connections go and what they trust, beyond DNS and the public roots (tests).
    pub(crate) upstream: Upstream,
    /// HTTP/3 upstream connections, made on first use (requests that arrived over HTTP/3).
    h3_up: tokio::sync::OnceCell<Option<Arc<crate::h3::Up>>>,
    /// Blocked attempts this run: per request (or host), and in total.
    strikes: std::sync::Mutex<(std::collections::HashMap<String, u32>, u32)>,
    /// The run's model proxy, which vets and accounts model calls that reach the model host through
    /// here (a wrapped session's, #112).
    model_gate: std::sync::OnceLock<Arc<crate::llm::Llm>>,
}

/// How upstream connections are made. The default (public DNS and the public roots) is what runs
/// use; tests point hosts at local origins with their own CA.
#[derive(Clone, Default)]
pub struct Upstream {
    /// Host -> address, instead of DNS. Pinned by whoever configures the proxy, so not subject to the
    /// dial-time address check (tests point hosts at local origins this way).
    pub resolve: std::collections::HashMap<String, std::net::SocketAddr>,
    /// Host -> the addresses DNS would answer (tests). Unlike `resolve`, these are checked like real
    /// answers: a name with a non-public address is refused (#116).
    pub dns: std::collections::HashMap<String, Vec<std::net::IpAddr>>,
    /// Extra trusted roots (PEM), besides the public ones.
    pub roots_pem: Option<String>,
    /// Re-originate requests that arrived over HTTP/3 over HTTP/3 too, when the upstream offers it
    /// (default on; HTTP/2 or HTTP/1.1 otherwise).
    pub no_h3: bool,
    /// HTTP/1.1 to every upstream, even one that offers HTTP/2 (benchmarks; an upstream whose
    /// HTTP/2 misbehaves). Default off: HTTP/2 where offered (#142).
    pub http1_only: bool,
}

impl Upstream {
    pub(crate) fn lookup(&self) -> crate::dial::Lookup {
        crate::dial::Lookup { fixed: Arc::new(self.dns.clone()) }
    }
}

/// How a request reached the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    /// CONNECT (or plain HTTP) over the box's TCP forwarder.
    Tcp,
    /// HTTP/3 over the box's UDP forwarder.
    H3,
}

/// A request ready to go upstream: decided, credentials stripped and injected.
pub(crate) struct Outgoing {
    pub method: http::Method,
    pub url: String,
    pub headers: http::HeaderMap,
    pub body: OutBody,
    /// What must never be reflected back into the box (injected secrets and their rendering).
    pub injected: Vec<String>,
}

/// A request body on its way upstream.
pub(crate) enum OutBody {
    /// Read whole (GET and HEAD, which must be empty; requests that arrived over HTTP/3).
    Buffered(Bytes),
    /// Streamed from the box as it arrives, never held whole (#142), within [`MAX_STREAMED_BODY`].
    Streamed(reqwest::Body),
}

impl OutBody {
    /// The whole body, if it was read whole.
    pub(crate) fn buffered(&self) -> Option<&Bytes> {
        match self {
            OutBody::Buffered(b) => Some(b),
            OutBody::Streamed(_) => None,
        }
    }
}

/// A byte stream to the control host (one tunnel over the node's control channel).
pub trait RelayStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> RelayStream for T {}

/// A node's way to the control host's egress proxy for this run.
pub trait Relay: Send + Sync {
    /// Whether the node terminates this host or tunnels it to the control host.
    fn route(&self, host: &str) -> Route;
    /// Opens a stream to the run's egress proxy on the control host; an error if the control host is
    /// unreachable.
    fn open(&self) -> futures_util::future::BoxFuture<'_, std::io::Result<Box<dyn RelayStream>>>;
}

/// The largest response head (and refusal body) read back from a forwarded CONNECT.
const MAX_FORWARDED_HEAD: usize = 64 * 1024;

impl Egress {
    /// The control host's egress proxy for a run: the run's own CA, decisions from the ledger.
    pub fn new(ctx: RunCtx, ca: Arc<RunCa>) -> Result<Arc<Egress>> {
        Egress::with(ctx, ca, Arc::new(Central), None)
    }

    /// An egress proxy with its own decision source, CA and (on a node) relay to the control host.
    pub fn with(ctx: RunCtx, ca: Arc<dyn Minter>, decider: Arc<dyn Decider>, relay: Option<Arc<dyn Relay>>) -> Result<Arc<Egress>> {
        Egress::with_upstream(ctx, ca, decider, relay, Upstream::default())
    }

    /// As [`Egress::with`], with upstream connections made as `upstream` says.
    pub fn with_upstream(
        ctx: RunCtx,
        ca: Arc<dyn Minter>,
        decider: Arc<dyn Decider>,
        relay: Option<Arc<dyn Relay>>,
        upstream: Upstream,
    ) -> Result<Arc<Egress>> {
        let mut b = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(15))
            // HTTP/2 where the upstream offers it (ALPN), else HTTP/1.1; one pooled HTTP/2 connection
            // per host carries many box connections' requests (#142). Fixed windows large enough for
            // a far upstream (8 MiB at 100 ms is 80 MB/s per stream) and 1 MiB frames: hyper's
            // adaptive window measured at less than half the download rate, and 16 KiB frames cost
            // CPU on both ends (docs/performance.md).
            .http2_initial_stream_window_size(H2_STREAM_WINDOW)
            .http2_initial_connection_window_size(H2_CONN_WINDOW)
            .http2_max_frame_size(H2_MAX_FRAME)
            // Every name is resolved by wicket and dialled only at checked, public addresses (#116).
            .dns_resolver(Arc::new(crate::dial::PublicResolver(upstream.lookup())));
        if upstream.http1_only {
            b = b.http1_only();
        }
        for (host, addr) in &upstream.resolve {
            b = b.resolve(host, *addr);
        }
        if let Some(pem) = &upstream.roots_pem {
            for c in reqwest::Certificate::from_pem_bundle(pem.as_bytes())? {
                b = b.add_root_certificate(c);
            }
        }
        let client = b.build()?;
        Ok(Arc::new(Egress {
            ctx,
            ca,
            decider,
            relay,
            client,
            upstream,
            h3_up: Default::default(),
            strikes: Default::default(),
            model_gate: Default::default(),
        }))
    }

    /// Model calls to the model host that come through this proxy (a wrapped Claude Code session's)
    /// go through `llm`'s budget, body filter and accounting (#112).
    pub fn set_model_gate(&self, llm: Arc<crate::llm::Llm>) {
        let _ = self.model_gate.set(llm);
    }

    /// Serves CONNECT (and plain absolute-form HTTP) on a unix socket until the task is dropped.
    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        let _ = std::fs::remove_file(socket);
        let listener = UnixListener::bind(socket)?;
        loop {
            let (stream, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| me.clone().outer(req));
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).with_upgrades().await;
            });
        }
    }

    async fn outer(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<BoxBody>, hyper::Error> {
        if req.method() == Method::CONNECT {
            let Some(auth) = req.uri().authority().cloned() else {
                return Ok(problem(400, "bad-request", "Bad CONNECT", "CONNECT needs host:port", None));
            };
            let port = auth.port_u16().unwrap_or(443);
            // One spelling per host, and no IP addresses in any spelling (#116).
            let host = match wicket_core::canonical_host(auth.host()) {
                Ok(h) => h,
                Err(e) => return Ok(self.refuse(&auth.host().to_ascii_lowercase(), "CONNECT", "/", &e.to_string())),
            };
            if port != 443 {
                return Ok(self.refuse(&host, "CONNECT", "/", &format!("only port 443 is proxied (asked for {port})")));
            }
            // A superseded activation (#70) gets no tunnel at all.
            if let Some(why) = self.ctx.superseded() {
                return Ok(self.refuse(&host, "CONNECT", "/", &why));
            }
            if let Some(r) = self.judge_host(&host, "CONNECT") {
                return Ok(r);
            }
            if let Some(relay) = &self.relay {
                if let Route::Forward(why) = relay.route(&host) {
                    return Ok(self.clone().forward_connect(req, host, why).await);
                }
            }
            if let Some(rule) = self.splice_rule(&host) {
                return Ok(self.clone().splice_connect(req, host, rule).await);
            }
            let me = self.clone();
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = me.clone().tunnel(upgraded, host.clone()).await {
                            tracing::debug!(%host, error = %e, "tunnel ended");
                        }
                    }
                    Err(e) => tracing::debug!(error = %e, "upgrade failed"),
                }
            });
            return Ok(Response::new(full(Bytes::new())));
        }
        // Absolute-form plain HTTP request.
        let host = req.uri().host().map(|h| (h.to_ascii_lowercase(), wicket_core::canonical_host(h)));
        match host {
            Some((raw, Err(e))) if req.uri().scheme_str() == Some("http") => {
                let method = req.method().to_string();
                Ok(self.refuse(&raw, &method, "/", &e.to_string()))
            }
            Some((_, Ok(h))) if req.uri().scheme_str() == Some("http") => {
                // The URL sent upstream has no port: say so rather than quietly using port 80.
                if let Some(port) = req.uri().port_u16().filter(|p| *p != 80) {
                    let method = req.method().to_string();
                    return Ok(self.refuse(&h, &method, "/", &format!("plain HTTP is proxied to port 80 only (asked for {port})")));
                }
                if let Some(r) = self.judge_host(&h, req.method().as_str()) {
                    return Ok(r);
                }
                if let Some(Route::Forward(why)) = self.relay.as_ref().map(|r| r.route(&h)) {
                    let method = req.method().to_string();
                    return Ok(self.refuse(&h, &method, "/", &format!("plain HTTP to {h} isn't served on this node ({why}); use https")));
                }
                let me = self.clone();
                Ok(me.handle(req, h, "http", Via::Tcp).await)
            }
            _ => Ok(problem(400, "bad-request", "Not a proxy request", "use CONNECT or an absolute http:// URL", None)),
        }
    }

    /// The reach rule that allows `host` wholesale, if this connection may be spliced through (#62):
    /// the decider says so (on a node, only while its policy is fresh, #141), and nothing is swapped
    /// in for the host. Asked at CONNECT and again every few seconds while a spliced connection lasts.
    pub(crate) fn splice_rule(&self, host: &str) -> Option<usize> {
        if self.ctx.swaps.iter().any(|s| host_matches(&s.host, host)) {
            return None;
        }
        if self.model_gate.get().is_some() && host == crate::llm::MODEL_HOST {
            return None;
        }
        self.decider.splice(&self.ctx, host)
    }

    /// A CONNECT to a host allowed wholesale: dial it now (a refused dial is the CONNECT's answer),
    /// then relay the box's TLS unmodified (see [`crate::splice`]).
    async fn splice_connect(self: Arc<Self>, req: Request<Incoming>, host: String, rule: usize) -> Response<BoxBody> {
        let up = match crate::splice::dial(&self.upstream, &host).await {
            Ok(s) => s,
            Err(e) => {
                let refused = e.kind() == std::io::ErrorKind::PermissionDenied;
                self.ctx.emit(Event::Egress {
                    method: "CONNECT".into(),
                    host: host.clone(),
                    path: "/".into(),
                    risk: "-".into(),
                    outcome: if refused { "forbidden" } else { "error" }.into(),
                    detail: format!("splice-through (reach rule {rule}): {e}"),
                });
                return problem(502, "upstream", "Upstream error", &format!("{host}: {e}"), None);
            }
        };
        let me = self.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => crate::splice::serve(me, upgraded, up, host, rule).await,
                Err(e) => tracing::debug!(error = %e, "upgrade failed"),
            }
        });
        Response::new(full(Bytes::new()))
    }

    async fn tunnel(self: Arc<Self>, upgraded: hyper::upgrade::Upgraded, host: String) -> Result<()> {
        self.tunnel_io(TokioIo::new(upgraded), host).await
    }

    /// Terminates the box's TLS for `host` on any byte stream and serves its requests.
    pub(crate) async fn tunnel_io<S>(self: Arc<Self>, io: S, host: String) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let cfg = self.ca.server_config(&host)?;
        let tls = tokio_rustls::TlsAcceptor::from(cfg).accept(io).await?;
        let me = self.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let host = host.clone();
            async move { Ok::<_, hyper::Error>(me.handle(req, host, "https", Via::Tcp).await) }
        });
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await?;
        Ok(())
    }

    /// Tunnels a CONNECT, raw, to the control host's egress proxy for this run (a node's forwarded
    /// host): the control host decides and terminates TLS there. Its answer to the CONNECT is the
    /// box's answer; after a 200 the bytes are piped both ways. Unreachable: a 403 that says so.
    async fn forward_connect(self: Arc<Self>, req: Request<Incoming>, host: String, why: String) -> Response<BoxBody> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let unreachable = |me: &Egress| {
            me.ctx.emit(Event::Egress {
                method: "CONNECT".into(),
                host: host.clone(),
                path: "/".into(),
                risk: "-".into(),
                outcome: "unavailable".into(),
                detail: format!("served by the control host ({why}), which is unreachable"),
            });
            problem(
                403,
                "unavailable",
                "Blocked by wicket sandbox: control plane unreachable",
                &format!(
                    "{host} is served by wicket's control host ({why}), which this node can't reach right now; retry later. {}",
                    crate::SANDBOX_FACT
                ),
                None,
            )
        };
        let Some(relay) = self.relay.clone() else { return unreachable(&self) };
        let mut s = match relay.open().await {
            Ok(s) => s,
            Err(_) => return unreachable(&self),
        };
        let connect = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
        if s.write_all(connect.as_bytes()).await.is_err() {
            return unreachable(&self);
        }
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match s.read(&mut byte).await {
                Ok(1) if head.len() < MAX_FORWARDED_HEAD => head.push(byte[0]),
                _ => return unreachable(&self),
            }
        }
        let Some((status, reason, headers)) = parse_head(&head) else { return unreachable(&self) };
        self.ctx.emit(Event::Egress {
            method: "CONNECT".into(),
            host: host.clone(),
            path: "/".into(),
            risk: "-".into(),
            outcome: "forwarded".into(),
            detail: format!("to the control host ({why}): {status}"),
        });
        if status == 200 {
            tokio::spawn(async move {
                if let Ok(up) = hyper::upgrade::on(req).await {
                    let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(up), &mut s).await;
                }
            });
            return Response::new(full(Bytes::new()));
        }
        let len = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse::<usize>().ok()).unwrap_or(0);
        let mut body = vec![0u8; len.min(MAX_FORWARDED_HEAD)];
        if s.read_exact(&mut body).await.is_err() {
            body.clear();
        }
        let mut b = Response::builder().status(status);
        for (k, v) in headers.iter().filter(|(k, _)| k == "content-type" || k.starts_with("x-wicket") || k == "retry-after") {
            b = b.header(k.as_str(), v.as_str());
        }
        let mut resp = b.body(full(body)).unwrap_or_else(|_| unreachable(&self));
        if let Ok(r) = hyper::ext::ReasonPhrase::try_from(reason) {
            resp.extensions_mut().insert(r);
        }
        resp
    }

    /// Decides about a host before any request to it (and before TLS): never-reachable hosts are
    /// refused, saying so; in zones that hide unlisted hosts, they behave as if they didn't exist.
    pub(crate) fn judge_host(&self, host: &str, method: &str) -> Option<Response<BoxBody>> {
        match self.decider.host_verdict(&self.ctx, host) {
            wicket_core::HostVerdict::Open => None,
            wicket_core::HostVerdict::Forbidden(why) => {
                self.ctx.emit(Event::Egress {
                    method: method.into(),
                    host: host.into(),
                    path: "/".into(),
                    risk: "-".into(),
                    outcome: "forbidden".into(),
                    detail: why.clone(),
                });
                let note = self.strike(&format!("host {host}"));
                Some(problem(403, "forbidden", "Blocked by wicket sandbox: never allowed", &format!(
                    "{why}. This will never be allowed from this sandbox, and no approval can change that. {} Do not retry it; tell the user it is blocked.{note}",
                    crate::SANDBOX_FACT
                ), None))
            }
            wicket_core::HostVerdict::Hidden => {
                self.ctx.emit(Event::Egress {
                    method: method.into(),
                    host: host.into(),
                    path: "/".into(),
                    risk: "-".into(),
                    outcome: "hidden".into(),
                    detail: "not a host this zone can see".into(),
                });
                let note = self.strike(&format!("host {host}"));
                Some(problem(502, "unknown-host", "wicket sandbox: unknown host", &format!(
                    "{host} does not exist as far as this sandbox is concerned: it can only see the hosts its zone names. {} Do not retry it.{note}",
                    crate::SANDBOX_FACT
                ), None))
            }
        }
    }

    /// Counts a blocked attempt and returns a note for the agent once it starts repeating itself: the
    /// point is that an agent at the edge of its sandbox stops and asks, rather than spinning.
    pub(crate) fn strike(&self, key: &str) -> String {
        let (same, total) = {
            let mut s = self.strikes.lock().expect("strikes");
            let same = {
                let n = s.0.entry(key.to_string()).or_insert(0);
                *n += 1;
                *n
            };
            s.1 += 1;
            (same, s.1)
        };
        if total == 10 || (total > 10 && total % 10 == 0) {
            self.ctx
                .emit(Event::Tool { name: "wicket".into(), detail: format!("agent may be stuck: {total} blocked requests in this run") });
        }
        let mut note = String::new();
        if same >= 3 {
            note.push_str(&format!(" This exact request has now been blocked {same} times: stop retrying it."));
        }
        if total >= 10 {
            note.push_str(&format!(" This run has hit the sandbox's limits {total} times. Stop exploring alternatives: tell the user what you need, or call request_access once with a reason."));
        }
        note
    }

    pub(crate) fn refuse(&self, host: &str, method: &str, path: &str, why: &str) -> Response<BoxBody> {
        self.ctx.emit(Event::Egress {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            risk: "-".into(),
            outcome: "forbidden".into(),
            detail: why.into(),
        });
        problem(403, "forbidden", "Blocked by wicket sandbox: malformed request", &format!("{why}. {}", crate::SANDBOX_FACT), None)
    }

    /// Decide and, if allowed, forward one request. `host` is the CONNECT target (or the absolute
    /// URL's host), never a client-supplied Host header.
    pub(crate) async fn handle<B>(self: Arc<Self>, req: Request<B>, host: String, scheme: &str, via: Via) -> Response<BoxBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let method = req.method().as_str().to_string();
        if let Some(why) = self.ctx.superseded() {
            return self.refuse(&host, &method, "/", &why);
        }
        // Authority pinning: a Host header that disagrees with the tunnel target is an attack.
        if let Some(h) = req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()) {
            let h = h.split(':').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
            if !h.is_empty() && h != host {
                return self.refuse(&host, &method, "/", &format!("Host header {h:?} does not match the tunnel target"));
            }
        }
        if let Some(why) = refused_shape(&req) {
            return self.refuse(&host, &method, "/", &why);
        }
        // A credential never goes out in cleartext (#129): plain HTTP to a host the zone injects a
        // credential into, or swaps a placeholder for, is refused before anything is decided or read
        // from the vault, whether or not this request would have carried one.
        if scheme != "https" && self.credentials_for(&host) {
            return self.refuse(
                &host,
                &method,
                "/",
                &format!("plain HTTP to {host} is refused: wicket attaches a credential to requests for this host and never sends one unencrypted; use https://{host}/"),
            );
        }
        let pq = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        let path = match canonical_path(&pq) {
            Ok(p) => p.to_string(),
            Err(e) => return self.refuse(&host, &method, &pq, &format!("ambiguous path: {e}")),
        };
        let ctx = &self.ctx;
        let query = pq.split_once('?').map(|(_, q)| q).unwrap_or("");
        let op = Op::egress_with_query(&ctx.tenant, &ctx.run, &ctx.zone.name, &method, &host, &path, query);
        let risk = format!("{:?}", op.risk);
        let emit = |outcome: &str, detail: String| {
            ctx.emit(Event::Egress {
                method: method.clone(),
                host: host.clone(),
                path: path.clone(),
                risk: risk.clone(),
                outcome: outcome.into(),
                detail,
            })
        };
        // Who in the box is asking (reported by the agent's own event stream, not proven).
        let who = ctx.attribute.as_ref().and_then(|f| f(&host, &path));
        match self.decider.decide(ctx, &op, who.as_ref()).await {
            Outcome::Allow(detail) => {
                // A grant's use must be on the record before the request goes ahead (fail closed).
                let ev = Event::Egress {
                    method: method.clone(),
                    host: host.clone(),
                    path: path.clone(),
                    risk: risk.clone(),
                    outcome: "allow".into(),
                    detail: detail.clone(),
                };
                if let Err(e) = ctx.record(ev) {
                    emit("unavailable", format!("{detail}; refused: the audit record could not be written ({e})"));
                    return problem(
                        503,
                        "audit-unavailable",
                        "Blocked by wicket sandbox: the audit log is unavailable",
                        &format!(
                            "wicket could not record this request in its audit log, so it was not sent; retry later. {}",
                            crate::SANDBOX_FACT
                        ),
                        None,
                    );
                }
            }
            Outcome::Forbidden(why) => {
                emit("forbidden", why.clone());
                let note = self.strike(&op.digest());
                return problem(403, "forbidden", "Blocked by wicket sandbox: never allowed", &format!(
                    "{why}. This will never be allowed from this sandbox, and no approval can change that. {} Do not retry it; tell the user it is blocked.{note}",
                    crate::SANDBOX_FACT
                ), None);
            }
            Outcome::NoEscalation(why) => {
                emit("forbidden", format!("{why}; this run does not escalate (on_pending: fail)"));
                return problem(
                    403,
                    "forbidden",
                    "Outside this program's reach",
                    &format!("{why}. Programs do not escalate: change the program's approved reach instead."),
                    None,
                );
            }
            Outcome::Denied { request: rid } => {
                emit("denied", format!("request {rid} was denied"));
                let note = self.strike(&op.digest());
                return problem(403, "denied", "Blocked by wicket sandbox: denied by a human", &format!(
                    "A human denied request {rid} for exactly this request. {} Do not retry it; continue without it and tell the user.{note}",
                    crate::SANDBOX_FACT
                ), None);
            }
            Outcome::Pending { request: rid, fresh, why } => {
                let for_line = who.as_ref().map(|(_, l)| format!("; for {l}")).unwrap_or_default();
                emit("pending", format!("{rid}{}: {why}{for_line}", if fresh { " (new)" } else { "" }));
                let note = self.strike(&op.digest());
                return problem(403, "pending-approval", "Blocked by wicket sandbox: needs human approval", &format!(
                    "{why}. wicket has asked a human to approve request {rid}; until they do, this request fails every time. {} Call await_grant with {rid} to wait, or tell the user that request {rid} is waiting for their approval in wicket (approvals happen in wicket, not in this conversation).{note}",
                    crate::SANDBOX_FACT
                ), Some(&rid));
            }
            Outcome::Unavailable(why) => {
                emit("unavailable", why.clone());
                return problem(
                    403,
                    "unavailable",
                    "Blocked by wicket sandbox: control plane unreachable",
                    &format!("{why}. {}", crate::SANDBOX_FACT),
                    None,
                );
            }
            Outcome::Error(e) => return problem(500, "error", "Ledger error", &e, None),
        }
        if let Some(llm) = self.model_gate.get().filter(|_| crate::llm::is_model_call(&host, &path)) {
            return llm.clone().through_egress(&self, req, &host, &pq, via).await;
        }
        match self.forward(req, &host, scheme, &pq, via).await {
            Ok(r) => r,
            // The whole chain: a refused dial (#116) says why at its end.
            Err(e) => problem(502, "upstream", "Upstream error", &format!("{e:#}"), None),
        }
    }

    /// Whether the zone injects a credential into requests for `host`, or swaps one in.
    fn credentials_for(&self, host: &str) -> bool {
        self.ctx.zone.inject.iter().any(|r| host_matches(&r.host, host)) || self.ctx.swaps.iter().any(|s| host_matches(&s.host, host))
    }

    pub(crate) async fn forward<B>(&self, req: Request<B>, host: &str, scheme: &str, pq: &str, via: Via) -> Result<Response<BoxBody>>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // Over HTTP/3 the request may be re-sent over HTTP/2 if the HTTP/3 connection is gone, so its
        // body is read whole; otherwise it streams.
        let out = self.prepare(req, host, scheme, pq, via != Via::H3).await?;
        if via == Via::H3 && scheme == "https" && !self.upstream.no_h3 {
            if let Some(up) = self.h3_up().await {
                if let Some(r) = up.try_send(host, &out).await {
                    return r.map(|r| self.clean(r, &out.injected));
                }
            }
        }
        let Outgoing { method, url, headers, body, injected } = out;
        let body = match body {
            OutBody::Buffered(b) => reqwest::Body::from(b),
            OutBody::Streamed(b) => b,
        };
        let resp = self.client.request(method, &url).headers(headers).body(body).send().await?;
        let mut head = Response::builder().status(StatusCode::from_u16(resp.status().as_u16())?);
        for (name, value) in resp.headers().iter() {
            head = head.header(name, value);
        }
        let stream = resp.bytes_stream().map_ok(Frame::data).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        Ok(self.clean(head.body(BodyExt::boxed(StreamBody::new(stream)))?, &injected))
    }

    /// The HTTP/3 upstream (made on first use); None if its UDP socket can't be had.
    async fn h3_up(&self) -> Option<Arc<crate::h3::Up>> {
        self.h3_up
            .get_or_init(|| async {
                match crate::h3::Up::new(&self.upstream) {
                    Ok(u) => Some(Arc::new(u)),
                    Err(e) => {
                        tracing::warn!(error = %e, "no HTTP/3 upstream; using HTTP/2");
                        None
                    }
                }
            })
            .await
            .clone()
    }

    /// Drops hop-by-hop response headers, and any that would reflect an injected credential back into
    /// the box. `content-length` stays: the body passes through unchanged (#142), so clients keep
    /// download sizes and progress.
    fn clean(&self, resp: Response<BoxBody>, injected: &[String]) -> Response<BoxBody> {
        let (mut parts, body) = resp.into_parts();
        let names: Vec<http::HeaderName> = parts.headers.keys().cloned().collect();
        for name in names {
            if HOP_BY_HOP.contains(&name.as_str()) {
                parts.headers.remove(&name);
                continue;
            }
            let leaks = parts
                .headers
                .get_all(&name)
                .iter()
                .any(|v| injected.iter().any(|s| v.as_bytes().windows(s.len()).any(|w| w == s.as_bytes())));
            if leaks {
                parts.headers.remove(&name);
            }
        }
        Response::from_parts(parts, body)
    }

    /// Strips the box's credentials and headers, injects the zone's, and readies the body: streamed
    /// if `stream` (keeping the request's `content-length`), else read whole (bounded). GET and HEAD
    /// are always read, and refused if they carry a body.
    async fn prepare<B>(&self, req: Request<B>, host: &str, scheme: &str, pq: &str, stream: bool) -> Result<Outgoing>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (parts, body) = req.into_parts();
        // What the box put in Authorization: only ever a placeholder, to be swapped (below) or dropped.
        let box_auth = parts.headers.get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);
        let url = format!("{scheme}://{host}{pq}");
        // Only allow-listed headers go upstream (#130); credentials are added below, by wicket.
        let mut headers = http::HeaderMap::new();
        for (name, value) in parts.headers.iter() {
            if FORWARD_REQUEST.contains(&name.as_str()) || crate::provider_request_header(host, name.as_str()) {
                headers.append(name.clone(), value.clone());
            }
        }
        let body = if stream && !matches!(parts.method, Method::GET | Method::HEAD) {
            // The length the box declared goes upstream as declared (hyper has already checked it
            // is one well-formed number, and holds the body to it); without one, chunked.
            let length = match parts.headers.get(http::header::CONTENT_LENGTH) {
                None => None,
                Some(v) => Some(
                    v.to_str()
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .ok_or_else(|| anyhow::anyhow!("refused: a malformed content-length"))?,
                ),
            };
            if let Some(n) = length.filter(|n| *n > MAX_STREAMED_BODY) {
                anyhow::bail!("refused: a {n}-byte request body (the limit is {MAX_STREAMED_BODY})");
            }
            if let Some(n) = length {
                headers.insert(http::header::CONTENT_LENGTH, n.into());
            }
            let limited = Limited::new(body, usize::try_from(MAX_STREAMED_BODY).unwrap_or(usize::MAX));
            OutBody::Streamed(reqwest::Body::wrap_stream(limited.into_data_stream()))
        } else {
            let body = Limited::new(body, MAX_REQUEST_BODY).collect().await.map_err(|e| anyhow::anyhow!("request body: {e}"))?.to_bytes();
            if matches!(parts.method, Method::GET | Method::HEAD) && !body.is_empty() {
                anyhow::bail!("refused: a {} request with a body", parts.method);
            }
            OutBody::Buffered(body)
        };
        // Inject the zone's credential for this host into its one declared slot. An optional rule
        // whose secret isn't set sends the request without it (e.g. anonymous reads).
        let mut injected: Vec<String> = Vec::new();
        for rule in &self.ctx.zone.inject {
            if host_matches(&rule.host, host) {
                // Whatever the zone says, a secret goes only to the hosts it is bound to in the vault.
                self.ctx.vault.check(&rule.secret, host)?;
                let secret = match self.ctx.vault.get(&rule.secret) {
                    Ok(s) => s,
                    Err(_) if rule.optional => break,
                    Err(e) => return Err(e),
                };
                let value = render_credential(&rule.format, &secret);
                headers.insert(http::HeaderName::from_bytes(rule.header.as_bytes())?, http::HeaderValue::from_str(&value)?);
                injected.push(secret);
                injected.push(value);
                break;
            }
        }
        if injected.is_empty() {
            if let Some(auth) = &box_auth {
                let presented = auth.strip_prefix("Bearer ").unwrap_or("");
                match self.ctx.swaps.iter().find(|s| host_matches(&s.host, host) && !presented.is_empty() && s.placeholder == presented) {
                    Some(sw) => {
                        let real = match &sw.real {
                            crate::SwapSource::Vault(name) => self.ctx.vault.get_for(name, host)?,
                            crate::SwapSource::Value(v) => v.clone(),
                        };
                        headers.insert(http::header::AUTHORIZATION, http::HeaderValue::from_str(&format!("Bearer {real}"))?);
                        injected.push(real);
                        tracing::debug!(host, swap = %sw.name, "credential swapped");
                    }
                    None if self.ctx.swaps.iter().any(|s| s.box_bearers && host_matches(&s.host, host)) && auth.starts_with("Bearer ") => {
                        headers.insert(http::header::AUTHORIZATION, http::HeaderValue::from_str(auth)?);
                        tracing::debug!(host, "the box's own bearer passed (box_bearers)");
                    }
                    None => tracing::debug!(host, "box-supplied authorization dropped (not a known placeholder)"),
                }
            }
        }
        Ok(Outgoing { method: parts.method, url, headers, body, injected })
    }
}

/// Why a request is refused before any decision, by its method, headers or body framing (#130,
/// design §9.1): methods other than the usual ones (TRACE, and CONNECT inside a tunnel, among them),
/// method-override and URL-rewrite headers, and a body on GET or HEAD.
fn refused_shape<B>(req: &Request<B>) -> Option<String> {
    let method = req.method().as_str();
    if !FORWARD_METHODS.contains(&method) {
        return Some(format!("the {method} method is not proxied"));
    }
    if let Some(h) = REFUSE_REQUEST.iter().find(|h| req.headers().contains_key(**h)) {
        return Some(format!("the {h} header is refused: the request must be decided as it will run"));
    }
    if matches!(*req.method(), Method::GET | Method::HEAD) {
        let h = req.headers();
        let length = h.get(http::header::CONTENT_LENGTH).map(|v| v.as_bytes() != b"0").unwrap_or(false);
        if length || h.contains_key(http::header::TRANSFER_ENCODING) {
            return Some(format!("a {method} request with a body is not proxied"));
        }
    }
    None
}

/// A response head: status, reason phrase, and headers with lowercase names.
type Head = (u16, String, Vec<(String, String)>);

/// Parses an HTTP/1.1 response head.
fn parse_head(head: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.splitn(3, ' ');
    let status = first.nth(1)?.parse().ok()?;
    let reason = first.next().unwrap_or("").to_string();
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    Some((status, reason, headers))
}

/// Renders an injection format: `{secret}` is the secret itself; `{basic:USER}` is
/// base64("USER:secret"), for HTTP Basic credentials such as git over HTTPS with a token.
pub fn render_credential(format: &str, secret: &str) -> String {
    use base64::Engine;
    let mut out = format.replace("{secret}", secret);
    while let Some(start) = out.find("{basic:") {
        let Some(len) = out[start..].find('}') else { break };
        let user = out[start + 7..start + len].to_string();
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}"));
        out.replace_range(start..start + len + 1, &enc);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn forwarded_response_heads_parse_and_garbage_does_not() {
        let (st, reason, h) =
            super::parse_head(b"HTTP/1.1 403 Blocked by wicket sandbox: x\r\nContent-Length: 12\r\nX-Wicket: pending-approval\r\n\r\n")
                .unwrap();
        assert_eq!((st, reason.as_str()), (403, "Blocked by wicket sandbox: x"));
        assert!(h.contains(&("x-wicket".into(), "pending-approval".into())));
        assert!(super::parse_head(b"\xff\xfe").is_none());
        assert!(super::parse_head(b"HTTP/1.1 x\r\n\r\n").is_none());
    }

    /// A run context for a zone, with a vault where `gh` may go only to api.github.com.
    fn ctx(zone: &str, swaps: Vec<crate::CredentialSwap>, tag: &str) -> (crate::RunCtx, std::path::PathBuf) {
        use std::sync::{Arc, Mutex};
        let dir = std::env::temp_dir().join(format!("wicket-egress-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = crate::vault::Vault::new(dir.join("vault"));
        vault.set("gh", "the-real-token").unwrap();
        vault.set_hosts("gh", &["api.github.com".into()]).unwrap();
        let m = wicket_core::Manifest::from_yaml(&format!("task: t\nagent: {{name: a}}\nzone: {{name: z, llm: {{secret: m}}, {zone}}}"))
            .unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let c = crate::RunCtx {
            tenant: wicket_core::TenantId::single(),
            run: wicket_core::RunId("run_x".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(m.zone.clone()).unwrap()),
            ledger: Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().unwrap())),
            vault,
            events: tx,
            escalate: true,
            attribute: None,
            identity: None,
            spawner: None,
            swaps,
            boxes: None,
            capacity: None,
            fence: None,
            waker: None,
        };
        (c, dir)
    }

    async fn prepare(c: crate::RunCtx, host: &str, auth: Option<&str>) -> anyhow::Result<super::Outgoing> {
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::new(c, ca).unwrap();
        let mut b = http::Request::get("/x").header("host", host);
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        e.prepare(b.body(http_body_util::Full::new(bytes::Bytes::new())).unwrap(), host, "https", "/x", true).await
    }

    /// Whatever a zone says, the proxy never attaches a secret to a host it isn't bound to.
    #[tokio::test]
    async fn a_secret_is_injected_only_into_its_bound_hosts() {
        let inject = |host: &str| format!("inject: [{{host: '{host}', header: Authorization, format: 'Bearer {{secret}}', secret: gh}}]");
        let (c, dir) = ctx(&inject("attacker.example"), vec![], "evil");
        let e = prepare(c, "attacker.example", None).await.err().expect("refused").to_string();
        assert!(e.contains("not to attacker.example"), "{e}");
        let (c, _) = ctx(&inject("*.example"), vec![], "evil-wild");
        assert!(prepare(c, "attacker.example", None).await.is_err());
        let (c, _) = ctx(&inject("api.github.com"), vec![], "ok");
        let out = prepare(c, "api.github.com", None).await.unwrap();
        assert_eq!(out.headers.get("authorization").unwrap(), "Bearer the-real-token");
        // A swap from the vault is bound the same way, whatever host the swap names.
        let swap = |host: &str| crate::CredentialSwap {
            box_bearers: false,
            name: "t".into(),
            host: host.into(),
            placeholder: "ph-123".into(),
            real: crate::SwapSource::Vault("gh".into()),
        };
        let (c, _) = ctx("reach: []", vec![swap("attacker.example")], "swap-evil");
        assert!(prepare(c, "attacker.example", Some("Bearer ph-123")).await.is_err());
        let (c, _) = ctx("reach: []", vec![swap("api.github.com")], "swap-ok");
        let out = prepare(c, "api.github.com", Some("Bearer ph-123")).await.unwrap();
        assert_eq!(out.headers.get("authorization").unwrap(), "Bearer the-real-token");
        for t in ["evil", "evil-wild", "ok", "swap-evil", "swap-ok"] {
            let _ = std::fs::remove_dir_all(dir.with_file_name(format!("wicket-egress-{t}-{}", std::process::id())));
        }
    }

    /// #130: only allow-listed headers go upstream, and requests that could run as something other
    /// than what was decided are refused before the decision.
    #[tokio::test]
    async fn headers_are_forwarded_by_allowlist_and_override_shapes_are_refused() {
        use http_body_util::BodyExt;
        let (c, dir) = ctx("reach: [{host: api.github.com, methods: [GET, POST]}]", vec![], "shape");
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::new(c, ca).unwrap();
        let empty = || http_body_util::Full::new(bytes::Bytes::new());
        let refused = [
            http::Request::builder().method("TRACE").uri("/x").body(empty()).unwrap(),
            http::Request::builder().method("TRACK").uri("/x").body(empty()).unwrap(),
            http::Request::builder().method("CONNECT").uri("/x").body(empty()).unwrap(),
            http::Request::post("/repos/a/b/issues").header("x-http-method-override", "DELETE").body(empty()).unwrap(),
            http::Request::get("/safe").header("X-Original-URL", "/admin").body(empty()).unwrap(),
            http::Request::get("/safe").header("x-rewrite-url", "/admin").body(empty()).unwrap(),
            http::Request::get("/safe")
                .header("content-length", "5")
                .body(http_body_util::Full::new(bytes::Bytes::from_static(b"hello")))
                .unwrap(),
            http::Request::head("/safe").header("transfer-encoding", "chunked").body(empty()).unwrap(),
        ];
        for req in refused {
            let what = format!("{} {:?}", req.method(), req.headers());
            let resp = e.clone().handle(req, "api.github.com".into(), "https", super::Via::Tcp).await;
            let status = resp.status();
            let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
            assert_eq!(status, 403, "{what}: {body}");
            assert!(body.contains("malformed request") || body.contains("not proxied") || body.contains("refused"), "{what}: {body}");
        }
        // What does go upstream: the allow-list, plus the provider's own headers on its hosts only.
        let req = || {
            http::Request::post("/x")
                .header("accept", "application/json")
                .header("content-type", "application/json")
                .header("git-protocol", "version=2")
                .header("x-github-api-version", "2022-11-28")
                .header("anthropic-beta", "b")
                .header("x-forwarded-for", "10.0.0.1")
                .header("x-forwarded-host", "internal")
                .header("forwarded", "for=10.0.0.1")
                .header("cookie", "a=b")
                .header("x-api-key", "k")
                .header("x-anything", "y")
                .body(empty())
                .unwrap()
        };
        let gh = e.prepare(req(), "api.github.com", "https", "/x", true).await.unwrap();
        let names: Vec<&str> = gh.headers.keys().map(|k| k.as_str()).collect();
        assert_eq!(names, ["accept", "content-type", "git-protocol", "x-github-api-version"], "{names:?}");
        let other = e.prepare(req(), "example.com", "https", "/x", true).await.unwrap();
        assert!(!other.headers.contains_key("x-github-api-version") && !other.headers.contains_key("anthropic-beta"));
        let ant = e.prepare(req(), "api.anthropic.com", "https", "/x", true).await.unwrap();
        assert!(ant.headers.contains_key("anthropic-beta") && !ant.headers.contains_key("x-github-api-version"));
        // A GET body that arrives without framing headers (HTTP/3) is caught when it is read.
        let get = http::Request::get("/x").body(http_body_util::Full::new(bytes::Bytes::from_static(b"x"))).unwrap();
        assert!(e.prepare(get, "api.github.com", "https", "/x", true).await.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #112: a wrapped session's model calls, which come through the egress proxy, get the model
    /// proxy's budget and body checks there: never forwarded once the budget is spent, nor as a
    /// batch or an encoded body.
    #[tokio::test]
    async fn model_calls_through_egress_are_vetted_and_counted() {
        use http_body_util::BodyExt;
        let (c, dir) = ctx("reach: [{host: api.anthropic.com, methods: [GET, POST]}]", vec![], "model-gate");
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::new(c.clone(), ca).unwrap();
        let llm = crate::llm::Llm::new(c).unwrap();
        e.set_model_gate(llm.clone());
        let send = |path: &str, enc: Option<&str>| {
            let mut b = http::Request::post(path).header("content-type", "application/json");
            if let Some(x) = enc {
                b = b.header("content-encoding", x);
            }
            let req =
                b.body(http_body_util::Full::new(bytes::Bytes::from_static(br#"{"model":"m","max_tokens":5,"messages":[]}"#))).unwrap();
            let e = e.clone();
            async move {
                let r = e.handle(req, "api.anthropic.com".into(), "https", super::Via::Tcp).await;
                let st = r.status().as_u16();
                (st, String::from_utf8_lossy(&r.into_body().collect().await.unwrap().to_bytes()).into_owned())
            }
        };
        assert_eq!(send("/v1/messages/batches", None).await.0, 403);
        assert_eq!(send("/v1/messages", Some("gzip")).await.0, 415);
        assert_eq!(llm.requests.load(std::sync::atomic::Ordering::SeqCst), 2, "counted as model requests");
        llm.spent_before(u64::MAX / 4, 0, 0);
        let (st, body) = send("/v1/messages", None).await;
        assert_eq!(st, 429, "{body}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #129: no credential is ever sent over plain HTTP: requests to a host with an inject rule or a
    /// swap are refused with a 403 that says to use https, before the vault is read.
    #[tokio::test]
    async fn plain_http_to_a_credentialed_host_is_refused() {
        use http_body_util::BodyExt;
        let swap = crate::CredentialSwap {
            box_bearers: false,
            name: "t".into(),
            host: "api.github.com".into(),
            placeholder: "ph-123".into(),
            real: crate::SwapSource::Vault("gh".into()),
        };
        let inject = "reach: [{host: api.github.com, methods: [GET]}], inject: [{host: api.github.com, header: Authorization, format: 'Bearer {secret}', secret: gh}]";
        for (zone, swaps, tag) in
            [(inject, vec![], "http-inject"), ("reach: [{host: api.github.com, methods: [GET]}]", vec![swap], "http-swap")]
        {
            let (c, dir) = ctx(zone, swaps, tag);
            let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
            let e = super::Egress::new(c, ca).unwrap();
            let req = http::Request::get("/user")
                .header("host", "api.github.com")
                .header("authorization", "Bearer ph-123")
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .unwrap();
            let resp = e.clone().handle(req, "api.github.com".into(), "http", super::Via::Tcp).await;
            let status = resp.status();
            let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
            assert_eq!(status, 403, "{tag}: {body}");
            assert!(body.contains("never sends one unencrypted") && !body.contains("the-real-token"), "{tag}: {body}");
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// #116: a name in reach whose DNS answer is a non-public address is never dialled.
    #[tokio::test]
    async fn a_name_resolving_to_a_private_address_is_not_dialled() {
        use http_body_util::BodyExt;
        let (c, dir) = ctx("reach: [{host: rebind.example, methods: [GET]}, {host: meta.example, methods: [GET]}]", vec![], "rebind");
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let mut up = super::Upstream::default();
        up.dns.insert("rebind.example".into(), vec!["127.0.0.1".parse().unwrap()]);
        up.dns.insert("meta.example".into(), vec!["8.8.8.8".parse().unwrap(), "169.254.169.254".parse().unwrap()]);
        let e = super::Egress::with_upstream(c, ca, std::sync::Arc::new(crate::decide::Central), None, up).unwrap();
        for host in ["rebind.example", "meta.example"] {
            let req =
                http::Request::get("/latest/user-data").header("host", host).body(http_body_util::Full::new(bytes::Bytes::new())).unwrap();
            let resp = e.clone().handle(req, host.into(), "http", super::Via::Tcp).await;
            let status = resp.status();
            let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned();
            assert_eq!(status, 502, "{body}");
            assert!(body.contains("non-public address"), "{body}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn credential_formats() {
        assert_eq!(super::render_credential("Bearer {secret}", "tok"), "Bearer tok");
        // base64("x-access-token:tok")
        assert_eq!(super::render_credential("Basic {basic:x-access-token}", "tok"), "Basic eC1hY2Nlc3MtdG9rZW46dG9r");
    }
}
