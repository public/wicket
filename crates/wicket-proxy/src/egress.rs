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
use crate::{full, problem, BoxBody, Event, RunCtx, STRIP_REQUEST, STRIP_RESPONSE};
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

const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

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
}

/// How upstream connections are made. The default (public DNS and the public roots) is what runs
/// use; tests point hosts at local origins with their own CA.
#[derive(Clone, Default)]
pub struct Upstream {
    /// Host -> address, instead of DNS.
    pub resolve: std::collections::HashMap<String, std::net::SocketAddr>,
    /// Extra trusted roots (PEM), besides the public ones.
    pub roots_pem: Option<String>,
    /// Re-originate requests that arrived over HTTP/3 over HTTP/3 too, when the upstream offers it
    /// (default on; HTTP/2 or HTTP/1.1 otherwise).
    pub no_h3: bool,
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
    pub body: Bytes,
    /// What must never be reflected back into the box (injected secrets and their rendering).
    pub injected: Vec<String>,
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
            .connect_timeout(std::time::Duration::from_secs(15));
        for (host, addr) in &upstream.resolve {
            b = b.resolve(host, *addr);
        }
        if let Some(pem) = &upstream.roots_pem {
            for c in reqwest::Certificate::from_pem_bundle(pem.as_bytes())? {
                b = b.add_root_certificate(c);
            }
        }
        let client = b.build()?;
        Ok(Arc::new(Egress { ctx, ca, decider, relay, client, upstream, h3_up: Default::default(), strikes: Default::default() }))
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
            let host = auth.host().trim_end_matches('.').to_ascii_lowercase();
            let port = auth.port_u16().unwrap_or(443);
            if port != 443 {
                return Ok(self.refuse(&host, "CONNECT", "/", &format!("only port 443 is proxied (asked for {port})")));
            }
            if host.parse::<std::net::IpAddr>().is_ok() {
                return Ok(self.refuse(&host, "CONNECT", "/", "IP literals are not proxied; use a hostname"));
            }
            if let Some(r) = self.judge_host(&host, "CONNECT") {
                return Ok(r);
            }
            if let Some(relay) = &self.relay {
                if let Route::Forward(why) = relay.route(&host) {
                    return Ok(self.clone().forward_connect(req, host, why).await);
                }
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
        let host = req.uri().host().map(|h| h.to_ascii_lowercase());
        match host {
            Some(h) if req.uri().scheme_str() == Some("http") => {
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

    async fn tunnel(self: Arc<Self>, upgraded: hyper::upgrade::Upgraded, host: String) -> Result<()> {
        let cfg = self.ca.server_config(&host)?;
        let tls = tokio_rustls::TlsAcceptor::from(cfg).accept(TokioIo::new(upgraded)).await?;
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
        // Authority pinning: a Host header that disagrees with the tunnel target is an attack.
        if let Some(h) = req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()) {
            let h = h.split(':').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
            if !h.is_empty() && h != host {
                return self.refuse(&host, &method, "/", &format!("Host header {h:?} does not match the tunnel target"));
            }
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
            Outcome::Allow(detail) => emit("allow", detail),
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
        match self.forward(req, &host, scheme, &pq, via).await {
            Ok(r) => r,
            Err(e) => problem(502, "upstream", "Upstream error", &e.to_string(), None),
        }
    }

    async fn forward<B>(&self, req: Request<B>, host: &str, scheme: &str, pq: &str, via: Via) -> Result<Response<BoxBody>>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let out = self.prepare(req, host, scheme, pq).await?;
        if via == Via::H3 && scheme == "https" && !self.upstream.no_h3 {
            if let Some(up) = self.h3_up().await {
                if let Some(r) = up.try_send(host, &out).await {
                    return r.map(|r| self.clean(r, &out.injected));
                }
            }
        }
        let mut rb = self.client.request(out.method.clone(), &out.url).headers(out.headers.clone());
        rb = rb.body(out.body.clone());
        let resp = rb.send().await?;
        let mut head = Response::builder().status(StatusCode::from_u16(resp.status().as_u16())?);
        for (name, value) in resp.headers().iter() {
            head = head.header(name, value);
        }
        let stream = resp.bytes_stream().map_ok(Frame::data).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        Ok(self.clean(head.body(BodyExt::boxed(StreamBody::new(stream)))?, &out.injected))
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

    /// Drops hop-by-hop and stripped response headers, and any that would reflect an injected
    /// credential back into the box.
    fn clean(&self, resp: Response<BoxBody>, injected: &[String]) -> Response<BoxBody> {
        let (mut parts, body) = resp.into_parts();
        let names: Vec<http::HeaderName> = parts.headers.keys().cloned().collect();
        for name in names {
            if STRIP_RESPONSE.contains(&name.as_str()) {
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

    /// Reads the body (bounded), strips the box's credentials and headers, and injects the zone's.
    async fn prepare<B>(&self, req: Request<B>, host: &str, scheme: &str, pq: &str) -> Result<Outgoing>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (parts, body) = req.into_parts();
        // What the box put in Authorization: only ever a placeholder, to be swapped (below) or dropped.
        let box_auth = parts.headers.get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);
        let body = Limited::new(body, MAX_REQUEST_BODY).collect().await.map_err(|e| anyhow::anyhow!("request body: {e}"))?.to_bytes();
        let url = format!("{scheme}://{host}{pq}");
        let mut headers = http::HeaderMap::new();
        for (name, value) in parts.headers.iter() {
            if !STRIP_REQUEST.contains(&name.as_str()) {
                headers.append(name.clone(), value.clone());
            }
        }
        // Inject the zone's credential for this host into its one declared slot. An optional rule
        // whose secret isn't set sends the request without it (e.g. anonymous reads).
        let mut injected: Vec<String> = Vec::new();
        for rule in &self.ctx.zone.inject {
            if host_matches(&rule.host, host) {
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
                            crate::SwapSource::Vault(name) => self.ctx.vault.get(name)?,
                            crate::SwapSource::Value(v) => v.clone(),
                        };
                        headers.insert(http::header::AUTHORIZATION, http::HeaderValue::from_str(&format!("Bearer {real}"))?);
                        injected.push(real);
                        tracing::debug!(host, swap = %sw.name, "credential swapped");
                    }
                    None => tracing::debug!(host, "box-supplied authorization dropped (not a known placeholder)"),
                }
            }
        }
        Ok(Outgoing { method: parts.method, url, headers, body, injected })
    }
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

    #[test]
    fn credential_formats() {
        assert_eq!(super::render_credential("Bearer {secret}", "tok"), "Bearer tok");
        // base64("x-access-token:tok")
        assert_eq!(super::render_credential("Basic {basic:x-access-token}", "tok"), "Basic eC1hY2Nlc3MtdG9rZW46dG9r");
    }
}
