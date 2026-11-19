//! The egress proxy (design §9.1): CONNECT, terminate TLS with the run's CA, canonicalize-or-reject,
//! decide, then forward with client credentials stripped and the zone's credential injected into
//! its one declared header slot.
//!
//! It runs on the box's node (`wicket node serve`, #57) with the node's [`Decider`] (its feed
//! replica), the node's name-constrained CA as its [`Minter`], and a [`Router`] that says which
//! hosts that CA covers. A host it doesn't cover (see [`crate::decide::route`]) is spliced through
//! if the box's token allows it wholesale, and refused otherwise: since #257's slice 3 nothing is
//! forwarded to the control host, which decides no request.

use crate::ca::Minter;
use crate::decide::{Decider, Outcome, Route};
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
use wicket_core::{canonical_path, manifest::host_matches};

mod canary;
mod connect;
mod hosts;
mod outgoing;

pub(crate) use canary::tripped_response;
use outgoing::refused_shape;
pub use outgoing::render_credential;

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
    pub(crate) router: Option<Arc<dyn Router>>,
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
    /// Optional injections skipped for want of their secret, each noted once (#175).
    skipped: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Registered domains checked for existence this run, and what was found (#19): each is asked
    /// about once, and at most [`MAX_DOMAIN_CHECKS`] are.
    registered: std::sync::Mutex<std::collections::HashMap<String, crate::exists::Exists>>,
    /// Per wildcard reach rule, the names under it that have had an allowed request this run (#20).
    wild: std::sync::Mutex<std::collections::HashMap<String, std::collections::HashSet<String>>>,
}

/// How many distinct registered domains one run may have checked (#19); past that, unnamed hosts
/// escalate unchecked, as they did before the check existed, so the check can't be used as a channel
/// of its own.
pub(crate) const MAX_DOMAIN_CHECKS: usize = 256;

/// How long a model call the node can't decide yet is held before it is answered (#352), and how
/// often it is decided again meanwhile.
pub(crate) const MODEL_CALL_HOLD: std::time::Duration = std::time::Duration::from_secs(3);
const MODEL_CALL_HOLD_POLL: std::time::Duration = std::time::Duration::from_millis(100);

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
    /// Registered domain -> whether it exists, instead of asking DNS (tests, #19).
    pub domains: std::collections::HashMap<String, bool>,
}

impl Upstream {
    pub(crate) fn lookup(&self) -> crate::dial::Lookup {
        crate::dial::Lookup { fixed: Arc::new(self.dns.clone()), own: None }
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
    /// Set when a streamed body is cut off by the tripwire (#362): what it held.
    pub tripped: Arc<std::sync::OnceLock<String>>,
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

/// Which hosts a node's proxy can terminate (its CA's name constraints and lifetime).
pub trait Router: Send + Sync {
    /// Whether the node terminates this host, or can only splice it (or refuse it).
    fn route(&self, host: &str) -> Route;
}

impl Egress {
    /// An egress proxy with its own decision source, CA and (on a node) router: which hosts that CA
    /// covers. Without one, the CA covers every host.
    pub fn with(ctx: RunCtx, ca: Arc<dyn Minter>, decider: Arc<dyn Decider>, router: Option<Arc<dyn Router>>) -> Result<Arc<Egress>> {
        Egress::with_upstream(ctx, ca, decider, router, Upstream::default())
    }

    /// As [`Egress::with`], with upstream connections made as `upstream` says.
    pub fn with_upstream(
        ctx: RunCtx,
        ca: Arc<dyn Minter>,
        decider: Arc<dyn Decider>,
        router: Option<Arc<dyn Router>>,
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
            // CPU on both ends (docs/explanation/performance.md).
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
            router,
            client,
            upstream,
            h3_up: Default::default(),
            strikes: Default::default(),
            model_gate: Default::default(),
            skipped: Default::default(),
            registered: Default::default(),
            wild: Default::default(),
        }))
    }

    /// Model calls to the model host that come through this proxy (a wrapped harness session's)
    /// go through `llm`'s budget, body filter and accounting (#112).
    pub fn set_model_gate(&self, llm: Arc<crate::llm::Llm>) {
        let _ = self.model_gate.set(llm);
    }

    /// Serves CONNECT (and plain absolute-form HTTP) on a unix socket until the task is dropped.
    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        let listener = crate::sockpath::listen(socket)?;
        self.serve_on(listener).await
    }

    /// As [`Self::serve`], on a socket already listening ([`crate::sockpath::listen`]): its
    /// caller knows it is ready the moment it is bound, with no wait for it to appear (#287).
    pub async fn serve_on(self: Arc<Self>, listener: tokio::net::UnixListener) -> Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            tokio::spawn(self.clone().serve_io(stream, hyper::server::conn::http1::Builder::new()));
        }
    }

    /// Serves one connection from the box (CONNECT, or plain absolute-form HTTP) on any byte stream,
    /// with `http1`'s settings, until it ends: what [`Self::serve_on`] does with each connection it
    /// accepts. Public for the fuzz targets (#323), which feed it raw bytes.
    #[doc(hidden)]
    pub async fn serve_io<S>(self: Arc<Self>, io: S, http1: hyper::server::conn::http1::Builder)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let svc = service_fn(move |req| self.clone().outer(req));
        let _ = http1.serve_connection(TokioIo::new(io), svc).with_upgrades().await;
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
            if let Some(r) = self.judge_unlisted(&host, "CONNECT").await {
                return Ok(r);
            }
            // A host the node's CA can't cover is spliced if its token allows it wholesale (nothing is
            // terminated then), and refused otherwise (#257: never forwarded).
            if let Some(rule) = self.splice_rule(&host) {
                return Ok(self.clone().splice_connect(req, host, rule).await);
            }
            if let Some(Route::Uncovered(why)) = self.router.as_ref().map(|r| r.route(&host)) {
                return Ok(self.refuse_uncovered(&host, &why));
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
                if let Some(r) = self.judge_unlisted(&h, req.method().as_str()).await {
                    return Ok(r);
                }
                // Plain HTTP needs no certificate: the node decides it whatever its CA covers.
                let me = self.clone();
                Ok(me.handle(req, h, "http", Via::Tcp).await)
            }
            _ => Ok(problem(400, "bad-request", "Not a proxy request", "use CONNECT or an absolute http:// URL", None)),
        }
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
        // Authority pinning: a Host header that disagrees with the tunnel target is an attack, and
        // so is a second one (RFC 9112 §3.2: a server answers 400), which a server behind could read
        // instead of the first.
        if req.headers().get_all(http::header::HOST).iter().count() > 1 {
            return self.refuse(&host, &method, "/", "more than one Host header");
        }
        // An absolute-form URL names its own authority (RFC 9112 §3.2.2: it wins over Host): inside
        // a tunnel it must be the tunnel's target, on its port, or the request names another host
        // than the one decided (#361).
        if let Some(a) = req.uri().authority().filter(|_| via != Via::H3) {
            let named = a.host().trim_end_matches('.').to_ascii_lowercase();
            let default = if scheme == "https" { 443 } else { 80 };
            if named != host || a.port_u16().is_some_and(|p| p != default) || req.uri().scheme_str().is_some_and(|s| s != scheme) {
                return self.refuse(&host, &method, "/", &format!("the request's URL names {a}, not the tunnel target {host}"));
            }
        }
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
        // Both requests of a git push are decided as the push of its repository: one request, one
        // approval (#26).
        let op = wicket_core::git::op_for(&ctx.tenant, &ctx.run, &ctx.zone.name, &method, &host, &path, query);
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
        // An unnamed host whose domain doesn't exist is unknown, not a pending request (#19). Over TCP
        // this was answered at CONNECT; HTTP/3 requests are first seen here. Cached per run.
        if let Some(r) = self.judge_unlisted(&host, &method).await {
            return r;
        }
        // Who in the box is asking (reported by the agent's own event stream, not proven).
        let who = ctx.attribute.as_ref().and_then(|f| f(&host, &path));
        let mut outcome = self.decider.decide(ctx, &op, who.as_ref()).await;
        // A model call the node can't decide yet (catching up with its feed, which takes
        // milliseconds, or a brief cut) is held a short, bounded while before it is answered (#352).
        if matches!(outcome, Outcome::Unavailable(_)) && self.model_gate.get().is_some_and(|l| l.is_model_call(&host, &path)) {
            let until = tokio::time::Instant::now() + MODEL_CALL_HOLD;
            while matches!(outcome, Outcome::Unavailable(_)) && tokio::time::Instant::now() < until {
                tokio::time::sleep(MODEL_CALL_HOLD_POLL).await;
                outcome = self.decider.decide(ctx, &op, who.as_ref()).await;
            }
        }
        match outcome {
            Outcome::Allow(detail) => {
                // A name under a wildcard counts against the rule's limit before it is resolved (#20).
                if let Some((w, why)) = self.admit_wildcard(&host) {
                    emit("forbidden", why.clone());
                    let note = self.strike(&format!("wildcard {w}"));
                    return problem(403, "forbidden", "Blocked by wicket box: never allowed", &format!(
                        "{why}. No more new names under {w} are reached in this run, and no approval can change that; the names already reached keep working. {} Do not retry it; tell the user if you need it.{note}",
                        crate::BOX_FACT
                    ), None);
                }
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
                        "Blocked by wicket box: the audit log is unavailable",
                        &format!(
                            "wicket could not record this request in its audit log, so it was not sent; retry later. {}",
                            crate::BOX_FACT
                        ),
                        None,
                    );
                }
            }
            Outcome::Forbidden(why) => {
                emit("forbidden", why.clone());
                let note = self.strike(&op.digest());
                return problem(403, "forbidden", "Blocked by wicket box: never allowed", &format!(
                    "{why}. This will never be allowed from this box, and no approval can change that. {} Do not retry it; tell the user it is blocked.{note}",
                    crate::BOX_FACT
                ), None);
            }
            Outcome::NoEscalation(why) => {
                emit("forbidden", format!("{why}; this run does not escalate (escalation.request: false)"));
                return problem(
                    403,
                    "forbidden",
                    "Blocked by wicket box: never allowed",
                    &format!(
                        "{why}. This box may not ask for anything outside its reach (its zone's escalation.request is false), so this will never be allowed from here. {} Do not retry it; tell the user it is blocked.",
                        crate::BOX_FACT
                    ),
                    None,
                );
            }
            Outcome::Denied { request: rid } => {
                emit("denied", format!("request {rid} was denied"));
                let note = self.strike(&op.digest());
                return problem(
                    403,
                    "denied",
                    "Blocked by wicket box: denied",
                    &format!(
                    "Request {rid} for exactly this request was denied. {} Do not retry it; continue without it and tell the user.{note}",
                    crate::BOX_FACT
                ),
                    None,
                );
            }
            Outcome::Pending { request: rid, fresh, why } => {
                let for_line = who.as_ref().map(|(_, l)| format!("; for {l}")).unwrap_or_default();
                emit("pending", format!("{rid}{}: {why}{for_line}", if fresh { " (new)" } else { "" }));
                let note = self.strike(&op.digest());
                return problem(403, "pending-approval", "Blocked by wicket box: needs approval", &format!(
                    "{why}. wicket has asked for request {rid} to be approved (an operator decides it, or an agent above you may); until it is, this request fails every time. {} Call await_grant with {rid} to wait, or tell the user that request {rid} is waiting for their approval in wicket (approvals happen in wicket, not in this conversation).{note}",
                    crate::BOX_FACT
                ), Some(&rid));
            }
            Outcome::Queued { id, why } => {
                let for_line = who.as_ref().map(|(_, l)| format!("; for {l}")).unwrap_or_default();
                emit("queued", format!("{id}: {why}{for_line}"));
                let note = self.strike(&op.digest());
                return problem(403, "queued", "Blocked by wicket box: needs approval (queued offline)", &format!(
                    "{why}. wicket's control host is unreachable from this node, so this ask is queued here as {id} and will be put to an operator when it is back; nothing new can be approved until then. {} Continue without it for now, or retry later.{note}",
                    crate::BOX_FACT
                ), None);
            }
            Outcome::Unavailable(why) => {
                emit("unavailable", why.clone());
                return crate::unavailable(&format!("{why}. {}", crate::BOX_FACT));
            }
            Outcome::Error(e) => return problem(500, "error", "Ledger error", &e, None),
        }
        if let Some(llm) = self.model_gate.get().filter(|l| l.is_model_call(&host, &path)) {
            return llm.clone().through_egress(&self, req, &host, &pq, via).await;
        }
        match self.forward(req, &host, scheme, &pq, via).await {
            Ok(r) => r,
            // The tripwire (#362) refuses; otherwise the whole chain: a refused dial (#116) says why at its end.
            Err(e) => canary::tripped_response(&e).unwrap_or_else(|| problem(502, "upstream", "Upstream error", &format!("{e:#}"), None)),
        }
    }
}

#[cfg(test)]
mod tests {
    /// A run context for a zone, with a vault where `gh` may go only to api.github.com.
    fn ctx(zone: &str, swaps: Vec<crate::CredentialSwap>, tag: &str) -> (crate::RunCtx, std::path::PathBuf) {
        use std::sync::{Arc, Mutex};
        let dir = std::env::temp_dir().join(format!("wicket-egress-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = crate::vault::Vault::new(dir.join("vault"));
        vault.set("gh", "the-real-token").unwrap();
        vault.set_hosts("gh", &["api.github.com".into()]).unwrap();
        let mut m =
            wicket_core::Manifest::from_yaml(&format!("task: t\nagent: {{name: a}}\nzone: {{name: z, llm: {{secret: m}}, {zone}}}"))
                .unwrap();
        crate::provider::fill_test_route(&mut m);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let c = crate::RunCtx {
            tenant: wicket_core::TenantId::single(),
            run: wicket_core::RunId("run_x".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(m.zone.clone()).unwrap()),
            org: None,
            ledger: Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().unwrap())),
            vault,
            events: tx,
            escalate: true,
            attribute: None,
            identity: None,
            swaps,
            boxes: None,
            capacity: None,
            decisions: None,
            fence: None,
            waker: None,
            lifecycle: None,
        };
        (c, dir)
    }

    async fn prepare(c: crate::RunCtx, host: &str, auth: Option<&str>) -> anyhow::Result<super::Outgoing> {
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::with(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None).unwrap();
        let mut b = http::Request::get("/x").header("host", host);
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        e.prepare(b.body(http_body_util::Full::new(bytes::Bytes::new())).unwrap(), host, "https", "/x", true).await
    }

    fn egress(c: crate::RunCtx) -> std::sync::Arc<super::Egress> {
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        super::Egress::with(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None).unwrap()
    }

    /// The same blocked request a third time is told to stop; a run blocked ten times is told to
    /// ask, and its operator hears the agent may be stuck at ten and every ten after (#130).
    #[tokio::test]
    async fn repeated_blocks_are_counted_and_said() {
        let (mut c, _) = ctx("reach: []", vec![], "strike");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        c.events = tx;
        let e = egress(c);
        assert_eq!(e.strike("a"), "");
        assert_eq!(e.strike("a"), "");
        assert!(e.strike("a").contains("blocked 3 times"), "the same request, a third time");
        for i in 4..10 {
            let note = e.strike(&format!("other {i}"));
            assert!(!note.contains("blocked") && !note.contains("hit the box's limits"), "{i}: {note}");
        }
        let stuck = |rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::Event>| {
            let mut n = vec![];
            while let Ok(ev) = rx.try_recv() {
                if let crate::Event::Tool { detail, .. } = ev {
                    n.push(detail);
                }
            }
            n
        };
        assert!(stuck(&mut rx).is_empty(), "not before ten");
        assert!(e.strike("tenth").contains("hit the box's limits 10 times"));
        assert_eq!(stuck(&mut rx), ["agent may be stuck: 10 blocked requests in this run"]);
        for i in 11..20 {
            e.strike(&format!("more {i}"));
        }
        assert!(stuck(&mut rx).is_empty(), "nothing between ten and twenty");
        e.strike("twentieth");
        assert_eq!(stuck(&mut rx), ["agent may be stuck: 20 blocked requests in this run"]);
    }

    /// A host is judged before any request to it: never-reachable ones are refused as such, ones a
    /// hiding zone doesn't name look as if they don't exist, and the rest go on to be decided.
    #[tokio::test]
    async fn a_host_is_judged_before_any_request_to_it() {
        use http_body_util::BodyExt;
        let body = |r: http::Response<super::BoxBody>| async move {
            String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
        };
        let (c, _) = ctx("reach: [{host: api.example.com}]", vec![], "judge");
        let e = egress(c);
        let r = e.judge_host("169.254.169.254", "GET").expect("refused");
        assert_eq!(r.status(), 403);
        assert!(body(r).await.contains("no approval can change that"));
        assert!(e.judge_host("api.example.com", "GET").is_none(), "a reachable host goes on");
        let (c, _) = ctx("unlisted_hosts: hide, reach: [{host: api.example.com}]", vec![], "judge-hide");
        let e = egress(c);
        let r = e.judge_host("news.example.org", "GET").expect("hidden");
        assert_eq!(r.status(), 502);
        assert!(body(r).await.contains("does not exist as far as this box is concerned"));
        assert!(e.judge_host("api.example.com", "GET").is_none());
    }

    /// A streamed request body's declared length may be the limit, not more.
    #[tokio::test]
    async fn a_streamed_body_may_be_the_limit_and_no_more() {
        let (c, _) = ctx("reach: [{host: api.example.com, methods: [PUT]}]", vec![], "limit");
        let e = egress(c);
        let put = |n: u64| {
            http::Request::put("/x")
                .header("host", "api.example.com")
                .header("content-length", n.to_string())
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .unwrap()
        };
        assert!(e.prepare(put(super::MAX_STREAMED_BODY), "api.example.com", "https", "/x", true).await.is_ok());
        let err = e.prepare(put(super::MAX_STREAMED_BODY + 1), "api.example.com", "https", "/x", true).await.err().expect("refused");
        assert!(err.to_string().contains("request body (the limit is"), "{err}");
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

    /// #175: an optional injection whose secret isn't in the vault is as if it weren't there: the
    /// request goes without the header (and without the box's own), not a 502, and the skip is noted
    /// in the audit log once, not per request. A required one still fails.
    #[tokio::test]
    async fn an_optional_injection_with_no_secret_sends_the_request_without_it() {
        let inject = |optional: bool| {
            format!("reach: [{{host: api.github.com, methods: [GET]}}], inject: [{{host: api.github.com, header: Authorization, format: 'Bearer {{secret}}', secret: github-wicket, optional: {optional}}}]")
        };
        let (c, dir) = ctx(&inject(true), vec![], "optional-unset");
        let ledger = c.ledger.clone();
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::with(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None).unwrap();
        assert!(!e.credentials_for("api.github.com"), "no credential goes to the host");
        for auth in [None, Some("Bearer the-box-own")] {
            let mut b = http::Request::get("/x").header("host", "api.github.com");
            if let Some(a) = auth {
                b = b.header("authorization", a);
            }
            let req = b.body(http_body_util::Full::new(bytes::Bytes::new())).unwrap();
            let out = e.prepare(req, "api.github.com", "https", "/x", true).await.expect("goes through");
            assert!(out.headers.get("authorization").is_none(), "{:?}", out.headers);
            assert!(out.injected.is_empty());
        }
        let notes = ledger.lock().unwrap().audit_tail(100).unwrap().into_iter().filter(|r| r.2 == "inject.skipped").count();
        assert_eq!(notes, 1, "one note per run, not per request");
        let (c, _) = ctx(&inject(false), vec![], "required-unset");
        assert!(prepare(c, "api.github.com", None).await.is_err(), "a required injection with no secret still fails");
        for t in ["optional-unset", "required-unset"] {
            let _ = std::fs::remove_dir_all(dir.with_file_name(format!("wicket-egress-{t}-{}", std::process::id())));
        }
    }

    /// #51 with #180: the org policy is checked on an injected host before anything else, so a
    /// credential it refuses is never fetched or sent, required or optional; one it allows goes in.
    #[tokio::test]
    async fn the_org_policy_decides_an_injection_before_the_vault_is_asked() {
        let inject = |optional: bool| {
            format!("reach: [{{host: api.github.com, methods: [GET]}}], inject: [{{host: api.github.com, header: Authorization, format: 'Bearer {{secret}}', secret: gh, optional: {optional}}}]")
        };
        let org = |keys: Vec<String>| {
            Some(std::sync::Arc::new(wicket_authz::OrgLayer {
                version: "v1".into(),
                http: None,
                forbid: vec![],
                spawn: None,
                msg_from: None,
                inject: Some(keys),
            }))
        };
        for optional in [false, true] {
            let (mut c, dir) = ctx(&inject(optional), vec![], "org-refused");
            c.org = org(vec![]);
            let e = prepare(c, "api.github.com", None).await.err().expect("refused").to_string();
            assert!(e.contains("org policy (v1) doesn't allow injecting gh"), "{e}");
            let (mut c, _) = ctx(&inject(optional), vec![], "org-allowed");
            c.org = org(vec!["api.github.com|Authorization|gh".into()]);
            let out = prepare(c, "api.github.com", None).await.unwrap();
            assert_eq!(out.headers.get("authorization").unwrap(), "Bearer the-real-token");
            for t in ["org-refused", "org-allowed"] {
                let _ = std::fs::remove_dir_all(dir.with_file_name(format!("wicket-egress-{t}-{}", std::process::id())));
            }
        }
        // The order: an optional rule whose secret isn't set is still the org's to refuse (it is
        // checked first), not skipped as unset.
        let unset = inject(true).replace("secret: gh", "secret: absent");
        let (mut c, dir) = ctx(&unset, vec![], "org-unset");
        c.org = org(vec![]);
        assert!(prepare(c, "api.github.com", None).await.is_err(), "refused by the org, before the unset skip");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #130: only allow-listed headers go upstream, and requests that could run as something other
    /// than what was decided are refused before the decision.
    #[tokio::test]
    async fn headers_are_forwarded_by_allowlist_and_override_shapes_are_refused() {
        use http_body_util::BodyExt;
        let (c, dir) = ctx("reach: [{host: api.github.com, methods: [GET, POST]}]", vec![], "shape");
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::with(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None).unwrap();
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

    /// #361: what would upgrade, re-route or re-frame a request at the next hop never goes upstream:
    /// WebSocket and h2c upgrades, hop-by-hop headers, proxy headers, and the box's own Host (the
    /// upstream's is wicket's, from the URL).
    #[tokio::test]
    async fn upgrade_hop_by_hop_and_proxy_headers_never_go_upstream() {
        let (c, dir) = ctx("reach: [{host: api.github.com, methods: [GET, POST]}]", vec![], "hops");
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::with(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None).unwrap();
        let mut b = http::Request::post("/x").header("accept", "*/*");
        for (k, v) in [
            ("host", "evil.test"),
            ("connection", "Upgrade, HTTP2-Settings, keep-alive"),
            ("upgrade", "websocket, h2c"),
            ("http2-settings", "AAMAAABkAARAAAAAAAIAAAAA"),
            ("sec-websocket-key", "AAAAAAAAAAAAAAAAAAAAAA=="),
            ("sec-websocket-version", "13"),
            ("sec-websocket-protocol", "chat"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("trailer", "x-smuggled"),
            ("proxy-authorization", "Basic eDp5"),
            ("proxy-connection", "keep-alive"),
            ("x-forwarded-proto", "http"),
            ("x-real-ip", "127.0.0.1"),
            ("via", "1.1 evil"),
            ("expect", "100-continue"),
        ] {
            b = b.header(k, v);
        }
        let out = e
            .prepare(b.body(http_body_util::Full::new(bytes::Bytes::new())).unwrap(), "api.github.com", "https", "/x", true)
            .await
            .unwrap();
        let names: Vec<&str> = out.headers.keys().map(|k| k.as_str()).collect();
        assert_eq!(names, ["accept"], "{names:?}");
        assert_eq!(out.url, "https://api.github.com/x");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #361: a body over the limits is refused before anything goes upstream: one read whole (an
    /// HTTP/3 request's, which may be re-sent over HTTP/2) past [`super::MAX_REQUEST_BODY`], and a
    /// streamed one that declares more than [`super::MAX_STREAMED_BODY`], refused without reading it.
    #[tokio::test]
    async fn oversized_bodies_are_refused_before_they_go_upstream() {
        let (c, dir) = ctx("reach: [{host: api.github.com, methods: [GET, POST]}]", vec![], "big");
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::with(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None).unwrap();
        // Over HTTP/3, in pieces and with no length, as a QUIC stream delivers it.
        let piece = bytes::Bytes::from(vec![b'a'; 1 << 20]);
        let n = super::MAX_REQUEST_BODY / piece.len() + 1;
        let frames =
            futures_util::stream::iter((0..n).map(move |_| Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(piece.clone()))));
        let req = http::Request::post("/upload").body(http_body_util::StreamBody::new(frames)).unwrap();
        let Err(err) = e.forward(req, "api.github.com", "https", "/upload", super::Via::H3).await else {
            panic!("an oversized HTTP/3 body went")
        };
        assert!(format!("{err:#}").contains("length limit exceeded"), "{err:#}");
        // Streamed, declaring more than the limit: refused on the declaration alone.
        let declared = (super::MAX_STREAMED_BODY + 1).to_string();
        let req =
            http::Request::post("/upload").header("content-length", declared).body(http_body_util::Empty::<bytes::Bytes>::new()).unwrap();
        let err = e.prepare(req, "api.github.com", "https", "/upload", true).await.err().expect("refused");
        assert!(format!("{err:#}").contains("request body (the limit is"), "{err:#}");
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
        let e = super::Egress::with(c.clone(), ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None).unwrap();
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
        assert_eq!(llm.count.requests.load(std::sync::atomic::Ordering::SeqCst), 2, "counted as model requests");
        llm.spent_before(u64::MAX / 4, 0, 0);
        let (st, body) = send("/v1/messages", None).await;
        assert_eq!(st, 429, "{body}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A node's copy of a secret that a source serves (the control host's, which reads a linked login
    /// through the secret helper, `wicket secret serve`): `get` returns what the source holds, and
    /// `refetch` asks it again. `next` is what it will hold once `changed` is set (#552).
    struct Served {
        value: std::sync::Mutex<String>,
        next: Option<&'static str>,
        changed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl crate::vault::SecretSource for Served {
        fn get(&self, _: &str) -> anyhow::Result<String> {
            Ok(self.value.lock().unwrap().clone())
        }
        fn hosts(&self, _: &str) -> Vec<String> {
            vec!["api.anthropic.com".into()]
        }
        fn has(&self, _: &str) -> bool {
            true
        }
        fn refetch<'a>(&'a self, _: &'a str) -> futures_util::future::BoxFuture<'a, anyhow::Result<()>> {
            if let (Some(n), true) = (self.next, self.changed.load(std::sync::atomic::Ordering::SeqCst)) {
                *self.value.lock().unwrap() = n.into();
            }
            Box::pin(async { Ok(()) })
        }
    }

    /// A model call through the egress gate whose credential is swapped in from a served secret, to a
    /// stand-in for the model host that accepts only `tok-new`. On its first refusal the source
    /// holds `next` after `delay` (a login refreshed by its owner: the old token revoked first, the
    /// new one written a moment later). Returns the status, the bearers the host saw, and the
    /// call's `llm` op records.
    async fn served_relogin(next: Option<&'static str>, delay: std::time::Duration, tag: &str) -> (u16, Vec<String>, Vec<String>) {
        use http_body_util::BodyExt;
        let origin = crate::ca::RunCa::generate("origin").unwrap();
        let mut cfg = (*origin.server_config("api.anthropic.com").unwrap()).clone();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let changed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen2, changed2) = (seen.clone(), changed.clone());
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let (acceptor, seen, changed) = (acceptor.clone(), seen2.clone(), changed2.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(s).await else { return };
                    let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                        let (seen, changed) = (seen.clone(), changed.clone());
                        async move {
                            let bearer = req
                                .headers()
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .trim_start_matches("Bearer ")
                                .to_string();
                            let _ = req.into_body().collect().await?;
                            seen.lock().unwrap().push(bearer.clone());
                            let r = if bearer == "tok-new" {
                                http::Response::builder().header("content-type", "application/json").body(http_body_util::Full::new(
                                    bytes::Bytes::from_static(br#"{"usage":{"input_tokens":1,"output_tokens":1}}"#),
                                ))
                            } else {
                                tokio::spawn(async move {
                                    tokio::time::sleep(delay).await;
                                    changed.store(true, std::sync::atomic::Ordering::SeqCst);
                                });
                                http::Response::builder().status(401).header("content-type", "application/json").body(
                                    http_body_util::Full::new(bytes::Bytes::from_static(
                                        br#"{"type":"error","error":{"type":"authentication_error","message":"OAuth token revoked"}}"#,
                                    )),
                                )
                            };
                            Ok::<_, hyper::Error>(r.unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), svc).await;
                });
            }
        });
        let swap = crate::CredentialSwap {
            name: "claude-login".into(),
            host: "api.anthropic.com".into(),
            placeholder: "ph-run-x".into(),
            real: crate::SwapSource::Vault("claude-login".into()),
            box_bearers: false,
        };
        let (mut c, dir) = ctx("reach: [{host: api.anthropic.com, methods: [POST]}]", vec![swap], tag);
        let source = Served { value: std::sync::Mutex::new("tok-old".into()), next, changed };
        c.vault = crate::vault::Vault::from_source(std::sync::Arc::new(source));
        let up = super::Upstream {
            resolve: [("api.anthropic.com".to_string(), addr)].into(),
            roots_pem: Some(origin.cert_pem()),
            ..Default::default()
        };
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::with_upstream(c.clone(), ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None, up).unwrap();
        let llm = crate::llm::Llm::new(c.clone()).unwrap();
        e.set_model_gate(llm.clone());
        let body = r#"{"model":"m","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}"#;
        let req = http::Request::post("/v1/messages")
            .header("host", "api.anthropic.com")
            .header("content-type", "application/json")
            .header("authorization", "Bearer ph-run-x")
            .header("content-length", body.len())
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .unwrap();
        let r = e.clone().handle(req, "api.anthropic.com".into(), "https", super::Via::Tcp).await;
        let status = r.status().as_u16();
        let _ = r.into_body().collect().await;
        let mut ops = vec![];
        for _ in 0..300 {
            ops = c
                .ledger
                .lock()
                .unwrap()
                .audit_of_kind("op")
                .unwrap()
                .into_iter()
                .map(|r| r.body)
                .filter(|b| b.contains("\"kind\":\"llm\""))
                .collect::<Vec<_>>();
            if ops.iter().any(|o| o.contains("\"status\":200") || o.contains("not retried")) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let _ = std::fs::remove_dir_all(dir);
        let seen = seen.lock().unwrap().clone();
        (status, seen, ops)
    }

    /// #552: a wrapped session's model call through the egress gate, its credential swapped in from
    /// a served login (as `claude-login` is on a node), races a refresh: the host refuses the old
    /// token, the new one is served 300 ms later. The call waits for it, goes once more, and
    /// succeeds; the box never sees the 401, and the call's note says it was retried.
    #[tokio::test]
    async fn a_model_call_through_egress_that_races_a_login_refresh_is_retried() {
        let (status, seen, ops) = served_relogin(Some("tok-new"), std::time::Duration::from_millis(300), "egress-relogin").await;
        assert_eq!(status, 200, "{ops:?}");
        assert_eq!(seen, ["tok-old", "tok-new"], "one retry, with the new token");
        assert!(ops.iter().any(|o| o.contains("\"status\":200") && o.contains("retried once after a 401")), "{ops:?}");
        assert!(ops.iter().all(|o| !o.contains("tok-")), "no token in the audit: {ops:?}");
    }

    /// #552: the same with a login that doesn't change (a real revocation): the 401 goes to the box,
    /// once, and the call's note says why it wasn't retried (#552's calls had no note at all).
    #[tokio::test]
    async fn a_revoked_login_through_egress_passes_its_401_on_with_a_note() {
        let (status, seen, ops) = served_relogin(None, std::time::Duration::from_millis(10), "egress-revoked").await;
        assert_eq!(status, 401, "{ops:?}");
        assert_eq!(seen, ["tok-old"], "not retried");
        assert!(ops.iter().any(|o| o.contains("\"status\":401") && o.contains("is unchanged: not retried")), "{ops:?}");
    }

    /// #310: a model call through the egress gate is charged its real usage, as one through the model
    /// proxy is. The box asks for a compressed response; the gate asks upstream for identity (an
    /// upstream given the box's `Accept-Encoding` answers gzip here, whose usage can't be read), and
    /// sends the rewritten body with its own length (a field stripped makes it shorter).
    #[tokio::test]
    async fn a_streamed_model_call_through_egress_is_charged_its_real_usage() {
        use http_body_util::BodyExt;
        use std::sync::atomic::Ordering::SeqCst;
        let origin = crate::ca::RunCa::generate("origin").unwrap();
        let mut cfg = (*origin.server_config("api.anthropic.com").unwrap()).clone();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        // What the stand-in got: (Accept-Encoding, body).
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let (acceptor, seen) = (acceptor.clone(), seen2.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(s).await else { return };
                    let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let enc = req.headers().get("accept-encoding").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                            let body = req.into_body().collect().await?.to_bytes();
                            seen.lock().unwrap().push((enc.clone(), String::from_utf8_lossy(&body).into_owned()));
                            let sse = [
                                (
                                    "message_start",
                                    r#"{"type":"message_start","message":{"usage":{"input_tokens":12,"cache_read_input_tokens":5,"output_tokens":1}}}"#,
                                ),
                                ("content_block_delta", r#"{"type":"content_block_delta","delta":{"text":"hi"}}"#),
                                ("message_delta", r#"{"type":"message_delta","usage":{"output_tokens":42}}"#),
                                ("message_stop", r#"{"type":"message_stop"}"#),
                            ];
                            let mut r = http::Response::builder().header("content-type", "text/event-stream");
                            let frames: Vec<bytes::Bytes> = if enc == "identity" {
                                sse.iter().map(|(e, d)| bytes::Bytes::from(format!("event: {e}\ndata: {d}\n\n"))).collect()
                            } else {
                                r = r.header("content-encoding", "gzip");
                                vec![bytes::Bytes::from_static(b"\x1f\x8b\x08\x00compressed")]
                            };
                            let stream =
                                futures_util::stream::iter(frames.into_iter().map(|b| Ok::<_, hyper::Error>(hyper::body::Frame::data(b))));
                            Ok::<_, hyper::Error>(r.body(http_body_util::StreamBody::new(stream)).unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), svc).await;
                });
            }
        });
        let (c, dir) = ctx("reach: [{host: api.anthropic.com, methods: [POST]}]", vec![], "model-usage");
        let up = super::Upstream {
            resolve: [("api.anthropic.com".to_string(), addr)].into(),
            roots_pem: Some(origin.cert_pem()),
            ..Default::default()
        };
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::with_upstream(c.clone(), ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None, up).unwrap();
        let llm = crate::llm::Llm::new(c).unwrap();
        e.set_model_gate(llm.clone());
        let body =
            r#"{"model":"m","max_tokens":300,"stream":true,"messages":[{"role":"user","content":"hi"}],"some_future_field":{"x":1}}"#;
        let req = http::Request::post("/v1/messages")
            .header("host", "api.anthropic.com")
            .header("content-type", "application/json")
            .header("accept-encoding", "gzip, deflate, br")
            .header("content-length", body.len())
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .unwrap();
        let r = e.clone().handle(req, "api.anthropic.com".into(), "https", super::Via::Tcp).await;
        assert_eq!(r.status(), 200);
        let got = String::from_utf8_lossy(&r.into_body().collect().await.unwrap().to_bytes()).into_owned();
        assert!(got.contains("message_stop"), "{got}");
        let (enc, sent) = seen.lock().unwrap()[0].clone();
        assert_eq!(enc, "identity");
        assert!(!sent.contains("some_future_field") && sent.contains("\"max_tokens\":300"), "{sent}");
        for _ in 0..300 {
            if llm.count.inflight_output_tokens.load(SeqCst) == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(llm.count.inflight_output_tokens.load(SeqCst), 0, "settled");
        assert_eq!(llm.count.output_tokens.load(SeqCst), 42, "charged its real output, not the 300 reserved");
        assert_eq!((llm.count.input_tokens.load(SeqCst), llm.count.cache_read_tokens.load(SeqCst)), (12, 5));
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
            let e = super::Egress::with(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None).unwrap();
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
        let e = super::Egress::with_upstream(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None, up).unwrap();
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

    /// Sends one GET to `host` through `e` (as a request inside a CONNECT tunnel), and returns the
    /// status and body.
    async fn get(e: &std::sync::Arc<super::Egress>, host: &str) -> (u16, String) {
        use http_body_util::BodyExt;
        let req = http::Request::get("/x").header("host", host).body(http_body_util::Full::new(bytes::Bytes::new())).unwrap();
        let resp = e.clone().handle(req, host.into(), "https", super::Via::Tcp).await;
        let status = resp.status().as_u16();
        (status, String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned())
    }

    /// #19: in an escalate zone, a host no rule names whose registered domain doesn't exist is an
    /// unknown host, with no pending request, and only the registered domain is looked up, never the
    /// name the agent chose. One whose domain exists still escalates. Named hosts aren't checked.
    #[tokio::test]
    async fn an_unregistered_domain_is_an_unknown_host_and_only_it_is_looked_up() {
        let (c, dir) = ctx("reach: [{host: api.github.com, methods: [GET]}]", vec![], "nxdomain");
        let ledger = c.ledger.clone();
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let mut up = super::Upstream::default();
        up.domains.insert("no-such-domain-wkt.com".into(), false);
        up.domains.insert("example.co.uk".into(), true);
        let e = super::Egress::with_upstream(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None, up).unwrap();

        let (st, body) = get(&e, "c2vjcmv0.payload.no-such-domain-wkt.com").await;
        assert_eq!(st, 502, "{body}");
        assert!(body.contains("unknown host") && body.contains("there is no domain no-such-domain-wkt.com"), "{body}");
        // Over CONNECT, it's answered before TLS.
        let r = e.judge_unlisted("other.no-such-domain-wkt.com", "CONNECT").await.expect("refused at CONNECT");
        assert_eq!(r.status(), 502);
        assert_eq!(e.domains_checked(), ["no-such-domain-wkt.com"], "never the agent's subdomain");
        assert!(ledger.lock().unwrap().pending(&wicket_core::TenantId::single()).unwrap().is_empty(), "nothing for a human");

        let (st, body) = get(&e, "anything.example.co.uk").await;
        assert_eq!(st, 403, "{body}");
        assert!(body.contains("needs approval"), "{body}");
        assert_eq!(e.domains_checked(), ["example.co.uk", "no-such-domain-wkt.com"]);

        // A host the zone names is never checked, and a run that doesn't escalate checks nothing.
        assert!(e.judge_unlisted("api.github.com", "CONNECT").await.is_none());
        assert_eq!(e.domains_checked().len(), 2);
        let (mut c, _) = ctx("reach: []", vec![], "nxdomain-noesc");
        c.escalate = false;
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::with(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None).unwrap();
        assert!(e.judge_unlisted("a.no-such-domain-wkt.com", "CONNECT").await.is_none());
        assert!(e.domains_checked().is_empty());
        for t in ["nxdomain", "nxdomain-noesc"] {
            let _ = std::fs::remove_dir_all(dir.with_file_name(format!("wicket-egress-{t}-{}", std::process::id())));
        }
    }

    /// #20: a name under a wildcard reach rule is not dialled (so not resolved) before a request to it
    /// has been allowed: its CONNECT is inspected, not spliced, until then; spliced after.
    #[tokio::test]
    async fn a_wildcard_name_is_not_resolved_before_an_allowed_request() {
        let all = "methods: [GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE]";
        let (c, dir) = ctx(&format!("reach: [{{host: '*.cdn.example', {all}}}, {{host: exact.example, {all}}}]"), vec![], "wild-first");
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let mut up = super::Upstream::default();
        // Loopback answers: a dial is refused (and says so) instead of reaching anything.
        up.dns.insert("a.cdn.example".into(), vec!["127.0.0.1".parse().unwrap()]);
        let e = super::Egress::with_upstream(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None, up).unwrap();
        assert!(e.splice_rule("exact.example").is_some(), "an exact host splices from the first connection");
        assert!(e.splice_rule("a.cdn.example").is_none(), "inspected until a request is allowed");
        assert!(!e.wildcard_reached("a.cdn.example"));
        // The first request is decided, allowed, and only then resolved (here: refused at dial).
        let (st, body) = get(&e, "a.cdn.example").await;
        assert_eq!(st, 502, "{body}");
        assert!(body.contains("non-public address"), "resolved after the allow: {body}");
        assert!(e.wildcard_reached("a.cdn.example"));
        assert_eq!(e.splice_rule("a.cdn.example"), Some(0), "spliced from now on");
        assert!(e.splice_rule("b.cdn.example").is_none(), "per name, not per rule");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #20: each wildcard rule reaches at most `wildcards.max_names` distinct names per run. A new name
    /// past it is refused before it is resolved; names already reached, and exact hosts, still work.
    #[tokio::test]
    async fn distinct_names_per_wildcard_are_limited_per_run() {
        let zone = "wildcards: {max_names: 2}, reach: [{host: '*.cdn.example', methods: [GET]}, {host: '*.other.example', methods: [GET]}, {host: x.cdn.example, methods: [GET]}]";
        let (c, dir) = ctx(zone, vec![], "wild-limit");
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let mut up = super::Upstream::default();
        for h in ["a.cdn.example", "b.cdn.example", "c.cdn.example", "x.cdn.example", "a.other.example"] {
            up.dns.insert(h.into(), vec!["127.0.0.1".parse().unwrap()]);
        }
        let e = super::Egress::with_upstream(c, ca, std::sync::Arc::new(crate::zone_decider::ZoneDecider), None, up).unwrap();
        let resolved = |(st, body): (u16, String)| st == 502 && body.contains("non-public address");
        assert!(resolved(get(&e, "a.cdn.example").await));
        assert!(resolved(get(&e, "b.cdn.example").await));
        let (st, body) = get(&e, "c.cdn.example").await;
        assert_eq!(st, 403, "{body}");
        assert!(
            body.contains("never allowed") && body.contains("wildcards.max_names") && body.contains("2 distinct names under *.cdn.example"),
            "{body}"
        );
        assert!(resolved(get(&e, "a.cdn.example").await), "a name already reached keeps working");
        assert!(resolved(get(&e, "x.cdn.example").await), "an exact host isn't counted");
        assert!(resolved(get(&e, "a.other.example").await), "the limit is per wildcard");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn credential_formats() {
        assert_eq!(super::render_credential("Bearer {secret}", "tok"), "Bearer tok");
        // base64("x-access-token:tok")
        assert_eq!(super::render_credential("Basic {basic:x-access-token}", "tok"), "Basic eC1hY2Nlc3MtdG9rZW46dG9r");
    }

    /// A decider that answers from a script, then its last line for ever, counting the calls.
    struct Scripted {
        script: std::sync::Mutex<std::collections::VecDeque<crate::decide::Outcome>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Scripted {
        fn new(script: Vec<crate::decide::Outcome>) -> std::sync::Arc<Scripted> {
            std::sync::Arc::new(Scripted { script: std::sync::Mutex::new(script.into()), calls: Default::default() })
        }
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl crate::decide::Decider for Scripted {
        fn host_verdict(&self, _: &crate::RunCtx, _: &str) -> wicket_core::HostVerdict {
            wicket_core::HostVerdict::Open
        }
        fn decide<'a>(
            &'a self,
            _: &'a crate::RunCtx,
            _: &'a wicket_core::Op,
            _: Option<&'a (serde_json::Value, String)>,
        ) -> futures_util::future::BoxFuture<'a, crate::decide::Outcome> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut s = self.script.lock().unwrap();
            let o = if s.len() > 1 { s.pop_front().unwrap() } else { s.front().cloned().unwrap() };
            Box::pin(async move { o })
        }
    }

    fn catching_up() -> crate::decide::Outcome {
        crate::decide::Outcome::Unavailable(crate::decide::stale_text(wicket_feed::Mode::Lagging, "catching up with the feed"))
    }

    /// #352: a node catching up with its feed answers egress and model calls with 503 and
    /// Retry-After, which clients retry (a 403 ends a harness's turn); a model call is held a short
    /// while first, and answered as soon as the node can decide. A real refusal is still a 403, and
    /// the egress log says what it said before.
    #[tokio::test]
    async fn a_node_catching_up_answers_retryably_and_a_refusal_is_still_403() {
        use http_body_util::BodyExt;
        let reach = "reach: [{host: api.anthropic.com, methods: [GET, POST]}, {host: files.example, methods: [GET]}]";
        let (mut c, dir) = ctx(reach, vec![], "catch-up");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        c.events = tx;
        let send = |d: std::sync::Arc<Scripted>, model: bool| {
            let c = c.clone();
            async move {
                let ca = std::sync::Arc::new(crate::ca::RunCa::generate("node").unwrap());
                let e = super::Egress::with(c.clone(), ca, d, None).unwrap();
                e.set_model_gate(crate::llm::Llm::new(c).unwrap());
                let (req, host) = if model {
                    let body = bytes::Bytes::from_static(br#"{"model":"m","max_tokens":5,"messages":[]}"#);
                    let req = http::Request::post("/v1/messages").header("content-type", "application/json");
                    (req.body(http_body_util::Full::new(body)).unwrap(), "api.anthropic.com")
                } else {
                    (http::Request::get("/x").body(http_body_util::Full::new(bytes::Bytes::new())).unwrap(), "files.example")
                };
                let started = std::time::Instant::now();
                let r = e.handle(req, host.into(), "https", super::Via::Tcp).await;
                let took = started.elapsed();
                let st = r.status().as_u16();
                let retry = r.headers().get("retry-after").map(|v| v.to_str().unwrap().to_string());
                (st, retry, String::from_utf8_lossy(&r.into_body().collect().await.unwrap().to_bytes()).into_owned(), took)
            }
        };
        // Egress: answered at once, retryably.
        let d = Scripted::new(vec![catching_up()]);
        let (st, retry, body, _) = send(d.clone(), false).await;
        assert_eq!((st, retry.as_deref()), (503, Some("5")), "{body}");
        assert!(body.contains("catching up") && body.contains("\"retry_after\": 5"), "{body}");
        assert_eq!(d.calls(), 1, "egress isn't held");
        match rx.try_recv() {
            Ok(crate::Event::Egress { outcome, detail, .. }) => {
                assert_eq!(outcome, "unavailable");
                assert!(detail.contains("catching up with wicket's policy feed"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
        // A model call: held, decided again, then answered retryably.
        let d = Scripted::new(vec![catching_up()]);
        let (st, retry, body, took) = send(d.clone(), true).await;
        assert_eq!((st, retry.as_deref()), (503, Some("5")), "{body}");
        assert!(took >= super::MODEL_CALL_HOLD && took < super::MODEL_CALL_HOLD * 3, "{took:?}");
        assert!(d.calls() > 2, "decided again while held: {}", d.calls());
        // A model call the node can decide while it is held is answered by that decision (here a
        // refusal, so nothing goes upstream), well before the hold ends.
        let d = Scripted::new(vec![catching_up(), catching_up(), crate::decide::Outcome::Forbidden("org policy".into())]);
        let (st, retry, body, took) = send(d.clone(), true).await;
        assert_eq!((st, retry), (403, None), "{body}");
        assert!(took < super::MODEL_CALL_HOLD, "{took:?}");
        assert_eq!(d.calls(), 3);
        // Real refusals stay 403.
        let (st, _, body, _) = send(Scripted::new(vec![crate::decide::Outcome::Forbidden("org policy".into())]), false).await;
        assert!(st == 403 && body.contains("never allowed"), "{body}");
        let denied = crate::decide::Outcome::Denied { request: "r-1".into() };
        assert_eq!(send(Scripted::new(vec![denied.clone()]), false).await.0, 403);
        assert_eq!(send(Scripted::new(vec![denied]), true).await.0, 403, "a model call isn't held for a refusal");
        let _ = std::fs::remove_dir_all(dir);
    }
}
