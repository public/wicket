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
use wicket_core::{canonical_path, manifest::host_matches, Op};

mod connect;
mod hosts;
mod outgoing;

#[cfg(test)]
use connect::parse_head;
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
            relay,
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

    /// Model calls to the model host that come through this proxy (a wrapped Claude Code session's)
    /// go through `llm`'s budget, body filter and accounting (#112).
    pub fn set_model_gate(&self, llm: Arc<crate::llm::Llm>) {
        let _ = self.model_gate.set(llm);
    }

    /// Serves CONNECT (and plain absolute-form HTTP) on a unix socket until the task is dropped.
    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        let _ = std::fs::remove_file(socket);
        let listener = crate::sockpath::bind(socket)?;
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
            if let Some(r) = self.judge_unlisted(&host, "CONNECT").await {
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
                if let Some(r) = self.judge_unlisted(&h, req.method().as_str()).await {
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
        // An unnamed host whose domain doesn't exist is unknown, not a pending request (#19). Over TCP
        // this was answered at CONNECT; HTTP/3 requests are first seen here. Cached per run.
        if let Some(r) = self.judge_unlisted(&host, &method).await {
            return r;
        }
        // Who in the box is asking (reported by the agent's own event stream, not proven).
        let who = ctx.attribute.as_ref().and_then(|f| f(&host, &path));
        match self.decider.decide(ctx, &op, who.as_ref()).await {
            Outcome::Allow(detail) => {
                // A name under a wildcard counts against the rule's limit before it is resolved (#20).
                if let Some((w, why)) = self.admit_wildcard(&host) {
                    emit("forbidden", why.clone());
                    let note = self.strike(&format!("wildcard {w}"));
                    return problem(403, "forbidden", "Blocked by wicket sandbox: never allowed", &format!(
                        "{why}. No more new names under {w} are reached in this run, and no approval can change that; the names already reached keep working. {} Do not retry it; tell the user if you need it.{note}",
                        crate::SANDBOX_FACT
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
            Outcome::Queued { id, why } => {
                let for_line = who.as_ref().map(|(_, l)| format!("; for {l}")).unwrap_or_default();
                emit("queued", format!("{id}: {why}{for_line}"));
                let note = self.strike(&op.digest());
                return problem(403, "queued", "Blocked by wicket sandbox: needs human approval (queued offline)", &format!(
                    "{why}. wicket's control plane is unreachable from this node, so this ask is queued here as {id} and will be put to a human when it is back; nothing new can be approved until then. {} Continue without it for now, or retry later.{note}",
                    crate::SANDBOX_FACT
                ), None);
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
            org: None,
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
            lifecycle: None,
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
        let e = super::Egress::new(c, ca).unwrap();
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
        let e = super::Egress::with_upstream(c, ca, std::sync::Arc::new(crate::decide::Central), None, up).unwrap();

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
        assert!(body.contains("needs human approval"), "{body}");
        assert_eq!(e.domains_checked(), ["example.co.uk", "no-such-domain-wkt.com"]);

        // A host the zone names is never checked, and a run that doesn't escalate checks nothing.
        assert!(e.judge_unlisted("api.github.com", "CONNECT").await.is_none());
        assert_eq!(e.domains_checked().len(), 2);
        let (mut c, _) = ctx("reach: []", vec![], "nxdomain-noesc");
        c.escalate = false;
        let ca = std::sync::Arc::new(crate::ca::RunCa::generate("run_x").unwrap());
        let e = super::Egress::new(c, ca).unwrap();
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
        let e = super::Egress::with_upstream(c, ca, std::sync::Arc::new(crate::decide::Central), None, up).unwrap();
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
        let e = super::Egress::with_upstream(c, ca, std::sync::Arc::new(crate::decide::Central), None, up).unwrap();
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
}
