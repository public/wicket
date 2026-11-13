//! The LLM proxy (design §9.3): holds the Claude subscription token (never an API key), strips
//! whatever credential the agent sends,
//! enforces request and token budgets, strips server-side tools the zone doesn't allow (they would
//! bypass the egress proxy), and is the run's liveness sensor.

use crate::{problem, BoxBody, Event, RunCtx, FORWARD_REQUEST, STRIP_RESPONSE};
use anyhow::Result;
use bytes::Bytes;
use futures_util::StreamExt;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

const MAX_REQUEST_BODY: usize = 32 * 1024 * 1024;
/// What a node's secret source says when its control host keeps the credential (an older protocol):
/// the call is relayed there instead.
pub const RELAY_INSTEAD: &str = "the control host speaks an older protocol";
/// How long a response is still read to its end after the agent stopped reading it, so its final
/// usage is seen (#113). Past this, the call is charged its whole reservation.
const DRAIN_AFTER_DISCONNECT: std::time::Duration = std::time::Duration::from_secs(600);

/// An upstream's answer: status, headers and body.
type Upstream =
    (u16, http::HeaderMap, futures_util::stream::BoxStream<'static, std::result::Result<Bytes, Box<dyn std::error::Error + Send + Sync>>>);

/// Opens a byte stream to the run's own model proxy on the control host (#151).
pub type LlmRelay =
    Arc<dyn Fn() -> futures_util::future::BoxFuture<'static, std::io::Result<Box<dyn crate::egress::RelayStream>>> + Send + Sync>;

pub struct Llm {
    ctx: RunCtx,
    client: reqwest::Client,
    /// On a node without a secret source (#151): the vetted request goes to the run's model proxy on
    /// the control host, which adds the credential. Otherwise (a node's cache, #152, or None) the call
    /// goes straight to the upstream from here, with the secret.
    relay: Option<LlmRelay>,
    pub requests: AtomicU64,
    /// Uncached input tokens.
    pub input_tokens: AtomicU64,
    /// Input tokens read from the prompt cache, and written to it.
    pub cache_read_tokens: AtomicU64,
    pub cache_creation_tokens: AtomicU64,
    pub output_tokens: AtomicU64,
    /// Budget handed to boxes this run started (spawn): no longer this run's to spend.
    pub reserved_requests: AtomicU64,
    pub reserved_output_tokens: AtomicU64,
    pub reserved_input_tokens: AtomicU64,
    /// What a long-lived agent's earlier activations already spent (#70): the zone's budget is the
    /// agent's, over its whole life, so a wake starts from what is left, not from a fresh budget.
    pub prior_requests: AtomicU64,
    pub prior_input_tokens: AtomicU64,
    pub prior_output_tokens: AtomicU64,
    /// Output tokens reserved by model calls in flight (#113): each call reserves its `max_tokens`
    /// up front, and settles to what it actually generated when its final usage arrives.
    pub inflight_output_tokens: AtomicU64,
    /// On a node (#152): the slice of the budget the control host has leased it, as caps on this
    /// activation's own counters. None: no slice (the zone's budget alone bounds it).
    slice: std::sync::Mutex<Option<Slice>>,
    last_activity: std::sync::Mutex<Instant>,
}

/// A budget slice leased to a node (#152): this activation may count up to these totals of its own
/// (requests; output tokens, in flight included; input tokens, cached ones included) before the
/// control host leases it more. Offline, the node spends its current slice and nothing more.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Slice {
    pub requests: u64,
    pub output_tokens: u64,
    #[serde(default)]
    pub input_tokens: Option<u64>,
}

/// What a run's model proxy has counted, as a node reports it to its control host (#152).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Spent {
    pub requests: u64,
    pub input_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_tokens: u64,
    pub output_tokens: u64,
}

impl Spent {
    /// What was counted since `base`.
    pub fn since(self, base: Spent) -> Spent {
        Spent {
            requests: self.requests.saturating_sub(base.requests),
            input_tokens: self.input_tokens.saturating_sub(base.input_tokens),
            cache_read_tokens: self.cache_read_tokens.saturating_sub(base.cache_read_tokens),
            cache_creation_tokens: self.cache_creation_tokens.saturating_sub(base.cache_creation_tokens),
            output_tokens: self.output_tokens.saturating_sub(base.output_tokens),
        }
    }
}

impl Llm {
    /// Model requests and output tokens this run has left to spend or hand on.
    pub fn remaining(&self) -> Option<(u64, u64)> {
        let spec = self.ctx.zone.llm.as_ref()?;
        let used_r = self.requests.load(Ordering::SeqCst)
            + self.reserved_requests.load(Ordering::SeqCst)
            + self.prior_requests.load(Ordering::SeqCst);
        Some((spec.max_requests.saturating_sub(used_r), spec.max_output_tokens.saturating_sub(self.output_committed())))
    }

    /// Output tokens spent, handed to children, spent by earlier activations, or reserved by calls
    /// in flight: what is no longer available to a new call.
    fn output_committed(&self) -> u64 {
        self.output_tokens.load(Ordering::SeqCst)
            + self.reserved_output_tokens.load(Ordering::SeqCst)
            + self.prior_output_tokens.load(Ordering::SeqCst)
            + self.inflight_output_tokens.load(Ordering::SeqCst)
    }

    /// Reserves up to `want` output tokens for one call, atomically (parallel calls can't each
    /// claim the same tokens): what is left, if less. None when nothing is left.
    fn reserve_output(&self, max: u64, want: u64) -> Option<u64> {
        loop {
            let inflight = self.inflight_output_tokens.load(Ordering::SeqCst);
            let used = self.output_tokens.load(Ordering::SeqCst)
                + self.reserved_output_tokens.load(Ordering::SeqCst)
                + self.prior_output_tokens.load(Ordering::SeqCst)
                + inflight;
            let left = max.saturating_sub(used);
            if left == 0 {
                return None;
            }
            let take = want.min(left);
            if self.inflight_output_tokens.compare_exchange(inflight, inflight + take, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                return Some(take);
            }
        }
    }

    /// Settles a call's reservation: releases it and charges what the call used. A call whose final
    /// usage wasn't seen is charged its whole reservation (or what was seen, if more).
    fn settle(&self, reserved: u64, u: Usage, settled: bool) {
        self.inflight_output_tokens.fetch_sub(reserved, Ordering::SeqCst);
        self.input_tokens.fetch_add(u.input, Ordering::SeqCst);
        self.cache_read_tokens.fetch_add(u.cache_read, Ordering::SeqCst);
        self.cache_creation_tokens.fetch_add(u.cache_creation, Ordering::SeqCst);
        self.output_tokens.fetch_add(if settled { u.output } else { u.output.max(reserved) }, Ordering::SeqCst);
    }

    /// Every input token this run's model calls used: uncached, cache reads and cache writes.
    pub fn input_total(&self) -> u64 {
        self.input_tokens.load(Ordering::SeqCst)
            + self.cache_read_tokens.load(Ordering::SeqCst)
            + self.cache_creation_tokens.load(Ordering::SeqCst)
    }

    /// Input tokens this run has left to spend or hand on, if its zone caps them.
    pub fn remaining_input(&self) -> Option<u64> {
        let max = self.ctx.zone.llm.as_ref()?.max_input_tokens?;
        Some(max.saturating_sub(
            self.input_total() + self.reserved_input_tokens.load(Ordering::SeqCst) + self.prior_input_tokens.load(Ordering::SeqCst),
        ))
    }

    pub fn new(ctx: RunCtx) -> Result<Arc<Llm>> {
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Arc::new(Llm {
            ctx,
            client,
            relay: None,
            requests: AtomicU64::new(0),
            input_tokens: AtomicU64::new(0),
            cache_read_tokens: AtomicU64::new(0),
            cache_creation_tokens: AtomicU64::new(0),
            output_tokens: AtomicU64::new(0),
            reserved_requests: AtomicU64::new(0),
            reserved_output_tokens: AtomicU64::new(0),
            reserved_input_tokens: AtomicU64::new(0),
            prior_requests: AtomicU64::new(0),
            prior_input_tokens: AtomicU64::new(0),
            prior_output_tokens: AtomicU64::new(0),
            inflight_output_tokens: AtomicU64::new(0),
            slice: std::sync::Mutex::new(None),
            last_activity: std::sync::Mutex::new(Instant::now()),
        }))
    }

    /// A model proxy on a node (#151): requests it lets through go on to the run's own proxy on the
    /// control host over `relay`, without a credential.
    pub fn relayed(ctx: RunCtx, relay: LlmRelay) -> Result<Arc<Llm>> {
        let mut l = Arc::into_inner(Llm::new(ctx)?).expect("fresh");
        l.relay = Some(relay);
        Ok(Arc::new(l))
    }

    /// What this activation has counted itself.
    pub fn spent(&self) -> Spent {
        Spent {
            requests: self.requests.load(Ordering::SeqCst),
            input_tokens: self.input_tokens.load(Ordering::SeqCst),
            cache_read_tokens: self.cache_read_tokens.load(Ordering::SeqCst),
            cache_creation_tokens: self.cache_creation_tokens.load(Ordering::SeqCst),
            output_tokens: self.output_tokens.load(Ordering::SeqCst),
        }
    }

    /// Takes in what another counter of this activation has seen (#152): the run's node, which
    /// calls the model itself and is the counter of record. Counters only go up.
    pub fn merge_spent(&self, s: Spent) {
        self.requests.fetch_max(s.requests, Ordering::SeqCst);
        self.input_tokens.fetch_max(s.input_tokens, Ordering::SeqCst);
        self.cache_read_tokens.fetch_max(s.cache_read_tokens, Ordering::SeqCst);
        self.cache_creation_tokens.fetch_max(s.cache_creation_tokens, Ordering::SeqCst);
        self.output_tokens.fetch_max(s.output_tokens, Ordering::SeqCst);
    }

    /// The budget slice leased to this node (#152).
    pub fn set_slice(&self, s: Option<Slice>) {
        *self.slice.lock().expect("slice") = s;
    }

    pub fn slice(&self) -> Option<Slice> {
        *self.slice.lock().expect("slice")
    }

    /// The slice this activation may be leased next (#152): what it has counted plus `fraction` of
    /// the zone's budget, never past what is left of it.
    pub fn next_slice(&self, fraction: f64) -> Option<Slice> {
        let spec = self.ctx.zone.llm.as_ref()?;
        let part = |max: u64| ((max as f64) * fraction).ceil().max(1.0) as u64;
        let (left_r, left_o) = self.remaining()?;
        let s = self.spent();
        Some(Slice {
            requests: s.requests + left_r.min(part(spec.max_requests)),
            output_tokens: s.output_tokens + left_o.min(part(spec.max_output_tokens)),
            input_tokens: spec.max_input_tokens.map(|m| self.input_total() + self.remaining_input().unwrap_or(0).min(part(m))),
        })
    }

    /// Starts this activation from what the agent's earlier ones spent (#70).
    pub fn spent_before(&self, requests: u64, input_tokens: u64, output_tokens: u64) {
        self.prior_requests.store(requests, Ordering::SeqCst);
        self.prior_input_tokens.store(input_tokens, Ordering::SeqCst);
        self.prior_output_tokens.store(output_tokens, Ordering::SeqCst);
    }

    /// What counts against the zone's budget so far, over the agent's life: (requests, input tokens
    /// with cached ones, output tokens). Budget handed to children counts as spent.
    pub fn spent_total(&self) -> (u64, u64, u64) {
        (
            self.requests.load(Ordering::SeqCst)
                + self.reserved_requests.load(Ordering::SeqCst)
                + self.prior_requests.load(Ordering::SeqCst),
            self.input_total() + self.reserved_input_tokens.load(Ordering::SeqCst) + self.prior_input_tokens.load(Ordering::SeqCst),
            self.output_tokens.load(Ordering::SeqCst)
                + self.reserved_output_tokens.load(Ordering::SeqCst)
                + self.prior_output_tokens.load(Ordering::SeqCst),
        )
    }

    /// How the budget is described: per run, or (for a woken agent) over its life.
    fn whose(&self) -> &'static str {
        if self.prior_requests.load(Ordering::SeqCst) + self.prior_output_tokens.load(Ordering::SeqCst) > 0 {
            "this agent, over all its activations,"
        } else {
            "this run"
        }
    }

    /// Seconds since the agent last called the model: the liveness signal.
    pub fn idle_secs(&self) -> u64 {
        self.last_activity.lock().map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }

    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        let _ = std::fs::remove_file(socket);
        let listener = crate::sockpath::bind(socket)?;
        loop {
            let (stream, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let me = me.clone();
                    async move { Ok::<_, hyper::Error>(me.handle(req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    }

    async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<BoxBody> {
        if let Ok(mut t) = self.last_activity.lock() {
            *t = Instant::now();
        }
        let Some(spec) = self.ctx.zone.llm.as_ref() else {
            return problem(404, "no-model", "No model", "this zone has no model route", None);
        };
        let Some(profile) = crate::provider::profile(&spec.provider) else {
            return problem(404, "no-model", "No model", &format!("no provider profile for {:?}", spec.provider), None);
        };
        if let Err(why) = profile.allowed_route(req.method().as_str(), req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/")) {
            self.event(None, 404, Usage::default(), &format!("refused route: {why}"));
            return problem(404, "route", "Not a model route", &why, None);
        }
        if let Some(why) = self.ctx.superseded() {
            self.event(None, 409, Usage::default(), "stale generation");
            return problem(409, "stale-generation", "This activation is stale", &why, None);
        }
        if let Some(r) = self.admit(Some(spec)) {
            return r;
        }
        match self.forward(req).await {
            Ok(r) => r,
            Err(e) => {
                self.event(None, 502, Usage::default(), &format!("upstream error: {e}"));
                problem(502, "upstream", "Model upstream error", &e.to_string(), None)
            }
        }
    }

    /// Counts a model request and checks the budgets before it is sent: None if it may go, else the
    /// refusal. Without a model route (a wrapped session's zone may have none), only counts.
    fn admit(&self, spec: Option<&wicket_core::manifest::LlmSpec>) -> Option<Response<BoxBody>> {
        // A node's slice (#152), before counting: a refusal here spends nothing, so a box retrying
        // against a spent slice offline doesn't burn its budget.
        if let (Some(_), Some(sl)) = (spec, self.slice()) {
            let over = if self.requests.load(Ordering::SeqCst) >= sl.requests {
                Some("request")
            } else if sl.input_tokens.is_some_and(|m| self.input_total() >= m) {
                Some("input token")
            } else {
                None
            };
            if let Some(what) = over {
                self.event(None, 429, Usage::default(), &format!("budget: this node's {what} slice is spent"));
                return Some(problem(
                    429,
                    "budget",
                    "Model budget slice exhausted on this node",
                    "this node has spent the slice of the model budget it was leased; the control host leases more when it can be reached. Retry later",
                    None,
                ));
            }
        }
        let n = self.requests.fetch_add(1, Ordering::SeqCst)
            + 1
            + self.reserved_requests.load(Ordering::SeqCst)
            + self.prior_requests.load(Ordering::SeqCst);
        let spec = spec?;
        if n > spec.max_requests {
            self.event(None, 429, Usage::default(), "budget: request cap reached");
            return Some(problem(
                429,
                "budget",
                "Model request budget exhausted",
                &format!("{} may make at most {} model requests", self.whose(), spec.max_requests),
                None,
            ));
        }
        if self.output_committed() >= spec.max_output_tokens {
            self.event(None, 429, Usage::default(), "budget: output token cap reached");
            return Some(problem(
                429,
                "budget",
                "Model token budget exhausted",
                &format!("{} may generate at most {} output tokens", self.whose(), spec.max_output_tokens),
                None,
            ));
        }
        if let (Some(max), Some(0)) = (spec.max_input_tokens, self.remaining_input()) {
            self.event(None, 429, Usage::default(), "budget: input token cap reached");
            return Some(problem(
                429,
                "budget",
                "Model token budget exhausted",
                &format!("{} may use at most {max} input tokens, cached ones included", self.whose()),
                None,
            ));
        }
        None
    }

    fn event(&self, model: Option<String>, status: u16, u: Usage, outcome: &str) {
        self.ctx.emit(Event::Llm {
            model,
            status,
            input_tokens: u.input,
            cached_tokens: u.cache_read + u.cache_creation,
            output_tokens: u.output,
            requests: self.requests.load(Ordering::SeqCst),
            outcome: outcome.into(),
        });
    }

    async fn forward(self: &Arc<Self>, req: Request<Incoming>) -> Result<Response<BoxBody>> {
        let spec = self.ctx.zone.llm.as_ref().ok_or_else(|| anyhow::anyhow!("this zone has no model route"))?;
        let (parts, body) = req.into_parts();
        let body = Limited::new(body, MAX_REQUEST_BODY).collect().await.map_err(|e| anyhow::anyhow!("request body: {e}"))?.to_bytes();
        let Filtered { body, model, note, reserved } = match self.filter(Some(spec), &parts, body) {
            Ok(f) => f,
            Err(r) => return Ok(*r),
        };
        // On a node (#152), the credential comes from the node's cache (fetched from the control host
        // on first use) and the call goes from here; the control host isn't asked per call. Without
        // the credential (first use while the control host is unreachable), the call fails clearly.
        // With a control host too old to release it, the call is relayed to the run's own proxy there.
        let mut relay = !self.ctx.vault.is_sourced();
        if self.ctx.vault.is_sourced() {
            if let Err(e) = self.ctx.vault.ensure(&spec.secret).await {
                if self.relay.is_some() && format!("{e:#}").contains(RELAY_INSTEAD) {
                    relay = true;
                } else {
                    self.settle(reserved, Usage::default(), true);
                    self.event(model, 503, Usage::default(), "credential unavailable on this node");
                    return Ok(problem(503, "credential", "Model credential unavailable on this node", &format!("{e:#}"), None));
                }
            }
        }
        let up = match &self.relay {
            Some(r) if relay => self.send_relayed(r, &parts, body).await,
            _ => self.send_upstream(spec, &parts, body).await.map(|r| {
                let (status, headers) = (r.status().as_u16(), r.headers().clone());
                let stream = r.bytes_stream().map(|c| c.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)).boxed();
                (status, headers, stream)
            }),
        };
        let (status, headers, stream) = match up {
            Ok(r) => r,
            Err(e) => {
                self.settle(reserved, Usage::default(), true);
                return Err(e);
            }
        };
        let mut out = Response::builder().status(StatusCode::from_u16(status)?);
        for (name, value) in headers.iter() {
            if !STRIP_RESPONSE.contains(&name.as_str()) {
                out = out.header(name.as_str(), value.as_bytes());
            }
        }
        let sse = headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("text/event-stream"));
        let body = self.account(model, status, sse, stream, reserved, note);
        Ok(out.body(body)?)
    }

    /// Sends a vetted request to the run's own model proxy on the control host (#151).
    async fn send_relayed(&self, relay: &LlmRelay, parts: &http::request::Parts, body: Bytes) -> Result<Upstream> {
        let io = relay().await.map_err(|e| anyhow::anyhow!("the control host's model proxy is unreachable: {e}"))?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut rb = Request::builder().method(parts.method.clone()).uri(parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
        for (name, value) in parts.headers.iter() {
            let n = name.as_str();
            if n != "accept-encoding"
                && n != "content-length"
                && (FORWARD_REQUEST.contains(&n) || crate::provider_request_header(MODEL_HOST, n))
            {
                rb = rb.header(n, value);
            }
        }
        let req = rb.header("host", "wicket.internal").header("accept-encoding", "identity").body(http_body_util::Full::new(body))?;
        let resp = send.send_request(req).await?;
        let (status, headers) = (resp.status().as_u16(), resp.headers().clone());
        let stream = http_body_util::BodyStream::new(resp.into_body())
            .filter_map(|f| async move {
                match f {
                    Ok(f) => f.into_data().ok().map(Ok),
                    Err(e) => Some(Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>)),
                }
            })
            .boxed();
        Ok((status, headers, stream))
    }

    async fn send_upstream(
        &self,
        spec: &wicket_core::manifest::LlmSpec,
        parts: &http::request::Parts,
        body: Bytes,
    ) -> Result<reqwest::Response> {
        let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let url = format!("{}{}", spec.upstream.trim_end_matches('/'), pq);
        let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?;
        let mut rb = self.client.request(method, &url);
        // Allow-listed headers only (#112, as on the egress proxy): never a client credential.
        for (name, value) in parts.headers.iter() {
            let n = name.as_str();
            if n != "accept-encoding" && (FORWARD_REQUEST.contains(&n) || crate::provider_request_header(MODEL_HOST, n)) {
                rb = rb.header(n, value.as_bytes());
            }
        }
        // The real subscription token, injected into the one slot Claude Code uses for it.
        // Only to an upstream the secret is bound to, whatever the zone's `upstream` says.
        let up_host = reqwest::Url::parse(&spec.upstream)?.host_str().map(String::from).unwrap_or_default();
        let token = self.ctx.vault.get_for(&spec.secret, &up_host)?;
        let profile =
            crate::provider::profile(&spec.provider).ok_or_else(|| anyhow::anyhow!("no provider profile for {:?}", spec.provider))?;
        rb = (profile.attach)(rb, &token).header("accept-encoding", "identity");
        Ok(rb.body(body).send().await?)
    }

    /// Vets a model request's body (#112) and reserves its output (#113). Only `POST /v1/messages` and
    /// `/v1/messages/count_tokens` carry bodies; reads (GET, HEAD) pass without one. The body must be
    /// a plain (not `Content-Encoding`-ed) JSON object; it is re-encoded from what was parsed, keeping
    /// only known top-level fields, and only client tools (executed by the agent, in its box) unless
    /// the zone has `allow_server_tools`: server tools, the MCP connector, containers and URL
    /// sources make the provider fetch from or send to hosts the zone never allowed. A messages call
    /// must say its `max_tokens`, which is reserved, lowered to what is left of the output budget if
    /// it asks for more (#113). The caller settles `reserved`.
    pub(crate) fn filter(
        &self,
        spec: Option<&wicket_core::manifest::LlmSpec>,
        parts: &http::request::Parts,
        body: Bytes,
    ) -> std::result::Result<Filtered, Box<Response<BoxBody>>> {
        let refuse = |status: u16, why: String| {
            self.event(None, status, Usage::default(), &format!("refused: {why}"));
            Box::new(problem(
                status,
                "forbidden",
                "Blocked by wicket: model request refused",
                &format!("{why}. {}", crate::SANDBOX_FACT),
                None,
            ))
        };
        let path = parts.uri.path();
        if matches!(parts.method, http::Method::GET | http::Method::HEAD) {
            if !body.is_empty() {
                return Err(refuse(400, format!("a {} request with a body", parts.method)));
            }
            return Ok(Filtered { body, model: None, note: "ok".into(), reserved: 0 });
        }
        if parts.method != http::Method::POST || !MODEL_ENDPOINTS.contains(&path) {
            return Err(refuse(
                403,
                format!("{} {path} is not a model call wicket proxies (only POST {})", parts.method, MODEL_ENDPOINTS.join(" and ")),
            ));
        }
        if let Some(enc) = parts.headers.get(http::header::CONTENT_ENCODING) {
            if !enc.as_bytes().eq_ignore_ascii_case(b"identity") {
                return Err(refuse(415, "a Content-Encoding-ed model request body (send it uncompressed)".into()));
            }
        }
        let Ok(serde_json::Value::Object(mut json)) = serde_json::from_slice::<serde_json::Value>(&body) else {
            return Err(refuse(400, "a model request body that isn't a JSON object".into()));
        };
        let server_ok = spec.is_some_and(|s| s.allow_server_tools);
        let model = json.get("model").and_then(|m| m.as_str()).map(String::from);
        let mut notes = Vec::new();
        let before = json.len();
        json.retain(|k, _| REQUEST_FIELDS.contains(&k.as_str()) || (server_ok && SERVER_FIELDS.contains(&k.as_str())));
        if json.len() != before {
            notes.push(format!("stripped {} request field(s)", before - json.len()));
        }
        if !server_ok {
            if let Some(tools) = json.get_mut("tools").and_then(|t| t.as_array_mut()) {
                let before = tools.len();
                tools.retain(|t| client_tool(t.get("type").and_then(|v| v.as_str())));
                if tools.len() != before {
                    notes.push(format!("stripped {} server-side tool(s)", before - tools.len()));
                }
            }
        }
        // URL sources (images, documents) are fetched by the provider: a way around the egress proxy.
        if !server_ok && has_url_source(&serde_json::Value::Object(json.clone())) {
            return Err(refuse(403, "a content block with a URL source, which the provider would fetch (send the content itself)".into()));
        }
        // The call's output is reserved up front (#113), here, so the amount reserved is the amount
        // the body asks for: one asking for more than is left is lowered to what is left, and
        // parallel calls can't each claim the same tokens.
        let mut reserved = 0;
        if path == "/v1/messages" {
            let Some(asked) = json.get("max_tokens").and_then(|v| v.as_u64()) else {
                return Err(refuse(400, "a messages request without an integer max_tokens".into()));
            };
            if let Some(spec) = spec {
                // A node's slice (#152) caps this activation's own output, in flight included.
                let cap = match self.slice() {
                    Some(sl) => spec.max_output_tokens.min(
                        sl.output_tokens
                            + self.reserved_output_tokens.load(Ordering::SeqCst)
                            + self.prior_output_tokens.load(Ordering::SeqCst),
                    ),
                    None => spec.max_output_tokens,
                };
                let Some(r) = self.reserve_output(cap, asked) else {
                    self.event(model.clone(), 429, Usage::default(), "budget: output token cap reached");
                    return Err(Box::new(problem(
                        429,
                        "budget",
                        "Model token budget exhausted",
                        &format!("{} may generate at most {} output tokens", self.whose(), spec.max_output_tokens),
                        None,
                    )));
                };
                if r < asked {
                    json.insert("max_tokens".into(), r.into());
                    notes.push(format!("max_tokens {asked} lowered to the {r} output tokens left"));
                }
                reserved = r;
            }
        }
        let body = match serde_json::to_vec(&json) {
            Ok(b) => Bytes::from(b),
            Err(e) => {
                self.settle(reserved, Usage::default(), true);
                return Err(refuse(400, format!("the model request body can't be re-encoded ({e})")));
            }
        };
        Ok(Filtered { body, model, note: if notes.is_empty() { "ok".into() } else { notes.join("; ") }, reserved })
    }

    /// A wrapped session's model call, which reaches the model host through the egress proxy (its
    /// credential swapped there) rather than through this proxy (#112): the same budget, body
    /// filter and accounting as a call to this proxy, then the egress proxy's own forwarding.
    pub(crate) async fn through_egress<B>(
        self: &Arc<Self>,
        egress: &crate::egress::Egress,
        req: Request<B>,
        host: &str,
        pq: &str,
        via: crate::egress::Via,
    ) -> Response<BoxBody>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        if let Ok(mut t) = self.last_activity.lock() {
            *t = Instant::now();
        }
        let spec = self.ctx.zone.llm.as_ref();
        if let Some(r) = self.admit(spec) {
            return r;
        }
        let (parts, body) = req.into_parts();
        let body = match Limited::new(body, MAX_REQUEST_BODY).collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => return problem(400, "bad-request", "Bad model request", &format!("request body: {e}"), None),
        };
        let f = match self.filter(spec, &parts, body) {
            Ok(f) => f,
            Err(r) => return *r,
        };
        let reserved = f.reserved;
        let req = Request::from_parts(parts, http_body_util::Full::new(f.body));
        match egress.forward(req, host, "https", pq, via).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let sse = resp
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("text/event-stream"));
                let (head, body) = resp.into_parts();
                Response::from_parts(head, self.account(f.model, status, sse, body.into_data_stream(), reserved, f.note))
            }
            Err(e) => {
                self.settle(reserved, Usage::default(), true);
                self.event(f.model, 502, Usage::default(), &format!("upstream error: {e:#}"));
                problem(502, "upstream", "Model upstream error", &format!("{e:#}"), None)
            }
        }
    }

    /// Streams an upstream response to the agent while reading its usage as it goes (in constant
    /// memory, #113), and settles the call's reservation when the response ends. If the agent stops
    /// reading, the response is still read to its end (for up to [`DRAIN_AFTER_DISCONNECT`]), so a
    /// call can't escape its charge by disconnecting before the final usage. A successful response
    /// that ends without its final usage (`message_stop` for a stream) is charged its whole
    /// reservation; an error response, only what it reports.
    pub(crate) fn account<S, E>(
        self: &Arc<Self>,
        model: Option<String>,
        status: u16,
        sse: bool,
        mut upstream: S,
        reserved: u64,
        note: String,
    ) -> BoxBody
    where
        S: futures_util::Stream<Item = std::result::Result<Bytes, E>> + Send + Unpin + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>(16);
        let me = self.clone();
        tokio::spawn(async move {
            let mut scan = UsageScanner {
                reader: me.ctx.zone.llm.as_ref().and_then(|l| crate::provider::profile(&l.provider)).map(|p| p.usage),
                ..UsageScanner::default()
            };
            let mut client = true;
            let mut deadline = None;
            let mut clean_end = false;
            loop {
                let next = match deadline {
                    None => upstream.next().await,
                    Some(d) => match tokio::time::timeout_at(d, upstream.next()).await {
                        Ok(n) => n,
                        Err(_) => break,
                    },
                };
                match next {
                    Some(Ok(b)) => {
                        scan.feed(&b);
                        if client && tx.send(Ok(Frame::data(b))).await.is_err() {
                            client = false;
                            deadline = Some(tokio::time::Instant::now() + DRAIN_AFTER_DISCONNECT);
                        }
                    }
                    Some(Err(e)) => {
                        if client {
                            let _ = tx.send(Err(e.into())).await;
                        }
                        break;
                    }
                    None => {
                        clean_end = true;
                        break;
                    }
                }
            }
            let u = scan.usage;
            let ok = (200..300).contains(&status);
            let settled = !ok || (clean_end && if sse { scan.stopped } else { scan.saw_output });
            me.settle(reserved, u, settled);
            let note = if settled { note } else { format!("{note}; no final usage seen: charged the {reserved} reserved output tokens") };
            let charged = Usage { output: if settled { u.output } else { u.output.max(reserved) }, ..u };
            me.event(model, status, charged, &note);
        });
        let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|item| (item, rx)) });
        BodyExt::boxed(StreamBody::new(stream))
    }
}

/// The host Claude Code's model calls go to.
pub(crate) const MODEL_HOST: &str = wicket_core::splice::MODEL_HOST;

/// The only model endpoints that take a request body (#112). Batches, files and anything else are
/// refused: a batch carries requests (and tools) of its own.
const MODEL_ENDPOINTS: &[&str] = &["/v1/messages", "/v1/messages/count_tokens"];

/// Whether a request to the model host is a model call, vetted and accounted as one, when it
/// arrives at the egress proxy (a wrapped session's).
pub(crate) fn is_model_call(host: &str, path: &str) -> bool {
    host == MODEL_HOST && (path == "/v1/messages" || path.starts_with("/v1/messages/") || path == "/v1/complete")
}

/// Top-level Messages request fields that are forwarded (#112): none of them makes the provider
/// reach another host.
const REQUEST_FIELDS: &[&str] = &[
    "model",
    "messages",
    "system",
    "max_tokens",
    "metadata",
    "stop_sequences",
    "stream",
    "temperature",
    "top_k",
    "top_p",
    "tools",
    "tool_choice",
    "thinking",
    "output_config",
    "output_format",
    "service_tier",
    "context_management",
    "inference_geo",
    "speed",
    "cache_control",
    "thread",
];

/// Fields that run things on the provider's side (the MCP connector, code-execution containers and
/// skills): forwarded only with `allow_server_tools`.
const SERVER_FIELDS: &[&str] = &["mcp_servers", "container"];

/// Whether a tool `type` is one the agent itself executes: a custom tool (no type, or `custom`), or
/// one of the schema-less client tools (bash, text editor, memory, computer use). Everything else
/// (web search and fetch, code execution, tool search, MCP toolsets, the advisor, and any type
/// added later) runs on the provider's side.
fn client_tool(ty: Option<&str>) -> bool {
    match ty {
        None | Some("custom") => true,
        Some(t) => ["bash_", "text_editor_", "memory_", "computer_2"].iter().any(|p| t.starts_with(p)),
    }
}

/// A vetted model request body, and what it reserves.
pub(crate) struct Filtered {
    pub body: Bytes,
    pub model: Option<String>,
    pub note: String,
    /// Output tokens reserved for it (its `max_tokens`, or what was left): to be settled.
    pub reserved: u64,
}

/// Whether any content block (at any depth: messages, system, tool results) has a URL source.
fn has_url_source(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Object(o) => {
            o.get("source").and_then(|s| s.get("type")).and_then(|t| t.as_str()) == Some("url") || o.values().any(has_url_source)
        }
        serde_json::Value::Array(a) => a.iter().any(has_url_source),
        _ => false,
    }
}

/// Reads token usage from a response as it streams past, in constant memory: each chunk is scanned
/// with the end of the previous one, so a key or number split across chunks is still read (the
/// largest value per field wins, so reading one twice changes nothing).
#[derive(Default)]
pub(crate) struct UsageScanner {
    carry: Vec<u8>,
    pub usage: Usage,
    /// An `output_tokens` count was seen (a non-streamed response's usage).
    pub saw_output: bool,
    /// The stream's `message_stop` event was seen: the final usage (in `message_delta`) came before it.
    pub stopped: bool,
    /// The provider profile's usage reader (None: Anthropic's).
    pub reader: Option<fn(&[u8]) -> Usage>,
}

/// Longer than any key plus its number, so nothing is split past the carried tail.
const SCAN_CARRY: usize = 96;

impl UsageScanner {
    pub(crate) fn feed(&mut self, chunk: &[u8]) {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let u = self.reader.unwrap_or(usage)(&buf);
        self.usage = Usage {
            input: self.usage.input.max(u.input),
            cache_read: self.usage.cache_read.max(u.cache_read),
            cache_creation: self.usage.cache_creation.max(u.cache_creation),
            output: self.usage.output.max(u.output),
        };
        let text = String::from_utf8_lossy(&buf);
        self.saw_output |= text.contains("\"output_tokens\"");
        // As the event's own type, never as text inside a JSON string (where quotes are escaped).
        self.stopped |= text.contains("event: message_stop") || text.contains("\"type\":\"message_stop\"");
        let keep = buf.len().saturating_sub(SCAN_CARRY);
        self.carry = buf.split_off(keep);
    }
}

/// Token usage of one model call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Input not read from or written to the prompt cache.
    pub input: u64,
    pub cache_read: u64,
    pub cache_creation: u64,
    pub output: u64,
}

/// Best-effort usage from a Messages response, streamed (SSE) or not: the largest value seen for
/// each field (streamed counts are cumulative). The keys include their opening quote, so
/// `"input_tokens":` doesn't also match `"cache_read_input_tokens":`.
/// The only requests the model route forwards, as (method, path): inference and token counting
/// (and listing models). Everything else under the upstream would also carry the real token, so
/// it is refused here, before any budget is spent.
/// Ok if `method` and `path_and_query` name an allowed Anthropic model route (the [`crate::provider`]
/// profile's), exactly and canonically.
pub fn allowed_route(method: &str, path_and_query: &str) -> std::result::Result<(), String> {
    crate::provider::ANTHROPIC.allowed_route(method, path_and_query)
}

/// Anthropic's usage fields in a response body (the Anthropic profile's [`crate::provider::Profile::usage`]).
pub fn usage(body: &[u8]) -> Usage {
    let s = String::from_utf8_lossy(body);
    Usage {
        input: max_after(&s, "\"input_tokens\":"),
        cache_read: max_after(&s, "\"cache_read_input_tokens\":"),
        cache_creation: max_after(&s, "\"cache_creation_input_tokens\":"),
        output: max_after(&s, "\"output_tokens\":"),
    }
}

fn max_after(s: &str, key: &str) -> u64 {
    let mut best = 0;
    for (i, _) in s.match_indices(key) {
        let digits: String = s[i + key.len()..].trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(v) = digits.parse::<u64>() {
            best = best.max(v);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::{usage, Usage};

    /// A run context for zone `z` (with a model route), fenced as `fence` if given.
    fn ctx(ledger: wicket_store::Ledger, fence: Option<crate::Fence>, llm: &str) -> crate::RunCtx {
        use std::sync::{Arc, Mutex};
        let m = wicket_core::Manifest::from_yaml(&format!("task: t\nagent: {{name: a}}\nzone: {{name: z, llm: {llm}}}")).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        crate::RunCtx {
            tenant: wicket_core::TenantId::single(),
            run: wicket_core::RunId("run_old".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(m.zone.clone()).unwrap()),
            ledger: Arc::new(Mutex::new(ledger)),
            vault: crate::vault::Vault::new(std::env::temp_dir().join("wicket-llm-no-vault")),
            events: tx,
            escalate: true,
            attribute: None,
            identity: None,
            spawner: None,
            swaps: vec![],
            boxes: None,
            capacity: None,
            fence,
            waker: None,
        }
    }

    fn hibernated_agent(ledger: &mut wicket_store::Ledger) -> String {
        let agent = wicket_store::new_agent_id();
        ledger
            .create_agent(&wicket_store::NewAgent {
                id: &agent,
                tenant: "t0",
                zone: "z",
                name: "a",
                run: "run_old",
                session_id: "s",
                manifest: "m",
                image: "i",
                workspace: None,
                lease_until: 0,
            })
            .unwrap();
        assert!(ledger.commit_agent_push(&agent, 1, 0, 1, "h", 1).unwrap());
        agent
    }

    /// Serves `llm` on a socket and sends it one model request: (status, body).
    async fn post(llm: std::sync::Arc<super::Llm>, tag: &str) -> (u16, String) {
        send(llm, tag, "POST", "/v1/messages").await
    }

    /// Serves `llm` on a socket and sends it one request: (status, body).
    async fn send(llm: std::sync::Arc<super::Llm>, tag: &str, method: &str, path: &str) -> (u16, String) {
        use http_body_util::BodyExt;
        let dir = std::env::temp_dir().join(format!("wicket-llm-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("llm.sock");
        let server = tokio::spawn({
            let sock = sock.clone();
            async move { llm.serve(&sock).await }
        });
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
        tokio::spawn(conn);
        let req = http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "wicket.internal")
            .body(http_body_util::Full::new(bytes::Bytes::from_static(br#"{"max_tokens":1,"messages":[]}"#)))
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        let b = resp.into_body().collect().await.unwrap().to_bytes();
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
        (status, String::from_utf8_lossy(&b).into_owned())
    }

    /// The model route sends its secret only to an upstream the vault binds it to: a zone pointing
    /// `upstream` elsewhere gets an error, and the other host never sees a request.
    #[tokio::test]
    async fn the_model_secret_goes_only_to_its_bound_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let mut buf = vec![0u8; 8192];
                let n = c.read(&mut buf).await.unwrap_or(0);
                seen2.lock().await.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = c
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                    .await;
            }
        });
        let dir = std::env::temp_dir().join(format!("wicket-llm-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = crate::vault::Vault::new(dir.clone());
        vault.set("model", "the-model-token").unwrap();
        vault.set_hosts("model", &["api.anthropic.com".into()]).unwrap();
        let llm = format!("{{secret: model, upstream: 'http://127.0.0.1:{port}'}}");
        let mut c = ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &llm);
        c.vault = vault.clone();
        let (status, _) = post(super::Llm::new(c).unwrap(), "unbound").await;
        assert!(status >= 500, "{status}");
        assert!(seen.lock().await.is_empty(), "the other host saw nothing");
        vault.set_hosts("model", &["127.0.0.1".into()]).unwrap();
        let mut c = ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &llm);
        c.vault = vault;
        let (status, _) = post(super::Llm::new(c).unwrap(), "bound").await;
        assert_eq!(status, 200);
        assert!(seen.lock().await.iter().any(|r| r.to_ascii_lowercase().contains("authorization: bearer the-model-token")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_model_routes_are_allowed() {
        use super::allowed_route as a;
        assert!(a("POST", "/v1/messages").is_ok());
        assert!(a("POST", "/v1/messages?beta=true").is_ok());
        assert!(a("POST", "/v1/messages/count_tokens?beta=true").is_ok());
        assert!(a("GET", "/v1/models").is_ok());
        for (m, p) in [
            ("GET", "/v1/messages"),
            ("DELETE", "/v1/messages"),
            ("POST", "/v1/messages/../../api/x"),
            ("POST", "/v1/messages/%2e%2e/x"),
            ("POST", "//v1/messages"),
            ("POST", "/v1/messages/"),
            ("POST", "/v1/messages?beta=true&x=1"),
            ("GET", "/api/oauth/profile"),
            ("POST", "/v1/other"),
            ("GET", "/"),
        ] {
            assert!(a(m, p).is_err(), "{m} {p}");
        }
    }

    /// Any other path is refused before it reaches the upstream with the token.
    #[tokio::test]
    async fn other_routes_never_reach_the_upstream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let mut buf = vec![0u8; 8192];
                let _ = c.read(&mut buf).await;
                seen2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}").await;
            }
        });
        let dir = std::env::temp_dir().join(format!("wicket-llm-routes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = crate::vault::Vault::new(dir.clone());
        vault.set("model", "tok").unwrap();
        vault.set_hosts("model", &["127.0.0.1".into()]).unwrap();
        let llm = format!("{{secret: model, upstream: 'http://127.0.0.1:{port}'}}");
        for (i, (m, p)) in [("GET", "/v1/code/sessions"), ("POST", "/api/oauth/x"), ("POST", "/v1/messages/../x")].into_iter().enumerate() {
            let mut c = ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &llm);
            c.vault = vault.clone();
            let (status, _) = send(super::Llm::new(c).unwrap(), &format!("r{i}"), m, p).await;
            assert_eq!(status, 404, "{m} {p}");
        }
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0);
        let mut c = ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &llm);
        c.vault = vault;
        let (status, _) = send(super::Llm::new(c).unwrap(), "ok", "POST", "/v1/messages?beta=true").await;
        assert_eq!(status, 200);
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #70: once the agent has been woken again, an older activation's model calls are refused.
    #[tokio::test]
    async fn a_stale_generation_is_refused() {
        let mut ledger = wicket_store::Ledger::open_in_memory().unwrap();
        let agent = hibernated_agent(&mut ledger);
        let ctx = ctx(ledger, Some(crate::Fence { agent: agent.clone(), generation: 1 }), "{}");
        assert_eq!(ctx.superseded(), None, "generation 1 is current");
        // A second activation claims the agent: generation 2.
        assert_eq!(ctx.ledger.lock().unwrap().claim_wake(&agent, "run_new", 0).unwrap(), Some(2));
        assert!(ctx.superseded().unwrap().contains("stale"));
        let llm = super::Llm::new(ctx).unwrap();
        let (status, body) = post(llm.clone(), "fence").await;
        assert_eq!(status, 409);
        assert!(body.contains("generation 2"), "{body}");
        assert_eq!(llm.requests.load(std::sync::atomic::Ordering::SeqCst), 0, "not counted, never forwarded");
    }

    /// #70: the zone's model budget is the agent's over its life. A woken activation starts from
    /// what its earlier ones left, and an exhausted agent gets 429 without a model call.
    #[tokio::test]
    async fn a_woken_agent_continues_its_budget() {
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{max_requests: 5, max_output_tokens: 100}"))
            .unwrap();
        llm.spent_before(3, 40, 60);
        assert_eq!(llm.remaining(), Some((2, 40)), "children are carved from what is left");
        llm.reserved_requests.store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(llm.spent_total(), (4, 40, 60));
        // Every request is spent: refused, never forwarded (the default upstream is never contacted).
        llm.spent_before(5, 40, 60);
        llm.reserved_requests.store(0, std::sync::atomic::Ordering::SeqCst);
        let (status, body) = post(llm.clone(), "budget").await;
        assert_eq!(status, 429, "{body}");
        assert!(body.contains("over all its activations"), "{body}");
        // Output tokens spent instead.
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{max_requests: 5, max_output_tokens: 100}"))
            .unwrap();
        llm.spent_before(1, 0, 100);
        let (status, _) = post(llm, "tokens").await;
        assert_eq!(status, 429);
    }

    /// A model upstream that answers every request with `chunks` (an SSE stream, chunked), pausing
    /// `pause` before each of the last two, then ends cleanly. It records each request it got.
    async fn sse_upstream(chunks: Vec<Vec<u8>>, pause: std::time::Duration) -> (u16, std::sync::Arc<tokio::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let (chunks, seen) = (chunks.clone(), seen2.clone());
                tokio::spawn(async move {
                    let mut req = Vec::new();
                    let mut buf = vec![0u8; 65536];
                    while !String::from_utf8_lossy(&req).contains("\r\n\r\n") {
                        let n = c.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        req.extend_from_slice(&buf[..n]);
                    }
                    // The body follows the head (small in these tests): give it a moment to arrive.
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    if let Ok(Ok(n)) = tokio::time::timeout(std::time::Duration::from_millis(50), c.read(&mut buf)).await {
                        req.extend_from_slice(&buf[..n]);
                    }
                    seen.lock().await.push(String::from_utf8_lossy(&req).into_owned());
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n").await;
                    let last = chunks.len().saturating_sub(1);
                    for (i, ch) in chunks.iter().enumerate() {
                        if i > 0 && i + 1 >= last {
                            tokio::time::sleep(pause).await;
                        }
                        if c.write_all(format!("{:x}\r\n", ch.len()).as_bytes()).await.is_err()
                            || c.write_all(ch).await.is_err()
                            || c.write_all(b"\r\n").await.is_err()
                        {
                            return;
                        }
                    }
                    let _ = c.write_all(b"0\r\n\r\n").await;
                });
            }
        });
        (port, seen)
    }

    fn sse(event: &str, data: &str) -> Vec<u8> {
        format!("event: {event}\ndata: {data}\n\n").into_bytes()
    }

    /// An Llm with a model route to the mock on `port` and an output budget of `max_output`.
    fn llm_to(port: u16, max_output: u64, tag: &str) -> (std::sync::Arc<super::Llm>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("wicket-llm-v-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = crate::vault::Vault::new(dir.clone());
        vault.set("model", "tok").unwrap();
        vault.set_hosts("model", &["127.0.0.1".into()]).unwrap();
        let llm = format!("{{secret: model, upstream: 'http://127.0.0.1:{port}', max_output_tokens: {max_output}, max_requests: 100}}");
        let mut c = ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &llm);
        c.vault = vault;
        (super::Llm::new(c).unwrap(), dir)
    }

    /// Sends one model request; reads the whole response, or (`whole` false) its first frame only,
    /// then hangs up.
    async fn call(llm: std::sync::Arc<super::Llm>, tag: &str, body: &str, whole: bool) -> u16 {
        use http_body_util::BodyExt;
        let dir = std::env::temp_dir().join(format!("wicket-llm-c-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("llm.sock");
        let server = tokio::spawn({
            let sock = sock.clone();
            async move { llm.serve(&sock).await }
        });
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
        let conn = tokio::spawn(conn);
        let req = http::Request::post("/v1/messages")
            .header("host", "wicket.internal")
            .header("content-type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(body.to_string())))
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        let mut b = resp.into_body();
        if whole {
            let _ = b.collect().await;
        } else {
            let _ = b.frame().await;
            drop(b);
            drop(send);
            conn.abort();
        }
        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
        status
    }

    async fn output_settles(llm: &super::Llm, want: u64) -> u64 {
        for _ in 0..300 {
            if llm.inflight_output_tokens.load(std::sync::atomic::Ordering::SeqCst) == 0
                && llm.output_tokens.load(std::sync::atomic::Ordering::SeqCst) == want
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        llm.output_tokens.load(std::sync::atomic::Ordering::SeqCst)
    }

    const ASK: &str = r#"{"model":"m","max_tokens":300,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;

    /// #113: an agent that hangs up after the first event is still charged what the call generated.
    #[tokio::test]
    async fn a_client_that_disconnects_early_is_charged_the_final_usage() {
        let chunks = vec![
            sse("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":12,"output_tokens":1}}}"#),
            sse("content_block_delta", r#"{"type":"content_block_delta","delta":{"text":"lots"}}"#),
            [
                sse("message_delta", r#"{"type":"message_delta","usage":{"output_tokens":250}}"#),
                sse("message_stop", r#"{"type":"message_stop"}"#),
            ]
            .concat(),
        ];
        let (port, _) = sse_upstream(chunks, std::time::Duration::from_millis(300)).await;
        let (llm, dir) = llm_to(port, 1000, "early");
        assert_eq!(call(llm.clone(), "early", ASK, false).await, 200);
        assert_eq!(output_settles(&llm, 250).await, 250);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #113: usage at the end of a stream larger than any bounded copy is still read.
    #[tokio::test]
    async fn the_final_usage_of_a_large_stream_is_counted() {
        let delta =
            sse("content_block_delta", &format!(r#"{{"type":"content_block_delta","delta":{{"text":"{}"}}}}"#, "x".repeat(64 * 1024)));
        let mut chunks = vec![sse("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":3,"output_tokens":1}}}"#)];
        chunks.extend(std::iter::repeat_n(delta, 150)); // ~9.6 MiB
        chunks.push(
            [
                sse("message_delta", r#"{"type":"message_delta","usage":{"output_tokens":77}}"#),
                sse("message_stop", r#"{"type":"message_stop"}"#),
            ]
            .concat(),
        );
        let (port, _) = sse_upstream(chunks, std::time::Duration::ZERO).await;
        let (llm, dir) = llm_to(port, 1000, "large");
        assert_eq!(call(llm.clone(), "large", ASK, true).await, 200);
        assert_eq!(output_settles(&llm, 77).await, 77);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #113: a stream that ends without its final usage is charged the whole reservation, and a
    /// call asking for more than is left is lowered to what is left.
    #[tokio::test]
    async fn an_unsettled_call_is_charged_its_reservation_and_asks_are_capped() {
        let chunks = vec![
            sse("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":3,"output_tokens":1}}}"#),
            b": keep-alive\n\n".to_vec(),
        ];
        let (port, seen) = sse_upstream(chunks, std::time::Duration::ZERO).await;
        let (llm, dir) = llm_to(port, 1000, "unsettled");
        assert_eq!(call(llm.clone(), "unsettled", ASK, true).await, 200);
        assert_eq!(output_settles(&llm, 300).await, 300, "charged max_tokens");
        // 700 left: an ask for 5000 goes upstream as 700.
        let big = ASK.replace("\"max_tokens\":300", "\"max_tokens\":5000");
        assert_eq!(call(llm.clone(), "unsettled2", &big, true).await, 200);
        assert!(seen.lock().await.iter().any(|r| r.contains("\"max_tokens\":700")), "{:?}", seen.lock().await);
        assert_eq!(output_settles(&llm, 1000).await, 1000);
        // Nothing left: refused without a model call.
        let n = seen.lock().await.len();
        assert_eq!(call(llm.clone(), "unsettled3", ASK, true).await, 429);
        assert_eq!(seen.lock().await.len(), n);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #113: the amount a call reserves is the amount its body asks for, so a call made while
    /// another holds part of the budget goes upstream lowered to what is left; a messages call that
    /// doesn't say how much it may generate isn't sent.
    #[test]
    fn a_call_asks_upstream_for_no_more_than_it_reserved() {
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{max_output_tokens: 100}")).unwrap();
        let spec = llm.ctx.zone.llm.clone().unwrap();
        let parts = || http::Request::post("/v1/messages").body(()).unwrap().into_parts().0;
        let ask = |n: &str| bytes::Bytes::from(format!(r#"{{"model":"m","max_tokens":{n},"messages":[]}}"#));
        let first = llm.filter(Some(&spec), &parts(), ask("60")).ok().unwrap();
        assert_eq!(first.reserved, 60);
        let second = llm.filter(Some(&spec), &parts(), ask("60")).ok().unwrap();
        assert_eq!(second.reserved, 40);
        let out: serde_json::Value = serde_json::from_slice(&second.body).unwrap();
        assert_eq!(out["max_tokens"], 40);
        assert_eq!(llm.filter(Some(&spec), &parts(), ask("1")).err().map(|r| r.status().as_u16()), Some(429));
        llm.settle(60, Usage::default(), true);
        for bad in
            [r#"{"messages":[]}"#, r#"{"max_tokens":64000.0,"messages":[]}"#, r#"{"max_tokens":"9","messages":[]}"#, r#"{"max_tokens":-1}"#]
        {
            let r = llm.filter(Some(&spec), &parts(), bytes::Bytes::from(bad));
            assert_eq!(r.err().map(|r| r.status().as_u16()), Some(400), "{bad}");
        }
        // A URL source is a fetch by the provider.
        let url = r#"{"max_tokens":5,"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"url","url":"https://evil.example/x.png"}}]}]}]}"#;
        assert_eq!(llm.filter(Some(&spec), &parts(), bytes::Bytes::from(url)).err().map(|r| r.status().as_u16()), Some(403));
        let b64 = r#"{"max_tokens":5,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA"}}]}]}"#;
        assert!(llm.filter(Some(&spec), &parts(), bytes::Bytes::from(b64)).is_ok());
    }

    /// #113: parallel calls reserve from what is left, so together they can't overshoot.
    /// #152: a node spends its budget slice and nothing more; the next slice is a fraction of the
    /// zone's budget on top of what was counted, never past what is left; the node's counts merge in.
    #[test]
    fn a_node_spends_its_slice_and_nothing_more() {
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{max_requests: 8, max_output_tokens: 1000}"))
            .unwrap();
        assert_eq!(llm.next_slice(0.25), Some(super::Slice { requests: 2, output_tokens: 250, input_tokens: None }));
        llm.set_slice(llm.next_slice(0.25));
        let spec = llm.ctx.zone.llm.clone().unwrap();
        assert!(llm.admit(Some(&spec)).is_none());
        assert!(llm.admit(Some(&spec)).is_none());
        let r = llm.admit(Some(&spec)).expect("the third request is past the slice");
        assert_eq!(r.status(), 429);
        assert_eq!(r.headers()["x-wicket"], "budget");
        // Output is capped by the slice too, in flight included.
        let parts = http::Request::post("/v1/messages").body(()).unwrap().into_parts().0;
        let f =
            llm.filter(Some(&spec), &parts, bytes::Bytes::from_static(br#"{"model":"m","max_tokens":900,"messages":[]}"#)).ok().unwrap();
        assert_eq!(f.reserved, 250);
        llm.settle(f.reserved, Usage { output: 250, ..Usage::default() }, true);
        // Renewed (connected): what was counted plus a quarter, never past the budget.
        assert_eq!(llm.spent().requests, 2, "the refusal spent nothing");
        let next = llm.next_slice(0.25).unwrap();
        assert_eq!((next.requests, next.output_tokens), (2 + 2, 250 + 250));
        llm.merge_spent(super::Spent { requests: 7, output_tokens: 900, ..Default::default() });
        assert_eq!(llm.next_slice(0.25).map(|s| (s.requests, s.output_tokens)), Some((8, 1000)), "never past what is left");
        assert_eq!(llm.spent().requests, 7, "a node's count only raises this one");
        llm.merge_spent(super::Spent { requests: 1, ..Default::default() });
        assert_eq!(llm.spent().requests, 7);
    }

    #[test]
    fn reservations_are_carved_from_what_is_left() {
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{max_output_tokens: 100}")).unwrap();
        assert_eq!(llm.reserve_output(100, 60), Some(60));
        assert_eq!(llm.reserve_output(100, 60), Some(40));
        assert_eq!(llm.reserve_output(100, 1), None);
        assert_eq!(llm.remaining().map(|r| r.1), Some(0), "spawn carve-outs see the reservations");
        llm.settle(60, Usage { output: 10, ..Usage::default() }, true);
        assert_eq!(llm.remaining().map(|r| r.1), Some(50));
        llm.settle(40, Usage { output: 3, ..Usage::default() }, false);
        assert_eq!(llm.output_tokens.load(std::sync::atomic::Ordering::SeqCst), 50, "10 settled, 40 charged in full");
    }

    #[test]
    fn usage_split_across_chunks_is_read() {
        let mut s = super::UsageScanner::default();
        s.feed(b"event: message_delta\ndata: {\"usage\":{\"output_tok");
        s.feed(b"ens\":12");
        s.feed(b"34}}\n\nevent: message_st");
        assert!(!s.stopped);
        s.feed(b"op\ndata: {\"type\":\"message_stop\"}\n\n");
        assert_eq!(s.usage.output, 1234);
        assert!(s.saw_output && s.stopped);
        // Text that merely mentions the event doesn't end the stream.
        let mut t = super::UsageScanner::default();
        t.feed(br#"data: {"delta":{"text":"say \"type\":\"message_stop\" now"}}"#);
        assert!(!t.stopped);
    }

    /// #112: only known fields and client tools reach the provider, unless the zone allows server
    /// tools; bodies that can't be vetted, and endpoints other than messages, are refused.
    #[test]
    fn model_requests_are_filtered_by_allowlist() {
        let parts = |m: &str, path: &str, enc: Option<&str>| {
            let mut b = http::Request::builder().method(m).uri(path);
            if let Some(e) = enc {
                b = b.header("content-encoding", e);
            }
            b.body(()).unwrap().into_parts().0
        };
        let body = br#"{"model":"m","max_tokens":10,"messages":[],"mcp_servers":[{"type":"url","url":"https://evil.example/mcp","name":"x"}],"container":{"skills":[]},"some_future_field":1,
            "tools":[{"name":"a","input_schema":{}},{"type":"custom","name":"b","input_schema":{}},{"type":"bash_20250124","name":"bash"},
                     {"type":"web_search_20260209","name":"web_search"},{"type":"web_fetch_20250910","name":"web_fetch"},{"type":"code_execution_20260521","name":"code_execution"},
                     {"type":"mcp_toolset","mcp_server_name":"x"},{"type":"tool_search_tool_regex_20251119","name":"t"},{"type":"advisor_20260301","name":"adv"},{"type":"some_new_server_tool","name":"n"}]}"#;
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{}")).unwrap();
        let spec = llm.ctx.zone.llm.clone().unwrap();
        let f = llm.filter(Some(&spec), &parts("POST", "/v1/messages?beta=true", None), bytes::Bytes::from_static(body)).ok().unwrap();
        let out: serde_json::Value = serde_json::from_slice(&f.body).unwrap();
        let keys: Vec<&String> = out.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["max_tokens", "messages", "model", "tools"], "{out}");
        let names: Vec<&str> = out["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["a", "b", "bash"]);
        assert!(f.note.contains("stripped 3 request field(s)") && f.note.contains("stripped 7 server-side tool(s)"), "{}", f.note);
        // With server tools allowed, they and their fields go through.
        let mut open = spec.clone();
        open.allow_server_tools = true;
        let f = llm.filter(Some(&open), &parts("POST", "/v1/messages", None), bytes::Bytes::from_static(body)).ok().unwrap();
        let out: serde_json::Value = serde_json::from_slice(&f.body).unwrap();
        assert!(out.get("mcp_servers").is_some() && out["tools"].as_array().unwrap().len() == 10);
        // Refused: unparseable, encoded, a batch, another method.
        for (m, path, enc, b, status) in [
            ("POST", "/v1/messages", None, &b"\x1f\x8b gzip"[..], 400),
            ("POST", "/v1/messages", None, &b"[1]"[..], 400),
            ("POST", "/v1/messages", Some("gzip"), &body[..], 415),
            ("POST", "/v1/messages/batches", None, &body[..], 403),
            ("POST", "/v1/files", None, &b"{}"[..], 403),
            ("PUT", "/v1/messages", None, &body[..], 403),
            ("GET", "/v1/models", None, &b"{}"[..], 400),
        ] {
            let r = llm.filter(Some(&spec), &parts(m, path, enc), bytes::Bytes::copy_from_slice(b));
            assert_eq!(r.err().map(|r| r.status().as_u16()), Some(status), "{m} {path}");
        }
        assert!(llm.filter(Some(&spec), &parts("GET", "/v1/models", None), bytes::Bytes::new()).is_ok());
    }

    #[test]
    fn usage_from_sse_and_json() {
        let sse = b"event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":120,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"usage\":{\"output_tokens\":57}}\n";
        assert_eq!(usage(sse), Usage { input: 120, output: 57, ..Usage::default() });
        assert_eq!(usage(br#"{"usage": {"input_tokens": 9, "output_tokens": 4}}"#), Usage { input: 9, output: 4, ..Usage::default() });
        assert_eq!(usage(b"nothing"), Usage::default());
    }

    /// #28: a long cached conversation reports a handful of uncached input tokens, and the rest as
    /// cache reads. Each field is counted on its own.
    #[test]
    fn cached_input_is_counted() {
        let sse = b"event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":4,\"cache_creation_input_tokens\":1200,\"cache_read_input_tokens\":48000,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"usage\":{\"output_tokens\":310}}\n";
        assert_eq!(usage(sse), Usage { input: 4, cache_read: 48_000, cache_creation: 1_200, output: 310 });
        let json = br#"{"usage": {"cache_read_input_tokens": 7, "input_tokens": 3, "cache_creation_input_tokens": 0, "output_tokens": 2}}"#;
        assert_eq!(usage(json), Usage { input: 3, cache_read: 7, cache_creation: 0, output: 2 });
    }
}
