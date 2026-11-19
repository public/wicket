//! The LLM proxy (design §9.3): holds the zone's model credential (a subscription login, never an API key), strips
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
use std::sync::atomic::Ordering;
use std::sync::Arc;

const MAX_REQUEST_BODY: usize = 32 * 1024 * 1024;
/// How long a response is still read to its end after the agent stopped reading it, so its final
/// usage is seen (#113). Past this, the call is charged its whole reservation.
const DRAIN_AFTER_DISCONNECT: std::time::Duration = std::time::Duration::from_secs(600);
/// How long a model call waits for its secret to become readable again (#350): one refresh's worth
/// (a harness rewriting its login file, or its secret helper restarting), then it fails, naming the
/// secret and the cause.
pub const SECRET_PATIENCE: std::time::Duration = std::time::Duration::from_secs(3);

/// How long a call refused with a 401 waits for its secret to change before the 401 goes to the box
/// (#552). A login refresh revokes the old access token when the new one is issued, and its owner
/// writes the new one a moment later: read once at once, the secret is often still the old value.
#[cfg(not(test))]
pub const RELOGIN_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
/// In tests, shorter: the race tests write the new token well within it.
#[cfg(test)]
pub const RELOGIN_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// How often, while waiting, the secret is read again.
const RELOGIN_POLL: std::time::Duration = std::time::Duration::from_millis(250);
/// What a refusal for an unreadable model secret suggests.
const SECRET_UNAVAILABLE_FIX: &str =
    "On the host, `wicket doctor` checks every secret; a login linked from a file wicket can't read can be served by `wicket secret serve` \
     (docs/how-to/store-and-link-secrets.md)";

pub struct Llm {
    ctx: RunCtx,
    client: reqwest::Client,
    /// What this run has counted, carved out for its children, and spent in earlier activations
    /// (#70, #152, #256): shared by its calls, its spawns' carve-outs and its node's reports.
    pub count: Counter,
    /// On a node (#152): the slice of the budget the control host has sent it, as caps on this
    /// activation's own counters. None: no slice (the zone's budget alone bounds it).
    slice: std::sync::Mutex<Option<Slice>>,
    /// The model budget this proxy enforces (#256): on the control host, the amounts of the run's
    /// quota grants ([`Llm::with_quota`]); on a node, the zone its token carries, its slices
    /// bounding it. None: the zone has no model route.
    quota: Option<ModelQuota>,
    /// When the box's first request reached this proxy (Unix ms, #287).
    first_request_ms: std::sync::OnceLock<i64>,
    /// Told [`Llm::spent_charged`] as each call is sent upstream ([`Llm::set_journal`]).
    journal: std::sync::Mutex<Option<Journal>>,
}

/// Where a node writes its count before a call goes upstream ([`Llm::set_journal`]).
type Journal = Box<dyn Fn(Spent) + Send + Sync>;

use wicket_core::budget::Counter;
pub use wicket_core::budget::{ModelQuota, Slice, Spent};

impl Llm {
    /// Model requests and output tokens this run has left to spend or hand on.
    pub fn remaining(&self) -> Option<(u64, u64)> {
        Some(self.count.counts().remaining(self.quota()?))
    }

    /// Output tokens spent, handed to children, spent by earlier activations, or reserved by calls
    /// in flight: what is no longer available to a new call.
    fn output_committed(&self) -> u64 {
        self.count.counts().output_committed()
    }

    /// Reserves up to `want` output tokens for one call, atomically (parallel calls, and a spawn's
    /// carve-out, can't each claim the same tokens): what is left, if less. None when nothing is left.
    fn reserve_output(&self, max: u64, want: u64) -> Option<u64> {
        self.count.reserve_output(max, want)
    }

    /// Settles a call's reservation: releases it and charges what the call used. A call whose final
    /// usage wasn't seen is charged its whole reservation (or what was seen, if more).
    fn settle(&self, reserved: u64, u: Usage, settled: bool) {
        self.count.settle(reserved, u.input, u.cache_read, u.cache_creation, if settled { u.output } else { u.output.max(reserved) });
    }

    /// Every input token this run's model calls used: uncached, cache reads and cache writes.
    pub fn input_total(&self) -> u64 {
        self.count.input_total()
    }

    /// Input tokens this run has left to spend or hand on, if its zone caps them.
    pub fn remaining_input(&self) -> Option<u64> {
        self.count.counts().remaining_input(self.quota()?)
    }

    /// The model budget this proxy enforces: see [`ModelQuota`].
    pub fn quota(&self) -> Option<ModelQuota> {
        self.quota
    }

    /// A model proxy enforcing its zone's budget: a node's, whose slices bound it.
    pub fn new(ctx: RunCtx) -> Result<Arc<Llm>> {
        let quota = ctx.zone.llm.as_ref().map(ModelQuota::of_zone);
        Self::with_quota(ctx, quota)
    }

    /// A model proxy enforcing `quota` (#256): the control host's, from the run's quota grants. A
    /// zone with a model route and no quota is given none to spend.
    pub fn with_quota(ctx: RunCtx, quota: Option<ModelQuota>) -> Result<Arc<Llm>> {
        let quota = ctx.zone.llm.as_ref().map(|_| quota.unwrap_or_default());
        // As the egress proxy's (#116): the model route's host is resolved by wicket and dialled
        // only at checked, public addresses, and a connection that doesn't come up in 15 s fails.
        // An address the zone names itself (`http://127.0.0.1:…`, the tests' local models) is the
        // operator's choice and isn't resolved, so isn't checked.
        let lookup = crate::dial::Lookup { fixed: Arc::default(), own: None };
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(15))
            .dns_resolver(Arc::new(crate::dial::PublicResolver(lookup)))
            .build()?;
        Ok(Arc::new(Llm {
            ctx,
            client,
            count: Counter::default(),
            slice: std::sync::Mutex::new(None),
            quota,
            first_request_ms: std::sync::OnceLock::new(),
            journal: std::sync::Mutex::new(None),
        }))
    }

    /// What this activation has counted itself.
    pub fn spent(&self) -> Spent {
        self.count.spent()
    }

    /// What this activation has counted, with the output tokens reserved by calls in flight charged
    /// in full: what a node persists (#324). A call in flight when the node's `serve` crashes was
    /// billed upstream and is never settled here, so a restarted node counts it as a call whose
    /// final usage wasn't seen is counted: its whole reservation.
    pub fn spent_charged(&self) -> Spent {
        self.count.spent_charged()
    }

    /// Has `f` told [`Llm::spent_charged`] as each model call is sent, before it goes upstream:
    /// a node persists it there, so a crash can't lose a call the provider bills (#324).
    pub fn set_journal(&self, f: impl Fn(Spent) + Send + Sync + 'static) {
        *self.journal.lock().expect("journal") = Some(Box::new(f));
    }

    /// Tells the journal [`Llm::spent_charged`] now. The count is read under the journal's lock,
    /// so of two calls the later write is never the older count.
    pub fn journal(&self) {
        if let Some(f) = &*self.journal.lock().expect("journal") {
            f(self.spent_charged());
        }
    }

    /// Takes in what another counter of this activation has seen (#152): the run's node, which
    /// calls the model itself and is the counter of record. Counters only go up.
    pub fn merge_spent(&self, s: Spent) {
        self.count.merge_spent(s);
    }

    /// The budget slice sent to this node (#152).
    pub fn set_slice(&self, s: Option<Slice>) {
        *self.slice.lock().expect("slice") = s;
    }

    pub fn slice(&self) -> Option<Slice> {
        *self.slice.lock().expect("slice")
    }

    /// The slice this activation's node may be sent next (#152): what it has counted plus `fraction` of
    /// the zone's budget, never past what is left of it.
    pub fn next_slice(&self, fraction: f64) -> Option<Slice> {
        Some(self.count.next_slice(self.quota()?, fraction))
    }

    /// Starts this activation from what the agent's earlier ones spent (#70).
    pub fn spent_before(&self, requests: u64, input_tokens: u64, output_tokens: u64) {
        self.count.prior_requests.store(requests, Ordering::SeqCst);
        self.count.prior_input_tokens.store(input_tokens, Ordering::SeqCst);
        self.count.prior_output_tokens.store(output_tokens, Ordering::SeqCst);
    }

    /// What counts against the zone's budget so far, over the agent's life: (requests, input tokens
    /// with cached ones, output tokens). Budget handed to children counts as spent.
    pub fn spent_total(&self) -> (u64, u64, u64) {
        let c = self.count.counts();
        (
            c.requests_committed(),
            c.input_committed(),
            c.output_tokens.saturating_add(c.reserved_output_tokens).saturating_add(c.prior_output_tokens),
        )
    }

    /// How the budget is described: per run, or (for a woken agent) over its life.
    fn whose(&self) -> &'static str {
        if self.count.prior_requests.load(Ordering::SeqCst) + self.count.prior_output_tokens.load(Ordering::SeqCst) > 0 {
            "this agent, over all its activations,"
        } else {
            "this run"
        }
    }

    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        let listener = crate::sockpath::listen(socket)?;
        self.serve_on(listener).await
    }

    /// As [`Self::serve`], on a socket already listening ([`crate::sockpath::listen`]): its
    /// caller knows it is ready the moment it is bound, with no wait for it to appear (#287).
    pub async fn serve_on(self: Arc<Self>, listener: tokio::net::UnixListener) -> Result<()> {
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

    /// When the box's first request reached this proxy (Unix ms), if one has (#287).
    pub fn first_request_ms(&self) -> Option<i64> {
        self.first_request_ms.get().copied()
    }

    /// The zone's model provider's profile, if it has a model route wicket has a profile for.
    fn profile(&self) -> Option<&'static crate::provider::Profile> {
        self.ctx.zone.llm.as_ref().and_then(|l| crate::provider::profile(&l.provider))
    }

    /// Whether `host` is one of this run's model hosts: its provider's API host, or its route's
    /// upstream.
    pub(crate) fn is_model_host(&self, host: &str) -> bool {
        let upstream = self.ctx.zone.llm.as_ref().and_then(|l| reqwest::Url::parse(&l.upstream).ok());
        self.profile().is_some_and(|p| p.host.eq_ignore_ascii_case(host))
            || upstream.as_ref().and_then(|u| u.host_str()).is_some_and(|h| h.eq_ignore_ascii_case(host))
    }

    /// Whether a request to a model host is a model call, vetted and accounted as one, when it
    /// arrives at the egress proxy (a wrapped session's).
    pub(crate) fn is_model_call(&self, host: &str, path: &str) -> bool {
        self.is_model_host(host) && self.profile().is_some_and(|p| (p.model_call)(path))
    }

    async fn handle(self: Arc<Self>, req: Request<Incoming>) -> Response<BoxBody> {
        let Some(spec) = self.ctx.zone.llm.as_ref() else {
            return problem(404, "no-model", "No model", "this zone has no model route", None);
        };
        if crate::provider::profile(&spec.provider).is_none() {
            return problem(404, "no-model", "No model", &format!("no provider profile for {:?}", spec.provider), None);
        }
        // A stale activation (#70). The egress proxy refuses one for its whole tunnel, before a
        // wrapped session's call reaches its gate (`route_parity.rs`'s INTENDED).
        if let Some(why) = self.ctx.superseded() {
            self.event(None, 409, Usage::default(), "stale generation");
            return problem(409, "stale-generation", "This activation is stale", &why, None);
        }
        let pq = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        self.call(ModelRoute::Direct, pq, req).await
    }

    /// Counts a model request and checks the budgets before it is sent: None if it may go, else the
    /// refusal. Without a model route (a wrapped session's zone may have none), only counts.
    fn admit(&self, spec: Option<&wicket_core::manifest::LlmSpec>) -> Option<Response<BoxBody>> {
        // A node's slice (#152), before counting: a refusal here spends nothing, so a box retrying
        // against a spent slice offline doesn't burn its budget.
        if let (Some(_), Some(sl)) = (spec, self.slice()) {
            let over = if self.count.requests.load(Ordering::SeqCst) >= sl.requests {
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
                    "this node has spent the slice of the model budget it was sent; the control host sends more when it can be reached. Retry later",
                    None,
                ));
            }
        }
        let n = self.count.admit_request();
        spec?;
        let spec = self.quota()?;
        if n > spec.requests {
            self.event(None, 429, Usage::default(), "budget: request cap reached");
            return Some(problem(
                429,
                "budget",
                "Model request budget exhausted",
                &format!("{} may make at most {} model requests", self.whose(), spec.requests),
                None,
            ));
        }
        if self.output_committed() >= spec.output_tokens {
            self.event(None, 429, Usage::default(), "budget: output token cap reached");
            return Some(problem(
                429,
                "budget",
                "Model token budget exhausted",
                &format!("{} may generate at most {} output tokens", self.whose(), spec.output_tokens),
                None,
            ));
        }
        if let (Some(max), Some(0)) = (spec.input_tokens, self.remaining_input()) {
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
            provider: self.ctx.zone.llm.as_ref().map(|l| l.provider.clone()),
            model,
            status,
            input_tokens: u.input,
            cached_tokens: u.cache_read + u.cache_creation,
            output_tokens: u.output,
            requests: self.count.requests.load(Ordering::SeqCst),
            outcome: outcome.into(),
        });
    }

    /// The one model call, whichever route it came by (#552): the provider's routes, the budgets,
    /// the body and its filter, the reservation, the credential (fetched to a node, #152, and read
    /// patiently, #350), the send on a task of its own (settled by what the provider answers,
    /// whether or not the box still waits, #422), a 401's wait for a refreshed login and one
    /// retry (#360), the answer's credential checks (#362), and the accounting. Only where the
    /// call goes and how its credential is attached differ by route ([`ModelRoute`]), so the two
    /// can't drift apart (`route_parity.rs`).
    pub(crate) async fn call<B>(self: &Arc<Self>, route: ModelRoute, pq: String, req: Request<B>) -> Response<BoxBody>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.first_request_ms
            .get_or_init(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0));
        if let Some(profile) = self.profile() {
            if let Err(why) = profile.allowed_route(req.method().as_str(), &pq) {
                self.event(None, 404, Usage::default(), &format!("refused route: {why}"));
                return problem(404, "route", "Not a model route", &why, None);
            }
        }
        let spec = self.ctx.zone.llm.as_ref();
        if let Some(r) = self.admit(spec) {
            return r;
        }
        let (parts, body) = req.into_parts();
        let body = match Limited::new(body, MAX_REQUEST_BODY).collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => {
                self.event(None, 400, Usage::default(), &format!("refused: request body: {e}"));
                return problem(400, "bad-request", "Bad model request", &format!("request body: {e}"), None);
            }
        };
        let Filtered { body, model, note, reserved } = match self.filter(spec, &parts, body) {
            Ok(f) => f,
            Err(r) => return *r,
        };
        // From here the reservation is held by `held`: a box that gives up on the call before it is
        // sent (its client times out while the credential is fetched, #422) drops this future, and
        // the drop gives the reservation back instead of leaving it counted for good.
        let held = Reservation::new(self, reserved);
        self.journal();
        let head = Head { method: parts.method, uri: parts.uri, version: parts.version, headers: parts.headers, pq };
        let host = route.host(self);
        // The credential this route attaches: on a node fetched from the control host on first use
        // (#152), and read patiently (a linked login's owner may be rewriting its file, #350).
        let secret = route.secret(self, &head.headers);
        let mut token = None;
        if let Some(name) = &secret {
            if let Err(e) = self.ctx.vault.ensure(name).await {
                drop(held);
                self.event(model, 503, Usage::default(), "credential unavailable on this node");
                return problem(503, "credential", "Model credential unavailable on this node", &format!("{e:#}"), None);
            }
            match self.ctx.vault.get_for_patiently(name, &host, SECRET_PATIENCE).await {
                Ok(t) => token = Some(t),
                Err(e) if e.downcast_ref::<crate::vault::SecretUnavailable>().is_some() => {
                    drop(held);
                    self.event(model, 503, Usage::default(), &format!("model secret unavailable: {e}"));
                    return problem(503, "secret-unavailable", "Model secret unavailable", &format!("{e}. {SECRET_UNAVAILABLE_FIX}"), None);
                }
                Err(e) => {
                    drop(held);
                    self.event(model, 502, Usage::default(), &format!("upstream error: {e:#}"));
                    return problem(502, "upstream", "Model upstream error", &format!("{e:#}"), None);
                }
            }
        }
        // Sent upstream on a task of its own: once the call may reach the provider it is settled by
        // what the provider answers (`account`, which reads the answer to its end), whether or not
        // the box still waits for it.
        let me = self.clone();
        let call = tokio::spawn(async move {
            let reserved = held.take();
            let mut note = note;
            let first = route.send(&me, &head, body.clone(), token.as_deref()).await;
            // The upstream refused the credential (401): a login refreshed by its owner while the
            // call was out revokes the old token (#360), and its new one is written a moment later
            // (#552). Wait for the secret to change and send the call once more with the new value;
            // an unchanged one is a real revocation, passed on. Nothing of the first answer has
            // reached the box yet, so it sees one call either way.
            let sent = match (first, &secret, &token) {
                (Ok(resp), Some(name), Some(old)) if resp.status() == StatusCode::UNAUTHORIZED => {
                    match Self::changed_secret(&me.ctx.vault, name, &host, old).await {
                        Ok(Some(fresh)) => {
                            drop(resp);
                            me.event(
                                model.clone(),
                                401,
                                Usage::default(),
                                &format!("upstream refused the credential (401); secret {name:?} has changed since it was read: retrying once with its new value"),
                            );
                            note.push_str(&format!("; retried once after a 401 with the new value of secret {name:?}"));
                            route.send(&me, &head, body, Some(&fresh)).await
                        }
                        Ok(None) => {
                            note.push_str(&format!(
                                "; upstream refused the credential (401); secret {name:?} read again for {}s is unchanged: not retried",
                                RELOGIN_WAIT.as_secs()
                            ));
                            Ok(resp)
                        }
                        Err(e) => {
                            note.push_str(&format!(
                                "; upstream refused the credential (401); secret {name:?} could not be read again ({e:#}): not retried"
                            ));
                            Ok(resp)
                        }
                    }
                }
                (sent, ..) => sent,
            };
            match sent {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let sse = resp
                        .headers()
                        .get(http::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| v.starts_with("text/event-stream"));
                    // An upstream that encodes anyway: its usage can't be read, so say why it is charged.
                    if let Some(enc) =
                        resp.headers().get(http::header::CONTENT_ENCODING).filter(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
                    {
                        note.push_str(&format!("; response Content-Encoding {}", String::from_utf8_lossy(enc.as_bytes())));
                    }
                    let (head, body) = resp.into_parts();
                    Response::from_parts(head, me.account(model, status, sse, body.into_data_stream(), reserved, note))
                }
                Err(e) => {
                    me.settle(reserved, Usage::default(), true);
                    if let Some(r) = crate::egress::tripped_response(&e) {
                        me.event(model, 403, Usage::default(), &format!("{e}"));
                        return r;
                    }
                    me.event(model, 502, Usage::default(), &format!("upstream error: {e:#}"));
                    problem(502, "upstream", "Model upstream error", &format!("{e:#}"), None)
                }
            }
        });
        call.await.unwrap_or_else(|e| problem(502, "upstream", "Model upstream error", &format!("the model call's task: {e}"), None))
    }

    /// Reads secret `name` again from its source until its value is no longer `old`, for up to
    /// [`RELOGIN_WAIT`] (#552: a login refresh revokes the old token before its owner writes the new
    /// one). `Ok(Some(new))` if it changed, `Ok(None)` if it stayed `old` (a real revocation).
    async fn changed_secret(vault: &crate::vault::Vault, name: &str, host: &str, old: &str) -> Result<Option<String>> {
        let deadline = tokio::time::Instant::now() + RELOGIN_WAIT;
        loop {
            vault.refetch(name).await?;
            let now = vault.get_for_patiently(name, host, SECRET_PATIENCE).await?;
            if now != old {
                return Ok(Some(now));
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep(RELOGIN_POLL).await;
        }
    }

    async fn send_upstream(
        &self,
        spec: &wicket_core::manifest::LlmSpec,
        parts: &http::request::Parts,
        body: Bytes,
        token: &str,
    ) -> Result<reqwest::Response> {
        let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let url = format!("{}{}", spec.upstream.trim_end_matches('/'), pq);
        let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?;
        let mut rb = self.client.request(method, &url);
        // Allow-listed headers only (#112, as on the egress proxy): never a client credential.
        for (name, value) in parts.headers.iter() {
            let n = name.as_str();
            if n != "accept-encoding" && (FORWARD_REQUEST.contains(&n) || self.profile().is_some_and(|p| (p.request_header)(n))) {
                rb = rb.header(n, value.as_bytes());
            }
        }
        // The real credential, attached as the provider's profile says (the one slot it uses).
        // Only to an upstream the secret is bound to ([`Llm::call`] read it
        // for this host), whatever the zone's `upstream` says.
        let profile =
            crate::provider::profile(&spec.provider).ok_or_else(|| anyhow::anyhow!("no provider profile for {:?}", spec.provider))?;
        rb = (profile.attach)(rb, token).header("accept-encoding", "identity");
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
            Box::new(problem(status, "forbidden", "Blocked by wicket: model request refused", &format!("{why}. {}", crate::BOX_FACT), None))
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
        // The zone's model list (#366): a call naming another model, or none, never goes upstream.
        if let Some(allowed) = spec.and_then(|s| s.models.as_ref().map(|ms| (s, ms))) {
            let (s, ms) = allowed;
            let list = if ms.is_empty() { "none".to_string() } else { ms.join(", ") };
            match model.as_deref() {
                Some(m) if s.allows_model(m) => {}
                Some(m) => return Err(refuse(403, format!("model {m:?} is not one this zone allows (allowed: {list})"))),
                None => return Err(refuse(403, format!("a model call that names no model: this zone allows only {list}"))),
            }
        }
        let mut notes = Vec::new();
        // Stripped fields and tools are named (#307), by their names and types only, never their values.
        let mut stripped = Vec::new();
        json.retain(|k, _| {
            let keep = REQUEST_FIELDS.contains(&k.as_str()) || (server_ok && SERVER_FIELDS.contains(&k.as_str()));
            if !keep {
                stripped.push(k.clone());
            }
            keep
        });
        if !stripped.is_empty() {
            notes.push(format!("stripped {} request field(s): {}", stripped.len(), named(stripped)));
        }
        if !server_ok {
            if let Some(tools) = json.get_mut("tools").and_then(|t| t.as_array_mut()) {
                let mut types = Vec::new();
                tools.retain(|t| {
                    let ty = t.get("type").and_then(|v| v.as_str());
                    let keep = client_tool(ty);
                    if !keep {
                        types.push(ty.unwrap_or("?").to_string());
                    }
                    keep
                });
                if !types.is_empty() {
                    notes.push(format!("stripped {} server-side tool(s): {}", types.len(), named(types)));
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
            if let (Some(_), Some(q)) = (spec, self.quota()) {
                // A node's slice (#152) caps this activation's own output, in flight included.
                let cap = match self.slice() {
                    Some(sl) => {
                        let c = self.count.counts();
                        q.output_tokens.min(sl.output_tokens.saturating_add(c.reserved_output_tokens).saturating_add(c.prior_output_tokens))
                    }
                    None => q.output_tokens,
                };
                let Some(r) = self.reserve_output(cap, asked) else {
                    self.event(model.clone(), 429, Usage::default(), "budget: output token cap reached");
                    return Err(Box::new(problem(
                        429,
                        "budget",
                        "Model token budget exhausted",
                        &format!("{} may generate at most {} output tokens", self.whose(), q.output_tokens),
                        None,
                    )));
                };
                if r < asked {
                    // Extended thinking's budget counts within max_tokens and must stay below it (and
                    // at or above the provider's minimum), or the lowered request is refused upstream
                    // (#310): lower it with max_tokens, or refuse here when no valid request fits.
                    if let Some(thinking) = json.get_mut("thinking").and_then(|t| t.as_object_mut()) {
                        let enabled = thinking.get("type").and_then(|t| t.as_str()) == Some("enabled");
                        if let Some(budget) = thinking.get("budget_tokens").and_then(|b| b.as_u64()).filter(|b| enabled && *b >= r) {
                            if r <= THINKING_MIN_BUDGET {
                                self.settle(r, Usage::default(), true);
                                let why = format!(
                                    "budget left: {r} output tokens, too few for this request's extended thinking (thinking.budget_tokens {budget}; it must be at least {THINKING_MIN_BUDGET} and below max_tokens)"
                                );
                                self.event(model.clone(), 429, Usage::default(), &format!("budget: {why}"));
                                return Err(Box::new(problem(
                                    429,
                                    "budget",
                                    "Model token budget too low for this request",
                                    &format!(
                                        "{why}. Send it without extended thinking or with a smaller max_tokens, or ask for more budget. {}",
                                        crate::BOX_FACT
                                    ),
                                    None,
                                )));
                            }
                            thinking.insert("budget_tokens".into(), (r - 1).into());
                            notes.push(format!("thinking.budget_tokens {budget} lowered to {}", r - 1));
                        }
                    }
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
        egress: Arc<crate::egress::Egress>,
        req: Request<B>,
        host: &str,
        pq: &str,
        via: crate::egress::Via,
    ) -> Response<BoxBody>
    where
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.call(ModelRoute::Through { egress, host: host.to_string(), pq: pq.to_string(), via }, pq.to_string(), req).await
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

/// A call's output reservation (#113) until its call is sent: settled by whoever takes it
/// ([`Reservation::take`], the call's task). Dropped untaken, the call was given up on before it
/// went (the box's client went away, #422): its reservation is given back, uncharged. Once sent, a
/// call runs on its own task and is settled by what the provider answers, on either route (#552).
struct Reservation {
    llm: Arc<Llm>,
    tokens: u64,
}

impl Reservation {
    fn new(llm: &Arc<Llm>, tokens: u64) -> Reservation {
        Reservation { llm: llm.clone(), tokens }
    }

    /// Hands the reservation to the caller, who settles it.
    fn take(mut self) -> u64 {
        std::mem::take(&mut self.tokens)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.tokens == 0 {
            return;
        }
        self.llm.count.settle(self.tokens, 0, 0, 0, 0);
        self.llm.journal();
    }
}

/// The provider's smallest `thinking.budget_tokens` (Anthropic's Messages API): a request lowered
/// to fit the budget keeps its thinking budget at least this and below its `max_tokens` (#310).
const THINKING_MIN_BUDGET: u64 = 1024;

/// The only model endpoints that take a request body (#112). Batches, files and anything else are
/// refused: a batch carries requests (and tools) of its own.
const MODEL_ENDPOINTS: &[&str] = &["/v1/messages", "/v1/messages/count_tokens"];

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
    // Prompt-cache diagnosis (#307), sent with the `cache-diagnosis-2026-04-07` beta:
    // `{"previous_message_id": "msg_…" | null}`, the id of this conversation's previous response,
    // so the provider can say why the prompt cache missed (`diagnostics` on the response). It
    // names a message only: nothing runs on the provider's side and nothing is fetched. Claude
    // Code sends it when the base URL counts as first party, as in driven Remote Control mode,
    // and the provider refuses the request with 400 when the beta comes without it.
    "diagnostics",
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

/// How many stripped names a note lists, and how much of each it keeps.
const NAMED_MAX: usize = 4;
const NAME_MAX_CHARS: usize = 32;

/// The names of stripped fields or tool types for a note (#307): distinct, sorted, each clipped and
/// kept printable (they come from the agent), at most [`NAMED_MAX`] of them, then "…".
fn named(mut names: Vec<String>) -> String {
    for n in names.iter_mut() {
        let clean: String = n.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
        *n = if clean.chars().count() > NAME_MAX_CHARS {
            format!("{}…", clean.chars().take(NAME_MAX_CHARS).collect::<String>())
        } else {
            clean
        };
    }
    names.sort();
    names.dedup();
    let more = names.len() > NAMED_MAX;
    names.truncate(NAMED_MAX);
    let mut out = names.join(", ");
    if more {
        out.push_str(", …");
    }
    out
}

/// A model call's request line and headers, kept for its attempts (one, or two after a 401).
struct Head {
    method: http::Method,
    uri: http::Uri,
    version: http::Version,
    headers: http::HeaderMap,
    /// Its path and query, as the box sent them.
    pq: String,
}

/// How one attempt of a model call reaches its upstream: all that differs between the two routes
/// a model call takes (#552). Everything else is [`Llm::call`]'s.
pub(crate) enum ModelRoute {
    /// The model proxy's own socket: the route's upstream, the zone's model secret attached by the
    /// provider's profile, sent with this proxy's client.
    Direct,
    /// A wrapped session's call, through the egress proxy's gate (#112): the host the box named,
    /// the run's swap or inject rule, and the egress proxy's dialer (`route_parity.rs`'s
    /// INTENDED_UNTESTED).
    Through { egress: Arc<crate::egress::Egress>, host: String, pq: String, via: crate::egress::Via },
}

impl ModelRoute {
    /// The host the call goes to: what a secret's host binding is checked against.
    fn host(&self, llm: &Llm) -> String {
        match self {
            ModelRoute::Direct => llm
                .ctx
                .zone
                .llm
                .as_ref()
                .and_then(|s| reqwest::Url::parse(&s.upstream).ok())
                .and_then(|u| u.host_str().map(String::from))
                .unwrap_or_default(),
            ModelRoute::Through { host, .. } => host.clone(),
        }
    }

    /// The vault secret this route attaches to the call, if any.
    fn secret(&self, llm: &Llm, headers: &http::HeaderMap) -> Option<String> {
        match self {
            ModelRoute::Direct => llm.ctx.zone.llm.as_ref().map(|s| s.secret.clone()),
            ModelRoute::Through { egress, host, .. } => egress.credential_secret(host, headers),
        }
    }

    /// Sends one attempt, with `token` (the secret's value read for it), and answers what the box
    /// may see: the answer's credential checks (#362) applied on both routes.
    async fn send(&self, llm: &Llm, head: &Head, body: Bytes, token: Option<&str>) -> Result<Response<BoxBody>> {
        match self {
            ModelRoute::Direct => {
                let spec = llm.ctx.zone.llm.as_ref().ok_or_else(|| anyhow::anyhow!("this zone has no model route"))?;
                let host = self.host(llm);
                // The tripwire (#362): a placeholder of this run's anywhere in the URL or a header
                // the model proxy would forward. (The box's Authorization isn't forwarded here: the
                // proxy attaches the zone's secret.) The egress proxy runs it in its own forwarding.
                let scan = crate::egress::CanaryScanner::placeholders(llm.ctx.swaps.iter().map(|s| s.placeholder.as_str()));
                let mut seen = head.headers.clone();
                seen.remove(http::header::AUTHORIZATION);
                if let Some(what) = crate::egress::placeholder_moved(&llm.ctx, &scan, &seen, &host, &head.pq) {
                    crate::egress::anomaly(&llm.ctx, &host, "placeholder.moved", &what);
                    return Err(crate::egress::Tripped { what, note: String::new() }.into());
                }
                let token = token.ok_or_else(|| anyhow::anyhow!("no model secret to send"))?;
                let mut b = Request::builder().method(head.method.clone()).uri(head.uri.clone()).version(head.version);
                if let Some(h) = b.headers_mut() {
                    *h = head.headers.clone();
                }
                let (parts, ()) = b.body(())?.into_parts();
                let r = llm.send_upstream(spec, &parts, body, token).await?;
                let mut out = Response::builder().status(StatusCode::from_u16(r.status().as_u16())?);
                for (name, value) in r.headers().iter() {
                    if !STRIP_RESPONSE.contains(&name.as_str()) {
                        out = out.header(name.as_str(), value.as_bytes());
                    }
                }
                let stream = r
                    .bytes_stream()
                    .map(|c| c.map(hyper::body::Frame::data).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>));
                let resp = out.body(BodyExt::boxed(http_body_util::StreamBody::new(stream)))?;
                Ok(crate::egress::guard_credential(&llm.ctx, resp, &host, &head.method, &[token.to_string()]))
            }
            ModelRoute::Through { egress, host, pq, via } => {
                // The body may have been rewritten (fields stripped, max_tokens lowered): its own
                // length goes up, not the one the box declared. And the answer is asked for
                // unencoded, so its usage can be read as it streams past (#310) and it can be
                // checked for the credential (#362). The egress proxy swaps the credential in.
                let mut b = Request::builder().method(head.method.clone()).uri(head.uri.clone()).version(head.version);
                if let Some(h) = b.headers_mut() {
                    *h = head.headers.clone();
                    h.insert(http::header::CONTENT_LENGTH, body.len().into());
                    h.insert(http::header::ACCEPT_ENCODING, http::HeaderValue::from_static("identity"));
                }
                egress.forward(b.body(http_body_util::Full::new(body))?, host, "https", pq, *via).await
            }
        }
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

/// Anthropic's usage fields in a response body (the Anthropic profile's [`crate::provider::Profile::usage`]):
/// best-effort, from a Messages response streamed (SSE) or not, the largest value seen for each
/// field (streamed counts are cumulative). The keys include their opening quote, so
/// `"input_tokens":` doesn't also match `"cache_read_input_tokens":`.
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

/// The deterministic simulation's seam (#324, `wicket-sim`): one model call through this proxy's
/// own checks and accounting, without HTTP or an upstream. [`Llm::sim_begin`] is what
/// [`Llm::handle`] does before it sends a call (the slice and budget checks of `admit`, then
/// `filter`'s reservation of `max_tokens`); [`Llm::sim_settle`] is what the call's end does
/// (`settle`). Built only with the `sim` feature.
#[cfg(feature = "sim")]
impl Llm {
    /// Admits a `POST /v1/messages` asking for `max_tokens`: the output tokens reserved for it
    /// (possibly lowered to what is left), or the status it is refused with (429 for a budget).
    pub fn sim_begin(&self, max_tokens: u64) -> std::result::Result<u64, u16> {
        let spec = self.ctx.zone.llm.as_ref();
        if let Some(r) = self.admit(spec) {
            return Err(r.status().as_u16());
        }
        let (parts, ()) = Request::post("/v1/messages").body(()).expect("a static request").into_parts();
        let body = serde_json::json!({"model": "sim", "max_tokens": max_tokens, "messages": []});
        match self.filter(spec, &parts, Bytes::from(body.to_string())) {
            Ok(f) => {
                self.journal();
                Ok(f.reserved)
            }
            Err(r) => Err(r.status().as_u16()),
        }
    }

    /// Settles a call [`Llm::sim_begin`] admitted with `reserved`: charged `output` and `input`
    /// tokens if its final usage was seen (`settled`), else its whole reservation.
    pub fn sim_settle(&self, reserved: u64, input: u64, output: u64, settled: bool) {
        self.settle(reserved, Usage { input, output, ..Default::default() }, settled);
    }
}

#[cfg(test)]
mod tests {
    use super::{usage, Usage};

    /// A run context for zone `z` (with a model route), fenced as `fence` if given.
    fn ctx(ledger: wicket_store::Ledger, fence: Option<crate::Fence>, llm: &str) -> crate::RunCtx {
        use std::sync::{Arc, Mutex};
        let mut m = wicket_core::Manifest::from_yaml(&format!("task: t\nagent: {{name: a}}\nzone: {{name: z, llm: {llm}}}")).unwrap();
        crate::provider::fill_test_route(&mut m);
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        crate::RunCtx {
            tenant: wicket_core::TenantId::single(),
            run: wicket_core::RunId("run_old".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(m.zone.clone()).unwrap()),
            org: None,
            ledger: Arc::new(Mutex::new(ledger)),
            vault: crate::vault::Vault::new(std::env::temp_dir().join("wicket-llm-no-vault")),
            events: tx,
            escalate: true,
            attribute: None,
            identity: None,
            swaps: vec![],
            boxes: None,
            capacity: None,
            decisions: None,
            fence,
            waker: None,
            lifecycle: None,
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
                claim_until: 0,
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

    /// The box's first request is timed as it arrives (#287), whatever becomes of it, and later
    /// ones don't move it.
    #[tokio::test]
    async fn the_first_request_is_timed_when_it_arrives() {
        let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{secret: model}")).unwrap();
        assert_eq!(llm.first_request_ms(), None, "no request yet");
        let before = now();
        send(llm.clone(), "first-1", "GET", "/not-a-model-route").await;
        let first = llm.first_request_ms().expect("timed");
        assert!(first >= before && first <= now(), "{first} not within the request");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        send(llm.clone(), "first-2", "GET", "/not-a-model-route").await;
        assert_eq!(llm.first_request_ms(), Some(first), "only the first counts");
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

    /// As egress (#116): a model route's host is resolved by wicket and dialled only at public
    /// addresses, so a name that resolves to loopback is refused before anything is sent; an
    /// address the zone names itself is the operator's choice, and is dialled.
    #[tokio::test]
    async fn a_model_route_by_name_reaches_only_public_addresses() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                seen2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = vec![0u8; 8192];
                let _ = c.read(&mut buf).await;
                let _ = c
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                    .await;
            }
        });
        let dir = std::env::temp_dir().join(format!("wicket-llm-public-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = crate::vault::Vault::new(dir.clone());
        vault.set("model", "the-model-token").unwrap();
        vault.set_hosts("model", &["localhost".into(), "127.0.0.1".into()]).unwrap();
        let named = format!("{{secret: model, upstream: 'http://localhost:{port}'}}");
        let mut c = ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &named);
        c.vault = vault.clone();
        let (status, _) = post(super::Llm::new(c).unwrap(), "public-named").await;
        assert!(status >= 500, "{status}");
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing was dialled");
        let literal = format!("{{secret: model, upstream: 'http://127.0.0.1:{port}'}}");
        let mut c = ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &literal);
        c.vault = vault;
        let (status, _) = post(super::Llm::new(c).unwrap(), "public-literal").await;
        assert_eq!(status, 200);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A model secret that can't be read (#350): the call waits a refresh's worth for it, then fails
    /// with a 503 naming the secret and the cause, and the upstream sees nothing. Readable again in
    /// time, the call goes through.
    #[tokio::test]
    async fn an_unreadable_model_secret_is_retried_then_named() {
        use std::os::unix::fs::PermissionsExt;
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
                let _ = c
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                    .await;
            }
        });
        let dir = std::env::temp_dir().join(format!("wicket-llm-secret-retry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let creds = dir.join("creds.json");
        let write = |p: &std::path::Path, t: &str| {
            std::fs::write(p, format!(r#"{{"o":{{"accessToken":"{t}"}}}}"#)).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write(&creds, "tok-1");
        let vault = crate::vault::Vault::new(dir.join("vault"));
        vault.link("model", creds.to_str().unwrap(), Some("/o/accessToken"), None, None).unwrap();
        vault.set_hosts("model", &["127.0.0.1".into()]).unwrap();
        let llm = format!("{{secret: model, upstream: 'http://127.0.0.1:{port}'}}");
        let with_vault = || {
            let mut c = ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &llm);
            c.vault = vault.clone();
            super::Llm::new(c).unwrap()
        };

        std::fs::remove_file(&creds).unwrap();
        let t = std::time::Instant::now();
        let (status, body) = post(with_vault(), "unreadable").await;
        assert!(t.elapsed() >= super::SECRET_PATIENCE, "retried for its patience");
        assert_eq!(status, 503, "{body}");
        assert!(body.contains("secret \\\"model\\\" could not be read") && body.contains("missing"), "{body}");
        assert!(body.contains("wicket doctor"), "{body}");
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0, "the upstream saw nothing");

        // Rewritten while the call waits: it goes through with the new token.
        let c2 = creds.clone();
        let back = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            write(&c2, "tok-2");
        });
        let (status, body) = post(with_vault(), "rewritten").await;
        back.join().unwrap();
        assert_eq!(status, 200, "{body}");
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    /// The only requests the model route forwards: inference and token counting (and listing
    /// models). Everything else under the upstream would also carry the real token, so it is refused
    /// before any budget is spent.
    fn only_model_routes_are_allowed() {
        let a = |m, p| crate::provider::ANTHROPIC.allowed_route(m, p);
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
        assert_eq!(llm.count.requests.load(std::sync::atomic::Ordering::SeqCst), 0, "not counted, never forwarded");
    }

    /// #70: the zone's model budget is the agent's over its life. A woken activation starts from
    /// what its earlier ones left, and an exhausted agent gets 429 without a model call.
    #[tokio::test]
    async fn a_woken_agent_continues_its_budget() {
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{max_requests: 5, max_output_tokens: 100}"))
            .unwrap();
        llm.spent_before(3, 40, 60);
        assert_eq!(llm.remaining(), Some((2, 40)), "children are carved from what is left");
        llm.count.reserved_requests.store(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(llm.spent_total(), (4, 40, 60));
        // Every request is spent: refused, never forwarded (the default upstream is never contacted).
        llm.spent_before(5, 40, 60);
        llm.count.reserved_requests.store(0, std::sync::atomic::Ordering::SeqCst);
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

    /// #256: on the control host the run's quota grants are its budget: their amounts are the
    /// limits every check reads, with the same refusals, whatever the zone says.
    #[tokio::test]
    async fn the_quota_grants_amounts_are_the_budget() {
        let zone = "{max_requests: 50, max_output_tokens: 1000, max_input_tokens: 9000}";
        let q = super::ModelQuota { requests: 2, output_tokens: 100, input_tokens: Some(500) };
        let llm = super::Llm::with_quota(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, zone), Some(q)).unwrap();
        assert_eq!(llm.quota(), Some(q));
        assert_eq!((llm.remaining(), llm.remaining_input()), (Some((2, 100)), Some(500)));
        let sl = llm.next_slice(0.5).unwrap();
        assert_eq!((sl.requests, sl.output_tokens, sl.input_tokens), (1, 50, Some(250)), "slices are cut from the grant's amount");
        llm.spent_before(2, 0, 0);
        let (status, body) = post(llm.clone(), "quota").await;
        assert_eq!(status, 429, "{body}");
        assert!(body.contains("at most 2 model requests"), "{body}");
        // A zone with a model route and no quota granted has nothing to spend.
        let llm = super::Llm::with_quota(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, zone), None).unwrap();
        assert_eq!(llm.remaining(), Some((0, 0)));
        let (status, _) = post(llm, "none").await;
        assert_eq!(status, 429);
        // A node's proxy enforces the zone in its token, as before.
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, zone)).unwrap();
        assert_eq!(llm.quota(), Some(super::ModelQuota { requests: 50, output_tokens: 1000, input_tokens: Some(9000) }));
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

    /// A node's secret cache whose first fetch waits for `go` (#422): the control host a restarted
    /// node fetches the model credential from is still reconnecting.
    struct SlowFetch {
        dir: crate::vault::Vault,
        held: std::sync::atomic::AtomicBool,
        go: tokio::sync::Notify,
    }

    impl crate::vault::SecretSource for SlowFetch {
        fn get(&self, name: &str) -> anyhow::Result<String> {
            self.dir.get(name)
        }
        fn hosts(&self, name: &str) -> Vec<String> {
            self.dir.hosts(name)
        }
        fn has(&self, _: &str) -> bool {
            self.held.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn fetch<'a>(&'a self, _: &'a str) -> futures_util::future::BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async move {
                self.go.notified().await;
                self.held.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
        }
    }

    /// #422: a call the box gives up on while its node fetches the credential (its client timed
    /// out) gives its output reservation back. It used to stay reserved for good, and the node
    /// refused every later call with "Model token budget exhausted" though nothing was spent.
    #[tokio::test]
    async fn a_call_given_up_before_it_is_sent_gives_its_reservation_back() {
        use http_body_util::BodyExt;
        use std::sync::atomic::Ordering::SeqCst;
        let done = [
            sse("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":12,"output_tokens":1}}}"#),
            [
                sse("message_delta", r#"{"type":"message_delta","usage":{"output_tokens":250}}"#),
                sse("message_stop", r#"{"type":"message_stop"}"#),
            ]
            .concat(),
        ];
        let (port, seen) = sse_upstream(done.to_vec(), std::time::Duration::ZERO).await;
        // A budget of one call's max_tokens: a reservation left behind leaves nothing.
        let (direct, dir) = llm_to(port, 300, "given-up");
        let source = std::sync::Arc::new(SlowFetch { dir: direct.ctx.vault.clone(), held: false.into(), go: tokio::sync::Notify::new() });
        let mut c = direct.ctx.clone();
        c.vault = crate::vault::Vault::from_source(source.clone());
        let llm = super::Llm::new(c).unwrap();
        let sock = dir.join("llm.sock");
        let server = tokio::spawn({
            let (llm, sock) = (llm.clone(), sock.clone());
            async move { llm.serve(&sock).await }
        });
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // The first call waits for the credential with its output reserved; its client gives up.
        let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
        let conn = tokio::spawn(conn);
        let req = http::Request::post("/v1/messages")
            .header("host", "wicket.internal")
            .header("content-type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(ASK)))
            .unwrap();
        let pending = tokio::spawn(async move { send.send_request(req).await.map(|r| r.status().as_u16()) });
        for _ in 0..300 {
            if llm.count.inflight_output_tokens.load(SeqCst) == 300 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(llm.count.inflight_output_tokens.load(SeqCst), 300, "the call holds its reservation while it waits");
        pending.abort();
        conn.abort();
        for _ in 0..300 {
            if llm.count.inflight_output_tokens.load(SeqCst) == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(llm.count.inflight_output_tokens.load(SeqCst), 0, "given up before it was sent: its reservation is back");
        assert_eq!(llm.count.output_tokens.load(SeqCst), 0, "and nothing is charged for it");
        assert!(seen.lock().await.is_empty(), "it never reached the upstream");
        // The credential arrives: the next call gets the whole budget and completes within it.
        source.go.notify_one();
        let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
        let conn = tokio::spawn(conn);
        let req = http::Request::post("/v1/messages")
            .header("host", "wicket.internal")
            .header("content-type", "application/json")
            .body(http_body_util::Full::new(bytes::Bytes::from(ASK)))
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let _ = resp.into_body().collect().await;
        assert_eq!(output_settles(&llm, 250).await, 250);
        conn.abort();
        server.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #422: the control host restarts with a call in flight on the node, whose `serve` restarts
    /// too and charges that call its whole reservation (#324). The re-attached supervisor counts the
    /// node's spend from its first report, and the slice it sends is in the node's counts: the node
    /// completes the next call within the budget. (A slice in the supervisor's own counts was that
    /// report short: the node held less than it had spent and refused every call.)
    #[tokio::test]
    async fn after_a_restart_with_a_call_in_flight_the_next_call_completes_within_the_budget() {
        let done = [
            sse("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":12,"output_tokens":1}}}"#),
            [
                sse("message_delta", r#"{"type":"message_delta","usage":{"output_tokens":250}}"#),
                sse("message_stop", r#"{"type":"message_stop"}"#),
            ]
            .concat(),
        ];
        let (port, _) = sse_upstream(done.to_vec(), std::time::Duration::ZERO).await;
        let budget = 4000;
        // Before the restart: two calls settled at 20 tokens, and one in flight with 1000 reserved.
        let (before, dir) = llm_to(port, budget, "restart-inflight");
        before.count.admit_request();
        before.count.admit_request();
        before.count.settle(0, 10, 0, 0, 40);
        before.count.admit_request();
        assert_eq!(before.count.reserve_output(budget, 1000), Some(1000));
        // What the node's journal holds, and the supervisor's last heartbeat (the agent's row).
        let journaled = before.spent_charged();
        let heartbeat = before.spent_total();
        // The node's `serve` restarts: it counts the journal, the call in flight charged in full.
        let (node, _) = llm_to(port, budget, "restart-inflight");
        node.merge_spent(journaled);
        assert_eq!(node.spent().output_tokens, 1040);
        // The re-attached supervisor: the agent's spend as its prior, the node's first report its base.
        let (control, _) = llm_to(port, budget, "restart-inflight-control");
        control.spent_before(heartbeat.0, heartbeat.1, heartbeat.2);
        let base = node.spent();
        control.merge_spent(base.since(base));
        let fraction = 0.25;
        let next = control.next_slice(fraction).unwrap();
        let slice = super::Slice::renewed_from(None, next, control.spent(), control.input_total(), base);
        assert!(slice.output_tokens > node.spent().output_tokens, "{slice:?}: the node holds more than it spent");
        node.set_slice(Some(slice));
        assert_eq!(call(node.clone(), "restart-inflight", ASK, true).await, 200);
        assert_eq!(output_settles(&node, 1040 + 250).await, 1040 + 250);
        // A slice in the supervisor's own counts would have left the node nothing.
        let unoffset = super::Slice::renewed(None, next, control.spent(), control.input_total());
        assert!(unoffset.output_tokens <= base.output_tokens, "{unoffset:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// #366: a zone with a model list sends upstream only calls naming one of its models; any other
    /// model, or none, is refused here with a 403 naming what is allowed, and audited.
    #[tokio::test]
    async fn only_the_zones_models_are_called() {
        let done = [
            sse("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":1,"output_tokens":1}}}"#),
            sse("message_stop", r#"{"type":"message_stop"}"#),
        ]
        .concat();
        let (port, seen) = sse_upstream(vec![done], std::time::Duration::ZERO).await;
        let dir = std::env::temp_dir().join(format!("wicket-llm-models-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = crate::vault::Vault::new(dir.clone());
        vault.set("model", "tok").unwrap();
        vault.set_hosts("model", &["127.0.0.1".into()]).unwrap();
        let spec = format!("{{secret: model, upstream: 'http://127.0.0.1:{port}', models: [claude-opus-4-5, 'claude-haiku-*']}}");
        let mut c = ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &spec);
        c.vault = vault;
        let llm = super::Llm::new(c).unwrap();
        let body = |m: &str| format!(r#"{{{m}"max_tokens":5,"stream":true,"messages":[]}}"#);
        assert_eq!(call(llm.clone(), "m-opus", &body(r#""model":"claude-opus-4-5","#), true).await, 200);
        assert_eq!(call(llm.clone(), "m-haiku", &body(r#""model":"claude-haiku-4-5-20251001","#), true).await, 200);
        assert_eq!(call(llm.clone(), "m-sonnet", &body(r#""model":"claude-sonnet-4-5","#), true).await, 403);
        assert_eq!(call(llm.clone(), "m-none", &body(""), true).await, 403);
        assert_eq!(seen.lock().await.len(), 2, "refused calls never reach the upstream");
        let ops: Vec<String> = llm.ctx.ledger.lock().unwrap().audit_of_kind("op").unwrap().into_iter().map(|r| r.body).collect();
        assert!(
            ops.iter().any(
                |o| o.contains(r#"model \"claude-sonnet-4-5\" is not one this zone allows (allowed: claude-opus-4-5, claude-haiku-*)"#)
            ),
            "{ops:?}"
        );
        assert!(ops.iter().any(|o| o.contains("names no model")), "{ops:?}");
        let _ = std::fs::remove_dir_all(dir);
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
            if llm.count.inflight_output_tokens.load(std::sync::atomic::Ordering::SeqCst) == 0
                && llm.count.output_tokens.load(std::sync::atomic::Ordering::SeqCst) == want
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        llm.count.output_tokens.load(std::sync::atomic::Ordering::SeqCst)
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

    /// #310: a request lowered to what is left of the budget stays valid with extended thinking: its
    /// thinking budget is lowered below the new max_tokens, never under the provider's minimum, and
    /// a request no valid lowering fits is refused with the reason (its reservation released).
    #[tokio::test]
    async fn a_lowered_request_with_thinking_stays_valid_or_is_refused() {
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{max_output_tokens: 90000}")).unwrap();
        let spec = llm.ctx.zone.llm.clone().unwrap();
        let parts = || http::Request::post("/v1/messages").body(()).unwrap().into_parts().0;
        let ask = |max: u64, thinking: &str| {
            bytes::Bytes::from(format!(r#"{{"model":"m","max_tokens":{max},"thinking":{thinking},"messages":[]}}"#))
        };
        let enabled = |b: u64| format!(r#"{{"type":"enabled","budget_tokens":{b}}}"#);
        // 2000 spent: 88000 left. Thinking within the lowered max_tokens stays as it is.
        llm.spent_before(0, 0, 2000);
        let f = llm.filter(Some(&spec), &parts(), ask(128000, &enabled(31999))).ok().unwrap();
        let out: serde_json::Value = serde_json::from_slice(&f.body).unwrap();
        assert_eq!((out["max_tokens"].as_u64(), out["thinking"]["budget_tokens"].as_u64()), (Some(88000), Some(31999)));
        llm.settle(f.reserved, Usage::default(), true);
        // A thinking budget at or above it is lowered below it.
        let f = llm.filter(Some(&spec), &parts(), ask(128000, &enabled(127999))).ok().unwrap();
        let out: serde_json::Value = serde_json::from_slice(&f.body).unwrap();
        assert_eq!((out["max_tokens"].as_u64(), out["thinking"]["budget_tokens"].as_u64()), (Some(88000), Some(87999)));
        assert!(f.note.contains("thinking.budget_tokens 127999 lowered to 87999"), "{}", f.note);
        llm.settle(f.reserved, Usage::default(), true);
        // Adaptive thinking has no budget of its own: only max_tokens is lowered.
        let f = llm.filter(Some(&spec), &parts(), ask(128000, r#"{"type":"adaptive"}"#)).ok().unwrap();
        let out: serde_json::Value = serde_json::from_slice(&f.body).unwrap();
        assert_eq!((out["max_tokens"].as_u64(), out["thinking"]["type"].as_str()), (Some(88000), Some("adaptive")));
        llm.settle(f.reserved, Usage::default(), true);
        // 1024 left: no thinking budget is both at least 1024 and below max_tokens. Refused, clearly.
        llm.spent_before(0, 0, 90000 - 1024);
        let r = llm.filter(Some(&spec), &parts(), ask(128000, &enabled(4000))).err().expect("refused");
        assert_eq!(r.status().as_u16(), 429);
        let body = http_body_util::BodyExt::collect(r.into_body()).await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("budget left: 1024 output tokens") && body.contains("thinking.budget_tokens 4000"), "{body}");
        assert_eq!(llm.count.inflight_output_tokens.load(std::sync::atomic::Ordering::SeqCst), 0, "the reservation is released");
        // Without thinking (or with it disabled) the same request is lowered and sent.
        let f = llm.filter(Some(&spec), &parts(), ask(128000, r#"{"type":"disabled"}"#)).ok().unwrap();
        assert_eq!(f.reserved, 1024);
        // 1025 left: the smallest valid lowering, thinking 1024 below max_tokens 1025.
        llm.settle(f.reserved, Usage::default(), true);
        llm.spent_before(0, 0, 90000 - 1025);
        let f = llm.filter(Some(&spec), &parts(), ask(128000, &enabled(4000))).ok().unwrap();
        let out: serde_json::Value = serde_json::from_slice(&f.body).unwrap();
        assert_eq!((out["max_tokens"].as_u64(), out["thinking"]["budget_tokens"].as_u64()), (Some(1025), Some(1024)));
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

    /// #324: what a node persists counts the calls in flight at their whole reservation, so a node
    /// restarted mid-call never counts less than its upstream billed. The journal reads the count
    /// when it is told, not when its caller looked.
    #[test]
    fn the_journal_charges_calls_in_flight_in_full() {
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{max_output_tokens: 1000}")).unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let s = seen.clone();
        llm.set_journal(move |sp| s.lock().unwrap().push(sp.output_tokens));
        let spec = llm.ctx.zone.llm.clone().unwrap();
        assert!(llm.admit(Some(&spec)).is_none());
        let parts = http::Request::post("/v1/messages").body(()).unwrap().into_parts().0;
        let f =
            llm.filter(Some(&spec), &parts, bytes::Bytes::from_static(br#"{"model":"m","max_tokens":300,"messages":[]}"#)).ok().unwrap();
        assert_eq!((llm.spent().output_tokens, llm.spent_charged().output_tokens), (0, 300));
        llm.journal();
        llm.settle(f.reserved, Usage { output: 40, ..Usage::default() }, true);
        llm.journal();
        assert_eq!(*seen.lock().unwrap(), vec![300, 40], "in flight: its reservation; settled: what it used");
        assert_eq!(llm.spent_charged(), llm.spent());
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
        assert_eq!(llm.count.output_tokens.load(std::sync::atomic::Ordering::SeqCst), 50, "10 settled, 40 charged in full");
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
        // (Sorted: JSON objects keep their insertion order when serde_json's preserve_order is on,
        // which cedar-policy turns on for the whole binary, #51.)
        let mut keys: Vec<&String> = out.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["max_tokens", "messages", "model", "tools"], "{out}");
        let names: Vec<&str> = out["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["a", "b", "bash"]);
        // The note names what was stripped (#307), sorted, at most a handful, never a value.
        assert!(f.note.contains("stripped 3 request field(s): container, mcp_servers, some_future_field"), "{}", f.note);
        assert!(
            f.note.contains(
                "stripped 7 server-side tool(s): advisor_20260301, code_execution_20260521, mcp_toolset, some_new_server_tool, …"
            ),
            "{}",
            f.note
        );
        for value in ["evil.example", "https", "skills"] {
            assert!(!f.note.contains(value), "{value} in {}", f.note);
        }
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

    /// #307: Claude Code's prompt-cache `diagnostics` field (as captured from `claude` 2.1.319 with
    /// the `cache-diagnosis-2026-04-07` beta) passes the gate unchanged, with or without a
    /// previous message id, and nothing is noted as stripped.
    #[test]
    fn the_cache_diagnostics_field_passes_unchanged() {
        let parts = http::Request::builder().method("POST").uri("/v1/messages?beta=true").body(()).unwrap().into_parts().0;
        let llm = super::Llm::new(ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, "{}")).unwrap();
        let spec = llm.ctx.zone.llm.clone().unwrap();
        for diag in [r#"{"previous_message_id":null}"#, r#"{"previous_message_id":"msg_01AbC"}"#] {
            let body = format!(
                r#"{{"model":"m","max_tokens":10,"messages":[{{"role":"user","content":"hi"}}],"diagnostics":{diag},"stream":true}}"#
            );
            let f = llm.filter(Some(&spec), &parts, bytes::Bytes::from(body.clone())).ok().unwrap();
            let sent: serde_json::Value = serde_json::from_slice(&f.body).unwrap();
            let asked: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(sent, asked, "{diag}");
            assert_eq!(f.note, "ok");
        }
    }

    /// #307: names are distinct, sorted, clipped and printable, and only a handful are listed.
    #[test]
    fn stripped_names_are_listed_briefly() {
        let v = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(super::named(v(&["b", "a", "b"])), "a, b");
        assert_eq!(super::named(v(&["e", "d", "c", "b", "a"])), "a, b, c, d, …");
        assert_eq!(super::named(v(&[&"x".repeat(40), "a\nb"])), format!("a?b, {}…", "x".repeat(32)));
    }

    /// #307: a call that had fields stripped names them, not their values, in the `op` audit record.
    #[tokio::test]
    async fn the_audit_record_names_stripped_fields_without_values() {
        let chunks = vec![[
            sse("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":1}}}"#),
            sse("message_delta", r#"{"type":"message_delta","usage":{"output_tokens":7}}"#),
            sse("message_stop", r#"{"type":"message_stop"}"#),
        ]
        .concat()];
        let (port, _) = sse_upstream(chunks, std::time::Duration::ZERO).await;
        let (llm, dir) = llm_to(port, 1000, "named");
        let body = r#"{"model":"m","max_tokens":30,"stream":true,"messages":[{"role":"user","content":"hi"}],
            "program_use_case_id":"secret-use-case","some_future_field":{"nested":"secret-nested"},
            "tools":[{"name":"a","input_schema":{}},{"type":"web_search_20260209","name":"secret_search"}]}"#;
        assert_eq!(call(llm.clone(), "named", body, true).await, 200);
        let mut op = None;
        for _ in 0..300 {
            let recs = llm.ctx.ledger.lock().unwrap().audit_of_kind("op").unwrap();
            op = recs.into_iter().map(|r| r.body).find(|b| b.contains("\"kind\":\"llm\""));
            if op.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let op = op.expect("an llm op record");
        assert!(op.contains("stripped 2 request field(s): program_use_case_id, some_future_field"), "{op}");
        assert!(op.contains("stripped 1 server-side tool(s): web_search_20260209"), "{op}");
        for value in ["secret-use-case", "secret-nested", "nested", "secret_search"] {
            assert!(!op.contains(value), "{value} in {op}");
        }
        let _ = std::fs::remove_dir_all(dir);
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

    /// A fake model upstream that accepts only the bearer `good` and answers anything else 401
    /// (`token revoked`), calling `on_reject` first: the login's owner refreshing it while the call
    /// is out (#360). Records each request's bearer.
    async fn relogin_upstream(
        good: &'static str,
        on_reject: impl Fn() + Send + Sync + 'static,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let mut req = Vec::new();
                let mut buf = vec![0u8; 8192];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&req).to_ascii_lowercase();
                let bearer = text.lines().find_map(|l| l.strip_prefix("authorization: bearer ")).unwrap_or("").trim().to_string();
                seen2.lock().unwrap().push(bearer.clone());
                let resp: &[u8] = if bearer == good {
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}"
                } else {
                    on_reject();
                    b"HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: 75\r\nconnection: close\r\n\r\n{\"type\":\"error\",\"error\":{\"type\":\"authentication_error\",\"message\":\"revoked\"}}"
                };
                let _ = c.write_all(resp).await;
            }
        });
        (port, seen)
    }

    /// The `llm` op records written so far.
    async fn llm_ops(llm: &super::Llm, want: usize) -> Vec<String> {
        let mut ops = vec![];
        for _ in 0..300 {
            let recs = llm.ctx.ledger.lock().unwrap().audit_of_kind("op").unwrap();
            ops = recs.into_iter().map(|r| r.body).filter(|b| b.contains("\"kind\":\"llm\"")).collect();
            if ops.len() >= want {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        ops
    }

    /// A model call that races a login refresh (#360): the upstream refuses the old access token
    /// the call went out with, the secret's file already holds the new one, so the call is sent once
    /// more with it, and both the retry and the call's end are audited. The box sees one call, and
    /// the budget counts one request.
    #[tokio::test]
    async fn a_call_that_races_a_login_refresh_is_retried_once_with_the_new_token() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wicket-llm-relogin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let creds = dir.join("creds.json");
        let write = |p: &std::path::Path, t: &str| {
            std::fs::write(p, format!(r#"{{"o":{{"accessToken":"{t}"}}}}"#)).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write(&creds, "tok-old");
        let c2 = creds.clone();
        let (port, seen) = relogin_upstream("tok-new", move || write(&c2, "tok-new")).await;
        let vault = crate::vault::Vault::new(dir.join("vault"));
        vault.link("model", creds.to_str().unwrap(), Some("/o/accessToken"), None, None).unwrap();
        vault.set_hosts("model", &["127.0.0.1".into()]).unwrap();
        let mut c =
            ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &format!("{{secret: model, upstream: 'http://127.0.0.1:{port}'}}"));
        c.vault = vault;
        let llm = super::Llm::new(c).unwrap();
        let (status, body) = post(llm.clone(), "relogin").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(*seen.lock().unwrap(), ["tok-old", "tok-new"], "one retry, with the new token");
        assert_eq!(llm.count.requests.load(std::sync::atomic::Ordering::SeqCst), 1, "one call for the budget");
        let ops = llm_ops(&llm, 2).await;
        assert!(ops.iter().any(|o| o.contains("\"status\":401") && o.contains("retrying once with its new value")), "{ops:?}");
        assert!(ops.iter().any(|o| o.contains("\"status\":200") && o.contains("retried once after a 401")), "{ops:?}");
        assert!(ops.iter().all(|o| !o.contains("tok-")), "no token in the audit: {ops:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A linked login and an upstream that accepts only `tok-new`; the refused call's `on_reject`
    /// writes `tok-new` into the login after `delay`, as a refresh's owner does a moment after the
    /// old token is revoked (#552). Returns the proxy, the bearers seen, and the directory.
    async fn relogin_after(
        delay: std::time::Duration,
        tag: &str,
    ) -> (std::sync::Arc<super::Llm>, std::sync::Arc<std::sync::Mutex<Vec<String>>>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("wicket-llm-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let creds = dir.join("creds.json");
        fn write(p: &std::path::Path, t: &str) {
            use std::os::unix::fs::PermissionsExt;
            let tmp = p.with_extension("tmp");
            std::fs::write(&tmp, format!(r#"{{"o":{{"accessToken":"{t}"}}}}"#)).unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::rename(&tmp, p).unwrap();
        }
        write(&creds, "tok-old");
        let c2 = creds.clone();
        let (port, seen) = relogin_upstream("tok-new", move || {
            let c3 = c2.clone();
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                write(&c3, "tok-new");
            });
        })
        .await;
        let vault = crate::vault::Vault::new(dir.join("vault"));
        vault.link("model", creds.to_str().unwrap(), Some("/o/accessToken"), None, None).unwrap();
        vault.set_hosts("model", &["127.0.0.1".into()]).unwrap();
        let mut c =
            ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &format!("{{secret: model, upstream: 'http://127.0.0.1:{port}'}}"));
        c.vault = vault;
        (super::Llm::new(c).unwrap(), seen, dir)
    }

    /// #552: the login's new token is written a moment after the upstream refused the old one (the
    /// refresh revokes first). The call waits for it, is sent once more with it, and succeeds; the
    /// box never sees the 401.
    #[tokio::test]
    async fn a_login_written_just_after_the_401_is_waited_for() {
        let (llm, seen, dir) = relogin_after(std::time::Duration::from_millis(300), "relogin-late").await;
        let (status, body) = post(llm.clone(), "late").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(*seen.lock().unwrap(), ["tok-old", "tok-new"], "one retry, with the new token");
        let ops = llm_ops(&llm, 2).await;
        assert!(ops.iter().any(|o| o.contains("\"status\":200") && o.contains("retried once after a 401")), "{ops:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #552: the client's own retry arrives while the refresh is still being written (Claude Code
    /// retries a 401 at once). Both calls wait for the new token, and both succeed: neither 401
    /// reaches the box.
    #[tokio::test]
    async fn a_client_retry_during_the_refresh_also_succeeds() {
        let (llm, seen, dir) = relogin_after(std::time::Duration::from_millis(500), "relogin-retry").await;
        let first = tokio::spawn(post(llm.clone(), "first"));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let (s2, b2) = post(llm.clone(), "retry").await;
        let (s1, b1) = first.await.unwrap();
        assert_eq!((s1, s2), (200, 200), "{b1} / {b2}");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.iter().filter(|b| *b == "tok-new").count(), 2, "each call ends with the new token: {seen:?}");
        assert!(seen.iter().filter(|b| *b == "tok-old").count() <= 2, "the old token at most once per call: {seen:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A 401 when the secret hasn't changed (#360): a real revocation, passed through to the box,
    /// and the same value is never sent again.
    #[tokio::test]
    async fn a_401_with_an_unchanged_secret_passes_through() {
        let (port, seen) = relogin_upstream("tok-never", || {}).await;
        let dir = std::env::temp_dir().join(format!("wicket-llm-revoked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = crate::vault::Vault::new(dir.clone());
        vault.set("model", "tok-revoked").unwrap();
        vault.set_hosts("model", &["127.0.0.1".into()]).unwrap();
        let mut c =
            ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &format!("{{secret: model, upstream: 'http://127.0.0.1:{port}'}}"));
        c.vault = vault;
        let llm = super::Llm::new(c).unwrap();
        let (status, body) = post(llm.clone(), "revoked").await;
        assert_eq!(status, 401, "{body}");
        assert!(body.contains("authentication_error"), "the upstream's answer: {body}");
        assert_eq!(*seen.lock().unwrap(), ["tok-revoked"], "not retried");
        let ops = llm_ops(&llm, 1).await;
        assert!(ops.iter().any(|o| o.contains("\"status\":401") && o.contains("is unchanged: not retried")), "{ops:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node's copy of the login (#152, #360): after a 401 the node asks its source again even
    /// though it holds a copy (the control host may not have said yet that it changed), and the
    /// call is retried with what comes back.
    #[tokio::test]
    async fn a_node_asks_its_source_again_after_a_401() {
        struct Source {
            value: std::sync::Mutex<String>,
            refetches: std::sync::atomic::AtomicUsize,
        }
        impl crate::vault::SecretSource for Source {
            fn get(&self, _: &str) -> anyhow::Result<String> {
                Ok(self.value.lock().unwrap().clone())
            }
            fn hosts(&self, _: &str) -> Vec<String> {
                vec!["127.0.0.1".into()]
            }
            fn has(&self, _: &str) -> bool {
                true
            }
            fn refetch<'a>(&'a self, _: &'a str) -> futures_util::future::BoxFuture<'a, anyhow::Result<()>> {
                self.refetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                *self.value.lock().unwrap() = "tok-new".into();
                Box::pin(async { Ok(()) })
            }
        }
        let (port, seen) = relogin_upstream("tok-new", || {}).await;
        let source = std::sync::Arc::new(Source { value: std::sync::Mutex::new("tok-old".into()), refetches: Default::default() });
        let mut c =
            ctx(wicket_store::Ledger::open_in_memory().unwrap(), None, &format!("{{secret: model, upstream: 'http://127.0.0.1:{port}'}}"));
        c.vault = crate::vault::Vault::from_source(source.clone());
        let (status, body) = post(super::Llm::new(c).unwrap(), "node-relogin").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(*seen.lock().unwrap(), ["tok-old", "tok-new"]);
        assert_eq!(source.refetches.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
