//! The LLM proxy (design §9.3): holds the Claude subscription token (never an API key), strips
//! whatever credential the agent sends,
//! enforces request and token budgets, strips server-side tools the zone doesn't allow (they would
//! bypass the egress proxy), and is the run's liveness sensor.

use crate::{problem, BoxBody, Event, RunCtx, STRIP_REQUEST, STRIP_RESPONSE};
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
use tokio::net::UnixListener;

const MAX_REQUEST_BODY: usize = 32 * 1024 * 1024;
/// How long a response is still read to its end after the agent stopped reading it, so its final
/// usage is seen (#113). Past this, the call is charged its whole reservation.
const DRAIN_AFTER_DISCONNECT: std::time::Duration = std::time::Duration::from_secs(600);

pub struct Llm {
    ctx: RunCtx,
    client: reqwest::Client,
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
    last_activity: std::sync::Mutex<Instant>,
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
            last_activity: std::sync::Mutex::new(Instant::now()),
        }))
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
        let listener = UnixListener::bind(socket)?;
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
        if let Some(why) = self.ctx.superseded() {
            self.event(None, 409, Usage::default(), "stale generation");
            return problem(409, "stale-generation", "This activation is stale", &why, None);
        }
        let n = self.requests.fetch_add(1, Ordering::SeqCst)
            + 1
            + self.reserved_requests.load(Ordering::SeqCst)
            + self.prior_requests.load(Ordering::SeqCst);
        if n > spec.max_requests {
            self.event(None, 429, Usage::default(), "budget: request cap reached");
            return problem(
                429,
                "budget",
                "Model request budget exhausted",
                &format!("{} may make at most {} model requests", self.whose(), spec.max_requests),
                None,
            );
        }
        if self.output_committed() >= spec.max_output_tokens {
            self.event(None, 429, Usage::default(), "budget: output token cap reached");
            return problem(
                429,
                "budget",
                "Model token budget exhausted",
                &format!("{} may generate at most {} output tokens", self.whose(), spec.max_output_tokens),
                None,
            );
        }
        if let (Some(max), Some(0)) = (spec.max_input_tokens, self.remaining_input()) {
            self.event(None, 429, Usage::default(), "budget: input token cap reached");
            return problem(
                429,
                "budget",
                "Model token budget exhausted",
                &format!("{} may use at most {max} input tokens, cached ones included", self.whose()),
                None,
            );
        }
        match self.forward(req).await {
            Ok(r) => r,
            Err(e) => {
                self.event(None, 502, Usage::default(), &format!("upstream error: {e}"));
                problem(502, "upstream", "Model upstream error", &e.to_string(), None)
            }
        }
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
        let mut body = Limited::new(body, MAX_REQUEST_BODY).collect().await.map_err(|e| anyhow::anyhow!("request body: {e}"))?.to_bytes();
        let mut model = None;
        let mut note = String::from("ok");
        let mut want = 0;
        if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&body) {
            model = json.get("model").and_then(|m| m.as_str()).map(String::from);
            let mut changed = false;
            if !spec.allow_server_tools {
                if let Some(tools) = json.get_mut("tools").and_then(|t| t.as_array_mut()) {
                    let before = tools.len();
                    tools.retain(|t| {
                        let ty = t.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        !(ty.starts_with("web_search") || ty.starts_with("web_fetch") || ty.starts_with("code_execution"))
                    });
                    if tools.len() != before {
                        note = format!("stripped {} server-side tool(s)", before - tools.len());
                        changed = true;
                    }
                }
            }
            // The call's output is reserved up front (#113); one asking for more than is left gets
            // what is left, so it can't generate past the budget.
            if let Some(asked) = json.get("max_tokens").and_then(|v| v.as_u64()) {
                want = asked;
                let left = spec.max_output_tokens.saturating_sub(self.output_committed());
                if asked > left && left > 0 {
                    json["max_tokens"] = left.into();
                    note = format!("{note}; max_tokens {asked} lowered to the {left} output tokens left");
                    changed = true;
                }
            }
            if changed {
                body = Bytes::from(serde_json::to_vec(&json)?);
            }
        }
        let Some(reserved) = self.reserve_output(spec.max_output_tokens, want) else {
            self.event(model, 429, Usage::default(), "budget: output token cap reached");
            return Ok(problem(
                429,
                "budget",
                "Model token budget exhausted",
                &format!("{} may generate at most {} output tokens", self.whose(), spec.max_output_tokens),
                None,
            ));
        };
        let up = self.send_upstream(spec, &parts, body).await;
        let resp = match up {
            Ok(r) => r,
            Err(e) => {
                self.settle(reserved, Usage::default(), true);
                return Err(e);
            }
        };
        let status = resp.status().as_u16();
        let mut out = Response::builder().status(StatusCode::from_u16(status)?);
        for (name, value) in resp.headers().iter() {
            if !STRIP_RESPONSE.contains(&name.as_str()) {
                out = out.header(name.as_str(), value.as_bytes());
            }
        }
        let sse = resp.headers().get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("text/event-stream"));
        let body = self.account(model, status, sse, resp.bytes_stream(), reserved, note);
        Ok(out.body(body)?)
    }

    async fn send_upstream(&self, spec: &wicket_core::manifest::LlmSpec, parts: &http::request::Parts, body: Bytes) -> Result<reqwest::Response> {
        let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let url = format!("{}{}", spec.upstream.trim_end_matches('/'), pq);
        let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?;
        let mut rb = self.client.request(method, &url);
        for (name, value) in parts.headers.iter() {
            if !STRIP_REQUEST.contains(&name.as_str()) && name.as_str() != "accept-encoding" {
                rb = rb.header(name.as_str(), value.as_bytes());
            }
        }
        // The real subscription token, injected into the one slot Claude Code uses for it.
        // Only to an upstream the secret is bound to, whatever the zone's `upstream` says.
        let up_host = reqwest::Url::parse(&spec.upstream)?.host_str().map(String::from).unwrap_or_default();
        let token = self.ctx.vault.get_for(&spec.secret, &up_host)?;
        rb = rb.header("authorization", format!("Bearer {token}")).header("accept-encoding", "identity");
        Ok(rb.body(body).send().await?)
    }

    /// Streams an upstream response to the agent while reading its usage as it goes (in constant
    /// memory, #113), and settles the call's reservation when the response ends. If the agent stops
    /// reading, the response is still read to its end (for up to [`DRAIN_AFTER_DISCONNECT`]), so a
    /// call can't escape its charge by disconnecting before the final usage. A successful response
    /// that ends without its final usage (`message_stop` for a stream) is charged its whole
    /// reservation; an error response, only what it reports.
    pub(crate) fn account<S, E>(self: &Arc<Self>, model: Option<String>, status: u16, sse: bool, mut upstream: S, reserved: u64, note: String) -> BoxBody
    where
        S: futures_util::Stream<Item = std::result::Result<Bytes, E>> + Send + Unpin + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>(16);
        let me = self.clone();
        tokio::spawn(async move {
            let mut scan = UsageScanner::default();
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
                            let _ = tx.send(Err(Box::new(e))).await;
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
}

/// Longer than any key plus its number, so nothing is split past the carried tail.
const SCAN_CARRY: usize = 96;

impl UsageScanner {
    pub(crate) fn feed(&mut self, chunk: &[u8]) {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        let u = usage(&buf);
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
        let req = http::Request::post("/v1/messages")
            .header("host", "wicket.internal")
            .body(http_body_util::Full::new(bytes::Bytes::from_static(b"{}")))
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
    /// `pause` before the last one, then ends cleanly. It records each request it got.
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
                        if i == last {
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
            if llm.inflight_output_tokens.load(std::sync::atomic::Ordering::SeqCst) == 0 && llm.output_tokens.load(std::sync::atomic::Ordering::SeqCst) == want {
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
            [sse("message_delta", r#"{"type":"message_delta","usage":{"output_tokens":250}}"#), sse("message_stop", r#"{"type":"message_stop"}"#)].concat(),
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
        let delta = sse("content_block_delta", &format!(r#"{{"type":"content_block_delta","delta":{{"text":"{}"}}}}"#, "x".repeat(64 * 1024)));
        let mut chunks = vec![sse("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":3,"output_tokens":1}}}"#)];
        chunks.extend(std::iter::repeat_n(delta, 150)); // ~9.6 MiB
        chunks.push([sse("message_delta", r#"{"type":"message_delta","usage":{"output_tokens":77}}"#), sse("message_stop", r#"{"type":"message_stop"}"#)].concat());
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
        let chunks = vec![sse("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":3,"output_tokens":1}}}"#), b": keep-alive\n\n".to_vec()];
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

    /// #113: parallel calls reserve from what is left, so together they can't overshoot.
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
