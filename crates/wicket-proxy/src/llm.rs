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
const MAX_ACCOUNTED_RESPONSE: usize = 8 * 1024 * 1024;

pub struct Llm {
    ctx: RunCtx,
    client: reqwest::Client,
    pub requests: AtomicU64,
    pub input_tokens: AtomicU64,
    pub output_tokens: AtomicU64,
    last_activity: std::sync::Mutex<Instant>,
}

impl Llm {
    pub fn new(ctx: RunCtx) -> Result<Arc<Llm>> {
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Arc::new(Llm {
            ctx,
            client,
            requests: AtomicU64::new(0),
            input_tokens: AtomicU64::new(0),
            output_tokens: AtomicU64::new(0),
            last_activity: std::sync::Mutex::new(Instant::now()),
        }))
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
        let n = self.requests.fetch_add(1, Ordering::SeqCst) + 1;
        if n > spec.max_requests {
            self.event(None, 429, 0, 0, "budget: request cap reached");
            return problem(429, "budget", "Model request budget exhausted", &format!("this run may make at most {} model requests", spec.max_requests), None);
        }
        if self.output_tokens.load(Ordering::SeqCst) >= spec.max_output_tokens {
            self.event(None, 429, 0, 0, "budget: output token cap reached");
            return problem(429, "budget", "Model token budget exhausted", &format!("this run may generate at most {} output tokens", spec.max_output_tokens), None);
        }
        match self.forward(req).await {
            Ok(r) => r,
            Err(e) => {
                self.event(None, 502, 0, 0, &format!("upstream error: {e}"));
                problem(502, "upstream", "Model upstream error", &e.to_string(), None)
            }
        }
    }

    fn event(&self, model: Option<String>, status: u16, input: u64, output: u64, outcome: &str) {
        self.ctx.emit(Event::Llm {
            model,
            status,
            input_tokens: input,
            output_tokens: output,
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
        if let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&body) {
            model = json.get("model").and_then(|m| m.as_str()).map(String::from);
            if !spec.allow_server_tools {
                if let Some(tools) = json.get_mut("tools").and_then(|t| t.as_array_mut()) {
                    let before = tools.len();
                    tools.retain(|t| {
                        let ty = t.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        !(ty.starts_with("web_search") || ty.starts_with("web_fetch") || ty.starts_with("code_execution"))
                    });
                    if tools.len() != before {
                        note = format!("stripped {} server-side tool(s)", before - tools.len());
                        body = Bytes::from(serde_json::to_vec(&json)?);
                    }
                }
            }
        }
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
        let token = self.ctx.vault.get(&spec.secret)?;
        rb = rb.header("authorization", format!("Bearer {token}")).header("accept-encoding", "identity");
        let resp = rb.body(body).send().await?;
        let status = resp.status().as_u16();
        let mut out = Response::builder().status(StatusCode::from_u16(status)?);
        for (name, value) in resp.headers().iter() {
            if !STRIP_RESPONSE.contains(&name.as_str()) {
                out = out.header(name.as_str(), value.as_bytes());
            }
        }
        // Stream through to the agent while keeping a bounded copy for token accounting.
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>(16);
        let me = self.clone();
        let mut upstream = resp.bytes_stream();
        tokio::spawn(async move {
            let mut seen: Vec<u8> = Vec::new();
            while let Some(chunk) = upstream.next().await {
                match chunk {
                    Ok(b) => {
                        if seen.len() < MAX_ACCOUNTED_RESPONSE {
                            seen.extend_from_slice(&b);
                        }
                        if tx.send(Ok(Frame::data(b))).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(Box::new(e))).await;
                        break;
                    }
                }
            }
            let (input, output) = usage(&seen);
            me.input_tokens.fetch_add(input, Ordering::SeqCst);
            me.output_tokens.fetch_add(output, Ordering::SeqCst);
            me.event(model, status, input, output, &note);
        });
        let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|item| (item, rx)) });
        Ok(out.body(BodyExt::boxed(StreamBody::new(stream)))?)
    }
}

/// Best-effort usage from a Messages response, streamed (SSE) or not: the largest
/// `input_tokens` and `output_tokens` values seen (streamed output counts are cumulative).
pub fn usage(body: &[u8]) -> (u64, u64) {
    let s = String::from_utf8_lossy(body);
    (max_after(&s, "\"input_tokens\":"), max_after(&s, "\"output_tokens\":"))
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
    use super::usage;

    #[test]
    fn usage_from_sse_and_json() {
        let sse = b"event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":120,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"usage\":{\"output_tokens\":57}}\n";
        assert_eq!(usage(sse), (120, 57));
        assert_eq!(usage(br#"{"usage": {"input_tokens": 9, "output_tokens": 4}}"#), (9, 4));
        assert_eq!(usage(b"nothing"), (0, 0));
    }
}
