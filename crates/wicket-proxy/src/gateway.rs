//! A minimal MCP gateway (design §9.2, PoC cut): JSON-RPC over streamable HTTP on a unix socket,
//! serving wicket's own tools. `await_grant` lets a blocked agent wait for the human's decision
//! instead of sleeping and retrying; `pending_requests` shows what this run is waiting on.

use crate::{BoxBody, Event, RunCtx};
use anyhow::Result;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixListener;

pub struct Gateway {
    ctx: RunCtx,
}

fn body(status: StatusCode, v: Option<Value>) -> Response<BoxBody> {
    let mut b = Response::builder().status(status);
    let bytes = match v {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Bytes::from(v.to_string())
        }
        None => Bytes::new(),
    };
    b.body(Full::new(bytes).map_err(|never| match never {}).boxed()).expect("response")
}

impl Gateway {
    pub fn new(ctx: RunCtx) -> Arc<Gateway> {
        Arc::new(Gateway { ctx })
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
        if req.method() != Method::POST {
            // No server-initiated stream in the PoC.
            return body(StatusCode::METHOD_NOT_ALLOWED, None);
        }
        let raw = match Limited::new(req.into_body(), 1024 * 1024).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return body(StatusCode::PAYLOAD_TOO_LARGE, None),
        };
        let Ok(msg) = serde_json::from_slice::<Value>(&raw) else {
            return body(StatusCode::OK, Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } })));
        };
        if msg.is_array() {
            return body(StatusCode::OK, Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "batches are not accepted" } })));
        }
        let Some(id) = msg.get("id").cloned() else {
            return body(StatusCode::ACCEPTED, None); // a notification
        };
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params.get("protocolVersion").cloned().unwrap_or(json!("2025-06-18")),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "wicket", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "wicket mediates this sandbox. When a request returns 403 pending-approval with a request_id, call await_grant with that id, then retry the request once it is granted."
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tools() })),
            "tools/call" => Ok(self.call(&params).await),
            _ => Err((-32601, format!("method {method} not found"))),
        };
        let reply = match result {
            Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
            Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
        };
        body(StatusCode::OK, Some(reply))
    }

    async fn call(&self, params: &Value) -> Value {
        let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(json!({}));
        let (text, is_error) = match name {
            "await_grant" => self.await_grant(&args).await,
            "pending_requests" => self.pending_requests(),
            _ => (format!("unknown tool {name}"), true),
        };
        self.ctx.emit(Event::Tool { name: name.to_string(), detail: text.lines().next().unwrap_or("").to_string() });
        json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
    }

    async fn await_grant(&self, args: &Value) -> (String, bool) {
        let Some(id) = args.get("request_id").and_then(|v| v.as_str()) else {
            return ("request_id is required".into(), true);
        };
        let timeout = Duration::from_secs(args.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(300).clamp(5, 600));
        let start = Instant::now();
        loop {
            let req = {
                let l = self.ctx.ledger.lock().expect("ledger");
                l.request(id)
            };
            let req = match req {
                Ok(r) => r,
                Err(_) => return (format!("no request {id}"), true),
            };
            // A run may only wait on its own requests.
            if req.tenant != self.ctx.tenant.0 || req.run != self.ctx.run.0 {
                return (format!("request {id} does not belong to this run"), true);
            }
            match req.status.as_str() {
                "granted" => return (format!("granted: {id} was approved. Retry the same request now ({} {}{}).", req.method, req.host, req.path), false),
                "denied" => return (format!("denied: {id} was denied by a human. Do not retry it or look for another route."), false),
                "withdrawn" => return (format!("withdrawn: {id} is no longer pending."), false),
                _ => {}
            }
            if start.elapsed() >= timeout {
                return (format!("pending: {id} is still waiting for a human after {}s. You may call await_grant again.", timeout.as_secs()), false);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    fn pending_requests(&self) -> (String, bool) {
        let l = self.ctx.ledger.lock().expect("ledger");
        match l.pending(&self.ctx.tenant) {
            Ok(v) => {
                let mine: Vec<String> = v
                    .into_iter()
                    .filter(|r| r.run == self.ctx.run.0)
                    .map(|r| format!("{} {} {}{} ({})", r.id, r.method, r.host, r.path, r.risk))
                    .collect();
                if mine.is_empty() {
                    ("no pending requests".into(), false)
                } else {
                    (mine.join("\n"), false)
                }
            }
            Err(e) => (e.to_string(), true),
        }
    }
}

fn tools() -> Value {
    json!([
        {
            "name": "await_grant",
            "description": "Wait for a human to decide a pending wicket request (the request_id from a 403 pending-approval response). Returns granted, denied, withdrawn, or still pending after the timeout. After 'granted', retry the original request once.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": { "type": "string", "description": "e.g. r-1a2b3c4d" },
                    "timeout_seconds": { "type": "integer", "minimum": 5, "maximum": 600, "default": 300 }
                },
                "required": ["request_id"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true }
        },
        {
            "name": "pending_requests",
            "description": "List this run's requests that are still waiting for a human decision.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": { "readOnlyHint": true }
        }
    ])
}
