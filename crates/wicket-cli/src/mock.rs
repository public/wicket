//! A scripted stand-in for the Anthropic Messages API, for testing the whole path without a key.
//! Every user turn: ask the agent to run one Bash command. Once its result is back: finish, saying how
//! many messages the request carried (a resumed session carries its whole earlier conversation).
//!
//! Every reply has its own message id: Claude Code merges entries that share one when it loads a
//! session, so with a fixed id a resumed session folds its turns together and loops (#70).

use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

/// The text of the conversation's last message, if it is the user's words (not a tool result).
fn last_user_text(v: &Value) -> Option<String> {
    let last = v.get("messages")?.as_array()?.last()?;
    if last.get("role")?.as_str()? != "user" {
        return None;
    }
    let text = match last.get("content")? {
        Value::String(s) => s.clone(),
        Value::Array(c) => c
            .iter()
            .filter_map(|b| (b.get("type")?.as_str()? == "text").then(|| b.get("text")?.as_str().map(String::from))?)
            .collect::<Vec<_>>()
            .join(" "),
        _ => return None,
    };
    (!text.trim().is_empty()).then_some(text)
}

static REPLIES: AtomicU64 = AtomicU64::new(0);

/// Whether the conversation's last message carries a tool result (the command ran): then the turn
/// ends. Otherwise the last message is the user's: run the command.
fn tool_result_last(v: &Value) -> bool {
    v.get("messages")
        .and_then(|m| m.as_array())
        .and_then(|m| m.last())
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
        .is_some_and(|c| c.iter().any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_result")))
}

pub async fn serve(listen: &str, command: &str) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    eprintln!("mock LLM on http://{listen} (command: {command})");
    let command = Arc::new(command.to_string());
    loop {
        let (stream, _) = listener.accept().await?;
        let command = command.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let command = command.clone();
                async move { Ok::<_, hyper::Error>(handle(req, &command).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}

async fn handle(req: Request<Incoming>, command: &str) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    let key = req
        .headers()
        .get("authorization")
        .or_else(|| req.headers().get("x-api-key"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    eprintln!(
        "mock: {path} key={} model={}",
        if key.contains("placeholder") {
            "PLACEHOLDER (leak!)"
        } else if key.is_empty() {
            "none"
        } else {
            "injected"
        },
        v.get("model").and_then(|m| m.as_str()).unwrap_or("?")
    );
    if path.ends_with("/count_tokens") {
        return json_resp(json!({ "input_tokens": 10 }));
    }
    if !path.ends_with("/v1/messages") {
        return Response::builder().status(404).body(Full::new(Bytes::from_static(b"{}"))).unwrap();
    }
    let model = v.get("model").and_then(|m| m.as_str()).unwrap_or("mock").to_string();
    let has_tools = v
        .get("tools")
        .and_then(|t| t.as_array())
        .map(|t| t.iter().any(|t| t.get("name").and_then(|n| n.as_str()) == Some("Bash")))
        .unwrap_or(false);
    let done = tool_result_last(&v);
    let stream = v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let n = REPLIES.fetch_add(1, Ordering::SeqCst) + 1;
    let msg_id = format!("msg_mock_{}_{n}", std::process::id());
    let messages = v.get("messages").and_then(|m| m.as_array()).map(|m| m.len()).unwrap_or(0);
    let (block, stop) = if has_tools && !done {
        (
            json!({ "type": "tool_use", "id": format!("toolu_mock_{n}"), "name": "Bash", "input": { "command": command, "description": "wicket mock step" } }),
            "tool_use",
        )
    } else {
        (json!({ "type": "text", "text": format!("Done: the mock model finished. The request carried {messages} messages.") }), "end_turn")
    };
    eprintln!(
        "mock: reply {msg_id}: {} ({messages} messages in the request)",
        if stop == "tool_use" { "run the command" } else { "finish" }
    );
    if let Some(t) = last_user_text(&v) {
        eprintln!("mock: the user said: {}", t.chars().take(1000).collect::<String>().replace('\n', " "));
    }
    if !stream {
        return json_resp(json!({
            "id": msg_id, "type": "message", "role": "assistant", "model": model,
            "content": [block], "stop_reason": stop, "stop_sequence": null,
            "usage": { "input_tokens": 10, "output_tokens": 20 }
        }));
    }
    let mut sse = String::new();
    let mut ev = |name: &str, data: Value| sse.push_str(&format!("event: {name}\ndata: {data}\n\n"));
    ev(
        "message_start",
        json!({ "type": "message_start", "message": { "id": msg_id, "type": "message", "role": "assistant", "model": model, "content": [], "stop_reason": null, "stop_sequence": null, "usage": { "input_tokens": 10, "output_tokens": 1 } } }),
    );
    if block["type"] == "tool_use" {
        let mut start = block.clone();
        start["input"] = json!({});
        ev("content_block_start", json!({ "type": "content_block_start", "index": 0, "content_block": start }));
        ev(
            "content_block_delta",
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "input_json_delta", "partial_json": block["input"].to_string() } }),
        );
    } else {
        ev("content_block_start", json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }));
        ev(
            "content_block_delta",
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": block["text"] } }),
        );
    }
    ev("content_block_stop", json!({ "type": "content_block_stop", "index": 0 }));
    ev(
        "message_delta",
        json!({ "type": "message_delta", "delta": { "stop_reason": stop, "stop_sequence": null }, "usage": { "output_tokens": 20 } }),
    );
    ev("message_stop", json!({ "type": "message_stop" }));
    Response::builder().header("content-type", "text/event-stream").body(Full::new(Bytes::from(sse))).unwrap()
}

fn json_resp(v: Value) -> Response<Full<Bytes>> {
    Response::builder().header("content-type", "application/json").body(Full::new(Bytes::from(v.to_string()))).unwrap()
}
