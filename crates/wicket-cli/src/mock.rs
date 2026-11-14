//! A scripted stand-in for the Anthropic Messages API, for testing the whole path without a key.
//! Every user turn: ask the agent to run one Bash command. Once its result is back, the agent decides
//! its own lifetime (#249), as the command's output says:
//! - by default it calls wicket's `finish` tool (through Bash, so it needs no MCP tool search), then
//!   ends its turn: wicket closes the session and the run ends;
//! - a line `wicket-mock: hibernate` calls `hibernate` instead;
//! - a line `wicket-mock: stay` just ends the turn: the session stays open for follow-ups.
//!
//! The last reply of a turn says how many messages the request carried (a resumed session carries
//! its whole earlier conversation).
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

/// The tool result the conversation's last message carries, if any: (its tool_use id, its text).
/// None: the last message is the user's words, so the turn starts with the command.
fn tool_result_last(v: &Value) -> Option<(String, String)> {
    let c = v.get("messages")?.as_array()?.last()?.get("content")?.as_array()?;
    let r = c.iter().find(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_result"))?;
    let id = r.get("tool_use_id").and_then(|i| i.as_str()).unwrap_or("").to_string();
    let text = match r.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a.iter().filter_map(|b| b.get("text").and_then(|t| t.as_str())).collect::<Vec<_>>().join("\n"),
        _ => String::new(),
    };
    Some((id, text))
}

/// The id prefix of the scripted lifetime call: its result ends the turn.
const END_ID: &str = "toolu_mock_end_";

/// What the agent does once its command has run (see the module notes).
#[derive(Debug, PartialEq)]
enum Next {
    /// Run the scripted command (a new turn).
    Command,
    /// Call this gateway tool.
    Call(&'static str),
    EndTurn,
}

fn next_after(id: &str, output: &str) -> Next {
    if id.starts_with(END_ID) {
        return Next::EndTurn;
    }
    match output.lines().map(str::trim).find_map(|l| l.strip_prefix("wicket-mock:")).map(str::trim) {
        Some("stay") => Next::EndTurn,
        Some("hibernate") => Next::Call("hibernate"),
        _ => Next::Call("finish"),
    }
}

/// A Bash command that calls one of wicket's gateway tools from inside the box.
fn gateway_call(tool: &str) -> String {
    let rpc = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": tool, "arguments": {} } });
    format!(
        "curl -sS --max-time 30 -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d '{rpc}' http://{}:8081/mcp",
        wicket_agent::WICKET_HOST
    )
}

/// The Bash tool's own limit for the scripted command (Claude Code's most): the default, two minutes,
/// would cut off a step that waits for a human or keeps a child agent's box up.
const BASH_TIMEOUT_MS: u64 = 600_000;

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
    let last = tool_result_last(&v);
    let stream = v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false);
    let n = REPLIES.fetch_add(1, Ordering::SeqCst) + 1;
    let msg_id = format!("msg_mock_{}_{n}", std::process::id());
    let messages = v.get("messages").and_then(|m| m.as_array()).map(|m| m.len()).unwrap_or(0);
    let next = match (&last, has_tools) {
        (_, false) => Next::EndTurn,
        (None, true) => Next::Command,
        (Some((id, out)), true) => next_after(id, out),
    };
    let bash = |id: String, command: &str, description: &str| json!({ "type": "tool_use", "id": id, "name": "Bash", "input": { "command": command, "description": description, "timeout": BASH_TIMEOUT_MS } });
    let (block, stop, what) = match next {
        Next::Command => (bash(format!("toolu_mock_{n}"), command, "wicket mock step"), "tool_use", "run the command".to_string()),
        Next::Call(tool) => {
            (bash(format!("{END_ID}{n}"), &gateway_call(tool), "wicket mock: lifetime"), "tool_use", format!("call {tool}"))
        }
        Next::EndTurn => (
            json!({ "type": "text", "text": format!("Done: the mock model finished. The request carried {messages} messages.") }),
            "end_turn",
            "end the turn".to_string(),
        ),
    };
    eprintln!("mock: reply {msg_id}: {what} ({messages} messages in the request)");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_s_output_decides_the_agent_s_lifetime() {
        assert_eq!(next_after("toolu_mock_1", "ok\n"), Next::Call("finish"));
        assert_eq!(next_after("toolu_mock_1", "x\n  wicket-mock: hibernate \n"), Next::Call("hibernate"));
        assert_eq!(next_after("toolu_mock_1", "wicket-mock: stay"), Next::EndTurn);
        assert_eq!(next_after("toolu_mock_end_2", "wicket-mock: hibernate"), Next::EndTurn, "the lifetime call's result ends the turn");
        let v = json!({ "messages": [{ "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "toolu_mock_3", "content": [{ "type": "text", "text": "wicket-mock: stay" }] }] }] });
        assert_eq!(tool_result_last(&v), Some(("toolu_mock_3".into(), "wicket-mock: stay".into())));
        assert!(gateway_call("finish").contains(r#""name":"finish""#));
    }
}
