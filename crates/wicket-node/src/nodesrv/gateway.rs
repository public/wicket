//! The box's MCP gateway, on its node only (#151, #257): MCP's own methods answered here, the
//! tools this node decides answered from the box's token (#164), and the control host's tools
//! (`chan::ControlTool`) asked of it with a typed call (`Msg::Call`). Split out of `nodesrv.rs`
//! (#220).

use super::*;

/// One MCP gateway call from a box. A tool this node decides (#164) is answered here from the
/// box's token, connected or not ([`gw`]); one of the control host's is asked of it as a call and
/// answered when it is done, so a call cut short by the control host going away gets a clear,
/// retryable tool error.
///
/// With push delivery on for the box's harness (#252, [`chan::EdgeStart::push`]), a `GET` opens the
/// session's stream, which carries incoming messages as notifications ([`gw::push`]), and
/// `initialize` declares the capability the harness looks for.
pub(super) async fn gateway_call(node: &Arc<Node>, run: &str, req: hyper::Request<hyper::body::Incoming>) -> hyper::Response<GwOut> {
    use http_body_util::BodyExt;
    let push = node.edge_start(run).and_then(|e| e.push);
    if let (&http::Method::GET, Some(p)) = (req.method(), &push) {
        return push_stream(gw::push(node, run, p.clone()));
    }
    let resp = gateway_rpc(node, run, req, push.as_ref()).await;
    resp.map(|b| b.map_err(|never| match never {}).boxed_unsync())
}

/// What a box's gateway answers: a body sent whole, or a stream (#252).
pub(super) type GwOut = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, std::io::Error>;

/// The session's stream (MCP's streamable HTTP `GET`, server-sent events): each notification as
/// an event, and a comment every 15 s to keep it open. It ends when the box's client closes it.
pub(super) fn push_stream(rx: tokio::sync::mpsc::Receiver<serde_json::Value>) -> hyper::Response<GwOut> {
    use http_body_util::BodyExt;
    let events = futures_util::stream::unfold(rx, |mut rx| async move {
        let chunk = match tokio::time::timeout(std::time::Duration::from_secs(15), rx.recv()).await {
            Ok(Some(v)) => format!("event: message\ndata: {v}\n\n"),
            Ok(None) => return None,
            Err(_) => ": keepalive\n\n".to_string(),
        };
        Some((Ok::<_, std::io::Error>(hyper::body::Frame::data(bytes::Bytes::from(chunk))), rx))
    });
    hyper::Response::builder()
        .status(200)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(http_body_util::StreamBody::new(events).boxed_unsync())
        .expect("response")
}

/// `initialize`'s answer with push on (#252): the harness's capability declared, and MCP's
/// protocol held at a revision with a stream for server notifications (2026-07-28's has none).
pub(super) fn with_push(
    resp: hyper::Response<GwBody>,
    p: &wicket_agent::harness::MessagePush,
    asked: Option<&str>,
) -> hyper::Response<GwBody> {
    const LAST_WITH_STREAM: &str = "2025-11-25";
    let (parts, body) = resp.into_parts();
    let bytes = futures_util::FutureExt::now_or_never(http_body_util::BodyExt::collect(body)).map(|b| b.expect("infallible").to_bytes());
    let Some(mut v) = bytes.and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) else {
        return hyper::Response::from_parts(parts, GwBody::new(bytes::Bytes::new()));
    };
    if let Some(r) = v.get_mut("result").and_then(|r| r.as_object_mut()) {
        let version = asked.filter(|a| *a <= LAST_WITH_STREAM).unwrap_or(LAST_WITH_STREAM);
        r.insert("protocolVersion".into(), serde_json::json!(version));
        let caps = r.entry("capabilities").or_insert_with(|| serde_json::json!({}));
        if let Some(c) = caps.as_object_mut() {
            let ex = c.entry("experimental").or_insert_with(|| serde_json::json!({}));
            if let Some(ex) = ex.as_object_mut() {
                ex.insert(p.capability.clone(), serde_json::json!({}));
            }
        }
    }
    let mut out = hyper::Response::from_parts(parts, GwBody::new(bytes::Bytes::from(v.to_string())));
    out.headers_mut().remove(http::header::CONTENT_LENGTH);
    out
}

async fn gateway_rpc(
    node: &Arc<Node>,
    run: &str,
    req: hyper::Request<hyper::body::Incoming>,
    push: Option<&wicket_agent::harness::MessagePush>,
) -> hyper::Response<GwBody> {
    use http_body_util::BodyExt;
    let error = |id: serde_json::Value, code: i64, message: &str| {
        gw_reply(200, serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }))
    };
    let body = match http_body_util::Limited::new(req.into_body(), 1 << 20).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return gw_reply(
                413,
                serde_json::json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "request too large" } }),
            )
        }
    };
    let Ok(rpc) = serde_json::from_slice::<serde_json::Value>(&body) else { return error(serde_json::Value::Null, -32700, "parse error") };
    if !rpc.is_object() {
        return error(serde_json::Value::Null, -32600, "batches are not accepted");
    }
    let method = rpc.get("method").and_then(|m| m.as_str()).unwrap_or("");
    // A notification: nothing to answer.
    if rpc.get("id").is_none_or(|i| i.is_null()) {
        return gw_reply(202, serde_json::Value::Null);
    }
    let id = rpc["id"].clone();
    // MCP's own methods are the node's to answer (#257), the same answer wherever the gateway runs.
    if let Some(result) = wicket_proxy::gateway::handshake(method, &rpc["params"]) {
        let resp = gw_reply(200, serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }));
        return match push {
            Some(p) if method == "initialize" => with_push(resp, p, rpc["params"]["protocolVersion"].as_str()),
            _ => resp,
        };
    }
    if method != "tools/call" {
        return error(id, -32601, &format!("method {method} not found"));
    }
    let name = rpc["params"]["name"].as_str().unwrap_or("").to_string();
    let args = rpc["params"].get("arguments").cloned().unwrap_or(serde_json::json!({}));
    // The tools this node decides (#164), else the control host's (#257 slice 4b), asked as a call.
    let answer = match gw::tool(node, run, &name, &args).await {
        Some(a) => {
            gw::record(node, run, &name, &a.0);
            a
        }
        None => match chan::ControlTool::of(&name) {
            Some(chan::ControlTool::AwaitMessage) => await_control_message(node, run, &args).await,
            Some(tool) => call_or_offline(node, run, tool, &args).await,
            None => (format!("unknown tool {name}"), true),
        },
    };
    gw_reply(
        200,
        serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": {
        "content": [{ "type": "text", "text": answer.0 }], "isError": answer.1,
    } }),
    )
}

/// `await_message`, answered by the control host (#445). A message this box has had, given again by
/// a supervisor that took the run over after a control-host restart, is dropped (and the control
/// host told it was read), and the wait goes on; one it hasn't had is kept as read, and the control
/// host told, as its reply goes to the box.
async fn await_control_message(node: &Arc<Node>, run: &str, args: &serde_json::Value) -> (String, bool) {
    let wait = std::time::Duration::from_secs(args.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(300).clamp(1, 600));
    let until = std::time::Instant::now() + wait;
    loop {
        let (text, is_error) = call_or_offline(node, run, chan::ControlTool::AwaitMessage, args).await;
        match message_id(&text).filter(|_| !is_error) {
            Some(id) if node.had_message(run, &id) => {
                node.message_read(run, &id);
                if std::time::Instant::now() >= until {
                    return (format!("no message after {}s. You may call await_message again.", wait.as_secs()), false);
                }
            }
            Some(id) => {
                node.message_read(run, &id);
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    gw::note_heard(node, run, &v);
                }
                return (text, is_error);
            }
            None => return (text, is_error),
        }
    }
}

/// The id of the message an `await_message` answer gives, if it gives one.
pub(super) fn message_id(text: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(text).ok()?.get("message_id")?.as_str().map(String::from)
}

/// One of the control host's tools, asked of it; while it can't be reached, a clear refusal.
async fn call_or_offline(node: &Arc<Node>, run: &str, tool: chan::ControlTool, args: &serde_json::Value) -> (String, bool) {
    let mut tries = 0;
    loop {
        match node.call_control(run, tool, args).await {
            Ok(a) => return a,
            // A child this node started (#164) is answered once its control host has taken it over
            // and supervises it: a call before that waits for it (while its parent's control
            // connection is up, so its supervisor is on the way), for up to a minute.
            Err(_) if tries < 60 && started_here(node, run) && parent_connected(node, run) => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(e) => return offline(&e.to_string()),
        }
    }
}

/// A box this node started itself (#164).
pub(super) fn started_here(node: &Node, run: &str) -> bool {
    node.replica.lock().expect("replica").local(run).is_some()
}

/// Whether the control connection of the box that started `run` here is up.
pub(super) fn parent_connected(node: &Node, run: &str) -> bool {
    let path = node.replica.lock().expect("replica").box_path_of(run);
    path.and_then(|p| p.rsplit('/').nth(1).map(String::from)).is_some_and(|parent| node.owner(&parent).is_some())
}

/// What one of the control host's tools answers while it can't be reached: a clear refusal.
fn offline(why: &str) -> (String, bool) {
    (
        format!("the control host is unreachable ({why}): this needs it. Retry this call in a minute; if it was a wait (await_grant, await_message), call it again."),
        true,
    )
}

pub(super) fn gw_reply(status: u16, v: serde_json::Value) -> hyper::Response<GwBody> {
    let body = if v.is_null() { bytes::Bytes::new() } else { bytes::Bytes::from(v.to_string()) };
    hyper::Response::builder().status(status).header("content-type", "application/json").body(GwBody::new(body)).expect("response")
}
