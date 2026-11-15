//! The box's MCP gateway on its node (#151): calls relayed to the run's own gateway, and MCP's
//! handshake answered while the control host can't be reached. Split out of `nodesrv.rs` (#220).

use super::*;

/// One MCP gateway call from a box. A tool this node decides (#164) is answered here from the
/// box's token, connected or not ([`gw`]); every other call is relayed to the run's gateway on the
/// control host, whole (the answers are small), so a call cut short by the control host going
/// away gets a clear, retryable tool error instead of a broken response.
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
pub(super) fn with_push(resp: hyper::Response<GwBody>, p: &wicket_agent::harness::MessagePush, asked: Option<&str>) -> hyper::Response<GwBody> {
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
    let (parts, body) = req.into_parts();
    let body = match http_body_util::Limited::new(body, 1 << 20).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            return gw_reply(
                413,
                serde_json::json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32600, "message": "request too large" } }),
            )
        }
    };
    let rpc: serde_json::Value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    if rpc.get("method").and_then(|m| m.as_str()) == Some("tools/call") && rpc.get("id").is_some() && node.edge_start(run).is_some() {
        let name = rpc["params"]["name"].as_str().unwrap_or("").to_string();
        let args = rpc["params"].get("arguments").cloned().unwrap_or(serde_json::json!({}));
        if let Some((text, is_error)) = gw::tool(node, run, &name, &args).await {
            gw::record(node, run, &name, &text);
            return gw_reply(
                200,
                serde_json::json!({ "jsonrpc": "2.0", "id": rpc["id"], "result": {
                    "content": [{ "type": "text", "text": text }], "isError": is_error,
                } }),
            );
        }
    }
    let init = rpc.get("method").and_then(|m| m.as_str()) == Some("initialize");
    let resp = relay_or_offline(node, run, &parts, &body, &rpc).await;
    match push {
        Some(p) if init => with_push(resp, p, rpc["params"]["protocolVersion"].as_str()),
        _ => resp,
    }
}

async fn relay_or_offline(
    node: &Arc<Node>,
    run: &str,
    parts: &http::request::Parts,
    body: &bytes::Bytes,
    rpc: &serde_json::Value,
) -> hyper::Response<GwBody> {
    let mut tries = 0;
    loop {
        match relay_rpc(node, run, Some(parts), body.clone()).await {
            Ok(r) => return r,
            // A child this node started (#164) is relayed to once its control host has taken it
            // over and supervises it: a call before that waits for it (while its parent's control
            // connection is up, so its supervisor is on the way), for up to a minute.
            Err(_) if tries < 60 && started_here(node, run) && parent_connected(node, run) => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(e) => return gateway_offline(rpc, &e.to_string()),
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

/// Relays one JSON-RPC request to the run's gateway on the control host, and reads its answer.
pub(super) async fn relay_rpc(
    node: &Arc<Node>,
    run: &str,
    parts: Option<&http::request::Parts>,
    body: bytes::Bytes,
) -> std::io::Result<hyper::Response<GwBody>> {
    use http_body_util::BodyExt;
    let io = node.open_tunnel(run, "gateway").await?;
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io)).await.map_err(std::io::Error::other)?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut rb = match parts {
        Some(p) => {
            let mut rb = hyper::Request::builder().method(p.method.clone()).uri(p.uri.clone());
            for (k, v) in p.headers.iter() {
                rb = rb.header(k, v);
            }
            rb
        }
        None => hyper::Request::builder().method("POST").uri("/mcp").header("content-type", "application/json"),
    };
    if parts.is_none() {
        rb = rb.header("accept", "application/json");
    }
    let resp = send.send_request(rb.body(GwBody::new(body)).map_err(std::io::Error::other)?).await.map_err(std::io::Error::other)?;
    let (rp, rb) = resp.into_parts();
    let bytes = rb.collect().await.map_err(std::io::Error::other)?.to_bytes();
    Ok(hyper::Response::from_parts(rp, GwBody::new(bytes)))
}

/// What the gateway answers while the control host can't be reached: MCP's own handshake, and a
/// clear refusal for every tool (each needs the control plane).
pub(super) fn gateway_offline(rpc: &serde_json::Value, why: &str) -> hyper::Response<GwBody> {
    let id = rpc.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = rpc.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let result = match method {
        "initialize" => serde_json::json!({
            "protocolVersion": rpc["params"]["protocolVersion"].as_str().unwrap_or("2025-03-26"),
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "wicket", "version": env!("CARGO_PKG_VERSION") },
        }),
        "ping" => serde_json::json!({}),
        _ if id.is_null() => return gw_reply(202, serde_json::Value::Null),
        _ => serde_json::json!({
            "content": [{ "type": "text", "text": format!(
                "the control plane is unreachable ({why}): this needs it. Retry this call in a minute; if it was a wait (await_grant, await_message), call it again."
            ) }],
            "isError": true,
        }),
    };
    gw_reply(200, serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

pub(super) fn gw_reply(status: u16, v: serde_json::Value) -> hyper::Response<GwBody> {
    let body = if v.is_null() { bytes::Bytes::new() } else { bytes::Bytes::from(v.to_string()) };
    hyper::Response::builder().status(status).header("content-type", "application/json").body(GwBody::new(body)).expect("response")
}
