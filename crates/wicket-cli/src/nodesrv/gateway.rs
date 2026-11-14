//! The box's MCP gateway on its node (#151): calls relayed to the run's own gateway, and MCP's
//! handshake answered while the control host can't be reached. Split out of `nodesrv.rs` (#220).

use super::*;

/// One MCP gateway call from a box. A tool this node decides (#164) is answered here from the
/// box's token, connected or not ([`gw`]); every other call is relayed to the run's gateway on the
/// control host, whole (the answers are small), so a call cut short by the control host going
/// away gets a clear, retryable tool error instead of a broken response.
pub(super) async fn gateway_call(node: &Arc<Node>, run: &str, req: hyper::Request<hyper::body::Incoming>) -> hyper::Response<GwBody> {
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
    let mut tries = 0;
    loop {
        match relay_rpc(node, run, Some(&parts), body.clone()).await {
            Ok(r) => return r,
            // A child this node started (#164) is relayed to once its control host has taken it
            // over and supervises it: a call before that waits for it (while its parent's control
            // connection is up, so its supervisor is on the way), for up to a minute.
            Err(_) if tries < 60 && started_here(node, run) && parent_connected(node, run) => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(e) => return gateway_offline(&rpc, &e.to_string()),
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
