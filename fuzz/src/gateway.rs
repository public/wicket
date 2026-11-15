//! Target 2: the MCP gateway's JSON-RPC (tool calls, their arguments, oversized and nested
//! inputs), through its real HTTP/1.1 server. The input is a JSON-RPC body, POSTed as is; with a
//! leading `\0` the rest is the raw connection instead (requests of the fuzzer's own framing).
//!
//! Time is paused and advances on its own, so `await_grant` and `await_message` (which wait for up
//! to minutes) answer at once. The oracle: no panic, every connection ends, and a request with an
//! `id` gets one JSON-RPC reply with that `id`.

use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn vault() -> std::path::PathBuf {
    static V: OnceLock<std::path::PathBuf> = OnceLock::new();
    V.get_or_init(|| crate::util::scratch("gateway-vault")).clone()
}

pub fn run(data: &[u8]) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().expect("runtime");
    let raw = data.first() == Some(&0);
    let wire = if raw {
        data[1..].to_vec()
    } else {
        let mut w = format!("POST /mcp HTTP/1.1\r\nhost: gateway\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", data.len())
            .into_bytes();
        w.extend_from_slice(data);
        w
    };
    let (ctx, _events) = crate::util::ctx("reach: [{host: api.example.com, methods: [GET], paths: ['/**']}]", vault());
    let out = rt.block_on(async {
        let gw = wicket_proxy::gateway::Gateway::new(ctx);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(gw.serve_io(server, crate::egress::half_closing()));
        let talk = async {
            let (mut rd, mut wr) = tokio::io::split(&mut client);
            let write = async {
                let _ = wr.write_all(&wire).await;
                let _ = wr.shutdown().await;
            };
            let mut out = Vec::new();
            let read = async {
                let _ = rd.read_to_end(&mut out).await;
            };
            tokio::join!(write, read);
            out
        };
        // Paused time: an hour passes in no time when nothing else can run.
        let out = tokio::time::timeout(Duration::from_secs(3600), talk).await;
        served.abort();
        out
    });
    let out = out.expect("the gateway didn't answer within an hour of (paused) time");
    if raw {
        return;
    }
    let Ok(req) = serde_json::from_slice::<serde_json::Value>(data) else { return };
    let Some(id) = req.get("id").filter(|_| req.is_object()) else { return };
    let text = String::from_utf8_lossy(&out);
    let Some((head, body)) = text.split_once("\r\n\r\n") else { panic!("no response to a request with an id: {text:?}") };
    if !head.starts_with("HTTP/1.1 200") {
        return; // 409 superseded, 413 too large: no reply body expected
    }
    let reply: serde_json::Value = serde_json::from_str(body).unwrap_or_else(|e| panic!("a reply that isn't JSON ({e}): {body:?}"));
    assert_eq!(reply.get("id"), Some(id), "the reply's id isn't the request's: {reply}");
}
