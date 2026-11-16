//! Target 2: the control host's half of the MCP gateway (#257 slice 4b): its tools, with the
//! arguments a box gives them, as a box's node asks them (`Msg::Call`, `Gateway::call_tool`), and
//! MCP's handshake (`wicket_proxy::gateway::handshake`), which every gateway answers alike. The
//! input is a JSON-RPC body; with a leading `\0`, the rest is a raw HTTP request whose body is
//! taken (the seeds of the HTTP server this target fuzzed before the node took it over).
//!
//! Time is paused and advances on its own, so `await_grant` and `await_message` (which wait for up
//! to minutes) answer at once. The oracle: no panic, every call answers, a name that isn't one of
//! the control host's tools (`chan::ControlTool`) is never asked of it, and `initialize` answers
//! with a protocol version and wicket's instructions.

use std::sync::OnceLock;
use std::time::Duration;

fn vault() -> std::path::PathBuf {
    static V: OnceLock<std::path::PathBuf> = OnceLock::new();
    V.get_or_init(|| crate::util::scratch("gateway-vault")).clone()
}

pub fn run(data: &[u8]) {
    let body = match data.first() {
        Some(0) => {
            let raw = &data[1..];
            match raw.windows(4).position(|w| w == b"\r\n\r\n") {
                Some(i) => &raw[i + 4..],
                None => return,
            }
        }
        _ => data,
    };
    let Ok(rpc) = serde_json::from_slice::<serde_json::Value>(body) else { return };
    let method = rpc.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let params = rpc.get("params").cloned().unwrap_or(serde_json::Value::Null);
    if let Some(r) = wicket_proxy::gateway::handshake(method, &params) {
        if method == "initialize" {
            assert!(r.get("protocolVersion").is_some() && r["instructions"].is_string(), "{r}");
        }
        return;
    }
    if method != "tools/call" {
        return;
    }
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    // What the node would send: only the control host's own tools, by name.
    let Some(tool) = crate::chan::ControlTool::of(name) else { return };
    let args = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().start_paused(true).build().expect("runtime");
    let (ctx, _events) = crate::util::ctx("reach: [{host: api.example.com, methods: [GET], paths: ['/**']}]", vault());
    let answered = rt.block_on(async {
        let gw = wicket_proxy::gateway::Gateway::new(ctx);
        // Paused time: an hour passes in no time when nothing else can run.
        tokio::time::timeout(Duration::from_secs(3600), gw.call_tool(&tool.name(), args)).await
    });
    let (text, _) = answered.unwrap_or_else(|_| panic!("{name} didn't answer within an hour of (paused) time"));
    assert!(!text.is_empty(), "{name} answered nothing");
}
