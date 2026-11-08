//! Enforcement points (design §9). Both proxies listen on unix sockets that are bind-mounted into
//! the sandbox: the socket a request arrives on *is* the sandbox's identity, so no bearer token is
//! ever needed inside the box.

pub mod ca;
pub mod egress;
pub mod gateway;
pub mod llm;
pub mod vault;

use serde::Serialize;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::UnboundedSender;
use wicket_core::{RunId, TenantId, ZoneSpec};
use wicket_store::Ledger;

/// What a run's enforcement points share.
#[derive(Clone)]
pub struct RunCtx {
    pub tenant: TenantId,
    pub run: RunId,
    pub zone: Arc<ZoneSpec>,
    pub ledger: Arc<Mutex<Ledger>>,
    pub vault: vault::Vault,
    pub events: UnboundedSender<Event>,
    /// False for programs with `on_pending: fail`: out-of-reach requests fail without a pending request.
    pub escalate: bool,
    /// Who inside the box is making a request to (host, path), as reported by the agent's event
    /// stream: the attribution as JSON, plus a one-line summary. Untrusted; for humans only.
    pub attribute: Option<Attributor>,
}

pub type Attributor = Arc<dyn Fn(&str, &str) -> Option<(serde_json::Value, String)> + Send + Sync>;

/// One line describing an attribution object, for terminals and logs.
pub fn attribution_line(v: &serde_json::Value) -> String {
    let rs = v.get("requesters").and_then(|r| r.as_array()).cloned().unwrap_or_default();
    let one = |r: &serde_json::Value| {
        let g = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("?").to_string();
        format!("{} via {}: {}", g("agent"), g("tool"), g("call").chars().take(80).collect::<String>())
    };
    match v.get("basis").and_then(|b| b.as_str()).unwrap_or("none") {
        "none" => "unknown (no tool call in flight)".into(),
        "ambiguous" => format!("one of: {}", rs.iter().map(one).collect::<Vec<_>>().join(" | ")),
        _ => rs.first().map(one).unwrap_or_default(),
    }
}

/// The agents an attribution object names.
pub fn attributed_agents(v: &serde_json::Value) -> Vec<String> {
    v.get("requesters")
        .and_then(|r| r.as_array())
        .map(|rs| rs.iter().filter_map(|r| r.get("agent").and_then(|a| a.as_str()).map(String::from)).collect())
        .unwrap_or_default()
}

/// Live events for the operator's console and the audit log.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Egress { method: String, host: String, path: String, risk: String, outcome: String, detail: String },
    Llm { model: Option<String>, status: u16, input_tokens: u64, output_tokens: u64, requests: u64, outcome: String },
    Tool { name: String, detail: String },
}

impl RunCtx {
    pub(crate) fn emit(&self, ev: Event) {
        if let Ok(v) = serde_json::to_value(&ev) {
            if let Ok(l) = self.ledger.lock() {
                let _ = l.audit(&self.tenant, Some(&self.run), "op", &v);
            }
        }
        let _ = self.events.send(ev);
    }
}

pub(crate) type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) fn full(b: impl Into<bytes::Bytes>) -> BoxBody {
    use http_body_util::BodyExt;
    http_body_util::Full::new(b.into()).map_err(|never| match never {}).boxed()
}

/// An RFC 9457 problem+json response that tells the agent what happened and what it can do.
pub(crate) fn problem(status: u16, kind: &str, title: &str, detail: &str, request_id: Option<&str>) -> http::Response<BoxBody> {
    let mut body = serde_json::json!({
        "type": format!("https://wicket.dev/e/{kind}"),
        "title": title,
        "status": status,
        "detail": detail,
    });
    if let Some(id) = request_id {
        body["request_id"] = id.into();
        body["retry_after"] = 30.into();
        body["hint"] = "A human must approve this request. Do not try another route. Wait (e.g. sleep 30), then retry the same request; it will succeed once approved, or fail with status 'denied'.".into();
    }
    let mut b = http::Response::builder()
        .status(status)
        .header("content-type", "application/problem+json")
        .header("x-wicket", kind);
    if let Some(id) = request_id {
        b = b.header("x-wicket-request-id", id).header("retry-after", "30");
    }
    b.body(full(serde_json::to_vec_pretty(&body).unwrap_or_default())).expect("valid response")
}

/// Headers never forwarded from a sandbox to an upstream: hop-by-hop headers and every client
/// credential (the proxy injects its own).
pub(crate) const STRIP_REQUEST: &[&str] = &[
    "connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer",
    "transfer-encoding", "upgrade", "host", "content-length", "authorization", "x-api-key", "cookie",
];

pub(crate) const STRIP_RESPONSE: &[&str] = &["connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "content-length"];
