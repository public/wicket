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
    /// This agent instance's wicket-issued identity (design §3.2), rotated while it runs. None for
    /// programs.
    pub identity: Option<Arc<IdentityCell>>,
    /// Starts a child agent in its own sandbox; None when the agent may not spawn.
    pub spawner: Option<Spawner>,
    /// Placeholders the box holds in place of real credentials, swapped at the egress proxy.
    pub swaps: Vec<CredentialSwap>,
}

/// A credential the box only ever sees as a placeholder. When a request to `host` carries exactly
/// `Authorization: Bearer <placeholder>`, the egress proxy sends the real value instead. The
/// placeholder is worthless anywhere else (it's stripped like every client credential), and the real
/// value never enters the box.
#[derive(Clone)]
pub struct CredentialSwap {
    /// For logs: what this credential is (never its value).
    pub name: String,
    pub host: String,
    pub placeholder: String,
    pub real: SwapSource,
}

#[derive(Clone)]
pub enum SwapSource {
    /// A vault secret, read per request (e.g. a reference to the host's login, refreshed there).
    Vault(String),
    /// A value handed to wicket by the process that launched the agent, kept in memory only.
    Value(String),
}

/// An agent instance's identity: the document wicket issued and the key it signs with on the
/// agent's behalf. The key lives here, in the `wicket run` process, never in the box.
pub struct RunIdentity {
    pub jws: String,
    pub claims: wicket_identity::AgentClaims,
    pub key: wicket_identity::AgentKey,
    /// The installation issuer's public key, for verifying other agents' envelopes.
    pub issuer: wicket_identity::VerifyingKey,
}

/// The current identity of a run. The runner swaps in a fresh document and key every few minutes;
/// readers always take the latest.
pub struct IdentityCell(std::sync::RwLock<Arc<RunIdentity>>);

impl IdentityCell {
    pub fn new(i: RunIdentity) -> IdentityCell {
        IdentityCell(std::sync::RwLock::new(Arc::new(i)))
    }
    pub fn current(&self) -> Arc<RunIdentity> {
        self.0.read().expect("identity").clone()
    }
    pub fn replace(&self, i: RunIdentity) {
        *self.0.write().expect("identity") = Arc::new(i);
    }
}

/// A box an agent asks to start (design §5.1): an agent or a program, in a zone the agent writes
/// itself, which must be a subset of its own unless a human approves exactly that zone.
#[derive(Debug, Clone, Default)]
pub struct SpawnRequest {
    pub name: String,
    /// "agent" or "program" (a program can be a long-running service).
    pub kind: String,
    /// An agent's task.
    pub task: Option<String>,
    /// A program's command line.
    pub command: Vec<String>,
    /// Default: the parent's image.
    pub image: Option<String>,
    /// The new zone, in manifest form (JSON). Omitted fields default to the parent's (limits with the
    /// time it has left, isolation, unlisted_hosts) or to nothing (reach, inject, volumes).
    pub zone: Option<serde_json::Value>,
    pub max_children: u32,
    /// If the zone isn't a subset of the parent's, put exactly this zone to a human instead of refusing.
    pub ask_human: bool,
    /// spawn_agent's shorthand: the parent's zone, narrowed to these hosts.
    pub reach_hosts: Option<Vec<String>>,
}

/// Ok: what to tell the agent (started, or waiting for approval). Err: why not.
pub type Spawner = Arc<dyn Fn(SpawnRequest) -> std::result::Result<String, String> + Send + Sync>;

/// Maximum size of a message body, in bytes of JSON.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

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
    /// Sends a signed message from this agent to the agent running as `to_run`. The sender is this
    /// run's identity, set by wicket; the agent can't choose it. Allowed between parent and child,
    /// or when the recipient's zone lists this zone in `accept_from`, within one tenant.
    pub fn send_message(&self, to_run: &str, kind: &str, body: serde_json::Value) -> std::result::Result<String, String> {
        let me = self.identity.as_ref().ok_or("this run has no wicket identity")?.current();
        let now = wicket_store::now();
        if me.claims.exp <= now {
            return Err("this agent's identity has expired and was not refreshed; it can't send".into());
        }
        let size = body.to_string().len();
        if size > MAX_MESSAGE_BYTES {
            return Err(format!("message body is {size} bytes; the limit is {MAX_MESSAGE_BYTES}"));
        }
        let l = self.ledger.lock().map_err(|_| "ledger lock")?;
        if let Some((r, ..)) = l.revoked_in_chain(&self.run.0).map_err(|e| e.to_string())? {
            return Err(format!("this agent's identity was revoked (revoked: {r})"));
        }
        let rec = match l.identity(to_run).map_err(|e| e.to_string())? {
            Some(r) if r.tenant == self.tenant.0 => r,
            _ => return Err(format!("no agent {to_run}")),
        };
        if l.run_status(to_run).map_err(|e| e.to_string())?.as_deref() != Some("running") {
            return Err(format!("agent {} ({to_run}) is not running", rec.agent));
        }
        let relation = if rec.parent_run.as_deref() == Some(&self.run.0) {
            "child"
        } else if me.claims.parent_run.as_deref() == Some(to_run) {
            "parent"
        } else if rec.accept_from.iter().any(|z| z == &self.zone.name) {
            "peer"
        } else {
            return Err(format!("zone {} does not accept messages from zone {} (its accept_from does not list it)", rec.zone, self.zone.name));
        };
        let id = format!("m-{}", ulid::Ulid::new().to_string().to_lowercase());
        let payload = serde_json::json!({
            "jti": id, "iat": now, "kind": kind,
            "to": rec.spiffe_id, "to_run": to_run, "body": body,
        });
        let env = wicket_identity::sign_envelope(&me.key, &me.jws, &payload);
        l.add_message(&id, &self.tenant, &self.run.0, to_run, &env).map_err(|e| e.to_string())?;
        let _ = l.audit(&self.tenant, Some(&self.run), "message", &serde_json::json!({
            "id": id, "kind": kind, "from": me.claims.sub, "to": rec.spiffe_id, "to_run": to_run, "relation": relation, "bytes": size,
        }));
        Ok(id)
    }

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
        body["hint"] = format!("Call the wicket MCP tool await_grant with request_id {id} to wait for a human's decision, then retry this same request once. Nothing else will reach this destination from the sandbox.").into();
    }
    let mut b = http::Response::builder()
        .status(status)
        .header("content-type", "application/problem+json")
        .header("x-wicket", kind);
    if let Some(id) = request_id {
        b = b.header("x-wicket-request-id", id).header("retry-after", "30");
    }
    let mut resp = b.body(full(serde_json::to_vec_pretty(&body).unwrap_or_default())).expect("valid response");
    // Many tools show only the status line, not the body: make it say what happened.
    let reason: String = match request_id {
        Some(id) => format!("{title} ({id})"),
        None => title.to_string(),
    }
    .chars()
    .filter(|c| c.is_ascii() && !c.is_ascii_control())
    .collect();
    if let Ok(r) = hyper::ext::ReasonPhrase::try_from(reason) {
        resp.extensions_mut().insert(r);
    }
    resp
}

/// What every refusal reminds the agent of: where it is, and that there is no other way out.
pub(crate) const SANDBOX_FACT: &str = "You are in a wicket sandbox (a gVisor container with no network of its own); wicket's proxy is its only route out, so no other tool, host, mirror or cache will reach this either.";

/// Headers never forwarded from a sandbox to an upstream: hop-by-hop headers and every client
/// credential (the proxy injects its own).
pub(crate) const STRIP_REQUEST: &[&str] = &[
    "connection", "keep-alive", "proxy-connection", "proxy-authorization", "proxy-authenticate", "te", "trailer",
    "transfer-encoding", "upgrade", "host", "content-length", "authorization", "x-api-key", "cookie",
];

pub(crate) const STRIP_RESPONSE: &[&str] = &["connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "content-length"];
