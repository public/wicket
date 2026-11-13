//! The MCP gateway's tools, decided on the box's node (#164).
//!
//! Every authorization decision is made as close to the action as it can be: here, at the edge of
//! the sandbox, from the box's token in the node's verified feed replica. The control host issues
//! authority and takes human approvals; it isn't asked per tool call. What each tool needs:
//!
//! | tool | decided here from | the control host is asked for |
//! |---|---|---|
//! | `whoami` | the identity's stable claims ([`crate::chan::EdgeStart`]) and the token | nothing |
//! | `request_access` | the token and its grants (a use isn't spent) | the human's request, if it needs one; queued while unreachable |
//! | `await_grant` | this node's queue (`q-…`) | the human's decision (read where it is taken) |
//! | `pending_requests` | this node's queue | the human's open requests |
//! | `request_capacity`, `request_update` | (a human decides) | the request; queued while unreachable |
//!
//! A call that needs a human while the control host can't be reached is queued on this node's disk
//! (`edge.json`, beside #153's `asks.json`) under a node-local id `q-…`, made when the run's
//! connection is back, and its answer kept for `await_grant` on that id. Nothing is approved on
//! the node alone. Every other tool is relayed to the run's gateway on the control host.

use super::{Node, OLD_CONTROL};
use crate::chan::{Frame, Msg};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wicket_proxy::decide::Asked;

/// A tool call that needs a human, made while the run's control host was unreachable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueuedCall {
    /// Node-local id (`q-…`).
    pub id: String,
    pub run: String,
    pub name: String,
    pub args: Value,
    /// When it was made (Unix ms, node clock).
    pub at: i64,
    /// What the control host answered when it was made there.
    #[serde(default)]
    pub answer: Option<(String, bool)>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Raised {
    run: String,
    request: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Held {
    #[serde(default)]
    calls: BTreeMap<String, QueuedCall>,
    /// Queued asks (#153's, and `request_access`'s) the control host has since raised: their
    /// request ids, for `await_grant` on the node-local id.
    #[serde(default)]
    raised: BTreeMap<String, Raised>,
}

/// The node's queued tool calls and raised asks, on its disk (`edge.json`).
pub struct EdgeQueue {
    file: PathBuf,
    held: Mutex<Held>,
}

impl EdgeQueue {
    pub fn open(root: &Path) -> EdgeQueue {
        let file = root.join("edge.json");
        let held = std::fs::read(&file).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        EdgeQueue { file, held: Mutex::new(held) }
    }

    fn save(&self, held: &Held) {
        let _ = crate::nodesecrets::write_atomic(&self.file, &serde_json::to_vec(held).unwrap_or_default());
    }

    /// Queues a call (or finds the same one queued already): its id, and whether it is new.
    pub fn push_call(&self, run: &str, name: &str, args: &Value, at: i64) -> (String, bool) {
        use sha2::Digest;
        let digest = hex::encode(sha2::Sha256::digest(format!("{run}\n{name}\n{args}").as_bytes()));
        let id = format!("q-{}", &digest[..12]);
        let mut held = self.held.lock().expect("edge");
        if held.calls.contains_key(&id) {
            return (id, false);
        }
        held.calls
            .insert(id.clone(), QueuedCall { id: id.clone(), run: run.into(), name: name.into(), args: args.clone(), at, answer: None });
        self.save(&held);
        (id, true)
    }

    /// `run`'s calls not yet made on the control host.
    pub fn unmade(&self, run: &str) -> Vec<QueuedCall> {
        self.held.lock().expect("edge").calls.values().filter(|c| c.run == run && c.answer.is_none()).cloned().collect()
    }

    pub fn answer(&self, id: &str, text: String, is_error: bool) {
        let mut held = self.held.lock().expect("edge");
        if let Some(c) = held.calls.get_mut(id) {
            c.answer = Some((text, is_error));
            self.save(&held);
        }
    }

    fn call(&self, id: &str) -> Option<QueuedCall> {
        self.held.lock().expect("edge").calls.get(id).cloned()
    }

    /// The control host raised queued ask `id` of `run` as `request`.
    pub fn raised(&self, id: &str, run: &str, request: &str) {
        let mut held = self.held.lock().expect("edge");
        held.raised.insert(id.into(), Raised { run: run.into(), request: request.into() });
        self.save(&held);
    }

    fn request_of(&self, id: &str, run: &str) -> Option<String> {
        self.held.lock().expect("edge").raised.get(id).filter(|r| r.run == run).map(|r| r.request.clone())
    }

    pub fn drop_run(&self, run: &str) {
        let mut held = self.held.lock().expect("edge");
        let n = (held.calls.len(), held.raised.len());
        held.calls.retain(|_, c| c.run != run);
        held.raised.retain(|_, r| r.run != run);
        if (held.calls.len(), held.raised.len()) != n {
            self.save(&held);
        }
    }
}

/// Whether `run`'s control connection is up.
fn connected(node: &Node, run: &str) -> bool {
    node.owner(run).is_some()
}

/// Decides `name` here if it is one this node decides: its answer and whether it is an error. None:
/// relay it to the run's gateway on the control host.
pub(super) async fn tool(node: &Arc<Node>, run: &str, name: &str, args: &Value) -> Option<(String, bool)> {
    match name {
        "whoami" => Some(whoami(node, run)),
        "request_access" => Some(request_access(node, run, args).await),
        "await_grant" => Some(await_grant(node, run, args).await),
        "pending_requests" => Some(pending_requests(node, run).await),
        "request_capacity" | "request_update" if !connected(node, run) => Some(queue_call(node, run, name, args)),
        _ => None,
    }
}

fn whoami(node: &Arc<Node>, run: &str) -> (String, bool) {
    let Some(mut v) = node.edge_start(run).map(|e| e.who).filter(|w| w.is_object()) else {
        return ("this run has no wicket identity".into(), true);
    };
    let (until, accepts) = {
        let r = node.replica.lock().expect("replica");
        (r.authority_until(run), r.zone_of(run).map(|z| z.accept_from.clone()))
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("accepts_messages_from_zones".into(), json!(accepts.unwrap_or_default()));
        o.insert("authority_until".into(), json!(until.map(|ms| ms / 1000)));
        o.insert("decided_on".into(), json!(format!("node {}", node.name)));
        o.insert(
            "note".into(),
            json!("Your identity is issued and held by wicket's control host, short-lived and re-issued while you run; messages you send are signed with it there. What you may do is decided here, on your node, from your token."),
        );
    }
    (serde_json::to_string_pretty(&v).unwrap_or_default(), false)
}

/// An agent asking ahead for reach it needs, decided from its token here: already allowed or never
/// allowed are answered at once; anything else is put to a human (queued while unreachable).
async fn request_access(node: &Arc<Node>, run: &str, args: &Value) -> (String, bool) {
    let Some(url) = args.get("url").and_then(|v| v.as_str()) else {
        return ("`url` is required, e.g. https://example.org/docs/".into(), true);
    };
    let reason = args.get("reason").and_then(|v| v.as_str()).unwrap_or("").trim();
    if reason.is_empty() {
        return ("`reason` is required: say what you need it for, in a sentence".into(), true);
    }
    let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_ascii_uppercase();
    let prefix = args.get("scope").and_then(|v| v.as_str()) == Some("prefix");
    let Some(rest) = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")) else {
        return ("`url` must start with https:// (or http://)".into(), true);
    };
    let (authority, pq) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = match wicket_core::canonical_host(authority.rsplit_once(':').map_or(authority, |(h, _)| h)) {
        Ok(h) => h,
        Err(e) => return (format!("not requested: {e}"), true),
    };
    let pq = if pq.is_empty() { "/" } else { pq };
    let (raw_path, query) = pq.split_once('?').unwrap_or((pq, ""));
    let path = match wicket_core::canonical_path(raw_path) {
        Ok(p) => p.to_string(),
        Err(e) => return (format!("not requested: ambiguous path ({e})"), true),
    };
    let Some((tenant, zone)) = node.tenant_zone(run) else { return ("no authority for this box on its node".into(), true) };
    let verdict = node.replica.lock().expect("replica").host_verdict(run, &host);
    match verdict {
        wicket_core::HostVerdict::Forbidden(why) => {
            return (format!("not requested: {why}. This will never be allowed from this sandbox; tell the user."), false)
        }
        wicket_core::HostVerdict::Hidden => return (format!("not requested: {host} is not a host this sandbox can see."), false),
        wicket_core::HostVerdict::Open => {}
    }
    let op = wicket_core::Op::egress_with_query(&tenant, &wicket_core::RunId(run.into()), &zone, &method, &host, &path, query);
    if let Some(why) = op.refused_for_agents() {
        return (format!("not requested: {why}"), true);
    }
    let now = (node.clock)();
    let decision = node.replica.lock().expect("replica").peek(&op, now);
    match decision {
        wicket_feed::Decision::Allow(_) if !prefix => {
            return (format!("{method} {host}{path} is already allowed: just make the request."), false)
        }
        wicket_feed::Decision::Forbidden(why) => {
            return (format!("not requested: {why}. This will never be allowed from this sandbox; tell the user."), false)
        }
        wicket_feed::Decision::Refused { mode, why } => return (wicket_proxy::decide::stale_text(mode, &why), true),
        _ => {}
    }
    let scope = match prefix {
        true => format!("{method} {host}{}… (every path under it)", wicket_core::prefix_dir(&path)),
        false => format!("{method} {host}{path}"),
    };
    let why = format!("{}{reason}", crate::noderun::AGENT_ASKS);
    if connected(node, run) {
        match node.ask_control(run, &op, &why, None, prefix).await {
            Ok(Asked::Pending { request, fresh }) => {
                return (
                    format!(
                        "{} {request} for {scope}. Call await_grant with request_id {request} to wait for the decision. Don't try other routes meanwhile.",
                        if fresh { "requested:" } else { "already requested:" }
                    ),
                    false,
                )
            }
            Ok(Asked::Denied { request }) => {
                return (
                    format!("not requested: a human denied {request} for this a few minutes ago. Don't ask again; continue without it."),
                    false,
                )
            }
            Err(e) if e != super::NO_ANSWER => return (e, true),
            // Cut off mid-ask: queued, as when the control host is known to be down.
            Err(_) => {}
        }
    }
    let (id, new) = node.queue.push(run, &op, &why, None, now, prefix);
    if new {
        node.audit_note(
            run,
            "node.ask_queued",
            json!({ "id": id, "host": op.host, "method": op.method, "path": op.path, "prefix": prefix }),
        );
    }
    (
        format!(
            "queued: {id} for {scope}. wicket's control host is unreachable from your node, so it is put to a human when it is back. Call await_grant with request_id {id} to follow it."
        ),
        false,
    )
}

/// Waits for a human's decision. A node-local id (`q-…`) waits here until the control host has
/// raised it, then follows the request it became; a request id is read where the human decides.
async fn await_grant(node: &Arc<Node>, run: &str, args: &Value) -> (String, bool) {
    let Some(id) = args.get("request_id").and_then(|v| v.as_str()).map(String::from) else {
        return ("request_id is required".into(), true);
    };
    let timeout = Duration::from_secs(args.get("timeout_seconds").and_then(|v| v.as_u64()).unwrap_or(300).clamp(5, 600));
    let start = Instant::now();
    let left = || timeout.saturating_sub(start.elapsed());
    let mut request = id.clone();
    if id.starts_with("q-") {
        loop {
            if let Some(r) = node.edge.request_of(&id, run) {
                request = r;
                break;
            }
            if let Some(c) = node.edge.call(&id).filter(|c| c.run == run) {
                if let Some((text, is_error)) = c.answer {
                    return (format!("{id} was made when the control host came back: {text}"), is_error);
                }
            } else if !node.queue.of(run).iter().any(|q| q.id == id) {
                return (format!("no request {id} for this run"), true);
            }
            if left().is_zero() {
                return (
                    format!(
                        "pending: {id} is queued on your node, and wicket's control host is still unreachable after {}s. It is put to a human when it is back; you may call await_grant again.",
                        timeout.as_secs()
                    ),
                    false,
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    // Decided by a human, on the control host: read there, waiting for it to be reachable.
    loop {
        if connected(node, run) {
            let mut a = args.clone();
            a["request_id"] = json!(request);
            a["timeout_seconds"] = json!(left().as_secs().max(5));
            match relay_tool(node, run, "await_grant", &a).await {
                Ok((text, is_error)) if request != id => return (format!("{id} became {request}. {text}"), is_error),
                Ok(r) => return r,
                Err(_) => {}
            }
        }
        if left().is_zero() {
            return (
                format!(
                    "pending: wicket's control host is unreachable from your node, so {request} can't be decided now. Any decision reaches your node when it is back; you may call await_grant again."
                ),
                false,
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// The human's open requests (on the control host, when reachable) and what this node queued.
async fn pending_requests(node: &Arc<Node>, run: &str) -> (String, bool) {
    let mut out = match connected(node, run) {
        true => relay_tool(node, run, "pending_requests", &json!({})).await.map(|(t, _)| t).unwrap_or_else(|e| format!("({e})")),
        false => {
            "wicket's control host is unreachable from your node: requests already put to a human aren't listed until it is back.".into()
        }
    };
    let now = (node.clock)();
    let ago = |at: i64| (now - at).max(0) / 1000;
    let mut queued: Vec<String> = node
        .queue
        .of(run)
        .into_iter()
        .map(|q| {
            format!("- {} {} {}{}{} (queued {}s ago)", q.id, q.op.method, q.op.host, q.op.path, if q.prefix { "…" } else { "" }, ago(q.at))
        })
        .collect();
    queued.extend(node.edge.unmade(run).into_iter().map(|c| format!("- {} {} (queued {}s ago)", c.id, c.name, ago(c.at))));
    if !queued.is_empty() {
        out.push_str(&format!(
            "\n\nQueued on your node while the control host was unreachable (put to a human when it is back; await_grant follows each):\n{}",
            queued.join("\n")
        ));
    }
    (out, false)
}

fn queue_call(node: &Arc<Node>, run: &str, name: &str, args: &Value) -> (String, bool) {
    let (id, new) = node.edge.push_call(run, name, args, (node.clock)());
    if new {
        node.audit_note(run, "node.call_queued", json!({ "id": id, "tool": name }));
    }
    (
        format!(
            "queued: {name} needs a human, and wicket's control host is unreachable from your node. It is made as {id} when the control host is back; call await_grant with request_id {id} to follow it."
        ),
        false,
    )
}

/// Makes the calls `run` queued while its control host was unreachable, now that it is back, and
/// keeps their answers for `await_grant`.
pub(super) fn replay(node: &Arc<Node>, run: &str) {
    for c in node.edge.unmade(run) {
        let (n, run) = (node.clone(), run.to_string());
        tokio::spawn(async move {
            for _ in 0..5 {
                if let Ok((text, is_error)) = relay_tool(&n, &run, &c.name, &c.args).await {
                    n.edge.answer(&c.id, text, is_error);
                    n.audit_note(&run, "node.call_made", json!({ "id": c.id, "tool": c.name }));
                    return;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
}

/// Calls tool `name` on the run's gateway on the control host: its text and whether it is an error.
pub(super) async fn relay_tool(node: &Arc<Node>, run: &str, name: &str, args: &Value) -> std::io::Result<(String, bool)> {
    if (1..crate::chan::EDGE_DECISIONS).contains(&node.proto_of(run)) {
        return Err(std::io::Error::other(OLD_CONTROL));
    }
    let rpc = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": args } });
    let resp = super::relay_rpc(node, run, None, bytes::Bytes::from(rpc.to_string())).await?;
    let body = http_body_util::BodyExt::collect(resp.into_body()).await.map_err(std::io::Error::other)?.to_bytes();
    let v: Value = serde_json::from_slice(&body).map_err(std::io::Error::other)?;
    let r = &v["result"];
    let text = r["content"][0]["text"].as_str().map(String::from);
    match text {
        Some(t) => Ok((t, r["isError"].as_bool().unwrap_or(false))),
        None => Err(std::io::Error::other(v["error"]["message"].as_str().unwrap_or("no answer").to_string())),
    }
}

/// The control host's record of a tool decided here, for its console.
pub(super) fn record(node: &Node, run: &str, name: &str, text: &str) {
    let ev =
        wicket_proxy::Event::Tool { name: name.into(), detail: format!("{} (on node {})", text.lines().next().unwrap_or(""), node.name) };
    if let Ok(event) = serde_json::to_value(&ev) {
        node.send_run(run, Frame::Msg(Msg::Event { run: run.into(), event }));
    }
}
