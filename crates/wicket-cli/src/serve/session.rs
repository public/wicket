//! A boxed agent's session over ACP, for the browser (#327): `GET /api/runs/<run>/acp`, a WebSocket
//! that speaks the Agent Client Protocol (v1) with wicket as the *agent* and the browser as the
//! client. One endpoint per run; the session id is the run id.
//!
//! **Who.** The socket acts as one operator's principal (#11): the one whose passkey signed the
//! `open_session` action that issued its ticket. Opening needs all of:
//! - a signed-in operator session (the cookie), and the console's own `Origin` (no cross-site
//!   WebSocket: browsers send cookies on cross-site upgrades, so the origin is what stops them);
//! - a ticket from a fresh passkey assertion over `{"action":"open_session","run":…}`, single use,
//!   [`TICKET_TTL`] long, bound to the session that asked and the run it names, sent as the
//!   `wicket.ticket.<hex>` WebSocket subprotocol (never in the URL, which logs keep);
//! - the run still running and its identity not revoked.
//!
//! The socket closes when its console session ends (sign-out, idle, expiry, revoked passkey) or the
//! run does. A stolen cookie alone opens nothing.
//!
//! **Bridge.** wicket's supervisor is the box's only ACP client (#66): it drives the agent over the
//! box's stdio, through the node channel, and answers the agent's permission requests by wicket's
//! policy. This endpoint doesn't talk to the box itself; it reads both sides of that conversation:
//! the agent's from the run's transcript, wicket's from [`crate::transcript::ACP_LOG`], put back in
//! order by transcript offset. A prompt from the browser becomes an operator message, which the
//! supervisor hands to its ACP client as the next turn (v1 has no steering),
//! and its `session/prompt` is answered with the agent's stop reason when that turn ends.
//!
//! What the browser gets:
//! - the agent's `session/update` notifications (messages, thoughts, tool calls with their input,
//!   output and diffs, plans, commands), with its `_meta` dropped everywhere and the session id
//!   rewritten to the run id; updates using wicket's reserved tool-call ids are dropped;
//! - other principals' prompts (the task, other operators, wicket's own notices) as
//!   `user_message_chunk`s, with `_meta.wicket.by`;
//! - how wicket answered each of the agent's permission requests, as a `tool_call_update` with
//!   `_meta.wicket.permission` (allow_once, reject_once or cancelled: already decided by policy);
//! - **wicket's escalations** for the run (its pending requests in the ledger) as
//!   `session/request_permission` requests with a tool call `wicket:escalation:<id>` and
//!   `_meta.wicket.escalation`. The browser's answer **decides nothing**: a decision is made only
//!   through the console's signed decide action (a fresh passkey assertion, `/api/decide/*`, the same
//!   decide path as everywhere, #256). When the browser answers, the endpoint reads the request's
//!   status from the ledger and audits what it saw. Nothing the agent or a peer says can raise one of
//!   these prompts, since they come from the ledger only, and `_meta` from the agent never passes.
//!
//! **Audit.** `session.opened` (with the signed assertion), `session.attached`, every prompt
//! (`session.prompt`, by principal, with the text's digest and the operator message it queued),
//! every answer to an escalation prompt (`session.escalation_answered`, with the ledger's status), and
//! `session.closed`. Decisions themselves are audited by the decide path, and wicket's answers to the
//! agent's permission requests by the supervisor (`run.agent_prompt`).
//!
//! **Cancel.** `session/cancel` is queued in the ledger for the run's supervisor (`session.cancel`),
//! which sends the agent ACP's own `session/cancel` for its running turn within a second or so
//! (`run.turn_cancel`); the turn ends with `cancelled`, which answers that turn's `session/prompt`.
//! Prompts queued behind it stay queued.
//!
//! **Caps.** Upgraded sockets leave the console's connection cap, so they have their own:
//! [`MAX_SOCKETS_PER_SESSION`] per console session and [`MAX_SOCKETS`] in all, checked when the
//! ticket is issued and taken at the upgrade (429 over a cap, without spending the ticket).
//!
//! Not in this slice: the human answering the agent's own permission requests (#67's
//! `answer_agent_prompts`), images and resources in prompts, and more than one run per socket.

use super::{check_running, session as console_session, Ctx, OperatorCredential, SessionKind, State};
use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame, Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::Message;
use wicket_core::RunId;
use wicket_store::Ledger;

/// How long an `open_session` ticket may wait for its WebSocket.
pub const TICKET_TTL: Duration = Duration::from_secs(60);
/// The subprotocol the browser offers and wicket selects.
pub const SUBPROTOCOL: &str = "acp.v1";
/// The subprotocol prefix that carries the ticket.
pub const TICKET_PREFIX: &str = "wicket.ticket.";
/// The tool-call id prefix that only wicket's own escalation prompts use.
pub const RESERVED_ID: &str = "wicket:";
/// Longest message the browser may send (a prompt is at most the console's MAX_TEXT anyway).
const MAX_IN: usize = 256 << 10;
/// Longest agent line forwarded; longer ones are replaced by a notice.
const MAX_LINE: usize = 1 << 20;
/// How much of the transcript one poll reads.
const READ_CHUNK: usize = 4 << 20;
/// How often the run's files and the ledger are polled.
const POLL: Duration = Duration::from_millis(250);
/// How often the console session and the run are re-checked.
const RECHECK: Duration = Duration::from_secs(15);
/// How often one socket may ask for a cancel.
const CANCEL_EVERY: Duration = Duration::from_secs(1);
/// Prompts one socket may have waiting for their turn.
const MAX_WAITING: usize = 16;
/// Pending tickets in all.
const MAX_TICKETS: usize = 64;
/// Session sockets one console session may hold open at once (a few tabs or devices' worth: each
/// is one run's session).
pub const MAX_SOCKETS_PER_SESSION: usize = 4;
/// Session sockets open at once, in all. Upgraded connections leave the console's connection cap
/// (`--max-connections`), so they have this one of their own.
pub const MAX_SOCKETS: usize = 32;

/// The open session sockets, counted at the upgrade and freed when each one ends ([`Slot`]).
#[derive(Debug, Default)]
pub struct Sockets {
    total: usize,
    by_session: HashMap<String, usize>,
    /// Open sockets by (passkey credential, run): who watches which run's session now (#364).
    watching: HashMap<(String, String), usize>,
}

impl Sockets {
    /// Why another socket for `console_session` would be refused, if it would.
    fn full(&self, console_session: &str) -> Option<&'static str> {
        if self.total >= MAX_SOCKETS {
            return Some("too many sessions are open on this console; close one and try again");
        }
        if self.by_session.get(console_session).copied().unwrap_or(0) >= MAX_SOCKETS_PER_SESSION {
            return Some("this sign-in has too many sessions open; close one (another tab or device) and try again");
        }
        None
    }

    /// Whether the operator with passkey `cred` has `run`'s session open now.
    pub fn watching(&self, cred: &str, run: &str) -> bool {
        self.watching.get(&(cred.to_string(), run.to_string())).is_some_and(|n| *n > 0)
    }

    /// How many are open, in all and for `console_session`.
    #[cfg(test)]
    pub fn open(&self, console_session: &str) -> (usize, usize) {
        (self.total, self.by_session.get(console_session).copied().unwrap_or(0))
    }
}

/// One open (or opening) session socket's place under the caps; dropping it frees the place.
#[derive(Debug)]
pub struct Slot {
    sockets: std::sync::Arc<std::sync::Mutex<Sockets>>,
    console_session: String,
    /// The (passkey credential, run) this socket watches, once its ticket is checked.
    watch: Option<(String, String)>,
}

impl Slot {
    /// Takes a place for `console_session`, or says why not.
    pub fn take(sockets: &std::sync::Arc<std::sync::Mutex<Sockets>>, console_session: &str) -> Result<Slot, &'static str> {
        let mut s = sockets.lock().expect("lock");
        if let Some(why) = s.full(console_session) {
            return Err(why);
        }
        s.total += 1;
        *s.by_session.entry(console_session.to_string()).or_default() += 1;
        Ok(Slot { sockets: sockets.clone(), console_session: console_session.to_string(), watch: None })
    }

    /// Records that this socket is the operator with passkey `cred` watching `run`, until it drops.
    pub fn watch(&mut self, cred: &str, run: &str) {
        let key = (cred.to_string(), run.to_string());
        let mut s = self.sockets.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(old) = self.watch.replace(key.clone()) {
            if let Some(n) = s.watching.get_mut(&old) {
                *n = n.saturating_sub(1);
            }
        }
        *s.watching.entry(key).or_default() += 1;
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut s = self.sockets.lock().unwrap_or_else(|p| p.into_inner());
        s.total = s.total.saturating_sub(1);
        if let Some(n) = s.by_session.get_mut(&self.console_session) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                s.by_session.remove(&self.console_session);
            }
        }
        if let Some(w) = self.watch.take() {
            if let Some(n) = s.watching.get_mut(&w) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    s.watching.remove(&w);
                }
            }
        }
    }
}

/// The `sessionUpdate` kinds forwarded from the agent (ACP v1's).
const UPDATES: &[&str] = &[
    "agent_message_chunk",
    "agent_thought_chunk",
    "user_message_chunk",
    "tool_call",
    "tool_call_update",
    "plan",
    "available_commands_update",
    "current_mode_update",
];

/// A passkey-signed permission to open one run's session socket, once.
#[derive(Clone, Debug)]
pub struct Ticket {
    pub console_session: String,
    pub run: String,
    pub cred: String,
    pub name: String,
    pub expires: Instant,
}

/// Why another session socket for `console_session` would be refused now, if it would.
pub(super) fn over_cap(state: &State, console_session: &str) -> Option<&'static str> {
    state.sockets.lock().expect("lock").full(console_session)
}

/// Issues a ticket after the `open_session` action verified, and audits the signed open.
pub(super) fn open(state: &State, run: &str, oc: &OperatorCredential, console_session: &str, signed: Value) -> Result<Value> {
    let l = state.ledger()?;
    check_running(&l, run).map_err(|r| anyhow::anyhow!("{}", r.body["error"].as_str().unwrap_or("not running")))?;
    // Checked again here (sockets may have opened since the action began): no ticket for a socket
    // that would be refused.
    if let Some(why) = over_cap(state, console_session) {
        anyhow::bail!("{why}");
    }
    let op = crate::operators::Operator::console(&state.tenant.0, &oc.name)?;
    let ticket = super::random_hex(32);
    {
        let mut t = state.tickets.lock().expect("lock");
        let now = Instant::now();
        t.retain(|_, v| v.expires > now);
        if t.len() >= MAX_TICKETS {
            anyhow::bail!("too many sessions being opened; try again shortly");
        }
        t.insert(
            ticket.clone(),
            Ticket {
                console_session: console_session.to_string(),
                run: run.to_string(),
                cred: oc.id.clone(),
                name: oc.name.clone(),
                expires: now + TICKET_TTL,
            },
        );
    }
    l.audit(
        &state.tenant,
        Some(&RunId(run.to_string())),
        "session.opened",
        &json!({ "action": "open_session", "run": run, "by": op.label, "principal": op.id, "via": "console", "signed": signed }),
    )?;
    Ok(json!({
        "ok": format!("session for {run} opened as {} (signed with {}): connect within {}s", op.id, oc.name, TICKET_TTL.as_secs()),
        "ticket": ticket, "subprotocol": SUBPROTOCOL, "url": format!("/api/runs/{run}/acp"),
    }))
}

/// The run a path names, for `/api/runs/<run>/acp`.
pub fn run_of(path: &str) -> Option<&str> {
    let run = path.strip_prefix("/api/runs/")?.strip_suffix("/acp")?;
    (!run.is_empty() && run.len() <= 64 && run.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')).then_some(run)
}

/// Why an upgrade is refused (status and the one message the client sees).
pub type Refused = (http::StatusCode, &'static str);

/// Checks an upgrade request and takes its ticket and a place under the socket caps: what the
/// socket runs as, or why not.
pub(super) fn check_upgrade(
    state: &State,
    h: &http::HeaderMap,
    run: &str,
    sess: &(String, SessionKind),
) -> Result<(Ticket, String, Slot), Refused> {
    use http::StatusCode as S;
    let SessionKind::Operator { cred } = &sess.1 else { return Err((S::UNAUTHORIZED, "sign in with your passkey")) };
    let header = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("");
    if h.get("origin").map(|v| v.as_bytes()) != Some(state.rp.origin.as_bytes()) {
        return Err((S::FORBIDDEN, "cross-origin request refused"));
    }
    if h.get("sec-fetch-site").is_some_and(|v| v.as_bytes() != b"same-origin") {
        return Err((S::FORBIDDEN, "cross-origin request refused"));
    }
    let has = |k: &str, want: &str| header(k).split(',').any(|t| t.trim().eq_ignore_ascii_case(want));
    if !has("upgrade", "websocket") || !has("connection", "upgrade") || header("sec-websocket-version") != "13" {
        return Err((S::BAD_REQUEST, "a WebSocket upgrade (version 13) is required"));
    }
    let key = header("sec-websocket-key");
    if key.is_empty() {
        return Err((S::BAD_REQUEST, "a WebSocket upgrade (version 13) is required"));
    }
    let protocols: Vec<&str> = header("sec-websocket-protocol").split(',').map(str::trim).collect();
    if !protocols.contains(&SUBPROTOCOL) {
        return Err((S::BAD_REQUEST, "offer the acp.v1 subprotocol"));
    }
    let Some(tk) = protocols.iter().find_map(|p| p.strip_prefix(TICKET_PREFIX)) else {
        return Err((S::FORBIDDEN, "open the session with your passkey first"));
    };
    // Over a cap, the ticket isn't spent: the operator can close a socket and use it within its TTL.
    let mut slot = Slot::take(&state.sockets, &sess.0).map_err(|why| (S::TOO_MANY_REQUESTS, why))?;
    // Single use, whatever happens next.
    let t = state.tickets.lock().expect("lock").remove(tk);
    let Some(t) = t.filter(|t| t.expires > Instant::now()) else { return Err((S::FORBIDDEN, "unknown, used or expired ticket")) };
    if t.console_session != sess.0 || &t.cred != cred || t.run != run {
        return Err((S::FORBIDDEN, "the ticket was issued for something else"));
    }
    let l = state.ledger().map_err(|_| (S::INTERNAL_SERVER_ERROR, "the ledger is unavailable"))?;
    if check_running(&l, run).is_err() {
        return Err((S::CONFLICT, "the run is not running"));
    }
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    // The run's pushes don't go to this operator's devices while the socket is open (#364).
    slot.watch(cred, run);
    Ok((t, accept, slot))
}

/// What the socket (or `wicket session` in a terminal, #198) runs as.
#[derive(Clone, Debug)]
pub struct Who {
    /// The operator's principal id (`spiffe://…/op/passkey/<name>`).
    pub principal: String,
    /// The ledger's label for it (`passkey:<name>`), which operator messages carry.
    pub label: String,
    /// The console session's cookie token (to re-check the session).
    pub token: Option<String>,
    /// Where the session is open, for the audit log: `acp` (the console's socket) or `terminal`
    /// (`wicket session`).
    pub via: &'static str,
}

/// Serves an upgraded connection until the client, the console session or the run ends it.
pub(super) async fn serve<I>(io: I, state: std::sync::Arc<State>, run: String, who: Who, client: std::net::IpAddr)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut cfg = WebSocketConfig::default();
    cfg.max_message_size = Some(MAX_IN);
    cfg.max_frame_size = Some(MAX_IN);
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(io, Role::Server, Some(cfg)).await;
    let (mut tx, mut rx) = ws.split();
    let mut b = Bridge::new(state.ledger.clone(), state.data.join("runs").join(&run), state.tenant.clone(), run.clone(), who.clone());
    b.audit("session.attached", json!({ "run": run, "by": who.label, "principal": who.principal, "client": client.to_string() }));
    let mut poll = tokio::time::interval(POLL);
    let mut recheck = tokio::time::interval(RECHECK);
    recheck.tick().await;
    let ctx = Ctx { sid: who.token.clone(), client };
    // Why it ended, and the close code to send (None: the connection is already gone).
    let (code, reason): (Option<u16>, &'static str) = loop {
        let out = tokio::select! {
            m = rx.next() => match m {
                Some(Ok(Message::Text(t))) => {
                    // Activity on the socket keeps the console session alive, as requests do.
                    if console_session(&state, &ctx.sid).is_none() {
                        break (Some(4401), "the console session ended");
                    }
                    b.on_client(t.as_str())
                }
                Some(Ok(Message::Binary(_))) => b.error_out(Value::Null, -32700, "send JSON-RPC as text messages"),
                Some(Ok(Message::Close(_))) | None => break (None, "the client closed it"),
                Some(Ok(_)) => vec![],
                Some(Err(_)) => break (None, "the connection failed"),
            },
            _ = poll.tick() => b.poll(),
            _ = recheck.tick() => {
                if console_session(&state, &ctx.sid).is_none() {
                    break (Some(4401), "the console session ended");
                }
                if !b.running() {
                    let mut out = b.poll();
                    out.push(b.notice("the run ended"));
                    for m in out {
                        let _ = tx.send(Message::Text(m.to_string().into())).await;
                    }
                    break (Some(1000), "the run ended");
                }
                vec![]
            }
        };
        let mut failed = false;
        for m in out {
            if tx.send(Message::Text(m.to_string().into())).await.is_err() {
                failed = true;
                break;
            }
        }
        if failed {
            break (None, "the connection failed");
        }
    };
    if let Some(c) = code {
        let _ = tx.send(close(c, reason)).await;
    }
    b.audit("session.closed", json!({ "run": run, "by": who.label, "principal": who.principal, "prompts": b.prompts, "why": reason }));
}

fn close(code: u16, why: &'static str) -> Message {
    Message::Close(Some(CloseFrame { code: CloseCode::from(code), reason: why.into() }))
}

/// A prompt this socket queued, waiting for its turn's end.
#[derive(Debug)]
struct Waiting {
    /// The browser's JSON-RPC id for its `session/prompt`.
    rpc: Value,
}

/// A prompt handed to the supervisor's ACP client, in order (from the log's `queued` entries).
#[derive(Debug)]
struct Queued {
    by: String,
    op: Option<i64>,
}

/// One socket's view of a run's session. No sockets in here: it takes the browser's messages and
/// the run's files and returns the messages for the browser, so tests drive it directly.
pub struct Bridge {
    ledger: PathBuf,
    dir: PathBuf,
    tenant: wicket_core::TenantId,
    run: String,
    who: Who,
    /// Whether the client opened (`session/new` or `load`) the session: before, nothing is streamed.
    opened: bool,
    /// Where the bridge is in the transcript (absolute offset) and in the ACP log (bytes).
    agent_pos: u64,
    log_pos: u64,
    /// Log entries read but not yet due (written at a transcript offset not read yet).
    held: VecDeque<Value>,
    queued: VecDeque<Queued>,
    /// wicket's `session/prompt` request ids, with who the prompt was from and its operator message.
    prompt_rpc: HashMap<String, Queued>,
    /// This socket's prompts, by operator message.
    waiting: BTreeMap<i64, Waiting>,
    /// The agent's permission requests by their JSON-RPC id: their tool call id.
    permissions: HashMap<String, String>,
    /// Escalations shown (request ids), and the ones the client was asked about and hasn't answered.
    shown: BTreeSet<String>,
    asked: BTreeMap<String, String>,
    next_id: u64,
    pub prompts: u64,
    /// When this socket last asked for a cancel.
    last_cancel: Option<Instant>,
    /// For a harness that doesn't speak ACP (#364): its adapter's translation of both sides, named
    /// by the log's `format` entry.
    view: Option<Box<dyn wicket_agent::harness::SessionView>>,
    /// The log names a format this console can't read: nothing of the conversation is shown.
    unreadable: bool,
}

fn rpc_key(id: &Value) -> String {
    id.to_string()
}

/// Drops every `_meta` in an agent's message: only wicket sets it toward the browser.
fn strip_meta(v: &mut Value) {
    match v {
        Value::Object(o) => {
            o.remove("_meta");
            o.values_mut().for_each(strip_meta);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_meta),
        _ => {}
    }
}

impl Bridge {
    pub fn new(ledger: PathBuf, dir: PathBuf, tenant: wicket_core::TenantId, run: String, who: Who) -> Bridge {
        Bridge {
            ledger,
            dir,
            tenant,
            run,
            who,
            opened: false,
            agent_pos: 0,
            log_pos: 0,
            held: VecDeque::new(),
            queued: VecDeque::new(),
            prompt_rpc: HashMap::new(),
            waiting: BTreeMap::new(),
            permissions: HashMap::new(),
            shown: BTreeSet::new(),
            asked: BTreeMap::new(),
            next_id: 0,
            prompts: 0,
            last_cancel: None,
            view: None,
            unreadable: false,
        }
    }

    fn ledger(&self) -> Option<Ledger> {
        Ledger::open(&self.ledger).ok()
    }

    pub fn audit(&self, kind: &str, body: Value) {
        if let Some(l) = self.ledger() {
            let _ = l.audit(&self.tenant, Some(&RunId(self.run.clone())), kind, &body);
        }
    }

    pub fn running(&self) -> bool {
        self.ledger().is_some_and(|l| check_running(&l, &self.run).is_ok())
    }

    fn result(&self, id: Value, r: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "result": r })
    }

    pub fn error_out(&self, id: Value, code: i64, msg: &str) -> Vec<Value> {
        vec![json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } })]
    }

    fn update(&self, u: Value) -> Value {
        json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": self.run, "update": u } })
    }

    /// wicket's own words about the session, as an agent message marked as wicket's.
    fn notice(&self, text: &str) -> Value {
        self.update(json!({
            "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": format!("[wicket] {text}\n") },
            "_meta": { "wicket": { "notice": true } },
        }))
    }

    /// One message from the browser.
    pub fn on_client(&mut self, text: &str) -> Vec<Value> {
        let Ok(v) = serde_json::from_str::<Value>(text) else { return self.error_out(Value::Null, -32700, "not JSON") };
        let id = v.get("id").cloned().filter(|i| !i.is_null());
        let method = v.get("method").and_then(|m| m.as_str());
        let params = v.get("params").cloned().unwrap_or(Value::Null);
        match (method, id) {
            (Some(m), Some(id)) => self.request(m, id, &params),
            (Some("session/cancel"), None) => self.cancel(&params),
            // Other notifications have no meaning here.
            (Some(_), None) => vec![],
            (None, Some(id)) => self.answer(&id, &v),
            (None, None) => vec![],
        }
    }

    fn request(&mut self, m: &str, id: Value, p: &Value) -> Vec<Value> {
        let session_ok = |p: &Value| p.get("sessionId").and_then(|s| s.as_str()) == Some(self.run.as_str());
        match m {
            "initialize" => vec![self.result(
                id,
                json!({
                    "protocolVersion": wicket_agent::acp::PROTOCOL_VERSION,
                    "agentCapabilities": {
                        "loadSession": true,
                        "promptCapabilities": { "image": false, "audio": false, "embeddedContext": false },
                        "mcpCapabilities": { "http": false, "sse": false },
                    },
                    "agentInfo": { "name": "wicket", "title": format!("wicket: {}", self.run), "version": env!("CARGO_PKG_VERSION") },
                    "authMethods": [],
                }),
            )],
            // The client's cwd, MCP servers and capabilities are ignored: the session is the box's.
            "session/new" => {
                self.opened = true;
                let mut out = vec![self.result(id, json!({ "sessionId": self.run }))];
                out.extend(self.poll());
                out
            }
            "session/load" if session_ok(p) => {
                self.opened = true;
                let mut out = self.poll();
                out.push(self.result(id, Value::Null));
                out
            }
            "session/load" => self.error_out(id, -32602, "this socket serves its run's session only"),
            "session/prompt" if !session_ok(p) => self.error_out(id, -32602, "this socket serves its run's session only"),
            "session/prompt" => self.prompt(id, p),
            _ => self.error_out(id, wicket_agent::acp::METHOD_NOT_FOUND, "wicket offers no such method"),
        }
    }

    /// A prompt: queued as an operator message from this socket's principal, and audited.
    fn prompt(&mut self, id: Value, p: &Value) -> Vec<Value> {
        let blocks = p.get("prompt").and_then(|b| b.as_array()).cloned().unwrap_or_default();
        let text: Vec<&str> = blocks
            .iter()
            .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
            .filter_map(|b| b.get("text")?.as_str())
            .collect();
        let text = text.join("\n");
        if text.trim().is_empty() {
            return self.error_out(id, -32602, "a prompt needs text (images and resources aren't bridged yet)");
        }
        if text.chars().count() > super::MAX_TEXT {
            return self.error_out(id, -32602, "the prompt is too long");
        }
        if self.waiting.len() >= MAX_WAITING {
            return self.error_out(id, -32000, "too many prompts waiting for their turn");
        }
        let Some(l) = self.ledger() else { return self.error_out(id, -32603, "the ledger is unavailable") };
        if let Err(r) = check_running(&l, &self.run) {
            return self.error_out(id, -32000, r.body["error"].as_str().unwrap_or("the run is not running"));
        }
        let op = match l.add_operator_message(&self.run, &text, &self.who.label) {
            Ok(op) => op,
            Err(_) => return self.error_out(id, -32603, "couldn't queue the prompt"),
        };
        self.prompts += 1;
        let _ = l.audit(
            &self.tenant,
            Some(&RunId(self.run.clone())),
            "session.prompt",
            &json!({ "run": self.run, "by": self.who.label, "principal": self.who.principal, "via": self.who.via, "operator_message": op,
                     "chars": text.chars().count(), "sha256": hex::encode(sha2::Sha256::digest(text.as_bytes())) }),
        );
        self.waiting.insert(op, Waiting { rpc: id });
        vec![]
    }

    /// `session/cancel`: asks the run's supervisor, through the ledger, to cancel the agent's running
    /// turn (it sends the agent ACP's own `session/cancel`, and the turn ends with `cancelled`, which
    /// answers its prompt). Audited; at most one a second per socket.
    fn cancel(&mut self, p: &Value) -> Vec<Value> {
        if p.get("sessionId").and_then(|s| s.as_str()) != Some(self.run.as_str()) {
            return vec![];
        }
        let now = Instant::now();
        if self.last_cancel.is_some_and(|t| now.duration_since(t) < CANCEL_EVERY) {
            return vec![];
        }
        self.last_cancel = Some(now);
        let Some(l) = self.ledger() else { return vec![self.notice("couldn't ask for the cancel: the ledger is unavailable")] };
        if check_running(&l, &self.run).is_err() {
            return vec![];
        }
        let id = match l.request_turn_cancel(&self.run, &self.who.label) {
            Ok(id) => id,
            Err(_) => return vec![self.notice("couldn't ask for the cancel")],
        };
        let _ = l.audit(
            &self.tenant,
            Some(&RunId(self.run.clone())),
            "session.cancel",
            &json!({ "run": self.run, "by": self.who.label, "principal": self.who.principal, "via": self.who.via, "cancel": id }),
        );
        vec![self.notice("asked the agent to stop its running turn")]
    }

    /// The browser's answer to one of wicket's requests (an escalation prompt).
    fn answer(&mut self, id: &Value, v: &Value) -> Vec<Value> {
        let Some(request) = self.asked.remove(&rpc_key(id)) else { return vec![] };
        let said = match v.pointer("/result/outcome/outcome").and_then(|o| o.as_str()) {
            Some("selected") => v.pointer("/result/outcome/optionId").and_then(|o| o.as_str()).unwrap_or("?").to_string(),
            Some(o) => o.to_string(),
            None => "error".into(),
        };
        let status = self.ledger().and_then(|l| l.request(&request).ok()).map(|r| r.status).unwrap_or_else(|| "unknown".into());
        // What the browser said is recorded, and decides nothing: the ledger has the decision.
        self.audit(
            "session.escalation_answered",
            json!({ "run": self.run, "request": request, "said": wicket_core::text::clip(&said, 40), "status": status,
                    "by": self.who.label, "principal": self.who.principal }),
        );
        let mut out = vec![];
        if status == "pending" {
            out.push(
                self.notice(&format!("{request} is still pending: an answer here decides nothing, approve or deny it with your passkey")),
            );
        }
        out
    }

    /// Everything new in the run's files and the ledger.
    pub fn poll(&mut self) -> Vec<Value> {
        let mut out = vec![];
        if !self.opened {
            return out;
        }
        // The log first, then the transcript: every log entry is written after the transcript
        // line before it, so nothing it refers to is missed.
        let (entries, lp) = crate::transcript::read_acp_log(&self.dir, self.log_pos, 10_000);
        self.log_pos = lp;
        self.held.extend(entries);
        let (lines, ap) = crate::transcript::read_since(&self.dir, self.agent_pos, READ_CHUNK);
        for (at, line) in lines {
            while self.held.front().is_some_and(|e| e["at"].as_u64().unwrap_or(0) <= at) {
                let e = self.held.pop_front().expect("front");
                self.on_wicket(&e, &mut out);
            }
            self.on_agent(&line, &mut out);
        }
        self.agent_pos = ap;
        while self.held.front().is_some_and(|e| e["at"].as_u64().unwrap_or(0) <= ap) {
            let e = self.held.pop_front().expect("front");
            self.on_wicket(&e, &mut out);
        }
        self.escalations(&mut out);
        out
    }

    /// One line the agent wrote: an ACP message, or (through the run's view) what it amounts to.
    fn on_agent(&mut self, line: &str, out: &mut Vec<Value>) {
        if line.len() > MAX_LINE {
            out.push(self.notice(&format!("the agent sent a {} KiB message, too large to show here", line.len() >> 10)));
            return;
        }
        let msgs = match self.view.as_mut() {
            Some(view) => view.agent(line),
            None if self.unreadable => vec![],
            None => serde_json::from_str::<Value>(line).into_iter().collect(),
        };
        for v in msgs {
            self.on_agent_msg(v, out);
        }
    }

    /// One ACP message from the agent.
    fn on_agent_msg(&mut self, mut v: Value, out: &mut Vec<Value>) {
        let method = v.get("method").and_then(|m| m.as_str()).map(String::from);
        let id = v.get("id").cloned().filter(|i| !i.is_null());
        match (method.as_deref(), id) {
            (Some("session/update"), None) => {
                let Some(mut u) = v.pointer_mut("/params/update").map(Value::take) else { return };
                strip_meta(&mut u);
                let kind = u.get("sessionUpdate").and_then(|k| k.as_str()).unwrap_or("");
                if !UPDATES.contains(&kind) {
                    return;
                }
                if u.get("toolCallId").and_then(|t| t.as_str()).is_some_and(|t| t.starts_with(RESERVED_ID)) {
                    return;
                }
                out.push(self.update(u));
            }
            (Some("session/request_permission"), Some(id)) => {
                let tc = v.pointer("/params/toolCall/toolCallId").and_then(|t| t.as_str()).unwrap_or("").to_string();
                if !tc.starts_with(RESERVED_ID) && self.permissions.len() < 10_000 {
                    self.permissions.insert(rpc_key(&id), tc);
                }
            }
            // The agent's other requests were refused by the supervisor; nothing to show.
            (Some(_), _) => {}
            (None, Some(id)) => {
                // The end of a prompt turn.
                let Some(q) = self.prompt_rpc.remove(&rpc_key(&id)) else { return };
                let Some(w) = q.op.and_then(|op| self.waiting.remove(&op)) else { return };
                let reply = match (v.get("result"), v.get("error")) {
                    (_, Some(e)) => json!({ "jsonrpc": "2.0", "id": w.rpc, "error": {
                        "code": -32000, "message": wicket_core::text::clip(e.get("message").and_then(|m| m.as_str()).unwrap_or("the turn failed"), 300) } }),
                    (Some(r), _) => {
                        let stop = r.get("stopReason").and_then(|s| s.as_str()).unwrap_or("end_turn");
                        self.result(w.rpc, json!({ "stopReason": wicket_core::text::clip(stop, 40) }))
                    }
                    _ => return,
                };
                out.push(reply);
            }
            (None, None) => {}
        }
    }

    /// One entry of what wicket said to the agent.
    fn on_wicket(&mut self, e: &Value, out: &mut Vec<Value>) {
        if let Some(f) = e.get("format").and_then(|f| f.as_str()) {
            self.view = wicket_agent::harness::session_view(f);
            self.unreadable = self.view.is_none();
            if self.unreadable {
                out.push(
                    self.notice(&format!(
                        "this run's session is kept as {}, which this console can't show",
                        wicket_core::text::clip(f, 60)
                    )),
                );
            }
            return;
        }
        if let Some(q) = e.get("queued") {
            self.queued.push_back(Queued { by: q["by"].as_str().unwrap_or("wicket").to_string(), op: q["op"].as_i64() });
            return;
        }
        let Some(msg) = e.get("msg") else { return };
        let msgs = match self.view.as_mut() {
            Some(view) => view.wicket(msg),
            None if self.unreadable => vec![],
            None => vec![msg.clone()],
        };
        for m in &msgs {
            self.on_wicket_msg(m, out);
        }
    }

    /// One ACP message from wicket's client to the agent.
    fn on_wicket_msg(&mut self, msg: &Value, out: &mut Vec<Value>) {
        let id = msg.get("id").cloned().filter(|i| !i.is_null());
        match (msg.get("method").and_then(|m| m.as_str()), id) {
            (Some("session/prompt"), Some(id)) => {
                let q = self.queued.pop_front().unwrap_or(Queued { by: "wicket".into(), op: None });
                // This socket's own prompts are already on its screen; others' are shown.
                if !q.op.is_some_and(|op| self.waiting.contains_key(&op)) {
                    let text: Vec<&str> = msg
                        .pointer("/params/prompt")
                        .and_then(|p| p.as_array())
                        .map(|p| p.iter().filter_map(|b| b.get("text")?.as_str()).collect())
                        .unwrap_or_default();
                    out.push(self.update(json!({
                        "sessionUpdate": "user_message_chunk", "content": { "type": "text", "text": text.join("\n") },
                        "_meta": { "wicket": { "by": q.by } },
                    })));
                }
                self.prompt_rpc.insert(rpc_key(&id), q);
            }
            // wicket's answer to the agent's permission request.
            (None, Some(id)) => {
                let Some(tc) = self.permissions.remove(&rpc_key(&id)) else { return };
                let outcome = msg.pointer("/result/outcome/outcome").and_then(|o| o.as_str()).unwrap_or("cancelled");
                let option = msg.pointer("/result/outcome/optionId").cloned().unwrap_or(Value::Null);
                out.push(self.update(json!({
                    "sessionUpdate": "tool_call_update", "toolCallId": tc,
                    "_meta": { "wicket": { "permission": { "outcome": outcome, "optionId": option, "by": "wicket's policy" } } },
                })));
            }
            _ => {}
        }
    }

    /// wicket's pending requests for the run, as permission prompts; and the ones decided since.
    fn escalations(&mut self, out: &mut Vec<Value>) {
        let Some(l) = self.ledger() else { return };
        let Ok(pending) = l.pending(&self.tenant) else { return };
        let now: BTreeSet<String> = pending.iter().filter(|r| r.run == self.run).map(|r| r.id.clone()).collect();
        let new: Vec<&wicket_store::Request> = pending.iter().filter(|r| r.run == self.run && !self.shown.contains(&r.id)).collect();
        for r in new {
            self.shown.insert(r.id.clone());
            let tc = format!("{RESERVED_ID}escalation:{}", r.id);
            let esc = json!({ "id": r.id, "method": r.method, "host": r.host, "path": r.path, "risk": r.risk,
                              "reason": wicket_core::text::clip(&r.reason, 500), "prefix": r.scope_prefix, "status": "pending",
                              "decide": "/api/decide/begin" });
            let title = format!("wicket escalation {}: {} {}{}", r.id, r.method, r.host, r.path);
            out.push(self.update(json!({
                "sessionUpdate": "tool_call", "toolCallId": tc, "title": title, "kind": "fetch", "status": "pending",
                "rawInput": { "method": r.method, "host": r.host, "path": r.path, "risk": r.risk, "reason": r.reason },
                "_meta": { "wicket": { "escalation": esc } },
            })));
            let rpc = format!("wicket-{}", self.next_id);
            self.next_id += 1;
            self.asked.insert(rpc_key(&json!(rpc)), r.id.clone());
            out.push(json!({
                "jsonrpc": "2.0", "id": rpc, "method": "session/request_permission",
                "params": {
                    "sessionId": self.run,
                    "toolCall": { "toolCallId": tc, "title": title, "kind": "fetch", "status": "pending" },
                    "options": [
                        { "optionId": "approve", "name": "Approve once (passkey)", "kind": "allow_once" },
                        { "optionId": "deny", "name": "Deny (passkey)", "kind": "reject_once" },
                    ],
                    "_meta": { "wicket": { "escalation": esc } },
                },
            }));
        }
        let gone: Vec<String> = self.shown.iter().filter(|id| !now.contains(*id)).cloned().collect();
        for id in gone {
            self.shown.remove(&id);
            let status = l.request(&id).map(|r| r.status).unwrap_or_else(|_| "unknown".into());
            let done = if status == "approved" { "completed" } else { "failed" };
            out.push(self.update(json!({
                "sessionUpdate": "tool_call_update", "toolCallId": format!("{RESERVED_ID}escalation:{id}"), "status": done,
                "_meta": { "wicket": { "escalation": { "id": id, "status": status } } },
            })));
        }
    }
}
