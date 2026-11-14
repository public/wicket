//! wicket as an Agent Client Protocol client (#66): it drives any ACP agent in a box over the box's
//! stdio, with a client posture that is safe for a sandbox (research 21 §2):
//!
//! - it offers no `fs`, `terminal` or `auth.terminal` capability, and answers any agent request it
//!   didn't offer (`fs/*`, `terminal/*`, elicitation, anything else) with `-32601`;
//! - wicket's gateway is the only MCP server, and the sandbox notice goes in as a `systemPrompt` append;
//! - it answers `session/request_permission` only with an `allow_once` or `reject_once` option it was
//!   offered, chosen by the tool call's `kind` and its paths, never by a title, a name or a command
//!   string; with no such option it answers `cancelled`. It never selects an "always" option, which
//!   the agent would keep as policy of its own (the Claude adapter writes `.claude/settings.local.json`);
//! - a permission request that arrives while a `session/load` replays history is answered
//!   `cancelled`: replayed approvals are history, not decisions;
//! - agent-specific `_meta` comes only from wicket ([`AcpConfig::meta`]), never from a manifest or an editor.
//!
//! Enforcement stays where it is: the box boundary and the gates. An `allow_once` lets the agent
//! *attempt* something in its box; whatever crosses the boundary is still decided by the gates.
//!
//! The client is a state machine with no I/O: it is fed the box's stdout line by line and returns the
//! lines to write to the box's stdin and the [`SessionEvent`]s to show. It serialises, so a new
//! supervisor that re-attaches to a running box picks up where the last one stopped.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};

/// The ACP wire version wicket speaks. v2 is still a draft and isn't offered.
pub const PROTOCOL_VERSION: u64 = 1;
/// JSON-RPC "method not found": wicket's answer to every agent request it didn't offer.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// wicket's MCP gateway as the box reaches it (the same endpoint T1 agents get).
pub const GATEWAY_URL: &str = "http://wicket.internal:8081/mcp";

/// Files that control what runs or what is approved: an agent's request to write, move or delete one
/// is refused (`reject_once`). It is also the list for the extraction gate (design §6), which isn't
/// built yet. Matched on path components, so `a/.git/hooks/x` and `/workspace/.claude/settings.local.json`
/// both match.
pub const CONTROL_FILES: [&str; 14] = [
    ".git/hooks",
    ".git/config",
    ".gitmodules",
    ".claude",
    ".mcp.json",
    ".gemini",
    ".codex",
    ".cursor",
    ".vscode",
    ".zed",
    ".idea",
    ".envrc",
    ".devcontainer",
    ".github/workflows",
];

/// Which control file `path` is or lies under, if any (research 21 §2.2; `.claude/settings.local.json`
/// is where the Claude adapter keeps "always" decisions). The agent's own config dir under
/// `/wicket/state` counts too.
pub fn control_file(path: &str) -> Option<&'static str> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    for c in CONTROL_FILES {
        let want: Vec<&str> = c.split('/').collect();
        if parts.windows(want.len()).any(|w| w == want.as_slice()) {
            return Some(c);
        }
    }
    let state = crate::STATE_DIR.trim_start_matches('/');
    let p = parts.join("/");
    if p.starts_with(state) && parts.last().is_some_and(|f| f.starts_with("settings") && f.ends_with(".json")) {
        return Some("the agent's own settings");
    }
    None
}

/// Whether an ACP agent is Claude Code through its ACP adapter, which runs the `claude` binary through
/// the Claude Agent SDK: by wicket's profile for it, or by a command that starts the adapter (its
/// package or binary, under its current or earlier names).
pub fn is_claude_adapter(spec: &wicket_core::AcpSpec) -> bool {
    spec.profile.as_deref() == Some("claude-agent-acp")
        || spec.command.iter().any(|c| {
            let c = c.to_ascii_lowercase();
            ["claude-agent-acp", "claude-code-acp"].iter().any(|n| c.contains(n))
        })
}

/// The installation's settings for the Claude adapter (`acp` in `wicket.yaml`): decisions that
/// belong to the installation's owner, not to a manifest.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeAdapterSettings {
    /// Whether Claude Code may run through its ACP adapter (`claude-agent-acp`, which drives the
    /// `claude` binary through the Claude Agent SDK) on the installation's Claude subscription. The
    /// owner's reading of the subscription's terms (research 21 §2.6). Default: no.
    #[serde(default)]
    pub allow_subscription_backed_claude_adapter: bool,
}

/// Refuses, at run start, a manifest that runs the Claude adapter in a way the installation's
/// settings (read from `settings_path`) don't allow (#66). Every other agent passes.
pub fn check_claude_adapter(m: &wicket_core::Manifest, s: &ClaudeAdapterSettings, settings_path: &str) -> Result<(), String> {
    let Some(spec) = m.agent.as_ref().filter(|a| a.harness == wicket_core::Harness::Acp).and_then(|a| a.acp.as_ref()) else {
        return Ok(());
    };
    if !is_claude_adapter(spec) {
        return Ok(());
    }
    // Claude Code through its adapter goes through wicket's profile, and so through the check below.
    if spec.profile.as_deref() != Some("claude-agent-acp") {
        return Err("agent.acp.command starts Claude Code's ACP adapter: set agent.acp.profile: claude-agent-acp".into());
    }
    // The zone's model route is a Claude subscription (wicket never uses an API key).
    let subscription = m.zone.llm.as_ref().is_some_and(|l| l.provider == "anthropic");
    if subscription && !s.allow_subscription_backed_claude_adapter {
        return Err(format!(
            "this zone runs Claude Code through its ACP adapter (the Claude Agent SDK) on the Claude subscription in zone.llm, \
             which this installation doesn't allow. Whether the subscription may back the adapter is the owner's decision; \
             to allow it, set acp.allow_subscription_backed_claude_adapter: true in {settings_path}. Meanwhile, run Claude Code as harness: claude-code"
        ));
    }
    Ok(())
}

/// How wicket starts or continues an ACP session.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AcpConfig {
    /// The session's working directory in the box (absolute).
    pub cwd: String,
    /// Appended to the agent's system prompt: the sandbox notice.
    pub system_prompt: String,
    /// Agent-specific `_meta` for `session/new`, `load` and `resume`, built by wicket for a known
    /// adapter (e.g. the Claude adapter's `claudeCode.options`). Never taken from a manifest or editor.
    pub meta: Option<Value>,
    /// The agent's own session id to continue (a woken agent).
    pub resume: Option<String>,
}

/// What wicket shows of a session: the same events for every agent, whatever its wire format.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    /// The session is open. `how`: `new`, `resumed` or `loaded` (with `replayed` history updates
    /// that were shown as history only).
    Started {
        agent: String,
        session: String,
        how: String,
        replayed: u64,
    },
    /// A whole agent message (chunks joined).
    Message {
        text: String,
    },
    Thought {
        text: String,
    },
    ToolCall {
        id: String,
        title: String,
        kind: String,
        status: String,
        detail: String,
    },
    /// A tool call's status changed, or it reported a diff (`path`, and the new text's length).
    ToolUpdate {
        id: String,
        status: String,
        diff: Option<Diff>,
    },
    Plan {
        entries: Vec<PlanEntry>,
    },
    /// wicket answered a permission request: `answer` is `allow_once`, `reject_once` or `cancelled`.
    Permission {
        tool: String,
        kind: String,
        answer: String,
        why: String,
    },
    /// The agent called a method wicket doesn't offer; it got `-32601`.
    Refused {
        method: String,
    },
    /// A prompt turn ended (`stop` is ACP's stopReason).
    TurnDone {
        stop: String,
    },
    /// Something wicket should say about the session itself (a fallback, a launch problem).
    Notice {
        text: String,
    },
    /// The session can't go on.
    Failed {
        error: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Diff {
    pub path: String,
    pub old_text: Option<String>,
    pub new_text: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlanEntry {
    pub content: String,
    pub status: String,
}

/// What one input line produced.
#[derive(Debug, Default, PartialEq)]
pub struct Step {
    /// JSON-RPC messages to write to the agent's stdin, one per line.
    pub write: Vec<String>,
    pub events: Vec<SessionEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Req {
    Initialize,
    New,
    Load,
    Resume,
    Prompt,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// `initialize` sent.
    #[default]
    Starting,
    /// `session/new`, `load` or `resume` sent.
    Opening,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct AgentCaps {
    load: bool,
    resume: bool,
    system_prompt: bool,
}

/// An ACP client session with one agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcpClient {
    cfg: AcpConfig,
    next_id: u64,
    phase: Phase,
    session: Option<String>,
    agent: String,
    caps: AgentCaps,
    outstanding: BTreeMap<u64, Req>,
    /// Prompts waiting for the session to open or the running turn to end (v1 has no steering).
    queue: VecDeque<String>,
    /// The running turn's request id.
    turn: Option<u64>,
    cancelled: bool,
    /// A `session/load` is replaying history.
    replaying: bool,
    replayed: u64,
    /// The notice still has to go in front of the first prompt (an agent without `systemPrompt`).
    notice_in_prompt: bool,
    /// Tool kinds by toolCallId, as the agent reported them (permission requests may omit the kind).
    tools: BTreeMap<String, String>,
    message: String,
    thought: String,
}

impl AcpClient {
    /// A client, and the `initialize` request to send.
    pub fn start(cfg: AcpConfig) -> (AcpClient, Vec<String>) {
        let mut c = AcpClient {
            cfg,
            next_id: 0,
            phase: Phase::Starting,
            session: None,
            agent: String::new(),
            caps: AgentCaps::default(),
            outstanding: BTreeMap::new(),
            queue: VecDeque::new(),
            turn: None,
            cancelled: false,
            replaying: false,
            replayed: 0,
            notice_in_prompt: false,
            tools: BTreeMap::new(),
            message: String::new(),
            thought: String::new(),
        };
        let init = c.request(
            Req::Initialize,
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                // Offered: nothing that would let the agent act outside its box (research 21 §1.6).
                "clientCapabilities": { "fs": { "readTextFile": false, "writeTextFile": false }, "terminal": false },
                "clientInfo": { "name": "wicket", "version": env!("CARGO_PKG_VERSION") },
            }),
        );
        (c, vec![init])
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The agent's session id, once open.
    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }

    /// Whether a prompt turn is running or waiting to be sent.
    pub fn busy(&self) -> bool {
        self.turn.is_some() || !self.queue.is_empty() || matches!(self.phase, Phase::Starting | Phase::Opening)
    }

    /// Sends `text` as a prompt, now or when the running turn ends.
    pub fn prompt(&mut self, text: &str) -> Vec<String> {
        self.queue.push_back(text.to_string());
        self.pump()
    }

    /// Cancels the running turn (`session/cancel`); the agent ends it with `cancelled`.
    pub fn cancel(&mut self) -> Vec<String> {
        match (&self.session, self.turn) {
            (Some(s), Some(_)) => {
                self.cancelled = true;
                vec![json!({ "jsonrpc": "2.0", "method": "session/cancel", "params": { "sessionId": s } }).to_string()]
            }
            _ => vec![],
        }
    }

    /// One line of the agent's stdout.
    pub fn on_line(&mut self, line: &str) -> Step {
        let mut st = Step::default();
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { return st };
        let (method, id) = (v.get("method").and_then(|m| m.as_str()), v.get("id").filter(|i| !i.is_null()));
        match (method, id) {
            // A request from the agent.
            (Some(m), Some(id)) => {
                let result = match m {
                    "session/request_permission" => {
                        let (outcome, ev) = self.permission(v.get("params").unwrap_or(&Value::Null));
                        st.events.push(ev);
                        Ok(json!({ "outcome": outcome }))
                    }
                    _ => {
                        st.events.push(SessionEvent::Refused { method: wicket_core::text::clip(m, 80) });
                        Err(json!({ "code": METHOD_NOT_FOUND, "message": "wicket offers no such method" }))
                    }
                };
                let reply = match result {
                    Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
                    Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
                };
                st.write.push(reply.to_string());
            }
            (Some("session/update"), None) => self.update(v.pointer("/params/update").unwrap_or(&Value::Null), &mut st),
            (Some(_), None) => {}
            (None, Some(id)) => {
                let Some(req) = id.as_u64().and_then(|i| self.outstanding.remove(&i)) else { return st };
                self.response(req, id.as_u64().unwrap_or(0), &v, &mut st);
            }
            (None, None) => {}
        }
        st
    }

    fn request(&mut self, req: Req, method: &str, params: Value) -> String {
        let id = self.next_id;
        self.next_id += 1;
        self.outstanding.insert(id, req);
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
    }

    fn session_params(&self) -> Value {
        let mut p = json!({
            "cwd": self.cfg.cwd,
            "mcpServers": [{ "type": "http", "name": "wicket", "url": GATEWAY_URL, "headers": [] }],
        });
        if self.caps.system_prompt && !self.cfg.system_prompt.is_empty() {
            p["systemPrompt"] = json!({ "mode": "append", "content": [{ "type": "text", "text": self.cfg.system_prompt }] });
        }
        if let Some(m) = &self.cfg.meta {
            p["_meta"] = m.clone();
        }
        p
    }

    fn open(&mut self, st: &mut Step) {
        self.phase = Phase::Opening;
        let mut p = self.session_params();
        let resume = self.cfg.resume.clone().filter(|_| self.caps.resume || self.caps.load);
        let line = match resume {
            Some(id) => {
                p["sessionId"] = json!(id);
                if self.caps.resume {
                    self.request(Req::Resume, "session/resume", p)
                } else {
                    self.replaying = true;
                    self.request(Req::Load, "session/load", p)
                }
            }
            None => {
                if self.cfg.resume.is_some() {
                    st.events.push(SessionEvent::Notice { text: "the agent can't resume or load sessions: starting a new one".into() });
                }
                self.request(Req::New, "session/new", p)
            }
        };
        st.write.push(line);
    }

    fn response(&mut self, req: Req, id: u64, v: &Value, st: &mut Step) {
        let err = v.get("error").map(|e| wicket_core::text::clip(e.get("message").and_then(|m| m.as_str()).unwrap_or("an error"), 300));
        let r = v.get("result").cloned().unwrap_or(Value::Null);
        match req {
            Req::Initialize => {
                if let Some(e) = err {
                    return self.fail(format!("initialize failed: {e}"), st);
                }
                let version = r.get("protocolVersion").and_then(|p| p.as_u64());
                if version != Some(PROTOCOL_VERSION) {
                    return self.fail(format!("the agent speaks ACP {version:?}, wicket speaks {PROTOCOL_VERSION}"), st);
                }
                let caps = r.get("agentCapabilities").cloned().unwrap_or(Value::Null);
                if caps.pointer("/mcpCapabilities/http").and_then(|h| h.as_bool()) != Some(true) {
                    return self.fail("the agent can't use an HTTP MCP server, so it can't reach wicket's tools".into(), st);
                }
                let present = |p: &str| caps.pointer(p).is_some_and(|x| !x.is_null() && x != &Value::Bool(false));
                self.caps = AgentCaps {
                    load: caps.get("loadSession").and_then(|l| l.as_bool()) == Some(true),
                    resume: present("/sessionCapabilities/resume"),
                    system_prompt: present("/sessionCapabilities/systemPrompt"),
                };
                // Logged only: who the agent says it is decides nothing.
                self.agent = ["name", "version"]
                    .iter()
                    .filter_map(|k| r.pointer(&format!("/agentInfo/{k}")).and_then(|s| s.as_str()))
                    .map(|s| wicket_core::text::clip(s, 60))
                    .collect::<Vec<_>>()
                    .join(" ");
                if !self.caps.system_prompt {
                    self.notice_in_prompt = true;
                    st.events.push(SessionEvent::Notice {
                        text: "the agent takes no system prompt: the sandbox notice goes in front of the first prompt".into(),
                    });
                }
                self.open(st);
            }
            Req::New | Req::Load | Req::Resume => {
                let was_replay = std::mem::take(&mut self.replaying);
                if let Some(e) = err {
                    if req != Req::New {
                        st.events.push(SessionEvent::Notice { text: format!("couldn't continue session: {e}; starting a new one") });
                        self.cfg.resume = None;
                        return self.open(st);
                    }
                    return self.fail(format!("session/new failed: {e}"), st);
                }
                let session = match req {
                    Req::New => r.get("sessionId").and_then(|s| s.as_str()).map(String::from),
                    _ => self.cfg.resume.clone(),
                };
                let Some(session) = session.filter(|s| valid_session_id(s)) else {
                    return self.fail("the agent returned no usable session id".into(), st);
                };
                self.message.clear();
                self.thought.clear();
                self.session = Some(session.clone());
                self.phase = Phase::Ready;
                let how = match req {
                    Req::New => "new",
                    Req::Resume => "resumed",
                    _ => "loaded",
                };
                st.events.push(SessionEvent::Started {
                    agent: self.agent.clone(),
                    session,
                    how: how.into(),
                    replayed: if was_replay { self.replayed } else { 0 },
                });
                st.write.extend(self.pump());
            }
            Req::Prompt => {
                if self.turn == Some(id) {
                    self.turn = None;
                }
                self.flush(st);
                let stop = match err {
                    Some(e) => format!("error: {e}"),
                    None => {
                        r.get("stopReason").and_then(|s| s.as_str()).map(|s| wicket_core::text::clip(s, 40)).unwrap_or_else(|| "?".into())
                    }
                };
                self.cancelled = false;
                st.events.push(SessionEvent::TurnDone { stop });
                st.write.extend(self.pump());
            }
        }
    }

    fn fail(&mut self, error: String, st: &mut Step) {
        self.phase = Phase::Failed;
        self.queue.clear();
        st.events.push(SessionEvent::Failed { error });
    }

    /// Sends the next queued prompt if the session is open and idle.
    fn pump(&mut self) -> Vec<String> {
        if self.phase != Phase::Ready || self.turn.is_some() {
            return vec![];
        }
        let Some(mut text) = self.queue.pop_front() else { return vec![] };
        if std::mem::take(&mut self.notice_in_prompt) && !self.cfg.system_prompt.is_empty() {
            text = format!("{}\n\n---\n\n{text}", self.cfg.system_prompt);
        }
        let p = json!({ "sessionId": self.session, "prompt": [{ "type": "text", "text": text }] });
        let line = self.request(Req::Prompt, "session/prompt", p);
        self.turn = Some(self.next_id - 1);
        vec![line]
    }

    fn flush(&mut self, st: &mut Step) {
        let t = std::mem::take(&mut self.thought);
        if !t.trim().is_empty() {
            st.events.push(SessionEvent::Thought { text: t });
        }
        let m = std::mem::take(&mut self.message);
        if !m.trim().is_empty() {
            st.events.push(SessionEvent::Message { text: m });
        }
    }

    /// Remembers a tool call's kind, for permission requests that leave it out. Bounded: an agent
    /// can't grow wicket's state (kept in the run's ctl/acp.json) without limit.
    fn note_tool(&mut self, id: &str, kind: &str) {
        if id.len() <= 200 && kind.len() <= 40 && (self.tools.len() < MAX_TOOLS || self.tools.contains_key(id)) {
            self.tools.insert(id.into(), kind.into());
        }
    }

    fn update(&mut self, u: &Value, st: &mut Step) {
        let kind = u.get("sessionUpdate").and_then(|k| k.as_str()).unwrap_or("");
        if self.replaying {
            // History: shown as a count, never acted on.
            self.replayed += 1;
            if let (Some("tool_call"), Some(id), Some(k)) =
                (Some(kind), u.get("toolCallId").and_then(|s| s.as_str()), u.get("kind").and_then(|s| s.as_str()))
            {
                self.note_tool(id, k);
            }
            return;
        }
        let text = || u.pointer("/content/text").and_then(|t| t.as_str()).unwrap_or("").to_string();
        match kind {
            "agent_message_chunk" => {
                if !self.thought.is_empty() {
                    let t = std::mem::take(&mut self.thought);
                    st.events.push(SessionEvent::Thought { text: t });
                }
                push_capped(&mut self.message, &text());
            }
            "agent_thought_chunk" => push_capped(&mut self.thought, &text()),
            "tool_call" => {
                self.flush(st);
                let s = |k: &str| u.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                let id = s("toolCallId");
                let kind = if s("kind").is_empty() { "other".into() } else { s("kind") };
                self.note_tool(&id, &kind);
                let detail = u.get("rawInput").map(crate::summarise_input).unwrap_or_default();
                let status = if s("status").is_empty() { "pending".into() } else { s("status") };
                st.events.push(SessionEvent::ToolCall { id, title: s("title"), kind, status, detail });
            }
            "tool_call_update" => {
                let id = u.get("toolCallId").and_then(|x| x.as_str()).unwrap_or("").to_string();
                if let Some(k) = u.get("kind").and_then(|x| x.as_str()) {
                    self.note_tool(&id, k);
                }
                let diff = u.get("content").and_then(|c| c.as_array()).and_then(|c| {
                    c.iter().find(|x| x.get("type").and_then(|t| t.as_str()) == Some("diff")).map(|d| Diff {
                        path: d.get("path").and_then(|p| p.as_str()).unwrap_or("").into(),
                        old_text: d.get("oldText").and_then(|p| p.as_str()).map(String::from),
                        new_text: d.get("newText").and_then(|p| p.as_str()).unwrap_or("").into(),
                    })
                });
                let status = u.get("status").and_then(|x| x.as_str()).map(String::from);
                if status.is_some() || diff.is_some() {
                    self.flush(st);
                    st.events.push(SessionEvent::ToolUpdate { id, status: status.unwrap_or_default(), diff });
                }
            }
            "plan" => {
                self.flush(st);
                let entries = u
                    .get("entries")
                    .and_then(|e| e.as_array())
                    .map(|e| {
                        e.iter()
                            .map(|x| PlanEntry {
                                content: x.get("content").and_then(|c| c.as_str()).unwrap_or("").into(),
                                status: x.get("status").and_then(|c| c.as_str()).unwrap_or("").into(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                st.events.push(SessionEvent::Plan { entries });
            }
            _ => {}
        }
    }

    /// wicket's answer to a permission request, and the event that records it.
    fn permission(&self, p: &Value) -> (Value, SessionEvent) {
        let tc = p.get("toolCall").cloned().unwrap_or(Value::Null);
        let id = tc.get("toolCallId").and_then(|x| x.as_str()).unwrap_or("");
        let kind = tc
            .get("kind")
            .and_then(|k| k.as_str())
            .map(String::from)
            .or_else(|| self.tools.get(id).cloned())
            .unwrap_or_else(|| "other".into());
        let tool = wicket_core::text::clip(tc.get("title").and_then(|t| t.as_str()).unwrap_or(id), 120);
        let cancelled = |why: &str| {
            (
                json!({ "outcome": "cancelled" }),
                SessionEvent::Permission { tool: tool.clone(), kind: kind.clone(), answer: "cancelled".into(), why: why.into() },
            )
        };
        if self.replaying || self.phase != Phase::Ready {
            return cancelled("asked while the session's history was replaying: replayed approvals are history, not decisions");
        }
        if self.cancelled {
            return cancelled("the turn was cancelled");
        }
        let (want, why) = decide(&kind, &tc);
        let options = p.get("options").and_then(|o| o.as_array()).cloned().unwrap_or_default();
        let pick = options
            .iter()
            .find(|o| o.get("kind").and_then(|k| k.as_str()) == Some(want))
            .and_then(|o| o.get("optionId").and_then(|i| i.as_str()).map(String::from));
        match pick {
            Some(option) => {
                (json!({ "outcome": "selected", "optionId": option }), SessionEvent::Permission { tool, kind, answer: want.into(), why })
            }
            None => cancelled(&format!("{why}; the agent offered no {want} option, and wicket never chooses an \"always\" one")),
        }
    }
}

/// Which once-option a tool call gets, and why: the agent may attempt anything in its box except
/// lowering its own oversight or writing a control file (research 21 §2.2). Decided on the kind and
/// the paths, never on titles, option names or command text.
fn decide(kind: &str, tc: &Value) -> (&'static str, String) {
    if kind == "switch_mode" {
        return ("reject_once", "a mode change is wicket's to make, not the agent's".into());
    }
    if matches!(kind, "edit" | "delete" | "move" | "other" | "execute") {
        if let Some((path, c)) = paths(tc).into_iter().find_map(|p| control_file(&p).map(|c| (p, c))) {
            return ("reject_once", format!("{} would change a control file ({c})", wicket_core::text::clip(&path, 200)));
        }
    }
    ("allow_once", "inside the box; what leaves it is decided at wicket's gates".into())
}

/// The paths a tool call names: its locations, and the path fields of its raw input.
fn paths(tc: &Value) -> Vec<String> {
    let mut out: Vec<String> = tc
        .get("locations")
        .and_then(|l| l.as_array())
        .map(|l| l.iter().filter_map(|x| x.get("path").and_then(|p| p.as_str()).map(String::from)).collect())
        .unwrap_or_default();
    if let Some(raw) = tc.get("rawInput") {
        for k in ["file_path", "path", "notebook_path", "destination", "source", "target"] {
            if let Some(p) = raw.get(k).and_then(|p| p.as_str()) {
                out.push(p.to_string());
            }
        }
    }
    if let Some(c) = tc.get("content").and_then(|c| c.as_array()) {
        out.extend(c.iter().filter_map(|x| x.get("path").and_then(|p| p.as_str()).map(String::from)));
    }
    out
}

/// Tool calls whose kind wicket remembers per session.
const MAX_TOOLS: usize = 10_000;
/// How much of one agent message or thought wicket keeps before the rest is dropped.
const MAX_TEXT: usize = 64 << 10;

/// Appends a streamed chunk, up to [`MAX_TEXT`] (on a character boundary).
fn push_capped(buf: &mut String, chunk: &str) {
    let room = MAX_TEXT.saturating_sub(buf.len());
    let mut n = chunk.len().min(room);
    while !chunk.is_char_boundary(n) {
        n -= 1;
    }
    buf.push_str(&chunk[..n]);
}

/// A session id wicket keeps and sends back: printable, short.
pub fn valid_session_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_graphic())
}

/// A one-line rendering for the operator's terminal. Agent text is shown as data, clipped and
/// neutralised.
pub fn render(e: &SessionEvent) -> Option<String> {
    let clip = wicket_core::text::clip;
    Some(match e {
        SessionEvent::Started { agent, session, how, replayed } => {
            let r = if *replayed > 0 { format!(", {replayed} history updates replayed (history only)") } else { String::new() };
            let a = if agent.is_empty() { "the agent".to_string() } else { agent.clone() };
            format!("[agent] {a}: ACP session {} {how}{r}", clip(session, 64))
        }
        SessionEvent::Message { text } => format!("[agent] {}", clip(text.trim(), 400)),
        SessionEvent::Thought { .. } => return None,
        SessionEvent::ToolCall { title, kind, detail, .. } => {
            let d = if detail.is_empty() { String::new() } else { format!(": {}", clip(detail, 200)) };
            format!("[tool]  {} ({kind}){d}", clip(title, 120))
        }
        SessionEvent::ToolUpdate { status, diff: Some(d), .. } => format!("[tool]  {status} diff {}", clip(&d.path, 200)),
        SessionEvent::ToolUpdate { status, .. } if status == "failed" => "[tool]  failed".into(),
        SessionEvent::ToolUpdate { .. } => return None,
        SessionEvent::Plan { entries } => {
            let done = entries.iter().filter(|e| e.status == "completed").count();
            format!("[agent] plan: {done}/{} done", entries.len())
        }
        SessionEvent::Permission { tool, kind, answer, why } => format!("[wicket] agent prompt for {tool} ({kind}): {answer} ({why})"),
        SessionEvent::Refused { method } => format!("[wicket] the agent called {method}, which wicket doesn't offer: refused"),
        SessionEvent::TurnDone { stop } => format!("[agent] finished: {stop}"),
        SessionEvent::Notice { text } => format!("[wicket] {text}"),
        SessionEvent::Failed { error } => format!("[wicket] ACP session failed: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AcpConfig {
        AcpConfig { cwd: "/workspace".into(), system_prompt: "NOTICE".into(), meta: None, resume: None }
    }

    fn parse(l: &str) -> Value {
        serde_json::from_str(l).unwrap()
    }

    fn init_result(extra: Value) -> String {
        let mut caps = json!({ "loadSession": true, "mcpCapabilities": { "http": true }, "sessionCapabilities": { "systemPrompt": {} } });
        if let (Some(c), Some(e)) = (caps.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                c.insert(k.clone(), v.clone());
            }
        }
        json!({ "jsonrpc": "2.0", "id": 0, "result": { "protocolVersion": 1, "agentCapabilities": caps, "agentInfo": { "name": "mock", "version": "1" } } })
            .to_string()
    }

    /// A client with an open session "s1" and the task's turn running (request id 2).
    fn open() -> AcpClient {
        let (mut c, _) = AcpClient::start(cfg());
        c.prompt("the task");
        c.on_line(&init_result(json!({})));
        let st = c.on_line(&json!({ "jsonrpc": "2.0", "id": 1, "result": { "sessionId": "s1" } }).to_string());
        assert_eq!(parse(&st.write[0])["method"], "session/prompt");
        c
    }

    fn ask(c: &mut AcpClient, id: u64, tool_call: Value, options: &[(&str, &str)]) -> (Value, SessionEvent) {
        let opts: Vec<Value> = options.iter().map(|(i, k)| json!({ "optionId": i, "name": format!("name {i}"), "kind": k })).collect();
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": "session/request_permission", "params": { "sessionId": "s1", "toolCall": tool_call, "options": opts } });
        let st = c.on_line(&req.to_string());
        let r = parse(&st.write[0]);
        assert_eq!(r["id"], id);
        (r["result"]["outcome"].clone(), st.events[0].clone())
    }

    const ALL: [(&str, &str); 4] = [("aa", "allow_always"), ("a1", "allow_once"), ("r1", "reject_once"), ("ra", "reject_always")];

    #[test]
    fn initialize_offers_no_file_terminal_or_auth_capability() {
        let (_, out) = AcpClient::start(cfg());
        let v = parse(&out[0]);
        assert_eq!(v["method"], "initialize");
        assert_eq!(v["params"]["protocolVersion"], 1);
        let caps = &v["params"]["clientCapabilities"];
        assert_eq!(caps["fs"]["readTextFile"], false);
        assert_eq!(caps["fs"]["writeTextFile"], false);
        assert_eq!(caps["terminal"], false);
        assert!(caps.get("auth").is_none() && caps.get("elicitation").is_none());
    }

    #[test]
    fn the_session_gets_the_gateway_only_the_notice_as_an_append_and_wicket_s_meta() {
        let (mut c, _) =
            AcpClient::start(AcpConfig { meta: Some(json!({ "claudeCode": { "options": { "strictMcpConfig": true } } })), ..cfg() });
        let st = c.on_line(&init_result(json!({})));
        let v = parse(&st.write[0]);
        assert_eq!(v["method"], "session/new");
        assert_eq!(v["params"]["cwd"], "/workspace");
        assert_eq!(v["params"]["mcpServers"], json!([{ "type": "http", "name": "wicket", "url": GATEWAY_URL, "headers": [] }]));
        assert_eq!(v["params"]["systemPrompt"], json!({ "mode": "append", "content": [{ "type": "text", "text": "NOTICE" }] }));
        assert_eq!(v["params"]["_meta"]["claudeCode"]["options"]["strictMcpConfig"], true);
        // Without systemPrompt support, the notice leads the first prompt instead.
        let (mut c, _) = AcpClient::start(cfg());
        c.prompt("task");
        let st = c.on_line(&init_result(json!({ "sessionCapabilities": {} })));
        assert!(parse(&st.write[0])["params"].get("systemPrompt").is_none());
        let st = c.on_line(&json!({ "jsonrpc": "2.0", "id": 1, "result": { "sessionId": "s" } }).to_string());
        assert_eq!(parse(&st.write[0])["params"]["prompt"][0]["text"], "NOTICE\n\n---\n\ntask");
    }

    #[test]
    fn an_agent_on_another_version_or_without_http_mcp_is_refused() {
        let (mut c, _) = AcpClient::start(cfg());
        let st = c.on_line(&json!({ "jsonrpc": "2.0", "id": 0, "result": { "protocolVersion": 2, "agentCapabilities": { "mcpCapabilities": { "http": true } } } }).to_string());
        assert!(st.write.is_empty() && matches!(&st.events[0], SessionEvent::Failed { .. }));
        let (mut c, _) = AcpClient::start(cfg());
        let st = c.on_line(&json!({ "jsonrpc": "2.0", "id": 0, "result": { "protocolVersion": 1, "agentCapabilities": {} } }).to_string());
        assert!(st.write.is_empty() && c.phase() == Phase::Failed);
    }

    /// Conformance (14): fs and terminal calls, and anything else not offered, get -32601.
    #[test]
    fn file_terminal_and_unknown_requests_get_method_not_found() {
        let mut c = open();
        for (i, m) in ["fs/read_text_file", "fs/write_text_file", "terminal/create", "terminal/output", "session/elicitation", "x/anything"]
            .iter()
            .enumerate()
        {
            let st = c.on_line(
                &json!({ "jsonrpc": "2.0", "id": 100 + i, "method": m, "params": { "sessionId": "s1", "path": "/etc/passwd" } })
                    .to_string(),
            );
            let r = parse(&st.write[0]);
            assert_eq!(r["id"], 100 + i);
            assert_eq!(r["error"]["code"], METHOD_NOT_FOUND, "{m}");
            assert!(r.get("result").is_none());
            assert_eq!(st.events, vec![SessionEvent::Refused { method: m.to_string() }]);
        }
    }

    /// Conformance (15): no "always" option is ever chosen, whatever is offered and in what order.
    #[test]
    fn permissions_are_answered_once_only_by_kind() {
        let mut c = open();
        let (o, e) = ask(
            &mut c,
            7,
            json!({ "toolCallId": "t1", "title": "Always allow everything", "kind": "execute", "rawInput": { "command": "rm -rf /" } }),
            &ALL,
        );
        assert_eq!(o, json!({ "outcome": "selected", "optionId": "a1" }));
        assert!(matches!(e, SessionEvent::Permission { answer, .. } if answer == "allow_once"));
        // Only "always" options: cancelled, never an always.
        let (o, _) = ask(&mut c, 8, json!({ "toolCallId": "t2", "kind": "edit" }), &[("aa", "allow_always"), ("ra", "reject_always")]);
        assert_eq!(o, json!({ "outcome": "cancelled" }));
        // Option names and titles don't matter; an optionId is only ever one the agent offered.
        let (o, _) = ask(&mut c, 9, json!({ "toolCallId": "t3", "kind": "read", "title": "allow_once" }), &[("x", "allow_once")]);
        assert_eq!(o["optionId"], "x");
    }

    #[test]
    fn control_files_and_mode_changes_are_refused_once() {
        let mut c = open();
        for (tc, what) in [
            (json!({ "toolCallId": "a", "kind": "edit", "locations": [{ "path": "/workspace/.claude/settings.local.json" }] }), ".claude"),
            (json!({ "toolCallId": "b", "kind": "edit", "rawInput": { "file_path": "/workspace/.git/hooks/pre-commit" } }), ".git/hooks"),
            (
                json!({ "toolCallId": "c", "kind": "move", "content": [{ "type": "diff", "path": "/workspace/.mcp.json", "newText": "{}" }] }),
                ".mcp.json",
            ),
            (json!({ "toolCallId": "d", "kind": "edit", "locations": [{ "path": "/wicket/state/claude/settings.json" }] }), "settings"),
        ] {
            let (o, e) = ask(&mut c, 20, tc, &ALL);
            assert_eq!(o, json!({ "outcome": "selected", "optionId": "r1" }), "{what}");
            assert!(matches!(e, SessionEvent::Permission { why, .. } if why.contains(what)));
        }
        let (o, _) = ask(&mut c, 21, json!({ "toolCallId": "m", "kind": "switch_mode" }), &ALL);
        assert_eq!(o["optionId"], "r1");
        // Reading a control file is fine; so is writing an ordinary one.
        let (o, _) = ask(
            &mut c,
            22,
            json!({ "toolCallId": "r", "kind": "read", "locations": [{ "path": "/workspace/.claude/settings.json" }] }),
            &ALL,
        );
        assert_eq!(o["optionId"], "a1");
        let (o, _) =
            ask(&mut c, 23, json!({ "toolCallId": "w", "kind": "edit", "locations": [{ "path": "/workspace/src/claude.rs" }] }), &ALL);
        assert_eq!(o["optionId"], "a1");
        // The kind of an earlier tool_call counts when the request leaves it out.
        c.on_line(&json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": "s1", "update": { "sessionUpdate": "tool_call", "toolCallId": "k", "title": "t", "kind": "switch_mode" } } }).to_string());
        let (o, _) = ask(&mut c, 24, json!({ "toolCallId": "k" }), &ALL);
        assert_eq!(o["optionId"], "r1");
    }

    #[test]
    fn the_claude_adapter_is_recognised_by_profile_or_command() {
        let spec = |cmd: &[&str], profile: Option<&str>| wicket_core::AcpSpec {
            command: cmd.iter().map(|s| s.to_string()).collect(),
            profile: profile.map(String::from),
        };
        assert!(is_claude_adapter(&spec(&["my-agent"], Some("claude-agent-acp"))));
        assert!(is_claude_adapter(&spec(&["claude-agent-acp"], None)));
        assert!(is_claude_adapter(&spec(&["npx", "-y", "@agentclientprotocol/claude-agent-acp@0.104.1"], None)));
        assert!(is_claude_adapter(&spec(&["node", "/usr/local/lib/node_modules/@zed-industries/claude-code-acp/dist/index.js"], None)));
        assert!(is_claude_adapter(&spec(&["/opt/Claude-Agent-ACP"], None)));
        assert!(!is_claude_adapter(&spec(&["gemini", "--experimental-acp"], None)));
        assert!(!is_claude_adapter(&spec(&["python3", "/workspace/agent.py"], None)));
    }

    #[test]
    fn control_file_matching() {
        assert_eq!(control_file("/workspace/.claude/settings.local.json"), Some(".claude"));
        assert_eq!(control_file("a/./.git/hooks/x"), Some(".git/hooks"));
        assert_eq!(control_file(".git/config"), Some(".git/config"));
        assert_eq!(control_file("/workspace/.github/workflows/ci.yml"), Some(".github/workflows"));
        assert_eq!(control_file("/workspace/src/.gitignore"), None);
        assert_eq!(control_file("/workspace/my.claude/x"), None);
        assert_eq!(control_file("/workspace/.git/objects/ab"), None);
    }

    /// Conformance (16): a woken agent's history replays; permission prompts during it are not
    /// answered from it, and after it every prompt is decided afresh.
    #[test]
    fn replayed_approvals_are_not_honoured() {
        let (mut c, _) = AcpClient::start(AcpConfig { resume: Some("old".into()), ..cfg() });
        let st = c.on_line(&init_result(json!({})));
        let v = parse(&st.write[0]);
        assert_eq!((v["method"].as_str(), v["params"]["sessionId"].as_str()), (Some("session/load"), Some("old")));
        assert_eq!(v["params"]["mcpServers"][0]["name"], "wicket");
        // History: a tool call that was once approved "always", replayed as updates.
        for u in [
            json!({ "sessionUpdate": "tool_call", "toolCallId": "h1", "title": "push", "kind": "execute" }),
            json!({ "sessionUpdate": "tool_call_update", "toolCallId": "h1", "status": "completed" }),
            json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "approved always" } }),
        ] {
            let st = c.on_line(
                &json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": "old", "update": u } }).to_string(),
            );
            assert!(st.events.is_empty() && st.write.is_empty(), "history is not shown as current");
        }
        // A prompt that arrives during the replay is cancelled, whatever it offers.
        let (o, e) = ask(&mut c, 50, json!({ "toolCallId": "h1", "kind": "execute" }), &[("a1", "allow_once")]);
        assert_eq!(o, json!({ "outcome": "cancelled" }));
        assert!(matches!(e, SessionEvent::Permission { why, .. } if why.contains("replay")));
        let st = c.on_line(&json!({ "jsonrpc": "2.0", "id": 1, "result": {} }).to_string());
        assert_eq!(
            st.events[0],
            SessionEvent::Started { agent: "mock 1".into(), session: "old".into(), how: "loaded".into(), replayed: 3 }
        );
        // After it, decided by policy again (and still never "always").
        let (o, _) = ask(&mut c, 51, json!({ "toolCallId": "h1" }), &ALL);
        assert_eq!(o["optionId"], "a1");
    }

    #[test]
    fn resume_is_preferred_and_a_failed_continue_falls_back_to_a_new_session() {
        let (mut c, _) = AcpClient::start(AcpConfig { resume: Some("old".into()), ..cfg() });
        let st = c.on_line(&init_result(json!({ "sessionCapabilities": { "resume": {}, "systemPrompt": {} } })));
        assert_eq!(parse(&st.write[0])["method"], "session/resume");
        let st = c.on_line(&json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32002, "message": "no such session" } }).to_string());
        assert_eq!(parse(&st.write[0])["method"], "session/new");
        assert!(matches!(&st.events[0], SessionEvent::Notice { .. }));
    }

    #[test]
    fn a_turn_streams_events_and_queued_prompts_follow_it() {
        let mut c = open();
        assert!(c.busy());
        // A follow-up while the turn runs waits for it (v1 has no steering).
        assert!(c.prompt("next").is_empty());
        let up =
            |u: Value| json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": "s1", "update": u } }).to_string();
        assert!(c
            .on_line(&up(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "Hel" } })))
            .events
            .is_empty());
        c.on_line(&up(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "lo" } })));
        let st = c.on_line(&up(json!({ "sessionUpdate": "tool_call", "toolCallId": "t", "title": "Edit a.rs", "kind": "edit", "rawInput": { "file_path": "a.rs" } })));
        assert_eq!(st.events[0], SessionEvent::Message { text: "Hello".into() });
        assert_eq!(render(&st.events[1]).unwrap(), "[tool]  Edit a.rs (edit): a.rs");
        let st = c.on_line(&up(
            json!({ "sessionUpdate": "tool_call_update", "toolCallId": "t", "status": "completed", "content": [{ "type": "diff", "path": "/workspace/a.rs", "oldText": "a", "newText": "b" }] }),
        ));
        assert!(
            matches!(&st.events[0], SessionEvent::ToolUpdate { diff: Some(d), .. } if d.path == "/workspace/a.rs" && d.new_text == "b")
        );
        let st = c.on_line(&up(json!({ "sessionUpdate": "plan", "entries": [{ "content": "x", "priority": "high", "status": "completed" }, { "content": "y", "priority": "low", "status": "pending" }] })));
        assert_eq!(render(&st.events[0]).unwrap(), "[agent] plan: 1/2 done");
        let st = c.on_line(&json!({ "jsonrpc": "2.0", "id": 2, "result": { "stopReason": "end_turn" } }).to_string());
        assert_eq!(st.events, vec![SessionEvent::TurnDone { stop: "end_turn".into() }]);
        let v = parse(&st.write[0]);
        assert_eq!((v["method"].as_str(), v["params"]["prompt"][0]["text"].as_str()), (Some("session/prompt"), Some("next")));
        // Cancel: a notification, and prompts after it are cancelled until the turn ends.
        let out = c.cancel();
        assert_eq!(parse(&out[0])["method"], "session/cancel");
        let (o, _) = ask(&mut c, 60, json!({ "toolCallId": "z", "kind": "read" }), &ALL);
        assert_eq!(o, json!({ "outcome": "cancelled" }));
        // It serialises: a re-attached supervisor carries on.
        let mut c2: AcpClient = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        let st = c2.on_line(&json!({ "jsonrpc": "2.0", "id": 3, "result": { "stopReason": "cancelled" } }).to_string());
        assert_eq!(st.events, vec![SessionEvent::TurnDone { stop: "cancelled".into() }]);
        assert!(!c2.busy());
    }

    #[test]
    fn a_hostile_agent_cannot_grow_the_client_state_without_bound() {
        let mut c = open();
        let up =
            |u: Value| json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": "s1", "update": u } }).to_string();
        let big = "é".repeat(10_000);
        for _ in 0..20 {
            c.on_line(&up(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": big } })));
            c.on_line(&up(json!({ "sessionUpdate": "agent_thought_chunk", "content": { "type": "text", "text": big } })));
        }
        for i in 0..(MAX_TOOLS + 50) {
            c.on_line(&up(json!({ "sessionUpdate": "tool_call_update", "toolCallId": format!("t{i}"), "kind": "read" })));
        }
        c.on_line(&up(json!({ "sessionUpdate": "tool_call", "toolCallId": "x".repeat(5000), "title": "t", "kind": "read" })));
        assert!(c.message.len() <= MAX_TEXT && c.thought.len() <= MAX_TEXT);
        assert_eq!(c.tools.len(), MAX_TOOLS);
        assert!(serde_json::to_string(&c).unwrap().len() < 1 << 20);
    }

    #[test]
    fn junk_and_unknown_responses_are_ignored() {
        let mut c = open();
        assert_eq!(c.on_line("not json"), Step::default());
        assert_eq!(c.on_line(r#"{"jsonrpc":"2.0","id":999,"result":{}}"#), Step::default());
        assert_eq!(c.on_line(r#"{"jsonrpc":"2.0","method":"x/notify"}"#), Step::default());
    }
}
