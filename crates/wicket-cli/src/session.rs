//! `wicket session RUN [TEXT]` (#198): a running agent's session in the operator's terminal, which
//! replaces `wicket say` for a human at a shell (the console's session page is the other way in).
//!
//! **What shows.** For an ACP run, the session as the console's session page gets it: this drives
//! the same [`Bridge`] as the console's WebSocket endpoint (`serve::session`), so the browser and the
//! terminal read one stream: the agent's messages and thoughts as they stream, tool calls and their
//! updates (wicket's policy answers included), plans, other principals' prompts, and wicket's
//! escalations, which are decided with `wicket approve` or `wicket deny` (or in the console). For a
//! run that speaks Claude Code's stream-json, its transcript: messages, tool calls and results, and
//! the end of each turn, with the run's escalations.
//!
//! **Prompts.** Each line typed is a prompt, queued as an operator message from the operator
//! running the command (the unix user wicketd names, as for `wicket approve`); the run's supervisor
//! hands it to the agent as its next turn. Audited as `session.prompt` with `via: terminal`. `/stop`
//! cancels an ACP agent's running turn, as the console's Stop does. With TEXT, the command sends that
//! one prompt, shows its turn and exits when it ends (`--no-wait`: at once).
//!
//! **No passkey.** The console's socket needs a fresh passkey assertion because a browser is
//! remote; this command runs as the local operator through wicketd, who can already read the run's
//! files and write the ledger (as `say` did). It answers nothing for the agent and decides nothing.
//!
//! **Hibernated agents.** Opening a hibernated agent's session wakes it (#29): with TEXT, the text
//! is its first turn and the command returns once the wake is under way; without, it waits for the
//! woken run and follows it.

use crate::hibernate;
use crate::operators::Operator;
use crate::serve::session::{Bridge, Who};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use wicket_core::text::{clip, strip};
use wicket_core::{RunId, TenantId};
use wicket_store::Ledger;

/// How often the run's files and the ledger are read.
const POLL: Duration = Duration::from_millis(250);
/// How often the run is checked for having ended.
const RECHECK: Duration = Duration::from_secs(2);
/// How long a hibernated agent may take to wake before the command gives up following it.
const WAKE_WAIT: Duration = Duration::from_secs(300);
/// How much of the transcript one read takes.
const READ_CHUNK: usize = 4 << 20;
/// The JSON-RPC id of a TEXT prompt.
const ONE: &str = "terminal-prompt";

/// What `wicket session` was asked.
pub struct Opts {
    pub run: String,
    pub text: Option<String>,
    pub wait: bool,
    pub timeout: Option<Duration>,
}

/// Opens the session; returns when the user leaves, the run ends, or TEXT's turn does.
pub async fn open(o: Opts) -> Result<()> {
    let tenant = TenantId::single();
    let op = Operator::cli(&tenant.0)?;
    if let Some(t) = &o.text {
        if t.trim().is_empty() {
            bail!("the prompt is empty");
        }
        if t.chars().count() > crate::serve::MAX_TEXT {
            bail!("the prompt is too long (at most {} characters)", crate::serve::MAX_TEXT);
        }
    }
    let run = {
        let l = Ledger::open(&crate::ledger_path())?;
        match reach(&l, &tenant, &op, &o.run, o.text.as_deref())? {
            Reached::Run(r) => r,
            Reached::Waking(_) if o.text.is_some() => return Ok(()),
            Reached::Waking(agent) => awake(&agent).await?,
        }
    };
    {
        let l = Ledger::open(&crate::ledger_path())?;
        running(&l, &run)?;
    }
    let dir = crate::data_dir().join("runs").join(&run);
    let s = Session { run, dir, tenant, op, deadline: o.timeout.map(|t| Instant::now() + t) };
    if s.dir.join(crate::transcript::ACP_LOG).is_file() {
        s.acp(o.text, o.wait).await
    } else {
        s.stream_json(o.text, o.wait).await
    }
}

enum Reached {
    Run(String),
    /// A hibernated agent being woken (its id).
    Waking(String),
}

/// The run `who` names (a run, or an agent through its current run); a hibernated agent is woken,
/// with `text` as its first turn.
fn reach(l: &Ledger, tenant: &TenantId, op: &Operator, who: &str, text: Option<&str>) -> Result<Reached> {
    if l.run_status(who)?.as_deref() == Some("running") {
        return Ok(Reached::Run(who.to_string()));
    }
    let Ok(a) = hibernate::resolve(l, who) else { return Ok(Reached::Run(who.to_string())) };
    match a.state.as_str() {
        "hibernated" if a.restorable => {
            if let Some(why) = hibernate::exhausted(&a) {
                bail!("agent {} is hibernated and can't be woken: {why}", a.id);
            }
            if let Some(t) = text {
                let id = l.add_operator_message(&a.id, t, &op.label)?;
                l.audit(tenant, None, "session.prompt", &prompt_audit(op, None, Some(&a.id), id, t))?;
            }
            hibernate::trigger_wake(&a.id, &format!("wicket session by {}", op.label));
            let log = hibernate::agent_dir(&a.id).join("wake.log");
            match text {
                Some(_) => println!(
                    "agent {} is hibernated: waking it; the prompt is its first turn (log: {}; follow it with `wicket session {}`)",
                    a.id,
                    log.display(),
                    a.id
                ),
                None => println!("agent {} is hibernated: waking it (log: {})", a.id, log.display()),
            }
            Ok(Reached::Waking(a.id))
        }
        "active" | "waking" | "hibernating" => Ok(Reached::Run(a.run)),
        s => bail!("agent {} is {s}", a.id),
    }
}

/// Waits for a woken agent's run to be running, and returns it.
async fn awake(agent: &str) -> Result<String> {
    let start = Instant::now();
    loop {
        if let Ok(l) = Ledger::open(&crate::ledger_path()) {
            if let Ok(a) = hibernate::resolve(&l, agent) {
                if a.state == "active" && l.run_status(&a.run)?.as_deref() == Some("running") {
                    println!("agent {agent} is awake: run {}", a.run);
                    return Ok(a.run);
                }
                // Still hibernated well after the wake was started: it failed.
                if a.state == "hibernated" && start.elapsed() > Duration::from_secs(30) {
                    bail!("agent {agent} didn't wake: see {}", hibernate::agent_dir(agent).join("wake.log").display());
                }
            }
        }
        if start.elapsed() > WAKE_WAIT {
            bail!("agent {agent} didn't wake in {}s: see {}", WAKE_WAIT.as_secs(), hibernate::agent_dir(agent).join("wake.log").display());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Refuses a run that isn't running or whose identity is revoked, as the console does.
fn running(l: &Ledger, run: &str) -> Result<()> {
    match l.run_status(run)?.as_deref() {
        Some("running") => {}
        Some(s) => bail!("{run} is {s}, not running"),
        None => bail!("no run {run}"),
    }
    if let Some((r, ..)) = l.revoked_in_chain(run)? {
        bail!("{run}'s identity is revoked (via {r})");
    }
    Ok(())
}

/// A `session.prompt` audit body, as the console's endpoint writes it.
fn prompt_audit(op: &Operator, run: Option<&str>, agent: Option<&str>, id: i64, text: &str) -> Value {
    json!({ "run": run, "agent": agent, "by": op.label, "principal": op.id, "via": "terminal", "operator_message": id,
            "chars": text.chars().count(), "sha256": hex::encode(sha2::Sha256::digest(text.as_bytes())), "wakes": agent.is_some() })
}

/// The lines typed at the terminal, read on their own thread (a blocking read would hold the
/// runtime at exit): None when input ends.
fn typed() -> tokio::sync::mpsc::Receiver<String> {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            line.clear();
            match stdin.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.blocking_send(line.trim_end_matches(['\n', '\r']).to_string()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

fn show(s: &str) {
    if !s.is_empty() {
        let mut o = std::io::stdout().lock();
        let _ = o.write_all(s.as_bytes());
        let _ = o.flush();
    }
}

struct Session {
    run: String,
    dir: PathBuf,
    tenant: TenantId,
    op: Operator,
    deadline: Option<Instant>,
}

impl Session {
    fn ledger(&self) -> Result<Ledger> {
        Ok(Ledger::open(&crate::ledger_path())?)
    }

    fn who(&self) -> Who {
        Who { principal: self.op.id.clone(), label: self.op.label.clone(), token: None, via: "terminal" }
    }

    fn audit(&self, kind: &str, body: Value) {
        if let Ok(l) = self.ledger() {
            let _ = l.audit(&self.tenant, Some(&RunId(self.run.clone())), kind, &body);
        }
    }

    fn timed_out(&self) -> Result<()> {
        if self.deadline.is_some_and(|d| Instant::now() > d) {
            bail!("gave up following {}: its turn goes on", self.run);
        }
        Ok(())
    }

    fn ended(&self) -> Option<String> {
        let l = self.ledger().ok()?;
        running(&l, &self.run).err().map(|e| e.to_string())
    }

    /// An ACP run: the console endpoint's bridge, in the terminal.
    async fn acp(&self, text: Option<String>, wait: bool) -> Result<()> {
        let mut b = Bridge::new(crate::ledger_path(), self.dir.clone(), self.tenant.clone(), self.run.clone(), self.who());
        let mut scr = Screen::default();
        let rpc = |id: &str, method: &str, params: Value| json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        b.on_client(&rpc("init", "initialize", json!({ "protocolVersion": wicket_agent::acp::PROTOCOL_VERSION, "clientCapabilities": {} })));
        // The session so far: shown when opening it, not when sending one prompt.
        let history = b.on_client(&rpc("load", "session/load", json!({ "sessionId": self.run, "cwd": "/", "mcpServers": [] })));
        if let Some(t) = text {
            for m in b.on_client(&rpc(ONE, "session/prompt", json!({ "sessionId": self.run, "prompt": [{ "type": "text", "text": t }] }))) {
                if let Some(e) = m.pointer("/error/message").and_then(|e| e.as_str()) {
                    bail!("{}: {}", self.run, strip(e));
                }
            }
            if !wait {
                println!("queued for {}: the agent gets it as its next turn", self.run);
                return Ok(());
            }
            show(&format!("> {}: {}\n", strip(&self.op.label), lines(&t)));
            let mut checked = Instant::now();
            loop {
                tokio::time::sleep(POLL).await;
                for m in b.poll() {
                    show(&scr.acp(&m));
                    if m.get("id").and_then(|i| i.as_str()) == Some(ONE) && m.get("method").is_none() {
                        return match m.pointer("/error/message").and_then(|e| e.as_str()) {
                            Some(e) => bail!("the turn failed: {}", strip(e)),
                            None => Ok(()),
                        };
                    }
                }
                self.timed_out()?;
                if checked.elapsed() > RECHECK {
                    checked = Instant::now();
                    if let Some(why) = self.ended() {
                        bail!("{why}, before its turn ended");
                    }
                }
            }
        }
        b.audit("session.attached", json!({ "run": self.run, "by": self.op.label, "principal": self.op.id, "via": "terminal" }));
        show(&format!("session {} (type a prompt and Enter; /stop cancels the running turn; Ctrl-C leaves)\n", self.run));
        for m in history {
            show(&scr.acp(&m));
        }
        let mut input = typed();
        let mut n = 0u64;
        let mut tick = tokio::time::interval(POLL);
        let mut recheck = tokio::time::interval(RECHECK);
        let why = loop {
            tokio::select! {
                l = input.recv() => match l {
                    None => break "the input ended",
                    Some(l) if l.trim().is_empty() => {}
                    Some(l) if l.trim() == "/stop" => {
                        let m = json!({ "jsonrpc": "2.0", "method": "session/cancel", "params": { "sessionId": self.run } });
                        b.on_client(&m.to_string()).iter().for_each(|m| show(&scr.acp(m)));
                    }
                    Some(l) => {
                        n += 1;
                        let m = rpc(&format!("terminal-{n}"), "session/prompt", json!({ "sessionId": self.run, "prompt": [{ "type": "text", "text": l }] }));
                        b.on_client(&m).iter().for_each(|m| show(&scr.acp(m)));
                    }
                },
                _ = tokio::signal::ctrl_c() => break "the operator left",
                _ = tick.tick() => b.poll().iter().for_each(|m| show(&scr.acp(m))),
                _ = recheck.tick() => if let Some(why) = self.ended() {
                    b.poll().iter().for_each(|m| show(&scr.acp(m)));
                    show(&scr.line(&format!("[wicket] {why}")));
                    break "the run ended";
                },
            }
        };
        show(&scr.line(""));
        b.audit("session.closed", json!({ "run": self.run, "by": self.op.label, "principal": self.op.id, "via": "terminal", "prompts": b.prompts, "why": why }));
        Ok(())
    }

    /// Queues a prompt for a run that isn't ACP's, audited as the endpoint's are.
    fn queue(&self, text: &str) -> Result<i64> {
        if text.chars().count() > crate::serve::MAX_TEXT {
            bail!("the prompt is too long (at most {} characters)", crate::serve::MAX_TEXT);
        }
        let l = self.ledger()?;
        running(&l, &self.run)?;
        let id = l.add_operator_message(&self.run, text, &self.op.label)?;
        l.audit(&self.tenant, Some(&RunId(self.run.clone())), "session.prompt", &prompt_audit(&self.op, Some(&self.run), None, id, text))?;
        Ok(id)
    }

    /// A run speaking Claude Code's stream-json: its transcript, rendered.
    async fn stream_json(&self, text: Option<String>, wait: bool) -> Result<()> {
        let mut scr = Screen::default();
        if let Some(t) = text {
            let pos = crate::transcript::end_offset(&self.dir);
            let busy = self.ledger()?.run_activity(&self.run)?.as_deref() == Some("busy");
            let id = self.queue(&t)?;
            if !wait {
                println!("queued for {}: the agent gets it as its next turn", self.run);
                return Ok(());
            }
            show(&format!("> {}: {}\n", strip(&self.op.label), lines(&t)));
            return self.follow_turn(&mut scr, pos, id, busy).await;
        }
        self.audit("session.attached", json!({ "run": self.run, "by": self.op.label, "principal": self.op.id, "via": "terminal" }));
        show(&format!("session {} (type a prompt and Enter; Ctrl-C leaves)\n", self.run));
        let mut pos = 0;
        let mut input = typed();
        let mut prompts = 0u64;
        let mut tick = tokio::time::interval(POLL);
        let mut recheck = tokio::time::interval(RECHECK);
        let why = loop {
            tokio::select! {
                l = input.recv() => match l {
                    None => break "the input ended",
                    Some(l) if l.trim().is_empty() => {}
                    Some(l) if l.trim() == "/stop" => show(&scr.line("[wicket] /stop cancels an ACP agent's turn; this agent speaks stream-json")),
                    Some(l) => match self.queue(&l) {
                        Ok(_) => prompts += 1,
                        Err(e) => show(&scr.line(&format!("[wicket] not sent: {e}"))),
                    },
                },
                _ = tokio::signal::ctrl_c() => break "the operator left",
                _ = tick.tick() => {
                    pos = self.read(&mut scr, pos, |_| {});
                    self.escalations(&mut scr);
                }
                _ = recheck.tick() => if let Some(why) = self.ended() {
                    self.read(&mut scr, pos, |_| {});
                    show(&scr.line(&format!("[wicket] {why}")));
                    break "the run ended";
                },
            }
        };
        show(&scr.line(""));
        self.audit("session.closed", json!({ "run": self.run, "by": self.op.label, "principal": self.op.id, "via": "terminal", "prompts": prompts, "why": why }));
        Ok(())
    }

    /// Shows the transcript from `pos` until the turn of operator message `id` ends. `busy`: a turn
    /// was running when it was queued, so the first turn end after the agent takes it is that one's.
    async fn follow_turn(&self, scr: &mut Screen, mut pos: u64, id: i64, busy: bool) -> Result<()> {
        let mut taken = false;
        let mut skip = 0u32;
        let mut checked = Instant::now();
        loop {
            if !taken && self.ledger()?.operator_message_taken(id)? == Some(true) {
                taken = true;
                skip = u32::from(busy);
            }
            let mut ends = 0u32;
            pos = self.read(scr, pos, |_| ends += 1);
            self.escalations(scr);
            if taken && ends > skip {
                return Ok(());
            }
            if taken {
                skip -= ends;
            }
            self.timed_out()?;
            if checked.elapsed() > RECHECK {
                checked = Instant::now();
                if let Some(why) = self.ended() {
                    bail!("{why}, before its turn ended");
                }
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Shows the transcript's new lines; `turn_end` is called at each top-level turn's end.
    fn read(&self, scr: &mut Screen, pos: u64, mut turn_end: impl FnMut(())) -> u64 {
        let (got, next) = crate::transcript::read_since(&self.dir, pos, READ_CHUNK);
        for (_, l) in got {
            let (out, end) = scr.stream_json(&l);
            show(&out);
            if end {
                turn_end(());
            }
        }
        next
    }

    /// The run's new escalations, as the session endpoint shows them.
    fn escalations(&self, scr: &mut Screen) {
        let Ok(l) = self.ledger() else { return };
        let Ok(pending) = l.pending(&self.tenant) else { return };
        for r in pending.iter().filter(|r| r.run == self.run) {
            if scr.shown.insert(r.id.clone()) {
                show(&scr.line(&escalation(&r.id, &r.method, &r.host, &r.path, &r.risk, &r.reason)));
            }
        }
    }
}

/// How an escalation reads, and how to decide it.
fn escalation(id: &str, method: &str, host: &str, path: &str, risk: &str, reason: &str) -> String {
    let risk = if risk.is_empty() { String::new() } else { format!(", risk {}", clip(risk, 10)) };
    format!(
        "[wicket] escalation {}: {} {}{}{risk}: {}\n  decide it: wicket approve {0}, or wicket deny {0} (or in the console)",
        strip(id),
        clip(method, 20),
        clip(host, 200),
        clip(path, 300),
        clip(reason, 300)
    )
}

/// Untrusted text that may run over lines: each line stripped of escapes, indented after the first.
fn lines(s: &str) -> String {
    s.split('\n').map(strip).collect::<Vec<_>>().join("\n  ")
}

/// What the terminal shows: streamed chunks run on, everything else is a line of its own.
#[derive(Default)]
struct Screen {
    /// What is streaming now (the agent's message or its thought), if anything.
    streaming: Option<&'static str>,
    /// Tool calls' titles, by id.
    titles: HashMap<String, String>,
    /// Escalations shown (a stream-json run's).
    shown: BTreeSet<String>,
}

impl Screen {
    /// A line of its own (ending a stream first).
    fn line(&mut self, s: &str) -> String {
        let pre = if self.streaming.take().is_some() { "\n" } else { "" };
        if s.is_empty() {
            return pre.to_string();
        }
        format!("{pre}{s}\n")
    }

    /// A chunk of `kind`, run on after the last one of the same kind.
    fn chunk(&mut self, kind: &'static str, s: &str) -> String {
        let text = s.split('\n').map(strip).collect::<Vec<_>>().join("\n");
        if self.streaming == Some(kind) {
            return text;
        }
        let pre = if self.streaming.is_some() { "\n" } else { "" };
        self.streaming = Some(kind);
        let label = if kind == "thought" { "(thinking) " } else { "agent: " };
        format!("{pre}{label}{text}")
    }

    /// One message the session bridge gives the client.
    fn acp(&mut self, m: &Value) -> String {
        let method = m.get("method").and_then(|x| x.as_str());
        match method {
            Some("session/update") => self.update(m.pointer("/params/update").unwrap_or(&Value::Null)),
            Some("session/request_permission") => match m.pointer("/params/_meta/wicket/escalation") {
                Some(e) => {
                    let s = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("");
                    self.line(&escalation(s("id"), s("method"), s("host"), s("path"), s("risk"), s("reason")))
                }
                None => String::new(),
            },
            Some(_) => String::new(),
            None => match (m.pointer("/result/stopReason").and_then(|s| s.as_str()), m.pointer("/error/message").and_then(|s| s.as_str())) {
                (Some(stop), _) => self.line(&format!("[turn ended: {}]", clip(stop, 40))),
                (_, Some(e)) => self.line(&format!("[wicket] {}", clip(e, 300))),
                _ => String::new(),
            },
        }
    }

    fn update(&mut self, u: &Value) -> String {
        let s = |k: &str| u.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let text = u.pointer("/content/text").and_then(|t| t.as_str()).unwrap_or("");
        let wicket = u.pointer("/_meta/wicket");
        match s("sessionUpdate") {
            "agent_message_chunk" if wicket.and_then(|w| w.get("notice")).is_some() => self.line(&lines(text.trim_end())),
            "agent_message_chunk" => self.chunk("agent", text),
            "agent_thought_chunk" => self.chunk("thought", text),
            "user_message_chunk" => {
                let by = wicket.and_then(|w| w.get("by")).and_then(|b| b.as_str()).unwrap_or("someone");
                self.line(&format!("> {}: {}", strip(by), lines(text)))
            }
            "tool_call" => {
                let id = s("toolCallId").to_string();
                let title = clip(s("title"), 200);
                if self.titles.len() < 10_000 {
                    self.titles.insert(id, title.clone());
                }
                let input = u.get("rawInput").filter(|i| !i.is_null()).map(|i| format!("  {}", clip(&i.to_string(), 200))).unwrap_or_default();
                self.line(&format!("tool: {title} [{}]{input}", clip(s("status"), 20)))
            }
            "tool_call_update" => {
                let title = self.titles.get(s("toolCallId")).cloned().unwrap_or_else(|| clip(s("toolCallId"), 80));
                if let Some(p) = wicket.and_then(|w| w.get("permission")) {
                    let o = p.get("outcome").and_then(|o| o.as_str()).unwrap_or("?");
                    return self.line(&format!("  wicket's policy: {} ({title})", clip(o, 20)));
                }
                if let Some(e) = wicket.and_then(|w| w.get("escalation")) {
                    let g = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("?");
                    return self.line(&format!("[wicket] escalation {}: {}", strip(g("id")), clip(g("status"), 20)));
                }
                let mut out = String::new();
                for c in u.get("content").and_then(|c| c.as_array()).into_iter().flatten() {
                    match c.get("type").and_then(|t| t.as_str()) {
                        Some("diff") => out += &self.line(&format!("  diff: {}", clip(c.get("path").and_then(|p| p.as_str()).unwrap_or("?"), 200))),
                        Some("content") => {
                            if let Some(t) = c.pointer("/content/text").and_then(|t| t.as_str()) {
                                out += &self.line(&format!("  {}", clip(t, 300)));
                            }
                        }
                        _ => {}
                    }
                }
                if !s("status").is_empty() {
                    out += &self.line(&format!("tool: {title} [{}]", clip(s("status"), 20)));
                }
                out
            }
            "plan" => {
                let mut p = "plan:".to_string();
                for e in u.get("entries").and_then(|e| e.as_array()).into_iter().flatten() {
                    let g = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("");
                    p += &format!("\n  [{}] {}", clip(g("status"), 20), clip(g("content"), 200));
                }
                self.line(&p)
            }
            _ => String::new(),
        }
    }

    /// One stream-json line of the transcript, and whether it ends a top-level turn.
    fn stream_json(&mut self, line: &str) -> (String, bool) {
        let Ok(v) = serde_json::from_str::<Value>(line) else { return (String::new(), false) };
        let blocks = v.pointer("/message/content").and_then(|c| c.as_array()).cloned().unwrap_or_default();
        let mut out = String::new();
        match v.get("type").and_then(|t| t.as_str()) {
            Some("assistant") => {
                for b in &blocks {
                    match b.get("type").and_then(|t| t.as_str()) {
                        Some("text") => out += &self.line(&format!("agent: {}", lines(b["text"].as_str().unwrap_or("").trim_end()))),
                        Some("thinking") => out += &self.line(&format!("(thinking) {}", clip(b["thinking"].as_str().unwrap_or(""), 300))),
                        Some("tool_use") => {
                            out += &self.line(&format!("tool: {}  {}", clip(b["name"].as_str().unwrap_or("?"), 80), clip(&b["input"].to_string(), 200)))
                        }
                        _ => {}
                    }
                }
            }
            Some("user") => {
                for b in blocks.iter().filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_result")) {
                    let text = match &b["content"] {
                        Value::String(s) => s.clone(),
                        Value::Array(a) => a.iter().filter_map(|c| c.get("text")?.as_str()).collect::<Vec<_>>().join("\n"),
                        _ => String::new(),
                    };
                    let err = if b["is_error"].as_bool() == Some(true) { " (error)" } else { "" };
                    out += &self.line(&format!("  result{err}: {}", clip(&text, 300)));
                }
            }
            Some("result") if v.get("parent_tool_use_id").is_none_or(|p| p.is_null()) => {
                let sub = v.get("subtype").and_then(|s| s.as_str()).unwrap_or("done");
                return (self.line(&format!("[turn ended: {}]", clip(sub, 40))), true);
            }
            _ => {}
        }
        (out, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upd(u: Value) -> Value {
        json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": "run_a", "update": u } })
    }

    #[test]
    fn an_acp_session_reads_as_lines_with_chunks_run_on() {
        let mut s = Screen::default();
        let mut out = String::new();
        out += &s.acp(&upd(json!({ "sessionUpdate": "user_message_chunk", "content": { "type": "text", "text": "fix it" }, "_meta": { "wicket": { "by": "task" } } })));
        out += &s.acp(&upd(json!({ "sessionUpdate": "agent_thought_chunk", "content": { "type": "text", "text": "hmm" } })));
        out += &s.acp(&upd(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "On " } })));
        out += &s.acp(&upd(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "it." } })));
        out += &s.acp(&upd(json!({ "sessionUpdate": "tool_call", "toolCallId": "t1", "title": "Edit a.rs", "kind": "edit", "status": "pending" })));
        out += &s.acp(&upd(json!({ "sessionUpdate": "tool_call_update", "toolCallId": "t1",
                                    "_meta": { "wicket": { "permission": { "outcome": "selected", "optionId": "allow" } } } })));
        out += &s.acp(&upd(json!({ "sessionUpdate": "tool_call_update", "toolCallId": "t1", "status": "completed",
                                    "content": [{ "type": "diff", "path": "/workspace/a.rs", "oldText": "a", "newText": "b" }] })));
        out += &s.acp(&upd(json!({ "sessionUpdate": "plan", "entries": [{ "content": "test", "status": "pending", "priority": "high" }] })));
        out += &s.acp(&json!({ "jsonrpc": "2.0", "id": "terminal-1", "result": { "stopReason": "end_turn" } }));
        assert_eq!(
            out,
            "> task: fix it\n(thinking) hmm\nagent: On it.\ntool: Edit a.rs [pending]\n  wicket's policy: selected (Edit a.rs)\n  diff: /workspace/a.rs\n\
             tool: Edit a.rs [completed]\nplan:\n  [pending] test\n[turn ended: end_turn]\n"
        );
    }

    #[test]
    fn escalations_say_how_to_decide_them_and_escapes_never_reach_the_terminal() {
        let mut s = Screen::default();
        let esc = json!({ "id": "R-1", "method": "POST", "host": "api.github.com", "path": "/repos", "risk": "R2", "reason": "open a PR\u{1b}[2J" });
        let out = s.acp(&json!({ "jsonrpc": "2.0", "id": "wicket-0", "method": "session/request_permission",
                                 "params": { "sessionId": "run_a", "_meta": { "wicket": { "escalation": esc } } } }));
        assert!(out.contains("escalation R-1: POST api.github.com/repos, risk R2: open a PR [2J"), "{out}");
        assert!(out.contains("wicket approve R-1, or wicket deny R-1"), "{out}");
        let out = s.acp(&upd(json!({ "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": "a\u{1b}]0;owned\u{7}\nb" } })));
        assert!(!out.contains('\u{1b}') && !out.contains('\u{7}') && out.contains("a ]0;owned \nb"), "{out:?}");
    }

    #[test]
    fn a_stream_json_transcript_reads_as_lines_and_top_level_results_end_turns() {
        let mut s = Screen::default();
        let a = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Running it."},{"type":"tool_use","id":"t","name":"Bash","input":{"command":"ls"}}]}}"#;
        let u = r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t","content":"a\nb"}]}}"#;
        let sub = r#"{"type":"result","subtype":"success","parent_tool_use_id":"toolu_x"}"#;
        let end = r#"{"type":"result","subtype":"success","parent_tool_use_id":null}"#;
        assert_eq!(s.stream_json(a), ("agent: Running it.\ntool: Bash  {\"command\":\"ls\"}\n".into(), false));
        assert_eq!(s.stream_json(u), ("  result: a ⏎ b\n".into(), false));
        assert_eq!(s.stream_json(sub), (String::new(), false));
        assert_eq!(s.stream_json(end), ("[turn ended: success]\n".into(), true));
        assert_eq!(s.stream_json("not json"), (String::new(), false));
    }
}
