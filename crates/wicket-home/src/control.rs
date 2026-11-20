//! A driven harness's control channel (#363): interrupting its turn, changing its permission mode
//! while it runs, and its prompts before a tool call. The harness's own protocol is its adapter's
//! ([`wicket_agent::harness::Controller`]); this is what wicket does with it, with no I/O of its
//! own. The channel's two directions are read in two places (#257 step 8), and never share a
//! request id:
//!
//! - **[`Supervised`], on the control host**: the requests wicket starts, which are an operator's
//!   commands (an interrupt, a mode change), and the harness's answers to them. It writes nothing
//!   in answer to the harness.
//! - **[`Prompts`], on the box's node**: the requests the harness starts. Its prompts before a tool
//!   call, and anything else it asks (answered with an error). The node feeds it the box's stdout
//!   and writes what it says to the box's stdin.
//!
//! **Prompts.** A harness in a mode that asks (Claude Code with `--permission-prompt-tool stdio`,
//! see `wicket_agent::claude::control`) asks its stdin host before a tool call. What wicket's rule
//! refuses (a control file, a mode change, a question) the adapter's controller has already
//! answered. For anything else:
//!
//! - in `bypassPermissions` it is allowed at once (#423): the harness was told to ask no one, and a
//!   human isn't asked about a call its own mode allows. The mode is the manifest's, changed only by
//!   an operator ([`Prompts::set_mode`]), never by anything the box writes;
//! - otherwise the node decides it ([`Step::Decide`]): a TOOL grant in its replica, a zone that may
//!   not ask, or a request in wicket's own approval namespace for a human (`wicket approve`/`wicket
//!   deny`, the console). The op is `TOOL wicket.internal /tools/<tool>/<digest of its input>` ([`op`]),
//!   bound to the run, so a retry of the same call is the same request, and a prefix approval
//!   (`/tools/Bash/`) lets that tool run for the grant's life without asking again. Its risk is by
//!   the call's kind: a command R4, an edit R2, a read or fetch R1 (what leaves the box is still
//!   decided at the gates), anything else R3.
//!
//! Each harness request is answered once: the ids answered (the last [`KEPT_ANSWERED`]) and the
//! prompts still waiting are what a node keeps of a box's prompts across its own restarts, and a
//! line naming one of them again (a replay of the box's output, a repeated id) is ignored. An
//! interrupt withdraws a waiting prompt (its request stays on the record, pending, and a later
//! identical call finds it).

use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{BTreeMap, VecDeque};
use wicket_agent::harness::{ControlEvent, Controller};
use wicket_core::{Op, RemotePermissionMode, RiskClass, RunId, TenantId};

/// The reserved method of a tool prompt's request.
pub const METHOD: &str = "TOOL";

/// How many answered harness request ids a box's prompts keep, to answer none twice.
pub const KEPT_ANSWERED: usize = 256;

/// The longest harness line read for its control requests: a longer one is skipped whole.
const MAX_LINE: usize = 8 << 20;

/// Why a prompt is allowed in `bypassPermissions`.
pub const BYPASS_WHY: &str = "bypassPermissions: the agent acts without asking in this mode; wicket's gates decide what leaves the box";

/// The digest of a tool call's input that its op names it by.
pub fn digest(input: &Value) -> String {
    hex::encode(&sha2::Sha256::digest(input.to_string().as_bytes())[..8])
}

/// The op a tool call's request is for: its tool's name, its kind, and the digest of its input.
pub fn op(tenant: &TenantId, run: &RunId, zone: &str, tool: &str, kind: &str, digest: &str) -> Op {
    let tool: String = tool.chars().map(|ch| if ch.is_ascii_alphanumeric() || "_-.".contains(ch) { ch } else { '_' }).take(80).collect();
    let digest: String = digest.chars().filter(char::is_ascii_hexdigit).take(64).collect();
    let mut op = Op::egress(tenant, run, zone, METHOD, wicket_core::link::DOMAIN, &format!("/tools/{tool}/{digest}"));
    op.risk = match kind {
        "execute" => RiskClass::R4ExecOrPrivilege,
        "edit" | "delete" | "move" => RiskClass::R2WriteReversible,
        "read" | "fetch" | "search" | "think" => RiskClass::R1ReadScoped,
        _ => RiskClass::R3ExternalOrIrreversible,
    };
    op
}

/// The request's card: what the human is shown. The tool and its input are the agent's data.
pub fn card(tool: &str, kind: &str, detail: &str) -> String {
    format!(
        "the agent asks to use {} ({}): {}. Approving lets it make this call in its box; what leaves the box is still decided at wicket's gates.",
        wicket_agent::clip(tool, 120),
        wicket_agent::clip(kind, 40),
        wicket_agent::clip(detail, 300)
    )
}

/// A prompt the node decides: the harness's id for it, and what the call is.
#[derive(Clone, Debug, PartialEq)]
pub struct Prompt {
    pub id: String,
    pub tool: String,
    pub kind: String,
    /// A short, clipped account of its input (agent data, for a human to read).
    pub detail: String,
    /// [`digest`] of its input.
    pub digest: String,
}

/// What a box's node does after its harness wrote something.
#[derive(Debug, PartialEq)]
pub enum Step {
    /// A line to feed the harness's stdin.
    Write(String),
    /// A prompt for the node to decide, then to answer with [`Prompts::answer`].
    Decide(Prompt),
    /// The harness stopped waiting on this prompt (its turn was interrupted).
    Withdrawn(String),
    /// A `run.agent_prompt` audit record's body.
    Audit(Value),
    /// A line for the operator.
    Say(String),
}

/// The requests a box's harness starts, on its node: its prompts, answered once each.
pub struct Prompts {
    control: Box<dyn Controller>,
    mode: RemotePermissionMode,
    /// The current line so far, and whether it is being skipped (past [`MAX_LINE`]).
    partial: Vec<u8>,
    skipping: bool,
    answered: VecDeque<String>,
    /// Prompts waiting on the node's decision: id, the line that raised it.
    waiting: BTreeMap<String, String>,
}

impl Prompts {
    pub fn new(control: Box<dyn Controller>, mode: RemotePermissionMode) -> Prompts {
        Prompts { control, mode, partial: vec![], skipping: false, answered: VecDeque::new(), waiting: BTreeMap::new() }
    }

    /// Picks up from what a node kept before a restart: the ids it answered, and the lines of the
    /// prompts still waiting, which are raised again.
    pub fn restore(&mut self, answered: &[String], waiting: &[String]) -> Vec<Step> {
        self.answered = answered.iter().rev().take(KEPT_ANSWERED).rev().cloned().collect();
        waiting.iter().flat_map(|l| self.on_line(l)).collect()
    }

    /// The ids answered, oldest first.
    pub fn answered(&self) -> Vec<String> {
        self.answered.iter().cloned().collect()
    }

    /// The lines of the prompts still waiting.
    pub fn waiting_lines(&self) -> Vec<String> {
        self.waiting.values().cloned().collect()
    }

    pub fn is_waiting(&self, id: &str) -> bool {
        self.waiting.contains_key(id)
    }

    pub fn mode(&self) -> RemotePermissionMode {
        self.mode
    }

    /// An operator changed the harness's permission mode: prompts from now on are answered by it.
    pub fn set_mode(&mut self, mode: RemotePermissionMode) {
        self.mode = mode;
    }

    /// Bytes of the harness's stdout, as they come.
    pub fn on_bytes(&mut self, bytes: &[u8]) -> Vec<Step> {
        let mut out = vec![];
        for chunk in bytes.split_inclusive(|b| *b == b'\n') {
            let ends = chunk.ends_with(b"\n");
            if !self.skipping {
                self.partial.extend_from_slice(chunk);
                if self.partial.len() > MAX_LINE {
                    self.partial.clear();
                    self.skipping = true;
                }
            }
            if ends {
                if !self.skipping {
                    let line = String::from_utf8_lossy(&self.partial).into_owned();
                    out.extend(self.on_line(&line));
                }
                self.partial.clear();
                self.skipping = false;
            }
        }
        out
    }

    fn mark_answered(&mut self, id: &str) {
        self.waiting.remove(id);
        if !self.answered.iter().any(|a| a == id) {
            self.answered.push_back(id.to_string());
        }
        while self.answered.len() > KEPT_ANSWERED {
            self.answered.pop_front();
        }
    }

    /// One whole line of the harness's stdout.
    fn on_line(&mut self, line: &str) -> Vec<Step> {
        let v: Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(_) => return vec![],
        };
        let id = v.get("request_id").and_then(|i| i.as_str()).unwrap_or("").to_string();
        match v.get("type").and_then(|t| t.as_str()) {
            // The harness's own request: once each.
            Some("control_request") if !id.is_empty() => {
                if self.answered.contains(&id) || self.waiting.contains_key(&id) {
                    return vec![];
                }
            }
            Some("control_cancel_request") => {}
            // Answers to wicket's requests are the control host's.
            _ => return vec![],
        }
        let st = self.control.on_line(line);
        let mut out = vec![];
        if !st.write.is_empty() {
            self.mark_answered(&id);
            out.extend(st.write.into_iter().map(Step::Write));
        }
        for e in st.events {
            match e {
                ControlEvent::Prompt { tool, kind, detail, refused: Some(why), .. } => {
                    out.push(Step::Say(format!("[wicket] refused the agent's {tool} ({kind}): {why}")));
                    out.push(Step::Audit(json!({ "tool": tool, "kind": kind, "detail": detail, "answer": "deny", "why": why })));
                }
                ControlEvent::Prompt { id, tool, kind, detail, refused: None, .. }
                    if self.mode == RemotePermissionMode::BypassPermissions =>
                {
                    let lines = self.control.answer(&id, true, BYPASS_WHY);
                    self.mark_answered(&id);
                    out.extend(lines.into_iter().map(Step::Write));
                    out.push(Step::Say(format!("[wicket] allowed the agent's {tool} ({kind}): {BYPASS_WHY}")));
                    out.push(Step::Audit(json!({ "tool": tool, "kind": kind, "detail": detail, "answer": "allow", "why": BYPASS_WHY })));
                }
                ControlEvent::Prompt { id, tool, kind, detail, input, refused: None } => {
                    self.waiting.insert(id.clone(), line.trim_end().to_string());
                    out.push(Step::Decide(Prompt { id, tool, kind, detail, digest: digest(&input) }));
                }
                ControlEvent::Withdrawn { id } => {
                    if self.waiting.remove(&id).is_some() {
                        out.push(Step::Withdrawn(id));
                    }
                }
                // wicket's requests are sent from the control host, not from here.
                ControlEvent::Answered { .. } => {}
            }
        }
        out
    }

    /// Answers a waiting prompt as the node decided it (`request`: the human's request it waited
    /// on, if any). Nothing if it no longer waits (withdrawn, or answered already).
    pub fn answer(&mut self, p: &Prompt, allow: bool, why: &str, request: Option<&str>) -> Vec<Step> {
        if !self.waiting.contains_key(&p.id) {
            return vec![];
        }
        let lines = self.control.answer(&p.id, allow, why);
        self.mark_answered(&p.id);
        let answer = if allow { "allow" } else { "deny" };
        let mut out: Vec<Step> = lines.into_iter().map(Step::Write).collect();
        out.push(Step::Say(format!("[wicket] {} the agent's {} ({}): {why}", if allow { "allowed" } else { "refused" }, p.tool, p.kind)));
        out.push(Step::Audit(
            json!({ "tool": p.tool, "kind": p.kind, "detail": p.detail, "answer": answer, "why": why, "request": request }),
        ));
        out
    }
}

/// What the control host does after one of the harness's lines: lines to show the operator, and
/// audit records (kind, body).
#[derive(Debug, Default)]
pub struct Out {
    pub say: Vec<String>,
    pub audit: Vec<(&'static str, Value)>,
}

/// A driven run's control channel on the control host: an operator's commands, and the harness's
/// answers to them.
pub struct Supervised {
    control: Box<dyn Controller>,
}

/// The mode a `wicket session` `/mode` (or any asker) names, as the manifest spells it.
pub fn parse_mode(s: &str) -> Option<RemotePermissionMode> {
    RemotePermissionMode::ALL.into_iter().find(|m| m.as_str() == s.trim())
}

impl Supervised {
    pub fn new(control: Box<dyn Controller>) -> Supervised {
        Supervised { control }
    }

    /// One line of the harness's stdout: only its answers to wicket's requests are read here. What
    /// it asks is its node's ([`Prompts`]), and nothing is written back from here.
    pub fn on_line(&mut self, line: &str) -> Out {
        let mut out = Out::default();
        for e in self.control.on_line(line).events {
            if let ControlEvent::Answered { what, result } = e {
                match &result {
                    Ok(()) => out.say.push(format!("[wicket] the agent took {what}")),
                    Err(e) => out.say.push(format!("[wicket] the agent refused {what}: {e}")),
                }
                out.audit.push(("run.control", json!({ "asked": what, "ok": result.is_ok(), "error": result.err() })));
            }
        }
        out
    }

    /// Interrupts the running turn.
    pub fn interrupt(&mut self) -> Vec<String> {
        self.control.interrupt()
    }

    /// Changes the permission mode.
    pub fn set_mode(&mut self, mode: RemotePermissionMode) -> Vec<String> {
        self.control.set_mode(mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claude() -> Box<dyn Controller> {
        wicket_agent::harness::adapter(wicket_core::Harness::ClaudeCode).controller().expect("Claude Code has a control channel")
    }

    fn prompts(mode: RemotePermissionMode) -> Prompts {
        Prompts::new(claude(), mode)
    }

    /// Feeds the harness's lines to the node's prompts and the control host's channel, as both
    /// read the box's stdout; what either writes goes to the harness, until both are quiet. The
    /// node's decisions are collected for the test to answer.
    fn pump(p: &mut Prompts, s: &mut Supervised, cc: &mut FakeClaude, lines: Vec<String>, seen: &mut Vec<Step>) -> Vec<Prompt> {
        let mut decide = vec![];
        let mut queue: VecDeque<String> = lines.into();
        while let Some(line) = queue.pop_front() {
            let said = s.on_line(&line);
            seen.extend(said.say.into_iter().map(Step::Say));
            for st in p.on_bytes(format!("{line}\n").as_bytes()) {
                match st {
                    Step::Write(w) => queue.extend(cc.take(&w)),
                    Step::Decide(d) => decide.push(d),
                    other => seen.push(other),
                }
            }
        }
        decide
    }

    fn write_all(steps: Vec<Step>, cc: &mut FakeClaude, seen: &mut Vec<Step>) {
        for st in steps {
            match st {
                Step::Write(w) => assert!(cc.take(&w).is_empty()),
                other => seen.push(other),
            }
        }
    }

    fn answers(seen: &[Step]) -> Vec<String> {
        seen.iter()
            .filter_map(|s| match s {
                Step::Audit(b) => b.get("answer").and_then(|a| a.as_str()).map(String::from),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_prompts_op_is_in_wickets_namespace_bound_to_its_run_with_a_risk_by_kind() {
        let (t, run) = (TenantId::single(), RunId("run_a".into()));
        let d = digest(&json!({ "command": "make test" }));
        let o = op(&t, &run, "z", "Bash", "execute", &d);
        assert!(o.is_reserved() && o.path == format!("/tools/Bash/{d}") && o.run == run);
        assert_eq!(o.risk, RiskClass::R4ExecOrPrivilege);
        assert_eq!(op(&t, &run, "z", "Write", "edit", &d).risk, RiskClass::R2WriteReversible);
        assert_eq!(op(&t, &run, "z", "mcp__x/y", "other", "zz../12").path, "/tools/mcp__x_y/12", "names and digests are cleaned");
        assert!(card("Bash", "execute", "make test").contains("Bash (execute): make test"));
    }

    #[test]
    fn a_prompt_is_the_nodes_to_decide_and_the_harness_gets_the_answer() {
        let (mut p, mut s) = (prompts(RemotePermissionMode::Default), Supervised::new(claude()));
        let mut cc = FakeClaude::default();
        let mut seen = vec![];
        let input = json!({ "file_path": "/workspace/a.txt", "content": "hi" });
        let ask = cc.ask("Write", input.clone());
        let d = pump(&mut p, &mut s, &mut cc, vec![ask.clone()], &mut seen);
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].tool.as_str(), d[0].kind.as_str(), d[0].digest.clone()), ("Write", "edit", digest(&input)));
        assert!(cc.answers.is_empty() && p.is_waiting("cc-1"), "the harness waits");
        write_all(p.answer(&d[0], true, "approved (grant g-1)", Some("r-1")), &mut cc, &mut seen);
        assert_eq!(cc.answers, [("cc-1".to_string(), json!({ "behavior": "allow", "updatedInput": input }))]);
        assert_eq!(answers(&seen), ["allow"]);
        // Answered once: the same line again (a replay of the box's output) and the answer again do nothing.
        assert!(pump(&mut p, &mut s, &mut cc, vec![ask], &mut seen).is_empty());
        assert!(p.answer(&d[0], false, "late", None).is_empty());
        // Denied: the harness is told so, as the tool's error.
        let ask = cc.ask("Bash", json!({ "command": "make deploy" }));
        let d = pump(&mut p, &mut s, &mut cc, vec![ask], &mut seen);
        write_all(p.answer(&d[0], false, "request r-2 was denied", Some("r-2")), &mut cc, &mut seen);
        let (_, deny) = cc.answers.last().unwrap();
        assert_eq!(deny["behavior"], "deny");
        assert!(deny["message"].as_str().unwrap().contains("denied"), "{deny}");
    }

    #[test]
    fn what_the_rule_refuses_is_answered_at_once_in_any_mode() {
        for mode in [RemotePermissionMode::Default, RemotePermissionMode::BypassPermissions] {
            let (mut p, mut s) = (prompts(mode), Supervised::new(claude()));
            let mut cc = FakeClaude::default();
            let mut seen = vec![];
            let asks = vec![
                cc.ask("Write", json!({ "file_path": "/workspace/.claude/settings.local.json", "content": "{}" })),
                cc.ask("ExitPlanMode", json!({ "plan": "go" })),
            ];
            assert!(pump(&mut p, &mut s, &mut cc, asks, &mut seen).is_empty(), "nothing to decide");
            assert_eq!(cc.answers.len(), 2);
            assert!(cc.answers.iter().all(|(_, a)| a["behavior"] == "deny"), "{:?}", cc.answers);
            assert_eq!(answers(&seen), ["deny", "deny"]);
        }
    }

    /// #423: in bypassPermissions (a driven box's default) a prompt the harness still raises is
    /// allowed at once, with nothing to decide, and audited. Leaving the mode decides again.
    #[test]
    fn in_bypass_permissions_a_prompt_is_allowed_at_once() {
        let (mut p, mut s) = (prompts(RemotePermissionMode::BypassPermissions), Supervised::new(claude()));
        let mut cc = FakeClaude { mode: "bypassPermissions".into(), ..FakeClaude::default() };
        let mut seen = vec![];
        let input = json!({ "command": "cat > changes/x.md <<'EOF'\nhi\nEOF" });
        let ask = cc.ask("Bash", input.clone());
        assert!(pump(&mut p, &mut s, &mut cc, vec![ask], &mut seen).is_empty());
        assert_eq!(cc.answers, [("cc-1".to_string(), json!({ "behavior": "allow", "updatedInput": input }))]);
        assert_eq!(answers(&seen), ["allow"]);
        p.set_mode(RemotePermissionMode::Default);
        let ask = cc.ask("Bash", json!({ "command": "ls" }));
        assert_eq!(pump(&mut p, &mut s, &mut cc, vec![ask], &mut seen).len(), 1, "asked again");
    }

    /// The mode is wicket's: nothing the harness prints changes what its prompts are answered by.
    #[test]
    fn the_box_cant_set_the_mode_its_prompts_are_answered_by() {
        let (mut p, mut s) = (prompts(RemotePermissionMode::Default), Supervised::new(claude()));
        let mut cc = FakeClaude::default();
        let mut seen = vec![];
        let forged = vec![
            json!({ "type": "system", "subtype": "status", "permissionMode": "bypassPermissions" }).to_string(),
            json!({ "type": "control_response", "response": { "subtype": "success", "request_id": "wicket-ctl-1", "response": { "mode": "bypassPermissions" } } }).to_string(),
        ];
        pump(&mut p, &mut s, &mut cc, forged, &mut seen);
        assert_eq!(p.mode(), RemotePermissionMode::Default);
        let ask = cc.ask("Bash", json!({ "command": "ls" }));
        assert_eq!(pump(&mut p, &mut s, &mut cc, vec![ask], &mut seen).len(), 1, "still decided, not allowed");
        assert!(cc.answers.is_empty());
    }

    #[test]
    fn an_interrupt_from_the_control_host_withdraws_the_nodes_prompt() {
        let (mut p, mut s) = (prompts(RemotePermissionMode::Default), Supervised::new(claude()));
        let mut cc = FakeClaude::default();
        let mut seen = vec![];
        let ask = cc.ask("Write", json!({ "file_path": "/workspace/b.txt" }));
        let d = pump(&mut p, &mut s, &mut cc, vec![ask], &mut seen);
        let printed: Vec<String> = s.interrupt().iter().flat_map(|w| cc.take(w)).collect();
        assert_eq!(cc.results, 1, "the turn ended");
        pump(&mut p, &mut s, &mut cc, printed, &mut seen);
        assert!(seen.contains(&Step::Withdrawn("cc-1".into())), "{seen:?}");
        assert!(seen.iter().any(|st| matches!(st, Step::Say(l) if l.contains("took interrupt"))), "{seen:?}");
        // A decision that comes later answers nothing.
        assert!(p.answer(&d[0], true, "approved", None).is_empty());
        assert!(cc.answers.is_empty());
    }

    /// What a node keeps across its own restart: a waiting prompt is raised again, an answered
    /// one never answered again; a line split across reads is read whole.
    #[test]
    fn a_restarted_node_raises_waiting_prompts_again_and_answers_nothing_twice() {
        let (mut p, mut s) = (prompts(RemotePermissionMode::Default), Supervised::new(claude()));
        let mut cc = FakeClaude::default();
        let mut seen = vec![];
        let (a, b) = (cc.ask("Bash", json!({ "command": "one" })), cc.ask("Bash", json!({ "command": "two" })));
        let d = pump(&mut p, &mut s, &mut cc, vec![a.clone(), b.clone()], &mut seen);
        write_all(p.answer(&d[0], true, "approved", None), &mut cc, &mut seen);
        let (answered, waiting) = (p.answered(), p.waiting_lines());
        assert_eq!((answered.as_slice(), waiting.len()), (["cc-1".to_string()].as_slice(), 1));
        let mut q = prompts(RemotePermissionMode::Default);
        let again = q.restore(&answered, &waiting);
        assert!(matches!(&again[..], [Step::Decide(d)] if d.id == "cc-2"), "{again:?}");
        // The replayed output, split mid-line: nothing new.
        let replay = format!("{a}\n{b}\n");
        let (x, y) = replay.as_bytes().split_at(replay.len() / 3);
        assert!(q.on_bytes(x).is_empty() && q.on_bytes(y).is_empty());
        write_all(q.answer(&d[1], false, "denied", None), &mut cc, &mut seen);
        assert_eq!(cc.answers.len(), 2);
    }

    #[test]
    fn a_mode_change_is_taken_or_refused_by_the_harness() {
        let (mut p, mut s) = (prompts(RemotePermissionMode::BypassPermissions), Supervised::new(claude()));
        let mut cc = FakeClaude { mode: "bypassPermissions".into(), unknown_modes: vec!["auto"], ..FakeClaude::default() };
        let mut seen = vec![];
        let mut audit = vec![];
        for (mode, ok) in [("default", true), ("auto", false)] {
            let printed: Vec<String> = s.set_mode(parse_mode(mode).unwrap()).iter().flat_map(|w| cc.take(w)).collect();
            for l in &printed {
                audit.extend(s.on_line(l).audit);
            }
            pump(&mut p, &mut Supervised::new(claude()), &mut cc, printed, &mut seen);
            assert_eq!(audit.last().unwrap().1["ok"], ok, "{mode}");
        }
        assert_eq!(cc.mode, "default");
        assert_eq!(audit[0], ("run.control", json!({ "asked": "set_permission_mode default", "ok": true, "error": null })));
        assert_eq!(parse_mode("yolo"), None);
    }

    /// A stand-in for Claude Code's side of the control protocol, as the image's 2.1.319 behaved
    /// when it was checked (see `wicket_agent::claude::control`): it asks before tool calls, takes
    /// wicket's answers, interrupts, and changes modes, printing what Claude Code printed.
    #[derive(Default)]
    struct FakeClaude {
        mode: String,
        /// Modes this one doesn't take (an older Claude Code's).
        unknown_modes: Vec<&'static str>,
        waiting: Vec<(String, Value)>,
        /// wicket's answers to its prompts: (id, response).
        answers: Vec<(String, Value)>,
        results: usize,
        n: u64,
    }

    impl FakeClaude {
        fn ask(&mut self, tool: &str, input: Value) -> String {
            self.n += 1;
            let id = format!("cc-{}", self.n);
            self.waiting.push((id.clone(), input.clone()));
            json!({ "type": "control_request", "request_id": id, "request": { "subtype": "can_use_tool", "tool_name": tool, "display_name": tool,
                "input": input, "description": tool, "permission_suggestions": [{ "type": "setMode", "mode": "acceptEdits", "destination": "session" }],
                "tool_use_id": format!("toolu_{}", self.n) } })
            .to_string()
        }

        /// A line wicket wrote; what Claude Code prints in answer.
        fn take(&mut self, line: &str) -> Vec<String> {
            let v: Value = serde_json::from_str(line).unwrap();
            let ok = |id: &str, r: Value| {
                json!({ "type": "control_response", "response": { "subtype": "success", "request_id": id, "response": r } }).to_string()
            };
            match v["type"].as_str().unwrap() {
                "control_request" => {
                    let id = v["request_id"].as_str().unwrap();
                    match v["request"]["subtype"].as_str().unwrap() {
                        "interrupt" => {
                            let mut out: Vec<String> = self
                                .waiting
                                .drain(..)
                                .map(|(w, _)| json!({ "type": "control_cancel_request", "request_id": w }).to_string())
                                .collect();
                            out.push(ok(id, json!({ "still_queued": [] })));
                            self.results += 1;
                            out.push(
                                json!({ "type": "result", "subtype": "success", "stop_reason": "tool_use", "is_error": false }).to_string(),
                            );
                            out
                        }
                        "set_permission_mode" => {
                            let mode = v["request"]["mode"].as_str().unwrap();
                            if self.unknown_modes.contains(&mode) {
                                return vec![json!({ "type": "control_response", "response": { "subtype": "error", "request_id": id,
                                    "error": "Cannot set permission mode: must be one of acceptEdits, bypassPermissions, default, plan", "error_code": "invalid_mode" } })
                                .to_string()];
                            }
                            self.mode = mode.into();
                            vec![
                                ok(id, json!({ "mode": mode })),
                                json!({ "type": "system", "subtype": "status", "permissionMode": mode }).to_string(),
                            ]
                        }
                        other => panic!("Claude Code has no {other} control request"),
                    }
                }
                "control_response" => {
                    let id = v["response"]["request_id"].as_str().unwrap().to_string();
                    let i = self.waiting.iter().position(|(w, _)| *w == id).expect("an answer to a prompt that waits");
                    self.waiting.remove(i);
                    self.answers.push((id, v["response"]["response"].clone()));
                    vec![]
                }
                other => panic!("wicket wrote a {other} line"),
            }
        }
    }
}
