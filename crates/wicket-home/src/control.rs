//! A driven harness's control channel, supervised (#363): interrupting its turn, changing its
//! permission mode while it runs, and its prompts before a tool call, as wicket approvals. The
//! harness's own protocol is its adapter's ([`wicket_agent::harness::Controller`]); this is what the
//! run's supervisor does with it, with no I/O of its own: [`Supervised`] takes the harness's lines
//! and the ledger, and returns what to write, say and audit.
//!
//! **Prompts.**
//! A harness in a mode that asks (Claude Code with `--permission-prompt-tool stdio`, see
//! `wicket_agent::claude::control`) asks its stdin host, the run's supervisor, before a tool call.
//! What wicket's rule refuses (a control file, a mode change, a question) the harness's controller
//! has already answered. Anything else is raised here as a request in wicket's own approval
//! namespace, decided like any other (`wicket approve`/`wicket deny`, the console, an operator whose
//! authority has the `tool` kind), and answered when it is:
//!
//! - the op is `TOOL wicket.internal /tools/<tool>/<digest of its input>`, bound to the run, so a
//!   retry of the same call is the same request, and a prefix approval (`/tools/Bash/`) lets that
//!   tool run for the grant's life without asking again;
//! - its risk is by the call's kind: a command R4, an edit R2, a read or fetch R1 (what leaves
//!   the box is still decided at the gates), anything else R3;
//! - a zone that may not ask (`escalation.request: false`) gets a refusal, as its other asks do; a
//!   call denied in the last few minutes is refused without asking again.
//!
//! The harness waits while a request is pending; an interrupt withdraws its prompt (the request
//! stays on the record, pending, and a later identical call finds it).

use serde_json::{json, Value};
use sha2::Digest;
use wicket_agent::harness::{ControlEvent, Controller};
use wicket_core::{Op, RemotePermissionMode, RiskClass, RunId, TenantId};
use wicket_store::Ledger;

/// The reserved method of a tool prompt's request.
pub const METHOD: &str = "TOOL";

/// What a tool call is, for its request.
pub struct Call<'a> {
    pub tool: &'a str,
    pub kind: &'a str,
    pub detail: &'a str,
    pub input: &'a Value,
}

/// The op a tool call's request is for.
pub fn op(tenant: &TenantId, run: &RunId, zone: &str, c: &Call) -> Op {
    let tool: String = c.tool.chars().map(|ch| if ch.is_ascii_alphanumeric() || "_-.".contains(ch) { ch } else { '_' }).take(80).collect();
    let digest = hex::encode(&sha2::Sha256::digest(c.input.to_string().as_bytes())[..8]);
    let mut op = Op::egress(tenant, run, zone, METHOD, wicket_core::link::DOMAIN, &format!("/tools/{tool}/{digest}"));
    op.risk = match c.kind {
        "execute" => RiskClass::R4ExecOrPrivilege,
        "edit" | "delete" | "move" => RiskClass::R2WriteReversible,
        "read" | "fetch" | "search" | "think" => RiskClass::R1ReadScoped,
        _ => RiskClass::R3ExternalOrIrreversible,
    };
    op
}

/// The request's card: what the human is shown. The tool's input is the agent's data.
fn card(c: &Call) -> String {
    format!(
        "the agent asks to use {} ({}): {}. Approving lets it make this call in its box; what leaves the box is still decided at wicket's gates.",
        wicket_agent::clip(c.tool, 120),
        c.kind,
        wicket_agent::clip(c.detail, 300)
    )
}

/// What became of a raised prompt.
#[derive(Debug, PartialEq)]
pub enum Raised {
    /// A request waits on a decision (`new`: just raised).
    Asked { request: String, new: bool },
    /// Answered now.
    Answer { allow: bool, why: String },
}

/// One prompt waiting on its request.
struct Ask {
    prompt: String,
    request: String,
    op: Op,
}

/// The run's prompts waiting on their requests.
#[derive(Default)]
pub struct Prompts {
    asks: Vec<Ask>,
}

/// A prompt's request was decided: answer it.
#[derive(Debug, PartialEq)]
pub struct Decided {
    pub prompt: String,
    pub request: String,
    pub allow: bool,
    pub why: String,
}

impl Prompts {
    /// Raises a prompt (`prompt` is the harness's id for it), or answers it at once.
    pub fn raise(&mut self, l: &mut Ledger, op: Op, may_ask: bool, prompt: &str, c: &Call) -> Result<Raised, String> {
        if let Some(g) = l.consume_grant(&op).map_err(|e| e.to_string())? {
            return Ok(Raised::Answer { allow: true, why: format!("approved (grant {g})") });
        }
        if !may_ask {
            return Ok(Raised::Answer {
                allow: false,
                why: "this zone may not ask for approval (escalation.request: false), and the call needs one".into(),
            });
        }
        if let Some(rid) = l.denied_recently(&op).map_err(|e| e.to_string())? {
            return Ok(Raised::Answer { allow: false, why: format!("exactly this call ({rid}) was denied a few minutes ago") });
        }
        let (request, new) = l.pending_for(&op, &card(c), None).map_err(|e| e.to_string())?;
        self.asks.push(Ask { prompt: prompt.into(), request: request.clone(), op });
        Ok(Raised::Asked { request, new })
    }

    /// The prompts whose requests were decided since the last poll.
    pub fn poll(&mut self, l: &mut Ledger) -> Vec<Decided> {
        let mut out = vec![];
        self.asks.retain(|a| {
            let decided = match l.consume_grant(&a.op) {
                Ok(Some(g)) => Some((true, format!("approved (grant {g})"))),
                _ => match l.request(&a.request).map(|r| r.status) {
                    Ok(s) if s == "pending" => None,
                    // Granted, but its grant is already used or gone: asked again.
                    Ok(s) if s == "granted" => {
                        Some((false, format!("request {} was approved, but its grant no longer covers this call", a.request)))
                    }
                    Ok(s) => Some((false, format!("request {} was {s}", a.request))),
                    Err(e) => Some((false, format!("request {}: {e}", a.request))),
                },
            };
            match decided {
                Some((allow, why)) => {
                    out.push(Decided { prompt: a.prompt.clone(), request: a.request.clone(), allow, why });
                    false
                }
                None => true,
            }
        });
        out
    }

    /// The harness stopped waiting on `prompt`: its request, if it had one.
    pub fn withdraw(&mut self, prompt: &str) -> Option<String> {
        let i = self.asks.iter().position(|a| a.prompt == prompt)?;
        Some(self.asks.remove(i).request)
    }

    pub fn is_empty(&self) -> bool {
        self.asks.is_empty()
    }
}

/// The run a [`Supervised`] channel belongs to.
pub struct RunOf {
    pub tenant: TenantId,
    pub run: RunId,
    pub zone: String,
    /// The zone's `escalation.request`.
    pub may_ask: bool,
}

/// What the supervisor does after a step: lines to write to the harness's stdin, lines to show
/// the operator, and audit records (kind, body).
#[derive(Debug, Default)]
pub struct Out {
    pub write: Vec<String>,
    pub say: Vec<String>,
    pub audit: Vec<(&'static str, Value)>,
}

/// A driven run's control channel and the prompts waiting on its requests.
pub struct Supervised {
    control: Box<dyn Controller>,
    prompts: Prompts,
    of: RunOf,
}

/// The mode a `wicket session` `/mode` (or any asker) names, as the manifest spells it.
pub fn parse_mode(s: &str) -> Option<RemotePermissionMode> {
    RemotePermissionMode::ALL.into_iter().find(|m| m.as_str() == s.trim())
}

impl Supervised {
    pub fn new(control: Box<dyn Controller>, of: RunOf) -> Supervised {
        Supervised { control, prompts: Prompts::default(), of }
    }

    /// One line of the harness's stdout.
    pub fn on_line(&mut self, l: &mut Ledger, line: &str) -> Out {
        let st = self.control.on_line(line);
        let mut out = Out { write: st.write, ..Out::default() };
        for e in st.events {
            match e {
                ControlEvent::Prompt { tool, kind, detail, refused: Some(why), .. } => {
                    out.say.push(format!("[wicket] refused the agent's {tool} ({kind}): {why}"));
                    out.audit
                        .push(("run.agent_prompt", json!({ "tool": tool, "kind": kind, "detail": detail, "answer": "deny", "why": why })));
                }
                ControlEvent::Prompt { id, tool, kind, detail, input, refused: None } => {
                    let c = Call { tool: &tool, kind: &kind, detail: &detail, input: &input };
                    let op = op(&self.of.tenant, &self.of.run, &self.of.zone, &c);
                    let (answer, why, request) = match self.prompts.raise(l, op, self.of.may_ask, &id, &c) {
                        Ok(Raised::Asked { request, new }) => {
                            let again = if new { "" } else { " (already pending)" };
                            out.say.push(format!(
                                "[wicket] the agent asks to use {tool} ({kind}): {}; request {request}{again}: `wicket approve {request}` or `wicket deny {request}`",
                                wicket_agent::clip(&detail, 200)
                            ));
                            ("asked", String::new(), Some(request))
                        }
                        Ok(Raised::Answer { allow, why }) => {
                            out.write.extend(self.control.answer(&id, allow, &why));
                            out.say
                                .push(format!("[wicket] {} the agent's {tool} ({kind}): {why}", if allow { "allowed" } else { "refused" }));
                            (if allow { "allow" } else { "deny" }, why, None)
                        }
                        Err(e) => {
                            let why = format!("wicket couldn't raise its approval: {e}");
                            out.write.extend(self.control.answer(&id, false, &why));
                            out.say.push(format!("[wicket] refused the agent's {tool}: {why}"));
                            ("deny", why, None)
                        }
                    };
                    out.audit.push((
                        "run.agent_prompt",
                        json!({ "tool": tool, "kind": kind, "detail": detail, "answer": answer, "why": why, "request": request }),
                    ));
                }
                ControlEvent::Withdrawn { id } => {
                    if let Some(request) = self.prompts.withdraw(&id) {
                        out.say.push(format!("[wicket] the agent stopped waiting on request {request} (its turn was interrupted)"));
                        out.audit.push(("run.agent_prompt", json!({ "answer": "withdrawn", "request": request })));
                    }
                }
                ControlEvent::Answered { what, result } => {
                    match &result {
                        Ok(()) => out.say.push(format!("[wicket] the agent took {what}")),
                        Err(e) => out.say.push(format!("[wicket] the agent refused {what}: {e}")),
                    }
                    out.audit.push(("run.control", json!({ "asked": what, "ok": result.is_ok(), "error": result.err() })));
                }
            }
        }
        out
    }

    /// Answers the prompts whose requests were decided.
    pub fn poll(&mut self, l: &mut Ledger) -> Out {
        let mut out = Out::default();
        if self.prompts.is_empty() {
            return out;
        }
        for d in self.prompts.poll(l) {
            out.write.extend(self.control.answer(&d.prompt, d.allow, &d.why));
            out.say.push(format!("[wicket] request {}: {}", d.request, d.why));
            out.audit.push((
                "run.agent_prompt",
                json!({ "answer": if d.allow { "allow" } else { "deny" }, "why": d.why, "request": d.request }),
            ));
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
    use std::time::Duration;

    fn approval(by: &str) -> wicket_store::Approval {
        wicket_store::Approval { uses: Some(1), ttl: Duration::from_secs(3600), path_prefix: None, decided_by: by.into() }
    }

    fn call(input: &Value) -> Call<'_> {
        Call { tool: "Bash", kind: "execute", detail: "make test", input }
    }

    #[test]
    fn a_prompt_is_a_request_in_wickets_namespace_answered_when_decided() {
        let mut l = Ledger::open_in_memory().unwrap();
        let (t, run) = (TenantId::single(), RunId("run_a".into()));
        let input = json!({ "command": "make test" });
        let op = op(&t, &run, "z", &call(&input));
        assert!(op.is_reserved() && op.path.starts_with("/tools/Bash/"));
        assert_eq!(op.risk, RiskClass::R4ExecOrPrivilege);
        let mut p = Prompts::default();
        let Raised::Asked { request, new: true } = p.raise(&mut l, op.clone(), true, "p1", &call(&input)).unwrap() else { panic!() };
        let r = l.request(&request).unwrap();
        assert_eq!((r.method.as_str(), r.host.as_str(), r.risk.as_str()), ("TOOL", "wicket.internal", "R4ExecOrPrivilege"));
        assert!(r.reason.contains("Bash") && r.reason.contains("make test"), "{}", r.reason);
        assert!(p.poll(&mut l).is_empty(), "pending: nothing to answer");
        l.approve(&request, &approval("alex")).unwrap();
        let d = p.poll(&mut l);
        assert_eq!(d.len(), 1);
        assert!(d[0].allow && d[0].prompt == "p1" && d[0].why.starts_with("approved"), "{d:?}");
        assert!(p.is_empty());
        // Its one use is spent: the same call again is asked again.
        assert!(matches!(p.raise(&mut l, op.clone(), true, "p2", &call(&input)).unwrap(), Raised::Asked { new: true, .. }));
        // A denial is answered as one, and the same call soon after is refused without asking.
        let rid = p.asks[0].request.clone();
        l.deny(&rid, "alex").unwrap();
        let d = p.poll(&mut l);
        assert!(!d[0].allow && d[0].why.contains("denied"), "{d:?}");
        match p.raise(&mut l, op, true, "p3", &call(&input)).unwrap() {
            Raised::Answer { allow: false, why } => assert!(why.contains("denied a few minutes ago"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_prefix_approval_lets_the_tool_run_and_a_zone_that_may_not_ask_is_refused() {
        let mut l = Ledger::open_in_memory().unwrap();
        let (t, run) = (TenantId::single(), RunId("run_a".into()));
        let first = json!({ "command": "ls" });
        let mut p = Prompts::default();
        let Raised::Asked { request, .. } = p.raise(&mut l, op(&t, &run, "z", &call(&first)), true, "p1", &call(&first)).unwrap() else {
            panic!()
        };
        let a = wicket_store::Approval { uses: None, path_prefix: Some("/tools/Bash/".into()), ..approval("alex") };
        l.approve(&request, &a).unwrap();
        assert!(p.poll(&mut l)[0].allow);
        let other = json!({ "command": "make" });
        assert!(matches!(
            p.raise(&mut l, op(&t, &run, "z", &call(&other)), true, "p2", &call(&other)).unwrap(),
            Raised::Answer { allow: true, .. }
        ));
        // Bound to its run.
        let elsewhere = op(&t, &RunId("run_b".into()), "z", &call(&other));
        match p.raise(&mut l, elsewhere, false, "p3", &call(&other)).unwrap() {
            Raised::Answer { allow: false, why } => assert!(why.contains("escalation.request: false"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_withdrawn_prompt_is_forgotten() {
        let mut l = Ledger::open_in_memory().unwrap();
        let input = json!({ "file_path": "/workspace/a" });
        let c = Call { tool: "Write", kind: "edit", detail: "/workspace/a", input: &input };
        let o = op(&TenantId::single(), &RunId("run_a".into()), "z", &c);
        assert_eq!(o.risk, RiskClass::R2WriteReversible);
        let mut p = Prompts::default();
        let Raised::Asked { request, .. } = p.raise(&mut l, o, true, "p1", &c).unwrap() else { panic!() };
        assert_eq!(p.withdraw("p1"), Some(request.clone()));
        assert_eq!(p.withdraw("p1"), None);
        l.approve(&request, &approval("alex")).unwrap();
        assert!(p.poll(&mut l).is_empty());
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

    /// Plays the line through: what the harness prints goes to wicket, what wicket writes to the
    /// harness, until both are quiet. What wicket said and audited, collected.
    fn pump(s: &mut Supervised, l: &mut Ledger, cc: &mut FakeClaude, lines: Vec<String>, seen: &mut Out) {
        let mut queue: std::collections::VecDeque<String> = lines.into();
        while let Some(line) = queue.pop_front() {
            let out = s.on_line(l, &line);
            for w in &out.write {
                queue.extend(cc.take(w));
            }
            seen.say.extend(out.say);
            seen.audit.extend(out.audit);
        }
    }

    fn supervised(may_ask: bool) -> (Supervised, Ledger) {
        let a = wicket_agent::harness::adapter(wicket_core::Harness::ClaudeCode);
        let m = wicket_agent::load("task: t\nagent: { name: a }\nzone: { name: z, llm: {} }\n").unwrap();
        let of = RunOf { tenant: TenantId::single(), run: RunId("run_a".into()), zone: "z".into(), may_ask };
        (Supervised::new(a.controller(&m).expect("Claude Code has a control channel"), of), Ledger::open_in_memory().unwrap())
    }

    fn kinds(o: &Out) -> Vec<String> {
        o.audit.iter().map(|(k, b)| format!("{k}:{}", b.get("answer").or(b.get("asked")).and_then(|a| a.as_str()).unwrap_or(""))).collect()
    }

    #[test]
    fn a_prompt_waits_on_its_request_and_the_harness_gets_the_decision() {
        let (mut s, mut l) = supervised(true);
        let mut cc = FakeClaude::default();
        let mut seen = Out::default();
        let input = json!({ "file_path": "/workspace/a.txt", "content": "hi" });
        let ask = cc.ask("Write", input.clone());
        pump(&mut s, &mut l, &mut cc, vec![ask], &mut seen);
        assert!(cc.answers.is_empty(), "the harness waits");
        let pending = l.pending(&TenantId::single()).unwrap();
        assert_eq!(pending.len(), 1);
        let rid = pending[0].id.clone();
        assert!(seen.say[0].contains(&format!("wicket approve {rid}")), "{:?}", seen.say);
        assert!(s.poll(&mut l).write.is_empty(), "undecided");
        l.approve(&rid, &approval("alex")).unwrap();
        let out = s.poll(&mut l);
        for w in &out.write {
            assert!(cc.take(w).is_empty());
        }
        assert_eq!(cc.answers, [("cc-1".to_string(), json!({ "behavior": "allow", "updatedInput": input }))]);
        assert_eq!(kinds(&seen), ["run.agent_prompt:asked"]);
        assert_eq!(kinds(&out), ["run.agent_prompt:allow"]);

        // Denied: the harness is told so, as the tool's error.
        let ask = cc.ask("Bash", json!({ "command": "make deploy" }));
        pump(&mut s, &mut l, &mut cc, vec![ask], &mut seen);
        let rid = l.pending(&TenantId::single()).unwrap()[0].id.clone();
        l.deny(&rid, "alex").unwrap();
        for w in s.poll(&mut l).write {
            cc.take(&w);
        }
        let (_, deny) = cc.answers.last().unwrap();
        assert_eq!(deny["behavior"], "deny");
        assert!(deny["message"].as_str().unwrap().contains("denied"), "{deny}");
    }

    #[test]
    fn what_the_rule_refuses_is_answered_at_once_and_nobody_is_asked() {
        let (mut s, mut l) = supervised(true);
        let mut cc = FakeClaude::default();
        let mut seen = Out::default();
        let asks = vec![
            cc.ask("Write", json!({ "file_path": "/workspace/.claude/settings.local.json", "content": "{}" })),
            cc.ask("ExitPlanMode", json!({ "plan": "go" })),
        ];
        pump(&mut s, &mut l, &mut cc, asks, &mut seen);
        assert_eq!(cc.answers.len(), 2);
        assert!(cc.answers.iter().all(|(_, a)| a["behavior"] == "deny"), "{:?}", cc.answers);
        assert!(l.pending(&TenantId::single()).unwrap().is_empty());
        assert_eq!(kinds(&seen), ["run.agent_prompt:deny", "run.agent_prompt:deny"]);
        // A zone that may not ask: refused too, without a request.
        let (mut s, mut l) = supervised(false);
        let ask = cc.ask("Bash", json!({ "command": "ls" }));
        pump(&mut s, &mut l, &mut cc, vec![ask], &mut seen);
        assert_eq!(cc.answers.last().unwrap().1["behavior"], "deny");
        assert!(l.pending(&TenantId::single()).unwrap().is_empty());
    }

    #[test]
    fn an_interrupt_ends_the_turn_and_withdraws_its_prompt() {
        let (mut s, mut l) = supervised(true);
        let mut cc = FakeClaude::default();
        let mut seen = Out::default();
        let ask = cc.ask("Write", json!({ "file_path": "/workspace/b.txt" }));
        pump(&mut s, &mut l, &mut cc, vec![ask], &mut seen);
        let mut printed = vec![];
        for w in s.interrupt() {
            printed.extend(cc.take(&w));
        }
        assert_eq!(cc.results, 1, "the turn ended");
        pump(&mut s, &mut l, &mut cc, printed, &mut seen);
        assert_eq!(kinds(&seen), ["run.agent_prompt:asked", "run.agent_prompt:withdrawn", "run.control:interrupt"]);
        assert_eq!(seen.audit[2].1["ok"], true);
        // Its request stays on the record; approving it later answers nothing.
        let rid = l.pending(&TenantId::single()).unwrap()[0].id.clone();
        l.approve(&rid, &approval("alex")).unwrap();
        assert!(s.poll(&mut l).write.is_empty());
        assert!(cc.answers.is_empty());
    }

    #[test]
    fn a_mode_change_is_taken_or_refused_by_the_harness() {
        let (mut s, mut l) = supervised(true);
        let mut cc = FakeClaude { mode: "bypassPermissions".into(), unknown_modes: vec!["auto"], ..FakeClaude::default() };
        let mut seen = Out::default();
        let printed = s.set_mode(parse_mode("default").unwrap()).iter().flat_map(|w| cc.take(w)).collect();
        pump(&mut s, &mut l, &mut cc, printed, &mut seen);
        assert_eq!(cc.mode, "default");
        assert_eq!(seen.audit[0], ("run.control", json!({ "asked": "set_permission_mode default", "ok": true, "error": null })));
        let printed = s.set_mode(parse_mode("auto").unwrap()).iter().flat_map(|w| cc.take(w)).collect();
        pump(&mut s, &mut l, &mut cc, printed, &mut seen);
        assert_eq!(cc.mode, "default");
        assert_eq!(seen.audit[1].1["ok"], false);
        assert!(seen.say[1].contains("refused set_permission_mode auto: Cannot set permission mode"), "{:?}", seen.say);
        assert_eq!(parse_mode("yolo"), None);
    }
}
