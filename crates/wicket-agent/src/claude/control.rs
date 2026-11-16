//! Claude Code's stream-json control protocol (#363), as wicket drives it: the control requests
//! wicket writes to a driven session's stdin, and the ones Claude Code writes to its stdout.
//!
//! Checked against the image's Claude Code (2.1.319), run with `--permission-prompt-tool stdio`:
//!
//! - `{"type":"control_request","request_id":…,"request":{"subtype":"interrupt"}}` ends the running
//!   turn (its `result` follows) and keeps the session open; the answer is a `control_response`
//!   with `subtype: success` and `{still_queued: […]}`. A prompt it was waiting on is withdrawn
//!   first, with a `control_cancel_request` naming it.
//! - `{"subtype":"set_permission_mode","mode":…}` changes the mode at once (a `system` `status`
//!   line carries the new `permissionMode`); a mode it doesn't take is answered `subtype: error`
//!   with `error_code: invalid_mode`.
//! - Before a tool call its mode doesn't allow, Claude Code asks with a control request of its own:
//!   `{"subtype":"can_use_tool","tool_name":…,"input":{…},"tool_use_id":…,"permission_suggestions":[…]}`,
//!   and waits. The answer is a `control_response` whose `response` is `{"behavior":"allow",
//!   "updatedInput":{…}}` or `{"behavior":"deny","message":…}` (the message is the tool's error
//!   result, which the model reads).
//!
//! wicket answers a prompt by the rule its ACP client uses ([`crate::acp::decide`]: the call's kind
//! and paths, never its title or command text): a write to a control file, a mode change, and a
//! question are refused at once; anything else is wicket's to decide, as an approval (the
//! supervisor raises it), and is answered when it is decided. wicket never takes a permission
//! suggestion: an "always" rule would be the agent's own policy.

use crate::harness::{ControlEvent, ControlStep, Controller};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wicket_core::RemotePermissionMode;

/// The prefix of wicket's own control request ids (besides [`crate::REMOTE_CONTROL_REQUEST_ID`]).
pub const ID_PREFIX: &str = "wicket-ctl-";

/// How many prompts may wait on wicket at once: one more is refused. Claude Code asks one at a time
/// per turn (parallel tool calls ask in turn), so this is only a bound on a misbehaving session.
pub const MAX_PROMPTS: usize = 32;
/// How many of wicket's requests may wait on an answer before the oldest is forgotten.
const MAX_SENT: usize = 64;

/// The ACP kind a Claude Code tool's call is, for [`crate::acp::decide`]. A tool wicket doesn't know
/// (an MCP tool, a new one) is `other`, whose paths are checked as an edit's.
pub fn kind_of(tool: &str) -> &'static str {
    match tool {
        "Read" | "Glob" | "Grep" | "LS" | "NotebookRead" => "read",
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => "edit",
        "Bash" | "BashOutput" | "KillShell" | "KillBash" => "execute",
        "WebFetch" | "WebSearch" => "fetch",
        "ExitPlanMode" | "EnterPlanMode" => "switch_mode",
        "TodoWrite" => "think",
        "AskUserQuestion" => "question",
        _ => "other",
    }
}

/// A short account of a tool call's input for a human deciding on it: the command, the path or
/// the URL when the tool has one, else the input as JSON. Clipped; it is the agent's data.
fn detail(input: &Value) -> String {
    for k in ["command", "file_path", "notebook_path", "path", "url", "pattern"] {
        if let Some(v) = input.get(k).and_then(|v| v.as_str()) {
            return crate::clip(v, 300);
        }
    }
    crate::clip(&input.to_string(), 300)
}

/// A driven Claude Code session's control channel.
#[derive(Debug, Default)]
pub struct Control {
    next: u64,
    /// wicket's requests waiting on an answer: id, what was asked.
    sent: BTreeMap<String, String>,
    /// Prompts waiting on wicket: id, the tool's input (sent back as it was, on an allow).
    asked: BTreeMap<String, Value>,
}

impl Control {
    fn request(&mut self, what: String, request: Value) -> String {
        self.next += 1;
        let id = format!("{ID_PREFIX}{}", self.next);
        if self.sent.len() >= MAX_SENT {
            self.sent.pop_first();
        }
        self.sent.insert(id.clone(), what);
        json!({ "type": "control_request", "request_id": id, "request": request }).to_string()
    }

    /// The prompts that wait on wicket.
    pub fn waiting(&self) -> impl Iterator<Item = &str> {
        self.asked.keys().map(String::as_str)
    }

    fn prompt(&mut self, id: &str, r: &Value, st: &mut ControlStep) {
        let tool = crate::clip(r.get("tool_name").and_then(|t| t.as_str()).unwrap_or(""), 120);
        let input = r.get("input").cloned().filter(|i| i.is_object()).unwrap_or_else(|| json!({}));
        let kind = kind_of(&tool);
        let refused = if kind == "question" {
            Some("nobody answers the agent's questions in a prompt here: ask in your reply instead".to_string())
        } else if self.asked.len() >= MAX_PROMPTS {
            Some(format!("{MAX_PROMPTS} prompts already wait on wicket"))
        } else {
            match crate::acp::decide(kind, &json!({ "rawInput": input })) {
                ("reject_once", why) => Some(why),
                _ => None,
            }
        };
        match &refused {
            Some(why) => st.write.push(deny(id, &format!("wicket refused this: {why}"))),
            None => {
                self.asked.insert(id.to_string(), input.clone());
            }
        }
        st.events.push(ControlEvent::Prompt { id: id.into(), tool, kind: kind.into(), detail: detail(&input), input, refused });
    }
}

/// wicket's answer to a prompt, as a `control_response`.
fn answer_line(id: &str, response: Value) -> String {
    json!({ "type": "control_response", "response": { "subtype": "success", "request_id": id, "response": response } }).to_string()
}

fn deny(id: &str, message: &str) -> String {
    answer_line(id, json!({ "behavior": "deny", "message": message }))
}

impl Controller for Control {
    fn on_line(&mut self, line: &str) -> ControlStep {
        let mut st = ControlStep::default();
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { return st };
        let id = v.get("request_id").and_then(|i| i.as_str()).unwrap_or("");
        match v.get("type").and_then(|t| t.as_str()) {
            Some("control_request") if !id.is_empty() => {
                let r = v.get("request").cloned().unwrap_or(Value::Null);
                match r.get("subtype").and_then(|s| s.as_str()) {
                    Some("can_use_tool") => self.prompt(id, &r, &mut st),
                    // wicket registered no hooks, MCP servers of its own or anything else that asks.
                    other => {
                        let what = crate::clip(other.unwrap_or("(none)"), 80);
                        st.write.push(
                            json!({ "type": "control_response", "response": { "subtype": "error", "request_id": id,
                                "error": format!("wicket answers no {what} control request") } })
                            .to_string(),
                        );
                    }
                }
            }
            Some("control_cancel_request") => {
                if self.asked.remove(id).is_some() {
                    st.events.push(ControlEvent::Withdrawn { id: id.into() });
                }
            }
            Some("control_response") => {
                let r = v.get("response").cloned().unwrap_or(Value::Null);
                let rid = r.get("request_id").and_then(|i| i.as_str()).unwrap_or("");
                if let Some(what) = self.sent.remove(rid) {
                    let result = match r.get("subtype").and_then(|s| s.as_str()) {
                        Some("success") => Ok(()),
                        _ => Err(crate::clip(r.get("error").and_then(|e| e.as_str()).unwrap_or("no reason given"), 300)),
                    };
                    st.events.push(ControlEvent::Answered { what, result });
                }
            }
            _ => {}
        }
        st
    }

    fn interrupt(&mut self) -> Vec<String> {
        vec![self.request("interrupt".into(), json!({ "subtype": "interrupt" }))]
    }

    fn set_mode(&mut self, mode: RemotePermissionMode) -> Vec<String> {
        vec![self.request(format!("set_permission_mode {mode}"), json!({ "subtype": "set_permission_mode", "mode": mode.as_str() }))]
    }

    fn answer(&mut self, id: &str, allow: bool, why: &str) -> Vec<String> {
        let Some(input) = self.asked.remove(id) else { return vec![] };
        vec![if allow {
            answer_line(id, json!({ "behavior": "allow", "updatedInput": input }))
        } else {
            deny(id, &format!("wicket refused this: {why}"))
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(l: &str) -> Value {
        serde_json::from_str(l).unwrap()
    }

    /// A `can_use_tool` request as Claude Code 2.1.319 writes it.
    fn can_use_tool(id: &str, tool: &str, input: Value) -> String {
        json!({ "type": "control_request", "request_id": id, "request": { "subtype": "can_use_tool", "tool_name": tool,
            "display_name": tool, "input": input, "description": "x",
            "permission_suggestions": [{ "type": "setMode", "mode": "acceptEdits", "destination": "session" }],
            "tool_use_id": "toolu_01" } })
        .to_string()
    }

    #[test]
    fn interrupt_and_set_mode_are_control_requests_with_their_own_ids() {
        let mut c = Control::default();
        let i = parse(&c.interrupt()[0]);
        assert_eq!(i["type"], "control_request");
        assert_eq!(i["request"], json!({ "subtype": "interrupt" }));
        let m = parse(&c.set_mode(RemotePermissionMode::AcceptEdits)[0]);
        assert_eq!(m["request"], json!({ "subtype": "set_permission_mode", "mode": "acceptEdits" }));
        assert_ne!(i["request_id"], m["request_id"]);
        assert!(i["request_id"].as_str().unwrap().starts_with(ID_PREFIX));
    }

    #[test]
    fn answers_to_wickets_requests_are_matched_by_id() {
        let mut c = Control::default();
        let i = parse(&c.interrupt()[0])["request_id"].as_str().unwrap().to_string();
        let m = parse(&c.set_mode(RemotePermissionMode::Plan)[0])["request_id"].as_str().unwrap().to_string();
        let ok = json!({ "type": "control_response", "response": { "subtype": "success", "request_id": i, "response": { "still_queued": [] } } });
        assert_eq!(c.on_line(&ok.to_string()).events, [ControlEvent::Answered { what: "interrupt".into(), result: Ok(()) }]);
        // Answered once: a repeat is nobody's.
        assert!(c.on_line(&ok.to_string()).events.is_empty());
        let bad = json!({ "type": "control_response", "response": { "subtype": "error", "request_id": m,
            "error": "Cannot set permission mode: must be one of acceptEdits, auto, bypassPermissions, default, dontAsk, plan", "error_code": "invalid_mode" } });
        match &c.on_line(&bad.to_string()).events[..] {
            [ControlEvent::Answered { what, result: Err(e) }] => {
                assert_eq!(what, "set_permission_mode plan");
                assert!(e.starts_with("Cannot set permission mode"));
            }
            other => panic!("{other:?}"),
        }
        // Remote Control's answer isn't this channel's.
        let rc = r#"{"type":"control_response","response":{"subtype":"success","request_id":"wicket-remote-control","response":{}}}"#;
        assert!(c.on_line(rc).events.is_empty());
    }

    #[test]
    fn a_prompt_inside_the_box_waits_on_wicket_and_is_answered_with_its_input() {
        let mut c = Control::default();
        let input = json!({ "file_path": "/workspace/a.txt", "content": "hi" });
        let st = c.on_line(&can_use_tool("p1", "Write", input.clone()));
        assert!(st.write.is_empty(), "nothing is answered until wicket decides");
        assert_eq!(
            st.events,
            [ControlEvent::Prompt {
                id: "p1".into(),
                tool: "Write".into(),
                kind: "edit".into(),
                detail: "/workspace/a.txt".into(),
                input: input.clone(),
                refused: None
            }]
        );
        assert_eq!(c.waiting().collect::<Vec<_>>(), ["p1"]);
        let a = parse(&c.answer("p1", true, "approved")[0]);
        assert_eq!(
            a,
            json!({ "type": "control_response", "response": { "subtype": "success", "request_id": "p1",
            "response": { "behavior": "allow", "updatedInput": input } } })
        );
        // Answered once.
        assert!(c.answer("p1", true, "again").is_empty());
        c.on_line(&can_use_tool("p2", "Bash", json!({ "command": "rm -rf /workspace/x" })));
        let d = parse(&c.answer("p2", false, "denied by alex")[0]);
        assert_eq!(d["response"]["response"], json!({ "behavior": "deny", "message": "wicket refused this: denied by alex" }));
    }

    #[test]
    fn a_write_to_a_control_file_a_mode_change_and_a_question_are_refused_at_once() {
        let mut c = Control::default();
        for (tool, input, why) in [
            ("Write", json!({ "file_path": "/workspace/.claude/settings.local.json", "content": "{}" }), "control file (.claude)"),
            ("Edit", json!({ "file_path": "/workspace/.git/hooks/pre-commit" }), "control file (.git/hooks)"),
            ("mcp__x__write", json!({ "path": "/workspace/.github/workflows/ci.yml" }), "control file (.github/workflows)"),
            ("ExitPlanMode", json!({ "plan": "do it" }), "a mode change is wicket's"),
            ("AskUserQuestion", json!({ "questions": [] }), "ask in your reply"),
        ] {
            let st = c.on_line(&can_use_tool("p", tool, input));
            match &st.events[..] {
                [ControlEvent::Prompt { refused: Some(w), .. }] => assert!(w.contains(why), "{tool}: {w}"),
                other => panic!("{tool}: {other:?}"),
            }
            let a = parse(&st.write[0]);
            assert_eq!(a["response"]["request_id"], "p");
            assert_eq!(a["response"]["response"]["behavior"], "deny", "{tool}");
            assert_eq!(c.waiting().count(), 0, "{tool}: nothing waits");
        }
        // A read of a control file is inside the box; and a command is never judged by its text.
        for (tool, input) in
            [("Read", json!({ "file_path": "/workspace/.claude/settings.json" })), ("Bash", json!({ "command": "cat .git/config" }))]
        {
            assert!(c.on_line(&can_use_tool("q", tool, input)).write.is_empty(), "{tool}");
            c.answer("q", false, "x");
        }
    }

    #[test]
    fn an_interrupted_prompt_is_withdrawn() {
        let mut c = Control::default();
        c.on_line(&can_use_tool("p1", "Write", json!({ "file_path": "/workspace/b.txt" })));
        let cancel = r#"{"type":"control_cancel_request","request_id":"p1"}"#;
        assert_eq!(c.on_line(cancel).events, [ControlEvent::Withdrawn { id: "p1".into() }]);
        assert!(c.answer("p1", true, "late").is_empty(), "a withdrawn prompt isn't answered");
        assert!(c.on_line(cancel).events.is_empty());
    }

    #[test]
    fn other_control_requests_are_answered_with_an_error() {
        let mut c = Control::default();
        let st = c.on_line(r#"{"type":"control_request","request_id":"h1","request":{"subtype":"hook_callback","callback_id":"x"}}"#);
        let a = parse(&st.write[0]);
        assert_eq!(a["response"]["subtype"], "error");
        assert_eq!(a["response"]["request_id"], "h1");
        assert!(st.events.is_empty());
        // Not a control line, or not JSON: nothing.
        assert_eq!(c.on_line(r#"{"type":"assistant"}"#), ControlStep::default());
        assert_eq!(c.on_line("not json"), ControlStep::default());
    }

    #[test]
    fn prompts_waiting_on_wicket_are_bounded() {
        let mut c = Control::default();
        for i in 0..MAX_PROMPTS {
            assert!(c.on_line(&can_use_tool(&format!("p{i}"), "Bash", json!({ "command": "true" }))).write.is_empty());
        }
        let st = c.on_line(&can_use_tool("over", "Bash", json!({ "command": "true" })));
        assert_eq!(parse(&st.write[0])["response"]["response"]["behavior"], "deny");
        assert_eq!(c.waiting().count(), MAX_PROMPTS);
    }
}
