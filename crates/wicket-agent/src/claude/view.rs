//! Claude Code's stream-json, as the Agent Client Protocol (#364): one event schema for the
//! console's session view, whichever harness a run has. wicket keeps the raw stream (the run's
//! transcript, and what wicket wrote to the agent in `acp-client.jsonl`), and this translates it
//! when it is read, so a better translation shows every run better, old ones included.
//!
//! What an ACP agent would have said, from what Claude Code said:
//! - an `assistant` message's blocks: `text` as `agent_message_chunk`, `thinking` as
//!   `agent_thought_chunk`, `tool_use` as a `tool_call` (its id, the tool's name and the input's gist
//!   as the title, the ACP kind wicket decides prompts by, the input as `rawInput`), and a
//!   `TodoWrite` call also as a `plan`;
//! - a `user` message's `tool_result` blocks: `tool_call_update`s, `completed` or `failed`, with the
//!   result's text;
//! - a `can_use_tool` control request: a `session/request_permission` for its tool call, so wicket's
//!   answer shows on it;
//! - a `result`: the end of the oldest prompt turn still running, as the answer to its
//!   `session/prompt` (`end_turn`, `max_turn_requests`, `cancelled` after an interrupt, or an
//!   error naming the result's subtype).
//!
//! And what wicket's client would have said, from what wicket wrote to Claude Code:
//! - a `user` turn: a `session/prompt` (with an id of the view's own, `wicket-turn-N`);
//! - its answer to a `can_use_tool`: the permission outcome (`allow` or `deny`);
//! - an `interrupt`: marks the running turn as cancelled.
//!
//! Everything else (system lines, partial messages, wicket's other control requests and the
//! answers to them) has no ACP counterpart here and is left out. All of it is the agent's data: the
//! session view filters it as it does an ACP agent's (`_meta` dropped, wicket's reserved ids refused).

use crate::harness::SessionView;
use serde_json::{json, Value};
use std::collections::VecDeque;

/// The name the run's `acp-client.jsonl` gives this translation.
pub const FORMAT: &str = "claude-stream-json";

/// The most text of one tool result shown (the rest is cut, saying so).
const MAX_RESULT: usize = 64 << 10;
/// Prompt turns remembered while running: more is a session wicket didn't drive this way.
const MAX_TURNS: usize = 256;

#[derive(Default)]
pub struct View {
    /// The `session/prompt` ids of turns still running, oldest first.
    turns: VecDeque<String>,
    next: u64,
    /// wicket asked for an interrupt since the last turn ended.
    interrupted: bool,
}

fn update(u: Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": "session/update", "params": { "sessionId": "", "update": u } })
}

fn text(t: &str) -> Value {
    json!({ "type": "text", "text": t })
}

/// The text of a message's content: a string, or the `text` of its text blocks.
fn text_of(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks.iter().filter_map(|b| b.get("text")?.as_str()).collect::<Vec<_>>().join("\n"),
        _ => String::new(),
    }
}

fn cut(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut at = max;
        while !s.is_char_boundary(at) {
            at -= 1;
        }
        let more = s.len() - at;
        s.truncate(at);
        s.push_str(&format!("\n… ({more} more bytes not shown)"));
    }
    s
}

/// A TodoWrite call's list as an ACP plan's entries.
fn plan(input: &Value) -> Option<Value> {
    let todos = input.get("todos")?.as_array()?;
    let entries: Vec<Value> = todos
        .iter()
        .map(|t| {
            let status = match t.get("status").and_then(|s| s.as_str()) {
                Some("in_progress") => "in_progress",
                Some("completed") => "completed",
                _ => "pending",
            };
            json!({ "content": t.get("content").and_then(|c| c.as_str()).unwrap_or(""), "priority": "medium", "status": status })
        })
        .collect();
    Some(update(json!({ "sessionUpdate": "plan", "entries": entries })))
}

impl View {
    fn assistant(&self, v: &Value, out: &mut Vec<Value>) {
        let Some(blocks) = v.pointer("/message/content").and_then(|c| c.as_array()) else { return };
        for b in blocks {
            match b.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    let t = b.get("text").and_then(|t| t.as_str()).unwrap_or("");
                    if !t.is_empty() {
                        out.push(update(json!({ "sessionUpdate": "agent_message_chunk", "content": text(t) })));
                    }
                }
                Some("thinking") => {
                    let t = b.get("thinking").and_then(|t| t.as_str()).unwrap_or("");
                    if !t.is_empty() {
                        out.push(update(json!({ "sessionUpdate": "agent_thought_chunk", "content": text(t) })));
                    }
                }
                Some("tool_use") => {
                    let Some(id) = b.get("id").and_then(|i| i.as_str()) else { continue };
                    let name = b.get("name").and_then(|n| n.as_str()).unwrap_or("tool");
                    let input = b.get("input").cloned().unwrap_or(Value::Null);
                    let gist = crate::summarise_input(&input);
                    let title = if input.is_null() { name.to_string() } else { format!("{name}: {}", crate::clip(&gist, 200)) };
                    out.push(update(json!({
                        "sessionUpdate": "tool_call", "toolCallId": id, "title": title,
                        "kind": super::control::kind_of(name), "status": "in_progress", "rawInput": input,
                    })));
                    if name == "TodoWrite" {
                        out.extend(plan(&input));
                    }
                }
                _ => {}
            }
        }
    }

    fn tool_results(&self, v: &Value, out: &mut Vec<Value>) {
        let Some(blocks) = v.pointer("/message/content").and_then(|c| c.as_array()) else { return };
        for b in blocks.iter().filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_result")) {
            let Some(id) = b.get("tool_use_id").and_then(|i| i.as_str()) else { continue };
            let failed = b.get("is_error").and_then(|e| e.as_bool()).unwrap_or(false);
            let body = cut(text_of(b.get("content").unwrap_or(&Value::Null)), MAX_RESULT);
            let content = if body.is_empty() { json!([]) } else { json!([{ "type": "content", "content": text(&body) }]) };
            out.push(update(json!({
                "sessionUpdate": "tool_call_update", "toolCallId": id,
                "status": if failed { "failed" } else { "completed" }, "content": content,
            })));
        }
    }

    fn result(&mut self, v: &Value, out: &mut Vec<Value>) {
        let interrupted = std::mem::take(&mut self.interrupted);
        let Some(id) = self.turns.pop_front() else { return };
        let sub = v.get("subtype").and_then(|s| s.as_str()).unwrap_or("");
        let failed = v.get("is_error").and_then(|e| e.as_bool()).unwrap_or(false);
        let stop = match sub {
            _ if interrupted => Some("cancelled"),
            "error_max_turns" => Some("max_turn_requests"),
            "success" if !failed => Some("end_turn"),
            _ => None,
        };
        out.push(match stop {
            Some(s) => json!({ "jsonrpc": "2.0", "id": id, "result": { "stopReason": s } }),
            None => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000,
                "message": format!("the turn ended with {}", crate::clip(if sub.is_empty() { "an error" } else { sub }, 60)) } }),
        });
    }
}

impl SessionView for View {
    fn agent(&mut self, line: &str) -> Vec<Value> {
        let Ok(v) = serde_json::from_str::<Value>(line) else { return vec![] };
        let mut out = vec![];
        match v.get("type").and_then(|t| t.as_str()) {
            Some("assistant") => self.assistant(&v, &mut out),
            Some("user") => self.tool_results(&v, &mut out),
            Some("result") => self.result(&v, &mut out),
            Some("control_request") if v.pointer("/request/subtype").and_then(|s| s.as_str()) == Some("can_use_tool") => {
                if let (Some(rid), Some(tc)) =
                    (v.get("request_id").and_then(|r| r.as_str()), v.pointer("/request/tool_use_id").and_then(|t| t.as_str()))
                {
                    out.push(json!({ "jsonrpc": "2.0", "id": rid, "method": "session/request_permission",
                                     "params": { "sessionId": "", "toolCall": { "toolCallId": tc } } }));
                }
            }
            _ => {}
        }
        out
    }

    fn wicket(&mut self, msg: &Value) -> Vec<Value> {
        match msg.get("type").and_then(|t| t.as_str()) {
            Some("user") => {
                let body = text_of(msg.pointer("/message/content").unwrap_or(&Value::Null));
                let id = format!("wicket-turn-{}", self.next);
                self.next += 1;
                if self.turns.len() >= MAX_TURNS {
                    self.turns.pop_front();
                }
                self.turns.push_back(id.clone());
                vec![json!({ "jsonrpc": "2.0", "id": id, "method": "session/prompt",
                             "params": { "sessionId": "", "prompt": [text(&body)] } })]
            }
            Some("control_request") => {
                if msg.pointer("/request/subtype").and_then(|s| s.as_str()) == Some("interrupt") && !self.turns.is_empty() {
                    self.interrupted = true;
                }
                vec![]
            }
            Some("control_response") => {
                let r = &msg["response"];
                let (Some(rid), Some(behavior)) =
                    (r.get("request_id").and_then(|i| i.as_str()), r.pointer("/response/behavior").and_then(|b| b.as_str()))
                else {
                    return vec![];
                };
                let option = if behavior == "allow" { "allow" } else { "deny" };
                vec![json!({ "jsonrpc": "2.0", "id": rid, "result": { "outcome": { "outcome": "selected", "optionId": option } } })]
            }
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(v: &[Value]) -> Vec<String> {
        v.iter()
            .map(|m| match m.pointer("/params/update/sessionUpdate").and_then(|k| k.as_str()) {
                Some(k) => k.to_string(),
                None => m.get("method").and_then(|x| x.as_str()).map(String::from).unwrap_or_else(|| "response".into()),
            })
            .collect()
    }

    #[test]
    fn a_turn_reads_as_an_acp_agent_would_say_it() {
        let mut v = View::default();
        let p = v.wicket(&serde_json::from_str(&crate::user_message("fix the build")).unwrap());
        assert_eq!(p[0]["method"], "session/prompt");
        assert_eq!(p[0]["params"]["prompt"][0]["text"], "fix the build");
        let id = p[0]["id"].clone();
        let lines = [
            r#"{"type":"system","subtype":"init","model":"m","tools":[]}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"hmm"},{"type":"text","text":"Looking."}]}}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"cargo build"}}]}}"#,
            r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"error[E0425]"}],"is_error":true}]}}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_2","name":"TodoWrite","input":{"todos":[{"content":"fix","status":"in_progress"},{"content":"test","status":"pending"}]}}]}}"#,
            r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_2","content":"ok"}]}}"#,
            r#"{"type":"result","subtype":"success","is_error":false,"num_turns":3}"#,
        ];
        let out: Vec<Value> = lines.iter().flat_map(|l| v.agent(l)).collect();
        assert_eq!(
            kinds(&out),
            [
                "agent_thought_chunk",
                "agent_message_chunk",
                "tool_call",
                "tool_call_update",
                "tool_call",
                "plan",
                "tool_call_update",
                "response"
            ]
        );
        assert_eq!(out[2]["params"]["update"]["kind"], "execute");
        assert_eq!(out[2]["params"]["update"]["title"], "Bash: cargo build");
        assert_eq!(out[2]["params"]["update"]["rawInput"]["command"], "cargo build");
        assert_eq!(out[3]["params"]["update"]["status"], "failed");
        assert_eq!(out[3]["params"]["update"]["content"][0]["content"]["text"], "error[E0425]");
        assert_eq!(out[5]["params"]["update"]["entries"][0]["status"], "in_progress");
        assert_eq!(out[6]["params"]["update"]["status"], "completed");
        assert_eq!(out[7], json!({ "jsonrpc": "2.0", "id": id, "result": { "stopReason": "end_turn" } }));
        assert!(v.agent(r#"{"type":"result","subtype":"success"}"#).is_empty(), "no turn running: nothing ends");
    }

    #[test]
    fn turns_end_in_order_and_say_how() {
        let mut v = View::default();
        let a = v.wicket(&serde_json::from_str(&crate::user_message("one")).unwrap())[0]["id"].clone();
        let b = v.wicket(&serde_json::from_str(&crate::user_message("two")).unwrap())[0]["id"].clone();
        let c = v.wicket(&serde_json::from_str(&crate::user_message("three")).unwrap())[0]["id"].clone();
        let r = v.agent(r#"{"type":"result","subtype":"error_max_turns","is_error":true}"#);
        assert_eq!((r[0]["id"].clone(), r[0]["result"]["stopReason"].clone()), (a, json!("max_turn_requests")));
        assert!(v.wicket(&json!({"type":"control_request","request_id":"wicket-ctl-1","request":{"subtype":"interrupt"}})).is_empty());
        let r = v.agent(r#"{"type":"result","subtype":"error_during_execution","is_error":true}"#);
        assert_eq!((r[0]["id"].clone(), r[0]["result"]["stopReason"].clone()), (b, json!("cancelled")));
        let r = v.agent(r#"{"type":"result","subtype":"error_during_execution","is_error":true}"#);
        assert_eq!(r[0]["id"], c);
        assert_eq!(r[0]["error"]["message"], "the turn ended with error_during_execution");
    }

    #[test]
    fn a_prompt_and_wickets_answer_are_a_permission_request_and_its_outcome() {
        let mut v = View::default();
        let ask = v.agent(
            r#"{"type":"control_request","request_id":"r-7","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"rm -rf /"},"tool_use_id":"toolu_9"}}"#,
        );
        assert_eq!(ask[0]["method"], "session/request_permission");
        assert_eq!((ask[0]["id"].clone(), ask[0]["params"]["toolCall"]["toolCallId"].clone()), (json!("r-7"), json!("toolu_9")));
        let ans = v.wicket(&json!({"type":"control_response","response":{"subtype":"success","request_id":"r-7","response":{"behavior":"deny","message":"no"}}}));
        assert_eq!(
            ans[0],
            json!({ "jsonrpc": "2.0", "id": "r-7", "result": { "outcome": { "outcome": "selected", "optionId": "deny" } } })
        );
        // Other control traffic has no counterpart.
        assert!(v
            .wicket(&json!({"type":"control_response","response":{"subtype":"success","request_id":"wicket-ctl-2","response":{}}}))
            .is_empty());
        assert!(v.agent(r#"{"type":"control_request","request_id":"x","request":{"subtype":"mcp_message"}}"#).is_empty());
        assert!(v.agent("not json").is_empty());
    }

    #[test]
    fn long_results_are_cut_on_a_character() {
        let s = cut("é".repeat(MAX_RESULT), MAX_RESULT);
        assert!(s.len() < MAX_RESULT + 64 && s.contains("more bytes not shown"));
    }
}
