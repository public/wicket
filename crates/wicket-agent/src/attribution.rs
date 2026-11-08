//! Who inside the box asked (design §11, "Who a request is for").
//!
//! Claude Code runs its subagents inside the same process and box, so they share the box's sockets:
//! the socket a request arrives on identifies the run, not the subagent. What wicket can do is read
//! the agent's own event stream (stream-json on stdout, read outside the box) and match a blocked
//! request to the tool calls in flight at that moment. Subagent tool calls carry
//! `parent_tool_use_id`, which points at the `Agent` (formerly `Task`) call that started the
//! subagent, with its type and description.
//!
//! The result is *reported by the agent*, not proven: anything in the box could act during another
//! call, and a compromised agent can shape its own stream. It tells the human what the request is
//! for; it is not an authentication mechanism. Enforced per-agent identity needs a separate sandbox
//! (a wicket child or team member) with its own sockets.

use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

/// One tool call that could have made a request.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Requester {
    /// "main agent", or "subagent general-purpose: <description>".
    pub agent: String,
    pub tool: String,
    /// The call's main argument (command, URL, path), clipped. Untrusted text.
    pub call: String,
    pub tool_use_id: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Attribution {
    /// `matched`: exactly one in-flight call names this request (host or git operation);
    /// `only`: exactly one call was in flight; `ambiguous`: several candidates; `none`: no call in
    /// flight (a background process, or the agent runtime itself).
    pub basis: &'static str,
    pub requesters: Vec<Requester>,
}

impl Attribution {
    /// One line for terminals and logs.
    pub fn summary(&self) -> String {
        match self.basis {
            "none" => "unknown (no tool call in flight)".into(),
            "ambiguous" => format!(
                "one of: {}",
                self.requesters.iter().map(|r| format!("{} via {}", r.agent, r.tool)).collect::<Vec<_>>().join(" | ")
            ),
            _ => self.requesters.first().map(|r| format!("{} via {}: {}", r.agent, r.tool, crate::clip(&r.call, 80))).unwrap_or_default(),
        }
    }

    /// The distinct agents this attribution names.
    pub fn agents(&self) -> Vec<String> {
        let mut v: Vec<String> = self.requesters.iter().map(|r| r.agent.clone()).collect();
        v.dedup();
        v
    }
}

#[derive(Default, Debug)]
pub struct Tracker {
    /// `Agent`/`Task` tool_use id → the subagent's label.
    subagents: HashMap<String, String>,
    /// Calls that have started and not yet returned a result, in order.
    inflight: Vec<Requester>,
}

const SUBAGENT_TOOLS: [&str; 2] = ["Agent", "Task"];
const MAX_CANDIDATES: usize = 5;

impl Tracker {
    /// Feeds one stream-json line. Returns the label of the agent the line belongs to, if any
    /// (for terminal rendering).
    pub fn observe(&mut self, line: &str) -> Option<String> {
        let v: Value = serde_json::from_str(line).ok()?;
        let parent = v.get("parent_tool_use_id").and_then(|p| p.as_str()).map(String::from);
        let agent = match &parent {
            None => "main agent".to_string(),
            Some(p) => self.subagents.get(p).cloned().unwrap_or_else(|| "subagent (unknown)".into()),
        };
        let content = v.pointer("/message/content").and_then(|c| c.as_array());
        match v.get("type").and_then(|t| t.as_str()) {
            Some("assistant") => {
                for c in content.into_iter().flatten() {
                    if c.get("type").and_then(|t| t.as_str()) != Some("tool_use") {
                        continue;
                    }
                    let id = c.get("id").and_then(|s| s.as_str()).unwrap_or("").to_string();
                    let tool = c.get("name").and_then(|s| s.as_str()).unwrap_or("?").to_string();
                    let input = c.get("input").cloned().unwrap_or(Value::Null);
                    if SUBAGENT_TOOLS.contains(&tool.as_str()) {
                        let kind = input.get("subagent_type").and_then(|s| s.as_str()).unwrap_or("general-purpose");
                        let desc = input.get("description").and_then(|s| s.as_str()).unwrap_or("");
                        let label = if desc.is_empty() { format!("subagent {kind}") } else { format!("subagent {kind}: {}", crate::clip(desc, 60)) };
                        // A subagent started by a subagent: keep the chain visible.
                        let label = if parent.is_some() { format!("{label} (inside {agent})") } else { label };
                        self.subagents.insert(id, label);
                        continue; // the subagent's own calls are what make requests
                    }
                    let call = crate::clip(&crate::summarise_input(&input), 200);
                    self.inflight.push(Requester { agent: agent.clone(), tool, call, tool_use_id: id });
                }
            }
            Some("user") => {
                for c in content.into_iter().flatten() {
                    if c.get("type").and_then(|t| t.as_str()) == Some("tool_result") {
                        if let Some(id) = c.get("tool_use_id").and_then(|s| s.as_str()) {
                            self.inflight.retain(|r| r.tool_use_id != id);
                        }
                    }
                }
            }
            _ => {}
        }
        parent.map(|_| agent)
    }

    /// Who could have made a request to `host` + `path` right now.
    pub fn attribute(&self, host: &str, path: &str) -> Attribution {
        let mut hints = vec![host.to_ascii_lowercase()];
        if path.contains("git-receive-pack") {
            hints.push("git push".into());
        } else if path.contains("git-upload-pack") {
            hints.extend(["git fetch", "git clone", "git pull", "git ls-remote"].map(String::from));
        }
        let matched: Vec<Requester> = self
            .inflight
            .iter()
            .filter(|r| {
                let c = r.call.to_ascii_lowercase();
                hints.iter().any(|h| c.contains(h.as_str()))
            })
            .cloned()
            .collect();
        let (basis, requesters) = match (matched.len(), self.inflight.len()) {
            (1, _) => ("matched", matched),
            (n, _) if n > 1 => ("ambiguous", matched),
            (_, 0) => ("none", vec![]),
            (_, 1) => ("only", self.inflight.clone()),
            _ => ("ambiguous", self.inflight.clone()),
        };
        Attribution { basis, requesters: requesters.into_iter().take(MAX_CANDIDATES).collect() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assistant(parent: Option<&str>, id: &str, name: &str, input: Value) -> String {
        serde_json::json!({"type":"assistant","parent_tool_use_id":parent,
            "message":{"content":[{"type":"tool_use","id":id,"name":name,"input":input}]}}).to_string()
    }
    fn result(parent: Option<&str>, id: &str) -> String {
        serde_json::json!({"type":"user","parent_tool_use_id":parent,
            "message":{"content":[{"type":"tool_result","tool_use_id":id}]}}).to_string()
    }

    #[test]
    fn subagent_calls_are_attributed_to_the_subagent() {
        let mut t = Tracker::default();
        t.observe(&assistant(None, "A1", "Agent", serde_json::json!({"subagent_type":"general-purpose","description":"Push the fix"})));
        assert_eq!(t.attribute("github.com", "/x").basis, "none");
        let who = t.observe(&assistant(Some("A1"), "B1", "Bash", serde_json::json!({"command":"git push origin fix"})));
        assert_eq!(who.as_deref(), Some("subagent general-purpose: Push the fix"));
        let a = t.attribute("github.com", "/acme/api.git/git-receive-pack");
        assert_eq!(a.basis, "matched");
        assert_eq!(a.requesters[0].agent, "subagent general-purpose: Push the fix");
        assert_eq!(a.requesters[0].tool, "Bash");
        t.observe(&result(Some("A1"), "B1"));
        assert_eq!(t.attribute("github.com", "/x").basis, "none");
    }

    #[test]
    fn concurrent_calls_match_by_host_or_stay_ambiguous() {
        let mut t = Tracker::default();
        t.observe(&assistant(None, "A1", "Agent", serde_json::json!({"subagent_type":"researcher","description":"Read docs"})));
        t.observe(&assistant(None, "A2", "Agent", serde_json::json!({"subagent_type":"fixer","description":"Fetch deps"})));
        t.observe(&assistant(Some("A1"), "B1", "WebFetch", serde_json::json!({"url":"https://docs.rs/tokio"})));
        t.observe(&assistant(Some("A2"), "B2", "Bash", serde_json::json!({"command":"cargo fetch"})));
        let a = t.attribute("docs.rs", "/tokio");
        assert_eq!((a.basis, a.requesters[0].agent.as_str()), ("matched", "subagent researcher: Read docs"));
        let a = t.attribute("index.crates.io", "/config.json");
        assert_eq!(a.basis, "ambiguous");
        assert_eq!(a.agents().len(), 2);
        assert!(a.summary().starts_with("one of: "));
    }

    #[test]
    fn a_single_call_in_flight_is_the_only_candidate() {
        let mut t = Tracker::default();
        t.observe(&assistant(None, "B1", "Bash", serde_json::json!({"command":"npm install"})));
        let a = t.attribute("registry.npmjs.org", "/left-pad");
        assert_eq!((a.basis, a.requesters[0].agent.as_str()), ("only", "main agent"));
    }
}
