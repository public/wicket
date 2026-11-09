//! Inner-agent adapters (design §6). The PoC drives Claude Code in print mode with stream-json
//! output. Everything configured here is advisory: the box boundary and the proxies enforce.
//! The launch carries placeholders and routes only, never a credential.

pub mod attribution;

use serde_json::Value;
use wicket_core::{Manifest, RunId};

/// Paths inside the box.
pub const SOCK_DIR: &str = "/wicket/sock";
pub const CA_DIR: &str = "/wicket/ca";
pub const STATE_DIR: &str = "/wicket/state";
pub const WORKSPACE: &str = "/workspace";
pub const OUTBOX: &str = "/workspace/out/result.json";

pub struct LaunchPlan {
    pub env: Vec<(String, String)>,
    pub argv: Vec<String>,
    /// The first message to write to the agent's stdin (stream-json input), if it takes its task
    /// that way. Follow-ups from the operator are written the same way while the session is open.
    pub stdin_task: Option<String>,
}

/// The run's CA bundle (system roots plus the run CA) inside the box, built by wicket-entry. Tools that
/// don't read SSL_CERT_FILE can be pointed at it through the manifest's env (e.g. CARGO_HTTP_CAINFO).
pub const CA_BUNDLE: &str = "/tmp/ca-bundle.pem";

/// One user turn in Claude Code's stream-json input format.
pub fn user_message(text: &str) -> String {
    serde_json::json!({ "type": "user", "message": { "role": "user", "content": [{ "type": "text", "text": text }] } }).to_string()
}

const NOTICE: &str = "You are running inside a wicket sandbox. Rules of this environment:\n\
- Your network access is mediated. Allowed requests succeed normally. A request outside your allowed reach returns HTTP 403 with a JSON body. If it is type .../pending-approval it includes a request_id: a human has been asked to approve it. Do not look for another route. Call the wicket MCP tool await_grant with that request_id (it waits for the decision), and retry the same request once it says granted. If the result is denied, or the 403 is type .../denied or .../forbidden, give up on that request and continue without it.\n\
- You have no credentials and need none: authentication for allowed services is added outside the sandbox. Do not ask for or look for tokens.\n\
- Work in /workspace. When you finish, write a short JSON summary to /workspace/out/result.json with fields: status (\"done\" or \"blocked\"), summary (string), and pending_requests (list of request ids you are still waiting on).";

/// Routes every program and agent shares: the egress proxy, the CA, and run identity.
fn common_env(m: &Manifest, run: &RunId) -> Vec<(String, String)> {
    [
        ("HTTPS_PROXY", "http://127.0.0.1:3128"),
        ("HTTP_PROXY", "http://127.0.0.1:3128"),
        ("https_proxy", "http://127.0.0.1:3128"),
        ("http_proxy", "http://127.0.0.1:3128"),
        ("NO_PROXY", "127.0.0.1,localhost"),
        ("no_proxy", "127.0.0.1,localhost"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .chain([
        ("HOME".to_string(), format!("{STATE_DIR}/home")),
        ("WICKET_RUN".to_string(), run.0.clone()),
        ("WICKET_TENANT".to_string(), m.tenant.0.clone()),
        ("WICKET_CA_BUNDLE".to_string(), CA_BUNDLE.to_string()),
    ])
    .collect()
}

/// A deterministic program: no model, no placeholder credential, just the command.
pub fn program_plan(m: &Manifest, run: &RunId) -> Option<LaunchPlan> {
    let p = m.program.as_ref()?;
    let mut argv = vec!["wicket-entry".to_string()];
    argv.extend(p.command.iter().cloned());
    Some(LaunchPlan { env: common_env(m, run), argv, stdin_task: None })
}

pub fn claude_code_plan(m: &Manifest, run: &RunId) -> LaunchPlan {
    let agent = m.agent.as_ref().expect("an agent manifest");
    let env = vec![
        ("ANTHROPIC_BASE_URL", "http://127.0.0.1:8080".to_string()),
        // A placeholder shaped like a subscription token: the LLM proxy strips it and injects the real
        // one. The box never holds a usable credential, and no API key is ever involved.
        ("CLAUDE_CODE_OAUTH_TOKEN", format!("sk-ant-oat01-wicket-placeholder-{}", run.0.replace('_', "-"))),
        ("HTTPS_PROXY", "http://127.0.0.1:3128".into()),
        ("HTTP_PROXY", "http://127.0.0.1:3128".into()),
        ("https_proxy", "http://127.0.0.1:3128".into()),
        ("http_proxy", "http://127.0.0.1:3128".into()),
        ("NO_PROXY", "127.0.0.1,localhost".into()),
        ("no_proxy", "127.0.0.1,localhost".into()),
        ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1".into()),
        ("DISABLE_AUTOUPDATER", "1".into()),
        ("DISABLE_TELEMETRY", "1".into()),
        ("DISABLE_ERROR_REPORTING", "1".into()),
        ("CLAUDE_CONFIG_DIR", format!("{STATE_DIR}/claude")),
        ("HOME", format!("{STATE_DIR}/home")),
        ("WICKET_RUN", run.0.clone()),
        // await_grant blocks until a human decides (up to 10 minutes).
        ("MCP_TOOL_TIMEOUT", "660000".into()),
        ("WICKET_TENANT", m.tenant.0.clone()),
        ("WICKET_CA_BUNDLE", CA_BUNDLE.into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    // The manifest's own non-secret variables (validated: none of wicket's reserved names).
    .chain(agent.env.iter().map(|(k, v)| (k.clone(), v.clone())))
    .collect();

    let mut argv = vec![
        "wicket-entry".to_string(),
        "claude".into(),
        "-p".into(),
        // The task arrives on stdin as the first user turn; follow-ups use the same channel.
        "--input-format".into(),
        "stream-json".into(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
        // Enforcement is outside the box, so the agent's own prompts would only stall it.
        "--permission-mode".into(),
        "bypassPermissions".into(),
        // Server-side search would bypass the egress proxy (the LLM proxy strips it too).
        "--disallowedTools".into(),
        // In-box subagents can't be told apart by identity; when the manifest says so, the only way
        // to start a subagent is wicket's spawn_agent (its own sandbox and identity).
        if m.agent.as_ref().map(|a| a.in_box_subagents).unwrap_or(true) { "WebSearch".into() } else { "WebSearch,Agent,Task".into() },
        "--append-system-prompt".into(),
        NOTICE.into(),
        // The only MCP server is wicket's gateway; repo-supplied MCP config is ignored.
        "--mcp-config".into(),
        r#"{"mcpServers":{"wicket":{"type":"http","url":"http://127.0.0.1:8081/mcp"}}}"#.into(),
        "--strict-mcp-config".into(),
    ];
    if let Some(model) = &agent.model {
        argv.push("--model".into());
        argv.push(model.clone());
    }
    if let Some(n) = agent.max_turns {
        argv.push("--max-turns".into());
        argv.push(n.to_string());
    }
    LaunchPlan { env, argv, stdin_task: Some(user_message(&m.task)) }
}

/// A one-line, human-readable rendering of a stream-json event, or None to skip it.
/// Free text from the agent is shown to the operator as data, never acted on.
pub fn render_event(line: &str) -> Option<String> {
    let v: Value = serde_json::from_str(line).ok()?;
    match v.get("type")?.as_str()? {
        "system" => {
            let sub = v.get("subtype").and_then(|s| s.as_str()).unwrap_or("");
            if sub == "init" {
                let model = v.get("model").and_then(|s| s.as_str()).unwrap_or("?");
                let tools = v.get("tools").and_then(|t| t.as_array()).map(|t| t.len()).unwrap_or(0);
                Some(format!("[agent] started: model {model}, {tools} tools"))
            } else {
                None
            }
        }
        "assistant" => {
            let content = v.pointer("/message/content")?.as_array()?;
            let mut out = Vec::new();
            for c in content {
                match c.get("type").and_then(|t| t.as_str()) {
                    Some("text") => {
                        let t = c.get("text").and_then(|t| t.as_str()).unwrap_or("").trim();
                        if !t.is_empty() {
                            out.push(format!("[agent] {}", clip(t, 400)));
                        }
                    }
                    Some("tool_use") => {
                        let name = c.get("name").and_then(|t| t.as_str()).unwrap_or("?");
                        let input = c.get("input").map(summarise_input).unwrap_or_default();
                        out.push(format!("[tool]  {name}: {}", clip(&input, 200)));
                    }
                    _ => {}
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out.join("\n"))
            }
        }
        "result" => {
            let sub = v.get("subtype").and_then(|s| s.as_str()).unwrap_or("?");
            let turns = v.get("num_turns").and_then(|n| n.as_u64()).unwrap_or(0);
            let cost = v.get("total_cost_usd").and_then(|n| n.as_f64()).unwrap_or(0.0);
            Some(format!("[agent] finished: {sub}, {turns} turns, ${cost:.4} (agent's estimate)"))
        }
        _ => None,
    }
}

pub(crate) fn summarise_input(v: &Value) -> String {
    for key in ["command", "file_path", "url", "pattern", "path", "description"] {
        if let Some(s) = v.get(key).and_then(|s| s.as_str()) {
            return s.to_string();
        }
    }
    v.to_string()
}

/// Clip and neutralise untrusted text for the operator's terminal: no control characters.
pub fn clip(s: &str, n: usize) -> String {
    let clean: String = s.chars().map(|c| if c.is_control() && c != '\n' { ' ' } else { c }).collect();
    let clean = clean.replace('\n', " ⏎ ");
    if clean.chars().count() > n {
        format!("{}…", clean.chars().take(n).collect::<String>())
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_has_no_real_credentials_and_routes_through_proxies() {
        let m = Manifest::from_yaml("task: hi\nagent: {name: a}\nzone: {name: z, llm: {}}").unwrap();
        let p = claude_code_plan(&m, &RunId("run_x".into()));
        let get = |k: &str| p.env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
        assert!(get("CLAUDE_CODE_OAUTH_TOKEN").unwrap().contains("placeholder"));
        assert!(get("ANTHROPIC_API_KEY").is_none(), "never an API key");
        assert_eq!(get("ANTHROPIC_BASE_URL").unwrap(), "http://127.0.0.1:8080");
        assert_eq!(get("HTTPS_PROXY").unwrap(), "http://127.0.0.1:3128");
        assert!(p.argv.contains(&"--disallowedTools".to_string()));
    }

    #[test]
    fn renders_and_neutralises_events() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"hello\u001b[31m"},{"type":"tool_use","name":"Bash","input":{"command":"ls -la"}}]}}"#;
        let r = render_event(line).unwrap();
        assert!(r.contains("[agent] hello"));
        assert!(!r.contains('\u{1b}'));
        assert!(r.contains("[tool]  Bash: ls -la"));
        assert!(render_event("not json").is_none());
    }
}
