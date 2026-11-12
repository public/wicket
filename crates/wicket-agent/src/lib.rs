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

/// wicket's services inside the box: their own name and address (set up by wicket-entry), so the
/// agent keeps all of localhost. 198.18.0.0/15 is reserved for benchmarking and never routed.
pub const WICKET_HOST: &str = "wicket.internal";
pub const WICKET_ADDR: &str = "198.18.0.1";
const PROXY_URL: &str = "http://wicket.internal:3128";
const LLM_URL: &str = "http://wicket.internal:8080";
const NO_PROXY: &str = "localhost,127.0.0.1,::1,wicket.internal";

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

/// What every agent under wicket is told about where it is. Shared by batch runs and wrapped sessions.
pub const SANDBOX_NOTICE: &str = "You are running inside a wicket sandbox: a gVisor container with no network interface of its own. Everything you send leaves through wicket's proxy, which decides what you may reach. Rules of this environment:\n\
- You hold no credentials and need none: authentication for allowed services is added outside the sandbox. Do not look for or ask for tokens.\n\
- A request outside what you may reach fails with HTTP 403 and a status line starting \"Blocked by wicket sandbox\", which says which case it is. \"never allowed\": it will never work from here, and nobody can approve it; do not retry. \"needs human approval\": the response has a request_id; call the wicket MCP tool await_grant with it to wait for the decision, then retry the same request once. \"denied by a human\": final for that request.\n\
- There is no other route out of the sandbox. Do not try other tools, other hosts, mirrors, caches or proxies to get the same thing; it wastes time and is logged.\n\
- If you need reach you don't have, ask once: call the wicket MCP tool request_access with the URL (scope \"prefix\" for everything under a path) and a one-sentence reason, then wait with await_grant. If it's denied or never allowed, stop and tell the user what you couldn't do.\n\
- Approvals happen only in wicket (its console or its operator), never in this conversation. If something is waiting for approval, tell the user and give the request id.";

const BATCH_NOTICE: &str = "- Work in /workspace. When you finish, write a short JSON summary to /workspace/out/result.json with fields: status (\"done\" or \"blocked\"), summary (string), and pending_requests (list of request ids you are still waiting on).";

/// wicket's MCP gateway as the agent's only MCP server; repo- or account-supplied servers are ignored.
const WICKET_MCP: &str = r#"{"mcpServers":{"wicket":{"type":"http","url":"http://wicket.internal:8081/mcp"}}}"#;

/// Routes every program and agent shares: the egress proxy, the CA, and run identity.
fn common_env(m: &Manifest, run: &RunId) -> Vec<(String, String)> {
    [
        ("HTTPS_PROXY", PROXY_URL),
        ("HTTP_PROXY", PROXY_URL),
        ("https_proxy", PROXY_URL),
        ("http_proxy", PROXY_URL),
        ("NO_PROXY", NO_PROXY),
        ("no_proxy", NO_PROXY),
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

/// A Claude Code command line that another program launched (e.g. Remote Control's session process,
/// through CLAUDE_CODE_PROCESS_WRAPPER), adapted to run in a box.
pub struct WrappedPlan {
    pub plan: LaunchPlan,
    /// Files to create under the box's state dir: (path relative to STATE_DIR, contents).
    pub files: Vec<(String, Vec<u8>)>,
    /// The real session credential the launcher passed, which the box sees only as `session_placeholder`.
    pub session_token: Option<String>,
    pub session_placeholder: String,
    /// Placeholders for the account login in the box's credentials file.
    pub login_placeholder: String,
}

/// Environment the wrapped agent may keep from its launcher: its own session settings. Everything
/// that names host resources (sockets, paths, the wrapper itself) or carries a credential is dropped
/// or replaced.
fn keep_launcher_var(k: &str) -> bool {
    let drop = [
        "CLAUDE_CODE_SESSION_ACCESS_TOKEN",
        "CLAUDE_CODE_MESSAGING_SOCKET",
        "CLAUDE_CODE_MESSAGING_TOKEN",
        "CLAUDE_CODE_PROCESS_WRAPPER",
        "CLAUDE_CODE_EXECPATH",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_PID",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    ];
    (k.starts_with("CLAUDE_") || k == "CLAUDECODE") && !drop.contains(&k)
}

/// Adapts a wrapped Claude Code command line: the box's own `claude`, its prompt file copied in, the
/// launcher's session settings kept, and every credential replaced by a placeholder that wicket's
/// egress proxy swaps back (design §14.1, `vendor_rc`). `login_meta` holds the non-secret fields of
/// the host's login (scopes, subscription type) so the placeholder login looks like the real one.
pub fn claude_code_wrapped_plan(
    m: &Manifest,
    run: &RunId,
    argv: &[String],
    launcher_env: &[(String, String)],
    login_meta: &Value,
) -> anyhow_free::Result<WrappedPlan> {
    let tag = run.0.replace('_', "-");
    let login_placeholder = format!("sk-ant-oat01-wicket-placeholder-{tag}");
    let session_token = launcher_env.iter().find(|(k, _)| k == "CLAUDE_CODE_SESSION_ACCESS_TOKEN").map(|(_, v)| v.clone());
    let session_placeholder = format!("wicket-session-placeholder-{tag}");
    let mut files = Vec::new();
    let mut out = vec!["wicket-entry".to_string(), "claude".to_string()];
    let mut it = argv.iter().skip(1).peekable(); // argv[0] is the launcher's own claude binary
    while let Some(a) = it.next() {
        let file_arg = |path: &str, files: &mut Vec<(String, Vec<u8>)>| -> anyhow_free::Result<String> {
            let mut body = std::fs::read(path).map_err(|e| anyhow_free::Error(format!("reading {path}: {e}")))?;
            // The launcher's system-prompt addition, followed by wicket's notice.
            body.extend_from_slice(format!("\n\n{SANDBOX_NOTICE}\n").as_bytes());
            let rel = format!("launcher/file{}", files.len());
            files.push((rel.clone(), body));
            Ok(format!("{STATE_DIR}/{rel}"))
        };
        if let Some(path) = a.strip_prefix("--append-system-prompt-file=") {
            out.push(format!("--append-system-prompt-file={}", file_arg(path, &mut files)?));
        } else if a == "--append-system-prompt-file" {
            let path = it.next().ok_or_else(|| anyhow_free::Error("--append-system-prompt-file without a path".into()))?;
            out.push(a.clone());
            out.push(file_arg(path, &mut files)?);
        } else if a == "--mcp-config" || a == "--strict-mcp-config" {
            // The launcher's MCP servers are replaced by wicket's gateway below.
            if a == "--mcp-config" {
                it.next();
            }
        } else if a.starts_with("--mcp-config=") {
        } else {
            out.push(a.clone());
        }
    }
    if !files.iter().any(|(rel, _)| rel.starts_with("launcher/")) {
        out.push("--append-system-prompt".into());
        out.push(SANDBOX_NOTICE.into());
    }
    // wicket's tools (await_grant, whoami, …) as the only MCP server: the account's connectors and any
    // project servers stay out of the box.
    out.extend(["--mcp-config".to_string(), WICKET_MCP.to_string(), "--strict-mcp-config".to_string()]);
    let far =
        (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0) + 365 * 86_400_000) as u64;
    let mut oauth = serde_json::json!({
        "accessToken": login_placeholder,
        "refreshToken": format!("sk-ant-ort01-wicket-placeholder-{tag}"),
        "expiresAt": far,
    });
    for k in ["scopes", "subscriptionType", "rateLimitTier"] {
        if let Some(v) = login_meta.get(k) {
            oauth[k] = v.clone();
        }
    }
    files.push((
        "claude/.credentials.json".into(),
        serde_json::to_vec_pretty(&serde_json::json!({ "claudeAiOauth": oauth })).unwrap_or_default(),
    ));
    let mut env: Vec<(String, String)> = launcher_env.iter().filter(|(k, _)| keep_launcher_var(k)).cloned().collect();
    if session_token.is_some() {
        env.push(("CLAUDE_CODE_SESSION_ACCESS_TOKEN".into(), session_placeholder.clone()));
    }
    for (k, v) in [
        ("HTTPS_PROXY", PROXY_URL),
        ("HTTP_PROXY", PROXY_URL),
        ("https_proxy", PROXY_URL),
        ("http_proxy", PROXY_URL),
        ("NO_PROXY", NO_PROXY),
        ("no_proxy", NO_PROXY),
        ("DISABLE_AUTOUPDATER", "1"),
        ("MCP_TOOL_TIMEOUT", "660000"),
        ("WICKET_CA_BUNDLE", CA_BUNDLE),
        // Remote Control needs Anthropic's API, but not telemetry or error reporting.
        ("DISABLE_TELEMETRY", "1"),
        ("DISABLE_ERROR_REPORTING", "1"),
    ] {
        env.push((k.into(), v.into()));
    }
    env.push(("CLAUDE_CONFIG_DIR".into(), format!("{STATE_DIR}/claude")));
    env.push(("HOME".into(), format!("{STATE_DIR}/home")));
    env.push(("WICKET_RUN".into(), run.0.clone()));
    env.push(("WICKET_TENANT".into(), m.tenant.0.clone()));
    env.extend(m.agent.as_ref().map(|a| a.env.clone()).unwrap_or_default());
    Ok(WrappedPlan { plan: LaunchPlan { env, argv: out, stdin_task: None }, files, session_token, session_placeholder, login_placeholder })
}

/// A tiny error type, so this crate stays free of anyhow.
pub mod anyhow_free {
    #[derive(Debug)]
    pub struct Error(pub String);
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Error {}
    pub type Result<T> = std::result::Result<T, Error>;
}

/// How long Claude Code keeps sessions (its `cleanupPeriodDays`). Claude Code deletes transcripts older
/// than this when it starts, which would erase a long-lived agent's own history on wake (#70), so
/// wicket sets it in every generated settings file and a manifest can't lower it.
pub const CLEANUP_PERIOD_DAYS: u32 = 36_500;

/// The settings.json wicket generates for a Claude Code agent: the manifest's allowlisted
/// `adapter_settings`, plus what wicket owns (applied last, so it always wins).
pub fn claude_settings(m: &Manifest) -> Value {
    let mut s = m.agent.as_ref().map(|a| a.adapter_settings.clone()).unwrap_or_default();
    s.insert("cleanupPeriodDays".into(), Value::from(CLEANUP_PERIOD_DAYS));
    Value::Object(s)
}

/// Which Claude Code session an activation runs (#70). The first activation of an agent starts the
/// session wicket chose; a wake resumes it, so the agent continues its own conversation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSession {
    /// A UUID, chosen by wicket.
    pub id: String,
    pub resume: bool,
}

impl AgentSession {
    /// A new session with a fresh random (v4) UUID.
    pub fn new() -> AgentSession {
        let mut b = [0u8; 16];
        getrandom::getrandom(&mut b).expect("random bytes");
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let h = hex::encode(b);
        AgentSession { id: format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]), resume: false }
    }

    /// Whether `s` is a session id wicket would choose (a lowercase hyphenated UUID).
    pub fn valid(s: &str) -> bool {
        s.len() == 36
            && s.char_indices()
                .all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() && !c.is_ascii_uppercase() })
    }
}

impl Default for AgentSession {
    fn default() -> Self {
        AgentSession::new()
    }
}

pub fn claude_code_plan(m: &Manifest, run: &RunId, session: &AgentSession) -> LaunchPlan {
    let agent = m.agent.as_ref().expect("an agent manifest");
    let env = vec![
        ("ANTHROPIC_BASE_URL", LLM_URL.to_string()),
        // A placeholder shaped like a subscription token: the LLM proxy strips it and injects the real
        // one. The box never holds a usable credential, and no API key is ever involved.
        ("CLAUDE_CODE_OAUTH_TOKEN", format!("sk-ant-oat01-wicket-placeholder-{}", run.0.replace('_', "-"))),
        ("HTTPS_PROXY", PROXY_URL.into()),
        ("HTTP_PROXY", PROXY_URL.into()),
        ("https_proxy", PROXY_URL.into()),
        ("http_proxy", PROXY_URL.into()),
        ("NO_PROXY", NO_PROXY.into()),
        ("no_proxy", NO_PROXY.into()),
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
        format!("{SANDBOX_NOTICE}\n{BATCH_NOTICE}"),
        // The only MCP server is wicket's gateway; repo-supplied MCP config is ignored.
        "--mcp-config".into(),
        WICKET_MCP.into(),
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
    argv.push(if session.resume { "--resume" } else { "--session-id" }.into());
    argv.push(session.id.clone());
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

/// Clip and neutralise untrusted text for the operator's terminal (`wicket_core::text::clip`): no
/// control, bidi or zero-width characters.
pub fn clip(s: &str, n: usize) -> String {
    wicket_core::text::clip(s, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrapped_session_gets_placeholders_and_keeps_its_own_settings() {
        let m = Manifest::from_yaml("task: hi\nagent: {name: a}\nzone: {name: z, llm: {}}").unwrap();
        let dir = std::env::temp_dir().join(format!("wicket-wrap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prompt = dir.join("p.txt");
        std::fs::write(&prompt, "be nice").unwrap();
        let argv: Vec<String> = [
            "/host/claude",
            "--print",
            "--sdk-url",
            "https://api.anthropic.com/v1/code/sessions/x",
            "--append-system-prompt-file",
            prompt.to_str().unwrap(),
            "--model",
            "m",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let env: Vec<(String, String)> = [
            ("CLAUDE_CODE_SESSION_ACCESS_TOKEN", "REAL-SESSION"),
            ("CLAUDE_CODE_MESSAGING_SOCKET", "/tmp/s"),
            ("CLAUDE_CODE_MESSAGING_TOKEN", "REAL-MSG"),
            ("CLAUDE_CODE_ENVIRONMENT_KIND", "bridge"),
            ("CLAUDE_CODE_OAUTH_TOKEN", "REAL-OAUTH"),
            ("PATH", "/usr/bin"),
            ("SECRET_THING", "x"),
        ]
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect();
        let w = claude_code_wrapped_plan(
            &m,
            &RunId("run_x".into()),
            &argv,
            &env,
            &serde_json::json!({"scopes": ["user:inference"], "subscriptionType": "max", "refreshToken": "REAL-R"}),
        )
        .unwrap();
        let all = format!(
            "{:?} {:?} {:?}",
            w.plan.env,
            w.plan.argv,
            w.files.iter().map(|(p, b)| (p.clone(), String::from_utf8_lossy(b).to_string())).collect::<Vec<_>>()
        );
        for real in ["REAL-SESSION", "REAL-MSG", "REAL-OAUTH", "REAL-R", "/tmp/s", "SECRET_THING", "/host/claude"] {
            assert!(!all.contains(real), "{real} must not reach the box");
        }
        assert_eq!(w.session_token.as_deref(), Some("REAL-SESSION"));
        assert!(all.contains(&w.session_placeholder) && all.contains(&w.login_placeholder));
        assert!(all.contains("CLAUDE_CODE_ENVIRONMENT_KIND") && all.contains("user:inference"));
        assert!(w.plan.argv.contains(&format!("{STATE_DIR}/launcher/file0")));
        assert!(String::from_utf8_lossy(&w.files[0].1).starts_with("be nice") && String::from_utf8_lossy(&w.files[0].1).contains("gVisor"));
        assert!(w.plan.argv.windows(2).any(|p| p[0] == "--mcp-config" && p[1].contains("wicket.internal:8081")));
        assert!(w.plan.argv.contains(&"--strict-mcp-config".to_string()));
        assert_eq!(&w.plan.argv[..2], &["wicket-entry".to_string(), "claude".to_string()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn plan_has_no_real_credentials_and_routes_through_proxies() {
        let m = Manifest::from_yaml("task: hi\nagent: {name: a}\nzone: {name: z, llm: {}}").unwrap();
        let s = AgentSession::new();
        assert!(AgentSession::valid(&s.id), "{}", s.id);
        assert!(!AgentSession::valid("../../etc") && !AgentSession::valid(&s.id.to_uppercase()));
        let p = claude_code_plan(&m, &RunId("run_x".into()), &s);
        let at = p.argv.iter().position(|a| a == "--session-id").expect("a chosen session id");
        assert_eq!(p.argv[at + 1], s.id);
        let r = claude_code_plan(&m, &RunId("run_y".into()), &AgentSession { resume: true, ..s.clone() });
        assert!(r.argv.windows(2).any(|w| w[0] == "--resume" && w[1] == s.id) && !r.argv.contains(&"--session-id".to_string()));
        let set = claude_settings(
            &Manifest::from_yaml("task: hi\nagent: {name: a, adapter_settings: {language: fr}}\nzone: {name: z, llm: {}}").unwrap(),
        );
        assert_eq!(set["cleanupPeriodDays"], CLEANUP_PERIOD_DAYS);
        assert_eq!(set["language"], "fr");
        let get = |k: &str| p.env.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
        assert!(get("CLAUDE_CODE_OAUTH_TOKEN").unwrap().contains("placeholder"));
        assert!(get("ANTHROPIC_API_KEY").is_none(), "never an API key");
        assert_eq!(get("ANTHROPIC_BASE_URL").unwrap(), "http://wicket.internal:8080");
        assert_eq!(get("HTTPS_PROXY").unwrap(), "http://wicket.internal:3128");
        assert!(get("NO_PROXY").unwrap().contains("localhost"), "the agent's own localhost stays local");
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
