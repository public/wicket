//! Inner-agent adapters (design §6). The PoC drives Claude Code in print mode with stream-json
//! output. Everything configured here is advisory: the box boundary and the proxies enforce.
//! The launch carries placeholders and routes only, never a credential.

pub mod acp;
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
    /// An ACP agent (#66): wicket speaks the protocol on its stdio, starting with this.
    pub acp: Option<acp::AcpConfig>,
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
    Some(LaunchPlan { env: common_env(m, run), argv, stdin_task: None, acp: None })
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
    files.push(placeholder_login(&login_placeholder, &tag, login_meta));
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
    Ok(WrappedPlan {
        plan: LaunchPlan { env, argv: out, stdin_task: None, acp: None },
        files,
        session_token,
        session_placeholder,
        login_placeholder,
    })
}

/// The box's `.credentials.json`: the account login as placeholders (`login_placeholder`, which
/// wicket's egress proxy swaps for the real access token toward `api.anthropic.com`, and a
/// refresh token that refreshes nothing), expiring far ahead so Claude Code never tries to refresh
/// it, with the real login's non-secret fields (`login_meta`: scopes, subscription type).
fn placeholder_login(login_placeholder: &str, tag: &str, login_meta: &Value) -> (String, Vec<u8>) {
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
    ("claude/.credentials.json".into(), serde_json::to_vec_pretty(&serde_json::json!({ "claudeAiOauth": oauth })).unwrap_or_default())
}

/// What a remote session's adapter may know of the login, from the host (never a credential):
/// `linked` is the object holding the linked token in its file, `file` that file. For claude-code:
/// the login's scopes and plan, and its account (`oauthAccount`).
pub fn remote_login_meta(m: &Manifest, linked: Option<&Value>, file: Option<&std::path::Path>) -> Value {
    match m.agent.as_ref().map(|a| a.kind.as_str()) {
        Some("claude-code") => {
            let mut meta = serde_json::json!({});
            if let Some(o) = linked {
                for k in ["scopes", "subscriptionType", "rateLimitTier"] {
                    if let Some(v) = o.get(k) {
                        meta[k] = v.clone();
                    }
                }
            }
            if let Some(a) = file.and_then(claude_code_account) {
                meta["oauthAccount"] = a;
            }
            meta
        }
        _ => Value::Null,
    }
}

/// The claude.ai account a Claude Code login belongs to (its config's `oauthAccount`: account and
/// organization ids, plan, roles; no credential), next to the login's credentials file: Remote
/// Control won't start without it. `~/.claude/.credentials.json` has it in `~/.claude.json`; a
/// `CLAUDE_CONFIG_DIR` keeps both in one directory. The holder's full name is left out.
pub fn claude_code_account(credentials: &std::path::Path) -> Option<Value> {
    let dir = credentials.parent()?;
    let mut candidates = vec![dir.join(".claude.json")];
    if dir.file_name().is_some_and(|n| n == ".claude") {
        candidates.insert(0, dir.parent()?.join(".claude.json"));
    }
    for c in candidates {
        let Some(v) = std::fs::read(&c).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { continue };
        if let Some(Value::Object(mut a)) = v.get("oauthAccount").cloned() {
            a.remove("fullName");
            return Some(Value::Object(a));
        }
    }
    None
}

/// The account login's placeholder for a run (what the box's credentials file holds).
pub fn login_placeholder(run: &RunId) -> String {
    format!("sk-ant-oat01-wicket-placeholder-{}", run.0.replace('_', "-"))
}

/// What a Remote Control agent is told, besides the sandbox notice: its messages come from the app.
const RC_NOTICE: &str = "- You are a Remote Control session: the user talks to you from the Claude app. Work in /workspace.";

/// The adapter's plan for a remote session (`agent.remote`, #169): which harnesses have one. Each
/// harness adapter that adds the feature adds its arm; the others refuse, saying so.
pub fn remote_plan(m: &Manifest, run: &RunId, login_meta: &Value) -> anyhow_free::Result<WrappedPlan> {
    match m.agent.as_ref().map(|a| a.kind.as_str()) {
        Some("claude-code") => claude_code_remote_control_plan(m, run, login_meta),
        Some(k) => Err(anyhow_free::Error(format!("agent.remote: the {k} adapter has no remote sessions"))),
        None => Err(anyhow_free::Error("agent.remote applies to agents only".into())),
    }
}

/// The address of the remote session a harness's server printed on this line of its output, if
/// any: where the owner opens it (for claude-code, a claude.ai/code link).
pub fn remote_session_url(m: &Manifest, line: &str) -> Option<String> {
    let prefix = match m.agent.as_ref()?.kind.as_str() {
        "claude-code" => "https://claude.ai/code",
        _ => return None,
    };
    let start = line.find(prefix)?;
    let url: String = line[start..].chars().take_while(|c| !c.is_whitespace() && !"\"'<>)]".contains(*c)).collect();
    Some(url)
}

/// A Remote Control agent (#169): Claude Code booted in the box as `claude remote-control`, so the
/// box registers its own session in the owner's Claude apps. The account login is a placeholder
/// (swapped by the egress proxy toward `api.anthropic.com`, refreshed only on the host); wicket's
/// gateway is the only MCP server, the sandbox notice is the user memory, and `/workspace` is
/// trusted, so nothing waits on a terminal that isn't there.
pub fn claude_code_remote_control_plan(m: &Manifest, run: &RunId, login_meta: &Value) -> anyhow_free::Result<WrappedPlan> {
    let agent = m.agent.as_ref().ok_or_else(|| anyhow_free::Error("not an agent manifest".into()))?;
    let rc = agent.remote.as_ref().ok_or_else(|| anyhow_free::Error("no agent.remote".into()))?;
    let tag = run.0.replace('_', "-");
    let login_placeholder = login_placeholder(run);
    let mut files = vec![placeholder_login(&login_placeholder, &tag, login_meta)];
    let mcp: Value = serde_json::from_str(WICKET_MCP).unwrap_or_default();
    let mut config = serde_json::json!({
        "hasCompletedOnboarding": true,
        // The owner chose Remote Control by asking for a remote session: no one-time prompt, which
        // a box without a terminal can't answer.
        "remoteDialogSeen": true,
        "projects": { WORKSPACE: { "hasTrustDialogAccepted": true, "hasCompletedProjectOnboarding": true } },
        "mcpServers": mcp["mcpServers"],
    });
    if let Some(a) = login_meta.get("oauthAccount").filter(|a| a.is_object()) {
        config["oauthAccount"] = a.clone();
    }
    files.push(("claude/.claude.json".into(), serde_json::to_vec_pretty(&config).unwrap_or_default()));
    files.push(("claude/CLAUDE.md".into(), format!("{SANDBOX_NOTICE}\n{RC_NOTICE}\n").into_bytes()));
    let argv = [
        "wicket-entry",
        "claude",
        "remote-control",
        "--name",
        rc.name.as_str(),
        // One session per box: the box ends with it.
        "--spawn",
        "session",
        // Claude Code asks in the app before it acts, as a session on the owner's own machine would;
        // wicket's proxies decide what the box can reach either way.
        "--permission-mode",
        "default",
    ]
    .map(String::from)
    .to_vec();
    let mut env: Vec<(String, String)> = [
        ("HTTPS_PROXY", PROXY_URL),
        ("HTTP_PROXY", PROXY_URL),
        ("https_proxy", PROXY_URL),
        ("http_proxy", PROXY_URL),
        ("NO_PROXY", NO_PROXY),
        ("no_proxy", NO_PROXY),
        ("DISABLE_AUTOUPDATER", "1"),
        ("MCP_TOOL_TIMEOUT", "660000"),
        ("WICKET_CA_BUNDLE", CA_BUNDLE),
        ("DISABLE_TELEMETRY", "1"),
        ("DISABLE_ERROR_REPORTING", "1"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    env.push(("CLAUDE_CONFIG_DIR".into(), format!("{STATE_DIR}/claude")));
    env.push(("HOME".into(), format!("{STATE_DIR}/home")));
    env.push(("WICKET_RUN".into(), run.0.clone()));
    env.push(("WICKET_TENANT".into(), m.tenant.0.clone()));
    env.extend(agent.env.clone());
    Ok(WrappedPlan {
        plan: LaunchPlan { env, argv, stdin_task: None, acp: None },
        files,
        session_token: None,
        session_placeholder: String::new(),
        login_placeholder,
    })
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

/// Claude Code's environment in a box: routes and placeholders only, whichever way it is driven.
fn claude_env(m: &Manifest, run: &RunId) -> Vec<(String, String)> {
    let agent = m.agent.as_ref().expect("an agent manifest");
    vec![
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
    .collect()
}

/// Whether wicket writes Claude Code's settings.json for this agent (allowlisted adapter settings
/// plus the keys wicket owns): Claude Code, driven directly or through its ACP adapter.
pub fn uses_claude_settings(m: &Manifest) -> bool {
    m.agent
        .as_ref()
        .is_some_and(|a| a.kind == "claude-code" || a.acp.as_ref().and_then(|p| p.profile.as_deref()) == Some("claude-agent-acp"))
}

/// An ACP agent (#66): its command in the box, and how wicket opens its session. The task becomes
/// the first prompt once the session is open. A generic agent gets the shared routes only; a known
/// profile also gets what wicket sets for that adapter, and its `_meta` is wicket's, never the
/// manifest's.
pub fn acp_plan(m: &Manifest, run: &RunId) -> Option<LaunchPlan> {
    let agent = m.agent.as_ref().filter(|a| a.kind == "acp")?;
    let spec = agent.acp.as_ref()?;
    let claude = spec.profile.as_deref() == Some("claude-agent-acp");
    let env = if claude {
        claude_env(m, run)
    } else {
        common_env(m, run).into_iter().chain(agent.env.iter().map(|(k, v)| (k.clone(), v.clone()))).collect()
    };
    let meta = claude.then(|| {
        let mut disallowed = vec!["WebSearch"];
        if !agent.in_box_subagents {
            disallowed.extend(["Agent", "Task"]);
        }
        let mut options = serde_json::json!({
            // wicket's gateway is the only MCP server; repo- or account-supplied servers are ignored.
            "strictMcpConfig": true,
            // Not "local": .claude/settings.local.json is where the adapter keeps "always" decisions,
            // which wicket never makes and doesn't let an earlier session's file make either.
            "settingSources": ["user", "project"],
            "disallowedTools": disallowed,
        });
        if let Some(model) = &agent.model {
            options["model"] = Value::from(model.clone());
        }
        serde_json::json!({ "claudeCode": { "options": options } })
    });
    let mut argv = vec!["wicket-entry".to_string()];
    argv.extend(spec.command.iter().cloned());
    let cfg = acp::AcpConfig { cwd: WORKSPACE.into(), system_prompt: format!("{SANDBOX_NOTICE}\n{BATCH_NOTICE}"), meta, resume: None };
    Some(LaunchPlan { env, argv, stdin_task: None, acp: Some(cfg) })
}

pub fn claude_code_plan(m: &Manifest, run: &RunId, session: &AgentSession) -> LaunchPlan {
    let agent = m.agent.as_ref().expect("an agent manifest");
    let env = claude_env(m, run);

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
    LaunchPlan { env, argv, stdin_task: Some(user_message(&m.task)), acp: None }
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
    use std::collections::HashMap;

    #[test]
    fn an_acp_agent_gets_routes_its_command_and_only_wicket_s_meta() {
        let y = |extra: &str, llm: &str| {
            format!("task: hi\nagent: {{name: a, kind: acp, acp: {{command: [my-agent, --acp]{extra}}}, env: {{FOO: bar}}}}\nzone: {{name: z{llm}}}")
        };
        let m = Manifest::from_yaml(&y("", "")).unwrap();
        let p = acp_plan(&m, &RunId("run_x".into())).unwrap();
        assert_eq!(p.argv, ["wicket-entry", "my-agent", "--acp"]);
        assert!(p.stdin_task.is_none());
        let env: HashMap<_, _> = p.env.iter().cloned().collect();
        assert_eq!(env.get("HTTPS_PROXY").map(String::as_str), Some(PROXY_URL));
        assert_eq!(env.get("FOO").map(String::as_str), Some("bar"));
        assert!(!env.contains_key("CLAUDE_CODE_OAUTH_TOKEN"), "a generic agent gets no Claude placeholder");
        let cfg = p.acp.unwrap();
        assert_eq!((cfg.cwd.as_str(), cfg.meta.is_none()), (WORKSPACE, true));
        assert!(cfg.system_prompt.starts_with(SANDBOX_NOTICE));
        assert!(!uses_claude_settings(&m));
        // The Claude adapter: Claude Code's placeholders, and wicket's lockdown in _meta.
        let m = Manifest::from_yaml(&y(", profile: claude-agent-acp", ", llm: {}")).unwrap();
        let p = acp_plan(&m, &RunId("run_x".into())).unwrap();
        assert!(p.env.iter().any(|(k, v)| k == "CLAUDE_CODE_OAUTH_TOKEN" && v.contains("placeholder")));
        let o = &p.acp.unwrap().meta.unwrap()["claudeCode"]["options"];
        assert_eq!(o["strictMcpConfig"], true);
        assert_eq!(o["settingSources"], serde_json::json!(["user", "project"]));
        assert!(uses_claude_settings(&m));
        // Not an ACP agent: no plan.
        let m = Manifest::from_yaml("task: hi\nagent: {name: a}\nzone: {name: z, llm: {}}").unwrap();
        assert!(acp_plan(&m, &RunId("run_x".into())).is_none());
    }

    #[test]
    fn acp_manifests_are_checked() {
        let bad = |agent: &str| Manifest::from_yaml(&format!("task: hi\nagent: {agent}\nzone: {{name: z}}")).unwrap_err().to_string();
        assert!(bad("{name: a, kind: acp}").contains("acp.command"));
        assert!(bad("{name: a, kind: acp, acp: {command: []}}").contains("acp.command"));
        assert!(bad("{name: a, acp: {command: [x]}}").contains("kind: acp"));
        assert!(bad("{name: a, kind: acp, acp: {command: [x], profile: nope}}").contains("profile"));
        assert!(bad("{name: a, kind: acp, acp: {command: [x]}, model: m}").contains("profile"));
        assert!(bad("{name: a, kind: acp, acp: {command: [x]}, max_turns: 3}").contains("max_turns"));
        assert!(bad("{name: a, kind: acp, acp: {command: [x], _meta: {}}}").contains("unknown field"));
        assert!(bad("{name: a, kind: gemini}").contains("claude-code or acp"));
        // The zone's model route is a Claude subscription: Claude Code only (#174 adds other routes).
        let with_llm = |agent: &str| Manifest::from_yaml(&format!("task: hi\nagent: {agent}\nzone: {{name: z, llm: {{}}}}"));
        assert!(with_llm("{name: a, kind: acp, acp: {command: [x]}}").unwrap_err().to_string().contains("only Claude Code"));
        assert!(with_llm("{name: a, kind: acp, acp: {command: [x], profile: claude-agent-acp}}").is_ok());
        assert!(bad("{name: a, kind: acp, acp: {command: [x], profile: claude-agent-acp}}").contains("llm section"));
        assert!(Manifest::from_yaml("task: hi\nagent: {name: a, kind: acp, acp: {command: [x]}}\nzone: {name: z}").is_ok());
    }

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

    fn remote_manifest(kind: &str) -> Manifest {
        let mut m =
            Manifest::from_yaml("agent: { name: rc, remote: { name: my box } }\nzone: { name: z, llm: { secret: claude-login } }\n")
                .unwrap();
        m.agent.as_mut().unwrap().kind = kind.into();
        m
    }

    #[test]
    fn a_remote_session_boots_claude_remote_control_with_placeholders_only() {
        let m = remote_manifest("claude-code");
        let run = RunId("run_rc1".into());
        let meta = serde_json::json!({
            "scopes": ["user:inference"], "subscriptionType": "max",
            "oauthAccount": { "organizationUuid": "org-1", "emailAddress": "a@example.com" }
        });
        let w = remote_plan(&m, &run, &meta).unwrap();
        assert_eq!(&w.plan.argv[..5], ["wicket-entry", "claude", "remote-control", "--name", "my box"]);
        assert!(w.plan.argv.windows(2).any(|p| p == ["--spawn", "session"]));
        assert!(w.plan.stdin_task.is_none());
        let file = |rel: &str| -> Value { serde_json::from_slice(&w.files.iter().find(|(r, _)| r == rel).unwrap().1).unwrap() };
        let creds = file("claude/.credentials.json");
        assert_eq!(creds["claudeAiOauth"]["accessToken"], w.login_placeholder);
        assert_eq!(creds["claudeAiOauth"]["subscriptionType"], "max");
        assert!(creds["claudeAiOauth"]["refreshToken"].as_str().unwrap().contains("placeholder"));
        let cfg = file("claude/.claude.json");
        assert_eq!(cfg["remoteDialogSeen"], true);
        assert_eq!(cfg["projects"][WORKSPACE]["hasTrustDialogAccepted"], true);
        assert_eq!(cfg["oauthAccount"]["organizationUuid"], "org-1");
        assert_eq!(cfg["mcpServers"]["wicket"]["url"], "http://wicket.internal:8081/mcp");
        let notice = String::from_utf8(w.files.iter().find(|(r, _)| r == "claude/CLAUDE.md").unwrap().1.clone()).unwrap();
        assert!(notice.contains("wicket sandbox"));
        // No credential anywhere but the placeholders, and the routes are wicket's.
        let env: HashMap<_, _> = w.plan.env.iter().cloned().collect();
        assert_eq!(env["HTTPS_PROXY"], "http://wicket.internal:3128");
        assert!(!env.contains_key("CLAUDE_CODE_OAUTH_TOKEN") && !env.contains_key("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn a_harness_without_remote_sessions_refuses_one() {
        let m = remote_manifest("codex");
        let e = remote_plan(&m, &RunId("run_x".into()), &Value::Null).err().unwrap();
        assert!(e.to_string().contains("the codex adapter has no remote sessions"), "{e}");
        assert_eq!(remote_session_url(&m, "see https://chatgpt.example/x"), None);
    }

    #[test]
    fn the_session_url_is_read_from_the_servers_output() {
        let m = remote_manifest("claude-code");
        assert_eq!(
            remote_session_url(&m, "Continue at https://claude.ai/code/session_01abc?x=1 (or the app)").as_deref(),
            Some("https://claude.ai/code/session_01abc?x=1")
        );
        assert_eq!(remote_session_url(&m, "visit claude.ai/code in a browser"), None);
    }

    #[test]
    fn the_account_comes_from_the_config_beside_the_login_without_the_holders_name() {
        let d = std::env::temp_dir().join(format!("wicket-agent-acct-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".claude")).unwrap();
        std::fs::write(d.join(".claude.json"), r#"{"oauthAccount":{"organizationUuid":"o","fullName":"A Person"},"projects":{}}"#).unwrap();
        let a = claude_code_account(&d.join(".claude/.credentials.json")).unwrap();
        assert_eq!(a, serde_json::json!({ "organizationUuid": "o" }));
        // A CLAUDE_CONFIG_DIR layout: both in one directory.
        std::fs::write(d.join(".claude/.claude.json"), r#"{"oauthAccount":{"organizationUuid":"p"}}"#).unwrap();
        assert_eq!(claude_code_account(&d.join("cfg/.credentials.json")), None);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        std::fs::copy(d.join(".claude/.claude.json"), d.join("cfg/.claude.json")).unwrap();
        assert_eq!(claude_code_account(&d.join("cfg/.credentials.json")).unwrap()["organizationUuid"], "p");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
