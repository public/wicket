//! The harness adapter interface (#174, #255): what the rest of wicket calls to run an agent's
//! harness (`agent.harness`) in a box. Everything a harness needs that is its own (its launch, its
//! config directory and files, its account login, its processes, its remote and wrapped modes) is
//! behind [`Adapter`]; wicket's runner, node and hibernation name no harness.

use crate::{claude, AgentSession, LaunchPlan, WrappedPlan};
use serde_json::Value;
use wicket_core::{AgentSpec, Harness, Manifest, RemotePermissionMode, RemoteSpec, RunId};

/// How a harness runs in its box. One workload kind, the agent, in one of three modes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode<'a> {
    /// wicket starts the harness and drives it: the task, follow-ups and messages are its turns. Only
    /// this mode is long-lived (hibernated, woken).
    Driven,
    /// `agent.remote` (#169): the harness registers its own session with its vendor's apps, and the
    /// owner drives it from there (Claude Code: Remote Control).
    Remote(&'a RemoteSpec),
    /// `wicket wrap`: a command line another program launched (Claude Code: Remote Control's
    /// session process), run in a box. Its launcher keeps its stdio.
    Wrapped(&'a [String]),
}

impl<'a> Mode<'a> {
    /// The mode an agent runs in: `wrap` is `wicket wrap`'s command line, if wrapped.
    pub fn of(agent: &'a AgentSpec, wrap: Option<&'a [String]>) -> Result<Mode<'a>, String> {
        match (&agent.remote, wrap) {
            (Some(_), Some(_)) => Err("agent.remote boots its own session in the box: it isn't wrapped".into()),
            (Some(r), None) => Ok(Mode::Remote(r)),
            (None, Some(argv)) => Ok(Mode::Wrapped(argv)),
            (None, None) => Ok(Mode::Driven),
        }
    }
}

/// An account login a box holds only as a placeholder: the secret it comes from, and the host the
/// egress proxy swaps the real one in toward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login {
    pub secret: String,
    pub host: &'static str,
}

/// One credential a wrapped session's box sees only as `placeholder`, swapped for the real one at
/// the egress proxy toward `host`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Swap {
    pub name: &'static str,
    pub host: &'static str,
    pub placeholder: String,
    pub real: SwapSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwapSource {
    /// A secret in the vault, by name.
    Secret(String),
    /// A value the launcher passed.
    Value(String),
}

/// A harness's adapter. Every method takes the agent's manifest, so a harness can vary by its own
/// settings (an ACP agent's profile, say).
pub trait Adapter: Send + Sync {
    fn harness(&self) -> Harness;

    /// Directories under the box's state dir the harness keeps its own configuration in, which wicket
    /// creates (as real directories) before the box starts.
    fn state_dirs(&self, _m: &Manifest) -> Vec<String> {
        vec![]
    }

    /// Files wicket writes under the box's state dir at every activation (after any restore, so
    /// wicket's values win): (path relative to it, contents).
    fn state_files(&self, _m: &Manifest) -> Vec<(String, Vec<u8>)> {
        vec![]
    }

    /// The plan for [`Mode::Driven`]: `first` is the first turn (the task, or what woke the agent).
    fn plan(&self, m: &Manifest, run: &RunId, session: &AgentSession, first: &str) -> Result<LaunchPlan, String>;

    /// Whether a process in the box (its command line) is the harness's own runtime: the quiet-point
    /// check for hibernation counts nothing else (besides wicket's own and the agent's command).
    fn is_runtime(&self, _m: &Manifest, _cmd: &str) -> bool {
        false
    }

    /// The account login a remote or wrapped session's box holds as a placeholder.
    fn login(&self, _m: &Manifest) -> Option<Login> {
        None
    }

    /// [`Mode::Remote`]'s plan. `login_meta` is what [`Adapter::remote_login_meta`] read.
    fn remote_plan(&self, _m: &Manifest, _run: &RunId, _login_meta: &Value) -> Result<WrappedPlan, String> {
        Err(format!("agent.remote: the {} harness has no remote mode", self.harness()))
    }

    /// The harness's own spelling of `agent.remote.permission_mode` (#285): None leaves the
    /// harness's default. A harness without the setting refuses any mode but `default`.
    fn remote_permission_mode(&self, mode: RemotePermissionMode) -> Result<Option<&'static str>, String> {
        if mode.is_default() {
            Ok(None)
        } else {
            Err(format!("agent.remote.permission_mode {:?}: the {} harness has no permission modes", mode.as_str(), self.harness()))
        }
    }

    /// What a remote session may know of its login, from the host (never a credential): `linked` is
    /// the object holding the linked token in its file, `file` that file.
    fn remote_login_meta(&self, _linked: Option<&Value>, _file: Option<&std::path::Path>) -> Value {
        Value::Null
    }

    /// The address of the remote session the harness printed on this line of its output, if any.
    fn remote_session_url(&self, _line: &str) -> Option<String> {
        None
    }

    /// [`Mode::Wrapped`]'s plan: the launcher's command line and environment, and the host user's
    /// home (where the host's own login is).
    fn wrapped_plan(
        &self,
        _m: &Manifest,
        _run: &RunId,
        _argv: &[String],
        _launcher_env: &[(String, String)],
        _home: &std::path::Path,
    ) -> Result<WrappedPlan, String> {
        Err(format!("the {} harness has no wrapped mode", self.harness()))
    }

    /// Who drives a wrapped session (a principal), from its launcher's environment.
    fn wrapped_principal(&self, _launcher_env: &[(String, String)]) -> Value {
        serde_json::json!({ "type": "human", "id": "unknown", "via": "wrap" })
    }
}

/// The adapter for a harness.
pub fn adapter(h: Harness) -> &'static dyn Adapter {
    match h {
        Harness::ClaudeCode => &ClaudeCode,
        Harness::Acp => &Acp,
    }
}

/// The adapter for a manifest's agent; None for a program.
pub fn of(m: &Manifest) -> Option<&'static dyn Adapter> {
    m.agent.as_ref().map(|a| adapter(a.harness))
}

/// Whether the manifest runs Claude Code: its own CLI, or through its ACP adapter's profile.
fn runs_claude_code(m: &Manifest) -> bool {
    crate::uses_claude_settings(m)
}

fn claude_state(m: &Manifest) -> (Vec<String>, Vec<(String, Vec<u8>)>) {
    if !runs_claude_code(m) {
        return (vec![], vec![]);
    }
    let settings = serde_json::to_vec_pretty(&crate::claude_settings(m)).unwrap_or_default();
    (vec![claude::STATE_SUBDIR.into()], vec![(format!("{}/settings.json", claude::STATE_SUBDIR), settings)])
}

/// Claude Code, driven over stream-json; Remote Control is its remote mode, and its Remote Control
/// session processes are what `wicket wrap` wraps.
pub struct ClaudeCode;

impl Adapter for ClaudeCode {
    fn harness(&self) -> Harness {
        Harness::ClaudeCode
    }

    fn state_dirs(&self, _m: &Manifest) -> Vec<String> {
        // Remote and wrapped sessions keep their config there too, with no settings file of wicket's.
        vec![claude::STATE_SUBDIR.into()]
    }

    fn state_files(&self, m: &Manifest) -> Vec<(String, Vec<u8>)> {
        claude_state(m).1
    }

    fn plan(&self, m: &Manifest, run: &RunId, session: &AgentSession, first: &str) -> Result<LaunchPlan, String> {
        let mut p = crate::claude_code_plan(m, run, session);
        p.stdin_task = Some(crate::user_message(first));
        Ok(p)
    }

    fn is_runtime(&self, _m: &Manifest, cmd: &str) -> bool {
        claude::is_runtime(cmd)
    }

    fn login(&self, m: &Manifest) -> Option<Login> {
        let secret = m.zone.llm.as_ref().map(|l| l.secret.clone()).unwrap_or_else(|| claude::LOGIN_SECRET.into());
        Some(Login { secret, host: claude::LOGIN_HOST })
    }

    fn remote_plan(&self, m: &Manifest, run: &RunId, login_meta: &Value) -> Result<WrappedPlan, String> {
        let mode = m.agent.as_ref().and_then(|a| a.remote.as_ref()).map(|r| r.permission_mode).unwrap_or_default();
        let mode = self.remote_permission_mode(mode)?.unwrap_or(RemotePermissionMode::Default.as_str());
        crate::claude_code_remote_control_plan(m, run, login_meta, mode).map_err(|e| e.0)
    }

    fn remote_permission_mode(&self, mode: RemotePermissionMode) -> Result<Option<&'static str>, String> {
        // `claude remote-control --permission-mode` takes the manifest's spellings as they are.
        Ok(Some(mode.as_str()))
    }

    fn remote_login_meta(&self, linked: Option<&Value>, file: Option<&std::path::Path>) -> Value {
        let mut meta = serde_json::json!({});
        if let Some(o) = linked {
            for k in ["scopes", "subscriptionType", "rateLimitTier"] {
                if let Some(v) = o.get(k) {
                    meta[k] = v.clone();
                }
            }
        }
        if let Some(a) = file.and_then(crate::claude_code_account) {
            meta["oauthAccount"] = a;
        }
        meta
    }

    fn remote_session_url(&self, line: &str) -> Option<String> {
        let start = line.find("https://claude.ai/code")?;
        Some(line[start..].chars().take_while(|c| !c.is_whitespace() && !"\"'<>)]".contains(*c)).collect())
    }

    fn wrapped_plan(
        &self,
        m: &Manifest,
        run: &RunId,
        argv: &[String],
        launcher_env: &[(String, String)],
        home: &std::path::Path,
    ) -> Result<WrappedPlan, String> {
        // Only the host login's non-secret fields (scopes, subscription type) are kept.
        let login_meta = std::fs::read(home.join(claude::HOST_CREDENTIALS))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.get("claudeAiOauth").cloned())
            .map(|o| serde_json::json!({ "scopes": o.get("scopes"), "subscriptionType": o.get("subscriptionType"), "rateLimitTier": o.get("rateLimitTier") }))
            .unwrap_or(Value::Null);
        let mut w = crate::claude_code_wrapped_plan(m, run, argv, launcher_env, &login_meta).map_err(|e| e.0)?;
        let login = self.login(m).expect("Claude Code has a login");
        w.swaps.push(Swap {
            name: "claude login",
            host: login.host,
            placeholder: w.login_placeholder.clone(),
            real: SwapSource::Secret(login.secret),
        });
        if let Some(t) = &w.session_token {
            w.swaps.push(Swap {
                name: "remote-control session",
                host: claude::LOGIN_HOST,
                placeholder: w.session_placeholder.clone(),
                real: SwapSource::Value(t.clone()),
            });
        }
        Ok(w)
    }

    fn wrapped_principal(&self, launcher_env: &[(String, String)]) -> Value {
        // The human driving the session through their claude.ai account.
        let who = launcher_env.iter().find(|(k, _)| k == "CLAUDE_CODE_BRIDGE_OWNER_ACCOUNT_UUID").map_or("unknown", |(_, v)| v.as_str());
        serde_json::json!({ "type": "human", "id": format!("claude.ai account {who}"), "via": "remote-control", "assurance": "claude.ai login" })
    }
}

/// Any agent that speaks the Agent Client Protocol (#66); wicket is its client. Claude Code through
/// its ACP adapter (`acp.profile: claude-agent-acp`) also gets Claude Code's config.
pub struct Acp;

impl Adapter for Acp {
    fn harness(&self) -> Harness {
        Harness::Acp
    }

    fn state_dirs(&self, m: &Manifest) -> Vec<String> {
        claude_state(m).0
    }

    fn state_files(&self, m: &Manifest) -> Vec<(String, Vec<u8>)> {
        claude_state(m).1
    }

    fn plan(&self, m: &Manifest, run: &RunId, session: &AgentSession, _first: &str) -> Result<LaunchPlan, String> {
        // The first prompt goes over the protocol once the session is open.
        let mut p = crate::acp_plan(m, run).ok_or("an ACP agent's plan needs agent.acp")?;
        if let Some(c) = p.acp.as_mut() {
            // A wake continues the agent's own session (the id its agent chose, #66).
            c.resume = session.resume.then(|| session.id.clone()).filter(|s| crate::acp::valid_session_id(s));
        }
        Ok(p)
    }

    fn is_runtime(&self, m: &Manifest, cmd: &str) -> bool {
        runs_claude_code(m) && claude::is_runtime(cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(agent: &str) -> Manifest {
        Manifest::from_yaml(&format!("task: hi\nagent: {agent}\nzone: {{ name: z, llm: {{}} }}\n")).unwrap()
    }

    #[test]
    fn the_mode_is_driven_remote_or_wrapped() {
        let m = manifest("{ name: a }");
        let a = m.agent.as_ref().unwrap();
        assert_eq!(Mode::of(a, None), Ok(Mode::Driven));
        let argv = ["claude".to_string()];
        assert_eq!(Mode::of(a, Some(&argv)), Ok(Mode::Wrapped(&argv)));
        let rc = manifest("{ name: a, remote: { name: box } }");
        let r = rc.agent.as_ref().unwrap();
        assert!(matches!(Mode::of(r, None), Ok(Mode::Remote(s)) if s.name == "box"));
        assert!(Mode::of(r, Some(&argv)).is_err());
    }

    #[test]
    fn claude_specifics_come_from_the_adapter() {
        let m = manifest("{ name: a }");
        let a = of(&m).unwrap();
        assert_eq!(a.harness(), Harness::ClaudeCode);
        assert_eq!(a.state_dirs(&m), ["claude"]);
        let files = a.state_files(&m);
        assert_eq!(files[0].0, "claude/settings.json");
        assert_eq!(a.login(&m), Some(Login { secret: "claude-oauth".into(), host: "api.anthropic.com" }));
        assert!(a.is_runtime(&m, "claude -p --input-format stream-json"));
        assert!(a.is_runtime(&m, "/usr/bin/node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"));
        assert!(!a.is_runtime(&m, "node /workspace/server.js"));
        assert_eq!(a.remote_session_url("open https://claude.ai/code/session_1) now"), Some("https://claude.ai/code/session_1".into()));
        let p = a.plan(&m, &RunId("run_1".into()), &AgentSession::new(), "hello").unwrap();
        assert!(p.stdin_task.unwrap().contains("hello"));
    }

    #[test]
    fn a_generic_acp_agent_has_no_claude_and_no_remote_or_wrapped_mode() {
        let m = Manifest::from_yaml("task: hi\nagent: { name: a, harness: acp, acp: { command: [x] } }\nzone: { name: z }\n").unwrap();
        let a = of(&m).unwrap();
        assert!(a.state_dirs(&m).is_empty() && a.state_files(&m).is_empty() && a.login(&m).is_none());
        assert!(!a.is_runtime(&m, "claude -p"));
        let run = RunId("run_1".into());
        assert!(a.remote_plan(&m, &run, &Value::Null).err().unwrap().contains("no remote mode"));
        assert_eq!(a.remote_permission_mode(RemotePermissionMode::Default), Ok(None));
        let e = a.remote_permission_mode(RemotePermissionMode::BypassPermissions).unwrap_err();
        assert_eq!(e, "agent.remote.permission_mode \"bypassPermissions\": the acp harness has no permission modes");
        assert!(a.wrapped_plan(&m, &run, &[], &[], std::path::Path::new("/")).err().unwrap().contains("no wrapped mode"));
        let claude = Manifest::from_yaml(
            "task: hi\nagent: { name: a, harness: acp, acp: { command: [claude-agent-acp], profile: claude-agent-acp } }\nzone: { name: z, llm: {} }\n",
        )
        .unwrap();
        assert_eq!(a.state_files(&claude)[0].0, "claude/settings.json");
        assert!(a.is_runtime(&claude, "claude -p"));
    }
}
