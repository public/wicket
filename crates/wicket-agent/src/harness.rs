//! The harness adapter interface (#174, #255): what the rest of wicket calls to run an agent's
//! harness (`agent.harness`) in a box. Everything a harness needs that is its own (its launch, its
//! config directory and files, its account login, its processes, its remote and wrapped modes) is
//! behind [`Adapter`]; wicket's runner, node and hibernation name no harness.

use crate::{claude, AgentSession, LaunchPlan, WrappedPlan};
use serde_json::Value;
use wicket_core::{AgentSpec, Harness, Manifest, RemotePermissionMode, RemoteSpec, RunId};

/// How a harness runs in its box. One workload kind, the agent, in one of four modes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mode<'a> {
    /// wicket starts the harness and drives it: the task, follow-ups and messages are its turns. Only
    /// this mode is long-lived (hibernated, woken).
    Driven,
    /// `agent.remote` (#169): the harness registers its own session with its vendor's apps, and the
    /// owner drives it from there (Claude Code: Remote Control).
    Remote(&'a RemoteSpec),
    /// `agent.remote` with `drive: true` (#285): driven by wicket as [`Mode::Driven`] (and as
    /// long-lived), with its session also registered in its vendor's apps, where the owner watches
    /// it and can send it messages.
    DrivenRemote(&'a RemoteSpec),
    /// `wicket wrap`: a command line another program launched (Claude Code: Remote Control's
    /// session process), run in a box. Its launcher keeps its stdio.
    Wrapped(&'a [String]),
}

impl<'a> Mode<'a> {
    /// The mode an agent runs in: `wrap` is `wicket wrap`'s command line, if wrapped.
    pub fn of(agent: &'a AgentSpec, wrap: Option<&'a [String]>) -> Result<Mode<'a>, String> {
        match (&agent.remote, wrap) {
            (Some(_), Some(_)) => Err("agent.remote boots its own session in the box: it isn't wrapped".into()),
            (Some(r), None) if r.drive => Ok(Mode::DrivenRemote(r)),
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

/// How wicket's MCP gateway pushes an incoming message into a harness's conversation (#252): the
/// capability it declares in `initialize` (under `experimental`), and the notification it sends on
/// the session's stream, `{ content, meta }`, with the verified sender in `meta` and the content
/// marked as data from a peer. A harness that turns that notification into a turn gets the message
/// as one; without push, the agent reads messages with `await_message` (long-poll).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MessagePush {
    pub capability: String,
    pub method: String,
}

/// A driven harness's control channel (#363): the requests wicket makes of it besides turns
/// (interrupt the running turn, change its permission mode), and its prompts before a tool call,
/// which wicket answers. A state machine with no I/O, like the ACP client: fed the harness's stdout
/// line by line, it returns the lines to write to its stdin and what happened.
pub trait Controller: Send {
    /// One line of the harness's stdout.
    fn on_line(&mut self, line: &str) -> ControlStep;
    /// Interrupts the running turn: the lines to write.
    fn interrupt(&mut self) -> Vec<String>;
    /// Changes the session's permission mode while it runs: the lines to write.
    fn set_mode(&mut self, mode: RemotePermissionMode) -> Vec<String>;
    /// Answers a prompt that [`ControlEvent::Prompt`] left to wicket (`refused: None`): the lines to
    /// write, none if the harness no longer waits on it.
    fn answer(&mut self, id: &str, allow: bool, why: &str) -> Vec<String>;
}

/// What a [`Controller`] made of a line: what to write back, and what happened.
#[derive(Debug, Default, PartialEq)]
pub struct ControlStep {
    pub write: Vec<String>,
    pub events: Vec<ControlEvent>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ControlEvent {
    /// The harness asks before a tool call. `kind` is the call's kind as ACP spells it (`edit`,
    /// `execute`, `read`, `fetch`, `switch_mode`, `other`), `detail` a short, clipped account of its
    /// input (agent data, for a human to read), `input` the input itself. `refused`: wicket's rule
    /// refused it and the answer is already written (why); None: it is wicket's to decide, as an
    /// approval, and to answer with [`Controller::answer`].
    Prompt { id: String, tool: String, kind: String, detail: String, input: Value, refused: Option<String> },
    /// The harness stopped waiting on a prompt (its turn was interrupted).
    Withdrawn { id: String },
    /// The harness's answer to one of wicket's control requests: what was asked, and Ok or why not.
    Answered { what: String, result: Result<(), String> },
}

/// A harness's adapter. Every method takes the agent's manifest, so a harness can vary by its own
/// settings (an ACP agent's profile, say).
pub trait Adapter: Send + Sync {
    fn harness(&self) -> Harness;

    /// Whether the gateway pushes messages into this harness's conversation, and how (#252). None
    /// (the default): it reads them with `await_message`.
    fn message_push(&self, _m: &Manifest) -> Option<MessagePush> {
        None
    }

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

    /// [`Mode::DrivenRemote`]'s plan: as [`Adapter::plan`]'s, with the session also registered in the
    /// vendor's apps. `login_meta` is what [`Adapter::remote_login_meta`] read.
    fn driven_remote_plan(
        &self,
        _m: &Manifest,
        _run: &RunId,
        _session: &AgentSession,
        _first: &str,
        _login_meta: &Value,
    ) -> Result<WrappedPlan, String> {
        Err(format!("agent.remote.drive: the {} harness has no driven remote mode", self.harness()))
    }

    /// The driven session's control channel (#363), for [`Mode::Driven`] and [`Mode::DrivenRemote`].
    /// None (the default): wicket only writes turns, and nothing can be interrupted.
    fn controller(&self) -> Option<Box<dyn Controller>> {
        None
    }

    /// What a [`Mode::DrivenRemote`] session's output line says of its remote session: Ok(its
    /// address), Err(why it didn't start). None for any other line.
    fn driven_remote_status(&self, _line: &str) -> Option<Result<String, String>> {
        None
    }

    /// Whether a process in the box (its command line) is the harness's own runtime: the quiet-point
    /// check for hibernation counts nothing else (besides wicket's own and the agent's command).
    fn is_runtime(&self, _m: &Manifest, _cmd: &str) -> bool {
        false
    }

    /// The model route a zone's `llm` gets where the manifest leaves a field out: provider, secret and
    /// upstream. None: this agent takes no model route (a zone with `llm` is refused).
    fn model_route(&self, _m: &Manifest) -> Option<wicket_core::ModelRoute> {
        None
    }

    /// Checks what only this harness knows about the agent's manifest (beyond core's checks).
    fn check(&self, _m: &Manifest) -> Result<(), String> {
        Ok(())
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
    /// the object holding the linked token in its file, `stored` what [`Adapter::link_login_meta`]
    /// kept with the secret when it was linked.
    fn remote_login_meta(&self, _linked: Option<&Value>, _stored: Option<&Value>) -> Value {
        Value::Null
    }

    /// At `wicket secret link`, for a link to this harness's login (`file`, the JSON `pointer` into
    /// it): the non-secret fields to keep with the secret for later remote sessions (#298). None
    /// when the link isn't this harness's login; Err (the link still stands) when the fields can't
    /// be read now, saying what that leaves out.
    fn link_login_meta(&self, _file: &std::path::Path, _pointer: Option<&str>) -> Option<Result<Value, String>> {
        None
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

/// Every harness's adapter.
pub fn adapters() -> [&'static dyn Adapter; 2] {
    [&ClaudeCode, &Acp]
}

/// At `wicket secret link`: what the harness whose login the link is keeps with the secret (see
/// [`Adapter::link_login_meta`]); None when it is no harness's login.
pub fn link_login_meta(file: &std::path::Path, pointer: Option<&str>) -> Option<Result<Value, String>> {
    adapters().into_iter().find_map(|a| a.link_login_meta(file, pointer))
}

/// The ACP adapter profiles wicket knows (`agent.acp.profile`).
pub const ACP_PROFILES: [&str; 1] = [claude::ACP_PROFILE];

/// A harness's default model secret, for `wicket doctor`.
pub struct ModelSecret {
    pub harness: Harness,
    pub secret: String,
    /// How its owner gets the credential.
    pub how: &'static str,
}

/// Every harness's default model secret (one per secret name).
pub fn model_secrets() -> Vec<ModelSecret> {
    vec![ModelSecret { harness: Harness::ClaudeCode, secret: claude::LOGIN_SECRET.into(), how: claude::LOGIN_HOW }]
}

/// The hosts a harness's default model secret is bound to when `wicket secret set` or `link` stores
/// it with no binding of its own: its default route's upstream host. Empty for any other name.
pub fn default_secret_hosts(name: &str) -> Vec<String> {
    let routes = [claude::model_route()];
    routes.iter().filter(|r| r.secret == name).filter_map(|r| url_host(&r.upstream)).fold(vec![], |mut v, h| {
        if !v.contains(&h) {
            v.push(h);
        }
        v
    })
}

fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let host = host.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h).unwrap_or(host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Fills in and checks what a manifest's harness decides (#255): the zone's model route defaults
/// (an agent whose harness takes a route needs `zone.llm`; one that takes none may not have it), and
/// the harness's own checks. A program takes no model route (core refuses `zone.llm` for it).
pub fn resolve(m: &mut Manifest) -> Result<(), String> {
    let Some(a) = of(m) else { return Ok(()) };
    a.check(m)?;
    let route = a.model_route(m);
    match (m.zone.llm.as_mut(), route) {
        (Some(_), None) => {
            return Err(format!(
                "zone.llm: this agent's harness ({}) takes no model route yet; leave llm out (routes per provider are #174)",
                a.harness()
            ))
        }
        (None, Some(_)) => return Err("an agent zone needs an llm section".into()),
        (Some(l), Some(r)) => {
            l.fill(&r);
            if let Some(f) = l.missing() {
                return Err(format!("zone.llm.{f} is empty"));
            }
        }
        (None, None) => {}
    }
    Ok(())
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
    let files = vec![
        (format!("{}/settings.json", claude::STATE_SUBDIR), settings),
        // wicket's guide for an agent in a box, as one of Claude Code's own skills.
        (claude::BOX_SKILL_FILE.into(), crate::BOX_SKILL.as_bytes().to_vec()),
    ];
    (vec![claude::STATE_SUBDIR.into()], files)
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

    fn message_push(&self, _m: &Manifest) -> Option<MessagePush> {
        claude::CHANNELS_IN_BOX
            .then(|| MessagePush { capability: claude::CHANNEL_CAPABILITY.into(), method: claude::CHANNEL_NOTIFICATION.into() })
    }

    fn is_runtime(&self, _m: &Manifest, cmd: &str) -> bool {
        claude::is_runtime(cmd)
    }

    fn model_route(&self, _m: &Manifest) -> Option<wicket_core::ModelRoute> {
        Some(claude::model_route())
    }

    fn login(&self, m: &Manifest) -> Option<Login> {
        let secret = m.zone.llm.as_ref().map(|l| l.secret.clone()).unwrap_or_else(|| claude::LOGIN_SECRET.into());
        Some(Login { secret, host: claude::LOGIN_HOST })
    }

    fn remote_plan(&self, m: &Manifest, run: &RunId, login_meta: &Value) -> Result<WrappedPlan, String> {
        let mode = m.agent.as_ref().and_then(|a| a.remote.as_ref()).map(|r| r.permission_mode()).unwrap_or_default();
        let mode = self.remote_permission_mode(mode)?.unwrap_or(RemotePermissionMode::Default.as_str());
        crate::claude_code_remote_control_plan(m, run, login_meta, mode).map_err(|e| e.0)
    }

    fn driven_remote_plan(
        &self,
        m: &Manifest,
        run: &RunId,
        session: &AgentSession,
        first: &str,
        login_meta: &Value,
    ) -> Result<WrappedPlan, String> {
        let r = m.agent.as_ref().and_then(|a| a.remote.as_ref()).ok_or("agent.remote.drive needs agent.remote")?;
        // `default` asks before acting: a driven Claude Code asks wicket (its stdin host), not the
        // app, and wicket raises each prompt as an approval (#363).
        let mode = r.permission_mode();
        let mode = self.remote_permission_mode(mode)?.unwrap_or(RemotePermissionMode::BypassPermissions.as_str());
        crate::claude_code_driven_remote_plan(m, run, session, first, login_meta, mode).map_err(|e| e.0)
    }

    fn driven_remote_status(&self, line: &str) -> Option<Result<String, String>> {
        crate::driven_remote_status(line)
    }

    fn controller(&self) -> Option<Box<dyn Controller>> {
        Some(Box::new(claude::control::Control::default()))
    }

    fn remote_permission_mode(&self, mode: RemotePermissionMode) -> Result<Option<&'static str>, String> {
        // `claude remote-control --permission-mode` takes the manifest's spellings as they are.
        Ok(Some(mode.as_str()))
    }

    fn remote_login_meta(&self, linked: Option<&Value>, stored: Option<&Value>) -> Value {
        let mut meta = serde_json::json!({});
        if let Some(o) = linked {
            for k in ["scopes", "subscriptionType", "rateLimitTier"] {
                if let Some(v) = o.get(k) {
                    meta[k] = v.clone();
                }
            }
        }
        // The account fields as they were at link time: `~/.claude.json` is never read at a start
        // (Claude Code replaces it often, dropping any ACL that let wicket read it).
        if let Some(a) = stored.and_then(|s| s.get("oauthAccount")).filter(|a| a.is_object()) {
            let mut a = a.clone();
            if let Some(o) = a.as_object_mut() {
                o.remove("fullName");
            }
            meta["oauthAccount"] = a;
        }
        meta
    }

    fn link_login_meta(&self, file: &std::path::Path, pointer: Option<&str>) -> Option<Result<Value, String>> {
        if !pointer.is_some_and(|p| p.starts_with("/claudeAiOauth/")) {
            return None;
        }
        Some(match crate::claude_code_account(file) {
            Some(a) => Ok(serde_json::json!({ "oauthAccount": a })),
            None => Err(format!(
                "no oauthAccount readable in the Claude config next to {} (~/.claude.json, or .claude.json in a CLAUDE_CONFIG_DIR): \
                 a Remote Control box needs it, so make it readable and re-link this secret before starting one",
                file.display()
            )),
        })
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
        if runs_claude_code(m) {
            return claude_state(m).1;
        }
        // Any other ACP agent: wicket's guide as a plain file, which its notice points to.
        vec![(crate::BOX_GUIDE_FILE.into(), crate::box_guide().as_bytes().to_vec())]
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

    fn model_route(&self, m: &Manifest) -> Option<wicket_core::ModelRoute> {
        // Claude Code through its ACP adapter has Claude Code's route; a generic ACP agent gets none
        // until routes per provider exist (#174).
        runs_claude_code(m).then(claude::model_route)
    }

    fn check(&self, m: &Manifest) -> Result<(), String> {
        let Some(a) = m.agent.as_ref() else { return Ok(()) };
        let known = match a.acp.as_ref().and_then(|p| p.profile.as_deref()) {
            None => false,
            Some(p) if ACP_PROFILES.contains(&p) => true,
            Some(p) => return Err(format!("agent.acp.profile {p:?}: known profiles are {ACP_PROFILES:?}")),
        };
        if !known && (a.model.is_some() || !a.adapter_settings.is_empty()) {
            return Err(
                "agent.model and agent.adapter_settings need an ACP profile wicket knows; set them in the agent's own configuration".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(agent: &str) -> Manifest {
        crate::load(&format!("task: hi\nagent: {agent}\nzone: {{ name: z, llm: {{}} }}\n")).unwrap()
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
        let d = crate::load("task: hi\nagent: { name: a, remote: { name: box, drive: true } }\nzone: { name: z, llm: {} }\n").unwrap();
        let d = d.agent.as_ref().unwrap();
        assert!(matches!(Mode::of(d, None), Ok(Mode::DrivenRemote(s)) if s.name == "box" && s.drive));
        assert!(Mode::of(d, Some(&argv)).is_err());
    }

    #[test]
    fn claude_specifics_come_from_the_adapter() {
        let m = manifest("{ name: a }");
        let a = of(&m).unwrap();
        assert_eq!(a.harness(), Harness::ClaudeCode);
        assert_eq!(a.state_dirs(&m), ["claude"]);
        let files = a.state_files(&m);
        assert_eq!(files[0].0, "claude/settings.json");
        // wicket's guide is one of Claude Code's skills, in its config directory, as the plugin ships it.
        let skill = files.iter().find(|(r, _)| r == claude::BOX_SKILL_FILE).expect("the wicket-box skill");
        assert!(claude::BOX_SKILL_FILE.starts_with(&format!("{}/skills/", claude::STATE_SUBDIR)));
        assert_eq!(skill.1, crate::BOX_SKILL.as_bytes());
        assert_eq!(a.login(&m), Some(Login { secret: "claude-oauth".into(), host: "api.anthropic.com" }));
        assert!(a.is_runtime(&m, "claude -p --input-format stream-json"));
        assert!(a.is_runtime(&m, "/usr/bin/node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"));
        assert!(!a.is_runtime(&m, "node /workspace/server.js"));
        assert_eq!(a.remote_session_url("open https://claude.ai/code/session_1) now"), Some("https://claude.ai/code/session_1".into()));
        let p = a.plan(&m, &RunId("run_1".into()), &AgentSession::new(), "hello").unwrap();
        assert!(p.stdin_task.unwrap().contains("hello"));
    }

    #[test]
    fn the_box_guide_is_the_wicket_box_skill() {
        let fm = crate::BOX_SKILL.strip_prefix("---\n").expect("the skill starts with its frontmatter");
        let fm = &fm[..fm.find("\n---\n").expect("the frontmatter ends")];
        assert!(fm.lines().any(|l| l == "name: wicket-box"));
        assert!(fm.lines().any(|l| l.starts_with("description: ")));
        // The guide is the body alone: Markdown, starting with its title.
        let guide = crate::box_guide();
        assert!(guide.starts_with("# ") && !guide.contains("\nname: wicket-box\n"));
        assert!(crate::BOX_SKILL.ends_with(guide));
    }

    #[test]
    fn a_generic_acp_agent_has_no_claude_and_no_remote_or_wrapped_mode() {
        let m = crate::load("task: hi\nagent: { name: a, harness: acp, acp: { command: [x] } }\nzone: { name: z }\n").unwrap();
        let a = of(&m).unwrap();
        assert!(a.state_dirs(&m).is_empty() && a.login(&m).is_none());
        // No Claude config, but wicket's guide as a plain file, which the agent's notice names.
        assert_eq!(a.state_files(&m), vec![(crate::BOX_GUIDE_FILE.to_string(), crate::box_guide().as_bytes().to_vec())]);
        let p = a.plan(&m, &RunId("run_1".into()), &AgentSession::new(), "hi").unwrap();
        let guide = format!("{}/{}", crate::STATE_DIR, crate::BOX_GUIDE_FILE);
        assert!(p.acp.unwrap().system_prompt.contains(&guide));
        assert!(!a.is_runtime(&m, "claude -p"));
        let run = RunId("run_1".into());
        assert!(a.remote_plan(&m, &run, &Value::Null).err().unwrap().contains("no remote mode"));
        let e = a.driven_remote_plan(&m, &run, &AgentSession::new(), "hi", &Value::Null).err().unwrap();
        assert_eq!(e, "agent.remote.drive: the acp harness has no driven remote mode");
        assert!(a.driven_remote_status(r#"{"type":"control_response"}"#).is_none());
        assert_eq!(a.remote_permission_mode(RemotePermissionMode::Default), Ok(None));
        let e = a.remote_permission_mode(RemotePermissionMode::BypassPermissions).unwrap_err();
        assert_eq!(e, "agent.remote.permission_mode \"bypassPermissions\": the acp harness has no permission modes");
        assert!(a.wrapped_plan(&m, &run, &[], &[], std::path::Path::new("/")).err().unwrap().contains("no wrapped mode"));
        let claude = crate::load(
            "task: hi\nagent: { name: a, harness: acp, acp: { command: [claude-agent-acp], profile: claude-agent-acp } }\nzone: { name: z, llm: {} }\n",
        )
        .unwrap();
        assert_eq!(a.state_files(&claude)[0].0, "claude/settings.json");
        assert!(a.state_files(&claude).iter().any(|(r, _)| r == claude::BOX_SKILL_FILE));
        let p = a.plan(&claude, &run, &AgentSession::new(), "hi").unwrap();
        assert!(!p.acp.unwrap().system_prompt.contains(crate::BOX_GUIDE_FILE));
        assert!(a.is_runtime(&claude, "claude -p"));
    }
}
