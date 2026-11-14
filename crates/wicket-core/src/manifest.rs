//! The task manifest: trusted task text plus one zone (design §5). The PoC supports one zone and one
//! agent per run; gates between zones come later.

use crate::TenantId;
use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid path glob {glob:?}: {err}")]
    Glob { glob: String, err: String },
    #[error("invalid duration {0:?}")]
    Duration(String),
    #[error("{0}")]
    Invalid(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default)]
    pub tenant: TenantId,
    /// Trusted task text: the only input policy derivation ever sees. Optional only for a remote
    /// session (`agent.remote`), whose messages come from the harness's own app.
    #[serde(default)]
    pub task: String,
    /// Exactly one of `agent` or `program`.
    #[serde(default)]
    pub agent: Option<AgentSpec>,
    #[serde(default)]
    pub program: Option<ProgramSpec>,
    pub zone: ZoneSpec,
}

/// A deterministic workload: no model, same sandbox and enforcement (design §17).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramSpec {
    pub name: String,
    /// Command run inside the box (working directory /workspace).
    pub command: Vec<String>,
    /// Source directory, relative to the manifest; copied into /workspace.
    #[serde(default)]
    pub source: Option<String>,
    /// The approved source digest. When set, a run refuses any other source.
    #[serde(default)]
    pub digest: Option<String>,
    /// What happens when the program needs something outside its reach.
    #[serde(default)]
    pub on_pending: OnPending,
    /// Runtime image (default: the agent image, which has bash, curl, jq, git, python3).
    #[serde(default)]
    pub image: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnPending {
    /// Out-of-reach requests fail outright; nothing is queued for a human. The default for programs.
    #[default]
    Fail,
    /// Queue an escalation like an agent would, and let the program wait (e.g. via await_grant).
    Wait,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub name: String,
    /// The harness that runs the agent in its box: `claude-code` (default) or `acp`. Its adapter
    /// (`wicket-agent`) is the only part of wicket that knows it.
    #[serde(default)]
    pub harness: Harness,
    /// Model id passed to the agent; None = the agent's default.
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub max_turns: Option<u32>,
    /// The image the agent's box starts from (default: the installation's current agent image). Any
    /// other image must be listed in `zone.images`, as for `spawn`. `wicket run --image` overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// How many child agents this agent may start with `spawn_agent`, each in its own sandbox with
    /// its own identity (design §3.2, §5.1). 0 = none.
    #[serde(default)]
    pub max_children: u32,
    /// Whether the agent may also run its own in-box subagents (Claude Code's Agent tool). Their
    /// requests are attributed but not provably identified; set false to require that every
    /// subagent is a wicket child with its own identity.
    #[serde(default = "yes")]
    pub in_box_subagents: bool,
    /// Extra environment for the agent: non-secret configuration only. Variables
    /// wicket controls (proxies, CA, model routes, credentials) can't be set here.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Settings for the agent's own adapter (for claude-code: written to its settings.json), limited
    /// to keys that can't change what the agent can reach or run (ADAPTER_SETTINGS_ALLOWED).
    #[serde(default)]
    pub adapter_settings: serde_json::Map<String, serde_json::Value>,
    /// The harness's remote mode (#169): the harness in the box registers its own session with its
    /// vendor's apps, and the owner drives it from there (for `claude-code`, Remote Control). The
    /// account login is the zone's `llm.secret`, which the box only ever holds as a placeholder.
    /// Harness adapters that have no such mode refuse it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteSpec>,
    /// For `harness: acp`: how to start the agent in its box.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acp: Option<AcpSpec>,
}

/// `agent.acp` (#66): an Agent Client Protocol agent in the box, driven by wicket over its stdio.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpSpec {
    /// The agent's command inside the box. The image must already have it, at a pinned version:
    /// nothing is installed at start.
    pub command: Vec<String>,
    /// A wicket profile for a known adapter: what wicket itself sets for it (environment, `_meta`).
    /// `claude-agent-acp`: Claude Code through its ACP adapter. None: a generic ACP agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// The adapter profiles wicket knows (`agent.acp.profile`).
pub const ACP_PROFILES: [&str; 1] = ["claude-agent-acp"];

/// `agent.remote`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSpec {
    /// The session's name in the vendor's apps.
    pub name: String,
    /// How far the harness acts without asking in the app (#285). Whatever the mode, wicket's
    /// proxies decide what the box can reach. Left out when `default`, so manifests that don't set it
    /// serialize as before.
    #[serde(default, skip_serializing_if = "RemotePermissionMode::is_default")]
    pub permission_mode: RemotePermissionMode,
}

/// `agent.remote.permission_mode`: the modes `claude remote-control --permission-mode` takes. A
/// harness adapter maps them to its own, and one without the setting refuses any but `default`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemotePermissionMode {
    AcceptEdits,
    Auto,
    BypassPermissions,
    /// The harness asks in the app before it acts, as a session on the owner's own machine would.
    #[default]
    Default,
    DontAsk,
    Plan,
}

impl RemotePermissionMode {
    pub const ALL: [RemotePermissionMode; 6] = [
        RemotePermissionMode::AcceptEdits,
        RemotePermissionMode::Auto,
        RemotePermissionMode::BypassPermissions,
        RemotePermissionMode::Default,
        RemotePermissionMode::DontAsk,
        RemotePermissionMode::Plan,
    ];

    pub fn is_default(&self) -> bool {
        *self == RemotePermissionMode::Default
    }

    /// The mode's name, as the manifest spells it.
    pub fn as_str(&self) -> &'static str {
        match self {
            RemotePermissionMode::AcceptEdits => "acceptEdits",
            RemotePermissionMode::Auto => "auto",
            RemotePermissionMode::BypassPermissions => "bypassPermissions",
            RemotePermissionMode::Default => "default",
            RemotePermissionMode::DontAsk => "dontAsk",
            RemotePermissionMode::Plan => "plan",
        }
    }
}

impl std::fmt::Display for RemotePermissionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Adapter settings a manifest may set: presentation and commit metadata only. Hooks, permissions,
/// MCP servers, environment, credential helpers and the like stay under wicket's control.
pub const ADAPTER_SETTINGS_ALLOWED: [&str; 5] = ["includeCoAuthoredBy", "attribution", "outputStyle", "alwaysThinkingEnabled", "language"];

/// Adapter settings wicket sets itself and a manifest may not override. `cleanupPeriodDays`: Claude
/// Code deletes sessions older than it on start, which would erase a long-lived agent's own history
/// when it wakes (#70).
pub const ADAPTER_SETTINGS_OWNED: [&str; 1] = ["cleanupPeriodDays"];

/// Environment variables a manifest may not set: wicket's routes, trust and placeholders.
pub const RESERVED_ENV_PREFIXES: [&str; 12] =
    ["ANTHROPIC_", "CLAUDE_", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "SSL_", "CURL_", "NODE_", "MCP_", "GIT_SSL", "WICKET_"];

fn yes() -> bool {
    true
}

/// `agent.harness`: what runs an agent in its box. How each is launched, configured and resumed is
/// its adapter's, in `wicket-agent`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Harness {
    /// Claude Code, driven by wicket over its stream-json stdio.
    #[default]
    ClaudeCode,
    /// Any agent that speaks the Agent Client Protocol, started from `agent.acp.command` (#66).
    Acp,
}

impl Harness {
    pub fn as_str(self) -> &'static str {
        match self {
            Harness::ClaudeCode => "claude-code",
            Harness::Acp => "acp",
        }
    }
}

impl std::fmt::Display for Harness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Isolation {
    /// gVisor (runsc): the default floor.
    #[default]
    Gvisor,
    /// Plain runc containers: development only.
    Runc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneSpec {
    pub name: String,
    #[serde(default)]
    pub isolation: Isolation,
    /// What the zone may reach over HTTP(S). Anything else becomes a pending escalation.
    #[serde(default)]
    pub reach: Vec<ReachRule>,
    /// What a host that no reach rule names looks like from inside: `escalate` (default) treats a
    /// request to it as a pending request a human can approve; `hide` makes it look like it doesn't
    /// exist (the proxy refuses the connection before TLS, with a not-found status), for zones that
    /// should never learn or ask about anything beyond their reach.
    #[serde(default)]
    pub unlisted_hosts: UnlistedHosts,
    /// Wildcard reach rules (`*.cdn.example`) and the DNS channel they open (#20): every name under one
    /// is resolved on the host, so a zone may forbid them, and bounds how many distinct names under
    /// each one a run may reach.
    #[serde(default)]
    pub wildcards: WildcardSpec,
    /// Hosts or paths refused outright, whatever the method: no pending request, no grant. Checked
    /// before `reach`.
    #[serde(default)]
    pub forbid: Vec<ForbidRule>,
    /// Credentials injected by the egress proxy into exactly one header slot per host.
    #[serde(default)]
    pub inject: Vec<InjectRule>,
    /// The model route; required for agents, absent for programs.
    #[serde(default)]
    pub llm: Option<LlmSpec>,
    /// Named directories that persist between runs of this zone, mounted read-write at `path`: any
    /// state a workload keeps (a cache, a dataset, model weights, a database). Per tenant and zone,
    /// and shared by the zone's runs, so whatever one run leaves there the next one reads (and
    /// inherits its labels, design §12).
    #[serde(default)]
    pub volumes: Vec<VolumeSpec>,
    /// Images boxes in this zone may start other boxes from (besides their own), with `spawn`.
    #[serde(default)]
    pub images: Vec<String>,
    /// Zones whose agents may send messages to agents in this zone (besides parent and children).
    /// Empty = nobody else. Senders are identified by wicket, never by their own claim.
    #[serde(default)]
    pub accept_from: Vec<String>,
    #[serde(default)]
    pub limits: Limits,
}

impl ZoneSpec {
    /// Drops the optional injections whose secret `is_set` says isn't set, and returns them (#175).
    /// Such a rule behaves as if it weren't there: requests to its host go without the credential,
    /// and a host with no injection left is spliced when its reach rule allows it wholesale.
    pub fn drop_unset_optional_injections(&mut self, is_set: impl Fn(&str) -> bool) -> Vec<InjectRule> {
        let (dropped, kept) = std::mem::take(&mut self.inject).into_iter().partition(|i| i.optional && !is_set(&i.secret));
        self.inject = kept;
        dropped
    }
}

/// What a zone allows of wildcard reach rules (#20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WildcardSpec {
    /// No reach rule may be a wildcard: every host the zone reaches is named exactly. For sensitive
    /// zones, where even a narrow DNS channel matters.
    #[serde(default)]
    pub forbid: bool,
    /// How many distinct names under each wildcard reach rule one run may reach; past that, a new
    /// name is refused (names already reached keep working). At least 1.
    #[serde(default = "default_wildcard_names")]
    pub max_names: u32,
}

/// The default bound on distinct names per wildcard per run: enough for a CDN's or a cloud
/// provider's handful of hostnames, too few to carry much in the names themselves.
pub const DEFAULT_WILDCARD_NAMES: u32 = 32;

fn default_wildcard_names() -> u32 {
    DEFAULT_WILDCARD_NAMES
}

impl Default for WildcardSpec {
    fn default() -> Self {
        WildcardSpec { forbid: false, max_names: DEFAULT_WILDCARD_NAMES }
    }
}

impl ZoneSpec {
    /// The wildcard reach rules' patterns (`*.cdn.example`), each once, in rule order.
    pub fn wildcard_reach(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for r in &self.reach {
            if r.host.starts_with("*.") && !out.iter().any(|h| h.eq_ignore_ascii_case(&r.host)) {
                out.push(&r.host);
            }
        }
        out
    }

    /// Whether the zone's wildcard settings hold: `max_names` is at least 1, and with `forbid`, no
    /// reach rule is a wildcard.
    pub fn check_wildcards(&self) -> Result<(), ManifestError> {
        if self.wildcards.max_names == 0 {
            return Err(ManifestError::Invalid("zone.wildcards.max_names must be at least 1".into()));
        }
        if self.wildcards.forbid {
            if let Some(w) = self.wildcard_reach().first() {
                return Err(ManifestError::Invalid(format!(
                    "zone.wildcards.forbid: reach rule host {w} is a wildcard; name each host exactly"
                )));
            }
        }
        Ok(())
    }

    /// The wildcard reach rule `host` is reached through, if no exact reach rule names it: the
    /// first wildcard pattern that matches. None for a host named exactly, or not reached at all.
    pub fn wildcard_for(&self, host: &str) -> Option<&str> {
        if self.reach.iter().any(|r| !r.host.starts_with("*.") && host_matches(&r.host, host)) {
            return None;
        }
        self.reach.iter().find(|r| r.host.starts_with("*.") && host_matches(&r.host, host)).map(|r| r.host.as_str())
    }

    /// Whether any reach or inject rule names `host` (exactly or by wildcard).
    pub fn names_host(&self, host: &str) -> bool {
        self.reach.iter().any(|r| host_matches(&r.host, host)) || self.inject.iter().any(|r| host_matches(&r.host, host))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UnlistedHosts {
    #[default]
    Escalate,
    Hide,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbidRule {
    pub host: String,
    /// Path globs, as in reach rules, but matched ignoring ASCII case (#115): many upstreams
    /// (GitHub's owner and repository names, for one) fold case, so `/repos/ACME/prod` must not dodge
    /// a forbid on `/repos/acme/prod/**`. Reach globs stay case-sensitive (narrower is safer there).
    /// Default: everything on the host.
    #[serde(default = "default_paths")]
    pub paths: Vec<String>,
}

impl ForbidRule {
    /// Whether this rule covers every path on `host` (so the host itself is off limits).
    pub fn covers_host(&self, host: &str) -> bool {
        host_matches(&self.host, host) && self.paths.iter().any(|p| p == "/**")
    }

    pub fn matches(&self, host: &str, path: &str) -> bool {
        // A glob that doesn't compile counts as matching: a broken forbid rule forbids, never allows.
        host_matches(&self.host, host)
            && self.paths.iter().any(|p| compile_glob(&fold_case_glob(p)).map(|g| g.is_match(path)).unwrap_or(true))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeSpec {
    /// `[a-z0-9-]+`, unique within the zone.
    pub name: String,
    /// Absolute path inside the box, under /volumes.
    pub path: String,
    /// What happens to it when an agent hibernates (#70).
    #[serde(default)]
    pub persist: Persist,
}

/// A volume's class when an agent hibernates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Persist {
    /// Per agent, bundled with its state and restored on wake (the agent's own data).
    Durable,
    /// Shared by the zone on the node that runs it, kept there and not bundled (the default).
    #[default]
    Node,
    /// Re-derivable (`node_modules`, `target/`): never bundled, and may be empty on wake.
    Cache,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReachRule {
    /// Exact host, or `*.example.com`.
    pub host: String,
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
    /// Path globs: `*` matches within one segment, `**` across segments.
    #[serde(default = "default_paths")]
    pub paths: Vec<String>,
    /// Allow requests that the dangerous-pattern list rates R3+ without a grant. Default false.
    #[serde(default)]
    pub allow_dangerous: bool,
}

fn default_methods() -> Vec<String> {
    vec!["GET".into(), "HEAD".into()]
}
fn default_paths() -> Vec<String> {
    vec!["/**".into()]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectRule {
    pub host: String,
    pub header: String,
    /// e.g. `Bearer {secret}`, or `Basic {basic:x-access-token}` for base64("x-access-token:<secret>").
    #[serde(default = "default_format")]
    pub format: String,
    /// Name of the secret in wicket's vault.
    pub secret: String,
    /// If the secret isn't in the vault, send requests to this host without it instead of refusing
    /// to start (e.g. anonymous reads of a public repo until a token is set up).
    #[serde(default)]
    pub optional: bool,
}

fn default_format() -> String {
    "{secret}".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmSpec {
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Vault secret holding the Claude subscription token (from `claude setup-token`). wicket never
    /// uses Anthropic API keys: the inner agent is the Claude Code CLI on the owner's subscription.
    #[serde(default = "default_llm_secret")]
    pub secret: String,
    /// Upstream base URL; override for a mock in tests.
    #[serde(default = "default_upstream")]
    pub upstream: String,
    #[serde(default = "default_max_requests")]
    pub max_requests: u64,
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u64,
    /// Optional cap on input tokens, counting cached ones (cache reads and cache writes) too: with
    /// prompt caching, a long conversation's input is mostly cache reads. None: no input cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_input_tokens: Option<u64>,
    /// Allow server-side tools (web search/fetch). They bypass the egress proxy, so default false.
    #[serde(default)]
    pub allow_server_tools: bool,
}

fn default_provider() -> String {
    "anthropic".into()
}
fn default_llm_secret() -> String {
    "claude-oauth".into()
}
fn default_upstream() -> String {
    "https://api.anthropic.com".into()
}
fn default_max_requests() -> u64 {
    300
}
fn default_max_output_tokens() -> u64 {
    400_000
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_memory")]
    pub memory: String,
    #[serde(default = "default_cpus")]
    pub cpus: f32,
    #[serde(default = "default_timeout")]
    pub timeout: String,
    /// How long the box's authority lasts from the run's start (#153): its token's block 0, and so
    /// how long its node keeps working for it without the control host. The box stops when it
    /// ends. Default: the run's `timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    #[serde(default = "default_pids")]
    pub pids: u32,
    /// What a box's output may take on its node's disk (its stdout and stderr together), outside
    /// the box's own limits (#151). Default 64 MiB.
    #[serde(default = "default_output")]
    pub output: String,
    /// When a box's output passes `output`: keep its newest output (the oldest goes, and the bytes
    /// dropped are recorded), or stop the box.
    #[serde(default)]
    pub on_output_full: OnOutputFull,
}

/// What happens when a box's output passes its zone's `limits.output`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnOutputFull {
    #[default]
    KeepNewest,
    Stop,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            memory: default_memory(),
            cpus: default_cpus(),
            timeout: default_timeout(),
            authority: None,
            pids: default_pids(),
            output: default_output(),
            on_output_full: OnOutputFull::default(),
        }
    }
}

fn default_output() -> String {
    "64m".into()
}

fn default_memory() -> String {
    "2g".into()
}
fn default_cpus() -> f32 {
    1.0
}
fn default_timeout() -> String {
    "30m".into()
}
fn default_pids() -> u32 {
    512
}

impl Limits {
    pub fn timeout(&self) -> Result<Duration, ManifestError> {
        humantime::parse_duration(&self.timeout).map_err(|_| ManifestError::Duration(self.timeout.clone()))
    }

    /// How long the box's authority lasts from the run's start (#153): `authority`, or the
    /// `timeout`. Never longer than the timeout (the box stops then anyway), never zero.
    pub fn authority(&self) -> Result<Duration, ManifestError> {
        let t = self.timeout()?;
        match &self.authority {
            None => Ok(t),
            Some(a) => match humantime::parse_duration(a) {
                Ok(d) if !d.is_zero() => Ok(d.min(t)),
                _ => Err(ManifestError::Duration(a.clone())),
            },
        }
    }

    /// The memory limit in bytes, if readable.
    pub fn memory_bytes(&self) -> Option<u64> {
        crate::subset::parse_bytes(&self.memory)
    }

    /// The output cap in bytes, if readable.
    pub fn output_bytes(&self) -> Option<u64> {
        crate::subset::parse_bytes(&self.output)
    }

    /// Every limit is a real bound: Docker reads `--memory 0`, `--cpus 0` and `--pids-limit 0` as
    /// "no limit" (#126), so each has a floor of 1 (byte, CPU share, process; `MIN_CPUS` for cpus).
    pub fn check(&self) -> Result<(), ManifestError> {
        let bad = |what: String| Err(ManifestError::Invalid(format!("limits.{what}: every limit must be a positive bound")));
        if !self.memory_bytes().is_some_and(|m| m >= 1) {
            return bad(format!("memory {:?}", self.memory));
        }
        if !(self.cpus.is_finite() && self.cpus >= MIN_CPUS) {
            return bad(format!("cpus {}", self.cpus));
        }
        if self.pids < 1 {
            return bad(format!("pids {}", self.pids));
        }
        // At least 64 KiB: Docker's log rotation needs room for two files.
        if !self.output_bytes().is_some_and(|o| o >= 64 << 10) {
            return Err(ManifestError::Invalid(format!("limits.output {:?}: at least 64k", self.output)));
        }
        if self.timeout()?.is_zero() {
            return bad(format!("timeout {:?}", self.timeout));
        }
        Ok(())
    }
}

/// The smallest CPU limit Docker takes (`--cpus 0.01`).
pub const MIN_CPUS: f32 = 0.01;

impl Manifest {
    pub fn from_yaml(s: &str) -> Result<Self, ManifestError> {
        let m: Manifest = serde_yaml::from_str(s)?;
        m.validate()?;
        Ok(m)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        self.zone.limits.authority()?;
        self.zone.check_wildcards()?;
        // Every image named, by tag or pinned by digest (#192): a pin is strict, never a tag.
        let named = self.zone.images.iter().map(|i| ("zone.images", i.as_str()));
        let own = self.agent.as_ref().and_then(|a| a.image.as_deref()).map(|i| ("agent.image", i));
        let prog = self.program.as_ref().and_then(|p| p.image.as_deref()).map(|i| ("program.image", i));
        for (field, i) in named.chain(own).chain(prog) {
            if !i.trim().is_empty() {
                crate::image::parse(i).map_err(|e| ManifestError::Invalid(format!("{field}: {e}")))?;
            }
        }
        match (&self.agent, &self.program) {
            (Some(a), None) => {
                match (a.harness, &a.acp) {
                    (Harness::ClaudeCode, None) => {}
                    (Harness::ClaudeCode, Some(_)) => return Err(ManifestError::Invalid("agent.acp is for harness: acp".into())),
                    (Harness::Acp, None) => return Err(ManifestError::Invalid("harness: acp needs agent.acp.command".into())),
                    (Harness::Acp, Some(acp)) => {
                        if acp.command.is_empty() || acp.command.iter().any(|c| c.is_empty() || c.contains('\0')) {
                            return Err(ManifestError::Invalid("agent.acp.command: the agent's command and arguments, none empty".into()));
                        }
                        let claude = match acp.profile.as_deref() {
                            None => false,
                            Some(p) if ACP_PROFILES.contains(&p) => true,
                            Some(p) => {
                                return Err(ManifestError::Invalid(format!("agent.acp.profile {p:?}: known profiles are {ACP_PROFILES:?}")))
                            }
                        };
                        if a.remote.is_some() {
                            return Err(ManifestError::Invalid("agent.remote: an ACP agent has no remote session of its own".into()));
                        }
                        if a.max_turns.is_some() {
                            return Err(ManifestError::Invalid(
                                "agent.max_turns isn't part of ACP; set it in the agent's own configuration".into(),
                            ));
                        }
                        if !claude && (a.model.is_some() || !a.adapter_settings.is_empty()) {
                            return Err(ManifestError::Invalid(
                                "agent.model and agent.adapter_settings need an ACP profile wicket knows; set them in the agent's own configuration".into(),
                            ));
                        }
                    }
                }
                // The zone's model route is a Claude subscription, which backs Claude Code only (its
                // own CLI, or through its ACP adapter). A generic ACP agent gets no model route until
                // routes per provider exist (#174).
                let claude =
                    a.harness == Harness::ClaudeCode || a.acp.as_ref().and_then(|p| p.profile.as_deref()) == Some("claude-agent-acp");
                match &self.zone.llm {
                    Some(_) if !claude => {
                        return Err(ManifestError::Invalid(
                            "zone.llm: a generic ACP agent gets no model route yet. The zone's llm is a Claude subscription, which only Claude Code may use; \
                             leave llm out (routes per provider are #174)"
                                .into(),
                        ))
                    }
                    Some(l) if l.provider == "anthropic" => {}
                    Some(_) => return Err(ManifestError::Invalid("only the anthropic LLM provider is supported in the PoC".into())),
                    None if claude => return Err(ManifestError::Invalid("an agent zone needs an llm section".into())),
                    None => {}
                }
                if a.image.as_deref().is_some_and(|i| i.trim().is_empty()) {
                    return Err(ManifestError::Invalid("agent.image is empty: name an image, or leave it out for the default".into()));
                }
                match &a.remote {
                    Some(r) => {
                        let ok = !r.name.trim().is_empty()
                            && r.name.len() <= 64
                            && r.name.chars().all(|c| c.is_ascii_alphanumeric() || " -_.".contains(c));
                        if !ok {
                            return Err(ManifestError::Invalid("agent.remote.name: 1-64 letters, digits, spaces, '-', '_' or '.'".into()));
                        }
                    }
                    None if self.task.trim().is_empty() => {
                        return Err(ManifestError::Invalid("task is empty (only an agent.remote session may leave it out)".into()))
                    }
                    None => {}
                }
                if let Some(k) = a.adapter_settings.keys().find(|k| ADAPTER_SETTINGS_OWNED.contains(&k.as_str())) {
                    return Err(ManifestError::Invalid(format!(
                        "agent.adapter_settings may not set {k:?}: wicket sets it, so a long-lived agent keeps its sessions"
                    )));
                }
                if let Some(k) = a.adapter_settings.keys().find(|k| !ADAPTER_SETTINGS_ALLOWED.contains(&k.as_str())) {
                    return Err(ManifestError::Invalid(format!(
                        "agent.adapter_settings may not set {k:?} (allowed: {})",
                        ADAPTER_SETTINGS_ALLOWED.join(", ")
                    )));
                }
                for k in a.env.keys() {
                    let ok = !k.is_empty() && k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
                    if !ok || RESERVED_ENV_PREFIXES.iter().any(|p| k.starts_with(p)) || ["HOME", "PATH", "USER"].contains(&k.as_str()) {
                        return Err(ManifestError::Invalid(format!("agent.env may not set {k:?}: wicket controls it")));
                    }
                }
            }
            (None, Some(p)) => {
                if p.command.is_empty() {
                    return Err(ManifestError::Invalid("program.command is empty".into()));
                }
                if self.zone.llm.is_some() {
                    return Err(ManifestError::Invalid("a program zone has no model: remove the llm section".into()));
                }
            }
            _ => return Err(ManifestError::Invalid("a manifest names exactly one of agent or program".into())),
        }
        for r in &self.zone.reach {
            if r.host.is_empty() || r.host.contains('/') {
                return Err(ManifestError::Invalid(format!("bad reach host {:?}", r.host)));
            }
            for p in &r.paths {
                compile_glob(p)?;
            }
        }
        for f in &self.zone.forbid {
            if f.host.is_empty() || f.host.contains('/') {
                return Err(ManifestError::Invalid(format!("bad forbid host {:?}", f.host)));
            }
            for p in &f.paths {
                compile_glob(p)?;
            }
        }
        for i in &self.zone.inject {
            if !i.format.contains("{secret}") && !i.format.contains("{basic:") {
                return Err(ManifestError::Invalid(format!("inject format for {} lacks {{secret}} or {{basic:USER}}", i.host)));
            }
        }
        let mut names = std::collections::HashSet::new();
        for v in &self.zone.volumes {
            let name_ok = !v.name.is_empty() && v.name.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-');
            let path_ok = v.path.starts_with("/volumes/") && !v.path.contains("..") && v.path.len() > "/volumes/".len();
            if !name_ok || !path_ok || !names.insert(v.name.clone()) {
                return Err(ManifestError::Invalid(format!(
                    "volume {:?} at {:?}: names are [a-z0-9-]+ and unique; paths live under /volumes/",
                    v.name, v.path
                )));
            }
        }
        self.zone.limits.check()?;
        Ok(())
    }
}

pub(crate) fn compile_glob(p: &str) -> Result<GlobMatcher, ManifestError> {
    GlobBuilder::new(p)
        .literal_separator(true)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| ManifestError::Glob { glob: p.to_string(), err: e.to_string() })
}

/// A glob that matches what `glob` matches, ignoring ASCII case: every ASCII letter `x` becomes the
/// class `[xX]`, and every class gets its letters' other case added. Forbid globs are compiled from
/// this, here and in the Biscuit ceiling (wicket-authz), so both match byte for byte the same paths
/// (a regex case flag would fold non-ASCII characters differently in the two).
pub fn fold_case_glob(glob: &str) -> String {
    let swap = |c: char| if c.is_ascii_lowercase() { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
    let mut out = String::with_capacity(glob.len() * 2);
    let mut chars = glob.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(n) if n.is_ascii_alphabetic() => out.push_str(&format!("[{n}{}]", swap(n))),
                Some(n) => {
                    out.push('\\');
                    out.push(n);
                }
                None => out.push('\\'),
            },
            '[' => {
                // A class: `[` then an optional `!`/`^`, then up to the first `]` after one char.
                let mut body = String::new();
                if let Some(&neg @ ('!' | '^')) = chars.peek() {
                    out.push('[');
                    out.push(neg);
                    chars.next();
                } else {
                    out.push('[');
                }
                let mut closed = false;
                for n in chars.by_ref() {
                    if n == ']' && !body.is_empty() {
                        closed = true;
                        break;
                    }
                    body.push(n);
                }
                if !closed {
                    out.push_str(&body);
                } else {
                    // The other case of each letter and letter range (`a-z` gains `A-Z`), put right
                    // after a leading `]` or `-` (literals there), so it never joins another range.
                    let b: Vec<char> = body.chars().collect();
                    let mut extra = String::new();
                    let mut i = 0;
                    while i < b.len() {
                        if i + 2 < b.len() && b[i + 1] == '-' {
                            if b[i].is_ascii_alphabetic() && b[i + 2].is_ascii_alphabetic() {
                                extra.extend([swap(b[i]), '-', swap(b[i + 2])]);
                            }
                            i += 3;
                        } else {
                            if b[i].is_ascii_alphabetic() {
                                extra.push(swap(b[i]));
                            }
                            i += 1;
                        }
                    }
                    let lead = usize::from(matches!(b.first(), Some(']' | '-')));
                    out.extend(&b[..lead]);
                    out.push_str(&extra);
                    out.extend(&b[lead..]);
                    out.push(']');
                }
            }
            c if c.is_ascii_alphabetic() => out.push_str(&format!("[{c}{}]", swap(c))),
            c => out.push(c),
        }
    }
    out
}

impl ReachRule {
    pub fn host_matches(&self, host: &str) -> bool {
        host_matches(&self.host, host)
    }
}

/// `*.example.com` matches one or more labels under example.com, never example.com itself.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => host == pattern,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #126: a zero limit means no limit to Docker, so a manifest can't set one.
    #[test]
    fn every_limit_is_a_positive_bound() {
        let with =
            |l: &str| Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone: {{ name: z, llm: {{}}, limits: {{ {l} }} }}\n"));
        assert!(with("memory: 1g, cpus: 0.5, pids: 64").is_ok());
        for bad in ["memory: \"0\"", "memory: 0g", "memory: lots", "cpus: 0", "cpus: -1", "cpus: .nan", "pids: 0", "timeout: 0s"] {
            assert!(with(bad).is_err(), "{bad} was accepted");
        }
    }

    /// #20: a zone may forbid wildcard reach rules; one that does and has one is refused, at load
    /// and when compiled (a spawned zone is compiled, not loaded from a manifest).
    #[test]
    fn a_zone_forbidding_wildcards_refuses_wildcard_reach() {
        let with = |z: &str| Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone: {{ name: z, llm: {{}}, {z} }}\n"));
        let wild = "reach: [{ host: api.example.com }, { host: '*.cdn.example' }]";
        let e = with(&format!("wildcards: {{ forbid: true }}, {wild}")).unwrap_err().to_string();
        assert!(e.contains("*.cdn.example is a wildcard"), "{e}");
        // Forbid rules may still use wildcards: they only narrow.
        assert!(with("wildcards: { forbid: true }, reach: [{ host: api.example.com }], forbid: [{ host: '*.example.com' }]").is_ok());
        let m = with(wild).unwrap();
        assert_eq!(m.zone.wildcards, WildcardSpec::default());
        assert_eq!(m.zone.wildcard_reach(), ["*.cdn.example"]);
        assert_eq!(m.zone.wildcard_for("a.b.cdn.example"), Some("*.cdn.example"));
        assert_eq!(m.zone.wildcard_for("api.example.com"), None);
        assert!(with("wildcards: { max_names: 0 }").is_err());
        let mut z = m.zone;
        z.wildcards.forbid = true;
        assert!(crate::CompiledZone::new(z).is_err(), "compiled zones are checked too");
    }

    const EXAMPLE: &str = r#"
task: summarise the README
agent: { name: summariser }
zone:
  name: research
  reach:
    - { host: api.github.com, paths: ["/repos/octocat/Hello-World/**"] }
  llm: {}
"#;

    #[test]
    fn parses_example_with_defaults() {
        let m = Manifest::from_yaml(EXAMPLE).unwrap();
        assert_eq!(m.tenant, TenantId::single());
        assert_eq!(m.zone.isolation, Isolation::Gvisor);
        assert_eq!(m.zone.reach[0].methods, vec!["GET", "HEAD"]);
        assert_eq!(m.zone.llm.as_ref().unwrap().upstream, "https://api.anthropic.com");
    }

    #[test]
    fn programs_have_no_model_and_fail_on_pending_by_default() {
        let m = Manifest::from_yaml("task: t\nprogram: {name: p, command: [bash, run.sh]}\nzone: {name: z}").unwrap();
        assert_eq!(m.program.unwrap().on_pending, OnPending::Fail);
        assert!(Manifest::from_yaml("task: t\nprogram: {name: p, command: [x]}\nzone: {name: z, llm: {}}").is_err());
        assert!(Manifest::from_yaml("task: t\nzone: {name: z}").is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = EXAMPLE.replace("name: research", "name: research\n  surprise: 1");
        assert!(Manifest::from_yaml(&bad).is_err());
    }

    #[test]
    fn env_and_volumes_are_validated() {
        let base = |extra: &str| format!("task: t\nagent: {{ name: a{extra} }}\nzone: {{ name: z, llm: {{}} }}\n");
        assert!(Manifest::from_yaml(&base(", env: { DATA_DIR: /volumes/data }")).is_ok());
        for bad in ["HTTPS_PROXY", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN", "SSL_CERT_FILE", "HOME", "lower"] {
            assert!(Manifest::from_yaml(&base(&format!(", env: {{ {bad}: x }}"))).is_err(), "{bad} must be refused");
        }
        // The harness decides its lifetime (#249): wicket has no turn timers to set.
        assert!(Manifest::from_yaml(&base(", idle_timeout: 30m")).is_err());
        assert!(Manifest::from_yaml(&base(", hibernate_after: 10m")).is_err());
        assert!(Manifest::from_yaml(&base(", adapter_settings: { includeCoAuthoredBy: false }")).is_ok());
        for bad in ["hooks", "permissions", "apiKeyHelper", "env", "mcpServers"] {
            assert!(Manifest::from_yaml(&base(&format!(", adapter_settings: {{ {bad}: {{}} }}"))).is_err(), "{bad} must be refused");
        }
        let e = Manifest::from_yaml(&base(", adapter_settings: { cleanupPeriodDays: 1 }")).unwrap_err().to_string();
        assert!(e.contains("cleanupPeriodDays") && e.contains("wicket sets it"), "{e}");
        let vol = |v: &str| format!("task: t\nagent: {{ name: a }}\nzone: {{ name: z, llm: {{}}, volumes: [{v}] }}\n");
        assert!(Manifest::from_yaml(&vol("{ name: data, path: /volumes/data }")).is_ok());
        let m = Manifest::from_yaml(&vol("{ name: data, path: /volumes/data, persist: durable }")).unwrap();
        assert_eq!(m.zone.volumes[0].persist, Persist::Durable);
        assert_eq!(Manifest::from_yaml(&vol("{ name: data, path: /volumes/data }")).unwrap().zone.volumes[0].persist, Persist::Node);
        assert!(Manifest::from_yaml(&vol("{ name: data, path: /volumes/data, persist: forever }")).is_err());
        assert!(Manifest::from_yaml(&vol("{ name: data, path: /workspace/x }")).is_err());
        assert!(Manifest::from_yaml(&vol("{ name: data, path: /volumes/../etc }")).is_err());
        assert!(Manifest::from_yaml(&vol("{ name: a, path: /volumes/a }, { name: a, path: /volumes/b }")).is_err());
    }

    #[test]
    fn agent_env_may_not_set_path_or_user() {
        for name in ["PATH", "USER"] {
            let y = format!("task: t\nagent: {{ name: a, env: {{ {name}: x }} }}\nzone: {{ name: z, llm: {{}} }}\n");
            let err = Manifest::from_yaml(&y).unwrap_err().to_string();
            assert!(err.contains("agent.env may not set"), "{name}: {err}");
        }
    }

    #[test]
    fn the_harness_is_agent_harness() {
        let y = |agent: &str| Manifest::from_yaml(&format!("task: t\nagent: {{ name: a{agent} }}\nzone: {{ name: z, llm: {{}} }}\n"));
        assert_eq!(y("").unwrap().agent.unwrap().harness, Harness::ClaudeCode);
        assert_eq!(y(", harness: claude-code").unwrap().agent.unwrap().harness, Harness::ClaudeCode);
        assert!(y(", harness: nope").unwrap_err().to_string().contains("unknown variant"));
        // `kind` is spawn's word for a workload (agent or program), not a manifest field.
        assert!(y(", kind: claude-code").unwrap_err().to_string().contains("unknown field `kind`"));
        let plain = serde_yaml::to_string(&y("").unwrap()).unwrap();
        assert!(plain.contains("harness: claude-code"), "{plain}");
    }

    #[test]
    fn wildcard_hosts() {
        assert!(host_matches("*.githubusercontent.com", "raw.githubusercontent.com"));
        assert!(!host_matches("*.githubusercontent.com", "githubusercontent.com"));
        assert!(!host_matches("*.githubusercontent.com", "evilgithubusercontent.com"));
        assert!(host_matches("api.github.com", "API.GitHub.com."));
    }

    fn m_mode(y: &dyn Fn(&str) -> Result<Manifest, ManifestError>, extra: &str) -> Result<RemotePermissionMode, ManifestError> {
        Ok(y(&format!(", remote: {{ name: x{extra} }}"))?.agent.unwrap().remote.unwrap().permission_mode)
    }

    #[test]
    fn a_remote_session_needs_no_task_but_a_good_name() {
        let y = |agent: &str| Manifest::from_yaml(&format!("agent: {{ name: a{agent} }}\nzone: {{ name: z, llm: {{}} }}\n"));
        let m = y(", remote: { name: my box }").unwrap();
        assert_eq!(m.agent.unwrap().remote.unwrap().name, "my box");
        assert!(y("").unwrap_err().to_string().contains("task is empty"));
        assert!(y(", remote: { name: '' }").is_err());
        assert!(y(", remote: { name: 'a/b' }").is_err());
        assert!(y(", remote: { name: x, mode: y }").is_err(), "unknown fields");
        assert_eq!(m_mode(&y, "").unwrap(), RemotePermissionMode::Default);
        assert_eq!(m_mode(&y, ", permission_mode: bypassPermissions").unwrap(), RemotePermissionMode::BypassPermissions);
        for mode in RemotePermissionMode::ALL {
            assert_eq!(m_mode(&y, &format!(", permission_mode: {mode}")).unwrap(), mode);
        }
        let e = y(", remote: { name: x, permission_mode: yolo }").unwrap_err().to_string();
        assert!(e.contains("unknown variant `yolo`"), "{e}");
        assert!(y(", remote: { name: x, permission_mode: BypassPermissions }").is_err(), "spelled as the CLI takes it");
        // A default mode isn't written out, so a remote manifest's digest is unchanged.
        let rc = serde_yaml::to_string(&y(", remote: { name: x, permission_mode: default }").unwrap()).unwrap();
        assert!(!rc.contains("permission_mode"), "{rc}");
        let rc = serde_yaml::to_string(&y(", remote: { name: x, permission_mode: plan }").unwrap()).unwrap();
        assert!(rc.contains("permission_mode: plan"), "{rc}");
        // Other manifests serialize as before (their identity digests don't change).
        let plain = Manifest::from_yaml("task: t\nagent: { name: a }\nzone: { name: z, llm: {} }\n").unwrap();
        assert!(!serde_yaml::to_string(&plain).unwrap().contains("remote"));
    }
}
