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

#[derive(Clone, Debug, Deserialize)]
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

/// As derived, except that a program's zone always writes its `escalation`: a program's default is
/// `request: false` (#255), so a `request: true` left out as the zone's default would read back as
/// false.
impl Serialize for Manifest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Out<'a> {
            tenant: &'a TenantId,
            task: &'a String,
            agent: &'a Option<AgentSpec>,
            program: &'a Option<ProgramSpec>,
            zone: ZoneOut<'a>,
        }
        #[derive(Serialize)]
        struct ZoneOut<'a> {
            #[serde(flatten)]
            zone: &'a ZoneSpec,
            #[serde(skip_serializing_if = "Option::is_none")]
            escalation: Option<&'a Escalation>,
        }
        let escalation = (self.program.is_some() && self.zone.escalation.is_default()).then_some(&self.zone.escalation);
        Out {
            tenant: &self.tenant,
            task: &self.task,
            agent: &self.agent,
            program: &self.program,
            zone: ZoneOut { zone: &self.zone, escalation },
        }
        .serialize(s)
    }
}

/// A deterministic workload: an agent with no model, in the same sandbox under the same enforcement
/// (design §17). Its zone may not ask for more unless it says so (`escalation.request` defaults to
/// false for a program, #255).
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
    /// Runtime image (default: the agent image, which has bash, curl, jq, git, python3).
    #[serde(default)]
    pub image: Option<String>,
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
    /// How many child agents this agent may start with `spawn_agent`, each in its own box with
    /// its own identity (design §3.2, §5.1). 0 = none.
    #[serde(default)]
    pub max_children: u32,
    /// Whether the agent may also run its own in-box subagents (its harness's own, e.g. an Agent tool). Their
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
    /// The profiles are the harness adapter's (`wicket-agent`). None: a generic ACP agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// `agent.remote`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSpec {
    /// The session's name in the vendor's apps.
    pub name: String,
    /// How far the harness acts without asking (#285). Whatever the mode, wicket's proxies decide
    /// what the box can reach. Unset: `default` (ask in the app before acting) for a session the
    /// owner drives, `bypassPermissions` for one wicket drives (`drive`), as in any driven box.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<RemotePermissionMode>,
    /// wicket drives the session too (#285 part 2): it starts the harness as in a driven box and
    /// gives it the manifest's task, follow-ups and messages, and the session is also registered
    /// with the vendor's apps, where the owner watches it and can send it messages. Needs a task.
    /// Left out when false, so manifests that don't set it serialize as before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub drive: bool,
}

impl RemoteSpec {
    /// The permission mode the session runs in: the manifest's, or its mode's default.
    pub fn permission_mode(&self) -> RemotePermissionMode {
        self.permission_mode.unwrap_or(if self.drive { RemotePermissionMode::BypassPermissions } else { RemotePermissionMode::Default })
    }
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
    /// Whether this zone's agents may ask for what is outside their reach, and decide their
    /// descendants' requests within it (#50). Both default on. Written out only when it isn't the
    /// default, so a zone that doesn't use it reads the same to a node that doesn't know it.
    #[serde(default, skip_serializing_if = "Escalation::is_default")]
    pub escalation: Escalation,
}

/// Who may escalate (#50): ask for more, and grant others what this zone may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Escalation {
    /// May raise pending requests (a blocked request, `request_access`, `spawn` with `escalate`,
    /// `request_capacity`, `request_update`). Off: anything outside the zone's reach is "never
    /// allowed" instead of pending.
    #[serde(default = "yes")]
    pub request: bool,
    /// May approve or deny its descendants' requests, only for what its own zone reaches (the
    /// gateway's `decide` tool).
    #[serde(default = "yes")]
    pub grant: bool,
}

impl Default for Escalation {
    fn default() -> Self {
        Escalation { request: true, grant: true }
    }
}

impl Escalation {
    pub fn is_default(&self) -> bool {
        *self == Escalation::default()
    }
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
    /// Kept on the node across runs, shared by the zone's runs (#377). Not kept (the default), it
    /// is the run's own cache: empty when the run starts, and deleted once its work is collected,
    /// or [`Self::retention`] after the run ends if it never is.
    #[serde(default)]
    pub keep: bool,
    /// For a kept volume, how long it may go unused before the node deletes it (none: never); for
    /// a run's cache, how long after the run ends it is kept if the run's work isn't collected
    /// (default [`CACHE_RETENTION`]). A duration: `12h`, `7d`.
    #[serde(default)]
    pub retention: Option<String>,
}

/// How long after its run ends a run's cache volume is kept if the run's work is never collected.
pub const CACHE_RETENTION: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

impl VolumeSpec {
    /// [`Self::retention`] as a duration: a kept volume's (None: kept forever), or a cache's (its
    /// default if unset).
    pub fn retention(&self) -> Result<Option<std::time::Duration>, ManifestError> {
        match &self.retention {
            Some(r) => humantime::parse_duration(r).map(Some).map_err(|_| ManifestError::Duration(r.clone())),
            None if self.keep => Ok(None),
            None => Ok(Some(CACHE_RETENTION)),
        }
    }
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
    /// The model provider (the model proxy's profile for its API). Empty: the harness's own, filled
    /// in by its adapter when the manifest is loaded ([`LlmSpec::fill`]).
    #[serde(default)]
    pub provider: String,
    /// Vault secret holding the model credential. Empty: the harness's own default secret.
    #[serde(default)]
    pub secret: String,
    /// Upstream base URL (override for a mock in tests). Empty: the harness's provider's.
    #[serde(default)]
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
    /// The models a box may call (#366): each an exact name (`claude-opus-4-5`) or a prefix ending
    /// in `*` (`claude-sonnet-*`). The model proxy refuses a call naming any other, or none. Left
    /// out: any model the credential reaches. A zone a box starts may only narrow it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<String>>,
}

/// A harness's default model route: what its adapter fills into a zone's `llm` where the manifest
/// leaves a field out. Core and the proxies take it as data; only the adapter knows its values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRoute {
    pub provider: String,
    pub secret: String,
    pub upstream: String,
}

impl LlmSpec {
    /// Fills the route's fields the manifest left empty from the harness's default.
    pub fn fill(&mut self, route: &ModelRoute) {
        for (field, default) in
            [(&mut self.provider, &route.provider), (&mut self.secret, &route.secret), (&mut self.upstream, &route.upstream)]
        {
            if field.trim().is_empty() {
                *field = default.clone();
            }
        }
    }

    /// The first route field still empty, if any: a run needs all three.
    pub fn missing(&self) -> Option<&'static str> {
        [("provider", &self.provider), ("secret", &self.secret), ("upstream", &self.upstream)]
            .into_iter()
            .find(|(_, v)| v.trim().is_empty())
            .map(|(k, _)| k)
    }
}

impl LlmSpec {
    /// Whether the zone lets a box call `model` ([`LlmSpec::models`]).
    pub fn allows_model(&self, model: &str) -> bool {
        self.models.as_ref().is_none_or(|ms| ms.iter().any(|m| model_covers(m, model)))
    }

    /// Whether every entry of `models` is a model name or a prefix ending in its only `*`.
    pub fn check_models(&self) -> Result<(), ManifestError> {
        for m in self.models.iter().flatten() {
            let name = m.strip_suffix('*').unwrap_or(m);
            let ok = !m.is_empty()
                && m.len() <= 128
                && !name.contains('*')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:@/".contains(c));
            if !ok {
                return Err(ManifestError::Invalid(format!(
                    "zone.llm.models: {m:?} is neither a model name nor a prefix ending in '*' (letters, digits, '-', '_', '.', ':', '@', '/')"
                )));
            }
        }
        Ok(())
    }
}

/// Whether model pattern `pattern` (a name, or a prefix ending in `*`) covers `other`: a model
/// name, or a pattern of its own, for which it covers every name `other` covers.
pub fn model_covers(pattern: &str, other: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => other.starts_with(prefix),
        None => pattern == other,
    }
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
    /// How long the harness has to exit by itself once its session is over (#293): after the agent
    /// asked to `finish` and its session closed, or when it asked to hibernate and other processes
    /// still run in the box. Then wicket stops what is left. Default 30 s.
    /// (Left out when it is the default, so a node of an earlier version reads the manifest.)
    #[serde(default = "default_exit_grace", skip_serializing_if = "is_default_exit_grace")]
    pub exit_grace: String,
    /// Advice for this zone's work, appended to the warning its agent gets near its memory limit
    /// (#348): operator text from the manifest, one line of at most [`MEMORY_ADVICE_MAX`]
    /// characters ("for example CARGO_BUILD_JOBS=1, `make -j1`"). A spawned zone inherits it, and
    /// may replace it (empty: none). (Left out when unset, so a node of an earlier version reads
    /// the manifest.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_advice: Option<String>,
}

/// The longest `limits.memory_advice`, in characters.
pub const MEMORY_ADVICE_MAX: usize = 300;

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
            exit_grace: default_exit_grace(),
            memory_advice: None,
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
fn default_exit_grace() -> String {
    "30s".into()
}
fn is_default_exit_grace(g: &String) -> bool {
    *g == default_exit_grace()
}
fn default_pids() -> u32 {
    512
}

impl Limits {
    pub fn timeout(&self) -> Result<Duration, ManifestError> {
        humantime::parse_duration(&self.timeout).map_err(|_| ManifestError::Duration(self.timeout.clone()))
    }

    /// [`Limits::exit_grace`], read.
    pub fn exit_grace(&self) -> Result<Duration, ManifestError> {
        humantime::parse_duration(&self.exit_grace).map_err(|_| ManifestError::Duration(self.exit_grace.clone()))
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

    /// [`Limits::memory_advice`], if set and not empty.
    pub fn memory_advice(&self) -> Option<&str> {
        self.memory_advice.as_deref().map(str::trim).filter(|a| !a.is_empty())
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
        if let Some(a) = &self.memory_advice {
            if a.chars().count() > MEMORY_ADVICE_MAX || a.chars().any(char::is_control) {
                return Err(ManifestError::Invalid(format!(
                    "limits.memory_advice: one line of at most {MEMORY_ADVICE_MAX} characters, without control characters"
                )));
            }
        }
        Ok(())
    }
}

/// The smallest CPU limit Docker takes (`--cpus 0.01`).
pub const MIN_CPUS: f32 = 0.01;

impl Manifest {
    /// Parses and checks a manifest. A program's zone may not ask for more unless the manifest says
    /// `escalation.request: true` (#255). The model route's defaults are the harness adapter's: load
    /// an agent's manifest through `wicket_agent::load` to fill them.
    pub fn from_yaml(s: &str) -> Result<Self, ManifestError> {
        let mut m: Manifest = serde_yaml::from_str(s)?;
        if m.program.is_some() {
            #[derive(Deserialize)]
            struct Probe {
                zone: ProbeZone,
            }
            #[derive(Deserialize)]
            struct ProbeZone {
                #[serde(default)]
                escalation: Option<ProbeEscalation>,
            }
            #[derive(Deserialize)]
            struct ProbeEscalation {
                #[serde(default)]
                request: Option<bool>,
            }
            let said = serde_yaml::from_str::<Probe>(s)?.zone.escalation.and_then(|e| e.request);
            m.zone.escalation.request = said.unwrap_or(false);
        }
        m.validate()?;
        Ok(m)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        self.zone.limits.authority()?;
        self.zone.limits.exit_grace()?;
        self.zone.check_wildcards()?;
        self.zone.llm.as_ref().map_or(Ok(()), LlmSpec::check_models)?;
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
                        if a.remote.is_some() {
                            return Err(ManifestError::Invalid(
                                "agent.remote: an ACP agent has no Remote Control session of its own".into(),
                            ));
                        }
                        if a.max_turns.is_some() {
                            return Err(ManifestError::Invalid(
                                "agent.max_turns isn't part of ACP; set it in the agent's own configuration".into(),
                            ));
                        }
                    }
                }
                // Whether the agent's harness takes a model route (`zone.llm`), its default route, and
                // which ACP profiles exist are its adapter's: `wicket_agent::load` checks them.
                if let (Some(m), Some(l)) = (&a.model, &self.zone.llm) {
                    if !l.allows_model(m) {
                        return Err(ManifestError::Invalid(format!(
                            "agent.model {m:?} is not in zone.llm.models ({}): every call it made would be refused",
                            l.models.as_deref().unwrap_or_default().join(", ")
                        )));
                    }
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
                        if r.drive && self.task.trim().is_empty() {
                            return Err(ManifestError::Invalid(
                                "task is empty: agent.remote.drive gives the session the manifest's task, so it needs one".into(),
                            ));
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
            v.retention()?;
            if v.keep && v.persist == Persist::Durable {
                return Err(ManifestError::Invalid(format!(
                    "volume {:?}: a durable volume is the agent's own and goes with its state; `keep` is for volumes the node keeps",
                    v.name
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
                    // The other case of each letter, and of the letters inside each range (`a-z`
                    // gains `A-Z`; a mixed range such as `0-z` or `a-~` gains the other case of the
                    // letters it holds), put right after a leading `]` or `-` (literals there), so it
                    // never joins another range.
                    let b: Vec<char> = body.chars().collect();
                    let mut extra = String::new();
                    let mut i = 0;
                    while i < b.len() {
                        if i + 2 < b.len() && b[i + 1] == '-' {
                            fold_range(b[i], b[i + 2], &mut extra);
                            i += 3;
                        } else {
                            if b[i].is_ascii_alphabetic() {
                                extra.push(swap(b[i]));
                            }
                            i += 1;
                        }
                    }
                    // What stays first: a leading `]` or `-` (a literal only there), and the whole
                    // range if it starts one (`--a`, `]-a`): the folded spelling of every other class
                    // is what it always was.
                    let lead = match b.first() {
                        Some(']' | '-') if b.len() > 2 && b[1] == '-' => 3,
                        Some(']' | '-') => 1,
                        _ => 0,
                    };
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

/// Adds to `extra` the other case of the ASCII letters in the class range `lo-hi`: the lowercase
/// letters it holds, as capitals, and the capitals it holds, as lowercase. Nothing for a reversed
/// range (which globset refuses anyway) or one without letters.
fn fold_range(lo: char, hi: char, extra: &mut String) {
    for (first, last) in [('a', 'z'), ('A', 'Z')] {
        let (from, to) = (lo.max(first), hi.min(last));
        if from <= to {
            let swap = |c: char| if c.is_ascii_lowercase() { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
            if from == to {
                extra.push(swap(from));
            } else {
                extra.extend([swap(from), '-', swap(to)]);
            }
        }
    }
}

impl ReachRule {
    pub fn host_matches(&self, host: &str) -> bool {
        host_matches(&self.host, host)
    }
}

/// `*.example.com` matches one or more labels under example.com, never example.com itself. ASCII
/// case is ignored, as is a trailing dot on the host. Allocation-free, so the Kani harnesses (#325,
/// `proofs/host.rs`) check this function itself.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let mut host = host.as_bytes();
    while let [rest @ .., b'.'] = host {
        host = rest;
    }
    match pattern.as_bytes().strip_prefix(b"*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && label_under(host, suffix),
        None => host.eq_ignore_ascii_case(pattern.as_bytes()),
    }
}

/// Whether `name` ends with `.` and then `suffix`, ignoring ASCII case: `name` is `suffix` with at
/// least one more label (possibly empty) in front.
pub(crate) fn label_under(name: &[u8], suffix: &[u8]) -> bool {
    let Some(at) = name.len().checked_sub(suffix.len() + 1) else { return false };
    name[at] == b'.' && name[at + 1..].eq_ignore_ascii_case(suffix)
}

#[cfg(test)]
mod tests {

    /// #326: a class's ranges are folded as ranges and its other letters one by one; a `-` at the
    /// end of a class is a literal, never the start of a range past it.
    #[test]
    fn folded_classes_keep_their_ranges_and_their_letters() {
        let m = |g: &str| compile_glob(&fold_case_glob(g)).unwrap();
        let ends_in_dash = m("/[a-]");
        for p in ["/a", "/A", "/-"] {
            assert!(ends_in_dash.is_match(p), "/[a-] matches {p}");
        }
        assert!(!ends_in_dash.is_match("/b"));
        let letters = m("/[axz]");
        assert!(letters.is_match("/X") && letters.is_match("/z"));
        assert!(!letters.is_match("/M") && !letters.is_match("/m"), "three letters, not the range a-z");
        let mixed = m("/[xa-c-]");
        for p in ["/X", "/B", "/-"] {
            assert!(mixed.is_match(p), "/[xa-c-] matches {p}");
        }
        assert!(!mixed.is_match("/d"));
    }

    /// #326: a zone names a host by a reach rule or an inject rule, exactly or by wildcard; a host
    /// named exactly isn't reached through a wildcard.
    #[test]
    fn a_zone_names_its_hosts_by_reach_or_inject() {
        let z: ZoneSpec = serde_yaml::from_str(
            "name: z\nreach: [{ host: \"*.example.com\" }, { host: api.example.com }]\ninject: [{ host: up.other.org, header: X, secret: s }]\n",
        )
        .unwrap();
        assert!(z.names_host("api.example.com") && z.names_host("x.example.com"), "by reach");
        assert!(z.names_host("up.other.org"), "by inject alone");
        assert!(!z.names_host("other.org") && !z.names_host("example.org"));
        assert_eq!(z.wildcard_for("x.example.com"), Some("*.example.com"));
        assert_eq!(z.wildcard_for("api.example.com"), None, "named exactly");
        assert_eq!(z.wildcard_for("other.org"), None);
    }

    /// A folded glob matches a path exactly when the glob matches it in some ASCII case (the Lean
    /// spec's `ciEq`, which it states for globs without classes), and a folded negated class matches
    /// only what it excludes in neither case (the closure of the class is negated, so a forbid rule
    /// written with one never forbids less than either spelling says): checked here for one-character
    /// classes, exhaustively over printable ASCII, for every class body from a small alphabet of
    /// letters of both cases, the punctuation around them in ASCII, and the class's own `-`, `]`,
    /// `!` and `^`. Mixed ranges (a letter to a non-letter, or across cases) gain exactly the
    /// other case of the letters inside them.
    #[test]
    fn a_folded_class_matches_a_character_in_either_case_and_nothing_else() {
        let alphabet = ['a', 'c', 'z', 'A', 'C', 'Z', '-', '~', '0', '_', '`', '@', '[', ']', '!', '^'];
        let swap = |c: char| if c.is_ascii_lowercase() { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
        let mut bodies: Vec<String> = alphabet.iter().map(|c| c.to_string()).collect();
        for _ in 0..2 {
            let more: Vec<String> = bodies.iter().flat_map(|b| alphabet.iter().map(move |c| format!("{b}{c}"))).collect();
            bodies.extend(more);
        }
        let (mut checked, mut wrong) = (0, vec![]);
        for body in &bodies {
            let glob = format!("/[{body}]");
            // Only classes globset reads (a reversed range like `z-a` is an error either way).
            let Ok(plain) = compile_glob(&glob) else { continue };
            let folded = match compile_glob(&fold_case_glob(&glob)) {
                Ok(m) => m,
                Err(e) => {
                    wrong.push(format!("{glob}: folded to {} which doesn't compile: {e}", fold_case_glob(&glob)));
                    continue;
                }
            };
            checked += 1;
            for c in (0x20u8..0x7f).map(char::from).filter(|c| *c != '/') {
                let path = format!("/{c}");
                // A class matches in either case; a negated one, only what it doesn't exclude in either.
                let negated = body.starts_with(['!', '^']);
                let other = plain.is_match(format!("/{}", swap(c)));
                let want = if negated { plain.is_match(&path) && other } else { plain.is_match(&path) || other };
                if folded.is_match(&path) != want {
                    wrong.push(format!(
                        "{glob} folded to {}: {path:?} should {}match",
                        fold_case_glob(&glob),
                        if want { "" } else { "not " }
                    ));
                }
            }
        }
        assert!(checked > 1000, "only {checked} classes checked");
        assert!(wrong.is_empty(), "{} wrong, such as:\n{}", wrong.len(), wrong.iter().take(12).cloned().collect::<Vec<_>>().join("\n"));
    }

    /// The ranges #326's mutation testing found, by name.
    #[test]
    fn mixed_ranges_fold_the_letters_inside_them() {
        let m = |g: &str| compile_glob(&fold_case_glob(g)).unwrap();
        // A letter to a non-letter: a-z inside, so A-Z too.
        let r = m("/[a-~]");
        assert!(r.is_match("/b") && r.is_match("/B") && r.is_match("/~") && !r.is_match("/@"));
        // A non-letter to a letter, from below the capitals: 0-Z holds A-Z, so a-z too.
        let r = m("/x[0-Z]");
        assert!(r.is_match("/X5") && r.is_match("/xq") && r.is_match("/XQ") && !r.is_match("/x_"));
        // Across the cases: A-z (A-Z, [\]^_`, a-z).
        let r = m("/[A-z]");
        assert!(r.is_match("/q") && r.is_match("/Q") && r.is_match("/_") && !r.is_match("/~"));
        // Part of the letters: Z-a holds Z and a (and [\]^_`), so z and A.
        let r = m("/[Z-a]");
        assert!(r.is_match("/z") && r.is_match("/A") && !r.is_match("/b") && !r.is_match("/Y"));
        // A trailing dash is a literal, and stays one.
        let r = m("/[a-]");
        assert!(r.is_match("/A") && r.is_match("/-") && !r.is_match("/b"));
        let r = m("/[x-]");
        assert!(r.is_match("/X") && r.is_match("/-") && !r.is_match("/y"));
        // A negated mixed range refuses both cases.
        let r = m("/[!a-~]");
        assert!(!r.is_match("/b") && !r.is_match("/B") && r.is_match("/@"));
    }

    use super::*;

    /// #50: both rights default on, and a zone that doesn't restrict them serializes without the
    /// field (the feed carries zones to nodes that refuse unknown fields).
    #[test]
    fn escalation_defaults_on_and_is_written_only_when_restricted() {
        let z: ZoneSpec = serde_yaml::from_str("name: z\n").unwrap();
        assert_eq!(z.escalation, Escalation { request: true, grant: true });
        assert!(!serde_json::to_string(&z).unwrap().contains("escalation"));
        let r: ZoneSpec = serde_yaml::from_str("name: z\nescalation: { request: false }\n").unwrap();
        assert_eq!(r.escalation, Escalation { request: false, grant: true });
        let back: ZoneSpec = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back.escalation, r.escalation);
        assert!(serde_yaml::from_str::<ZoneSpec>("name: z\nescalation: { ask: false }\n").is_err(), "unknown fields refused");
    }

    /// #293: the harness's grace to exit defaults to 30 s, is written only when set otherwise (nodes
    /// of an earlier version refuse unknown fields), and must be a duration.
    #[test]
    fn exit_grace_defaults_to_30s_and_is_written_only_when_set() {
        let with =
            |l: &str| Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone: {{ name: z, llm: {{}}, limits: {{ {l} }} }}\n"));
        let d = with("cpus: 1").unwrap();
        assert_eq!(d.zone.limits.exit_grace().unwrap(), Duration::from_secs(30));
        assert!(!serde_json::to_string(&d.zone.limits).unwrap().contains("exit_grace"));
        let s = with("exit_grace: 5s").unwrap();
        assert_eq!(s.zone.limits.exit_grace().unwrap(), Duration::from_secs(5));
        let back: Limits = serde_json::from_str(&serde_json::to_string(&s.zone.limits).unwrap()).unwrap();
        assert_eq!(back.exit_grace, "5s");
        assert!(with("exit_grace: soon").is_err());
    }

    /// #348: a zone's memory advice is optional, written only when set, one line, and capped.
    #[test]
    fn memory_advice_is_optional_one_line_and_capped() {
        let with =
            |l: &str| Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone: {{ name: z, llm: {{}}, limits: {{ {l} }} }}\n"));
        let d = with("cpus: 1").unwrap();
        assert_eq!(d.zone.limits.memory_advice(), None);
        assert!(!serde_json::to_string(&d.zone.limits).unwrap().contains("memory_advice"));
        let s = with("memory_advice: 'CARGO_BUILD_JOBS=1, `make -j1`'").unwrap();
        assert_eq!(s.zone.limits.memory_advice(), Some("CARGO_BUILD_JOBS=1, `make -j1`"));
        let back: Limits = serde_json::from_str(&serde_json::to_string(&s.zone.limits).unwrap()).unwrap();
        assert_eq!(back.memory_advice, s.zone.limits.memory_advice);
        assert_eq!(with("memory_advice: ''").unwrap().zone.limits.memory_advice(), None, "empty: none");
        assert!(with(&format!("memory_advice: {}", "x".repeat(MEMORY_ADVICE_MAX))).is_ok());
        assert!(with(&format!("memory_advice: {}", "x".repeat(MEMORY_ADVICE_MAX + 1))).is_err(), "capped");
        assert!(with("memory_advice: \"a\\nb\"").is_err(), "one line");
    }

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
        assert_eq!(m.zone.llm.as_ref().unwrap().upstream, "", "the harness adapter fills the route in");
    }

    #[test]
    fn programs_have_no_model_and_may_not_ask_by_default() {
        let m = Manifest::from_yaml("task: t\nprogram: {name: p, command: [bash, run.sh]}\nzone: {name: z}").unwrap();
        assert!(!m.zone.escalation.request && m.zone.escalation.grant);
        let back = Manifest::from_yaml(&serde_yaml::to_string(&m).unwrap()).unwrap();
        assert!(!back.zone.escalation.request, "the default survives a round trip");
        let asks = Manifest::from_yaml("task: t\nprogram: {name: p, command: [x]}\nzone: {name: z, escalation: {request: true}}").unwrap();
        assert!(asks.zone.escalation.request);
        let back = Manifest::from_yaml(&serde_yaml::to_string(&asks).unwrap()).unwrap();
        assert!(back.zone.escalation.request, "so does a program's request: true");
        let back = Manifest::from_yaml(&serde_json::to_string(&asks).unwrap()).unwrap();
        assert!(back.zone.escalation.request, "in JSON too");
        let agent = Manifest::from_yaml("task: t\nagent: {name: a}\nzone: {name: z, llm: {}}").unwrap();
        assert!(agent.zone.escalation.request, "an agent's zone asks by default");
        assert!(
            Manifest::from_yaml("task: t\nprogram: {name: p, command: [x], on_pending: wait}\nzone: {name: z}").is_err(),
            "on_pending is gone"
        );
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
        // #377: a volume is the run's cache unless it is kept; each has a retention.
        let v = |y: &str| Manifest::from_yaml(&vol(y)).map(|m| m.zone.volumes[0].clone());
        let cache = v("{ name: data, path: /volumes/data }").unwrap();
        assert!(!cache.keep);
        assert_eq!(cache.retention().unwrap(), Some(CACHE_RETENTION));
        let kept = v("{ name: data, path: /volumes/data, keep: true }").unwrap();
        assert_eq!(kept.retention().unwrap(), None, "kept forever");
        let kept = v("{ name: data, path: /volumes/data, keep: true, retention: 30d }").unwrap();
        assert_eq!(kept.retention().unwrap(), Some(std::time::Duration::from_secs(30 * 86400)));
        assert!(v("{ name: data, path: /volumes/data, retention: soon }").is_err());
        assert!(v("{ name: data, path: /volumes/data, keep: true, persist: durable }").is_err());
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
        Ok(y(&format!(", remote: {{ name: x{extra} }}"))?.agent.unwrap().remote.unwrap().permission_mode())
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
        // An unset mode isn't written out, so a remote manifest's digest is unchanged; a set one is,
        // `default` included (a driven session's default differs).
        let rc = serde_yaml::to_string(&y(", remote: { name: x }").unwrap()).unwrap();
        assert!(!rc.contains("permission_mode") && !rc.contains("drive"), "{rc}");
        let rc = serde_yaml::to_string(&y(", remote: { name: x, permission_mode: default }").unwrap()).unwrap();
        assert!(rc.contains("permission_mode: default"), "{rc}");
        let rc = serde_yaml::to_string(&y(", remote: { name: x, permission_mode: plan }").unwrap()).unwrap();
        assert!(rc.contains("permission_mode: plan"), "{rc}");
        // Other manifests serialize as before (their identity digests don't change).
        let plain = Manifest::from_yaml("task: t\nagent: { name: a }\nzone: { name: z, llm: {} }\n").unwrap();
        assert!(!serde_yaml::to_string(&plain).unwrap().contains("remote"));
    }

    #[test]
    fn a_driven_remote_session_needs_a_task_and_bypasses_permissions_by_default() {
        let y = |task: &str, remote: &str| {
            Manifest::from_yaml(&format!("{task}agent: {{ name: a, remote: {{ name: x{remote} }} }}\nzone: {{ name: z, llm: {{}} }}\n"))
        };
        let e = y("", ", drive: true").unwrap_err().to_string();
        assert!(e.contains("task is empty") && e.contains("agent.remote.drive"), "{e}");
        let m = y("task: t\n", ", drive: true").unwrap();
        let r = m.agent.as_ref().unwrap().remote.as_ref().unwrap();
        assert!(r.drive);
        assert_eq!(r.permission_mode(), RemotePermissionMode::BypassPermissions);
        let r = y("task: t\n", ", drive: true, permission_mode: acceptEdits").unwrap().agent.unwrap().remote.unwrap();
        assert_eq!(r.permission_mode(), RemotePermissionMode::AcceptEdits);
        assert_eq!(y("", "").unwrap().agent.unwrap().remote.unwrap().permission_mode(), RemotePermissionMode::Default);
        assert!(serde_yaml::to_string(&m).unwrap().contains("drive: true"));
    }
}
