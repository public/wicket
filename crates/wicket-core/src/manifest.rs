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
    /// Only `claude-code` in the PoC.
    #[serde(default = "default_agent_kind")]
    pub kind: String,
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
    /// Keep the session open this long after each turn for follow-up messages from the operator
    /// (`wicket say <run> …`). "0s" (default) ends the run when the first task is done.
    #[serde(default = "zero")]
    pub idle_timeout: String,
    /// Long-lived agents (#70): once a turn has ended and `idle_timeout` has passed with no follow-up,
    /// the box is paused (Idle) instead of closed. At `hibernate_after` (from the end of the turn) the
    /// agent is hibernated: its box is stopped, its writable state bundled, and it is woken later by
    /// `wicket wake`, `wicket say` or a message. None (default): the session closes at `idle_timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hibernate_after: Option<String>,
    /// Extra environment for the agent: non-secret configuration only. Variables
    /// wicket controls (proxies, CA, model routes, credentials) can't be set here.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Settings for the agent's own adapter (for claude-code: written to its settings.json), limited
    /// to keys that can't change what the agent can reach or run (ADAPTER_SETTINGS_ALLOWED).
    #[serde(default)]
    pub adapter_settings: serde_json::Map<String, serde_json::Value>,
    /// A remote session (#169): the harness in the box registers its own session with its vendor's
    /// apps, and the owner drives it from there (for `claude-code`, Remote Control). The account
    /// login is the zone's `llm.secret`, which the box only ever holds as a placeholder. Harness
    /// adapters that have no such feature refuse it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteSpec>,
}

/// `agent.remote`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSpec {
    /// The session's name in the vendor's apps.
    pub name: String,
}

/// Adapter settings a manifest may set: presentation and commit metadata only. Hooks, permissions,
/// MCP servers, environment, credential helpers and the like stay under wicket's control.
pub const ADAPTER_SETTINGS_ALLOWED: [&str; 5] = ["includeCoAuthoredBy", "attribution", "outputStyle", "alwaysThinkingEnabled", "language"];

/// Adapter settings wicket sets itself and a manifest may not override. `cleanupPeriodDays`: Claude
/// Code deletes sessions older than it on start, which would erase a long-lived agent's own history
/// when it wakes (#70).
pub const ADAPTER_SETTINGS_OWNED: [&str; 1] = ["cleanupPeriodDays"];

fn zero() -> String {
    "0s".into()
}

/// Environment variables a manifest may not set: wicket's routes, trust and placeholders.
pub const RESERVED_ENV_PREFIXES: [&str; 12] =
    ["ANTHROPIC_", "CLAUDE_", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "SSL_", "CURL_", "NODE_", "MCP_", "GIT_SSL", "WICKET_"];

impl AgentSpec {
    pub fn idle(&self) -> Result<std::time::Duration, ManifestError> {
        humantime::parse_duration(&self.idle_timeout).map_err(|e| ManifestError::Invalid(format!("agent.idle_timeout: {e}")))
    }

    /// When to hibernate after a turn ends, if the agent hibernates at all.
    pub fn hibernate(&self) -> Result<Option<std::time::Duration>, ManifestError> {
        self.hibernate_after
            .as_deref()
            .map(|h| humantime::parse_duration(h).map_err(|e| ManifestError::Invalid(format!("agent.hibernate_after: {e}"))))
            .transpose()
    }
}

fn yes() -> bool {
    true
}

fn default_agent_kind() -> String {
    "claude-code".into()
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
        match (&self.agent, &self.program) {
            (Some(a), None) => {
                if a.kind != "claude-code" {
                    return Err(ManifestError::Invalid(format!("agent kind {:?} not supported in the PoC", a.kind)));
                }
                match &self.zone.llm {
                    Some(l) if l.provider == "anthropic" => {}
                    Some(_) => return Err(ManifestError::Invalid("only the anthropic LLM provider is supported in the PoC".into())),
                    None => return Err(ManifestError::Invalid("an agent zone needs an llm section".into())),
                }
                if a.image.as_deref().is_some_and(|i| i.trim().is_empty()) {
                    return Err(ManifestError::Invalid("agent.image is empty: name an image, or leave it out for the default".into()));
                }
                a.idle()?;
                match &a.remote {
                    Some(r) => {
                        let ok = !r.name.trim().is_empty()
                            && r.name.len() <= 64
                            && r.name.chars().all(|c| c.is_ascii_alphanumeric() || " -_.".contains(c));
                        if !ok {
                            return Err(ManifestError::Invalid("agent.remote.name: 1-64 letters, digits, spaces, '-', '_' or '.'".into()));
                        }
                        if a.hibernate_after.is_some() {
                            return Err(ManifestError::Invalid(
                                "agent.remote can't hibernate: its session lives in the vendor's apps, not in the box (#169)".into(),
                            ));
                        }
                    }
                    None if self.task.trim().is_empty() => {
                        return Err(ManifestError::Invalid("task is empty (only an agent.remote session may leave it out)".into()))
                    }
                    None => {}
                }
                if let Some(h) = a.hibernate()? {
                    if h < a.idle()? {
                        return Err(ManifestError::Invalid("agent.hibernate_after must not be shorter than agent.idle_timeout".into()));
                    }
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
        assert!(Manifest::from_yaml(&base(", idle_timeout: 30m")).is_ok());
        assert!(Manifest::from_yaml(&base(", adapter_settings: { includeCoAuthoredBy: false }")).is_ok());
        for bad in ["hooks", "permissions", "apiKeyHelper", "env", "mcpServers"] {
            assert!(Manifest::from_yaml(&base(&format!(", adapter_settings: {{ {bad}: {{}} }}"))).is_err(), "{bad} must be refused");
        }
        assert!(Manifest::from_yaml(&base(", idle_timeout: soon")).is_err());
        let e = Manifest::from_yaml(&base(", adapter_settings: { cleanupPeriodDays: 1 }")).unwrap_err().to_string();
        assert!(e.contains("cleanupPeriodDays") && e.contains("wicket sets it"), "{e}");
        assert!(Manifest::from_yaml(&base(", idle_timeout: 1m, hibernate_after: 10m")).is_ok());
        assert!(Manifest::from_yaml(&base(", idle_timeout: 10m, hibernate_after: 1m")).is_err());
        assert!(Manifest::from_yaml(&base(", hibernate_after: later")).is_err());
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
    fn wildcard_hosts() {
        assert!(host_matches("*.githubusercontent.com", "raw.githubusercontent.com"));
        assert!(!host_matches("*.githubusercontent.com", "githubusercontent.com"));
        assert!(!host_matches("*.githubusercontent.com", "evilgithubusercontent.com"));
        assert!(host_matches("api.github.com", "API.GitHub.com."));
    }

    #[test]
    fn a_remote_session_needs_no_task_but_a_good_name_and_never_hibernates() {
        let y = |agent: &str| Manifest::from_yaml(&format!("agent: {{ name: a{agent} }}\nzone: {{ name: z, llm: {{}} }}\n"));
        let m = y(", remote: { name: my box }").unwrap();
        assert_eq!(m.agent.unwrap().remote.unwrap().name, "my box");
        assert!(y("").unwrap_err().to_string().contains("task is empty"));
        assert!(y(", remote: { name: '' }").is_err());
        assert!(y(", remote: { name: 'a/b' }").is_err());
        assert!(y(", remote: { name: x, mode: y }").is_err(), "unknown fields");
        assert!(y(", remote: { name: x }, idle_timeout: 1m, hibernate_after: 1h").unwrap_err().to_string().contains("can't hibernate"));
        // Other manifests serialize as before (their identity digests don't change).
        let plain = Manifest::from_yaml("task: t\nagent: { name: a }\nzone: { name: z, llm: {} }\n").unwrap();
        assert!(!serde_yaml::to_string(&plain).unwrap().contains("remote"));
    }
}
