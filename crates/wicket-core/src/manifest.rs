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
    /// Trusted task text: the only input policy derivation ever sees.
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
    /// How many child agents this agent may start with `spawn_agent`, each in its own sandbox with
    /// its own identity (design §3.2, §5.1). 0 = none.
    #[serde(default)]
    pub max_children: u32,
    /// Whether the agent may also run its own in-box subagents (Claude Code's Agent tool). Their
    /// requests are attributed but not provably identified; set false to require that every
    /// subagent is a wicket child with its own identity.
    #[serde(default = "yes")]
    pub in_box_subagents: bool,
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
    /// Credentials injected by the egress proxy into exactly one header slot per host.
    #[serde(default)]
    pub inject: Vec<InjectRule>,
    /// The model route; required for agents, absent for programs.
    #[serde(default)]
    pub llm: Option<LlmSpec>,
    /// Zones whose agents may send messages to agents in this zone (besides parent and children).
    /// Empty = nobody else. Senders are identified by wicket, never by their own claim.
    #[serde(default)]
    pub accept_from: Vec<String>,
    #[serde(default)]
    pub limits: Limits,
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
    /// e.g. `Bearer {secret}`.
    #[serde(default = "default_format")]
    pub format: String,
    /// Name of the secret in wicket's vault.
    pub secret: String,
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
}

impl Default for Limits {
    fn default() -> Self {
        Limits { memory: default_memory(), cpus: default_cpus(), timeout: default_timeout(), pids: default_pids() }
    }
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
}

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
        for i in &self.zone.inject {
            if !i.format.contains("{secret}") {
                return Err(ManifestError::Invalid(format!("inject format for {} lacks {{secret}}", i.host)));
            }
        }
        self.zone.limits.timeout()?;
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
    fn wildcard_hosts() {
        assert!(host_matches("*.githubusercontent.com", "raw.githubusercontent.com"));
        assert!(!host_matches("*.githubusercontent.com", "githubusercontent.com"));
        assert!(!host_matches("*.githubusercontent.com", "evilgithubusercontent.com"));
        assert!(host_matches("api.github.com", "API.GitHub.com."));
    }
}
