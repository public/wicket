//! What is Claude's, in one place: names the rest of wicket reaches only through the harness
//! adapter ([`crate::harness`]), or as the installation's defaults.

/// The agent image's repository, built from `images/claude-code`, and the tag a box gets when
/// nothing names another.
pub const IMAGE_REPO: &str = "wicket/claude-code";
pub const DEFAULT_IMAGE: &str = "wicket/claude-code:poc";

/// The secret a wrapped session's account login comes from when the zone has no model route, and the
/// host its placeholders are swapped toward.
pub const LOGIN_SECRET: &str = "claude-oauth";
pub const LOGIN_HOST: &str = "api.anthropic.com";
/// How the installation's owner gets [`LOGIN_SECRET`]'s value.
pub const LOGIN_HOW: &str = "run `claude setup-token` (your Claude subscription token), or link the host's Claude login";

/// Claude Code's model route, filled into a zone's `llm` where the manifest leaves a field out: the
/// model proxy's `anthropic` profile, the subscription login (from `claude setup-token`, or linked
/// to the host's Claude login; never an API key), and Anthropic's API.
pub const MODEL_PROVIDER: &str = "anthropic";
pub const MODEL_UPSTREAM: &str = "https://api.anthropic.com";

/// The ACP profile for Claude Code through its ACP adapter (`agent.acp.profile`).
pub const ACP_PROFILE: &str = "claude-agent-acp";

/// [`MODEL_PROVIDER`], [`LOGIN_SECRET`] and [`MODEL_UPSTREAM`] as a route.
pub fn model_route() -> wicket_core::ModelRoute {
    wicket_core::ModelRoute { provider: MODEL_PROVIDER.into(), secret: LOGIN_SECRET.into(), upstream: MODEL_UPSTREAM.into() }
}

/// Claude Code's config directory, under the box's state dir (`CLAUDE_CONFIG_DIR`).
pub const STATE_SUBDIR: &str = "claude";

/// The host's own Claude Code login, relative to `$HOME`: a wrapped session keeps its non-secret
/// fields (scopes, plan).
pub const HOST_CREDENTIALS: &str = ".claude/.credentials.json";

/// Whether a process in the box is Claude Code itself (its CLI, or Node running it).
pub fn is_runtime(cmd: &str) -> bool {
    let base = cmd.split_whitespace().next().unwrap_or("").rsplit('/').next().unwrap_or("");
    base == "claude" || (base == "node" && cmd.contains("claude"))
}
