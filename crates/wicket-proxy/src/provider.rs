//! Model provider profiles: what the model proxy (on the control host or a node, #152) does
//! differently per provider, chosen by the zone's `llm.provider`. wicket is to be harness-agnostic
//! (Claude Code today; Codex, opencode and others later), so what is provider-specific goes behind a
//! [`Profile`]: its routes, how the credential is attached upstream, and how usage is read from a
//! response. Budgets, budget slices, the node's secret cache and its fetches are provider-neutral
//! (requests and token counts; a named secret with its host binding, whatever its kind).
//!
//! Anthropic is the only profile today. Still Anthropic-specific outside it, to move into profiles as
//! others arrive: the request body filter (`max_tokens`, server tools, the fields kept) and the
//! streaming scanner's end-of-message event, in `llm.rs`; the `claude-oauth` default host binding in
//! `vault.rs`; the agent image's harness.

use crate::llm::Usage;

/// One provider's model API, as the proxy needs it.
pub struct Profile {
    /// The `llm.provider` value that selects it.
    pub name: &'static str,
    /// The routes a box may call: (method, canonical path).
    pub routes: &'static [(&'static str, &'static str)],
    /// Query parameters a route may carry.
    pub query: &'static [&'static str],
    /// Attaches the credential to an upstream request.
    pub attach: fn(reqwest::RequestBuilder, &str) -> reqwest::RequestBuilder,
    /// Reads usage from (part of) a response body, JSON or a server-sent event stream.
    pub usage: fn(&[u8]) -> Usage,
}

impl Profile {
    /// Ok if `method` and `path_and_query` name one of this provider's routes, exactly and
    /// canonically.
    pub fn allowed_route(&self, method: &str, path_and_query: &str) -> Result<(), String> {
        let path = wicket_core::canon::canonical_path(path_and_query).map_err(|e| e.to_string())?;
        if !self.routes.iter().any(|(m, p)| *m == method && *p == path) {
            return Err(format!("{method} {path} is not a model route"));
        }
        if let Some((_, q)) = path_and_query.split_once('?') {
            if q.split('&').any(|kv| !self.query.contains(&kv)) {
                return Err(format!("query {q:?} is not allowed on a model route"));
            }
        }
        Ok(())
    }
}

/// Anthropic's Messages API, with the Claude subscription's OAuth access token as a bearer (never
/// an API key).
pub static ANTHROPIC: Profile = Profile {
    name: "anthropic",
    routes: &[("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens"), ("GET", "/v1/models")],
    // Claude Code sends `?beta=true`.
    query: &["beta=true"],
    attach: |rb, token| rb.header("authorization", format!("Bearer {token}")),
    usage: crate::llm::usage,
};

/// The profile for `provider`, if wicket has one.
pub fn profile(provider: &str) -> Option<&'static Profile> {
    [&ANTHROPIC].into_iter().find(|p| p.name == provider)
}
