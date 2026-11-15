//! Model provider profiles: what the model proxy (on the control host or a node, #152) does
//! differently per provider, chosen by the zone's `llm.provider`. wicket is to be harness-agnostic
//! (Claude Code today; Codex, opencode and others later), so what is provider-specific goes behind a
//! [`Profile`]: its routes, how the credential is attached upstream, and how usage is read from a
//! response. Budgets, budget slices, the node's secret cache and its fetches are provider-neutral
//! (requests and token counts; a named secret with its host binding, whatever its kind).
//!
//! Anthropic is the only profile today. Still Anthropic-specific outside it, to move into profiles as
//! others arrive: the request body filter (`max_tokens`, server tools, the fields kept) and the
//! streaming scanner's end-of-message event, in `llm.rs`. Which provider, secret and upstream a zone
//! uses by default is its harness adapter's (`wicket-agent`), filled into `zone.llm` at load.

use crate::llm::Usage;

/// One provider's model API, as the proxy needs it.
pub struct Profile {
    /// The `llm.provider` value that selects it.
    pub name: &'static str,
    /// The provider's own API host: a harness talking to it directly (a wrapped session, through the
    /// egress proxy) has its model calls vetted and counted as the model proxy's, and the host is never
    /// spliced while the zone has a model route.
    pub host: &'static str,
    /// Whether a request to `host` on this path is a model call.
    pub model_call: fn(&str) -> bool,
    /// The provider's own request headers, forwarded to its host only.
    pub request_header: fn(&str) -> bool,
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
    host: "api.anthropic.com",
    model_call: |path| path == "/v1/messages" || path.starts_with("/v1/messages/") || path == "/v1/complete",
    // Its SDKs' and harnesses' headers (model and remote-session traffic).
    request_header: |name| {
        name.starts_with("anthropic-") || name.starts_with("x-stainless-") || name.starts_with("x-claude-") || name == "x-app"
    },
};

const PROFILES: [&Profile; 1] = [&ANTHROPIC];

/// The profile for `provider`, if wicket has one.
pub fn profile(provider: &str) -> Option<&'static Profile> {
    PROFILES.into_iter().find(|p| p.name == provider)
}

/// For tests: fills a zone's model route as a harness adapter would, with [`ANTHROPIC`]'s profile.
#[cfg(test)]
pub(crate) fn fill_test_route(m: &mut wicket_core::Manifest) {
    if let Some(l) = m.zone.llm.as_mut() {
        l.fill(&wicket_core::ModelRoute {
            provider: ANTHROPIC.name.into(),
            secret: "model".into(),
            upstream: format!("https://{}", ANTHROPIC.host),
        });
    }
}

/// The profile whose API host is `host`, if any.
pub fn for_host(host: &str) -> Option<&'static Profile> {
    PROFILES.into_iter().find(|p| p.host.eq_ignore_ascii_case(host))
}
