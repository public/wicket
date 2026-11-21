//! The console's read views of what only `wicket …` on the host listed before (#713): grants,
//! links, triggers, nodes, per-node services, agent identities and console sessions. Each prints
//! what its CLI command's `--json` does, through the same function, so the two surfaces show the
//! same thing; for an operator's session only.
//!
//! - **Read-only.** Nothing here writes.
//! - **Never shown:** a token, a signature, a key or a session's token. An identity is its verified
//!   fields, never its signed document. A console session is the prefix of its token's hash, which
//!   nothing signs in with. A trigger is named fields, never its document (a webhook's URL token).
//!   A test scans each for these (`authority_views_never_carry_a_token_signature_secret_or_key`).

use super::State;
use anyhow::Result;
use serde_json::Value;

/// The paths here, so a request without an operator's session is refused before any is built.
pub(super) fn handles(path: &str) -> bool {
    matches!(path, "/api/grants" | "/api/links" | "/api/triggers" | "/api/nodes" | "/api/services" | "/api/identities" | "/api/sessions")
}

/// How many identities the view lists: the newest.
const IDENTITIES: usize = 200;

/// The GET endpoints here, for an operator's session. None: not one of them.
pub(super) fn get(state: &State, path: &str) -> Option<Result<Value>> {
    let view = match path {
        "/api/grants" => grants,
        "/api/links" => links,
        "/api/triggers" => triggers,
        "/api/nodes" => nodes,
        "/api/services" => services,
        "/api/identities" => identities,
        "/api/sessions" => sessions,
        _ => return None,
    };
    Some(state.ledger().and_then(|l| view(state, &l)))
}

/// `wicket grant list --json --all`: live, expired and revoked grants, newest first (the last 200).
fn grants(state: &State, l: &wicket_store::Ledger) -> Result<Value> {
    Ok(crate::cmd::approve::grants_json(&l.grants(&state.tenant, true, 200)?, wicket_store::now()))
}

/// `wicket links --json`: the last 200 links between boxes.
fn links(state: &State, l: &wicket_store::Ledger) -> Result<Value> {
    Ok(crate::cmd::approve::links_json(&l.links(&state.tenant, 200)?))
}

/// `wicket trigger list --json`.
fn triggers(state: &State, l: &wicket_store::Ledger) -> Result<Value> {
    Ok(crate::cmd::trigger::list_json(&l.triggers(&state.tenant.0, None)?, wicket_store::now()))
}

/// `wicket node list --json`: the tenant's enrolled nodes.
fn nodes(state: &State, l: &wicket_store::Ledger) -> Result<Value> {
    let nodes: Vec<_> = l.nodes()?.into_iter().filter(|n| n.tenant == state.tenant.0).collect();
    wicket_control::enrol::list_json_of(l, &nodes)
}

/// `wicket service list --json`: the tenant's.
fn services(state: &State, l: &wicket_store::Ledger) -> Result<Value> {
    let rows: Vec<_> = l.services()?.into_iter().filter(|s| s.tenant == state.tenant.0).collect();
    Ok(crate::cmd::service::services_json(&rows))
}

/// `wicket identity list --json`: the tenant's newest, checked as the console checks the identities
/// it shows beside a request.
fn identities(state: &State, l: &wicket_store::Ledger) -> Result<Value> {
    let mut rows: Vec<_> = l.identities()?.into_iter().filter(|r| r.tenant == state.tenant.0).collect();
    rows.drain(..rows.len().saturating_sub(IDENTITIES));
    crate::cmd::identity::list_json(l, &rows, state.identity)
}

/// `wicket operator sessions --json`: the tenant's live console sessions.
fn sessions(state: &State, l: &wicket_store::Ledger) -> Result<Value> {
    Ok(crate::cmd::operator::sessions_json(&l.console_sessions(&state.tenant, wicket_store::now())?))
}
