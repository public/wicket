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

/// `wicket node list --json`: every enrolled node.
fn nodes(_: &State, l: &wicket_store::Ledger) -> Result<Value> {
    wicket_control::enrol::list_json(l)
}

/// `wicket service list --json`.
fn services(_: &State, l: &wicket_store::Ledger) -> Result<Value> {
    Ok(crate::cmd::service::services_json(&l.services()?))
}

/// `wicket identity list --json`.
fn identities(_: &State, l: &wicket_store::Ledger) -> Result<Value> {
    crate::cmd::identity::list_json(l)
}

/// `wicket operator sessions --json`: the tenant's live console sessions.
fn sessions(state: &State, l: &wicket_store::Ledger) -> Result<Value> {
    Ok(crate::cmd::operator::sessions_json(&l.console_sessions(&state.tenant, wicket_store::now())?))
}
