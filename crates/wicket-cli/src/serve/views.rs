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

/// The narrowing actions here (#713): each only takes authority or access away, so, as revoking a
/// capacity grant or standing reach, it needs the operator's session, not a passkey signature.
pub(super) fn posts(path: &str) -> bool {
    matches!(path, "/api/grants/revoke" | "/api/links/cut" | "/api/triggers/pause" | "/api/sessions/end")
}

/// One of [`posts`], for the operator `oc` signed in with: `{ "id" }`. Each goes through its CLI
/// command's function, for the console's tenant only (another tenant's id is not found, as one that
/// doesn't exist), and is audited with the operator and `via: console`.
pub(super) fn post(state: &State, oc: &wicket_store::OperatorCredential, path: &str, body: &Value) -> super::Reply {
    use http::StatusCode;
    let Some(id) = super::str_field(body, "id").map(str::trim).filter(|i| !i.is_empty() && i.len() <= 128) else {
        return super::err(StatusCode::BAD_REQUEST, "id required");
    };
    let l = match state.ledger() {
        Ok(l) => l,
        Err(e) => return super::err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let by = format!("passkey:{}", oc.name);
    let via = serde_json::json!({ "via": "console" });
    let r: Result<String> = match path {
        "/api/grants/revoke" => crate::cmd::approve::revoke_grant(&l, &state.tenant, id, &by, via),
        "/api/links/cut" => crate::cmd::approve::cut_link(&l, &state.tenant, id, &by, via).map(|cut| {
            if cut {
                format!("cut {id}; its relay closes it within a few seconds")
            } else {
                format!("{id} was already closed")
            }
        }),
        "/api/triggers/pause" => pause_trigger(state, &l, oc, id),
        "/api/sessions/end" => end_session(state, &l, oc, id, &by),
        _ => return super::err(StatusCode::NOT_FOUND, "not found"),
    };
    match r {
        Ok(said) => super::ok(serde_json::json!({ "ok": said })),
        Err(e) => {
            let status = match wicket_home::exit::code_of(&e) {
                Some(wicket_home::exit::Code::NotFound) => StatusCode::NOT_FOUND,
                _ => StatusCode::CONFLICT,
            };
            super::err(status, format!("{e:#}"))
        }
    }
}

/// `wicket trigger pause`: any operator may pause a trigger (it only stops it firing), as on the host.
fn pause_trigger(state: &State, l: &wicket_store::Ledger, oc: &wicket_store::OperatorCredential, id: &str) -> Result<String> {
    let t = l
        .trigger(id)?
        .filter(|t| t.tenant == state.tenant.0 && t.status != "deleted")
        .ok_or_else(|| wicket_home::exit::not_found(format!("no trigger {id}")))?;
    let op = crate::operators::Operator::console(&state.tenant.0, &oc.name)?;
    let t = wicket_control::triggers::set_status_via(l, &op, &t.id, "paused", serde_json::json!({ "via": "console" }))?;
    Ok(format!("paused trigger {} ({}): it fires nothing until resumed", crate::cmd::trigger::clean(&t.name), t.id))
}

/// Ends one of the operator's own console sessions, named as `/api/sessions` names it (the first 16
/// hex digits of its token's hash): ending another passkey's needs the host
/// (`wicket operator revoke-session`, root's).
fn end_session(state: &State, l: &wicket_store::Ledger, oc: &wicket_store::OperatorCredential, id: &str, by: &str) -> Result<String> {
    let own: Vec<_> = l
        .console_sessions(&state.tenant, wicket_store::now())?
        .into_iter()
        .filter(|s| s.kind == "operator" && s.credential.as_deref() == Some(oc.id.as_str()) && s.id.starts_with(id))
        .collect();
    // At least as much of its id as the list shows, so a short prefix can't pick one by chance.
    if id.len() < 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(wicket_home::exit::not_found(format!("no console session {id} of yours")));
    }
    let [s] = own.as_slice() else {
        return Err(wicket_home::exit::not_found(format!("no console session {id} of yours")));
    };
    let ids = l.revoke_console_sessions(&state.tenant, Some(&s.id), by)?;
    l.audit(&state.tenant, None, "operator.sessions_revoked", &serde_json::json!({ "sessions": ids, "by": by, "via": "console" }))?;
    Ok(format!("ended console session {}", &s.id[..16.min(s.id.len())]))
}
