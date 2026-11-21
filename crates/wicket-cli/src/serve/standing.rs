//! The console's standing reach cards (#572): an agent's standing requests, decided once, and the
//! standing rules approved, renewed or revoked there.
//!
//! - **Approve** (`standing_approve`), **deny** (`standing_deny`) and **renew** (`standing_renew`)
//!   are passkey-signed actions, as decide is. The signed JSON names the rule (as asked, or narrowed
//!   to the evidence), who it is for (the agent or its zone), its lifetime, and the effect
//!   (`wicket_store::standing_effect`); an approval of an ask that changed since is refused.
//! - **Revoke** (`/api/standing/revoke`) only narrows, so it needs only the session, as the
//!   capacity card's does. It is audited with the operator.
//! - The card shows each ask with the ledger's evidence and what the rule allows beyond it, and
//!   each approved rule with who it is for and when it lapses.

use super::{err, str_field, Action, Reply, State};
use crate::grant;
use serde_json::{json, Value};
use std::time::Duration;
use wicket_control::standing as st;
use wicket_store::{Ledger, OperatorCredential, Standing, StandingBound, StandingTerms};

fn pending(state: &State, l: &Ledger, id: &str) -> Result<Standing, Reply> {
    let s = l.standing(id).map_err(|e| err(http::StatusCode::NOT_FOUND, e))?;
    if s.tenant != state.tenant.0 {
        return Err(err(http::StatusCode::NOT_FOUND, format!("no standing request {id}")));
    }
    Ok(s)
}

/// The lifetime asked for: `ttl_secs` (default 30 days), or `forever: true`.
fn lasts(body: &Value) -> Result<Option<u64>, String> {
    if body.get("forever").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    let t = body.get("ttl_secs").and_then(Value::as_u64).unwrap_or(st::DEFAULT_STANDING_TTL.as_secs());
    if t == 0 || Duration::from_secs(t) > st::MAX_STANDING_TTL {
        return Err(format!(
            "a standing rule lasts more than 0 and at most {} days, or until revoked",
            st::MAX_STANDING_TTL.as_secs() / 86400
        ));
    }
    Ok(Some(t))
}

/// `standing_approve`, at begin: what the passkey will sign.
pub(super) fn build_approve(state: &State, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let bad = |m: String| err(http::StatusCode::BAD_REQUEST, m);
    let Some(id) = str_field(body, "id") else { return Err(bad("id required".into())) };
    let s = pending(state, l, id)?;
    if s.status != "pending" {
        return Err(err(http::StatusCode::CONFLICT, format!("{id} is {}, not pending", s.status)));
    }
    let bound = match str_field(body, "for").unwrap_or("agent") {
        "agent" => StandingBound::Agent,
        "zone" => StandingBound::Zone,
        x => return Err(bad(format!("for is agent or zone, not {x:?}"))),
    };
    let ttl_secs = lasts(body).map_err(bad)?;
    let narrow = body.get("narrow").and_then(Value::as_bool).unwrap_or(false);
    let rule = match narrow {
        true => st::narrowed(&s).ok_or_else(|| bad("nothing to narrow to: the ask has no evidence".into()))?,
        false => s.rule.clone(),
    };
    let effect = wicket_store::standing_effect(&s, &rule, Some(&StandingTerms { bound, ttl_secs }));
    let v = json!({
        "v": 1, "action": "standing_approve", "tenant": state.tenant.0, "standing": s.id, "principal": s.principal,
        "zone": s.zone, "rule": rule, "for": bound.as_str(), "ttl_secs": ttl_secs, "narrowed": narrow, "effect_sha256": effect,
    });
    Ok((Action::StandingApprove { id: s.id, rule: Box::new(rule), bound, ttl_secs, effect }, v))
}

/// `standing_deny`, at begin.
pub(super) fn build_deny(state: &State, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let Some(id) = str_field(body, "id") else { return Err(err(http::StatusCode::BAD_REQUEST, "id required")) };
    let s = pending(state, l, id)?;
    let v = json!({ "v": 1, "action": "standing_deny", "tenant": state.tenant.0, "standing": s.id, "rule": s.rule });
    Ok((Action::StandingDeny { id: s.id }, v))
}

/// `standing_renew`, at begin.
pub(super) fn build_renew(state: &State, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let bad = |m: String| err(http::StatusCode::BAD_REQUEST, m);
    let Some(id) = str_field(body, "id") else { return Err(bad("id required".into())) };
    let s = pending(state, l, id)?;
    if !s.live(wicket_store::now()) {
        return Err(err(http::StatusCode::CONFLICT, format!("{id} is not live: it is asked for again, not renewed")));
    }
    let ttl_secs = lasts(body).map_err(bad)?;
    let v = json!({
        "v": 1, "action": "standing_renew", "tenant": state.tenant.0, "standing": s.id, "rule": s.rule,
        "ttl_secs": ttl_secs, "previous_until": s.expires_at,
    });
    Ok((Action::StandingRenew { id: s.id, ttl_secs }, v))
}

fn human(state: &State, oc: &OperatorCredential) -> anyhow::Result<grant::Granter> {
    Ok(grant::Granter::Human(crate::operators::Operator::console(&state.tenant.0, &oc.name)?))
}

/// Applies a signed `standing_approve`.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_approve(
    state: &State,
    l: &Ledger,
    oc: &OperatorCredential,
    id: &str,
    rule: &wicket_core::manifest::ReachRule,
    bound: StandingBound,
    ttl_secs: Option<u64>,
    effect: &str,
    signed: Value,
) -> anyhow::Result<String> {
    let a = st::Approve { rule: Some(rule.clone()), bound, ttl: ttl_secs.map(Duration::from_secs) };
    st::approve(l, &human(state, oc)?, id, &a, Some(effect), json!({ "via": "console", "signed": signed }))?;
    let lasts = ttl_secs.map(|t| format!("for {} days", t / 86400)).unwrap_or_else(|| "until revoked".into());
    Ok(format!("approved standing reach {id} for the {}, {lasts} (signed with {})", bound.as_str(), oc.name))
}

/// Applies a signed `standing_deny`.
pub(super) fn apply_deny(state: &State, l: &Ledger, oc: &OperatorCredential, id: &str, signed: Value) -> anyhow::Result<String> {
    st::deny(l, &human(state, oc)?, id, json!({ "via": "console", "signed": signed }))?;
    Ok(format!("denied standing reach {id} (signed with {})", oc.name))
}

/// Applies a signed `standing_renew`.
pub(super) fn apply_renew(
    state: &State,
    l: &Ledger,
    oc: &OperatorCredential,
    id: &str,
    ttl_secs: Option<u64>,
    signed: Value,
) -> anyhow::Result<String> {
    let until = st::renew(l, &human(state, oc)?, id, ttl_secs.map(Duration::from_secs), json!({ "via": "console", "signed": signed }))?;
    Ok(match until {
        Some(u) => format!("renewed standing reach {id} until {} (signed with {})", wicket_core::time::unix_rfc3339(u), oc.name),
        None => format!("renewed standing reach {id} until revoked (signed with {})", oc.name),
    })
}

/// `/api/standing/revoke`: session-only, as it only narrows.
pub(super) fn revoke(state: &State, oc: &OperatorCredential, body: &Value) -> Reply {
    let Some(id) = str_field(body, "id") else { return err(http::StatusCode::BAD_REQUEST, "id required") };
    let l = match state.ledger() {
        Ok(l) => l,
        Err(e) => return err(http::StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    if let Err(r) = pending(state, &l, id) {
        return r;
    }
    match st::revoke(&l, &format!("passkey:{}", oc.name), id) {
        Ok(_) => {
            super::ok(json!({ "ok": format!("revoked standing reach {id}: each run it allowed publishes the revocation to its node") }))
        }
        Err(e) => err(http::StatusCode::CONFLICT, format!("{e:#}")),
    }
}

/// The card: pending asks (with their evidence, what they allow beyond it, and the narrowed rule),
/// and approved rules (live first, then lapsed).
pub(crate) fn view(l: &Ledger, tenant: &str) -> anyhow::Result<Value> {
    let t = wicket_core::TenantId(tenant.to_string());
    let now = wicket_store::now();
    let asks: Vec<Value> = l
        .standing_with_status(&t, "pending")?
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id, "principal": s.principal, "zone": s.zone, "zone_digest": s.zone_digest, "run": s.run, "rule": s.rule, "reason": s.reason,
                "evidence": s.evidence, "beyond": st::beyond(&s, &s.rule), "narrowed": st::narrowed(&s), "created_at": s.created_at,
            })
        })
        .collect();
    let rules: Vec<Value> = l
        .standing_with_status(&t, "approved")?
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id, "principal": s.principal, "zone": s.zone, "rule": s.rule, "for": s.bound.map(|b| b.as_str()),
                "expires_at": s.expires_at, "live": s.live(now), "decided_by": s.decided_by, "decided_at": s.decided_at,
            })
        })
        .collect();
    Ok(json!({ "asks": asks, "rules": rules }))
}
