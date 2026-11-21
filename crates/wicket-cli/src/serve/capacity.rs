//! The console's Capacity card (#256): standing capacity grants.
//!
//! - **Issue** (`capacity_grant`) and **renew** (`capacity_renew`) widen what a principal may lease
//!   without asking, so each is a passkey-signed action, like decide: the signed JSON names the
//!   principal, the plans, the regions, the hourly and daily money, the nodes at once and the
//!   lifetime (at most 24h). Both go through [`crate::grant`]: an issue is one grant record and a
//!   `decision` audit record, a renewal is [`grant::decide`]'s `Renew`.
//! - **Revoke** (`/api/capacity/revoke`) only narrows, so it needs only the session, as removing
//!   a notification device does. It is audited with the operator. Nodes already made under the
//!   grant keep their own leases.
//! - The card lists live grants: what each covers, what its uses take and leave, and when it ends.

use super::{err, str_field, Action, Reply, State};
use crate::grant;
use serde_json::{json, Value};
use std::time::Duration;
use wicket_placement::MicroUsd;
use wicket_store::{CapacityGrant, CapacityTerms, Ledger, OperatorCredential};

/// The default lifetime the card offers: 8 hours.
pub const DEFAULT_TTL_SECS: u64 = 8 * 3600;

pub(crate) fn usd(m: i64) -> String {
    MicroUsd(m.max(0) as u64).to_string()
}

/// A micro-USD amount as the console shows money (`$0.0500`).
pub(super) fn usd_of(m: i64) -> String {
    usd(m)
}

/// A principal as the card takes it: an identity (`spiffe://…`), or an operator as `unix/<user>` or
/// `passkey/<name>`, made into the identity it has here.
pub fn principal(tenant: &str, s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.starts_with("spiffe://") {
        return Ok(s.to_string());
    }
    match s.split_once('/') {
        Some((via @ ("unix" | "passkey"), name)) if !name.is_empty() && !name.contains('/') => {
            Ok(wicket_identity::operator_id(&crate::operators::trust_domain(), tenant, via, name))
        }
        _ => Err(format!("principal: an identity (spiffe://…), unix/<user> or passkey/<name>, not {s:?}")),
    }
}

/// Plans or regions as the card and `wicket capacity grant` (#713) take them: each trimmed, empty
/// ones dropped, and each item split at commas.
pub(crate) fn names<'a>(items: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    items.into_iter().flat_map(|s| s.split(',')).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

fn list(body: &Value, k: &str) -> Vec<String> {
    match body.get(k) {
        Some(Value::Array(a)) => names(a.iter().filter_map(|v| v.as_str())),
        Some(Value::String(s)) => names([s.as_str()]),
        _ => vec![],
    }
}

/// A dollar amount (`0.05`, or `$0.05`) as micro-USD, for the card and `wicket capacity grant`
/// (#713): `what` names it in the error.
pub(crate) fn dollars_of(what: &str, s: &str) -> Result<i64, String> {
    let s = s.trim();
    MicroUsd::parse_dollars(s).and_then(|m| i64::try_from(m.0).ok()).ok_or_else(|| format!("{what}: {s:?} is not a dollar amount"))
}

fn dollars(body: &Value, k: &str) -> Result<i64, String> {
    match body.get(k) {
        Some(Value::String(s)) => dollars_of(k, s),
        Some(Value::Number(n)) => dollars_of(k, &n.to_string()),
        _ => Err(format!("{k} required")),
    }
}

fn ttl(body: &Value) -> Result<u64, String> {
    check_ttl(body.get("ttl_secs").and_then(Value::as_u64).unwrap_or(DEFAULT_TTL_SECS))
}

/// A capacity grant's lifetime, in seconds, as the card and `wicket capacity` (#713) take it.
pub(crate) fn check_ttl(t: u64) -> Result<u64, String> {
    if t == 0 || Duration::from_secs(t) > grant::MAX_TTL {
        return Err("a capacity grant lasts more than 0 and at most 24h; renew it for longer".into());
    }
    Ok(t)
}

/// The JSON a capacity grant's terms are signed and shown as.
pub(crate) fn terms_json(t: &CapacityTerms) -> Value {
    json!({ "plans": t.plans, "regions": t.regions, "hourly_micros": t.hourly, "hourly_usd": usd(t.hourly),
            "daily_micros": t.daily, "daily_usd": usd(t.daily), "nodes": t.nodes })
}

/// `capacity_grant`, at begin: the grant as the passkey will sign it.
pub(super) fn build_grant(state: &State, body: &Value) -> Result<(Action, Value), Reply> {
    let bad = |m: String| err(http::StatusCode::BAD_REQUEST, m);
    let p = principal(&state.tenant.0, str_field(body, "principal").unwrap_or("")).map_err(bad)?;
    let terms = CapacityTerms {
        plans: list(body, "plans"),
        regions: list(body, "regions"),
        hourly: dollars(body, "max_hourly_usd").map_err(bad)?,
        daily: dollars(body, "max_daily_usd").map_err(bad)?,
        nodes: body.get("nodes").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
    };
    // Refused before the passkey is asked for, by the same rules the grant is made with.
    terms.check().map_err(bad)?;
    let ttl_secs = ttl(body).map_err(bad)?;
    let v = json!({
        "v": 1, "action": "capacity_grant", "tenant": state.tenant.0, "principal": p,
        "terms": terms_json(&terms), "ttl_secs": ttl_secs,
    });
    Ok((Action::CapacityGrant { principal: p, terms, ttl_secs }, v))
}

/// `capacity_renew`, at begin.
pub(super) fn build_renew(state: &State, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let bad = |m: String| err(http::StatusCode::BAD_REQUEST, m);
    let Some(id) = str_field(body, "id") else { return Err(bad("id required".into())) };
    let g = live(state, l, id)?;
    let ttl_secs = ttl(body).map_err(bad)?;
    let v = json!({
        "v": 1, "action": "capacity_renew", "tenant": state.tenant.0, "grant": g.id, "principal": g.principal,
        "terms": terms_json(&g.terms), "ttl_secs": ttl_secs, "previous_until": g.expires_at,
    });
    Ok((Action::CapacityRenew { grant: g.id, ttl_secs }, v))
}

fn live(state: &State, l: &Ledger, id: &str) -> Result<CapacityGrant, Reply> {
    live_grant(l, &state.tenant.0, id).map_err(|(status, m)| err(status, m))
}

/// The tenant's capacity grant `id`, if it is live: what a renewal renews, on the card and with
/// `wicket capacity renew` (#713). Not found, or ended (conflict), with why.
pub(crate) fn live_grant(l: &Ledger, tenant: &str, id: &str) -> Result<CapacityGrant, (http::StatusCode, String)> {
    let g = l
        .capacity_grant(id)
        .map_err(|e| (http::StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?
        .filter(|g| g.tenant == tenant)
        .ok_or_else(|| (http::StatusCode::NOT_FOUND, format!("no capacity grant {id}")))?;
    if !g.live(wicket_store::now()) {
        return Err((http::StatusCode::CONFLICT, format!("capacity grant {id} has ended: issue a new one")));
    }
    Ok(g)
}

/// Applies a signed `capacity_grant`.
pub(super) fn apply_grant(
    state: &State,
    l: &mut Ledger,
    oc: &OperatorCredential,
    principal: &str,
    terms: &CapacityTerms,
    ttl_secs: u64,
    signed: Value,
) -> anyhow::Result<String> {
    let by = grant::Granter::Human(crate::operators::Operator::console(&state.tenant.0, &oc.name)?);
    let id = grant::issue_capacity_grant(
        l,
        &by,
        &state.tenant,
        principal,
        terms,
        Duration::from_secs(ttl_secs),
        json!({ "action": "capacity_grant", "via": "console", "signed": signed }),
    )?;
    Ok(format!(
        "capacity grant {id} to {principal}: {} node(s) at once, {}/h, {} a day, for {}h (signed with {})",
        terms.nodes,
        usd(terms.hourly),
        usd(terms.daily),
        ttl_secs / 3600,
        oc.name
    ))
}

/// Applies a signed `capacity_renew`.
pub(super) fn apply_renew(
    state: &State,
    l: &mut Ledger,
    oc: &OperatorCredential,
    id: &str,
    ttl_secs: u64,
    signed: Value,
) -> anyhow::Result<String> {
    let by = grant::Granter::Human(crate::operators::Operator::console(&state.tenant.0, &oc.name)?);
    match grant::decide(
        l,
        &by,
        id,
        &grant::Verdict::Renew(Duration::from_secs(ttl_secs)),
        json!({ "action": "capacity_renew", "via": "console", "signed": signed }),
    )? {
        grant::Decided::Renewed { until, .. } => {
            Ok(format!("renewed capacity grant {id} until {} (signed with {})", wicket_core::time::unix_rfc3339(until), oc.name))
        }
        _ => unreachable!("a renewal renews"),
    }
}

/// `/api/capacity/revoke`: session-only, as it only narrows.
pub(super) fn revoke(state: &State, oc: &OperatorCredential, body: &Value) -> Reply {
    let Some(id) = str_field(body, "id") else { return err(http::StatusCode::BAD_REQUEST, "id required") };
    let l = match state.ledger() {
        Ok(l) => l,
        Err(e) => return err(http::StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    match grant::revoke_capacity_grant(&l, &format!("passkey:{}", oc.name), &state.tenant, id, json!({ "via": "console" })) {
        Ok(()) => super::ok(json!({ "ok": format!("revoked capacity grant {id}: nothing more is approved under it") })),
        Err(e) => err(http::StatusCode::CONFLICT, format!("{e:#}")),
    }
}

/// The card: every live capacity grant, with what its uses take and leave.
pub(crate) fn view(l: &Ledger, tenant: &str) -> anyhow::Result<Vec<Value>> {
    view_of(l, tenant, false)
}

/// The card's grants, or with `all` also revoked and expired ones (`wicket capacity list --all`,
/// #713). `state` says which: `live`, `expired` or `revoked`.
pub(crate) fn view_of(l: &Ledger, tenant: &str, all: bool) -> anyhow::Result<Vec<Value>> {
    let mut out = vec![];
    let now = wicket_store::now();
    for g in l.capacity_grants(tenant, None, all)? {
        let u = l.capacity_used(&g.id)?;
        let t = &g.terms;
        let state = if g.revoked {
            "revoked"
        } else if g.live(now) {
            "live"
        } else {
            "expired"
        };
        out.push(json!({
            "id": g.id, "state": state, "principal": g.principal, "terms": terms_json(t), "expires_at": g.expires_at, "decided_by": g.decided_by,
            "created_at": g.created_at,
            "used": { "nodes": u.nodes, "hourly_usd": usd(u.hourly), "daily_usd": usd(u.daily) },
            "left": { "nodes": t.nodes.saturating_sub(u.nodes), "hourly_usd": usd(t.hourly - u.hourly), "daily_usd": usd(t.daily - u.daily) },
        }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_principal_is_an_identity_or_an_operator() {
        assert_eq!(principal("t", " spiffe://x/t/t/op/unix/alex ").unwrap(), "spiffe://x/t/t/op/unix/alex");
        assert!(principal("t", "unix/alex").unwrap().ends_with("/t/t/op/unix/alex"));
        assert!(principal("t", "passkey/laptop").unwrap().ends_with("/t/t/op/passkey/laptop"));
        for bad in ["", "alex", "unix/", "unix/a/b", "agent/x"] {
            assert!(principal("t", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn money_and_lists_are_read_as_the_card_sends_them() {
        let b = json!({ "a": "$0.05", "b": 2, "c": "x", "plans": "vc2-1c-2gb, vc2-2c-4gb,", "regions": ["lhr", " "] });
        assert_eq!(dollars(&b, "a").unwrap(), 50_000);
        assert_eq!(dollars(&b, "b").unwrap(), 2_000_000);
        assert!(dollars(&b, "c").is_err() && dollars(&b, "d").is_err());
        assert_eq!(list(&b, "plans"), vec!["vc2-1c-2gb", "vc2-2c-4gb"]);
        assert_eq!(list(&b, "regions"), vec!["lhr"]);
        assert_eq!(ttl(&json!({})).unwrap(), DEFAULT_TTL_SECS);
        assert!(ttl(&json!({ "ttl_secs": 86_401 })).is_err() && ttl(&json!({ "ttl_secs": 0 })).is_err());
        // One parser for both surfaces (#713 review): a leading $, and no amount that wraps.
        assert_eq!(dollars_of("--max-daily-usd", "$1.5").unwrap(), 1_500_000);
        assert!(dollars_of("--max-daily-usd", "99999999999999999999").is_err());
        assert_eq!(names(["a, b", " ", "c"]), vec!["a", "b", "c"]);
    }
}
