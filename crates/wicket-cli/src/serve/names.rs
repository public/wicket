//! The console's Names card (#575 step 4d; design in `docs/explanation/box-dns.md`, "Audit and
//! console"): every name of the console's tenant, and the decisions on them.
//!
//! - **Shown:** `/api/names` (and the dashboard's `names`) lists pending asks, live names and those
//!   that ended in the last week; `/api/names/<id>` adds a name's records, the last plan's entries
//!   for it and its last connections ([`crate::names_view`]). Another tenant's name is not found.
//! - **Approve** (`name_approve`), **deny** (`name_deny`), **renew** (`name_renew`) and **revoke**
//!   (`name_revoke`) are passkey-signed actions. Approving, denying and renewing are refused at begin
//!   (403) to an operator whose authority (`operators.yaml`) doesn't cover `name` at R4, and checked
//!   again when applied. An approval's signed JSON names the full name, its zone and principal, the
//!   box's port and service, who it is for and how long, the node the asking run is on now with
//!   that node's public addresses, and the effect; when applied, the effect is recomputed under the
//!   installation's settings as they are then and the node read again: either changed, the approval
//!   is refused, and the refusal is on the record. The decision is recorded first, in the same write
//!   as the approval ([`wicket_control::names::approve`]).
//! - **Node addresses** (`node_addresses`): setting or clearing a node's public addresses, signed,
//!   needs kind `node` at R4. The signed JSON names the node and each address before and after; a
//!   node whose addresses changed since is refused. Recorded first (`node.addresses`), in the same
//!   write ([`wicket_store::Ledger::set_node_addresses_checked`]).

use super::{err, str_field, Action, Reply, State};
use crate::names_view::{self, Settings};
use serde_json::{json, Value};
use std::time::Duration;
use wicket_control::names as nm;
use wicket_store::{AddressChange, Ledger, NameKind, NameRow, NameScope, NodeAddresses, OperatorCredential, StandingBound};

#[cfg(test)]
thread_local! {
    /// Tests: the installation's `names:` settings, instead of `wicket.yaml`'s.
    pub(super) static SETTINGS: std::cell::RefCell<Option<Settings>> = const { std::cell::RefCell::new(None) };
}

/// The installation's `names:` settings as `wicket.yaml` has them now (tests: the hook's, or none,
/// never the host's file).
fn settings() -> Settings {
    #[cfg(test)]
    return SETTINGS.with(|s| s.borrow().clone()).unwrap_or_else(|| Ok(wicket_names::NamesConfig::default()));
    #[cfg(not(test))]
    wicket_agent::acp::names_settings()
}

fn ctx<'a>(l: &'a Ledger, settings: &'a Settings) -> names_view::Ctx<'a> {
    names_view::Ctx { l, settings, listens: &wicket_control::namesync::node_listens, now: wicket_store::now() }
}

/// The card, for the dashboard and `/api/names`.
pub(super) fn view(state: &State, l: &Ledger) -> anyhow::Result<Value> {
    let s = settings();
    names_view::card(&ctx(l, &s), &state.tenant)
}

/// The card when the ledger can't be read.
pub(super) fn empty() -> Value {
    json!({ "names": [], "public": null, "settings_error": null, "warning": nm::WARNING })
}

fn not_found(id: &str) -> Reply {
    err(http::StatusCode::NOT_FOUND, format!("no name {id}"))
}

/// Name `id` of this console's tenant: another tenant's is not found, as an unknown one is.
fn name_of(state: &State, l: &Ledger, id: &str) -> Result<NameRow, Reply> {
    match l.name(id) {
        Ok(n) if n.tenant == state.tenant.0 => Ok(n),
        _ => Err(not_found(id)),
    }
}

/// `/api/names/<id>`.
pub(super) fn detail(state: &State, id: &str) -> Result<Value, Reply> {
    let l = state.ledger().map_err(|e| err(http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let n = name_of(state, &l, id)?;
    let s = settings();
    names_view::detail(&ctx(&l, &s), &n).map_err(|e| err(http::StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))
}

/// A lifetime: `lasts` (a duration such as `30d`, or `forever`: until revoked), 30 days if absent.
fn lasts(body: &Value) -> Result<Option<Duration>, Reply> {
    let bad = |m: String| err(http::StatusCode::BAD_REQUEST, m);
    match str_field(body, "lasts").unwrap_or("30d") {
        "forever" => Ok(None),
        d => wicket_core::time::parse_duration(d).map(Some).map_err(|e| bad(format!("lasts: {e} (a duration such as 30d, or forever)"))),
    }
}

/// How a lifetime reads where it is signed.
fn lasts_text(n: &NameRow, ttl: Option<Duration>) -> String {
    match (n.scope, ttl) {
        (NameScope::Run, _) => "as its run does".into(),
        (NameScope::Standing, None) => "until revoked".into(),
        (NameScope::Standing, Some(t)) => wicket_core::time::format_duration(t).to_string(),
    }
}

/// The node the asking run of `n` is on now, and that node's public addresses: where an approval
/// publishes it first, bound by the signature.
fn target_now(l: &Ledger, n: &NameRow) -> wicket_store::Result<Value> {
    let node = match l.run_status(&n.asked_run)?.as_deref() {
        Some("running") => l.run_node(&n.asked_run)?,
        _ => None,
    };
    let a = match &node {
        Some(node) => l.node_addresses(node)?,
        None => NodeAddresses::default(),
    };
    Ok(json!({ "node": node, "public_ipv4": a.ipv4.map(|a| a.to_string()), "public_ipv6": a.ipv6.map(|a| a.to_string()) }))
}

/// The agent's words about name `n`, apart from wicket's in what the passkey signs (#575 review,
/// L7): its label, the service it says the port serves, and its reason.
fn agent_words(n: &NameRow) -> Value {
    json!({ "label": n.label, "service": n.service, "reason": n.reason })
}

fn forbidden(e: anyhow::Error) -> Reply {
    err(http::StatusCode::FORBIDDEN, format!("{e:#}"))
}

fn internal(e: impl std::fmt::Display) -> Reply {
    err(http::StatusCode::INTERNAL_SERVER_ERROR, e)
}

/// Told now, before a passkey is asked for; checked again (and a refusal audited) when applied.
fn check_decider(state: &State, oc: &OperatorCredential) -> Result<(), Reply> {
    let by = super::fence::human(state, oc).map_err(internal)?;
    nm::may_decide(&by).map(|_| ()).map_err(forbidden)
}

/// `name_approve`, at begin: what the passkey will sign.
pub(super) fn build_approve(state: &State, oc: &OperatorCredential, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let bad = |m: String| err(http::StatusCode::BAD_REQUEST, m);
    let conflict = |m: String| err(http::StatusCode::CONFLICT, m);
    let Some(id) = str_field(body, "id") else { return Err(bad("id required".into())) };
    let n = name_of(state, l, id)?;
    if n.kind != NameKind::Public {
        return Err(conflict(format!("{id} is an internal name, which needs no approval")));
    }
    if n.status != "pending" {
        return Err(conflict(format!("{id} is {}, not pending", n.status)));
    }
    let bound = match str_field(body, "for").unwrap_or("agent") {
        "agent" => StandingBound::Agent,
        "zone" => StandingBound::Zone,
        x => return Err(bad(format!("for is agent or zone, not {x:?}"))),
    };
    let ttl = lasts(body)?;
    let terms = nm::terms(bound, ttl).map_err(|e| bad(format!("{e:#}")))?;
    check_decider(state, oc)?;
    let names = settings().map_err(|e| conflict(format!("the installation's settings can't be read: {e}")))?;
    let public = nm::public_settings(&names).map_err(|e| conflict(format!("{e:#}")))?;
    let effect = wicket_store::name_effect(&n, &terms, &public.domain());
    let target = target_now(l, &n).map_err(internal)?;
    let standing = n.scope == NameScope::Standing;
    // The exact approval the passkey will sign. `decision` and `name` are what the verifier
    // (`wicket audit --verify`) matches the decision's record against.
    let v = json!({
        "v": 1, "action": "name_approve", "decision": "approve", "tenant": state.tenant.0, "name": n.id, "kind": "public",
        "fqdn": public.fqdn(&n.label), "zone": n.zone, "zone_digest": n.zone_digest, "principal": n.principal,
        "asked_run": n.asked_run, "box_port": n.port, "scope": n.scope.as_str(), "agent": agent_words(&n),
        "for": standing.then(|| bound.as_str()), "ttl_secs": if standing { terms.ttl_secs } else { None },
        "lasts": lasts_text(&n, ttl), "target": target, "warning": nm::WARNING, "effect_sha256": effect,
    });
    let ttl_secs = if standing { terms.ttl_secs } else { None };
    Ok((Action::NameApprove { id: n.id, bound, ttl_secs, effect, target: Box::new(v["target"].clone()) }, v))
}

/// `name_deny`, at begin.
pub(super) fn build_deny(state: &State, oc: &OperatorCredential, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let Some(id) = str_field(body, "id") else { return Err(err(http::StatusCode::BAD_REQUEST, "id required")) };
    let n = name_of(state, l, id)?;
    if n.status != "pending" {
        return Err(err(http::StatusCode::CONFLICT, format!("{id} is {}, not pending", n.status)));
    }
    check_decider(state, oc)?;
    let s = settings();
    let v = json!({
        "v": 1, "action": "name_deny", "decision": "deny", "tenant": state.tenant.0, "name": n.id, "kind": n.kind.as_str(),
        "fqdn": names_view::full_name(&n, s.as_ref().ok().and_then(|s| s.public.as_ref())), "zone": n.zone,
        "principal": n.principal, "asked_run": n.asked_run, "box_port": n.port, "agent": agent_words(&n),
    });
    Ok((Action::NameDeny { id: n.id }, v))
}

/// `name_renew`, at begin.
pub(super) fn build_renew(state: &State, oc: &OperatorCredential, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let bad = |m: String| err(http::StatusCode::BAD_REQUEST, m);
    let Some(id) = str_field(body, "id") else { return Err(bad("id required".into())) };
    let n = name_of(state, l, id)?;
    if n.scope != NameScope::Standing {
        return Err(err(http::StatusCode::CONFLICT, format!("{id} is run-scoped: it lasts as its run does")));
    }
    if !n.live(wicket_store::now()) {
        return Err(err(http::StatusCode::CONFLICT, format!("{id} is not live: it is asked for again, not renewed")));
    }
    let ttl = lasts(body)?;
    nm::terms(StandingBound::Agent, ttl).map_err(|e| bad(format!("{e:#}")))?;
    check_decider(state, oc)?;
    let s = settings();
    let ttl_secs = ttl.map(|t| t.as_secs());
    let v = json!({
        "v": 1, "action": "name_renew", "tenant": state.tenant.0, "name": n.id, "kind": n.kind.as_str(),
        "fqdn": names_view::full_name(&n, s.as_ref().ok().and_then(|s| s.public.as_ref())), "zone": n.zone, "principal": n.principal,
        "for": n.bound.map(|b| b.as_str()), "ttl_secs": ttl_secs, "lasts": lasts_text(&n, ttl), "previous_until": n.expires_at,
        "agent": agent_words(&n),
    });
    Ok((Action::NameRenew { id: n.id, ttl_secs, previous: n.expires_at }, v))
}

/// `name_revoke`, at begin: it only narrows, so any signed-in operator may; signed, as the card's
/// other actions are.
pub(super) fn build_revoke(state: &State, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let Some(id) = str_field(body, "id") else { return Err(err(http::StatusCode::BAD_REQUEST, "id required")) };
    let n = name_of(state, l, id)?;
    if n.status != "live" {
        return Err(err(http::StatusCode::CONFLICT, format!("{id} is {}, not live", n.status)));
    }
    let s = settings();
    let v = json!({
        "v": 1, "action": "name_revoke", "tenant": state.tenant.0, "name": n.id, "kind": n.kind.as_str(),
        "fqdn": names_view::full_name(&n, s.as_ref().ok().and_then(|s| s.public.as_ref())), "zone": n.zone, "principal": n.principal,
        "holder": n.holder, "agent": agent_words(&n),
    });
    Ok((Action::NameRevoke { id: n.id }, v))
}

/// An address field of `node_addresses`: absent keeps it, `none` clears it, an address on the
/// public internet sets it.
fn address<T: std::str::FromStr + Copy + Into<std::net::IpAddr>>(body: &Value, k: &str) -> Result<AddressChange<T>, Reply> {
    let bad = |m: String| err(http::StatusCode::BAD_REQUEST, m);
    match body.get(k) {
        None | Some(Value::Null) => Ok(AddressChange::Keep),
        Some(Value::String(s)) if s == "none" => Ok(AddressChange::Clear),
        Some(Value::String(s)) => {
            let a: T = s.parse().map_err(|_| bad(format!("{k}: an address, or none")))?;
            if !wicket_core::op::is_public_ip(&a.into()) {
                return Err(bad(format!("{k}: not an address on the public internet")));
            }
            Ok(AddressChange::Set(a))
        }
        Some(_) => Err(bad(format!("{k}: an address, or none"))),
    }
}

fn text<T: ToString>(a: Option<T>) -> Option<String> {
    a.map(|a| a.to_string())
}

/// `node_addresses`, at begin: the node, and each address before and after.
pub(super) fn build_node_addresses(state: &State, oc: &OperatorCredential, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let bad = |m: &str| err(http::StatusCode::BAD_REQUEST, m);
    let Some(node) = str_field(body, "node") else { return Err(bad("node required")) };
    let ipv4 = address::<std::net::Ipv4Addr>(body, "ipv4")?;
    let ipv6 = address::<std::net::Ipv6Addr>(body, "ipv6")?;
    let row = match l.node(node).map_err(internal)? {
        Some(r) if r.tenant == state.tenant.0 => r,
        _ => return Err(err(http::StatusCode::NOT_FOUND, format!("no node {node}"))),
    };
    if row.status != "active" {
        return Err(err(http::StatusCode::CONFLICT, format!("node {node} is {}, not active", row.status)));
    }
    let by = super::fence::human(state, oc).map_err(internal)?;
    nm::may_set_addresses(&by, node).map_err(forbidden)?;
    let old = l.node_addresses(node).map_err(internal)?;
    let new = NodeAddresses { ipv4: ipv4.apply(old.ipv4), ipv6: ipv6.apply(old.ipv6) };
    if new == old {
        return Err(bad("nothing changes: the node has those addresses"));
    }
    let v = json!({
        "v": 1, "action": "node_addresses", "tenant": state.tenant.0, "node": node,
        "ipv4": { "from": text(old.ipv4), "to": text(new.ipv4) }, "ipv6": { "from": text(old.ipv6), "to": text(new.ipv6) },
    });
    Ok((Action::NodeAddresses { node: node.into(), ipv4, ipv6, old }, v))
}

/// Applies a signed `name_approve`.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_approve(
    state: &State,
    l: &Ledger,
    oc: &OperatorCredential,
    id: &str,
    bound: StandingBound,
    ttl_secs: Option<u64>,
    effect: &str,
    target: &Value,
    signed: Value,
) -> anyhow::Result<String> {
    let by = super::fence::human(state, oc)?;
    let names = settings().map_err(|e| anyhow::anyhow!("the installation's settings can't be read: {e}"))?;
    let terms = nm::terms(bound, ttl_secs.map(Duration::from_secs))?;
    // The node shown, read again in the approval's own write (#575 step 4d; review, L3): a run
    // that moved, or a node whose addresses changed, isn't what the passkey signed.
    let same_target = |l: &Ledger| {
        if target_now(l, &l.name(id)?)? == *target {
            return Ok(());
        }
        Err(wicket_store::StoreError::Refused(format!(
            "{id}: the node its run is on, or that node's public addresses, changed since you were shown them: look again"
        )))
    };
    // The effect is recomputed under the settings as they are now, and refused if it differs.
    nm::approve_checked(l, &by, id, &terms, effect, &names, json!({ "via": "console", "signed": signed }), same_target)?;
    Ok(format!(
        "approved {id} (signed with {}): the next reconcile publishes it once a run holds it on a node with a public address",
        oc.name
    ))
}

/// Applies a signed `name_deny`.
pub(super) fn apply_deny(state: &State, l: &Ledger, oc: &OperatorCredential, id: &str, signed: Value) -> anyhow::Result<String> {
    nm::deny(l, &super::fence::human(state, oc)?, id, json!({ "via": "console", "signed": signed }))?;
    Ok(format!("denied {id} (signed with {})", oc.name))
}

/// Applies a signed `name_renew`.
pub(super) fn apply_renew(
    state: &State,
    l: &Ledger,
    oc: &OperatorCredential,
    id: &str,
    ttl_secs: Option<u64>,
    previous: Option<i64>,
    signed: Value,
) -> anyhow::Result<String> {
    let by = super::fence::human(state, oc)?;
    let extra = json!({ "action": "name_renew", "via": "console", "signed": signed });
    // The end shown is compared in the renewal's own write.
    let n = nm::renew_from(l, &by, id, ttl_secs.map(Duration::from_secs), Some(previous), extra)?;
    Ok(match n.expires_at {
        Some(u) => format!("renewed {id} until {} (signed with {})", wicket_core::time::unix_rfc3339(u), oc.name),
        None => format!("renewed {id} until revoked (signed with {})", oc.name),
    })
}

/// Applies a signed `name_revoke`.
pub(super) fn apply_revoke(l: &Ledger, oc: &OperatorCredential, id: &str, signed: Value) -> anyhow::Result<String> {
    let extra = json!({ "action": "name_revoke", "via": "console", "signed": signed });
    nm::revoke_with(l, &format!("passkey:{}", oc.name), id, extra)?;
    Ok(format!("revoked {id}: its records are withdrawn by the next reconcile (signed with {})", oc.name))
}

/// Applies a signed `node_addresses`: only on the addresses shown, recorded first.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_node_addresses(
    state: &State,
    l: &Ledger,
    oc: &OperatorCredential,
    node: &str,
    ipv4: AddressChange<std::net::Ipv4Addr>,
    ipv6: AddressChange<std::net::Ipv6Addr>,
    old: &NodeAddresses,
    signed: Value,
) -> anyhow::Result<String> {
    let by = super::fence::human(state, oc)?;
    let extra = json!({ "action": "node_addresses", "via": "console", "signed": signed });
    // Authority checked again, the addresses shown compared in the change's own write, and any
    // refusal (the authority's or the ledger's) on the record (#575 review, L2).
    let a = nm::set_node_addresses(l, &by, node, Some(old), ipv4, ipv6, extra)?;
    let show = |a: Option<String>| a.unwrap_or_else(|| "none".into());
    Ok(format!("node {node}: public IPv4 {}, IPv6 {} (signed with {})", show(text(a.ipv4)), show(text(a.ipv6)), oc.name))
}
