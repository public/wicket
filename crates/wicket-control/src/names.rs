//! Decisions on public names (#575; design in `docs/explanation/box-dns.md`): a human approves a
//! box's ask for a name on the internet, denies it, renews a standing name, or revokes a name. Each
//! is on the audit record, written first, in the same write as the change (#575 step 4d): a
//! decision whose record can't be written isn't made (fail closed), and one the ledger refuses
//! leaves only its refusal on the record (`decision.refused`, under the name's tenant).
//!
//! Only a human decides, and only one whose authority (`operators.yaml`) covers `name` decisions at
//! the highest risk: a public name lets anyone on the internet connect to the box's port and read
//! what it serves, an outbound channel as much as an inbound one. No agent's `decide` reaches it.

use crate::grant::{merged, Granter};
use anyhow::{bail, Result};
use std::time::Duration;
use wicket_core::TenantId;
use wicket_store::{AddressChange, Ledger, NameRow, NameScope, NameTerms, NodeAddresses, StandingBound, StoreError};

/// A refusal of `decision` on `id` (of `tenant`) by `by`, on that tenant's audit record (#575
/// review, L4).
fn refused(l: &Ledger, tenant: &str, by: &Granter, id: &str, decision: &str, why: anyhow::Error) -> anyhow::Error {
    crate::grant::refused_in(l, &TenantId(tenant.into()), by, id, decision, why)
}

/// The longest lifetime a standing name may be approved for (beyond it: until revoked).
pub const MAX_NAME_TTL: Duration = Duration::from_secs(366 * 24 * 3600);
/// The lifetime offered first.
pub const DEFAULT_NAME_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// What the human is told a public name means, on every card.
pub const WARNING: &str =
    "anyone on the internet can connect to this box's port and read whatever it serves: it is a way out for the box's data, not only a way in";

/// The human operator `by`, if its authority covers `name` decisions at R4: Err says why not.
pub fn may_decide(by: &Granter) -> Result<crate::operators::Operator> {
    let o = crate::grant::human(by, "a public name")?;
    o.may_decide(&crate::operators::Asked { kind: "name".into(), host: String::new(), risk: Some(4) }).map_err(anyhow::Error::msg)?;
    Ok(o.clone())
}

/// The terms of an approval: for a standing name, who it is for and how long; a run-scoped one
/// lasts as its run does, whatever is given.
pub fn terms(bound: StandingBound, ttl: Option<Duration>) -> Result<NameTerms> {
    if let Some(t) = ttl {
        if t.is_zero() {
            bail!("a standing name needs a lifetime (or until revoked)");
        }
        if t > MAX_NAME_TTL {
            bail!("a standing name lasts at most {} unless it is approved until revoked", wicket_core::time::format_duration(MAX_NAME_TTL));
        }
    }
    Ok(NameTerms { bound, ttl_secs: ttl.map(|t| t.as_secs()) })
}

/// This installation's public-names settings, or why it publishes no names.
pub fn public_settings(names: &wicket_names::NamesConfig) -> Result<&wicket_names::PublicConfig> {
    names.public.as_ref().ok_or_else(|| anyhow::anyhow!("this installation publishes no public names (names.public in wicket.yaml)"))
}

/// Approves public-name ask `id` as `by` with `terms`, on the effect `shown`: the one the decider
/// was shown, always (#680 review, L6: a caller can't approve what it didn't show), under the
/// installation's `names` settings as they are now (#575 review, M1: its boxes domain, reserved
/// labels and per-workload limit). `extra` goes on the decision's audit record. The effect approved.
pub fn approve(
    l: &Ledger,
    by: &Granter,
    id: &str,
    terms: &NameTerms,
    shown: &str,
    names: &wicket_names::NamesConfig,
    extra: serde_json::Value,
) -> Result<String> {
    approve_checked(l, by, id, terms, shown, names, extra, |_| Ok(()))
}

/// [`approve`], only if `check` passes inside the approval's own write, before anything is
/// written (the console's signed target, read again under the write lock, #575 review, L3): a
/// `StoreError::Refused` from it is refused on the record, as the ledger's own refusals are.
#[allow(clippy::too_many_arguments)]
pub fn approve_checked(
    l: &Ledger,
    by: &Granter,
    id: &str,
    terms: &NameTerms,
    shown: &str,
    names: &wicket_names::NamesConfig,
    extra: serde_json::Value,
    check: impl FnOnce(&Ledger) -> wicket_store::Result<()>,
) -> Result<String> {
    let n = l.name(id)?;
    let refused = |d: &str, why| refused(l, &n.tenant, by, id, d, why);
    if n.kind != wicket_store::NameKind::Public {
        return Err(refused("approve", anyhow::anyhow!("{id} is an internal name, which needs no approval")));
    }
    let o = match may_decide(by) {
        Ok(o) => o,
        Err(why) => return Err(refused("approve", why)),
    };
    let public = match public_settings(names) {
        Ok(p) => p,
        Err(why) => return Err(refused("approve", why)),
    };
    // The effect as it is now, checked before anything is written, so the refusal is on the
    // record (inside the write below it would be rolled back with the rest).
    let effect = wicket_store::name_effect(&n, terms, &public.domain());
    if effect != shown {
        return Err(refused("approve", StoreError::EffectChanged(id.into(), shown.into(), effect).into()));
    }
    let standing = n.scope == NameScope::Standing;
    let record = serde_json::json!({
        "decision": "approve", "name": id, "label": n.label, "fqdn": public.fqdn(&n.label), "kind": "public", "port": n.port, "service": n.service,
        "by": o.label, "granter": "human", "granter_identity": o.id, "principal": n.principal, "zone": n.zone, "run": n.asked_run,
        "scope": n.scope.as_str(), "bound": standing.then(|| terms.bound.as_str()), "ttl_secs": standing.then_some(terms.ttl_secs),
        "effect_sha256": effect,
    });
    let record = merged(record, extra);
    // On the record first, in the same write as the approval (#575 step 4d): an approval that
    // can't be recorded isn't made, and one the ledger refuses leaves no decision behind.
    let made = l.immediate(|l| {
        check(l)?;
        l.audit(&TenantId(n.tenant.clone()), Some(&wicket_core::RunId(n.asked_run.clone())), "decision", &record)?;
        l.approve_name(id, terms, &o.label, Some(shown), public)
    });
    match made {
        Ok(e) => Ok(e),
        Err(e @ (StoreError::EffectChanged(..) | StoreError::Refused(_) | StoreError::NotPending(..))) => Err(refused("approve", e.into())),
        Err(e) => Err(anyhow::Error::from(e).context("the approval could not be recorded in the audit log, so it wasn't made")),
    }
}

/// A refusal of `decision` on name `id` by `by`, on the audit record (`decision.refused`): for a
/// caller that checks more than this module does before deciding (the console's signed target).
pub fn refuse(l: &Ledger, tenant: &TenantId, by: &Granter, id: &str, decision: &str, why: anyhow::Error) -> anyhow::Error {
    crate::grant::refused_in(l, tenant, by, id, decision, why)
}

/// Renews live standing name `id` as `by` (a human whose authority covers `name` at R4, as
/// approving needs): it lapses `ttl` from now (None: until revoked; at most [`MAX_NAME_TTL`]).
/// Audited `name.renewed`, in the same write and first (#575 step 4d); `extra` goes on the
/// record. The name as renewed.
pub fn renew(l: &Ledger, by: &Granter, id: &str, ttl: Option<Duration>, extra: serde_json::Value) -> Result<NameRow> {
    renew_from(l, by, id, ttl, None, extra)
}

/// [`renew`], only if the name's end is still `shown` (what the decider was shown), checked in
/// the same write.
pub fn renew_from(
    l: &Ledger,
    by: &Granter,
    id: &str,
    ttl: Option<Duration>,
    shown: Option<Option<i64>>,
    extra: serde_json::Value,
) -> Result<NameRow> {
    let n = l.name(id)?;
    let refused = |why| refused(l, &n.tenant, by, id, "renew", why);
    let o = match may_decide(by).and_then(|o| terms(StandingBound::Agent, ttl).map(|_| o)) {
        Ok(o) => o,
        Err(why) => return Err(refused(why)),
    };
    let until = ttl.map(|t| wicket_store::now().saturating_add(i64::try_from(t.as_secs()).unwrap_or(i64::MAX)));
    let record = merged(
        serde_json::json!({
            "name": id, "kind": n.kind.as_str(), "label": n.label, "zone": n.zone, "principal": n.principal, "until": until,
            "previous_until": n.expires_at, "by": o.label, "granter": "human", "granter_identity": o.id,
        }),
        extra,
    );
    let made = l.immediate(|l| {
        l.audit(&TenantId(n.tenant.clone()), None, "name.renewed", &record)?;
        l.renew_name_from(id, until, shown)
    });
    match made {
        Ok(n) => Ok(n),
        Err(e @ (StoreError::Refused(_) | StoreError::NoSuchRequest(_))) => Err(refused(e.into())),
        Err(e) => Err(anyhow::Error::from(e).context("the renewal could not be recorded in the audit log, so it wasn't made")),
    }
}

/// Denies public-name ask `id` as `by`; `extra` goes on the audit record, written first, in the
/// same write as the denial (#575 review, M1).
pub fn deny(l: &Ledger, by: &Granter, id: &str, extra: serde_json::Value) -> Result<()> {
    let n = l.name(id)?;
    let refused = |why| refused(l, &n.tenant, by, id, "deny", why);
    let o = match may_decide(by) {
        Ok(o) => o,
        Err(why) => return Err(refused(why)),
    };
    let record = merged(
        serde_json::json!({ "decision": "deny", "name": id, "label": n.label, "by": o.label, "granter": "human", "granter_identity": o.id }),
        extra,
    );
    let made = l.immediate(|l| {
        l.audit(&TenantId(n.tenant.clone()), Some(&wicket_core::RunId(n.asked_run.clone())), "decision", &record)?;
        l.deny_name(id, &o.label)
    });
    match made {
        Ok(()) => Ok(()),
        Err(e @ (StoreError::Refused(_) | StoreError::NotPending(..))) => Err(refused(e.into())),
        Err(e) => Err(anyhow::Error::from(e).context("the denial could not be recorded in the audit log, so it wasn't made")),
    }
}

/// A run of `principal` in `zone` started: it takes up the live standing names bound to its agent
/// or zone that no run holds (#575 review, M2), under the zone's name and digest as the ask stored
/// them, each audited `name.claimed` (`Ledger::claim_standing_names`). A run starts without them if
/// the ledger refuses, and says so.
pub fn claim_for_run(
    l: &Ledger,
    tenant: &TenantId,
    run: &wicket_core::RunId,
    principal: &str,
    zone: &wicket_core::ZoneSpec,
) -> Vec<NameRow> {
    match l.claim_standing_names(tenant, run, principal, &zone.name, &wicket_store::zone_digest(zone)) {
        Ok(c) => c,
        Err(e) => {
            wicket_home::say_err!("[wicket] {run}: its standing names could not be taken up: {e}");
            vec![]
        }
    }
}

/// Revokes live name `id` (public or internal): it ends now, whoever holds it.
pub fn revoke(l: &Ledger, by: &str, id: &str) -> Result<NameRow> {
    revoke_with(l, by, id, serde_json::json!({}))
}

/// [`revoke`], with `extra` on the audit record (the console's signed action, #575 step 4d). The
/// record is written first, in the same write as the revocation (#575 review, M1); a name the
/// ledger won't revoke (not live) leaves its refusal on the record.
pub fn revoke_with(l: &Ledger, by: &str, id: &str, extra: serde_json::Value) -> Result<NameRow> {
    let n = l.name(id)?;
    let record = merged(serde_json::json!({ "name": id, "label": n.label, "kind": n.kind.as_str(), "zone": n.zone, "by": by }), extra);
    let made = l.immediate(|l| {
        l.audit(&TenantId(n.tenant.clone()), None, "name.revoked", &record)?;
        l.revoke_name(id, by)
    });
    match made {
        Ok(n) => Ok(n),
        Err(e @ (StoreError::Refused(_) | StoreError::NotPending(..))) => {
            let why = anyhow::Error::from(e);
            let refusal = serde_json::json!({ "target": id, "decision": "revoke", "by": by, "why": format!("{why:#}") });
            Err(crate::grant::refusal_recorded(l, &TenantId(n.tenant.clone()), &refusal, why))
        }
        Err(e) => Err(anyhow::Error::from(e).context("the revocation could not be recorded in the audit log, so it wasn't made")),
    }
}

/// What setting a node's public addresses asks of an operator's authority (#575 step 4d): kind
/// `node`, at R4, since a public name's records point at them.
pub fn node_asked(node: &str) -> crate::operators::Asked {
    crate::operators::Asked { kind: "node".into(), host: node.into(), risk: Some(4) }
}

/// The human operator `by`, if its authority covers setting node `node`'s public addresses.
pub fn may_set_addresses(by: &Granter, node: &str) -> Result<crate::operators::Operator> {
    let o = crate::grant::human(by, "a node's public addresses")?;
    o.may_decide(&node_asked(node)).map_err(anyhow::Error::msg)?;
    Ok(o.clone())
}

/// Sets node `node`'s public addresses as `by` (the console's signed change and `wicket node set`,
/// #575 review, L5): only a human whose authority covers kind `node` at R4, and, given `expected`,
/// only if the node's addresses are still those. Audited `node.addresses` first, in the same write
/// (`extra` on the record); a refusal, the authority's or the ledger's, is on the node's tenant's
/// record as `decision.refused`. The addresses as set.
pub fn set_node_addresses(
    l: &Ledger,
    by: &Granter,
    node: &str,
    expected: Option<&NodeAddresses>,
    ipv4: AddressChange<std::net::Ipv4Addr>,
    ipv6: AddressChange<std::net::Ipv6Addr>,
    extra: serde_json::Value,
) -> Result<NodeAddresses> {
    let tenant = TenantId(l.node(node)?.map(|r| r.tenant).unwrap_or_else(|| TenantId::single().0));
    let o = match may_set_addresses(by, node) {
        Ok(o) => o,
        Err(why) => return Err(refuse(l, &tenant, by, node, "node_addresses", why)),
    };
    match l.set_node_addresses_checked(node, expected, ipv4, ipv6, &o.label, extra) {
        Ok(a) => Ok(a),
        Err(e @ StoreError::Refused(_)) => Err(refuse(l, &tenant, by, node, "node_addresses", e.into())),
        Err(e) => Err(anyhow::Error::from(e).context("the change could not be recorded in the audit log, so it wasn't made")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::RunId;
    use wicket_store::{NameAsk, NameScope};

    fn cfg() -> wicket_names::NamesConfig {
        serde_json::from_value(serde_json::json!({ "public": { "provider": "noop", "zone": "boxes.example.com", "owner": "a1b2c3d4" } }))
            .unwrap()
    }

    fn op(policy: &str) -> Granter {
        let p: crate::operators::Policy = crate::operators::Policy::parse(policy).unwrap();
        Granter::Human(crate::operators::Operator::new("t0", "unix", "ann", "ann".into(), &p))
    }

    fn asked(l: &Ledger, label: &str, scope: NameScope) -> String {
        let t = TenantId::single();
        let r = RunId("run_w".into());
        l.run_started(&t, &r, "work", "worker").unwrap();
        let ask = NameAsk {
            tenant: &t,
            run: &r,
            zone: "work",
            zone_digest: "d",
            principal: "spiffe://x/worker",
            label,
            port: 3000,
            service: Some("http"),
            reason: "the demo",
            scope,
        };
        l.ask_public(&ask).unwrap().0
    }

    #[test]
    fn a_human_with_name_authority_approves_bound_to_the_effect_and_it_is_audited() {
        let l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "demo", NameScope::Standing);
        let t = terms(StandingBound::Agent, Some(DEFAULT_NAME_TTL)).unwrap();
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &t, "boxes.example.com");
        // An operator whose kinds leave out `name` can't.
        let narrow = op("default: { kinds: [http] }\n");
        assert!(approve(&l, &narrow, &id, &t, &shown, &cfg(), serde_json::json!({})).unwrap_err().to_string().contains("refused"));
        // Another effect than the one shown is refused.
        let wide = terms(StandingBound::Zone, None).unwrap();
        assert!(approve(&l, &op("default: anything\n"), &id, &wide, &shown, &cfg(), serde_json::json!({})).is_err());
        let effect = approve(&l, &op("default: anything\n"), &id, &t, &shown, &cfg(), serde_json::json!({ "via": "cli" })).unwrap();
        assert_eq!(effect, shown);
        assert_eq!(l.name(&id).unwrap().status, "live");
        let audit = l.audit_tail(10).unwrap();
        assert!(audit.iter().any(|a| a.2 == "decision" && a.4.contains("\"approve\"") && a.4.contains(&id) && a.4.contains("\"cli\"")));
        assert!(audit.iter().filter(|a| a.2 == "decision.refused").count() >= 2);
        // Revoked: ended and audited.
        let n = revoke(&l, "ann", &id).unwrap();
        assert_eq!(n.end_reason.as_deref(), Some("revoked"));
        assert!(l.audit_tail(10).unwrap().iter().any(|a| a.2 == "name.revoked"));
    }

    /// #575 step 4d: the decision is recorded first, in the same write: an approval whose record
    /// can't be written isn't made.
    #[test]
    fn an_approval_that_cant_be_recorded_isnt_made() {
        let l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "demo", NameScope::Run);
        let t = terms(StandingBound::Agent, None).unwrap();
        assert!(deny(&l, &op("default: nothing\n"), &id, serde_json::json!({})).is_err());
        l.fail_audit_inserts_for_tests().unwrap();
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &t, "boxes.example.com");
        let e = approve(&l, &op("default: anything\n"), &id, &t, &shown, &cfg(), serde_json::json!({})).unwrap_err();
        assert!(format!("{e:#}").contains("wasn't made"), "{e:#}");
        assert_eq!(l.name(&id).unwrap().status, "pending", "not made");
        assert!(terms(StandingBound::Agent, Some(Duration::ZERO)).is_err());
        assert!(terms(StandingBound::Agent, Some(MAX_NAME_TTL * 2)).is_err());
    }

    /// #680 review, L4: only a human whose authority covers `name` at R4 decides: an operator with
    /// the kind but a lower risk ceiling can't, nor a granter that isn't a human.
    #[test]
    fn only_a_human_with_name_at_r4_decides() {
        let l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "demo", NameScope::Run);
        let t = terms(StandingBound::Agent, None).unwrap();
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &t, "boxes.example.com");
        let r2 = op("default: { kinds: [name], max_risk: R2 }\n");
        assert!(format!("{:#}", approve(&l, &r2, &id, &t, &shown, &cfg(), serde_json::json!({})).unwrap_err()).contains("risk"));
        assert!(deny(&l, &r2, &id, serde_json::json!({})).is_err());
        let capacity = Granter::Capacity {
            grant: "g-1".into(),
            ask: wicket_store::CapacityAsk { node: "n1".into(), plan: "p".into(), region: "r".into(), hourly: 1, worst: 1 },
        };
        assert!(format!("{:#}", approve(&l, &capacity, &id, &t, &shown, &cfg(), serde_json::json!({})).unwrap_err()).contains("human"));
        assert!(deny(&l, &capacity, &id, serde_json::json!({})).is_err());
        assert_eq!(l.name(&id).unwrap().status, "pending");
        // Without names.public, nothing is approved, and the refusal is on the record.
        let none = wicket_names::NamesConfig::default();
        let e = approve(&l, &op("default: { kinds: [name] }\n"), &id, &t, &shown, &none, serde_json::json!({})).unwrap_err();
        assert!(format!("{e:#}").contains("names.public"), "{e:#}");
        // The kind at R4 (no ceiling) decides.
        approve(&l, &op("default: { kinds: [name] }\n"), &id, &t, &shown, &cfg(), serde_json::json!({})).unwrap();
    }

    /// #575 step 4d: a live standing name is renewed by a human with name authority, recorded
    /// first; a renewal that can't be recorded, or by an operator without the authority, isn't made.
    #[test]
    fn a_standing_name_is_renewed_on_the_record() {
        let l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "demo", NameScope::Standing);
        let t = terms(StandingBound::Agent, Some(DEFAULT_NAME_TTL)).unwrap();
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &t, "boxes.example.com");
        approve(&l, &op("default: anything\n"), &id, &t, &shown, &cfg(), serde_json::json!({})).unwrap();
        let before = l.name(&id).unwrap().expires_at;
        let narrow = op("default: { kinds: [http] }\n");
        assert!(renew(&l, &narrow, &id, None, serde_json::json!({})).is_err());
        assert!(renew(&l, &op("default: anything\n"), &id, Some(MAX_NAME_TTL * 2), serde_json::json!({})).is_err());
        assert_eq!(l.name(&id).unwrap().expires_at, before);
        assert_eq!(l.audit_tail(20).unwrap().iter().filter(|a| a.2 == "decision.refused").count(), 2);
        let n = renew(&l, &op("default: anything\n"), &id, None, serde_json::json!({ "via": "cli" })).unwrap();
        assert_eq!(n.expires_at, None);
        let rec = l.audit_tail(20).unwrap().into_iter().rev().find(|a| a.2 == "name.renewed").unwrap().4;
        let rec: serde_json::Value = serde_json::from_str(&rec).unwrap();
        assert_eq!(
            (rec["until"].clone(), rec["previous_until"].as_i64(), rec["via"].as_str()),
            (serde_json::Value::Null, before, Some("cli"))
        );
        l.fail_audit_inserts_for_tests().unwrap();
        let e = renew(&l, &op("default: anything\n"), &id, Some(DEFAULT_NAME_TTL), serde_json::json!({})).unwrap_err();
        assert!(format!("{e:#}").contains("wasn't made"), "{e:#}");
        assert_eq!(l.name(&id).unwrap().expires_at, None, "not made");
    }

    /// #575 review, M1: a denial and a revocation are recorded first, in the same write: one whose
    /// record can't be written isn't made, and one the ledger refuses (not pending, not live) is
    /// refused on the record.
    #[test]
    fn a_denial_and_a_revocation_are_recorded_first() {
        let refusals = |l: &Ledger| l.audit_of_kind("decision.refused").unwrap().len();
        let any = op("default: anything\n");
        // A denial that can't be recorded: still pending.
        let l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "demo", NameScope::Run);
        l.fail_audit_inserts_for_tests().unwrap();
        let e = deny(&l, &any, &id, serde_json::json!({})).unwrap_err();
        assert!(format!("{e:#}").contains("wasn't made"), "{e:#}");
        assert_eq!(l.name(&id).unwrap().status, "pending", "not made");
        // Denied, on the record; denied again: refused, on the record.
        let l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "demo", NameScope::Run);
        deny(&l, &any, &id, serde_json::json!({ "via": "cli" })).unwrap();
        assert_eq!(l.name(&id).unwrap().status, "denied");
        assert_eq!(l.audit_of_kind("decision").unwrap().len(), 1);
        assert!(deny(&l, &any, &id, serde_json::json!({})).is_err());
        assert_eq!((refusals(&l), l.audit_of_kind("decision").unwrap().len()), (1, 1), "the refusal only");
        // A revocation that can't be recorded: still live.
        let l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "demo", NameScope::Run);
        let t = terms(StandingBound::Agent, None).unwrap();
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &t, "boxes.example.com");
        approve(&l, &any, &id, &t, &shown, &cfg(), serde_json::json!({})).unwrap();
        l.fail_audit_inserts_for_tests().unwrap();
        let e = revoke(&l, "ann", &id).unwrap_err();
        assert!(format!("{e:#}").contains("wasn't made"), "{e:#}");
        assert_eq!(l.name(&id).unwrap().status, "live", "not made");
        // Revoked; revoked again: refused, on the record, and no second revocation recorded.
        let l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "demo", NameScope::Run);
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &t, "boxes.example.com");
        approve(&l, &any, &id, &t, &shown, &cfg(), serde_json::json!({})).unwrap();
        revoke(&l, "ann", &id).unwrap();
        assert!(revoke(&l, "ann", &id).is_err());
        assert_eq!((refusals(&l), l.audit_of_kind("name.revoked").unwrap().len()), (1, 1));
    }

    /// #575 review, L3 and L4: an approval's own check runs in its write, and a refusal of a
    /// decision on another tenant's name is on that tenant's record.
    #[test]
    fn a_refusal_is_on_the_names_tenants_record_and_a_check_in_the_write_refuses() {
        let l = Ledger::open_in_memory().unwrap();
        let t9 = TenantId("t9".into());
        let r = RunId("run_t".into());
        l.run_started(&t9, &r, "work", "worker").unwrap();
        let ask = NameAsk {
            tenant: &t9,
            run: &r,
            zone: "work",
            zone_digest: "d",
            principal: "spiffe://x/worker",
            label: "demo",
            port: 3000,
            service: None,
            reason: "",
            scope: NameScope::Run,
        };
        let id = l.ask_public(&ask).unwrap().0;
        let t = terms(StandingBound::Agent, None).unwrap();
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &t, "boxes.example.com");
        let check = |_: &Ledger| Err(wicket_store::StoreError::Refused("its target changed".into()));
        let e = approve_checked(&l, &op("default: anything\n"), &id, &t, &shown, &cfg(), serde_json::json!({}), check).unwrap_err();
        assert!(format!("{e:#}").contains("its target changed"), "{e:#}");
        assert_eq!(l.name(&id).unwrap().status, "pending");
        assert!(l.audit_of_kind("decision").unwrap().is_empty(), "rolled back");
        assert!(deny(&l, &op("default: nothing\n"), &id, serde_json::json!({})).is_err());
        let refused = l.audit_of_kind("decision.refused").unwrap();
        assert_eq!(refused.iter().map(|r| r.tenant.as_str()).collect::<Vec<_>>(), vec!["t9", "t9"]);
    }

    /// #575 review, L2 and L5: a node's addresses are set only with `node` authority, and a
    /// refusal, the authority's or the ledger's, is on the record without naming another node.
    #[test]
    fn a_nodes_addresses_are_set_with_node_authority_and_refusals_recorded() {
        use wicket_store::AddressChange as A;
        let mut l = Ledger::open_in_memory().unwrap();
        for (n, tenant) in [("n1", TenantId::single()), ("n9", TenantId("t9".into()))] {
            let now = wicket_store::now();
            let tok = l.create_node_token(&tenant, n, 3600).unwrap();
            let row = wicket_store::NodeRow {
                name: n.into(),
                tenant: tenant.0.clone(),
                target: format!("wicket@{n}.example"),
                host_key: "ssh-ed25519 AAAA".into(),
                host_key_fp: "SHA256:x".into(),
                node_key: "00".repeat(32),
                ssh_key: None,
                hosts: vec![],
                enrolled_at: now,
                status: "active".into(),
                revoked_at: None,
            };
            let ca = wicket_store::NodeCaRow {
                serial: format!("{n}-01"),
                node: n.into(),
                issued_at: now,
                not_after: now + 3600,
                hosts: vec![],
                status: "active".into(),
            };
            l.enrol_node(&tok, &row, &ca).unwrap();
        }
        let a = std::net::Ipv4Addr::new(1, 1, 1, 1);
        let x = serde_json::json!({ "via": "cli" });
        let refusals = |l: &Ledger| l.audit_of_kind("decision.refused").unwrap();
        // Without `node` authority: refused, on the record, nothing set.
        assert!(set_node_addresses(&l, &op("default: { kinds: [name] }\n"), "n1", None, A::Set(a), A::Keep, x.clone()).is_err());
        assert!(l.node_addresses("n1").unwrap().is_empty());
        assert_eq!(refusals(&l).len(), 1);
        // Another tenant's node has it: refused, on the record, and neither says which node.
        set_node_addresses(&l, &op("default: anything\n"), "n9", None, A::Set(a), A::Keep, x.clone()).unwrap();
        let e = set_node_addresses(&l, &op("default: anything\n"), "n1", None, A::Set(a), A::Keep, x.clone()).unwrap_err();
        assert!(!format!("{e:#}").contains("n9"), "{e:#}");
        let r = refusals(&l);
        assert_eq!((r.len(), r[1].tenant.as_str()), (2, "t0"));
        assert!(!r[1].body.contains("n9"), "{}", r[1].body);
        // With it: set, recorded with what the caller adds.
        let b = std::net::Ipv4Addr::new(8, 8, 8, 8);
        assert_eq!(set_node_addresses(&l, &op("default: { kinds: [node] }\n"), "n1", None, A::Set(b), A::Keep, x).unwrap().ipv4, Some(b));
        let rec = l.audit_of_kind("node.addresses").unwrap();
        assert!(rec.last().unwrap().body.contains("\"via\":\"cli\""));
    }

    /// #575 step 4d: setting a node's public addresses needs kind `node` at R4.
    #[test]
    fn a_nodes_addresses_need_node_authority_at_r4() {
        assert!(may_set_addresses(&op("default: anything\n"), "n1").is_ok());
        assert!(may_set_addresses(&op("default: { kinds: [node] }\n"), "n1").is_ok());
        assert!(may_set_addresses(&op("default: { kinds: [name] }\n"), "n1").is_err());
        assert!(may_set_addresses(&op("default: { kinds: [node], max_risk: R3 }\n"), "n1").is_err());
    }

    /// #575 review, M2: a later run of the agent takes up its standing name when it starts, under
    /// the zone's name and digest as the ask stored them; a run of another zone definition doesn't.
    #[test]
    fn a_later_run_takes_up_its_standing_name() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let zone: wicket_core::ZoneSpec = wicket_core::yaml::from_str("name: work\n").unwrap();
        let r1 = RunId("run_w".into());
        l.run_started(&t, &r1, "work", "worker").unwrap();
        let digest = wicket_store::zone_digest(&zone);
        let ask = NameAsk {
            tenant: &t,
            run: &r1,
            zone: "work",
            zone_digest: &digest,
            principal: "spiffe://x/worker",
            label: "demo",
            port: 3000,
            service: Some("http"),
            reason: "the demo",
            scope: NameScope::Standing,
        };
        let id = l.ask_public(&ask).unwrap().0;
        let tm = terms(StandingBound::Agent, Some(DEFAULT_NAME_TTL)).unwrap();
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &tm, "boxes.example.com");
        approve(&l, &op("default: anything\n"), &id, &tm, &shown, &cfg(), serde_json::json!({})).unwrap();
        assert_eq!(l.name(&id).unwrap().holder.as_deref(), Some("run_w"));
        l.run_ended(&r1, "done", "").unwrap();
        assert_eq!(l.name(&id).unwrap().holder, None);
        let r2 = RunId("run_x".into());
        l.run_started(&t, &r2, "work", "worker").unwrap();
        let other: wicket_core::ZoneSpec = wicket_core::yaml::from_str("name: work\nreach: [{ host: api.example.com }]\n").unwrap();
        assert!(claim_for_run(&l, &t, &r2, "spiffe://x/worker", &other).is_empty());
        let got = claim_for_run(&l, &t, &r2, "spiffe://x/worker", &zone);
        assert_eq!(got.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), vec![id.as_str()]);
        assert_eq!(l.name(&id).unwrap().holder.as_deref(), Some("run_x"));
        assert!(l.audit_tail(10).unwrap().iter().any(|a| a.2 == "name.claimed" && a.4.contains(&id)));
    }
}
