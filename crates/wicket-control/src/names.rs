//! Decisions on public names (#575; design in `docs/explanation/box-dns.md`): a human approves a
//! box's ask for a name on the internet, denies it, or revokes an approved name. Each is on the
//! audit record, and an approval whose record can't be written is undone (fail closed).
//!
//! Only a human decides, and only one whose authority (`operators.yaml`) covers `name` decisions at
//! the highest risk: a public name lets anyone on the internet connect to the box's port and read
//! what it serves, an outbound channel as much as an inbound one. No agent's `decide` reaches it.

use crate::grant::Granter;
use anyhow::{bail, Result};
use std::time::Duration;
use wicket_core::TenantId;
use wicket_store::{Ledger, NameRow, NameScope, NameTerms, StandingBound};

/// The longest lifetime a standing name may be approved for (beyond it: until revoked).
pub const MAX_NAME_TTL: Duration = Duration::from_secs(366 * 24 * 3600);
/// The lifetime offered first.
pub const DEFAULT_NAME_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// What the human is told a public name means, on every card.
pub const WARNING: &str =
    "anyone on the internet can connect to this box's port and read whatever it serves: it is a way out for the box's data, not only a way in";

fn may_decide(by: &Granter) -> Result<crate::operators::Operator> {
    let Granter::Human(o) = by else { bail!("public names are decided by a human operator, not {}", by.label()) };
    o.may_decide(&crate::operators::Asked { kind: "name".into(), host: String::new(), risk: Some(4) }).map_err(anyhow::Error::msg)?;
    Ok(o.clone())
}

fn refused(l: &Ledger, by: &Granter, id: &str, decision: &str, why: anyhow::Error) -> anyhow::Error {
    let record = serde_json::json!({ "target": id, "decision": decision, "by": by.label(), "why": format!("{why:#}") });
    match l.audit(&TenantId::single(), None, "decision.refused", &record) {
        Ok(_) => why.context("refused (the refusal is on the audit record)"),
        Err(e) => why.context(format!("refused (the refusal could not be recorded: {e})")),
    }
}

fn merged(mut record: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
    if let (Some(r), serde_json::Value::Object(x)) = (record.as_object_mut(), extra) {
        r.extend(x);
    }
    record
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
    let n = l.name(id)?;
    if n.kind != wicket_store::NameKind::Public {
        return Err(refused(l, by, id, "approve", anyhow::anyhow!("{id} is an internal name, which needs no approval")));
    }
    let o = match may_decide(by) {
        Ok(o) => o,
        Err(why) => return Err(refused(l, by, id, "approve", why)),
    };
    let public = match public_settings(names) {
        Ok(p) => p,
        Err(why) => return Err(refused(l, by, id, "approve", why)),
    };
    let effect = match l.approve_name(id, terms, &o.label, Some(shown), public) {
        Ok(e) => e,
        Err(e @ (wicket_store::StoreError::EffectChanged(..) | wicket_store::StoreError::Refused(_))) => {
            return Err(refused(l, by, id, "approve", e.into()))
        }
        Err(e) => return Err(e.into()),
    };
    let standing = n.scope == NameScope::Standing;
    let record = serde_json::json!({
        "decision": "approve", "name": id, "label": n.label, "fqdn": public.fqdn(&n.label), "kind": "public", "port": n.port, "service": n.service,
        "by": o.label, "granter": "human", "granter_identity": o.id, "principal": n.principal, "zone": n.zone, "run": n.asked_run,
        "scope": n.scope.as_str(), "bound": standing.then(|| terms.bound.as_str()), "ttl_secs": standing.then_some(terms.ttl_secs),
        "effect_sha256": effect,
    });
    if let Err(e) = l.audit(&TenantId(n.tenant.clone()), Some(&wicket_core::RunId(n.asked_run.clone())), "decision", &merged(record, extra))
    {
        let _ = l.revoke_name(id, "wicket:audit-failed");
        return Err(anyhow::Error::from(e).context("the approval could not be recorded in the audit log, so it was undone"));
    }
    Ok(effect)
}

/// Denies public-name ask `id` as `by`; `extra` goes on the audit record.
pub fn deny(l: &Ledger, by: &Granter, id: &str, extra: serde_json::Value) -> Result<()> {
    let n = l.name(id)?;
    let o = match may_decide(by) {
        Ok(o) => o,
        Err(why) => return Err(refused(l, by, id, "deny", why)),
    };
    l.deny_name(id, &o.label)?;
    l.audit(
        &TenantId(n.tenant.clone()),
        Some(&wicket_core::RunId(n.asked_run.clone())),
        "decision",
        &merged(serde_json::json!({ "decision": "deny", "name": id, "label": n.label, "by": o.label, "granter": "human", "granter_identity": o.id }), extra),
    )?;
    Ok(())
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
    let n = l.revoke_name(id, by)?;
    l.audit(
        &TenantId(n.tenant.clone()),
        None,
        "name.revoked",
        &serde_json::json!({ "name": id, "label": n.label, "kind": n.kind.as_str(), "zone": n.zone, "by": by }),
    )?;
    Ok(n)
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

    #[test]
    fn an_approval_that_cant_be_recorded_is_undone() {
        let l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "demo", NameScope::Run);
        let t = terms(StandingBound::Agent, None).unwrap();
        assert!(deny(&l, &op("default: nothing\n"), &id, serde_json::json!({})).is_err());
        l.fail_audit_inserts_for_tests().unwrap();
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &t, "boxes.example.com");
        assert!(approve(&l, &op("default: anything\n"), &id, &t, &shown, &cfg(), serde_json::json!({})).is_err());
        assert_eq!(l.name(&id).unwrap().status, "ended", "undone");
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
