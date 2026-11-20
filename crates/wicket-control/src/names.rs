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

/// A live public name that gets no records: (its id, why).
pub type Unpublished = (String, String);

/// What one pass of the reconciler did.
#[derive(Debug)]
pub struct Reconciled {
    pub plan: wicket_names::Plan,
    /// Whether the provider changed the zone (never, for `noop`).
    pub applied: bool,
    /// Live public names that get no records this pass: (name id, why).
    pub skipped: Vec<Unpublished>,
    /// Host ports quarantined after release that may be handed out again from now on.
    pub freed: usize,
}

/// The records the ledger wants published (#575 design, "Records and reconciliation"): for each
/// live public name held by a running box, an A and an AAAA record for its node's public addresses.
/// A name gets none, and is listed in the second half with why, when its label isn't allowed under
/// the settings as they are now (#575 review, M1: a label reserved since it was approved), no run
/// holds it, its node isn't known or has no public address, or the node lacks the labels
/// `names.public.nodes` asks for. The SRV record comes with the name's host port (step 4c).
pub fn desired(l: &Ledger, public: &wicket_names::PublicConfig) -> Result<(Vec<wicket_names::Desired>, Vec<Unpublished>)> {
    let rules = public.rules();
    let zone = public.dns_zone();
    let (mut want, mut skipped) = (vec![], vec![]);
    for n in l.live_public_names_all()? {
        let fqdn = zone.name(&n.label);
        let why = (|| -> Result<std::result::Result<wicket_names::Desired, String>> {
            if let Err(e) = wicket_names::check_label(&n.label, &rules) {
                return Ok(Err(format!("{fqdn} isn't allowed here now: {e}")));
            }
            let Some(run) = n.holder.as_deref() else { return Ok(Err(format!("{fqdn}: no run holds it"))) };
            if l.run_status(run)?.as_deref() != Some("running") {
                return Ok(Err(format!("{fqdn}: run {run} isn't running")));
            }
            let Some(node) = l.run_node(run)? else { return Ok(Err(format!("{fqdn}: run {run} has no node yet"))) };
            let labels = l.node_labels(&node)?;
            if let Some((k, v)) = public.nodes.iter().find(|(k, v)| labels.get(*k) != Some(*v)) {
                return Ok(Err(format!("{fqdn}: node {node} can't publish (it has no label {k}={v})")));
            }
            let a = l.node_addresses(&node)?;
            if a.is_empty() {
                return Ok(Err(format!("{fqdn}: node {node} has no public address (wicket node set {node} --public-ipv4 …)")));
            }
            let mut records = vec![];
            records.extend(a.ipv4.map(|v4| wicket_names::Record::a(&fqdn, v4, public.ttl)));
            records.extend(a.ipv6.map(|v6| wicket_names::Record::aaaa(&fqdn, v6, public.ttl)));
            Ok(Ok(wicket_names::Desired { name: fqdn.clone(), grant: n.id.clone(), records, ttl: public.ttl }))
        })()?;
        match why {
            Ok(d) => want.push(d),
            Err(e) => skipped.push((n.id.clone(), e)),
        }
    }
    Ok((want, skipped))
}

/// One pass of the reconciler (`wicket reconcile`, the console's tick, and after a human's
/// decision on a name): lists the zone, plans the changes that make wicket's owned records the
/// [`desired`] ones and never touches another record ([`wicket_names::plan`]), and applies them.
///
/// - A provider that publishes has the plan's new records listed as this installation's before
///   it applies (so a crash leaves only records the ledger knows of), and the deleted ones
///   forgotten after; each change is audited `name.record`.
/// - The `noop` provider applies nothing and owns nothing: its plan is only recorded.
/// - The plan, with its conflicts and the names left out, is audited `name.plan` when it differs
///   from the last one recorded, so a pass that finds nothing new adds nothing to the record. Each
///   conflict is audited `name.conflict` then too.
/// - A host port released by a name is freed for reuse once no owned record of that name is left,
///   after twice the TTL, so a cached record for the old name doesn't reach the next box.
///
/// A dry run (`dry_run`) lists and plans only: nothing is applied, recorded or freed, and `freed`
/// counts the ports that would be. None where the installation publishes no names.
pub async fn reconcile<P: wicket_names::DnsProvider>(
    l: &Ledger,
    names: &wicket_names::NamesConfig,
    provider: &P,
    dry_run: bool,
) -> Result<Option<Reconciled>> {
    let Some(public) = names.public.as_ref() else { return Ok(None) };
    let zone = public.dns_zone();
    let owner = public.owner_id().ok_or_else(|| anyhow::anyhow!("names.public.owner isn't an owner id"))?;
    let (want, skipped) = desired(l, public)?;
    let zone_records = provider.list(&zone).await.map_err(|e| anyhow::anyhow!("listing {}: {e}", zone.apex()))?;
    let plan = wicket_names::plan(&zone, &owner, &want, &zone_records, &l.owned(&zone)?)?;
    let tenant = TenantId::single();
    let mut applied = false;
    if dry_run {
        let owned = l.owned_records(&zone)?;
        let freed = l
            .quarantined_ports()?
            .into_iter()
            .filter(|(_, _, _, last)| !l.name(last).ok().is_some_and(|n| owned.iter().any(|r| r.base() == zone.name(&n.label))))
            .count();
        return Ok(Some(Reconciled { plan, applied, skipped, freed }));
    }
    if !plan.is_empty() {
        if provider.publishes() {
            l.owned_before_apply(&zone, provider.id(), &plan)?;
            applied = provider.apply(&zone, &plan).await.map_err(|e| anyhow::anyhow!("applying to {}: {e}", zone.apex()))?.applied;
            l.owned_after_apply(&zone, &plan)?;
            for c in &plan.changes {
                l.audit(&tenant, None, "name.record", &serde_json::json!({ "zone": zone.apex(), "provider": provider.id(), "change": c }))?;
            }
        } else {
            provider.apply(&zone, &plan).await.map_err(|e| anyhow::anyhow!("planning for {}: {e}", zone.apex()))?;
        }
    }
    let body = serde_json::json!({
        "zone": zone.apex(), "provider": provider.id(), "applied": applied, "changes": plan.changes, "conflicts": plan.conflicts,
        "skipped": skipped.iter().map(|(id, why)| serde_json::json!({ "name": id, "why": why })).collect::<Vec<_>>(),
    });
    let last = l.last_audit_body("name.plan")?;
    let nothing = plan.is_empty() && plan.conflicts.is_empty() && skipped.is_empty();
    if last.as_deref() != Some(body.to_string().as_str()) && !(last.is_none() && nothing) {
        l.audit(&tenant, None, "name.plan", &body)?;
        for c in &plan.conflicts {
            l.audit(&tenant, None, "name.conflict", &serde_json::json!({ "zone": zone.apex(), "conflict": c }))?;
        }
    }
    // Quarantined ports: free once their name's records are gone.
    let owned = l.owned_records(&zone)?;
    let mut freed = 0;
    let after = wicket_store::now() + 2 * i64::from(public.ttl);
    for (node, proto, port, last_name) in l.quarantined_ports()? {
        let fqdn = l.name(&last_name).ok().map(|n| zone.name(&n.label));
        if fqdn.is_some_and(|f| owned.iter().any(|r| r.base() == f)) {
            continue;
        }
        l.free_port_after(&node, &proto, port, after)?;
        freed += 1;
    }
    Ok(Some(Reconciled { plan, applied, skipped, freed }))
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

    /// A live public name of `principal`'s run `run` on node `n1`, approved.
    fn live(l: &Ledger, run: &str, principal: &str, label: &str) -> String {
        let t = TenantId::single();
        let r = RunId(run.into());
        l.run_started(&t, &r, "work", "worker").unwrap();
        l.set_run_node(run, "n1").unwrap();
        let ask = NameAsk {
            tenant: &t,
            run: &r,
            zone: "work",
            zone_digest: "d",
            principal,
            label,
            port: 3000,
            service: Some("http"),
            reason: "the demo",
            scope: NameScope::Run,
        };
        let id = l.ask_public(&ask).unwrap().0;
        let tm = terms(StandingBound::Agent, None).unwrap();
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &tm, "boxes.example.com");
        approve(l, &op("default: anything\n"), &id, &tm, &shown, &cfg(), serde_json::json!({})).unwrap();
        id
    }

    fn node(l: &Ledger) {
        l.enrol_builtin_node(&wicket_store::NodeRow {
            name: "n1".into(),
            tenant: TenantId::single().0,
            target: "unix:/x/ctl.sock".into(),
            host_key: String::new(),
            host_key_fp: String::new(),
            node_key: "00".into(),
            ssh_key: None,
            hosts: vec![],
            enrolled_at: 1,
            status: "active".into(),
            revoked_at: None,
        })
        .unwrap();
    }

    fn kinds(l: &Ledger, kind: &str) -> usize {
        l.audit_tail(200).unwrap().iter().filter(|a| a.2 == kind).count()
    }

    /// #575 step 4b: the reconciler publishes a live name's records at its node's addresses, owner
    /// record first, leaves a name someone else holds in the zone as a conflict, takes the records
    /// away when the name ends (owner record last), and frees its port once they are gone.
    #[tokio::test]
    async fn the_reconciler_publishes_owned_records_and_nothing_else() {
        use wicket_names::{Record, RecordType};
        let l = Ledger::open_in_memory().unwrap();
        node(&l);
        let zone = wicket_names::Zone::new("boxes.example.com");
        let foreign = Record::a("taken.boxes.example.com", "1.1.1.1".parse().unwrap(), 300);
        let dns = wicket_names::MemoryProvider::new(zone.clone(), vec![foreign.clone()]);
        let demo = live(&l, "run_a", "spiffe://x/a", "demo");
        let taken = live(&l, "run_b", "spiffe://x/b", "taken");
        l.allocate_port("n1", "tcp", &demo, 20000..=20999, None).unwrap();

        // No address on the node yet: both are left out, and say why.
        let r = reconcile(&l, &cfg(), &dns, false).await.unwrap().unwrap();
        assert!(r.plan.is_empty());
        assert!(r.skipped.iter().all(|(_, why)| why.contains("no public address")), "{:?}", r.skipped);

        l.set_node_addresses(
            "n1",
            wicket_store::AddressChange::Set("1.1.1.1".parse().unwrap()),
            wicket_store::AddressChange::Set("2a00::1".parse().unwrap()),
            "ann",
        )
        .unwrap();
        let r = reconcile(&l, &cfg(), &dns, false).await.unwrap().unwrap();
        assert!(r.applied);
        assert_eq!(r.plan.conflicts.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), vec!["taken.boxes.example.com"]);
        let at = |name: &str| dns.records().into_iter().filter(|x| x.name == name).map(|x| x.rtype).collect::<Vec<_>>();
        let mut demo_types = at("demo.boxes.example.com");
        demo_types.sort_by_key(|t| t.to_string());
        assert_eq!(demo_types, vec![RecordType::A, RecordType::Aaaa]);
        assert_eq!(at("_wicket.demo.boxes.example.com"), vec![RecordType::Txt]);
        assert!(dns.records().contains(&foreign), "someone else's record is left");
        assert!(at("_wicket.taken.boxes.example.com").is_empty(), "never adopted");
        assert_eq!(l.owned_records(&zone).unwrap().len(), 3);
        assert_eq!((kinds(&l, "name.record"), kinds(&l, "name.conflict")), (3, 1));
        let plans = kinds(&l, "name.plan");

        // Nothing new: nothing on the record.
        let again = reconcile(&l, &cfg(), &dns, false).await.unwrap().unwrap();
        assert!(again.plan.is_empty());
        let plans_now = kinds(&l, "name.plan");
        reconcile(&l, &cfg(), &dns, false).await.unwrap().unwrap();
        assert_eq!(kinds(&l, "name.plan"), plans_now, "the same plan twice is recorded once");
        assert!(plans_now <= plans + 1);

        // A label the operator reserves since: its records go.
        let mut reserved = cfg();
        reserved.public.as_mut().unwrap().reserved.push("demo".into());
        let r = reconcile(&l, &reserved, &dns, false).await.unwrap().unwrap();
        assert!(r.skipped.iter().any(|(id, why)| id == &demo && why.contains("isn't allowed here now")), "{:?}", r.skipped);
        assert!(at("demo.boxes.example.com").is_empty() && at("_wicket.demo.boxes.example.com").is_empty());
        reconcile(&l, &cfg(), &dns, false).await.unwrap().unwrap();
        assert_eq!(at("demo.boxes.example.com").len(), 2, "back once allowed again");

        // Revoked: its records go, the owner record last, and its port is freed after twice the TTL.
        revoke(&l, "ann", &demo).unwrap();
        assert_eq!(l.quarantined_ports().unwrap().len(), 1);
        let r = reconcile(&l, &cfg(), &dns, false).await.unwrap().unwrap();
        let deleted: Vec<RecordType> = r
            .plan
            .changes
            .iter()
            .map(|c| match c {
                wicket_names::Change::Delete(x) => x.rtype,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(deleted.last(), Some(&RecordType::Txt), "{deleted:?}");
        assert!(at("demo.boxes.example.com").is_empty());
        assert!(l.owned_records(&zone).unwrap().is_empty());
        assert_eq!(r.freed, 1);
        assert!(l.quarantined_ports().unwrap().is_empty());
        let _ = taken;
    }

    /// With the `noop` provider the plan is recorded and nothing is applied or owned, and the same
    /// plan isn't recorded again on every pass.
    #[tokio::test]
    async fn the_noop_provider_records_its_plan_and_owns_nothing() {
        let l = Ledger::open_in_memory().unwrap();
        node(&l);
        l.set_node_addresses("n1", wicket_store::AddressChange::Set("1.1.1.1".parse().unwrap()), wicket_store::AddressChange::Keep, "ann")
            .unwrap();
        let noop = wicket_names::NoopProvider::new();
        assert!(reconcile(&l, &wicket_names::NamesConfig::default(), &noop, false).await.unwrap().is_none(), "no names.public: no pass");
        reconcile(&l, &cfg(), &noop, false).await.unwrap().unwrap();
        assert_eq!(kinds(&l, "name.plan"), 0, "nothing to say yet");
        live(&l, "run_a", "spiffe://x/a", "demo");
        // A dry run plans and changes nothing, the record included.
        let dry = reconcile(&l, &cfg(), &noop, true).await.unwrap().unwrap();
        assert!(!dry.plan.is_empty() && noop.plans().is_empty() && kinds(&l, "name.plan") == 0);
        let r = reconcile(&l, &cfg(), &noop, false).await.unwrap().unwrap();
        assert!(!r.applied && !r.plan.is_empty());
        assert_eq!(noop.plans().len(), 1);
        assert!(l.owned_records(&wicket_names::Zone::new("boxes.example.com")).unwrap().is_empty());
        assert_eq!((kinds(&l, "name.plan"), kinds(&l, "name.record")), (1, 0));
        let body: serde_json::Value = serde_json::from_str(&l.last_audit_body("name.plan").unwrap().unwrap()).unwrap();
        assert_eq!((body["provider"].as_str(), body["applied"].as_bool()), (Some("noop"), Some(false)));
        reconcile(&l, &cfg(), &noop, false).await.unwrap().unwrap();
        assert_eq!(kinds(&l, "name.plan"), 1, "the same plan again adds nothing");
    }
}
