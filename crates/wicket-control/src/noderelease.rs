//! Releasing a placed node (#710): what the decider is shown, the decision, and the release itself,
//! for `wicket node release` and the console's release of a node past its lease alike.
//!
//! A node `wicket node create` made is released by the reconciler once its lease ends, unless a
//! run still runs on it or keeps files a fetch didn't bring back: then it is kept, and bills, until
//! a human releases it. Releasing it destroys the machine, the boxes and service instances still
//! running there and the files it keeps, so the decision is bound to what the decider was shown
//! ([`PastLease::effect`]):
//!
//! 1. [`decide`]: an operator only within its authority (`operators.yaml`: `capacity` at R4), and
//!    from the console only a node past its lease; root on the host any node. Always on the effect
//!    shown, which must still be the node as it is now. A refusal is audited (`decision.refused`).
//!    The decision is audited (`placement.node_release_decided`) **before** anything is released:
//!    if that write fails, nothing is.
//! 2. [`release`], with the node's own placer (its owner and API key, as the reconciler's):
//!    - the node must still be what was decided on, and still active, just before the provider is
//!      asked (another release, or the reconciler, may have ended it);
//!    - its service instances are stopped as the reconciler stops them (`service.instance_stopped`);
//!    - the provider destroys the machine. A failure is audited `placement.node_release_failed`, and
//!      the node is as it was;
//!    - then the node is marked released. If something else ended it first, that is audited
//!      (`placement.node_release_already_ended`) and nothing more is done;
//!    - only on a confirmed destroy are the run files that went with it forgotten; the runs still on
//!      it are revoked either way (their boxes went with the machine);
//!    - `placement.node_released` (with `by`, the decision's sequence, what was stopped, revoked
//!      and lost), and its enrolment is revoked. A failure after the destroy is audited
//!      `placement.node_release_incomplete`.

use crate::grant::Granter;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wicket_core::TenantId;
use wicket_placement::{NodeId, PlacementError, Placer, Provider, ReleaseMode, Released, SpendApprover};
use wicket_store::Ledger;

/// The risk a release is decided at: it destroys running boxes and work a fetch didn't collect.
pub const RISK: i64 = 4;

/// A placed node as a decider is shown it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PastLease {
    /// The provider's instance id.
    pub id: String,
    pub name: String,
    pub backend: String,
    pub lease_until: i64,
    /// Whether its lease has ended.
    pub past_lease: bool,
    /// Runs still running on it (service instances aside: they never hold a node).
    pub running: Vec<String>,
    /// Live service instances on it, as `service:run`: stopped before it is destroyed.
    pub services: Vec<String>,
    /// Ended runs whose files on it a fetch didn't bring back: they go with it.
    pub uncollected: Vec<String>,
    /// The vault secret with the provider API key it was made with, and the owner tag's name.
    pub api_key_secret: String,
    pub owner: String,
}

impl PastLease {
    /// What releasing it does, as the decider is shown it and signs.
    pub fn effect(&self) -> Value {
        json!({
            "v": 2, "kind": "node_release", "id": self.id, "name": self.name, "backend": self.backend,
            "lease_until": self.lease_until, "running": self.running, "services": self.services, "uncollected": self.uncollected,
        })
    }

    pub fn effect_sha256(&self) -> String {
        hex::encode(Sha256::digest(self.effect().to_string().as_bytes()))
    }

    /// What releasing it does, in words.
    pub fn consequence(&self) -> String {
        let mut what = vec![format!("destroys server {} now", self.name)];
        if !self.running.is_empty() {
            what.push(format!("stops the boxes of run {} still running there, and revokes them", self.running.join(", ")));
        }
        if !self.services.is_empty() {
            what.push(format!("stops the service instances {} there", self.services.join(", ")));
        }
        if !self.uncollected.is_empty() {
            what.push(format!("loses the files of run {} that a fetch didn't bring back", self.uncollected.join(", ")));
        }
        what.push("revokes its enrolment".into());
        what.join(", ")
    }
}

/// Placed node `id` (its instance id, or the name `wicket node create` gave it) as it is now, if it
/// is active.
pub fn view(l: &Ledger, id: &str, now: i64) -> Result<Option<PastLease>> {
    let Some(row) = l.placed_nodes(&["active"])?.into_iter().find(|r| r.id == id || r.name == id) else { return Ok(None) };
    let instances: Vec<wicket_store::Instance> = l.live_service_instances()?;
    let running: Vec<String> = l.running_runs_on_node(&row.name)?.into_iter().filter(|r| !instances.iter().any(|i| &i.run == r)).collect();
    let services: Vec<String> = instances.iter().filter(|i| i.node == row.name).map(|i| format!("{}:{}", i.service, i.run)).collect();
    let uncollected: Vec<String> = l.uncollected_runs_on_node(&row.name)?.into_iter().filter(|r| !running.contains(r)).collect();
    Ok(Some(PastLease {
        past_lease: row.lease_until <= now,
        id: row.id,
        name: row.name,
        backend: row.backend,
        lease_until: row.lease_until,
        running,
        services,
        uncollected,
        api_key_secret: row.api_key_secret,
        owner: row.owner,
    }))
}

/// Who decides a release.
pub enum Decider<'a> {
    /// An operator: only within its authority. From the console, only a node past its lease.
    Operator { by: &'a Granter, console: bool },
    /// Root on the control host (`wicket node release`): any owned node. Its label, and its
    /// operator identity if it can be told.
    Root { label: String, identity: Option<String> },
}

impl Decider<'_> {
    pub fn label(&self) -> String {
        match self {
            Decider::Operator { by, .. } => by.label(),
            Decider::Root { label, .. } => label.clone(),
        }
    }
}

/// How a release was decided.
pub struct Decision<'a> {
    pub by: Decider<'a>,
    /// The sha256 of the effect the decider was shown ([`PastLease::effect_sha256`]).
    pub shown: &'a str,
    pub why: &'a str,
    /// More for the decision's audit record (`via`, the signed passkey assertion).
    pub extra: Value,
}

/// Whether `by` may release a placed node: a human whose authority covers `capacity` at R4.
pub fn may_decide(by: &Granter) -> Result<crate::operators::Operator> {
    let Granter::Human(o) = by else { bail!("a node is released by a human operator, not {}", by.label()) };
    o.may_decide(&crate::operators::Asked { kind: "capacity".into(), host: String::new(), risk: Some(RISK) })
        .map_err(anyhow::Error::msg)?;
    Ok(o.clone())
}

fn refused(l: &Ledger, d: &Decision, id: &str, why: anyhow::Error) -> anyhow::Error {
    let record = json!({ "target": id, "decision": "release_node", "by": d.by.label(), "why": format!("{why:#}") });
    match l.audit(&TenantId::single(), None, "decision.refused", &record) {
        Ok(_) => why.context("refused (the refusal is on the audit record)"),
        Err(e) => why.context(format!("refused (the refusal could not be recorded: {e})")),
    }
}

/// Decides to release placed node `id` as `d` says, and audits the decision before anything is
/// released. Returns the node as decided on and the decision's audit sequence, which [`release`]
/// records with the release.
pub fn decide(l: &Ledger, id: &str, d: &Decision, now: i64) -> Result<(PastLease, i64)> {
    let (granter, identity, console) = match &d.by {
        Decider::Root { identity, .. } => ("root", identity.clone(), false),
        Decider::Operator { by, console } => match may_decide(by) {
            Ok(o) => ("human", Some(o.id), *console),
            Err(why) => return Err(refused(l, d, id, why)),
        },
    };
    let Some(n) = view(l, id, now)? else {
        return Err(refused(l, d, id, anyhow::anyhow!("no active placed node {id}")));
    };
    if console && !n.past_lease {
        return Err(refused(l, d, id, anyhow::anyhow!("{}'s lease hasn't ended: it is released at its end", n.name)));
    }
    let effect = n.effect_sha256();
    if d.shown != effect {
        return Err(refused(
            l,
            d,
            id,
            anyhow::anyhow!(
                "{} changed after you were shown it (its runs, its services or its lease): look again before releasing it",
                n.name
            ),
        ));
    }
    let mut record = json!({
        "decision": "release_node", "id": n.id, "name": n.name, "backend": n.backend, "lease_until": n.lease_until,
        "past_lease": n.past_lease, "running": n.running, "services": n.services, "uncollected": n.uncollected,
        "effect_sha256": effect, "by": d.by.label(), "granter": granter, "granter_identity": identity, "why": d.why,
    });
    if let (Some(r), Value::Object(x)) = (record.as_object_mut(), d.extra.clone()) {
        r.extend(x);
    }
    let seq = l
        .audit(&TenantId::single(), None, "placement.node_release_decided", &record)
        .context("the decision could not be recorded in the audit log, so nothing was released")?;
    Ok((n, seq))
}

/// Releases placed node `n` with `p`, the node's own placer ([`crate::nodecreate::release_placer`]
/// with its owner and API key), after [`decide`] recorded decision `seq`. See the module's header
/// for the steps. Returns what happened, in words.
pub async fn release<Q: Provider, A: SpendApprover>(
    l: &mut Ledger,
    p: &Placer<Q, A>,
    n: &PastLease,
    by: &str,
    seq: i64,
    retire: fn(&mut Ledger, &wicket_placement::NodeHandle) -> Result<bool>,
    now: i64,
) -> Result<String> {
    let failed = |l: &Ledger, kind: &str, e: &str| {
        let _ = l.audit(&TenantId::single(), None, kind, &json!({ "id": n.id, "name": n.name, "by": by, "decision": seq, "error": e }));
    };
    // Still what was decided on, and still active: another release, or the reconciler, may have
    // ended it, or a run started on it, since.
    match view(l, &n.id, now)? {
        Some(now_n) if now_n.effect_sha256() == n.effect_sha256() => {}
        Some(_) => {
            failed(l, "placement.node_release_failed", "it changed after the decision (its runs, its services or its lease)");
            bail!("{} changed after it was decided on: nothing was released; decide again", n.name);
        }
        None => {
            failed(l, "placement.node_release_already_ended", "it was no longer an active placed node");
            bail!("{} was already released or ended", n.name);
        }
    }
    // Drained first, as the reconciler does (#579): its service instances are stopped, audited.
    let why = format!("its node {} is being released", n.name);
    let mut stopped = vec![];
    for i in l.live_service_instances()?.into_iter().filter(|i| i.node == n.name) {
        crate::services::stop(l, &i, &why)?;
        stopped.push(i.run);
    }
    let id = NodeId(n.id.clone());
    let r = async {
        let node = p.get(&id).await?;
        let r = p.release(&id, ReleaseMode::Now).await?;
        Ok::<_, PlacementError>((node, r))
    }
    .await;
    let (node, r) = match r {
        Ok(x) => x,
        Err(e) => {
            failed(l, "placement.node_release_failed", &e.to_string());
            bail!("releasing {}: {e} (it is as it was)", n.name);
        }
    };
    let done = finish(l, n, by, seq, node, r, stopped, retire);
    if let Err(e) = &done {
        failed(l, "placement.node_release_incomplete", &format!("{e:#}"));
    }
    done
}

/// After the provider answered: the ledger's side of a release.
#[allow(clippy::too_many_arguments)]
fn finish(
    l: &mut Ledger,
    n: &PastLease,
    by: &str,
    seq: i64,
    node: Option<wicket_placement::NodeHandle>,
    r: Released,
    stopped: Vec<String>,
    retire: fn(&mut Ledger, &wicket_placement::NodeHandle) -> Result<bool>,
) -> Result<String> {
    let id = &n.id;
    // Its own placer saw it gone, or never had it: no machine was destroyed by this release.
    let destroyed = r != Released::AlreadyGone && node.is_some();
    let mut said = if destroyed { format!("{id}: {r:?}") } else { format!("{id} was already gone") };
    if !l.placed_node_ended(id, "released", &format!("released by {by}"))? {
        // Something else (another release, the reconciler) ended it first: it records the rest.
        l.audit(
            &TenantId::single(),
            None,
            "placement.node_release_already_ended",
            &json!({ "id": id, "name": n.name, "by": by, "decision": seq, "destroyed": destroyed }),
        )?;
        said.push_str("; it had already been ended by another release, which recorded the rest");
        return Ok(said);
    }
    let name = node.as_ref().map(|h| h.name.clone()).unwrap_or_else(|| n.name.clone());
    // Files of runs a fetch didn't bring back went with it (#300): a human chose that. Only when
    // this release destroyed it: a machine the provider says is gone may be another account's.
    let lost = if destroyed { l.forget_uncollected_on_node(&name)? } else { 0 };
    if lost > 0 {
        said.push_str(&format!("; {lost} run(s)' uncollected files went with it"));
    }
    // Its runs' boxes went with the machine: their authority goes too, so nothing waits on them.
    let reason = format!("its node {name} was released");
    let mut revoked = vec![];
    for run in &n.running {
        if l.identity(run)?.is_some() {
            l.revoke(run, by, &reason)?;
            l.audit(
                &TenantId::single(),
                Some(&wicket_core::RunId(run.clone())),
                "identity.revoked",
                &json!({ "run": run, "by": by, "reason": reason, "decision": seq }),
            )?;
            revoked.push(run.clone());
        }
    }
    if !revoked.is_empty() {
        said.push_str(&format!("; revoked run {}", revoked.join(", ")));
    }
    l.audit(
        &TenantId::single(),
        None,
        "placement.node_released",
        &json!({ "id": id, "name": name, "uncollected_runs_lost": lost, "by": by, "decision": seq, "destroyed": destroyed,
                 "services_stopped": stopped, "runs_revoked": revoked }),
    )?;
    if let Some(h) = &node {
        if retire(l, h)? {
            said.push_str(&format!("; revoked node {}", h.name));
        }
    }
    Ok(said)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::{Operator, Policy};
    use wicket_placement::mock as vultr_mock;
    use wicket_store::PlacedNodeRow;

    const NOW: i64 = 1_700_000_000;

    fn placed(l: &Ledger, id: &str, name: &str, end: i64) {
        l.record_placed_node(&PlacedNodeRow {
            id: id.into(),
            backend: "vultr".into(),
            name: name.into(),
            owner: "example".into(),
            api_key_secret: "vultr-api-key".into(),
            created_at: NOW - 600,
            lease_until: end,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: None,
        })
        .unwrap();
    }

    fn human(policy: &str) -> Granter {
        Granter::Human(Operator::new("default", "passkey", "laptop", "passkey:laptop".into(), &Policy::parse(policy).unwrap()))
    }

    fn console<'a>(by: &'a Granter, shown: &'a str) -> Decision<'a> {
        Decision { by: Decider::Operator { by, console: true }, shown, why: "done with it", extra: json!({ "via": "console" }) }
    }

    fn kinds(l: &Ledger) -> Vec<String> {
        l.audit_tail(100).unwrap().into_iter().map(|r| r.2).collect()
    }

    fn no_retire(_: &mut Ledger, _: &wicket_placement::NodeHandle) -> Result<bool> {
        Ok(false)
    }

    fn running(l: &Ledger, run: &str, node: &str) {
        l.run_started(&TenantId::single(), &wicket_core::RunId(run.into()), "z", "a").unwrap();
        l.set_run_node(run, node).unwrap();
        l.put_identity(&wicket_store::IdentityRow {
            run: run.into(),
            tenant: TenantId::single().0,
            spiffe_id: format!("spiffe://w.test/t/{run}"),
            zone: "z".into(),
            agent: "a".into(),
            parent_run: None,
            accept_from: vec![],
            jws: "x.y.z".into(),
            issued_at: NOW,
        })
        .unwrap();
    }

    async fn mock(
        ids: &[(&str, bool)],
    ) -> (Placer<wicket_placement::vultr::VultrProvider, wicket_placement::envelope::DenyAll>, vultr_mock::Shared) {
        use wicket_placement::vultr::*;
        let (base, st) = vultr_mock::serve().await;
        let o = wicket_placement::Owner::new("example");
        for (id, owned) in ids {
            let tags = if *owned { vec![o.tag()] } else { vec![] };
            st.lock().unwrap().instances.push(vultr_mock::instance(id, &tags));
        }
        let c = Client::with_base(&base, ApiKey::new(vultr_mock::KEY))
            .unwrap()
            .with_retry(Retry { attempts: 1, base: std::time::Duration::from_millis(1) });
        (Placer::new(VultrProvider::new(c, VultrConfig::default()), wicket_placement::envelope::DenyAll, o), st)
    }

    fn deleted(st: &vultr_mock::Shared, id: &str) -> bool {
        st.lock().unwrap().seen.iter().any(|s| s.method == "DELETE" && s.path.ends_with(&format!("/{id}")))
    }

    /// The release itself, against the Vultr API mock: its service instances are stopped, the
    /// machine is deleted, its runs revoked and the release recorded with its decision; a machine
    /// without the owner tag is left, and that is audited.
    #[tokio::test]
    async fn a_decided_release_stops_its_services_destroys_the_node_and_a_failed_one_leaves_it() {
        let (p, st) = mock(&[("i-1", true), ("i-2", false)]).await;
        let mut l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-1", "placed-a", NOW - 60);
        placed(&l, "i-2", "placed-b", NOW - 60);
        running(&l, "run_busy", "placed-a");
        running(&l, "run_svc", "placed-a");
        l.record_service_instance("run_svc", "cache", "placed-a", &TenantId::single().0, "sha", NOW).unwrap();
        let by = human("default: anything\n");

        let n = view(&l, "i-1", NOW).unwrap().unwrap();
        assert_eq!((n.running.clone(), n.services.clone()), (vec!["run_busy".to_string()], vec!["cache:run_svc".to_string()]));
        assert!(n.consequence().contains("stops the service instances cache:run_svc"), "{}", n.consequence());
        let (n, seq) = decide(&l, "i-1", &console(&by, &n.effect_sha256()), NOW).unwrap();
        let said = release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.unwrap();
        assert!(said.contains("i-1") && said.contains("revoked run run_busy"), "{said}");
        assert!(deleted(&st, "i-1"));
        assert_eq!(l.placed_node("i-1").unwrap().unwrap().status, "released");
        assert!(l.revoked("run_busy").unwrap().is_some() && l.revoked("run_svc").unwrap().is_some());
        let ks = kinds(&l);
        let stop = ks.iter().position(|k| k == "service.instance_stopped").expect("the instance is stopped");
        assert!(stop < ks.iter().position(|k| k == "placement.node_released").unwrap());
        let rec = l.audit_tail(1).unwrap().pop().unwrap();
        assert_eq!(rec.2, "placement.node_released");
        let b: Value = serde_json::from_str(&rec.4).unwrap();
        assert_eq!(
            (b["decision"].as_i64(), b["by"].as_str(), b["destroyed"].as_bool()),
            (Some(seq), Some("passkey:laptop"), Some(true)),
            "{b}"
        );
        assert_eq!((b["services_stopped"].clone(), b["runs_revoked"].clone()), (json!(["run_svc"]), json!(["run_busy"])));

        // A second release of the same node (another tab): it is no longer an active placed node.
        let e = release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.unwrap_err();
        assert!(format!("{e:#}").contains("already released"), "{e:#}");
        assert_eq!(st.lock().unwrap().seen.iter().filter(|s| s.method == "DELETE").count(), 1, "deleted once");

        let shown = view(&l, "i-2", NOW).unwrap().unwrap().effect_sha256();
        let (n, seq) = decide(&l, "i-2", &console(&by, &shown), NOW).unwrap();
        assert!(release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.is_err(), "not this installation's machine");
        assert!(!deleted(&st, "i-2"));
        assert_eq!(l.placed_node("i-2").unwrap().unwrap().status, "active", "it is as it was");
        let rec = l.audit_tail(1).unwrap().pop().unwrap();
        assert_eq!(rec.2, "placement.node_release_failed");
        assert_eq!(serde_json::from_str::<Value>(&rec.4).unwrap()["decision"].as_i64(), Some(seq));
    }

    /// A machine its own placer finds gone isn't destroyed by this release: its uncollected files
    /// aren't forgotten. A node that changed after the decision (a run started on it) isn't
    /// released, and the provider isn't asked.
    #[tokio::test]
    async fn a_gone_machine_keeps_its_uncollected_runs_and_a_changed_node_isnt_released() {
        let (p, st) = mock(&[("i-3", true)]).await;
        let mut l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-gone", "placed-g", NOW - 60);
        placed(&l, "i-3", "placed-c", NOW - 60);
        running(&l, "run_files", "placed-g");
        l.run_ended(&wicket_core::RunId("run_files".into()), "ok", "done").unwrap();
        l.set_run_uncollected("run_files", Some("placed-g")).unwrap();
        let by = human("default: anything\n");

        let n = view(&l, "i-gone", NOW).unwrap().unwrap();
        assert_eq!(n.uncollected, ["run_files"]);
        let (n, seq) = decide(&l, "i-gone", &console(&by, &n.effect_sha256()), NOW).unwrap();
        let said = release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.unwrap();
        assert!(said.contains("already gone"), "{said}");
        assert_eq!(l.uncollected_runs_on_node("placed-g").unwrap(), ["run_files"], "not forgotten: nothing was destroyed");
        let b: Value = serde_json::from_str(&l.audit_tail(1).unwrap().pop().unwrap().4).unwrap();
        assert_eq!((b["destroyed"].as_bool(), b["uncollected_runs_lost"].as_i64()), (Some(false), Some(0)), "{b}");

        let n = view(&l, "i-3", NOW).unwrap().unwrap();
        let (n, seq) = decide(&l, "i-3", &console(&by, &n.effect_sha256()), NOW).unwrap();
        running(&l, "run_late", "placed-c");
        let e = release(&mut l, &p, &n, "passkey:laptop", seq, no_retire, NOW).await.unwrap_err();
        assert!(format!("{e:#}").contains("changed after it was decided on"), "{e:#}");
        assert!(!deleted(&st, "i-3"));
        assert_eq!(l.placed_node("i-3").unwrap().unwrap().status, "active");
    }

    #[test]
    fn a_release_is_decided_by_a_human_it_covers_on_the_effect_shown() {
        let l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-1", "placed-a", NOW - 60);
        placed(&l, "i-2", "placed-b", NOW + 3600);
        l.run_started(&TenantId::single(), &wicket_core::RunId("run_busy".into()), "z", "a").unwrap();
        l.set_run_node("run_busy", "placed-a").unwrap();
        let n = view(&l, "placed-a", NOW).unwrap().unwrap();
        assert_eq!((n.id.as_str(), n.past_lease, n.running.clone()), ("i-1", true, vec!["run_busy".to_string()]));
        assert!(n.consequence().contains("stops the boxes of run run_busy"), "{}", n.consequence());
        let shown = n.effect_sha256();

        let anyone = human("default: anything\n");
        for (by, why) in [
            (human("default: nothing\n"), "may decide nothing"),
            (human("default: { kinds: [http] }\n"), "may not decide capacity"),
            (human("default: { kinds: [capacity], max_risk: R3 }\n"), "up to risk R3"),
        ] {
            let e = decide(&l, "i-1", &console(&by, &shown), NOW).unwrap_err();
            assert!(format!("{e:#}").contains(why), "{e:#}");
        }
        let e = decide(&l, "i-2", &console(&anyone, &view(&l, "i-2", NOW).unwrap().unwrap().effect_sha256()), NOW).unwrap_err();
        assert!(format!("{e:#}").contains("lease hasn't ended"), "{e:#}");
        assert!(decide(&l, "i-9", &console(&anyone, &shown), NOW).is_err(), "not a placed node");
        assert_eq!(kinds(&l).iter().filter(|k| *k == "decision.refused").count(), 5, "every refusal is audited");

        // The run ended between being shown and signing: what was shown is stale.
        l.run_ended(&wicket_core::RunId("run_busy".into()), "ok", "done").unwrap();
        let e = decide(&l, "i-1", &console(&anyone, &shown), NOW).unwrap_err();
        assert!(format!("{e:#}").contains("changed after you were shown it"), "{e:#}");
        assert!(!kinds(&l).contains(&"placement.node_release_decided".to_string()));

        let now_shown = view(&l, "i-1", NOW).unwrap().unwrap().effect_sha256();
        let (n, seq) = decide(&l, "i-1", &console(&anyone, &now_shown), NOW).unwrap();
        assert!(n.running.is_empty());
        let rec = l.audit_tail(1).unwrap().pop().unwrap();
        assert_eq!((rec.0, rec.2.as_str()), (seq, "placement.node_release_decided"));
        let b: Value = serde_json::from_str(&rec.4).unwrap();
        assert_eq!(b["granter"], "human");
        assert_eq!(b["via"], "console");
        assert_eq!(b["effect_sha256"], now_shown);
        assert_eq!(b["why"], "done with it");
        assert!(b["granter_identity"].as_str().unwrap().ends_with("/op/passkey/laptop"), "{b}");

        // Root on the host releases a node whose lease hasn't ended; an operator on the CLI too,
        // within its authority.
        let shown_b = view(&l, "placed-b", NOW).unwrap().unwrap().effect_sha256();
        let root =
            Decision { by: Decider::Root { label: "root@host".into(), identity: None }, shown: &shown_b, why: "x", extra: json!({}) };
        assert!(decide(&l, "placed-b", &root, NOW).is_ok());
        let cli = Decision { by: Decider::Operator { by: &anyone, console: false }, shown: &shown_b, why: "x", extra: json!({}) };
        assert!(decide(&l, "placed-b", &cli, NOW).is_ok());
    }
}
