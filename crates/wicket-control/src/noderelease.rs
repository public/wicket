//! Releasing a placed node past its lease (#710): what the operator is shown, the decision, and
//! the release itself, for `wicket node release` and the console alike.
//!
//! A node `wicket node create` made is released by the reconciler once its lease ends, unless a
//! run still runs on it or keeps files a fetch didn't bring back: then it is kept, and bills, until
//! a human releases it. Releasing it destroys the machine, the boxes still running there and the
//! files it keeps, so the decision is bound to what the human was shown ([`PastLease::effect`]):
//!
//! 1. [`decide`]: only a human whose authority (`operators.yaml`) covers `capacity` at R4, on the
//!    effect shown, which must still be the node as it is now. A refusal is audited
//!    (`decision.refused`). The decision is audited (`placement.node_release_decided`) **before**
//!    anything is released: if that write fails, nothing is.
//! 2. [`release`]: the provider destroys the machine; then `placement.node_released` (the run files
//!    lost, `by`, the decision's audit sequence) and the node's enrolment is revoked. A release that
//!    fails is audited `placement.node_release_failed`, and the node stays as it was.
//!
//! `wicket node release` (root on the host) decides as root, with no effect to compare when it is
//! given none, and releases any owned node, past its lease or not; the console only a node past its
//! lease, on the effect it showed.

use crate::grant::Granter;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wicket_core::TenantId;
use wicket_placement::{NodeId, PlacementError, Placer, Provider, ReleaseMode, Released, SpendApprover};
use wicket_store::Ledger;

/// The risk a release is decided at: it destroys running boxes and work a fetch didn't collect.
pub const RISK: i64 = 4;

/// A placed node as a human deciding to release it is shown it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PastLease {
    /// The provider's instance id.
    pub id: String,
    pub name: String,
    pub backend: String,
    pub lease_until: i64,
    /// Whether its lease has ended.
    pub past_lease: bool,
    /// Runs still running on it (per-node service instances aside: they never hold a node).
    pub running: Vec<String>,
    /// Ended runs whose files on it a fetch didn't bring back: they go with it.
    pub uncollected: Vec<String>,
    /// The vault secret with the provider API key it was made with, and the owner tag's name.
    pub api_key_secret: String,
    pub owner: String,
}

impl PastLease {
    /// What releasing it does, as the human is shown it and signs.
    pub fn effect(&self) -> Value {
        json!({
            "v": 1, "kind": "node_release", "id": self.id, "name": self.name, "backend": self.backend,
            "lease_until": self.lease_until, "running": self.running, "uncollected": self.uncollected,
        })
    }

    pub fn effect_sha256(&self) -> String {
        hex::encode(Sha256::digest(self.effect().to_string().as_bytes()))
    }

    /// What releasing it does, in words.
    pub fn consequence(&self) -> String {
        let mut what = vec![format!("destroys server {} now", self.name)];
        if !self.running.is_empty() {
            what.push(format!("stops the boxes of run {} still running there", self.running.join(", ")));
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
    let instances: Vec<String> = l.live_service_instances()?.into_iter().map(|i| i.run).collect();
    let running: Vec<String> = l.running_runs_on_node(&row.name)?.into_iter().filter(|r| !instances.contains(r)).collect();
    let uncollected: Vec<String> = l.uncollected_runs_on_node(&row.name)?.into_iter().filter(|r| !running.contains(r)).collect();
    Ok(Some(PastLease {
        past_lease: row.lease_until <= now,
        id: row.id,
        name: row.name,
        backend: row.backend,
        lease_until: row.lease_until,
        running,
        uncollected,
        api_key_secret: row.api_key_secret,
        owner: row.owner,
    }))
}

/// Whether `by` may release a placed node: a human whose authority covers `capacity` at R4.
pub fn may_decide(by: &Granter) -> Result<crate::operators::Operator> {
    let Granter::Human(o) = by else { bail!("a node is released by a human operator, not {}", by.label()) };
    o.may_decide(&crate::operators::Asked { kind: "capacity".into(), host: String::new(), risk: Some(RISK) })
        .map_err(anyhow::Error::msg)?;
    Ok(o.clone())
}

/// How a release was decided.
pub struct Decision<'a> {
    pub by: &'a Granter,
    /// Root on the host (`wicket node release`): any owned node, past its lease or not, and
    /// `shown` may be None. Otherwise (the console) only a node past its lease, on the effect shown.
    pub root: bool,
    /// The sha256 of the effect the decider was shown ([`PastLease::effect_sha256`]).
    pub shown: Option<&'a str>,
    pub why: &'a str,
    /// More for the decision's audit record (`via`, the signed passkey assertion).
    pub extra: Value,
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
    let (granter, identity) = match (d.by, d.root) {
        (_, true) => ("root", None),
        (by, false) => match may_decide(by) {
            Ok(o) => ("human", Some(o.id)),
            Err(why) => return Err(refused(l, d, id, why)),
        },
    };
    let Some(n) = view(l, id, now)? else {
        return Err(refused(l, d, id, anyhow::anyhow!("no active placed node {id}")));
    };
    if !d.root && !n.past_lease {
        return Err(refused(l, d, id, anyhow::anyhow!("{}'s lease hasn't ended: it is released at its end", n.name)));
    }
    let effect = n.effect_sha256();
    match d.shown {
        Some(s) if s != effect => {
            return Err(refused(
                l,
                d,
                id,
                anyhow::anyhow!("{} changed after you were shown it (its runs or its lease): look again before releasing it", n.name),
            ))
        }
        None if !d.root => return Err(refused(l, d, id, anyhow::anyhow!("a release is decided on the effect shown"))),
        _ => {}
    }
    let mut record = json!({
        "decision": "release_node", "id": n.id, "name": n.name, "backend": n.backend, "lease_until": n.lease_until,
        "past_lease": n.past_lease, "running": n.running, "uncollected": n.uncollected, "effect_sha256": effect,
        "by": d.by.label(), "granter": granter, "granter_identity": identity, "why": d.why,
    });
    if let (Some(r), Value::Object(x)) = (record.as_object_mut(), d.extra.clone()) {
        r.extend(x);
    }
    let seq = l
        .audit(&TenantId::single(), None, "placement.node_release_decided", &record)
        .context("the decision could not be recorded in the audit log, so nothing was released")?;
    Ok((n, seq))
}

/// Releases placed node `n` with `p` (its owner's placer) after [`decide`] recorded decision `seq`:
/// destroys it, marks it released, forgets the run files that went with it, audits
/// `placement.node_released` and revokes its enrolment (`retire`). A failure is audited
/// `placement.node_release_failed`. Returns what happened, in words.
pub async fn release<Q: Provider, A: SpendApprover>(
    l: &mut Ledger,
    p: &Placer<Q, A>,
    n: &PastLease,
    by: &str,
    seq: i64,
    retire: fn(&mut Ledger, &wicket_placement::NodeHandle) -> Result<bool>,
) -> Result<String> {
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
            let _ = l.audit(
                &TenantId::single(),
                None,
                "placement.node_release_failed",
                &json!({ "id": n.id, "name": n.name, "by": by, "decision": seq, "error": e.to_string() }),
            );
            bail!("releasing {}: {e} (it is as it was)", n.name);
        }
    };
    let mut said = match r {
        Released::AlreadyGone => format!("{id} was already gone"),
        r => format!("{id}: {r:?}"),
    };
    l.placed_node_ended(&n.id, "released", &format!("released by {by}"))?;
    let name = node.as_ref().map(|h| h.name.clone()).unwrap_or_else(|| n.name.clone());
    // Files of runs a fetch didn't bring back went with it (#300): a human chose that.
    let lost = l.forget_uncollected_on_node(&name)?;
    if lost > 0 {
        said.push_str(&format!("; {lost} run(s)' uncollected files went with it"));
    }
    l.audit(
        &TenantId::single(),
        None,
        "placement.node_released",
        &json!({ "id": n.id, "name": name, "uncollected_runs_lost": lost, "by": by, "decision": seq }),
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

    fn console<'a>(by: &'a Granter, shown: Option<&'a str>) -> Decision<'a> {
        Decision { by, root: false, shown, why: "done with it", extra: json!({ "via": "console" }) }
    }

    fn kinds(l: &Ledger) -> Vec<String> {
        l.audit_tail(50).unwrap().into_iter().map(|r| r.2).collect()
    }

    fn no_retire(_: &mut Ledger, _: &wicket_placement::NodeHandle) -> Result<bool> {
        Ok(false)
    }

    /// The release itself, against the Vultr API mock: the machine is deleted and the release
    /// recorded with its decision; a machine without the owner tag is left, and that is audited.
    #[tokio::test]
    async fn a_decided_release_destroys_the_node_and_a_failed_one_leaves_it() {
        use wicket_placement::mock as vultr_mock;
        use wicket_placement::vultr::*;
        let (base, st) = vultr_mock::serve().await;
        let o = wicket_placement::Owner::new("example");
        {
            let mut m = st.lock().unwrap();
            m.instances.push(vultr_mock::instance("i-1", &[o.tag()]));
            m.instances.push(vultr_mock::instance("i-2", &[]));
        }
        let c = Client::with_base(&base, ApiKey::new(vultr_mock::KEY))
            .unwrap()
            .with_retry(Retry { attempts: 1, base: std::time::Duration::from_millis(1) });
        let p = Placer::new(VultrProvider::new(c, VultrConfig::default()), wicket_placement::envelope::DenyAll, o);
        let mut l = Ledger::open_in_memory().unwrap();
        placed(&l, "i-1", "placed-a", NOW - 60);
        placed(&l, "i-2", "placed-b", NOW - 60);
        let by = human("default: anything\n");

        let shown = view(&l, "i-1", NOW).unwrap().unwrap().effect_sha256();
        let (n, seq) = decide(&l, "i-1", &console(&by, Some(&shown)), NOW).unwrap();
        let said = release(&mut l, &p, &n, "passkey:laptop", seq, no_retire).await.unwrap();
        assert!(said.contains("i-1"), "{said}");
        assert!(st.lock().unwrap().seen.iter().any(|s| s.method == "DELETE" && s.path.ends_with("/i-1")));
        assert_eq!(l.placed_node("i-1").unwrap().unwrap().status, "released");
        let rec = l.audit_tail(1).unwrap().pop().unwrap();
        assert_eq!(rec.2, "placement.node_released");
        let b: Value = serde_json::from_str(&rec.4).unwrap();
        assert_eq!((b["decision"].as_i64(), b["by"].as_str()), (Some(seq), Some("passkey:laptop")), "{b}");

        let shown = view(&l, "i-2", NOW).unwrap().unwrap().effect_sha256();
        let (n, seq) = decide(&l, "i-2", &console(&by, Some(&shown)), NOW).unwrap();
        assert!(release(&mut l, &p, &n, "passkey:laptop", seq, no_retire).await.is_err(), "not this installation's machine");
        assert!(!st.lock().unwrap().seen.iter().any(|s| s.method == "DELETE" && s.path.ends_with("/i-2")));
        assert_eq!(l.placed_node("i-2").unwrap().unwrap().status, "active", "it is as it was");
        let rec = l.audit_tail(1).unwrap().pop().unwrap();
        assert_eq!(rec.2, "placement.node_release_failed");
        assert_eq!(serde_json::from_str::<Value>(&rec.4).unwrap()["decision"].as_i64(), Some(seq));
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
            let e = decide(&l, "i-1", &console(&by, Some(&shown)), NOW).unwrap_err();
            assert!(format!("{e:#}").contains(why), "{e:#}");
        }
        let e = decide(&l, "i-1", &console(&anyone, None), NOW).unwrap_err();
        assert!(format!("{e:#}").contains("effect shown"), "{e:#}");
        let e = decide(&l, "i-2", &console(&anyone, Some(&view(&l, "i-2", NOW).unwrap().unwrap().effect_sha256())), NOW).unwrap_err();
        assert!(format!("{e:#}").contains("lease hasn't ended"), "{e:#}");
        assert!(decide(&l, "i-9", &console(&anyone, Some(&shown)), NOW).is_err(), "not a placed node");
        assert_eq!(kinds(&l).iter().filter(|k| *k == "decision.refused").count(), 6, "every refusal is audited");

        // The run ended between being shown and signing: what was shown is stale.
        l.run_ended(&wicket_core::RunId("run_busy".into()), "ok", "done").unwrap();
        let e = decide(&l, "i-1", &console(&anyone, Some(&shown)), NOW).unwrap_err();
        assert!(format!("{e:#}").contains("changed after you were shown it"), "{e:#}");
        assert!(!kinds(&l).contains(&"placement.node_release_decided".to_string()));

        let now_shown = view(&l, "i-1", NOW).unwrap().unwrap().effect_sha256();
        let (n, seq) = decide(&l, "i-1", &console(&anyone, Some(&now_shown)), NOW).unwrap();
        assert!(n.running.is_empty());
        let rec = l.audit_tail(1).unwrap().pop().unwrap();
        assert_eq!((rec.0, rec.2.as_str()), (seq, "placement.node_release_decided"));
        let b: Value = serde_json::from_str(&rec.4).unwrap();
        assert_eq!(b["granter"], "human");
        assert_eq!(b["via"], "console");
        assert_eq!(b["effect_sha256"], now_shown);
        assert_eq!(b["why"], "done with it");
        assert!(b["granter_identity"].as_str().unwrap().ends_with("/op/passkey/laptop"), "{b}");

        // Root on the host releases a node whose lease hasn't ended, with nothing shown.
        let root = Decision { by: &anyone, root: true, shown: None, why: "wicket node release", extra: json!({ "via": "cli" }) };
        assert!(decide(&l, "placed-b", &root, NOW).is_ok());
    }
}
