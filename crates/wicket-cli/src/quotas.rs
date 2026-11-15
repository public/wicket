//! A run's own limits, from its quota grants (#256): what its model proxy and its spawns enforce on
//! the control host is the amount of each grant, read once when its supervisor starts.
//!
//! - A root run's zone budget is recorded as its own quota grants first, made by whoever started it
//!   (`record_quota_grants` keeps one already live: a re-attached run).
//! - A child's were recorded by its parent before its supervisor started (`spawn`, adopt): a child
//!   whose parent recorded none for a resource its zone has doesn't start.
//! - A re-attached run whose grants lapsed (its supervisor was gone for longer than they last) has
//!   them recorded again from its zone, by `wicket`: the zone it was started with, which its parent
//!   checked then.
//!
//! The supervisor then keeps them live while the run runs ([`RENEW_EVERY`]), at most a day ahead
//! each time, as every grant. Memory stays the box's limits on its node, and a node's budget slices
//! are cut from these limits as before.

use anyhow::{bail, Result};
use wicket_core::{Manifest, RunId};
use wicket_proxy::llm::ModelQuota;
use wicket_store::Ledger;

/// How often a run's supervisor renews its quota grants.
pub const RENEW_EVERY: std::time::Duration = std::time::Duration::from_secs(600);

/// How a run's supervisor starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start<'a> {
    /// A root run, started by principal `by` (`user:…`).
    Root { by: &'a str },
    /// A child its parent started or adopted.
    Child,
    /// A run re-attached to (#151).
    Reattached,
}

/// What a run may use, as read from its quota grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Its model budget (None: its zone has no model route).
    pub model: Option<ModelQuota>,
    /// The boxes it may start, its children's included: its `children` quota, less its own box.
    pub max_children: u32,
}

/// Records what is still to be recorded of `run`'s quotas, as `start` says, and reads its limits.
pub fn at_start(l: &Ledger, m: &Manifest, run: &RunId, start: Start<'_>) -> Result<Limits> {
    let weight = m.agent.as_ref().map_or(0, |a| a.max_children).saturating_add(1);
    let want = crate::spawn::quotas(m, weight);
    let ttl = i64::try_from(m.zone.limits.timeout()?.as_secs()).unwrap_or(i64::MAX);
    let recorded = match start {
        Start::Root { by } => Some(l.record_quota_grants(&m.tenant, &m.zone.name, run, by, &want, ttl)?),
        Start::Reattached => Some(l.record_quota_grants(&m.tenant, &m.zone.name, run, "wicket", &want, ttl)?),
        Start::Child => None,
    };
    if let Some(ids) = &recorded {
        l.audit(&m.tenant, Some(run), "run.quotas", &serde_json::json!({ "grants": ids }))?;
    }
    let got = l.quota_amounts(&run.0)?;
    if start == Start::Child {
        if let Some(q) = want.iter().find(|q| q.amount > 0 && !got.has(q.resource)) {
            bail!("its parent recorded no {} quota for this run: it can't start without one (#256)", q.resource);
        }
    }
    let model = m.zone.llm.as_ref().map(|z| ModelQuota {
        requests: got.get("model.requests").unwrap_or(0),
        output_tokens: got.get("model.output_tokens").unwrap_or(0),
        input_tokens: z.max_input_tokens.map(|_| got.get("model.input_tokens").unwrap_or(0)),
    });
    let max_children = u32::try_from(got.get("children").unwrap_or(0).saturating_sub(1)).unwrap_or(u32::MAX);
    Ok(Limits { model, max_children })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(max_children: u32) -> Manifest {
        wicket_agent::load(&format!(
            "task: t\nagent: {{ name: lead, max_children: {max_children} }}\nzone:\n  name: z\n  llm: {{ max_requests: 40, max_output_tokens: 900, max_input_tokens: 5000 }}\n  limits: {{ memory: 1g, cpus: 1, timeout: 1h }}\n"
        ))
        .unwrap()
    }

    #[test]
    fn a_root_runs_zone_budget_is_recorded_as_its_quota_grants_and_read_back_as_its_limits() {
        let l = Ledger::open_in_memory().unwrap();
        let (m, run) = (manifest(3), RunId("run_root".into()));
        let lim = at_start(&l, &m, &run, Start::Root { by: "user:alex" }).unwrap();
        assert_eq!(lim.model, Some(ModelQuota { requests: 40, output_tokens: 900, input_tokens: Some(5000) }));
        assert_eq!(lim.max_children, 3);
        let gs = l.grants(&m.tenant, false, 100).unwrap();
        let mut got: Vec<(&str, i64, &str)> =
            gs.iter().map(|g| (g.grant.quota().unwrap(), g.grant.amount.unwrap(), g.decided_by.as_str())).collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("bytes", 1 << 30, "user:alex"),
                ("children", 4, "user:alex"),
                ("model.input_tokens", 5000, "user:alex"),
                ("model.output_tokens", 900, "user:alex"),
                ("model.requests", 40, "user:alex"),
            ]
        );
        assert!(gs.iter().all(|g| g.grant.expires_at <= wicket_store::now() + 3600), "its timeout, at most a day");
        // Re-attached: kept, not doubled.
        assert_eq!(at_start(&l, &m, &run, Start::Reattached).unwrap(), lim);
        assert_eq!(l.grants(&m.tenant, true, 100).unwrap().len(), 5);
    }

    #[test]
    fn a_childs_limits_are_what_its_parent_granted_it() {
        let l = Ledger::open_in_memory().unwrap();
        let (m, run) = (manifest(2), RunId("run_child".into()));
        // Nothing recorded by a parent: it doesn't start.
        let e = at_start(&l, &m, &run, Start::Child).unwrap_err().to_string();
        assert!(e.contains("recorded no"), "{e}");
        // Its parent granted less than its manifest says: the grants are the limit.
        use wicket_store::Quota;
        let carved = [
            Quota { resource: "model.requests", amount: 7 },
            Quota { resource: "model.output_tokens", amount: 70 },
            Quota { resource: "model.input_tokens", amount: 700 },
            Quota { resource: "children", amount: 2 },
            Quota { resource: "bytes", amount: 1 << 30 },
        ];
        l.record_quota_grants(&m.tenant, "z", &run, "agent:run_parent", &carved, 600).unwrap();
        let lim = at_start(&l, &m, &run, Start::Child).unwrap();
        assert_eq!(lim.model, Some(ModelQuota { requests: 7, output_tokens: 70, input_tokens: Some(700) }));
        assert_eq!(lim.max_children, 1);
        // Revoked: no longer a limit to spend. Re-attached, recorded again from its zone by wicket.
        for g in l.quota_grants(&run.0).unwrap() {
            l.revoke_grant(&g.id).unwrap();
        }
        let lim = at_start(&l, &m, &run, Start::Reattached).unwrap();
        assert_eq!((lim.model.map(|q| q.requests), lim.max_children), (Some(40), 2));
        assert!(l.grants(&m.tenant, false, 100).unwrap().iter().all(|g| g.decided_by == "wicket"));
    }
}
