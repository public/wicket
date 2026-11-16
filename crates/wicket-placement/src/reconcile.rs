//! The reconciler's decision, as a pure function (for #38, which runs it at start-up and
//! periodically): what should exist (leases) against what the provider says exists (by tag).
//!
//! Rules:
//! - A node without this installation's owner tag, or with `wicket-protected`, is never touched
//!   ([`Action::Ignore`]): the control host lives in the same account.
//! - A lease with no node is created ([`Action::Create`]), unless it has already ended.
//! - A node whose lease is live, or that is pinned (a task or a parked snapshot is on it), is kept.
//! - A node with no lease, or an ended one, is kept warm until shortly before its next paid hour if
//!   `warm_pool` says more work may come and enough paid time is left ([`Action::Pool`]); otherwise it
//!   is destroyed.
//! - Two nodes for one lease (two processes raced a create): the oldest is kept, the rest destroyed.
//!
//! What it can't tell from leases alone: whether a node no lease asks for is an orphan or one its
//! creator hasn't recorded yet (#324: `wicket node create` records its node as soon as the
//! provider answers, and a pass that listed the instance in between destroyed a node its human had
//! just been given). A caller that knows no record of a node's idempotency key leaves it alone while
//! [`too_new_to_judge`] says so: an orphan a crash left is destroyed once the grace is over, still
//! early in its first paid hour.

use crate::billing::{release_decision, PoolRules, ReleaseDecision};
use crate::model::{NodeHandle, NodeId, NodeState, Owner, Timestamp, PROTECTED_TAG};
use std::collections::BTreeMap;

/// A lease: a node that should exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Desired {
    pub idempotency_key: String,
    pub lease_until: Timestamp,
    /// A task or parked snapshot is on it: keep it past its lease until that is resolved. A pinned
    /// lease whose node is gone still yields `Create`, which restores nothing that was on it; #38
    /// decides what a lost pinned node means for its task.
    pub pinned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DestroyReason {
    NoLease,
    LeaseEnded,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IgnoreReason {
    NotOwned,
    Protected,
}

/// How long a node nothing records is left alone after its creation, for its creator to record it.
pub const UNRECORDED_GRACE_SECS: i64 = 10 * 60;

/// For a node no record knows: until when it is left for its creator to record (None: it is old
/// enough to be an orphan). A creation time ahead of `now` (clock skew) counts as new.
pub fn too_new_to_judge(n: &NodeHandle, now: Timestamp) -> Option<Timestamp> {
    (now - n.created_at < UNRECORDED_GRACE_SECS).then_some(n.created_at + UNRECORDED_GRACE_SECS)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Create { idempotency_key: String },
    Keep { node: NodeId, idempotency_key: String },
    Pool { node: NodeId, until: Timestamp },
    Destroy { node: NodeId, reason: DestroyReason },
    Ignore { node: NodeId, reason: IgnoreReason },
}

pub fn reconcile(
    owner: &Owner,
    desired: &[Desired],
    observed: &[NodeHandle],
    now: Timestamp,
    warm_pool: bool,
    rules: &PoolRules,
) -> Vec<Action> {
    let mut actions = vec![];
    // Owned, live nodes by idempotency tag, oldest first.
    let mut by_tag: BTreeMap<String, Vec<&NodeHandle>> = BTreeMap::new();
    for n in observed.iter().filter(|n| n.state != NodeState::Gone) {
        if !owner.owns(n) {
            actions.push(Action::Ignore { node: n.id.clone(), reason: IgnoreReason::NotOwned });
        } else if n.has_tag(PROTECTED_TAG) {
            actions.push(Action::Ignore { node: n.id.clone(), reason: IgnoreReason::Protected });
        } else {
            by_tag.entry(Owner::idem_tag_of(n).unwrap_or_default().to_string()).or_default().push(n);
        }
    }
    for v in by_tag.values_mut() {
        v.sort_by_key(|n| (n.created_at, n.id.clone()));
    }
    let idle = |n: &NodeHandle, reason: DestroyReason| match release_decision(&n.billing, n.created_at, now, warm_pool, rules) {
        ReleaseDecision::KeepUntil(until) => Action::Pool { node: n.id.clone(), until },
        ReleaseDecision::DestroyNow => Action::Destroy { node: n.id.clone(), reason },
    };
    for d in desired {
        let live = d.pinned || d.lease_until > now;
        match by_tag.remove(&owner.idem_tag(&d.idempotency_key)) {
            None if live => actions.push(Action::Create { idempotency_key: d.idempotency_key.clone() }),
            None => {}
            Some(nodes) => {
                let (first, rest) = nodes.split_first().expect("non-empty");
                actions.push(if live {
                    Action::Keep { node: first.id.clone(), idempotency_key: d.idempotency_key.clone() }
                } else {
                    idle(first, DestroyReason::LeaseEnded)
                });
                actions.extend(rest.iter().map(|n| Action::Destroy { node: n.id.clone(), reason: DestroyReason::Duplicate }));
            }
        }
    }
    // Owned nodes no lease asks for.
    for n in by_tag.into_values().flatten() {
        actions.push(idle(n, DestroyReason::NoLease));
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::BillingModel;
    use crate::model::{IsolationTier, Resources};
    use crate::money::MicroUsd;

    fn node(owner: &Owner, id: &str, key: Option<&str>, created: Timestamp, extra: &[&str]) -> NodeHandle {
        let mut tags = vec![owner.tag()];
        tags.extend(key.map(|k| owner.idem_tag(k)));
        tags.extend(extra.iter().map(|t| t.to_string()));
        NodeHandle {
            id: NodeId(id.into()),
            backend: "fake".into(),
            name: id.into(),
            ssh_target: None,
            region: None,
            plan: None,
            isolation: IsolationTier::Gvisor,
            resources: Resources { vcpus: 1, memory_mib: 2048 },
            billing: BillingModel::vultr(MicroUsd(14_000)),
            created_at: created,
            lease_until: None,
            host_key: None,
            tags,
            state: NodeState::Active,
        }
    }

    fn d(key: &str, until: Timestamp, pinned: bool) -> Desired {
        Desired { idempotency_key: key.into(), lease_until: until, pinned }
    }

    #[test]
    fn untagged_and_protected_machines_are_never_touched() {
        let me = Owner::new("example");
        let other = Owner::new("someone-else");
        let mut untagged = node(&me, "control-host", None, 0, &[]);
        untagged.tags.clear();
        let obs = vec![untagged, node(&other, "theirs", Some("k"), 0, &[]), node(&me, "broker", None, 0, &[PROTECTED_TAG])];
        let a = reconcile(&me, &[], &obs, 10_000, false, &PoolRules::default());
        assert_eq!(
            a,
            vec![
                Action::Ignore { node: NodeId("control-host".into()), reason: IgnoreReason::NotOwned },
                Action::Ignore { node: NodeId("theirs".into()), reason: IgnoreReason::NotOwned },
                Action::Ignore { node: NodeId("broker".into()), reason: IgnoreReason::Protected },
            ]
        );
    }

    #[test]
    fn leases_without_nodes_are_created_and_live_ones_kept() {
        let me = Owner::new("example");
        let obs = vec![node(&me, "n1", Some("a"), 0, &[])];
        let a = reconcile(&me, &[d("a", 3000, false), d("b", 3000, false), d("old", 10, false)], &obs, 100, false, &PoolRules::default());
        assert_eq!(
            a,
            vec![Action::Keep { node: NodeId("n1".into()), idempotency_key: "a".into() }, Action::Create { idempotency_key: "b".into() },]
        );
    }

    #[test]
    fn orphans_after_a_crash_are_destroyed_or_pooled_by_paid_time() {
        let me = Owner::new("example");
        let obs = [node(&me, "orphan", Some("gone"), 0, &[]), node(&me, "late", Some("gone2"), 0, &[])];
        // No warm pool: everything without a lease goes.
        let a = reconcile(&me, &[], &obs[..1], 15 * 60, false, &PoolRules::default());
        assert_eq!(a, vec![Action::Destroy { node: NodeId("orphan".into()), reason: DestroyReason::NoLease }]);
        // Warm pool: kept until minute 50 while 10+ minutes are paid; destroyed after.
        let a = reconcile(&me, &[], &obs[..1], 15 * 60, true, &PoolRules::default());
        assert_eq!(a, vec![Action::Pool { node: NodeId("orphan".into()), until: 50 * 60 }]);
        let a = reconcile(&me, &[], &obs[1..], 55 * 60, true, &PoolRules::default());
        assert_eq!(a, vec![Action::Destroy { node: NodeId("late".into()), reason: DestroyReason::NoLease }]);
    }

    #[test]
    fn ended_leases_go_unless_pinned_and_duplicates_go_always() {
        let me = Owner::new("example");
        let obs = vec![node(&me, "b2", Some("k"), 20, &[]), node(&me, "b1", Some("k"), 10, &[]), node(&me, "p", Some("pinned"), 0, &[])];
        let a = reconcile(&me, &[d("k", 50, false), d("pinned", 50, true)], &obs, 100, false, &PoolRules::default());
        assert_eq!(
            a,
            vec![
                Action::Destroy { node: NodeId("b1".into()), reason: DestroyReason::LeaseEnded },
                Action::Destroy { node: NodeId("b2".into()), reason: DestroyReason::Duplicate },
                Action::Keep { node: NodeId("p".into()), idempotency_key: "pinned".into() },
            ]
        );
    }

    /// #324: a node nothing records yet is left for its creator while it is new, then judged.
    #[test]
    fn a_node_too_new_to_be_recorded_is_left_alone_until_the_grace_ends() {
        let me = Owner::new("example");
        let n = node(&me, "fresh", Some("place-create:p0"), 1_000, &[]);
        assert_eq!(too_new_to_judge(&n, 1_030), Some(1_000 + UNRECORDED_GRACE_SECS));
        assert_eq!(too_new_to_judge(&n, 990), Some(1_000 + UNRECORDED_GRACE_SECS), "a clock behind the provider's");
        assert_eq!(too_new_to_judge(&n, 1_000 + UNRECORDED_GRACE_SECS), None);
    }

    #[test]
    fn gone_nodes_are_not_reported() {
        let me = Owner::new("example");
        let mut n = node(&me, "x", None, 0, &[]);
        n.state = NodeState::Gone;
        assert_eq!(reconcile(&me, &[], &[n], 100, false, &PoolRules::default()), vec![]);
    }
}
