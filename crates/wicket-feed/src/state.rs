//! The replicated state, the same on the control plane and the node, generic over the zone policy
//! payload ([`Policy`]).

use crate::format::{Change, Delta, Grant, RevokeKind, Revoked, RevokedMap, Snapshot, GENESIS};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;

/// A policy entry as the feed carries it: a box's capability token
/// ([`crate::token::BoxAuthority`], what nodes decide with). The feed, the replica and the
/// publisher don't depend on what the entry is.
pub trait Policy: Clone + Debug + Serialize + DeserializeOwned {
    /// The policy in the form decisions use, built once when an update is applied.
    type Compiled;
    /// What compiling needs besides the entry itself (a token's root key), held by the [`State`].
    type Ctx: Clone;
    /// The entry's key in [`State::zones`]: the zone's name, or the box's run id.
    fn zone_name(&self) -> &str;
    /// Prepares the policy for decisions. `revoked` answers for revocations already held. An error
    /// is kept, not refused (refusing a signed delta would desynchronise the chain): such an entry
    /// forbids everything.
    fn compile(&self, ctx: &Self::Ctx, revoked: &dyn Fn(RevokeKind, &str) -> bool) -> Result<Self::Compiled, String>;
    /// Whether a revocation applied after compiling invalidates the compiled entry (a token
    /// containing a revoked block). It then forbids everything, as if it had failed to compile.
    fn revoked_by(_compiled: &Self::Compiled, _kind: RevokeKind, _id: &str) -> bool {
        false
    }
}

/// A zone's policy, and its compiled form (or why it didn't compile).
pub struct Zone<P: Policy> {
    pub spec: P,
    pub compiled: Result<P::Compiled, String>,
}

/// The compiled form of a zone a replay skipped compiling: a later change in the replay replaces or
/// drops it before anything can read it.
const SUPERSEDED: &str = "superseded later in the replay";

/// For a replay of `deltas` in order: for each delta, which of its changes is a `PutZone` that a
/// later change replaces (another `PutZone` of the same entry) or drops (`DropZone`), so compiling
/// it can be skipped (#287). A log of runs puts and drops one entry per run: only the entries still
/// held at its end are compiled.
pub fn superseded<P: Policy>(deltas: &[Delta<P>]) -> Vec<Vec<bool>> {
    let mut later: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut out: Vec<Vec<bool>> = deltas.iter().map(|d| vec![false; d.changes.len()]).collect();
    for (di, d) in deltas.iter().enumerate().rev() {
        for (ci, c) in d.changes.iter().enumerate().rev() {
            match c {
                Change::PutZone { zone } => out[di][ci] = !later.insert(zone.zone_name()),
                Change::DropZone { name } => {
                    later.insert(name);
                }
                _ => {}
            }
        }
    }
    out
}

/// Zone policies, grants, revocations and the epoch and head they are at.
pub struct State<P: Policy> {
    /// What compiling an entry needs.
    pub ctx: P::Ctx,
    pub version: u64,
    pub epoch: u64,
    pub head: String,
    pub zones: BTreeMap<String, Zone<P>>,
    pub grants: HashMap<String, Grant>,
    /// Grant ids by op digest.
    pub by_op: HashMap<String, BTreeSet<String>>,
    revoked: RevokedMap,
}

impl<P: Policy> State<P> {
    /// The empty state at epoch 0.
    pub fn genesis(version: u64, ctx: P::Ctx) -> State<P> {
        State {
            ctx,
            version,
            epoch: 0,
            head: GENESIS.into(),
            zones: BTreeMap::new(),
            grants: HashMap::new(),
            by_op: HashMap::new(),
            revoked: BTreeMap::new(),
        }
    }

    /// Applies a delta that has been checked, moving to its epoch and `head`.
    pub fn apply(&mut self, d: &Delta<P>, head: String) {
        self.apply_replaying(d, head, &[]);
    }

    /// [`State::apply`] for a replay that knows what comes later (#287): the `PutZone`s at the
    /// indices `superseded` marks (see [`superseded`]) aren't compiled, as a later change in the
    /// same replay replaces or drops each one, so nothing reads their compiled form. The state
    /// reached at the end of the replay is the same as with [`State::apply`].
    pub fn apply_replaying(&mut self, d: &Delta<P>, head: String, superseded: &[bool]) {
        for (i, c) in d.changes.iter().enumerate() {
            match c {
                Change::PutZone { zone } if superseded.get(i).copied().unwrap_or(false) => {
                    self.zones.insert(zone.zone_name().to_string(), Zone { spec: zone.clone(), compiled: Err(SUPERSEDED.into()) });
                }
                c => self.change(c),
            }
        }
        self.epoch = d.epoch;
        self.head = head;
    }

    pub fn is_revoked(&self, kind: RevokeKind, id: &str) -> bool {
        self.revoked.contains_key(&(kind, id.to_string()))
    }

    /// The revocations held.
    pub(crate) fn revoked_keys(&self) -> impl Iterator<Item = &(RevokeKind, String)> {
        self.revoked.keys()
    }

    /// Number of revocations held.
    pub fn revoked_len(&self) -> usize {
        self.revoked.len()
    }

    fn change(&mut self, c: &Change<P>) {
        match c {
            Change::PutZone { zone } => {
                let revoked = |k: RevokeKind, id: &str| self.revoked.contains_key(&(k, id.to_string()));
                let compiled = zone.compile(&self.ctx, &revoked);
                self.zones.insert(zone.zone_name().to_string(), Zone { spec: zone.clone(), compiled });
            }
            Change::DropZone { name } => {
                self.zones.remove(name);
                let ids: Vec<String> = self.grants.values().filter(|g| &g.zone == name).map(|g| g.id.clone()).collect();
                ids.iter().for_each(|id| self.drop_grant(id));
            }
            Change::AddGrant { grant } => {
                if !self.is_revoked(RevokeKind::Grant, &grant.id) {
                    self.drop_grant(&grant.id);
                    self.by_op.entry(grant.op.clone()).or_default().insert(grant.id.clone());
                    self.grants.insert(grant.id.clone(), grant.clone());
                }
            }
            Change::Revoke { kind, id, until } => {
                self.revoked.insert((*kind, id.clone()), *until);
                if *kind == RevokeKind::Grant {
                    self.drop_grant(id);
                }
                for z in self.zones.values_mut() {
                    if z.compiled.as_ref().is_ok_and(|c| P::revoked_by(c, *kind, id)) {
                        z.compiled = Err(format!("revoked ({kind:?} {id})").to_lowercase());
                    }
                }
            }
        }
    }

    fn drop_grant(&mut self, id: &str) {
        if let Some(g) = self.grants.remove(id) {
            if let Some(s) = self.by_op.get_mut(&g.op) {
                s.remove(id);
                if s.is_empty() {
                    self.by_op.remove(&g.op);
                }
            }
        }
    }

    /// Drops grants and revocations that have expired by `now`. Expired grants are never honoured
    /// anyway, and a revocation's `until` is the revoked thing's own expiry.
    pub fn prune(&mut self, now: i64) {
        let gone: Vec<String> = self.grants.values().filter(|g| g.not_after <= now).map(|g| g.id.clone()).collect();
        gone.iter().for_each(|id| self.drop_grant(id));
        self.revoked.retain(|_, until| *until > now);
    }

    /// The state as a snapshot, without grants and revocations that have expired by `now`, so
    /// snapshots stay bounded.
    pub fn snapshot(&self, feed: &str, now: i64) -> Snapshot<P> {
        let mut grants: Vec<Grant> = self.grants.values().filter(|g| g.not_after > now).cloned().collect();
        grants.sort_by(|a, b| a.id.cmp(&b.id));
        Snapshot {
            feed: feed.into(),
            version: self.version,
            epoch: self.epoch,
            head: self.head.clone(),
            issued_at: now,
            zones: self.zones.values().map(|z| z.spec.clone()).collect(),
            grants,
            revoked: self
                .revoked
                .iter()
                .filter(|(_, until)| **until > now)
                .map(|((kind, id), until)| Revoked { kind: *kind, id: id.clone(), until: *until })
                .collect(),
        }
    }

    pub fn from_snapshot(s: &Snapshot<P>, ctx: P::Ctx) -> State<P> {
        let mut st = State::genesis(s.version, ctx);
        st.epoch = s.epoch;
        st.head = s.head.clone();
        for r in &s.revoked {
            st.revoked.insert((r.kind, r.id.clone()), r.until);
        }
        for z in &s.zones {
            st.change(&Change::PutZone { zone: z.clone() });
        }
        for g in &s.grants {
            st.change(&Change::AddGrant { grant: g.clone() });
        }
        st
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::BoxAuthority;

    fn delta(changes: Vec<Change<BoxAuthority>>) -> Delta<BoxAuthority> {
        Delta { feed: "n".into(), version: 1, epoch: 1, prev: GENESIS.into(), issued_at: 0, changes }
    }

    /// A record for run `name` (only its key matters here: nothing is compiled).
    fn put(name: &str) -> Change<BoxAuthority> {
        let zone = serde_json::json!({ "run": name, "box_path": name, "epoch": 0, "zone": { "name": "z" }, "token": "" });
        Change::PutZone { zone: serde_json::from_value(zone).unwrap() }
    }

    #[test]
    fn a_put_is_superseded_by_a_later_put_or_drop_of_the_same_entry_only() {
        let drop = |n: &str| Change::DropZone { name: n.into() };
        let ds =
            vec![delta(vec![put("a"), put("b"), put("c")]), delta(vec![drop("a"), put("b")]), delta(vec![put("d"), drop("d"), put("e")])];
        assert_eq!(superseded(&ds), [vec![true, true, false], vec![false, false], vec![true, false, false]]);
    }
}
