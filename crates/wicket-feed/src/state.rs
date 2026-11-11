//! The replicated state, the same on the control plane and the node, generic over the zone policy
//! payload ([`Policy`]).

use crate::format::{Change, Delta, Grant, RevokeKind, Revoked, RevokedMap, Snapshot, GENESIS};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use wicket_core::{CompiledZone, Op, Verdict, ZoneSpec};

/// A zone's policy as the feed carries it. Today it is a [`ZoneSpec`]; #76's capability tokens
/// replace it behind this trait without changing the feed, the replica or the publisher.
pub trait Policy: Clone + Debug + Serialize + DeserializeOwned {
    /// The policy in the form decisions use, built once when an update is applied.
    type Compiled;
    /// The zone it is for: the key in [`State::zones`].
    fn zone_name(&self) -> &str;
    /// Prepares the policy for decisions. An error is kept, not refused (refusing a signed delta
    /// would desynchronise the chain): such a zone forbids everything.
    fn compile(&self) -> Result<Self::Compiled, String>;
    /// The verdict for one op.
    fn evaluate(compiled: &Self::Compiled, op: &Op) -> Verdict;
}

impl Policy for ZoneSpec {
    type Compiled = CompiledZone;

    fn zone_name(&self) -> &str {
        &self.name
    }

    fn compile(&self) -> Result<CompiledZone, String> {
        CompiledZone::new(self.clone()).map_err(|e| e.to_string())
    }

    fn evaluate(compiled: &CompiledZone, op: &Op) -> Verdict {
        compiled.evaluate(op)
    }
}

/// A zone's policy, and its compiled form (or why it didn't compile).
pub struct Zone<P: Policy> {
    pub spec: P,
    pub compiled: Result<P::Compiled, String>,
}

impl<P: Policy> Zone<P> {
    fn new(spec: P) -> Zone<P> {
        let compiled = spec.compile();
        Zone { spec, compiled }
    }

    /// The verdict for one op; `Forbidden` if the policy didn't compile.
    pub fn evaluate(&self, op: &Op) -> Verdict {
        match &self.compiled {
            Ok(c) => P::evaluate(c, op),
            Err(e) => Verdict::Forbidden(format!("this zone's policy is invalid: {e}")),
        }
    }
}

/// Zone policies, grants, revocations and the epoch and head they are at.
pub struct State<P: Policy> {
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
    pub fn genesis(version: u64) -> State<P> {
        State {
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
        for c in &d.changes {
            self.change(c);
        }
        self.epoch = d.epoch;
        self.head = head;
    }

    pub fn is_revoked(&self, kind: RevokeKind, id: &str) -> bool {
        self.revoked.contains_key(&(kind, id.to_string()))
    }

    /// Number of revocations held.
    pub fn revoked_len(&self) -> usize {
        self.revoked.len()
    }

    fn change(&mut self, c: &Change<P>) {
        match c {
            Change::PutZone { zone } => {
                self.zones.insert(zone.zone_name().to_string(), Zone::new(zone.clone()));
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

    pub fn from_snapshot(s: &Snapshot<P>) -> State<P> {
        let mut st = State::genesis(s.version);
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
