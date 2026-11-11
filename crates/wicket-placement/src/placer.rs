//! [`Placer`]: the one [`Placement`] implementation, over any [`Provider`]. See the crate docs for
//! the rules it enforces.

use crate::billing::{self, PoolRules, ReleaseDecision};
use crate::envelope::{self, Approval, MoneyEnvelope, SpendApprover, SpendRequest};
use crate::model::*;
use crate::money::MicroUsd;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// How to release a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseMode {
    /// Destroy it now.
    Now,
    /// Keep it warm until shortly before its next paid hour if more work may come (and enough paid
    /// time is left), else destroy it now.
    Billing { more_work_expected: bool },
}

pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

#[derive(Default)]
struct State {
    /// Idempotency key → node, for keys this process has acquired.
    by_key: HashMap<String, NodeHandle>,
    /// Warm nodes, already paid for, released by their last user.
    pool: Vec<(NodeHandle, Timestamp)>,
}

pub struct Placer<P, A> {
    provider: P,
    approver: A,
    owner: Owner,
    envelope: MoneyEnvelope,
    rules: PoolRules,
    clock: Clock,
    state: Mutex<State>,
}

impl<P: Provider, A: SpendApprover> Placer<P, A> {
    pub fn new(provider: P, approver: A, owner: Owner, envelope: MoneyEnvelope) -> Placer<P, A> {
        Placer { provider, approver, owner, envelope, rules: PoolRules::default(), clock: Arc::new(now), state: Mutex::default() }
    }

    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_rules(mut self, rules: PoolRules) -> Self {
        self.rules = rules;
        self
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    /// Warm nodes and when each is to be destroyed (for the reconciler and the console).
    pub async fn pooled(&self) -> Vec<(NodeHandle, Timestamp)> {
        self.state.lock().await.pool.clone()
    }

    /// Destroys pooled nodes whose keep-until has passed. Returns what it destroyed.
    pub async fn expire_pool(&self) -> Result<Vec<NodeId>> {
        let now = (self.clock)();
        let expired: Vec<NodeHandle> = {
            let mut st = self.state.lock().await;
            let (gone, keep) = std::mem::take(&mut st.pool).into_iter().partition(|(_, until)| *until <= now);
            st.pool = keep;
            gone.into_iter().map(|(n, _)| n).collect()
        };
        let mut out = vec![];
        for n in expired {
            self.provider.destroy(&n.id).await?;
            out.push(n.id);
        }
        Ok(out)
    }

    fn rank_offers(&self, req: &CapacityRequest, offers: Vec<Offer>) -> Vec<Offer> {
        let mut ok: Vec<Offer> = offers
            .into_iter()
            .filter(|o| req.resources.fits_in(&o.resources) && o.isolation >= req.min_isolation)
            .filter(|o| req.max_hourly.is_none_or(|m| o.billing.hourly_rate() <= m))
            .collect();
        // Preferred plan, then preferred region, then cheapest, then smallest; otherwise the
        // provider's order (static hosts: the order the operator listed them).
        ok.sort_by_key(|o| {
            (
                req.plan_hint.as_ref().is_some_and(|p| p != &o.plan),
                req.region_hint.is_some() && o.region != req.region_hint,
                o.billing.hourly_rate(),
                o.resources.vcpus,
                o.resources.memory_mib,
            )
        });
        ok
    }

    async fn owned(&self) -> Result<Vec<NodeHandle>> {
        let tag = self.owner.tag();
        Ok(self.provider.list_tagged(&tag).await?.into_iter().filter(|n| n.has_tag(&tag) && n.state != NodeState::Gone).collect())
    }
}

impl<P: Provider, A: SpendApprover> Placement for Placer<P, A> {
    async fn acquire(&self, req: &CapacityRequest) -> Result<NodeHandle> {
        // One acquire at a time: the in-process half of idempotency.
        let mut st = self.state.lock().await;
        if let Some(n) = st.by_key.get(&req.idempotency_key) {
            return Ok(n.clone());
        }
        let idem = self.owner.idem_tag(&req.idempotency_key);
        // After a restart: the provider still has it, tagged.
        if let Some(n) = self.provider.list_tagged(&idem).await?.into_iter().find(|n| self.owner.owns(n) && n.state != NodeState::Gone) {
            st.by_key.insert(req.idempotency_key.clone(), n.clone());
            return Ok(n);
        }
        let now = (self.clock)();
        // A warm node, already paid for, if one fits with enough paid time left.
        let fits = |n: &NodeHandle| {
            req.resources.fits_in(&n.resources)
                && n.isolation >= req.min_isolation
                && req.max_hourly.is_none_or(|m| n.billing.hourly_rate() <= m)
                && billing::claimable(&n.billing, n.created_at, now, &self.rules)
                && n.billing.next_paid_hour_at(n.created_at, now).is_none_or(|next| now + req.lifetime_secs <= next - self.rules.margin)
        };
        if let Some(i) = st.pool.iter().position(|(n, _)| fits(n)) {
            let (n, _) = st.pool.remove(i);
            st.by_key.insert(req.idempotency_key.clone(), n.clone());
            return Ok(n);
        }

        let offers = self.rank_offers(req, self.provider.offers(req).await?);
        let offer = offers.into_iter().next().ok_or_else(|| {
            PlacementError::NoCapacity(format!(
                "{} offers nothing with {} vCPU, {} MiB, isolation {:?} or stronger{}",
                self.provider.id(),
                req.resources.vcpus,
                req.resources.memory_mib,
                req.min_isolation,
                req.max_hourly.map(|m| format!(", at most {m}/h")).unwrap_or_default()
            ))
        })?;
        let hourly = offer.billing.hourly_rate();
        let worst = offer.billing.worst_case(req.lifetime_secs);
        if worst > MicroUsd::ZERO || hourly > MicroUsd::ZERO {
            let owned = self.owned().await?;
            let committed = envelope::committed(&owned, now);
            self.envelope.check(committed, hourly, worst).map_err(PlacementError::Envelope)?;
            let ask = SpendRequest {
                backend: self.provider.id().to_string(),
                plan: offer.plan.clone(),
                region: offer.region.clone(),
                node_name: req.name.clone(),
                purpose: req.purpose.clone(),
                hourly,
                lifetime_secs: req.lifetime_secs,
                worst_case: worst,
                committed_hourly: committed.0,
                committed_total: committed.1,
                max_hourly: self.envelope.max_hourly,
                max_total: self.envelope.max_total,
            };
            if let Approval::Denied(why) = self.approver.approve(&ask).await {
                return Err(PlacementError::NotApproved(why));
            }
        }
        let until = offer.billing.granted_until(now, req.lifetime_secs, self.rules.margin);
        let spec = CreateSpec {
            offer,
            name: req.name.clone(),
            tags: vec![self.owner.tag(), idem, Owner::lease_tag(until)],
            boot: req.boot.clone(),
        };
        let mut n = self.provider.create(&spec).await?;
        if n.host_key.is_none() {
            n.host_key = req.boot.as_ref().map(|b| b.host_key.clone());
        }
        st.by_key.insert(req.idempotency_key.clone(), n.clone());
        Ok(n)
    }

    async fn get(&self, id: &NodeId) -> Result<Option<NodeHandle>> {
        Ok(self.provider.get(id).await?.filter(|n| self.owner.owns(n)))
    }

    async fn list(&self) -> Result<Vec<NodeHandle>> {
        self.owned().await
    }

    async fn release(&self, id: &NodeId, mode: ReleaseMode) -> Result<Released> {
        let Some(n) = self.provider.get(id).await? else {
            self.forget(id).await;
            return Ok(Released::AlreadyGone);
        };
        // Ownership is checked by tag before every destroy (#38).
        if !self.owner.owns(&n) {
            return Err(PlacementError::NotOwned(id.clone()));
        }
        if n.has_tag(PROTECTED_TAG) {
            return Err(PlacementError::Protected(id.clone()));
        }
        self.forget(id).await;
        let more = match mode {
            ReleaseMode::Now => false,
            ReleaseMode::Billing { more_work_expected } => more_work_expected,
        };
        match billing::release_decision(&n.billing, n.created_at, (self.clock)(), more, &self.rules) {
            ReleaseDecision::KeepUntil(until) => {
                self.state.lock().await.pool.push((n, until));
                Ok(Released::Pooled { until })
            }
            ReleaseDecision::DestroyNow => {
                self.provider.destroy(id).await?;
                Ok(Released::Destroyed)
            }
        }
    }

    fn next_paid_hour_at(&self, node: &NodeHandle) -> Option<Timestamp> {
        node.billing.next_paid_hour_at(node.created_at, (self.clock)())
    }
}

impl<P, A> Placer<P, A> {
    async fn forget(&self, id: &NodeId) {
        let mut st = self.state.lock().await;
        st.by_key.retain(|_, n| &n.id != id);
        st.pool.retain(|(n, _)| &n.id != id);
    }
}
