//! How a provider bills a node, as data (design §8.4), and the release rules that follow from it (§8.5).

use crate::money::MicroUsd;
use crate::model::Timestamp;

pub const HOUR: i64 = 3600;
/// Vultr's monthly cap: no instance bills more than 672 hours in a month.
pub const VULTR_MONTHLY_CAP_HOURS: u64 = 672;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BillingModel {
    /// The operator's own machines: no money effect.
    Free,
    /// Billed per *started* hour; each charge line rounded up to the cent; at most `monthly_cap_hours`
    /// hours in a month (Vultr, Hetzner).
    PerStartedHour { rate: MicroUsd, monthly_cap_hours: u64 },
    /// Billed per second with a minimum (AWS, GCP, Fly); rounded up to the cent per line.
    PerSecond { rate_per_hour: MicroUsd, min_secs: u64 },
}

impl BillingModel {
    pub fn vultr(rate: MicroUsd) -> BillingModel {
        BillingModel::PerStartedHour { rate, monthly_cap_hours: VULTR_MONTHLY_CAP_HOURS }
    }

    pub fn hourly_rate(&self) -> MicroUsd {
        match *self {
            BillingModel::Free => MicroUsd::ZERO,
            BillingModel::PerStartedHour { rate, .. } => rate,
            BillingModel::PerSecond { rate_per_hour, .. } => rate_per_hour,
        }
    }

    /// Hours started by a node alive for `lifetime` seconds: hour N covers `[(N-1)h, Nh)`, so a node
    /// alive at an exact hour boundary has started the next hour. A node that existed at all has
    /// started its first.
    pub fn started_hours(lifetime: i64) -> u64 {
        (lifetime.max(0) / HOUR) as u64 + 1
    }

    /// What one charge line costs for a node that lived `lifetime` seconds.
    pub fn billed(&self, lifetime: i64) -> MicroUsd {
        match *self {
            BillingModel::Free => MicroUsd::ZERO,
            BillingModel::PerStartedHour { rate, monthly_cap_hours } => {
                rate.times(Self::started_hours(lifetime).min(monthly_cap_hours.max(1))).ceil_to_cent()
            }
            BillingModel::PerSecond { rate_per_hour, min_secs } => {
                let secs = (lifetime.max(0) as u64).max(min_secs);
                rate_per_hour.mul_div_ceil(secs, HOUR as u64).ceil_to_cent()
            }
        }
    }

    /// The most a node leased for `lifetime` can cost: what to reserve before creating it. Under
    /// per-started-hour billing the lease ends before the hour it would otherwise run into
    /// ([`granted_until`](Self::granted_until)), so a lifetime of up to N whole hours costs N hours.
    pub fn worst_case(&self, lifetime: i64) -> MicroUsd {
        match *self {
            BillingModel::PerStartedHour { rate, monthly_cap_hours } => {
                let hours = (lifetime.max(1) as u64).div_ceil(HOUR as u64);
                rate.times(hours.min(monthly_cap_hours.max(1))).ceil_to_cent()
            }
            _ => self.billed(lifetime),
        }
    }

    /// When the next billing unit starts for a node created at `created`, seen at `now`: under
    /// per-started-hour billing, the next hour boundary strictly after `now`. `None` when keeping
    /// the node longer costs nothing extra in steps (free, or per-second billing).
    pub fn next_paid_hour_at(&self, created: Timestamp, now: Timestamp) -> Option<Timestamp> {
        match self {
            BillingModel::PerStartedHour { .. } => Some(created + Self::started_hours(now - created) as i64 * HOUR),
            _ => None,
        }
    }

    /// The end of a lease of `lifetime` seconds starting at `created`, snapped to the billing granule:
    /// under per-started-hour billing, `margin` seconds before the end of the last hour the lifetime
    /// reaches into ("minute 50"), so release happens before the next hour starts.
    pub fn granted_until(&self, created: Timestamp, lifetime: i64, margin: i64) -> Timestamp {
        match self {
            BillingModel::PerStartedHour { .. } => {
                let hours = (lifetime.max(1) as u64).div_ceil(HOUR as u64) as i64;
                created + hours * HOUR - margin
            }
            _ => created + lifetime.max(0),
        }
    }
}

/// The paid-time pool rules (the broker's, in docs/research/10-infrastructure.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolRules {
    /// Keep a released node warm only if at least this much paid time is left.
    pub pool_min_left: i64,
    /// Hand a pooled node to a new request only if at least this much paid time is left.
    pub claim_min_left: i64,
    /// Destroy this long before the next paid hour starts (minute 50): Vultr's hour starts a few
    /// seconds after ours, and the reconciler runs periodically.
    pub margin: i64,
}

impl Default for PoolRules {
    fn default() -> PoolRules {
        PoolRules { pool_min_left: 10 * 60, claim_min_left: 20 * 60, margin: 10 * 60 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseDecision {
    /// Destroy it now.
    DestroyNow,
    /// Keep it warm (already paid for) until this time, then destroy it.
    KeepUntil(Timestamp),
}

/// Whether a node nobody is using should go now or stay warm until shortly before its next paid hour.
/// It stays only if more work may come and enough of the paid hour is left to be worth it.
pub fn release_decision(model: &BillingModel, created: Timestamp, now: Timestamp, more_work_expected: bool, rules: &PoolRules) -> ReleaseDecision {
    match model.next_paid_hour_at(created, now) {
        Some(next) if more_work_expected && next - now >= rules.pool_min_left && next - rules.margin > now => {
            ReleaseDecision::KeepUntil(next - rules.margin)
        }
        _ => ReleaseDecision::DestroyNow,
    }
}

/// Whether a pooled node may take a new request now. Without stepped billing there is nothing to
/// waste, so any idle node may.
pub fn claimable(model: &BillingModel, created: Timestamp, now: Timestamp, rules: &PoolRules) -> bool {
    match model.next_paid_hour_at(created, now) {
        Some(next) => next - now >= rules.claim_min_left,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vultr(cents_per_hour_x100: u64) -> BillingModel {
        BillingModel::vultr(MicroUsd(cents_per_hour_x100 * 100))
    }

    #[test]
    fn per_started_hour_rounds_lines_up_to_the_cent_like_vultrs_pending_charges() {
        let m = vultr(89); // $0.0089/h, a 1 GB box
        assert_eq!(m.billed(46), MicroUsd::from_cents(1)); // a 46 s probe: one hour, $0.01
        assert_eq!(m.billed(137), MicroUsd::from_cents(1));
        assert_eq!(m.billed(82 * 60), MicroUsd::from_cents(2)); // 82 min: two hours, $0.0178 → $0.02
        let m = BillingModel::vultr(MicroUsd(59_500)); // $40/672 h
        assert_eq!(m.billed(3599), MicroUsd::from_cents(6));
        // The monthly cap: a month-long node bills 672 hours, not 744.
        assert_eq!(m.billed(31 * 24 * HOUR), MicroUsd(59_500 * 672).ceil_to_cent());
        assert_eq!(BillingModel::Free.billed(10 * HOUR), MicroUsd::ZERO);
    }

    #[test]
    fn an_exact_hour_boundary_starts_the_next_hour() {
        let m = vultr(140);
        let c = 1_000_000;
        assert_eq!(m.next_paid_hour_at(c, c), Some(c + HOUR));
        assert_eq!(m.next_paid_hour_at(c, c + HOUR - 1), Some(c + HOUR));
        assert_eq!(m.next_paid_hour_at(c, c + HOUR), Some(c + 2 * HOUR));
        assert_eq!(m.billed(HOUR - 1), MicroUsd::from_cents(2)); // $0.014 → $0.02
        assert_eq!(m.billed(HOUR), MicroUsd::from_cents(3)); // two hours: $0.028 → $0.03
        assert_eq!(BillingModel::PerSecond { rate_per_hour: MicroUsd(100_000), min_secs: 60 }.next_paid_hour_at(c, c), None);
    }

    #[test]
    fn the_worst_case_matches_a_lease_that_ends_at_minute_fifty() {
        let m = vultr(140);
        for lifetime in [1, 30 * 60, HOUR, 3 * HOUR, 3 * HOUR + 1] {
            let until = m.granted_until(0, lifetime, 600);
            assert_eq!(m.worst_case(lifetime), m.billed(until), "lifetime {lifetime}");
        }
        assert_eq!(m.worst_case(HOUR), MicroUsd::from_cents(2));
        assert_eq!(m.worst_case(HOUR + 1), MicroUsd::from_cents(3));
    }

    #[test]
    fn per_second_billing_has_a_minimum_and_rounds_up() {
        let m = BillingModel::PerSecond { rate_per_hour: MicroUsd(100_000), min_secs: 60 }; // $0.10/h
        assert_eq!(m.billed(1), MicroUsd::from_cents(1)); // 60 s minimum: $0.00167 → $0.01
        assert_eq!(m.billed(HOUR), MicroUsd::from_cents(10));
    }

    #[test]
    fn leases_end_at_minute_fifty_of_the_last_hour() {
        let m = vultr(140);
        let c = 7200;
        assert_eq!(m.granted_until(c, 30 * 60, 600), c + 50 * 60);
        assert_eq!(m.granted_until(c, HOUR, 600), c + 50 * 60);
        assert_eq!(m.granted_until(c, HOUR + 1, 600), c + HOUR + 50 * 60);
        assert_eq!(BillingModel::Free.granted_until(c, 90, 600), c + 90);
    }

    #[test]
    fn release_keeps_a_node_warm_only_while_enough_of_its_paid_hour_is_left() {
        let m = vultr(140);
        let r = PoolRules::default();
        let c = 0;
        // 15 minutes in, more work expected: keep it until minute 50.
        assert_eq!(release_decision(&m, c, 15 * 60, true, &r), ReleaseDecision::KeepUntil(50 * 60));
        // No more work: destroy it, paid time or not.
        assert_eq!(release_decision(&m, c, 15 * 60, false, &r), ReleaseDecision::DestroyNow);
        // 52 minutes in: less than 10 minutes left, so destroy before the next hour starts.
        assert_eq!(release_decision(&m, c, 52 * 60, true, &r), ReleaseDecision::DestroyNow);
        // In the second hour, the boundary that matters is the second one.
        assert_eq!(release_decision(&m, c, HOUR + 5 * 60, true, &r), ReleaseDecision::KeepUntil(HOUR + 50 * 60));
        // Per-second billing: nothing is paid ahead, release at once.
        let s = BillingModel::PerSecond { rate_per_hour: MicroUsd(100_000), min_secs: 60 };
        assert_eq!(release_decision(&s, c, 60, true, &r), ReleaseDecision::DestroyNow);
        assert_eq!(release_decision(&BillingModel::Free, c, 60, true, &r), ReleaseDecision::DestroyNow);
    }

    #[test]
    fn a_pooled_node_is_claimed_only_with_twenty_minutes_left() {
        let m = vultr(140);
        let r = PoolRules::default();
        assert!(claimable(&m, 0, 39 * 60, &r));
        assert!(claimable(&m, 0, 40 * 60, &r));
        assert!(!claimable(&m, 0, 41 * 60, &r));
        assert!(claimable(&BillingModel::Free, 0, 41 * 60, &r));
    }
}
