//! The one spend check (#256): money is a grant.
//!
//! - **The limit** is one tenant money quota grant, `QUOTA wicket.internal /quota/money.limit`,
//!   recorded from the installation's limits (`placement.yaml`'s `max_hourly_usd` and
//!   `max_total_usd`) by [`MONEY_LIMIT_BY`]: its `terms` hold both, its `amount` the total. It is
//!   recorded again (renewed, or replaced when the limits changed) at every check, so it lasts as
//!   long as anything is checked against it, and at most a day past that, as every grant.
//! - **What is reserved** is the live money quota grants: `/quota/money.hourly/<key>` and
//!   `/quota/money.reserved/<key>`, one pair per capacity lease (`<key>` its id, bound to the run
//!   that asked) and per node `wicket node create` makes (`<key>` `node-<name>`), revoked when the
//!   lease or the node ends.
//! - **The check** ([`check`]) runs in the transaction that records the new pair: the live pairs'
//!   sums plus the new one must fit the limit, or nothing is recorded. Two asks racing can't both fit.
//!
//! It replaces the sum over live leases that `create_lease` made and the placer's money envelope
//! (`MoneyEnvelope::check`, over the provider's own list). An owner-tagged machine the ledger
//! doesn't know is the reconciler's to destroy or adopt.

use crate::lease::{BudgetRefusal, LeaseBudget};
use crate::quota::{lease_quota_paths, quota_until, MONEY_HOURLY, MONEY_RESERVED, QUOTA_HOST, QUOTA_METHOD};
use crate::{now, Ledger, Result, MAX_QUOTA_TTL_SECS};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use wicket_core::new_grant_id;

/// The path of the tenant's money limit grant.
pub const MONEY_LIMIT_PATH: &str = "/quota/money.limit";
/// Who the money limit grant is recorded as made by: the installation's placement configuration.
pub const MONEY_LIMIT_BY: &str = "wicket:placement.yaml";
/// Who a node's money quota grants are recorded as made by (`wicket node create`).
pub const NODE_MONEY_BY: &str = "wicket:node-create";

/// The key of a node `wicket node create` made, for its money quota grants.
pub fn node_money_key(name: &str) -> String {
    format!("node-{name}")
}

/// Records `budget` as `tenant`'s money limit grant: renews the live one if it holds the same
/// limits, else revokes it and records a new one.
pub(crate) fn record_limit(conn: &rusqlite::Connection, tenant: &str, budget: LeaseBudget) -> Result<()> {
    let t = now();
    let terms = serde_json::json!({ "hourly": budget.max_hourly, "total": budget.max_total }).to_string();
    let live: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT id, terms FROM grants WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND path = ?4 AND run IS NULL
               AND amount IS NOT NULL AND revoked = 0 AND expires_at > ?5 ORDER BY created_at DESC, rowid DESC LIMIT 1",
            params![tenant, QUOTA_METHOD, QUOTA_HOST, MONEY_LIMIT_PATH, t],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((id, Some(held))) = &live {
        if serde_json::from_str::<serde_json::Value>(held).ok() == serde_json::from_str(&terms).ok() {
            conn.execute("UPDATE grants SET expires_at = ?2 WHERE id = ?1", params![id, t + MAX_QUOTA_TTL_SECS])?;
            return Ok(());
        }
    }
    conn.execute(
        "UPDATE grants SET revoked = 1 WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND path = ?4 AND run IS NULL AND revoked = 0",
        params![tenant, QUOTA_METHOD, QUOTA_HOST, MONEY_LIMIT_PATH],
    )?;
    conn.execute(
        "INSERT INTO grants (id, tenant, zone, method, host, path, prefix, uses_left, expires_at, request_id, decided_by, created_at, amount, terms)
         VALUES (?1, ?2, '', ?3, ?4, ?5, 0, NULL, ?6, NULL, ?7, ?8, ?9, ?10)",
        params![new_grant_id(), tenant, QUOTA_METHOD, QUOTA_HOST, MONEY_LIMIT_PATH, t + MAX_QUOTA_TTL_SECS, MONEY_LIMIT_BY, t, budget.max_total, terms],
    )?;
    Ok(())
}

/// `tenant`'s live money limit grant: its limits.
pub(crate) fn limit(conn: &rusqlite::Connection, tenant: &str) -> Result<Option<LeaseBudget>> {
    let terms: Option<Option<String>> = conn
        .query_row(
            "SELECT terms FROM grants WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND path = ?4 AND run IS NULL
               AND amount IS NOT NULL AND revoked = 0 AND expires_at > ?5 ORDER BY created_at DESC, rowid DESC LIMIT 1",
            params![tenant, QUOTA_METHOD, QUOTA_HOST, MONEY_LIMIT_PATH, now()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(terms.flatten().and_then(|t| {
        let v: serde_json::Value = serde_json::from_str(&t).ok()?;
        Some(LeaseBudget { max_hourly: v["hourly"].as_i64()?, max_total: v["total"].as_i64()? })
    }))
}

/// What `tenant`'s live money quota grants reserve: (hourly, total), micro-USD.
pub(crate) fn reserved(conn: &rusqlite::Connection, tenant: &str) -> Result<(i64, i64)> {
    let sum = |resource: &str| -> Result<i64> {
        Ok(conn.query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM grants WHERE tenant = ?1 AND method = ?2 AND host = ?3
               AND substr(path, 1, length(?4)) = ?4 AND amount IS NOT NULL AND revoked = 0 AND expires_at > ?5",
            params![tenant, QUOTA_METHOD, QUOTA_HOST, format!("/quota/{resource}/"), now()],
            |r| r.get(0),
        )?)
    };
    Ok((sum(MONEY_HOURLY)?, sum(MONEY_RESERVED)?))
}

/// The one spend check: records `budget` as the tenant's limit grant, then refuses `hourly` and
/// `reserved` more if the live money quota grants plus them would go over it. Run it in the
/// transaction that records them.
pub(crate) fn check(
    conn: &rusqlite::Connection,
    tenant: &str,
    budget: LeaseBudget,
    hourly: i64,
    reserved_new: i64,
) -> Result<std::result::Result<(), BudgetRefusal>> {
    record_limit(conn, tenant, budget)?;
    let max = limit(conn, tenant)?.unwrap_or(budget);
    let (h, r) = reserved(conn, tenant)?;
    if h + hourly > max.max_hourly {
        return Ok(Err(BudgetRefusal::Hourly { reserved: h, new: hourly, max: max.max_hourly }));
    }
    if r + reserved_new > max.max_total {
        return Ok(Err(BudgetRefusal::Total { reserved: r, new: reserved_new, max: max.max_total }));
    }
    Ok(Ok(()))
}

impl Ledger {
    /// Reserves money for something that isn't a lease (a node `wicket node create` makes, keyed
    /// [`node_money_key`]): the one check, then its money quota grants (`hourly` per hour and
    /// `reserved` in all, micro-USD), lasting `ttl_secs` (at most a day; [`Ledger::renew_money`]
    /// keeps them for longer), in one transaction. Nothing is recorded if it doesn't fit. Reserving
    /// again for a key that holds a live reservation keeps that one.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_money(
        &mut self,
        tenant: &str,
        key: &str,
        hourly: i64,
        reserved: i64,
        ttl_secs: i64,
        budget: LeaseBudget,
        by: &str,
    ) -> Result<std::result::Result<(), BudgetRefusal>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let [hp, rp] = lease_quota_paths(key);
        let held: i64 = tx.query_row(
            "SELECT COUNT(*) FROM grants WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND path IN (?4, ?5) AND revoked = 0 AND expires_at > ?6",
            params![tenant, QUOTA_METHOD, QUOTA_HOST, hp, rp, now()],
            |r| r.get(0),
        )?;
        if held > 0 {
            return Ok(Ok(()));
        }
        if let Err(r) = check(&tx, tenant, budget, hourly, reserved)? {
            // The limit grant as configured is kept; nothing else was recorded.
            tx.commit()?;
            return Ok(Err(r));
        }
        let (t, until) = (now(), quota_until(ttl_secs));
        for (path, amount) in [(hp, hourly), (rp, reserved)] {
            if amount > 0 {
                tx.execute(
                    "INSERT INTO grants (id, tenant, zone, method, host, path, prefix, uses_left, expires_at, request_id, decided_by, created_at, amount)
                     VALUES (?1, ?2, '', ?3, ?4, ?5, 0, NULL, ?6, NULL, ?7, ?8, ?9)",
                    params![new_grant_id(), tenant, QUOTA_METHOD, QUOTA_HOST, path, until, by, t, amount],
                )?;
            }
        }
        tx.commit()?;
        Ok(Ok(()))
    }

    /// Gives back what `key` reserved (its node was released, or never made).
    pub fn release_money(&self, key: &str) -> Result<usize> {
        crate::quota::revoke_lease_quotas(&self.conn, key)
    }

    /// Keeps `key`'s live money quota grants live until `until` (at most a day from now): the
    /// reconciler, for each node `wicket node create` made, while it bills.
    pub fn renew_money(&self, key: &str, until: i64) -> Result<usize> {
        let [hp, rp] = lease_quota_paths(key);
        let t = now();
        Ok(self.conn.execute(
            "UPDATE grants SET expires_at = ?5 WHERE method = ?1 AND host = ?2 AND path IN (?3, ?4) AND amount IS NOT NULL
               AND revoked = 0 AND expires_at > ?6 AND expires_at < ?5",
            params![QUOTA_METHOD, QUOTA_HOST, hp, rp, until.min(t + MAX_QUOTA_TTL_SECS), t],
        )?)
    }

    /// `tenant`'s live money limit grant, if one is recorded.
    pub fn money_limit(&self, tenant: &str) -> Result<Option<LeaseBudget>> {
        limit(&self.conn, tenant)
    }

    /// What `tenant`'s live money quota grants reserve: (hourly, total), micro-USD.
    pub fn money_reserved(&self, tenant: &str) -> Result<(i64, i64)> {
        reserved(&self.conn, tenant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Today's limits (`examples/placement/placement.yaml`): $2/h and $20 in all.
    const TODAY: LeaseBudget = LeaseBudget { max_hourly: 2_000_000, max_total: 20_000_000 };

    /// #256: the limit is one tenant grant; leases and nodes reserve against it together; what
    /// doesn't fit records nothing; a released reservation gives its money back.
    #[test]
    fn one_limit_grant_covers_leases_and_nodes_together() {
        let mut l = Ledger::open_in_memory().unwrap();
        assert_eq!(l.money_limit("t").unwrap(), None);
        l.reserve_money("t", &node_money_key("n1"), 1_500_000, 15_000_000, 3600, TODAY, NODE_MONEY_BY).unwrap().unwrap();
        assert_eq!(l.money_limit("t").unwrap(), Some(TODAY), "recorded as a grant");
        assert_eq!(l.money_reserved("t").unwrap(), (1_500_000, 15_000_000));
        // The hourly limit, then the total.
        assert_eq!(
            l.reserve_money("t", &node_money_key("n2"), 600_000, 1, 3600, TODAY, NODE_MONEY_BY).unwrap(),
            Err(BudgetRefusal::Hourly { reserved: 1_500_000, new: 600_000, max: 2_000_000 })
        );
        assert_eq!(
            l.reserve_money("t", &node_money_key("n2"), 500_000, 5_000_001, 3600, TODAY, NODE_MONEY_BY).unwrap(),
            Err(BudgetRefusal::Total { reserved: 15_000_000, new: 5_000_001, max: 20_000_000 })
        );
        assert_eq!(l.money_reserved("t").unwrap(), (1_500_000, 15_000_000), "refused: nothing recorded");
        // Exactly the limit fits.
        l.reserve_money("t", &node_money_key("n2"), 500_000, 5_000_000, 3600, TODAY, NODE_MONEY_BY).unwrap().unwrap();
        // Another tenant has its own.
        l.reserve_money("u", &node_money_key("n3"), 2_000_000, 20_000_000, 3600, TODAY, NODE_MONEY_BY).unwrap().unwrap();
        // A release gives it back.
        assert_eq!(l.release_money(&node_money_key("n1")).unwrap(), 2);
        assert_eq!(l.money_reserved("t").unwrap(), (500_000, 5_000_000));
        // Reserving again for a key that holds one keeps it (an acquire retried).
        l.reserve_money("t", &node_money_key("n2"), 500_000, 5_000_000, 3600, TODAY, NODE_MONEY_BY).unwrap().unwrap();
        assert_eq!(l.money_reserved("t").unwrap(), (500_000, 5_000_000));
    }

    /// Changed limits replace the grant; the same ones renew it.
    #[test]
    fn the_limit_grant_follows_the_configured_limits() {
        let mut l = Ledger::open_in_memory().unwrap();
        l.reserve_money("t", "a", 0, 0, 60, TODAY, NODE_MONEY_BY).unwrap().unwrap();
        l.reserve_money("t", "b", 0, 0, 60, TODAY, NODE_MONEY_BY).unwrap().unwrap();
        let live = |l: &Ledger| {
            l.grants(&wicket_core::TenantId("t".into()), false, 100).unwrap().iter().filter(|g| g.grant.path == MONEY_LIMIT_PATH).count()
        };
        assert_eq!(live(&l), 1, "renewed, not repeated");
        let lower = LeaseBudget { max_hourly: 1, max_total: 1 };
        assert!(l.reserve_money("t", "c", 2, 0, 60, lower, NODE_MONEY_BY).unwrap().is_err());
        assert_eq!((live(&l), l.money_limit("t").unwrap()), (1, Some(lower)));
    }
}
