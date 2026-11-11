//! Capacity leases (#7, #38): a node an agent asked for, a human approved and the reconciler keeps
//! alive until the lease ends. The ledger is the desired state; the provider's owner-tagged instances
//! are the observed state; `wicket reconcile` makes them agree.
//!
//! **Lifecycle** (`status`):
//! - `pending`: asked for (`request_capacity`), waiting for a human. Its money is already reserved.
//! - `approved`: the human said yes (its request is `granted`); the reconciler is to acquire the node.
//! - `active`: the node exists, is enrolled and runs `wicket node serve`; `not_after` is set.
//! - `ended`: released (lease end, holder run ended, or by the operator); `billed` is what the
//!   provider billed by then, at its billing model.
//! - `denied`, `withdrawn` (the holder run ended first), `failed` (provisioning failed; the reconciler
//!   destroys whatever was created, since nothing desires it any more).
//!
//! **Money.** Each lease reserves `reserved`, the worst case at its own price cap (`hourly_cap` per
//! started hour for its whole duration), from the moment it is asked for. [`Ledger::create_lease`]
//! refuses, atomically, a lease that would take the reservations of every `pending`, `approved` or
//! `active` lease over the installation's limits. Only `ended`, `denied`, `withdrawn` and `failed`
//! leases give their reservation back.

use crate::{now, Ledger, Result, StoreError};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Serialize;

/// The statuses whose reservation counts against the budget.
pub const LIVE: &[&str] = &["pending", "approved", "active"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaseRow {
    pub id: String,
    pub tenant: String,
    /// The run that holds it (asked for it); its children may be placed on it.
    pub run: String,
    /// The approval request (`requests.id`) a human decides.
    pub request_id: Option<String>,
    /// The placement backend (`static`, `vultr`).
    pub provider: String,
    /// The request as asked (resources, isolation, region, duration, price cap, reason): enough to
    /// rebuild the placement request after a restart.
    pub spec: serde_json::Value,
    /// Price cap per hour, micro-USD.
    pub hourly_cap: i64,
    /// Worst-case cost reserved, micro-USD.
    pub reserved: i64,
    pub duration_secs: i64,
    pub created_at: i64,
    /// When the node must be gone (set when it is acquired: the provider's billing granule, minute 50).
    pub not_after: Option<i64>,
    pub status: String,
    /// The provider's id for the node.
    pub node_id: Option<String>,
    /// The enrolled node's name (what `wicket run --node` takes).
    pub node_name: Option<String>,
    pub ssh_target: Option<String>,
    /// The ssh host key pinned for the node (stored before it is created, so a retried provisioning
    /// pins the key the node actually booted with).
    pub host_key: Option<String>,
    /// Micro-USD billed by the provider's model when the lease ended.
    pub billed: Option<i64>,
    pub ended_at: Option<i64>,
    pub detail: Option<String>,
}

/// Why [`Ledger::create_lease`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetRefusal {
    Hourly { reserved: i64, new: i64, max: i64 },
    Total { reserved: i64, new: i64, max: i64 },
}

impl std::fmt::Display for BudgetRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let usd = |m: i64| format!("${}.{:06}", m / 1_000_000, m % 1_000_000);
        match self {
            BudgetRefusal::Hourly { reserved, new, max } => {
                write!(f, "{}/h already reserved + {}/h asked is over the {}/h limit", usd(*reserved), usd(*new), usd(*max))
            }
            BudgetRefusal::Total { reserved, new, max } => {
                write!(f, "{} already reserved + {} worst case asked is over the {} limit", usd(*reserved), usd(*new), usd(*max))
            }
        }
    }
}

/// The installation's limits for leases (micro-USD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseBudget {
    pub max_hourly: i64,
    pub max_total: i64,
}

const LEASE_COLS: &str = "id, tenant, run, request_id, provider, spec, hourly_cap, reserved, duration_secs, created_at, not_after, \
                          status, node_id, node_name, ssh_target, host_key, billed, ended_at, detail";

fn row_to_lease(r: &rusqlite::Row<'_>) -> rusqlite::Result<LeaseRow> {
    Ok(LeaseRow {
        id: r.get(0)?,
        tenant: r.get(1)?,
        run: r.get(2)?,
        request_id: r.get(3)?,
        provider: r.get(4)?,
        spec: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
        hourly_cap: r.get(6)?,
        reserved: r.get(7)?,
        duration_secs: r.get(8)?,
        created_at: r.get(9)?,
        not_after: r.get(10)?,
        status: r.get(11)?,
        node_id: r.get(12)?,
        node_name: r.get(13)?,
        ssh_target: r.get(14)?,
        host_key: r.get(15)?,
        billed: r.get(16)?,
        ended_at: r.get(17)?,
        detail: r.get(18)?,
    })
}

pub fn new_lease_id() -> String {
    let mut b = [0u8; 6];
    let _ = getrandom::getrandom(&mut b);
    format!("l-{}", hex::encode(b))
}

fn live_in() -> String {
    LIVE.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(",")
}

impl Ledger {
    /// Records a `pending` lease, reserving `reserved` and `hourly_cap`, unless that would take the
    /// live leases' reservations over `budget` (checked and inserted in one transaction, so two asks
    /// racing can't both fit). The caller fills in `id`, `tenant`, `run`, `provider`, `spec`,
    /// `hourly_cap`, `reserved` and `duration_secs`; the rest is set here.
    pub fn create_lease(&mut self, l: &LeaseRow, budget: LeaseBudget) -> Result<std::result::Result<(), BudgetRefusal>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (hourly, total): (i64, i64) = tx.query_row(
            &format!("SELECT COALESCE(SUM(hourly_cap), 0), COALESCE(SUM(reserved), 0) FROM leases WHERE tenant = ?1 AND status IN ({})", live_in()),
            params![l.tenant],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if hourly + l.hourly_cap > budget.max_hourly {
            return Ok(Err(BudgetRefusal::Hourly { reserved: hourly, new: l.hourly_cap, max: budget.max_hourly }));
        }
        if total + l.reserved > budget.max_total {
            return Ok(Err(BudgetRefusal::Total { reserved: total, new: l.reserved, max: budget.max_total }));
        }
        tx.execute(
            &format!("INSERT INTO leases ({LEASE_COLS}) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7, ?8, ?9, NULL, 'pending', NULL, NULL, NULL, NULL, NULL, NULL, NULL)"),
            params![l.id, l.tenant, l.run, l.provider, l.spec.to_string(), l.hourly_cap, l.reserved, l.duration_secs, now()],
        )?;
        tx.commit()?;
        Ok(Ok(()))
    }

    /// The reservations of live leases other than `except`: (hourly, total), micro-USD. Only leases
    /// whose node doesn't exist yet if `unbound_only` (a bound node is counted by the provider's own
    /// list instead).
    pub fn lease_reservations(&self, tenant: &str, except: Option<&str>, unbound_only: bool) -> Result<(i64, i64)> {
        Ok(self.conn.query_row(
            &format!(
                "SELECT COALESCE(SUM(hourly_cap), 0), COALESCE(SUM(reserved), 0) FROM leases
                 WHERE tenant = ?1 AND status IN ({}) AND id != ?2 AND (?3 = 0 OR node_id IS NULL)",
                live_in()
            ),
            params![tenant, except.unwrap_or(""), unbound_only as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    pub fn set_lease_request(&self, id: &str, request_id: &str) -> Result<()> {
        self.conn.execute("UPDATE leases SET request_id = ?2 WHERE id = ?1", params![id, request_id])?;
        Ok(())
    }

    pub fn lease(&self, id: &str) -> Result<Option<LeaseRow>> {
        Ok(self.conn.query_row(&format!("SELECT {LEASE_COLS} FROM leases WHERE id = ?1"), params![id], row_to_lease).optional()?)
    }

    pub fn lease_for_request(&self, request_id: &str) -> Result<Option<LeaseRow>> {
        Ok(self
            .conn
            .query_row(&format!("SELECT {LEASE_COLS} FROM leases WHERE request_id = ?1"), params![request_id], row_to_lease)
            .optional()?)
    }

    /// Leases in any of `statuses` (every lease if empty), oldest first.
    pub fn leases(&self, statuses: &[&str]) -> Result<Vec<LeaseRow>> {
        let filter = if statuses.is_empty() {
            String::new()
        } else {
            format!("WHERE status IN ({})", statuses.iter().map(|s| format!("'{}'", s.replace('\'', ""))).collect::<Vec<_>>().join(","))
        };
        let mut st = self.conn.prepare(&format!("SELECT {LEASE_COLS} FROM leases {filter} ORDER BY created_at, id"))?;
        let rows = st.query_map([], row_to_lease)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Moves a lease from one of `from` to `to` (with a detail). False if it wasn't in `from`.
    pub fn lease_transition(&self, id: &str, from: &[&str], to: &str, detail: &str) -> Result<bool> {
        let from = from.iter().map(|s| format!("'{}'", s.replace('\'', ""))).collect::<Vec<_>>().join(",");
        let n = self.conn.execute(
            &format!("UPDATE leases SET status = ?2, detail = ?3 WHERE id = ?1 AND status IN ({from})"),
            params![id, to, detail],
        )?;
        Ok(n == 1)
    }

    /// Records the ssh host key a lease's node is to boot with, before it is created.
    pub fn set_lease_host_key(&self, id: &str, host_key: &str) -> Result<()> {
        self.conn.execute("UPDATE leases SET host_key = ?2 WHERE id = ?1", params![id, host_key])?;
        Ok(())
    }

    /// Records the provider's node for a lease (just created, or adopted after a crash).
    pub fn set_lease_node(&self, id: &str, node_id: &str, ssh_target: Option<&str>, not_after: Option<i64>) -> Result<()> {
        self.conn.execute(
            "UPDATE leases SET node_id = ?2, ssh_target = COALESCE(?3, ssh_target), not_after = COALESCE(?4, not_after) WHERE id = ?1",
            params![id, node_id, ssh_target, not_after],
        )?;
        Ok(())
    }

    /// An `approved` lease whose node is up, enrolled and serving becomes `active`.
    pub fn lease_activated(&self, id: &str, node_name: &str, ssh_target: &str, not_after: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE leases SET status = 'active', node_name = ?2, ssh_target = ?3, not_after = ?4, detail = NULL
             WHERE id = ?1 AND status = 'approved'",
            params![id, node_name, ssh_target, not_after],
        )?;
        if n != 1 {
            return Err(StoreError::Node(id.into(), "is not an approved lease"));
        }
        Ok(())
    }

    /// Ends a live lease: `status` is `ended`, `failed`, `denied` or `withdrawn`. False if it had
    /// already ended.
    pub fn lease_ended(&self, id: &str, status: &str, detail: &str, billed: Option<i64>) -> Result<bool> {
        let n = self.conn.execute(
            &format!(
                "UPDATE leases SET status = ?2, detail = ?3, billed = COALESCE(?4, billed), ended_at = ?5 WHERE id = ?1 AND status IN ({})",
                live_in()
            ),
            params![id, status, detail, billed, now()],
        )?;
        Ok(n == 1)
    }

    // ---- which process owns a run ----

    /// Records the process supervising a run (`<machine>:<pid>:<start>`), so a reconciler on the same
    /// machine can tell when it is gone.
    pub fn set_run_owner(&self, run: &str, owner: &str) -> Result<()> {
        self.conn.execute("UPDATE runs SET owner = ?2 WHERE id = ?1", params![run, owner])?;
        Ok(())
    }

    /// Records that a run was placed on a lease's node (`spawn` with `placement: {lease}`): when the
    /// lease ends, the reconciler stops it.
    pub fn set_run_lease(&self, run: &str, lease: &str) -> Result<()> {
        self.conn.execute("UPDATE runs SET lease = ?2 WHERE id = ?1", params![run, lease])?;
        Ok(())
    }

    /// Runs placed on a lease, with their status.
    pub fn runs_on_lease(&self, lease: &str) -> Result<Vec<(String, String)>> {
        let mut st = self.conn.prepare("SELECT id, status FROM runs WHERE lease = ?1 ORDER BY started_at")?;
        let rows = st.query_map(params![lease], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Runs recorded as `running`, with their owner label if any.
    pub fn running_runs(&self) -> Result<Vec<(String, Option<String>)>> {
        let mut st = self.conn.prepare("SELECT id, owner FROM runs WHERE status = 'running' ORDER BY started_at")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::{RunId, TenantId};

    fn ask(l: &mut Ledger, run: &str, hourly: i64, reserved: i64, budget: LeaseBudget) -> (String, std::result::Result<(), BudgetRefusal>) {
        let id = new_lease_id();
        let row = LeaseRow {
            id: id.clone(),
            tenant: "t".into(),
            run: run.into(),
            request_id: None,
            provider: "fake".into(),
            spec: serde_json::json!({ "vcpus": 1 }),
            hourly_cap: hourly,
            reserved,
            duration_secs: 3600,
            created_at: 0,
            not_after: None,
            status: String::new(),
            node_id: None,
            node_name: None,
            ssh_target: None,
            host_key: None,
            billed: None,
            ended_at: None,
            detail: None,
        };
        let r = l.create_lease(&row, budget).unwrap();
        (id, r)
    }

    #[test]
    fn reservations_count_from_the_ask_until_the_lease_ends() {
        let mut l = Ledger::open_in_memory().unwrap();
        let b = LeaseBudget { max_hourly: 50_000, max_total: 100_000 };
        let (a, r) = ask(&mut l, "run_a", 20_000, 60_000, b);
        r.unwrap();
        // A second worst case of 60k doesn't fit next to the first.
        let (_, r) = ask(&mut l, "run_b", 20_000, 60_000, b);
        assert_eq!(r, Err(BudgetRefusal::Total { reserved: 60_000, new: 60_000, max: 100_000 }));
        // Nor does an hourly rate over the limit.
        let (_, r) = ask(&mut l, "run_b", 40_000, 10_000, b);
        assert_eq!(r, Err(BudgetRefusal::Hourly { reserved: 20_000, new: 40_000, max: 50_000 }));
        assert_eq!(l.leases(&[]).unwrap().len(), 1, "refused asks leave nothing behind");
        // Approved and active still hold it.
        assert!(l.lease_transition(&a, &["pending"], "approved", "").unwrap());
        assert_eq!(l.lease_reservations("t", None, false).unwrap(), (20_000, 60_000));
        l.set_lease_node(&a, "i-1", Some("wicket@203.0.113.5"), Some(1000)).unwrap();
        // Bound to a node: the provider's own list counts it, so the unbound sum drops it.
        assert_eq!(l.lease_reservations("t", None, true).unwrap(), (0, 0));
        l.lease_activated(&a, "cap-1", "wicket@203.0.113.5", 1000).unwrap();
        assert_eq!(l.lease(&a).unwrap().unwrap().status, "active");
        // Ended: the reservation is given back, and ending twice is a no-op.
        assert!(l.lease_ended(&a, "ended", "lease end", Some(20_000)).unwrap());
        assert!(!l.lease_ended(&a, "ended", "again", None).unwrap());
        assert_eq!(l.lease(&a).unwrap().unwrap().billed, Some(20_000));
        let (_, r) = ask(&mut l, "run_b", 20_000, 60_000, b);
        r.unwrap();
    }

    #[test]
    fn a_pending_lease_is_withdrawn_when_its_run_ends() {
        let mut l = Ledger::open_in_memory().unwrap();
        l.run_started(&TenantId("t".into()), &RunId("run_a".into()), "z", "a").unwrap();
        l.set_run_owner("run_a", "m:1:2").unwrap();
        assert_eq!(l.running_runs().unwrap(), vec![("run_a".to_string(), Some("m:1:2".to_string()))]);
        let (id, r) = ask(&mut l, "run_a", 1, 1, LeaseBudget { max_hourly: 10, max_total: 10 });
        r.unwrap();
        l.run_ended(&RunId("run_a".into()), "succeeded", "").unwrap();
        assert_eq!(l.lease(&id).unwrap().unwrap().status, "withdrawn");
        assert!(l.running_runs().unwrap().is_empty());
        l.set_run_lease("run_a", &id).unwrap();
        assert_eq!(l.runs_on_lease(&id).unwrap(), vec![("run_a".to_string(), "succeeded".to_string())]);
    }
}
