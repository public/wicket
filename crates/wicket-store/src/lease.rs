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
//! leases give their reservation back. A lease's money is also recorded as two quota grants bound
//! to the run that asked (#256): `QUOTA wicket.internal /quota/money.hourly/<lease>` (its
//! `hourly_cap`) and `/quota/money.reserved/<lease>` (its `reserved`), made by
//! [`LEASE_QUOTA_BY`] in the same transaction, revoked when the lease ends. They are the record;
//! the check stays the installation's limits over the live leases' reservations, here.
//!
//! **Placed nodes** ([`PlacedNodeRow`], #294) are the other kind of owned node: made by `wicket node
//! create` for the installation rather than asked for by a run. They have no reservation here (the
//! placer's money envelope covered them); the reconciler releases one at its `lease_until` unless a
//! run still placed on it (by its enrolled name) holds it, which it records in `held_by`.

use crate::{now, Ledger, Result, StoreError};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Serialize;

/// Who a lease's money quota grants are recorded as made by: the installation's lease budget.
pub const LEASE_QUOTA_BY: &str = "wicket:lease-budget";
/// How much longer than its duration a lease's money quotas last: it waits for a human and for its
/// node first (renewable past that, and at most a day, as every grant).
const LEASE_QUOTA_SLACK_SECS: i64 = 3600;

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
            &format!(
                "SELECT COALESCE(SUM(hourly_cap), 0), COALESCE(SUM(reserved), 0) FROM leases WHERE tenant = ?1 AND status IN ({})",
                live_in()
            ),
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
        // Its money, recorded as quota grants bound to the run that asked (#256), in the same
        // transaction: what it reserves is a grant of the installation's lease budget.
        let zone: Option<String> = tx.query_row("SELECT zone FROM runs WHERE id = ?1", params![l.run], |r| r.get(0)).optional()?;
        let [hp, rp] = crate::quota::lease_quota_paths(&l.id);
        let amount = |m: i64| u64::try_from(m).unwrap_or(0);
        crate::quota::insert_quotas(
            &tx,
            &l.tenant,
            zone.as_deref().unwrap_or(""),
            &l.run,
            LEASE_QUOTA_BY,
            &[(hp, amount(l.hourly_cap)), (rp, amount(l.reserved))],
            crate::quota::quota_until(l.duration_secs.saturating_add(LEASE_QUOTA_SLACK_SECS)),
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

    /// Brings an active lease's end forward to `at` (the operator releasing it early): the next
    /// reconcile pass stops what runs on it and destroys its node.
    pub fn set_lease_not_after(&self, id: &str, at: i64) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE leases SET not_after = MIN(COALESCE(not_after, ?2), ?2) WHERE id = ?1 AND status = 'active'",
            params![id, at],
        )?;
        Ok(n == 1)
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
        if n == 1 {
            crate::quota::revoke_lease_quotas(&self.conn, id)?;
        }
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

    /// The process supervising a run, as last recorded (it changes when a supervisor re-attaches).
    pub fn run_owner(&self, run: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT owner FROM runs WHERE id = ?1", params![run], |r| r.get::<_, Option<String>>(0))
            .optional()?
            .flatten())
    }

    /// Runs recorded as `running`, with their owner label if any.
    pub fn running_runs(&self) -> Result<Vec<(String, Option<String>)>> {
        let mut st = self.conn.prepare("SELECT id, owner FROM runs WHERE status = 'running' ORDER BY started_at")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Runs recorded as `running` on a node (by its enrolled name), oldest first.
    pub fn running_runs_on_node(&self, node: &str) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT id FROM runs WHERE status = 'running' AND node = ?1 ORDER BY started_at, id")?;
        let rows = st.query_map(params![node], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    // ---- nodes made by `wicket node create` (#294) ----

    /// Records a node `wicket node create` made (again: a retried create updates its lease end and
    /// makes it active).
    pub fn record_placed_node(&self, n: &PlacedNodeRow) -> Result<()> {
        self.conn.execute(
            &format!(
                "INSERT INTO placed_nodes ({PLACED_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', NULL, NULL, NULL, ?8)
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, owner = excluded.owner, api_key_secret = excluded.api_key_secret,
                   lease_until = excluded.lease_until, status = 'active', held_by = NULL, ended_at = NULL, detail = NULL,
                   hourly = coalesce(excluded.hourly, hourly)"
            ),
            params![n.id, n.backend, n.name, n.owner, n.api_key_secret, n.created_at, n.lease_until, n.hourly],
        )?;
        Ok(())
    }

    pub fn placed_node(&self, id: &str) -> Result<Option<PlacedNodeRow>> {
        Ok(self.conn.query_row(&format!("SELECT {PLACED_COLS} FROM placed_nodes WHERE id = ?1"), params![id], row_to_placed).optional()?)
    }

    /// Placed nodes in any of `statuses` (every one if empty), oldest first.
    pub fn placed_nodes(&self, statuses: &[&str]) -> Result<Vec<PlacedNodeRow>> {
        let filter = if statuses.is_empty() {
            String::new()
        } else {
            format!("WHERE status IN ({})", statuses.iter().map(|s| format!("'{}'", s.replace('\'', ""))).collect::<Vec<_>>().join(","))
        };
        let mut st = self.conn.prepare(&format!("SELECT {PLACED_COLS} FROM placed_nodes {filter} ORDER BY created_at, id"))?;
        let rows = st.query_map([], row_to_placed)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Records the runs holding an active placed node past its lease end (None: none). True if that
    /// changed, so the caller audits a change once rather than every pass.
    pub fn set_placed_node_held(&self, id: &str, held_by: Option<&str>) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE placed_nodes SET held_by = ?2 WHERE id = ?1 AND status = 'active' AND held_by IS NOT ?2",
            params![id, held_by],
        )?;
        Ok(n == 1)
    }

    /// Ends an active placed node: `released` (destroyed, or found gone) or `left` (the provider
    /// refused: no longer owned, or protected). False if it had already ended.
    pub fn placed_node_ended(&self, id: &str, status: &str, detail: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE placed_nodes SET status = ?2, detail = ?3, held_by = NULL, ended_at = ?4 WHERE id = ?1 AND status = 'active'",
            params![id, status, detail, now()],
        )?;
        Ok(n == 1)
    }
}

/// A node `wicket node create` made (#294): owned by the installation, not by a run's capacity
/// lease, and released by the reconciler at `lease_until` unless a run still holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlacedNodeRow {
    /// The provider's instance id.
    pub id: String,
    pub backend: String,
    /// Its name (label, hostname and enrolled node name).
    pub name: String,
    /// The owner tag's installation name it was created under.
    pub owner: String,
    /// The vault secret holding the provider's API key it was created with.
    pub api_key_secret: String,
    pub created_at: i64,
    /// When its lease ends (minute 50 of its last paid hour).
    pub lease_until: i64,
    /// `active`, `released` or `left`.
    pub status: String,
    /// Runs still on it past its lease end, comma-separated.
    pub held_by: Option<String>,
    pub ended_at: Option<i64>,
    pub detail: Option<String>,
    /// What it costs per hour, micro-USD, as the provider priced it at creation (None: recorded
    /// before the ledger kept it).
    pub hourly: Option<i64>,
}

const PLACED_COLS: &str = "id, backend, name, owner, api_key_secret, created_at, lease_until, status, held_by, ended_at, detail, hourly";

fn row_to_placed(r: &rusqlite::Row<'_>) -> rusqlite::Result<PlacedNodeRow> {
    Ok(PlacedNodeRow {
        id: r.get(0)?,
        backend: r.get(1)?,
        name: r.get(2)?,
        owner: r.get(3)?,
        api_key_secret: r.get(4)?,
        created_at: r.get(5)?,
        lease_until: r.get(6)?,
        status: r.get(7)?,
        held_by: r.get(8)?,
        ended_at: r.get(9)?,
        detail: r.get(10)?,
        hourly: r.get(11)?,
    })
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
    fn a_leases_money_is_recorded_as_quota_grants_until_it_ends() {
        let mut l = Ledger::open_in_memory().unwrap();
        let b = LeaseBudget { max_hourly: 50_000, max_total: 100_000 };
        let (a, r) = ask(&mut l, "run_a", 20_000, 40_000, b);
        r.unwrap();
        let (c, r) = ask(&mut l, "run_a", 10_000, 30_000, b);
        r.unwrap();
        let gs = l.quota_grants("run_a").unwrap();
        let got: Vec<(&str, &str, Option<i64>)> = gs.iter().map(|g| (g.quota().unwrap(), g.path.as_str(), g.amount)).collect();
        let (ah, ar) = (format!("/quota/money.hourly/{a}"), format!("/quota/money.reserved/{a}"));
        assert_eq!(&got[..2], &[("money.hourly", ah.as_str(), Some(20_000)), ("money.reserved", ar.as_str(), Some(40_000))]);
        for g in &gs {
            assert_eq!((g.run.as_deref(), g.request_id.as_deref()), (Some("run_a"), None));
            assert!(g.expires_at > now() && g.expires_at - now() <= crate::MAX_QUOTA_TTL_SECS, "every grant has a lifetime");
        }
        // A run's money quotas add up over its leases.
        let q = l.quota_amounts("run_a").unwrap();
        assert_eq!((q.get("money.hourly"), q.get("money.reserved")), (Some(30_000), Some(70_000)));
        // They decide nothing, and no node is handed them.
        assert!(l.grants_for_run("run_a").unwrap().is_empty());
        // A refused ask records none.
        let (_, r) = ask(&mut l, "run_b", 40_000, 10_000, b);
        assert!(r.is_err());
        assert!(l.quota_grants("run_b").unwrap().is_empty());
        // The lease ends: its money quotas are revoked, the other lease's kept.
        assert!(l.lease_ended(&a, "denied", "no", None).unwrap());
        let q = l.quota_amounts("run_a").unwrap();
        assert_eq!((q.get("money.hourly"), q.get("money.reserved")), (Some(10_000), Some(30_000)));
        assert!(l.lease_ended(&c, "ended", "lease end", Some(1)).unwrap());
        assert_eq!(l.quota_amounts("run_a").unwrap(), crate::QuotaAmounts::default());
        // A lease with no cost (the operator's own machines) records nothing.
        let (_, r) = ask(&mut l, "run_c", 0, 0, b);
        r.unwrap();
        assert!(l.quota_grants("run_c").unwrap().is_empty());
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

    #[test]
    fn a_placed_node_is_recorded_held_once_and_ended_once() {
        let l = Ledger::open_in_memory().unwrap();
        let row = PlacedNodeRow {
            id: "i-1".into(),
            backend: "vultr".into(),
            name: "n1".into(),
            owner: "example".into(),
            api_key_secret: "vultr-api-key".into(),
            created_at: 100,
            lease_until: 3100,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: Some(14_000),
        };
        l.record_placed_node(&row).unwrap();
        let got = l.placed_node("i-1").unwrap().unwrap();
        assert_eq!((got.status.as_str(), got.lease_until, got.hourly), ("active", 3100, Some(14_000)));
        // A retry that doesn't know the price keeps the one recorded.
        l.record_placed_node(&PlacedNodeRow { hourly: None, ..row.clone() }).unwrap();
        assert_eq!(l.placed_node("i-1").unwrap().unwrap().hourly, Some(14_000));
        // A held node's holders are recorded; recording the same holders again is no change.
        assert!(l.set_placed_node_held("i-1", Some("run_a")).unwrap());
        assert!(!l.set_placed_node_held("i-1", Some("run_a")).unwrap());
        assert!(l.set_placed_node_held("i-1", Some("run_a,run_b")).unwrap());
        assert_eq!(l.placed_nodes(&["active"]).unwrap()[0].held_by.as_deref(), Some("run_a,run_b"));
        assert!(l.placed_node_ended("i-1", "released", "lease end").unwrap());
        assert!(!l.placed_node_ended("i-1", "released", "again").unwrap());
        assert!(!l.set_placed_node_held("i-1", Some("run_c")).unwrap(), "an ended node is not held");
        let got = l.placed_node("i-1").unwrap().unwrap();
        assert_eq!((got.status.as_str(), got.held_by, got.detail.as_deref()), ("released", None, Some("lease end")));
        assert!(l.placed_nodes(&["active"]).unwrap().is_empty());
        // Runs on a node, by its enrolled name.
        l.run_started(&TenantId("t".into()), &RunId("run_a".into()), "z", "a").unwrap();
        l.set_run_node("run_a", "n1").unwrap();
        assert_eq!(l.running_runs_on_node("n1").unwrap(), vec!["run_a".to_string()]);
        l.run_ended(&RunId("run_a".into()), "succeeded", "").unwrap();
        assert!(l.running_runs_on_node("n1").unwrap().is_empty());
    }
}
