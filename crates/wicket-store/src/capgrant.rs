//! Standing capacity grants (#256, PR 3): an operator's grant to a named principal of nodes it may
//! lease without asking each time, within amounts.
//!
//! **The record.** A capacity grant is one row of the ledger's `grants`, like every approval and
//! quota: `QUOTA wicket.internal /quota/capacity`, bound to a principal (`grants.principal`, an
//! operator's or agent's identity) rather than a run, with an `amount` (its daily money, micro-USD)
//! and its whole terms in `grants.terms`: the plans and regions it covers, its hourly and daily
//! money, and how many nodes it covers at once. Its lifetime is at most a day; it is renewed and
//! revoked as any grant is (`renew_grant`, `revoke_grant`). Like every quota grant it decides no op
//! (every lookup skips a grant with an amount) and is never handed to a node.
//!
//! **What it is used for.** A CAPACITY request a principal files (`wicket node create`) is decided
//! against that principal's live capacity grants: one that covers it is used
//! ([`Ledger::use_capacity_grant`]) and records a *use* in `capacity_uses`, in one transaction with
//! the checks, so two asks can't both take its last room. A use counts against the grant:
//! - **at once** (nodes and hourly money) while its node is active, or for [`APPROVED_HOLD_SECS`]
//!   after the approval while the node is being created;
//! - **daily** (its worst case) for a day from the approval, unless the create failed.
//!
//! The one spend check (#256, [`crate::money`]: the node's money reserved against the tenant's
//! money limit grant, `placement.yaml`'s limits) still comes first: a grant is a decision, not a
//! budget of its own.

use crate::{now, Ledger, Result};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

/// The path of a capacity grant (method [`crate::QUOTA_METHOD`], host [`crate::QUOTA_HOST`]).
pub const CAPACITY_GRANT_PATH: &str = "/quota/capacity";
/// How long an approved use with no node yet counts as at once: the create's own wait.
pub const APPROVED_HOLD_SECS: i64 = 30 * 60;
/// A day, the window a grant's daily money is counted over.
const DAY_SECS: i64 = 24 * 3600;

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS capacity_uses (
  id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, request_id TEXT NOT NULL, node TEXT NOT NULL, plan TEXT NOT NULL,
  region TEXT NOT NULL, hourly INTEGER NOT NULL, worst INTEGER NOT NULL, created_at INTEGER NOT NULL,
  status TEXT NOT NULL, instance TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS capacity_uses_grant ON capacity_uses (grant_id, created_at);
CREATE INDEX IF NOT EXISTS capacity_uses_request ON capacity_uses (request_id);
";

/// What a capacity grant covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityTerms {
    /// Plan ids (`vc2-1c-2gb`) a node may have.
    pub plans: Vec<String>,
    /// Regions (`lhr`) a node may be in.
    pub regions: Vec<String>,
    /// The most its nodes may cost per hour together, micro-USD.
    pub hourly: i64,
    /// The most its nodes approved in any day may cost (their worst cases), micro-USD.
    pub daily: i64,
    /// How many of its nodes may exist at once.
    pub nodes: u32,
}

impl CapacityTerms {
    /// Why these terms can't be granted, if they can't.
    pub fn check(&self) -> std::result::Result<(), String> {
        if self.plans.is_empty() || self.plans.iter().any(|p| p.trim().is_empty()) {
            return Err("name the plans it covers".into());
        }
        if self.regions.is_empty() || self.regions.iter().any(|r| r.trim().is_empty()) {
            return Err("name the regions it covers".into());
        }
        if self.hourly <= 0 || self.daily <= 0 {
            return Err("its hourly and daily money must be more than 0".into());
        }
        if self.hourly > self.daily {
            return Err("its hourly money can't be more than its daily money".into());
        }
        if self.nodes == 0 {
            return Err("it must cover at least one node".into());
        }
        Ok(())
    }
}

/// A capacity grant as recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapacityGrant {
    pub id: String,
    pub tenant: String,
    /// Who may use it: an operator's or agent's identity.
    pub principal: String,
    pub terms: CapacityTerms,
    pub expires_at: i64,
    pub revoked: bool,
    pub decided_by: String,
    pub created_at: i64,
}

impl CapacityGrant {
    pub fn live(&self, at: i64) -> bool {
        !self.revoked && self.expires_at > at
    }
}

/// One node asked for under a grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityAsk {
    /// The node's name.
    pub node: String,
    pub plan: String,
    pub region: String,
    /// What it costs per hour, micro-USD.
    pub hourly: i64,
    /// Its worst case through its lease, micro-USD.
    pub worst: i64,
}

/// What a grant's uses take now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CapacityUsed {
    /// Nodes at once.
    pub nodes: u32,
    /// Their hourly money, micro-USD.
    pub hourly: i64,
    /// Worst cases approved in the last day, micro-USD.
    pub daily: i64,
}

/// Whether `terms`, with `used` taken, cover `ask`: Err says why not, naming the limit.
pub fn covers(terms: &CapacityTerms, used: &CapacityUsed, ask: &CapacityAsk) -> std::result::Result<(), String> {
    if !terms.plans.iter().any(|p| p == &ask.plan) {
        return Err(format!("plan {} is not one it covers ({})", ask.plan, terms.plans.join(", ")));
    }
    if !terms.regions.iter().any(|r| r == &ask.region) {
        return Err(format!("region {} is not one it covers ({})", ask.region, terms.regions.join(", ")));
    }
    if used.nodes >= terms.nodes {
        return Err(format!("it covers {} node(s) at once, and {} are in use", terms.nodes, used.nodes));
    }
    if used.hourly.saturating_add(ask.hourly) > terms.hourly {
        return Err(format!(
            "{} µ$/h more would take its nodes to {} µ$/h, over its {} µ$/h",
            ask.hourly,
            used.hourly + ask.hourly,
            terms.hourly
        ));
    }
    if used.daily.saturating_add(ask.worst) > terms.daily {
        return Err(format!(
            "a worst case of {} µ$ would take the last day's to {} µ$, over its {} µ$ a day",
            ask.worst,
            used.daily + ask.worst,
            terms.daily
        ));
    }
    Ok(())
}

const CG_COLS: &str = "id, tenant, principal, terms, expires_at, revoked, decided_by, created_at";

fn row_to_cg(r: &rusqlite::Row<'_>) -> rusqlite::Result<CapacityGrant> {
    let terms: String = r.get(3)?;
    Ok(CapacityGrant {
        id: r.get(0)?,
        tenant: r.get(1)?,
        principal: r.get(2)?,
        terms: serde_json::from_str(&terms)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e)))?,
        expires_at: r.get(4)?,
        revoked: r.get::<_, i64>(5)? != 0,
        decided_by: r.get(6)?,
        created_at: r.get(7)?,
    })
}

fn used_in(conn: &rusqlite::Connection, grant: &str, t: i64) -> Result<CapacityUsed> {
    // At once: a use whose node is active, or approved and still being created.
    let (nodes, hourly): (i64, i64) = conn.query_row(
        "SELECT count(*), COALESCE(SUM(u.hourly), 0) FROM capacity_uses u LEFT JOIN placed_nodes p ON p.id = u.instance
         WHERE u.grant_id = ?1 AND ((u.status = 'approved' AND u.created_at > ?2) OR (u.status = 'created' AND p.status = 'active'))",
        params![grant, t - APPROVED_HOLD_SECS],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let daily: i64 = conn.query_row(
        "SELECT COALESCE(SUM(worst), 0) FROM capacity_uses WHERE grant_id = ?1 AND status IN ('approved', 'created') AND created_at > ?2",
        params![grant, t - DAY_SECS],
        |r| r.get(0),
    )?;
    Ok(CapacityUsed { nodes: u32::try_from(nodes).unwrap_or(u32::MAX), hourly, daily })
}

impl Ledger {
    /// Records a capacity grant to `principal`, made by `by`, lasting `ttl_secs` (clamped to (0, a
    /// day]). Returns its id. The caller checks who may grant it and audits the decision.
    pub fn issue_capacity_grant(&self, tenant: &str, principal: &str, terms: &CapacityTerms, ttl_secs: i64, by: &str) -> Result<String> {
        let t = now();
        let id = wicket_core::new_grant_id();
        self.conn.execute(
            "INSERT INTO grants (id, tenant, zone, method, host, path, prefix, uses_left, expires_at, request_id, decided_by, created_at,
                                 max_risk, run, amount, principal, terms)
             VALUES (?1, ?2, '', ?3, ?4, ?5, 0, NULL, ?6, NULL, ?7, ?8, NULL, NULL, ?9, ?10, ?11)",
            params![
                id,
                tenant,
                crate::QUOTA_METHOD,
                crate::QUOTA_HOST,
                CAPACITY_GRANT_PATH,
                t + ttl_secs.clamp(1, DAY_SECS),
                by,
                t,
                terms.daily,
                principal,
                serde_json::to_string(terms).expect("terms serialize"),
            ],
        )?;
        Ok(id)
    }

    pub fn capacity_grant(&self, id: &str) -> Result<Option<CapacityGrant>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {CG_COLS} FROM grants WHERE id = ?1 AND path = ?2 AND principal IS NOT NULL AND terms IS NOT NULL"),
                params![id, CAPACITY_GRANT_PATH],
                row_to_cg,
            )
            .optional()?)
    }

    /// The tenant's capacity grants (to `principal` only, if given), newest first: only live ones
    /// unless `all`.
    pub fn capacity_grants(&self, tenant: &str, principal: Option<&str>, all: bool) -> Result<Vec<CapacityGrant>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {CG_COLS} FROM grants WHERE tenant = ?1 AND path = ?2 AND method = ?3 AND host = ?4
               AND principal IS NOT NULL AND terms IS NOT NULL AND (?5 IS NULL OR principal = ?5)
               AND (?6 = 1 OR (revoked = 0 AND expires_at > ?7))
             ORDER BY created_at DESC, rowid DESC"
        ))?;
        let rows = st.query_map(
            params![tenant, CAPACITY_GRANT_PATH, crate::QUOTA_METHOD, crate::QUOTA_HOST, principal, all as i64, now()],
            row_to_cg,
        )?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// What grant `id`'s uses take now.
    pub fn capacity_used(&self, id: &str) -> Result<CapacityUsed> {
        used_in(&self.conn, id, now())
    }

    /// Uses grant `id` for `ask`, which request `request_id` of `principal` asked for: in one
    /// transaction, checks the grant is live, is `principal`'s and covers the ask with what its
    /// uses take now, and records the use. Ok(Err) says why it doesn't cover it.
    pub fn use_capacity_grant(
        &mut self,
        id: &str,
        principal: &str,
        ask: &CapacityAsk,
        request_id: &str,
    ) -> Result<std::result::Result<(String, CapacityUsed), String>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let t = now();
        let g = tx
            .query_row(
                &format!("SELECT {CG_COLS} FROM grants WHERE id = ?1 AND path = ?2 AND principal IS NOT NULL AND terms IS NOT NULL"),
                params![id, CAPACITY_GRANT_PATH],
                row_to_cg,
            )
            .optional()?;
        let Some(g) = g else { return Ok(Err(format!("no capacity grant {id}"))) };
        if !g.live(t) {
            return Ok(Err(format!("capacity grant {id} is {}", if g.revoked { "revoked" } else { "expired" })));
        }
        if g.principal != principal {
            return Ok(Err(format!("capacity grant {id} is {}'s, not {principal}'s", g.principal)));
        }
        let used = used_in(&tx, id, t)?;
        if let Err(why) = covers(&g.terms, &used, ask) {
            return Ok(Err(why));
        }
        let use_id = format!("cu-{}", wicket_core::new_ulid().to_string().to_lowercase());
        tx.execute(
            "INSERT INTO capacity_uses (id, grant_id, request_id, node, plan, region, hourly, worst, created_at, status, instance, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'approved', NULL, NULL)",
            params![use_id, id, request_id, ask.node, ask.plan, ask.region, ask.hourly, ask.worst, t],
        )?;
        tx.commit()?;
        Ok(Ok((use_id, used)))
    }

    /// The node of request `request_id`'s use was created: it counts while instance `instance` is an
    /// active placed node.
    pub fn capacity_use_created(&self, request_id: &str, instance: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE capacity_uses SET status = 'created', instance = ?2 WHERE request_id = ?1 AND status = 'approved'",
            params![request_id, instance],
        )? > 0)
    }

    /// Request `request_id`'s use made no node: it no longer counts.
    pub fn capacity_use_failed(&self, request_id: &str, why: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE capacity_uses SET status = 'failed', detail = ?2 WHERE request_id = ?1 AND status = 'approved'",
            params![request_id, why],
        )? > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlacedNodeRow;

    fn terms() -> CapacityTerms {
        CapacityTerms { plans: vec!["vc2-1c-2gb".into()], regions: vec!["lhr".into()], hourly: 30_000, daily: 50_000, nodes: 2 }
    }

    fn ask(node: &str) -> CapacityAsk {
        CapacityAsk { node: node.into(), plan: "vc2-1c-2gb".into(), region: "lhr".into(), hourly: 14_000, worst: 20_000 }
    }

    fn placed(l: &Ledger, id: &str) {
        l.record_placed_node(&PlacedNodeRow {
            id: id.into(),
            backend: "vultr".into(),
            name: id.into(),
            owner: "example".into(),
            api_key_secret: "k".into(),
            created_at: now(),
            lease_until: now() + 3000,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: Some(14_000),
        })
        .unwrap();
    }

    #[test]
    fn terms_are_checked_and_cover_only_what_they_name() {
        assert!(terms().check().is_ok());
        assert!(CapacityTerms { plans: vec![], ..terms() }.check().is_err());
        assert!(CapacityTerms { regions: vec![" ".into()], ..terms() }.check().is_err());
        assert!(CapacityTerms { nodes: 0, ..terms() }.check().is_err());
        assert!(CapacityTerms { hourly: 0, ..terms() }.check().is_err());
        assert!(CapacityTerms { hourly: 60_000, ..terms() }.check().is_err());
        let none = CapacityUsed::default();
        assert!(covers(&terms(), &none, &ask("a")).is_ok());
        assert!(covers(&terms(), &none, &CapacityAsk { plan: "vc2-2c-4gb".into(), ..ask("a") }).unwrap_err().contains("plan"));
        assert!(covers(&terms(), &none, &CapacityAsk { region: "ewr".into(), ..ask("a") }).unwrap_err().contains("region"));
        assert!(covers(&terms(), &CapacityUsed { nodes: 2, ..none }, &ask("a")).unwrap_err().contains("at once"));
        assert!(covers(&terms(), &CapacityUsed { hourly: 20_000, ..none }, &ask("a")).unwrap_err().contains("µ$/h"));
        assert!(covers(&terms(), &CapacityUsed { daily: 40_000, ..none }, &ask("a")).unwrap_err().contains("a day"));
    }

    #[test]
    fn a_grant_is_one_grant_record_used_within_its_amounts() {
        let mut l = Ledger::open_in_memory().unwrap();
        let p = "spiffe://example/t/default/op/unix/alex";
        let id = l.issue_capacity_grant("default", p, &terms(), 7 * DAY_SECS, "passkey:laptop").unwrap();
        let g = l.capacity_grant(&id).unwrap().unwrap();
        assert_eq!((g.principal.as_str(), g.terms.clone(), g.decided_by.as_str()), (p, terms(), "passkey:laptop"));
        assert!(g.expires_at <= now() + DAY_SECS, "at most a day");
        // A grant record like any other: listed, renewable, revocable, and it decides no op.
        let row = l.grant(&id).unwrap().unwrap();
        assert_eq!(
            (row.method.as_str(), row.path.as_str(), row.amount, row.run.as_deref()),
            ("QUOTA", CAPACITY_GRANT_PATH, Some(50_000), None)
        );
        assert_eq!(row.quota(), Some("capacity"));
        assert_eq!(l.capacity_grants("default", Some(p), false).unwrap().len(), 1);
        assert!(l.capacity_grants("default", Some("someone else"), false).unwrap().is_empty());

        // Someone else can't use it.
        assert!(l.use_capacity_grant(&id, "spiffe://example/t/default/op/unix/eve", &ask("n0"), "r-0").unwrap().is_err());
        // Two nodes fit; the second is still being created, and counts.
        let (_, before) = l.use_capacity_grant(&id, p, &ask("n1"), "r-1").unwrap().unwrap();
        assert_eq!(before, CapacityUsed::default());
        placed(&l, "i-1");
        assert!(l.capacity_use_created("r-1", "i-1").unwrap());
        l.use_capacity_grant(&id, p, &ask("n2"), "r-2").unwrap().unwrap();
        assert_eq!(l.capacity_used(&id).unwrap(), CapacityUsed { nodes: 2, hourly: 28_000, daily: 40_000 });
        // A third is over its nodes at once.
        assert!(l.use_capacity_grant(&id, p, &ask("n3"), "r-3").unwrap().unwrap_err().contains("at once"));
        // The second failed: it frees its room, but n1's day's money stays counted.
        assert!(l.capacity_use_failed("r-2", "unreachable").unwrap());
        assert_eq!(l.capacity_used(&id).unwrap(), CapacityUsed { nodes: 1, hourly: 14_000, daily: 20_000 });
        // n1 released: no longer at once; its worst case still counts for the day, so a third
        // node's would be over the daily money.
        l.placed_node_ended("i-1", "released", "done").unwrap();
        assert_eq!(l.capacity_used(&id).unwrap(), CapacityUsed { nodes: 0, hourly: 0, daily: 20_000 });
        l.use_capacity_grant(&id, p, &ask("n4"), "r-4").unwrap().unwrap();
        assert!(l.use_capacity_grant(&id, p, &ask("n5"), "r-5").unwrap().unwrap_err().contains("a day"));

        // Revoked: nothing more under it.
        l.revoke_grant(&id).unwrap();
        assert!(l.use_capacity_grant(&id, p, &CapacityAsk { worst: 1, ..ask("n6") }, "r-6").unwrap().unwrap_err().contains("revoked"));
        assert!(l.capacity_grants("default", Some(p), false).unwrap().is_empty());
        assert_eq!(l.capacity_grants("default", Some(p), true).unwrap().len(), 1);
    }
}
