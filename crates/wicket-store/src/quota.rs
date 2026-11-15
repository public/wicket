//! Quotas as grants (#256): what wicket carves for a run when it starts it as a child (its model
//! budget, its box slots, its memory) is recorded as grant records in the ledger's `grants` table,
//! like every approval, so one listing (`wicket grant list`) shows a run's authority whole.
//!
//! A quota grant is `QUOTA wicket.internal /quota/<resource>`, bound to the run it was carved for,
//! with an `amount` (the column is NULL for every other grant) and a lifetime: at most
//! [`MAX_QUOTA_TTL_SECS`], never past the run's own end, and renewable as any grant is (`wicket
//! grant renew`). It answers no request, and decides no op: [`crate::Ledger::consume_grant`] and
//! every other lookup skip it, it is never handed to a node (only grants answering a run's requests
//! are, [`crate::Ledger::grants_for_run`]), and the reserved method keeps agents from asking for one.
//! Enforcement stays where it is (the model proxy's counters, the spawn slots, the box's limits);
//! this is the record. It is revoked with the rest of its run's grants when the run ends.

use crate::{now, GrantRow, Ledger, Result};
use rusqlite::params;
use serde::Serialize;
use wicket_core::{new_grant_id, RunId, TenantId};

/// The method of a quota grant.
pub const QUOTA_METHOD: &str = "QUOTA";
/// The host of a quota grant: wicket's own namespace.
pub const QUOTA_HOST: &str = "wicket.internal";
/// The longest lifetime a quota grant is recorded with: every grant has one, at most 24h.
pub const MAX_QUOTA_TTL_SECS: i64 = 24 * 3600;

/// One quota carved for a run: a resource and how much of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// `model.requests`, `model.output_tokens`, `model.input_tokens`, `children` or `bytes`.
    pub resource: &'static str,
    pub amount: u64,
}

impl Quota {
    /// The grant's path.
    pub fn path(&self) -> String {
        format!("/quota/{}", self.resource)
    }
}

/// A grant as `wicket grant list` shows it: the record, who made it and when.
#[derive(Clone, Debug, Serialize)]
pub struct GrantListing {
    #[serde(flatten)]
    pub grant: GrantRow,
    pub decided_by: String,
    pub created_at: i64,
}

impl GrantRow {
    /// The quota's resource, for a quota grant.
    pub fn quota(&self) -> Option<&str> {
        (self.method == QUOTA_METHOD && self.host == QUOTA_HOST && self.amount.is_some())
            .then(|| self.path.strip_prefix("/quota/"))
            .flatten()
    }
}

impl Ledger {
    /// Records the quotas carved for `run` (in `zone`) as grants made by `by`, each lasting `ttl_secs`
    /// (clamped to (0, [`MAX_QUOTA_TTL_SECS`]]). Quotas of amount 0 are not recorded. Returns the
    /// grant ids, in order. Idempotent per run and resource: a quota already recorded and live for
    /// the run is kept, not doubled (a re-adopted child).
    pub fn record_quota_grants(
        &self,
        tenant: &TenantId,
        zone: &str,
        run: &RunId,
        by: &str,
        quotas: &[Quota],
        ttl_secs: i64,
    ) -> Result<Vec<String>> {
        let t = now();
        let until = t + ttl_secs.clamp(1, MAX_QUOTA_TTL_SECS);
        let mut ids = vec![];
        for q in quotas.iter().filter(|q| q.amount > 0) {
            let path = q.path();
            let held: Option<String> = rusqlite::OptionalExtension::optional(self.conn.query_row(
                "SELECT id FROM grants WHERE run = ?1 AND method = ?2 AND host = ?3 AND path = ?4 AND amount IS NOT NULL
                   AND revoked = 0 AND expires_at > ?5 LIMIT 1",
                params![run.0, QUOTA_METHOD, QUOTA_HOST, path, t],
                |r| r.get(0),
            ))?;
            if let Some(id) = held {
                ids.push(id);
                continue;
            }
            let id = new_grant_id();
            self.conn.execute(
                "INSERT INTO grants (id, tenant, zone, method, host, path, prefix, uses_left, expires_at, request_id, decided_by, created_at, max_risk, run, amount)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, NULL, ?7, NULL, ?8, ?9, NULL, ?10, ?11)",
                params![id, tenant.0, zone, QUOTA_METHOD, QUOTA_HOST, path, until, by, t, run.0, i64::try_from(q.amount).unwrap_or(i64::MAX)],
            )?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// The quota grants recorded for `run`, live or not, oldest first.
    pub fn quota_grants(&self, run: &str) -> Result<Vec<GrantRow>> {
        Ok(self.grant_list(None, Some(run), true, usize::MAX)?.into_iter().map(|l| l.grant).filter(|g| g.quota().is_some()).collect())
    }

    /// The tenant's grants, newest first, at most `limit`: every kind (approvals, quotas), only live
    /// ones unless `all`.
    pub fn grants(&self, tenant: &TenantId, all: bool, limit: usize) -> Result<Vec<GrantListing>> {
        self.grant_list(Some(&tenant.0), None, all, limit)
    }

    fn grant_list(&self, tenant: Option<&str>, run: Option<&str>, all: bool, limit: usize) -> Result<Vec<GrantListing>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {}, g.decided_by, g.created_at FROM grants g
             WHERE (?5 IS NULL OR g.tenant = ?5) AND (?1 IS NULL OR g.run = ?1) AND (?2 = 1 OR (g.revoked = 0 AND g.expires_at > ?3))
             ORDER BY g.created_at {o}, g.rowid {o} LIMIT ?4",
            crate::node::GRANT_COLS,
            o = if run.is_some() { "ASC" } else { "DESC" }
        ))?;
        let rows = st.query_map(params![run, all as i64, now(), i64::try_from(limit).unwrap_or(i64::MAX), tenant], |r| {
            Ok(GrantListing { grant: crate::node::row_to_grant(r)?, decided_by: r.get(15)?, created_at: r.get(16)? })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Approval;
    use std::time::Duration;
    use wicket_core::Op;

    fn quotas() -> Vec<Quota> {
        vec![
            Quota { resource: "model.requests", amount: 50 },
            Quota { resource: "model.output_tokens", amount: 0 },
            Quota { resource: "children", amount: 3 },
            Quota { resource: "bytes", amount: 1 << 30 },
        ]
    }

    #[test]
    fn quotas_are_grants_with_an_amount_and_a_lifetime_of_at_most_a_day() {
        let l = Ledger::open_in_memory().unwrap();
        let (t, run) = (TenantId::single(), RunId("run_child".into()));
        let ids = l.record_quota_grants(&t, "z.child", &run, "agent:run_parent", &quotas(), 7 * 24 * 3600).unwrap();
        assert_eq!(ids.len(), 3, "a quota of 0 isn't recorded");
        let gs = l.quota_grants(&run.0).unwrap();
        let got: Vec<(&str, Option<i64>)> = gs.iter().map(|g| (g.quota().unwrap(), g.amount)).collect();
        assert_eq!(got, vec![("model.requests", Some(50)), ("children", Some(3)), ("bytes", Some(1 << 30))]);
        for g in &gs {
            assert_eq!(
                (g.method.as_str(), g.host.as_str(), g.run.as_deref(), g.request_id.as_deref()),
                ("QUOTA", "wicket.internal", Some("run_child"), None)
            );
            assert!(g.expires_at - now() <= MAX_QUOTA_TTL_SECS && g.expires_at > now(), "every grant has a lifetime, at most 24h");
        }
        // Recording again (a re-adopted child) keeps them.
        assert_eq!(l.record_quota_grants(&t, "z.child", &run, "agent:run_parent", &quotas(), 60).unwrap(), ids);
        // Listed with every other grant, with who made them.
        let listed = l.grants(&t, false, 100).unwrap();
        assert_eq!(listed.len(), 3);
        assert!(listed.iter().all(|g| g.decided_by == "agent:run_parent"));
        assert!(l.grants(&TenantId("other".into()), true, 100).unwrap().is_empty());
        // Renewable as any grant is, and ended with the run.
        assert!(l.renew_grant(&ids[0], now() + 3600 * 2).unwrap());
        l.run_ended(&run, "exited", "").unwrap();
        assert!(l.grants(&t, false, 100).unwrap().is_empty());
        assert_eq!(l.grants(&t, true, 100).unwrap().len(), 3);
        assert!(l.quota_grants(&run.0).unwrap().iter().all(|g| g.revoked));
    }

    #[test]
    fn a_quota_grant_decides_no_op() {
        let mut l = Ledger::open_in_memory().unwrap();
        let (t, run) = (TenantId::single(), RunId("run_child".into()));
        l.record_quota_grants(&t, "z", &run, "wicket", &[Quota { resource: "children", amount: 2 }], 600).unwrap();
        let op = Op::egress(&t, &run, "z", "QUOTA", "wicket.internal", "/quota/children");
        assert!(op.refused_for_agents().is_some(), "nobody may ask for one");
        assert_eq!(l.consume_grant(&op).unwrap(), None);
        // Nor is it handed to a node: it answers no request of the run's.
        assert!(l.grants_for_run(&run.0).unwrap().is_empty());
        // An ordinary approval still decides its op through the same lookup.
        let get = Op::egress(&t, &run, "z", "GET", "api.example.com", "/v1/x");
        let (rid, _) = l.pending_for(&get, "why", None).unwrap();
        let gid =
            l.approve(&rid, &Approval { uses: Some(1), ttl: Duration::from_secs(60), path_prefix: None, decided_by: "op".into() }).unwrap();
        assert_eq!(l.consume_grant(&get).unwrap(), Some(gid));
        assert_eq!(l.consume_grant(&get).unwrap(), None, "used up");
    }

    #[test]
    fn an_update_approval_is_found_by_the_same_lookup_and_only_for_its_own_request() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let sha = "ab".repeat(32);
        // A grant on the same path that answers some other request kind doesn't accept an update.
        let mut other = Op::egress(&t, &RunId("run_a".into()), "z", "UPDATE", "wicket.internal", "/self/other");
        other.risk = wicket_core::RiskClass::R4ExecOrPrivilege;
        let (rid, _) = l.pending_for(&other, "x", None).unwrap();
        let a = Approval { uses: None, ttl: Duration::from_secs(600), path_prefix: Some("/self/".into()), decided_by: "op".into() };
        l.approve(&rid, &a).unwrap();
        assert_eq!(l.use_update_approval(&sha).unwrap(), None, "a prefix grant, for another hash, never accepts this one");
        // Revoked or expired approvals don't either.
        let mut op = Op::egress(&t, &RunId("run_b".into()), "z", "UPDATE", "wicket.internal", &format!("/self/{sha}"));
        op.risk = wicket_core::RiskClass::R4ExecOrPrivilege;
        let (rid, _) = l.pending_for(&op, "a build", None).unwrap();
        let gid = l
            .approve(&rid, &Approval { uses: Some(5), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "op".into() })
            .unwrap();
        l.revoke_grant(&gid).unwrap();
        assert_eq!(l.use_update_approval(&sha).unwrap(), None);
    }
}
