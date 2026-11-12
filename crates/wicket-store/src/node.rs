//! What the ledger keeps for remote nodes running `wicket node serve` (#57): grants handed to a node
//! (whose uses the node then counts, so the ledger stops consuming them), and the audit records a
//! node ships back.
//!
//! **Node audit.** A node keeps its own hash-chained audit log (a ledger of its own, same
//! [`chain_hash`]) and ships records past the control host's watermark when it reconnects. Each
//! shipped record becomes one `node.audit` record in this ledger, with the node's `seq`, `prev` and
//! `hash` kept, so [`Ledger::verify_node_audit`] can recompute the node's own chain from them. A
//! record that doesn't continue the node's chain is refused. A node whose data was wiped starts its
//! chain again at seq 1 from the zero hash: that is accepted, recorded as a `node.audit.restart`
//! record, and reported as a restart by `verify_node_audit`, so it's visible rather than silently
//! stitched.
//!
//! **Attribution (#120).** The control host, not the node, decides which tenant and run a shipped
//! record is filed under: the session's tenant, and the run the node names only if that run was
//! placed on this node ([`Ledger::set_run_node`]) for the same tenant. Otherwise the record is filed
//! under no run (`"attributed": false`), so a node can't put records into another run's or tenant's
//! stream. What the node claimed is kept in the body (its chain hash covers it).

use crate::{ChainFields, ChainSummary, Ledger, Result, StoreError, CHAIN_V2_PREFIX, CHAIN_ZERO as ZERO};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

/// A grant, as the control host hands it to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    pub id: String,
    pub tenant: String,
    pub zone: String,
    pub method: String,
    pub host: String,
    pub path: String,
    /// A path-prefix grant (a node honours it for the exact path only).
    pub prefix: bool,
    pub uses_left: Option<i64>,
    /// Unix seconds.
    pub expires_at: i64,
    pub request_id: Option<String>,
    pub revoked: bool,
    /// The node it was handed to; the ledger no longer consumes it.
    pub node: Option<String>,
    /// The riskiest op it covers (`RiskClass::rank`); None for grants from older ledgers (#119).
    pub max_risk: Option<i64>,
}

/// One audit record with its chain fields, as a node ships it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: i64,
    pub ts: i64,
    pub tenant: String,
    pub run: Option<String>,
    pub kind: String,
    pub body: String,
    pub prev: String,
    pub hash: String,
}

/// What [`Ledger::verify_node_audit`] found for one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeAuditSummary {
    pub node: String,
    pub records: i64,
    /// Times the node's chain started again from seq 1 (its data was wiped).
    pub restarts: i64,
}

const GRANT_COLS: &str =
    "g.id, g.tenant, g.zone, g.method, g.host, g.path, g.prefix, g.uses_left, g.expires_at, g.request_id, g.revoked, g.node, g.max_risk";

fn row_to_grant(r: &rusqlite::Row<'_>) -> rusqlite::Result<GrantRow> {
    Ok(GrantRow {
        id: r.get(0)?,
        tenant: r.get(1)?,
        zone: r.get(2)?,
        method: r.get(3)?,
        host: r.get(4)?,
        path: r.get(5)?,
        prefix: r.get::<_, i64>(6)? != 0,
        uses_left: r.get(7)?,
        expires_at: r.get(8)?,
        request_id: r.get(9)?,
        revoked: r.get::<_, i64>(10)? != 0,
        node: r.get(11)?,
        max_risk: r.get(12)?,
    })
}

impl Ledger {
    /// Grants made for requests that `run` raised, oldest first.
    pub fn grants_for_run(&self, run: &str) -> Result<Vec<GrantRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {GRANT_COLS} FROM grants g JOIN requests q ON q.id = g.request_id WHERE q.run = ?1 ORDER BY g.created_at, g.id"
        ))?;
        let rows = st.query_map(params![run], row_to_grant)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn grant(&self, id: &str) -> Result<Option<GrantRow>> {
        Ok(self.conn.query_row(&format!("SELECT {GRANT_COLS} FROM grants g WHERE g.id = ?1"), params![id], row_to_grant).optional()?)
    }

    /// Hands a grant to a node: from now on the node counts its uses, and the ledger never consumes
    /// it. Returns false if it was already handed to a node.
    pub fn hand_grant_to_node(&self, id: &str, node: &str) -> Result<bool> {
        Ok(self.conn.execute("UPDATE grants SET node = ?2 WHERE id = ?1 AND node IS NULL", params![id, node])? == 1)
    }

    /// Revokes a grant. Grants handed to a node are revoked there through the feed by whoever
    /// publishes it (the run's control-host process).
    pub fn revoke_grant(&self, id: &str) -> Result<()> {
        if self.conn.execute("UPDATE grants SET revoked = 1 WHERE id = ?1", params![id])? == 0 {
            return Err(StoreError::Node(id.into(), "no such grant"));
        }
        Ok(())
    }

    /// Audit records after `seq`, oldest first, at most `limit`.
    pub fn audit_records_after(&self, seq: i64, limit: usize) -> Result<Vec<AuditRecord>> {
        let mut st =
            self.conn.prepare("SELECT seq, ts, tenant, run, kind, body, prev, hash FROM audit WHERE seq > ?1 ORDER BY seq LIMIT ?2")?;
        let rows = st.query_map(params![seq, limit as i64], |r| {
            Ok(AuditRecord {
                seq: r.get(0)?,
                ts: r.get(1)?,
                tenant: r.get(2)?,
                run: r.get(3)?,
                kind: r.get(4)?,
                body: r.get(5)?,
                prev: r.get(6)?,
                hash: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The last record shipped from `node`: its seq and hash on the node.
    pub fn node_audit_head(&self, node: &str) -> Result<Option<(i64, String)>> {
        let body: Option<String> = self
            .conn
            .query_row(
                "SELECT body FROM audit WHERE kind = 'node.audit' AND json_extract(body, '$.node') = ?1 ORDER BY seq DESC LIMIT 1",
                params![node],
                |r| r.get(0),
            )
            .optional()?;
        let Some(b) = body else { return Ok(None) };
        let v: serde_json::Value = serde_json::from_str(&b)?;
        match (v["seq"].as_i64(), v["hash"].as_str()) {
            (Some(s), Some(h)) => Ok(Some((s, h.to_string()))),
            _ => Err(StoreError::Node(node.into(), "unreadable node.audit record")),
        }
    }

    /// Records that `run` was placed on `node`: records the node ships for it are filed under it.
    pub fn set_run_node(&self, run: &str, node: &str) -> Result<()> {
        if self.conn.execute("UPDATE runs SET node = ?2 WHERE id = ?1", params![run, node])? == 0 {
            return Err(StoreError::Node(node.into(), "no such run to place"));
        }
        Ok(())
    }

    /// The node a run's box was placed on, if recorded.
    pub fn run_node(&self, run: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT node FROM runs WHERE id = ?1", params![run], |r| r.get::<_, Option<String>>(0)).optional()?.flatten())
    }

    /// Whether `node` has ever shipped a v2 record: from then on, v1 records from it are refused.
    fn node_shipped_v2(&self, node: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM audit WHERE kind = 'node.audit' AND json_extract(body, '$.node') = ?1
                              AND substr(json_extract(body, '$.hash'), 1, 3) = ?2)",
            params![node, CHAIN_V2_PREFIX],
            |r| r.get(0),
        )?)
    }

    /// Appends records shipped by `node`, in a session for `tenant`, each as a `node.audit` record.
    /// They must continue the node's chain from what was shipped before (or restart it at seq 1,
    /// which is recorded as a `node.audit.restart`), and each hash must recompute under the version
    /// it names. Each is filed under `tenant`, and under the run it names only if that run was placed
    /// on `node` for `tenant`. Returns how many were appended; nothing is appended if any record
    /// doesn't check.
    pub fn append_node_audit(&self, node: &str, tenant: &wicket_core::TenantId, recs: &[AuditRecord]) -> Result<usize> {
        let refuse = || StoreError::Node(node.into(), "shipped audit records do not continue the node's chain");
        let head = self.node_audit_head(node)?;
        let (mut seq, mut prev) = head.clone().unwrap_or((0, ZERO.to_string()));
        let mut sum = ChainSummary { v1: 0, v2: self.node_shipped_v2(node)? as i64 };
        for r in recs {
            let restart = r.seq == 1 && r.prev == ZERO;
            let f = ChainFields { seq: r.seq, ts: r.ts, tenant: &r.tenant, run: r.run.as_deref(), kind: &r.kind, body: &r.body };
            if !(restart || (r.seq == seq + 1 && r.prev == prev)) || !sum.accept(&r.prev, &f, &r.hash) {
                return Err(refuse());
            }
            (seq, prev) = (r.seq, r.hash.clone());
        }
        let placed = |run: &str| -> Result<bool> {
            Ok(self
                .conn
                .query_row("SELECT tenant FROM runs WHERE id = ?1 AND node = ?2", params![run, node], |r| r.get::<_, String>(0))
                .optional()?
                .is_some_and(|t| t == tenant.0))
        };
        let (mut seq, mut prev) = head.unwrap_or((0, ZERO.to_string()));
        for r in recs {
            if r.seq == 1 && r.prev == ZERO && seq > 0 {
                let why = serde_json::json!({ "node": node, "after_seq": seq, "after_hash": prev });
                self.audit(tenant, None, "node.audit.restart", &why)?;
            }
            let run = match r.run.as_deref() {
                Some(run) if r.tenant == tenant.0 && placed(run)? => Some(wicket_core::RunId(run.to_string())),
                _ => None,
            };
            let body = serde_json::json!({
                "node": node, "seq": r.seq, "ts": r.ts, "tenant": r.tenant, "run": r.run, "kind": r.kind, "body": r.body,
                "prev": r.prev, "hash": r.hash, "attributed": run.is_some() || (r.run.is_none() && r.tenant == tenant.0),
            });
            self.audit(tenant, run.as_ref(), "node.audit", &body)?;
            (seq, prev) = (r.seq, r.hash.clone());
        }
        Ok(recs.len())
    }

    /// Recomputes every node's shipped chain from its `node.audit` records.
    pub fn verify_node_audit(&self) -> Result<Vec<NodeAuditSummary>> {
        let mut st = self.conn.prepare("SELECT seq, body FROM audit WHERE kind = 'node.audit' ORDER BY seq")?;
        let mut rows = st.query([])?;
        type Head = (i64, String, ChainSummary, NodeAuditSummary);
        let mut heads: std::collections::BTreeMap<String, Head> = Default::default();
        while let Some(r) = rows.next()? {
            let (at, body): (i64, String) = (r.get(0)?, r.get(1)?);
            let v: serde_json::Value = serde_json::from_str(&body)?;
            let s = |k: &str| v[k].as_str().map(String::from).ok_or(StoreError::ChainBroken(at));
            let (node, kind, b, p, h) = (s("node")?, s("kind")?, s("body")?, s("prev")?, s("hash")?);
            let seq = v["seq"].as_i64().ok_or(StoreError::ChainBroken(at))?;
            // Records shipped before #120 carry neither ts nor tenant in the body; they are v1, whose
            // hash doesn't cover them. A v2 record without them fails.
            let (ts, tenant) = (v["ts"].as_i64().unwrap_or(0), v["tenant"].as_str().unwrap_or(""));
            let f = ChainFields { seq, ts, tenant, run: v["run"].as_str(), kind: &kind, body: &b };
            let e = heads
                .entry(node.clone())
                .or_insert_with(|| (0, ZERO.to_string(), ChainSummary::default(), NodeAuditSummary { node, records: 0, restarts: 0 }));
            let restart = seq == 1 && p == ZERO;
            if (h.starts_with(CHAIN_V2_PREFIX) && v["tenant"].as_str().is_none())
                || !(restart || (seq == e.0 + 1 && p == e.1))
                || !e.2.accept(&p, &f, &h)
            {
                return Err(StoreError::ChainBroken(at));
            }
            if restart && e.3.records > 0 {
                e.3.restarts += 1;
            }
            e.0 = seq;
            e.1 = h;
            e.3.records += 1;
        }
        Ok(heads.into_values().map(|(_, _, _, s)| s).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Approval;
    use std::time::Duration;
    use wicket_core::{Op, RunId, TenantId};

    #[test]
    fn grants_handed_to_a_node_are_never_consumed_by_the_ledger() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let op = Op::egress(&t, &RunId("run_a".into()), "z", "GET", "api.example.com", "/x");
        let (rid, _) = l.pending_for(&op, "out of reach", None).unwrap();
        let gid =
            l.approve(&rid, &Approval { uses: Some(2), ttl: Duration::from_secs(60), path_prefix: None, decided_by: "t".into() }).unwrap();
        let g = l.grants_for_run("run_a").unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!((g[0].id.as_str(), g[0].uses_left, g[0].node.as_deref()), (gid.as_str(), Some(2), None));
        assert!(l.grants_for_run("run_b").unwrap().is_empty());
        assert!(l.hand_grant_to_node(&gid, "n1").unwrap());
        assert!(!l.hand_grant_to_node(&gid, "n2").unwrap(), "handed once");
        assert_eq!(l.consume_grant(&op).unwrap(), None, "the node counts it now");
        l.revoke_grant(&gid).unwrap();
        assert!(l.grant(&gid).unwrap().unwrap().revoked);
        assert!(l.revoke_grant("g-nope").is_err());
    }

    /// #120: the control host files shipped records: under the session's tenant, and under the run a
    /// record names only if that run was placed on this node for that tenant.
    #[test]
    fn a_node_cannot_file_records_under_runs_or_tenants_it_does_not_hold() {
        let t = TenantId::single();
        let ctl = Ledger::open_in_memory().unwrap();
        for (run, tenant, node) in [("run_a", "t0", "n1"), ("run_b", "t0", "n2"), ("run_x", "other", "n1")] {
            ctl.run_started(&TenantId(tenant.into()), &RunId(run.into()), "z", "agent").unwrap();
            ctl.set_run_node(run, node).unwrap();
        }
        ctl.run_started(&t, &RunId("run_c".into()), "z", "agent").unwrap();
        assert!(ctl.set_run_node("run_nope", "n1").is_err());
        let node_l = Ledger::open_in_memory().unwrap();
        let claims = [
            ("t0", Some("run_a")),
            ("t0", Some("run_b")),
            ("t0", Some("run_c")),
            ("other", Some("run_x")),
            ("other", Some("run_a")),
            ("t0", None),
        ];
        for (tenant, run) in claims {
            node_l.audit(&TenantId(tenant.into()), run.map(|r| RunId(r.into())).as_ref(), "op", &serde_json::json!({})).unwrap();
        }
        let recs = node_l.audit_records_after(0, 100).unwrap();
        assert_eq!(ctl.append_node_audit("n1", &t, &recs).unwrap(), 6);
        let filed: Vec<(String, Option<String>, bool)> = ctl
            .audit_records_after(0, 100)
            .unwrap()
            .into_iter()
            .filter(|r| r.kind == "node.audit")
            .map(|r| {
                let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
                (r.tenant, r.run, v["attributed"].as_bool().unwrap())
            })
            .collect();
        let d = || t.0.clone();
        assert_eq!(
            filed,
            vec![
                (d(), Some("run_a".into()), true),
                (d(), None, false), // placed on another node
                (d(), None, false), // placed on no node
                (d(), None, false), // another tenant's run, even on this node
                (d(), None, false), // a claimed tenant that isn't the session's
                (d(), None, true),
            ]
        );
        assert_eq!(ctl.verify_node_audit().unwrap()[0].records, 6);
        ctl.verify_audit().unwrap();

        // What the node claimed is covered by its own chain: editing the claim in the body is caught.
        let at: i64 = ctl.conn.query_row("SELECT seq FROM audit WHERE kind = 'node.audit' ORDER BY seq LIMIT 1", [], |r| r.get(0)).unwrap();
        ctl.conn.execute("UPDATE audit SET body = json_set(body, '$.run', 'run_b') WHERE seq = ?1", params![at]).unwrap();
        assert!(matches!(ctl.verify_node_audit(), Err(StoreError::ChainBroken(_))));
    }

    /// #120: a node that restarts its chain gets an explicit audit record, and a node that has shipped
    /// v2 records can't go back to v1 (which doesn't cover ts, tenant or run).
    #[test]
    fn node_chain_restarts_are_recorded_and_v1_never_follows_v2() {
        let t = TenantId::single();
        let ctl = Ledger::open_in_memory().unwrap();
        let node_l = Ledger::open_in_memory().unwrap();
        node_l.audit(&t, None, "op", &serde_json::json!({})).unwrap();
        ctl.append_node_audit("n1", &t, &node_l.audit_records_after(0, 10).unwrap()).unwrap();
        let fresh = Ledger::open_in_memory().unwrap();
        fresh.audit(&t, None, "op", &serde_json::json!({ "again": true })).unwrap();
        ctl.append_node_audit("n1", &t, &fresh.audit_records_after(0, 10).unwrap()).unwrap();
        let kinds: Vec<String> = ctl.audit_records_after(0, 10).unwrap().into_iter().map(|r| r.kind).collect();
        assert_eq!(kinds, ["node.audit", "node.audit.restart", "node.audit"]);
        // A v1 restart (an old-format chain, which hides ts, tenant and run) is refused now.
        let body = "{}".to_string();
        let v1 = AuditRecord {
            seq: 1,
            ts: 5,
            tenant: "t0".into(),
            run: Some("run_a".into()),
            kind: "op".into(),
            hash: crate::chain_hash(ZERO, "op", &body),
            body,
            prev: ZERO.into(),
        };
        assert!(ctl.append_node_audit("n1", &t, std::slice::from_ref(&v1)).is_err());
        // A node that has only ever shipped v1 (an older node) is still accepted.
        assert_eq!(ctl.append_node_audit("old", &t, &[v1]).unwrap(), 1);
        assert_eq!(ctl.verify_node_audit().unwrap().len(), 2);
    }

    #[test]
    fn shipped_node_audit_must_continue_the_chain_and_verifies() {
        let node_l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        for i in 0..5 {
            node_l.audit(&t, Some(&RunId("run_a".into())), "op", &serde_json::json!({ "i": i })).unwrap();
        }
        let all = node_l.audit_records_after(0, 100).unwrap();
        let ctl = Ledger::open_in_memory().unwrap();
        ctl.audit(&t, None, "run.start", &serde_json::json!({})).unwrap();
        assert_eq!(ctl.append_node_audit("n1", &t, &all[..2]).unwrap(), 2);
        assert_eq!(ctl.node_audit_head("n1").unwrap().unwrap().0, 2);
        // A gap, a replay, and a tampered body are refused, and nothing is appended.
        assert!(ctl.append_node_audit("n1", &t, &all[3..]).is_err());
        assert!(ctl.append_node_audit("n1", &t, &all[1..3]).is_err());
        let mut bad = all[2..].to_vec();
        bad[0].body = "{\"i\":99}".into();
        assert!(ctl.append_node_audit("n1", &t, &bad).is_err());
        assert_eq!(ctl.append_node_audit("n1", &t, &all[2..]).unwrap(), 3);
        ctl.verify_audit().unwrap();
        let v = ctl.verify_node_audit().unwrap();
        assert_eq!(v, vec![NodeAuditSummary { node: "n1".into(), records: 5, restarts: 0 }]);
        // A wiped node starts again from seq 1: accepted and reported.
        let fresh = Ledger::open_in_memory().unwrap();
        fresh.audit(&t, None, "op", &serde_json::json!({})).unwrap();
        ctl.append_node_audit("n1", &t, &fresh.audit_records_after(0, 10).unwrap()).unwrap();
        assert_eq!(ctl.verify_node_audit().unwrap()[0].restarts, 1);
    }
}
