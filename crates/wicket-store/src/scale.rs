//! What keeps the ledger's cost per box flat as boxes and history grow (#582 step 1).
//!
//! - **Indexes** on every lookup a run's supervisor, a node's feed status or a request makes
//!   (`grants`, `runs`, the cancel tables, `audit` by kind), so none scans a table that grows with
//!   history. `tests::no_hot_path_scans_a_growing_table` checks each such statement's query plan.
//! - **A stored per-node audit head** (`node_audit_heads`): the last record each node shipped, kept
//!   by a trigger on `audit`, instead of searching back through every record for it. A trigger
//!   because it lives in the database: a build from before it (a rollback within the floor) still
//!   keeps the head right.
//! - **Archiving ended rows** ([`Ledger::archive_ended`]): a run's settled requests and dead grants
//!   move to `requests_archive` and `grants_archive` once it has been over for
//!   [`ARCHIVE_AFTER_SECS`]. Nothing live moves: not a pending request, a live grant, a money or
//!   quota grant, or a standing grant with no run. The few reads of history look there too.
//! - **Maintenance** ([`Ledger::maintain`], each reconcile pass): the archive, `PRAGMA optimize`
//!   (so SQLite's planner has statistics; it does nothing when they are fresh), and a passive WAL
//!   checkpoint, so the WAL doesn't grow without bound while readers are always present.

use crate::{Ledger, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

/// How long after a run ends its settled rows stay in the hot tables.
pub const ARCHIVE_AFTER_SECS: i64 = 7 * 24 * 3600;

/// At most this many grants (and as many requests) move per [`Ledger::archive_ended`], so one pass
/// holds the write lock briefly (about 100 ms for 2,000 on a VPS disk); the rest go in the next.
pub const ARCHIVE_BATCH: i64 = 2000;

pub(crate) const SCHEMA: &str = r#"
CREATE INDEX IF NOT EXISTS grants_request ON grants (request_id);
CREATE INDEX IF NOT EXISTS grants_node ON grants (node, node_epoch);
CREATE INDEX IF NOT EXISTS grants_run ON grants (run, method, host);
CREATE INDEX IF NOT EXISTS grants_scope ON grants (method, host, path);
CREATE INDEX IF NOT EXISTS runs_status ON runs (status, node);
CREATE INDEX IF NOT EXISTS runs_lease ON runs (lease) WHERE lease IS NOT NULL;
CREATE INDEX IF NOT EXISTS runs_uncollected ON runs (uncollected) WHERE uncollected IS NOT NULL;
CREATE INDEX IF NOT EXISTS runs_tenant ON runs (tenant, started_at);
CREATE INDEX IF NOT EXISTS runs_ended ON runs (ended_at) WHERE ended_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS turn_cancels_run ON turn_cancels (run, consumed_at);
CREATE INDEX IF NOT EXISTS mode_changes_run ON mode_changes (run, consumed_at);
CREATE INDEX IF NOT EXISTS audit_kind ON audit (kind, seq);
CREATE INDEX IF NOT EXISTS node_ca_wants_run ON node_ca_wants (run);
CREATE TABLE IF NOT EXISTS grants_archive AS SELECT * FROM grants WHERE 0;
CREATE TABLE IF NOT EXISTS requests_archive AS SELECT * FROM requests WHERE 0;
CREATE INDEX IF NOT EXISTS grants_archive_id ON grants_archive (id);
CREATE INDEX IF NOT EXISTS grants_archive_request ON grants_archive (request_id);
CREATE INDEX IF NOT EXISTS requests_archive_id ON requests_archive (id);
CREATE INDEX IF NOT EXISTS requests_archive_run ON requests_archive (run);
"#;

const HEADS: &str = r#"
CREATE TABLE IF NOT EXISTS node_audit_heads (
  node TEXT PRIMARY KEY, seq INTEGER NOT NULL, hash TEXT NOT NULL, audit_seq INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS node_audit_head AFTER INSERT ON audit
WHEN NEW.kind = 'node.audit' AND CASE WHEN json_valid(NEW.body) THEN json_type(NEW.body, '$.node') = 'text'
  AND json_type(NEW.body, '$.seq') = 'integer' AND json_type(NEW.body, '$.hash') = 'text' ELSE 0 END
BEGIN
  INSERT OR REPLACE INTO node_audit_heads (node, seq, hash, audit_seq)
  VALUES (json_extract(NEW.body, '$.node'), json_extract(NEW.body, '$.seq'), json_extract(NEW.body, '$.hash'), NEW.seq);
END;
"#;

/// Creates what this module keeps, and the per-node heads from the records already shipped (once:
/// when the table is new; the trigger keeps it after).
pub(crate) fn migrate(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    let had: bool = conn
        .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'node_audit_heads'", [], |r| r.get::<_, i64>(0))?
        > 0;
    if had {
        return conn.execute_batch(HEADS).map_err(Into::into);
    }
    conn.execute_batch(&format!(
        "BEGIN IMMEDIATE;
         {HEADS}
         INSERT OR REPLACE INTO node_audit_heads (node, seq, hash, audit_seq)
           SELECT json_extract(body, '$.node'), json_extract(body, '$.seq'), json_extract(body, '$.hash'), seq
           FROM audit WHERE kind = 'node.audit' AND CASE WHEN json_valid(body) THEN json_type(body, '$.node') = 'text'
             AND json_type(body, '$.seq') = 'integer' AND json_type(body, '$.hash') = 'text' ELSE 0 END
           ORDER BY seq;
         COMMIT;"
    ))?;
    Ok(())
}

/// What one [`Ledger::maintain`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Maintained {
    pub archived_grants: usize,
    pub archived_requests: usize,
    /// Cancel and mode-change rows taken or stale, and reservations settled a day ago (#579), deleted.
    pub dropped_asks: usize,
    /// WAL frames checkpointed, and the WAL's frames (both -1 for a ledger not in WAL mode).
    pub checkpointed: i64,
    pub wal_frames: i64,
}

impl Ledger {
    /// The last record `node` shipped: its seq and hash on the node.
    pub(crate) fn stored_node_audit_head(&self, node: &str) -> Result<Option<(i64, String)>> {
        Ok(self
            .conn
            .query_row("SELECT seq, hash FROM node_audit_heads WHERE node = ?1", params![node], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    }

    /// Moves the settled rows of runs that ended before `now - ARCHIVE_AFTER_SECS` to the archive
    /// tables (see the module's doc), at most [`ARCHIVE_BATCH`] of each. Returns (grants, requests).
    pub fn archive_ended(&self, now: i64) -> Result<(usize, usize)> {
        let cutoff = now - ARCHIVE_AFTER_SECS;
        let tx = self.conn.unchecked_transaction()?;
        same_columns(&tx, "grants", "grants_archive")?;
        same_columns(&tx, "requests", "requests_archive")?;
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS moving (id TEXT PRIMARY KEY); DELETE FROM moving;")?;
        // Dead grants of ended runs: bound to one, or made for one's request.
        let g = tx.execute(
            "INSERT OR IGNORE INTO moving (id)
             SELECT g.id FROM runs r JOIN requests q ON q.run = r.id JOIN grants g ON g.request_id = q.id
             WHERE r.ended_at IS NOT NULL AND r.ended_at < ?1
               AND g.amount IS NULL AND g.principal IS NULL
               AND (g.revoked = 1 OR g.expires_at <= ?2 OR g.uses_left = 0)
             UNION
             SELECT g.id FROM runs r JOIN grants g ON g.run = r.id
             WHERE r.ended_at IS NOT NULL AND r.ended_at < ?1
               AND g.amount IS NULL AND g.principal IS NULL
               AND (g.revoked = 1 OR g.expires_at <= ?2 OR g.uses_left = 0)
             LIMIT ?3",
            params![cutoff, now, ARCHIVE_BATCH],
        )?;
        let cols = columns(&tx, "grants")?;
        tx.execute(&format!("INSERT INTO grants_archive ({cols}) SELECT {cols} FROM grants WHERE id IN (SELECT id FROM moving)"), [])?;
        tx.execute("DELETE FROM grants WHERE id IN (SELECT id FROM moving)", [])?;
        tx.execute("DELETE FROM moving", [])?;
        // Their settled requests, once no grant in the hot table still names them.
        let q = tx.execute(
            "INSERT OR IGNORE INTO moving (id)
             SELECT q.id FROM runs r JOIN requests q ON q.run = r.id
             WHERE r.ended_at IS NOT NULL AND r.ended_at < ?1 AND q.status != 'pending'
               AND NOT EXISTS (SELECT 1 FROM grants g WHERE g.request_id = q.id)
             LIMIT ?2",
            params![cutoff, ARCHIVE_BATCH],
        )?;
        let cols = columns(&tx, "requests")?;
        tx.execute(&format!("INSERT INTO requests_archive ({cols}) SELECT {cols} FROM requests WHERE id IN (SELECT id FROM moving)"), [])?;
        tx.execute("DELETE FROM requests WHERE id IN (SELECT id FROM moving)", [])?;
        tx.execute("DELETE FROM moving", [])?;
        tx.commit()?;
        Ok((g, q))
    }

    /// Deletes cancel and mode-change asks already taken, or too old to be taken (a supervisor
    /// drops those older than its freshness window, a minute at most).
    pub fn drop_spent_asks(&self, now: i64) -> Result<usize> {
        let stale = now - 3600;
        let mut n = 0;
        for t in ["turn_cancels", "mode_changes"] {
            n += self.conn.execute(&format!("DELETE FROM {t} WHERE consumed_at IS NOT NULL OR created_at < ?1"), params![stale])?;
        }
        Ok(n)
    }

    /// One maintenance pass (see the module's doc).
    pub fn maintain(&self, now: i64) -> Result<Maintained> {
        let (archived_grants, archived_requests) = self.archive_ended(now)?;
        let dropped_asks = self.drop_spent_asks(now)? + self.drop_settled_placements(now)?;
        // Statistics for the planner, limited so a large table costs milliseconds (SQLite's advice
        // for long-lived connections; it only analyses tables whose size moved a lot).
        self.conn.execute_batch("PRAGMA analysis_limit = 400; PRAGMA optimize;")?;
        let (busy, wal_frames, checkpointed): (i64, i64, i64) =
            self.conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        let _ = busy;
        Ok(Maintained { archived_grants, archived_requests, dropped_asks, checkpointed, wal_frames })
    }
}

fn names(conn: &rusqlite::Connection, table: &str) -> Result<Vec<(String, String)>> {
    let mut st = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

fn columns(conn: &rusqlite::Connection, table: &str) -> Result<String> {
    Ok(names(conn, table)?.into_iter().map(|(n, _)| format!("\"{n}\"")).collect::<Vec<_>>().join(", "))
}

/// Adds to `archive` any column `table` has gained since the archive was made.
fn same_columns(conn: &rusqlite::Connection, table: &str, archive: &str) -> Result<()> {
    let have: Vec<String> = names(conn, archive)?.into_iter().map(|(n, _)| n).collect();
    for (n, ty) in names(conn, table)? {
        if !have.contains(&n) {
            conn.execute_batch(&format!("ALTER TABLE {archive} ADD COLUMN \"{n}\" {ty}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::Approval;
    use rusqlite::trace::{TraceEvent, TraceEventCodes};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use wicket_core::{Op, RunId, TenantId};

    /// Tables that grow with boxes and history: no hot path may scan one.
    const GROWING: &[&str] = &[
        "grants",
        "requests",
        "runs",
        "audit",
        "messages",
        "turn_cancels",
        "mode_changes",
        "identities",
        "identity_history",
        "node_ca_wants",
        "placements",
        "grants_archive",
        "requests_archive",
    ];

    /// A ledger with `runs` runs, each with a request and its grant, most of them ended (a tenth
    /// of those over a week ago), and 3 nodes' shipped audit.
    pub(crate) fn populated(runs: usize) -> Ledger {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let node_l = Ledger::open_in_memory().unwrap();
        for i in 0..runs {
            let run = RunId(format!("run_{i:06}"));
            l.run_started(&t, &run, "z", "a").unwrap();
            l.set_run_node(&run.0, &format!("n{}", i % 3)).unwrap();
            let op = Op::egress(&t, &run, "z", "GET", &format!("h{}.example.com", i % 50), &format!("/p/{i}"));
            let (rid, _) = l.pending_for(&op, "out of reach", None).unwrap();
            let a = Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "t".into() };
            let gid = l.approve(&rid, &a).unwrap();
            if i % 2 == 0 {
                l.hand_grant_to_node(&gid, &format!("n{}", i % 3)).unwrap();
            }
            if i % 10 != 0 {
                l.run_ended(&run, "done", "").unwrap();
            }
            node_l.audit(&t, Some(&run), "op", &serde_json::json!({ "i": i })).unwrap();
        }
        l.conn
            .execute(
                "UPDATE runs SET ended_at = ended_at - ?1 WHERE ended_at IS NOT NULL AND rowid % 10 = 2",
                params![ARCHIVE_AFTER_SECS + 60],
            )
            .unwrap();
        let recs = node_l.audit_records_after(0, runs).unwrap();
        for (k, chunk) in recs.chunks(recs.len().div_ceil(3).max(1)).enumerate() {
            // Each node's chain from seq 1: the same records shipped by three nodes.
            let _ = k;
            for n in ["n0", "n1", "n2"] {
                if l.node_audit_head(n).unwrap().is_none() || k > 0 {
                    l.append_node_audit(n, &t, chunk).unwrap();
                }
            }
        }
        l
    }

    /// The statements `l` runs while `f` does, each once: (SQL as written, with its values).
    /// The statements `l` runs while `f` does, each once: (SQL as written, with its values, and
    /// the most rows any run of it stepped through in a full scan).
    fn traced(l: &mut Ledger, f: impl FnOnce(&mut Ledger)) -> Vec<(String, String, i32)> {
        let seen: Arc<Mutex<Vec<(String, String, i32)>>> = Arc::default();
        let into = seen.clone();
        l.conn
            .trace_v2(
                TraceEventCodes::SQLITE_TRACE_PROFILE,
                Some(move |e: TraceEvent<'_>| {
                    if let TraceEvent::Profile(s, _) = e {
                        let sql = s.sql().to_string();
                        let steps = s.get_status(rusqlite::StatementStatus::FullscanStep);
                        let mut v = into.lock().unwrap();
                        match v.iter_mut().find(|(q, _, _)| q == &sql) {
                            Some(x) => x.2 = x.2.max(steps),
                            None => v.push((sql, s.expanded_sql().unwrap_or_default(), steps)),
                        }
                    }
                }),
            )
            .unwrap();
        f(l);
        l.conn.trace_v2(TraceEventCodes::SQLITE_TRACE_PROFILE, None::<fn(TraceEvent<'_>)>).unwrap();
        let v = seen.lock().unwrap().clone();
        v
    }

    /// The query plan's lines that scan a growing table (`SCAN grants`, `SCAN g` for an alias of
    /// one): every line naming a scan of anything but a temporary result or a small table.
    fn scans(l: &Ledger, sql: &str) -> Vec<String> {
        let trimmed = sql.trim_start().to_ascii_uppercase();
        if trimmed.starts_with("PRAGMA") || trimmed.starts_with("BEGIN") || trimmed.starts_with("COMMIT") || trimmed.starts_with("ROLLBACK")
        {
            return vec![];
        }
        let mut st = l.conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let lines: Vec<String> = st.query_map([], |r| r.get::<_, String>(3)).unwrap().map(|r| r.unwrap()).collect();
        let small = ["nodes", "node_health", "schema_meta", "node_audit_heads", "moving", "CONSTANT"];
        lines
            .into_iter()
            .filter(|d| {
                let Some(rest) = d.strip_prefix("SCAN ") else { return false };
                let what = rest.split_whitespace().next().unwrap_or("");
                !(what.starts_with('(') || what.starts_with("subquery") || small.contains(&what))
                    && (GROWING.contains(&what) || what.len() <= 2)
            })
            .collect()
    }

    /// What a run's supervisor, a node's feed status, a box's request and its approval do, on a
    /// ledger with history: none of their statements may scan a table that grows with it.
    #[test]
    fn no_hot_path_scans_a_growing_table() {
        let mut l = populated(600);
        let t = TenantId::single();
        let hot = |l: &mut Ledger| {
            let run = "run_000010";
            l.grants_for_run(run).unwrap();
            l.node_feed_at("n1", 7).unwrap();
            l.take_turn_cancels(run, 30).unwrap();
            l.take_mode_changes(run, 30).unwrap();
            l.request_turn_cancel(run, "op").unwrap();
            l.request_mode_change(run, "default", "op").unwrap();
            l.take_turn_cancels(run, 30).unwrap();
            l.take_mode_changes(run, 30).unwrap();
            l.node_audit_head("n1").unwrap();
            l.set_node_health("n1", 1, "{}").unwrap();
            l.run_node(run).unwrap();
            l.running_runs_on_node("n1").unwrap();
            l.runs_on_lease("lease_x").unwrap();
            l.uncollected_runs_on_node("n1").unwrap();
            let op = Op::egress(&t, &RunId("run_000020".into()), "z", "GET", "h3.example.com", "/fresh");
            l.grant_covering(&op).unwrap();
            let (rid, _) = l.pending_for(&op, "out of reach", None).unwrap();
            l.request(&rid).unwrap();
            let a = Approval { uses: Some(1), ttl: Duration::from_secs(60), path_prefix: None, decided_by: "t".into() };
            let gid = l.approve(&rid, &a).unwrap();
            l.grant(&gid).unwrap();
            l.grant_in_flight(&rid).unwrap();
            l.grant_unhanded(&rid).unwrap();
            l.hand_grant_to_node(&gid, "n2").unwrap();
            l.grants_published(std::slice::from_ref(&gid), 9).unwrap();
            l.grant_provenance(&gid).unwrap();
            l.audit_head().unwrap();
            l.run_ended(&RunId("run_000020".into()), "done", "").unwrap();
        };
        for when in ["before any statistics", "after maintenance"] {
            let seen = traced(&mut l, hot);
            assert!(seen.len() > 20, "{} statements traced", seen.len());
            let bad: Vec<String> = seen
                .iter()
                // A plan's SCAN that stops after a row or two (`ORDER BY seq DESC LIMIT 1` walks
                // the rowid from its end) is not a scan of the table: SQLite's own count of
                // full-scan steps tells them apart.
                .filter_map(|(sql, expanded, steps)| {
                    let s = scans(&l, expanded);
                    (!s.is_empty() && *steps > 2).then(|| {
                        format!(
                            "{}\n    plan: {} ({steps} rows stepped)",
                            sql.split_whitespace().collect::<Vec<_>>().join(" "),
                            s.join("; ")
                        )
                    })
                })
                .collect();
            assert!(bad.is_empty(), "{when}, these scan a table that grows with history:\n  {}", bad.join("\n  "));
            l.maintain(crate::now()).unwrap();
        }
    }

    #[test]
    fn each_nodes_audit_head_is_kept_as_records_are_shipped_and_backfilled_once() {
        let l = populated(30);
        let heads: Vec<_> = ["n0", "n1", "n2"].iter().map(|n| l.node_audit_head(n).unwrap().unwrap()).collect();
        assert!(heads.iter().all(|h| h.0 == 30), "{heads:?}");
        // What the head was found by before #582: the last node.audit record naming the node.
        let searched: String = l
            .conn
            .query_row(
                "SELECT json_extract(body, '$.hash') FROM audit WHERE kind = 'node.audit' AND json_extract(body, '$.node') = 'n1' ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(heads[1].1, searched);
        // A ledger from before the table: backfilled from the records when it is first made.
        l.conn.execute_batch("DROP TRIGGER node_audit_head; DROP TABLE node_audit_heads;").unwrap();
        assert!(
            l.conn.query_row("SELECT count(*) FROM sqlite_master WHERE name = 'node_audit_heads'", [], |r| r.get::<_, i64>(0)).unwrap()
                == 0
        );
        migrate(&l.conn).unwrap();
        assert_eq!(l.node_audit_head("n1").unwrap().unwrap(), heads[1]);
        verify(&l);
    }

    fn verify(l: &Ledger) {
        l.verify_audit().unwrap();
        assert_eq!(l.verify_node_audit().unwrap().len(), 3);
    }

    #[test]
    fn only_settled_rows_of_runs_long_ended_are_archived_and_still_read() {
        let mut l = populated(200);
        let count = |l: &Ledger, t: &str| l.conn.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get::<_, i64>(0)).unwrap();
        let (g0, q0) = (count(&l, "grants"), count(&l, "requests"));
        // Old enough: one in ten of the runs (those with rowid % 10 == 2).
        let old: Vec<String> = {
            let mut st = l.conn.prepare("SELECT id FROM runs WHERE ended_at < ?1 ORDER BY id").unwrap();
            st.query_map(params![crate::now() - ARCHIVE_AFTER_SECS], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
        };
        assert_eq!(old.len(), 20);
        let before: Vec<_> = old.iter().map(|r| l.grants_for_run(r).unwrap()).collect();
        let rid = before[0][0].request_id.clone().unwrap();
        let request = l.request(&rid).unwrap();
        // A live grant of a long-ended run (zone-wide, not bound to it) stays.
        let live_run = &old[1];
        l.conn
            .execute(
                "UPDATE grants SET revoked = 0, run = NULL, expires_at = ?2 WHERE id = ?1",
                params![before[1][0].id, crate::now() + 600],
            )
            .unwrap();
        let m = l.maintain(crate::now()).unwrap();
        assert_eq!((m.archived_grants, m.archived_requests), (19, 19), "{m:?}");
        assert_eq!((count(&l, "grants"), count(&l, "requests")), (g0 - 19, q0 - 19));
        assert_eq!(count(&l, "grants_archive"), 19);
        for (r, b) in old.iter().zip(&before) {
            if r != live_run {
                assert_eq!(&l.grants_for_run(r).unwrap(), b, "{r}: still read, from the archive");
            }
        }
        assert_eq!(l.request(&rid).unwrap().id, request.id);
        assert_eq!(l.grant(&before[0][0].id).unwrap().as_ref(), before[0].first());
        assert!(
            l.conn.query_row("SELECT count(*) FROM grants WHERE id = ?1", params![before[1][0].id], |r| r.get::<_, i64>(0)).unwrap() == 1
        );
        // Nothing more to move; a run ended recently isn't touched.
        assert_eq!(l.archive_ended(crate::now()).unwrap(), (0, 0));
        // A column added to grants later is added to the archive before rows move.
        l.conn.execute_batch("ALTER TABLE grants ADD COLUMN later TEXT").unwrap();
        l.conn.execute("UPDATE runs SET ended_at = ended_at - ?1", params![ARCHIVE_AFTER_SECS + 60]).unwrap();
        let (g, _) = l.archive_ended(crate::now() + 3600).unwrap();
        assert!(g > 0);
        assert!(names(&l.conn, "grants_archive").unwrap().iter().any(|(n, _)| n == "later"));
        let _ = &mut l;
    }

    #[test]
    fn spent_asks_are_dropped_and_a_supervisor_with_none_takes_no_write_lock() {
        let mut l = Ledger::open_in_memory().unwrap();
        l.request_turn_cancel("r", "op").unwrap();
        assert_eq!(l.take_turn_cancels("r", 30).unwrap(), vec!["op".to_string()]);
        l.request_mode_change("r", "default", "op").unwrap();
        assert_eq!(l.drop_spent_asks(crate::now()).unwrap(), 1, "the taken cancel; the mode change waits");
        let seen = traced(&mut l, |l| {
            l.take_turn_cancels("r", 30).unwrap();
        });
        assert!(seen.iter().all(|(s, _, _)| !s.contains("UPDATE") && !s.contains("BEGIN")), "{seen:?}");
        assert_eq!(l.take_mode_changes("r", 30).unwrap().len(), 1);
    }
}
