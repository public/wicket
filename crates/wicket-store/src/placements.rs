//! Reservations of node room for boxes being started (#579 step 2).
//!
//! Placement reads each node's room from its last health report (`node_health`), which doesn't
//! count the boxes started since. A start reserves what its box asks for on the node it chose, in
//! the same transaction as the choice ([`Ledger::immediate`]), so two starts can't count the same
//! room. A reservation counts against the node until the node's own report includes the box:
//!
//! - `reserved`: chosen, not started yet. Counted for [`RESERVE_SECS`], then ignored (a start that
//!   neither failed nor started: a crashed supervisor).
//! - `bound`: its box started at `bound_at_ms`. Counted until a report received after that.
//! - `released`: its start failed or its run ended. Never counted.
//!
//! The node's admission stays the last word: a box it refuses releases its reservation.

use crate::{Ledger, Result};
use rusqlite::{params, OptionalExtension};

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS placements (
  run TEXT PRIMARY KEY, node TEXT NOT NULL, vcpus REAL NOT NULL, memory_mib INTEGER NOT NULL,
  at_ms INTEGER NOT NULL, state TEXT NOT NULL, bound_at_ms INTEGER
);
CREATE INDEX IF NOT EXISTS placements_node ON placements (node, state);
CREATE TABLE IF NOT EXISTS placement_decisions (run TEXT PRIMARY KEY, at_ms INTEGER NOT NULL, decision TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS placement_waits (
  run TEXT PRIMARY KEY, at_ms INTEGER NOT NULL, seen_ms INTEGER NOT NULL, request TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_terms (
  run TEXT PRIMARY KEY, vcpus REAL NOT NULL, memory_mib INTEGER NOT NULL, priority INTEGER NOT NULL,
  preemptible INTEGER NOT NULL, at_ms INTEGER NOT NULL
);
"#;

/// A waiter not seen for this long (ms) has gone (its process ended): it no longer holds its place.
pub const WAIT_SEEN_MS: i64 = 10_000;

/// How long an unconfirmed reservation counts against its node (s).
pub const RESERVE_SECS: i64 = 120;

/// A running run on a node ([`Ledger::running_boxes`]).
#[derive(Clone, Debug, PartialEq)]
pub struct RunningBox {
    pub run: String,
    pub node: String,
    pub tenant: String,
    pub zone: String,
    /// Its principal's id, if it has an identity.
    pub principal: Option<String>,
}

/// A running box's placement terms, for preemption (#579 step 4): what it holds, where, and
/// whether a box of higher priority may stop it ([`Ledger::preemption_view`]).
#[derive(Clone, Debug, PartialEq)]
pub struct BoxTerms {
    pub run: String,
    pub node: String,
    pub tenant: String,
    pub vcpus: f32,
    pub memory_mib: u64,
    pub priority: i32,
    pub preemptible: bool,
    /// Its run is revoked: it is being stopped.
    pub revoked: bool,
}

/// A run's reservation.
#[derive(Clone, Debug, PartialEq)]
pub struct Placement {
    pub run: String,
    pub node: String,
    pub vcpus: f32,
    pub memory_mib: u64,
    pub at_ms: i64,
    pub state: String,
}

impl Ledger {
    /// Runs `f` under the ledger's write lock (`BEGIN IMMEDIATE`), committing if it returns Ok: a
    /// read and the write it decides on, with no other writer between them.
    pub fn immediate<T, E: From<crate::StoreError>>(
        &self,
        f: impl FnOnce(&Ledger) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(|e| E::from(e.into()))?;
        let r = f(self);
        let end = if r.is_ok() { "COMMIT" } else { "ROLLBACK" };
        match (r, self.conn.execute_batch(end)) {
            (Ok(v), Ok(())) => Ok(v),
            (Ok(_), Err(e)) => Err(E::from(e.into())),
            (Err(e), _) => Err(e),
        }
    }

    /// Reserves `vcpus` and `memory_mib` on `node` for `run`'s box (replacing a reservation it had).
    pub fn reserve_placement(&self, run: &str, node: &str, vcpus: f32, memory_mib: u64, now_ms: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO placements (run, node, vcpus, memory_mib, at_ms, state, bound_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'reserved', NULL)",
            params![run, node, vcpus as f64, memory_mib as i64, now_ms],
        )?;
        Ok(())
    }

    /// `run`'s box started: its reservation counts until the node's next report.
    pub fn placement_bound(&self, run: &str, now_ms: i64) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE placements SET state = 'bound', bound_at_ms = ?2 WHERE run = ?1 AND state = 'reserved'",
            params![run, now_ms],
        )? > 0)
    }

    /// `run`'s start failed, or it ended: its reservation counts no more.
    pub fn placement_released(&self, run: &str) -> Result<bool> {
        Ok(self.conn.execute("UPDATE placements SET state = 'released' WHERE run = ?1 AND state != 'released'", params![run])? > 0)
    }

    pub fn placement(&self, run: &str) -> Result<Option<Placement>> {
        Ok(self
            .conn
            .query_row("SELECT run, node, vcpus, memory_mib, at_ms, state FROM placements WHERE run = ?1", params![run], |r| {
                Ok(Placement {
                    run: r.get(0)?,
                    node: r.get(1)?,
                    vcpus: r.get::<_, f64>(2)? as f32,
                    memory_mib: r.get::<_, i64>(3)? as u64,
                    at_ms: r.get(4)?,
                    state: r.get(5)?,
                })
            })
            .optional()?)
    }

    /// Records why `run`'s box went where it did, or why it went nowhere (JSON: the request, the
    /// node, the ranking and the refusals): its latest decision, for `wicket why-here`.
    pub fn record_placement_decision(&self, run: &str, decision: &str, now_ms: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO placement_decisions (run, at_ms, decision) VALUES (?1, ?2, ?3)",
            params![run, now_ms, decision],
        )?;
        Ok(())
    }

    /// `run`'s latest placement decision: (when, JSON).
    pub fn placement_decision(&self, run: &str) -> Result<Option<(i64, String)>> {
        Ok(self
            .conn
            .query_row("SELECT at_ms, decision FROM placement_decisions WHERE run = ?1", params![run], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    }

    /// `run` waits for a node (#579 step 2's queue), asking for `request` (JSON, as placement reads
    /// it). Its place is when it first waited; each call is a heartbeat.
    pub fn wait_for_placement(&self, run: &str, request: &str, now_ms: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO placement_waits (run, at_ms, seen_ms, request) VALUES (?1, ?2, ?2, ?3)
             ON CONFLICT(run) DO UPDATE SET seen_ms = excluded.seen_ms, request = excluded.request",
            params![run, now_ms, request],
        )?;
        Ok(())
    }

    /// `run` waits no more: placed, given up, or ended.
    pub fn stop_waiting(&self, run: &str) -> Result<()> {
        self.conn.execute("DELETE FROM placement_waits WHERE run = ?1", params![run])?;
        Ok(())
    }

    /// The live waiters, oldest first: (run, when it first waited (ms), request). A waiter not seen
    /// for [`WAIT_SEEN_MS`] is left out. Which go ahead of a run is the scheduler's
    /// (`wicket-placement::schedule::ahead`: by priority, then first come, first served).
    pub fn live_waiters(&self, now_ms: i64) -> Result<Vec<(String, i64, String)>> {
        let mut st = self.conn.prepare("SELECT run, at_ms, request FROM placement_waits WHERE seen_ms > ?1 ORDER BY at_ms, run")?;
        let rows = st.query_map(params![now_ms - WAIT_SEEN_MS], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Records the terms `run`'s box started with (#579 step 4): its limits as requests, its
    /// priority, and whether it may be preempted. Recorded for every box at its start.
    pub fn record_run_terms(&self, run: &str, vcpus: f32, memory_mib: u64, priority: i32, preemptible: bool, now_ms: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO run_terms (run, vcpus, memory_mib, priority, preemptible, at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![run, vcpus as f64, memory_mib as i64, priority, preemptible, now_ms],
        )?;
        Ok(())
    }

    /// Every running box placed on a node with its recorded terms: what preemption may choose from.
    /// A box without terms (started before they were recorded) is left out: it is never preempted.
    pub fn preemption_view(&self) -> Result<Vec<BoxTerms>> {
        let mut st = self.conn.prepare(
            "SELECT r.id, r.node, r.tenant, t.vcpus, t.memory_mib, t.priority, t.preemptible, v.run IS NOT NULL
             FROM runs r JOIN run_terms t ON t.run = r.id LEFT JOIN revocations v ON v.run = r.id
             WHERE r.status = 'running' AND r.node IS NOT NULL ORDER BY r.node, r.id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(BoxTerms {
                run: r.get(0)?,
                node: r.get(1)?,
                tenant: r.get(2)?,
                vcpus: r.get::<_, f64>(3)? as f32,
                memory_mib: r.get::<_, i64>(4)?.max(0) as u64,
                priority: r.get(5)?,
                preemptible: r.get(6)?,
                revoked: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Every running run placed on a node: what affinity sees on each (#579 step 4).
    pub fn running_boxes(&self) -> Result<Vec<RunningBox>> {
        let mut st = self.conn.prepare(
            "SELECT r.id, r.node, r.tenant, r.zone, i.spiffe_id FROM runs r LEFT JOIN identities i ON i.run = r.id
             WHERE r.status = 'running' AND r.node IS NOT NULL ORDER BY r.node, r.id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(RunningBox { run: r.get(0)?, node: r.get(1)?, tenant: r.get(2)?, zone: r.get(3)?, principal: r.get(4)? })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The nodes that ran a box of `tenant`'s `zone`, by name: where its kept volumes are (#377: a
    /// kept volume is the zone's, on the node, until its retention deletes it).
    pub fn nodes_that_ran(&self, tenant: &str, zone: &str) -> Result<Vec<String>> {
        let mut st =
            self.conn.prepare("SELECT DISTINCT node FROM runs WHERE tenant = ?1 AND zone = ?2 AND node IS NOT NULL ORDER BY node")?;
        let rows = st.query_map(params![tenant, zone], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Deletes reservations settled (bound or released) over a day before `now` (s): what each
    /// reconcile pass's upkeep drops (#582), so the table holds the boxes being started.
    pub fn drop_settled_placements(&self, now: i64) -> Result<usize> {
        let cutoff = (now - 86_400) * 1000;
        let mut n = self.conn.execute("DELETE FROM placements WHERE state != 'reserved' AND at_ms < ?1", params![cutoff])?;
        // A box's terms go with it: once its run has ended (a day ago, as for reservations).
        n += self.conn.execute(
            "DELETE FROM run_terms WHERE at_ms < ?1 AND run NOT IN (SELECT id FROM runs WHERE status = 'running')",
            params![cutoff],
        )?;
        // Decisions are kept with their run: a week, as #582's archive keeps its settled rows.
        let week = (now - crate::ARCHIVE_AFTER_SECS) * 1000;
        Ok(n + self.conn.execute("DELETE FROM placement_decisions WHERE at_ms < ?1", params![week])?)
    }

    /// What reservations hold on `node` beyond its report received at `report_at_ms`: (vCPUs, MiB).
    /// See the module's doc for which count.
    pub fn held_on(&self, node: &str, report_at_ms: i64, now_ms: i64) -> Result<(f32, u64)> {
        let (cpu, mib): (f64, i64) = self.conn.query_row(
            "SELECT COALESCE(SUM(vcpus), 0), COALESCE(SUM(memory_mib), 0) FROM placements
             WHERE node = ?1 AND ((state = 'reserved' AND at_ms > ?3) OR (state = 'bound' AND bound_at_ms > ?2))",
            params![node, report_at_ms, now_ms - RESERVE_SECS * 1000],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((cpu as f32, mib.max(0) as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reservation_holds_room_until_the_nodes_report_counts_its_box() {
        let l = Ledger::open_in_memory().unwrap();
        let t = 1_000_000;
        l.reserve_placement("run_a", "n1", 1.0, 1024, t).unwrap();
        l.reserve_placement("run_b", "n1", 0.5, 512, t + 1).unwrap();
        l.reserve_placement("run_c", "n2", 2.0, 2048, t).unwrap();
        assert_eq!(l.held_on("n1", t - 1, t + 2).unwrap(), (1.5, 1536), "both, made after the report");
        assert_eq!(l.held_on("n1", t - 1, t + RESERVE_SECS * 1000 + 1).unwrap(), (0.0, 0), "unconfirmed past its time: ignored");
        // run_a started; a report received before that doesn't count it, one after does.
        assert!(l.placement_bound("run_a", t + 10).unwrap());
        assert!(!l.placement_bound("run_a", t + 11).unwrap(), "once");
        assert_eq!(l.held_on("n1", t + 5, t + 20).unwrap(), (1.5, 1536));
        assert_eq!(l.held_on("n1", t + 10, t + 20).unwrap(), (0.5, 512), "the report at its start counts it");
        assert!(l.placement_released("run_b").unwrap());
        assert_eq!(l.held_on("n1", t - 1, t + 20).unwrap(), (1.0, 1024));
        assert_eq!(l.placement("run_b").unwrap().unwrap().state, "released");
        assert_eq!(l.held_on("n2", t - 1, t + 20).unwrap(), (2.0, 2048), "per node");
    }

    #[test]
    fn waiters_keep_their_place_while_they_are_seen() {
        let l = Ledger::open_in_memory().unwrap();
        let t = 1_000_000;
        l.wait_for_placement("run_a", "{}", t).unwrap();
        l.wait_for_placement("run_b", "{\"b\":1}", t + 1).unwrap();
        l.wait_for_placement("run_a", "{\"a\":2}", t + 5).unwrap(); // a heartbeat keeps its place
        let names = |v: Vec<(String, i64, String)>| v.into_iter().map(|(r, _, _)| r).collect::<Vec<_>>();
        assert_eq!(names(l.live_waiters(t + 6).unwrap()), ["run_a", "run_b"]);
        assert_eq!(l.live_waiters(t + 6).unwrap()[0], ("run_a".into(), t, "{\"a\":2}".into()), "its first wait, its latest request");
        // run_a's process went: not seen for WAIT_SEEN_MS, it holds no place; run_b, seen since, does.
        l.wait_for_placement("run_b", "{\"b\":1}", t + 6).unwrap();
        assert_eq!(names(l.live_waiters(t + 5 + WAIT_SEEN_MS).unwrap()), ["run_b"]);
        l.stop_waiting("run_b").unwrap();
        assert_eq!(names(l.live_waiters(t + 6).unwrap()), ["run_a"]);
    }

    #[test]
    fn preemption_sees_running_boxes_with_their_terms() {
        let l = Ledger::open_in_memory().unwrap();
        let t = wicket_core::TenantId("t0".into());
        for (run, node) in [("r1", "n1"), ("r2", "n1"), ("r3", "n2"), ("r4", "n2")] {
            l.run_started(&t, &wicket_core::RunId(run.into()), "z", "a").unwrap();
            l.set_run_node(run, node).unwrap();
        }
        l.record_run_terms("r1", 1.0, 1024, -1, true, 1).unwrap();
        l.record_run_terms("r2", 0.5, 512, 3, false, 1).unwrap();
        l.record_run_terms("r3", 2.0, 2048, 0, true, 1).unwrap();
        // r4 has no terms (started before they were recorded): never a candidate.
        l.revoke("r3", "x", "y").unwrap();
        let v = l.preemption_view().unwrap();
        assert_eq!(v.iter().map(|b| b.run.as_str()).collect::<Vec<_>>(), ["r1", "r2", "r3"]);
        assert_eq!(
            v[0],
            BoxTerms {
                run: "r1".into(),
                node: "n1".into(),
                tenant: "t0".into(),
                vcpus: 1.0,
                memory_mib: 1024,
                priority: -1,
                preemptible: true,
                revoked: false
            }
        );
        assert!(!v[1].preemptible && v[2].revoked);
        l.run_ended(&wicket_core::RunId("r1".into()), "done", "").unwrap();
        assert_eq!(l.preemption_view().unwrap().len(), 2, "running only");
        // Settled a day on, an ended run's terms go; a running one's stay.
        l.drop_settled_placements(1 + 86_400 + 1).unwrap();
        let left: i64 = l.conn.query_row("SELECT count(*) FROM run_terms", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 2);
    }

    #[test]
    fn what_runs_where() {
        let l = Ledger::open_in_memory().unwrap();
        let t = wicket_core::TenantId("t0".into());
        for (run, zone, node) in [("r1", "z1", Some("n1")), ("r2", "z2", Some("n1")), ("r3", "z1", Some("n2")), ("r4", "z1", None)] {
            l.run_started(&t, &wicket_core::RunId(run.into()), zone, "a").unwrap();
            if let Some(n) = node {
                l.set_run_node(run, n).unwrap();
            }
        }
        l.run_ended(&wicket_core::RunId("r3".into()), "done", "").unwrap();
        let on: Vec<(String, String, String)> = l.running_boxes().unwrap().into_iter().map(|b| (b.run, b.node, b.zone)).collect();
        assert_eq!(on, [("r1".into(), "n1".into(), "z1".into()), ("r2".into(), "n1".into(), "z2".into())], "running and placed only");
        assert_eq!(l.nodes_that_ran("t0", "z1").unwrap(), ["n1", "n2"], "ended runs too");
        assert!(l.nodes_that_ran("t1", "z1").unwrap().is_empty(), "per tenant");
    }

    #[test]
    fn a_runs_latest_placement_decision_is_kept_a_week() {
        let l = Ledger::open_in_memory().unwrap();
        let now = crate::now();
        l.record_placement_decision("run_a", r#"{"node":null}"#, now * 1000).unwrap();
        l.record_placement_decision("run_a", r#"{"node":"n1"}"#, now * 1000 + 1).unwrap();
        assert_eq!(l.placement_decision("run_a").unwrap().unwrap().1, r#"{"node":"n1"}"#, "the latest");
        assert!(l.placement_decision("run_b").unwrap().is_none());
        l.drop_settled_placements(now + 3600).unwrap();
        assert!(l.placement_decision("run_a").unwrap().is_some());
        l.drop_settled_placements(now + crate::ARCHIVE_AFTER_SECS + 1).unwrap();
        assert!(l.placement_decision("run_a").unwrap().is_none());
    }

    #[test]
    fn immediate_commits_on_ok_and_rolls_back_on_err() {
        let l = Ledger::open_in_memory().unwrap();
        l.immediate::<_, crate::StoreError>(|l| l.reserve_placement("run_a", "n1", 1.0, 1, 1)).unwrap();
        let r: std::result::Result<(), crate::StoreError> = l.immediate(|l| {
            l.reserve_placement("run_b", "n1", 1.0, 1, 1)?;
            Err(crate::StoreError::Node("n1".into(), "refused"))
        });
        assert!(r.is_err());
        assert!(l.placement("run_a").unwrap().is_some() && l.placement("run_b").unwrap().is_none());
    }
}
