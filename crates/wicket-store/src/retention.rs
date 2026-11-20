//! Audit log retention on the host (#582): the `audit` table pruned from the front, never past a
//! checkpoint a durable sink acknowledged, so the chain still verifies from there.
//!
//! - **`audit_checkpoints`:** the signed checkpoints sinks acknowledged: the sink, the seq and head
//!   hash it covers, when, and its JWS. What a prune may cut back to.
//! - **`audit_anchor`:** the checkpoint the local chain now starts from, once anything was pruned.
//!   It is set before anything is deleted, so a prune cut short (deleting in chunks) still
//!   verifies: `verify_audit` reads from the anchor's record on.
//! - **`audit_sink_targets`:** what each sink's cursor was made against (its path, endpoint or
//!   bucket), so a sink renamed onto another target, or another target given an old name, starts
//!   again rather than inheriting a cursor for records that target never got.
//! - **`audit_checkpoint_wants`:** seqs retention wants a checkpoint at: checkpoints are otherwise
//!   made at a sink's cursor (near the head), and a prune may only cut back to one.
//!
//! Whether to prune (a durable sink, the state store streaming, how big the table may grow) is the
//! caller's (`wicket_home::audit_export::retention_with`); this module holds the rules every prune
//! keeps to.

use crate::{now, Ledger, Result, StoreError};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use wicket_core::TenantId;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_checkpoints (
  sink TEXT NOT NULL, seq INTEGER NOT NULL, head TEXT NOT NULL, ts INTEGER NOT NULL, jws TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '', PRIMARY KEY (sink, seq)
);
CREATE TABLE IF NOT EXISTS audit_anchor (
  id INTEGER PRIMARY KEY CHECK (id = 1), seq INTEGER NOT NULL, hash TEXT NOT NULL, jws TEXT NOT NULL, sink TEXT NOT NULL,
  pruned_at INTEGER NOT NULL, pruned INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_sink_targets (sink TEXT PRIMARY KEY, target TEXT NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_checkpoint_wants (seq INTEGER PRIMARY KEY, created_at INTEGER NOT NULL);
"#;

/// Record kinds the host reads for itself, kept on the host when older records are pruned: a
/// run's Remote Control session (its page and the console read it) and restores (what
/// `verify --against` reads to tell discarded history from tampering). Not chained below the
/// anchor once kept: they are in the sinks whole, and the chain from the anchor is verified.
pub const KEPT_KINDS: &[&str] = &["run.remote_session", "state.restored"];

/// The schema a pruned ledger needs: a build before it walks the chain from seq 1.
pub const PRUNED_FLOOR: i64 = 32;

/// How many checkpoints of each sink are kept (the newest).
const CHECKPOINTS_KEPT: i64 = 500;

/// A checkpoint a sink acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checkpoint {
    pub sink: String,
    /// What the sink delivered it to (`SinkSpec::target`): a checkpoint counts only while the sink
    /// still points there.
    pub target: String,
    pub seq: i64,
    pub head: String,
    pub ts: i64,
    pub jws: String,
}

/// Where the local chain starts after a prune.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Anchor {
    /// The checkpoint's seq: the first record of the chain kept.
    pub seq: i64,
    /// Its record's hash, as the checkpoint signed it.
    pub hash: String,
    pub jws: String,
    /// The sink whose acknowledgement it was.
    pub sink: String,
    /// When the last prune was, and how many records all prunes deleted.
    pub pruned_at: i64,
    pub pruned: i64,
}

/// How big the audit table is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AuditUsage {
    /// The first record of the chain (the anchor's, after a prune) and the last (0 when empty).
    pub first: i64,
    pub head: i64,
    /// Records of the chain, from the seqs (the table is append-only and pruned from the front),
    /// and their estimated size: the count times the mean size of the newest records' fields (in
    /// bytes, with SQLite's per-row overhead). Cheap at any size; the indexes aren't counted (see
    /// [`Ledger::file_bytes`] for the file).
    pub rows: i64,
    pub bytes: i64,
}

/// How many recent records the size estimate samples.
const SAMPLE: i64 = 2000;
/// Per-row bytes beyond the fields: the row header, the seq and the b-tree's cell.
const ROW_OVERHEAD: i64 = 24;

impl Ledger {
    /// Records that `sink` acknowledged a checkpoint of the chain at `seq` (head `head`), keeping
    /// the sink's newest [`CHECKPOINTS_KEPT`].
    pub fn record_checkpoint(&self, sink: &str, target: &str, seq: i64, head: &str, ts: i64, jws: &str) -> Result<bool> {
        // Only for the sink's current target: one an exporter delivered to a target since
        // replaced counts for nothing (#582).
        let n = self.conn.execute(
            "INSERT OR REPLACE INTO audit_checkpoints (sink, seq, head, ts, jws, target)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6 WHERE EXISTS (SELECT 1 FROM audit_sink_targets t WHERE t.sink = ?1 AND t.target = ?6)",
            params![sink, seq, head, ts, jws, target],
        )?;
        if n == 0 {
            return Ok(false);
        }
        self.conn.execute(
            "DELETE FROM audit_checkpoints WHERE sink = ?1 AND seq NOT IN (SELECT seq FROM audit_checkpoints WHERE sink = ?1 ORDER BY seq DESC LIMIT ?2)",
            params![sink, CHECKPOINTS_KEPT],
        )?;
        Ok(true)
    }

    /// The checkpoints recorded, newest first.
    pub fn checkpoints(&self) -> Result<Vec<Checkpoint>> {
        let mut st = self.conn.prepare("SELECT sink, seq, head, ts, jws, target FROM audit_checkpoints ORDER BY seq DESC, sink")?;
        let rows = st.query_map([], |r| {
            Ok(Checkpoint { sink: r.get(0)?, seq: r.get(1)?, head: r.get(2)?, ts: r.get(3)?, jws: r.get(4)?, target: r.get(5)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Whether `sink` has acknowledged a checkpoint at `seq` while pointed at `target`.
    pub fn has_checkpoint(&self, sink: &str, target: &str, seq: i64) -> Result<bool> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM audit_checkpoints WHERE sink = ?1 AND seq = ?2 AND target = ?3", params![sink, seq, target], |_| {
                Ok(())
            })
            .optional()?
            .is_some())
    }

    /// Notes that `sink`'s cursor is for `target`. If the sink's cursor was made against another
    /// target (or before targets were recorded), it starts again from 0 and its checkpoints are
    /// forgotten; on any change its lease is given up, so an exporter for the old target (another
    /// process, started with the configuration before) stops feeding it. Whether it started again.
    pub fn sink_target(&self, sink: &str, target: &str) -> Result<bool> {
        self.immediate::<_, StoreError>(|l| {
            let was: Option<String> =
                l.conn.query_row("SELECT target FROM audit_sink_targets WHERE sink = ?1", params![sink], |r| r.get(0)).optional()?;
            let had_cursor = l.peek_export_cursor(sink)?.seq > 0;
            // A sink kept before targets were isn't trusted: what its cursor counts may have gone
            // anywhere, so it starts again too (at least once: a copy may get records twice).
            let moved = was.as_deref() != Some(target);
            if moved && had_cursor {
                l.ensure_export_row(sink)?;
                let why = match was.as_deref() {
                    Some(w) => format!("its target changed (was {w}): exporting from the start"),
                    None => "its cursor was kept before sinks' targets were: exporting from the start".to_string(),
                };
                l.conn.execute("UPDATE audit_export SET seq = 0, checkpoint_at = 0, error = ?2 WHERE sink = ?1", params![sink, why])?;
                l.conn.execute("DELETE FROM audit_checkpoints WHERE sink = ?1", params![sink])?;
            }
            if moved {
                // Whoever fed the old target stops now, and an exporter for this one takes over.
                l.conn.execute("UPDATE audit_export SET holder = NULL, lease_until = 0 WHERE sink = ?1", params![sink])?;
            }
            l.conn.execute(
                "INSERT INTO audit_sink_targets (sink, target, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT (sink) DO UPDATE SET target = excluded.target, updated_at = excluded.updated_at",
                params![sink, target, now()],
            )?;
            Ok(moved && had_cursor)
        })
    }

    /// Asks for a checkpoint at `seq`, which the exporter signs for each sink once its cursor is
    /// past it.
    pub fn want_checkpoint(&self, seq: i64) -> Result<()> {
        // One at a time: the newest cut asked for replaces any older.
        self.conn.execute("DELETE FROM audit_checkpoint_wants WHERE seq != ?1", params![seq])?;
        self.conn.execute("INSERT OR IGNORE INTO audit_checkpoint_wants (seq, created_at) VALUES (?1, ?2)", params![seq, now()])?;
        Ok(())
    }

    /// The target `sink`'s cursor was last kept for, if any.
    pub fn sink_target_of(&self, sink: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT target FROM audit_sink_targets WHERE sink = ?1", params![sink], |r| r.get(0)).optional()?)
    }

    /// The checkpoints asked for, oldest first.
    pub fn checkpoint_wants(&self) -> Result<Vec<i64>> {
        let mut st = self.conn.prepare("SELECT seq FROM audit_checkpoint_wants ORDER BY seq")?;
        let rows = st.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Where the chain starts, if anything was pruned.
    pub fn audit_anchor(&self) -> Result<Option<Anchor>> {
        Ok(self
            .conn
            .query_row("SELECT seq, hash, jws, sink, pruned_at, pruned FROM audit_anchor WHERE id = 1", [], |r| {
                Ok(Anchor { seq: r.get(0)?, hash: r.get(1)?, jws: r.get(2)?, sink: r.get(3)?, pruned_at: r.get(4)?, pruned: r.get(5)? })
            })
            .optional()?)
    }

    /// The audit table's size, estimated (see [`AuditUsage`]).
    pub fn audit_usage(&self) -> Result<AuditUsage> {
        let anchor = self.audit_anchor()?.map(|a| a.seq).unwrap_or(0);
        let head: i64 = self.conn.query_row("SELECT COALESCE(MAX(seq), 0) FROM audit", [], |r| r.get(0))?;
        let first: i64 = if head == 0 {
            0
        } else if anchor > 0 {
            anchor
        } else {
            self.conn.query_row("SELECT COALESCE(MIN(seq), 0) FROM audit", [], |r| r.get(0))?
        };
        let rows = if head == 0 { 0 } else { head - first + 1 };
        let mean: f64 = self.conn.query_row(
            "SELECT COALESCE(AVG(length(CAST(body AS BLOB)) + length(CAST(kind AS BLOB)) + length(CAST(tenant AS BLOB))
                 + COALESCE(length(CAST(run AS BLOB)), 0) + length(prev) + length(hash) + 8), 0)
             FROM (SELECT * FROM audit ORDER BY seq DESC LIMIT ?1)",
            params![SAMPLE],
            |r| r.get(0),
        )?;
        let bytes = (rows as f64 * (mean + ROW_OVERHEAD as f64)) as i64;
        Ok(AuditUsage { first, head, rows, bytes })
    }

    /// The checkpoint a prune may cut back to, for a cut wanted at or before `target`: the newest
    /// checkpoint, at or below `target`, some sink in `sinks` acknowledged, that every sink in
    /// `sinks` has exported past, that the state store had replicated (made no later than
    /// `synced_ms`), that no trigger is still to read past (#578's cursor), and past the current
    /// anchor. None if there is none: never one above `target`, so a prune never cuts deeper than
    /// asked.
    pub fn prune_point(&self, sinks: &[(&str, &str)], target: i64, synced_ms: i64) -> Result<Option<Checkpoint>> {
        if sinks.is_empty() {
            return Ok(None);
        }
        let mut limit = target;
        for (s, t) in sinks {
            // A sink pointed elsewhere since its cursor was kept counts for nothing until the
            // exporter has started it again (#582 re-review).
            if self.sink_target_of(s)?.as_deref() != Some(*t) {
                return Ok(None);
            }
            limit = limit.min(self.peek_export_cursor(s)?.seq);
        }
        // Wicket's own events (#578): what a trigger hasn't read yet stays.
        let has_triggers: bool =
            self.conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'trigger_cursors'", [], |r| {
                r.get::<_, i64>(0)
            })? > 0;
        if has_triggers {
            if let Some(c) = self.conn.query_row("SELECT MIN(seq) FROM trigger_cursors", [], |r| r.get::<_, Option<i64>>(0))? {
                limit = limit.min(c);
            }
        }
        let floor = self.audit_anchor()?.map(|a| a.seq).unwrap_or(0);
        Ok(self.checkpoints()?.into_iter().find(|c| {
            sinks.iter().any(|(s, t)| *s == c.sink && *t == c.target)
                && c.seq <= limit
                && c.seq > floor
                && c.ts.saturating_mul(1000) <= synced_ms
        }))
    }

    /// [`Ledger::prune_point`] and [`Ledger::begin_prune`] in one transaction, so nothing the check
    /// read (cursors, targets, checkpoints) changes between them. The checkpoint pruned to.
    pub fn begin_prune_at(&self, sinks: &[(&str, &str)], target: i64, synced_ms: i64) -> Result<Option<Checkpoint>> {
        self.immediate::<_, StoreError>(|l| {
            let Some(cp) = l.prune_point(sinks, target, synced_ms)? else { return Ok(None) };
            l.begin_prune_in(&cp)?;
            Ok(Some(cp))
        })
    }

    /// Starts a prune to `cp`: in one transaction, `cp` becomes the anchor (refused if the record at
    /// `cp.seq` isn't the one it signed), an `audit.pruned` record says what goes, and the
    /// schema floor rises to [`PRUNED_FLOOR`]. Nothing is deleted yet: [`Ledger::prune_chunk`] does
    /// that, a chunk at a time, and the chain verifies from the anchor throughout.
    pub fn begin_prune(&self, cp: &Checkpoint) -> Result<()> {
        self.immediate::<_, StoreError>(|l| l.begin_prune_in(cp))
    }

    /// [`Ledger::begin_prune`] inside the caller's transaction.
    fn begin_prune_in(&self, cp: &Checkpoint) -> Result<()> {
        let l = self;
        {
            let at: Option<String> = l.conn.query_row("SELECT hash FROM audit WHERE seq = ?1", params![cp.seq], |r| r.get(0)).optional()?;
            if at.as_deref() != Some(cp.head.as_str()) {
                return Err(StoreError::Refused(format!(
                    "checkpoint {} of sink {}: the local record there isn't the one it signed",
                    cp.seq, cp.sink
                )));
            }
            let from: i64 = l.conn.query_row("SELECT COALESCE(MIN(seq), 0) FROM audit", [], |r| r.get(0))?;
            // The restores kept below the cut, by seq and hash: below the anchor nothing chains
            // them, so this (chained) record is what vouches for them (`trusted_restores`).
            // Only those the chain vouches for now, by the anchor before this one: one forged below
            // that, which nothing chains, isn't listed and so isn't laundered by this prune.
            let restored: Vec<(i64, String)> =
                l.trusted_restores()?.into_iter().filter(|r| r.seq < cp.seq).map(|r| (r.seq, r.hash)).collect();
            l.conn.execute(
                "INSERT INTO audit_anchor (id, seq, hash, jws, sink, pruned_at, pruned) VALUES (1, ?1, ?2, ?3, ?4, ?5, 0)
                 ON CONFLICT (id) DO UPDATE SET seq = ?1, hash = ?2, jws = ?3, sink = ?4, pruned_at = ?5",
                params![cp.seq, cp.head, cp.jws, cp.sink, now()],
            )?;
            l.conn.execute("UPDATE schema_meta SET value = MAX(value, ?1) WHERE key = 'floor'", params![PRUNED_FLOOR])?;
            l.audit(
                &TenantId::single(),
                None,
                "audit.pruned",
                &serde_json::json!({ "from": from, "before": cp.seq, "checkpoint": cp.seq, "head": cp.head, "sink": cp.sink, "kept_kinds": KEPT_KINDS, "kept_restores": restored }),
            )?;
            l.conn.execute("DELETE FROM audit_checkpoints WHERE seq < ?1", params![cp.seq])?;
            l.conn.execute("DELETE FROM audit_checkpoint_wants WHERE seq <= ?1", params![cp.seq])?;
            Ok(())
        }
    }

    /// The `state.restored` records the chain vouches for: those from the anchor on that are chained
    /// (their fields hash to their hash, and the next record's `prev` is it), and those kept below
    /// it that the newest `audit.pruned` record lists by seq and hash and whose own fields still
    /// hash to it. One inserted or changed below the anchor isn't among them, nor one inserted out
    /// of the chain above it.
    pub fn trusted_restores(&self) -> Result<Vec<crate::AuditRecord>> {
        let anchor = self.audit_anchor()?.map(|a| a.seq).unwrap_or(0);
        let all = self.audit_of_kind("state.restored")?;
        let listed: Vec<(i64, String)> = match anchor {
            0 => vec![],
            _ => self
                .audit_of_kind("audit.pruned")?
                .iter()
                .rfind(|r| r.seq >= anchor)
                .and_then(|r| serde_json::from_str::<serde_json::Value>(&r.body).ok())
                .and_then(|v| serde_json::from_value(v["kept_restores"].clone()).ok())
                .unwrap_or_default(),
        };
        let own_hash = |r: &crate::AuditRecord| {
            crate::chain_hash_v2(
                &r.prev,
                &crate::ChainFields { seq: r.seq, ts: r.ts, tenant: &r.tenant, run: r.run.as_deref(), kind: &r.kind, body: &r.body },
            ) == r.hash
        };
        let mut out = vec![];
        for r in all {
            let ok = if r.seq >= anchor {
                let next: Option<String> = self
                    .conn
                    .query_row("SELECT prev FROM audit WHERE seq > ?1 ORDER BY seq LIMIT 1", params![r.seq], |x| x.get(0))
                    .optional()?;
                own_hash(&r) && next.is_none_or(|p| p == r.hash)
            } else {
                listed.iter().any(|(s, h)| *s == r.seq && *h == r.hash) && own_hash(&r)
            };
            if ok {
                out.push(r);
            }
        }
        Ok(out)
    }

    /// Deletes up to `rows` audit records before the anchor (all but [`KEPT_KINDS`]), in one short
    /// transaction. The records deleted (0: done).
    pub fn prune_chunk(&self, rows: i64) -> Result<i64> {
        let Some(a) = self.audit_anchor()? else { return Ok(0) };
        let marks = KEPT_KINDS.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(", ");
        self.immediate::<_, StoreError>(|l| {
            let n = l.conn.execute(
                &format!(
                    "DELETE FROM audit WHERE seq IN (SELECT seq FROM audit WHERE seq < ?1 AND kind NOT IN ({marks}) ORDER BY seq LIMIT ?2)"
                ),
                params![a.seq, rows],
            )? as i64;
            l.conn.execute("UPDATE audit_anchor SET pruned = pruned + ?1 WHERE id = 1", params![n])?;
            Ok(n)
        })
    }

    /// Whether the file gives freed pages back (`auto_vacuum = incremental`).
    pub fn auto_vacuum_incremental(&self) -> Result<bool> {
        Ok(self.conn.query_row("PRAGMA auto_vacuum", [], |r| r.get::<_, i64>(0))? == 2)
    }

    /// Switches an existing ledger to `auto_vacuum = incremental`: a full `VACUUM`, which rewrites
    /// the whole file under an exclusive lock (about a minute per 2.5 GB, needing as much free
    /// space again, and as much WAL). Only for `wicket audit compact`, with wicket's services
    /// stopped: never during a reconcile pass. Whether it vacuumed (a no-op on a ledger already
    /// switched, as every new one is).
    pub fn make_auto_vacuum_incremental(&self) -> Result<bool> {
        if self.auto_vacuum_incremental()? {
            return Ok(false);
        }
        self.conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
        Ok(true)
    }

    /// [`Ledger::make_auto_vacuum_incremental`], but only if nothing else has the ledger: no busy
    /// wait (another connection's lock fails it at once), and an exclusive transaction taken and
    /// released first to prove it.
    pub fn compact_exclusively(&self) -> Result<bool> {
        self.conn.busy_timeout(std::time::Duration::ZERO)?;
        let r =
            self.conn.execute_batch("BEGIN EXCLUSIVE; COMMIT;").map_err(StoreError::from).and_then(|_| self.make_auto_vacuum_incremental());
        let _ = self.conn.busy_timeout(std::time::Duration::from_secs(5));
        r
    }

    /// Gives up to `pages` free pages back to the file system, in one short transaction (the
    /// pragma's rows stepped to completion: it frees a page per step). The pages freed; 0 when
    /// there are none, or the file isn't incremental.
    pub fn vacuum_step(&self, pages: i64) -> Result<i64> {
        if !self.auto_vacuum_incremental()? {
            return Ok(0);
        }
        let before: i64 = self.conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        {
            let mut st = self.conn.prepare(&format!("PRAGMA incremental_vacuum({})", pages.max(1)))?;
            let mut rows = st.query([])?;
            while rows.next()?.is_some() {}
        }
        let after: i64 = self.conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        Ok(before - after)
    }

    /// The ledger file's size in bytes, as SQLite counts it (pages in use and free).
    pub fn file_bytes(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()", [], |r| r.get(0))?)
    }

    /// The schema floor recorded, for tests.
    #[cfg(test)]
    fn floor_for_test(&self) -> i64 {
        self.conn.query_row("SELECT value FROM schema_meta WHERE key = 'floor'", [], |r| r.get(0)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(l: &Ledger, n: usize) {
        for i in 0..n {
            l.audit(&TenantId::single(), None, "op", &serde_json::json!({ "i": i, "pad": "x".repeat(200) })).unwrap();
        }
    }

    fn prune(l: &Ledger, cp: &Checkpoint) -> i64 {
        l.begin_prune(cp).unwrap();
        let mut n = 0;
        loop {
            let k = l.prune_chunk(7).unwrap();
            if k == 0 {
                return n;
            }
            n += k;
        }
    }

    /// A prune cuts back only to a checkpoint every sink has exported past, that the state store
    /// replicated, and never deeper than asked; it keeps the checkpoint's record as the anchor and
    /// the kinds the host reads, and the chain verifies from there, while it runs and after.
    #[test]
    fn a_prune_keeps_the_chain_verifiable() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 30);
        l.audit(&TenantId::single(), None, "run.remote_session", &serde_json::json!({ "url": "x" })).unwrap();
        chain(&l, 69);
        let hash = |s: i64| l.audit_hash_at(s).unwrap().unwrap();
        l.sink_target("a", "t").unwrap();
        l.sink_target("b", "t").unwrap();
        l.record_checkpoint("a", "t", 40, &hash(40), 1, "jws40").unwrap();
        l.record_checkpoint("a", "t", 70, &hash(70), 2, "jws70").unwrap();
        l.advance_export("a", "t", 80).unwrap();
        l.advance_export("b", "t", 50).unwrap();
        let far = i64::MAX;
        assert_eq!(l.prune_point(&[("a", "t")], 90, far).unwrap().map(|c| c.seq), Some(70));
        assert_eq!(l.prune_point(&[("a", "t"), ("b", "t")], 90, far).unwrap().map(|c| c.seq), Some(40), "b has only 50");
        assert_eq!(l.prune_point(&[("a", "t"), ("b", "t")], 30, far).unwrap(), None, "never deeper than asked");
        assert_eq!(l.prune_point(&[("a", "t")], 90, 1500).unwrap().map(|c| c.seq), Some(40), "the store had synced only the first");
        assert_eq!(l.prune_point(&[], 90, far).unwrap(), None, "no sink, no prune");
        let cp = l.begin_prune_at(&[("a", "t"), ("b", "t")], 90, far).unwrap().unwrap();
        assert_eq!(cp.seq, 40);
        assert_eq!(
            l.verify_audit().unwrap(),
            62,
            "verifies from the anchor (its record to the audit.pruned one) before anything is deleted"
        );
        assert_eq!(l.prune_chunk(5).unwrap(), 5);
        assert_eq!(l.verify_audit().unwrap(), 62, "and half-way");
        while l.prune_chunk(7).unwrap() > 0 {}
        let u = l.audit_usage().unwrap();
        assert_eq!((u.first, u.head, u.rows), (40, 101, 62), "the audit.pruned record is the last");
        assert_eq!(l.verify_audit().unwrap(), 62);
        let a = l.audit_anchor().unwrap().unwrap();
        assert_eq!((a.seq, a.pruned, a.jws.as_str()), (40, 38, "jws40"), "the remote session record kept");
        assert_eq!(l.audit_of_kind("run.remote_session").unwrap().len(), 1);
        assert_eq!(l.audit_of_kind("audit.pruned").unwrap().len(), 1);
        assert_eq!(l.floor_for_test(), PRUNED_FLOOR, "the floor rose");
        assert_eq!(l.prune_point(&[("a", "t"), ("b", "t")], 90, far).unwrap(), None, "nothing past the anchor b has");
    }

    /// A trigger that hasn't read past a record holds the prune before it (#578's cursor).
    #[test]
    fn a_lagging_trigger_cursor_holds_the_prune() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 50);
        l.sink_target("a", "t").unwrap();
        l.record_checkpoint("a", "t", 40, &l.audit_hash_at(40).unwrap().unwrap(), 1, "j").unwrap();
        l.record_checkpoint("a", "t", 20, &l.audit_hash_at(20).unwrap().unwrap(), 1, "j").unwrap();
        l.advance_export("a", "t", 50).unwrap();
        l.conn
            .execute_batch("CREATE TABLE IF NOT EXISTS trigger_cursors (tenant TEXT, source TEXT, seq INTEGER, updated_at INTEGER)")
            .unwrap();
        l.conn.execute("INSERT INTO trigger_cursors VALUES ('t0', 'wicket', 30, 0)", []).unwrap();
        assert_eq!(l.prune_point(&[("a", "t")], 45, i64::MAX).unwrap().map(|c| c.seq), Some(20));
    }

    /// A record changed under the anchor is caught; a checkpoint that doesn't match its record is
    /// refused; an anchor over an empty table doesn't verify.
    #[test]
    fn a_wrong_anchor_is_caught() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 10);
        let bad = Checkpoint { sink: "a".into(), target: "t".into(), seq: 5, head: "v2:nope".into(), ts: 0, jws: String::new() };
        assert!(l.begin_prune(&bad).is_err());
        assert_eq!(l.audit_usage().unwrap().rows, 10);
        let good = Checkpoint {
            sink: "a".into(),
            target: "t".into(),
            seq: 5,
            head: l.audit_hash_at(5).unwrap().unwrap(),
            ts: 0,
            jws: String::new(),
        };
        prune(&l, &good);
        l.conn.execute("UPDATE audit SET body = '{}' WHERE seq = 5", []).unwrap();
        assert!(matches!(l.verify_audit(), Err(StoreError::ChainBroken(5))));
        l.conn.execute("DELETE FROM audit", []).unwrap();
        assert!(l.verify_audit().is_err(), "an anchor over nothing");
    }

    /// #582 re-review N1: an anchor copied in from a saved checkpoint, the records before it
    /// deleted, doesn't verify: no `audit.pruned` record after it names it.
    #[test]
    fn a_copied_anchor_is_caught() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 20);
        let head = l.audit_hash_at(10).unwrap().unwrap();
        l.conn
            .execute(
                "INSERT INTO audit_anchor (id, seq, hash, jws, sink, pruned_at, pruned) VALUES (1, 10, ?1, 'j', 'a', 0, 9)",
                params![head],
            )
            .unwrap();
        l.conn.execute("DELETE FROM audit WHERE seq < 10", []).unwrap();
        assert!(matches!(l.verify_audit(), Err(StoreError::ChainBroken(10))), "{:?}", l.verify_audit());
        // A real prune names its anchor, and verifies.
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 20);
        let cp = Checkpoint {
            sink: "a".into(),
            target: "t".into(),
            seq: 10,
            head: l.audit_hash_at(10).unwrap().unwrap(),
            ts: 0,
            jws: String::new(),
        };
        prune(&l, &cp);
        assert!(l.verify_audit().is_ok());
    }

    /// #582 re-review N2: a sink pointed at another target since its cursor was kept, or whose
    /// checkpoint went to another target, allows no prune.
    #[test]
    fn a_retargeted_sink_allows_no_prune() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 50);
        l.sink_target("a", "jsonl:/a").unwrap();
        l.advance_export("a", "jsonl:/a", 50).unwrap();
        assert!(!l.record_checkpoint("a", "jsonl:/b", 40, &l.audit_hash_at(40).unwrap().unwrap(), 1, "j").unwrap(), "not its target");
        l.record_checkpoint("a", "jsonl:/a", 40, &l.audit_hash_at(40).unwrap().unwrap(), 1, "j").unwrap();
        assert_eq!(l.prune_point(&[("a", "jsonl:/a")], 45, i64::MAX).unwrap().map(|c| c.seq), Some(40));
        assert_eq!(l.prune_point(&[("a", "jsonl:/b")], 45, i64::MAX).unwrap(), None, "the sink now points elsewhere");
        assert!(l.begin_prune_at(&[("a", "jsonl:/b")], 45, i64::MAX).unwrap().is_none());
        assert!(l.audit_anchor().unwrap().is_none());
        // Only one checkpoint asked for at a time.
        l.want_checkpoint(10).unwrap();
        l.want_checkpoint(20).unwrap();
        assert_eq!(l.checkpoint_wants().unwrap(), [20]);
    }

    /// #677 third check: a restore kept below the anchor counts only as the audit.pruned record
    /// lists it (seq and hash, its fields still hashing to it); one inserted there, or changed,
    /// doesn't.
    #[test]
    fn only_vouched_restores_below_the_anchor_count() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 10);
        l.audit(&TenantId::single(), None, "state.restored", &serde_json::json!({ "rolled_back_after": 4 })).unwrap();
        chain(&l, 20);
        let at = |s: i64| Checkpoint {
            sink: "a".into(),
            target: "t".into(),
            seq: s,
            head: l.audit_hash_at(s).unwrap().unwrap(),
            ts: 0,
            jws: String::new(),
        };
        prune(&l, &at(25));
        let seqs = |l: &Ledger| l.trusted_restores().unwrap().iter().map(|r| r.seq).collect::<Vec<_>>();
        assert_eq!(seqs(&l), [11], "kept, and listed");
        // One forged below the anchor, where nothing chains it.
        let r = l.audit_record_at(11).unwrap().unwrap();
        l.conn
            .execute(
                "INSERT INTO audit (seq, ts, tenant, run, kind, body, prev, hash) VALUES (3, ?1, ?2, NULL, 'state.restored', ?3, ?4, ?5)",
                params![r.ts, r.tenant, r#"{"rolled_back_after":0}"#, r.prev, r.hash],
            )
            .unwrap();
        assert_eq!(seqs(&l), [11], "not listed at its seq");
        // The listed one changed in place.
        l.conn.execute("UPDATE audit SET body = '{\"rolled_back_after\":0}' WHERE seq = 11", []).unwrap();
        assert!(seqs(&l).is_empty(), "its fields no longer hash to what was listed");
    }

    /// #677 follow-up: a second prune lists only the restores the chain vouched for before it, so a
    /// forged one below the first anchor isn't laundered into the second's list.
    #[test]
    fn a_second_prune_doesnt_launder_a_forged_restore() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 10);
        l.audit(&TenantId::single(), None, "state.restored", &serde_json::json!({ "rolled_back_after": 4 })).unwrap();
        chain(&l, 20);
        let at = |l: &Ledger, s: i64| Checkpoint {
            sink: "a".into(),
            target: "t".into(),
            seq: s,
            head: l.audit_hash_at(s).unwrap().unwrap(),
            ts: 0,
            jws: String::new(),
        };
        prune(&l, &at(&l, 25));
        let seqs = |l: &Ledger| l.trusted_restores().unwrap().iter().map(|r| r.seq).collect::<Vec<_>>();
        // A restore forged below the first anchor, its own fields hashing as a real record's do.
        let r = l.audit_record_at(11).unwrap().unwrap();
        let body = r#"{"rolled_back_after":0}"#;
        let hash = crate::chain_hash_v2(
            &r.prev,
            &crate::ChainFields { seq: 3, ts: r.ts, tenant: &r.tenant, run: None, kind: "state.restored", body },
        );
        l.conn
            .execute(
                "INSERT INTO audit (seq, ts, tenant, run, kind, body, prev, hash) VALUES (3, ?1, ?2, NULL, 'state.restored', ?3, ?4, ?5)",
                params![r.ts, r.tenant, body, r.prev, hash],
            )
            .unwrap();
        assert_eq!(seqs(&l), [11], "not trusted after the first prune");
        chain(&l, 20);
        let head = l.audit_head().unwrap().unwrap().0;
        prune(&l, &at(&l, head - 5));
        assert_eq!(seqs(&l), [11], "nor after the second");
        let pruned = l.audit_of_kind("audit.pruned").unwrap();
        let listed = &serde_json::from_str::<serde_json::Value>(&pruned.last().unwrap().body).unwrap()["kept_restores"];
        assert_eq!(listed.as_array().unwrap().len(), 1, "{listed}");
        // One inserted above the anchor, out of the chain, isn't trusted either.
        let anchor = l.audit_anchor().unwrap().unwrap().seq;
        let tail = l.audit_record_at(anchor + 1).unwrap().unwrap();
        l.conn.execute("UPDATE audit SET kind = 'state.restored' WHERE seq = ?1", params![tail.seq]).unwrap();
        assert_eq!(seqs(&l), [11], "its fields don't hash to its hash");
    }

    /// A sink pointed at another target starts again, and its checkpoints are forgotten.
    #[test]
    fn a_sink_moved_to_another_target_starts_again() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 5);
        assert!(!l.sink_target("s", "jsonl:/a").unwrap());
        l.advance_export("s", "jsonl:/a", 5).unwrap();
        assert!(l.record_checkpoint("s", "jsonl:/a", 5, &l.audit_hash_at(5).unwrap().unwrap(), 1, "j").unwrap());
        assert!(!l.sink_target("s", "jsonl:/a").unwrap(), "the same target");
        assert!(l.sink_target("s", "jsonl:/b").unwrap());
        let c = l.peek_export_cursor("s").unwrap();
        assert_eq!(c.seq, 0);
        assert!(c.error.unwrap().contains("target changed"));
        assert!(l.checkpoints().unwrap().is_empty());
        // A cursor kept before targets were recorded isn't trusted either: it starts again.
        l.ensure_export_row("old").unwrap();
        l.conn.execute("UPDATE audit_export SET seq = 5 WHERE sink = 'old'", []).unwrap();
        assert!(l.sink_target("old", "jsonl:/a").unwrap());
        assert_eq!(l.peek_export_cursor("old").unwrap().seq, 0);
    }

    /// New ledgers give freed pages back, many a step; the step is bounded and does nothing on a
    /// file that isn't incremental.
    #[test]
    fn freed_pages_go_back() {
        let dir = std::env::temp_dir().join(format!("wicket-retention-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ledger.db");
        let _ = std::fs::remove_file(&path);
        let l = Ledger::open(&path).unwrap();
        assert!(l.auto_vacuum_incremental().unwrap(), "a new ledger is incremental");
        assert!(!l.make_auto_vacuum_incremental().unwrap());
        chain(&l, 2000);
        let cp = Checkpoint {
            sink: "a".into(),
            target: "t".into(),
            seq: 1900,
            head: l.audit_hash_at(1900).unwrap().unwrap(),
            ts: 0,
            jws: String::new(),
        };
        let big = l.file_bytes().unwrap();
        prune(&l, &cp);
        assert_eq!(l.vacuum_step(10).unwrap(), 10, "ten pages a step of ten, not one");
        let mut steps = 0;
        while l.vacuum_step(1000).unwrap() > 0 {
            steps += 1;
            assert!(steps < 100);
        }
        assert!(l.file_bytes().unwrap() < big / 2, "{} of {big}", l.file_bytes().unwrap());
        let mem = Ledger::open_in_memory().unwrap();
        assert_eq!(mem.vacuum_step(10).unwrap(), 0, "not incremental: nothing");
        // Compacting needs the ledger to itself: another connection's write fails it at once.
        let other = Ledger::open(&path).unwrap();
        other.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let t = std::time::Instant::now();
        assert!(l.compact_exclusively().is_err());
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "no busy wait");
        other.conn.execute_batch("ROLLBACK").unwrap();
        assert!(!l.compact_exclusively().unwrap(), "already incremental: nothing to do");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
