//! Audit log retention on the host (#582): the `audit` table pruned from the front, never past a
//! checkpoint a sink acknowledged, so the chain still verifies from there.
//!
//! - **`audit_checkpoints`:** every signed checkpoint a sink acknowledged: the sink, the seq and
//!   head hash it covers, and its JWS. What a prune may cut back to.
//! - **`audit_anchor`:** the checkpoint the local chain now starts from, once anything was pruned:
//!   its record is kept, the ones before it deleted. `verify_audit` starts there, checking the
//!   record's hash against the anchor's, and the CLI checks the anchor's signature.
//!
//! Whether to prune (a sink and the state store configured, and how big the table may grow) is the
//! caller's decision (`wicket_home::audit_export::retention_pass`); this module only keeps the
//! rules every prune holds to: never past the newest record every sink has, never to a seq that
//! isn't a recorded checkpoint, and the anchor's record kept.

use crate::{now, Ledger, Result, StoreError};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_checkpoints (
  sink TEXT NOT NULL, seq INTEGER NOT NULL, head TEXT NOT NULL, ts INTEGER NOT NULL, jws TEXT NOT NULL, PRIMARY KEY (sink, seq)
);
CREATE TABLE IF NOT EXISTS audit_anchor (
  id INTEGER PRIMARY KEY CHECK (id = 1), seq INTEGER NOT NULL, hash TEXT NOT NULL, jws TEXT NOT NULL, sink TEXT NOT NULL,
  pruned_at INTEGER NOT NULL, pruned INTEGER NOT NULL
);
"#;

/// A checkpoint a sink acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checkpoint {
    pub sink: String,
    pub seq: i64,
    pub head: String,
    pub ts: i64,
    pub jws: String,
}

/// Where the local chain starts after a prune.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Anchor {
    /// The checkpoint's seq: the first record kept.
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
    /// The first and last records' seqs (0 when empty).
    pub first: i64,
    pub head: i64,
    /// Records kept, and their estimated size on disk: the count times the mean size of the
    /// newest records' fields (with SQLite's per-row overhead), which is cheap at any size.
    pub rows: i64,
    pub bytes: i64,
}

/// How many recent records the size estimate samples.
const SAMPLE: i64 = 2000;
/// Per-row bytes beyond the fields: the row header, the seq and the b-tree's cell.
const ROW_OVERHEAD: i64 = 24;

impl Ledger {
    /// Records that `sink` acknowledged a checkpoint of the chain at `seq` (head `head`).
    pub fn record_checkpoint(&self, sink: &str, seq: i64, head: &str, ts: i64, jws: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO audit_checkpoints (sink, seq, head, ts, jws) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![sink, seq, head, ts, jws],
        )?;
        Ok(())
    }

    /// The checkpoints recorded, newest first.
    pub fn checkpoints(&self) -> Result<Vec<Checkpoint>> {
        let mut st = self.conn.prepare("SELECT sink, seq, head, ts, jws FROM audit_checkpoints ORDER BY seq DESC, sink")?;
        let rows =
            st.query_map([], |r| Ok(Checkpoint { sink: r.get(0)?, seq: r.get(1)?, head: r.get(2)?, ts: r.get(3)?, jws: r.get(4)? }))?;
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
        let (first, head, rows): (i64, i64, i64) =
            self.conn.query_row("SELECT COALESCE(MIN(seq), 0), COALESCE(MAX(seq), 0), COUNT(*) FROM audit", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?;
        let mean: f64 = self.conn.query_row(
            "SELECT COALESCE(AVG(length(body) + length(kind) + length(tenant) + COALESCE(length(run), 0) + length(prev) + length(hash) + 8), 0)
             FROM (SELECT * FROM audit ORDER BY seq DESC LIMIT ?1)",
            params![SAMPLE],
            |r| r.get(0),
        )?;
        let bytes = (rows as f64 * (mean + ROW_OVERHEAD as f64)) as i64;
        Ok(AuditUsage { first, head, rows, bytes })
    }

    /// The checkpoint a prune may cut back to, for a cut wanted at `target`: of the checkpoints
    /// some sink in `sinks` acknowledged that every sink in `sinks` has exported past (its records
    /// acknowledged) and that are past the current anchor, the newest at or below `target`, or
    /// failing that the oldest above it (checkpoints are made at a sink's cursor, so the first may
    /// be newer than the cut: pruning a little more is still only records every sink has). None
    /// if there is none.
    pub fn prune_point(&self, sinks: &[&str], target: i64) -> Result<Option<Checkpoint>> {
        if sinks.is_empty() {
            return Ok(None);
        }
        let mut exported = i64::MAX;
        for s in sinks {
            exported = exported.min(self.export_cursor(s)?.seq);
        }
        let floor = self.audit_anchor()?.map(|a| a.seq).unwrap_or(0);
        let ok: Vec<Checkpoint> =
            self.checkpoints()?.into_iter().filter(|c| sinks.contains(&c.sink.as_str()) && c.seq <= exported && c.seq > floor).collect();
        // Newest first: the first at or below the target, else the last (oldest) above it.
        Ok(ok.iter().find(|c| c.seq <= target).cloned().or_else(|| ok.last().cloned()))
    }

    /// Deletes every audit record before `cp`'s, which becomes the chain's anchor (its record is
    /// kept). Refused if the record at `cp.seq` isn't the one the checkpoint signed. Checkpoints
    /// before it go too. The records deleted.
    pub fn prune_audit_to(&self, cp: &Checkpoint) -> Result<i64> {
        self.immediate::<_, StoreError>(|l| {
            let at: Option<String> = l.conn.query_row("SELECT hash FROM audit WHERE seq = ?1", params![cp.seq], |r| r.get(0)).optional()?;
            if at.as_deref() != Some(cp.head.as_str()) {
                return Err(StoreError::Refused(format!(
                    "checkpoint {} of sink {}: the local record there isn't the one it signed",
                    cp.seq, cp.sink
                )));
            }
            let n = l.conn.execute("DELETE FROM audit WHERE seq < ?1", params![cp.seq])? as i64;
            l.conn.execute("DELETE FROM audit_checkpoints WHERE seq < ?1", params![cp.seq])?;
            l.conn.execute(
                "INSERT INTO audit_anchor (id, seq, hash, jws, sink, pruned_at, pruned) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (id) DO UPDATE SET seq = ?1, hash = ?2, jws = ?3, sink = ?4, pruned_at = ?5, pruned = pruned + ?6",
                params![cp.seq, cp.head, cp.jws, cp.sink, now(), n],
            )?;
            Ok(n)
        })
    }

    /// Whether the file gives freed pages back (`auto_vacuum = incremental`).
    pub fn auto_vacuum_incremental(&self) -> Result<bool> {
        Ok(self.conn.query_row("PRAGMA auto_vacuum", [], |r| r.get::<_, i64>(0))? == 2)
    }

    /// Switches an existing ledger to `auto_vacuum = incremental`, which takes a full `VACUUM`
    /// (the whole file rewritten under an exclusive lock: seconds per hundred MB). Once; a no-op
    /// on a ledger already switched (every new one is). Whether it vacuumed.
    pub fn make_auto_vacuum_incremental(&self) -> Result<bool> {
        if self.auto_vacuum_incremental()? {
            return Ok(false);
        }
        self.conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
        Ok(true)
    }

    /// Gives up to `pages` free pages back to the file system, in one short transaction. The free
    /// pages left.
    pub fn vacuum_step(&self, pages: i64) -> Result<i64> {
        self.conn.execute_batch(&format!("PRAGMA incremental_vacuum({});", pages.max(1)))?;
        Ok(self.conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?)
    }

    /// The ledger file's size in bytes, as SQLite counts it (pages in use and free).
    pub fn file_bytes(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::TenantId;

    fn chain(l: &Ledger, n: usize) {
        for i in 0..n {
            l.audit(&TenantId::single(), None, "op", &serde_json::json!({ "i": i, "pad": "x".repeat(200) })).unwrap();
        }
    }

    /// A prune cuts back only to a checkpoint every sink has exported past, keeps the
    /// checkpoint's record as the anchor, and the chain verifies from there.
    #[test]
    fn a_prune_keeps_the_chain_verifiable() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 100);
        let hash = |s: i64| l.audit_hash_at(s).unwrap().unwrap();
        l.record_checkpoint("a", 40, &hash(40), 1, "jws40").unwrap();
        l.record_checkpoint("a", 70, &hash(70), 2, "jws70").unwrap();
        l.advance_export("a", 80).unwrap();
        l.advance_export("b", 50).unwrap();
        assert_eq!(l.prune_point(&["a"], 90).unwrap().map(|c| c.seq), Some(70));
        assert_eq!(l.prune_point(&["a", "b"], 90).unwrap().map(|c| c.seq), Some(40), "b has only 50");
        assert_eq!(l.prune_point(&["a", "b"], 30).unwrap().map(|c| c.seq), Some(40), "none that low: the nearest above");
        assert_eq!(l.prune_point(&[], 90).unwrap(), None, "no sink, no prune");
        let cp = l.prune_point(&["a", "b"], 90).unwrap().unwrap();
        let before = l.audit_usage().unwrap();
        assert_eq!(l.prune_audit_to(&cp).unwrap(), 39);
        let after = l.audit_usage().unwrap();
        assert_eq!((after.first, after.head, after.rows), (40, 100, 61));
        assert!(after.bytes < before.bytes);
        assert_eq!(l.verify_audit().unwrap(), 61, "verifies from the anchor");
        let a = l.audit_anchor().unwrap().unwrap();
        assert_eq!((a.seq, a.pruned, a.jws.as_str()), (40, 39, "jws40"));
        assert_eq!(l.checkpoints().unwrap().iter().map(|c| c.seq).collect::<Vec<_>>(), [70, 40]);
        assert_eq!(l.prune_point(&["a", "b"], 90).unwrap(), None, "nothing past the anchor b has");
        chain(&l, 1);
        assert_eq!(l.verify_audit().unwrap(), 62, "appends chain on");
    }

    /// A record changed under the anchor is caught; a checkpoint that doesn't match its record is
    /// refused rather than pruned to.
    #[test]
    fn a_wrong_anchor_is_caught() {
        let l = Ledger::open_in_memory().unwrap();
        chain(&l, 10);
        let bad = Checkpoint { sink: "a".into(), seq: 5, head: "v2:nope".into(), ts: 0, jws: String::new() };
        assert!(l.prune_audit_to(&bad).is_err());
        assert_eq!(l.audit_usage().unwrap().rows, 10);
        let good = Checkpoint { sink: "a".into(), seq: 5, head: l.audit_hash_at(5).unwrap().unwrap(), ts: 0, jws: String::new() };
        l.prune_audit_to(&good).unwrap();
        l.conn.execute("UPDATE audit SET body = '{}' WHERE seq = 5", []).unwrap();
        assert!(matches!(l.verify_audit(), Err(StoreError::ChainBroken(5))));
    }

    /// New ledgers give freed pages back; the step frees them in bounded chunks.
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
        let cp = Checkpoint { sink: "a".into(), seq: 1900, head: l.audit_hash_at(1900).unwrap().unwrap(), ts: 0, jws: String::new() };
        let big = l.file_bytes().unwrap();
        l.prune_audit_to(&cp).unwrap();
        let mut left = l.vacuum_step(10).unwrap();
        assert!(left > 0, "a chunk at a time");
        while left > 0 {
            left = l.vacuum_step(1000).unwrap();
        }
        assert!(l.file_bytes().unwrap() < big / 2, "{} of {big}", l.file_bytes().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
