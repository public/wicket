//! Export bookkeeping (#91): where each sink is in the audit chain, and which process feeds it.
//!
//! The ledger stays the source of truth and is also the export buffer: a sink's cursor is the last
//! sequence number it acknowledged, and delivery reads `seq > cursor` from the audit table. A sink
//! that is down simply doesn't advance; nothing is held in memory and nothing is lost. A record may
//! be delivered twice (the process dies between a sink's acknowledgement and the cursor update), so
//! receivers deduplicate on `seq` when they care: delivery is at least once.
//!
//! Several wicket processes share a ledger. Each sink is fed by one of them at a time, the holder
//! of its lease (renewed while it works; taken over once it lapses).

use crate::{now, Ledger, Result};
use rusqlite::{params, OptionalExtension};

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_export (
  sink TEXT PRIMARY KEY, seq INTEGER NOT NULL DEFAULT 0, checkpoint_at INTEGER NOT NULL DEFAULT 0,
  holder TEXT, lease_until INTEGER NOT NULL DEFAULT 0, error TEXT, updated_at INTEGER NOT NULL DEFAULT 0
);
"#;

/// How long a sink's lease lasts unless renewed, in seconds.
pub const EXPORT_LEASE_SECS: i64 = 30;

/// One sink's position.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExportCursor {
    pub sink: String,
    /// The last sequence number the sink acknowledged.
    pub seq: i64,
    /// When it last acknowledged a checkpoint.
    pub checkpoint_at: i64,
    /// Who feeds it, while the lease lasts.
    pub holder: Option<String>,
    pub lease_until: i64,
    /// The last delivery error, cleared on success.
    pub error: Option<String>,
}

impl Ledger {
    fn ensure_export_row(&self, sink: &str) -> Result<()> {
        self.conn.execute("INSERT OR IGNORE INTO audit_export (sink) VALUES (?1)", params![sink])?;
        Ok(())
    }

    /// Takes or renews the lease on `sink` for `holder` at `at`. True if `holder` now feeds it.
    pub fn lease_export(&self, sink: &str, holder: &str, at: i64) -> Result<bool> {
        self.ensure_export_row(sink)?;
        Ok(self.conn.execute(
            "UPDATE audit_export SET holder = ?2, lease_until = ?3 WHERE sink = ?1 AND (holder IS NULL OR holder = ?2 OR lease_until < ?4)",
            params![sink, holder, at + EXPORT_LEASE_SECS, at],
        )? == 1)
    }

    /// Gives up the lease on `sink`, if `holder` has it.
    pub fn release_export(&self, sink: &str, holder: &str) -> Result<()> {
        self.conn
            .execute("UPDATE audit_export SET holder = NULL, lease_until = 0 WHERE sink = ?1 AND holder = ?2", params![sink, holder])?;
        Ok(())
    }

    /// Records that `sink` acknowledged everything up to `seq`. Never moves a cursor back.
    pub fn advance_export(&self, sink: &str, seq: i64) -> Result<()> {
        self.ensure_export_row(sink)?;
        self.conn.execute(
            "UPDATE audit_export SET seq = MAX(seq, ?2), error = NULL, updated_at = ?3 WHERE sink = ?1",
            params![sink, seq, now()],
        )?;
        Ok(())
    }

    /// Records that `sink` acknowledged a checkpoint made at `at`.
    pub fn export_checkpointed(&self, sink: &str, at: i64) -> Result<()> {
        self.ensure_export_row(sink)?;
        self.conn.execute("UPDATE audit_export SET checkpoint_at = MAX(checkpoint_at, ?2) WHERE sink = ?1", params![sink, at])?;
        Ok(())
    }

    /// Records a delivery failure for `sink`, for `wicket audit export --status`.
    pub fn export_failed(&self, sink: &str, error: &str) -> Result<()> {
        self.ensure_export_row(sink)?;
        self.conn.execute("UPDATE audit_export SET error = ?2, updated_at = ?3 WHERE sink = ?1", params![sink, error, now()])?;
        Ok(())
    }

    pub fn export_cursor(&self, sink: &str) -> Result<ExportCursor> {
        self.ensure_export_row(sink)?;
        Ok(self.conn.query_row(
            "SELECT sink, seq, checkpoint_at, holder, lease_until, error FROM audit_export WHERE sink = ?1",
            params![sink],
            |r| {
                Ok(ExportCursor {
                    sink: r.get(0)?,
                    seq: r.get(1)?,
                    checkpoint_at: r.get(2)?,
                    holder: r.get(3)?,
                    lease_until: r.get(4)?,
                    error: r.get(5)?,
                })
            },
        )?)
    }

    /// The newest record: (seq, hash).
    pub fn audit_head(&self) -> Result<Option<(i64, String)>> {
        Ok(self.conn.query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?))).optional()?)
    }

    /// The record at `seq`, with its chain fields, if there is one.
    pub fn audit_record_at(&self, seq: i64) -> Result<Option<crate::AuditRecord>> {
        Ok(self.audit_records_after(seq - 1, 1)?.into_iter().next().filter(|r| r.seq == seq))
    }

    /// The hash of the record at `seq`, if there is one.
    pub fn audit_hash_at(&self, seq: i64) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT hash FROM audit WHERE seq = ?1", params![seq], |r| r.get(0)).optional()?)
    }

    /// Every audit record of one kind, oldest first.
    pub fn audit_of_kind(&self, kind: &str) -> Result<Vec<crate::AuditRecord>> {
        let mut st = self.conn.prepare("SELECT seq, ts, tenant, run, kind, body, prev, hash FROM audit WHERE kind = ?1 ORDER BY seq")?;
        let rows = st.query_map(params![kind], |r| {
            Ok(crate::AuditRecord {
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

    /// After a restore (#154): appends records exported before the control host was lost, as they
    /// were, where they continue the restored chain. Stops at the first that doesn't (its seq, prev
    /// or hash), and returns how many were appended.
    pub fn import_exported_audit(&self, recs: &[crate::AuditRecord]) -> Result<usize> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let r = (|| {
            let (mut seq, mut prev) = self.audit_head()?.unwrap_or((0, crate::CHAIN_ZERO.to_string()));
            let mut sum = crate::ChainSummary::default();
            let mut n = 0;
            let start = seq;
            for r in recs.iter().skip_while(|r| r.seq <= start) {
                let f = crate::ChainFields { seq: r.seq, ts: r.ts, tenant: &r.tenant, run: r.run.as_deref(), kind: &r.kind, body: &r.body };
                if r.seq != seq + 1 || r.prev != prev || !sum.accept(&prev, &f, &r.hash) {
                    break;
                }
                self.conn.execute(
                    "INSERT INTO audit (seq, ts, tenant, run, kind, body, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![r.seq, r.ts, r.tenant, r.run, r.kind, r.body, r.prev, r.hash],
                )?;
                (seq, prev) = (r.seq, r.hash.clone());
                n += 1;
            }
            Ok(n)
        })();
        let _ = self.conn.execute_batch(if r.is_ok() { "COMMIT" } else { "ROLLBACK" });
        r
    }

    /// Moves every export cursor back to at most `seq` (a restored chain ends there), so what comes
    /// after it is exported again.
    pub fn rewind_exports(&self, seq: i64) -> Result<()> {
        self.conn.execute("UPDATE audit_export SET seq = MIN(seq, ?1), holder = NULL, lease_until = 0", params![seq])?;
        Ok(())
    }

    /// After a restore (#154): moves every agent's generation past any a lost control host may have
    /// handed out after the restore point, so a box still running at one of those is fenced off.
    pub fn bump_agent_generations(&self, by: i64) -> Result<usize> {
        Ok(self.conn.execute("UPDATE agents SET generation = generation + ?1, lease_until = 0", params![by])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_holder_per_sink_until_its_lease_lapses() {
        let l = Ledger::open_in_memory().unwrap();
        assert!(l.lease_export("otel", "a", 100).unwrap());
        assert!(!l.lease_export("otel", "b", 100).unwrap(), "held by a");
        assert!(l.lease_export("file", "b", 100).unwrap(), "leases are per sink");
        assert!(l.lease_export("otel", "a", 110).unwrap(), "a renews");
        assert!(!l.lease_export("otel", "b", 110 + EXPORT_LEASE_SECS).unwrap());
        assert!(l.lease_export("otel", "b", 111 + EXPORT_LEASE_SECS).unwrap(), "lapsed: b takes over");
        l.release_export("otel", "b").unwrap();
        assert!(l.lease_export("otel", "a", 112 + EXPORT_LEASE_SECS).unwrap());
    }

    #[test]
    fn cursors_only_move_forward() {
        let l = Ledger::open_in_memory().unwrap();
        l.advance_export("s", 10).unwrap();
        l.advance_export("s", 4).unwrap();
        assert_eq!(l.export_cursor("s").unwrap().seq, 10);
        l.export_failed("s", "connection refused").unwrap();
        assert_eq!(l.export_cursor("s").unwrap().error.as_deref(), Some("connection refused"));
        l.advance_export("s", 11).unwrap();
        assert_eq!(l.export_cursor("s").unwrap().error, None);
    }
}
