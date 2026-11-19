//! A change stream from the ledger (#582 step 2): per-topic change counters, kept by triggers, so a
//! run's supervisor does ledger work only when something it depends on changed.
//!
//! - `ledger_changes (topic, seq)`: one row per [`Topic`], whose `seq` goes up on every insert,
//!   update and delete of the tables the topic covers. Triggers keep it, so every writer does,
//!   whichever process or build it is, and a write and its count commit together.
//! - [`ChangeWatch`]: a reader's view. It first asks SQLite's `PRAGMA data_version`, which changes
//!   only when another connection has committed: unchanged, nothing has, and it reads no table. Changed,
//!   it reads the few counter rows and says which topics moved since it last looked.

use crate::{Ledger, Result};
use std::collections::BTreeMap;

/// What a supervisor watches, and the tables each covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Topic {
    Grants,
    /// Turn cancels and mode changes (#327, #363).
    Asks,
    /// Identity revocations, and nodes' status and certificates.
    Revocations,
    /// Node CAs, their widening policy and what boxes want of them (#573).
    NodeCa,
}

impl Topic {
    pub const ALL: [Topic; 4] = [Topic::Grants, Topic::Asks, Topic::Revocations, Topic::NodeCa];

    pub fn as_str(self) -> &'static str {
        match self {
            Topic::Grants => "grants",
            Topic::Asks => "asks",
            Topic::Revocations => "revocations",
            Topic::NodeCa => "node_ca",
        }
    }

    fn tables(self) -> &'static [&'static str] {
        match self {
            Topic::Grants => &["grants"],
            Topic::Asks => &["turn_cancels", "mode_changes"],
            Topic::Revocations => &["revocations", "nodes", "node_certs"],
            Topic::NodeCa => &["node_cas", "node_ca_policy", "node_ca_wants"],
        }
    }
}

/// Creates the counters and their triggers (after every table they cover exists).
pub(crate) fn migrate(conn: &rusqlite::Connection) -> Result<()> {
    let mut sql = String::from("CREATE TABLE IF NOT EXISTS ledger_changes (topic TEXT PRIMARY KEY, seq INTEGER NOT NULL);\n");
    for t in Topic::ALL {
        sql.push_str(&format!("INSERT OR IGNORE INTO ledger_changes (topic, seq) VALUES ('{}', 0);\n", t.as_str()));
        for table in t.tables() {
            for op in ["INSERT", "UPDATE", "DELETE"] {
                sql.push_str(&format!(
                    "CREATE TRIGGER IF NOT EXISTS ledger_changes_{table}_{} AFTER {op} ON {table} \
                     BEGIN UPDATE ledger_changes SET seq = seq + 1 WHERE topic = '{}'; END;\n",
                    op.to_ascii_lowercase(),
                    t.as_str()
                ));
            }
        }
    }
    conn.execute_batch(&sql)?;
    Ok(())
}

/// A reader's view of the change counters: which topics moved since it last looked.
#[derive(Debug, Default)]
pub struct ChangeWatch {
    /// The connection's `data_version` and `total_changes()` when the counters were last read.
    version: Option<i64>,
    own: Option<i64>,
    /// Each topic's `seq` when this watch last reported it changed.
    seen: BTreeMap<Topic, i64>,
    /// The counters as last read.
    now: BTreeMap<Topic, i64>,
}

impl ChangeWatch {
    pub fn new() -> ChangeWatch {
        ChangeWatch::default()
    }

    /// Whether `topic` changed since this watch last said so (true the first time). Reads no table
    /// when no other connection has committed since the last look.
    pub fn changed(&mut self, l: &Ledger, topic: Topic) -> Result<bool> {
        self.refresh(l)?;
        let now = self.now.get(&topic).copied().unwrap_or(0);
        let moved = self.seen.get(&topic) != Some(&now);
        if moved {
            self.seen.insert(topic, now);
        }
        Ok(moved)
    }

    /// Forgets what was seen: every topic counts as changed at the next look (a new connection).
    pub fn reset(&mut self) {
        self.seen.clear();
    }

    fn refresh(&mut self, l: &Ledger) -> Result<()> {
        // Another connection's commits move data_version; this connection's own (a supervisor's
        // gateway writes through it) move total_changes(). Neither reads a table.
        let v: i64 = l.conn.query_row("PRAGMA data_version", [], |r| r.get(0))?;
        let own: i64 = l.conn.query_row("SELECT total_changes()", [], |r| r.get(0))?;
        if self.version == Some(v) && self.own == Some(own) {
            return Ok(());
        }
        let mut st = l.conn.prepare_cached("SELECT topic, seq FROM ledger_changes")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (name, seq) = row?;
            if let Some(t) = Topic::ALL.into_iter().find(|t| t.as_str() == name) {
                self.now.insert(t, seq);
            }
        }
        self.version = Some(v);
        // Read after the counters: a change between the two is seen at the next look.
        self.own = Some(l.conn.query_row("SELECT total_changes()", [], |r| r.get(0))?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::{RunId, TenantId};

    fn file_ledger(name: &str) -> (std::path::PathBuf, Ledger) {
        let dir = std::env::temp_dir().join(format!("wicket-changes-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ledger.db");
        let l = Ledger::open(&p).unwrap();
        (p, l)
    }

    #[test]
    fn a_write_to_a_covered_table_moves_its_topic_for_other_connections() {
        let (path, writer) = file_ledger("topics");
        let reader = Ledger::open(&path).unwrap();
        let mut w = ChangeWatch::new();
        for t in Topic::ALL {
            assert!(w.changed(&reader, t).unwrap(), "{t:?}: the first look counts as a change");
            assert!(!w.changed(&reader, t).unwrap(), "{t:?}: nothing since");
        }
        writer.request_turn_cancel("run_a", "op").unwrap();
        assert!(w.changed(&reader, Topic::Asks).unwrap());
        assert!(!w.changed(&reader, Topic::Grants).unwrap(), "another topic didn't move");
        let t = TenantId::single();
        let op = wicket_core::Op::egress(&t, &RunId("run_a".into()), "z", "GET", "h.example.com", "/x");
        let mut writer = writer;
        let (rid, _) = writer.pending_for(&op, "out of reach", None).unwrap();
        let a = crate::Approval { uses: Some(1), ttl: std::time::Duration::from_secs(60), path_prefix: None, decided_by: "t".into() };
        let gid = writer.approve(&rid, &a).unwrap();
        assert!(w.changed(&reader, Topic::Grants).unwrap(), "a grant made");
        writer.revoke_grant(&gid).unwrap();
        assert!(w.changed(&reader, Topic::Grants).unwrap(), "a grant revoked (an update)");
        assert!(!w.changed(&reader, Topic::Asks).unwrap());
        writer.set_node_ca_policy("n1", &crate::CaHosts::Auto).unwrap();
        assert!(w.changed(&reader, Topic::NodeCa).unwrap());
        // A new connection's watch sees everything once.
        w.reset();
        assert!(w.changed(&reader, Topic::Revocations).unwrap());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// The point of it: with nothing committed elsewhere, a look reads no table.
    #[test]
    fn an_idle_look_reads_nothing_but_data_version() {
        let (path, writer) = file_ledger("idle");
        let mut reader = Ledger::open(&path).unwrap();
        let mut w = ChangeWatch::new();
        w.changed(&reader, Topic::Grants).unwrap();
        let reads = crate::scale::tests::traced_sql(&mut reader, |l| {
            for _ in 0..10 {
                w.changed(l, Topic::Grants).unwrap();
                w.changed(l, Topic::Asks).unwrap();
            }
        });
        assert!(reads.iter().all(|s| s.contains("data_version") || s.contains("total_changes")), "{reads:?}");
        writer.request_turn_cancel("run_a", "op").unwrap();
        let reads = crate::scale::tests::traced_sql(&mut reader, |l| {
            assert!(w.changed(l, Topic::Asks).unwrap());
        });
        assert!(reads.iter().any(|s| s.contains("ledger_changes")), "{reads:?}");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
