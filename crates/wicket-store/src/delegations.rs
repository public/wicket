//! Delegation (#252): what a parent handed to a child it spawned, and where that work is.
//!
//! A delegation is a record, not an authority: the child's authority is its zone, fixed when it was
//! spawned within its parent's (#256), and nothing here widens it. Each row says who delegated
//! (the parent's run and principal), to whom (the child's run, principal and name), the brief, and
//! its state:
//!
//! - `working`: the child has a brief it hasn't reported on (its first turn, or a continuation);
//! - `reported`: its last turn ended and its report went to the parent as a message;
//! - `ended`: its run ended (its final `run_finished` went to the parent).
//!
//! `turn` counts the briefs: 1 for the spawn's task, one more for each continuation. The report
//! and the latest brief are messages (`report_message`, `brief_message`), with receipts of their own.

use crate::{now, Ledger, Result};
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS delegations (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL,
  parent_run TEXT NOT NULL, parent_principal TEXT NOT NULL,
  child_run TEXT NOT NULL, child_principal TEXT NOT NULL, name TEXT NOT NULL,
  brief TEXT NOT NULL, state TEXT NOT NULL, turn INTEGER NOT NULL DEFAULT 1,
  brief_message TEXT, report_message TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS delegations_parent ON delegations (tenant, parent_principal, created_at);
CREATE INDEX IF NOT EXISTS delegations_child ON delegations (child_run);
"#;

/// The most of a brief the record keeps (the brief itself goes to the child in full).
pub const MAX_BRIEF_RECORD: usize = 16 * 1024;

/// A delegation, as the ledger records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Delegation {
    pub id: String,
    pub tenant: String,
    pub parent_run: String,
    pub parent_principal: String,
    pub child_run: String,
    pub child_principal: String,
    pub name: String,
    pub brief: String,
    /// `working`, `reported` or `ended`.
    pub state: String,
    pub turn: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brief_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_message: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

const COLS: &str = "id, tenant, parent_run, parent_principal, child_run, child_principal, name, brief, state, turn, \
                    brief_message, report_message, created_at, updated_at";

fn row(r: &Row) -> rusqlite::Result<Delegation> {
    Ok(Delegation {
        id: r.get(0)?,
        tenant: r.get(1)?,
        parent_run: r.get(2)?,
        parent_principal: r.get(3)?,
        child_run: r.get(4)?,
        child_principal: r.get(5)?,
        name: r.get(6)?,
        brief: r.get(7)?,
        state: r.get(8)?,
        turn: r.get(9)?,
        brief_message: r.get(10)?,
        report_message: r.get(11)?,
        created_at: r.get(12)?,
        updated_at: r.get(13)?,
    })
}

/// A new delegation: what `spawn` records for an agent it started.
#[derive(Clone, Copy, Debug)]
pub struct NewDelegation<'a> {
    pub id: &'a str,
    pub tenant: &'a str,
    pub parent_run: &'a str,
    pub parent_principal: &'a str,
    pub child_run: &'a str,
    pub child_principal: &'a str,
    pub name: &'a str,
    pub brief: &'a str,
}

impl Ledger {
    /// Records a delegation, `working` on its first brief. Idempotent by id: a child adopted twice
    /// (#164) has one.
    pub fn record_delegation(&self, d: &NewDelegation) -> Result<()> {
        let brief: String = d.brief.chars().take(MAX_BRIEF_RECORD).collect();
        let t = now();
        self.conn.execute(
            "INSERT OR IGNORE INTO delegations (id, tenant, parent_run, parent_principal, child_run, child_principal, name, brief,
                                                state, turn, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'working', 1, ?9, ?9)",
            params![d.id, d.tenant, d.parent_run, d.parent_principal, d.child_run, d.child_principal, d.name, brief, t],
        )?;
        Ok(())
    }

    pub fn delegation(&self, id: &str) -> Result<Option<Delegation>> {
        Ok(self.conn.query_row(&format!("SELECT {COLS} FROM delegations WHERE id = ?1"), params![id], row).optional()?)
    }

    /// The delegation run `child_run` works on, if it was delegated.
    pub fn delegation_of_child(&self, child_run: &str) -> Result<Option<Delegation>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM delegations WHERE child_run = ?1 ORDER BY created_at DESC, rowid DESC LIMIT 1"),
                params![child_run],
                row,
            )
            .optional()?)
    }

    /// The delegations principal `parent` made in `tenant`, newest first.
    pub fn delegations_of(&self, tenant: &str, parent: &str, limit: usize) -> Result<Vec<Delegation>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM delegations WHERE tenant = ?1 AND parent_principal = ?2 ORDER BY created_at DESC, rowid DESC LIMIT ?3"
        ))?;
        let rows = st.query_map(params![tenant, parent, limit as i64], row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The newest delegation in `tenant` to a child named `child` (its name, principal or the
    /// delegation's id), whoever made it: what `continue_child` looks for, so it can tell a child
    /// that isn't the caller's from one that doesn't exist.
    pub fn find_delegation(&self, tenant: &str, child: &str) -> Result<Vec<Delegation>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM delegations WHERE tenant = ?1 AND (name = ?2 OR child_principal = ?2 OR id = ?2)
             ORDER BY created_at DESC, rowid DESC"
        ))?;
        let rows = st.query_map(params![tenant, child], row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// A continuation (#252): one more brief, sent as message `brief_message`; `working` again.
    /// Only from `reported`: false if the delegation is still working or has ended.
    pub fn delegation_continued(&self, id: &str, brief_message: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE delegations SET state = 'working', turn = turn + 1, brief_message = ?2, updated_at = ?3
             WHERE id = ?1 AND state = 'reported'",
            params![id, brief_message, now()],
        )?;
        Ok(n == 1)
    }

    /// The child reported on its brief with message `report_message`: `reported`. Only from
    /// `working`: false otherwise (nothing was waiting for a report).
    pub fn delegation_reported(&self, id: &str, report_message: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE delegations SET state = 'reported', report_message = ?2, updated_at = ?3 WHERE id = ?1 AND state = 'working'",
            params![id, report_message, now()],
        )?;
        Ok(n == 1)
    }

    /// The child's run ended: its delegations are `ended`, and can't be continued.
    pub fn delegation_ended(&self, child_run: &str, final_message: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE delegations SET state = 'ended', report_message = COALESCE(?2, report_message), updated_at = ?3
             WHERE child_run = ?1 AND state != 'ended'",
            params![child_run, final_message, now()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new<'a>(id: &'a str, parent: &'a str, child_run: &'a str, name: &'a str) -> NewDelegation<'a> {
        NewDelegation {
            id,
            tenant: "t0",
            parent_run: "run_p",
            parent_principal: parent,
            child_run,
            child_principal: "spiffe://x/t/t0/z/z.c/a/c",
            name,
            brief: "do it",
        }
    }

    #[test]
    fn a_delegation_goes_working_reported_working_ended() {
        let l = Ledger::open_in_memory().unwrap();
        l.record_delegation(&new("d-1", "spiffe://x/t/t0/z/z/a/p", "run_c", "c")).unwrap();
        l.record_delegation(&new("d-1", "spiffe://x/t/t0/z/z/a/p", "run_c", "c")).unwrap();
        let d = l.delegation("d-1").unwrap().unwrap();
        assert_eq!((d.state.as_str(), d.turn), ("working", 1));
        assert!(!l.delegation_continued("d-1", "m-b").unwrap(), "not while it works");
        assert!(l.delegation_reported("d-1", "m-r").unwrap());
        assert!(!l.delegation_reported("d-1", "m-r2").unwrap(), "one report per brief");
        assert!(l.delegation_continued("d-1", "m-b").unwrap());
        let d = l.delegation_of_child("run_c").unwrap().unwrap();
        assert_eq!((d.state.as_str(), d.turn, d.brief_message.as_deref()), ("working", 2, Some("m-b")));
        l.delegation_ended("run_c", Some("m-f")).unwrap();
        let d = l.delegation("d-1").unwrap().unwrap();
        assert_eq!((d.state.as_str(), d.report_message.as_deref()), ("ended", Some("m-f")));
        assert!(!l.delegation_continued("d-1", "m-c").unwrap(), "an ended one can't be continued");
        assert_eq!(l.delegations_of("t0", "spiffe://x/t/t0/z/z/a/p", 10).unwrap().len(), 1);
        assert!(l.delegations_of("t0", "spiffe://x/t/t0/z/z/a/other", 10).unwrap().is_empty());
        assert_eq!(l.find_delegation("t0", "c").unwrap().len(), 1);
        assert!(l.find_delegation("t1", "c").unwrap().is_empty(), "another tenant's are never found");
    }
}
