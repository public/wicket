//! Links between boxes (issue #6): the ports boxes expose, and every link wicket relays. The ledger
//! is where the `wicket run` processes of two boxes meet: the one that opens a link records it here,
//! and its relay keeps checking it, so a link cut from anywhere (`wicket unlink`, the agent's
//! `unlink`, a revocation, either run ending) closes within a poll.

use crate::{now, Ledger, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use wicket_core::TenantId;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS exposes (
  run TEXT NOT NULL, port INTEGER NOT NULL, tenant TEXT NOT NULL, name TEXT, zone TEXT NOT NULL,
  created_at INTEGER NOT NULL, PRIMARY KEY (run, port)
);
CREATE TABLE IF NOT EXISTS links (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, from_run TEXT NOT NULL, to_run TEXT NOT NULL, port INTEGER NOT NULL,
  name TEXT NOT NULL, addr TEXT NOT NULL, by_run TEXT NOT NULL, basis TEXT NOT NULL, status TEXT NOT NULL,
  created_at INTEGER NOT NULL, closed_at INTEGER, closed_by TEXT, close_reason TEXT
);
CREATE INDEX IF NOT EXISTS links_from ON links (from_run, status);
"#;

/// A port a box offers to others.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExposeRow {
    pub run: String,
    pub port: u16,
    pub tenant: String,
    pub name: Option<String>,
    /// The exposing box's zone (JSON), so a connector in another process can check containment.
    pub zone: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkRow {
    pub id: String,
    pub tenant: String,
    /// The connecting box: the link appears there as `name.wicket.internal:port` at `addr`.
    pub from_run: String,
    /// The box whose port it reaches.
    pub to_run: String,
    pub port: u16,
    pub name: String,
    pub addr: String,
    /// The run that opened it (the connector, or the parent that linked two of its children).
    pub by_run: String,
    /// Why it opened: "child", "accept_from", "both ends are the caller's", or a grant id.
    pub basis: String,
    /// "open" or "closed".
    pub status: String,
    pub created_at: i64,
    pub closed_at: Option<i64>,
    pub closed_by: Option<String>,
    pub close_reason: Option<String>,
}

const COLS: &str = "id, tenant, from_run, to_run, port, name, addr, by_run, basis, status, created_at, closed_at, closed_by, close_reason";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<LinkRow> {
    Ok(LinkRow {
        id: r.get(0)?,
        tenant: r.get(1)?,
        from_run: r.get(2)?,
        to_run: r.get(3)?,
        port: r.get::<_, i64>(4)? as u16,
        name: r.get(5)?,
        addr: r.get(6)?,
        by_run: r.get(7)?,
        basis: r.get(8)?,
        status: r.get(9)?,
        created_at: r.get(10)?,
        closed_at: r.get(11)?,
        closed_by: r.get(12)?,
        close_reason: r.get(13)?,
    })
}

impl Ledger {
    /// Records that `run` offers `port` (again: the latest name and zone win).
    pub fn expose(&self, tenant: &TenantId, run: &str, port: u16, name: Option<&str>, zone_json: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO exposes (run, port, tenant, name, zone, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![run, port as i64, tenant.0, name, zone_json, now()],
        )?;
        Ok(())
    }

    /// Takes back an expose (one that could not be recorded in the audit log).
    pub fn unexpose(&self, run: &str, port: u16) -> Result<()> {
        self.conn.execute("DELETE FROM exposes WHERE run = ?1 AND port = ?2", params![run, port])?;
        Ok(())
    }

    pub fn exposed(&self, run: &str, port: u16) -> Result<Option<ExposeRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT run, port, tenant, name, zone, created_at FROM exposes WHERE run = ?1 AND port = ?2",
                params![run, port as i64],
                |r| {
                    Ok(ExposeRow {
                        run: r.get(0)?,
                        port: r.get::<_, i64>(1)? as u16,
                        tenant: r.get(2)?,
                        name: r.get(3)?,
                        zone: r.get(4)?,
                        created_at: r.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn add_link(&self, l: &LinkRow) -> Result<()> {
        self.conn.execute(
            &format!("INSERT INTO links ({COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"),
            params![
                l.id,
                l.tenant,
                l.from_run,
                l.to_run,
                l.port as i64,
                l.name,
                l.addr,
                l.by_run,
                l.basis,
                l.status,
                l.created_at,
                l.closed_at,
                l.closed_by,
                l.close_reason
            ],
        )?;
        Ok(())
    }

    pub fn link(&self, id: &str) -> Result<Option<LinkRow>> {
        Ok(self.conn.query_row(&format!("SELECT {COLS} FROM links WHERE id = ?1"), params![id], row).optional()?)
    }

    /// The most recent links of a tenant, newest first.
    pub fn links(&self, tenant: &TenantId, limit: usize) -> Result<Vec<LinkRow>> {
        let mut st =
            self.conn.prepare(&format!("SELECT {COLS} FROM links WHERE tenant = ?1 ORDER BY created_at DESC, id DESC LIMIT ?2"))?;
        let rows = st.query_map(params![tenant.0, limit as i64], row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Every link (open or closed) into the box `from_run`: the names and addresses it has used.
    pub fn links_from(&self, from_run: &str) -> Result<Vec<LinkRow>> {
        let mut st = self.conn.prepare(&format!("SELECT {COLS} FROM links WHERE from_run = ?1 ORDER BY created_at, id"))?;
        let rows = st.query_map(params![from_run], row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// An open link between the same ends on the same port, if there is one.
    pub fn open_link(&self, from_run: &str, to_run: &str, port: u16) -> Result<Option<LinkRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM links WHERE from_run = ?1 AND to_run = ?2 AND port = ?3 AND status = 'open' LIMIT 1"),
                params![from_run, to_run, port as i64],
                row,
            )
            .optional()?)
    }

    /// Closes an open link. Returns whether it was open.
    pub fn close_link(&self, id: &str, by: &str, reason: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE links SET status = 'closed', closed_at = ?2, closed_by = ?3, close_reason = ?4 WHERE id = ?1 AND status = 'open'",
            params![id, now(), by, reason],
        )?;
        Ok(n > 0)
    }

    /// A run ended: every open link that has it at either end, or that it opened, closes.
    pub(crate) fn close_links_of(&self, run: &str) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE links SET status = 'closed', closed_at = ?2, closed_by = 'wicket:run-ended', close_reason = 'run ' || ?1 || ' ended'
             WHERE status = 'open' AND (from_run = ?1 OR to_run = ?1 OR by_run = ?1)",
            params![run, now()],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::RunId;

    fn link(id: &str, from: &str, to: &str, by: &str) -> LinkRow {
        LinkRow {
            id: id.into(),
            tenant: "t0".into(),
            from_run: from.into(),
            to_run: to.into(),
            port: 8000,
            name: "svc".into(),
            addr: "198.18.1.1".into(),
            by_run: by.into(),
            basis: "child".into(),
            status: "open".into(),
            created_at: now(),
            closed_at: None,
            closed_by: None,
            close_reason: None,
        }
    }

    #[test]
    fn links_close_when_cut_or_when_either_run_ends() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        l.expose(&t, "run_b", 8000, Some("svc"), "{}").unwrap();
        assert_eq!(l.exposed("run_b", 8000).unwrap().unwrap().name.as_deref(), Some("svc"));
        assert!(l.exposed("run_b", 9000).unwrap().is_none());

        l.add_link(&link("l-1", "run_a", "run_b", "run_a")).unwrap();
        l.add_link(&link("l-2", "run_c", "run_d", "run_p")).unwrap();
        l.add_link(&link("l-3", "run_e", "run_f", "run_e")).unwrap();
        assert_eq!(l.open_link("run_a", "run_b", 8000).unwrap().unwrap().id, "l-1");

        // Cut by an operator.
        assert!(l.close_link("l-1", "alice", "cut").unwrap());
        assert!(!l.close_link("l-1", "alice", "again").unwrap(), "already closed");
        let r = l.link("l-1").unwrap().unwrap();
        assert_eq!((r.status.as_str(), r.closed_by.as_deref()), ("closed", Some("alice")));
        assert!(l.open_link("run_a", "run_b", 8000).unwrap().is_none());

        // The run that opened a link (here a parent linking two children) ending closes it; so does
        // either end's run ending.
        l.run_started(&t, &RunId("run_p".into()), "z", "p").unwrap();
        l.run_ended(&RunId("run_p".into()), "succeeded", "{}").unwrap();
        assert_eq!(l.link("l-2").unwrap().unwrap().status, "closed");
        l.run_started(&t, &RunId("run_f".into()), "z", "f").unwrap();
        l.run_ended(&RunId("run_f".into()), "failed", "{}").unwrap();
        let r = l.link("l-3").unwrap().unwrap();
        assert_eq!((r.status.as_str(), r.closed_by.as_deref()), ("closed", Some("wicket:run-ended")));
        assert_eq!(l.links(&t, 10).unwrap().len(), 3);
        assert_eq!(l.links_from("run_a").unwrap().len(), 1);
    }
}
