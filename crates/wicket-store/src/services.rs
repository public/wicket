//! Per-node services (#579 step 3): which are installed, which boxes want them on which node, and
//! the instances running for them. The reconciler keeps one instance per service, node and tenant
//! that something wants (`wicket-control`'s `services` pass).
//!
//! A service is installed from a snapshot: `wicket service add` copies its manifest and source into
//! a directory wicket owns and records the snapshot's sha256. Instances start, and users' environment
//! is computed, from that snapshot only, so no later edit to the file it was installed from changes
//! what runs; that takes another, audited, `add`.

use crate::{Ledger, Result};
use rusqlite::{params, OptionalExtension};

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS services (
  name TEXT PRIMARY KEY, manifest TEXT NOT NULL, sha256 TEXT NOT NULL, tenant TEXT NOT NULL,
  added_by TEXT NOT NULL, added_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS service_wants (
  service TEXT NOT NULL, node TEXT NOT NULL, tenant TEXT NOT NULL, run TEXT NOT NULL, at INTEGER NOT NULL,
  PRIMARY KEY (service, node, tenant, run)
);
CREATE INDEX IF NOT EXISTS service_wants_run ON service_wants (run);
CREATE TABLE IF NOT EXISTS service_instances (
  run TEXT PRIMARY KEY, service TEXT NOT NULL, node TEXT NOT NULL, tenant TEXT NOT NULL, started_at INTEGER NOT NULL,
  sha256 TEXT NOT NULL, wanted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS service_instances_of ON service_instances (service, node, tenant);
"#;

/// The tenant a shared instance is kept under (one for every tenant, #579's `tenancy: shared`).
pub const SHARED_TENANT: &str = "*";

/// An instance whose run has no row this long after it was started (s) never started: it counts as
/// gone, so another is tried.
pub const START_GRACE_SECS: i64 = 120;

/// An installed service: its name, its snapshot's manifest and sha256, and its tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRow {
    pub name: String,
    /// The snapshot's manifest, in a directory wicket owns.
    pub manifest: String,
    pub sha256: String,
    pub tenant: String,
    pub added_by: String,
    pub added_at: i64,
}

/// A service instance: its run, and for which service, node and tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub run: String,
    pub service: String,
    pub node: String,
    pub tenant: String,
    pub started_at: i64,
    /// The snapshot it was started from.
    pub sha256: String,
    /// When a live run last wanted it (the idle stop counts from this).
    pub wanted_at: i64,
    /// Whether its run is live: running, or (no row yet) started under [`START_GRACE_SECS`] ago.
    pub live: bool,
}

const INSTANCE_COLS: &str = "i.run, i.service, i.node, i.tenant, i.started_at, i.sha256, i.wanted_at, r.id IS NOT NULL, r.ended_at IS NULL";

fn instance(r: &rusqlite::Row<'_>) -> rusqlite::Result<Instance> {
    let (has_run, running): (bool, bool) = (r.get(7)?, r.get(8)?);
    let started_at: i64 = r.get(4)?;
    Ok(Instance {
        run: r.get(0)?,
        service: r.get(1)?,
        node: r.get(2)?,
        tenant: r.get(3)?,
        started_at,
        sha256: r.get(5)?,
        wanted_at: r.get(6)?,
        live: if has_run { running } else { started_at > crate::now() - START_GRACE_SECS },
    })
}

impl Ledger {
    /// Installs (or replaces) a service from its snapshot. Returns the sha256 it replaced, if any.
    pub fn add_service(&self, name: &str, manifest: &str, sha256: &str, tenant: &str, by: &str) -> Result<Option<String>> {
        let old: Option<String> =
            self.conn.query_row("SELECT sha256 FROM services WHERE name = ?1", params![name], |r| r.get(0)).optional()?;
        self.conn.execute(
            "INSERT INTO services (name, manifest, sha256, tenant, added_by, added_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(name) DO UPDATE SET manifest = excluded.manifest, sha256 = excluded.sha256, tenant = excluded.tenant,
               added_by = excluded.added_by, added_at = excluded.added_at",
            params![name, manifest, sha256, tenant, by, crate::now()],
        )?;
        Ok(old)
    }

    /// Removes an installed service. Returns its row, if there was one.
    pub fn remove_service(&self, name: &str) -> Result<Option<ServiceRow>> {
        let row = self.services()?.into_iter().find(|s| s.name == name);
        self.conn.execute("DELETE FROM services WHERE name = ?1", params![name])?;
        Ok(row)
    }

    pub fn services(&self) -> Result<Vec<ServiceRow>> {
        let mut st = self.conn.prepare("SELECT name, manifest, sha256, tenant, added_by, added_at FROM services ORDER BY name")?;
        let rows = st.query_map([], |r| {
            Ok(ServiceRow {
                name: r.get(0)?,
                manifest: r.get(1)?,
                sha256: r.get(2)?,
                tenant: r.get(3)?,
                added_by: r.get(4)?,
                added_at: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// `run`, a box on `node` for `tenant`, uses `service` (its zone's `uses`): an instance is kept
    /// there while it runs.
    pub fn want_service(&self, service: &str, node: &str, tenant: &str, run: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO service_wants (service, node, tenant, run, at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![service, node, tenant, run, crate::now()],
        )?;
        Ok(())
    }

    /// What live runs want: (service, node, tenant), each once, by service and node.
    pub fn service_demand(&self) -> Result<Vec<(String, String, String)>> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT w.service, w.node, w.tenant FROM service_wants w JOIN runs r ON r.id = w.run
             WHERE r.ended_at IS NULL ORDER BY w.service, w.node, w.tenant",
        )?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn record_service_instance(&self, run: &str, service: &str, node: &str, tenant: &str, sha256: &str, now: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO service_instances (run, service, node, tenant, started_at, sha256, wanted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5)",
            params![run, service, node, tenant, now, sha256],
        )?;
        Ok(())
    }

    /// A live run still wants `service` on `node` for `tenant`: its instances' idle time restarts.
    pub fn touch_service_instances(&self, service: &str, node: &str, tenant: &str, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE service_instances SET wanted_at = ?4 WHERE service = ?1 AND node = ?2 AND tenant = ?3",
            params![service, node, tenant, now],
        )?;
        Ok(())
    }

    /// The instances started for `service` on `node` for `tenant`, newest first.
    pub fn service_instances(&self, service: &str, node: &str, tenant: &str) -> Result<Vec<Instance>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {INSTANCE_COLS} FROM service_instances i LEFT JOIN runs r ON r.id = i.run
             WHERE i.service = ?1 AND i.node = ?2 AND i.tenant = ?3 ORDER BY i.started_at DESC, i.run"
        ))?;
        let rows = st.query_map(params![service, node, tenant], instance)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Every live instance (of any service): the idle stop's candidates, and what holds no node.
    pub fn live_service_instances(&self) -> Result<Vec<Instance>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {INSTANCE_COLS} FROM service_instances i LEFT JOIN runs r ON r.id = i.run
             ORDER BY i.service, i.node, i.tenant, i.started_at DESC"
        ))?;
        let rows = st.query_map([], instance)?;
        Ok(rows.collect::<std::result::Result<Vec<Instance>, _>>()?.into_iter().filter(|i| i.live).collect())
    }

    /// `run`'s instance row, if `run` is a service instance wicket started.
    pub fn service_instance_of(&self, run: &str) -> Result<Option<Instance>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {INSTANCE_COLS} FROM service_instances i LEFT JOIN runs r ON r.id = i.run WHERE i.run = ?1"))?;
        Ok(st.query_row(params![run], instance).optional()?)
    }

    /// Drops what `run` wanted of services: it ended.
    pub fn drop_service_wants(&self, run: &str) -> Result<usize> {
        Ok(self.conn.execute("DELETE FROM service_wants WHERE run = ?1", params![run])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::{RunId, TenantId};

    #[test]
    fn demand_comes_from_live_runs_and_instances_from_their_runs() {
        let l = Ledger::open_in_memory().unwrap();
        assert_eq!(l.add_service("npm-cache", "/data/services/npm-cache/aa/manifest.yaml", "aa", "t0", "alex").unwrap(), None);
        assert_eq!(l.add_service("npm-cache", "/data/services/npm-cache/bb/manifest.yaml", "bb", "t0", "alex").unwrap(), Some("aa".into()));
        assert_eq!(l.services().unwrap()[0].sha256, "bb");
        let t = TenantId::single();
        for r in ["run_a", "run_b", "run_c"] {
            l.run_started(&t, &RunId(r.into()), "z", "a").unwrap();
        }
        l.want_service("npm-cache", "n1", "t0", "run_a").unwrap();
        l.want_service("npm-cache", "n1", "t0", "run_b").unwrap();
        l.want_service("npm-cache", "n2", "t0", "run_c").unwrap();
        assert_eq!(
            l.service_demand().unwrap(),
            vec![("npm-cache".into(), "n1".into(), "t0".into()), ("npm-cache".into(), "n2".into(), "t0".into())],
            "one per service, node and tenant"
        );
        l.run_ended(&RunId("run_c".into()), "done", "").unwrap();
        assert_eq!(l.service_demand().unwrap().len(), 1, "an ended run wants nothing");
        // An instance is live while its run is, and while it is starting (no row yet, for a while).
        let now = crate::now();
        l.record_service_instance("run_svc1", "npm-cache", "n1", "t0", "bb", now).unwrap();
        assert!(l.service_instances("npm-cache", "n1", "t0").unwrap()[0].live, "starting");
        l.record_service_instance("run_never", "npm-cache", "n2", "t0", "bb", now - START_GRACE_SECS - 1).unwrap();
        assert!(!l.service_instances("npm-cache", "n2", "t0").unwrap()[0].live, "a start that never made its run");
        l.run_started(&t, &RunId("run_svc1".into()), "npm-cache", "npm-cache").unwrap();
        assert!(l.service_instance_of("run_svc1").unwrap().unwrap().live);
        assert_eq!(l.live_service_instances().unwrap().len(), 1);
        l.touch_service_instances("npm-cache", "n1", "t0", now + 50).unwrap();
        assert_eq!(l.service_instance_of("run_svc1").unwrap().unwrap().wanted_at, now + 50);
        l.run_ended(&RunId("run_svc1".into()), "failed", "").unwrap();
        assert!(!l.service_instances("npm-cache", "n1", "t0").unwrap()[0].live);
        assert!(l.service_instance_of("run_other").unwrap().is_none(), "not an instance");
        assert_eq!(l.remove_service("npm-cache").unwrap().unwrap().sha256, "bb");
        assert!(l.remove_service("npm-cache").unwrap().is_none());
    }
}
