//! Per-node services (#579 step 3): which are installed, which boxes want them on which node, and
//! the instances running for them. The reconciler keeps one instance per service, node and tenant
//! that something wants (`wicket-cli`'s `services` pass).

use crate::{Ledger, Result};
use rusqlite::params;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS services (
  name TEXT PRIMARY KEY, manifest TEXT NOT NULL, added_by TEXT NOT NULL, added_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS service_wants (
  service TEXT NOT NULL, node TEXT NOT NULL, tenant TEXT NOT NULL, run TEXT NOT NULL, at INTEGER NOT NULL,
  PRIMARY KEY (service, node, tenant, run)
);
CREATE INDEX IF NOT EXISTS service_wants_run ON service_wants (run);
CREATE TABLE IF NOT EXISTS service_instances (
  run TEXT PRIMARY KEY, service TEXT NOT NULL, node TEXT NOT NULL, tenant TEXT NOT NULL, started_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS service_instances_of ON service_instances (service, node, tenant);
"#;

/// The tenant a shared instance is kept under (one for every tenant, #579's `tenancy: shared`).
pub const SHARED_TENANT: &str = "*";

/// An installed service: its name and its manifest's path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRow {
    pub name: String,
    pub manifest: String,
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
    /// Whether its run is still live.
    pub live: bool,
}

impl Ledger {
    pub fn add_service(&self, name: &str, manifest: &str, by: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO services (name, manifest, added_by, added_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET manifest = excluded.manifest, added_by = excluded.added_by, added_at = excluded.added_at",
            params![name, manifest, by, crate::now()],
        )?;
        Ok(())
    }

    /// Removes an installed service. Returns whether there was one.
    pub fn remove_service(&self, name: &str) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM services WHERE name = ?1", params![name])? > 0)
    }

    pub fn services(&self) -> Result<Vec<ServiceRow>> {
        let mut st = self.conn.prepare("SELECT name, manifest, added_by, added_at FROM services ORDER BY name")?;
        let rows =
            st.query_map([], |r| Ok(ServiceRow { name: r.get(0)?, manifest: r.get(1)?, added_by: r.get(2)?, added_at: r.get(3)? }))?;
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

    pub fn record_service_instance(&self, run: &str, service: &str, node: &str, tenant: &str, now: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO service_instances (run, service, node, tenant, started_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![run, service, node, tenant, now],
        )?;
        Ok(())
    }

    /// The instances started for `service` on `node` for `tenant`, newest first. An instance whose
    /// run has no row yet (its process is starting) counts as live.
    pub fn service_instances(&self, service: &str, node: &str, tenant: &str) -> Result<Vec<Instance>> {
        let mut st = self.conn.prepare(
            "SELECT i.run, i.service, i.node, i.tenant, i.started_at, r.id IS NULL OR r.ended_at IS NULL
             FROM service_instances i LEFT JOIN runs r ON r.id = i.run
             WHERE i.service = ?1 AND i.node = ?2 AND i.tenant = ?3 ORDER BY i.started_at DESC, i.run",
        )?;
        let rows = st.query_map(params![service, node, tenant], |r| {
            Ok(Instance { run: r.get(0)?, service: r.get(1)?, node: r.get(2)?, tenant: r.get(3)?, started_at: r.get(4)?, live: r.get(5)? })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
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
        l.add_service("npm-cache", "/etc/wicket/services/npm-cache/manifest.yaml", "alex").unwrap();
        assert_eq!(l.services().unwrap().len(), 1);
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
        assert_eq!(l.drop_service_wants("run_c").unwrap(), 0, "run_ended dropped it");
        // An instance is live while its run is (and while it is starting, before its row).
        l.record_service_instance("run_svc1", "npm-cache", "n1", "t0", 100).unwrap();
        assert!(l.service_instances("npm-cache", "n1", "t0").unwrap()[0].live, "starting");
        l.run_started(&t, &RunId("run_svc1".into()), "npm-cache", "npm-cache").unwrap();
        assert!(l.service_instances("npm-cache", "n1", "t0").unwrap()[0].live);
        l.run_ended(&RunId("run_svc1".into()), "failed", "").unwrap();
        assert!(!l.service_instances("npm-cache", "n1", "t0").unwrap()[0].live);
        assert!(l.remove_service("npm-cache").unwrap() && !l.remove_service("npm-cache").unwrap());
    }
}
