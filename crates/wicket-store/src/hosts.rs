//! Supervisor hosts, their shards, leases and epochs (#582 step 5; research note 25, §3.1).
//!
//! A supervisor host (`wicket supervise`) runs many runs' supervisors as tasks in one process. Runs
//! are sharded by node: each node belongs to one shard, and a shard is held by one host process at a
//! time, under a lease, at an epoch.
//!
//! - `supervisor_hosts`: one row per shard. `owner` is the process holding it
//!   (`<machine>:<pid>:<start>`, as `runs.owner` was), `epoch` goes up each time the shard is taken,
//!   `lease_until` is when the holder's lease lapses unless renewed, and `stopping` is the clean-stop
//!   marker (§3.4: a death without one is a crash). `adopting` is the batch of runs a host is
//!   adopting in safe mode, recorded before it starts.
//! - `shard_nodes`: which shard each node belongs to.
//! - `runs.host`: the shard whose host supervises a run.
//!
//! **Fencing.** Taking a shard ([`Ledger::take_shard`]) works only while the shard is free or its
//! lease has lapsed, and raises its epoch in the same transaction that names the shard's nodes and
//! sets its runs' `runs.host`. A host's writes ([`Ledger::as_shard`]) are made only while the shard
//! is still at its epoch and held by its process, so a host whose shard was taken writes nothing.
//! Who takes a dead shard, and when, is wicketd's ([`lapsed_alone`]: never when every lease lapsed
//! together, which is the ledger stalling, not a host).
//!
//! Nothing here decides a request (#257): this is bookkeeping about who supervises which run.

use crate::{Ledger, Result, StoreError};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS supervisor_hosts (
  host TEXT PRIMARY KEY, owner TEXT, epoch INTEGER NOT NULL DEFAULT 0, lease_until INTEGER NOT NULL DEFAULT 0,
  stopping INTEGER NOT NULL DEFAULT 0, adopting TEXT, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS shard_nodes (node TEXT PRIMARY KEY, host TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS shard_nodes_host ON shard_nodes (host);
"#;

/// `runs.host` (schema 42), added to an existing ledger once.
pub(crate) fn migrate(conn: &rusqlite::Connection) -> Result<()> {
    let n: i64 = conn.query_row("SELECT count(*) FROM pragma_table_info('runs') WHERE name = 'host'", [], |r| r.get(0))?;
    if n == 0 {
        conn.execute_batch("ALTER TABLE runs ADD COLUMN host TEXT")?;
    }
    conn.execute_batch("CREATE INDEX IF NOT EXISTS runs_host ON runs (host) WHERE host IS NOT NULL")?;
    Ok(())
}

/// A shard as the ledger records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SupervisorHost {
    pub host: String,
    pub owner: Option<String>,
    pub epoch: i64,
    pub lease_until: i64,
    /// A clean-stop marker was written (an update, a lost lease, a shutdown).
    pub stopping: bool,
    /// The runs being adopted in safe mode, as the host recorded them before it began.
    pub adopting: Vec<String>,
    pub updated_at: i64,
}

/// A shard taken: the epoch it is now held at, the holder before (if any), and how many of its runs
/// now name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Taken {
    pub epoch: i64,
    pub previous: Option<String>,
    pub runs: usize,
}

/// Which hosts wicketd may fence at `now` (§3.1): those whose lease has lapsed while another host's
/// lease is live, so the cause is that host, not the ledger. When every held lease has lapsed
/// together, none is: the ledger stalled, and killing hosts would only make it worse. A shard with
/// no holder, or one that stopped cleanly, isn't fenced; it is simply free to take.
pub fn lapsed_alone(hosts: &[SupervisorHost], now: i64) -> Vec<String> {
    let held: Vec<&SupervisorHost> = hosts.iter().filter(|h| h.owner.is_some() && !h.stopping).collect();
    let lapsed: Vec<&SupervisorHost> = held.iter().copied().filter(|h| h.lease_until <= now).collect();
    if lapsed.len() == held.len() {
        return Vec::new();
    }
    lapsed.into_iter().map(|h| h.host.clone()).collect()
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SupervisorHost> {
    let adopting: Option<String> = r.get(5)?;
    Ok(SupervisorHost {
        host: r.get(0)?,
        owner: r.get(1)?,
        epoch: r.get(2)?,
        lease_until: r.get(3)?,
        stopping: r.get::<_, i64>(4)? != 0,
        adopting: adopting.and_then(|a| serde_json::from_str(&a).ok()).unwrap_or_default(),
        updated_at: r.get(6)?,
    })
}

const COLUMNS: &str = "host, owner, epoch, lease_until, stopping, adopting, updated_at";

impl Ledger {
    /// Takes shard `host` for the process `owner`, for `nodes`, with a lease to `now + lease_secs`.
    /// Refused ([`StoreError::ShardHeld`]) while another process's lease is live and it hasn't
    /// stopped. Every take raises the epoch. One transaction: the epoch, the shard's nodes (a node
    /// moves here from any other shard) and every running run on them (`runs.host`).
    pub fn take_shard(&self, host: &str, owner: &str, nodes: &[&str], lease_secs: i64, now: i64) -> Result<Taken> {
        self.immediate::<_, StoreError>(|l| {
            let cur = l.supervisor_host(host)?;
            if let Some(c) = cur.as_ref().filter(|c| c.owner.as_deref().is_some_and(|o| o != owner) && !c.stopping && c.lease_until > now) {
                return Err(StoreError::ShardHeld(host.to_string(), c.lease_until - now));
            }
            let epoch = cur.as_ref().map_or(0, |c| c.epoch) + 1;
            l.conn.execute(
                "INSERT INTO supervisor_hosts (host, owner, epoch, lease_until, stopping, adopting, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 0, NULL, ?5)
                 ON CONFLICT(host) DO UPDATE SET owner = excluded.owner, epoch = excluded.epoch,
                   lease_until = excluded.lease_until, stopping = 0, adopting = NULL, updated_at = excluded.updated_at",
                params![host, owner, epoch, now + lease_secs, now],
            )?;
            l.conn.execute("DELETE FROM shard_nodes WHERE host = ?1", params![host])?;
            let mut runs = 0;
            for node in nodes {
                l.conn.execute(
                    "INSERT INTO shard_nodes (node, host) VALUES (?1, ?2) ON CONFLICT(node) DO UPDATE SET host = excluded.host",
                    params![node, host],
                )?;
                runs += l.conn.execute("UPDATE runs SET host = ?2 WHERE status = 'running' AND node = ?1", params![node, host])?;
            }
            Ok(Taken { epoch, previous: cur.and_then(|c| c.owner), runs })
        })
    }

    /// wicketd's fence (§3.1), before it kills `holder` and starts a fresh host: raises the shard's
    /// epoch and clears its holder, so `holder` can renew and write nothing from here on, and the
    /// fresh host takes the shard at once. Only while `holder` still holds it, and only once its lease
    /// has lapsed or wicketd has seen its process exit (`gone`). Returns the new epoch, or None if
    /// the shard wasn't `holder`'s or its lease is still live.
    pub fn fence_shard(&self, host: &str, holder: &str, gone: bool, now: i64) -> Result<Option<i64>> {
        self.immediate::<_, StoreError>(|l| {
            let n = l.conn.execute(
                "UPDATE supervisor_hosts SET owner = NULL, epoch = epoch + 1, lease_until = 0, updated_at = ?3
                 WHERE host = ?1 AND owner = ?2 AND (?4 OR lease_until <= ?3)",
                params![host, holder, now, gone],
            )?;
            Ok(if n == 0 { None } else { l.supervisor_host(host)?.map(|h| h.epoch) })
        })
    }

    /// Renews the lease of shard `host` to `now + lease_secs`, only while `owner` holds it at
    /// `epoch` and hasn't stopped. Returns whether it did: false means the shard was taken (or
    /// stopped), and its host must stop writing.
    pub fn renew_shard_lease(&self, host: &str, owner: &str, epoch: i64, lease_secs: i64, now: i64) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE supervisor_hosts SET lease_until = ?4, updated_at = ?5
             WHERE host = ?1 AND owner = ?2 AND epoch = ?3 AND stopping = 0",
            params![host, owner, epoch, now + lease_secs, now],
        )?;
        Ok(n > 0)
    }

    /// The clean-stop marker (§3.4), written by the holder before a planned stop: the host's death
    /// that follows isn't counted as a crash, and the shard is free to take at once. Only by its
    /// holder at its epoch.
    pub fn mark_shard_stopping(&self, host: &str, owner: &str, epoch: i64, now: i64) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE supervisor_hosts SET stopping = 1, updated_at = ?4 WHERE host = ?1 AND owner = ?2 AND epoch = ?3",
            params![host, owner, epoch, now],
        )?;
        Ok(n > 0)
    }

    /// Records the batch of runs a host is about to adopt in safe mode (§3.4), before it starts, or
    /// clears it (an empty batch). Only by the holder at its epoch.
    pub fn set_shard_adopting(&self, host: &str, owner: &str, epoch: i64, runs: &[String], now: i64) -> Result<bool> {
        let batch = (!runs.is_empty()).then(|| serde_json::to_string(runs)).transpose()?;
        let n = self.conn.execute(
            "UPDATE supervisor_hosts SET adopting = ?4, updated_at = ?5 WHERE host = ?1 AND owner = ?2 AND epoch = ?3",
            params![host, owner, epoch, batch, now],
        )?;
        Ok(n > 0)
    }

    pub fn supervisor_host(&self, host: &str) -> Result<Option<SupervisorHost>> {
        Ok(self.conn.query_row(&format!("SELECT {COLUMNS} FROM supervisor_hosts WHERE host = ?1"), params![host], row).optional()?)
    }

    pub fn supervisor_hosts(&self) -> Result<Vec<SupervisorHost>> {
        let mut st = self.conn.prepare(&format!("SELECT {COLUMNS} FROM supervisor_hosts ORDER BY host"))?;
        let rows = st.query_map([], row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The shard a node belongs to, if any.
    pub fn shard_of_node(&self, node: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT host FROM shard_nodes WHERE node = ?1", params![node], |r| r.get(0)).optional()?)
    }

    /// The nodes of a shard.
    pub fn shard_nodes(&self, host: &str) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT node FROM shard_nodes WHERE host = ?1 ORDER BY node")?;
        let rows = st.query_map(params![host], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// The shard whose host supervises a run, if a host does.
    pub fn run_host(&self, run: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT host FROM runs WHERE id = ?1", params![run], |r| r.get(0)).optional()?.flatten())
    }

    /// The running runs a shard's host supervises.
    pub fn shard_runs(&self, host: &str) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT id FROM runs WHERE host = ?1 AND status = 'running' ORDER BY id")?;
        let rows = st.query_map(params![host], |r| r.get(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Runs `f` in one immediate transaction only while `owner` holds shard `host` at `epoch`
    /// (§3.1: every ledger write a host makes carries its epoch). Refused with
    /// [`StoreError::ShardLost`] otherwise, writing nothing; the host must then stop.
    pub fn as_shard<T, E: From<StoreError>>(
        &self,
        host: &str,
        owner: &str,
        epoch: i64,
        f: impl FnOnce(&Ledger) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        self.immediate(|l| {
            let held: bool = l
                .conn
                .query_row(
                    "SELECT count(*) FROM supervisor_hosts WHERE host = ?1 AND owner = ?2 AND epoch = ?3",
                    params![host, owner, epoch],
                    |r| r.get::<_, i64>(0),
                )
                .map_err(StoreError::from)?
                > 0;
            if !held {
                return Err(E::from(StoreError::ShardLost(host.to_string(), epoch)));
            }
            f(l)
        })
    }

    /// Whether a run's writes may be made by shard `host` at `epoch`, inside [`Ledger::as_shard`]:
    /// the run names that shard. (The shard's epoch and holder are `as_shard`'s check.)
    pub fn run_in_shard(&self, run: &str, host: &str) -> Result<bool> {
        Ok(self.run_host(run)?.as_deref() == Some(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::{RunId, TenantId};

    const A: &str = "m:1:1";
    const B: &str = "m:2:2";

    fn ledger_with_runs() -> Ledger {
        let l = Ledger::open_in_memory().unwrap();
        for (run, node) in [("run_1", "n1"), ("run_2", "n2"), ("run_3", "n1")] {
            l.run_started(&TenantId("t".into()), &RunId(run.into()), "z", "w").unwrap();
            l.conn.execute("UPDATE runs SET node = ?2 WHERE id = ?1", params![run, node]).unwrap();
        }
        l
    }

    #[test]
    fn taking_a_shard_raises_its_epoch_and_names_its_nodes_and_runs() {
        let l = ledger_with_runs();
        let t = l.take_shard("0", A, &["n1"], 30, 100).unwrap();
        assert_eq!((t.epoch, t.previous, t.runs), (1, None, 2));
        assert_eq!(l.shard_runs("0").unwrap(), ["run_1", "run_3"]);
        assert_eq!(l.run_host("run_2").unwrap(), None);
        assert_eq!(l.shard_of_node("n1").unwrap().as_deref(), Some("0"));
        // A node moves between shards whole.
        l.take_shard("1", B, &["n1", "n2"], 30, 100).unwrap();
        assert_eq!(l.shard_nodes("0").unwrap(), Vec::<String>::new());
        assert_eq!(l.shard_runs("1").unwrap(), ["run_1", "run_2", "run_3"]);
    }

    #[test]
    fn a_live_lease_keeps_the_shard_and_a_lapsed_one_gives_it_up() {
        let l = ledger_with_runs();
        l.take_shard("0", A, &["n1"], 30, 100).unwrap();
        assert!(matches!(l.take_shard("0", B, &["n1"], 30, 110), Err(StoreError::ShardHeld(_, 20))));
        assert!(l.renew_shard_lease("0", A, 1, 30, 125).unwrap());
        assert!(matches!(l.take_shard("0", B, &["n1"], 30, 150), Err(StoreError::ShardHeld(_, 5))));
        let t = l.take_shard("0", B, &["n1"], 30, 155).unwrap();
        assert_eq!((t.epoch, t.previous.as_deref()), (2, Some(A)));
        // The old holder can no longer renew, mark or write.
        assert!(!l.renew_shard_lease("0", A, 1, 30, 156).unwrap());
        assert!(!l.mark_shard_stopping("0", A, 1, 156).unwrap());
        let w: Result<()> = l.as_shard("0", A, 1, |l| {
            l.set_run_owner("run_1", "x")?;
            Ok(())
        });
        assert!(matches!(w, Err(StoreError::ShardLost(_, 1))));
        assert!(l.as_shard::<_, StoreError>("0", B, 2, |l| l.run_in_shard("run_1", "0")).unwrap());
    }

    #[test]
    fn wicketd_fences_only_a_lapsed_or_exited_holder_and_the_fresh_host_takes_at_once() {
        let l = ledger_with_runs();
        l.take_shard("0", A, &["n1"], 30, 100).unwrap();
        // Live lease, process not seen to exit: no fence.
        assert_eq!(l.fence_shard("0", A, false, 110).unwrap(), None);
        // Not the holder wicketd thought: no fence.
        assert_eq!(l.fence_shard("0", B, true, 110).unwrap(), None);
        // Seen to exit: fenced at once, whatever the lease.
        assert_eq!(l.fence_shard("0", A, true, 110).unwrap(), Some(2));
        assert!(!l.renew_shard_lease("0", A, 1, 30, 111).unwrap());
        let t = l.take_shard("0", B, &["n1"], 30, 111).unwrap();
        assert_eq!((t.epoch, t.previous), (3, None));
        // A lapsed lease is fenced without the process having exited.
        assert_eq!(l.fence_shard("0", B, false, 140).unwrap(), None, "the lease runs to 141");
        assert_eq!(l.fence_shard("0", B, false, 141).unwrap(), Some(4));
    }

    #[test]
    fn a_clean_stop_frees_the_shard_at_once_and_stops_renewals() {
        let l = ledger_with_runs();
        l.take_shard("0", A, &["n1"], 30, 100).unwrap();
        assert!(l.mark_shard_stopping("0", A, 1, 101).unwrap());
        assert!(!l.renew_shard_lease("0", A, 1, 30, 102).unwrap());
        let t = l.take_shard("0", B, &["n1"], 30, 103).unwrap();
        assert_eq!(t.epoch, 2);
        assert!(!l.supervisor_host("0").unwrap().unwrap().stopping);
    }

    #[test]
    fn an_adopting_batch_is_recorded_and_cleared_by_its_holder() {
        let l = ledger_with_runs();
        l.take_shard("0", A, &["n1"], 30, 100).unwrap();
        let batch = vec!["run_1".to_string(), "run_3".to_string()];
        assert!(l.set_shard_adopting("0", A, 1, &batch, 101).unwrap());
        assert_eq!(l.supervisor_host("0").unwrap().unwrap().adopting, batch);
        assert!(!l.set_shard_adopting("0", B, 1, &[], 102).unwrap());
        assert!(l.set_shard_adopting("0", A, 1, &[], 102).unwrap());
        assert!(l.supervisor_host("0").unwrap().unwrap().adopting.is_empty());
    }

    fn host(h: &str, lease_until: i64) -> SupervisorHost {
        SupervisorHost {
            host: h.into(),
            owner: Some(format!("m:{h}:1")),
            epoch: 1,
            lease_until,
            stopping: false,
            adopting: vec![],
            updated_at: 0,
        }
    }

    #[test]
    fn only_a_lease_that_lapsed_alone_is_fenced() {
        // One lapsed while the other renewed: that host.
        assert_eq!(lapsed_alone(&[host("0", 99), host("1", 130)], 100), ["0"]);
        // Every lease lapsed together: the ledger stalled, so no one.
        assert!(lapsed_alone(&[host("0", 99), host("1", 95)], 100).is_empty());
        // A single host: its lapse can't be told from a stall.
        assert!(lapsed_alone(&[host("0", 99)], 100).is_empty());
        // A stopped or unheld shard is free, not fenced, and doesn't count as live.
        let mut stopped = host("1", 99);
        stopped.stopping = true;
        let mut free = host("2", 0);
        free.owner = None;
        assert!(lapsed_alone(&[host("0", 99), stopped, free.clone()], 100).is_empty());
        assert_eq!(lapsed_alone(&[host("0", 99), free, host("3", 200)], 100), ["0"]);
    }

    #[test]
    fn an_existing_ledger_gains_runs_host_once() {
        let l = Ledger::open_in_memory().unwrap();
        migrate(&l.conn).unwrap();
        let n: i64 = l.conn.query_row("SELECT count(*) FROM pragma_table_info('runs') WHERE name = 'host'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }
}
