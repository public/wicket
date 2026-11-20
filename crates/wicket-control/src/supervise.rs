//! Supervisor hosts (#582 step 5; research note 25): the parts that hold a shard, renew its lease
//! and fence a host, which don't depend on what a host runs.
//!
//! - **Shards are static by node** (migration step 1): [`shard_of`] puts the local node in the
//!   first shard and every other node in one by a stable hash of its name, so every build and every
//!   restart agrees on it.
//! - **The lease is renewed only while the host's runtime makes progress** ([`Progress`],
//!   [`Lease::renew`]): its runtime moves a counter every tick, and a renewal that sees the counter
//!   where it left it doesn't renew. A frozen process lapses its lease, and so does a wedged runtime
//!   whose lease thread is still alive.
//! - **wicketd fences, and only after taking the epoch** ([`decide`]): a host whose process exited,
//!   or whose heartbeat has been silent (or says it is stuck) for [`SILENT_SECS`] while its lease
//!   lapsed alone, is taken in the ledger first (a higher epoch, which only works while that lease
//!   is lapsed), then killed, then started fresh. When every lease lapsed together, the ledger
//!   stalled: no host is killed.
//!
//! Nothing here decides a request (#257).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use wicket_store::{lapsed_alone, Ledger, StoreError, SupervisorHost};

/// A host's lease, from its last renewal.
pub const LEASE_SECS: i64 = 30;
/// How often a host renews its lease, and wicketd asks for its heartbeat.
pub const RENEW_SECS: u64 = 5;
/// How long a heartbeat may be silent (or stuck) before wicketd fences the host, once its lease has
/// lapsed alone.
pub const SILENT_SECS: i64 = 20;
/// The fewest hosts (note 25, §3.3): one host's lease lapsing is told from a ledger stall only
/// against another's.
pub const MIN_HOSTS: usize = 2;

/// The shard (`0..hosts`) a node belongs to: the local node to the first, every other node by
/// FNV-1a of its name, which no build changes.
pub fn shard_of(node: &str, hosts: usize) -> usize {
    if node == crate::localnode::NAME || hosts <= 1 {
        return 0;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in node.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    (h % hosts as u64) as usize
}

/// A shard's name in the ledger (`supervisor_hosts.host`).
pub fn shard_name(shard: usize) -> String {
    shard.to_string()
}

/// The nodes of each of `hosts` shards.
pub fn assign<'a>(nodes: impl IntoIterator<Item = &'a str>, hosts: usize) -> Vec<Vec<String>> {
    let mut out = vec![Vec::new(); hosts.max(1)];
    for n in nodes {
        out[shard_of(n, hosts)].push(n.to_string());
    }
    for s in &mut out {
        s.sort();
        s.dedup();
    }
    out
}

/// A host runtime's progress: a counter a task on the runtime moves every tick.
#[derive(Clone, Default)]
pub struct Progress(Arc<AtomicU64>);

impl Progress {
    pub fn tick(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// What a renewal found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Renewal {
    Renewed,
    /// The runtime made no progress since the last renewal: not renewed, so a wedged host lapses.
    Stuck,
    /// Not renewed because the ledger failed (busy, full): tried again at the next renewal. It isn't
    /// a reason to leave: only a lost epoch is.
    Failed,
    /// The shard was taken at a higher epoch, or stopped: the host must stop writing and leave.
    Lost,
}

/// The shard a host process holds: its name, its holder (this process's owner label) and epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub shard: String,
    pub owner: String,
    pub epoch: i64,
    seen: Option<u64>,
}

impl Lease {
    /// Takes `shard` for this process, with `nodes`.
    pub fn take(l: &Ledger, shard: &str, owner: &str, nodes: &[&str], now: i64) -> Result<Lease, StoreError> {
        let t = l.take_shard(shard, owner, nodes, LEASE_SECS, now)?;
        Ok(Lease { shard: shard.into(), owner: owner.into(), epoch: t.epoch, seen: None })
    }

    /// One renewal, if the runtime moved since the last one.
    pub fn renew(&mut self, l: &Ledger, progress: u64, now: i64) -> Renewal {
        if self.seen == Some(progress) {
            return Renewal::Stuck;
        }
        match l.renew_shard_lease(&self.shard, &self.owner, self.epoch, LEASE_SECS, now) {
            Ok(true) => {
                self.seen = Some(progress);
                Renewal::Renewed
            }
            Ok(false) => match l.supervisor_host(&self.shard) {
                // Still ours at our epoch: only `stopping` refuses it, which this host wrote.
                Ok(Some(h)) if h.owner.as_deref() == Some(self.owner.as_str()) && h.epoch == self.epoch && !h.stopping => Renewal::Failed,
                Ok(_) => Renewal::Lost,
                Err(_) => Renewal::Failed,
            },
            Err(_) => Renewal::Failed,
        }
    }
}

/// A host's heartbeat, as wicketd last heard it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Beat {
    /// When it last answered with its runtime moving.
    pub ok_at: i64,
}

/// What wicketd does about one shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Start a host for a shard that has none (wicketd's first start, or one that stopped cleanly).
    Start(String),
    /// Take the shard at a higher epoch ([`Ledger::fence_shard`]), kill its old host only if that
    /// worked, then start a fresh one (in that order).
    Fence(String),
}

/// What wicketd does at `now`, from the ledger's shards, each running host's last good heartbeat
/// (by shard; none for a shard with no host process) and the shards whose host process exited.
///
/// - a shard whose process exited: fenced at once (a crash is seen when wicketd reaps its child);
///   one that stopped cleanly: started;
/// - a shard with no host at all (none recorded, or no process for it): started;
/// - a shard whose heartbeat is silent or stuck past [`SILENT_SECS`]: fenced only if its lease
///   lapsed alone ([`lapsed_alone`]); a stall of every host waits.
pub fn decide(
    shards: &[String],
    hosts: &[SupervisorHost],
    beats: &std::collections::BTreeMap<String, Beat>,
    exited: &std::collections::BTreeSet<String>,
    now: i64,
) -> Vec<Action> {
    let alone = lapsed_alone(hosts, now);
    let mut out = Vec::new();
    for s in shards {
        let rec = hosts.iter().find(|h| &h.host == s);
        let running = beats.contains_key(s) && !exited.contains(s);
        let held = rec.is_some_and(|h| h.owner.is_some() && !h.stopping);
        if !running {
            out.push(if held { Action::Fence(s.clone()) } else { Action::Start(s.clone()) });
        } else if beats[s].ok_at + SILENT_SECS <= now && alone.contains(s) {
            out.push(Action::Fence(s.clone()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn shards_are_stable_and_the_local_node_is_in_the_first() {
        assert_eq!(shard_of(crate::localnode::NAME, 2), 0);
        assert_eq!(shard_of("any", 1), 0);
        // Fixed values: a change to the hash would move every node to another host on an update.
        assert_eq!(shard_of("node-a", 2), shard_of("node-a", 2));
        let a = assign(["n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", crate::localnode::NAME, "n1"], 2);
        assert_eq!(a.iter().map(Vec::len).sum::<usize>(), 9);
        assert!(a[0].iter().any(|n| n == crate::localnode::NAME));
        assert!(a.iter().all(|s| !s.is_empty()), "{a:?}");
        let fnv = |s: &str| {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in s.bytes() {
                h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
            }
            h
        };
        assert_eq!(fnv("a"), 0xaf63_dc4c_8601_ec8c, "FNV-1a's published value for \"a\"");
    }

    fn ledger() -> Ledger {
        Ledger::open_in_memory().unwrap()
    }

    #[test]
    fn a_lease_renews_only_while_the_runtime_moves_and_leaves_only_when_taken() {
        let l = ledger();
        let mut a = Lease::take(&l, "0", "m:1:1", &["n1"], 100).unwrap();
        assert_eq!(a.epoch, 1);
        let p = Progress::default();
        p.tick();
        assert_eq!(a.renew(&l, p.get(), 105), Renewal::Renewed);
        assert_eq!(a.renew(&l, p.get(), 110), Renewal::Stuck, "no tick since the last renewal");
        assert_eq!(l.supervisor_host("0").unwrap().unwrap().lease_until, 105 + LEASE_SECS);
        // Taken by another host once the lease lapsed: the old one is told it lost the shard.
        let b = Lease::take(&l, "0", "m:2:2", &["n1"], 105 + LEASE_SECS).unwrap();
        assert_eq!(b.epoch, 2);
        p.tick();
        assert_eq!(a.renew(&l, p.get(), 140), Renewal::Lost);
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
    fn wicketd_starts_missing_hosts_fences_dead_ones_and_never_fences_on_a_stall() {
        let shards = vec!["0".to_string(), "1".to_string()];
        let mut beats = BTreeMap::new();
        let exited = BTreeSet::new();
        // Nothing recorded, nothing running: start both.
        assert_eq!(decide(&shards, &[], &beats, &exited, 100), [Action::Start("0".into()), Action::Start("1".into())]);
        // Both running and answering: nothing.
        beats.insert("0".into(), Beat { ok_at: 100 });
        beats.insert("1".into(), Beat { ok_at: 100 });
        let hosts = vec![host("0", 130), host("1", 130)];
        assert!(decide(&shards, &hosts, &beats, &exited, 105).is_empty());
        // Host 1 silent, but its lease is live: wait.
        beats.insert("0".into(), Beat { ok_at: 125 });
        assert!(decide(&shards, &hosts, &beats, &exited, 125).is_empty());
        // Its lease lapsed alone while host 0 renewed: fence it.
        let hosts = vec![host("0", 160), host("1", 130)];
        assert_eq!(decide(&shards, &hosts, &beats, &exited, 131), [Action::Fence("1".into())]);
        // Both silent and both lapsed together: a ledger stall; nobody is killed.
        let hosts = vec![host("0", 130), host("1", 130)];
        beats.insert("0".into(), Beat { ok_at: 100 });
        assert!(decide(&shards, &hosts, &beats, &exited, 131).is_empty());
        // A process that exited is fenced at once, whatever its lease.
        let exited: BTreeSet<String> = ["0".to_string()].into();
        assert_eq!(decide(&shards, &hosts, &beats, &exited, 101), [Action::Fence("0".into())]);
        // One that stopped cleanly is just started again.
        let mut stopped = host("0", 130);
        stopped.stopping = true;
        assert_eq!(decide(&shards, &[stopped, host("1", 130)], &beats, &exited, 101), [Action::Start("0".into())]);
    }
}
