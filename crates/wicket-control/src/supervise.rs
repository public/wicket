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
//! - **wicketd fences, and only after taking the epoch** ([`Fencer`]): it fences a holder whose
//!   process it saw exit at once, and one whose heartbeat is silent (or stuck) only once its lease
//!   has lapsed alone for [`STALL_WINDOW_SECS`], several renewals, so the end of a ledger stall
//!   (when the first host to renew makes the rest look lapsed alone) fences no one. Each fence names
//!   the holder it is for, so a late reap never fences that shard's next holder. A held shard whose
//!   process wicketd doesn't know (wicketd itself restarted) is watched, not fenced, while its lease
//!   is live. The ledger step is `Ledger::fence_shard`: a higher epoch, only for that holder; the
//!   kill and the fresh start follow only if it worked.
//! - Leases and heartbeats are wall-clock seconds from the control host's one clock: every host and
//!   wicketd run there in this version.
//!
//! Nothing here decides a request (#257).

use std::collections::BTreeMap;
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
/// How long a host's lease must have lapsed alone, continuously, before wicketd fences it: several
/// renewals, so a host that renews once the ledger is back after a stall isn't fenced.
pub const STALL_WINDOW_SECS: i64 = 3 * RENEW_SECS as i64;
/// How long a host that wrote its clean-stop marker may take to exit before wicketd fences it.
pub const STOP_SECS: i64 = 60;
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
    seen: u64,
}

impl Lease {
    /// Takes `shard` for this process, with `nodes`, at the runtime's `progress` now: the first
    /// renewal, like every later one, needs the runtime to have moved since.
    pub fn take(l: &Ledger, shard: &str, owner: &str, nodes: &[&str], progress: u64, now: i64) -> Result<Lease, StoreError> {
        let t = l.take_shard(shard, owner, nodes, LEASE_SECS, now)?;
        Ok(Lease { shard: shard.into(), owner: owner.into(), epoch: t.epoch, seen: progress })
    }

    /// One renewal, if the runtime moved since the last one.
    pub fn renew(&mut self, l: &Ledger, progress: u64, now: i64) -> Renewal {
        if self.seen == progress {
            return Renewal::Stuck;
        }
        match l.renew_shard_lease(&self.shard, &self.owner, self.epoch, LEASE_SECS, now) {
            Ok(true) => {
                self.seen = progress;
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

/// A host process wicketd started, as it knows it: whose shard, the holder label it took the shard
/// as, its last heartbeat with its runtime moving, and whether wicketd has reaped it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proc {
    pub owner: String,
    pub ok_at: i64,
    pub exited: bool,
}

/// What wicketd does about one shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Start a host for a shard that has none: never held, stopped cleanly and gone, or fenced.
    Start(String),
    /// Fence `holder` ([`Ledger::fence_shard`] with `gone`), then, only if that worked, kill it
    /// (unless gone) and start a fresh host, in that order.
    Fence { shard: String, holder: String, gone: bool },
    /// Held, its lease live, by a process wicketd doesn't know (wicketd restarted): wait for it to
    /// heartbeat, stop, or lapse. Never fenced on that alone.
    Watch(String),
}

/// wicketd's decisions over time. It remembers, per shard, since when its holder has been lapsed
/// alone, so one instant of it (a stall ending) fences no one.
#[derive(Debug, Default)]
pub struct Fencer {
    alone_since: BTreeMap<String, (String, i64)>,
}

impl Fencer {
    /// What to do at `now` for `shards`, from the ledger's records (`hosts`) and the host processes
    /// wicketd knows (`procs`, by shard):
    /// - a shard with no live holder (none, or stopped and its process gone or unknown): start;
    /// - its holder's process reaped: fence that holder, gone, at once;
    /// - stopping for longer than [`STOP_SECS`] and still running: fence (its lease has lapsed by
    ///   then, as a stopping host doesn't renew);
    /// - its heartbeat silent or stuck for [`SILENT_SECS`], or its process unknown, and its lease
    ///   lapsed alone continuously for [`STALL_WINDOW_SECS`]: fence;
    /// - held, its lease live, its process unknown: watch.
    pub fn decide(&mut self, shards: &[String], hosts: &[SupervisorHost], procs: &BTreeMap<String, Proc>, now: i64) -> Vec<Action> {
        let alone = lapsed_alone(hosts, now);
        self.alone_since.retain(|s, (holder, _)| {
            alone.contains(s) && hosts.iter().any(|h| &h.host == s && h.owner.as_deref() == Some(holder.as_str()))
        });
        for s in &alone {
            if let Some(holder) = hosts.iter().find(|h| &h.host == s).and_then(|h| h.owner.clone()) {
                self.alone_since.entry(s.clone()).or_insert((holder, now));
            }
        }
        let mut out = Vec::new();
        for s in shards {
            let rec = hosts.iter().find(|h| &h.host == s);
            let holder = rec.and_then(|h| h.owner.clone());
            // The process wicketd knows for this shard, if it is the holder on record.
            let proc = procs.get(s).filter(|p| holder.as_deref() == Some(p.owner.as_str()));
            let Some(holder) = holder else {
                out.push(Action::Start(s.clone()));
                continue;
            };
            let rec = rec.expect("a holder has a record");
            let fence = |gone| Action::Fence { shard: s.clone(), holder: holder.clone(), gone };
            if rec.stopping {
                match proc {
                    Some(p) if !p.exited && rec.updated_at + STOP_SECS <= now => out.push(fence(false)),
                    Some(p) if !p.exited => {}
                    _ => out.push(Action::Start(s.clone())),
                }
                continue;
            }
            match proc {
                Some(p) if p.exited => out.push(fence(true)),
                _ => {
                    let lapsed_long = self.alone_since.get(s).is_some_and(|(_, since)| since + STALL_WINDOW_SECS <= now);
                    let silent = proc.is_none_or(|p| p.ok_at + SILENT_SECS <= now);
                    if silent && lapsed_long {
                        out.push(fence(false));
                    } else if proc.is_none() && rec.lease_until > now {
                        out.push(Action::Watch(s.clone()));
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FNV-1a 64 of each name, mod 2 and 3, computed outside Rust.
    const PINNED_2: [usize; 5] = [0, 1, 0, 1, 0];
    const PINNED_3: [usize; 5] = [0, 0, 2, 0, 1];

    #[test]
    fn shards_are_stable_and_the_local_node_is_in_the_first() {
        assert_eq!(shard_of(crate::localnode::NAME, 2), 0);
        assert_eq!(shard_of("any", 1), 0);
        // Pinned: a change to the hash would move nodes to other hosts on an update.
        assert_eq!(["n1", "n2", "n3", "node-a", "vultr-ams-1"].map(|n| shard_of(n, 2)), PINNED_2, "FNV-1a of each name, mod 2");
        assert_eq!(["n1", "n2", "n3", "node-a", "vultr-ams-1"].map(|n| shard_of(n, 3)), PINNED_3);
        let a = assign(["n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", crate::localnode::NAME, "n1"], 2);
        assert_eq!(a.iter().map(Vec::len).sum::<usize>(), 9);
        assert!(a[0].iter().any(|n| n == crate::localnode::NAME));
        assert!(a.iter().all(|s| !s.is_empty()), "{a:?}");
    }

    fn ledger() -> Ledger {
        Ledger::open_in_memory().unwrap()
    }

    #[test]
    fn a_lease_renews_only_while_the_runtime_moves_and_leaves_only_when_taken() {
        let l = ledger();
        let p = Progress::default();
        let mut a = Lease::take(&l, "0", "m:1:1", &["n1"], p.get(), 100).unwrap();
        assert_eq!(a.epoch, 1);
        // The first renewal needs progress too: a runtime that wedged right after the take lapses.
        assert_eq!(a.renew(&l, p.get(), 105), Renewal::Stuck);
        p.tick();
        assert_eq!(a.renew(&l, p.get(), 105), Renewal::Renewed);
        assert_eq!(a.renew(&l, p.get(), 110), Renewal::Stuck, "no tick since the last renewal");
        assert_eq!(l.supervisor_host("0").unwrap().unwrap().lease_until, 105 + LEASE_SECS);
        // Taken by another host once the lease lapsed: the old one is told it lost the shard.
        let b = Lease::take(&l, "0", "m:2:2", &["n1"], 0, 105 + LEASE_SECS).unwrap();
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
            updated_at: lease_until - LEASE_SECS,
        }
    }

    fn proc(h: &str, ok_at: i64) -> Proc {
        Proc { owner: format!("m:{h}:1"), ok_at, exited: false }
    }

    fn fence(s: &str, gone: bool) -> Action {
        Action::Fence { shard: s.into(), holder: format!("m:{s}:1"), gone }
    }

    fn shards() -> Vec<String> {
        vec!["0".into(), "1".into()]
    }

    #[test]
    fn wicketd_starts_missing_hosts_and_leaves_live_ones() {
        let mut f = Fencer::default();
        assert_eq!(f.decide(&shards(), &[], &BTreeMap::new(), 100), [Action::Start("0".into()), Action::Start("1".into())]);
        let procs = BTreeMap::from([("0".into(), proc("0", 100)), ("1".into(), proc("1", 100))]);
        assert!(f.decide(&shards(), &[host("0", 130), host("1", 130)], &procs, 105).is_empty());
    }

    #[test]
    fn an_exited_holder_is_fenced_at_once_and_a_late_reap_names_the_old_holder() {
        let mut f = Fencer::default();
        let mut procs = BTreeMap::from([("0".into(), proc("0", 100)), ("1".into(), proc("1", 100))]);
        procs.get_mut("0").unwrap().exited = true;
        assert_eq!(f.decide(&shards(), &[host("0", 130), host("1", 130)], &procs, 101), [fence("0", true)]);
        // The shard was fenced and a fresh host (m:9:9) holds it; the old process is reaped only now:
        // nothing, as the reaped process isn't the holder on record.
        let mut fresh = host("0", 140);
        fresh.owner = Some("m:9:9".into());
        procs.insert("0".into(), Proc { owner: "m:0:1".into(), ok_at: 100, exited: true });
        assert_eq!(f.decide(&shards(), &[fresh, host("1", 140)], &procs, 111), [Action::Watch("0".into())]);
    }

    #[test]
    fn after_wicketd_restarts_held_shards_are_watched_not_fenced() {
        let mut f = Fencer::default();
        let hosts = [host("0", 130), host("1", 130)];
        // wicketd knows no process: both held, both live.
        assert_eq!(f.decide(&shards(), &hosts, &BTreeMap::new(), 101), [Action::Watch("0".into()), Action::Watch("1".into())]);
        // One renews on (its process lives on, wicketd just doesn't know it), the other lapses:
        // watched until it has been lapsed alone for the window, then fenced (not gone).
        let hosts = [host("0", 130), host("1", 150)];
        assert_eq!(f.decide(&shards(), &hosts, &BTreeMap::new(), 131), [Action::Watch("1".into())]);
        assert_eq!(f.decide(&shards(), &hosts, &BTreeMap::new(), 131 + STALL_WINDOW_SECS - 1), [Action::Watch("1".into())]);
        let hosts = [host("0", 130), host("1", 170)];
        assert_eq!(f.decide(&shards(), &hosts, &BTreeMap::new(), 131 + STALL_WINDOW_SECS), [fence("0", false), Action::Watch("1".into())]);
    }

    #[test]
    fn the_moment_a_ledger_stall_ends_fences_no_one() {
        let mut f = Fencer::default();
        // A stall from 70 to 130: both leases (to 100) lapsed, both heartbeats are fine (they are
        // off the ledger), and neither is fenced while both are lapsed.
        let procs = BTreeMap::from([("0".into(), proc("0", 70)), ("1".into(), proc("1", 70))]);
        assert!(f.decide(&shards(), &[host("0", 100), host("1", 100)], &procs, 120).is_empty());
        // At 130 host 1 renews first: host 0 looks lapsed alone for a moment, silent heartbeat or not.
        assert!(f.decide(&shards(), &[host("0", 100), host("1", 160)], &procs, 130).is_empty());
        // Host 0 renews 4 s later: never fenced.
        assert!(f.decide(&shards(), &[host("0", 164), host("1", 160)], &procs, 134).is_empty());
        // Had it not renewed for the whole window, with its heartbeat silent, it would have been.
        let mut f = Fencer::default();
        assert!(f.decide(&shards(), &[host("0", 100), host("1", 160)], &procs, 130).is_empty());
        assert_eq!(f.decide(&shards(), &[host("0", 100), host("1", 175)], &procs, 130 + STALL_WINDOW_SECS), [fence("0", false)]);
    }

    #[test]
    fn a_heartbeating_host_is_not_fenced_for_a_lapse_and_a_stopping_one_has_a_time_limit() {
        let mut f = Fencer::default();
        // Lapsed alone for the window, but its heartbeat says its runtime moves: its renewals are
        // failing for a reason of its own (not a stall); not fenced while it answers.
        let procs = BTreeMap::from([("0".into(), proc("0", 150)), ("1".into(), proc("1", 150))]);
        f.decide(&shards(), &[host("0", 100), host("1", 160)], &procs, 131);
        assert!(f.decide(&shards(), &[host("0", 100), host("1", 175)], &procs, 150).is_empty());
        // Stopping: left alone while it exits, fenced after STOP_SECS if it doesn't, started again
        // once it has.
        let mut stopping = host("0", 160);
        stopping.stopping = true;
        stopping.updated_at = 140;
        let hosts = [stopping.clone(), host("1", 175)];
        assert!(f.decide(&shards(), &hosts, &procs, 150).is_empty());
        assert_eq!(f.decide(&shards(), &hosts, &procs, 140 + STOP_SECS), [fence("0", false)]);
        let mut gone = procs.clone();
        gone.get_mut("0").unwrap().exited = true;
        assert_eq!(f.decide(&shards(), &hosts, &gone, 150), [Action::Start("0".into())]);
    }
}
