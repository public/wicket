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
//! - **wicketd fences, and only after taking the epoch** ([`Fencer`]): a holder whose process is
//!   gone (reaped, or after a restart or reboot, not running) at once; one whose heartbeat, which is
//!   off the ledger, is silent or stuck and whose lease has lapsed for [`STALL_WINDOW_SECS`] (several
//!   renewals). A ledger stall leaves heartbeats answering, so it fences no one, and the end of one
//!   (the first host to renew makes the rest look lapsed alone for a moment) doesn't either. Each
//!   fence names the holder it is for, so a late reap never fences that shard's next holder. A held
//!   shard whose running process wicketd didn't start is watched, not fenced. The ledger step is
//!   `Ledger::fence_shard`: a higher epoch, only for that holder; the kill and the fresh start
//!   follow only if it worked.
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
    /// Held by a running process wicketd didn't start (wicketd restarted), or one it can't tell
    /// about, whose lease is live, lapsed only briefly, or lapsed with every other: wait for it to
    /// renew, stop or lapse alone past [`STALL_WINDOW_SECS`] (then it is fenced).
    Watch(String),
}

/// wicketd's decisions over time. It remembers, per shard and holder, since when the holder's lease
/// has been lapsed, and since when lapsed alone, so one instant of either (a stall ending) fences
/// no one.
#[derive(Debug, Default)]
pub struct Fencer {
    lapsed_since: BTreeMap<String, (String, i64)>,
    alone_since: BTreeMap<String, (String, i64)>,
}

/// Keeps `since` to the shards in `now_in` whose holder is unchanged, and adds the new ones at `now`.
fn track(since: &mut BTreeMap<String, (String, i64)>, now_in: &[String], hosts: &[SupervisorHost], now: i64) {
    let holder = |s: &str| hosts.iter().find(|h| h.host == s).and_then(|h| h.owner.clone());
    since.retain(|s, (h, _)| now_in.contains(s) && holder(s).as_deref() == Some(h.as_str()));
    for s in now_in {
        if let Some(h) = holder(s) {
            since.entry(s.clone()).or_insert((h, now));
        }
    }
}

impl Fencer {
    /// What to do at `now` for `shards`, from the ledger's records (`hosts`), the host processes
    /// wicketd started (`procs`, by shard), and whether a holder label's process runs
    /// (`holder_alive`: `wicket_home::owner::owner_alive`, None when it can't tell):
    /// - no holder (none recorded, fenced): start;
    /// - stopping: left to exit; fenced if it still runs after [`STOP_SECS`]; started again once its
    ///   process is gone;
    /// - its process reaped by wicketd, or (a process wicketd didn't start, after wicketd or the
    ///   control host restarted) not running: fence that holder, gone, at once. A reboot is this:
    ///   every lease lapsed, every holder gone, every shard fenced and started;
    /// - a process wicketd started whose heartbeat is silent or stuck for [`SILENT_SECS`], and whose
    ///   lease has lapsed for [`STALL_WINDOW_SECS`]: fence. Its heartbeat is off the ledger, so a
    ///   ledger stall alone (heartbeats answering) fences no one, and a single wedged host is fenced
    ///   with no other host to compare it with;
    /// - a process wicketd didn't start that runs, or that it can't tell about: watched while its
    ///   lease is live, lapsed only briefly, or lapsed with every other; fenced once its lease has
    ///   lapsed alone for [`STALL_WINDOW_SECS`].
    pub fn decide(
        &mut self,
        shards: &[String],
        hosts: &[SupervisorHost],
        procs: &BTreeMap<String, Proc>,
        holder_alive: &dyn Fn(&str) -> Option<bool>,
        now: i64,
    ) -> Vec<Action> {
        let lapsed: Vec<String> =
            hosts.iter().filter(|h| h.owner.is_some() && !h.stopping && h.lease_until <= now).map(|h| h.host.clone()).collect();
        track(&mut self.lapsed_since, &lapsed, hosts, now);
        track(&mut self.alone_since, &lapsed_alone(hosts, now), hosts, now);
        let long = |m: &BTreeMap<String, (String, i64)>, s: &str| m.get(s).is_some_and(|(_, since)| since + STALL_WINDOW_SECS <= now);
        let mut out = Vec::new();
        for s in shards {
            let rec = hosts.iter().find(|h| &h.host == s);
            let holder = rec.and_then(|h| h.owner.clone());
            // The process wicketd started for this shard, if it is the holder on record.
            let proc = procs.get(s).filter(|p| holder.as_deref() == Some(p.owner.as_str()));
            let Some(holder) = holder else {
                out.push(Action::Start(s.clone()));
                continue;
            };
            let rec = rec.expect("a holder has a record");
            let fence = |gone| Action::Fence { shard: s.clone(), holder: holder.clone(), gone };
            let alive = match proc {
                Some(p) => !p.exited,
                None => holder_alive(&holder) != Some(false),
            };
            if rec.stopping {
                if !alive {
                    out.push(Action::Start(s.clone()));
                } else if rec.updated_at + STOP_SECS <= now {
                    out.push(fence(false));
                }
                continue;
            }
            match proc {
                _ if !alive => out.push(fence(true)),
                Some(p) => {
                    if p.ok_at + SILENT_SECS <= now && long(&self.lapsed_since, s) {
                        out.push(fence(false));
                    }
                }
                // Running (or can't tell) but not wicketd's: watched while its lease is live or lapsed only
                // briefly, or lapsed together with every other (a stall); fenced once lapsed alone past
                // the window, as there is no heartbeat to say its runtime moves.
                None if long(&self.alone_since, s) => out.push(fence(false)),
                None => out.push(Action::Watch(s.clone())),
            }
        }
        out
    }
}

// ---- The host process (`wicket supervise`, migration step 1, item 1) ----

/// What a host answers on its heartbeat socket: one JSON line per connection, read from atomics
/// only, so a ledger stall can't silence it (note 25, §3.1). `stuck` and `lease_ok` are sampled at
/// each request: the progress counter is compared with what the previous request saw.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Heartbeat {
    pub shard: String,
    /// The holder label it took the shard as (`machine:pid:start`).
    pub owner: String,
    pub epoch: i64,
    /// Its runtime's progress counter.
    pub progress: u64,
    /// The host can't be trusted to hold its shard: its progress counter hasn't moved for
    /// [`STUCK_SECS`], or its lease thread hasn't been through its loop for [`LEASE_STALE_RENEWALS`]
    /// renewals (dead or wedged), or the lease thread found the shard taken.
    pub stuck: bool,
    /// The lease thread has been through its loop recently (an attempt that failed on a busy ledger
    /// counts: a stall isn't a dead thread).
    pub lease_ok: bool,
    /// The lease thread found the shard taken at a higher epoch.
    pub lost: bool,
}

/// How long a host's progress counter may stand still before its heartbeat says it is stuck: three
/// of its one-second ticks.
pub const STUCK_SECS: u64 = 3;

/// How many renewal intervals the lease thread may go without finishing a pass through its loop
/// before the heartbeat says so: a pass is a sleep and one attempt, and an attempt on a busy ledger
/// can take its 5 s busy timeout, so two would be too tight.
pub const LEASE_STALE_RENEWALS: u32 = 3;

/// Whether `shard` is a shard's name: a number, as [`shard_name`] makes them. It goes into a path.
pub fn valid_shard(shard: &str) -> bool {
    !shard.is_empty() && shard.len() <= 4 && shard.bytes().all(|b| b.is_ascii_digit())
}

/// Where shard `shard`'s host answers its heartbeat, under the data directory.
pub fn heartbeat_socket(data_dir: &std::path::Path, shard: &str) -> std::path::PathBuf {
    data_dir.join("supervise").join(format!("{shard}.sock"))
}

/// Asks a host for its heartbeat (what wicketd does every [`RENEW_SECS`]), with a deadline.
pub fn heartbeat(sock: &std::path::Path, timeout: std::time::Duration) -> anyhow::Result<Heartbeat> {
    use std::io::BufRead;
    let s = std::os::unix::net::UnixStream::connect(sock)?;
    s.set_read_timeout(Some(timeout))?;
    let mut line = String::new();
    std::io::BufReader::new(s).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

/// Timings a host runs on: the defaults in production, shorter in tests.
#[derive(Clone, Copy, Debug)]
pub struct HostTimes {
    pub tick: std::time::Duration,
    pub renew: std::time::Duration,
    pub stuck: std::time::Duration,
}

impl Default for HostTimes {
    fn default() -> Self {
        HostTimes {
            tick: std::time::Duration::from_secs(1),
            renew: std::time::Duration::from_secs(RENEW_SECS),
            stuck: std::time::Duration::from_secs(STUCK_SECS),
        }
    }
}

/// Why a host ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// Asked to stop (SIGTERM, an update): the clean-stop marker was written.
    Stopped,
    /// Its shard was taken at a higher epoch: it leaves without writing anything.
    Lost,
}

/// The lease thread's liveness: when (ms after the host started) it last finished a pass.
#[derive(Clone)]
struct Pulse {
    born: std::time::Instant,
    at_ms: Arc<AtomicU64>,
}

impl Pulse {
    fn new() -> Pulse {
        Pulse { born: std::time::Instant::now(), at_ms: Arc::new(AtomicU64::new(0)) }
    }
    fn beat(&self) {
        self.at_ms.store(self.born.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    fn age(&self) -> std::time::Duration {
        self.born.elapsed().saturating_sub(std::time::Duration::from_millis(self.at_ms.load(Ordering::Relaxed)))
    }
}

/// A running host: holds its shard, renews its lease from a thread of its own, and answers its
/// heartbeat from another. It supervises no runs yet (note 25, §5.1: runs move into hosts later).
pub struct Host {
    pub lease: Lease,
    progress: Progress,
    lost: Arc<std::sync::atomic::AtomicBool>,
    /// Ends the heartbeat thread.
    stop: Arc<std::sync::atomic::AtomicBool>,
    /// Ends the lease thread (its own flag, so a test can end it alone, as a panic would).
    lease_stop: Arc<std::sync::atomic::AtomicBool>,
    lease_thread: std::thread::JoinHandle<()>,
    heartbeat_thread: Option<std::thread::JoinHandle<()>>,
    /// The listener's fd, to wake its accept on a stop (`shutdown`).
    listener_fd: std::os::fd::RawFd,
    /// The socket this host bound: its path and inode, so only that one is ever unlinked (a
    /// successor binds the same path).
    sock: (std::path::PathBuf, u64, u64),
    ledger_path: std::path::PathBuf,
}

impl Host {
    /// Takes `shard` (with `nodes`) for this process as `owner`, then starts its lease and heartbeat
    /// threads. Only a free shard ([`Ledger::take_free_shard`]): one held by another process, lapsed
    /// or not, is refused with [`StoreError::ShardHeld`] and left to wicketd's fence.
    pub fn start(
        ledger_path: &std::path::Path,
        sock: &std::path::Path,
        shard: &str,
        owner: &str,
        nodes: &[&str],
        times: HostTimes,
    ) -> anyhow::Result<Host> {
        anyhow::ensure!(valid_shard(shard), "{shard:?} isn't a shard (a number)");
        let progress = Progress::default();
        let lease = {
            let l = Ledger::open(ledger_path)?;
            let t = l.take_free_shard(shard, owner, nodes, LEASE_SECS, wicket_store::now())?;
            Lease { shard: shard.into(), owner: owner.into(), epoch: t.epoch, seen: progress.get() }
        };
        let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let lease_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pulse = Pulse::new();
        // The lease thread: its own ledger connection and its own small transaction, so a stalled
        // batch elsewhere in the host can't lapse it. It leaves only when the shard is taken, or on a
        // stop. Every pass, renewed or not, moves its pulse.
        let lease_thread = {
            let (mut lease, progress, lost, stop, path, pulse) =
                (lease.clone(), progress.clone(), lost.clone(), lease_stop.clone(), ledger_path.to_path_buf(), pulse.clone());
            std::thread::Builder::new().name(format!("lease-{shard}")).spawn(move || {
                let mut l = None;
                pulse.beat();
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(times.renew);
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if l.is_none() {
                        l = Ledger::open(&path).ok();
                    }
                    if let Some(ledger) = &l {
                        match lease.renew(ledger, progress.get(), wicket_store::now()) {
                            Renewal::Lost => {
                                lost.store(true, Ordering::Relaxed);
                                pulse.beat();
                                break;
                            }
                            Renewal::Failed => l = None,
                            Renewal::Renewed | Renewal::Stuck => {}
                        }
                    }
                    pulse.beat();
                }
            })?
        };
        // The heartbeat thread: atomics only, never the ledger.
        if let Some(dir) = sock.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        }
        // This host holds the shard (it was free), so a socket left there is a dead holder's.
        let _ = std::fs::remove_file(sock);
        let listener = std::os::unix::net::UnixListener::bind(sock)?;
        std::fs::set_permissions(sock, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        let meta = std::os::unix::fs::MetadataExt::ino(&std::fs::symlink_metadata(sock)?);
        let dev = std::os::unix::fs::MetadataExt::dev(&std::fs::symlink_metadata(sock)?);
        let listener_fd = std::os::fd::AsRawFd::as_raw_fd(&listener);
        let heartbeat_thread = {
            let (beat, progress, stop, lost, pulse) = (lease.clone(), progress.clone(), stop.clone(), lost.clone(), pulse.clone());
            let stale = times.renew * LEASE_STALE_RENEWALS;
            std::thread::Builder::new().name(format!("heartbeat-{shard}")).spawn(move || {
                let (mut last, mut moved_at) = (progress.get(), std::time::Instant::now());
                for conn in listener.incoming() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(mut conn) = conn else { continue };
                    let now = progress.get();
                    if now != last {
                        (last, moved_at) = (now, std::time::Instant::now());
                    }
                    let lease_ok = pulse.age() < stale;
                    let lost = lost.load(Ordering::Relaxed);
                    let hb = Heartbeat {
                        shard: beat.shard.clone(),
                        owner: beat.owner.clone(),
                        epoch: beat.epoch,
                        progress: now,
                        stuck: moved_at.elapsed() >= times.stuck || !lease_ok || lost,
                        lease_ok,
                        lost,
                    };
                    // One write: a reader sees the whole line or nothing.
                    let mut line = serde_json::to_vec(&hb).unwrap_or_default();
                    line.push(b'\n');
                    let _ = std::io::Write::write_all(&mut conn, &line);
                }
            })?
        };
        Ok(Host {
            lease,
            progress,
            lost,
            stop,
            lease_stop,
            lease_thread,
            heartbeat_thread: Some(heartbeat_thread),
            listener_fd,
            sock: (sock.to_path_buf(), dev, meta),
            ledger_path: ledger_path.to_path_buf(),
        })
    }

    /// The runtime's progress counter: a task on the host's runtime ticks it ([`Host::run`]).
    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    /// Whether the lease thread found the shard taken.
    pub fn lost(&self) -> bool {
        self.lost.load(Ordering::Relaxed)
    }

    /// Runs the host until `stop` resolves (a signal) or its shard is lost: ticks the progress
    /// counter every `times.tick` on this runtime, then stops (writing the clean-stop marker unless
    /// the shard was lost). A lease thread that ended without finding the shard lost (it panicked) is
    /// an error: the host can no longer renew or learn that it was fenced.
    pub async fn run(self, times: HostTimes, stop: impl std::future::Future<Output = ()>) -> anyhow::Result<Ended> {
        tokio::pin!(stop);
        let mut tick = tokio::time::interval(times.tick);
        let ended = loop {
            tokio::select! {
                _ = &mut stop => break Ended::Stopped,
                _ = tick.tick() => {
                    if self.lost() {
                        break Ended::Lost;
                    }
                    if self.lease_thread.is_finished() {
                        self.quiet();
                        anyhow::bail!("shard {}: its lease thread ended without losing the shard", self.lease.shard);
                    }
                    self.progress.tick();
                }
            }
        };
        self.finish(ended)
    }

    /// Stops answering (the heartbeat thread is woken and ends) and unlinks the socket, only if it
    /// is still the one this host bound.
    fn quiet(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.lease_stop.store(true, Ordering::Relaxed);
        // SAFETY: a plain syscall on this host's own listener; it wakes the blocked accept.
        unsafe { libc::shutdown(self.listener_fd, libc::SHUT_RDWR) };
        let (path, dev, ino) = &self.sock;
        if let Ok(m) = std::fs::symlink_metadata(path) {
            if std::os::unix::fs::MetadataExt::dev(&m) == *dev && std::os::unix::fs::MetadataExt::ino(&m) == *ino {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// Stops the host: its heartbeat first (and its socket, if still its own), then, for a planned
    /// stop, the clean-stop marker.
    pub fn finish(mut self, ended: Ended) -> anyhow::Result<Ended> {
        self.quiet();
        if let Some(t) = self.heartbeat_thread.take() {
            let _ = t.join();
        }
        if ended == Ended::Stopped {
            let l = Ledger::open(&self.ledger_path)?;
            if !l.mark_shard_stopping(&self.lease.shard, &self.lease.owner, self.lease.epoch, wicket_store::now())? {
                say_err!("[supervise] shard {}: not marked stopping: it was taken at a higher epoch meanwhile", self.lease.shard);
            }
        }
        Ok(ended)
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

    /// What `owner_alive` says of a process wicketd didn't start.
    fn alive(_: &str) -> Option<bool> {
        Some(true)
    }
    fn dead(_: &str) -> Option<bool> {
        Some(false)
    }
    fn unknown(_: &str) -> Option<bool> {
        None
    }

    #[test]
    fn wicketd_starts_missing_hosts_and_leaves_live_ones() {
        let mut f = Fencer::default();
        assert_eq!(f.decide(&shards(), &[], &BTreeMap::new(), &alive, 100), [Action::Start("0".into()), Action::Start("1".into())]);
        let procs = BTreeMap::from([("0".into(), proc("0", 100)), ("1".into(), proc("1", 100))]);
        assert!(f.decide(&shards(), &[host("0", 130), host("1", 130)], &procs, &alive, 105).is_empty());
    }

    #[test]
    fn an_exited_holder_is_fenced_at_once_and_a_late_reap_names_the_old_holder() {
        let mut f = Fencer::default();
        let mut procs = BTreeMap::from([("0".into(), proc("0", 100)), ("1".into(), proc("1", 100))]);
        procs.get_mut("0").unwrap().exited = true;
        assert_eq!(f.decide(&shards(), &[host("0", 130), host("1", 130)], &procs, &alive, 101), [fence("0", true)]);
        // The shard was fenced and a fresh host (m:9:9) holds it; the old process is reaped only now:
        // the reap isn't the holder on record, so the fresh one is judged on its own process.
        let mut fresh = host("0", 140);
        fresh.owner = Some("m:9:9".into());
        procs.insert("0".into(), Proc { owner: "m:0:1".into(), ok_at: 100, exited: true });
        assert_eq!(f.decide(&shards(), &[fresh, host("1", 140)], &procs, &alive, 111), [Action::Watch("0".into())]);
    }

    #[test]
    fn after_wicketd_restarts_a_running_holder_is_watched_until_its_lease_lapses_alone() {
        for holder_alive in [alive as fn(&str) -> Option<bool>, unknown] {
            let mut f = Fencer::default();
            // Both live: watched.
            let hosts = [host("0", 130), host("1", 130)];
            assert_eq!(
                f.decide(&shards(), &hosts, &BTreeMap::new(), &holder_alive, 101),
                [Action::Watch("0".into()), Action::Watch("1".into())]
            );
            // 0 lapses while 1 renews: watched through the window, then fenced (not gone).
            let hosts = [host("0", 130), host("1", 150)];
            assert_eq!(
                f.decide(&shards(), &hosts, &BTreeMap::new(), &holder_alive, 131),
                [Action::Watch("0".into()), Action::Watch("1".into())]
            );
            let hosts = [host("0", 130), host("1", 170)];
            assert_eq!(
                f.decide(&shards(), &hosts, &BTreeMap::new(), &holder_alive, 131 + STALL_WINDOW_SECS - 1),
                [Action::Watch("0".into()), Action::Watch("1".into())]
            );
            assert_eq!(
                f.decide(&shards(), &hosts, &BTreeMap::new(), &holder_alive, 131 + STALL_WINDOW_SECS),
                [fence("0", false), Action::Watch("1".into())]
            );
        }
    }

    #[test]
    fn holders_wicketd_cant_tell_about_are_watched_when_every_lease_has_lapsed() {
        // A stall, or every holder elsewhere: nothing to tell one from the other, so no fence, however
        // long, until one renews and another doesn't.
        for holder_alive in [alive as fn(&str) -> Option<bool>, unknown] {
            let mut f = Fencer::default();
            let hosts = [host("0", 100), host("1", 100)];
            for now in [101, 200, 5_000] {
                assert_eq!(
                    f.decide(&shards(), &hosts, &BTreeMap::new(), &holder_alive, now),
                    [Action::Watch("0".into()), Action::Watch("1".into())]
                );
            }
        }
    }

    #[test]
    fn after_a_reboot_every_lapsed_shard_of_a_gone_holder_is_fenced_and_started() {
        let mut f = Fencer::default();
        // Every lease lapsed long ago, no process known, every holder's process gone.
        let hosts = [host("0", 100), host("1", 100)];
        assert_eq!(f.decide(&shards(), &hosts, &BTreeMap::new(), &dead, 5_000), [fence("0", true), fence("1", true)]);
        // Once fenced (no holder), started.
        let mut fenced = hosts.clone();
        for h in &mut fenced {
            h.owner = None;
        }
        assert_eq!(f.decide(&shards(), &fenced, &BTreeMap::new(), &dead, 5_001), [Action::Start("0".into()), Action::Start("1".into())]);
    }

    #[test]
    fn a_single_wedged_host_is_fenced_without_another_to_compare() {
        let one = vec!["0".to_string()];
        let mut f = Fencer::default();
        // Its heartbeat stopped at 100 and its lease lapsed at 130: no other lease is live.
        let procs = BTreeMap::from([("0".into(), proc("0", 100))]);
        assert!(f.decide(&one, &[host("0", 130)], &procs, &alive, 131).is_empty());
        assert_eq!(f.decide(&one, &[host("0", 130)], &procs, &alive, 131 + STALL_WINDOW_SECS), [fence("0", false)]);
    }

    #[test]
    fn the_moment_a_ledger_stall_ends_fences_no_one() {
        let mut f = Fencer::default();
        // A stall from 70 to 130: both leases (to 100) lapsed. The heartbeats are off the ledger and
        // go on answering, so neither host is fenced, however long the stall.
        let at = |t| BTreeMap::from([("0".into(), proc("0", t)), ("1".into(), proc("1", t))]);
        assert!(f.decide(&shards(), &[host("0", 100), host("1", 100)], &at(119), &alive, 120).is_empty());
        assert!(f.decide(&shards(), &[host("0", 100), host("1", 100)], &at(129), &alive, 129).is_empty());
        // At 130 host 1 renews first: host 0 looks lapsed alone for a moment; still nothing.
        assert!(f.decide(&shards(), &[host("0", 100), host("1", 160)], &at(130), &alive, 130).is_empty());
        assert!(f.decide(&shards(), &[host("0", 164), host("1", 160)], &at(134), &alive, 134).is_empty());
    }

    #[test]
    fn a_heartbeating_host_is_not_fenced_for_a_lapse_and_a_stopping_one_has_a_time_limit() {
        let mut f = Fencer::default();
        // Lapsed alone for the window, but its heartbeat says its runtime moves: its renewals are
        // failing for a reason of its own; not fenced while it answers.
        let procs = BTreeMap::from([("0".into(), proc("0", 150)), ("1".into(), proc("1", 150))]);
        f.decide(&shards(), &[host("0", 100), host("1", 160)], &procs, &alive, 131);
        assert!(f.decide(&shards(), &[host("0", 100), host("1", 175)], &procs, &alive, 150).is_empty());
        // Stopping: left alone while it exits, fenced after STOP_SECS if it doesn't, started again
        // once it has.
        let mut stopping = host("0", 160);
        stopping.stopping = true;
        stopping.updated_at = 140;
        let hosts = [stopping.clone(), host("1", 175)];
        assert!(f.decide(&shards(), &hosts, &procs, &alive, 150).is_empty());
        assert_eq!(f.decide(&shards(), &hosts, &procs, &alive, 140 + STOP_SECS), [fence("0", false)]);
        let mut gone = procs.clone();
        gone.get_mut("0").unwrap().exited = true;
        assert_eq!(f.decide(&shards(), &hosts, &gone, &alive, 150), [Action::Start("0".into())]);
        // A stopping holder wicketd didn't start, gone: started.
        assert_eq!(f.decide(&shards(), &hosts, &BTreeMap::new(), &dead, 150)[0], Action::Start("0".into()));
    }

    /// A test's directory, removed when it ends.
    struct TestDir(std::path::PathBuf);

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn host_dir(tag: &str) -> TestDir {
        let d = std::env::temp_dir().join(format!("wsup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        TestDir(d)
    }

    fn fast() -> HostTimes {
        HostTimes {
            tick: std::time::Duration::from_millis(20),
            renew: std::time::Duration::from_millis(50),
            stuck: std::time::Duration::from_millis(200),
        }
    }

    fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
        let t = std::time::Instant::now();
        while !f() {
            assert!(t.elapsed() < std::time::Duration::from_secs(10), "{what}");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    /// `host.run` with no stop signal, bounded by a deadline.
    fn run_until_it_ends(host: Host) -> anyhow::Result<Ended> {
        rt().block_on(async { tokio::time::timeout(std::time::Duration::from_secs(10), host.run(fast(), std::future::pending())).await })
            .expect("the host ended within 10 s")
    }

    #[test]
    fn a_host_holds_its_shard_answers_heartbeats_and_stops_cleanly() {
        let d = host_dir("clean");
        let (db, sock) = (d.0.join("ledger.db"), heartbeat_socket(&d.0, "0"));
        let host = Host::start(&db, &sock, "0", "m:1:1", &["n1"], fast()).unwrap();
        assert_eq!(host.lease.epoch, 1);
        // A second host of the same shard is refused while it is held.
        let other = Host::start(&db, &heartbeat_socket(&d.0, "9"), "0", "m:2:2", &["n1"], fast());
        assert!(matches!(other.err().and_then(|e| e.downcast::<StoreError>().ok()), Some(StoreError::ShardHeld(..))));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let runner = std::thread::spawn(move || {
            rt().block_on(host.run(fast(), async {
                let _ = rx.await;
            }))
        });
        // Its heartbeat answers with its holder and epoch, its runtime moving, its lease thread alive.
        let first = heartbeat(&sock, std::time::Duration::from_secs(2)).unwrap();
        assert_eq!((first.shard.as_str(), first.owner.as_str(), first.epoch), ("0", "m:1:1", 1));
        wait_for("progress moves", || heartbeat(&sock, std::time::Duration::from_secs(2)).unwrap().progress > first.progress);
        let hb = heartbeat(&sock, std::time::Duration::from_secs(2)).unwrap();
        assert!(hb.lease_ok && !hb.stuck && !hb.lost, "{hb:?}");
        // Its lease is renewed (while its runtime moves) from its own thread.
        let l = Ledger::open(&db).unwrap();
        let taken = l.supervisor_host("0").unwrap().unwrap().updated_at;
        wait_for("a renewal", || l.supervisor_host("0").unwrap().unwrap().updated_at > taken);
        tx.send(()).unwrap();
        assert_eq!(runner.join().unwrap().unwrap(), Ended::Stopped);
        let rec = l.supervisor_host("0").unwrap().unwrap();
        assert!(rec.stopping, "the clean-stop marker");
        assert!(!sock.exists());
        // Stopped cleanly: the shard is free to take at once.
        assert_eq!(l.take_free_shard("0", "m:3:3", &["n1"], LEASE_SECS, wicket_store::now()).unwrap().epoch, 2);
    }

    #[test]
    fn a_host_whose_shard_is_taken_leaves_without_writing_or_touching_its_successor() {
        let d = host_dir("lost");
        let (db, sock) = (d.0.join("ledger.db"), heartbeat_socket(&d.0, "0"));
        let host = Host::start(&db, &sock, "0", "m:1:1", &["n1"], fast()).unwrap();
        // wicketd fences it, and a fresh host takes the shard and binds the same socket path.
        let l = Ledger::open(&db).unwrap();
        assert_eq!(l.fence_shard("0", "m:1:1", true, wicket_store::now()).unwrap(), Some(2));
        l.take_free_shard("0", "m:9:9", &["n1"], LEASE_SECS, wicket_store::now()).unwrap();
        std::fs::remove_file(&sock).unwrap();
        let successor = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert_eq!(run_until_it_ends(host).unwrap(), Ended::Lost);
        let rec = l.supervisor_host("0").unwrap().unwrap();
        assert_eq!((rec.owner.as_deref(), rec.epoch, rec.stopping), (Some("m:9:9"), 3, false), "the new holder's record is untouched");
        assert!(sock.exists(), "the successor's socket is left alone");
        std::os::unix::net::UnixStream::connect(&sock).unwrap();
        successor.accept().unwrap();
    }

    #[test]
    fn a_host_takes_only_a_free_shard_never_a_lapsed_holders() {
        let d = host_dir("free");
        let db = d.0.join("ledger.db");
        let l = Ledger::open(&db).unwrap();
        // Held by a process whose lease lapsed long ago: still not this host's to take.
        l.take_shard("0", "m:5:5", &["n1"], LEASE_SECS, 1).unwrap();
        let r = Host::start(&db, &heartbeat_socket(&d.0, "0"), "0", "m:1:1", &["n1"], fast());
        assert!(matches!(r.err().and_then(|e| e.downcast::<StoreError>().ok()), Some(StoreError::ShardHeld(_, 0))));
        // And a shard's name goes into a path: only numbers.
        for bad in ["", "../x", "0/1", "a", "12345"] {
            assert!(Host::start(&db, &heartbeat_socket(&d.0, "x"), bad, "m:1:1", &["n1"], fast()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_wedged_runtime_says_stuck_and_stops_renewing_while_the_heartbeat_answers() {
        let d = host_dir("stuck");
        let (db, sock) = (d.0.join("ledger.db"), heartbeat_socket(&d.0, "0"));
        // Started, but its runtime never runs (`run` isn't called): nothing ticks.
        let host = Host::start(&db, &sock, "0", "m:1:1", &["n1"], fast()).unwrap();
        let l = Ledger::open(&db).unwrap();
        let lease_until = l.supervisor_host("0").unwrap().unwrap().lease_until;
        heartbeat(&sock, std::time::Duration::from_secs(2)).unwrap();
        // Over a second, so a renewal (whole seconds in the ledger) would show.
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let hb = heartbeat(&sock, std::time::Duration::from_secs(2)).unwrap();
        assert!(hb.stuck && hb.lease_ok && !hb.lost, "{hb:?}");
        assert_eq!(l.supervisor_host("0").unwrap().unwrap().lease_until, lease_until, "never renewed without progress");
        host.finish(Ended::Lost).unwrap();
    }

    #[test]
    fn a_dead_lease_thread_shows_in_the_heartbeat_and_ends_the_host() {
        let d = host_dir("dead");
        let (db, sock) = (d.0.join("ledger.db"), heartbeat_socket(&d.0, "0"));
        let host = Host::start(&db, &sock, "0", "m:1:1", &["n1"], fast()).unwrap();
        // The lease thread ends without losing the shard (as a panic in it would).
        host.lease_stop.store(true, Ordering::Relaxed);
        wait_for("the lease thread ends", || host.lease_thread.is_finished());
        wait_for("the heartbeat says so", || {
            let hb = heartbeat(&sock, std::time::Duration::from_secs(2)).unwrap();
            !hb.lease_ok && hb.stuck && !hb.lost
        });
        let e = run_until_it_ends(host).unwrap_err();
        assert!(e.to_string().contains("lease thread ended"), "{e}");
        assert!(!sock.exists());
    }
}
