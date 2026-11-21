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

/// A host process as wicketd knows it (one it started, or one found answering on its shard's socket
/// after wicketd restarted): the holder label it took the shard as, its last heartbeat with its
/// runtime moving, and whether it has exited.
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
    /// The heartbeat's format ([`HEARTBEAT_VERSION`]); fields added later default when absent.
    #[serde(default)]
    pub v: u32,
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
    #[serde(default = "yes")]
    pub lease_ok: bool,
    /// The lease thread found the shard taken at a higher epoch.
    #[serde(default)]
    pub lost: bool,
    /// The progress counter alone hasn't moved for [`STUCK_SECS`] (part of `stuck`): wicketd tells a
    /// host whose lease thread waits on a stalled ledger from one whose runtime is wedged by it.
    #[serde(default)]
    pub runtime_stuck: bool,
}

/// The heartbeat's format: 1 has `lease_ok`, `lost` and `runtime_stuck`.
pub const HEARTBEAT_VERSION: u32 = 1;

fn yes() -> bool {
    true
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
    /// The listener, shared with the heartbeat thread, so its fd stays open (never reused) until
    /// both are done; a stop shuts it down to wake the thread's accept.
    listener: Arc<std::os::unix::net::UnixListener>,
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
        let listener = Arc::new(listener);
        let heartbeat_thread = {
            let (beat, progress, stop, lost, pulse, listener) =
                (lease.clone(), progress.clone(), stop.clone(), lost.clone(), pulse.clone(), listener.clone());
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
                    let runtime_stuck = moved_at.elapsed() >= times.stuck;
                    let hb = Heartbeat {
                        v: HEARTBEAT_VERSION,
                        shard: beat.shard.clone(),
                        owner: beat.owner.clone(),
                        epoch: beat.epoch,
                        progress: now,
                        stuck: runtime_stuck || !lease_ok || lost,
                        lease_ok,
                        lost,
                        runtime_stuck,
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
            listener,
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
                        // It may have found the shard lost just now, between the check above and this.
                        if self.lost() {
                            break Ended::Lost;
                        }
                        self.quiet(true);
                        anyhow::bail!("shard {}: its lease thread ended without losing the shard", self.lease.shard);
                    }
                    self.progress.tick();
                }
            }
        };
        self.finish(ended)
    }

    /// Stops answering (the heartbeat thread is woken and ends), and with `unlink` removes the
    /// socket, only if it is still the one this host bound. A host that lost its shard leaves the
    /// path alone: its successor may have bound it, and a stale file is removed by the next start.
    fn quiet(&self, unlink: bool) {
        self.stop.store(true, Ordering::Relaxed);
        self.lease_stop.store(true, Ordering::Relaxed);
        // SAFETY: a plain syscall on this host's own listener, which `self.listener` keeps open; it
        // wakes the blocked accept.
        unsafe { libc::shutdown(std::os::fd::AsRawFd::as_raw_fd(&*self.listener), libc::SHUT_RDWR) };
        if !unlink {
            return;
        }
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
        self.quiet(ended == Ended::Stopped);
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

// ---- wicketd's side: starting, heartbeating and fencing hosts (migration step 1, item 2) ----

/// What the manager does to host processes, so its rules can be tested without them. Processes
/// are named by owner label (`machine:pid:start`), never by pid alone, so a reused pid is never
/// mistaken for a host.
pub trait HostIo {
    /// Starts a host for `shard` with `nodes`; its owner label.
    fn spawn(&mut self, shard: &str, nodes: &[String]) -> anyhow::Result<String>;
    /// Whether the process a label names has gone: no thread of it left. wicketd's own child is
    /// gone only once `waitpid` has reaped it; any other, once nothing runs under its label.
    fn gone(&mut self, owner: &str) -> bool;
    /// Shard `shard`'s heartbeat, if a host answers on its socket.
    fn heartbeat(&mut self, shard: &str) -> Option<Heartbeat>;
    /// SIGKILLs the process a label names, if it is still that process.
    fn kill(&mut self, owner: &str);
    /// SIGTERMs it (a clean stop: it writes its clean-stop marker), if it is still that process.
    fn terminate(&mut self, owner: &str);
    /// Whether the process a label names runs (`wicket_home::owner::owner_alive`).
    fn alive(&self, owner: &str) -> Option<bool>;
    /// What the manager recorded last ([`Record`]), so a wicketd that restarts or re-executes still
    /// kills what it fenced and reaps what it started.
    fn load(&mut self) -> Record;
    /// Records it; an error means it isn't on disk.
    fn save(&mut self, r: &Record) -> anyhow::Result<()>;
    /// Whether the ledger stalls for wicketd too: a small write of its own fails or takes longer
    /// than [`STALL_PROBE`].
    fn ledger_stalled(&mut self, l: &Ledger) -> bool;
}

/// What wicketd's manager keeps across its own restarts and re-execs.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Record {
    /// Holders fenced (or about to be) and killed, whose death hasn't been seen, by shard.
    #[serde(default)]
    pub dying: BTreeMap<String, Vec<String>>,
    /// The host last started for each shard, until it answers or is seen gone.
    #[serde(default)]
    pub started: BTreeMap<String, String>,
}

/// The longest wicketd waits before starting a host for a shard again.
pub const START_BACKOFF_MAX_SECS: i64 = 60;

/// How long a host just started has to take its shard and answer before wicketd gives up on it:
/// it is killed, and a fresh one is started once it is gone (one that fails sooner, exiting, frees
/// the shard at once).
pub const START_GRACE_SECS: i64 = 10;

/// How long the ledger-stall exemption ([`Manager::tick`]) may last: past it, hosts whose lease
/// threads are all stuck are judged as hosts again.
pub const STALL_EXEMPT_MAX_SECS: i64 = 120;

/// How long wicketd's own write probe of the ledger may take before the ledger counts as stalled.
pub const STALL_PROBE: std::time::Duration = std::time::Duration::from_secs(1);

/// wicketd's host manager: one [`Manager::tick`] every [`RENEW_SECS`]. It keeps what it knows of
/// each shard's host process (started by it, found answering on the shard's socket, or, after
/// wicketd restarted, the holder on record if that process runs), asks [`Fencer`] what to do, and
/// does it: start (backed off per shard, and only once every process killed for the shard has
/// gone), or fence (recorded as dying first, then the ledger's epoch, then the kill).
pub struct Manager {
    pub shards: Vec<String>,
    procs: BTreeMap<String, Proc>,
    fencer: Fencer,
    backoff: BTreeMap<String, (i64, i64)>,
    /// A host just started, not yet heard from: its label and when.
    pending: BTreeMap<String, (String, i64)>,
    /// Processes killed for each shard whose death hasn't been seen: no host is started for the
    /// shard until they are gone (two hosts of a shard never overlap, note 25 §3.1).
    dying: BTreeMap<String, Vec<String>>,
    /// What is on disk, to write only what changed.
    saved: Option<Record>,
    /// When this manager first ran: what a holder it never heard from is judged against.
    born: Option<i64>,
    /// Holders of shards outside `shards` (`supervise.hosts` lowered) asked to stop, and when.
    terminated: BTreeMap<String, (String, i64)>,
    /// Since when every answering host's lease thread has been stuck with wicketd's own probe of
    /// the ledger failing (a stall).
    stall_since: Option<i64>,
}

/// What one tick did, for wicketd's log and the tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tick {
    pub started: Vec<String>,
    pub fenced: Vec<String>,
    pub watched: Vec<String>,
    /// Hosts asked to stop: of a shard this manager doesn't run.
    pub stopped: Vec<String>,
    pub errors: Vec<String>,
}

impl Manager {
    /// A manager of `hosts` shards (`0` to `hosts - 1`).
    pub fn new(hosts: usize) -> Manager {
        Manager {
            shards: (0..hosts).map(shard_name).collect(),
            procs: BTreeMap::new(),
            fencer: Fencer::default(),
            backoff: BTreeMap::new(),
            pending: BTreeMap::new(),
            dying: BTreeMap::new(),
            saved: None,
            born: None,
            terminated: BTreeMap::new(),
            stall_since: None,
        }
    }

    fn record(&self) -> Record {
        Record { dying: self.dying.clone(), started: self.pending.iter().map(|(s, (o, _))| (s.clone(), o.clone())).collect() }
    }

    /// Writes the record if it changed; false if it couldn't be written.
    fn save(&mut self, io: &mut dyn HostIo, out: &mut Tick) -> bool {
        let r = self.record();
        if self.saved.as_ref() == Some(&r) {
            return true;
        }
        match io.save(&r) {
            Ok(()) => {
                self.saved = Some(r);
                true
            }
            Err(e) => {
                out.errors.push(format!("recording the supervisor hosts' state: {e}"));
                false
            }
        }
    }

    /// One pass at `now`: learn each shard's process, decide, act.
    pub fn tick(&mut self, l: &Ledger, io: &mut dyn HostIo, now: i64) -> Tick {
        let mut out = Tick::default();
        let hosts = match l.supervisor_hosts() {
            Ok(h) => h,
            Err(e) => {
                // A ledger that can't be read decides nothing: no host is started or fenced on it.
                out.errors.push(format!("reading the supervisor hosts: {e}"));
                return out;
            }
        };
        let holds = |o: &str| hosts.iter().any(|h| h.owner.as_deref() == Some(o));
        let born = match self.born {
            Some(b) => b,
            None => {
                // A previous wicketd's record. A dying holder the ledger still names as a shard's
                // owner was never fenced (the fence didn't land, or wicketd stopped between the
                // record and the fence): left alone, for the rules to judge again. One the ledger
                // no longer names is killed again and waited for. A host started and never heard
                // from is pending again, from now.
                let r = io.load();
                self.saved = Some(r.clone());
                for (shard, list) in r.dying {
                    for o in list.into_iter().filter(|o| !holds(o)) {
                        io.kill(&o);
                        self.dying.entry(shard.clone()).or_default().push(o);
                    }
                }
                for (shard, o) in r.started {
                    self.pending.insert(shard, (o, now));
                }
                self.born = Some(now);
                now
            }
        };
        // The dead, reaped.
        for list in self.dying.values_mut() {
            list.retain(|o| !io.gone(o));
        }
        self.dying.retain(|_, list| !list.is_empty());
        // Each shard's heartbeat, once.
        let beats: BTreeMap<String, Heartbeat> =
            self.shards.iter().filter_map(|s| io.heartbeat(s).filter(|hb| &hb.shard == s).map(|hb| (s.clone(), hb))).collect();
        for s in self.shards.clone() {
            if let Some(p) = self.procs.get_mut(&s) {
                if !p.exited && io.gone(&p.owner) {
                    p.exited = true;
                }
            }
            if let Some((owner, at)) = self.pending.get(&s).cloned() {
                if io.gone(&owner) {
                    self.pending.remove(&s);
                } else if at + START_GRACE_SECS <= now && beats.get(&s).is_none_or(|b| b.owner != owner) {
                    // Never answered: given up on. A host takes its shard before it binds its
                    // socket, so a slow one may hold a live epoch: one the ledger names (read again
                    // now, not from the start of the tick) is left to the rules for a holder never
                    // heard from (below), which fence before they kill. One that doesn't hold it
                    // is killed, and waited for before another starts. (One that takes the shard
                    // between that read and the kill is a dead holder the rules fence as gone, and
                    // no host starts for the shard until every thread of it has gone.)
                    self.pending.remove(&s);
                    match l.supervisor_host(&s) {
                        Ok(Some(h)) if h.owner.as_deref() == Some(owner.as_str()) => {}
                        Ok(_) => {
                            io.kill(&owner);
                            self.dying.entry(s.clone()).or_default().push(owner);
                        }
                        Err(e) => {
                            // Can't tell whether it holds the shard: neither killed nor forgotten.
                            self.pending.insert(s.clone(), (owner, at));
                            out.errors.push(format!("reading shard {s}'s holder: {e}"));
                        }
                    }
                }
            }
            if let Some(hb) = beats.get(&s) {
                if self.pending.get(&s).is_some_and(|(o, _)| o == &hb.owner) {
                    self.pending.remove(&s);
                }
                let p = self.procs.entry(s.clone()).or_insert(Proc { owner: hb.owner.clone(), ok_at: born, exited: false });
                if p.owner != hb.owner {
                    *p = Proc { owner: hb.owner.clone(), ok_at: born, exited: false };
                }
                if !hb.stuck {
                    p.ok_at = now;
                }
            }
        }
        // A host started for a shard this manager no longer runs (`supervise.hosts` lowered, or a
        // record from before): one that holds the shard is left to the rules for such holders
        // (below); one that doesn't is killed and waited for, as one that never answered.
        let gone_shards: Vec<String> = self.pending.keys().filter(|s| !self.shards.contains(s)).cloned().collect();
        for s in gone_shards {
            let Some((owner, _)) = self.pending.remove(&s) else { continue };
            if io.gone(&owner) || hosts.iter().any(|h| h.host == s && h.owner.as_deref() == Some(owner.as_str())) {
                continue;
            }
            io.kill(&owner);
            self.dying.entry(s).or_default().push(owner);
        }
        // A ledger stall shows in every host at once: each lease thread waits on it, so every
        // heartbeat says its lease isn't renewing. Taken as one only when wicketd's own write to the
        // ledger stalls too, and for at most STALL_EXEMPT_MAX_SECS: then a host whose runtime still
        // moves counts as answering. Heartbeats from before version 1 can't say whether their
        // runtime moves, and get no exemption.
        let all_lease_stuck = !beats.is_empty() && beats.values().all(|b| !b.lease_ok && !b.lost);
        let stalled = all_lease_stuck && io.ledger_stalled(l);
        // First seen, kept while every lease thread stays stuck, so a probe that flaps between
        // stalled and not doesn't restart the limit.
        self.stall_since = if !all_lease_stuck {
            None
        } else if stalled {
            Some(self.stall_since.unwrap_or(now))
        } else {
            self.stall_since
        };
        if stalled && self.stall_since.is_some_and(|since| since + STALL_EXEMPT_MAX_SECS > now) {
            for b in beats.values().filter(|b| b.v >= 1 && !b.runtime_stuck) {
                if let Some(p) = self.procs.get_mut(&b.shard) {
                    p.ok_at = now;
                }
            }
        }
        // A holder on record this manager never heard from (wicketd restarted while it ran, or it
        // never answered): if its process runs here, it is judged as a silent host from this
        // manager's start, so a frozen or wedged one is fenced once its lease lapses.
        for h in &hosts {
            if let Some(owner) = h.owner.as_ref().filter(|_| !h.stopping && self.shards.contains(&h.host)) {
                let known = self.procs.get(&h.host).is_some_and(|p| &p.owner == owner);
                if !known && io.alive(owner) == Some(true) {
                    self.procs.insert(h.host.clone(), Proc { owner: owner.clone(), ok_at: born, exited: false });
                }
            }
        }
        // Holders of shards this manager doesn't run (`supervise.hosts` lowered): a gone one is
        // reaped (if it is wicketd's child) and fenced at once, so its nodes can move; a live one is
        // asked to stop, and fenced and killed if it still runs STOP_SECS later. One this machine
        // can't tell about is left alone. Those asked are reaped as they go.
        for h in &hosts {
            if self.shards.contains(&h.host) {
                continue;
            }
            let Some(owner) = h.owner.clone() else { continue };
            match io.alive(&owner) {
                Some(true) => {}
                Some(false) => {
                    io.gone(&owner);
                    if let Ok(Some(_)) = l.fence_shard(&h.host, &owner, true, now) {
                        out.fenced.push(h.host.clone());
                    }
                    continue;
                }
                None => continue,
            }
            match self.terminated.get(&owner).cloned() {
                None => {
                    // One already stopping isn't asked again; it gets the same time to go.
                    if !h.stopping {
                        io.terminate(&owner);
                        out.stopped.push(h.host.clone());
                    }
                    self.terminated.insert(owner, (h.host.clone(), now));
                }
                Some((shard, at)) if at + STOP_SECS <= now => {
                    // Forced (it may still renew its lease): recorded as dying, fenced, then killed,
                    // and waited for as any killed host is. Once fenced it holds nothing, so it is
                    // never fenced twice.
                    if self.dying.get(&shard).is_some_and(|d| d.contains(&owner)) {
                        continue;
                    }
                    self.dying.entry(shard.clone()).or_default().push(owner.clone());
                    if !self.save(io, &mut out) {
                        self.forget_dying(&shard, &owner);
                        continue;
                    }
                    match l.fence_shard(&shard, &owner, true, now) {
                        Ok(Some(_)) => {
                            io.kill(&owner);
                            out.fenced.push(shard);
                        }
                        r => {
                            if let Err(e) = r {
                                out.errors.push(format!("fencing shard {shard}: {e}"));
                            }
                            self.forget_dying(&shard, &owner);
                            self.save(io, &mut out);
                        }
                    }
                }
                Some(_) => {}
            }
        }
        let terminated: Vec<String> = self.terminated.keys().cloned().collect();
        for o in terminated {
            if io.gone(&o) {
                self.terminated.remove(&o);
            }
        }
        let nodes = shard_nodes_now(l, self.shards.len());
        let actions = {
            let io: &dyn HostIo = io;
            self.fencer.decide(&self.shards, &hosts, &self.procs, &|o: &str| io.alive(o), now)
        };
        for a in actions {
            match a {
                Action::Watch(s) => out.watched.push(s),
                Action::Fence { shard, holder, gone } => {
                    // Recorded as dying before the epoch moves, so a restart between the two still
                    // kills it; no record, no fence.
                    if !gone {
                        self.dying.entry(shard.clone()).or_default().push(holder.clone());
                        if !self.save(io, &mut out) {
                            self.forget_dying(&shard, &holder);
                            continue;
                        }
                    }
                    let fenced = l.fence_shard(&shard, &holder, gone, now);
                    if let Ok(Some(_)) = fenced {
                        if !gone {
                            io.kill(&holder);
                        }
                        self.procs.remove(&shard);
                        out.fenced.push(shard);
                        continue;
                    }
                    if let Err(e) = fenced {
                        out.errors.push(format!("fencing shard {shard}: {e}"));
                    }
                    // Not fenced: it isn't dying, and the record says so before anything else.
                    if !gone {
                        self.forget_dying(&shard, &holder);
                        self.save(io, &mut out);
                    }
                }
                Action::Start(shard) => {
                    let (next_at, wait) = self.backoff.get(&shard).copied().unwrap_or((0, 0));
                    if now < next_at || self.pending.contains_key(&shard) || self.dying.contains_key(&shard) {
                        continue;
                    }
                    let i: usize = shard.parse().unwrap_or(0);
                    let shard_nodes = nodes.get(i).map(Vec::as_slice).unwrap_or(&[]);
                    // A shard with no nodes has nothing to supervise: its host starts once one is
                    // enrolled into it.
                    if shard_nodes.is_empty() {
                        continue;
                    }
                    match io.spawn(&shard, shard_nodes) {
                        Ok(owner) => {
                            self.pending.insert(shard.clone(), (owner, now));
                            // A host that keeps dying waits longer each time; one that stays up
                            // for the longest wait resets it (below).
                            let wait = (wait * 2).clamp(1, START_BACKOFF_MAX_SECS);
                            self.backoff.insert(shard.clone(), (now + wait, wait));
                            self.procs.remove(&shard);
                            out.started.push(shard);
                        }
                        Err(e) => out.errors.push(format!("starting shard {shard}'s host: {e}")),
                    }
                }
            }
        }
        self.save(io, &mut out);
        // A shard whose host has been heartbeating for the longest wait starts from 1 s again.
        for (s, p) in &self.procs {
            if !p.exited && p.ok_at > born {
                if let Some((next_at, _)) = self.backoff.get(s).copied() {
                    if now >= next_at + START_BACKOFF_MAX_SECS {
                        self.backoff.remove(s);
                    }
                }
            }
        }
        out
    }

    /// Whether this manager has nothing left in hand: no host starting, dying or asked to stop. With
    /// no shards (`supervise.hosts: 0`) and no holder left in the ledger, wicketd's manager ends.
    pub fn idle(&self) -> bool {
        self.pending.is_empty() && self.dying.is_empty() && self.terminated.is_empty()
    }

    fn forget_dying(&mut self, shard: &str, holder: &str) {
        if let Some(list) = self.dying.get_mut(shard) {
            list.retain(|o| o != holder);
        }
        self.dying.retain(|_, list| !list.is_empty());
    }
}

/// The nodes of each of `hosts` shards now: the local node and every enrolled node ([`assign`]).
fn shard_nodes_now(l: &Ledger, hosts: usize) -> Vec<Vec<String>> {
    let enrolled =
        l.nodes().map(|n| n.into_iter().filter(|n| n.status == "active").map(|n| n.name).collect::<Vec<_>>()).unwrap_or_default();
    assign(std::iter::once(crate::localnode::NAME).chain(enrolled.iter().map(String::as_str)), hosts)
}

/// The real [`HostIo`]: `exe supervise` children, their sockets under `data_dir`, and signals.
pub struct ProcIo {
    pub exe: std::path::PathBuf,
    pub data_dir: std::path::PathBuf,
    /// Extra environment for the children (tests point `WICKET_HOME` at their own directory).
    pub env: Vec<(String, String)>,
    /// The labels it started, the latest [`SPAWNED_KEPT`] (a test stops them all when it ends).
    pub spawned: Vec<String>,
}

/// How many started hosts' labels [`ProcIo`] keeps.
pub const SPAWNED_KEPT: usize = 1024;

/// A pid from an owner label (`machine:pid:start`).
fn pid_of(owner: &str) -> Option<u32> {
    owner.split(':').nth(1)?.parse().ok()
}

impl ProcIo {
    fn record_path(&self) -> std::path::PathBuf {
        self.data_dir.join("supervise").join("manager.json")
    }

    /// The pid a label names, if that process is still the one it names (its start time matches).
    fn still(owner: &str) -> Option<u32> {
        let pid = pid_of(owner)?;
        (wicket_home::owner::owner_label_of(pid).as_deref() == Some(owner)).then_some(pid)
    }

    fn signal(&self, owner: &str, sig: i32) {
        if let Some(pid) = Self::still(owner) {
            // SAFETY: a plain syscall, to the process the label names (checked just above).
            unsafe { libc::kill(pid as i32, sig) };
        }
    }
}

impl HostIo for ProcIo {
    fn spawn(&mut self, shard: &str, nodes: &[String]) -> anyhow::Result<String> {
        let mut c = std::process::Command::new(&self.exe);
        c.arg("supervise").arg("--shard").arg(shard);
        for n in nodes {
            c.arg("--node").arg(n);
        }
        // A host writes only to stderr (wicketd's, the journal's).
        c.envs(self.env.iter().map(|(k, v)| (k, v))).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null());
        let child = c.spawn()?;
        // Reaped by label in `gone`, not through the handle: after a re-exec wicketd has no handles.
        let pid = child.id();
        std::mem::forget(child);
        // Its label now: it is this process's child and can't be reaped before `gone`, so the pid
        // is still its own.
        let owner = wicket_home::owner::owner_label_of(pid).ok_or_else(|| anyhow::anyhow!("host {pid} has no /proc entry"))?;
        self.spawned.push(owner.clone());
        if self.spawned.len() > SPAWNED_KEPT {
            self.spawned.drain(..self.spawned.len() - SPAWNED_KEPT);
        }
        Ok(owner)
    }

    fn gone(&mut self, owner: &str) -> bool {
        // Not that process any more (gone and reaped, its pid reused or free).
        let Some(pid) = Self::still(owner) else { return true };
        let mut status = 0;
        // SAFETY: a plain syscall on the process the label names; WNOHANG never blocks.
        match unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) } {
            // This process's child, reaped: every thread of it gone.
            r if r == pid as i32 => true,
            // This process's child, still there: a thread of it may live on after its main
            // thread (a SIGKILLed host's lease thread in uninterruptible IO).
            0 => false,
            // Not this process's child: gone once nothing of it runs.
            _ => wicket_home::owner::owner_alive(owner) != Some(true),
        }
    }

    fn heartbeat(&mut self, shard: &str) -> Option<Heartbeat> {
        heartbeat(&heartbeat_socket(&self.data_dir, shard), std::time::Duration::from_secs(2)).ok()
    }

    fn kill(&mut self, owner: &str) {
        self.signal(owner, libc::SIGKILL);
    }

    fn terminate(&mut self, owner: &str) {
        self.signal(owner, libc::SIGTERM);
    }

    fn alive(&self, owner: &str) -> Option<bool> {
        wicket_home::owner::owner_alive(owner)
    }

    fn load(&mut self) -> Record {
        std::fs::read(self.record_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn ledger_stalled(&mut self, l: &Ledger) -> bool {
        let t = std::time::Instant::now();
        l.immediate::<_, StoreError>(|_| Ok(())).is_err() || t.elapsed() >= STALL_PROBE
    }

    fn save(&mut self, r: &Record) -> anyhow::Result<()> {
        let p = self.record_path();
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        wicket_chan::files::write_atomic(&p, &serde_json::to_vec(r)?)?;
        Ok(())
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

    /// A ledger with node `n2` enrolled: shard 1 of 2 (FNV-1a, pinned above), so both shards of two
    /// have a node (the local node is shard 0's).
    fn ledger() -> Ledger {
        let l = Ledger::open_in_memory().unwrap();
        l.enrol_builtin_node(&node("n2")).unwrap();
        l
    }

    fn node(name: &str) -> wicket_store::NodeRow {
        wicket_store::NodeRow {
            name: name.into(),
            tenant: "t0".into(),
            target: "local".into(),
            host_key: String::new(),
            host_key_fp: String::new(),
            node_key: "00".into(),
            ssh_key: None,
            hosts: vec![],
            enrolled_at: 0,
            status: "active".into(),
            revoked_at: None,
        }
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

    type OnSave = Box<dyn FnMut(&Record)>;

    /// A fake of host processes, by label (`m:<pid>:1`): which run, which have gone, what each
    /// shard's socket answers; it records what was started, killed and stopped, and the ledger's
    /// epoch for the shard when each kill was issued.
    #[derive(Default)]
    struct FakeIo {
        next_pid: u32,
        spawned: Vec<(String, Vec<String>, String)>,
        beats: BTreeMap<String, Heartbeat>,
        running: std::collections::BTreeSet<String>,
        killed: Vec<(String, Option<i64>)>,
        terminated: Vec<String>,
        record: Record,
        save_fails: bool,
        stalled: bool,
        /// Run on each save, before it lands (a holder renewing meanwhile, say).
        on_save: Option<OnSave>,
        ledger: Option<std::rc::Rc<Ledger>>,
    }

    impl FakeIo {
        fn with(l: &std::rc::Rc<Ledger>) -> FakeIo {
            FakeIo { ledger: Some(l.clone()), ..Default::default() }
        }
        fn dies(&mut self, owner: &str) {
            self.running.remove(owner);
            self.beats.retain(|_, b| b.owner != owner);
        }
        fn killed_labels(&self) -> Vec<String> {
            self.killed.iter().map(|(o, _)| o.clone()).collect()
        }
    }

    impl HostIo for FakeIo {
        fn spawn(&mut self, shard: &str, nodes: &[String]) -> anyhow::Result<String> {
            self.next_pid += 1;
            let owner = format!("m:{}:1", self.next_pid);
            self.running.insert(owner.clone());
            self.spawned.push((shard.into(), nodes.to_vec(), owner.clone()));
            Ok(owner)
        }
        fn gone(&mut self, owner: &str) -> bool {
            !self.running.contains(owner)
        }
        fn heartbeat(&mut self, shard: &str) -> Option<Heartbeat> {
            self.beats.get(shard).cloned()
        }
        fn kill(&mut self, owner: &str) {
            // The epoch of the shard this label holds or held, as the ledger has it at the kill.
            let epoch = self.ledger.as_ref().and_then(|l| {
                l.supervisor_hosts().unwrap().into_iter().find(|h| h.owner.as_deref() == Some(owner) || h.owner.is_none()).map(|h| h.epoch)
            });
            self.killed.push((owner.into(), epoch));
        }
        fn terminate(&mut self, owner: &str) {
            self.terminated.push(owner.into());
        }
        fn alive(&self, owner: &str) -> Option<bool> {
            Some(self.running.contains(owner))
        }
        fn load(&mut self) -> Record {
            self.record.clone()
        }
        fn save(&mut self, r: &Record) -> anyhow::Result<()> {
            if self.save_fails {
                anyhow::bail!("disk full");
            }
            if let Some(f) = self.on_save.as_mut() {
                f(r);
            }
            self.record = r.clone();
            Ok(())
        }
        fn ledger_stalled(&mut self, _: &Ledger) -> bool {
            self.stalled
        }
    }

    fn beat(shard: &str, owner: &str, epoch: i64) -> Heartbeat {
        Heartbeat {
            v: HEARTBEAT_VERSION,
            shard: shard.into(),
            owner: owner.into(),
            epoch,
            progress: 1,
            stuck: false,
            lease_ok: true,
            lost: false,
            runtime_stuck: false,
        }
    }

    /// What a started host does: takes its shard and answers its heartbeat.
    fn host_takes(l: &Ledger, io: &mut FakeIo, shard: &str, owner: &str, now: i64) {
        let t = l.take_shard(shard, owner, &[], LEASE_SECS, now).unwrap();
        io.running.insert(owner.into());
        io.beats.insert(shard.into(), beat(shard, owner, t.epoch));
    }

    fn rc_ledger() -> std::rc::Rc<Ledger> {
        std::rc::Rc::new(ledger())
    }

    #[test]
    fn the_manager_starts_every_shard_with_its_nodes_then_leaves_healthy_hosts_alone() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        let mut m = Manager::new(2);
        let t = m.tick(&l, &mut io, 100);
        assert_eq!(t.started, ["0", "1"]);
        assert!(io.spawned[0].1.iter().any(|n| n == crate::localnode::NAME), "the local node is shard 0's: {:?}", io.spawned);
        host_takes(&l, &mut io, "0", "m:1:1", 100);
        host_takes(&l, &mut io, "1", "m:2:1", 100);
        for now in [105, 110, 115] {
            for (s, o) in [("0", "m:1:1"), ("1", "m:2:1")] {
                l.renew_shard_lease(s, o, 1, LEASE_SECS, now).unwrap();
            }
            assert_eq!(m.tick(&l, &mut io, now), Tick::default(), "at {now}");
        }
        assert_eq!(io.spawned.len(), 2);
    }

    #[test]
    fn after_wicketd_restarts_it_adopts_answering_hosts_instead_of_starting_more() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        host_takes(&l, &mut io, "0", "m:7:1", 100);
        host_takes(&l, &mut io, "1", "m:8:1", 100);
        let mut m = Manager::new(2);
        assert_eq!(m.tick(&l, &mut io, 101), Tick::default());
        assert!(io.spawned.is_empty());
    }

    #[test]
    fn an_exited_host_is_fenced_without_a_kill_and_started_again_backed_off() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        let mut m = Manager::new(2);
        m.tick(&l, &mut io, 100);
        host_takes(&l, &mut io, "0", "m:1:1", 100);
        host_takes(&l, &mut io, "1", "m:2:1", 100);
        m.tick(&l, &mut io, 101);
        io.dies("m:1:1");
        assert_eq!(m.tick(&l, &mut io, 102).fenced, ["0"]);
        assert!(io.killed.is_empty(), "a gone process isn't killed");
        assert_eq!(l.supervisor_host("0").unwrap().unwrap().epoch, 2, "the fence raised the epoch");
        // Started again (its first start was 2 s ago, past its 1 s), then each fresh host dies at once:
        // each start waits twice as long as the one before.
        assert_eq!(m.tick(&l, &mut io, 102).started, ["0"]);
        let mut starts = vec![102];
        for now in 103..=120 {
            let last = io.spawned.last().unwrap().2.clone();
            io.dies(&last);
            if m.tick(&l, &mut io, now).started == ["0"] {
                starts.push(now);
            }
        }
        assert_eq!(starts, [102, 104, 108, 116], "backed off: 2, 4, 8 s");
    }

    #[test]
    fn a_wedged_host_is_killed_only_after_its_epoch_moved_and_replaced_only_once_dead() {
        for hosts in [1, 2] {
            let l = rc_ledger();
            let mut io = FakeIo::with(&l);
            let mut m = Manager::new(hosts);
            host_takes(&l, &mut io, "0", "m:1:1", 100);
            if hosts == 2 {
                host_takes(&l, &mut io, "1", "m:2:1", 100);
            }
            m.tick(&l, &mut io, 101);
            // It wedges: stuck, and its lease lapses at 130.
            io.beats.get_mut("0").unwrap().stuck = true;
            io.beats.get_mut("0").unwrap().runtime_stuck = true;
            let mut fenced_at = None;
            for now in (105..=200).step_by(5) {
                if hosts == 2 {
                    l.renew_shard_lease("1", "m:2:1", 1, LEASE_SECS, now).unwrap();
                }
                if m.tick(&l, &mut io, now).fenced == ["0"] {
                    fenced_at = Some(now);
                    break;
                }
            }
            let at = fenced_at.unwrap_or_else(|| panic!("{hosts} host(s): never fenced"));
            assert!(at >= 130 + STALL_WINDOW_SECS, "{hosts} host(s): fenced at {at}, before its lease had lapsed for the window");
            assert_eq!(io.killed, [("m:1:1".to_string(), Some(2))], "{hosts} host(s): killed once the ledger had epoch 2");
            assert_eq!(io.record.dying["0"], ["m:1:1"], "recorded as dying");
            // Still running (a D-state process, say): no fresh host for shard 0 meanwhile.
            for now in at + 1..at + 30 {
                assert!(
                    !m.tick(&l, &mut io, now).started.contains(&"0".to_string()),
                    "{hosts} host(s): started at {now} before the old one died"
                );
            }
            io.dies("m:1:1");
            assert_eq!(m.tick(&l, &mut io, at + 30).started, ["0"], "{hosts} host(s): started once it died");
            assert!(io.record.dying.is_empty());
        }
    }

    #[test]
    fn after_a_restart_a_silent_or_frozen_holder_is_fenced_and_a_zombie_at_once() {
        // Silent or frozen (SIGSTOP): its process runs, its socket never answers. One shard, so no
        // live peer to compare it with.
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        l.take_shard("0", "m:5:1", &[], LEASE_SECS, 100).unwrap();
        io.running.insert("m:5:1".into());
        let mut m = Manager::new(1);
        let mut fenced_at = None;
        for now in (101..=300).step_by(5) {
            let t = m.tick(&l, &mut io, now);
            assert!(t.started.is_empty() || fenced_at.is_some(), "a second host started beside it at {now}");
            if t.fenced == ["0"] {
                fenced_at = Some(now);
                break;
            }
        }
        let at = fenced_at.expect("the silent holder is fenced");
        assert!(at >= 130 + STALL_WINDOW_SECS, "fenced at {at}, before its lease (to 130) had lapsed for the window");
        assert_eq!(io.killed_labels(), ["m:5:1"]);
        // A zombie: it exited (owner_alive says so) but nobody reaped it. Fenced at once, no kill.
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        l.take_shard("0", "m:6:1", &[], LEASE_SECS, 100).unwrap();
        let t = Manager::new(1).tick(&l, &mut io, 101);
        assert_eq!(t.fenced, ["0"]);
        assert!(io.killed.is_empty());
    }

    #[test]
    fn a_ledger_stall_that_blocks_every_lease_thread_fences_no_one_but_a_wedged_runtime() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        let mut m = Manager::new(2);
        host_takes(&l, &mut io, "0", "m:1:1", 100);
        host_takes(&l, &mut io, "1", "m:2:1", 100);
        m.tick(&l, &mut io, 101);
        // The ledger stalls: both lease threads wait on it, both heartbeats say so, both leases lapse,
        // and wicketd's own write stalls too.
        io.stalled = true;
        for b in io.beats.values_mut() {
            (b.stuck, b.lease_ok) = (true, false);
        }
        for now in (105..=150).step_by(5) {
            assert!(m.tick(&l, &mut io, now).fenced.is_empty(), "fenced at {now} for a stall");
        }
        // Shard 0's runtime wedges too: that one is the host's own, and it is fenced, inside the
        // exemption (which ends at 105 + STALL_EXEMPT_MAX_SECS), while shard 1 isn't.
        io.beats.get_mut("0").unwrap().runtime_stuck = true;
        let fenced = (155..105 + STALL_EXEMPT_MAX_SECS).step_by(5).find(|&now| {
            let t = m.tick(&l, &mut io, now);
            assert!(!t.fenced.contains(&"1".to_string()), "shard 1 fenced at {now}, inside the exemption");
            t.fenced == ["0"]
        });
        assert!(fenced.is_some(), "a wedged runtime is fenced even in a stall");
    }

    #[test]
    fn a_restarted_wicketd_kills_what_it_had_fenced_and_waits_for_it() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        // A previous wicketd fenced shard 0's holder and was restarted before its kill landed.
        io.running.insert("m:3:1".into());
        io.record.dying = BTreeMap::from([("0".to_string(), vec!["m:3:1".to_string()])]);
        let mut m = Manager::new(1);
        let t = m.tick(&l, &mut io, 100);
        assert_eq!(io.killed_labels(), ["m:3:1"], "killed again on start");
        assert!(t.started.is_empty(), "no host while the fenced one lives");
        io.dies("m:3:1");
        assert_eq!(m.tick(&l, &mut io, 101).started, ["0"]);
        assert!(io.record.dying.is_empty());
    }

    #[test]
    fn a_starting_host_that_never_answers_is_killed_and_replaced_once_dead() {
        let l = std::rc::Rc::new(Ledger::open_in_memory().unwrap());
        let mut io = FakeIo::with(&l);
        let mut m = Manager::new(1);
        assert_eq!(m.tick(&l, &mut io, 100).started, ["0"]);
        for now in 101..100 + START_GRACE_SECS {
            assert!(m.tick(&l, &mut io, now).started.is_empty(), "at {now}");
        }
        // The grace has passed with no answer: killed, and waited for.
        m.tick(&l, &mut io, 100 + START_GRACE_SECS);
        assert_eq!(io.killed_labels(), ["m:1:1"]);
        assert!(m.tick(&l, &mut io, 100 + START_GRACE_SECS + 5).started.is_empty(), "not while it lives");
        io.dies("m:1:1");
        assert_eq!(m.tick(&l, &mut io, 100 + START_GRACE_SECS + 6).started, ["0"]);
    }

    #[test]
    fn a_shard_without_nodes_gets_no_host_until_one_is_enrolled() {
        let l = std::rc::Rc::new(Ledger::open_in_memory().unwrap());
        let mut io = FakeIo::with(&l);
        let mut m = Manager::new(2);
        // Only the local node, shard 0's: shard 1 has nothing to supervise.
        assert_eq!(m.tick(&l, &mut io, 100).started, ["0"]);
        l.enrol_builtin_node(&node("n2")).unwrap();
        assert_eq!(m.tick(&l, &mut io, 101).started, ["1"]);
    }

    #[test]
    fn hosts_of_shards_outside_the_setting_are_asked_to_stop_once() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        // supervise.hosts was 3, now 2: shard 2's host still runs.
        host_takes(&l, &mut io, "2", "m:9:1", 100);
        let mut m = Manager::new(2);
        assert_eq!(m.tick(&l, &mut io, 101).stopped, ["2"]);
        assert!(m.tick(&l, &mut io, 102).stopped.is_empty(), "once");
        assert_eq!(io.terminated, ["m:9:1"]);
        assert!(!io.spawned.iter().any(|(s, ..)| s == "2"));
    }

    #[test]
    fn a_late_reap_of_an_old_host_doesnt_fence_its_successor() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        let mut m = Manager::new(1);
        host_takes(&l, &mut io, "0", "m:1:1", 100);
        m.tick(&l, &mut io, 101);
        // Another process took over (the old one fenced elsewhere and replaced); the old one is
        // seen gone only now.
        l.fence_shard("0", "m:1:1", true, 102).unwrap();
        host_takes(&l, &mut io, "0", "m:9:1", 102);
        io.dies("m:1:1");
        let t = m.tick(&l, &mut io, 103);
        assert!(t.fenced.is_empty() && t.started.is_empty(), "{t:?}");
    }

    #[test]
    fn an_older_heartbeat_without_the_new_fields_still_reads() {
        let hb: Heartbeat = serde_json::from_str(r#"{"shard":"0","owner":"m:1:1","epoch":1,"progress":3,"stuck":false}"#).unwrap();
        assert_eq!((hb.v, hb.lease_ok, hb.lost, hb.runtime_stuck), (0, true, false, false));
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

    /// One host whose lease thread is stuck, its runtime moving (as an IO hang in the lease thread
    /// alone would leave it), its lease lapsing at 130.
    fn one_lease_stuck_host(stalled: bool) -> (std::rc::Rc<Ledger>, FakeIo, Manager) {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        io.stalled = stalled;
        host_takes(&l, &mut io, "0", "m:1:1", 100);
        let b = io.beats.get_mut("0").unwrap();
        (b.stuck, b.lease_ok) = (true, false);
        let mut m = Manager::new(1);
        m.tick(&l, &mut io, 101);
        (l, io, m)
    }

    #[test]
    fn one_host_with_a_stuck_lease_thread_is_fenced_unless_wicketds_own_write_stalls_too() {
        // wicketd's write goes through: it isn't the ledger. Fenced once lapsed for the window.
        let (l, mut io, mut m) = one_lease_stuck_host(false);
        let at = (105..=400).step_by(5).find(|&now| m.tick(&l, &mut io, now).fenced == ["0"]);
        assert!(at.is_some_and(|at| at >= 130 + STALL_WINDOW_SECS), "{at:?}");
        // wicketd's write stalls too: exempt, but only for STALL_EXEMPT_MAX_SECS.
        let (l, mut io, mut m) = one_lease_stuck_host(true);
        let at = (105..=600).step_by(5).find(|&now| m.tick(&l, &mut io, now).fenced == ["0"]).expect("fenced in the end");
        assert!(at >= 105 + STALL_EXEMPT_MAX_SECS, "fenced at {at}, inside the exemption");
    }

    #[test]
    fn an_older_hosts_heartbeat_gets_no_stall_exemption() {
        let (l, mut io, mut m) = one_lease_stuck_host(true);
        io.beats.get_mut("0").unwrap().v = 0;
        let at = (105..=400).step_by(5).find(|&now| m.tick(&l, &mut io, now).fenced == ["0"]);
        assert!(at.is_some_and(|at| at < 105 + STALL_EXEMPT_MAX_SECS), "{at:?}");
    }

    #[test]
    fn a_fence_that_doesnt_land_leaves_no_record_and_a_restart_kills_nothing() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        host_takes(&l, &mut io, "0", "m:1:1", 100);
        io.beats.get_mut("0").unwrap().stuck = true;
        io.beats.get_mut("0").unwrap().runtime_stuck = true;
        // The holder renews between the record and the fence, so the fence doesn't land.
        let renewer = l.clone();
        io.on_save = Some(Box::new(move |r: &Record| {
            if r.dying.contains_key("0") {
                renewer.renew_shard_lease("0", "m:1:1", 1, LEASE_SECS, 1_000).unwrap();
            }
        }));
        let mut m = Manager::new(1);
        let mut tried = false;
        for now in (101..=200).step_by(5) {
            let t = m.tick(&l, &mut io, now);
            assert!(t.fenced.is_empty(), "the fence landed at {now}");
            tried |= io.record.dying.is_empty() && l.supervisor_host("0").unwrap().unwrap().lease_until > 200;
        }
        assert!(tried, "the fence was tried");
        assert!(io.killed.is_empty() && io.record.dying.is_empty(), "{:?} {:?}", io.killed, io.record);
        // A restart: nothing to kill.
        io.on_save = None;
        Manager::new(1).tick(&l, &mut io, 201);
        assert!(io.killed.is_empty());
    }

    #[test]
    fn a_restart_doesnt_kill_a_recorded_holder_the_ledger_still_names() {
        // wicketd stopped between recording a holder as dying and fencing it.
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        host_takes(&l, &mut io, "0", "m:1:1", 100);
        io.record.dying = BTreeMap::from([("0".to_string(), vec!["m:1:1".to_string()])]);
        let t = Manager::new(1).tick(&l, &mut io, 101);
        assert!(io.killed.is_empty(), "the ledger still names it: not fenced, so not killed");
        assert!(io.record.dying.is_empty(), "and the record forgets it");
        assert!(t.started.is_empty(), "its host is live: nothing to start");
    }

    #[test]
    fn a_fence_whose_record_cant_be_written_isnt_made() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        host_takes(&l, &mut io, "0", "m:1:1", 100);
        io.beats.get_mut("0").unwrap().stuck = true;
        io.beats.get_mut("0").unwrap().runtime_stuck = true;
        io.save_fails = true;
        let mut m = Manager::new(1);
        for now in (101..=300).step_by(5) {
            let t = m.tick(&l, &mut io, now);
            assert!(t.fenced.is_empty(), "fenced at {now} without a record");
        }
        assert!(io.killed.is_empty());
        assert_eq!(l.supervisor_host("0").unwrap().unwrap().epoch, 1);
    }

    #[test]
    fn a_lowered_setting_fences_a_dead_out_of_range_holder_and_kills_one_that_wont_stop() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        // supervise.hosts was 4, now 2: shard 2's holder died uncleanly, shard 3's ignores SIGTERM.
        l.take_shard("2", "m:8:1", &[], LEASE_SECS, 100).unwrap();
        host_takes(&l, &mut io, "3", "m:9:1", 100);
        let mut m = Manager::new(2);
        let t = m.tick(&l, &mut io, 101);
        assert!(t.fenced.contains(&"2".to_string()), "{t:?}");
        assert_eq!(l.supervisor_host("2").unwrap().unwrap().owner, None, "free for its nodes to move");
        assert_eq!(t.stopped, ["3"]);
        assert_eq!(io.terminated, ["m:9:1"]);
        // It goes on renewing its lease, so it never lapses.
        let epoch = l.supervisor_host("3").unwrap().unwrap().epoch;
        for now in 102..101 + STOP_SECS {
            assert!(l.renew_shard_lease("3", "m:9:1", epoch, LEASE_SECS, now).unwrap());
            assert!(!m.tick(&l, &mut io, now).fenced.contains(&"3".to_string()), "at {now}");
        }
        let t = m.tick(&l, &mut io, 101 + STOP_SECS);
        assert!(t.fenced.contains(&"3".to_string()), "{t:?}");
        // Fenced (a higher epoch) before the kill.
        assert!(io.killed.iter().any(|(o, e)| o == "m:9:1" && *e > Some(epoch)), "{:?}", io.killed);
        assert_eq!(l.supervisor_host("3").unwrap().unwrap().owner, None);
        assert_eq!(io.record.dying.get("3").map(Vec::as_slice), Some(&["m:9:1".to_string()][..]));
        // The record is written once, not every tick, while it dies; then it is reaped.
        let saves = std::rc::Rc::new(std::cell::Cell::new(0));
        let n = saves.clone();
        io.on_save = Some(Box::new(move |_| n.set(n.get() + 1)));
        for now in 102 + STOP_SECS..110 + STOP_SECS {
            assert!(m.tick(&l, &mut io, now).fenced.is_empty());
        }
        assert_eq!(saves.get(), 0);
        io.dies("m:9:1");
        m.tick(&l, &mut io, 110 + STOP_SECS);
        assert!(!io.record.dying.contains_key("3"), "{:?}", io.record);
    }

    #[test]
    fn with_no_shards_it_stops_every_host_left_and_then_has_nothing_in_hand() {
        // supervise.hosts set to 0: shard 0's holder is asked to stop, and a host started for
        // shard 1 that never took it (from the record) is killed.
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        host_takes(&l, &mut io, "0", "m:1:1", 100);
        io.running.insert("m:2:1".into());
        io.record.started.insert("1".into(), "m:2:1".into());
        let mut m = Manager::new(0);
        let t = m.tick(&l, &mut io, 101);
        assert_eq!(t.stopped, ["0"]);
        assert!(t.started.is_empty());
        assert_eq!(io.killed_labels(), ["m:2:1"]);
        assert!(!m.idle());
        io.dies("m:2:1");
        // Shard 0's stops with its clean-stop marker.
        let epoch = l.supervisor_host("0").unwrap().unwrap().epoch;
        assert!(l.mark_shard_stopping("0", "m:1:1", epoch, 102).unwrap());
        io.dies("m:1:1");
        let t = m.tick(&l, &mut io, 103);
        assert_eq!(t.fenced, ["0"], "a gone holder's shard is freed");
        assert!(t.started.is_empty());
        assert!(m.idle());
        assert!(l.supervisor_hosts().unwrap().iter().all(|h| h.owner.is_none()));
    }

    #[test]
    fn a_slow_starting_host_that_took_its_shard_is_fenced_before_it_is_killed() {
        let l = rc_ledger();
        let mut io = FakeIo::with(&l);
        let mut m = Manager::new(1);
        assert_eq!(m.tick(&l, &mut io, 100).started, ["0"]);
        // It takes the shard but never binds its socket.
        let epoch = l.take_shard("0", "m:1:1", &[], LEASE_SECS, 101).unwrap().epoch;
        for now in 102..=100 + START_GRACE_SECS + 5 {
            m.tick(&l, &mut io, now);
        }
        assert!(io.killed.is_empty(), "past the grace, but it holds a live epoch: {:?}", io.killed);
        let at = (116..=400).find(|&now| m.tick(&l, &mut io, now).fenced == ["0"]).expect("fenced once its lease lapsed");
        assert!(at >= 101 + LEASE_SECS, "{at}");
        assert!(io.killed.iter().any(|(o, e)| o == "m:1:1" && *e > Some(epoch)), "fenced, then killed: {:?}", io.killed);
    }

    #[test]
    fn a_flapping_stall_probe_doesnt_extend_the_exemption() {
        let (l, mut io, mut m) = one_lease_stuck_host(true);
        let at = (105..=900)
            .step_by(5)
            .find(|&now| {
                io.stalled = now % 10 == 5;
                m.tick(&l, &mut io, now).fenced == ["0"]
            })
            .expect("fenced in the end");
        assert!(at <= 105 + STALL_EXEMPT_MAX_SECS + 2 * STALL_WINDOW_SECS + LEASE_SECS, "fenced at {at}");
    }

    #[test]
    fn proc_io_sees_a_running_child_until_it_is_reaped() {
        let mut io = ProcIo { exe: "/bin/false".into(), data_dir: std::env::temp_dir(), env: Vec::new(), spawned: Vec::new() };
        let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        std::mem::forget(child);
        let owner = wicket_home::owner::owner_label_of(pid).unwrap();
        // Running: waitpid says 0.
        assert!(!io.gone(&owner));
        assert_eq!(io.alive(&owner), Some(true));
        io.kill(&owner);
        let t = std::time::Instant::now();
        while !io.gone(&owner) {
            assert!(t.elapsed() < std::time::Duration::from_secs(5), "never reaped");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(io.alive(&owner), Some(false));
    }
}
