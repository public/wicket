//! A node's health (#377): its disk and inodes (for its data directory), memory, feed freshness,
//! boxes killed for memory, failures to persist its own state, and its CA's validity (#416). The node samples it and reports
//! it to the control host on its channel ([`crate::chan::Msg::Health`]); the control host keeps the
//! latest per node in the ledger, `wicket top` and the console show it, and the console pushes to
//! operators when it crosses a threshold ([`alerts`]).

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Disk (or inodes) used past this share alerts.
pub const DISK_ALERT_PCT: f64 = 85.0;
/// The feed stale for longer than this alerts.
pub const FEED_STALE_ALERT_MS: i64 = 5 * 60 * 1000;
/// How often a node reports its health on each connection.
pub const REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(30);
/// A report older than this says nothing about the node now: its disk and feed aren't alerted on.
pub const REPORT_FRESH_MS: i64 = 10 * 60 * 1000;
/// An out-of-memory kill or persistence failure older than this isn't announced (a restarted
/// console doesn't announce last week's).
pub const EVENT_ALERT_MS: i64 = 60 * 60 * 1000;
/// A node CA with less than this share of its lifetime left alerts (#416): renewal over the channel
/// is due at half, so it is late.
pub const CA_ALERT_SHARE: f64 = 0.25;

/// One sample of a node's health.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeHealth {
    /// When it was sampled (the node's clock, ms).
    pub at_ms: i64,
    /// The filesystem holding the node's data directory (its feed, audit log, runs and volumes).
    pub disk: Disk,
    pub memory: Memory,
    /// The node's feed: its mode, and when it stops being fresh (None: it never has been).
    pub feed_mode: String,
    pub feed_fresh_until_ms: Option<i64>,
    /// Boxes killed for memory since the node started, and the latest.
    pub oom_kills: u64,
    pub last_oom: Option<HealthEvent>,
    /// The node's own state (feed, audit log, spend journal) not written, since it started, and the
    /// latest failure.
    pub persist_failures: u64,
    pub last_persist_failure: Option<HealthEvent>,
    /// The node CA's validity (Unix s, #416), as the node holds it: None if it has none.
    #[serde(default)]
    pub ca_not_before: Option<i64>,
    #[serde(default)]
    pub ca_not_after: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Disk {
    pub total_bytes: u64,
    /// What an unprivileged writer may still use.
    pub avail_bytes: u64,
    pub files_total: u64,
    pub files_avail: u64,
    /// The node's reserve (#377), counted as free: it is the node's own, released when it needs it.
    #[serde(default)]
    pub reserve_bytes: u64,
}

impl Disk {
    /// The share of the disk in use (the reserve counted as free), 0 to 100.
    pub fn used_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        let free = (self.avail_bytes + self.reserve_bytes).min(self.total_bytes);
        100.0 * (self.total_bytes - free) as f64 / self.total_bytes as f64
    }

    /// The share of the inodes in use, 0 to 100 (0 where the filesystem doesn't count them).
    pub fn files_used_pct(&self) -> f64 {
        if self.files_total == 0 {
            return 0.0;
        }
        100.0 * (self.files_total - self.files_avail.min(self.files_total)) as f64 / self.files_total as f64
    }

    /// What is free to boxes (the reserve isn't).
    pub fn free_bytes(&self) -> u64 {
        self.avail_bytes
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Memory {
    pub total_mib: u64,
    /// What the kernel says can be had without swapping (MemAvailable).
    pub available_mib: u64,
    /// The sum of the memory limits of the boxes running.
    pub committed_mib: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthEvent {
    pub at_ms: i64,
    pub what: String,
}

/// The filesystem holding `dir` (or the nearest directory above it that exists).
pub fn disk(dir: &Path) -> Disk {
    for d in dir.ancestors() {
        let Ok(p) = std::ffi::CString::new(d.as_os_str().as_encoded_bytes()) else { break };
        // SAFETY: statvfs fills the struct it is given, from a NUL-terminated path.
        let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(p.as_ptr(), &mut v) } == 0 {
            let f = v.f_frsize as u64;
            return Disk {
                total_bytes: v.f_blocks as u64 * f,
                avail_bytes: v.f_bavail as u64 * f,
                files_total: v.f_files as u64,
                files_avail: v.f_favail as u64,
                reserve_bytes: 0,
            };
        }
    }
    Disk::default()
}

/// This machine's memory: (total, available), MiB.
pub fn memory() -> (u64, u64) {
    let Ok(s) = std::fs::read_to_string("/proc/meminfo") else { return (0, 0) };
    let kib = |k: &str| s.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok()).unwrap_or(0);
    (kib("MemTotal:") >> 10, kib("MemAvailable:") >> 10)
}

/// Counts events of one kind (out-of-memory kills, persistence failures) and keeps the latest.
#[derive(Default)]
pub struct Counter(std::sync::Mutex<(u64, Option<HealthEvent>)>);

impl Counter {
    pub fn note(&self, at_ms: i64, what: impl Into<String>) {
        let mut g = self.0.lock().expect("counter");
        g.0 += 1;
        g.1 = Some(HealthEvent { at_ms, what: what.into() });
    }

    pub fn get(&self) -> (u64, Option<HealthEvent>) {
        self.0.lock().expect("counter").clone()
    }
}

/// Something an operator is told about: `key` says which condition (a push is sent when one first
/// appears, and again only after it has cleared), `text` what to say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub key: String,
    pub text: String,
}

fn gib(b: u64) -> String {
    format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64)
}

/// The thresholds `h`, node `node`'s latest report, crosses at `now_ms`.
pub fn alerts(node: &str, h: &NodeHealth, now_ms: i64) -> Vec<Alert> {
    let mut out = Vec::new();
    if now_ms - h.at_ms <= REPORT_FRESH_MS {
        out.extend(disk_alerts(node, &format!("node {node}"), &h.disk));
        if let Some(u) = h.feed_fresh_until_ms.filter(|u| now_ms - u > FEED_STALE_ALERT_MS) {
            out.push(Alert {
                key: format!("{node}/feed"),
                text: format!(
                    "node {node}: its policy feed has been stale for {} min, so its boxes' requests are refused",
                    (now_ms - u) / 60_000
                ),
            });
        }
    }
    // The CA's end is a date: a stale report still says when it was (or is) due.
    out.extend(ca_alert(node, h, now_ms));
    let events = [("oom", "a box was killed for memory", &h.last_oom), ("persist", "could not persist its state", &h.last_persist_failure)];
    for (kind, say, e) in events {
        if let Some(e) = e.as_ref().filter(|e| now_ms - e.at_ms <= EVENT_ALERT_MS) {
            out.push(Alert { key: format!("{node}/{kind}/{}", e.at_ms), text: format!("node {node}: {say}: {}", e.what) });
        }
    }
    out
}

/// The node CA (#416): an alert once less than [`CA_ALERT_SHARE`] of its lifetime is left, and
/// another (its own key, so pushed again) once it has expired.
fn ca_alert(node: &str, h: &NodeHealth, now_ms: i64) -> Option<Alert> {
    let end = h.ca_not_after?;
    let now = now_ms / 1000;
    let fix = format!("the control host renews it over the channel while a run is connected; else `wicket node renew-ca {node}`");
    if now >= end {
        return Some(Alert {
            key: format!("{node}/ca-expired"),
            text: format!(
                "node {node}: its CA expired {} ago ({}), so boxes there can't reach their inspected hosts and none start: {fix}",
                human_secs(now - end),
                rfc3339(end)
            ),
        });
    }
    let life = (end - h.ca_not_before.unwrap_or(end)).max(0);
    ((end - now) as f64 <= CA_ALERT_SHARE * life as f64).then(|| Alert {
        key: format!("{node}/ca-expiring"),
        text: format!("node {node}: its CA expires in {} ({}) and was not renewed: {fix}", human_secs(end - now), rfc3339(end)),
    })
}

fn human_secs(s: i64) -> String {
    match s {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s => format!("{} h", s / 3600),
    }
}

fn rfc3339(s: i64) -> String {
    wicket_core::time::format_rfc3339_seconds(std::time::UNIX_EPOCH + std::time::Duration::from_secs(s.max(0) as u64)).to_string()
}

/// The disk thresholds of `key` (a node's, or the control host's own), named `who` in the text.
pub fn disk_alerts(key: &str, who: &str, d: &Disk) -> Vec<Alert> {
    let mut out = Vec::new();
    let pct = d.used_pct();
    if pct > DISK_ALERT_PCT {
        out.push(Alert { key: format!("{key}/disk"), text: format!("{who}: disk {pct:.0}% full ({} free)", gib(d.free_bytes())) });
    }
    let files = d.files_used_pct();
    if files > DISK_ALERT_PCT {
        out.push(Alert { key: format!("{key}/inodes"), text: format!("{who}: {files:.0}% of inodes used") });
    }
    out
}

/// A short line for `wicket top` and the console: disk, memory, and what is wrong.
pub fn summary(h: &NodeHealth, now_ms: i64) -> String {
    let mut s = format!("disk {:.0}%, mem {}/{} MiB free", h.disk.used_pct(), h.memory.available_mib, h.memory.total_mib);
    if h.oom_kills > 0 {
        s.push_str(&format!(", {} OOM kill(s)", h.oom_kills));
    }
    if h.persist_failures > 0 {
        s.push_str(&format!(", {} persist failure(s)", h.persist_failures));
    }
    if let Some(u) = h.feed_fresh_until_ms.filter(|u| *u < now_ms) {
        s.push_str(&format!(", feed stale {} s", (now_ms - u) / 1000));
    }
    match h.ca_not_after {
        Some(end) if end * 1000 <= now_ms => s.push_str(&format!(", CA EXPIRED {}", rfc3339(end))),
        Some(end) => s.push_str(&format!(", CA until {}", rfc3339(end))),
        None => {}
    }
    s
}

/// What a node keeps back from boxes' memory (#377): at least this much, MiB...
pub const MEMORY_MARGIN_MIB: u64 = 256;
/// ...and at least this share of the machine's memory, percent.
pub const MEMORY_MARGIN_PCT: u64 = 5;
/// The free disk below which a node starts no box (#377): at least this much...
pub const DISK_FLOOR_BYTES: u64 = 1 << 30;
/// ...and at least this share of the disk, percent.
pub const DISK_FLOOR_PCT: u64 = 5;
/// Free inodes below this share of them refuse a box too, percent.
pub const FILES_FLOOR_PCT: u64 = 1;

/// The memory a node keeps back from boxes, MiB.
pub fn memory_margin_mib(total_mib: u64) -> u64 {
    MEMORY_MARGIN_MIB.max(total_mib * MEMORY_MARGIN_PCT / 100)
}

/// The free disk below which a node starts no box.
pub fn disk_floor(d: &Disk) -> u64 {
    DISK_FLOOR_BYTES.max(d.total_bytes / 100 * DISK_FLOOR_PCT)
}

/// The memory a new box may be given now (MiB): what the kernel says is available, less what the
/// boxes already running may still take up to their limits (`unused_mib`, their limits less their
/// use), less the margin. Limits are never overcommitted against what is actually free.
pub fn room_mib(m: &Memory, unused_mib: u64) -> u64 {
    m.available_mib.saturating_sub(unused_mib + memory_margin_mib(m.total_mib))
}

/// Why this node starts no box at all now, if it doesn't: its disk (or inodes) below the floor.
pub fn refuses(d: &Disk) -> Option<String> {
    if d.total_bytes == 0 {
        return None; // not known: not refused for it
    }
    let floor = disk_floor(d);
    if d.free_bytes() < floor {
        return Some(format!("disk: {} free for boxes, below the node's floor of {}", gib(d.free_bytes()), gib(floor)));
    }
    if d.files_total > 0 && d.files_avail < d.files_total / 100 * FILES_FLOOR_PCT {
        return Some(format!("disk: {} inodes free of {}, below {FILES_FLOOR_PCT}%", d.files_avail, d.files_total));
    }
    None
}

/// What a box refused for room starts its refusal with: placement reads it (another node is tried).
pub const NO_ROOM: &str = "no room on this node for the box";

/// Admission (#377): whether a box with a `want_mib` memory limit may start, given the room
/// ([`room_mib`]) and the disk. The refusal names the reason.
pub fn admit(want_mib: u64, room_mib: u64, m: &Memory, d: &Disk) -> Result<(), String> {
    if let Some(why) = refuses(d) {
        return Err(format!("{NO_ROOM}: {why}"));
    }
    if m.total_mib > 0 && want_mib > room_mib {
        return Err(format!(
            "{NO_ROOM}: memory: its limit is {want_mib} MiB, and {room_mib} MiB can be given ({} MiB available, {} MiB committed to running boxes' limits, {} MiB kept back)",
            m.available_mib,
            m.committed_mib,
            memory_margin_mib(m.total_mib)
        ));
    }
    Ok(())
}

/// The node's disk reserve (#377): a file of preallocated space in its data directory that box
/// volumes can't use, because it is already taken. When the node can't write its own state (feed,
/// audit log, replica, spend journal) it releases the reserve and writes again; it takes it back
/// once the disk has room for it above the floor.
pub struct Reserve {
    pub path: std::path::PathBuf,
    pub size: u64,
}

/// The environment variable that sets a node's reserve, MiB (0: none).
pub const RESERVE_ENV: &str = "WICKET_NODE_RESERVE_MIB";

impl Reserve {
    /// The reserve for the node at `root`: [`RESERVE_ENV`] MiB, else 2% of the disk, at least
    /// 256 MiB and at most 2 GiB.
    pub fn for_node(root: &Path) -> Reserve {
        let size = match std::env::var(RESERVE_ENV).ok().and_then(|v| v.trim().parse::<u64>().ok()) {
            Some(mib) => mib << 20,
            None => (disk(root).total_bytes / 50).clamp(256 << 20, 2 << 30),
        };
        Reserve { path: root.join("reserve"), size }
    }

    /// The space it holds now.
    pub fn held(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    /// Takes the reserve if it isn't held and the disk has room for it above the floor. Returns
    /// whether it was taken now.
    pub fn take(&self) -> std::io::Result<bool> {
        if self.size == 0 || self.held() >= self.size {
            return Ok(false);
        }
        let d = disk(&self.path);
        if d.avail_bytes < self.size + disk_floor(&d) {
            return Ok(false);
        }
        let tmp = self.path.with_extension("tmp");
        let r = preallocate(&tmp, self.size).and_then(|_| std::fs::rename(&tmp, &self.path));
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        r.map(|_| true)
    }

    /// Gives the reserve's space back to the disk (for the node's own writes). Returns whether it
    /// held any.
    pub fn release(&self) -> bool {
        let held = self.held() > 0;
        let _ = std::fs::remove_file(&self.path);
        held
    }
}

/// A file of `len` bytes whose blocks are allocated (not sparse): `posix_fallocate`, or zeros where
/// the filesystem doesn't support it.
fn preallocate(path: &Path, len: u64) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(path)?;
    // SAFETY: posix_fallocate on a file descriptor this function owns.
    let rc = unsafe { libc::posix_fallocate(f.as_raw_fd(), 0, len as libc::off_t) };
    if rc == 0 {
        return f.sync_all();
    }
    if rc == libc::ENOSPC {
        return Err(std::io::Error::from_raw_os_error(rc));
    }
    let mut w = std::io::BufWriter::new(&f);
    let zeros = vec![0u8; 1 << 20];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        w.write_all(&zeros[..n])?;
        left -= n as u64;
    }
    w.flush()?;
    drop(w);
    f.sync_all()
}

/// Whether `dir` can be written now: a small file written, synced and removed (how a node with a
/// feed stalled for want of space learns the space is back).
pub fn writable(dir: &Path) -> bool {
    let p = dir.join(".probe");
    let ok = std::fs::write(&p, vec![0u8; 64 << 10]).and_then(|_| std::fs::File::open(&p)?.sync_all()).is_ok();
    let _ = std::fs::remove_file(&p);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy(now: i64) -> NodeHealth {
        NodeHealth {
            at_ms: now,
            disk: Disk { total_bytes: 100 << 30, avail_bytes: 50 << 30, files_total: 1000, files_avail: 900, reserve_bytes: 0 },
            memory: Memory { total_mib: 8192, available_mib: 4096, committed_mib: 2048 },
            feed_mode: "fresh".into(),
            feed_fresh_until_ms: Some(now + 60_000),
            ..Default::default()
        }
    }

    #[test]
    fn a_healthy_node_alerts_nothing() {
        let now = 10_000_000_000;
        assert!(alerts("n1", &healthy(now), now).is_empty());
    }

    #[test]
    fn each_threshold_alerts_once_by_its_key() {
        let now = 10_000_000_000;
        let mut h = healthy(now);
        h.disk.avail_bytes = 10 << 30; // 90% used
        h.disk.files_avail = 100; // 90% of inodes
        h.feed_fresh_until_ms = Some(now - 6 * 60_000);
        h.oom_kills = 1;
        h.last_oom = Some(HealthEvent { at_ms: now - 1000, what: "run_a (limit 512 MiB, peak 512 MiB)".into() });
        h.persist_failures = 2;
        h.last_persist_failure = Some(HealthEvent { at_ms: now - 2000, what: "feed: No space left on device".into() });
        let keys: Vec<String> = alerts("n1", &h, now).into_iter().map(|a| a.key).collect();
        assert_eq!(
            keys,
            ["n1/disk", "n1/inodes", "n1/feed", format!("n1/oom/{}", now - 1000).as_str(), format!("n1/persist/{}", now - 2000).as_str()]
        );
        // The reserve is the node's: counted as free.
        h.disk.reserve_bytes = 10 << 30;
        assert!(!alerts("n1", &h, now).iter().any(|a| a.key == "n1/disk"));
    }

    #[test]
    fn a_stale_report_and_old_events_alert_nothing() {
        let now = 10_000_000_000;
        let mut h = healthy(now - REPORT_FRESH_MS - 1);
        h.disk.avail_bytes = 1 << 30;
        h.last_oom = Some(HealthEvent { at_ms: now - EVENT_ALERT_MS - 1, what: "x".into() });
        assert!(alerts("n1", &h, now).is_empty());
        // The feed stale for less than 5 min is not yet alerted.
        let mut h = healthy(now);
        h.feed_fresh_until_ms = Some(now - 4 * 60_000);
        assert!(alerts("n1", &h, now).is_empty());
    }

    /// #416: a node CA in its last quarter alerts, and again (another key, so pushed again) once
    /// expired, whether or not the report is fresh; top and the console show its end.
    #[test]
    fn a_node_ca_alerts_in_its_last_quarter_and_again_once_expired() {
        let now = 10_000_000_000;
        let mut h = healthy(now);
        let s = now / 1000;
        h.ca_not_before = Some(s - 3600);
        h.ca_not_after = Some(s + 3600);
        assert!(alerts("n1", &h, now).is_empty(), "half its life left");
        assert!(summary(&h, now).contains("CA until "), "{}", summary(&h, now));
        h.ca_not_after = Some(s + 1200); // 1200 of 4800 s left: a quarter
        let a = alerts("n1", &h, now);
        assert_eq!(a.iter().map(|a| a.key.as_str()).collect::<Vec<_>>(), ["n1/ca-expiring"]);
        assert!(a[0].text.contains("expires in 20 min") && a[0].text.contains("wicket node renew-ca n1"), "{}", a[0].text);
        h.ca_not_after = Some(s);
        let a = alerts("n1", &h, now);
        assert_eq!(a.iter().map(|a| a.key.as_str()).collect::<Vec<_>>(), ["n1/ca-expired"]);
        assert!(a[0].text.contains("none start"), "{}", a[0].text);
        assert!(summary(&h, now).contains("CA EXPIRED"), "{}", summary(&h, now));
        // A stale report (the node not connected since) still says the CA is gone.
        h.at_ms = now - REPORT_FRESH_MS - 1;
        assert_eq!(alerts("n1", &h, now).len(), 1);
        // A report from before CA validity was reported: nothing.
        h.ca_not_after = None;
        assert!(alerts("n1", &h, now).is_empty());
    }

    #[test]
    fn this_hosts_disk_is_read() {
        let d = disk(&std::env::temp_dir().join("no-such-dir-wicket"));
        assert!(d.total_bytes > 0 && d.avail_bytes <= d.total_bytes);
    }

    #[test]
    fn a_box_is_admitted_only_into_memory_actually_free() {
        let m = Memory { total_mib: 8192, available_mib: 4096, committed_mib: 3072 };
        let d = healthy(0).disk;
        // 4096 available, 1024 still claimable by running boxes, 409 kept back: 2663 for a new box.
        let room = room_mib(&m, 1024);
        assert_eq!(room, 4096 - 1024 - 409);
        assert!(admit(2048, room, &m, &d).is_ok());
        let e = admit(3072, room, &m, &d).unwrap_err();
        assert!(e.starts_with(NO_ROOM) && e.contains("memory: its limit is 3072 MiB, and 2663 MiB can be given"), "{e}");
    }

    #[test]
    fn a_box_is_refused_below_the_disk_floor() {
        let m = Memory { total_mib: 8192, available_mib: 8000, committed_mib: 0 };
        let mut d = Disk { total_bytes: 100 << 30, avail_bytes: 4 << 30, files_total: 1000, files_avail: 500, reserve_bytes: 0 };
        let e = admit(512, room_mib(&m, 0), &m, &d).unwrap_err();
        assert!(e.contains("disk: 4.0 GiB free for boxes, below the node's floor of 5.0 GiB"), "{e}");
        d.avail_bytes = 50 << 30;
        assert!(admit(512, room_mib(&m, 0), &m, &d).is_ok());
        d.files_avail = 5;
        assert!(admit(512, room_mib(&m, 0), &m, &d).unwrap_err().contains("inodes"));
        // A disk wicket can't read refuses nothing for it.
        assert!(refuses(&Disk::default()).is_none());
    }

    #[test]
    fn the_reserve_is_taken_released_and_taken_back() {
        let dir = std::env::temp_dir().join(format!("wicket-reserve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r = Reserve { path: dir.join("reserve"), size: 4 << 20 };
        assert!(r.take().unwrap(), "taken");
        assert_eq!(r.held(), 4 << 20);
        assert!(!r.take().unwrap(), "already held");
        assert!(r.release());
        assert_eq!(r.held(), 0);
        assert!(!r.release(), "nothing held");
        assert!(r.take().unwrap(), "taken back");
        assert!(Reserve { path: dir.join("none"), size: 0 }.take().is_ok_and(|t| !t), "no reserve configured");
        assert!(writable(&dir));
        assert!(!writable(&dir.join("missing")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
