//! A node's health (#377): its disk and inodes (for its data directory), memory, feed freshness,
//! boxes killed for memory, and failures to persist its own state. The node samples it and reports
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
    let events = [("oom", "a box was killed for memory", &h.last_oom), ("persist", "could not persist its state", &h.last_persist_failure)];
    for (kind, say, e) in events {
        if let Some(e) = e.as_ref().filter(|e| now_ms - e.at_ms <= EVENT_ALERT_MS) {
            out.push(Alert { key: format!("{node}/{kind}/{}", e.at_ms), text: format!("node {node}: {say}: {}", e.what) });
        }
    }
    out
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
}
