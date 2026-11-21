//! Box owners (#21). A box is supervised by the `wicket run` process that started it: that process
//! holds its proxies, sockets and identity. If it dies hard (SIGKILL, a crash), Docker can keep the box
//! running with nothing behind it. Each box is labelled with its run and its owner process; the
//! reconciler (`wicket reconcile`) and a node's `serve` judge boxes by it.
//!
//! The owner label is `<machine>:<pid>:<start>`: the host's machine id, the process id, and the
//! process's start time (field 22 of /proc/<pid>/stat), so a reused pid isn't mistaken for the owner.
//! A box owned by a process on another machine is left alone: only that machine can tell.
//!
//! A run supervised as a task in a supervisor host (#582 step 5, `wicket supervise`) is owned by
//! `host:<shard>:<epoch>` instead ([`host_label`]). No process of this build vouches for one, so a
//! run's owner in that form is read as gone ([`owner_alive`]): a build that rolls back from hosts to
//! processes adopts those runs with a process, as on any update (each run's `ctl/supervisor.lock`
//! still keeps out a second supervisor while a host holds it). A box, though, is never stopped for
//! it ([`judge`]): only the ledger can say whether a host holds it.

use wicket_sandbox::BoxInfo;

/// The status a run whose box is gone ends with.
pub const LOST: &str = "lost";

fn machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().chars().take(16).collect())
        .unwrap_or_else(|_| "unknown".into())
}

/// A process's state (field 3: `R`, `S`, `D`, `Z` and the rest) and start time in clock ticks since
/// boot, or None if it doesn't exist.
fn stat(pid: u32) -> Option<(char, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name (field 2) is in parentheses and may contain spaces: count from after it.
    let mut rest = stat[stat.rfind(')')? + 1..].split_whitespace();
    let state = rest.next()?.chars().next()?;
    Some((state, rest.nth(18)?.parse().ok()?))
}

/// A process's start time in clock ticks since boot, or None if it doesn't exist.
fn start_time(pid: u32) -> Option<u64> {
    stat(pid).map(|(_, start)| start)
}

/// This process's owner label.
pub fn owner_label() -> String {
    let pid = std::process::id();
    format!("{}:{pid}:{}", machine_id(), start_time(pid).unwrap_or(0))
}

/// Process `pid`'s owner label, if it is running.
pub fn owner_label_of(pid: u32) -> Option<String> {
    Some(format!("{}:{pid}:{}", machine_id(), start_time(pid)?))
}

/// The owner label of a run a supervisor host holds (#582 step 5): its shard and the epoch it holds
/// the shard at.
pub fn host_label(shard: &str, epoch: i64) -> String {
    format!("{HOST_PREFIX}{shard}:{epoch}")
}

const HOST_PREFIX: &str = "host:";

/// Whether an owner label names a supervisor host (`host:<shard>:<epoch>`), not a process. A machine
/// id is hex, so it never reads `host`.
pub fn is_host_label(label: &str) -> bool {
    label
        .strip_prefix(HOST_PREFIX)
        .and_then(|r| r.rsplit_once(':'))
        .is_some_and(|(shard, epoch)| !shard.is_empty() && epoch.parse::<i64>().is_ok())
}

/// Whether the process an owner label names is still running: None if it's on another machine (or
/// the label is unreadable), so this machine can't tell. A supervisor host's label is `Some(false)`:
/// see the module's documentation. A zombie (exited, not yet reaped by its parent) isn't running,
/// but only once every thread has gone: a killed process's main thread is a zombie at once while a
/// thread in uninterruptible IO lives on, holding the process's files and locks.
pub fn owner_alive(label: &str) -> Option<bool> {
    if is_host_label(label) {
        return Some(false);
    }
    let (pid, start) = local_label(label)?;
    Some(match stat(pid) {
        Some((state, s)) if s == start => state != 'Z' || threads(pid) > 1,
        _ => false,
    })
}

/// Whether the process an owner label names is a zombie with nothing left of it: every thread gone,
/// its parent not yet having reaped it.
#[cfg(test)]
fn owner_zombie(label: &str) -> bool {
    local_label(label).is_some_and(|(pid, start)| stat(pid) == Some(('Z', start)) && threads(pid) <= 1)
}

/// How many threads a process has left, the main one included: the `Threads:` line of
/// `/proc/<pid>/status`, one counter the kernel keeps (a count of `/proc/<pid>/task` entries can miss
/// a live thread while a sibling exits mid-scan). 0 once the process is gone; a read that fails any
/// other way, or a line that can't be parsed, counts as more than one, so the process reads as
/// running: a kill that can't be confirmed isn't taken for one.
fn threads(pid: u32) -> usize {
    match std::fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(s) => s.lines().find_map(|l| l.strip_prefix("Threads:")).and_then(|n| n.trim().parse().ok()).unwrap_or(usize::MAX),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => usize::MAX,
    }
}

/// An owner label of this machine's: its pid and start time.
fn local_label(label: &str) -> Option<(u32, u64)> {
    let mut f = label.splitn(3, ':');
    let (machine, pid, start) = (f.next()?, f.next()?.parse::<u32>().ok()?, f.next()?.parse::<u64>().ok()?);
    (machine == machine_id()).then_some((pid, start))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Its owner is running.
    Live,
    /// Its owner is gone (or its run ended): stop it.
    Orphan(String),
    /// Can't tell from here: left alone.
    Unknown(String),
}

/// What to do with one box, by its owner label: a box without one is left alone (a node has no
/// ledger to ask about its run).
pub fn judge(b: &BoxInfo) -> Verdict {
    if b.owner.as_deref().is_some_and(is_host_label) {
        return Verdict::Unknown("supervised by a supervisor host: only the ledger can tell".into());
    }
    match b.owner.as_deref().map(owner_alive) {
        Some(Some(true)) => Verdict::Live,
        Some(Some(false)) => Verdict::Orphan("its wicket process has exited".into()),
        Some(None) => Verdict::Unknown("owned by a process on another machine, or an unreadable owner label".into()),
        None => Verdict::Unknown("no owner label".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(owner: Option<String>) -> BoxInfo {
        BoxInfo { name: "wicket-run-1".into(), run: Some("run_1".into()), owner }
    }

    #[test]
    fn a_box_whose_owner_runs_is_live() {
        assert_eq!(judge(&boxed(Some(owner_label()))), Verdict::Live);
    }

    #[test]
    fn a_box_whose_owner_exited_or_was_replaced_is_an_orphan() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let start = start_time(pid).unwrap_or(1);
        child.wait().unwrap();
        let gone = format!("{}:{pid}:{start}", machine_id());
        assert!(matches!(judge(&boxed(Some(gone))), Verdict::Orphan(_)));
        // Same pid as a live process, different start time: a reused pid, not the owner.
        let reused = format!("{}:{}:1", machine_id(), std::process::id());
        assert!(matches!(judge(&boxed(Some(reused))), Verdict::Orphan(_)));
    }

    #[test]
    fn other_machines_and_unlabelled_boxes_are_left_alone() {
        assert!(matches!(judge(&boxed(Some("another-host:1:1".into()))), Verdict::Unknown(_)));
        assert!(matches!(judge(&boxed(Some("garbage".into()))), Verdict::Unknown(_)));
        assert!(matches!(judge(&boxed(None)), Verdict::Unknown(_)));
    }

    #[test]
    fn a_host_label_reads_as_gone_for_a_run_and_unknown_for_a_box() {
        let l = host_label("2", 7);
        assert_eq!(l, "host:2:7");
        assert!(is_host_label(&l));
        // An older build's reconciler adopts the run with a process (#582 step 5, rollback).
        assert_eq!(owner_alive(&l), Some(false));
        // A node never stops a box for it.
        assert!(matches!(judge(&boxed(Some(l))), Verdict::Unknown(_)));
        for not in ["host:", "host:2", "host::7", "host:2:x", "hostx:2:7"] {
            assert!(!is_host_label(not), "{not}");
        }
        assert!(!is_host_label(&owner_label()));
    }

    #[test]
    fn a_zombie_owner_is_gone_and_known_as_a_zombie_until_reaped() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let label = owner_label_of(pid).unwrap();
        // Exited, not yet reaped: a zombie.
        let t = std::time::Instant::now();
        while !owner_zombie(&label) {
            assert!(t.elapsed() < std::time::Duration::from_secs(5), "never a zombie");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(owner_alive(&label), Some(false));
        child.wait().unwrap();
        assert!(!owner_zombie(&label));
        assert_eq!(owner_alive(&label), Some(false));
        assert_eq!(owner_alive(&owner_label()), Some(true));
        assert!(!owner_zombie(&owner_label()));
    }

    #[test]
    fn a_zombie_main_thread_with_a_live_thread_is_still_running() {
        // A process whose main thread has exited (pthread_exit) while another sleeps: its main thread
        // reads Z, as a SIGKILLed one's does while a thread in uninterruptible IO lives on. The forked child has one thread, the leader,
        // until it starts the sleeper.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let mut t: libc::pthread_t = 0;
            extern "C" fn sleeper(_: *mut libc::c_void) -> *mut libc::c_void {
                unsafe { libc::sleep(2) };
                std::ptr::null_mut()
            }
            unsafe {
                if libc::pthread_create(&mut t, std::ptr::null(), sleeper, std::ptr::null_mut()) != 0 {
                    libc::_exit(1);
                }
                // The leader alone exits, as pthread_exit would, without unwinding through the test
                // harness's frames.
                libc::syscall(libc::SYS_exit, 0);
                libc::_exit(1);
            }
        }
        let pid = pid as u32;
        let label = owner_label_of(pid).unwrap();
        let t = std::time::Instant::now();
        while stat(pid).map(|(s, _)| s) != Some('Z') {
            assert!(t.elapsed() < std::time::Duration::from_secs(5), "its main thread never exited");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(owner_alive(&label), Some(true), "a thread lives on");
        assert!(!owner_zombie(&label));
        assert_eq!(threads(pid), 2, "the zombie leader counts");
        let mut st = 0;
        assert_eq!(unsafe { libc::waitpid(pid as i32, &mut st, 0) }, pid as i32);
        assert!(libc::WIFEXITED(st), "the sleeper ended it: {st}");
        assert_eq!(owner_alive(&label), Some(false));
        assert_eq!(threads(pid), 0);
    }
}
