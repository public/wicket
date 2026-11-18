//! Box owners (#21). A box is supervised by the `wicket run` process that started it: that process
//! holds its proxies, sockets and identity. If it dies hard (SIGKILL, a crash), Docker can keep the box
//! running with nothing behind it. Each box is labelled with its run and its owner process; the
//! reconciler (`wicket reconcile`) and a node's `serve` judge boxes by it.
//!
//! The owner label is `<machine>:<pid>:<start>`: the host's machine id, the process id, and the
//! process's start time (field 22 of /proc/<pid>/stat), so a reused pid isn't mistaken for the owner.
//! A box owned by a process on another machine is left alone: only that machine can tell.

use wicket_sandbox::BoxInfo;

/// The status a run whose box is gone ends with.
pub const LOST: &str = "lost";

fn machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().chars().take(16).collect())
        .unwrap_or_else(|_| "unknown".into())
}

/// A process's start time in clock ticks since boot, or None if it doesn't exist.
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name (field 2) is in parentheses and may contain spaces: count from after it.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
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

/// Whether the process an owner label names is still running: None if it's on another machine (or
/// the label is unreadable), so this machine can't tell.
pub fn owner_alive(label: &str) -> Option<bool> {
    let mut f = label.splitn(3, ':');
    let (machine, pid, start) = (f.next()?, f.next()?.parse::<u32>().ok()?, f.next()?.parse::<u64>().ok()?);
    if machine != machine_id() {
        return None;
    }
    Some(start_time(pid) == Some(start))
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
}
