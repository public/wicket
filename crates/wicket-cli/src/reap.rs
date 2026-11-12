//! Orphaned boxes (#21). A box is supervised by the `wicket run` process that started it: that process
//! holds its proxies, sockets and identity. If it dies hard (SIGKILL, a crash), Docker can keep the box
//! running with nothing behind it. Each box is labelled with its run and its owner process, and the
//! reaper stops boxes whose owner is gone.
//!
//! The owner label is `<machine>:<pid>:<start>`: the host's machine id, the process id, and the
//! process's start time (field 22 of /proc/<pid>/stat), so a reused pid isn't mistaken for the owner.
//! A box owned by a process on another machine is left alone: only that machine can tell.

use anyhow::Result;
use wicket_core::{RunId, TenantId};
use wicket_sandbox::{BoxInfo, Docker};
use wicket_store::Ledger;

/// The status a reaped run ends with.
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

/// What to do with one box. `run_status` is the ledger's status for its run, if any.
pub fn judge(b: &BoxInfo, run_status: Option<&str>) -> Verdict {
    match b.owner.as_deref().map(owner_alive) {
        Some(Some(true)) => Verdict::Live,
        Some(Some(false)) => Verdict::Orphan("its wicket process has exited".into()),
        Some(None) => Verdict::Unknown("owned by a process on another machine, or an unreadable owner label".into()),
        // Boxes started before owner labels: only the ledger can say, and only an ended run is certain.
        None => match run_status {
            Some(s) if s != "running" => Verdict::Orphan(format!("its run has ended ({s})")),
            Some(_) => Verdict::Unknown("no owner label, and its run is recorded as still running".into()),
            None => Verdict::Unknown("no owner label and no run in this ledger".into()),
        },
    }
}

pub struct Reaped {
    pub name: String,
    pub run: Option<String>,
    pub verdict: Verdict,
}

/// Judges every wicket box Docker is running; unless `dry_run`, stops the orphans and ends their runs
/// in the ledger (which withdraws their pending requests).
pub async fn reap(docker: &Docker, ledger: &Ledger, dry_run: bool) -> Result<Vec<Reaped>> {
    let mut out = vec![];
    for mut b in docker.boxes().await? {
        let status = match &b.run {
            Some(r) => ledger.run_status(r)?,
            None => None,
        };
        // Judged by the run's supervisor as the ledger has it (it changes when one re-attaches, #151),
        // and a running run whose supervisor is gone is left to `wicket reconcile`, which re-attaches
        // to it or ends it.
        if let Some(o) = b.run.as_deref().map(|r| ledger.run_owner(r)).transpose()?.flatten() {
            b.owner = Some(o);
        }
        let verdict = match judge(&b, status.as_deref()) {
            Verdict::Orphan(_) if status.as_deref() == Some("running") => {
                Verdict::Unknown("its supervisor is gone: `wicket reconcile` re-attaches to its run or ends it".into())
            }
            v => v,
        };
        if let (Verdict::Orphan(why), false) = (&verdict, dry_run) {
            docker.kill(&b.name).await?;
            if let Some(r) = &b.run {
                if status.as_deref() == Some("running") {
                    ledger.run_ended(&RunId(r.clone()), LOST, &format!("box stopped by the reaper: {why}"))?;
                }
                let _ = ledger.audit(
                    &TenantId::single(),
                    Some(&RunId(r.clone())),
                    "box.reaped",
                    &serde_json::json!({ "box": b.name, "why": why }),
                );
            }
        }
        out.push(Reaped { name: b.name, run: b.run, verdict });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(owner: Option<String>) -> BoxInfo {
        BoxInfo { name: "wicket-run-1".into(), run: Some("run_1".into()), owner }
    }

    #[test]
    fn a_box_whose_owner_runs_is_live() {
        assert_eq!(judge(&boxed(Some(owner_label())), Some("running")), Verdict::Live);
    }

    #[test]
    fn a_box_whose_owner_exited_or_was_replaced_is_an_orphan() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let start = start_time(pid).unwrap_or(1);
        child.wait().unwrap();
        let gone = format!("{}:{pid}:{start}", machine_id());
        assert!(matches!(judge(&boxed(Some(gone)), Some("running")), Verdict::Orphan(_)));
        // Same pid as a live process, different start time: a reused pid, not the owner.
        let reused = format!("{}:{}:1", machine_id(), std::process::id());
        assert!(matches!(judge(&boxed(Some(reused)), Some("running")), Verdict::Orphan(_)));
    }

    #[test]
    fn other_machines_and_unlabelled_boxes_are_left_alone_unless_their_run_ended() {
        assert!(matches!(judge(&boxed(Some("another-host:1:1".into())), None), Verdict::Unknown(_)));
        assert!(matches!(judge(&boxed(Some("garbage".into())), None), Verdict::Unknown(_)));
        assert!(matches!(judge(&boxed(None), Some("running")), Verdict::Unknown(_)));
        assert!(matches!(judge(&boxed(None), None), Verdict::Unknown(_)));
        assert!(matches!(judge(&boxed(None), Some("succeeded")), Verdict::Orphan(_)));
    }
}
