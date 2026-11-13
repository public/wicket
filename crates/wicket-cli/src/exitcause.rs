//! Why a box ended (#185), as its node can tell: wicket's own stops (the node's timeout backstop, an
//! expired authority, the output cap, the control host's stop), the kernel's OOM killer (Docker's
//! `State.OOMKilled`, which runsc reports too, or the box cgroup's `memory.events` `oom_kill`), the
//! runtime's own error, or a signal from elsewhere. And the box's memory, sampled from its cgroup
//! while it runs: for the peak in an out-of-memory cause, and to warn the agent before the limit.

use std::path::{Path, PathBuf};
use wicket_sandbox::ExitInfo;

/// A box's memory, from its cgroup (cgroup v2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mem {
    pub current: u64,
    /// The limit (None: none).
    pub max: Option<u64>,
    /// The highest `memory.current` seen (or `memory.peak`, where the kernel has it).
    pub peak: u64,
    /// The OOM killer's kills in the cgroup so far (`memory.events` `oom_kill`).
    pub oom_kills: u64,
}

/// The cgroup v2 directory of the process `pid`.
pub fn cgroup_of(pid: u32) -> Option<PathBuf> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let rel = s.lines().find_map(|l| l.strip_prefix("0::"))?;
    let dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    dir.join("memory.current").exists().then_some(dir)
}

/// Reads a box's memory from its cgroup directory, keeping the highest values seen in `prev`.
pub fn sample(dir: &Path, prev: Mem) -> Option<Mem> {
    let num = |f: &str| std::fs::read_to_string(dir.join(f)).ok().and_then(|s| s.trim().parse::<u64>().ok());
    let current = num("memory.current")?;
    let max = std::fs::read_to_string(dir.join("memory.max")).ok().and_then(|s| s.trim().parse::<u64>().ok());
    let oom_kills = std::fs::read_to_string(dir.join("memory.events"))
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("oom_kill ").and_then(|n| n.trim().parse().ok())))
        .unwrap_or(0);
    let peak = num("memory.peak").unwrap_or(0).max(current).max(prev.peak);
    Some(Mem { current, max: max.or(prev.max), peak, oom_kills: oom_kills.max(prev.oom_kills) })
}

/// `3 GiB`, `512 MiB`.
pub fn human(b: u64) -> String {
    const G: u64 = 1 << 30;
    const M: u64 = 1 << 20;
    if b >= G {
        format!("{:.1} GiB", b as f64 / G as f64).replace(".0 ", " ")
    } else {
        format!("{} MiB", b.div_ceil(M))
    }
}

fn signal_name(sig: i32) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        15 => "SIGTERM",
        _ => "a signal",
    }
}

/// Why a box that exited with `code` ended, if there is more to say than its exit code: what wicket
/// stopped it for (`stopped`), else the OOM killer (with the limit and the peak seen), the runtime's
/// error, or a signal. None for a box that exited by itself (0, or its program's own code).
pub fn describe(code: i32, stopped: Option<&str>, info: Option<&ExitInfo>, mem: Option<&Mem>, limit: Option<u64>) -> Option<String> {
    if let Some(why) = stopped {
        return Some(format!("stopped by wicket: {why}"));
    }
    let oom = info.is_some_and(|i| i.oom_killed) || mem.is_some_and(|m| m.oom_kills > 0);
    if oom {
        let limit = mem.and_then(|m| m.max).or(limit);
        let mut s = "killed: out of memory".to_string();
        let mut parts = vec![];
        if let Some(l) = limit {
            parts.push(format!("limit {}", human(l)));
        }
        if let Some(m) = mem.filter(|m| m.peak > 0) {
            parts.push(format!("peak {}", human(m.peak)));
        }
        if !parts.is_empty() {
            s.push_str(&format!(" ({})", parts.join(", ")));
        }
        return Some(s);
    }
    if let Some(e) = info.and_then(|i| i.error.as_deref()) {
        return Some(format!("the container runtime failed: {}", wicket_agent::clip(e, 300)));
    }
    if code > 128 && code <= 128 + 64 {
        let sig = code - 128;
        let name = signal_name(sig);
        return Some(match sig {
            4 | 6 | 7 | 8 | 11 => format!("crashed: signal {sig} ({name})"),
            _ => format!("killed by signal {sig} ({name}), not by wicket and not for memory: from outside the box, or by a process in it"),
        });
    }
    None
}

/// The share of its memory limit a box uses at which the agent is warned, once per box (again only
/// after it has dropped below [`WARN_RESET`]).
pub const WARN_AT: f64 = 0.90;
pub const WARN_RESET: f64 = 0.75;

/// The warning for a box at `m`, if it is due (`warned`: whether it was already warned and hasn't
/// dropped below the reset level since). Returns the new `warned`, and the text to send.
pub fn pressure(m: &Mem, warned: bool) -> (bool, Option<String>) {
    let Some(max) = m.max.filter(|x| *x > 0) else { return (warned, None) };
    let share = m.current as f64 / max as f64;
    if share >= WARN_AT && !warned {
        let text = format!(
            "[wicket] This box is using {} of its {} memory limit ({:.0}%). If it goes over, the kernel kills the whole box and \
             anything not saved is lost. Reduce parallelism now (for example CARGO_BUILD_JOBS=1, `make -j1`, one test run at a time), \
             stop processes you don't need, and commit or save work in progress.",
            human(m.current),
            human(max),
            share * 100.0
        );
        return (true, Some(text));
    }
    (warned && share >= WARN_RESET, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    #[test]
    fn causes_read_as_people_would_say_them() {
        let oom = ExitInfo { code: 137, oom_killed: true, error: None };
        let mem = Mem { current: 0, max: Some(3 * GIB), peak: 3 * GIB - (1 << 20), oom_kills: 1 };
        assert_eq!(describe(137, None, Some(&oom), Some(&mem), None).unwrap(), "killed: out of memory (limit 3 GiB, peak 3 GiB)");
        // The cgroup's count alone is enough, and the limit can come from the zone.
        let quiet = ExitInfo { code: 137, oom_killed: false, error: None };
        let m2 = Mem { oom_kills: 2, peak: 600 << 20, ..Mem::default() };
        assert_eq!(
            describe(137, None, Some(&quiet), Some(&m2), Some(512 << 20)).unwrap(),
            "killed: out of memory (limit 512 MiB, peak 600 MiB)"
        );
        assert_eq!(describe(137, None, Some(&oom), None, None).unwrap(), "killed: out of memory");
        // wicket's own stops say so, whatever else is true.
        assert_eq!(
            describe(137, Some("past its timeout (30m)"), Some(&oom), None, None).unwrap(),
            "stopped by wicket: past its timeout (30m)"
        );
        // A signal from elsewhere, and a crash.
        assert!(describe(137, None, Some(&quiet), None, None).unwrap().starts_with("killed by signal 9 (SIGKILL), not by wicket"));
        assert_eq!(describe(139, None, None, None, None).unwrap(), "crashed: signal 11 (SIGSEGV)");
        let err = ExitInfo { code: 127, oom_killed: false, error: Some("OCI runtime create failed".into()) };
        assert!(describe(127, None, Some(&err), None, None).unwrap().contains("OCI runtime create failed"));
        // A program's own exit codes need no cause.
        assert_eq!(describe(0, None, Some(&quiet), None, None), None);
        assert_eq!(describe(1, None, None, None, None), None);
    }

    #[test]
    fn the_agent_is_warned_once_near_its_limit_and_again_after_dropping_back() {
        let at = |pct: u64| Mem { current: 10 * GIB * pct / 100, max: Some(10 * GIB), peak: 0, oom_kills: 0 };
        assert_eq!(pressure(&at(80), false), (false, None));
        let (w, t) = pressure(&at(92), false);
        assert!(w && t.unwrap().contains("9.2 GiB of its 10 GiB memory limit (92%)"));
        assert_eq!(pressure(&at(95), true), (true, None), "once");
        assert_eq!(pressure(&at(80), true), (true, None), "not reset above 75%");
        assert_eq!(pressure(&at(70), true), (false, None), "reset");
        assert!(pressure(&at(91), false).1.is_some(), "and warned again");
        assert_eq!(pressure(&Mem { current: 5, max: None, ..Mem::default() }, false), (false, None), "no limit, no warning");
    }

    #[test]
    fn a_cgroup_directory_is_read_and_its_peak_kept() {
        let d = std::env::temp_dir().join(format!("wicket-cg-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("memory.current"), "1000\n").unwrap();
        std::fs::write(d.join("memory.max"), "4000\n").unwrap();
        std::fs::write(d.join("memory.events"), "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n").unwrap();
        let m = sample(&d, Mem { peak: 2500, ..Mem::default() }).unwrap();
        assert_eq!(m, Mem { current: 1000, max: Some(4000), peak: 2500, oom_kills: 1 });
        std::fs::write(d.join("memory.max"), "max\n").unwrap();
        assert_eq!(sample(&d, Mem::default()).unwrap().max, None);
        let _ = std::fs::remove_dir_all(d);
    }
}
