//! How a long-running wicket process moves to a new build: from the versions root's `current`
//! (moved from wicket-cli's `update`, which re-exports it).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Whether `id` names a staged version (12 lowercase hex digits).
pub fn valid_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The versions root the running binary is in, if it is a staged version.
pub fn running_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let root = dir.parent()?;
    let staged = exe.file_name()? == "wicket" && valid_id(dir.file_name()?.to_str()?) && root.join("current").exists();
    staged.then(|| root.to_path_buf())
}

/// The binary a wicket process starts its children from: the versions root's `current` when this
/// process runs a staged version (so after a switch every new process is the new build), else this
/// binary.
pub fn self_exe() -> Result<PathBuf> {
    if let Some(root) = running_root() {
        let b = root.join("current").join("wicket");
        if b.is_file() {
            return Ok(b);
        }
    }
    std::env::current_exe().context("finding this binary")
}

/// Replaces this process with the current version in `versions` (else [`self_exe`]), same
/// arguments, same pid (only returns on failure).
pub fn reexec(versions: &Path) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let cur = versions.join("current").join("wicket");
    let exe = match cur.is_file() {
        true => cur,
        false => match self_exe() {
            Ok(e) => e,
            Err(e) => return e,
        },
    };
    let err = std::process::Command::new(&exe).args(std::env::args_os().skip(1)).exec();
    anyhow::anyhow!("re-executing {}: {err}", exe.display())
}

/// Writes this process's pid to `pidfile`, and on SIGHUP runs `before` and then re-executes from
/// the current version in `versions` ([`reexec`]): how a long-running wicket process moves to a new
/// build without a service manager. What `before` returns is held across the exec, and dropped only
/// if the exec fails (wicketd's handoff, #455). Must be called inside a tokio runtime.
pub fn reexec_on_hangup<G: 'static>(pidfile: PathBuf, versions: PathBuf, before: impl FnOnce() -> G + Send + 'static) {
    use tokio::signal::unix::{signal, SignalKind};
    if let Some(d) = pidfile.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = pidfile.with_extension(format!("{}.new", std::process::id()));
    if std::fs::write(&tmp, format!("{}\n", std::process::id())).is_ok() {
        let _ = std::fs::rename(&tmp, &pidfile);
    }
    // What this process runs, for checks that can't read `/proc/<pid>/exe`: a `node serve` makes
    // itself non-dumpable (it holds secrets in memory, #152), which hides that from its own user.
    if let Ok(exe) = std::env::current_exe().and_then(std::fs::canonicalize) {
        let tmp = pidfile.with_extension(format!("{}.exe-new", std::process::id()));
        if std::fs::write(&tmp, format!("{}\n{}\n", std::process::id(), exe.display())).is_ok() {
            let _ = std::fs::rename(&tmp, pidfile.with_extension("exe"));
        }
    }
    let Ok(mut hup) = signal(SignalKind::hangup()) else { return };
    tokio::spawn(async move {
        hup.recv().await;
        eprintln!("wicket: SIGHUP: re-executing from the current version");
        let _ = tokio::task::spawn_blocking(move || {
            let held = before();
            eprintln!("wicket: {:#}", reexec(&versions));
            drop(held);
        })
        .await;
    });
}

/// Makes `c` start detached from this process: in a session of its own, so a ^C or SIGHUP to this
/// process's terminal doesn't reach it, and with none of this process's descriptors but the stdio
/// `c` is given (a wrapped agent's launcher, say, would otherwise never see its stdout close).
/// How wicket starts what must outlive it: the local node's `serve`, a run's `attach`, a `wake`.
pub fn detach(c: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: async-signal-safe calls only, in the child before exec.
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            let max = match libc::sysconf(libc::_SC_OPEN_MAX) {
                n if n > 0 => n.min(65_536) as libc::c_int,
                _ => 1024,
            };
            for fd in 3..max {
                libc::close(fd);
            }
            Ok(())
        });
    }
}

/// The control host's versions root: the one the running binary is in (an installed host's
/// `/usr/local/bin/wicket` links into it), else `$WICKET_VERSIONS`, else `<data dir>/versions`.
pub fn control_root() -> PathBuf {
    if let Some(root) = running_root() {
        return root;
    }
    if let Some(v) = std::env::var_os("WICKET_VERSIONS").filter(|v| !v.is_empty()) {
        return PathBuf::from(v);
    }
    wicket_home::data_dir().join("versions")
}
