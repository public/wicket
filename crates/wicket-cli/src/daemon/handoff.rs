//! Commands that outlive the daemon image that started them (#455).
//!
//! Each command wicketd runs is a child process of the daemon, in its own process group, with the
//! caller's stdin, stdout and stderr. The daemon only follows it: it relays the caller's signals to
//! the child's group, and once the child exits it sends the caller its exit code. A long-lived run
//! is such a child for its whole life, so a daemon that waited for its children could never move
//! to a new build.
//!
//! So when `wicket self update` sends SIGHUP, the daemon hands its children to the build it
//! re-executes as. The process stays the same (its pid, and so its children), and so do the
//! callers' connections: each child's connection is kept open across the exec, and the new image
//! reads [`FILE`] and goes on following each child (relaying signals, sending the exit code).
//! Neither the caller nor the run notices.
//!
//! A restart by the service manager (`systemctl restart wicketd`, which `deploy/install.sh` runs)
//! is another process: wicketd.service's `KillMode=process` leaves the children running, as
//! orphans that carry on supervising their boxes; only their callers' connections end.
//!
//! The handoff is race-free: a child that exits is first waited for without being reaped
//! (`WNOWAIT`), then taken out of the registry, then reaped. The registry stays locked from the
//! handoff file's writing through the exec, so a child that exits meanwhile is reaped, with its
//! exit code, by the new image.

use super::proto::{self, kind};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// The handoff, in the data directory: written just before the exec, read and removed by the new
/// image at its start.
pub const FILE: &str = "daemon-handoff.json";

/// A child being followed: a copy of its caller's connection, and its staging directory (removed
/// once it exits).
struct Entry {
    conn: OwnedFd,
    stage: Option<PathBuf>,
}

fn registry() -> &'static Mutex<BTreeMap<i32, Entry>> {
    static R: OnceLock<Mutex<BTreeMap<i32, Entry>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn lock() -> MutexGuard<'static, BTreeMap<i32, Entry>> {
    registry().lock().unwrap_or_else(|e| e.into_inner())
}

/// What one image hands the next.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Handoff {
    /// The daemon's pid: only that process (after its exec) takes the handoff.
    pub daemon: u32,
    pub children: Vec<Handed>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Handed {
    pub pid: i32,
    /// The caller's connection, open across the exec.
    pub conn: i32,
    pub stage: Option<PathBuf>,
}

/// How many children are being followed.
pub fn followed() -> usize {
    lock().len()
}

/// Follows child `pid`, whose caller is on `conn`, until it exits: the caller's signals go to the
/// child's process group (its going away is a SIGTERM), and the result is the child's exit code
/// (128 + the signal, for one a signal ended). `stage` is removed after it exits, if this image
/// adopted the child (the image that started it drops its own).
/// `registered` runs once the child is in the registry, so a handoff from then on includes it.
pub fn follow(pid: i32, conn: &UnixStream, stage: Option<PathBuf>, registered: impl FnOnce()) -> Result<i32> {
    lock().insert(pid, Entry { conn: OwnedFd::from(conn.try_clone()?), stage });
    registered();
    let done = Arc::new(AtomicBool::new(false));
    relay(pid, conn.try_clone()?, done.clone());
    wait_exited(pid);
    let entry = lock().remove(&pid);
    let code = reap(pid);
    done.store(true, Ordering::SeqCst);
    drop(entry);
    Ok(code)
}

/// The caller's signals, relayed to the child's process group until it is done.
fn relay(pid: i32, mut rc: UnixStream, done: Arc<AtomicBool>) {
    std::thread::spawn(move || loop {
        match proto::read_frame(&mut rc) {
            Ok(Some((kind::SIGNAL, p))) if p.len() == 4 => {
                let sig = i32::from_be_bytes(p[..4].try_into().expect("4 bytes"));
                if [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT].contains(&sig) && !done.load(Ordering::SeqCst) {
                    // SAFETY: signalling the child's own process group.
                    unsafe { libc::kill(-pid, sig) };
                }
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                if !done.load(Ordering::SeqCst) {
                    // SAFETY: as above.
                    unsafe { libc::kill(-pid, libc::SIGTERM) };
                }
                return;
            }
        }
    });
}

/// Blocks until child `pid` has exited, without reaping it.
fn wait_exited(pid: i32) {
    loop {
        // SAFETY: a zeroed siginfo_t is a valid out-parameter for waitid.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: plain syscall on our own child.
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if r == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

/// Reaps child `pid`: its exit code, as a shell reports it (1 if it can't be had).
fn reap(pid: i32) -> i32 {
    let mut status = 0;
    loop {
        // SAFETY: plain syscall on our own child.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return exit_code(status);
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return 1;
    }
}

/// A wait status as an exit code: the code, or 128 + the signal that ended it.
pub fn exit_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}

/// Held from the handoff's writing through the exec. If the exec fails, dropping it gives the
/// connections back their close-on-exec flag and removes the handoff.
pub struct Prepared {
    _registry: MutexGuard<'static, BTreeMap<i32, Entry>>,
    fds: Vec<i32>,
    path: PathBuf,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        for fd in &self.fds {
            set_cloexec(*fd, true);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn set_cloexec(fd: i32, on: bool) {
    // SAFETY: plain fcntl on a descriptor this process owns.
    unsafe { libc::fcntl(fd, libc::F_SETFD, if on { libc::FD_CLOEXEC } else { 0 }) };
}

/// Writes the handoff to `path` for every child being followed, and keeps their connections open
/// across the coming exec. The registry stays locked while the result is held.
pub fn prepare(path: &Path) -> Result<Prepared> {
    let reg = lock();
    let h = Handoff {
        daemon: std::process::id(),
        children: reg.iter().map(|(pid, e)| Handed { pid: *pid, conn: e.conn.as_raw_fd(), stage: e.stage.clone() }).collect(),
    };
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(&h)?).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)?;
    let fds: Vec<i32> = h.children.iter().map(|c| c.conn).collect();
    for fd in &fds {
        set_cloexec(*fd, false);
    }
    Ok(Prepared { _registry: reg, fds, path: path.to_path_buf() })
}

/// What `path` hands this process, if it was written by this process before its exec: read and
/// removed. A handoff from another process (a daemon the service manager restarted) is stale: its
/// descriptors mean nothing here.
pub fn take(path: &Path) -> Option<Handoff> {
    let raw = std::fs::read(path).ok()?;
    let _ = std::fs::remove_file(path);
    let h: Handoff = serde_json::from_slice(&raw).ok()?;
    (h.daemon == std::process::id()).then_some(h)
}

/// Goes on following the children a previous image of this process handed over, each on a thread
/// of its own: the caller gets its exit code as if nothing had happened.
pub fn adopt(h: Handoff) {
    for c in h.children {
        // SAFETY: the previous image kept this descriptor open across the exec for this child alone.
        let conn = unsafe { OwnedFd::from_raw_fd(c.conn) };
        set_cloexec(conn.as_raw_fd(), true);
        let conn = UnixStream::from(conn);
        std::thread::spawn(move || {
            let code = follow(c.pid, &conn, c.stage.clone(), || {}).unwrap_or(1);
            let mut w = &conn;
            let _ = proto::write_frame(&mut w, kind::EXIT, &code.to_be_bytes());
            if let Some(s) = c.stage {
                let _ = std::fs::remove_dir_all(s);
            }
            say_err!("wicketd: a command handed over from the previous build ended ({code})");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    /// A child in its own process group, as the daemon starts each command; not waited for here.
    fn child(script: &str) -> i32 {
        let c = std::process::Command::new("sh").args(["-c", script]).process_group(0).spawn().unwrap();
        c.id() as i32
    }

    fn exit_frame(client: &mut UnixStream) -> i32 {
        loop {
            match proto::read_frame(client).unwrap() {
                Some((kind::EXIT, p)) => return i32::from_be_bytes(p[..4].try_into().unwrap()),
                Some(_) => {}
                None => panic!("no exit frame"),
            }
        }
    }

    fn cloexec(fd: i32) -> bool {
        // SAFETY: plain fcntl.
        unsafe { libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC != 0 }
    }

    #[test]
    fn a_followed_command_ends_with_its_exit_code_or_signal() {
        let (daemon, _client) = UnixStream::pair().unwrap();
        let mut registered = false;
        assert_eq!(follow(child("exit 7"), &daemon, None, || registered = true).unwrap(), 7);
        assert!(registered);
        assert_eq!(exit_code(9), 128 + 9, "a raw status for SIGKILL");
    }

    #[test]
    fn the_callers_signals_reach_the_command_and_its_leaving_stops_it() {
        let (daemon, mut client) = UnixStream::pair().unwrap();
        let pid = child("sleep 30");
        let t = std::thread::spawn(move || follow(pid, &daemon, None, || {}).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(200));
        proto::write_frame(&mut client, kind::SIGNAL, &libc::SIGINT.to_be_bytes()).unwrap();
        assert_eq!(t.join().unwrap(), 128 + libc::SIGINT);
        // The caller going away is a SIGTERM.
        let (daemon, client) = UnixStream::pair().unwrap();
        let pid = child("sleep 30");
        let t = std::thread::spawn(move || follow(pid, &daemon, None, || {}).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(200));
        drop(client);
        assert_eq!(t.join().unwrap(), 128 + libc::SIGTERM);
    }

    /// #455: the handoff names each followed command and keeps its connection open across the
    /// exec; if the exec fails, the connections close on exec again and the handoff is gone. Another
    /// process's handoff is never taken.
    #[test]
    fn a_handoff_carries_each_followed_command_and_is_undone_if_the_exec_fails() {
        let dir = std::env::temp_dir().join(format!("wicketd-handoff-{}", wicket_core::new_ulid()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE);
        let (daemon, client) = UnixStream::pair().unwrap();
        let pid = child("sleep 30");
        let stage = dir.join("stage");
        let s2 = stage.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || follow(pid, &daemon, Some(s2), move || tx.send(()).unwrap()).unwrap());
        rx.recv().unwrap();
        {
            let held = prepare(&path).unwrap();
            let h: Handoff = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let c = h.children.iter().find(|c| c.pid == pid).expect("handed");
            assert_eq!((h.daemon, c.stage.as_deref()), (std::process::id(), Some(stage.as_path())));
            assert!(!cloexec(c.conn), "kept open across the exec");
            let fd = c.conn;
            drop(held);
            assert!(cloexec(fd), "an exec that failed: closed on exec again");
            assert!(!path.exists());
        }
        // A handoff another process wrote is stale.
        std::fs::write(&path, serde_json::to_vec(&Handoff { daemon: std::process::id() + 1, children: vec![] }).unwrap()).unwrap();
        assert_eq!(take(&path), None);
        assert!(!path.exists(), "and removed");
        drop(client);
        assert_eq!(t.join().unwrap(), 128 + libc::SIGTERM);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #455: the new image follows a handed-over command to its end: its caller gets the exit code
    /// on the same connection, and its staging directory goes.
    #[test]
    fn an_adopted_command_reports_its_exit_code_to_its_caller() {
        let dir = std::env::temp_dir().join(format!("wicketd-adopt-{}", wicket_core::new_ulid()));
        std::fs::create_dir_all(dir.join("stage")).unwrap();
        let (daemon, mut client) = UnixStream::pair().unwrap();
        let pid = child("sleep 0.3; exit 3");
        // The previous image's copy of the connection, as the exec leaves it: the only one.
        let owned = OwnedFd::from(daemon);
        let conn = dup(owned.as_raw_fd());
        drop(owned);
        let h = Handoff { daemon: std::process::id(), children: vec![Handed { pid, conn, stage: Some(dir.join("stage")) }] };
        adopt(h);
        assert_eq!(exit_frame(&mut client), 3);
        for _ in 0..50 {
            if !dir.join("stage").exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!dir.join("stage").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn dup(fd: i32) -> i32 {
        // SAFETY: plain dup of a live descriptor; the copy is the handoff's to own.
        unsafe { libc::dup(fd) }
    }
}
