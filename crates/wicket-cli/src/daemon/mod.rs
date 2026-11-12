//! `wicketd` (#12): wicket as its own system user.
//!
//! The `wicket` user owns the data directory (ledger, vault, issuer key, CA, feed and authz keys,
//! run directories and their sockets; mode 0700) and is the only user in the `docker` group. Other
//! users reach wicket only through this daemon's socket (`/run/wicket/wicketd.sock`), which:
//! - learns who is calling from the kernel (`SO_PEERCRED`, `SO_PEERGROUPS`);
//! - parses the command line again and checks it against the policy ([`policy`]): operators may
//!   start and steer runs, read state and revoke; approving, denying and other privileged commands
//!   need root (the host break-glass), or a passkey in the console;
//! - runs the command as `wicket` (this same binary, a child process), with the caller's stdin,
//!   stdout and stderr, its principal and operator name set from the peer credentials, and the files
//!   it names sent as content ([`upload`]).
//!
//! Without the daemon (no socket), the CLI works as it always did, as one user: development mode,
//! which `wicket doctor` labels insecure.

pub mod client;
pub mod policy;
pub mod proto;
pub mod upload;

pub use proto::Peer;

use crate::Cmd;
use anyhow::{bail, Context, Result};
use policy::{Basis, Class, Policy, Route};
use proto::{kind, Hello, Welcome};
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Where the daemon listens (systemd's RuntimeDirectory=wicket).
pub const SOCKET_PATH: &str = "/run/wicket/wicketd.sock";

pub struct Daemon {
    pub data_dir: PathBuf,
    pub policy_path: PathBuf,
    /// The uid the daemon runs as: trusted with everything.
    pub uid: u32,
    pub user: String,
    /// The binary each command runs as.
    pub exe: PathBuf,
}

/// `wicket daemon`: serve the socket until killed.
pub fn serve(socket: &Path, policy_path: PathBuf) -> Result<()> {
    // SAFETY: plain syscalls.
    unsafe { libc::umask(0o077) };
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        bail!("wicketd runs as the wicket system user, not as root (see deploy/install.sh)");
    }
    let data_dir = crate::data_dir();
    prepare_data_dir(&data_dir, uid)?;
    Policy::load(&policy_path)?;
    let d = Arc::new(Daemon {
        data_dir,
        policy_path,
        uid,
        user: proto::user_name(uid).unwrap_or_else(|| uid.to_string()),
        exe: std::env::current_exe().context("finding this binary")?,
    });
    let listener = listen(socket)?;
    eprintln!("wicketd: {} as {} (uid {uid}), data {}, policy {}", socket.display(), d.user, d.data_dir.display(), d.policy_path.display());
    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                eprintln!("wicketd: accept: {e}");
                continue;
            }
        };
        let d = d.clone();
        std::thread::spawn(move || {
            if let Err(e) = d.handle(conn) {
                eprintln!("wicketd: {e:#}");
            }
        });
    }
    Ok(())
}

/// The data directory exists, is ours, and is 0700.
pub fn prepare_data_dir(dir: &Path, uid: u32) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
    let m = std::fs::metadata(dir)?;
    if m.uid() != uid {
        bail!("{} is owned by uid {}, not by this user (uid {uid})", dir.display(), m.uid());
    }
    if m.permissions().mode() & 0o077 != 0 {
        eprintln!("wicketd: {} was mode {:o}; setting 0700", dir.display(), m.permissions().mode() & 0o7777);
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Binds the socket, replacing a stale one. It is 0666: who may do what is decided per connection
/// from the peer's credentials, not by who can connect.
pub fn listen(socket: &Path) -> Result<UnixListener> {
    if let Ok(m) = std::fs::symlink_metadata(socket) {
        use std::os::unix::fs::FileTypeExt;
        if !m.file_type().is_socket() {
            bail!("{} exists and is not a socket", socket.display());
        }
        std::fs::remove_file(socket)?;
    }
    let l = UnixListener::bind(socket).with_context(|| format!("listening on {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))?;
    Ok(l)
}

/// What a forwarded command becomes.
struct Plan {
    argv: Vec<String>,
    cwd: PathBuf,
    stage: Option<upload::Stage>,
    /// The principal and operator name the child acts as (None: its own, as the daemon's uid).
    caller: Option<(serde_json::Value, String)>,
}

impl Daemon {
    fn handle(&self, conn: UnixStream) -> Result<()> {
        let peer = proto::peer(&conn)?;
        let mut fds = proto::recv_fds(&conn)?;
        let mut w = conn.try_clone()?;
        let mut r = conn.try_clone()?;
        let hello: Hello = match proto::read_frame(&mut r)? {
            Some((kind::HELLO, p)) => serde_json::from_slice(&p).context("bad hello")?,
            _ => bail!("uid {}: no hello", peer.uid),
        };
        if fds.len() < 3 || (hello.dir_fd && fds.len() < 4) {
            return refuse(&mut w, "the caller's stdin, stdout and stderr did not arrive");
        }
        let dir_fd = if hello.dir_fd { fds.pop() } else { None };
        let (cmd, class, basis) = match self.admit(&peer, &hello) {
            Ok(x) => x,
            Err(why) => {
                eprintln!("wicketd: refused uid {} ({}): {}: {why}", peer.uid, peer.user, words(&hello.argv));
                self.audit_refusal(&peer, &hello, &why);
                return refuse(&mut w, &why);
            }
        };
        let mut plan = match self.plan(&peer, &basis, &cmd, &hello, dir_fd) {
            Ok(p) => p,
            Err(e) => return refuse(&mut w, &format!("{e:#}")),
        };
        proto::write_json(
            &mut w,
            kind::WELCOME,
            &Welcome {
                version: env!("CARGO_PKG_VERSION").into(),
                data_dir: self.data_dir.display().to_string(),
                daemon_user: self.user.clone(),
                you: format!("{} (uid {})", peer.user, peer.uid),
                basis: match basis {
                    Basis::Root => "root",
                    Basis::Daemon => "daemon",
                    Basis::Policy => "policy",
                }
                .into(),
            },
        )?;
        // Uploads, then go.
        loop {
            match proto::read_frame(&mut r)? {
                Some((kind::UPLOAD, p)) => {
                    let (e, data) = proto::parse_upload(&p)?;
                    let stage = plan.stage.as_mut().context("this command takes no uploads")?;
                    if let Err(e) = stage.add(&e, data) {
                        return refuse(&mut w, &format!("{e:#}"));
                    }
                }
                Some((kind::GO, _)) => break,
                Some((k, _)) => bail!("unexpected frame {:?} before go", k as char),
                None => return Ok(()),
            }
        }
        if let Some(s) = plan.stage.as_mut() {
            if let Err(e) = s.finish().and_then(|_| check_staged(&cmd, &hello, s)) {
                return refuse(&mut w, &format!("{e:#}"));
            }
        }
        eprintln!("wicketd: uid {} ({}) {}: {} [{}]", peer.uid, peer.user, class.name(), words(&hello.argv), plan.argv.first().map(String::as_str).unwrap_or(""));
        let code = self.run_child(&plan, fds, &hello, &mut r)?;
        drop(plan.stage.take());
        proto::write_frame(&mut w, kind::EXIT, &code.to_be_bytes())?;
        Ok(())
    }

    /// Parses, routes and authorizes a command line.
    fn admit(&self, peer: &Peer, hello: &Hello) -> std::result::Result<(Cmd, Class, Basis), String> {
        use clap::Parser;
        let cmd = crate::Cli::try_parse_from(std::iter::once("wicket".to_string()).chain(hello.argv.iter().cloned()))
            .map_err(|e| e.to_string())?
            .cmd;
        let class = match policy::route(&cmd) {
            Route::Forward(c) => c,
            Route::Local => return Err("this command runs in the caller's own process, not through wicketd".into()),
            Route::Refuse(why) => return Err(why.into()),
        };
        let policy = Policy::load(&self.policy_path).map_err(|e| format!("the daemon's policy is unreadable: {e}"))?;
        let basis = policy::authorize(peer, class, &policy, self.uid)?;
        if basis != Basis::Daemon {
            if let Some(a) = policy::internal_args(&cmd) {
                return Err(format!("{a} is for wicket's own use"));
            }
        }
        Ok((cmd, class, basis))
    }

    fn audit_refusal(&self, peer: &Peer, hello: &Hello, why: &str) {
        let r = wicket_store::Ledger::open(&self.data_dir.join("ledger.db")).and_then(|l| {
            l.audit(
                &wicket_core::TenantId::single(),
                None,
                "daemon.refused",
                &serde_json::json!({ "uid": peer.uid, "user": peer.user, "pid": peer.pid, "command": words(&hello.argv), "why": why }),
            )
        });
        if let Err(e) = r {
            eprintln!("wicketd: recording the refusal: {e}");
        }
    }

    fn plan(&self, peer: &Peer, basis: &Basis, cmd: &Cmd, hello: &Hello, dir_fd: Option<OwnedFd>) -> Result<Plan> {
        let caller = match basis {
            Basis::Daemon => None,
            Basis::Root => Some((principal(peer), format!("{}@host (break-glass: uid 0 over wicketd's socket)", peer.user))),
            Basis::Policy => Some((principal(peer), format!("{}@cli (uid {}, over wicketd's socket)", peer.user, peer.uid))),
        };
        let dir = dir_fd.map(|fd| self.checked_dir(&fd, peer, basis)).transpose()?;
        let default_cwd = || {
            let c = PathBuf::from(&hello.cwd);
            if c.is_absolute() && accessible(&c) {
                c
            } else {
                self.data_dir.clone()
            }
        };
        let stage_parent = self.data_dir.join("daemon/stage");
        let stage_for = |workdir: bool| -> Result<(upload::Stage, PathBuf)> {
            let name = hello.manifest_name.clone().context("the manifest did not come with the command")?;
            let (m, src) = upload::manifest_layout(&name, hello.program_source.as_deref())?;
            let mut roots = vec![("manifest".to_string(), m.clone())];
            if let Some(s) = src {
                roots.push(("program".into(), s));
            }
            if workdir {
                roots.push(("workdir".into(), "w".into()));
            }
            let st = upload::Stage::new(&stage_parent, roots)?;
            let mp = st.dir.join(&m);
            Ok((st, mp))
        };
        Ok(match cmd {
            Cmd::Run { workdir, workspace_dir, task, image, node, .. } => {
                let (st, mp) = stage_for(workdir.is_some())?;
                let mut argv = vec!["run".to_string(), mp.display().to_string()];
                if workdir.is_some() {
                    argv.extend(["--workdir".into(), st.dir.join("w").display().to_string()]);
                }
                match (workspace_dir, &dir) {
                    (Some(_), Some(d)) => argv.extend(["--workspace-dir".into(), d.display().to_string()]),
                    (Some(_), None) => bail!("--workspace-dir needs the directory itself (it is passed open, to check who owns it)"),
                    _ => {}
                }
                if let Some(t) = task {
                    argv.extend(["--task".into(), t.clone()]);
                }
                argv.extend(["--image".into(), image.clone()]);
                if let Some(n) = node {
                    argv.extend(["--node".into(), n.clone()]);
                }
                Plan { argv, cwd: self.data_dir.clone(), stage: Some(st), caller }
            }
            Cmd::Wrap { image, argv: agent, .. } => {
                let (st, mp) = stage_for(false)?;
                let cwd = dir.context("a wrapped agent works in its launcher's directory, which must be passed open")?;
                let mut argv = vec!["wrap".to_string(), "--manifest".into(), mp.display().to_string(), "--image".into(), image.clone(), "--".into()];
                argv.extend(agent.iter().cloned());
                Plan { argv, cwd, stage: Some(st), caller }
            }
            _ => Plan { argv: hello.argv.clone(), cwd: default_cwd(), stage: None, caller },
        })
    }

    /// A directory the caller passed open (to mount in place): a directory, the caller's own, and
    /// neither inside nor above the data directory.
    fn checked_dir(&self, fd: &OwnedFd, peer: &Peer, basis: &Basis) -> Result<PathBuf> {
        let f = std::fs::File::from(fd.try_clone()?);
        let m = f.metadata()?;
        if !m.is_dir() {
            bail!("the directory passed is not a directory");
        }
        let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
        if !path.is_absolute() || path.to_string_lossy().ends_with(" (deleted)") {
            bail!("the directory passed has no path ({})", path.display());
        }
        if *basis == Basis::Policy && m.uid() != peer.uid {
            bail!("{} is owned by uid {}, not by you (uid {}): only your own directories can be mounted into a box", path.display(), m.uid(), peer.uid);
        }
        if path == Path::new("/") || path.starts_with(&self.data_dir) || self.data_dir.starts_with(&path) {
            bail!("{} can't be mounted into a box: it is, or holds, wicket's data", path.display());
        }
        Ok(path)
    }

    fn run_child(&self, plan: &Plan, fds: Vec<OwnedFd>, hello: &Hello, r: &mut UnixStream) -> Result<i32> {
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        let mut fds = fds.into_iter();
        let (i, o, e) = (fds.next().expect("3 fds"), fds.next().expect("3 fds"), fds.next().expect("3 fds"));
        let mut c = std::process::Command::new(&self.exe);
        c.args(&plan.argv)
            .current_dir(&plan.cwd)
            .env_remove("WICKET_PRINCIPAL")
            .env_remove("WICKET_OPERATOR")
            .env_remove("WICKET_DAEMON_SOCKET")
            .env("WICKET_HOME", &self.data_dir)
            .stdin(std::process::Stdio::from(i))
            .stdout(std::process::Stdio::from(o))
            .stderr(std::process::Stdio::from(e))
            .process_group(0);
        if let Some((p, op)) = &plan.caller {
            c.env("WICKET_PRINCIPAL", p.to_string()).env("WICKET_OPERATOR", op);
        }
        match hello.log.as_deref().filter(|l| valid_log_filter(l)) {
            Some(l) => c.env("WICKET_LOG", l),
            None => c.env_remove("WICKET_LOG"),
        };
        let mut child = c.spawn().context("starting the command")?;
        let pid = child.id() as i32;
        let done = Arc::new(AtomicBool::new(false));
        // Signals from the caller go to the command's process group; the caller going away stops it.
        let mut rc = r.try_clone()?;
        let done2 = done.clone();
        std::thread::spawn(move || {
            loop {
                match proto::read_frame(&mut rc) {
                    Ok(Some((kind::SIGNAL, p))) if p.len() == 4 => {
                        let sig = i32::from_be_bytes(p[..4].try_into().expect("4 bytes"));
                        if [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT].contains(&sig) && !done2.load(Ordering::SeqCst) {
                            // SAFETY: signalling the child's own process group.
                            unsafe { libc::kill(-pid, sig) };
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => {
                        if !done2.load(Ordering::SeqCst) {
                            // SAFETY: as above.
                            unsafe { libc::kill(-pid, libc::SIGTERM) };
                        }
                        return;
                    }
                }
            }
        });
        let st = child.wait()?;
        done.store(true, Ordering::SeqCst);
        Ok(st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0)))
    }
}

/// After uploads: the staged manifest's program source is the one the layout was made for, so it
/// resolves inside the staging directory.
fn check_staged(cmd: &Cmd, hello: &Hello, st: &upload::Stage) -> Result<()> {
    if !matches!(cmd, Cmd::Run { .. } | Cmd::Wrap { .. }) {
        return Ok(());
    }
    let path = st.root("manifest").context("no manifest")?;
    let raw = std::fs::read_to_string(&path).context("the manifest did not arrive")?;
    let m = wicket_core::manifest::Manifest::from_yaml(&raw)?;
    let source = m.program.as_ref().and_then(|p| p.source.clone());
    if source != hello.program_source {
        bail!("the manifest's program source differs from the one announced");
    }
    if let Some(p) = st.root("program") {
        if !p.is_dir() {
            bail!("the program's source did not arrive");
        }
    }
    Ok(())
}

/// The principal of a run a caller starts: the unix user the kernel named.
fn principal(peer: &Peer) -> serde_json::Value {
    serde_json::json!({ "type": "human", "id": peer.user, "via": "cli", "assurance": "unix-peercred" })
}

/// The command's words (no option values or free text: journals are readable by more people).
fn words(argv: &[String]) -> String {
    argv.iter().take_while(|a| !a.starts_with('-')).take(2).cloned().collect::<Vec<_>>().join(" ")
}

fn valid_log_filter(s: &str) -> bool {
    s.len() < 200 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_=,:.-".contains(c))
}

/// Whether this process may enter `dir`.
fn accessible(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else { return false };
    // SAFETY: a NUL-terminated path.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

fn refuse(w: &mut UnixStream, why: &str) -> Result<()> {
    let _ = proto::write_frame(w, kind::ERROR, why.as_bytes());
    let _ = w.flush();
    Ok(())
}

#[cfg(test)]
mod tests;
