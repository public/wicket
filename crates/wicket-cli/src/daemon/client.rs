//! The CLI's side of `wicketd`: when the daemon is installed, commands go to it instead of
//! touching wicket's data, which this user can't read.

use super::proto::{self, kind, Hello, Welcome};
use super::{policy, upload, SOCKET_PATH};
use crate::{Cmd, SecretCmd};
use anyhow::{bail, Context, Result};
use std::io::{IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// How this process reaches wicket's data.
#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    /// Itself: development mode (one user, no daemon), or the daemon's own user.
    Direct,
    /// Through the daemon at this socket.
    Daemon(PathBuf),
    /// A system install whose daemon isn't there: refuse rather than fall back to a private,
    /// empty development installation.
    Missing(String),
}

/// `WICKET_HOME` set (and no `WICKET_DAEMON_SOCKET`) means direct, as tests and development use;
/// otherwise the daemon's socket decides, unless it is this user's own.
pub fn mode() -> Mode {
    let explicit = std::env::var_os("WICKET_DAEMON_SOCKET").filter(|s| !s.is_empty()).map(PathBuf::from);
    if explicit.is_none() && std::env::var_os("WICKET_HOME").is_some() {
        return Mode::Direct;
    }
    let sock = explicit.clone().unwrap_or_else(|| PathBuf::from(SOCKET_PATH));
    // SAFETY: a plain getter.
    let me = unsafe { libc::geteuid() };
    match std::fs::metadata(&sock) {
        Ok(m) if m.uid() == me => Mode::Direct,
        Ok(_) => Mode::Daemon(sock),
        Err(_) if explicit.is_some() => Mode::Missing(format!("WICKET_DAEMON_SOCKET is {}, which doesn't exist", sock.display())),
        Err(_) if Path::new(policy::POLICY_PATH).exists() => Mode::Missing(format!(
            "wicket is installed for the whole host ({} exists) but wicketd isn't listening on {}: sudo systemctl start wicketd",
            policy::POLICY_PATH,
            sock.display()
        )),
        Err(_) => Mode::Direct,
    }
}

/// Runs `cmd` (this process's command line) through the daemon; returns its exit status.
pub async fn forward(sock: &Path, cmd: &Cmd) -> Result<i32> {
    let argv: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().map_err(|a| anyhow::anyhow!("argument {a:?} is not UTF-8")))
        .collect::<Result<_>>()?;
    forward_with(sock, cmd, argv, [0, 1, 2]).await
}

/// [`forward`], with the command line and the stdio fds given.
pub async fn forward_with(sock: &Path, cmd: &Cmd, argv: Vec<String>, stdio: [i32; 3]) -> Result<i32> {
    let s = UnixStream::connect(sock)
        .with_context(|| format!("connecting to wicketd at {} (sudo systemctl status wicketd)", sock.display()))?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));

    // stdin: a secret is read here, where the terminal is, and handed over through a pipe.
    let mut stdin_pipe: Option<OwnedFd> = None;
    if let Cmd::Secret { cmd: SecretCmd::Set { name } } = cmd {
        let value = if std::io::stdin().is_terminal() {
            rpassword::prompt_password(format!("value for {name} (not echoed): "))?
        } else {
            let mut v = String::new();
            std::io::stdin().read_to_string(&mut v)?;
            v
        };
        let (r, mut w) = std::io::pipe()?;
        // Written from a thread: a value larger than the pipe's buffer would block until read.
        std::thread::spawn(move || {
            let _ = w.write_all(value.as_bytes());
        });
        stdin_pipe = Some(r.into());
    }
    let stdin_fd = stdin_pipe.as_ref().map(|f| f.as_raw_fd()).unwrap_or(stdio[0]);

    // A directory mounted in place is passed open, so the daemon can check who owns it.
    let dir: Option<std::fs::File> = match cmd {
        Cmd::Run { workspace_dir: Some(d), .. } => Some(open_dir(d)?),
        Cmd::Wrap { .. } => Some(open_dir(&cwd)?),
        _ => None,
    };
    let mut fds = vec![stdin_fd, stdio[1], stdio[2]];
    if let Some(d) = &dir {
        fds.push(d.as_raw_fd());
    }
    proto::send_fds(&s, &fds)?;
    drop(stdin_pipe);
    drop(dir);

    // The files a run names go as content.
    let mut uploads: Vec<(&str, PathBuf)> = vec![];
    let mut manifest_name = None;
    let mut program_source = None;
    if let Cmd::Run { manifest, .. } | Cmd::Wrap { manifest, .. } = cmd {
        let raw = std::fs::read_to_string(manifest).with_context(|| format!("reading {}", manifest.display()))?;
        let m = wicket_core::manifest::Manifest::from_yaml(&raw).with_context(|| manifest.display().to_string())?;
        manifest_name = Some(manifest.file_name().context("the manifest has no file name")?.to_string_lossy().into_owned());
        uploads.push(("manifest", manifest.clone()));
        program_source = m.program.as_ref().and_then(|p| p.source.clone());
        if let Some(src) = &program_source {
            upload::manifest_layout(manifest_name.as_deref().unwrap_or_default(), Some(src))?;
            uploads.push(("program", manifest.parent().unwrap_or(Path::new(".")).join(src)));
        }
    }
    if let Cmd::Run { workdir: Some(w), .. } = cmd {
        uploads.push(("workdir", w.clone()));
    }

    let mut w = s.try_clone()?;
    let mut r = s.try_clone()?;
    let hello = Hello {
        version: env!("CARGO_PKG_VERSION").into(),
        argv,
        cwd: cwd.display().to_string(),
        log: std::env::var("WICKET_LOG").ok(),
        dir_fd: fds.len() > 3,
        manifest_name,
        program_source,
    };
    proto::write_json(&mut w, kind::HELLO, &hello)?;
    let welcome: Welcome = match proto::read_frame(&mut r)? {
        Some((kind::WELCOME, p)) => serde_json::from_slice(&p)?,
        Some((kind::ERROR, p)) => bail!("wicketd: {}", String::from_utf8_lossy(&p)),
        _ => bail!("wicketd closed the connection"),
    };
    let mut client_ok = true;
    if let Cmd::Doctor { .. } = cmd {
        client_ok = doctor(sock, &welcome);
    }
    for (role, path) in &uploads {
        upload::send(&mut w, role, path).with_context(|| format!("sending {}", path.display()))?;
    }
    proto::write_frame(&mut w, kind::GO, b"")?;

    // Wait for the exit status, passing on the signals a terminal sends.
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let res = (|| -> Result<i32> {
            loop {
                match proto::read_frame(&mut r)? {
                    Some((kind::EXIT, p)) if p.len() == 4 => return Ok(i32::from_be_bytes(p[..4].try_into().expect("4 bytes"))),
                    Some((kind::ERROR, p)) => bail!("wicketd: {}", String::from_utf8_lossy(&p)),
                    Some(_) => {}
                    None => bail!("wicketd closed the connection before the command finished"),
                }
            }
        })();
        let _ = tx.send(res);
    });
    use tokio::signal::unix::{signal, SignalKind};
    let mut int = signal(SignalKind::interrupt())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut quit = signal(SignalKind::quit())?;
    tokio::pin!(rx);
    let code = loop {
        let sig = tokio::select! {
            res = &mut rx => break res.context("wicketd's reader")??,
            _ = int.recv() => libc::SIGINT,
            _ = term.recv() => libc::SIGTERM,
            _ = hup.recv() => libc::SIGHUP,
            _ = quit.recv() => libc::SIGQUIT,
        };
        let _ = proto::write_frame(&mut w, kind::SIGNAL, &sig.to_be_bytes());
    };
    Ok(if code == 0 && !client_ok { 1 } else { code })
}

fn open_dir(d: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(d).with_context(|| format!("opening {}", d.display()))
}

/// `wicket doctor`'s checks from the caller's side: what the caller must *not* be able to do.
fn doctor(sock: &Path, w: &Welcome) -> bool {
    let mut ok = true;
    println!("mode: system install, through wicketd at {} (running as {}, version {})", sock.display(), w.daemon_user, w.version);
    if w.version != env!("CARGO_PKG_VERSION") {
        println!("  NOT OK: this wicket is version {}, the daemon's is {}", env!("CARGO_PKG_VERSION"), w.version);
        ok = false;
    }
    println!("you: {}; let in as {}", w.you, w.basis);
    // SAFETY: a plain getter.
    let root = unsafe { libc::geteuid() } == 0;
    if root {
        println!("  (as root: the host break-glass; the checks below are for operators' own users)");
        return ok;
    }
    match std::fs::read_dir(&w.data_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => println!("data {}: not readable by you (good)", w.data_dir),
        Err(e) => println!("data {}: {e}", w.data_dir),
        Ok(_) => {
            println!("data {}: NOT OK: readable by you; it must be the wicket user's alone (chmod 0700)", w.data_dir);
            ok = false;
        }
    }
    let ledger = Path::new(&w.data_dir).join("ledger.db");
    if std::fs::File::open(&ledger).is_ok() {
        println!("ledger: NOT OK: you can open {}", ledger.display());
        ok = false;
    }
    // Being in the docker group is root on the host: it reaches every box and every file.
    let docker = proto::group_id("docker");
    let mut groups = vec![0 as libc::gid_t; 512];
    // SAFETY: getgroups writes at most `groups.len()` gids.
    let n = unsafe { libc::getgroups(groups.len() as i32, groups.as_mut_ptr()) };
    groups.truncate(n.max(0) as usize);
    if docker.is_some_and(|g| groups.contains(&g)) {
        println!("docker: NOT OK: you are in the docker group, which is root on this host: anything running as you could reach every box and wicket's data. Only the wicket user should be (sudo gpasswd -d $USER docker)");
        ok = false;
    } else if UnixStream::connect("/var/run/docker.sock").is_ok() {
        println!("docker: NOT OK: you can connect to Docker's socket, which is root on this host");
        ok = false;
    } else {
        println!("docker: not reachable by you (good)");
    }
    ok
}
