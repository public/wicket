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
pub mod handoff;
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
use wicket_home::exit::Code;
use wicket_store::Ledger;

/// Where the daemon listens (systemd's RuntimeDirectory=wicket).
pub const SOCKET_PATH: &str = "/run/wicket/wicketd.sock";

pub struct Daemon {
    pub data_dir: PathBuf,
    pub policy_path: PathBuf,
    /// The uid the daemon runs as: trusted with everything.
    pub uid: u32,
    pub user: String,
    /// The binary each command runs as (resolved at each command).
    pub exe: PathBuf,
    /// The vault its commands use (`$HOME/.config/wicket/secrets`).
    pub vault_dir: PathBuf,
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
        // When installed as a version, the `current` link, so commands run as whichever build
        // `wicket self update` last switched to.
        exe: crate::update::self_exe()?,
        vault_dir: wicket_proxy::vault::Vault::default_dir(),
    });
    let listener = listen(socket)?;
    // The commands a previous image of this process handed over (#455): followed on to their end.
    let handoff_path = d.data_dir.join(handoff::FILE);
    let mut followed = None;
    if let Some(h) = handoff::take(&handoff_path) {
        say_err!("wicketd: following {} command(s) handed over by the previous build", h.children.len());
        followed = Some(h.children.len());
        handoff::adopt(h);
    }
    // Runs that outlived a previous wicketd (#468: `deploy/install.sh` restarts it) go on with
    // supervisors on the build they started on, which may not read this build's ledger (#475): each
    // moves to this build, as `wicket self update` moves them.
    {
        let exe = d.exe.clone();
        std::thread::spawn(move || hand_over_runs(&exe, followed));
    }
    // Supervisor hosts (#582 step 5), when the installation asks for them (`supervise.hosts`):
    // started, heartbeated and fenced by this process alone, so two never race for a shard.
    match wicket_agent::acp::load_supervise(&wicket_agent::acp::settings_path()) {
        Ok(s) if s.hosts > 0 => {
            let (exe, data) = (d.exe.clone(), d.data_dir.clone());
            std::thread::Builder::new().name("supervisor-hosts".into()).spawn(move || manage_hosts(s.hosts, exe, data))?;
        }
        Ok(_) => {}
        Err(e) => say_err!("wicketd: no supervisor hosts: {e}"),
    }
    // `wicket self update` moves the daemon to the new build last: on SIGHUP it re-executes itself
    // at once, handing its running commands (long-lived runs among them) to the new image
    // ([`handoff`]). Only commands not yet started (admission, uploads: seconds) are waited for;
    // new ones are refused meanwhile, to be tried again.
    crate::update::reexec_on_hangup(crate::update::pidfile("daemon"), crate::update::Versions::control().root, move || {
        drain(&handoff_path, &DRAINING, &IN_FLIGHT)
    });
    say_err!("wicketd: {} as {} (uid {uid}), data {}, policy {}", socket.display(), d.user, d.data_dir.display(), d.policy_path.display());
    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                say_err!("wicketd: accept: {e}");
                continue;
            }
        };
        let d = d.clone();
        std::thread::spawn(move || {
            if let Err(e) = d.handle(conn) {
                say_err!("wicketd: {e:#}");
            }
        });
    }
    Ok(())
}

/// wicketd's host manager (#582 step 5): a [`Manager`](wicket_control::supervise::Manager) tick
/// every few seconds, on a ledger connection of its own, reopened when it fails. Runs for wicketd's
/// life; after a re-exec the new image adopts the hosts that answer on their sockets.
fn manage_hosts(hosts: usize, exe: PathBuf, data_dir: PathBuf) {
    use wicket_control::supervise::{Manager, ProcIo, RENEW_SECS};
    let mut m = Manager::new(hosts);
    let mut io = ProcIo { exe, data_dir: data_dir.clone(), env: Vec::new(), spawned: Vec::new() };
    let mut ledger = None;
    say_err!("wicketd: {hosts} supervisor host(s)");
    loop {
        if ledger.is_none() {
            ledger = Ledger::open(&data_dir.join("ledger.db")).map_err(|e| say_err!("wicketd: supervisor hosts: the ledger: {e}")).ok();
        }
        if let Some(l) = &ledger {
            let t = m.tick(l, &mut io, wicket_store::now());
            for s in &t.started {
                say_err!("wicketd: started shard {s}'s supervisor host");
            }
            for s in &t.fenced {
                say_err!("wicketd: fenced shard {s}'s supervisor host (a higher epoch, then a fresh host)");
            }
            if !t.errors.is_empty() {
                for e in &t.errors {
                    say_err!("wicketd: supervisor hosts: {e}");
                }
                ledger = None;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(RENEW_SECS));
    }
}

/// What wicketd does on SIGHUP before it re-executes: refuses new commands, waits for the ones
/// being started, and writes the handoff of the running ones ([`handoff::prepare`]), held across
/// the exec. Returns at once whatever the running commands do (#487: it once deadlocked here).
fn drain(handoff_path: &Path, draining: &'static AtomicBool, in_flight: &std::sync::atomic::AtomicUsize) -> Draining {
    draining.store(true, Ordering::SeqCst);
    let mut waited = 0u64;
    while in_flight.load(Ordering::SeqCst) > 0 {
        if waited.is_multiple_of(10) {
            say_err!("wicketd: waiting for {} command(s) being started before moving to the new build", in_flight.load(Ordering::SeqCst));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        waited += 1;
    }
    let held = handoff::prepare(handoff_path);
    match &held {
        Ok(p) => say_err!("wicketd: handing {} running command(s) to the new build", p.handed()),
        Err(e) => say_err!("wicketd: no handoff ({e:#}): its running commands lose their callers' connections"),
    }
    Draining(held.ok(), draining)
}

/// Hands each run whose supervisor runs another build than `exe` over to `exe` (#475): the
/// supervisor is stopped without its box, and `exe`'s reconciler starts a new one that re-attaches.
///
/// This host's own node's serve moves to `exe` first (#529): a restart of wicketd leaves it, its
/// child, on the build it started on, and the new supervisors re-attach to it.
///
/// First it audits its own start (`daemon.started`: its build, and how many commands it followed
/// from a previous image, if it re-executed): with `wicket self update`'s `daemon.sighup`, what
/// shows a drain and how long it took in the audit trail (#487 left none: verification/tla's
/// `UpdateTrace`). Here, not in the drain: the drain must not wait on the ledger.
fn hand_over_runs(exe: &Path, followed: Option<usize>) {
    let build = std::fs::canonicalize(exe).ok().and_then(|p| Some(p.parent()?.file_name()?.to_string_lossy().into_owned()));
    let started = serde_json::json!({ "build": build, "followed": followed });
    if let Err(e) =
        Ledger::open(&crate::ledger_path()).and_then(|l| l.audit(&wicket_core::TenantId::single(), None, "daemon.started", &started))
    {
        say_err!("wicketd: auditing its start: {e:#}");
    }
    if let Some(line) = crate::update::reexec_local_node(exe) {
        say_err!("wicketd: {line}");
    }
    let killed =
        match Ledger::open(&crate::ledger_path()).map_err(anyhow::Error::from).and_then(|l| crate::update::stop_stale_supervisors(&l, exe))
        {
            Ok(k) => k,
            Err(e) => {
                say_err!("wicketd: checking runs' supervisors: {e:#}");
                return;
            }
        };
    if killed.is_empty() {
        return;
    }
    say_err!("wicketd: {} run(s) were supervised by another build: handing them to this one", killed.len());
    match crate::update::adopt_handed(exe, &killed) {
        Ok(s) => say_err!("wicketd: {s}"),
        Err(e) => say_err!("wicketd: {e:#}"),
    }
}

/// Commands being started through the daemon (admitted, uploading, not yet followed as a child).
static IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Set while the daemon moves to a new build: new commands are refused, to be tried again.
static DRAINING: AtomicBool = AtomicBool::new(false);

/// Held across the exec; if the exec fails, the daemon takes commands again.
struct Draining(#[allow(dead_code)] Option<handoff::Prepared>, &'static AtomicBool);
impl Drop for Draining {
    fn drop(&mut self) {
        self.1.store(false, Ordering::SeqCst);
    }
}

struct InFlight;
impl InFlight {
    fn enter() -> InFlight {
        IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        InFlight
    }
}
impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The data directory exists, is ours, and is 0700.
pub fn prepare_data_dir(dir: &Path, uid: u32) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
    let m = std::fs::metadata(dir)?;
    if m.uid() != uid {
        bail!("{} is owned by uid {}, not by this user (uid {uid})", dir.display(), m.uid());
    }
    if m.permissions().mode() & 0o077 != 0 {
        say_err!("wicketd: {} was mode {:o}; setting 0700", dir.display(), m.permissions().mode() & 0o7777);
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
        let busy = InFlight::enter();
        let peer = proto::peer(&conn)?;
        let mut fds = proto::recv_fds(&conn)?;
        let mut w = conn.try_clone()?;
        let mut r = conn.try_clone()?;
        let hello: Hello = match proto::read_frame(&mut r)? {
            Some((kind::HELLO, p)) => serde_json::from_slice(&p).context("bad hello")?,
            _ => bail!("uid {}: no hello", peer.uid),
        };
        if let Some((code, why)) = turned_away(DRAINING.load(Ordering::SeqCst), fds.len(), hello.dir_fd) {
            return fail_with(&mut w, hello.codes, code, why);
        }
        let dir_fd = if hello.dir_fd { fds.pop() } else { None };
        let (cmd, class, basis) = match self.admit(&peer, &hello) {
            Ok(x) => x,
            Err((code, why)) => {
                say_err!("wicketd: refused uid {} ({}): {}: {why}", peer.uid, peer.user, words(&hello.argv));
                self.audit_refusal(&peer, &hello, &why);
                return fail_with(&mut w, hello.codes, code, &why);
            }
        };
        let mut plan = match self.plan(&peer, &basis, &cmd, &hello, dir_fd) {
            Ok(p) => p,
            Err(e) => {
                let why = format!("{e:#}");
                say_err!("wicketd: refused uid {} ({}): {}: {why}", peer.uid, peer.user, words(&hello.argv));
                self.audit_refusal(&peer, &hello, &why);
                return refuse_or_fail(&mut w, hello.codes, &e, &why);
            }
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
                        return fail(&mut w, hello.codes, &format!("{e:#}"));
                    }
                }
                Some((kind::GO, _)) => break,
                Some((k, _)) => bail!("unexpected frame {:?} before go", k as char),
                None => return Ok(()),
            }
        }
        if let Some(s) = plan.stage.as_mut() {
            if let Err(e) = s.finish().and_then(|_| check_staged(&cmd, &hello, s, &self.vault_dir)) {
                let why = format!("{e:#}");
                say_err!("wicketd: refused uid {} ({}): {}: {why}", peer.uid, peer.user, words(&hello.argv));
                self.audit_refusal(&peer, &hello, &why);
                return refuse_or_fail(&mut w, hello.codes, &e, &why);
            }
        }
        say_err!(
            "wicketd: uid {} ({}) {}: {} [{}]",
            peer.uid,
            peer.user,
            class.name(),
            words(&hello.argv),
            plan.argv.first().map(String::as_str).unwrap_or("")
        );
        let stage = plan.stage.as_ref().map(|s| s.dir.clone());
        let code = self.run_child(&plan, fds, &hello, &r, stage, busy)?;
        drop(plan.stage.take());
        proto::write_frame(&mut w, kind::EXIT, &code.to_be_bytes())?;
        Ok(())
    }

    /// Parses, routes and authorizes a command line; what it won't run, with the caller's exit code
    /// (#574): a command line that doesn't parse is a usage error (2), an unreadable policy a
    /// failure (1), and the rest the policy's refusal (3).
    fn admit(&self, peer: &Peer, hello: &Hello) -> std::result::Result<(Cmd, Class, Basis), (Code, String)> {
        self.admit_inner(peer, hello).map_err(|(code, why)| (code.unwrap_or(Code::Refused), why))
    }

    fn admit_inner(&self, peer: &Peer, hello: &Hello) -> std::result::Result<(Cmd, Class, Basis), (Option<Code>, String)> {
        use clap::Parser;
        let cmd = crate::Cli::try_parse_from(std::iter::once("wicket".to_string()).chain(hello.argv.iter().cloned()))
            .map_err(|e| (Some(Code::Usage), e.to_string()))?
            .cmd;
        let class = match policy::route(&cmd) {
            Route::Forward(c) => c,
            Route::Local => return Err((None, "this command runs in the caller's own process, not through wicketd".into())),
            Route::Refuse(why) => return Err((None, why.into())),
        };
        let policy =
            Policy::load(&self.policy_path).map_err(|e| (Some(Code::Failed), format!("the daemon's policy is unreadable: {e}")))?;
        let basis = policy::authorize(peer, class, &policy, self.uid).map_err(|why| (None, why))?;
        if policy::root_only(&cmd) && basis != Basis::Root {
            return Err((
                None,
                "updating wicket needs root on the host (sudo wicket self …): no other user, and nothing wicket runs, may".into(),
            ));
        }
        if basis != Basis::Daemon {
            if let Some(a) = policy::internal_args(&cmd) {
                return Err((None, format!("{a} is for wicket's own use")));
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
            say_err!("wicketd: recording the refusal: {e}");
        }
    }

    fn plan(&self, peer: &Peer, basis: &Basis, cmd: &Cmd, hello: &Hello, dir_fd: Option<OwnedFd>) -> Result<Plan> {
        let caller = match basis {
            Basis::Daemon => None,
            Basis::Root => Some((principal(peer), format!("{}@host (break-glass: uid 0 over wicketd's socket)", peer.user))),
            Basis::Policy => Some((principal(peer), format!("{}@cli (uid {}, over wicketd's socket)", peer.user, peer.uid))),
        };
        // Mounting in place hands Docker a path, and the caller controls that path: after any check,
        // it could swap the directory for a link into wicket's data (another run's sockets). So only
        // root, which could read the data anyway, mounts in place through the daemon.
        if *basis == Basis::Policy {
            match cmd {
                Cmd::Run { workspace_dir: Some(_), .. } => {
                    return Err(wicket_home::exit::refused(
                        "--workspace-dir mounts a directory by its path, which its owner could swap for a link into wicket's data: \
                         through wicketd only root mounts in place. Copy it in with --workdir",
                    ))
                }
                Cmd::Wrap { .. } => {
                    return Err(wicket_home::exit::refused(
                        "wrap mounts its launcher's directory in place, by its path: through wicketd only root can (sudo wicket wrap ...)",
                    ))
                }
                _ => {}
            }
        }
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
                if let Some(i) = image {
                    argv.extend(["--image".into(), i.clone()]);
                }
                if let Some(n) = node {
                    argv.extend(["--node".into(), n.clone()]);
                }
                Plan { argv, cwd: self.data_dir.clone(), stage: Some(st), caller }
            }
            Cmd::Wrap { image, argv: agent, .. } => {
                let (st, mp) = stage_for(false)?;
                let cwd = dir.context("a wrapped agent works in its launcher's directory, which must be passed open")?;
                let mut argv = vec!["wrap".to_string(), "--manifest".into(), mp.display().to_string()];
                if let Some(i) = image {
                    argv.extend(["--image".into(), i.clone()]);
                }
                argv.push("--".into());
                argv.extend(agent.iter().cloned());
                Plan { argv, cwd, stage: Some(st), caller }
            }
            // The key and the build root names go as content too: the wicket user can't read a file
            // only root can (`/root/k.pub`), and must not read one root merely names.
            Cmd::Itself { cmd: crate::SelfCmd::TrustKey { .. } } => {
                let st = upload::Stage::new(&stage_parent, vec![("key".into(), "key.pub".into())])?;
                let argv = vec!["self".into(), "trust-key".into(), st.dir.join("key.pub").display().to_string()];
                Plan { argv, cwd: self.data_dir.clone(), stage: Some(st), caller }
            }
            Cmd::Itself {
                cmd:
                    crate::SelfCmd::Update {
                        artifact: Some(_),
                        from_ci: None,
                        sig: _,
                        nodes,
                        only_nodes,
                        window,
                        interval,
                        check,
                        canary,
                        image,
                        no_prune,
                    },
            } => {
                // Its signature (`--sig`, or the one beside it) lands beside it, where `update`
                // looks by default.
                let st = upload::Stage::new(
                    &stage_parent,
                    vec![("artifact".into(), "build/artifact".into()), ("sig".into(), "build/artifact.sig".into())],
                )?;
                let mut argv = vec!["self".into(), "update".into(), st.dir.join("build/artifact").display().to_string()];
                if let Some(n) = nodes {
                    argv.extend(["--nodes".into(), n.clone()]);
                }
                if *only_nodes {
                    argv.push("--only-nodes".into());
                }
                // Durations as clap parsed them, in ns: exact, and parsed again the same way.
                argv.extend([
                    "--window".into(),
                    format!("{}ns", window.as_nanos()),
                    "--interval".into(),
                    format!("{}ns", interval.as_nanos()),
                ]);
                for c in check {
                    argv.extend(["--check".into(), c.clone()]);
                }
                if let Some(c) = canary {
                    argv.extend(["--canary".into(), c.display().to_string()]);
                }
                if let Some(i) = image {
                    argv.extend(["--image".into(), i.clone()]);
                }
                if *no_prune {
                    argv.push("--no-prune".into());
                }
                Plan { argv, cwd: default_cwd(), stage: Some(st), caller }
            }
            // A trigger's document and a sample event go as content, as the key does.
            Cmd::Trigger { cmd: crate::TriggerCmd::Create { lasts, .. } } => {
                let st = upload::Stage::new(&stage_parent, vec![("trigger".into(), "trigger.yaml".into())])?;
                let file = st.dir.join("trigger.yaml").display().to_string();
                let argv = vec!["trigger".into(), "create".into(), "--file".into(), file, "--lasts".into(), lasts.clone()];
                Plan { argv, cwd: self.data_dir.clone(), stage: Some(st), caller }
            }
            // An edited manifest goes as content too (#713).
            Cmd::Manifest { cmd: m @ (crate::ManifestCmd::Check { .. } | crate::ManifestCmd::Save { .. }) } => {
                let st = upload::Stage::new(&stage_parent, vec![("edit".into(), "edit.yaml".into())])?;
                let file = st.dir.join("edit.yaml").display().to_string();
                let argv = match m {
                    crate::ManifestCmd::Check { name, json, .. } => {
                        let mut a = vec!["manifest".into(), "check".into(), name.clone(), "--file".into(), file];
                        if *json {
                            a.push("--json".into());
                        }
                        a
                    }
                    crate::ManifestCmd::Save { name, dry_run, .. } => {
                        let mut a = vec!["manifest".into(), "save".into(), name.clone(), "--file".into(), file];
                        if *dry_run {
                            a.push("--dry-run".into());
                        }
                        a
                    }
                    _ => unreachable!("matched above"),
                };
                Plan { argv, cwd: self.data_dir.clone(), stage: Some(st), caller }
            }
            Cmd::Trigger { cmd: crate::TriggerCmd::Fire { trigger: id, event: Some(_), .. } } => {
                let st = upload::Stage::new(&stage_parent, vec![("event".into(), "event.json".into())])?;
                let file = st.dir.join("event.json").display().to_string();
                let argv = vec!["trigger".into(), "fire".into(), id.clone(), "--event".into(), file, "--dry-run".into()];
                Plan { argv, cwd: self.data_dir.clone(), stage: Some(st), caller }
            }
            // `wicket manifest` reads the manifest roots, one of which is `<cwd>/examples` (#713
            // review): in the data directory, never a directory the caller chose, which could
            // point wicket's user at files the caller can't read.
            Cmd::Manifest { .. } => Plan { argv: hello.argv.clone(), cwd: self.data_dir.clone(), stage: None, caller },
            _ => Plan { argv: hello.argv.clone(), cwd: default_cwd(), stage: None, caller },
        })
    }

    /// A directory the caller passed open (to mount in place; root only, see `plan`): a directory,
    /// the caller's own unless root, and neither inside nor above the data directory.
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
            return Err(wicket_home::exit::refused(format!(
                "{} is owned by uid {}, not by you (uid {}): only your own directories can be mounted into a box",
                path.display(),
                m.uid(),
                peer.uid
            )));
        }
        if path == Path::new("/") || path.starts_with(&self.data_dir) || self.data_dir.starts_with(&path) {
            return Err(wicket_home::exit::refused(format!(
                "{} can't be mounted into a box: it is, or holds, wicket's data",
                path.display()
            )));
        }
        Ok(path)
    }

    /// Runs the command as a child and follows it to its end ([`handoff::follow`]); `busy` is
    /// released once it is followed, so a handoff from then on carries it.
    fn run_child(
        &self,
        plan: &Plan,
        fds: Vec<OwnedFd>,
        hello: &Hello,
        r: &UnixStream,
        stage: Option<PathBuf>,
        busy: InFlight,
    ) -> Result<i32> {
        use std::os::unix::process::CommandExt;
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
        let child = c.spawn().context("starting the command")?;
        // Reaped by `follow` (by pid), possibly in the next image: never waited for here.
        let pid = child.id() as i32;
        drop(child);
        handoff::follow(pid, r, stage, move || drop(busy))
    }
}

/// After uploads: the staged manifest's program source is the one the layout was made for, so it
/// resolves inside the staging directory.
fn check_staged(cmd: &Cmd, hello: &Hello, st: &upload::Stage, vault_dir: &Path) -> Result<()> {
    // `self trust-key`'s key and `self update`'s build: one file each, as named.
    let one_file = match cmd {
        Cmd::Itself { cmd: crate::SelfCmd::TrustKey { .. } } => Some("key"),
        Cmd::Itself { cmd: crate::SelfCmd::Update { artifact: Some(_), .. } } => Some("artifact"),
        Cmd::Trigger { cmd: crate::TriggerCmd::Create { .. } } => Some("trigger"),
        Cmd::Trigger { cmd: crate::TriggerCmd::Fire { event: Some(_), .. } } => Some("event"),
        Cmd::Manifest { cmd: crate::ManifestCmd::Check { .. } | crate::ManifestCmd::Save { .. } } => Some("edit"),
        _ => None,
    };
    if let Some(role) = one_file {
        let p = st.root(role).context("no upload role")?;
        if !std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
            bail!("the {role} did not arrive as a file");
        }
        // A signature is optional (an operator may approve the build's sha256 instead).
        let sig = st.root("sig").and_then(|s| std::fs::symlink_metadata(s).ok());
        if role == "artifact" && sig.is_some_and(|m| !m.file_type().is_file()) {
            bail!("the signature did not arrive as a file");
        }
        return Ok(());
    }
    if !matches!(cmd, Cmd::Run { .. } | Cmd::Wrap { .. }) {
        return Ok(());
    }
    let path = st.root("manifest").context("no manifest")?;
    let raw = std::fs::read_to_string(&path).context("the manifest did not arrive")?;
    let m = wicket_agent::load(&raw)?;
    let source = m.program.as_ref().and_then(|p| p.source.clone());
    if source != hello.program_source {
        bail!("the manifest's program source differs from the one announced");
    }
    // A caller writes its own manifest: it may not send a secret anywhere root didn't bind it to.
    crate::run::check_secret_hosts(&m, &wicket_proxy::vault::Vault::new(vault_dir.to_path_buf()), matches!(cmd, Cmd::Wrap { .. }))
        .map_err(|e| wicket_home::exit::refused(format!("{e:#}")))?;
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

/// Whether a command is turned away before it is looked at, and with what code (#574): while the
/// daemon moves to a new build (75: nothing was done, try again), or without the caller's stdio (1).
fn turned_away(draining: bool, fds: usize, dir_fd: bool) -> Option<(Code, &'static str)> {
    if draining {
        return Some((Code::TryAgain, "wicketd is moving to a new build: try again in a few seconds"));
    }
    if fds < 3 || (dir_fd && fds < 4) {
        return Some((Code::Failed, "the caller's stdin, stdout and stderr did not arrive"));
    }
    None
}

/// The command can't go ahead for another reason (the caller's fds or uploads didn't arrive
/// whole): the caller exits 1.
fn fail(w: &mut UnixStream, coded: bool, why: &str) -> Result<()> {
    fail_with(w, coded, Code::Failed, why)
}

/// Turns the command away with the caller's exit code (#574): in a `REFUSE` frame, the code a field
/// of its own (nothing in the text can pass for one), to a client that reads it; else the text in
/// an `ERROR` frame, as before.
fn fail_with(w: &mut UnixStream, coded: bool, code: Code, why: &str) -> Result<()> {
    let _ = match coded {
        true => proto::write_frame(w, kind::REFUSE, &proto::refuse_frame(code, why)),
        false => proto::write_frame(w, kind::ERROR, why.as_bytes()),
    };
    let _ = w.flush();
    Ok(())
}

/// Turns the command away with the code `e` says (the policy's refusal 3, a usage error 2, …), or 1.
fn refuse_or_fail(w: &mut UnixStream, coded: bool, e: &anyhow::Error, why: &str) -> Result<()> {
    fail_with(w, coded, wicket_home::exit::code_of(e).unwrap_or(Code::Failed), why)
}

#[cfg(test)]
mod tests;
