//! Links between boxes on this host (issue #6): what `wicket_proxy::link` needs from Docker.
//!
//! - In the connecting box, a `wicket-fwd --listen` on the link's address and port, relaying to the
//!   link's unix socket in the box's socket directory (where wicket listens). It runs as the agent's
//!   user, started with `docker exec`; the address is already on the box's loopback (`wicket-entry`).
//! - Into the target box, one `docker exec -i … wicket-fwd --dial 127.0.0.1:<port>` per connection,
//!   as the agent's user. A socket the box itself creates isn't reachable from the host under gVisor
//!   (`--host-uds=open` lets the box connect out to host sockets, not offer its own), so wicket
//!   reaches in instead; it costs one `docker exec` per connection.
//!
//! Both boxes need `wicket-fwd` (every image built on wicket's agent image has it). Boxes on remote
//! nodes can't link yet.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;
use wicket_core::{Manifest, ZoneSpec};
use wicket_proxy::link::{BoxOps, Stream};
use wicket_sandbox::Docker;

/// The Docker name of a run's box (as `wicket run` names it): `wicket-<run>`, or another prefix from
/// WICKET_BOX_PREFIX (tests name theirs, so they can be told apart and cleaned up).
pub fn box_name(run: &str) -> String {
    let prefix =
        std::env::var("WICKET_BOX_PREFIX").ok().filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    format!("{}-{}", prefix.as_deref().unwrap_or("wicket"), run.replace('_', "-"))
}

/// A box's hosts file, mounted read-only at /etc/hosts: wicket rewrites it in place as links open
/// and close.
pub fn hosts_path(run_dir: &std::path::Path) -> PathBuf {
    run_dir.join("hosts")
}

pub struct LocalBoxes {
    pub docker: Docker,
    /// Where every run's directory lives (`<data>/runs`).
    pub runs: PathBuf,
    /// This run's directory (its spawn records are in `children/`).
    pub dir: PathBuf,
    /// uid:gid the boxes run as.
    pub user: String,
    /// The in-box pid of each link listener, by (run, socket).
    listeners: Mutex<HashMap<(String, String), u32>>,
}

impl LocalBoxes {
    pub fn new(docker: Docker, runs: PathBuf, dir: PathBuf) -> LocalBoxes {
        // SAFETY: getuid and getgid can't fail.
        let user = unsafe { format!("{}:{}", libc::getuid(), libc::getgid()) };
        LocalBoxes { docker, runs, dir, user, listeners: Mutex::default() }
    }
}

impl BoxOps for LocalBoxes {
    fn box_dir(&self, run: &str) -> Option<PathBuf> {
        crate::run::check_run_id(run).ok()?;
        let d = self.runs.join(run);
        hosts_path(&d).exists().then_some(d)
    }

    fn child_zone(&self, child_run: &str) -> Option<ZoneSpec> {
        crate::run::check_run_id(child_run).ok()?;
        let y = std::fs::read_to_string(self.dir.join("children").join(format!("{child_run}.yaml"))).ok()?;
        Manifest::from_yaml(&y).ok().map(|m| m.zone)
    }

    fn listen(&self, run: &str, addr: Ipv4Addr, port: u16, sock: &str) -> Result<(), String> {
        if !wicket_core::link::in_pool(addr) {
            return Err(format!("{addr} is not a link address"));
        }
        // Started in the background; still alive a moment later means it bound. Prints its pid.
        let script = format!(
            "wicket-fwd --listen {addr}:{port}={sock} --bind-timeout 0 </dev/null >/dev/null 2>&1 & p=$!; sleep 0.3; kill -0 $p 2>/dev/null && echo $p"
        );
        let out = self
            .docker
            .exec_blocking(&box_name(run), &self.user, &[], &["sh".into(), "-c".into(), script])
            .output()
            .map_err(|e| format!("docker exec: {e}"))?;
        let pid = String::from_utf8_lossy(&out.stdout).trim().parse::<u32>().ok();
        match pid {
            Some(pid) if out.status.success() => {
                self.listeners.lock().expect("listeners").insert((run.to_string(), sock.to_string()), pid);
                Ok(())
            }
            _ => Err(format!(
                "the listener on {addr}:{port} didn't start (port in use, or an image whose wicket-entry predates links: rebuild it with `wicket image`) {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }

    fn unlisten(&self, run: &str, sock: &str) {
        let Some(pid) = self.listeners.lock().expect("listeners").remove(&(run.to_string(), sock.to_string())) else {
            return;
        };
        let _ = self
            .docker
            .exec_blocking(&box_name(run), &self.user, &[], &["kill".into(), pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    fn dial(&self, run: &str, port: u16) -> Result<Stream, String> {
        let mut c = self
            .docker
            .exec(&box_name(run), &self.user, &["-i"], &["wicket-fwd".into(), "--dial".into(), format!("127.0.0.1:{port}")])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("docker exec: {e}"))?;
        let (w, r) = (c.stdin.take().ok_or("no stdin")?, c.stdout.take().ok_or("no stdout")?);
        Ok(Stream { read: Box::new(r), write: Box::new(w), guard: Box::new(c) })
    }
}
