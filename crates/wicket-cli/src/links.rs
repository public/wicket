//! Links between boxes on this host (issue #6): what `wicket_proxy::link` needs from Docker.
//!
//! - In the connecting box, a `socat` listener on the link's address and port, forwarding to the
//!   link's unix socket in the box's socket directory (where wicket listens). It runs as the agent's
//!   user, started with `docker exec`; the address is already on the box's loopback (`wicket-entry`).
//! - Into the target box, one `docker exec -i … socat - TCP:127.0.0.1:<port>` per connection, as the
//!   agent's user. A socket the box itself creates isn't reachable from the host under gVisor
//!   (`--host-uds=open` lets the box connect out to host sockets, not offer its own), so wicket
//!   reaches in instead; it costs about 0.1 s per connection.
//!
//! Both images need `socat` (the agent image has it). Boxes on remote nodes can't link yet.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use wicket_core::{Manifest, ZoneSpec};
use wicket_proxy::link::{BoxOps, Stream};
use wicket_sandbox::Docker;

/// The Docker name of a run's box (as `wicket run` names it).
pub fn box_name(run: &str) -> String {
    format!("wicket-{}", run.replace('_', "-"))
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
}

impl LocalBoxes {
    pub fn new(docker: Docker, runs: PathBuf, dir: PathBuf) -> LocalBoxes {
        // SAFETY: getuid and getgid can't fail.
        let user = unsafe { format!("{}:{}", libc::getuid(), libc::getgid()) };
        LocalBoxes { docker, runs, dir, user }
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
        // Started in the background; still alive a moment later means it bound.
        let script = format!(
            "socat TCP-LISTEN:{port},bind={addr},fork,reuseaddr UNIX-CONNECT:{sock} </dev/null >/dev/null 2>&1 & p=$!; sleep 0.3; kill -0 $p 2>/dev/null"
        );
        let out = self
            .docker
            .exec_blocking(&box_name(run), &self.user, &[], &["sh".into(), "-c".into(), script])
            .output()
            .map_err(|e| format!("docker exec: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "the listener on {addr}:{port} didn't start (port in use, or an image whose wicket-entry predates links: rebuild it with `wicket image`) {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn unlisten(&self, run: &str, sock: &str) {
        let _ = self
            .docker
            .exec_blocking(&box_name(run), &self.user, &[], &["pkill".into(), "-f".into(), format!("UNIX-CONNECT:{sock}")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    fn dial(&self, run: &str, port: u16) -> Result<Stream, String> {
        let mut c = self
            .docker
            .exec(&box_name(run), &self.user, &["-i"], &["socat".into(), "-".into(), format!("TCP:127.0.0.1:{port}")])
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
