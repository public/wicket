//! A remote sandbox node reached over SSH (PoC of design §8: a node that holds no secrets).
//!
//! The node runs only Docker + gVisor. wicket's proxies, the model key, the CA key and the ledger
//! stay on the control host; the node gets the run's two unix sockets forwarded with `ssh -R`
//! (unix socket to unix socket), plus the CA's public certificate.
//!
//! An **enrolled** node (`wicket node enrol`, see `enrol.rs`) is reached with its host key pinned:
//! every ssh call checks it against a known_hosts file wicket manages, with `StrictHostKeyChecking=yes`,
//! so a node presenting any other key is refused. A target that isn't enrolled is still reached the old
//! way (trust on first use), with a warning.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use wicket_sandbox::shell_quote;

pub struct Node {
    pub target: String,
    /// The enrolled node's name; None for a target reached by trust on first use.
    pub name: Option<String>,
    base: Vec<String>,
}

/// Where an enrolled node's host key is pinned.
pub struct Pin {
    /// A known_hosts file holding only this node's key, under the alias.
    pub known_hosts: PathBuf,
    /// The name ssh looks the key up by (`HostKeyAlias`), independent of the address or port.
    pub alias: String,
}

impl Pin {
    pub fn for_node(nodes_dir: &Path, name: &str) -> Pin {
        Pin { known_hosts: nodes_dir.join(name).join("known_hosts"), alias: format!("wicket-node-{name}") }
    }
}

impl Node {
    /// A node that isn't enrolled: its host key is trusted on first use (`accept-new`).
    pub fn new(target: &str, key: Option<&Path>) -> Node {
        Node::with_options(target, key, &["StrictHostKeyChecking=accept-new".into()], None)
    }

    /// An enrolled node: only the pinned host key is accepted.
    pub fn pinned(target: &str, key: Option<&Path>, pin: &Pin, name: &str) -> Node {
        Node::with_options(target, key, &pinned_options(pin), Some(name))
    }

    fn with_options(target: &str, key: Option<&Path>, host_key_opts: &[String], name: Option<&str>) -> Node {
        let mut base = vec!["ssh".to_string()];
        if let Some(k) = key {
            base.push("-i".into());
            base.push(k.display().to_string());
        }
        let common = ["BatchMode=yes", "ConnectTimeout=15", "ServerAliveInterval=30"].map(String::from);
        for o in host_key_opts.iter().chain(common.iter()) {
            base.push("-o".into());
            base.push(o.clone());
        }
        Node { target: target.to_string(), name: name.map(String::from), base }
    }

    /// The name runs and identities record: the enrolled name, else the ssh target.
    pub fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.target.clone())
    }

    /// The ssh command up to and including the target (for Docker::over_ssh).
    pub fn ssh_prefix(&self) -> Vec<String> {
        let mut v = self.base.clone();
        v.push(self.target.clone());
        v
    }

    fn cmd(&self) -> Command {
        let p = self.ssh_prefix();
        let mut c = Command::new(&p[0]);
        c.args(&p[1..]);
        c
    }

    /// Runs a shell snippet on the node and returns stdout.
    pub async fn sh(&self, script: &str) -> Result<String> {
        let out = self.cmd().arg(script).output().await.with_context(|| format!("ssh {}", self.target))?;
        if !out.status.success() {
            bail!("on {}: `{}` failed: {}", self.target, script, String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Runs a longer script on the node, naming it `what` (not echoing it) if it fails.
    pub async fn script(&self, what: &str, script: &str) -> Result<String> {
        let out = self.cmd().arg(script).output().await.with_context(|| format!("ssh {}", self.target))?;
        if !out.status.success() {
            bail!("on {}: {what} failed: {}", self.target, String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Writes bytes to a file on the node.
    pub async fn put(&self, remote: &str, bytes: &[u8]) -> Result<()> {
        let mut child = self.cmd().arg(format!("cat > {}", shell_quote(remote))).stdin(Stdio::piped()).spawn()?;
        child.stdin.take().expect("stdin").write_all(bytes).await?;
        if !child.wait().await?.success() {
            bail!("writing {remote} on {} failed", self.target);
        }
        Ok(())
    }

    /// Copies a local directory's contents into a node directory (tar over ssh).
    pub async fn put_dir(&self, local: &Path, remote: &str) -> Result<()> {
        let tar = std::process::Command::new("tar").arg("-C").arg(local).args(["-cf", "-", "."]).stdout(Stdio::piped()).spawn()?;
        let p = self.ssh_prefix();
        let st = std::process::Command::new(&p[0])
            .args(&p[1..])
            .arg(format!("tar -C {} -xf -", shell_quote(remote)))
            .stdin(tar.stdout.expect("tar stdout"))
            .status()?;
        if !st.success() {
            bail!("copying {} to {}:{} failed", local.display(), self.target, remote);
        }
        Ok(())
    }

    /// Forwards local unix sockets to paths on the node for the life of the returned process.
    pub async fn forward(&self, pairs: &[(String, &Path)]) -> Result<Child> {
        let mut c = Command::new(&self.base[0]);
        c.args(&self.base[1..]).args(["-N", "-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindUnlink=yes"]);
        for (remote, local) in pairs {
            c.arg("-R").arg(format!("{}:{}", remote, local.display()));
        }
        c.arg(&self.target).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).kill_on_drop(true);
        let child = c.spawn().context("starting ssh socket forwarding")?;
        // Wait until the forwarded sockets exist on the node.
        let test = pairs.iter().map(|(r, _)| format!("test -S {}", shell_quote(r))).collect::<Vec<_>>().join(" && ");
        for _ in 0..50 {
            if self.sh(&test).await.is_ok() {
                return Ok(child);
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        bail!("forwarded sockets did not appear on {}", self.target)
    }
}

/// ssh options that accept only the pinned key: no global known_hosts, no learning or updating keys.
pub fn pinned_options(pin: &Pin) -> Vec<String> {
    vec![
        "StrictHostKeyChecking=yes".into(),
        // Quoted: ssh splits an unquoted value on spaces (it takes a list of files).
        format!("UserKnownHostsFile=\"{}\"", pin.known_hosts.display()),
        "GlobalKnownHostsFile=/dev/null".into(),
        format!("HostKeyAlias={}", pin.alias),
        "UpdateHostKeys=no".into(),
        "CheckHostIP=no".into(),
    ]
}
