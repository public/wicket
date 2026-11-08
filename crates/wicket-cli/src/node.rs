//! A remote sandbox node reached over SSH (PoC of design §8: a node that holds no secrets).
//!
//! The node runs only Docker + gVisor. wicket's proxies, the model key, the CA key and the ledger
//! stay on the control host; the node gets the run's two unix sockets forwarded with `ssh -R`
//! (unix socket to unix socket), plus the CA's public certificate.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use wicket_sandbox::shell_quote;

pub struct Node {
    pub target: String,
    base: Vec<String>,
}

impl Node {
    pub fn new(target: &str, key: Option<&Path>) -> Node {
        let mut base = vec!["ssh".to_string()];
        if let Some(k) = key {
            base.push("-i".into());
            base.push(k.display().to_string());
        }
        for o in ["BatchMode=yes", "StrictHostKeyChecking=accept-new", "ConnectTimeout=15", "ServerAliveInterval=30"] {
            base.push("-o".into());
            base.push(o.into());
        }
        Node { target: target.to_string(), base }
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
