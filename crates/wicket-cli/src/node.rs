//! A remote node reached over SSH (design §8: a node that holds no secrets).
//!
//! An **enrolled** node (`wicket node enrol`, see `enrol.rs`) is reached with its host key pinned:
//! every ssh call checks it against a known_hosts file wicket manages, with `StrictHostKeyChecking=yes`,
//! so a node presenting any other key is refused. Its boxes run through its `wicket node serve`
//! (`noderun.rs`), as this host's own boxes do through the built-in local node (`localnode.rs`, #146);
//! a target that isn't enrolled is reached only to enrol it (trust on first use, with a warning).
//!
//! **Test hook.** `WICKET_NODE_SSH` replaces `ssh <options> <target>` for every command sent to a node
//! with the command it names (split on spaces; it gets the remote command as one argument, as ssh
//! does), e.g. `env HOME=/tmp/node sh -c` to treat a directory on this machine as the node. Everything
//! but the ssh hop itself is then exercised (`ci/node-e2e.sh --local`).

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use wicket_sandbox::shell_quote;

pub struct Node {
    pub target: String,
    /// The enrolled node's name; None for a target reached by trust on first use.
    pub name: Option<String>,
    base: Vec<String>,
    /// `WICKET_NODE_SSH`: the whole prefix, target included.
    hook: Option<Vec<String>>,
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
        let hook = std::env::var("WICKET_NODE_SSH")
            .ok()
            .filter(|h| !h.trim().is_empty())
            .map(|h| h.split_whitespace().map(String::from).collect());
        Node { target: target.to_string(), name: name.map(String::from), base, hook }
    }

    /// The ssh command up to and including the target (for Docker::over_ssh).
    pub fn ssh_prefix(&self) -> Vec<String> {
        if let Some(h) = &self.hook {
            return h.clone();
        }
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
