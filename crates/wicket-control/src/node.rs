//! A remote node reached over SSH (design §8: a node that holds no secrets).
//!
//! An **enrolled** node (`wicket node enrol`, see `enrol.rs`) is reached with its host key pinned:
//! every ssh call checks it against a known_hosts file wicket manages, with `StrictHostKeyChecking=yes`,
//! so a node presenting any other key is refused. Its boxes run through its `wicket node serve`
//! (`noderun.rs`), as this host's own boxes do through the built-in local node (`localnode.rs`, #146);
//! a target that isn't enrolled is reached only to enrol it (trust on first use, with a warning).
//!
//! **One connection per node** (#287). An enrolled node's ssh shares one connection: the first
//! command to it opens a master (`ControlMaster=auto`), whose socket is in [`master_dir`] (the
//! wicket user's, 0700), and every later command for 10 minutes after the last one
//! (`ControlPersist`) is a session over it: no new TCP connection, key exchange or authentication
//! (a start on a node over ssh measured 0.39 s cold, 0.05 s over a master). The master was opened
//! with the pinned host key, as every connection is. Revoking or releasing a node closes it
//! ([`Node::close_master`]): a master would otherwise let commands through to a node whose pinned
//! key is gone. Keepalives end a master whose connection died within 30 s; a channel that gets no
//! answer through one closes it and dials again, fresh (`noderun.rs`).
//!
//! **Test hook.** `WICKET_NODE_SSH` replaces `ssh <options> <target>` for every command sent to a node
//! with the command it names (split on spaces; it gets the remote command as one argument, as ssh
//! does), e.g. `env HOME=/tmp/node sh -c` to treat a directory on this machine as the node. Everything
//! but the ssh hop itself is then exercised (`ci/node-e2e.sh --local`). A `%t` in it is replaced by
//! the node's ssh target, so one hook can stand in for several nodes (`ci/update.sh`).

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
        let common = ["BatchMode=yes", "ConnectTimeout=15", "ServerAliveInterval=10", "ServerAliveCountMax=3"].map(String::from);
        for o in host_key_opts.iter().chain(common.iter()) {
            base.push("-o".into());
            base.push(o.clone());
        }
        // An enrolled node's connection is shared (a target reached to enrol it isn't: its key isn't pinned yet).
        if name.is_some() {
            for o in master_options(&master_dir()) {
                base.push("-o".into());
                base.push(o);
            }
        }
        let hook = std::env::var("WICKET_NODE_SSH")
            .ok()
            .filter(|h| !h.trim().is_empty())
            .map(|h| h.split_whitespace().map(|w| w.replace("%t", target)).collect());
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

    /// Closes this node's shared connection, if one is open (`ssh -O exit`): after a revocation or a
    /// release, so nothing more reaches the node over it. Best effort: no master is not an error.
    /// It only talks to the local control socket, so it returns at once.
    pub fn close_master(&self) {
        let Some(argv) = self.close_master_argv() else { return };
        let _ =
            std::process::Command::new(&argv[0]).args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }

    /// The command [`Node::close_master`] runs: this node's ssh options (so the same control
    /// socket), then `-O exit` and the target. None for a node whose connection isn't shared.
    pub fn close_master_argv(&self) -> Option<Vec<String>> {
        if self.hook.is_some() || self.name.is_none() {
            return None;
        }
        let mut v = self.base.clone();
        v.extend(["-O".to_string(), "exit".to_string(), self.target.clone()]);
        Some(v)
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

/// Where the shared connections' control sockets are: `<data dir>/ssh`, made 0700 (the wicket user's).
pub fn master_dir() -> PathBuf {
    let d = crate::data_dir().join("ssh");
    if std::fs::create_dir_all(&d).is_ok() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    }
    d
}

/// ssh options that share one connection per node through a socket in `dir` (#287): `%C` is a hash
/// of the local host, the remote host, port and user, short enough for a socket's path.
pub fn master_options(dir: &Path) -> Vec<String> {
    vec!["ControlMaster=auto".into(), format!("ControlPath=\"{}/cm-%C\"", dir.display()), "ControlPersist=10m".into()]
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
