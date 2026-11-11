//! First boot of a provisioned node: the cloud-init user data that runs `deploy/vultr/node-setup.sh`,
//! the ssh host key the control host generates and pins before the node exists, and the readiness
//! probe that uses that pin.
//!
//! **Trust bootstrap, step by step** (what `wicket place create` does):
//! 1. The control host generates an ed25519 host key pair with `ssh-keygen` in a private temporary
//!    directory, reads it and deletes the files.
//! 2. The user data installs it as the node's only host key (`ssh_deletekeys`, no generated types), writes
//!    node-setup.sh and runs it, then touches [`READY_MARKER`].
//! 3. The instance is created with that user data and the operator's ssh key id (root's
//!    authorized_keys; node-setup.sh copies them to `wicket`).
//! 4. Once the API says the instance is active, [`wait_ssh_ready`] logs in as `wicket` with *only* the
//!    pinned key accepted (`StrictHostKeyChecking=yes`, a one-line known_hosts) until the marker exists.
//!    The `wicket` user exists only after setup, so this one probe covers "sshd is up" and "setup is done".
//! 5. `wicket node enrol` runs with `--host-key <the pinned public key>`: no keyscan, no trust on first use.
//! 6. The instance's user data is replaced, so the private host key no longer sits in the metadata service.

use anyhow::{bail, Context};
use base64::Engine;
use std::path::Path;
use std::time::Duration;

/// node-setup.sh, as committed: what the node runs on first boot.
pub const NODE_SETUP: &str = include_str!("../../../deploy/vultr/node-setup.sh");
/// Exists on the node once setup has finished.
pub const READY_MARKER: &str = "/var/lib/wicket-node-ready";
const SETUP_PATH: &str = "/opt/wicket/node-setup.sh";
const SETUP_LOG: &str = "/var/log/wicket-node-setup.log";

/// A host key pair. The private half prints as `[redacted]`.
#[derive(Clone)]
pub struct HostKeyPair {
    pub private_openssh: String,
    /// `ssh-ed25519 AAAA… comment`.
    pub public: String,
}

impl std::fmt::Debug for HostKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostKeyPair").field("private_openssh", &"[redacted]").field("public", &self.public).finish()
    }
}

/// A fresh ed25519 host key, from `ssh-keygen`, in a 0700 temporary directory removed afterwards.
pub async fn generate_host_key(comment: &str) -> anyhow::Result<HostKeyPair> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!("wicket-hostkey-{}", ulid::Ulid::new()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).context("temporary directory for the host key")?;
    let path = dir.join("key");
    let out = tokio::process::Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(&path)
        .output()
        .await
        .context("running ssh-keygen");
    let read = || -> anyhow::Result<HostKeyPair> {
        let out = out?;
        if !out.status.success() {
            bail!("ssh-keygen failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(HostKeyPair {
            private_openssh: std::fs::read_to_string(&path)?,
            public: std::fs::read_to_string(path.with_extension("pub"))?.trim().to_string(),
        })
    };
    let r = read();
    let _ = std::fs::remove_dir_all(&dir);
    r
}

/// The `#cloud-config` user data: install `host_key` as the only host key, write and run `setup`, mark
/// the node ready.
pub fn cloud_config(setup: &str, host_key: &HostKeyPair) -> anyhow::Result<String> {
    let kind = host_key.public.split_whitespace().next().unwrap_or_default();
    if kind != "ssh-ed25519" {
        bail!("the boot host key must be ssh-ed25519, not {kind:?}");
    }
    if host_key.public.contains(['\n', '\'']) {
        bail!("malformed host public key");
    }
    let private: String = host_key.private_openssh.trim_end().lines().map(|l| format!("    {l}\n")).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(setup);
    Ok(format!(
        "#cloud-config\n\
         ssh_deletekeys: true\n\
         ssh_genkeytypes: []\n\
         ssh_keys:\n\
         \x20 ed25519_private: |\n{private}\
         \x20 ed25519_public: '{public}'\n\
         write_files:\n\
         \x20 - path: {SETUP_PATH}\n\
         \x20   permissions: '0700'\n\
         \x20   encoding: b64\n\
         \x20   content: {b64}\n\
         runcmd:\n\
         \x20 - [bash, -c, 'bash {SETUP_PATH} > {SETUP_LOG} 2>&1 && touch {READY_MARKER}']\n",
        public = host_key.public,
    ))
}

/// What replaces the user data after enrolment: nothing secret.
pub const SCRUBBED_USER_DATA: &str = "#cloud-config\n{}\n";

/// The ssh arguments for a probe that accepts only `host_key` (written to `known_hosts` under `alias`).
pub fn pinned_ssh_args(known_hosts: &Path, alias: &str, identity: Option<&Path>, target: &str) -> Vec<String> {
    let mut a = vec![];
    if let Some(i) = identity {
        a.push("-i".into());
        a.push(i.display().to_string());
    }
    for o in [
        "BatchMode=yes".to_string(),
        "ConnectTimeout=10".into(),
        "StrictHostKeyChecking=yes".into(),
        format!("UserKnownHostsFile=\"{}\"", known_hosts.display()),
        "GlobalKnownHostsFile=/dev/null".into(),
        format!("HostKeyAlias={alias}"),
        "UpdateHostKeys=no".into(),
        "CheckHostIP=no".into(),
    ] {
        a.push("-o".into());
        a.push(o);
    }
    a.push(target.to_string());
    a.push(format!("test -f {READY_MARKER}"));
    a
}

/// Logs in to `target` with only `host_key_line` accepted, until node setup has finished or `timeout`.
pub async fn wait_ssh_ready(target: &str, host_key_line: &str, identity: Option<&Path>, poll: Duration, timeout: Duration) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = std::env::temp_dir().join(format!("wicket-probe-{}", ulid::Ulid::new()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let kh = dir.join("known_hosts");
    let alias = "wicket-node-new";
    let r: anyhow::Result<()> = async {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&kh)?;
        std::io::Write::write_all(&mut f, format!("{alias} {host_key_line}\n").as_bytes())?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let out = tokio::process::Command::new("ssh").args(pinned_ssh_args(&kh, alias, identity, target)).output().await.context("ssh")?;
            if out.status.success() {
                return Ok(());
            }
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if err.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") || err.contains("Host key verification failed") {
                bail!("{target} offered a host key other than the pinned one: refusing it ({err})");
            }
            if tokio::time::Instant::now() + poll > deadline {
                bail!("{target} was not ready after {timeout:?}: {err}");
            }
            tokio::time::sleep(poll).await;
        }
    }
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> HostKeyPair {
        HostKeyPair {
            private_openssh: "KEY-PLACEHOLDER line one\nKEY-PLACEHOLDER line two\n".into(),
            public: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExamplePlaceholderKeyDataxxxxxxxxxxxxxxxxxxx wicket-node".into(),
        }
    }

    #[test]
    fn the_user_data_pins_one_host_key_and_runs_node_setup() {
        let c = cloud_config(NODE_SETUP, &pair()).unwrap();
        assert!(c.starts_with("#cloud-config\n"));
        assert!(c.contains("ssh_deletekeys: true\nssh_genkeytypes: []\n"));
        assert!(c.contains("  ed25519_private: |\n    KEY-PLACEHOLDER line one\n    KEY-PLACEHOLDER line two\n  ed25519_public: 'ssh-ed25519 "));
        let b64 = c.lines().find_map(|l| l.trim().strip_prefix("content: ")).unwrap();
        let setup = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        assert_eq!(String::from_utf8(setup).unwrap(), NODE_SETUP);
        assert!(NODE_SETUP.contains("useradd") && NODE_SETUP.contains("runsc"));
        assert!(c.contains(&format!("&& touch {READY_MARKER}")));
        assert!(!format!("{:?}", pair()).contains("PLACEHOLDER line"));
    }

    #[test]
    fn only_an_ed25519_key_with_a_plain_public_line_is_accepted() {
        let mut p = pair();
        p.public = "ssh-rsa AAAA".into();
        assert!(cloud_config("x", &p).is_err());
        let mut p = pair();
        p.public = "ssh-ed25519 AAAA'\nruncmd: [evil]".into();
        assert!(cloud_config("x", &p).is_err());
    }

    #[test]
    fn the_probe_accepts_only_the_pinned_key() {
        let a = pinned_ssh_args(Path::new("/tmp/kh"), "wicket-node-new", None, "wicket@203.0.113.9").join(" ");
        assert!(a.contains("StrictHostKeyChecking=yes"));
        assert!(a.contains("GlobalKnownHostsFile=/dev/null"));
        assert!(a.contains("HostKeyAlias=wicket-node-new"));
        assert!(a.ends_with(&format!("wicket@203.0.113.9 test -f {READY_MARKER}")));
    }
}
