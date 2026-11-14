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
//!    Before each login a TCP connect to port 22 tells "no network" (timed out, unreachable) from
//!    "network up" (accepted, refused): a node that never answers is given up on after
//!    [`ReadyWait::silent_limit`] (default 4 minutes) instead of the whole timeout.
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

/// How long to wait for a new node, and when to give up on one that never answers at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyWait {
    /// Between attempts.
    pub poll: Duration,
    /// The longest wait for setup to finish once the node answers on the network.
    pub timeout: Duration,
    /// Give up early if the node has given no answer of any kind on its ssh port for this long: no
    /// network at all, as opposed to "network up, setup still running".
    pub silent_limit: Duration,
    /// The port probed (22; tests use others).
    pub port: u16,
}

/// The default for [`ReadyWait::silent_limit`]: 4 minutes.
pub const DEFAULT_SILENT_LIMIT: Duration = Duration::from_secs(240);

impl Default for ReadyWait {
    fn default() -> Self {
        ReadyWait { poll: Duration::from_secs(10), timeout: Duration::from_secs(900), silent_limit: DEFAULT_SILENT_LIMIT, port: 22 }
    }
}

/// What a TCP connect to the node's ssh port got back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Accepted or refused: the node is on the network (sshd may not be up yet).
    Answered,
    /// Timed out or unreachable: nothing answered.
    Silent,
}

/// One TCP connect to `host:port`, at most `timeout` long. A refusal counts as an answer: something
/// on the node's address sent it.
pub async fn tcp_reach(host: &str, port: u16, timeout: Duration) -> Reach {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => Reach::Answered,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Reach::Answered,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => Reach::Answered,
        _ => Reach::Silent,
    }
}

/// The host part of an ssh target (`user@host`, `host`, `[v6]`).
pub fn target_host(target: &str) -> &str {
    let h = target.rsplit_once('@').map_or(target, |(_, h)| h);
    h.trim_start_matches('[').trim_end_matches(']')
}

/// A node gave no answer of any kind on its ssh port for [`ReadyWait::silent_limit`]. Callers find it
/// with `downcast_ref` and release the node rather than leave it billing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreachable {
    pub target: String,
    pub port: u16,
    pub after: Duration,
}

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} never answered on port {} in {} (no network: every connect timed out or was unreachable)",
            self.target,
            self.port,
            humantime_secs(self.after)
        )
    }
}

impl std::error::Error for Unreachable {}

fn humantime_secs(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 60 && s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else if s > 0 {
        format!("{s}s")
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// The two checks [`wait_ready`] makes: is anything there, and is setup done.
pub trait Probe {
    /// Whether the node answers on `port` at all.
    fn reach(&self, target: &str, port: u16) -> impl std::future::Future<Output = Reach> + Send;
    /// `Ok(None)` when setup has finished, `Ok(Some(why))` when not yet, `Err` to stop waiting.
    fn ready(&self, target: &str) -> impl std::future::Future<Output = anyhow::Result<Option<String>>> + Send;
}

/// Waits until `probe` says `target` is ready. Gives up with [`Unreachable`] if the node has never
/// answered on the network within `wait.silent_limit`; once it has, keeps waiting up to `wait.timeout`.
pub async fn wait_ready(probe: &impl Probe, target: &str, wait: &ReadyWait) -> anyhow::Result<()> {
    let start = tokio::time::Instant::now();
    let deadline = start + wait.timeout;
    let mut answered = false;
    let mut last = String::from("no answer yet");
    loop {
        if !answered {
            answered = probe.reach(target, wait.port).await == Reach::Answered;
        }
        if answered {
            match probe.ready(target).await? {
                None => return Ok(()),
                Some(why) => last = why,
            }
        } else if start.elapsed() >= wait.silent_limit {
            return Err(Unreachable { target: target.to_string(), port: wait.port, after: wait.silent_limit }.into());
        }
        if tokio::time::Instant::now() + wait.poll > deadline {
            bail!("{target} was not ready after {:?}: {last}", wait.timeout);
        }
        tokio::time::sleep(wait.poll).await;
    }
}

/// The real probe: a TCP connect, then an ssh login with only the pinned host key accepted.
pub struct SshProbe {
    known_hosts: std::path::PathBuf,
    identity: Option<std::path::PathBuf>,
}

const PROBE_ALIAS: &str = "wicket-node-new";

impl Probe for SshProbe {
    async fn reach(&self, target: &str, port: u16) -> Reach {
        tcp_reach(target_host(target), port, Duration::from_secs(5)).await
    }
    async fn ready(&self, target: &str) -> anyhow::Result<Option<String>> {
        let out = tokio::process::Command::new("ssh")
            .args(pinned_ssh_args(&self.known_hosts, PROBE_ALIAS, self.identity.as_deref(), target))
            .output()
            .await
            .context("ssh")?;
        if out.status.success() {
            return Ok(None);
        }
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if err.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") || err.contains("Host key verification failed") {
            bail!("{target} offered a host key other than the pinned one: refusing it ({err})");
        }
        Ok(Some(err))
    }
}

/// Logs in to `target` with only `host_key_line` accepted, until node setup has finished. Gives up
/// early with [`Unreachable`] if nothing ever answers on the ssh port (see [`wait_ready`]).
pub async fn wait_ssh_ready(target: &str, host_key_line: &str, identity: Option<&Path>, wait: &ReadyWait) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = std::env::temp_dir().join(format!("wicket-probe-{}", ulid::Ulid::new()));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let kh = dir.join("known_hosts");
    let r: anyhow::Result<()> = async {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&kh)?;
        std::io::Write::write_all(&mut f, format!("{PROBE_ALIAS} {host_key_line}\n").as_bytes())?;
        wait_ready(&SshProbe { known_hosts: kh.clone(), identity: identity.map(Path::to_path_buf) }, target, wait).await
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
        assert!(
            c.contains("  ed25519_private: |\n    KEY-PLACEHOLDER line one\n    KEY-PLACEHOLDER line two\n  ed25519_public: 'ssh-ed25519 ")
        );
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

    /// A node that starts answering after `answers_after` and is set up `ready_after` later.
    struct Scripted {
        start: tokio::time::Instant,
        answers_after: Option<Duration>,
        ready_after: Duration,
        logins: std::sync::atomic::AtomicUsize,
    }

    impl Probe for Scripted {
        async fn reach(&self, _t: &str, _p: u16) -> Reach {
            match self.answers_after {
                Some(a) if self.start.elapsed() >= a => Reach::Answered,
                _ => Reach::Silent,
            }
        }
        async fn ready(&self, _t: &str) -> anyhow::Result<Option<String>> {
            self.logins.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let a = self.answers_after.unwrap_or(Duration::MAX);
            Ok((self.start.elapsed() < a + self.ready_after).then(|| "Permission denied".to_string()))
        }
    }

    fn scripted(answers_after: Option<u64>, ready_after: u64) -> Scripted {
        Scripted {
            start: tokio::time::Instant::now(),
            answers_after: answers_after.map(Duration::from_secs),
            ready_after: Duration::from_secs(ready_after),
            logins: Default::default(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_never_answers_is_given_up_on_at_the_silent_limit() {
        let p = scripted(None, 0);
        let t0 = tokio::time::Instant::now();
        let e = wait_ready(&p, "wicket@203.0.113.9", &ReadyWait::default()).await.unwrap_err();
        let u = e.downcast_ref::<Unreachable>().expect("Unreachable");
        assert_eq!(u.after, DEFAULT_SILENT_LIMIT);
        assert!(t0.elapsed() >= DEFAULT_SILENT_LIMIT && t0.elapsed() < DEFAULT_SILENT_LIMIT + Duration::from_secs(11));
        assert_eq!(p.logins.load(std::sync::atomic::Ordering::SeqCst), 0, "no ssh login without an answer");
        assert!(e.to_string().contains("never answered on port 22 in 4m"), "{e}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_answers_keeps_being_waited_for_up_to_the_timeout() {
        // Answers after 3 minutes, set up 10 minutes later: past the silent limit, inside the timeout.
        let p = scripted(Some(180), 600);
        let t0 = tokio::time::Instant::now();
        wait_ready(&p, "wicket@203.0.113.9", &ReadyWait::default()).await.unwrap();
        assert!(t0.elapsed() >= Duration::from_secs(780));
        // Answers but setup never finishes: the whole timeout, and not Unreachable.
        let p = scripted(Some(0), 10_000);
        let t0 = tokio::time::Instant::now();
        let e = wait_ready(&p, "wicket@203.0.113.9", &ReadyWait::default()).await.unwrap_err();
        assert!(e.downcast_ref::<Unreachable>().is_none(), "{e}");
        assert!(e.to_string().contains("not ready after 900s: Permission denied"), "{e}");
        assert!(t0.elapsed() >= Duration::from_secs(890));
    }

    #[tokio::test]
    async fn a_refused_connect_is_an_answer() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert_eq!(tcp_reach("127.0.0.1", port, Duration::from_secs(2)).await, Reach::Answered);
        drop(l);
        assert_eq!(tcp_reach("127.0.0.1", port, Duration::from_secs(2)).await, Reach::Answered);
        assert_eq!(target_host("wicket@203.0.113.9"), "203.0.113.9");
        assert_eq!(target_host("wicket@[2001:db8::1]"), "2001:db8::1");
    }
}
