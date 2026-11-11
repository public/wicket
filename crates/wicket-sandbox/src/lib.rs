//! Sandbox backends (design §7). The PoC has one: Docker, with gVisor as the default runtime. Every
//! box runs with `--network none`; its only way out is the unix sockets wicket bind-mounts in, which
//! an in-box forwarder exposes at wicket.internal (its own address, so the agent keeps localhost).

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Child, Command};
use wicket_core::Isolation;

#[derive(Clone, Debug)]
pub struct Mount {
    pub host: PathBuf,
    pub target: String,
    pub read_only: bool,
}

#[derive(Clone, Debug)]
pub struct SandboxSpec {
    pub name: String,
    pub image: String,
    pub isolation: Isolation,
    pub mounts: Vec<Mount>,
    pub env: Vec<(String, String)>,
    pub argv: Vec<String>,
    pub memory: String,
    pub cpus: f32,
    pub pids: u32,
    /// uid:gid inside the box (the host user, so files in the workspace stay ours).
    pub user: String,
    pub workdir: String,
    /// Keep the agent's stdin open (the supervisor writes its task and follow-ups there).
    pub interactive: bool,
    /// Extra labels, e.g. which run and which process own the box (`wicket reap` reads them).
    pub labels: Vec<(String, String)>,
}

/// A wicket box Docker is running, as `Docker::boxes` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoxInfo {
    pub name: String,
    /// The run it belongs to (`wicket.run`), if labelled.
    pub run: Option<String>,
    /// The process that supervises it (`wicket.owner`), if labelled.
    pub owner: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Docker {
    /// Command prefix, e.g. ["docker"] or ["sudo", "docker"] (from WICKET_DOCKER), or an ssh
    /// command ending in "docker" for a remote node.
    cmd: Vec<String>,
    /// Arguments pass through a remote shell (ssh) and must be quoted.
    quote: bool,
}

/// Quotes one argument for a POSIX shell.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=,@%+".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

impl Docker {
    pub fn from_env() -> Docker {
        let cmd = std::env::var("WICKET_DOCKER").unwrap_or_else(|_| "docker".into());
        Docker { cmd: cmd.split_whitespace().map(String::from).collect(), quote: false }
    }

    /// Docker on a remote node, reached with the given ssh command (ending in the target).
    pub fn over_ssh(mut ssh: Vec<String>) -> Docker {
        ssh.push("docker".into());
        Docker { cmd: ssh, quote: true }
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.cmd[0]);
        c.args(&self.cmd[1..]);
        c
    }

    fn command_with<I: IntoIterator<Item = String>>(&self, args: I) -> Command {
        let mut c = self.command();
        for a in args {
            c.arg(if self.quote { shell_quote(&a) } else { a });
        }
        c
    }

    /// Which runtimes the daemon offers (e.g. "runc", "runsc").
    pub async fn runtimes(&self) -> Result<Vec<String>> {
        let out = self
            .command_with(["info".to_string(), "--format".into(), "{{range $k, $v := .Runtimes}}{{$k}} {{end}}".into()])
            .output()
            .await
            .context("running docker info")?;
        if !out.status.success() {
            bail!("docker info failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).split_whitespace().map(String::from).collect())
    }

    pub async fn image_exists(&self, image: &str) -> Result<bool> {
        let st = self
            .command_with(["image".to_string(), "inspect".into(), image.into()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await?;
        Ok(st.success())
    }

    pub fn build_args(&self, spec: &SandboxSpec) -> Vec<String> {
        let runtime = match spec.isolation {
            Isolation::Gvisor => "runsc",
            Isolation::Runc => "runc",
        };
        let mut a: Vec<String> = vec![
            "run".into(),
            "--rm".into(),
            "--init".into(),
            "--name".into(),
            spec.name.clone(),
            "--runtime".into(),
            runtime.into(),
            "--network".into(),
            "none".into(),
            "--memory".into(),
            spec.memory.clone(),
            "--cpus".into(),
            format!("{}", spec.cpus),
            "--pids-limit".into(),
            spec.pids.to_string(),
            "--cap-drop".into(),
            "ALL".into(),
            "--security-opt".into(),
            "no-new-privileges".into(),
            "--read-only".into(),
            "--tmpfs".into(),
            "/tmp:rw,nosuid,size=512m".into(),
            // wicket-entry starts as root with only the capabilities it needs to give wicket.internal its
            // address, then becomes `spec.user` with no capabilities (no-new-privileges throughout).
            "--user".into(),
            "0:0".into(),
            "--env".into(),
            format!("WICKET_AS_USER={}", spec.user),
            "--cap-add".into(),
            "NET_ADMIN".into(),
            "--cap-add".into(),
            "SETUID".into(),
            "--cap-add".into(),
            "SETGID".into(),
            "--cap-add".into(),
            "SETPCAP".into(),
            "--workdir".into(),
            spec.workdir.clone(),
            "--label".into(),
            "wicket=1".into(),
        ];
        for (k, v) in &spec.labels {
            a.push("--label".into());
            a.push(format!("{k}={v}"));
        }
        // wicket.internal's name, unless wicket mounts its own hosts file (which links add names to).
        if !spec.mounts.iter().any(|m| m.target == "/etc/hosts") {
            a.push("--add-host".into());
            a.push("wicket.internal:198.18.0.1".into());
        }
        if spec.interactive {
            a.push("--interactive".into());
        }
        for m in &spec.mounts {
            a.push("--mount".into());
            a.push(format!("type=bind,source={},target={}{}", m.host.display(), m.target, if m.read_only { ",readonly" } else { "" }));
        }
        for (k, v) in &spec.env {
            a.push("--env".into());
            a.push(format!("{k}={v}"));
        }
        a.push(spec.image.clone());
        a.extend(spec.argv.iter().cloned());
        a
    }

    /// `docker exec` into a running box as `user` (uid:gid), with extra flags such as `-i` or `-d`.
    pub fn exec_args(&self, container: &str, user: &str, flags: &[&str], argv: &[String]) -> Vec<String> {
        let mut a = vec!["exec".to_string(), "--user".into(), user.into()];
        a.extend(flags.iter().map(|f| f.to_string()));
        a.push(container.into());
        a.extend(argv.iter().cloned());
        a
    }

    /// As [`Docker::exec_args`], as a command to spawn.
    pub fn exec(&self, container: &str, user: &str, flags: &[&str], argv: &[String]) -> Command {
        self.command_with(self.exec_args(container, user, flags, argv))
    }

    /// As [`Docker::exec`], for blocking callers.
    pub fn exec_blocking(&self, container: &str, user: &str, flags: &[&str], argv: &[String]) -> std::process::Command {
        let mut c = std::process::Command::new(&self.cmd[0]);
        c.args(&self.cmd[1..]);
        for a in self.exec_args(container, user, flags, argv) {
            c.arg(if self.quote { shell_quote(&a) } else { a });
        }
        c
    }

    /// Starts the box with the given stdin and stdout (e.g. inherited from whoever launched wicket,
    /// when wicket wraps an agent another program drives) and stderr piped.
    pub fn spawn_with(&self, spec: &SandboxSpec, stdin: Stdio, stdout: Stdio) -> Result<Child> {
        let mut c = self.command_with(self.build_args(spec));
        c.stdin(stdin).stdout(stdout).stderr(Stdio::piped()).kill_on_drop(true);
        c.spawn().context("starting docker run")
    }

    /// Starts the box with stdout and stderr piped.
    pub fn spawn(&self, spec: &SandboxSpec) -> Result<Child> {
        let mut c = self.command_with(self.build_args(spec));
        c.stdin(if spec.interactive { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        c.spawn().context("starting docker run")
    }

    /// Every running wicket box (label `wicket=1`).
    pub async fn boxes(&self) -> Result<Vec<BoxInfo>> {
        let out = self
            .command_with([
                "ps".to_string(),
                "--filter".into(),
                "label=wicket=1".into(),
                "--format".into(),
                "{{.Names}}\t{{.Label \"wicket.run\"}}\t{{.Label \"wicket.owner\"}}".into(),
            ])
            .stderr(Stdio::piped())
            .output()
            .await
            .context("docker ps")?;
        if !out.status.success() {
            bail!("docker ps failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(parse_boxes(&String::from_utf8_lossy(&out.stdout)))
    }

    pub async fn kill(&self, name: &str) -> Result<()> {
        let _ = self.command_with(["kill".to_string(), name.into()]).stdout(Stdio::null()).stderr(Stdio::null()).status().await?;
        Ok(())
    }

    /// Builds an image from a directory, with host networking for the build only (the daemon has no
    /// bridge network; sandboxes never get one).
    pub async fn build_image(&self, tag: &str, dir: &std::path::Path) -> Result<()> {
        let st = self
            .command_with(["build".to_string(), "--network".into(), "host".into(), "-t".into(), tag.into(), dir.display().to_string()])
            .status()
            .await?;
        if !st.success() {
            bail!("docker build failed");
        }
        Ok(())
    }
}

/// Parses `docker ps` lines of `name<TAB>run<TAB>owner`.
fn parse_boxes(out: &str) -> Vec<BoxInfo> {
    let some = |s: Option<&str>| s.map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut f = l.split('\t');
            BoxInfo { name: f.next().unwrap_or("").trim().to_string(), run: some(f.next()), owner: some(f.next()) }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_never_include_a_network() {
        let d = Docker { cmd: vec!["docker".into()], quote: false };
        let spec = SandboxSpec {
            name: "wicket-test".into(),
            image: "img".into(),
            isolation: Isolation::Gvisor,
            mounts: vec![Mount { host: "/x".into(), target: "/y".into(), read_only: true }],
            env: vec![("A".into(), "b".into())],
            argv: vec!["claude".into()],
            memory: "1g".into(),
            cpus: 1.0,
            pids: 64,
            user: "1000:1000".into(),
            workdir: "/workspace".into(),
            interactive: true,
            labels: vec![("wicket.run".into(), "run_1".into())],
        };
        let a = d.build_args(&spec).join(" ");
        assert!(a.contains("--label wicket=1 --label wicket.run=run_1"));
        assert!(a.contains("--network none"));
        assert!(a.contains("--runtime runsc"));
        assert!(a.contains("--cap-drop ALL"));
        assert!(a.contains("--user 0:0") && a.contains("WICKET_AS_USER=1000:1000"), "starts as root only to set up, then drops");
        assert!(a.contains("--add-host wicket.internal:198.18.0.1"));
        assert!(!a.contains("SYS_ADMIN") && !a.contains("--privileged"));
        assert!(a.contains("type=bind,source=/x,target=/y,readonly"));
        // With wicket's own hosts file mounted (links add names to it), no --add-host.
        let mut own = spec.clone();
        own.mounts.push(Mount { host: "/run/hosts".into(), target: "/etc/hosts".into(), read_only: true });
        let a = d.build_args(&own).join(" ");
        assert!(!a.contains("--add-host") && a.contains("source=/run/hosts,target=/etc/hosts,readonly"));
        let e = d.exec_args("wicket-x", "1000:1000", &["-i"], &["socat".into(), "-".into()]).join(" ");
        assert_eq!(e, "exec --user 1000:1000 -i wicket-x socat -");
        assert!(a.contains(" --interactive "));
        assert!(a.ends_with("img claude"));
    }

    #[test]
    fn docker_ps_lines_parse_into_boxes() {
        let out = "wicket-run-1\trun_1\tm1:42:9000\nwicket-old\t\t\n\n";
        assert_eq!(
            parse_boxes(out),
            vec![
                BoxInfo { name: "wicket-run-1".into(), run: Some("run_1".into()), owner: Some("m1:42:9000".into()) },
                BoxInfo { name: "wicket-old".into(), run: None, owner: None },
            ]
        );
    }

    #[test]
    fn shell_quoting_survives_hostile_text() {
        assert_eq!(shell_quote("plain-arg"), "plain-arg");
        assert_eq!(shell_quote(""), "''");
        // Round-trip through a real shell: what the remote shell sees must equal the input.
        for s in ["it's $(touch /tmp/pwned) `id` \\n \"q\" ; | & > <", "multi\nline\ttext", "''''", "a'b'c"] {
            let out = std::process::Command::new("sh").arg("-c").arg(format!("printf %s {}", shell_quote(s))).output().unwrap();
            assert_eq!(String::from_utf8(out.stdout).unwrap(), s);
        }
    }
}
