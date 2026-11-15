//! Sandbox backends (design §7). The PoC has one: Docker, with gVisor as the default runtime. Every
//! box runs with `--network none`; its only way out is the unix sockets wicket bind-mounts in, which
//! an in-box forwarder exposes at wicket.internal (its own address, so the agent keeps localhost).
//!
//! A box start's calls (create and start, inspect, wait, logs, kill, rm, image inspect, and the
//! image events) go to Docker's Engine API over its unix socket where this process can reach it
//! ([`engine`], #287); the rest, and every call where it can't, run the `docker` CLI.

mod engine;

use anyhow::{bail, Context, Result};
use hyper::{Method, StatusCode};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::process::{Child, Command};
use wicket_core::timing::{SpanGuard, Timings};
use wicket_core::Isolation;

/// The size of a box's /tmp, in MiB: the tmpfs's size, or the cap wicket keeps a host /tmp to.
pub const TMP_CAP_MB: u64 = 512;

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

/// A running box's CPU and memory, as Docker's stats report them (`wicket node top`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct BoxStats {
    /// Percent of one CPU (200 is two CPUs' worth), if Docker had two samples to tell it from.
    pub cpu_pct: Option<f64>,
    /// Memory in use, page cache left out, as `docker stats` counts it.
    pub memory: u64,
    /// Its limit (0: none reported).
    pub limit: u64,
}

/// [`BoxStats`] from the Engine API's `/containers/{id}/stats` answer.
pub fn stats_of(v: &serde_json::Value) -> Option<BoxStats> {
    let m = &v["memory_stats"];
    let usage = m["usage"].as_u64()?;
    // cgroup v2 reports `inactive_file`, v1 `total_inactive_file` (or `cache`): what `docker stats`
    // takes off.
    let st = &m["stats"];
    let cache = st["inactive_file"].as_u64().or_else(|| st["total_inactive_file"].as_u64()).or_else(|| st["cache"].as_u64()).unwrap_or(0);
    let (cpu, pre) = (&v["cpu_stats"], &v["precpu_stats"]);
    let total = |c: &serde_json::Value| c["cpu_usage"]["total_usage"].as_u64();
    let system = |c: &serde_json::Value| c["system_cpu_usage"].as_u64();
    let online = cpu["online_cpus"]
        .as_u64()
        .or_else(|| cpu["cpu_usage"]["percpu_usage"].as_array().map(|a| a.len() as u64))
        .filter(|n| *n > 0)
        .unwrap_or(1);
    let cpu_pct = match (total(cpu), total(pre), system(cpu), system(pre)) {
        (Some(t), Some(t0), Some(s), Some(s0)) if s > s0 && t >= t0 => Some((t - t0) as f64 / (s - s0) as f64 * online as f64 * 100.0),
        _ => None,
    };
    Some(BoxStats { cpu_pct, memory: usage.saturating_sub(cache), limit: m["limit"].as_u64().unwrap_or(0) })
}

/// [`BoxStats`] from a line of `docker stats --no-stream --format '{{json .}}'`.
pub fn stats_of_cli(line: &str) -> Option<BoxStats> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let cpu_pct = v["CPUPerc"].as_str().and_then(|c| c.trim().trim_end_matches('%').parse::<f64>().ok());
    let (used, limit) = v["MemUsage"].as_str()?.split_once('/')?;
    Some(BoxStats { cpu_pct, memory: size_of_cli(used)?, limit: size_of_cli(limit).unwrap_or(0) })
}

/// `412.3MiB`, `2GiB`, `512kB`, `0B`: as `docker stats` prints sizes.
fn size_of_cli(s: &str) -> Option<u64> {
    let s = s.trim();
    let at = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
    let n: f64 = s[..at].parse().ok()?;
    let unit: u64 = match s[at..].trim() {
        "B" | "" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "TiB" => 1 << 40,
        "kB" | "KB" => 1_000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        "TB" => 1_000_000_000_000,
        _ => return None,
    };
    Some((n * unit as f64) as u64)
}

/// An image as a Docker has it (#192).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageIdentity {
    /// `sha256:…`: what a box is started as, so a retag can't swap it.
    pub id: String,
    /// `repository@sha256:…`.
    pub repo_digests: Vec<String>,
    pub tags: Vec<String>,
}

impl ImageIdentity {
    /// Whether this image is the one `digest` (`sha256:…`) names: its id, or one of its repository
    /// digests.
    pub fn is(&self, digest: &str) -> bool {
        self.id == digest || self.repo_digests.iter().any(|r| r.rsplit_once('@').is_some_and(|(_, d)| d == digest))
    }
}

/// How far back [`Docker::watch_images`] asks for events when it (re)subscribes, in seconds: an
/// image changed while the CLI was starting still empties the cache.
const EVENTS_SLACK_SECS: u64 = 5;

/// What a Docker's images were when last inspected, by the reference inspected (#287), kept only
/// while [`Docker::watch_images`] follows its image events and emptied at each one: a reference
/// moved, an image pulled, loaded or deleted since is always inspected again. Callers still check
/// what they get (a pin, #192) as they would a fresh inspect.
#[derive(Debug, Default)]
pub struct ImageCache {
    s: std::sync::Mutex<CacheState>,
}

#[derive(Debug, Default)]
struct CacheState {
    /// The image events are being followed: the cache may be used.
    watching: bool,
    /// Counts every change (each event, each start or stop of the watch): an inspect is kept only
    /// if none came while it ran.
    gen: u64,
    ids: std::collections::HashMap<String, ImageIdentity>,
}

impl ImageCache {
    fn state(&self) -> std::sync::MutexGuard<'_, CacheState> {
        self.s.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What `image` was, if known and nothing changed since.
    pub fn get(&self, image: &str) -> Option<ImageIdentity> {
        let s = self.state();
        s.ids.get(image).filter(|_| s.watching).cloned()
    }

    /// Taken before an inspect: the generation it may be kept under, if the cache is in use.
    fn ticket(&self) -> Option<u64> {
        let s = self.state();
        s.watching.then_some(s.gen)
    }

    /// Keeps what an inspect said, unless something changed since its ticket was taken.
    fn put(&self, ticket: u64, image: &str, ident: &ImageIdentity) {
        let mut s = self.state();
        if s.watching && s.gen == ticket {
            s.ids.insert(image.to_string(), ident.clone());
        }
    }

    /// Something changed this Docker's images: forget everything.
    pub fn invalidate(&self) {
        let mut s = self.state();
        s.gen += 1;
        s.ids.clear();
    }

    /// Whether the image events are followed (when they stop, nothing known is kept).
    fn watching(&self, on: bool) {
        let mut s = self.state();
        s.watching = on;
        s.gen += 1;
        s.ids.clear();
    }

    /// How many references are cached.
    pub fn len(&self) -> usize {
        self.state().ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the cache is in use (its image events are being followed).
    pub fn in_use(&self) -> bool {
        self.state().watching
    }
}

#[derive(Clone, Debug)]
pub struct Docker {
    /// Command prefix, e.g. ["docker"] or ["sudo", "docker"] (from WICKET_DOCKER), or an ssh
    /// command ending in "docker" for a remote node.
    cmd: Vec<String>,
    /// Arguments pass through a remote shell (ssh) and must be quoted.
    quote: bool,
    /// Where each call's wall time goes, if anywhere (#287): `docker.<call>`.
    timings: Option<Arc<Timings>>,
    /// The daemon's Engine API, where a box start's calls go when this process can reach it (#287);
    /// else (and for everything else: exec, attach, save, load, build, ps, info) the CLI.
    api: Option<Arc<Api>>,
}

/// The Engine API a [`Docker`] may use, and whether it can.
#[derive(Debug)]
struct Api {
    engine: engine::Engine,
    /// [`API_UNKNOWN`], [`API_USED`], or [`API_REFUSED`].
    mode: AtomicU8,
}

/// Not reached yet (or not there when last tried): tried again at the next call.
const API_UNKNOWN: u8 = 0;
const API_USED: u8 = 1;
/// This process may not connect to the socket (its permissions): the CLI, for good.
const API_REFUSED: u8 = 2;

impl Api {
    fn new(sock: PathBuf) -> Arc<Api> {
        Arc::new(Api { engine: engine::Engine::new(sock), mode: AtomicU8::new(API_UNKNOWN) })
    }
}

/// How a box ended, as its runtime saw it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitInfo {
    pub code: i32,
    pub oom_killed: bool,
    pub error: Option<String>,
    /// When its runtime started its first process, and when it ended (RFC 3339, the host's clock),
    /// if Docker says (#287).
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

/// A box's stdout and stderr, followed ([`Docker::logs`]).
pub struct Logs {
    pub stdout: tokio::io::DuplexStream,
    pub stderr: tokio::io::DuplexStream,
    /// Ends once both have: Err if they couldn't be read at all, or stopped early.
    pub done: tokio::task::JoinHandle<Result<()>>,
}

/// Quotes one argument for a POSIX shell.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=,@%+".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The Engine API socket a Docker run as `cmd` talks to, if wicket can talk to it itself (#287): a
/// plain `docker` (any path), alone or with `-H`/`--host unix://…`; then its `-H`, else
/// `DOCKER_HOST` (`docker_host`), else the default socket unless a Docker context (`context`, from
/// `DOCKER_CONTEXT` or the CLI's config) points elsewhere. None (the CLI is used) for anything else:
/// `sudo -n docker`, an ssh command, a TCP or ssh host, a context.
fn engine_socket(cmd: &[String], docker_host: Option<&str>, context: Option<&str>) -> Option<PathBuf> {
    let (prog, rest) = cmd.split_first()?;
    if std::path::Path::new(prog).file_name()? != "docker" {
        return None;
    }
    let host = match rest {
        [] => None,
        [f, h] if f == "-H" || f == "--host" => Some(h.as_str()),
        [f] => Some(f.strip_prefix("-H=").or_else(|| f.strip_prefix("--host="))?),
        _ => return None,
    };
    let unix = |h: &str| h.strip_prefix("unix://").filter(|p| p.starts_with('/')).map(PathBuf::from);
    match host.or(docker_host) {
        Some(h) => unix(h),
        None if context.is_some_and(|c| c != "default") => None,
        None => Some(engine::DEFAULT_SOCKET.into()),
    }
}

/// The Docker CLI's current context, as its config names it (`currentContext`), if any.
fn config_context() -> Option<String> {
    let dir = std::env::var_os("DOCKER_CONFIG")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".docker")))?;
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("config.json")).ok()?).ok()?;
    v["currentContext"].as_str().filter(|c| !c.is_empty()).map(String::from)
}

impl Docker {
    /// The Docker `WICKET_DOCKER` names (a command, split on spaces; `docker` if unset), through its
    /// Engine API where [`engine_socket`] finds one.
    pub fn from_env() -> Docker {
        let cmd: Vec<String> =
            std::env::var("WICKET_DOCKER").unwrap_or_else(|_| "docker".into()).split_whitespace().map(String::from).collect();
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let context = env("DOCKER_CONTEXT").or_else(config_context);
        let api = engine_socket(&cmd, env("DOCKER_HOST").as_deref(), context.as_deref()).map(Api::new);
        Docker { cmd, quote: false, timings: None, api }
    }

    /// A Docker run as this command (its argv's start), on this host: the CLI only.
    pub fn with_command(cmd: Vec<String>) -> Docker {
        Docker { cmd, quote: false, timings: None, api: None }
    }

    /// The Docker whose Engine API is at `sock` (the CLI given `-H unix://sock` where it's needed).
    pub fn engine_at(sock: impl Into<PathBuf>) -> Docker {
        let sock = sock.into();
        let cmd = vec!["docker".into(), "-H".into(), format!("unix://{}", sock.display())];
        Docker { cmd, quote: false, timings: None, api: Some(Api::new(sock)) }
    }

    /// Docker on a remote node, reached with the given ssh command (ending in the target).
    pub fn over_ssh(mut ssh: Vec<String>) -> Docker {
        ssh.push("docker".into());
        Docker { cmd: ssh, quote: true, timings: None, api: None }
    }

    /// The Engine API, if this Docker has one this process can reach. The first call that finds
    /// the socket decides: connected, it is used from then on; refused (permissions), the CLI is.
    /// A socket that isn't there (the daemon not up yet) leaves it to the next call.
    async fn engine(&self) -> Option<&engine::Engine> {
        let api = self.api.as_deref()?;
        match api.mode.load(Ordering::Acquire) {
            API_USED => return Some(&api.engine),
            API_REFUSED => return None,
            _ => {}
        }
        match tokio::net::UnixStream::connect(api.engine.socket()).await {
            Ok(_) => {
                api.mode.store(API_USED, Ordering::Release);
                Some(&api.engine)
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                api.mode.store(API_REFUSED, Ordering::Release);
                None
            }
            Err(_) => None,
        }
    }

    /// How this Docker is reached, for a log line (and deciding it, if it isn't yet).
    pub async fn backend(&self) -> String {
        match self.engine().await {
            Some(e) => format!("the Engine API at {}", e.socket().display()),
            None => format!("the CLI ({})", self.cmd.join(" ")),
        }
    }

    /// This Docker, recording the wall time of each call it makes into `t` (#287), as
    /// `docker.<call>`: the CLI process, dockerd, and whatever it waits on (containerd, the shim, the
    /// runtime).
    pub fn timed(&self, t: Arc<Timings>) -> Docker {
        Docker { timings: Some(t), ..self.clone() }
    }

    /// A span for one call, if this Docker records them.
    fn span(&self, call: &str) -> Option<SpanGuard<'_>> {
        self.timings.as_deref().map(|t| t.span(format!("docker.{call}")))
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
        let _t = self.span("info");
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

    /// The arguments the daemon passes a runtime (e.g. runsc's `--host-uds=open`), or None if it
    /// has no such runtime.
    pub async fn runtime_args(&self, name: &str) -> Result<Option<Vec<String>>> {
        let _t = self.span("info");
        let out = self
            .command_with(["info".to_string(), "--format".into(), "{{json .Runtimes}}".into()])
            .output()
            .await
            .context("running docker info")?;
        if !out.status.success() {
            bail!("docker info failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).context("docker info's runtimes")?;
        Ok(v.get(name).map(|r| {
            r.get("runtimeArgs")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default()
        }))
    }

    /// What `image` is in this Docker (#192): its id and repository digests, as `docker image
    /// inspect` reports them. None if it has no such image.
    pub async fn image_identity(&self, image: &str) -> Result<Option<ImageIdentity>> {
        let _t = self.span("image_inspect");
        let v: serde_json::Value = match self.engine().await {
            Some(e) => match e.get_json(&format!("/images/{}/json", engine::enc(image, true))).await.context("docker image inspect")? {
                Some(v) => v,
                None => return Ok(None),
            },
            None => {
                let out = self
                    .command_with([
                        "image".to_string(),
                        "inspect".into(),
                        "--format".into(),
                        "{{json .}}".into(),
                        "--".into(),
                        image.into(),
                    ])
                    .stdin(Stdio::null())
                    .output()
                    .await?;
                if !out.status.success() {
                    return Ok(None);
                }
                serde_json::from_slice(&out.stdout).context("docker image inspect")?
            }
        };
        let strings =
            |k: &str| v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        let id = v["Id"].as_str().context("docker image inspect: no Id")?.to_string();
        Ok(Some(ImageIdentity { id, repo_digests: strings("RepoDigests"), tags: strings("RepoTags") }))
    }

    /// [`Docker::image_identity`] through `cache` (#287): what it last said for `image`, while
    /// nothing has changed this Docker's images since, else asked again (and kept, if nothing
    /// changed them while it was asked). A cache nobody keeps current ([`Docker::watch_images`]) is
    /// never used: every call asks.
    pub async fn image_identity_cached(&self, cache: &ImageCache, image: &str) -> Result<Option<ImageIdentity>> {
        if let Some(i) = cache.get(image) {
            let _t = self.span("image_cached");
            return Ok(Some(i));
        }
        let ticket = cache.ticket();
        let ident = self.image_identity(image).await?;
        if let (Some(t), Some(i)) = (ticket, &ident) {
            cache.put(t, image, i);
        }
        Ok(ident)
    }

    /// Keeps `cache` current for as long as it runs (spawn it): follows this Docker's image events
    /// (pull, load, import, tag, untag, delete, …: the Engine API's `/events`, or `docker events
    /// --filter type=image`), and empties the cache at each one. It asks for events from a few
    /// seconds before it starts, so none is missed while it subscribes. The cache is used only while
    /// the events are followed: if they end (the daemon restarted, say), it is emptied and set aside
    /// until they are again.
    pub async fn watch_images(self, cache: Arc<ImageCache>) {
        let mut backoff = std::time::Duration::from_secs(1);
        loop {
            let since = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
                .saturating_sub(EVENTS_SLACK_SECS);
            let watched = match self.engine().await {
                Some(e) => follow_events_api(e, since, &cache).await,
                None => self.follow_events_cli(since, &cache).await,
            };
            if watched.is_some_and(|d| d > std::time::Duration::from_secs(60)) {
                backoff = std::time::Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
        }
    }

    /// Follows the image events through the CLI until it ends: for how long, if it was followed.
    async fn follow_events_cli(&self, since: u64, cache: &ImageCache) -> Option<std::time::Duration> {
        use tokio::io::AsyncBufReadExt;
        let args = ["events", "--filter", "type=image", "--format", "{{.Action}}", "--since"].map(String::from);
        let mut child = self
            .command_with(args.into_iter().chain([since.to_string()]))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;
        let watched = match child.stdout.take() {
            Some(out) => {
                let began = std::time::Instant::now();
                cache.watching(true);
                let mut lines = tokio::io::BufReader::new(out).lines();
                while let Ok(Some(_)) = lines.next_line().await {
                    cache.invalidate();
                }
                cache.watching(false);
                Some(began.elapsed())
            }
            None => None,
        };
        let _ = child.kill().await;
        watched
    }

    pub async fn image_exists(&self, image: &str) -> Result<bool> {
        let _t = self.span("image_inspect");
        if let Some(e) = self.engine().await {
            return Ok(e.get_json(&format!("/images/{}/json", engine::enc(image, true))).await?.is_some());
        }
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
            // The box's resolver is wicket's DNS (#92), relayed by wicket-fwd: allowed hosts resolve
            // to synthetic addresses for HTTP/3, the rest to NXDOMAIN.
            "--dns".into(),
            "198.18.0.1".into(),
            "--memory".into(),
            spec.memory.clone(),
            // The limit is the box's memory, swap included: Docker's default lets a box swap as much
            // again on a host with swap, so it neither stays within its limit nor is OOM-killed at it.
            "--memory-swap".into(),
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
        // /tmp: a tmpfs, unless wicket mounts a host directory there (a local box's /tmp is kept with
        // the rest of its writable state, #70).
        if !spec.mounts.iter().any(|m| m.target == "/tmp") {
            a.push("--tmpfs".into());
            a.push(format!("/tmp:rw,nosuid,size={TMP_CAP_MB}m"));
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

    /// Starts the box detached (`docker run -d`, kept after it exits so its exit code can be read):
    /// its stdin, if interactive, stays open between attaches, so a supervisor that restarts can
    /// attach again ([`Docker::attach_stdin`]) and read its output from the start ([`Docker::logs`]).
    pub async fn start_detached(&self, spec: &SandboxSpec, log_cap: u64) -> Result<()> {
        let _t = self.span("run");
        if let Some(e) = self.engine().await {
            // `docker run -d` is these two calls (the CLI makes the same ones, after its own start).
            let body = create_body(spec, log_cap)?;
            let (st, b) = e.call(Method::POST, &format!("/containers/create?name={}", engine::enc(&spec.name, false)), Some(&body)).await?;
            if !st.is_success() {
                bail!("docker run failed: {}", engine::message(&b));
            }
            let id: serde_json::Value = serde_json::from_slice(&b).context("docker create's answer")?;
            let id = id["Id"].as_str().context("docker create: no Id")?;
            let (st, b) = e.call(Method::POST, &format!("/containers/{}/start", engine::enc(id, false)), None).await?;
            if !st.is_success() && st != StatusCode::NOT_MODIFIED {
                bail!("docker run failed: {}", engine::message(&b));
            }
            return Ok(());
        }
        let half = log_half(log_cap);
        let args: Vec<String> = self
            .build_args(spec)
            .into_iter()
            .flat_map(|a| match a.as_str() {
                "--rm" => vec![
                    "-d".to_string(),
                    "--log-driver".into(),
                    "json-file".into(),
                    "--log-opt".into(),
                    format!("max-size={half}"),
                    "--log-opt".into(),
                    "max-file=2".into(),
                ],
                _ => vec![a],
            })
            .collect();
        let out = self.command_with(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).output().await?;
        if !out.status.success() {
            bail!("docker run failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    /// Writes to a detached box's stdin (piped), for as long as the returned process lives; its own
    /// output is discarded ([`Docker::logs`] reads the box's).
    pub fn attach_stdin(&self, name: &str) -> Command {
        let mut c = self.command_with(["attach".to_string(), "--sig-proxy=false".into(), name.into()]);
        c.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
        c
    }

    /// A box's stdout and stderr as Docker still has them (from its start, unless rotated; or since
    /// `since`), followed until it exits: read from the Engine API's multiplexed stream, or the
    /// CLI's `docker logs --follow`, by a task of its own (spawned here, so a runtime is needed).
    pub fn logs(&self, name: &str, since: Option<std::time::SystemTime>) -> Logs {
        let (stdout, out_w) = tokio::io::duplex(64 << 10);
        let (stderr, err_w) = tokio::io::duplex(64 << 10);
        let (d, name) = (self.clone(), name.to_string());
        let done = tokio::spawn(async move {
            let since = since.map(unix_timestamp);
            let mut w = [out_w, err_w];
            match d.engine().await {
                Some(e) => logs_api(e, &name, since.as_deref(), &mut w).await,
                None => d.logs_cli(&name, since.as_deref(), w).await,
            }
        });
        Logs { stdout, stderr, done }
    }

    async fn logs_cli(&self, name: &str, since: Option<&str>, w: [tokio::io::DuplexStream; 2]) -> Result<()> {
        let mut a = vec!["logs".to_string(), "--follow".into()];
        if let Some(s) = since {
            a.push("--since".into());
            a.push(s.into());
        }
        a.push(name.into());
        let mut child = self
            .command_with(a)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("docker logs")?;
        let (out, err) = (child.stdout.take().context("docker logs' stdout")?, child.stderr.take().context("docker logs' stderr")?);
        let [ow, ew] = w;
        let (_, _, st) = tokio::join!(pass_on(out, ow), pass_on(err, ew), child.wait());
        let st = st?;
        if !st.success() {
            bail!("docker logs ended with {st}");
        }
        Ok(())
    }

    /// Waits for a box to exit; its exit code.
    pub async fn wait(&self, name: &str) -> Result<i32> {
        let _t = self.span("wait");
        if let Some(e) = self.engine().await {
            let (st, b) = e.call(Method::POST, &format!("/containers/{}/wait", engine::enc(name, false)), None).await?;
            if !st.is_success() {
                bail!("docker wait failed: {}", engine::message(&b));
            }
            let v: serde_json::Value = serde_json::from_slice(&b).context("docker wait's answer")?;
            return Ok(v["StatusCode"].as_i64().context("docker wait: no StatusCode")? as i32);
        }
        let out = self.command_with(["wait".to_string(), name.into()]).stdin(Stdio::null()).stderr(Stdio::piped()).output().await?;
        if !out.status.success() {
            bail!("docker wait failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        String::from_utf8_lossy(&out.stdout).trim().parse().context("docker wait's exit code")
    }

    /// What Docker says of a box (`docker container inspect`), None if there is no such box (or,
    /// through the CLI, its answer can't be read).
    async fn container(&self, name: &str) -> Result<Option<serde_json::Value>> {
        let _t = self.span("inspect");
        if let Some(e) = self.engine().await {
            return e.get_json(&format!("/containers/{}/json", engine::enc(name, false))).await.context("docker inspect");
        }
        let out = self
            .command_with(["container".to_string(), "inspect".into(), "--".into(), name.into()])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await?;
        if !out.status.success() {
            return Ok(None);
        }
        let v: Option<serde_json::Value> = serde_json::from_slice(&out.stdout).ok();
        Ok(v.and_then(|v| v.get(0).cloned()))
    }

    /// How a box that has exited ended, as the runtime saw it (#185): its exit code, whether the
    /// kernel's OOM killer ended it (Docker's `State.OOMKilled`, which runsc reports too), and the
    /// runtime's own error, if any; and when it started and ended (#287). None if the box doesn't
    /// exist.
    pub async fn exit_info(&self, name: &str) -> Result<Option<ExitInfo>> {
        Ok(self.container(name).await?.map(|v| exit_info_of(&v["State"])))
    }

    /// The host pid of a running box's init process (0 if it isn't running).
    pub async fn pid(&self, name: &str) -> Result<u32> {
        Ok(self.container(name).await?.and_then(|v| v["State"]["Pid"].as_u64()).map_or(0, |p| p as u32))
    }

    /// Whether a box exists, and if so whether it runs and its exit code.
    pub async fn state(&self, name: &str) -> Result<Option<(bool, i32)>> {
        Ok(self.container(name).await?.map(|v| {
            let st = &v["State"];
            (st["Running"].as_bool().unwrap_or(false), st["ExitCode"].as_i64().unwrap_or(-1) as i32)
        }))
    }

    /// When Docker created a box and when its runtime started it (#287), as Docker reports them
    /// (RFC 3339, UTC): between the two, containerd, the shim and the runtime (runsc: its sandbox
    /// and gofer) set it up and started its first process. None if the box doesn't exist.
    pub async fn start_times(&self, name: &str) -> Result<Option<(String, String)>> {
        Ok(self.container(name).await?.and_then(|v| start_times_of(&v)))
    }

    /// wicket boxes that have exited and are still there (started detached): (name, run).
    pub async fn exited_boxes(&self) -> Result<Vec<(String, String)>> {
        let out = self
            .command_with([
                "ps".to_string(),
                "-a".into(),
                "--filter".into(),
                "label=wicket=1".into(),
                "--filter".into(),
                "status=exited".into(),
                "--format".into(),
                "{{.Names}}\t{{.Label \"wicket.run\"}}".into(),
            ])
            .stderr(Stdio::piped())
            .output()
            .await
            .context("docker ps")?;
        if !out.status.success() {
            bail!("docker ps failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .filter(|(_, r)| !r.is_empty())
            .map(|(n, r)| (n.to_string(), r.to_string()))
            .collect())
    }

    /// Removes a box (running or not).
    pub async fn remove(&self, name: &str) -> Result<()> {
        let _t = self.span("rm");
        if let Some(e) = self.engine().await {
            let _ = e.call(Method::DELETE, &format!("/containers/{}?force=1", engine::enc(name, false)), None).await?;
            return Ok(());
        }
        let _ =
            self.command_with(["rm".to_string(), "-f".into(), name.into()]).stdout(Stdio::null()).stderr(Stdio::null()).status().await?;
        Ok(())
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

    /// A running box's CPU and memory (`wicket node top`): from the Engine API's stats (Docker
    /// samples twice, about a second apart, for the CPU), else `docker stats`. None if it isn't
    /// running.
    pub async fn stats(&self, name: &str) -> Result<Option<BoxStats>> {
        if let Some(e) = self.engine().await {
            let v = e.get_json(&format!("/containers/{}/stats?stream=false", engine::enc(name, false))).await?;
            return Ok(v.as_ref().and_then(stats_of));
        }
        let out = self
            .command_with(["stats".to_string(), "--no-stream".into(), "--format".into(), "{{json .}}".into(), name.into()])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await?;
        Ok(out.status.success().then(|| stats_of_cli(&String::from_utf8_lossy(&out.stdout))).flatten())
    }

    /// Freezes every process in the box (Idle, #70). Memory stays held; sockets and stdin stay open.
    pub async fn pause(&self, name: &str) -> Result<()> {
        self.simple(&["pause", name]).await
    }

    pub async fn unpause(&self, name: &str) -> Result<()> {
        self.simple(&["unpause", name]).await
    }

    async fn simple(&self, args: &[&str]) -> Result<()> {
        let _t = self.span(args[0]);
        if let (Some(e), [op, name]) = (self.engine().await, args) {
            let (st, b) = e.call(Method::POST, &format!("/containers/{}/{op}", engine::enc(name, false)), None).await?;
            if !st.is_success() {
                bail!("docker {op} failed: {}", engine::message(&b));
            }
            return Ok(());
        }
        let out = self.command_with(args.iter().map(|s| s.to_string())).stdout(Stdio::null()).stderr(Stdio::piped()).output().await?;
        if !out.status.success() {
            bail!("docker {} failed: {}", args[0], String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    /// The box's processes, read from its own /proc (`docker top` lists the host's under gVisor):
    /// (pid, ppid, command line). The reader itself is left out.
    pub async fn processes(&self, name: &str, user: &str) -> Result<Vec<(u32, u32, String)>> {
        let script = r#"for d in /proc/[0-9]*; do p=${d#/proc/}; [ "$p" = "$$" ] && continue; [ -r "$d/stat" ] || continue; s=$(cat "$d/stat" 2>/dev/null) || continue; s=${s##*) }; set -- $s; c=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null); printf '%s\t%s\t%s\n' "$p" "$2" "$c"; done"#;
        let out = self
            .exec(name, user, &[], &["sh".into(), "-c".into(), script.into()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("docker exec")?;
        if !out.status.success() {
            bail!("listing the box's processes failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(parse_processes(&String::from_utf8_lossy(&out.stdout)))
    }

    /// Stops processes `pids` in the box, as `user` (#293): SIGTERM, then SIGKILL to what is left
    /// after 2 s. A process that already ended is no error.
    pub async fn kill_processes(&self, name: &str, user: &str, pids: &[u32]) -> Result<()> {
        if pids.is_empty() {
            return Ok(());
        }
        let script = r#"kill -TERM "$@" 2>/dev/null; for _ in 1 2 3 4 5 6 7 8 9 10; do alive=; for p in "$@"; do kill -0 "$p" 2>/dev/null && alive=1; done; [ -z "$alive" ] && exit 0; sleep 0.2; done; kill -KILL "$@" 2>/dev/null; exit 0"#;
        let mut argv: Vec<String> = vec!["sh".into(), "-c".into(), script.into(), "sh".into()];
        argv.extend(pids.iter().map(|p| p.to_string()));
        let out = self
            .exec(name, user, &[], &argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("docker exec")?;
        if !out.status.success() {
            bail!("stopping the box's processes failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    pub async fn kill(&self, name: &str) -> Result<()> {
        let _t = self.span("kill");
        if let Some(e) = self.engine().await {
            let _ = e.call(Method::POST, &format!("/containers/{}/kill", engine::enc(name, false)), None).await?;
            return Ok(());
        }
        let _ = self.command_with(["kill".to_string(), name.into()]).stdout(Stdio::null()).stderr(Stdio::null()).status().await?;
        Ok(())
    }

    /// Writes image `image` (a reference or a digest) on stdout as an OCI image layout archive
    /// (#191): the child, its stdout piped. A Docker with the containerd image store writes one.
    pub fn export_image(&self, image: &str) -> Result<Child> {
        self.command_with(["save".to_string(), "--".into(), image.into()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("docker save")
    }

    /// Imports the OCI image layout in local directory `dir` (#191): what [`Docker::export_image`]
    /// wrote, verified and rebuilt by the caller. Only a local Docker takes a directory.
    pub async fn import_layout(&self, dir: &std::path::Path) -> Result<()> {
        if self.quote {
            bail!("a layout is imported only by the node's own Docker");
        }
        let mut tar = Command::new("tar")
            .arg("-C")
            .arg(dir)
            .args(["-cf", "-", "oci-layout", "index.json", "blobs"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("tar")?;
        let out: Stdio = tar.stdout.take().context("tar's output")?.try_into()?;
        let load = self.command_with(["load".to_string()]).stdin(out).stdout(Stdio::null()).stderr(Stdio::piped()).output();
        let (t, l) = tokio::join!(tar.wait(), load);
        let l = l.context("docker load")?;
        if !l.status.success() {
            bail!("docker load failed: {}", String::from_utf8_lossy(&l.stderr).trim());
        }
        if !t?.success() {
            bail!("archiving the image layout failed");
        }
        Ok(())
    }

    /// Builds an image from a directory with these `--build-arg`s, with host networking for the build
    /// only (the daemon has no bridge network; sandboxes never get one).
    pub async fn build_image(&self, tag: &str, dir: &std::path::Path, build_args: &[(&str, &str)]) -> Result<()> {
        let mut args = vec!["build".to_string(), "--network".into(), "host".into(), "-t".into(), tag.into()];
        for (k, v) in build_args {
            args.extend(["--build-arg".to_string(), format!("{k}={v}")]);
        }
        args.push(dir.display().to_string());
        let st = self.command_with(args).status().await?;
        if !st.success() {
            bail!("docker build failed");
        }
        Ok(())
    }
}

/// Parses `pid<TAB>ppid<TAB>cmdline` lines; the reader's own children (`cat`, `tr`) have the reader
/// as their parent and are dropped by [`Docker::processes`]'s caller, as is anything without a pid.
fn parse_processes(out: &str) -> Vec<(u32, u32, String)> {
    out.lines()
        .filter_map(|l| {
            let mut f = l.splitn(3, '\t');
            let pid = f.next()?.trim().parse().ok()?;
            let ppid = f.next()?.trim().parse().ok()?;
            Some((pid, ppid, f.next().unwrap_or("").trim().to_string()))
        })
        .collect()
}

/// A time Docker reports, unless it is Go's zero time (a box that never started, or hasn't ended).
fn docker_time(v: &serde_json::Value) -> Option<String> {
    v.as_str().filter(|t| !t.is_empty() && !t.starts_with("0001-")).map(String::from)
}

/// When a box was created and started, from what `docker inspect` says of it.
fn start_times_of(v: &serde_json::Value) -> Option<(String, String)> {
    Some((v["Created"].as_str()?.to_string(), docker_time(&v["State"]["StartedAt"])?))
}

/// How a box ended, from its `State`.
fn exit_info_of(st: &serde_json::Value) -> ExitInfo {
    ExitInfo {
        code: st["ExitCode"].as_i64().unwrap_or(-1) as i32,
        oom_killed: st["OOMKilled"].as_bool().unwrap_or(false),
        error: st["Error"].as_str().filter(|e| !e.is_empty()).map(String::from),
        started_at: docker_time(&st["StartedAt"]),
        finished_at: docker_time(&st["FinishedAt"]),
    }
}

/// The size of each of a detached box's two log files: half its cap (#151), at least 32 KiB.
fn log_half(log_cap: u64) -> String {
    format!("{}k", (log_cap / 2 / 1024).max(32))
}

/// A size as Docker's CLI reads `--memory` (go-units' RAMInBytes): a number, optionally a unit
/// (b, k, m, g, t, p, powers of 1024, with an optional i and b), in bytes.
fn ram_bytes(s: &str) -> Result<i64> {
    let l = s.trim().to_ascii_lowercase();
    let l = l.strip_suffix('b').unwrap_or(&l);
    let l = l.strip_suffix('i').unwrap_or(l);
    let (num, shift) = match l.char_indices().last() {
        Some((i, c @ ('k' | 'm' | 'g' | 't' | 'p'))) => (&l[..i], 10 * (1 + "kmgtp".find(c).unwrap_or(0) as u32)),
        _ => (l, 0),
    };
    let n: f64 = num.trim().parse().ok().filter(|n: &f64| n.is_finite() && *n >= 0.0).with_context(|| format!("bad memory size {s:?}"))?;
    Ok((n * (1u64 << shift) as f64) as i64)
}

/// `docker create`'s body for `spec`, detached with its logs capped at `log_cap` (#151): what
/// [`Docker::build_args`] asks the CLI for, as the API takes it.
fn create_body(spec: &SandboxSpec, log_cap: u64) -> Result<serde_json::Value> {
    let runtime = match spec.isolation {
        Isolation::Gvisor => "runsc",
        Isolation::Runc => "runc",
    };
    let mem = ram_bytes(&spec.memory)?;
    // As the CLI reads `--cpus` from its text (not the float's binary value).
    let nano_cpus = (format!("{}", spec.cpus).parse::<f64>().unwrap_or(0.0) * 1e9).round() as i64;
    let mut labels = serde_json::Map::new();
    labels.insert("wicket".into(), "1".into());
    for (k, v) in &spec.labels {
        labels.insert(k.clone(), v.clone().into());
    }
    let env: Vec<String> =
        std::iter::once(format!("WICKET_AS_USER={}", spec.user)).chain(spec.env.iter().map(|(k, v)| format!("{k}={v}"))).collect();
    let mounts: Vec<serde_json::Value> = spec
        .mounts
        .iter()
        .map(|m| serde_json::json!({ "Type": "bind", "Source": m.host.display().to_string(), "Target": m.target, "ReadOnly": m.read_only }))
        .collect();
    let mut host = serde_json::json!({
        "Init": true,
        "Runtime": runtime,
        "NetworkMode": "none",
        "Dns": ["198.18.0.1"],
        "Memory": mem,
        "MemorySwap": mem,
        "NanoCpus": nano_cpus,
        "PidsLimit": spec.pids,
        "CapDrop": ["ALL"],
        "CapAdd": ["NET_ADMIN", "SETUID", "SETGID", "SETPCAP"],
        "SecurityOpt": ["no-new-privileges"],
        "ReadonlyRootfs": true,
        "Mounts": mounts,
        "LogConfig": { "Type": "json-file", "Config": { "max-size": log_half(log_cap), "max-file": "2" } },
    });
    if !spec.mounts.iter().any(|m| m.target == "/tmp") {
        host["Tmpfs"] = serde_json::json!({ "/tmp": format!("rw,nosuid,size={TMP_CAP_MB}m") });
    }
    if !spec.mounts.iter().any(|m| m.target == "/etc/hosts") {
        host["ExtraHosts"] = serde_json::json!(["wicket.internal:198.18.0.1"]);
    }
    let mut body = serde_json::json!({
        "Image": spec.image,
        "User": "0:0",
        "Env": env,
        "WorkingDir": spec.workdir,
        "Labels": labels,
        "OpenStdin": spec.interactive,
        "StdinOnce": false,
        "AttachStdin": false,
        "AttachStdout": false,
        "AttachStderr": false,
        "Tty": false,
        "HostConfig": host,
    });
    if !spec.argv.is_empty() {
        body["Cmd"] = serde_json::json!(spec.argv);
    }
    Ok(body)
}

/// A time as Docker's `since` takes it: Unix seconds and nanoseconds.
fn unix_timestamp(t: std::time::SystemTime) -> String {
    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format!("{}.{:09}", d.as_secs(), d.subsec_nanos())
}

/// Copies `r` into `w` until `r` ends; once `w`'s reader has gone, the rest is read and dropped
/// (so a CLI writing both streams never blocks on one nobody reads).
async fn pass_on<R: tokio::io::AsyncRead + Unpin>(mut r: R, mut w: tokio::io::DuplexStream) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 32 << 10];
    let mut open = true;
    loop {
        let k = r.read(&mut buf).await?;
        if k == 0 {
            return Ok(());
        }
        if open && w.write_all(&buf[..k]).await.is_err() {
            open = false;
        }
    }
}

/// Follows a box's logs through the Engine API into `w` (stdout, stderr).
async fn logs_api(e: &engine::Engine, name: &str, since: Option<&str>, w: &mut [tokio::io::DuplexStream; 2]) -> Result<()> {
    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;
    let mut q = "follow=1&stdout=1&stderr=1".to_string();
    if let Some(s) = since {
        q.push_str(&format!("&since={}", engine::enc(s, false)));
    }
    let resp = e.send(Method::GET, &format!("/containers/{}/logs?{q}", engine::enc(name, false)), None).await?;
    if !resp.status().is_success() {
        let b = resp.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
        bail!("docker logs failed: {}", engine::message(&b));
    }
    // A box with a TTY has one raw stream; wicket's have none, so their streams come in frames.
    let raw = resp.headers().get(hyper::header::CONTENT_TYPE).is_some_and(|c| c.as_bytes() == b"application/vnd.docker.raw-stream");
    let mut open = [true, true];
    let mut demux = engine::Demux::default();
    let mut body = resp.into_body();
    while let Some(f) = body.frame().await {
        let Ok(d) = f.context("docker logs")?.into_data() else { continue };
        let parts = if raw { vec![(0, d.to_vec())] } else { demux.feed(&d) };
        for (i, d) in parts {
            // A reader gone: the rest of its stream is dropped, the other's still passed on.
            if open[i] && w[i].write_all(&d).await.is_err() {
                open[i] = false;
            }
        }
    }
    Ok(())
}

/// Follows the image events through the Engine API until they end: for how long, if they were
/// followed at all.
async fn follow_events_api(e: &engine::Engine, since: u64, cache: &ImageCache) -> Option<std::time::Duration> {
    use http_body_util::BodyExt;
    let filters = engine::enc(r#"{"type":["image"]}"#, false);
    let resp = e.send(Method::GET, &format!("/events?since={since}&filters={filters}"), None).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    // Docker sends the headers at once, then a JSON object per event.
    let began = std::time::Instant::now();
    cache.watching(true);
    let mut body = resp.into_body();
    while let Some(Ok(f)) = body.frame().await {
        if f.data_ref().is_some_and(|d| !d.is_empty()) {
            cache.invalidate();
        }
    }
    cache.watching(false);
    Some(began.elapsed())
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
    fn stats_read_as_docker_stats_shows_them() {
        // cgroup v2, as dockerd answers `stats?stream=false`: two samples.
        let v = serde_json::json!({
            "cpu_stats": { "cpu_usage": { "total_usage": 2_400_000_000u64 }, "system_cpu_usage": 120_000_000_000u64, "online_cpus": 2 },
            "precpu_stats": { "cpu_usage": { "total_usage": 2_200_000_000u64 }, "system_cpu_usage": 118_000_000_000u64 },
            "memory_stats": { "usage": 500u64 << 20, "limit": 2u64 << 30, "stats": { "inactive_file": 88u64 << 20 } }
        });
        let s = stats_of(&v).unwrap();
        assert!((s.cpu_pct.unwrap() - 20.0).abs() < 1e-9, "{s:?}");
        assert_eq!((s.memory, s.limit), (412 << 20, 2 << 30));
        // One sample only (`one-shot`, or the box just started): no CPU figure, rather than a wrong one.
        let mut one = v.clone();
        one["precpu_stats"] = serde_json::json!({ "cpu_usage": { "total_usage": 0 } });
        assert_eq!(stats_of(&one).unwrap().cpu_pct, None);
        // A box that isn't running has no memory stats.
        assert_eq!(stats_of(&serde_json::json!({ "memory_stats": {} })), None);
        // The CLI's.
        let s = stats_of_cli(r#"{"CPUPerc":"12.34%","MemUsage":"412MiB / 2GiB","Name":"x"}"#).unwrap();
        assert_eq!((s.cpu_pct, s.memory, s.limit), (Some(12.34), 412 << 20, 2 << 30));
        assert_eq!(stats_of_cli(r#"{"CPUPerc":"--","MemUsage":"0B / 0B"}"#).unwrap(), BoxStats { cpu_pct: None, memory: 0, limit: 0 });
        assert_eq!(stats_of_cli("garbage"), None);
    }

    #[test]
    fn args_never_include_a_network() {
        let d = Docker::with_command(vec!["docker".into()]);
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
        assert!(a.contains("--dns 198.18.0.1"));
        assert!(a.contains("--memory 1g --memory-swap 1g"), "the limit includes swap: a box can't swap past it");
        assert!(a.contains("--tmpfs /tmp:rw,nosuid,size=512m"));
        assert!(!a.contains("SYS_ADMIN") && !a.contains("--privileged"));
        assert!(a.contains("type=bind,source=/x,target=/y,readonly"));
        // With wicket's own hosts file mounted (links add names to it), no --add-host.
        let mut own = spec.clone();
        own.mounts.push(Mount { host: "/run/hosts".into(), target: "/etc/hosts".into(), read_only: true });
        own.mounts.push(Mount { host: "/run/box/tmp".into(), target: "/tmp".into(), read_only: false });
        let a = d.build_args(&own).join(" ");
        assert!(!a.contains("--add-host") && a.contains("source=/run/hosts,target=/etc/hosts,readonly"));
        assert!(!a.contains("--tmpfs") && a.contains("source=/run/box/tmp,target=/tmp"), "a host /tmp replaces the tmpfs");
        let e = d.exec_args("wicket-x", "1000:1000", &["-i"], &["socat".into(), "-".into()]).join(" ");
        assert_eq!(e, "exec --user 1000:1000 -i wicket-x socat -");
        assert!(a.contains(" --interactive "));
        assert!(a.ends_with("img claude"));
    }

    #[tokio::test]
    async fn a_timed_docker_records_each_call_under_its_name() {
        let t = Arc::new(Timings::new());
        // `true` stands in for the CLI: every call succeeds at once with no output.
        let d = Docker::with_command(vec!["true".into()]).timed(t.clone());
        assert!(d.image_exists("img").await.unwrap());
        d.remove("box").await.unwrap();
        d.pause("box").await.unwrap();
        assert_eq!(d.start_times("box").await.unwrap(), None, "no output: no times");
        let names: Vec<String> = t.spans().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["docker.image_inspect", "docker.rm", "docker.pause", "docker.inspect"]);
        // Untimed, nothing is recorded anywhere.
        let plain = Docker::with_command(vec!["true".into()]);
        plain.remove("box").await.unwrap();
        assert_eq!(t.spans().len(), 4);
    }

    fn ident(id: &str) -> ImageIdentity {
        ImageIdentity { id: id.into(), repo_digests: vec![], tags: vec![] }
    }

    #[test]
    fn the_image_cache_keeps_nothing_unwatched_or_across_a_change() {
        let c = ImageCache::default();
        assert_eq!(c.ticket(), None, "unwatched: not used");
        c.watching(true);
        let t = c.ticket().unwrap();
        c.put(t, "img", &ident("sha256:a"));
        assert_eq!(c.get("img"), Some(ident("sha256:a")));
        // An event while an inspect ran: what it said may be stale, so it isn't kept.
        let t = c.ticket().unwrap();
        c.invalidate();
        assert_eq!(c.get("img"), None, "an event empties it");
        c.put(t, "img", &ident("sha256:old"));
        assert_eq!(c.get("img"), None, "an inspect from before the event isn't kept");
        let t = c.ticket().unwrap();
        c.put(t, "img", &ident("sha256:b"));
        assert_eq!(c.get("img"), Some(ident("sha256:b")));
        // The watch stops: nothing is used, or kept, until it is followed again.
        let t = c.ticket().unwrap();
        c.watching(false);
        assert_eq!((c.get("img"), c.ticket()), (None, None));
        c.put(t, "img", &ident("sha256:c"));
        c.watching(true);
        assert_eq!(c.get("img"), None);
    }

    /// A fake Docker CLI in `dir`: `image inspect` answers with `dir/ident`'s id (counting calls
    /// in `dir/inspects`), `events` follows `dir/events`.
    fn fake_docker(dir: &std::path::Path) -> Docker {
        use std::os::unix::fs::PermissionsExt;
        let d = dir.display();
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n  events) exec tail -n +1 -f {d}/events ;;\n  image) echo . >> {d}/inspects; printf '{{\"Id\":\"%s\"}}' \"$(cat {d}/ident)\" ;;\nesac\n"
        );
        let p = dir.join("docker");
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(dir.join("events"), "").unwrap();
        Docker::with_command(vec![p.display().to_string()])
    }

    async fn until(what: impl Fn() -> bool) {
        for _ in 0..500 {
            if what() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("timed out");
    }

    #[tokio::test]
    async fn an_image_is_inspected_once_until_an_image_event() {
        let dir = std::env::temp_dir().join(format!("wicket-sandbox-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = fake_docker(&dir);
        let inspects = || std::fs::read_to_string(dir.join("inspects")).map_or(0, |s| s.lines().count());
        std::fs::write(dir.join("ident"), "sha256:a").unwrap();
        let cache = Arc::new(ImageCache::default());
        // Unwatched: every start inspects.
        for _ in 0..2 {
            assert_eq!(d.image_identity_cached(&cache, "img").await.unwrap().unwrap().id, "sha256:a");
        }
        assert_eq!(inspects(), 2);
        let watch = tokio::spawn(d.clone().watch_images(cache.clone()));
        until(|| cache.in_use()).await;
        let t = Arc::new(Timings::new());
        let timed = d.timed(t.clone());
        for _ in 0..3 {
            assert_eq!(timed.image_identity_cached(&cache, "img").await.unwrap().unwrap().id, "sha256:a");
        }
        assert_eq!(inspects(), 3, "inspected once while watched");
        let names: Vec<String> = t.spans().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["docker.image_inspect", "docker.image_cached", "docker.image_cached"]);
        // The tag moves: its event empties the cache, and the next start sees the new image.
        std::fs::write(dir.join("ident"), "sha256:b").unwrap();
        std::fs::write(dir.join("events"), "tag\n").unwrap();
        until(|| cache.is_empty()).await;
        assert_eq!(d.image_identity_cached(&cache, "img").await.unwrap().unwrap().id, "sha256:b");
        assert_eq!(d.image_identity_cached(&cache, "img").await.unwrap().unwrap().id, "sha256:b");
        assert_eq!(inspects(), 4);
        watch.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_times_parse_and_a_box_never_started_has_none() {
        let v = serde_json::json!({"Created": "2026-11-14T10:00:00.123456789Z", "State": {"StartedAt": "2026-11-14T10:00:00.456Z"}});
        assert_eq!(start_times_of(&v), Some(("2026-11-14T10:00:00.123456789Z".into(), "2026-11-14T10:00:00.456Z".into())));
        let never = serde_json::json!({"Created": "2026-11-14T10:00:00Z", "State": {"StartedAt": "0001-01-01T00:00:00Z"}});
        assert_eq!(start_times_of(&never), None);
        assert_eq!(start_times_of(&serde_json::json!({})), None);
    }

    /// What a [`FakeEngine`] answers.
    enum Reply {
        Json(u16, serde_json::Value),
        Status(u16),
        /// Streamed, chunk by chunk, until the sender is dropped.
        Stream(&'static str, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>),
    }

    /// Each request a [`FakeEngine`] took: method, path and query, body.
    type Seen = Arc<std::sync::Mutex<Vec<(String, String, Vec<u8>)>>>;

    type Route = Arc<dyn Fn(&str, &str, &[u8]) -> Reply + Send + Sync>;

    /// A fake Docker Engine API on a unix socket: each request (method, path and query, body) is
    /// kept in `seen` and answered by `route`.
    struct FakeEngine {
        dir: PathBuf,
        sock: PathBuf,
        seen: Seen,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for FakeEngine {
        fn drop(&mut self) {
            self.task.abort();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    impl FakeEngine {
        fn start(tag: &str, route: impl Fn(&str, &str, &[u8]) -> Reply + Send + Sync + 'static) -> FakeEngine {
            let dir = std::env::temp_dir().join(format!("wicket-engine-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let sock = dir.join("docker.sock");
            let l = tokio::net::UnixListener::bind(&sock).unwrap();
            let seen = Arc::new(std::sync::Mutex::new(vec![]));
            let route: Route = Arc::new(route);
            let s2 = seen.clone();
            let task = tokio::spawn(async move {
                while let Ok((c, _)) = l.accept().await {
                    tokio::spawn(Self::serve(c, route.clone(), s2.clone()));
                }
            });
            FakeEngine { dir, sock, seen, task }
        }

        async fn serve(mut c: tokio::net::UnixStream, route: Route, seen: Seen) {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![];
            let mut b = [0u8; 4096];
            let head_end = loop {
                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break p + 4;
                }
                match c.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(k) => buf.extend_from_slice(&b[..k]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let mut first = head.lines().next().unwrap_or("").split(' ');
            let (method, path) = (first.next().unwrap_or("").to_string(), first.next().unwrap_or("").to_string());
            let len = head
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                .unwrap_or(0);
            while buf.len() < head_end + len {
                match c.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(k) => buf.extend_from_slice(&b[..k]),
                }
            }
            let body = buf[head_end..head_end + len].to_vec();
            let reply = route(&method, &path, &body);
            seen.lock().unwrap().push((method, path, body));
            match reply {
                Reply::Json(code, v) => {
                    let b = serde_json::to_vec(&v).unwrap();
                    let h = format!(
                        "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        b.len()
                    );
                    let _ = c.write_all(&[h.as_bytes(), &b].concat()).await;
                }
                Reply::Status(code) => {
                    let _ = c.write_all(format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await;
                }
                Reply::Stream(ctype, mut rx) => {
                    let h = format!("HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nTransfer-Encoding: chunked\r\n\r\n");
                    if c.write_all(h.as_bytes()).await.is_err() {
                        return;
                    }
                    while let Some(d) = rx.recv().await {
                        if d.is_empty() {
                            continue;
                        }
                        let chunk = [format!("{:x}\r\n", d.len()).as_bytes(), &d, b"\r\n"].concat();
                        if c.write_all(&chunk).await.is_err() {
                            return;
                        }
                    }
                    let _ = c.write_all(b"0\r\n\r\n").await;
                }
            }
        }

        /// A Docker that has only this API: a call that fell back to the CLI would run `false`.
        fn docker(&self) -> Docker {
            Docker { cmd: vec!["false".into()], quote: false, timings: None, api: Some(Api::new(self.sock.clone())) }
        }

        fn seen(&self) -> Vec<(String, String)> {
            self.seen.lock().unwrap().iter().map(|(m, p, _)| (m.clone(), p.clone())).collect()
        }

        fn body_of(&self, path_start: &str) -> serde_json::Value {
            let s = self.seen.lock().unwrap();
            let (_, _, b) = s.iter().find(|(_, p, _)| p.starts_with(path_start)).expect("asked");
            serde_json::from_slice(b).unwrap()
        }
    }

    fn spec() -> SandboxSpec {
        SandboxSpec {
            name: "wicket-x".into(),
            image: "sha256:abc".into(),
            isolation: Isolation::Gvisor,
            mounts: vec![
                Mount { host: "/run/x/sock".into(), target: "/wicket/sock".into(), read_only: false },
                Mount { host: "/run/x/hosts".into(), target: "/etc/hosts".into(), read_only: true },
            ],
            env: vec![("A".into(), "b".into())],
            argv: vec!["sh".into(), "-c".into(), "echo hi".into()],
            memory: "1g".into(),
            cpus: 1.5,
            pids: 64,
            user: "1000:1000".into(),
            workdir: "/workspace".into(),
            interactive: false,
            labels: vec![("wicket.run".into(), "run_1".into())],
        }
    }

    fn container_json() -> serde_json::Value {
        serde_json::json!({
            "Id": "abc", "Created": "2026-11-15T10:00:00.1Z",
            "State": { "Running": false, "Pid": 0, "ExitCode": 137, "OOMKilled": true, "Error": "",
                       "StartedAt": "2026-11-15T10:00:00.3Z", "FinishedAt": "2026-11-15T10:00:01.5Z" },
        })
    }

    #[tokio::test]
    async fn a_box_starts_and_ends_through_the_engine_api() {
        let fake = FakeEngine::start("box", |m, p, _| match (m, p) {
            ("POST", "/containers/create?name=wicket-x") => Reply::Json(201, serde_json::json!({"Id": "abc", "Warnings": []})),
            ("POST", "/containers/abc/start") => Reply::Status(204),
            ("GET", "/containers/wicket-x/json") => Reply::Json(200, container_json()),
            ("GET", _) => Reply::Json(404, serde_json::json!({"message": "No such container: nope"})),
            ("POST", "/containers/wicket-x/wait") => Reply::Json(200, serde_json::json!({"StatusCode": 3})),
            ("POST", "/containers/wicket-x/kill" | "/containers/wicket-x/pause" | "/containers/wicket-x/unpause") => Reply::Status(204),
            ("DELETE", "/containers/wicket-x?force=1") => Reply::Status(204),
            _ => Reply::Json(500, serde_json::json!({"message": "unexpected"})),
        });
        let t = Arc::new(Timings::new());
        let d = fake.docker().timed(t.clone());
        assert!(d.backend().await.starts_with("the Engine API at "));
        d.start_detached(&spec(), 1 << 20).await.unwrap();
        // What the CLI's flags ask for, as the API takes them.
        let c = fake.body_of("/containers/create");
        let h = &c["HostConfig"];
        assert_eq!((h["NetworkMode"].as_str(), h["Runtime"].as_str(), h["Init"].as_bool()), (Some("none"), Some("runsc"), Some(true)));
        assert_eq!(h["CapDrop"], serde_json::json!(["ALL"]));
        assert_eq!(h["CapAdd"], serde_json::json!(["NET_ADMIN", "SETUID", "SETGID", "SETPCAP"]));
        assert_eq!(h["SecurityOpt"], serde_json::json!(["no-new-privileges"]));
        assert_eq!((h["Memory"].as_i64(), h["MemorySwap"].as_i64()), (Some(1 << 30), Some(1 << 30)), "swap included");
        assert_eq!((h["NanoCpus"].as_i64(), h["PidsLimit"].as_i64()), (Some(1_500_000_000), Some(64)));
        assert_eq!(h["ReadonlyRootfs"], true);
        assert_eq!(h["Dns"], serde_json::json!(["198.18.0.1"]));
        assert_eq!(h["Tmpfs"], serde_json::json!({"/tmp": "rw,nosuid,size=512m"}));
        assert!(h.get("ExtraHosts").is_none(), "wicket's own hosts file is mounted");
        assert_eq!(h["LogConfig"], serde_json::json!({"Type": "json-file", "Config": {"max-size": "512k", "max-file": "2"}}));
        assert_eq!(h["Mounts"][1], serde_json::json!({"Type": "bind", "Source": "/run/x/hosts", "Target": "/etc/hosts", "ReadOnly": true}));
        assert_eq!(c["User"], "0:0");
        assert_eq!(c["Env"], serde_json::json!(["WICKET_AS_USER=1000:1000", "A=b"]));
        assert_eq!(c["Labels"], serde_json::json!({"wicket": "1", "wicket.run": "run_1"}));
        assert_eq!(c["Cmd"], serde_json::json!(["sh", "-c", "echo hi"]));
        assert_eq!((c["Image"].as_str(), c["Tty"].as_bool(), c["OpenStdin"].as_bool()), (Some("sha256:abc"), Some(false), Some(false)));

        assert_eq!(d.start_times("wicket-x").await.unwrap(), Some(("2026-11-15T10:00:00.1Z".into(), "2026-11-15T10:00:00.3Z".into())));
        assert_eq!(d.state("wicket-x").await.unwrap(), Some((false, 137)));
        assert_eq!(d.pid("wicket-x").await.unwrap(), 0);
        let info = d.exit_info("wicket-x").await.unwrap().unwrap();
        assert_eq!((info.code, info.oom_killed, info.error), (137, true, None));
        assert_eq!(info.finished_at.as_deref(), Some("2026-11-15T10:00:01.5Z"));
        assert_eq!(d.exit_info("nope").await.unwrap(), None);
        assert_eq!(d.wait("wicket-x").await.unwrap(), 3);
        d.pause("wicket-x").await.unwrap();
        d.unpause("wicket-x").await.unwrap();
        d.kill("wicket-x").await.unwrap();
        d.remove("wicket-x").await.unwrap();
        // The same spans as through the CLI, so a before and after compare.
        let names: Vec<String> = t.spans().into_iter().map(|s| s.name).collect();
        let want = ["run", "inspect", "inspect", "inspect", "inspect", "inspect", "wait", "pause", "unpause", "kill", "rm"];
        assert_eq!(names, want.map(|n| format!("docker.{n}")));
        assert!(fake.seen().contains(&("POST".into(), "/containers/abc/start".into())));
    }

    #[tokio::test]
    async fn the_daemons_refusal_is_the_start_error() {
        let fake = FakeEngine::start("refused", |_, _, _| {
            Reply::Json(409, serde_json::json!({"message": "Conflict. The container name \"/wicket-x\" is already in use"}))
        });
        let e = fake.docker().start_detached(&spec(), 1 << 20).await.unwrap_err().to_string();
        assert!(e.starts_with("docker run failed: Conflict."), "{e}");
        let e = fake.docker().wait("wicket-x").await.unwrap_err().to_string();
        assert!(e.contains("already in use"), "{e}");
    }

    #[tokio::test]
    async fn logs_come_apart_by_stream_from_where_they_are_asked() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let rx = std::sync::Mutex::new(Some(rx));
        let fake =
            FakeEngine::start("logs", move |_, p, _| match (p.starts_with("/containers/wicket-x/logs?"), rx.lock().unwrap().take()) {
                (true, Some(rx)) => Reply::Stream("application/vnd.docker.multiplexed-stream", rx),
                _ => Reply::Json(404, serde_json::json!({"message": "no"})),
            });
        let mut wire = vec![];
        for (s, d) in [(1u8, &b"hello "[..]), (2, b"warn\n"), (1, b"world\n")] {
            wire.extend_from_slice(&[s, 0, 0, 0]);
            wire.extend_from_slice(&(d.len() as u32).to_be_bytes());
            wire.extend_from_slice(d);
        }
        // Frames split across chunks, as a socket may deliver them.
        for c in wire.chunks(5) {
            tx.send(c.to_vec()).unwrap();
        }
        drop(tx);
        let since = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_500);
        let mut logs = fake.docker().logs("wicket-x", Some(since));
        use tokio::io::AsyncReadExt;
        let (mut out, mut err) = (String::new(), String::new());
        let (a, b) = tokio::join!(logs.stdout.read_to_string(&mut out), logs.stderr.read_to_string(&mut err));
        a.unwrap();
        b.unwrap();
        assert_eq!((out.as_str(), err.as_str()), ("hello world\n", "warn\n"));
        logs.done.await.unwrap().unwrap();
        assert_eq!(fake.seen()[0].1, "/containers/wicket-x/logs?follow=1&stdout=1&stderr=1&since=1700000000.500000000");
        // A box Docker doesn't have: its streams end, and why is said.
        let mut gone = fake.docker().logs("wicket-x", None);
        assert_eq!(gone.stdout.read_to_end(&mut vec![]).await.unwrap(), 0);
        assert!(gone.done.await.unwrap().unwrap_err().to_string().contains("docker logs failed: no"));
    }

    #[tokio::test]
    async fn an_image_is_inspected_once_until_an_engine_api_image_event() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let rx = std::sync::Mutex::new(Some(rx));
        let id = Arc::new(std::sync::Mutex::new("sha256:a".to_string()));
        let id2 = id.clone();
        let fake = FakeEngine::start("events", move |_, p, _| {
            if p.starts_with("/events?since=") && p.ends_with("&filters=%7B%22type%22%3A%5B%22image%22%5D%7D") {
                return match rx.lock().unwrap().take() {
                    Some(rx) => Reply::Stream("application/json", rx),
                    None => Reply::Status(500),
                };
            }
            match p {
                "/images/ghcr.io/w/img:1/json" => {
                    Reply::Json(200, serde_json::json!({"Id": *id2.lock().unwrap(), "RepoTags": ["ghcr.io/w/img:1"]}))
                }
                _ => Reply::Json(404, serde_json::json!({"message": "No such image"})),
            }
        });
        let d = fake.docker();
        let inspects = || fake.seen().iter().filter(|(_, p)| p.starts_with("/images/")).count();
        let cache = Arc::new(ImageCache::default());
        let img = "ghcr.io/w/img:1";
        assert_eq!(d.image_identity_cached(&cache, img).await.unwrap().unwrap().tags, ["ghcr.io/w/img:1"]);
        assert_eq!(d.image_identity("other").await.unwrap(), None);
        assert_eq!(inspects(), 2, "unwatched: asked each time");
        let watch = tokio::spawn(d.clone().watch_images(cache.clone()));
        until(|| cache.in_use()).await;
        for _ in 0..3 {
            assert_eq!(d.image_identity_cached(&cache, img).await.unwrap().unwrap().id, "sha256:a");
        }
        assert_eq!(inspects(), 3, "inspected once while watched");
        *id.lock().unwrap() = "sha256:b".into();
        tx.send(br#"{"Type":"image","Action":"tag","Actor":{"ID":"sha256:b"}}"#.to_vec()).unwrap();
        tx.send(b"\n".to_vec()).unwrap();
        until(|| cache.is_empty()).await;
        assert_eq!(d.image_identity_cached(&cache, img).await.unwrap().unwrap().id, "sha256:b");
        // The daemon goes: the events end, and the cache is set aside until they are followed again.
        drop(tx);
        until(|| !cache.in_use()).await;
        assert_eq!(d.image_identity_cached(&cache, img).await.unwrap().unwrap().id, "sha256:b");
        assert_eq!(inspects(), 5);
        watch.abort();
    }

    #[tokio::test]
    async fn without_its_socket_a_docker_uses_the_cli() {
        let dir = std::env::temp_dir().join(format!("wicket-engine-none-{}", std::process::id()));
        // `true` stands in for the CLI.
        let d = Docker { cmd: vec!["true".into()], quote: false, timings: None, api: Some(Api::new(dir.join("docker.sock"))) };
        assert!(d.image_exists("img").await.unwrap());
        assert!(d.backend().await.starts_with("the CLI (true)"));
        assert_eq!(d.api.as_ref().unwrap().mode.load(Ordering::SeqCst), API_UNKNOWN, "tried again later: the daemon may come up");
        // A socket this process may not connect to (unless it is root): the CLI from then on.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("docker.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o000)).unwrap();
        let shut = Docker { api: Some(Api::new(sock.clone())), ..d.clone() };
        if std::os::unix::net::UnixStream::connect(&sock).is_err() {
            assert!(shut.image_exists("img").await.unwrap());
            assert_eq!(shut.api.as_ref().unwrap().mode.load(Ordering::SeqCst), API_REFUSED);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_api_is_used_for_a_plain_docker_on_a_unix_socket_only() {
        let c = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        let sock = |p: &str| Some(PathBuf::from(p));
        assert_eq!(engine_socket(&c("docker"), None, None), sock("/var/run/docker.sock"));
        assert_eq!(engine_socket(&c("/usr/bin/docker"), None, Some("default")), sock("/var/run/docker.sock"));
        assert_eq!(engine_socket(&c("docker -H unix:///run/user/1000/docker.sock"), None, None), sock("/run/user/1000/docker.sock"));
        assert_eq!(engine_socket(&c("docker --host=unix:///d.sock"), Some("tcp://x:2375"), Some("ctx")), sock("/d.sock"));
        assert_eq!(engine_socket(&c("docker"), Some("unix:///h.sock"), None), sock("/h.sock"));
        // The CLI: a command around docker, a host or a context the API client doesn't speak.
        assert_eq!(engine_socket(&c("sudo -n docker"), None, None), None);
        assert_eq!(engine_socket(&c("ssh node docker"), None, None), None);
        assert_eq!(engine_socket(&c("docker"), Some("ssh://me@node"), None), None);
        assert_eq!(engine_socket(&c("docker -H tcp://x:2375"), None, None), None);
        assert_eq!(engine_socket(&c("docker"), None, Some("rootless")), None);
        assert_eq!(engine_socket(&c("docker --tls"), None, None), None);
        assert_eq!(engine_socket(&[], None, None), None);
    }

    #[test]
    fn memory_sizes_read_as_the_cli_reads_them() {
        assert_eq!(ram_bytes("1g").unwrap(), 1 << 30);
        assert_eq!(ram_bytes("256m").unwrap(), 256 << 20);
        assert_eq!(ram_bytes("512MiB").unwrap(), 512 << 20);
        assert_eq!(ram_bytes("1.5k").unwrap(), 1536);
        assert_eq!(ram_bytes("1073741824").unwrap(), 1 << 30);
        assert_eq!(ram_bytes("10b").unwrap(), 10);
        assert!(ram_bytes("lots").is_err() && ram_bytes("-1g").is_err() && ram_bytes("").is_err());
        // With /tmp and hosts from the host, the box gets neither the tmpfs nor the extra host.
        let mut s = spec();
        s.mounts.retain(|m| m.target != "/etc/hosts");
        s.mounts.push(Mount { host: "/run/x/tmp".into(), target: "/tmp".into(), read_only: false });
        s.argv.clear();
        let b = create_body(&s, 1 << 20).unwrap();
        assert!(b["HostConfig"].get("Tmpfs").is_none() && b.get("Cmd").is_none(), "no argv: the image's own command");
        assert_eq!(b["HostConfig"]["ExtraHosts"], serde_json::json!(["wicket.internal:198.18.0.1"]));
    }

    #[test]
    fn process_lines_parse() {
        let p = parse_processes("1\t0\t/sbin/docker-init -- wicket-entry \n7\t1\tclaude -p \nx\t1\tbad\n");
        assert_eq!(p, vec![(1, 0, "/sbin/docker-init -- wicket-entry".into()), (7, 1, "claude -p".into())]);
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
