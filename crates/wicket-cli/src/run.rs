//! `wicket run`: one agent, one zone, one sandbox.

use crate::node::Node;
use crate::{data_dir, ledger_path};
use anyhow::{bail, Context, Result};
use sha2::Digest;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use wicket_core::{Manifest, RunId};
use wicket_proxy::{ca::RunCa, egress::Egress, gateway::Gateway, llm::Llm, vault::Vault, Event, RunCtx};
use wicket_sandbox::SandboxSpec;
use wicket_store::Ledger;

/// How long an agent identity is valid (seconds). Re-issued at half-life. WICKET_IDENTITY_TTL
/// overrides the 10-minute default (minimum 20 s, for tests).
fn identity_ttl() -> i64 {
    std::env::var("WICKET_IDENTITY_TTL").ok().and_then(|v| v.parse().ok()).unwrap_or(600).max(20)
}

/// Whether `id` is a run id wicket made (`run_` and 26 lowercase letters or digits).
pub fn check_run_id(id: &str) -> Result<()> {
    if id.len() == 30 && id.starts_with("run_") && id[4..].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        Ok(())
    } else {
        bail!("bad run id {id:?}")
    }
}

/// The run's box, on whichever node it runs: stop it, revoke it, pause it, look inside it.
#[derive(Clone)]
struct Stopper(Arc<crate::noderun::NodeCtl>);

impl Stopper {
    async fn kill(&self) -> Result<()> {
        // A paused (Idle) box is unpaused first, so it can be killed.
        let _ = self.unpause().await;
        self.0.kill();
        Ok(())
    }

    /// The run's identity was revoked: the revocation is published first (the node refuses its
    /// ops as soon as the delta applies), then the box is stopped.
    async fn revoke(&self) {
        let _ = self.unpause().await;
        self.0.revoke();
    }

    async fn pause(&self) -> Result<()> {
        self.0.calls.ctl(&self.0.run, "pause", "", "").await.map(|_| ())
    }

    async fn unpause(&self) -> Result<()> {
        self.0.calls.ctl(&self.0.run, "unpause", "", "").await.map(|_| ())
    }

    /// Whether the box is at a quiet point (only the agent's runtime running), as `user`.
    async fn check_quiet(&self, user: &str) -> std::result::Result<(), String> {
        let out = self.0.calls.ctl(&self.0.run, "processes", user, "").await.map_err(|e| format!("{e:#}"))?;
        let procs: Vec<(u32, u32, String)> = serde_json::from_str(out.as_deref().unwrap_or("[]")).map_err(|e| e.to_string())?;
        crate::hibernate::quiet(&procs).map_err(|others| format!("other processes run in the box: {}", others.join("; ")))
    }
}

/// The box's exit, as its node reports it.
struct BoxProc(tokio::sync::oneshot::Receiver<i32>);

impl BoxProc {
    /// Until the box exits (a wrapped agent's whole session).
    async fn exited(&mut self) -> Result<std::process::ExitStatus> {
        use std::os::unix::process::ExitStatusExt;
        let code = (&mut self.0).await.unwrap_or(255);
        Ok(std::process::ExitStatus::from_raw((code & 0xff) << 8))
    }

    /// After its output ended: the exit, if the node reports it within 2 s.
    async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        use std::os::unix::process::ExitStatusExt;
        // A node that never reported an exit (the channel gave up, or the run stopped waiting): a failure.
        let code = tokio::time::timeout(std::time::Duration::from_secs(2), &mut self.0).await.ok().and_then(|r| r.ok()).unwrap_or(255);
        Ok(std::process::ExitStatus::from_raw((code & 0xff) << 8))
    }
}

type Reader = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
type Writer = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;

/// What `wicket run` was asked to do.
pub struct RunOpts<'a> {
    pub manifest: &'a Path,
    /// Copied into the box's /workspace first.
    pub workdir: Option<&'a Path>,
    /// Mounted read-write as the box's /workspace, in place (local runs only).
    pub workspace_dir: Option<&'a Path>,
    /// Replaces the manifest's task text.
    pub task: Option<String>,
    pub image: &'a str,
    pub node: Option<&'a str>,
    pub ssh_key: Option<&'a Path>,
    pub run_id: Option<String>,
    pub parent_run: Option<String>,
    /// The capacity lease this run is placed on (recorded, so the reconciler stops it at lease end).
    pub lease: Option<String>,
    /// Wrap this agent command line (launched by another program, e.g. Claude Code Remote Control
    /// through CLAUDE_CODE_PROCESS_WRAPPER) instead of launching the agent ourselves. Its stdin and
    /// stdout stay connected to the launcher; wicket's own output goes to a log file.
    pub wrap: Option<Vec<String>>,
    /// Wake a hibernated agent (#70): its claim, bundle and first turn. The manifest, image and
    /// workspace come from the agent, not from the options above.
    pub wake: Option<crate::hibernate::Wake>,
    /// Re-attach to run `run_id`, still running on its node after this run's supervisor died (#151):
    /// everything comes from the run's record (`ctl/run.json`), nothing from the options above.
    pub attach: bool,
}

/// What a run's supervisor keeps in `<run dir>/ctl/run.json` so another can take over (#151).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct RunRecord {
    /// The effective manifest (YAML).
    manifest: String,
    image: String,
    /// The enrolled node it runs on (None: this host's own).
    node: Option<String>,
    workspace_dir: Option<std::path::PathBuf>,
    wrapped: bool,
    parent_run: Option<String>,
    lease: Option<String>,
    /// When the box started (Unix ms), and what earlier activations of its agent spent in a box.
    started_ms: i64,
    prior_secs: u64,
    /// The long-lived agent this run is an activation of, its generation, and its session.
    fence: Option<(String, i64)>,
    session_id: String,
    escalate: bool,
}

/// What a supervisor saves as it goes (`ctl/progress.json`), every few seconds: the model spend and
/// how far into the box's output it got.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct RunProgress {
    requests: u64,
    input_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_tokens: u64,
    output_tokens: u64,
    stdout: u64,
    stderr: u64,
}

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(p: &Path) -> Option<T> {
    serde_json::from_slice(&std::fs::read(p).ok()?).ok()
}

pub(crate) fn write_json<T: serde::Serialize>(p: &Path, v: &T) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = p.with_extension("json.new");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    std::io::Write::write_all(&mut f, &serde_json::to_vec(v)?)?;
    std::fs::rename(&tmp, p)?;
    Ok(())
}

/// Holds `<run dir>/ctl/supervisor.lock` for as long as this process supervises the run: one
/// supervisor per run (a second `wicket attach` is refused).
struct SupervisorLock(#[allow(dead_code)] std::fs::File);

fn supervise_lock(dir: &Path) -> Result<SupervisorLock> {
    use std::os::fd::AsRawFd;
    std::fs::create_dir_all(dir.join("ctl"))?;
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("ctl/supervisor.lock"))?;
    // SAFETY: flock on a file descriptor this function owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another wicket process supervises this run");
    }
    Ok(SupervisorLock(f))
}

/// Every secret the manifest would send goes only to hosts the vault binds it to: the model secret
/// to its upstream, each injected secret to its rule's host (a `*.` rule needs a `*.` binding
/// covering it), and a wrapped agent's login to Anthropic's API. Checked again where each is sent.
pub fn check_secret_hosts(m: &Manifest, vault: &Vault, wrapped: bool) -> Result<()> {
    if let Some(llm) = &m.zone.llm {
        let url = reqwest::Url::parse(&llm.upstream).with_context(|| format!("llm.upstream {:?}", llm.upstream))?;
        let host = url.host_str().with_context(|| format!("llm.upstream {:?} has no host", llm.upstream))?;
        vault.check(&llm.secret, host).context("the zone's model route")?;
        if wrapped {
            vault.check(&llm.secret, "api.anthropic.com").context("the wrapped agent's login")?;
        }
    } else if wrapped {
        vault.check("claude-oauth", "api.anthropic.com").context("the wrapped agent's login")?;
    }
    for i in &m.zone.inject {
        if i.optional && !vault.has(&i.secret) {
            continue;
        }
        vault.check(&i.secret, &i.host).with_context(|| format!("inject for {}", i.host))?;
    }
    Ok(())
}

pub async fn run(o: RunOpts<'_>) -> Result<()> {
    let RunOpts {
        manifest: manifest_path,
        workdir,
        workspace_dir,
        task,
        image,
        node,
        ssh_key,
        run_id,
        parent_run,
        lease,
        wrap,
        wake,
        attach,
    } = o;
    // Re-attaching (#151): the run's own record says what it is.
    let record: Option<RunRecord> = match (&run_id, attach) {
        (Some(id), true) => {
            check_run_id(id)?;
            let d = data_dir().join("runs").join(id);
            let r: RunRecord = read_json(&d.join("ctl/run.json")).with_context(|| format!("run {id} has no record to re-attach from"))?;
            if r.wrapped {
                bail!("run {id} wraps an agent whose launcher was this run's own process: it can't be re-attached");
            }
            Some(r)
        }
        (None, true) => bail!("re-attaching needs a run id"),
        _ => None,
    };
    let (image_owned, node_owned, parent_owned, lease_owned, wsd_owned) = match &record {
        Some(r) => (r.image.clone(), r.node.clone(), r.parent_run.clone(), r.lease.clone(), r.workspace_dir.clone()),
        // A new box: the default image means this build's own (#162); a re-attached one keeps its.
        None => (crate::image::effective(image), node.map(String::from), parent_run, lease, workspace_dir.map(Path::to_path_buf)),
    };
    let (image, node, parent_run, lease) = (image_owned.as_str(), node_owned.as_deref(), parent_owned, lease_owned);
    let workspace_dir = wsd_owned.as_deref();
    // `--node local` is this host's own node: the same as no --node.
    let node = node.filter(|n| *n != crate::localnode::NAME);
    // A wrapped agent's stdout is its launcher's protocol channel: keep it for the agent, and send
    // everything wicket prints to a log file instead.
    let mut agent_stdout: Option<std::os::fd::OwnedFd> = None;
    if wrap.is_some() {
        use std::os::fd::{AsRawFd, FromRawFd};
        let logs = data_dir().join("wrap-logs");
        std::fs::create_dir_all(&logs)?;
        let log = std::fs::File::create(logs.join(format!("{}.log", std::process::id())))?;
        // SAFETY: plain fd duplication on fds this process owns.
        let saved = unsafe { libc::dup(1) };
        if saved < 0 || unsafe { libc::dup2(log.as_raw_fd(), 1) } < 0 {
            bail!("could not redirect wicket's output for a wrapped agent");
        }
        agent_stdout = Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(saved) });
        eprintln!("[wicket] wrapping an agent; wicket's log: {}", logs.join(format!("{}.log", std::process::id())).display());
    }
    if wrap.is_some() && node.is_some() {
        bail!("wrapping an agent runs it on this host's own node; --node isn't supported with it");
    }
    // A wrapped agent works in its launcher's directory, mounted at the same path in the box.
    let wrap_cwd = match &wrap {
        Some(_) => Some(std::env::current_dir()?),
        None => None,
    };
    let workspace_dir = workspace_dir.or(wrap_cwd.as_deref());
    // A woken agent's in-place workspace is where it was: Claude Code keys sessions by directory. If
    // it's gone (another node, a lost disk), it is restored from the bundle first.
    let wake_ws: Option<std::path::PathBuf> = wake.as_ref().and_then(|w| w.agent.workspace.as_ref().map(std::path::PathBuf::from));
    if let (Some(w), Some(ws)) = (&wake, &wake_ws) {
        if !ws.exists() {
            println!("[wicket] the agent's workspace {} is gone; restoring it from the bundle", ws.display());
            crate::hibernate::restore(&w.state, "workspace", ws)?;
        }
    }
    let workspace_dir = workspace_dir.or(wake_ws.as_deref());
    let raw = match (&wake, &record) {
        (Some(w), _) => w.agent.manifest.clone(),
        (None, Some(r)) => r.manifest.clone(),
        (None, None) => std::fs::read_to_string(manifest_path).with_context(|| format!("reading {}", manifest_path.display()))?,
    };
    let mut m = Manifest::from_yaml(&raw)?;
    if let Some(t) = task {
        if m.agent.is_none() {
            bail!("--task applies to agent manifests only");
        }
        m.task = t;
    }
    // The effective manifest (after any --task) is what the identity's digest covers.
    let text = serde_yaml::to_string(&m)?;
    let workspace_dir = match workspace_dir {
        None => None,
        Some(_) if workdir.is_some() => bail!("use either --workdir (copy in) or --workspace-dir (mount in place)"),
        Some(w) => {
            let w = std::fs::canonicalize(w).with_context(|| format!("--workspace-dir {}", w.display()))?;
            let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
            if !w.is_dir() || w == Path::new("/") || w == home {
                bail!("--workspace-dir must be a project directory, not {}", w.display());
            }
            Some(w)
        }
    };
    let vault = Vault::new(Vault::default_dir());
    check_secret_hosts(&m, &vault, wrap.is_some())?;
    if let Some(llm) = &m.zone.llm {
        vault.get(&llm.secret).with_context(|| format!("the zone's LLM secret {:?} is not usable", llm.secret))?;
    }
    // A program runs only the source it was approved as (its digest), copied into the box.
    let program_src = match &m.program {
        Some(_) if record.is_some() => None,
        Some(p) => {
            let base = manifest_path.parent().unwrap_or(Path::new("."));
            let src = p.source.as_ref().map(|s| base.join(s));
            let digest = match &src {
                Some(s) => Some(crate::program::digest_dir(s)?),
                None => None,
            };
            match (&p.digest, &digest) {
                (Some(want), Some(got)) if want != got => {
                    bail!("program {} source digest is {got}, but the approved digest is {want}: re-approve the change", p.name)
                }
                (Some(_), None) => bail!("program {} pins a digest but has no source", p.name),
                (None, Some(got)) => println!("[wicket] program {} is not pinned (development run); its digest is {got}", p.name),
                _ => {}
            }
            src.map(|s| (s, digest.unwrap_or_default()))
        }
        None => None,
    };
    let image = m.program.as_ref().and_then(|p| p.image.clone()).unwrap_or_else(|| image.to_string());
    let image = image.as_str();
    let (workload, workload_kind) = match (&m.agent, &m.program) {
        (Some(a), _) => (a.name.clone(), a.kind.clone()),
        (_, Some(p)) => (p.name.clone(), "program".to_string()),
        _ => unreachable!("validated"),
    };
    // An optional injection whose secret isn't set is as if it weren't there (#175): dropped from
    // the zone every enforcement point sees (this run's proxies, the node's feed and routing), so
    // its host's requests go without it, and the host is spliced if reach allows it wholesale.
    let unset_injections = m.zone.drop_unset_optional_injections(|s| vault.get(s).is_ok());
    for i in &unset_injections {
        println!("[wicket] optional secret {:?} is not set: requests to {} go without it", i.secret, i.host);
    }
    for i in &m.zone.inject {
        if let Err(e) = vault.get(&i.secret) {
            return Err(e).with_context(|| format!("inject secret {:?} for {}", i.secret, i.host));
        }
    }
    // Every box runs on a node through its `wicket node serve` (#146): an enrolled node, reached over
    // its pinned ssh (a revoked one is refused), or this host's own built-in node over its unix socket.
    let node: Option<Node> = node.map(|n| crate::enrol::resolve_installed(n, ssh_key)).transpose()?;
    if let Some(n) = node.as_ref().filter(|n| n.name.is_none()) {
        bail!("{} is not an enrolled node: enrol it (wicket node enrol) and install wicket there (wicket node install); boxes run only through a node's `wicket node serve`", n.target);
    }
    let node_name = node.as_ref().and_then(|n| n.name.clone()).unwrap_or_else(|| crate::localnode::NAME.to_string());
    // This host's own node shares its filesystem. That is only transport: it lays the box out in the
    // run's own directory (so the run's trees needn't be sent to it), reaches the run's proxies by
    // their sockets, and can mount a directory of this host's in the box (in place, or wrapped).
    let shares_host = node.is_none();

    let run = match run_id {
        Some(id) => {
            check_run_id(&id).with_context(|| "--run-id".to_string())?;
            RunId(id)
        }
        None => RunId::new(),
    };
    // A long-lived agent (#70): one wicket launches itself, here, so its box can be paused,
    // hibernated and rebuilt. Wrapped sessions belong to their launcher, and boxes on nodes keep their
    // state there: both stay one-shot.
    let long_lived = m.agent.as_ref().is_some_and(|a| a.kind == "claude-code") && wrap.is_none();
    if wake.is_some() && !long_lived {
        bail!("only a local claude-code agent can be woken");
    }
    let dir = data_dir().join("runs").join(&run.0);
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let _supervising = supervise_lock(&dir)?;
    if let Some(w) = &wake {
        // The agent's writable state, verified against its manifest as it is unpacked.
        let t0 = std::time::Instant::now();
        for (name, sub) in [("state", "state"), ("tmp", "tmp")].into_iter().chain(wake_ws.is_none().then_some(("workspace", "workspace"))) {
            crate::hibernate::restore(&w.state, name, &dir.join(sub))?;
        }
        for v in m.zone.volumes.iter().filter(|v| v.persist == wicket_core::Persist::Durable) {
            crate::hibernate::restore(&w.state, &format!("volume.{}", v.name), &crate::hibernate::durable_volume(&w.agent.id, &v.name))?;
        }
        println!("[wicket] restored and verified the agent's state in {} ms", t0.elapsed().as_millis());
    }
    // What wicket mounts and writes into must be real directories, whatever a restored bundle held.
    crate::hibernate::real_dirs(
        &["ctl", "sock", "ca", "state", "state/home", "state/claude", "workspace", "workspace/out"].map(|s| dir.join(s)),
    )?;
    // An agent's /tmp is a directory its node keeps with the rest of its state (and through a crash),
    // capped at the size the tmpfs had. Programs keep the tmpfs.
    let box_tmp = m.program.is_none();
    if box_tmp && dir.join("tmp").exists() {
        crate::hibernate::real_dirs(&[dir.join("tmp")])?;
    }
    for w in workdir.into_iter().filter(|_| record.is_none()).chain(program_src.as_ref().map(|(s, _)| s.as_path())) {
        let st = std::process::Command::new("cp").arg("-a").arg(format!("{}/.", w.display())).arg(dir.join("workspace")).status()?;
        if !st.success() {
            bail!("copying {} failed", w.display());
        }
    }

    let ledger: Arc<Mutex<Ledger>> = Arc::new(Mutex::new(crate::audit_export::open_batched(&ledger_path())?));
    // Commits the audit records still queued however the run ends (#62).
    let _flush = crate::audit_export::FlushOnDrop(ledger.clone());
    // Until the run loop handles signals itself: a SIGTERM or ^C commits what is queued first.
    let early_signals = crate::audit_export::flush_on_signal(ledger.clone(), || {});
    // Feeds the installation's audit sinks while this run lasts, if it has any (#91).
    crate::audit_export::spawn_background();
    // The agent's session, and this activation's fencing token: new for a first run, the claimed
    // generation and the agent's own session for a wake.
    let session = match (&wake, &record) {
        (Some(w), _) => wicket_agent::AgentSession { id: w.agent.session_id.clone(), resume: true },
        (None, Some(r)) => wicket_agent::AgentSession { id: r.session_id.clone(), resume: true },
        (None, None) => wicket_agent::AgentSession::new(),
    };
    let mut fence: Option<wicket_proxy::Fence> =
        wake.as_ref().map(|w| wicket_proxy::Fence { agent: w.agent.id.clone(), generation: w.generation });
    if let Some(r) = &record {
        fence = r.fence.as_ref().map(|(a, g)| wicket_proxy::Fence { agent: a.clone(), generation: *g });
        let l = ledger.lock().expect("ledger");
        if l.run_status(&run.0)?.as_deref() != Some("running") {
            bail!("run {run} is not running in the ledger");
        }
        if let Some(f) = &fence {
            match l.agent(&f.agent)? {
                Some(a) if a.generation == f.generation => {
                    l.renew_agent_lease(&f.agent, f.generation, wicket_store::now() + crate::hibernate::LEASE_SECS)?;
                }
                _ => bail!("agent {} has moved past generation {}: this activation was superseded", f.agent, f.generation),
            }
        }
        // This process supervises it now (the reconciler judges the run by this).
        l.set_run_owner(&run.0, &crate::reap::owner_label())?;
        l.audit(&m.tenant, Some(&run), "run.attach", &serde_json::json!({ "owner": crate::reap::owner_label(), "node": node_name }))?;
    }
    if record.is_none() {
        let l = ledger.lock().expect("ledger");
        l.run_started(&m.tenant, &run, &m.zone.name, &workload)?;
        // Who supervises it, for the reconciler (#38), and the lease it is placed on, if any.
        l.set_run_owner(&run.0, &crate::reap::owner_label())?;
        if let Some(lease) = &lease {
            l.set_run_lease(&run.0, lease)?;
        }
        drop(l);
        if long_lived && wake.is_none() {
            let mut l = ledger.lock().expect("ledger");
            let id = wicket_store::new_agent_id();
            l.create_agent(&wicket_store::NewAgent {
                id: &id,
                tenant: &m.tenant.0,
                zone: &m.zone.name,
                name: &workload,
                run: &run.0,
                session_id: &session.id,
                manifest: &text,
                image,
                workspace: workspace_dir.as_deref().and_then(|w| w.to_str()),
                lease_until: wicket_store::now() + crate::hibernate::LEASE_SECS,
            })?;
            fence = Some(wicket_proxy::Fence { agent: id, generation: 1 });
        }
        let l = ledger.lock().expect("ledger");
        l.audit(
            &m.tenant,
            Some(&run),
            "run.start",
            &serde_json::json!({
                "zone": m.zone.name, "agent": workload, "kind": workload_kind, "isolation": m.zone.isolation, "image": image,
                "reach": m.zone.reach.len(), "task": m.task,
                "program_digest": program_src.as_ref().map(|(_, d)| d.clone()),
                "program_pinned": m.program.as_ref().map(|p| p.digest.is_some()),
                "agent_id": fence.as_ref().map(|f| f.agent.clone()), "generation": fence.as_ref().map(|f| f.generation),
                "session_id": long_lived.then(|| session.id.clone()), "resumed": session.resume,
            }),
        )?;
        // One note per run for each optional injection left out (#175), not one per request.
        for i in &unset_injections {
            l.audit(
                &m.tenant,
                Some(&run),
                "inject.skipped",
                &serde_json::json!({ "host": i.host, "secret": i.secret, "why": "optional secret not set" }),
            )?;
        }
    }

    // Enforcement points, on unix sockets that only this box gets.
    // Its key is kept in `ctl/` (never mounted in the box), for a supervisor that re-attaches.
    let ca = match &record {
        Some(_) => Arc::new(RunCa::load(
            &std::fs::read_to_string(dir.join("ctl/run-ca.pem")).context("the run CA's certificate")?,
            &std::fs::read_to_string(dir.join("ctl/run-ca.key")).context("the run CA's key")?,
        )?),
        None => {
            let ca = RunCa::generate(&run.0)?;
            std::fs::create_dir_all(dir.join("ctl"))?;
            std::fs::write(dir.join("ctl/run-ca.pem"), ca.cert_pem())?;
            write_secret(&dir.join("ctl/run-ca.key"), &ca.key_pem())?;
            Arc::new(ca)
        }
    };
    std::fs::write(dir.join("ca/ca.pem"), ca.cert_pem())?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let escalate = m.program.as_ref().map(|p| p.on_pending == wicket_core::OnPending::Wait).unwrap_or(true);
    // Identity (design §3.2): launch is registration. wicket issues this instance's identity from
    // facts it chose, and keeps the instance's key here; the box never sees either.
    // Identities are short-lived (identity_ttl) and re-issued with a fresh key at half-life while the
    // run lives, so a leaked key or document is useful for minutes, not for the run.
    let identity_ttl = identity_ttl();
    let mut id_spec: Option<wicket_identity::IdentitySpec> = None;
    // Every box gets one: agents and programs alike (a program signs its run_finished with it).
    let workload_name = m.agent.as_ref().map(|a| a.name.clone()).or_else(|| m.program.as_ref().map(|p| p.name.clone()));
    let identity: Option<Arc<wicket_proxy::IdentityCell>> = match &workload_name {
        None => None,
        Some(_) if record.is_some() => {
            // The same facts as the run's identity in the ledger, with a fresh key.
            let issuer = crate::issuer()?;
            let row = ledger.lock().expect("ledger").identity(&run.0)?.context("the run's identity")?;
            // Verified as of when it was issued (it may have expired while nobody supervised the run).
            let old = wicket_identity::verify_identity(&row.jws, &issuer.verifying_key(), row.issued_at).context("the run's identity")?;
            let spec = wicket_identity::IdentitySpec {
                tenant: old.tenant,
                zone: old.zone,
                agent: old.agent,
                run: old.run,
                parent_run: old.parent_run,
                manifest_sha256: old.manifest_sha256,
                image: old.image,
                node: old.node,
                principal: old.principal,
                act: old.act,
            };
            let key = wicket_identity::AgentKey::generate();
            let now = wicket_store::now();
            let jws = issuer.issue(&spec, now, identity_ttl, &key.public());
            let claims = wicket_identity::verify_identity(&jws, &issuer.verifying_key(), now)?;
            {
                let l = ledger.lock().expect("ledger");
                l.rotate_identity(&run.0, &jws, now, claims.exp)?;
                l.audit(&m.tenant, Some(&run), "identity.rotated", &serde_json::json!({
                    "id": claims.sub, "identity_sha256": wicket_identity::identity_digest(&jws), "expires_at": claims.exp, "reattached": true,
                }))?;
            }
            id_spec = Some(spec);
            Some(Arc::new(wicket_proxy::IdentityCell::new(wicket_proxy::RunIdentity { jws, claims, key, issuer: issuer.verifying_key() })))
        }
        Some(wname) => {
            let issuer = crate::issuer()?;
            let key = wicket_identity::AgentKey::generate();
            let now = wicket_store::now();
            let ttl = identity_ttl;
            let manifest_sha256 = hex::encode(sha2::Sha256::digest(text.as_bytes()));
            let node_name = node_name.clone();
            // Who this agent acts for. A root run: the human who started it, and how wicket knows
            // (the PoC CLI knows only the local unix user). A child: its parent's principal, with the
            // parent prepended to the delegation chain, read from the parent's verified identity
            // (not from anything the parent agent said).
            let (principal, act) = match &parent_run {
                Some(p) => {
                    let l = ledger.lock().expect("ledger");
                    let pc = match l.identity(p)? {
                        Some(pi)
                            if pi.tenant == m.tenant.0
                                && l.run_status(p)?.as_deref() == Some("running")
                                && l.revoked_in_chain(p)?.is_none() =>
                        {
                            wicket_identity::verify_identity(&pi.jws, &issuer.verifying_key(), now)
                                .with_context(|| format!("parent {p}'s identity"))?
                        }
                        _ => bail!("parent run {p} is not a running, unrevoked agent of this tenant"),
                    };
                    (pc.principal.clone(), Some(pc.act_for_child()))
                }
                None if wrap.is_some() => {
                    // The human driving the session through their claude.ai account.
                    let who = std::env::var("CLAUDE_CODE_BRIDGE_OWNER_ACCOUNT_UUID").unwrap_or_else(|_| "unknown".into());
                    (
                        serde_json::json!({ "type": "human", "id": format!("claude.ai account {who}"), "via": "remote-control", "assurance": "claude.ai login" }),
                        None,
                    )
                }
                None => (crate::cli_principal(), None),
            };
            let spec = wicket_identity::IdentitySpec {
                tenant: m.tenant.0.clone(),
                zone: m.zone.name.clone(),
                agent: wname.clone(),
                run: run.0.clone(),
                parent_run: parent_run.clone(),
                manifest_sha256: manifest_sha256.clone(),
                image: image.to_string(),
                node: node_name.clone(),
                principal,
                act,
            };
            let jws = issuer.issue(&spec, now, ttl, &key.public());
            id_spec = Some(spec);
            let claims = wicket_identity::verify_identity(&jws, &issuer.verifying_key(), now)?;
            {
                let l = ledger.lock().expect("ledger");
                l.put_identity(&wicket_store::IdentityRow {
                    run: run.0.clone(),
                    tenant: m.tenant.0.clone(),
                    spiffe_id: claims.sub.clone(),
                    zone: m.zone.name.clone(),
                    agent: wname.clone(),
                    parent_run: parent_run.clone(),
                    accept_from: m.zone.accept_from.clone(),
                    jws: jws.clone(),
                    issued_at: now,
                })?;
                l.audit(&m.tenant, Some(&run), "identity.issued", &serde_json::json!({
                    "id": claims.sub, "parent_run": parent_run, "identity_sha256": wicket_identity::identity_digest(&jws),
                    "issuer_kid": wicket_identity::key_id(&issuer.verifying_key()), "manifest_sha256": claims.manifest_sha256, "image": image, "node": node_name,
                    "acting_for": claims.chain(), "expires_at": claims.exp,
                }))?;
            }
            Some(Arc::new(wicket_proxy::IdentityCell::new(wicket_proxy::RunIdentity { jws, claims, key, issuer: issuer.verifying_key() })))
        }
    };

    // spawn_agent: a child is another `wicket run` process with its own sandbox, sockets, proxies and
    // identity. Its reach can only narrow. It gets the task text and nothing else from the parent.
    let children: Arc<Mutex<Vec<(String, std::process::Child)>>> = Arc::new(Mutex::new(Vec::new()));
    let llm_slot: Arc<std::sync::OnceLock<Arc<Llm>>> = Arc::new(std::sync::OnceLock::new());
    let spawner: Option<wicket_proxy::Spawner> = match &m.agent {
        Some(a) if a.max_children > 0 => Some(crate::spawn::spawner(crate::spawn::SpawnCtx {
            parent: m.clone(),
            // A re-attached run (#151) starts from the slots its children already hold.
            slots: Arc::new(Mutex::new(crate::spawn::reserved_slots(&dir, a.max_children))),
            exe: None,
            run: run.clone(),
            dir: dir.clone(),
            image: image.to_string(),
            node: node.as_ref().map(|n| n.target.clone()),
            ssh_key: ssh_key.map(|k| k.to_path_buf()),
            ledger: ledger.clone(),
            children: children.clone(),
            llm: llm_slot.clone(),
            deadline: std::time::Instant::now() + m.zone.limits.timeout()?,
        })),
        _ => None,
    };

    // Who inside the box made a request: read from the agent's event stream (outside the box).
    let tracker = Arc::new(Mutex::new(wicket_agent::attribution::Tracker::default()));
    let attribute: Option<wicket_proxy::Attributor> = if m.program.is_some() {
        None
    } else {
        let t = tracker.clone();
        Some(Arc::new(move |host: &str, path: &str| {
            let a = t.lock().ok()?.attribute(host, path);
            Some((serde_json::to_value(&a).ok()?, a.summary()))
        }))
    };
    // A wrapped Claude Code session: placeholders in the box, real credentials swapped at the proxy.
    let wrapped = match &wrap {
        None => None,
        Some(argv) => {
            if m.agent.as_ref().map(|a| a.kind.as_str()) != Some("claude-code") {
                bail!("only claude-code agents can be wrapped");
            }
            // Only the login's non-secret fields (scopes, subscription type) are kept.
            let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
            let login_meta = std::fs::read(home.join(".claude/.credentials.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v.get("claudeAiOauth").cloned())
                .map(|o| serde_json::json!({ "scopes": o.get("scopes"), "subscriptionType": o.get("subscriptionType"), "rateLimitTier": o.get("rateLimitTier") }))
                .unwrap_or(serde_json::Value::Null);
            let env: Vec<(String, String)> = std::env::vars().collect();
            Some(wicket_agent::claude_code_wrapped_plan(&m, &run, argv, &env, &login_meta).map_err(|e| anyhow::anyhow!("{e}"))?)
        }
    };
    let swaps = match &wrapped {
        None => vec![],
        Some(w) => {
            let login_secret = m.zone.llm.as_ref().map(|l| l.secret.clone()).unwrap_or_else(|| "claude-oauth".into());
            let mut v = vec![wicket_proxy::CredentialSwap {
                name: "claude login".into(),
                host: "api.anthropic.com".into(),
                placeholder: w.login_placeholder.clone(),
                real: wicket_proxy::SwapSource::Vault(login_secret),
            }];
            if let Some(t) = &w.session_token {
                v.push(wicket_proxy::CredentialSwap {
                    name: "remote-control session".into(),
                    host: "api.anthropic.com".into(),
                    placeholder: w.session_placeholder.clone(),
                    real: wicket_proxy::SwapSource::Value(t.clone()),
                });
            }
            v
        }
    };
    // request_capacity (#7): agents may ask when a placement backend is configured; a human decides.
    let capacity = match (&m.agent, crate::capacity::PlacementConfig::load()) {
        (Some(_), Ok(Some(cfg))) => Some(crate::capacity::hook(m.tenant.clone(), run.clone(), m.zone.name.clone(), ledger.clone(), cfg)),
        (Some(_), Err(e)) => {
            eprintln!("[wicket] request_capacity is off: {e:#}");
            None
        }
        _ => None,
    };
    // A node that lays out its own boxes keeps this one's files after it exits, until its state (or
    // an in-place workspace) is fetched back.
    let keep_on_node = long_lived || (!shares_host && workspace_dir.is_some());
    // Calls on boxes over this run's node connection (pause, exec, link sockets), made before the
    // connection itself: the link tools use them.
    let node_calls = Arc::new(crate::nodecall::Calls::default());
    let ctx = RunCtx {
        tenant: m.tenant.clone(),
        run: run.clone(),
        zone: Arc::new(wicket_core::CompiledZone::new(m.zone.clone())?),
        ledger: ledger.clone(),
        vault,
        events: tx,
        escalate,
        attribute,
        identity: identity.clone(),
        spawner,
        swaps,
        boxes: Some(Arc::new(crate::links::NodeBoxes::new(ledger.clone(), &run.0, &node_name, node_calls.clone(), dir.clone()))
            as Arc<dyn wicket_proxy::link::BoxOps>),
        capacity,
        fence: fence.clone(),
        waker: long_lived.then(|| Arc::new(|agent: &str, by: &str| crate::hibernate::trigger_wake(agent, by)) as wicket_proxy::Waker),
    };
    let egress = Egress::new(ctx.clone(), ca.clone())?;
    let llm = Llm::new(ctx.clone())?;
    let _ = llm_slot.set(llm.clone());
    // A wrapped session's model calls reach the model host through the egress proxy: they get the
    // model proxy's budget, filter and accounting there (#112).
    egress.set_model_gate(llm.clone());
    // A woken agent's budget continues from what its earlier activations spent (#70); a re-attached
    // long-lived agent's from what its agent row records (this activation's spend included, up to its
    // supervisor's last heartbeat), any other re-attached run's from what its supervisor last saved.
    let attach_agent = match (&record, &fence) {
        (Some(_), Some(f)) => ledger.lock().expect("ledger").agent(&f.agent)?,
        _ => None,
    };
    let prior_secs = match (&wake, &attach_agent, &record) {
        (Some(w), _, _) => {
            let a = &w.agent;
            llm.spent_before(a.used_requests.max(0) as u64, a.used_input_tokens.max(0) as u64, a.used_output_tokens.max(0) as u64);
            a.used_secs.max(0) as u64
        }
        (None, Some(a), _) => {
            llm.spent_before(a.used_requests.max(0) as u64, a.used_input_tokens.max(0) as u64, a.used_output_tokens.max(0) as u64);
            a.used_secs.max(0) as u64
        }
        (None, None, Some(r)) => {
            use std::sync::atomic::Ordering::SeqCst;
            let p: RunProgress = read_json(&dir.join("ctl/progress.json")).unwrap_or_default();
            llm.requests.store(p.requests, SeqCst);
            llm.input_tokens.store(p.input_tokens, SeqCst);
            llm.cache_read_tokens.store(p.cache_read_tokens, SeqCst);
            llm.cache_creation_tokens.store(p.cache_creation_tokens, SeqCst);
            llm.output_tokens.store(p.output_tokens, SeqCst);
            r.prior_secs + u64::try_from((wicket_feed::now_ms() - r.started_ms).max(0) / 1000).unwrap_or(0)
        }
        (None, None, None) => 0,
    };
    let gateway = Gateway::new(ctx.clone());
    // The run's own proxies, which its node reaches for what it doesn't decide itself (hosts it
    // forwards, the model, the MCP gateway): `ctl/`, not the box's `sock/`, which is the node's.
    let (es, ls, gs) = (dir.join("ctl/egress.sock"), dir.join("ctl/llm.sock"), dir.join("ctl/gateway.sock"));
    let g_task = tokio::spawn({
        let gs = gs.clone();
        async move { gateway.serve(&gs).await }
    });
    let e_task = tokio::spawn({
        let es = es.clone();
        async move { egress.serve(&es).await }
    });
    let l_task = tokio::spawn({
        let llm = llm.clone();
        let ls = ls.clone();
        async move { llm.serve(&ls).await }
    });
    for _ in 0..50 {
        if es.exists() && ls.exists() && gs.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let is_program = m.program.is_some();
    let (plan, wrap_files) = match (wicket_agent::program_plan(&m, &run), wrapped) {
        (Some(p), _) => (p, vec![]),
        (None, Some(w)) => (w.plan, w.files),
        (None, None) => {
            let mut p = wicket_agent::claude_code_plan(&m, &run, &session);
            if let Some(w) = &wake {
                p.stdin_task = Some(wicket_agent::user_message(&w.first));
            }
            (p, vec![])
        }
    };
    let box_root = dir.clone();
    for (rel, body) in &wrap_files {
        // `state/` may hold restored, agent-written entries: never write through them.
        crate::hibernate::write_owned(&box_root.join("state"), rel, body.as_ref())?;
    }
    if let (Some(w), None, true) = (&workspace_dir, &wrap_cwd, shares_host) {
        // Create the outbox mount point ourselves, so it isn't left behind owned by root.
        std::fs::create_dir_all(w.join("out"))?;
    }
    // On this host's own node, an in-place workspace (or a wrapped agent's directory, at the same
    // path it has on the host) is mounted as it is, with this run's outbox over its out/. Another
    // node gets a copy and sends it back at the end.
    let outbox = (box_root.join("workspace/out").display().to_string(), format!("{}/out", wicket_agent::WORKSPACE), false);
    let binds: Vec<(String, String, bool)> = match (&workspace_dir, shares_host) {
        (Some(w), true) if wrap_cwd.is_some() => vec![(w.display().to_string(), w.display().to_string(), false), outbox],
        (Some(w), true) => vec![(w.display().to_string(), wicket_agent::WORKSPACE.into(), false), outbox],
        _ => vec![],
    };
    // The agent's adapter settings (allowlisted keys only, plus what wicket owns, such as
    // cleanupPeriodDays), in its own config dir. Written after any restore, so wicket's values win.
    let mut state_files: Vec<(String, String)> = vec![];
    if m.agent.as_ref().is_some_and(|a| a.kind == "claude-code") {
        use base64::Engine;
        let json = serde_json::to_vec_pretty(&wicket_agent::claude_settings(&m))?;
        state_files.push(("claude/settings.json".into(), base64::engine::general_purpose::STANDARD.encode(&json)));
    }
    // The box's own user, as its node runs it.
    let box_user = String::new();
    let interactive = plan.stdin_task.is_some() || wrap_cwd.is_some();
    let stdin_task = plan.stdin_task.clone();
    let name = crate::links::box_name(&run.0);
    let spec = SandboxSpec {
        name: name.clone(),
        image: image.to_string(),
        isolation: m.zone.isolation,
        mounts: vec![],
        env: plan.env,
        argv: plan.argv,
        // In bytes, as the subset check read it, so Docker can't read the limit differently (#126).
        memory: m.zone.limits.memory_bytes().context("limits.memory is unreadable")?.to_string(),
        cpus: m.zone.limits.cpus,
        pids: m.zone.limits.pids,
        user: String::new(),
        workdir: wrap_cwd.as_ref().map(|c| c.display().to_string()).unwrap_or_else(|| wicket_agent::WORKSPACE.into()),
        interactive,
        labels: vec![],
    };

    println!(
        "wicket run {}  tenant {}  zone {}  {} {} ({})",
        run,
        m.tenant,
        m.zone.name,
        if is_program { "program" } else { "agent" },
        workload,
        workload_kind
    );
    println!("  isolation {:?}, no network; egress and model calls via wicket only", m.zone.isolation);
    if let Some(i) = &identity {
        let c = i.current().claims.clone();
        println!("  identity {}  (valid {}s, re-issued every {}s)", c.sub, identity_ttl, identity_ttl / 2);
        println!("  acting for {}", c.chain().join(" → "));
    }
    if node.is_some() {
        println!("  node {node_name} via wicket node serve (egress decided there from the signed feed; secrets stay here)");
    }
    println!("  approve escalations from another terminal: wicket pending / wicket approve <id>");
    println!("  run dir {}", dir.display());
    let started = std::time::Instant::now();
    // What another supervisor needs to take this run over (#151).
    if record.is_none() {
        write_json(
            &dir.join("ctl/run.json"),
            &RunRecord {
                manifest: text.clone(),
                image: image.to_string(),
                node: node.as_ref().and_then(|n| n.name.clone()),
                workspace_dir: workspace_dir.clone(),
                wrapped: wrap.is_some(),
                parent_run: parent_run.clone(),
                lease: lease.clone(),
                started_ms: wicket_feed::now_ms(),
                prior_secs,
                fence: fence.as_ref().map(|f| (f.agent.clone(), f.generation)),
                session_id: session.id.clone(),
                escalate,
            },
        )?;
    }
    // Where the last supervisor got to: its transcript is the box's stdout, line by line, so where it
    // ends is exactly what it processed (stderr only as of its last save).
    let resume_from: [u64; 2] = match &record {
        Some(_) => [
            crate::transcript::resume_offset(&dir),
            read_json::<RunProgress>(&dir.join("ctl/progress.json")).map(|p| p.stderr).unwrap_or(0),
        ],
        None => [0, 0],
    };
    // A wrapped agent's stdout, copied to its launcher until the box's ends.
    let mut wrapped_out: Option<tokio::task::JoinHandle<()>> = None;
    let (mut child, stopper, stdin, stdout, stderr): (BoxProc, Stopper, Option<Writer>, Option<Reader>, Reader) = {
        // The box's trees are sent to its node before it starts: the workspace (an in-place one too,
        // copied up and brought back at the end), and a long-lived agent's state, /tmp and durable
        // volumes, as restored here from its bundle. This host's own node lays the box out in the
        // run's directory, so only what lives elsewhere (durable volumes) is sent to it.
        let mut trees: Vec<(String, std::path::PathBuf, Vec<String>)> = vec![];
        if !shares_host {
            match &workspace_dir {
                Some(w) => trees.push(("workspace".into(), w.clone(), vec!["out".into()])),
                None => trees.push(("workspace".into(), dir.join("workspace"), vec![])),
            }
            if long_lived {
                trees.push(("state".into(), dir.join("state"), vec![]));
                if dir.join("tmp").is_dir() {
                    trees.push(("tmp".into(), dir.join("tmp"), vec![]));
                }
            }
        }
        if let Some(f) = fence.as_ref().filter(|_| long_lived) {
            for v in m.zone.volumes.iter().filter(|v| v.persist == wicket_core::Persist::Durable) {
                let d = crate::hibernate::durable_volume(&f.agent, &v.name);
                std::fs::create_dir_all(&d)?;
                trees.push((format!("volume.{}", v.name), d, vec![]));
            }
        }
        let start = crate::chan::BoxStart {
            run: run.0.clone(),
            tenant: m.tenant.0.clone(),
            zone: m.zone.name.clone(),
            image: spec.image.clone(),
            isolation: spec.isolation,
            env: spec.env.clone(),
            argv: spec.argv.clone(),
            memory: spec.memory.clone(),
            cpus: spec.cpus,
            pids: spec.pids,
            interactive: spec.interactive,
            // The node's own backstop, for when it can't reach the run. A long-lived agent's run
            // decides at its deadline (it may hibernate instead), so the node waits a little longer.
            timeout_secs: m.zone.limits.timeout()?.saturating_sub(std::time::Duration::from_secs(prior_secs)).as_secs()
                + if long_lived { 120 } else { 0 },
            escalate,
            ca_pem: ca.cert_pem(),
            workspace_tar: String::new(),
            state_files: state_files.clone(),
            volumes: m.zone.volumes.iter().map(|v| (v.name.clone(), v.path.clone())).collect(),
            streams: [1, 2, 3],
            binds,
            workdir: wrap_cwd.as_ref().map(|c| c.display().to_string()),
            owner: Some(crate::reap::owner_label()),
            long_lived: box_tmp,
            name: Some(spec.name.clone()),
            llm_prior: llm.spent_total(),
            output_cap: m.zone.limits.output_bytes().unwrap_or(64 << 20),
            output_stop: m.zone.limits.on_output_full == wicket_core::manifest::OnOutputFull::Stop,
            durable: match long_lived {
                true => m
                    .zone
                    .volumes
                    .iter()
                    .filter(|v| v.persist == wicket_core::Persist::Durable)
                    .map(|v| (v.name.clone(), v.path.clone()))
                    .collect(),
                false => vec![],
            },
        };
        let via = match &node {
            Some(n) => crate::nodecall::Via::Ssh(crate::nodecall::Via::attach_argv(n)),
            None => {
                crate::localnode::ensure(&ledger).await?;
                crate::nodecall::Via::Unix(crate::localnode::socket()?)
            }
        };
        let nb = crate::noderun::start(crate::noderun::Start {
            node: node_name.clone(),
            via,
            tenant: m.tenant.clone(),
            run: run.clone(),
            zone: m.zone.clone(),
            dir: dir.clone(),
            ledger: ledger.clone(),
            events: ctx.events.clone(),
            start,
            calls: node_calls.clone(),
            trees,
            keep: keep_on_node,
            attach: record.is_some(),
            resume_from,
            attribute: ctx.attribute.clone(),
        })
        .await?;
        let (mut si, mut so) = (nb.stdin.map(|s| Box::new(s) as Writer), Some(Box::new(nb.stdout) as Reader));
        // A wrapped agent's stdin and stdout are its launcher's: joined to the box's, not read here.
        if let Some(fd) = agent_stdout.take() {
            let (box_in, mut box_out) = (si.take(), so.take().expect("stdout"));
            if let Some(mut w) = box_in {
                // Read on a thread of its own: a blocking read of the launcher's stdin must not hold
                // up the runtime's shutdown.
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
                std::thread::spawn(move || {
                    use std::io::Read;
                    let mut buf = vec![0u8; 32 * 1024];
                    let mut input = std::io::stdin().lock();
                    while let Ok(n) = input.read(&mut buf) {
                        if n == 0 || tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    while let Some(b) = rx.recv().await {
                        if w.write_all(&b).await.is_err() {
                            break;
                        }
                    }
                    let _ = w.shutdown().await;
                });
            }
            wrapped_out = Some(tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let mut out = tokio::fs::File::from_std(std::fs::File::from(fd));
                let _ = tokio::io::copy(&mut box_out, &mut out).await;
                let _ = out.flush().await;
            }));
        }
        (BoxProc(nb.exit), Stopper(nb.ctl), si, so, Box::new(nb.stderr) as Reader)
    };
    if let Some(f) = fence.as_ref().filter(|_| record.is_none()) {
        let l = ledger.lock().expect("ledger");
        l.set_agent_state(&f.agent, f.generation, "active", None)?;
        if wake.is_some() {
            println!("  agent {} woken: generation {}, session {} resumed", f.agent, f.generation, session.id);
        } else {
            println!("  agent {} (long-lived; session {}): wicket hibernate {} / wicket wake {}", f.agent, session.id, run, f.agent);
        }
    }
    // Keep the identity fresh, and act on revocation: a revoked agent's box is stopped.
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rotate_task = match (&identity, id_spec) {
        (Some(cell), Some(spec)) => {
            let (cell, ledger, stopper, revoked) = (cell.clone(), ledger.clone(), stopper.clone(), revoked.clone());
            let tenant = m.tenant.clone();
            let run2 = run.clone();
            Some(tokio::spawn(async move {
                let issuer = match crate::issuer() {
                    Ok(i) => i,
                    Err(e) => return eprintln!("[wicket] identity refresh disabled: {e}"),
                };
                let mut next = wicket_store::now() + identity_ttl / 2;
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let rv = ledger.lock().ok().and_then(|l| l.revoked_in_chain(&run2.0).ok().flatten());
                    if let Some((r, _, by, reason)) = rv {
                        let whose = if r == run2.0 { "this agent's".to_string() } else { format!("ancestor {r}'s") };
                        println!("[wicket] {whose} identity was revoked by {by} ({reason}); stopping the box");
                        revoked.store(true, std::sync::atomic::Ordering::SeqCst);
                        stopper.revoke().await;
                        return;
                    }
                    let now = wicket_store::now();
                    if now < next {
                        continue;
                    }
                    let key = wicket_identity::AgentKey::generate();
                    let jws = issuer.issue(&spec, now, identity_ttl, &key.public());
                    let Ok(claims) = wicket_identity::verify_identity(&jws, &issuer.verifying_key(), now) else { continue };
                    if let Ok(l) = ledger.lock() {
                        let _ = l.rotate_identity(&run2.0, &jws, now, claims.exp);
                        let _ = l.audit(
                            &tenant,
                            Some(&run2),
                            "identity.rotated",
                            &serde_json::json!({
                                "id": claims.sub, "identity_sha256": wicket_identity::identity_digest(&jws), "expires_at": claims.exp,
                            }),
                        );
                    }
                    cell.replace(wicket_proxy::RunIdentity { jws, claims, key, issuer: issuer.verifying_key() });
                    next = now + identity_ttl / 2;
                }
            }))
        }
        _ => None,
    };
    // The task is the first user turn on stdin; follow-ups from the operator (`wicket say`) are
    // written the same way while the session is open; closing stdin ends it.
    let mut stdin = stdin;
    if let (Some(si), Some(t), None) = (stdin.as_mut(), &stdin_task, &record) {
        use tokio::io::AsyncWriteExt;
        si.write_all(format!("{t}\n").as_bytes()).await.context("sending the task to the agent")?;
    }
    let idle = m.agent.as_ref().map(|a| a.idle()).transpose()?.unwrap_or_default();
    // Re-attached: between turns if the box's last output line was a turn's result.
    let mut turn_running = match &record {
        Some(_) => !crate::transcript::last_line(&dir)
            .and_then(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
            .is_some_and(|v| v.get("type").and_then(|t| t.as_str()) == Some("result")),
        None => true,
    };
    let mut last_result = std::time::Instant::now();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    // A wrapped agent's stdout goes straight to its launcher; otherwise wicket reads it.
    let mut lines = stdout.map(|o| BufReader::new(o).lines());
    let mut wrapped_exit: Option<std::process::ExitStatus> = None;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // From here the loop handles SIGTERM and ^C, and the run ends through `_flush`.
    early_signals.abort();
    // What the control host keeps of the box's output is bounded like its node's (#160): the zone's
    // limits.output of each stream, the newest kept, and of a program's output shown, the first.
    let output_cap = m.zone.limits.output_bytes().unwrap_or(64 << 20);
    let log_path = dir.join("agent.stderr.log");
    let err_task = tokio::spawn(async move {
        let mut out = crate::transcript::Newest::new(output_cap);
        let mut l = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = l.next_line().await {
            out.line(&line);
        }
        let _ = std::fs::write(log_path, &out.text);
        out
    });
    let transcript = dir.join(crate::transcript::FILE);
    let mut transcript_f = crate::transcript::Transcript::open(&dir, output_cap, record.is_some())?;
    let mut shown: u64 = 0;
    let mut progress_tick = tokio::time::interval(std::time::Duration::from_secs(3));
    // limits.timeout is a long-lived agent's total time in a box: a wake gets what is left.
    let timeout = m.zone.limits.timeout()?.saturating_sub(std::time::Duration::from_secs(prior_secs));
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut timed_out = false;
    // After a stop, how long to wait for a node's box to end: a node that can't be reached stops it
    // itself at the run's timeout.
    let give_up = tokio::time::sleep(std::time::Duration::from_secs(86_400 * 365));
    tokio::pin!(give_up);
    let mut stopping = false;
    let stop_grace = std::time::Duration::from_secs(30);
    let mut status = "unknown".to_string();
    // A program's last lines of output: its result, when it reports to a parent.
    let mut program_tail: Vec<String> = Vec::new();
    // Long-lived agents (#70): Idle is a paused box; at a quiet point the agent hibernates.
    let hib_after = if fence.is_some() { m.agent.as_ref().and_then(|a| a.hibernate().ok().flatten()) } else { None };
    let mut paused = false;
    let mut hibernating = false;
    let mut hib_asked = false;
    let mut hib_tried = false;
    let mut notified_msgs = 0i64;
    let mut superseded = false;
    let mut saw_assistant = false;
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(5));
    let tmp_cap = wicket_sandbox::TMP_CAP_MB << 20;
    // The agent's spend over its life: what earlier activations spent, plus this one's.
    let usage = || {
        let (r, i, o) = llm.spent_total();
        wicket_store::AgentUsage {
            requests: r as i64,
            input_tokens: i as i64,
            output_tokens: o as i64,
            secs: (prior_secs + started.elapsed().as_secs()) as i64,
        }
    };
    let set_state = |state: &str, note: Option<&str>| {
        if let (Some(f), Ok(l)) = (&fence, ledger.lock()) {
            let _ = l.set_agent_state(&f.agent, f.generation, state, note);
        }
    };
    loop {
        tokio::select! {
            ex = child.exited(), if lines.is_none() => {
                wrapped_exit = Some(ex?);
                break;
            }
            _ = term.recv() => {
                println!("[wicket] terminated; stopping the box");
                stopper.kill().await?;
                status = "interrupted".into();
                if !stopping {
                    stopping = true;
                    give_up.as_mut().reset(tokio::time::Instant::now() + stop_grace);
                }
            }
            line = async { lines.as_mut().expect("guarded").next_line().await }, if lines.is_some() => match line? {
                Some(l) => {
                    if let Err(e) = transcript_f.line(&l) {
                        tracing::warn!("writing the transcript: {e:#}");
                    }
                    if is_program {
                        shown += l.len() as u64 + 1;
                        if shown <= output_cap {
                            println!("[program] {}", wicket_agent::clip(&l, 300));
                        } else if shown - (l.len() as u64 + 1) <= output_cap {
                            println!("[wicket] the program's output passed limits.output; the rest is only in its transcript, the newest kept");
                        }
                        program_tail.push(l.clone());
                        if program_tail.len() > 40 {
                            program_tail.remove(0);
                        }
                    } else {
                        // A top-level result ends the agent's turn (subagents' results carry a parent).
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) {
                            if v.get("type").and_then(|t| t.as_str()) == Some("assistant") {
                                if wake.is_some() && !saw_assistant {
                                    println!("[wicket] the woken agent's first reply, {} ms after its box started", started.elapsed().as_millis());
                                }
                                saw_assistant = true;
                            }
                            if v.get("type").and_then(|t| t.as_str()) == Some("result") && v.get("parent_tool_use_id").is_none_or(|p| p.is_null()) {
                                turn_running = false;
                                last_result = std::time::Instant::now();
                                if stdin.is_some() && !idle.is_zero() {
                                    println!("[wicket] turn done; follow-ups for {}: wicket say {} \"…\"", humantime::format_duration(idle), run);
                                }
                            }
                        }
                        let sub = tracker.lock().ok().and_then(|mut t| t.observe(&l));
                        if let Some(r) = wicket_agent::render_event(&l) {
                            match sub {
                                Some(who) => {
                                    let who = wicket_agent::clip(&who, 60);
                                    println!("{}", r.lines().map(|x| format!("  ↳ [{who}] {x}")).collect::<Vec<_>>().join("\n"));
                                }
                                None => println!("{r}"),
                            }
                        }
                    }
                }
                None => break,
            },
            Some(ev) = rx.recv() => print_event(&ev),
            _ = progress_tick.tick() => {
                use std::sync::atomic::Ordering::SeqCst;
                let (o, e) = stopper.0.offsets();
                let _ = write_json(&dir.join("ctl/progress.json"), &RunProgress {
                    requests: llm.requests.load(SeqCst),
                    input_tokens: llm.input_tokens.load(SeqCst),
                    cache_read_tokens: llm.cache_read_tokens.load(SeqCst),
                    cache_creation_tokens: llm.cache_creation_tokens.load(SeqCst),
                    output_tokens: llm.output_tokens.load(SeqCst),
                    stdout: o,
                    stderr: e,
                });
            }
            _ = heartbeat.tick(), if !stopping && !is_program => {
                // The holder's claim on its agent: renewed while the box lives. If it can't be, a
                // newer activation has the agent, and this box must not go on.
                if let Some(f) = &fence {
                    if let Ok(l) = ledger.lock() {
                        let _ = l.record_agent_usage(&f.agent, f.generation, &usage());
                    }
                    let ok = ledger.lock().ok().and_then(|l| l.renew_agent_lease(&f.agent, f.generation, wicket_store::now() + crate::hibernate::LEASE_SECS).ok());
                    if ok == Some(false) {
                        println!("[wicket] agent {} was woken elsewhere (this is generation {}); stopping this box", f.agent, f.generation);
                        superseded = true;
                        hibernating = false;
                        stopper.kill().await?;
                        status = "superseded".into();
                        stopping = true;
                        give_up.as_mut().reset(tokio::time::Instant::now() + stop_grace);
                    }
                }
                // The box's /tmp, measured by its node.
                let over = match box_tmp {
                    true => stopper
                        .0
                        .calls
                        .ctl(&run.0, "usage", "", "tmp")
                        .await
                        .ok()
                        .flatten()
                        .and_then(|b| b.parse::<u64>().ok())
                        .is_some_and(|b| b > tmp_cap),
                    false => false,
                };
                {
                    if over {
                        println!("[wicket] the box's /tmp is over its {} MiB cap; stopping the box", wicket_sandbox::TMP_CAP_MB);
                        hibernating = false;
                        stopper.kill().await?;
                        status = "failed (/tmp over its cap)".into();
                        stopping = true;
                        give_up.as_mut().reset(tokio::time::Instant::now() + stop_grace);
                    }
                }
            }
            _ = tick.tick(), if stdin.is_some() => {
                let msgs = ledger.lock().ok().and_then(|mut l| l.take_operator_messages(&run.0).ok()).unwrap_or_default();
                if !msgs.is_empty() && paused {
                    let _ = stopper.unpause().await;
                    paused = false;
                    set_state("active", None);
                }
                for (text, by) in msgs {
                    use tokio::io::AsyncWriteExt;
                    hib_tried = false;
                    println!("[operator] {by}: {}", wicket_agent::clip(&text, 300));
                    if let Some(si) = stdin.as_mut() {
                        if si.write_all(format!("{}\n", wicket_agent::user_message(&text)).as_bytes()).await.is_err() {
                            stdin = None;
                            break;
                        }
                    }
                    turn_running = true;
                }
                if let Some(f) = &fence {
                    if ledger.lock().ok().and_then(|l| l.take_agent_want(&f.agent, f.generation).ok().flatten()).as_deref() == Some("hibernate") {
                        hib_asked = true;
                        if turn_running {
                            println!("[wicket] hibernate asked: at the end of this turn");
                        }
                    }
                    // A peer's message waiting while the agent is between turns: tell it (wicket's
                    // own words; the message itself is read with await_message).
                    let waiting = ledger.lock().ok().and_then(|l| l.waiting_messages(&run.0).ok()).unwrap_or(0);
                    if waiting < notified_msgs {
                        notified_msgs = waiting;
                    }
                    if !turn_running && waiting > notified_msgs && hib_after.is_some() {
                        use tokio::io::AsyncWriteExt;
                        if paused {
                            let _ = stopper.unpause().await;
                            paused = false;
                            set_state("active", None);
                        }
                        let t = format!("[wicket] {waiting} message(s) from other agents are waiting: read them with wicket's await_message tool.");
                        println!("{t}");
                        if let Some(si) = stdin.as_mut() {
                            let _ = si.write_all(format!("{}\n", wicket_agent::user_message(&t)).as_bytes()).await;
                        }
                        notified_msgs = waiting;
                        turn_running = true;
                        hib_tried = false;
                    }
                    if !turn_running && !hibernating {
                        let since = last_result.elapsed();
                        if hib_asked || (hib_after.is_some_and(|h| since >= h) && !hib_tried) {
                            hib_asked = false;
                            {
                                if paused {
                                    let _ = stopper.unpause().await;
                                    paused = false;
                                }
                                match stopper.check_quiet(&box_user).await {
                                    Ok(()) => {
                                        println!("[wicket] quiet point: hibernating agent {}", f.agent);
                                        set_state("hibernating", None);
                                        hibernating = true;
                                        stdin = None; // EOF: the agent exits, then its state is pushed
                                    }
                                    Err(why) => {
                                        let note = format!("not hibernated: {why}");
                                        println!("[wicket] {note}; staying idle (paused)");
                                        let _ = stopper.pause().await;
                                        paused = true;
                                        hib_tried = true;
                                        set_state("idle", Some(&note));
                                    }
                                }
                            }
                        } else if hib_after.is_some() && !paused && since >= idle {
                            match stopper.pause().await {
                                Ok(()) => {
                                    paused = true;
                                    set_state("idle", None);
                                    println!("[wicket] idle: box paused (follow-ups still reach it: wicket say {run} \"…\")");
                                }
                                Err(e) => println!("[wicket] could not pause the box: {e:#}"),
                            }
                        }
                    }
                }
                if hibernating || hib_after.is_some() {
                    continue;
                }
                if !turn_running && last_result.elapsed() >= idle {
                    if !idle.is_zero() {
                        println!("[wicket] no follow-up for {}; closing the session", humantime::format_duration(idle));
                    }
                    stdin = None; // EOF: the agent finishes and exits
                }
            }
            _ = &mut deadline, if !timed_out => {
                timed_out = true;
                if let (Some(_), false, false, Some(_)) = (&fence, turn_running, hibernating, &stdin) {
                    let _ = stopper.unpause().await;
                    paused = false;
                    if stopper.check_quiet(&box_user).await.is_ok() {
                        println!("[wicket] timeout after {} while idle: hibernating instead", humantime::format_duration(timeout));
                        set_state("hibernating", None);
                        hibernating = true;
                        stdin = None;
                        continue;
                    }
                }
                hibernating = false;
                println!("[wicket] timeout after {}; stopping the box", humantime::format_duration(timeout));
                stopper.kill().await?;
                status = "timeout".into();
                if !stopping {
                    stopping = true;
                    give_up.as_mut().reset(tokio::time::Instant::now() + stop_grace);
                }
            }
            _ = &mut give_up, if stopping => {
                println!("[wicket] node unreachable; not waiting for the box any longer (the node stops it at the run's timeout)");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                println!("[wicket] interrupted; stopping the box");
                stopper.kill().await?;
                status = "interrupted".into();
                if !stopping {
                    stopping = true;
                    give_up.as_mut().reset(tokio::time::Instant::now() + stop_grace);
                }
            }
        }
    }
    let exit = match wrapped_exit {
        Some(e) => e,
        None => child.wait().await?,
    };
    if let Some(t) = wrapped_out.take() {
        // Everything the box wrote reaches the launcher before the run ends.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), t).await;
    }
    while let Ok(ev) = rx.try_recv() {
        print_event(&ev);
    }
    // (A node box that couldn't be reached has no end of stderr: don't wait for one.)
    let stderr_kept = match tokio::time::timeout(std::time::Duration::from_secs(5), err_task).await {
        Ok(r) => r.unwrap_or_default(),
        Err(_) => Default::default(),
    };
    let stderr_text = stderr_kept.text.clone();
    if let Some(t) = &rotate_task {
        t.abort();
    }
    if revoked.load(std::sync::atomic::Ordering::SeqCst) {
        status = "revoked".into();
    }
    if status == "unknown" {
        status = if exit.success() { "succeeded".into() } else { format!("failed ({exit})") };
    }
    if let Some(f) = &fence {
        ledger.lock().expect("ledger").record_agent_usage(&f.agent, f.generation, &usage())?;
    }
    // A node that lays out its own boxes kept this one's files: its state comes back here first (to be
    // bundled), and an in-place workspace goes back into the operator's directory.
    let mut fetched = !keep_on_node;
    if keep_on_node && !superseded {
        match fetch_trees(
            &stopper,
            Fetch {
                run: &run.0,
                m: &m,
                agent: fence.as_ref().map(|f| f.agent.as_str()),
                dir: &dir,
                in_place: workspace_dir.as_deref(),
                hibernating,
                same_dir: shares_host,
            },
        )
        .await
        {
            Ok(()) => fetched = true,
            Err(e) => {
                println!("[wicket] fetching the box's files from node {node_name} failed: {e:#} (they stay there)");
                if hibernating {
                    hibernating = false;
                    set_state("failed", Some(&format!("hibernate failed: fetching its state from node {node_name}: {e:#}")));
                    status = format!("failed (hibernate: fetching its state: {e})");
                }
            }
        }
    }
    if fetched || superseded {
        stopper.0.forget();
    }
    // A long-lived agent's activation ends: hibernated (its state pushed), a wake that never got its
    // session going (back to hibernated, to be retried), or ended.
    if let (Some(f), false) = (&fence, superseded) {
        if hibernating {
            let t0 = std::time::Instant::now();
            let row = {
                let l = ledger.lock().expect("ledger");
                // No heartbeat runs while the state is pushed: hold the claim for long enough.
                l.renew_agent_lease(&f.agent, f.generation, wicket_store::now() + crate::hibernate::BUSY_LEASE_SECS)?;
                l.agent(&f.agent)?.context("the agent row")?
            };
            let mut trees = crate::hibernate::trees(&m, &f.agent, &dir, workspace_dir.as_deref());
            let staged = crate::hibernate::stage_volumes(&mut trees, &dir)?;
            let pushed = crate::hibernate::push(&ledger, &row, f.generation, &trees);
            if !matches!(pushed, Ok(Some(_))) {
                crate::hibernate::unstage_volumes(&staged);
            }
            match pushed {
                Ok(Some(st)) => {
                    // The node is released: what was bundled goes (an in-place workspace is the
                    // operator's own directory, and stays).
                    for (name, p, _) in &trees {
                        match (name.as_str(), &workspace_dir) {
                            ("workspace", Some(_)) => {}
                            // The outbox stays: it is this run's result, read below.
                            ("workspace", None) => crate::hibernate::drop_tree_except(p, &["out"]),
                            _ => crate::hibernate::drop_tree(p),
                        }
                    }
                    let ms = t0.elapsed().as_millis();
                    println!(
                        "[wicket] agent {} hibernated in {ms} ms: {} trees, {} raw, {} stored (seq {}); wake it with: wicket wake {}",
                        f.agent,
                        st.trees.len(),
                        crate::hibernate::human(st.raw_bytes()),
                        crate::hibernate::human(st.stored_bytes()),
                        st.seq,
                        f.agent
                    );
                    let l = ledger.lock().expect("ledger");
                    l.audit(&m.tenant, Some(&run), "agent.hibernate", &serde_json::json!({
                        "agent": f.agent, "generation": f.generation, "seq": st.seq, "push_ms": ms,
                        "raw_bytes": st.raw_bytes(), "stored_bytes": st.stored_bytes(),
                        "trees": st.trees.iter().map(|t| serde_json::json!({ "name": t.name, "digest": t.digest, "files": t.files, "stored_bytes": t.stored_bytes })).collect::<Vec<_>>(),
                    }))?;
                    status = "hibernated".into();
                    // Anything sent while it was hibernating (this run was still its address) wakes it now.
                    let waiting = l.waiting_operator_messages(&run.0).unwrap_or(0) + l.waiting_messages(&run.0).unwrap_or(0);
                    drop(l);
                    if waiting > 0 {
                        println!("[wicket] {waiting} message(s) arrived while it hibernated: waking it again");
                        crate::hibernate::trigger_wake(&f.agent, "a message that arrived while it hibernated");
                    }
                }
                Ok(None) => {
                    println!("[wicket] agent {} was woken elsewhere while this one hibernated; its push was refused", f.agent);
                    status = "superseded".into();
                }
                Err(e) => {
                    println!("[wicket] hibernating agent {} failed: {e:#} (its state stays on this node, in {})", f.agent, dir.display());
                    set_state("failed", Some(&format!("hibernate failed: {e:#}")));
                    status = format!("failed (hibernate: {e})");
                }
            }
        } else if wake.is_some() && !saw_assistant {
            let why = stderr_text.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no output").to_string();
            println!("[wicket] the woken session never started ({}); agent {} stays hibernated", wicket_agent::clip(&why, 200), f.agent);
            let _ = ledger.lock().expect("ledger").release_failed_wake(
                &f.agent,
                f.generation,
                &format!("wake failed: {}", wicket_agent::clip(&why, 200)),
            );
            status = "failed (wake)".into();
        } else {
            set_state("ended", Some(&format!("its session closed ({status}) without hibernating")));
        }
    }
    if !exit.success() && !stderr_text.trim().is_empty() {
        println!("[wicket] agent stderr (last lines):");
        for l in stderr_text.lines().rev().take(8).collect::<Vec<_>>().into_iter().rev() {
            println!("    {}", wicket_agent::clip(l, 300));
        }
    }
    e_task.abort();
    l_task.abort();
    g_task.abort();

    // Typed output: the outbox, parsed and size-limited outside the box. (A node that lays out its
    // boxes sent it with the exit.)
    let result = crate::hibernate::read_outbox(&dir, 64 * 1024).and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    // A child reports back to its parent with a signed message, before its run is marked ended.
    if let (Some(i), Some(p)) = (identity.as_ref().map(|c| c.current()), &parent_run) {
        let output: String = program_tail.join("\n").chars().rev().take(4000).collect::<Vec<_>>().into_iter().rev().collect();
        let body = if is_program {
            serde_json::json!({ "status": status, "result": result, "output_tail": output })
        } else {
            serde_json::json!({ "status": status, "result": result })
        };
        match ctx.send_message(p, "run_finished", body) {
            Ok(id) => println!("[wicket] sent {id} (run_finished) to parent {p}"),
            Err(e) => println!("[wicket] could not report to parent {p}: {e} ({})", i.claims.sub),
        }
    }
    // A parent's children end with it: interrupt them (each stops its own box), then wait briefly.
    let kids: Vec<(String, std::process::Child)> = std::mem::take(&mut *children.lock().expect("children"));
    for (crun, mut proc) in kids {
        if proc.try_wait().ok().flatten().is_none() {
            println!("[wicket] stopping child {crun}");
            let _ = std::process::Command::new("kill").args(["-INT", &proc.id().to_string()]).status();
            for _ in 0..60 {
                if proc.try_wait().ok().flatten().is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            let _ = proc.kill();
        }
    }
    let pending: Vec<String> = {
        let l = ledger.lock().expect("ledger");
        l.pending(&m.tenant)?.into_iter().filter(|r| r.run == run.0).map(|r| r.id).collect()
    };
    // Pending requests are withdrawn by run_ended below; report them first.
    let summary = serde_json::json!({
        "status": status, "seconds": started.elapsed().as_secs(),
        "model_requests": llm.requests.load(std::sync::atomic::Ordering::SeqCst),
        "input_tokens": llm.input_tokens.load(std::sync::atomic::Ordering::SeqCst),
        "cache_read_input_tokens": llm.cache_read_tokens.load(std::sync::atomic::Ordering::SeqCst),
        "cache_creation_input_tokens": llm.cache_creation_tokens.load(std::sync::atomic::Ordering::SeqCst),
        "input_tokens_total": llm.input_total(),
        "output_tokens": llm.output_tokens.load(std::sync::atomic::Ordering::SeqCst),
        "pending_requests": pending, "result": result,
    });
    {
        let l = ledger.lock().expect("ledger");
        let _ = l.run_ended(&run, &status, &summary.to_string())?;
        // What the control host kept of the box's output, and dropped (#160).
        l.audit(
            &m.tenant,
            Some(&run),
            "run.output",
            &serde_json::json!({
                "cap": output_cap,
                "stdout_bytes": transcript_f.offset(), "stdout_dropped": transcript_f.dropped(),
                "stderr_bytes": stderr_kept.total, "stderr_dropped": stderr_kept.dropped(),
            }),
        )?;
        l.audit(&m.tenant, Some(&run), "run.end", &summary)?;
    }
    println!(
        "\n[wicket] run {run}: {status} in {}s; {} model requests, {} in ({} of them cached) / {} out tokens",
        summary["seconds"],
        summary["model_requests"],
        summary["input_tokens_total"],
        llm.input_total() - llm.input_tokens.load(std::sync::atomic::Ordering::SeqCst),
        summary["output_tokens"]
    );
    match &result {
        Some(r) => println!("[wicket] result.json: {}", wicket_agent::clip(&r.to_string(), 1200)),
        None => println!("[wicket] no valid result.json in the outbox"),
    }
    if !pending.is_empty() {
        println!("[wicket] withdrawn (still pending when the run ended): {}", pending.join(", "));
    }
    println!("[wicket] transcript {}", transcript.display());
    Ok(())
}

/// Brings a kept box's files back from its node: its workspace (into the run's directory, or an
/// in-place one into the operator's directory), and if it is hibernating, its state, /tmp and durable
/// volumes, where they are bundled from. Each comes into a fresh directory first, then replaces the
/// copy here, so what the box deleted is gone here too.
struct Fetch<'a> {
    run: &'a str,
    m: &'a Manifest,
    agent: Option<&'a str>,
    dir: &'a Path,
    in_place: Option<&'a Path>,
    hibernating: bool,
    /// The node keeps the box in the run's own directory (this host's own node).
    same_dir: bool,
}

async fn fetch_trees(stopper: &Stopper, f: Fetch<'_>) -> Result<()> {
    let Fetch { run, m, agent, dir, in_place, hibernating, same_dir } = f;
    let calls = &stopper.0.calls;
    let staging = dir.join("fetch");
    let _ = std::fs::remove_dir_all(&staging);
    let mut wanted: Vec<(String, std::path::PathBuf)> = vec![];
    if hibernating && !same_dir {
        for t in ["state", "tmp"] {
            wanted.push((t.into(), dir.join(t)));
        }
    }
    if hibernating {
        if let Some(a) = agent {
            for v in m.zone.volumes.iter().filter(|v| v.persist == wicket_core::Persist::Durable) {
                wanted.push((format!("volume.{}", v.name), crate::hibernate::durable_volume(a, &v.name)));
            }
        }
    }
    let t0 = std::time::Instant::now();
    // This host's own node kept the workspace in the run's directory (or had it mounted in place).
    let ws_staged = staging.join("workspace");
    if !same_dir {
        calls.get_tree(run, "workspace", &ws_staged).await?;
    }
    for (tree, _) in &wanted {
        calls.get_tree(run, tree, &staging.join(tree)).await?;
    }
    match (in_place, same_dir) {
        (_, true) => {}
        (Some(w), false) => crate::hibernate::sync_dir(&ws_staged, w, &["out"])?,
        (None, false) => crate::hibernate::sync_dir(&ws_staged, &dir.join("workspace"), &[])?,
    }
    for (tree, dest) in &wanted {
        crate::hibernate::sync_dir(&staging.join(tree), dest, &[])?;
    }
    let _ = std::fs::remove_dir_all(&staging);
    println!("[wicket] fetched the box's files from its node in {} ms", t0.elapsed().as_millis());
    Ok(())
}

fn print_event(ev: &Event) {
    match ev {
        Event::Egress { method, host, path, risk, outcome, detail } => {
            let tag = match outcome.as_str() {
                "allow" => "ALLOW  ",
                "pending" => "PENDING",
                "denied" => "DENIED ",
                "forwarded" => "FORWARD",
                "spliced" => "SPLICE ",
                "unavailable" => "STALE  ",
                _ => "BLOCKED",
            };
            // A node sends these events, and an agent chose the method, host and path: printed only
            // stripped (#128), and the hint only for what is shaped like a request id (#121).
            let clip = wicket_agent::clip;
            println!(
                "[egress] {tag} {} {}{}  ({}; {})",
                clip(method, 16),
                clip(host, 120),
                clip(path, 120),
                clip(risk, 24),
                clip(detail, 240)
            );
            if outcome == "pending" {
                if let Some(id) = detail.split([' ', ':']).next().filter(|id| is_request_id(id)) {
                    println!("         → a human decides: wicket approve {id}   or   wicket deny {id}");
                }
            }
        }
        Event::Tool { name, detail } => println!("[wicket-tool] {name}: {}", wicket_agent::clip(detail, 160)),
        Event::Llm { model, status, input_tokens, cached_tokens, output_tokens, requests, outcome } => {
            println!(
                "[llm]    #{requests} {} → {status}  in {input_tokens} (+{cached_tokens} cached) / out {output_tokens}  ({})",
                wicket_agent::clip(model.as_deref().unwrap_or("?"), 80),
                wicket_agent::clip(outcome, 120)
            );
        }
    }
}

/// A run that `wicket attach` could not take over is ended as lost (unless another process already
/// supervises it), so its box is stopped by the next reconcile pass instead of being adopted again.
pub fn attach_failed(run: &str, e: &anyhow::Error) {
    let why = format!("{e:#}");
    if why.contains("another wicket process supervises") || check_run_id(run).is_err() {
        return;
    }
    if let Ok(l) = Ledger::open(&ledger_path()) {
        if l.run_status(run).ok().flatten().as_deref() == Some("running") {
            let reason = format!("its supervisor is gone and it could not be taken over: {}", wicket_agent::clip(&why, 300));
            let _ = l.run_ended(&RunId(run.to_string()), crate::reap::LOST, &reason);
            let _ =
                l.audit(&wicket_core::TenantId::single(), Some(&RunId(run.to_string())), "run.lost", &serde_json::json!({ "why": reason }));
        }
    }
}

/// Starts a new supervisor for `run` (`wicket attach <run>`), detached, its output in
/// `<run dir>/ctl/attach.log`: what the reconciler does for a run whose supervisor is gone but whose
/// box still runs on its node (#151).
pub fn spawn_attach(run: &str) -> Result<()> {
    use std::os::unix::process::CommandExt;
    check_run_id(run)?;
    let dir = data_dir().join("runs").join(run).join("ctl");
    std::fs::create_dir_all(&dir)?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("attach.log"))?;
    let mut c = std::process::Command::new(crate::update::self_exe()?);
    c.args(["attach", run]).current_dir(&dir).stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log);
    // SAFETY: async-signal-safe calls only, in the child before exec: its own session, and no
    // descriptor of the reconciler's but stdio.
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            let max = match libc::sysconf(libc::_SC_OPEN_MAX) {
                n if n > 0 => n.min(65_536) as libc::c_int,
                _ => 1024,
            };
            for fd in 3..max {
                libc::close(fd);
            }
            Ok(())
        });
    }
    c.spawn().context("starting `wicket attach`")?;
    Ok(())
}

/// Writes a file only this user can read.
fn write_secret(p: &Path, body: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(p)?;
    std::io::Write::write_all(&mut f, body.as_bytes())?;
    Ok(())
}

/// Whether `id` has the shape of a request id (`r-` and lowercase letters or digits).
fn is_request_id(id: &str) -> bool {
    id.strip_prefix("r-").is_some_and(|r| (1..=32).contains(&r.len()) && r.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
}
