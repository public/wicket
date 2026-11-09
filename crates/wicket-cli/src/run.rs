//! `wicket run`: one agent, one zone, one sandbox.

use crate::node::Node;
use crate::{data_dir, ledger_path};
use anyhow::{bail, Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, BufReader};
use wicket_core::{Manifest, RunId};
use wicket_proxy::{ca::RunCa, egress::Egress, gateway::Gateway, llm::Llm, vault::Vault, Event, RunCtx};
use wicket_sandbox::{Docker, Mount, SandboxSpec};
use sha2::Digest;
use wicket_store::Ledger;

/// How long an agent identity is valid (seconds). Re-issued at half-life. WICKET_IDENTITY_TTL
/// overrides the 10-minute default (minimum 20 s, for tests).
fn identity_ttl() -> i64 {
    std::env::var("WICKET_IDENTITY_TTL").ok().and_then(|v| v.parse().ok()).unwrap_or(600).max(20)
}

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
    /// Wrap this agent command line (launched by another program, e.g. Claude Code Remote Control
    /// through CLAUDE_CODE_PROCESS_WRAPPER) instead of launching the agent ourselves. Its stdin and
    /// stdout stay connected to the launcher; wicket's own output goes to a log file.
    pub wrap: Option<Vec<String>>,
}

pub async fn run(o: RunOpts<'_>) -> Result<()> {
    let RunOpts { manifest: manifest_path, workdir, workspace_dir, task, image, node, ssh_key, run_id, parent_run, wrap } = o;
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
        bail!("wrapping an agent runs it on this host; --node isn't supported with it");
    }
    // A wrapped agent works in its launcher's directory, mounted at the same path in the box.
    let wrap_cwd = match &wrap {
        Some(_) => Some(std::env::current_dir()?),
        None => None,
    };
    let workspace_dir = workspace_dir.or(wrap_cwd.as_deref());
    let raw = std::fs::read_to_string(manifest_path).with_context(|| format!("reading {}", manifest_path.display()))?;
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
        Some(_) if node.is_some() => bail!("--workspace-dir mounts a local directory; it can't be used with --node"),
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
    if let Some(llm) = &m.zone.llm {
        vault.get(&llm.secret).with_context(|| format!("the zone's LLM secret {:?} is not usable", llm.secret))?;
    }
    // A program runs only the source it was approved as (its digest), copied into the box.
    let program_src = match &m.program {
        Some(p) => {
            let base = manifest_path.parent().unwrap_or(Path::new("."));
            let src = p.source.as_ref().map(|s| base.join(s));
            let digest = match &src {
                Some(s) => Some(crate::program::digest_dir(s)?),
                None => None,
            };
            match (&p.digest, &digest) {
                (Some(want), Some(got)) if want != got => bail!("program {} source digest is {got}, but the approved digest is {want}: re-approve the change", p.name),
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
    for i in &m.zone.inject {
        match vault.get(&i.secret) {
            Ok(_) => {}
            Err(_) if i.optional => println!("[wicket] optional secret {:?} is not set: requests to {} go without it", i.secret, i.host),
            Err(e) => return Err(e).with_context(|| format!("inject secret {:?} for {}", i.secret, i.host)),
        }
    }
    let node = node.map(|n| Node::new(n, ssh_key));
    let docker = match &node {
        Some(n) => Docker::over_ssh(n.ssh_prefix()),
        None => Docker::from_env(),
    };
    if !docker.image_exists(image).await? {
        bail!("image {image} not found{} (run: wicket image)", node.as_ref().map(|n| format!(" on {}", n.target)).unwrap_or_default());
    }

    let run = match run_id {
        Some(id) if id.len() == 30 && id.starts_with("run_") && id[4..].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) => RunId(id),
        Some(id) => bail!("bad --run-id {id:?}"),
        None => RunId::new(),
    };
    let dir = data_dir().join("runs").join(&run.0);
    for sub in ["sock", "ca", "state/home", "state/claude", "workspace/out"] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    for w in workdir.into_iter().chain(program_src.as_ref().map(|(s, _)| s.as_path())) {
        let st = std::process::Command::new("cp").arg("-a").arg(format!("{}/.", w.display())).arg(dir.join("workspace")).status()?;
        if !st.success() {
            bail!("copying {} failed", w.display());
        }
    }

    let ledger = Arc::new(Mutex::new(Ledger::open(&ledger_path())?));
    {
        let l = ledger.lock().expect("ledger");
        l.run_started(&m.tenant, &run, &m.zone.name, &workload)?;
        l.audit(&m.tenant, Some(&run), "run.start", &serde_json::json!({
            "zone": m.zone.name, "agent": workload, "kind": workload_kind, "isolation": m.zone.isolation, "image": image,
            "reach": m.zone.reach.len(), "task": m.task,
            "program_digest": program_src.as_ref().map(|(_, d)| d.clone()),
            "program_pinned": m.program.as_ref().map(|p| p.digest.is_some()),
        }))?;
    }

    // Enforcement points, on unix sockets that only this box gets.
    let ca = Arc::new(RunCa::generate(&run.0)?);
    std::fs::write(dir.join("ca/ca.pem"), ca.cert_pem())?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let escalate = m.program.as_ref().map(|p| p.on_pending == wicket_core::OnPending::Wait).unwrap_or(true);
    // Identity (design §3.2): launch is registration. wicket issues this instance's identity from
    // facts it chose, and keeps the instance's key here; the box never sees either.
    // Identities are short-lived (identity_ttl) and re-issued with a fresh key at half-life while the
    // run lives, so a leaked key or document is useful for minutes, not for the run.
    let identity_ttl = identity_ttl();
    let mut id_spec: Option<wicket_identity::IdentitySpec> = None;
    let identity: Option<Arc<wicket_proxy::IdentityCell>> = match &m.agent {
        None => None,
        Some(a) => {
            let issuer = crate::issuer()?;
            let key = wicket_identity::AgentKey::generate();
            let now = wicket_store::now();
            let ttl = identity_ttl;
            let manifest_sha256 = hex::encode(sha2::Sha256::digest(text.as_bytes()));
            let node_name = node.as_ref().map(|n| n.target.clone()).unwrap_or_else(|| "local".into());
            // Who this agent acts for. A root run: the human who started it, and how wicket knows
            // (the PoC CLI knows only the local unix user). A child: its parent's principal, with the
            // parent prepended to the delegation chain, read from the parent's verified identity
            // (not from anything the parent agent said).
            let (principal, act) = match &parent_run {
                Some(p) => {
                    let l = ledger.lock().expect("ledger");
                    let pc = match l.identity(p)? {
                        Some(pi) if pi.tenant == m.tenant.0 && l.run_status(p)?.as_deref() == Some("running") && l.revoked_in_chain(p)?.is_none() => {
                            wicket_identity::verify_identity(&pi.jws, &issuer.verifying_key(), now).with_context(|| format!("parent {p}'s identity"))?
                        }
                        _ => bail!("parent run {p} is not a running, unrevoked agent of this tenant"),
                    };
                    (pc.principal.clone(), Some(pc.act_for_child()))
                }
                None if wrap.is_some() => {
                    // The human driving the session through their claude.ai account.
                    let who = std::env::var("CLAUDE_CODE_BRIDGE_OWNER_ACCOUNT_UUID").unwrap_or_else(|_| "unknown".into());
                    (serde_json::json!({ "type": "human", "id": format!("claude.ai account {who}"), "via": "remote-control", "assurance": "claude.ai login" }), None)
                }
                None => (crate::cli_principal(), None),
            };
            let spec = wicket_identity::IdentitySpec {
                tenant: m.tenant.0.clone(), zone: m.zone.name.clone(), agent: a.name.clone(), run: run.0.clone(), parent_run: parent_run.clone(),
                manifest_sha256: manifest_sha256.clone(), image: image.to_string(), node: node_name.clone(), principal, act,
            };
            let jws = issuer.issue(&spec, now, ttl, &key.public());
            id_spec = Some(spec);
            let claims = wicket_identity::verify_identity(&jws, &issuer.verifying_key(), now)?;
            {
                let l = ledger.lock().expect("ledger");
                l.put_identity(&wicket_store::IdentityRow {
                    run: run.0.clone(), tenant: m.tenant.0.clone(), spiffe_id: claims.sub.clone(), zone: m.zone.name.clone(), agent: a.name.clone(),
                    parent_run: parent_run.clone(), accept_from: m.zone.accept_from.clone(), jws: jws.clone(), issued_at: now,
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
    let spawner: Option<wicket_proxy::Spawner> = match &m.agent {
        Some(a) if a.max_children > 0 => {
            let (pm, prun, pdir, kids) = (m.clone(), run.0.clone(), dir.clone(), children.clone());
            let (img, node_arg, key_arg) = (image.to_string(), node.as_ref().map(|n| n.target.clone()), ssh_key.map(|k| k.to_path_buf()));
            let max = a.max_children as usize;
            Some(Arc::new(move |req: wicket_proxy::SpawnRequest| -> Result<String> {
                let ok_name = !req.agent.is_empty() && req.agent.len() <= 32 && req.agent.starts_with(|c: char| c.is_ascii_lowercase())
                    && req.agent.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
                if !ok_name {
                    bail!("name must match ^[a-z][a-z0-9-]{{0,31}}$");
                }
                let mut kids = kids.lock().expect("children");
                if kids.len() >= max {
                    bail!("this agent may start at most {max} children");
                }
                let mut cm = pm.clone();
                cm.task = req.task;
                if let Some(ca) = cm.agent.as_mut() {
                    ca.name = req.agent.clone();
                    ca.max_children = 0; // no grandchildren in the PoC
                    ca.idle_timeout = "0s".into(); // a child reports to its parent, not the operator
                }
                if let Some(hosts) = &req.reach_hosts {
                    for h in hosts {
                        if !pm.zone.reach.iter().any(|r| &r.host == h) {
                            bail!("{h} is not in this agent's reach; a child's reach can only narrow");
                        }
                    }
                    cm.zone.reach.retain(|r| hosts.contains(&r.host));
                    cm.zone.inject.retain(|i| hosts.contains(&i.host));
                }
                let child = RunId::new();
                let cdir = pdir.join("children");
                std::fs::create_dir_all(&cdir)?;
                let yaml = cdir.join(format!("{}.yaml", child.0));
                std::fs::write(&yaml, serde_yaml::to_string(&cm)?)?;
                let log = std::fs::File::create(cdir.join(format!("{}.log", child.0)))?;
                let mut cmd = std::process::Command::new(std::env::current_exe()?);
                cmd.args(["run", "--run-id", &child.0, "--parent-run", &prun, "--image", &img]);
                if let Some(n) = &node_arg {
                    cmd.args(["--node", n]);
                }
                if let Some(k) = &key_arg {
                    cmd.arg("--ssh-key").arg(k);
                }
                cmd.arg(&yaml).stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log);
                let proc = cmd.spawn().context("starting the child agent")?;
                // The child records its identity before its box starts; wait for it so the parent can
                // message it straight away.
                let ledger = crate::ledger_path();
                for _ in 0..100 {
                    if Ledger::open(&ledger).ok().and_then(|l| l.identity(&child.0).ok().flatten()).is_some() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                kids.push((child.0.clone(), proc));
                Ok(child.0)
            }) as wicket_proxy::Spawner)
        }
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
                name: "claude login".into(), host: "api.anthropic.com".into(), placeholder: w.login_placeholder.clone(),
                real: wicket_proxy::SwapSource::Vault(login_secret),
            }];
            if let Some(t) = &w.session_token {
                v.push(wicket_proxy::CredentialSwap {
                    name: "remote-control session".into(), host: "api.anthropic.com".into(), placeholder: w.session_placeholder.clone(),
                    real: wicket_proxy::SwapSource::Value(t.clone()),
                });
            }
            v
        }
    };
    let ctx = RunCtx { tenant: m.tenant.clone(), run: run.clone(), zone: Arc::new(m.zone.clone()), ledger: ledger.clone(), vault, events: tx, escalate, attribute, identity: identity.clone(), spawner, swaps };
    let egress = Egress::new(ctx.clone(), ca.clone())?;
    let llm = Llm::new(ctx.clone())?;
    let gateway = Gateway::new(ctx.clone());
    let (es, ls, gs) = (dir.join("sock/egress.sock"), dir.join("sock/llm.sock"), dir.join("sock/gateway.sock"));
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
        (None, None) => (wicket_agent::claude_code_plan(&m, &run), vec![]),
    };
    // Where the box's directories live: here, or on the remote node (which gets no secrets: only
    // the CA's public certificate, the workspace, and the two forwarded sockets).
    let (box_root, user, _forward) = match &node {
        None => {
            let uid = std::process::Command::new("id").arg("-u").output()?;
            let gid = std::process::Command::new("id").arg("-g").output()?;
            (dir.clone(), format!("{}:{}", String::from_utf8_lossy(&uid.stdout).trim(), String::from_utf8_lossy(&gid.stdout).trim()), None)
        }
        Some(n) => {
            let home = n.sh("echo $HOME").await?;
            let rd = format!("{home}/wicket-runs/{}", run.0);
            n.sh(&format!("umask 077; mkdir -p {rd}/sock {rd}/ca {rd}/state/home {rd}/state/claude {rd}/workspace/out")).await?;
            n.put(&format!("{rd}/ca/ca.pem"), ca.cert_pem().as_bytes()).await?;
            if let Some(w) = workdir {
                n.put_dir(w, &format!("{rd}/workspace")).await?;
            }
            let fwd = n
                .forward(&[
                    (format!("{rd}/sock/egress.sock"), es.as_path()),
                    (format!("{rd}/sock/llm.sock"), ls.as_path()),
                    (format!("{rd}/sock/gateway.sock"), gs.as_path()),
                ])
                .await?;
            let user = n.sh("echo $(id -u):$(id -g)").await?;
            (std::path::PathBuf::from(rd), user, Some(fwd))
        }
    };
    // Volumes persist per tenant and zone, on whichever host runs the box.
    let mut volume_mounts = Vec::new();
    for v in &m.zone.volumes {
        let host = match &node {
            None => {
                let d = data_dir().join("volumes").join(&m.tenant.0).join(&m.zone.name).join(&v.name);
                std::fs::create_dir_all(&d)?;
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
                d
            }
            Some(n) => {
                let home = n.sh("echo $HOME").await?;
                let d = format!("{home}/wicket-volumes/{}/{}/{}", m.tenant.0, m.zone.name, v.name);
                n.sh(&format!("umask 077; mkdir -p {}", wicket_sandbox::shell_quote(&d))).await?;
                std::path::PathBuf::from(d)
            }
        };
        volume_mounts.push(Mount { host, target: v.path.clone(), read_only: false });
    }
    for (rel, body) in &wrap_files {
        let p = box_root.join("state").join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&p, body)?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    if let (Some(w), None) = (&workspace_dir, &wrap_cwd) {
        // Create the outbox mount point ourselves, so it isn't left behind owned by root.
        std::fs::create_dir_all(w.join("out"))?;
    }
    let workspace_mounts = match &workspace_dir {
        // A wrapped agent's directory, at the same path it has on the host.
        Some(w) if wrap_cwd.is_some() => vec![
            Mount { host: w.clone(), target: w.display().to_string(), read_only: false },
            Mount { host: box_root.join("workspace/out"), target: format!("{}/out", wicket_agent::WORKSPACE), read_only: false },
        ],
        // In place: the project directory itself, with this run's outbox mounted over its out/.
        Some(w) => vec![
            Mount { host: w.clone(), target: wicket_agent::WORKSPACE.into(), read_only: false },
            Mount { host: box_root.join("workspace/out"), target: format!("{}/out", wicket_agent::WORKSPACE), read_only: false },
        ],
        None => vec![Mount { host: box_root.join("workspace"), target: wicket_agent::WORKSPACE.into(), read_only: false }],
    };
    // The agent's adapter settings (allowlisted keys only), in its own config dir.
    if let Some(a) = m.agent.as_ref().filter(|a| !a.adapter_settings.is_empty()) {
        let json = serde_json::to_vec_pretty(&serde_json::Value::Object(a.adapter_settings.clone()))?;
        match &node {
            None => std::fs::write(box_root.join("state/claude/settings.json"), json)?,
            Some(n) => n.put(&format!("{}/state/claude/settings.json", box_root.display()), &json).await?,
        }
    }
    let interactive = plan.stdin_task.is_some() || wrap_cwd.is_some();
    let stdin_task = plan.stdin_task.clone();
    let name = format!("wicket-{}", run.0.replace('_', "-"));
    let spec = SandboxSpec {
        name: name.clone(),
        image: image.to_string(),
        isolation: m.zone.isolation,
        mounts: vec![
            Mount { host: box_root.join("sock"), target: wicket_agent::SOCK_DIR.into(), read_only: false },
            Mount { host: box_root.join("ca"), target: wicket_agent::CA_DIR.into(), read_only: true },
            Mount { host: box_root.join("state"), target: wicket_agent::STATE_DIR.into(), read_only: false },
        ]
        .into_iter()
        .chain(workspace_mounts)
        .chain(volume_mounts)
        .collect(),
        env: plan.env,
        argv: plan.argv,
        memory: m.zone.limits.memory.clone(),
        cpus: m.zone.limits.cpus,
        pids: m.zone.limits.pids,
        user,
        workdir: wrap_cwd.as_ref().map(|c| c.display().to_string()).unwrap_or_else(|| wicket_agent::WORKSPACE.into()),
        interactive,
    };

    println!("wicket run {}  tenant {}  zone {}  {} {} ({})", run, m.tenant, m.zone.name, if is_program { "program" } else { "agent" }, workload, workload_kind);
    println!("  isolation {:?}, no network; egress and model calls via wicket only", m.zone.isolation);
    if let Some(i) = &identity {
        let c = i.current().claims.clone();
        println!("  identity {}  (valid {}s, re-issued every {}s)", c.sub, identity_ttl, identity_ttl / 2);
        println!("  acting for {}", c.chain().join(" → "));
    }
    if let Some(n) = &node {
        println!("  node {} (holds no secrets; sockets forwarded over ssh)", n.target);
    }
    println!("  approve escalations from another terminal: wicket pending / wicket approve <id>");
    println!("  run dir {}", dir.display());
    let started = std::time::Instant::now();
    let mut child = match agent_stdout.take() {
        Some(fd) => docker.spawn_with(&spec, std::process::Stdio::inherit(), std::process::Stdio::from(fd))?,
        None => docker.spawn(&spec)?,
    };
    // Keep the identity fresh, and act on revocation: a revoked agent's box is stopped.
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let rotate_task = match (&identity, id_spec) {
        (Some(cell), Some(spec)) => {
            let (cell, ledger, docker, name, revoked) = (cell.clone(), ledger.clone(), docker.clone(), name.clone(), revoked.clone());
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
                        let _ = docker.kill(&name).await;
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
                        let _ = l.audit(&tenant, Some(&run2), "identity.rotated", &serde_json::json!({
                            "id": claims.sub, "identity_sha256": wicket_identity::identity_digest(&jws), "expires_at": claims.exp,
                        }));
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
    let mut stdin = child.stdin.take();
    if let (Some(si), Some(t)) = (stdin.as_mut(), &stdin_task) {
        use tokio::io::AsyncWriteExt;
        si.write_all(format!("{t}\n").as_bytes()).await.context("sending the task to the agent")?;
    }
    let idle = m.agent.as_ref().map(|a| a.idle()).transpose()?.unwrap_or_default();
    let mut turn_running = true;
    let mut last_result = std::time::Instant::now();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    // A wrapped agent's stdout goes straight to its launcher; otherwise wicket reads it.
    let mut lines = child.stdout.take().map(|o| BufReader::new(o).lines());
    let stderr = child.stderr.take().expect("stderr");
    let mut wrapped_exit: Option<std::process::ExitStatus> = None;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let log_path = dir.join("agent.stderr.log");
    let err_task = tokio::spawn(async move {
        let mut out = String::new();
        let mut l = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = l.next_line().await {
            out.push_str(&line);
            out.push('\n');
        }
        let _ = std::fs::write(log_path, &out);
        out
    });
    let transcript = dir.join("transcript.jsonl");
    let mut transcript_f = std::fs::File::create(&transcript)?;
    let timeout = m.zone.limits.timeout()?;
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut status = "unknown".to_string();
    loop {
        tokio::select! {
            ex = child.wait(), if lines.is_none() => {
                wrapped_exit = Some(ex?);
                break;
            }
            _ = term.recv() => {
                println!("[wicket] terminated; stopping the box");
                docker.kill(&name).await?;
                status = "interrupted".into();
            }
            line = async { lines.as_mut().expect("guarded").next_line().await }, if lines.is_some() => match line? {
                Some(l) => {
                    use std::io::Write;
                    let _ = writeln!(transcript_f, "{l}");
                    if is_program {
                        println!("[program] {}", wicket_agent::clip(&l, 300));
                    } else {
                        // A top-level result ends the agent's turn (subagents' results carry a parent).
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&l) {
                            if v.get("type").and_then(|t| t.as_str()) == Some("result") && v.get("parent_tool_use_id").map_or(true, |p| p.is_null()) {
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
            _ = tick.tick(), if stdin.is_some() => {
                let msgs = ledger.lock().ok().and_then(|mut l| l.take_operator_messages(&run.0).ok()).unwrap_or_default();
                for (text, by) in msgs {
                    use tokio::io::AsyncWriteExt;
                    println!("[operator] {by}: {}", wicket_agent::clip(&text, 300));
                    if let Some(si) = stdin.as_mut() {
                        if si.write_all(format!("{}\n", wicket_agent::user_message(&text)).as_bytes()).await.is_err() {
                            stdin = None;
                            break;
                        }
                    }
                    turn_running = true;
                }
                if !turn_running && last_result.elapsed() >= idle {
                    if !idle.is_zero() {
                        println!("[wicket] no follow-up for {}; closing the session", humantime::format_duration(idle));
                    }
                    stdin = None; // EOF: the agent finishes and exits
                }
            }
            _ = &mut deadline => {
                println!("[wicket] timeout after {}; stopping the box", humantime::format_duration(timeout));
                docker.kill(&name).await?;
                status = "timeout".into();
            }
            _ = tokio::signal::ctrl_c() => {
                println!("[wicket] interrupted; stopping the box");
                docker.kill(&name).await?;
                status = "interrupted".into();
            }
        }
    }
    let exit = match wrapped_exit {
        Some(e) => e,
        None => child.wait().await?,
    };
    while let Ok(ev) = rx.try_recv() {
        print_event(&ev);
    }
    let stderr_text = err_task.await.unwrap_or_default();
    if let Some(t) = &rotate_task {
        t.abort();
    }
    if revoked.load(std::sync::atomic::Ordering::SeqCst) {
        status = "revoked".into();
    }
    if status == "unknown" {
        status = if exit.success() { "succeeded".into() } else { format!("failed ({exit})") };
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

    // Typed output: the outbox, parsed and size-limited outside the box.
    if let Some(n) = &node {
        let rd = box_root.display().to_string();
        if let Ok(s) = n.sh(&format!("head -c 65537 {rd}/workspace/out/result.json 2>/dev/null || true")).await {
            let _ = std::fs::write(dir.join("workspace/out/result.json"), s);
        }
        let _ = n.sh(&format!("rm -rf {rd}")).await;
    }
    let outbox = dir.join("workspace/out/result.json");
    let result = std::fs::read(&outbox).ok().filter(|b| b.len() <= 64 * 1024).and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    // A child reports back to its parent with a signed message, before its run is marked ended.
    if let (Some(i), Some(p)) = (identity.as_ref().map(|c| c.current()), &parent_run) {
        let body = serde_json::json!({ "status": status, "result": result });
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
        "output_tokens": llm.output_tokens.load(std::sync::atomic::Ordering::SeqCst),
        "pending_requests": pending, "result": result,
    });
    {
        let l = ledger.lock().expect("ledger");
        let _ = l.run_ended(&run, &status, &summary.to_string())?;
        l.audit(&m.tenant, Some(&run), "run.end", &summary)?;
    }
    println!("\n[wicket] run {run}: {status} in {}s; {} model requests, {} in / {} out tokens",
        summary["seconds"], summary["model_requests"], summary["input_tokens"], summary["output_tokens"]);
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

fn print_event(ev: &Event) {
    match ev {
        Event::Egress { method, host, path, risk, outcome, detail } => {
            let tag = match outcome.as_str() {
                "allow" => "ALLOW  ",
                "pending" => "PENDING",
                "denied" => "DENIED ",
                _ => "BLOCKED",
            };
            println!("[egress] {tag} {method} {host}{}  ({risk}; {detail})", wicket_agent::clip(path, 120));
            if outcome == "pending" {
                if let Some(id) = detail.split(|c: char| c == ' ' || c == ':').next() {
                    println!("         → a human decides: wicket approve {id}   or   wicket deny {id}");
                }
            }
        }
        Event::Tool { name, detail } => println!("[wicket-tool] {name}: {}", wicket_agent::clip(detail, 160)),
        Event::Llm { model, status, input_tokens, output_tokens, requests, outcome } => {
            println!("[llm]    #{requests} {} → {status}  in {input_tokens} / out {output_tokens}  ({outcome})", model.as_deref().unwrap_or("?"));
        }
    }
}
