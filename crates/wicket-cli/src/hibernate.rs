//! Hibernate and wake (#70, design §13.2): long-lived agents that sleep and come back.
//!
//! - **Idle.** After a turn, a long-lived agent's box is paused (`docker pause`): every process is
//!   kept, memory stays held, a follow-up unpauses it in ~0.1 s.
//! - **Hibernated.** At a quiet point (the turn has ended and nothing but the agent runtime runs in
//!   the box) the agent's stdin is closed, the box exits, and its whole writable state is bundled
//!   into the object store: the workspace, all of `/wicket/state` (HOME and the Claude Code config),
//!   `/tmp`, and the zone's `durable` volumes. Nothing of it is left on the node except an in-place
//!   workspace (the operator's own directory). A box that isn't quiet (a background build, a dev
//!   server) stays Idle: a rebuild restores files, not processes.
//! - **Wake** rebuilds the box: a new run (activation) with a new identity, sockets, CA and
//!   placeholders, the bundle restored and verified, and Claude Code resumed with `--resume` on the
//!   agent's own session, at the same workspace path (Claude Code keys sessions by directory). Its
//!   first turn says it was woken, by what, and carries the operator's message if there is one.
//!   Sources: `wicket wake`, `wicket say`, a message from another agent.
//! - **Fencing.** Waking is a compare-and-set claim in the ledger that bumps the agent's generation;
//!   the proxies refuse a stale generation and a push commits only under the current one
//!   (`wicket_store::agents`).

use crate::{data_dir, ledger_path};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use wicket_core::{Manifest, Persist, RunId, TenantId};
use wicket_store::bundle::{self, StateManifest, TreeSrc};
use wicket_store::objects::DirStore;
use wicket_store::{AgentRow, Ledger};

/// How long a holder's claim on an agent lasts without renewal (seconds). The supervisor renews it
/// every few seconds; a waker may take over an agent whose holder let it lapse.
pub const LEASE_SECS: i64 = 30;

/// The object store agent state goes to: a directory under wicket's data dir (S3-compatible
/// backends later).
pub fn store() -> DirStore {
    DirStore::new(data_dir().join("objects"))
}

/// Per-agent files on this node: durable volumes, wake logs.
pub fn agent_dir(agent: &str) -> PathBuf {
    data_dir().join("agents").join(agent)
}

/// Where a durable volume of an agent lives while the agent is awake.
pub fn durable_volume(agent: &str, name: &str) -> PathBuf {
    agent_dir(agent).join("volumes").join(name)
}

/// Top-level names left out of a workspace tree: the outbox is the run's own result, not state.
const WORKSPACE_EXCLUDE: &[&str] = &["out"];

/// The trees of an activation: (bundle name, host path, excluded top-level names).
pub fn trees(m: &Manifest, agent: &str, run_dir: &Path, in_place: Option<&Path>) -> Vec<(String, PathBuf, &'static [&'static str])> {
    let mut t: Vec<(String, PathBuf, &'static [&'static str])> = vec![
        ("workspace".into(), in_place.map(Path::to_path_buf).unwrap_or_else(|| run_dir.join("workspace")), WORKSPACE_EXCLUDE),
        ("state".into(), run_dir.join("state"), &[]),
        ("tmp".into(), run_dir.join("tmp"), &[]),
    ];
    for v in m.zone.volumes.iter().filter(|v| v.persist == Persist::Durable) {
        t.push((format!("volume.{}", v.name), durable_volume(agent, &v.name), &[]));
    }
    t
}

/// Whether a box is at a quiet point: nothing runs in it but the agent runtime (the init, wicket's
/// forwarder, Claude Code). Err: what else runs.
pub fn quiet(procs: &[(u32, u32, String)]) -> std::result::Result<(), Vec<String>> {
    let runtime = |cmd: &str| {
        let argv0 = cmd.split_whitespace().next().unwrap_or("");
        let base = argv0.rsplit('/').next().unwrap_or("");
        matches!(base, "docker-init" | "tini" | "wicket-fwd" | "claude") || (base == "node" && cmd.contains("claude"))
    };
    let others: Vec<String> =
        procs.iter().filter(|(pid, _, cmd)| *pid != 1 && !cmd.is_empty() && !runtime(cmd)).map(|(pid, _, cmd)| format!("{pid}: {}", wicket_agent::clip(cmd, 80))).collect();
    if others.is_empty() {
        Ok(())
    } else {
        Err(others)
    }
}

/// Checks a running box for a quiet point (see [`quiet`]).
pub async fn check_quiet(docker: &wicket_sandbox::Docker, name: &str, user: &str) -> std::result::Result<(), String> {
    let procs = docker.processes(name, user).await.map_err(|e| format!("{e:#}"))?;
    quiet(&procs).map_err(|others| format!("other processes run in the box: {}", others.join("; ")))
}

/// Pushes an activation's trees as the agent's next bundle and commits it in the ledger. Returns the
/// manifest, or None if this activation was superseded (its push is refused; the objects it wrote
/// are orphans for GC).
pub fn push(ledger: &std::sync::Mutex<Ledger>, agent: &AgentRow, generation: i64, trees: &[(String, PathBuf, &[&str])]) -> Result<Option<StateManifest>> {
    let store = store();
    let prev = match &agent.head {
        Some(k) => Some(bundle::read_manifest(&store, k, &agent.id)?),
        None => None,
    };
    for (_, p, _) in trees {
        std::fs::create_dir_all(p)?;
    }
    let src: Vec<TreeSrc> = trees.iter().map(|(n, p, x)| TreeSrc { name: n.clone(), path: p.clone(), exclude: x }).collect();
    let seq = agent.head_seq + 1;
    let scratch = data_dir().join("objects-scratch");
    let (m, key) = bundle::push(&store, &agent.id, generation, seq, &agent.session_id, &src, prev.as_ref(), &scratch)
        .with_context(|| format!("pushing agent {}'s state", agent.id))?;
    let l = ledger.lock().expect("ledger");
    if !l.commit_agent_push(&agent.id, generation, agent.head_seq, seq, &key, m.stored_bytes() as i64)? {
        return Ok(None);
    }
    Ok(Some(m))
}

/// Restores a tree into `dest`, replacing whatever is there.
pub fn restore(m: &StateManifest, name: &str, dest: &Path) -> Result<()> {
    let Some(t) = m.tree(name) else { return Ok(()) };
    if dest.exists() {
        bundle::make_writable(dest)?;
        std::fs::remove_dir_all(dest)?;
    }
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p)?;
    }
    bundle::pull_tree(&store(), t, dest).with_context(|| format!("restoring {name}"))?;
    Ok(())
}

/// Removes a tree that is now in the bundle (the node is released).
pub fn drop_tree(p: &Path) {
    if p.exists() {
        let _ = bundle::make_writable(p);
        let _ = std::fs::remove_dir_all(p);
    }
}

/// Wakes an agent in the background: a detached `wicket wake`, logging to the agent's dir. Several
/// triggers at once are harmless: the ledger's claim lets exactly one of them wake it.
pub fn trigger_wake(agent: &str, by: &str) {
    if !wicket_store::valid_agent_id(agent) {
        return;
    }
    let dir = agent_dir(agent);
    let _ = std::fs::create_dir_all(&dir);
    let log = match std::fs::OpenOptions::new().create(true).append(true).open(dir.join("wake.log")) {
        Ok(f) => f,
        Err(e) => return eprintln!("[wicket] can't wake {agent}: {e}"),
    };
    let Ok(exe) = std::env::current_exe() else { return };
    let mut c = std::process::Command::new(exe);
    c.args(["wake", agent, "--by", by]).stdin(std::process::Stdio::null());
    if let Ok(l2) = log.try_clone() {
        c.stdout(l2);
    }
    c.stderr(log);
    use std::os::unix::process::CommandExt;
    // SAFETY: setsid in the child before exec; no allocation.
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    match c.spawn() {
        Ok(_) => {}
        Err(e) => eprintln!("[wicket] can't wake {agent}: {e}"),
    }
}

/// An agent named by its id or by any of its runs.
pub fn resolve(l: &Ledger, who: &str) -> Result<AgentRow> {
    if wicket_store::valid_agent_id(who) {
        return l.agent(who)?.with_context(|| format!("no agent {who}"));
    }
    match l.agent_of_run(who)? {
        Some((id, _)) => Ok(l.agent(&id)?.with_context(|| format!("no agent {id}"))?),
        None => bail!("{who} is not an agent or a run of one"),
    }
}

/// A claimed wake, handed to `wicket run`'s supervisor.
pub struct Wake {
    pub agent: AgentRow,
    pub generation: i64,
    pub state: StateManifest,
    /// The first user turn after `--resume`.
    pub first: String,
}

/// What a woken agent is told first.
fn wake_text(by: &str, said: &[(String, String)], messages: i64) -> String {
    let mut t = format!(
        "[wicket] You were hibernated and have just been woken ({by}). Your files are as you left them: the workspace, \
         $HOME and /tmp. Processes that were running before you slept are gone; restart any you need."
    );
    if messages > 0 {
        t.push_str(&format!(" {messages} message(s) from other agents are waiting: read them with wicket's await_message tool."));
    }
    for (text, who) in said {
        t.push_str(&format!("\n\nMessage from the operator ({who}):\n{text}"));
    }
    t
}

/// `wicket wake <agent>`: claims the agent and runs its next activation in the foreground.
pub async fn wake(who: &str, text: Option<String>, by: Option<String>) -> Result<()> {
    let (agent, generation, run, first) = {
        let mut l = Ledger::open(&ledger_path())?;
        let a = resolve(&l, who)?;
        for (r, _) in l.agent_runs(&a.id)? {
            if let Some((rv, _, rby, why)) = l.revoked_in_chain(&r)? {
                l.agent_not_restorable(&a.id, &format!("revoked ({rv} by {rby}: {why})"))?;
                bail!("agent {} can't be woken: {rv}'s identity was revoked by {rby} ({why})", a.id);
            }
        }
        if !a.restorable {
            bail!("agent {} can't be woken: {}", a.id, a.note.as_deref().unwrap_or("it is not restorable"));
        }
        if a.head.is_none() {
            bail!("agent {} has never hibernated (it is {}); there is nothing to wake", a.id, a.state);
        }
        let run = RunId::new();
        let Some(generation) = l.claim_wake(&a.id, &run.0, wicket_store::now() + LEASE_SECS)? else {
            let a = l.agent(&a.id)?.unwrap_or(a);
            println!("[wicket] agent {} not woken: it is {} (generation {}, run {})", a.id, a.state, a.generation, a.run);
            std::process::exit(2);
        };
        let by = by.unwrap_or_else(|| format!("wicket wake by {}", crate::cli_principal()["id"].as_str().unwrap_or("operator")));
        if let Some(t) = &text {
            l.add_operator_message(&run.0, t, &by)?;
        }
        let said = l.take_operator_messages(&run.0)?;
        let first = wake_text(&by, &said, l.waiting_messages(&run.0)?);
        l.audit(
            &TenantId(a.tenant.clone()),
            Some(&run),
            "agent.wake",
            &serde_json::json!({ "agent": a.id, "generation": generation, "by": by, "from_run": a.run, "head": a.head, "operator_messages": said.len() }),
        )?;
        (l.agent(&a.id)?.expect("claimed"), generation, run, first)
    };
    println!("[wicket] waking agent {} ({}): generation {generation}, run {run}", agent.id, agent.name);
    let res = async {
        let t0 = std::time::Instant::now();
        let state = bundle::read_manifest(&store(), agent.head.as_deref().expect("checked"), &agent.id)?;
        if state.session_id != agent.session_id {
            bail!("the bundle's session {} isn't the agent's {}", state.session_id, agent.session_id);
        }
        println!("[wicket] state: bundle {} ({} trees, {} stored, {} raw), read in {} ms", agent.head.as_deref().unwrap_or(""), state.trees.len(), human(state.stored_bytes()), human(state.raw_bytes()), t0.elapsed().as_millis());
        Ok(state)
    }
    .await;
    let state = match res {
        Ok(s) => s,
        Err(e) => {
            let l = Ledger::open(&ledger_path())?;
            l.release_failed_wake(&agent.id, generation, &format!("wake failed: {e:#}"))?;
            return Err(e);
        }
    };
    let image = agent.image.clone();
    let opts = crate::run::RunOpts {
        manifest: Path::new("(the agent's manifest)"),
        workdir: None,
        workspace_dir: None,
        task: None,
        image: &image,
        node: None,
        ssh_key: None,
        run_id: Some(run.0.clone()),
        parent_run: None,
        lease: None,
        wrap: None,
        wake: Some(Wake { agent: agent.clone(), generation, state, first }),
    };
    if let Err(e) = crate::run::run(opts).await {
        let l = Ledger::open(&ledger_path())?;
        // Only if the run didn't get as far as its box: then the head is untouched and it can be retried.
        if l.agent(&agent.id)?.is_some_and(|a| a.generation == generation && a.state == "waking") {
            l.release_failed_wake(&agent.id, generation, &format!("wake failed: {e:#}"))?;
        }
        return Err(e);
    }
    Ok(())
}

/// `wicket hibernate <run|agent>`: asks the agent's supervisor to hibernate it at the next quiet
/// point, and reports what happened.
pub async fn hibernate(who: &str, wait_secs: u64) -> Result<()> {
    let l = Ledger::open(&ledger_path())?;
    let a = resolve(&l, who)?;
    if a.state == "hibernated" {
        println!("agent {} is already hibernated ({})", a.id, human(a.bundle_bytes as u64));
        return Ok(());
    }
    let before = a.updated_at;
    if !l.want_agent(&a.id, "hibernate")? {
        bail!("agent {} is {}: only an active or idle agent can be hibernated", a.id, a.state);
    }
    println!("asked agent {} ({}) to hibernate at its next quiet point", a.id, a.run);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let Some(now) = l.agent(&a.id)? else { bail!("agent {} is gone", a.id) };
        match now.state.as_str() {
            "hibernated" => {
                println!("agent {} hibernated: {} stored (generation {}, bundle {})", a.id, human(now.bundle_bytes as u64), now.generation, now.head.unwrap_or_default());
                return Ok(());
            }
            "idle" if now.want.is_none() && now.updated_at >= before && now.note.as_deref().is_some_and(|n| n.starts_with("not hibernated")) => {
                println!("agent {} stays idle (paused): {}", a.id, now.note.unwrap_or_default());
                return Ok(());
            }
            "ended" | "failed" => bail!("agent {} {}: {}", a.id, now.state, now.note.unwrap_or_default()),
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            println!("agent {} is {} (the request stands: it hibernates when its turn ends)", a.id, now.state);
            return Ok(());
        }
    }
}

/// `wicket agents`.
pub fn list(json: bool) -> Result<()> {
    let l = Ledger::open(&ledger_path())?;
    let rows = l.agents(&TenantId::single().0)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&rows.iter().map(|a| serde_json::json!({
            "id": a.id, "name": a.name, "zone": a.zone, "state": a.state, "generation": a.generation, "run": a.run,
            "session_id": a.session_id, "bundle_bytes": a.bundle_bytes, "head": a.head, "restorable": a.restorable, "note": a.note,
            "workspace": a.workspace, "updated_at": a.updated_at,
        })).collect::<Vec<_>>())?);
        return Ok(());
    }
    if rows.is_empty() {
        println!("no agents");
        return Ok(());
    }
    println!("{:<30}  {:<16}  {:<11}  {:>3}  {:<30}  {:>9}  note", "agent", "name", "state", "gen", "run", "bundle");
    for a in rows {
        println!(
            "{:<30}  {:<16}  {:<11}  {:>3}  {:<30}  {:>9}  {}",
            a.id,
            wicket_agent::clip(&a.name, 16),
            a.state,
            a.generation,
            a.run,
            if a.head.is_some() { human(a.bundle_bytes as u64) } else { "-".into() },
            wicket_agent::clip(a.note.as_deref().unwrap_or(""), 80)
        );
    }
    Ok(())
}

pub fn human(b: u64) -> String {
    match b {
        b if b >= 10 << 20 => format!("{} MiB", b >> 20),
        b if b >= 10 << 10 => format!("{} KiB", b >> 10),
        b => format!("{b} B"),
    }
}

/// Whether `dir` holds more than `cap` bytes (stops counting once over). Symlinks aren't followed.
pub fn over(dir: &Path, cap: u64) -> bool {
    fn walk(d: &Path, total: &mut u64, cap: u64) -> bool {
        let Ok(rd) = std::fs::read_dir(d) else { return false };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                if walk(&e.path(), total, cap) {
                    return true;
                }
            } else {
                use std::os::unix::fs::MetadataExt;
                *total += m.blocks() * 512;
                if *total > cap {
                    return true;
                }
            }
        }
        false
    }
    let mut total = 0;
    walk(dir, &mut total, cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_agent_runtime_is_quiet() {
        let idle = vec![
            (1, 0, "/sbin/docker-init -- wicket-entry claude -p".to_string()),
            (5, 1, "wicket-fwd --listen 198.18.0.1:3128=/wicket/sock/egress.sock".to_string()),
            (9, 1, "claude -p --input-format stream-json".to_string()),
            (12, 9, String::new()),
        ];
        assert_eq!(quiet(&idle), Ok(()));
        let mut busy = idle.clone();
        busy.push((40, 1, "sleep 600".into()));
        busy.push((41, 9, "/usr/bin/node /workspace/server.js".into()));
        let e = quiet(&busy).unwrap_err();
        assert_eq!(e.len(), 2, "{e:?}");
        assert!(e[0].contains("sleep 600"));
    }

    #[test]
    fn the_wake_turn_says_what_woke_the_agent() {
        let t = wake_text("wicket say by op", &[("carry on".into(), "op".into())], 2);
        assert!(t.contains("woken (wicket say by op)") && t.contains("carry on") && t.contains("2 message(s)"));
        assert!(!wake_text("x", &[], 0).contains("message(s)"));
    }

    #[test]
    fn a_tree_over_its_cap_is_noticed() {
        let d = std::env::temp_dir().join(format!("wicket-cap-{}", std::process::id()));
        std::fs::create_dir_all(d.join("a")).unwrap();
        std::fs::write(d.join("a/f"), vec![7u8; 64 * 1024]).unwrap();
        assert!(!over(&d, 1 << 20));
        assert!(over(&d, 16 * 1024));
        let _ = std::fs::remove_dir_all(&d);
    }
}
