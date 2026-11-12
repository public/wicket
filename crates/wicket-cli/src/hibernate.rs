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

/// The claim held across the steps no heartbeat covers (a waker restoring and starting the box, a
/// supervisor pushing the state): long enough for a big bundle, after which a crashed holder's agent
/// can be woken again.
pub const BUSY_LEASE_SECS: i64 = 900;

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
    // The init, wicket's entrypoint (a shell running wicket-entry, which stays as the parent of the
    // forwarder), the forwarder and Claude Code.
    let runtime = |cmd: &str| {
        let mut words = cmd.split_whitespace().map(|w| w.rsplit('/').next().unwrap_or(""));
        let base = words.next().unwrap_or("");
        let second = words.next().unwrap_or("");
        matches!(base, "docker-init" | "tini" | "wicket-fwd" | "claude" | "wicket-entry")
            || (matches!(base, "bash" | "sh") && second == "wicket-entry")
            || (base == "node" && cmd.contains("claude"))
    };
    let others: Vec<String> = procs
        .iter()
        .filter(|(pid, _, cmd)| *pid != 1 && !cmd.is_empty() && !runtime(cmd))
        .map(|(pid, _, cmd)| format!("{pid}: {}", wicket_agent::clip(cmd, 80)))
        .collect();
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
pub fn push(
    ledger: &std::sync::Mutex<Ledger>,
    agent: &AgentRow,
    generation: i64,
    trees: &[(String, PathBuf, &[&str])],
) -> Result<Option<StateManifest>> {
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
    let to = bundle::PushTo { agent: &agent.id, generation, seq, session_id: &agent.session_id };
    let (m, key) =
        bundle::push(&store, &to, &src, prev.as_ref(), &scratch).with_context(|| format!("pushing agent {}'s state", agent.id))?;
    let l = ledger.lock().expect("ledger");
    if !l.commit_agent_push(&agent.id, generation, agent.head_seq, seq, &key, m.stored_bytes() as i64)? {
        return Ok(None);
    }
    Ok(Some(m))
}

/// Moves the agent's durable volumes into the run's directory before they are packed, so that once the
/// push commits (and the agent can be woken again) nothing this activation removes is shared with the
/// next one. Returns the moves, to undo if the push fails.
pub fn stage_volumes(trees: &mut [(String, PathBuf, &[&str])], run_dir: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut moved = Vec::new();
    for (name, p, _) in trees.iter_mut().filter(|(n, _, _)| n.starts_with("volume.")) {
        let staged = run_dir.join("hib-volumes").join(name.as_str());
        std::fs::create_dir_all(staged.parent().expect("a parent"))?;
        if p.exists() {
            std::fs::rename(&*p, &staged)?;
        } else {
            std::fs::create_dir_all(&staged)?;
        }
        moved.push((p.clone(), staged.clone()));
        *p = staged;
    }
    Ok(moved)
}

/// Puts staged volumes back (the push failed), unless something else is there now.
pub fn unstage_volumes(moved: &[(PathBuf, PathBuf)]) {
    for (home, staged) in moved {
        if !home.exists() {
            let _ = std::fs::rename(staged, home);
        }
    }
}

/// Makes sure each of `dirs` is a real directory, not a symlink or a file: they come from a bundle the
/// agent wrote, and wicket mounts them and writes into them on the host.
pub fn real_dirs(dirs: &[PathBuf]) -> Result<()> {
    for d in dirs {
        match std::fs::symlink_metadata(d) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                std::fs::remove_file(d)?;
                std::fs::create_dir_all(d)?;
            }
            Err(_) => std::fs::create_dir_all(d)?,
        }
    }
    Ok(())
}

/// Writes a file wicket owns into an agent-written tree: whatever is at `p` (a symlink, say) is
/// removed first, and the file is created new, never followed.
pub fn write_new(p: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            bundle::make_writable(p)?;
            std::fs::remove_dir_all(p)?;
        }
        Ok(_) => std::fs::remove_file(p)?,
        Err(_) => {}
    }
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(p)?;
    f.write_all(body)?;
    Ok(())
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

/// Removes everything in a tree but the named top-level entries.
pub fn drop_tree_except(p: &Path, keep: &[&str]) {
    let Ok(rd) = std::fs::read_dir(p) else { return };
    for e in rd.flatten() {
        if keep.iter().any(|k| e.file_name() == *k) {
            continue;
        }
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            drop_tree(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
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

/// Why an agent may not be woken again because its zone's budget is spent, over all its
/// activations: model requests, output or input tokens, or `limits.timeout` (its total time in a
/// box). A wake never resets a budget.
pub fn exhausted(a: &AgentRow) -> Option<String> {
    let m = match Manifest::from_yaml(&a.manifest) {
        Ok(m) => m,
        Err(e) => return Some(format!("its manifest no longer parses: {e}")),
    };
    if let Some(l) = &m.zone.llm {
        if a.used_requests as u64 >= l.max_requests {
            return Some(format!("its model request budget is spent ({} of {})", a.used_requests, l.max_requests));
        }
        if a.used_output_tokens as u64 >= l.max_output_tokens {
            return Some(format!("its output token budget is spent ({} of {})", a.used_output_tokens, l.max_output_tokens));
        }
        if let Some(max) = l.max_input_tokens.filter(|max| a.used_input_tokens as u64 >= *max) {
            return Some(format!("its input token budget is spent ({} of {max})", a.used_input_tokens));
        }
    }
    match m.zone.limits.timeout() {
        Ok(t) if a.used_secs as u64 >= t.as_secs() => {
            Some(format!("its time budget (limits.timeout, {}) is spent over its activations", humantime::format_duration(t)))
        }
        Ok(_) => None,
        Err(e) => Some(format!("its limits.timeout doesn't parse: {e}")),
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
        if let Some(why) = exhausted(&a) {
            let note = format!("not woken: {why}");
            l.set_agent_state(&a.id, a.generation, &a.state, Some(&note))?;
            l.audit(&TenantId(a.tenant.clone()), None, "agent.wake_refused", &serde_json::json!({ "agent": a.id, "by": by, "why": why }))?;
            bail!("agent {} can't be woken: {why}", a.id);
        }
        let run = RunId::new();
        let Some(generation) = l.claim_wake(&a.id, &run.0, wicket_store::now() + BUSY_LEASE_SECS)? else {
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
        println!(
            "[wicket] state: bundle {} ({} trees, {} stored, {} raw), read in {} ms",
            agent.head.as_deref().unwrap_or(""),
            state.trees.len(),
            human(state.stored_bytes()),
            human(state.raw_bytes()),
            t0.elapsed().as_millis()
        );
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
                println!(
                    "agent {} hibernated: {} stored (generation {}, bundle {})",
                    a.id,
                    human(now.bundle_bytes as u64),
                    now.generation,
                    now.head.unwrap_or_default()
                );
                return Ok(());
            }
            "idle"
                if now.want.is_none()
                    && now.updated_at >= before
                    && now.note.as_deref().is_some_and(|n| n.starts_with("not hibernated")) =>
            {
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
            "used": { "requests": a.used_requests, "input_tokens": a.used_input_tokens, "output_tokens": a.used_output_tokens, "secs": a.used_secs },
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
            (5, 1, "/bin/bash /usr/local/bin/wicket-entry claude -p".to_string()),
            (6, 5, "wicket-fwd --listen 198.18.0.1:3128=/wicket/sock/egress.sock".to_string()),
            (9, 1, "claude -p --input-format stream-json".to_string()),
            (12, 9, String::new()),
        ];
        assert_eq!(quiet(&idle), Ok(()));
        let mut busy = idle.clone();
        busy.push((40, 1, "sleep 600".into()));
        busy.push((41, 9, "/usr/bin/node /workspace/server.js".into()));
        busy.push((42, 9, "bash -c sleep 1000".into()));
        let e = quiet(&busy).unwrap_err();
        assert_eq!(e.len(), 3, "{e:?}");
        assert!(e[0].contains("sleep 600"));
    }

    #[test]
    fn a_spent_budget_is_never_reset_by_a_wake() {
        let manifest =
            "task: t\nagent: {name: a}\nzone: {name: z, llm: {max_requests: 4, max_output_tokens: 100}, limits: {timeout: 1m}}\n";
        let a = AgentRow {
            id: "agt_x".into(),
            tenant: "t0".into(),
            zone: "z".into(),
            name: "a".into(),
            state: "hibernated".into(),
            generation: 2,
            run: "run_x".into(),
            session_id: "s".into(),
            manifest: manifest.into(),
            image: "i".into(),
            workspace: None,
            head: Some("h".into()),
            head_seq: 1,
            bundle_bytes: 1,
            lease_until: None,
            restorable: true,
            want: None,
            note: None,
            created_at: 0,
            updated_at: 0,
            used_requests: 3,
            used_input_tokens: 0,
            used_output_tokens: 10,
            used_secs: 20,
        };
        assert_eq!(exhausted(&a), None);
        assert!(exhausted(&AgentRow { used_requests: 4, ..a.clone() }).unwrap().contains("request budget"));
        assert!(exhausted(&AgentRow { used_output_tokens: 100, ..a.clone() }).unwrap().contains("output token"));
        assert!(exhausted(&AgentRow { used_secs: 60, ..a.clone() }).unwrap().contains("limits.timeout"));
    }

    #[test]
    fn the_wake_turn_says_what_woke_the_agent() {
        let t = wake_text("wicket say by op", &[("carry on".into(), "op".into())], 2);
        assert!(t.contains("woken (wicket say by op)") && t.contains("carry on") && t.contains("2 message(s)"));
        assert!(!wake_text("x", &[], 0).contains("message(s)"));
    }

    #[test]
    fn wicket_never_writes_through_an_agent_s_symlink() {
        let d = std::env::temp_dir().join(format!("wicket-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("host")).unwrap();
        std::fs::create_dir_all(d.join("state")).unwrap();
        std::os::unix::fs::symlink(d.join("host"), d.join("state/claude")).unwrap();
        real_dirs(&[d.join("state"), d.join("state/claude"), d.join("state/home")]).unwrap();
        assert!(std::fs::symlink_metadata(d.join("state/claude")).unwrap().is_dir());
        std::os::unix::fs::symlink(d.join("host/settings.json"), d.join("state/claude/settings.json")).unwrap();
        write_new(&d.join("state/claude/settings.json"), b"{}").unwrap();
        assert!(!d.join("host/settings.json").exists(), "the host file was not written");
        assert_eq!(std::fs::read(d.join("state/claude/settings.json")).unwrap(), b"{}");
        let _ = std::fs::remove_dir_all(&d);
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
