//! Hibernate and wake (#70, design §13.2): long-lived agents that sleep and come back.
//!
//! - **Idle.** After a turn, a long-lived agent's box is paused (`docker pause`): every process is
//!   kept, memory stays held, a follow-up unpauses it in ~0.1 s.
//! - **Hibernated.** At a quiet point (the turn has ended and nothing but the agent runtime runs in
//!   the box) the agent's stdin is closed, the box exits, and its whole writable state is bundled
//!   into the object store: the workspace, all of `/wicket/state` (HOME and the Claude Code config),
//!   `/tmp`, and the zone's `durable` volumes. Nothing of it is left on the node except an in-place
//!   workspace (the operator's own directory). In a box that isn't quiet (a background build, a dev
//!   server), what else runs gets the zone's `limits.exit_grace` to end, then is stopped (#293): a
//!   rebuild restores files, not processes.
//! - **Wake** rebuilds the box: a new run (activation) with a new identity, sockets, CA and
//!   placeholders, the bundle restored and verified, and Claude Code resumed with `--resume` on the
//!   agent's own session, at the same workspace path (Claude Code keys sessions by directory). Its
//!   first turn says it was woken, by what, and carries the operator's message if there is one.
//!   Sources: opening its session (`wicket session`, or a prompt in the console), and a message
//!   from another agent; each starts the internal `wicket wake` ([`trigger_wake`]).
//! - **Incremental** (#365). State goes into the content-addressed store as a bundle tree
//!   (`wicket_store::bundle`, version 2): the control host's local store (`<data dir>/store`)
//!   writes only files that changed since an earlier hibernation, and with `bundles: s3` the state
//!   store is sent only what it lacks, before the ledger's head moves. A wake fetches what the local
//!   store lacks. A ledger whose head is still a version-1 bundle (from before #365) is refused at
//!   start ([`refuse_v1_heads`], #470); an agent whose files have names the tree format can't hold
//!   (not UTF-8) isn't hibernated, and the error names the file.
//! - **Fencing.** Waking is a compare-and-set claim in the ledger that bumps the agent's generation;
//!   the proxies refuse a stale generation and a push commits only under the current one
//!   (`wicket_store::agents`).

use crate::{data_dir, ledger_path};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use wicket_core::{Manifest, Persist, RunId, TenantId};
pub use wicket_node::boxfiles::{read_outbox, real_dirs, write_owned};
#[cfg(test)]
use wicket_node::boxfiles::{used_bytes, write_new};
use wicket_store::bundle::{self, StateManifest, TreeSrc};
use wicket_store::objects::DirStore;
use wicket_store::sealed::SealedStore;
use wicket_store::{AgentRow, Ledger};

/// How long a holder's claim on an agent lasts without renewal (seconds). The supervisor renews it
/// every few seconds; a waker may take over an agent whose holder let it lapse.
pub const CLAIM_SECS: i64 = 30;

/// The claim held across the steps no heartbeat covers (a waker restoring and starting the box, a
/// supervisor pushing the state): long enough for a big bundle, after which a crashed holder's agent
/// can be woken again.
pub const BUSY_CLAIM_SECS: i64 = 900;

/// The control host's local content-addressed store (#258, #365), sealed under `state.key` with no
/// plain reads, and the count of what its backend writes.
pub fn local_store() -> Result<(wicket_store::cas::Cas, std::sync::Arc<std::sync::atomic::AtomicU64>)> {
    let (dir, written) = wicket_store::objects::Counting::new(DirStore::new(data_dir().join("store")));
    Ok((wicket_store::cas::Cas::new(SealedStore::new(dir, &state_key()?)), written))
}

/// The shared content-addressed store bundles must reach before a head moves: the state store's, if
/// `state-store.yaml` puts bundles there (#154), sealed with no plain reads. None: the local store is
/// the bundles' home.
pub fn shared_store() -> Result<Option<wicket_store::cas::Cas>> {
    Ok(match crate::statestore::StateStore::load()? {
        Some(s) if s.bundles == crate::statestore::Where::S3 => {
            Some(wicket_store::cas::Cas::new(SealedStore::new(s.open_s3()?, &state_key()?)))
        }
        _ => None,
    })
}

/// Reads an agent's head (either version) from the stores it can be in.
pub fn read_head(head: &str, agent: &str) -> Result<StateManifest> {
    let (local, _) = local_store()?;
    let shared = shared_store()?;
    let stores = bundle::Stores { local: &local, shared: shared.as_ref(), written: None };
    Ok(bundle::read_head(stores, head, agent)?)
}

/// The key agent state is sealed with at rest (`<data dir>/state.key`, 0600, made on first use): it
/// stays on the control host, which bundles and restores agents; nodes never see it.
pub fn state_key() -> Result<[u8; 32]> {
    use std::os::unix::fs::OpenOptionsExt;
    let p = data_dir().join("state.key");
    let read = |p: &Path| std::fs::read_to_string(p).ok().and_then(|s| hex::decode(s.trim()).ok()).and_then(|b| b.try_into().ok());
    if let Some(k) = read(&p) {
        return Ok(k);
    }
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    std::fs::create_dir_all(data_dir())?;
    // Made once: a run racing this one keeps whichever key was written first.
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p) {
        let _ = std::io::Write::write_all(&mut f, hex::encode(k).as_bytes());
        let _ = f.sync_all();
    }
    read(&p).with_context(|| format!("{} could not be read or written", p.display()))
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
/// forwarder, what its harness adapter says is the harness's own (`harness`), or the agent's own
/// command, `agent`: an ACP agent's, #66). Err: what else runs. (The supervisor asks for
/// [`leftovers`], to stop them.)
#[cfg(test)]
pub fn quiet(procs: &[(u32, u32, String)], harness: &dyn Fn(&str) -> bool, agent: &[String]) -> std::result::Result<(), Vec<String>> {
    let others = leftovers(procs, harness, agent);
    if others.is_empty() {
        Ok(())
    } else {
        Err(others.iter().map(|(_, c)| c.clone()).collect())
    }
}

/// What runs in a box besides the agent runtime (see [`quiet`]): each process's pid, and its pid
/// and command line as wicket names it (`pid: command`, clipped).
pub fn leftovers(procs: &[(u32, u32, String)], harness: &dyn Fn(&str) -> bool, agent: &[String]) -> Vec<(u32, String)> {
    let base = |w: &str| w.rsplit('/').next().unwrap_or("").to_string();
    let agent0 = agent.first().map(|a| base(a)).unwrap_or_default();
    let agent_line = std::iter::once(agent0.clone()).chain(agent.iter().skip(1).cloned()).collect::<Vec<_>>().join(" ");
    // The init, wicket's entrypoint (a shell running wicket-entry, which stays as the parent of the
    // forwarder), the forwarder and the harness.
    let runtime = |cmd: &str| {
        let mut words = cmd.split_whitespace().map(|w| w.rsplit('/').next().unwrap_or(""));
        let base = words.next().unwrap_or("");
        let second = words.next().unwrap_or("");
        let line = std::iter::once(base).chain(cmd.split_whitespace().skip(1)).collect::<Vec<_>>().join(" ");
        wicket_runtime(base, second)
            || harness(cmd)
            // The agent's own command, as started (a script's interpreter runs it with its path).
            || (!agent0.is_empty() && (line == agent_line || (matches!(base, "node" | "python3" | "python" | "sh" | "bash") && second == agent0)))
    };
    procs
        .iter()
        .filter(|(pid, _, cmd)| *pid != 1 && !cmd.is_empty() && !runtime(cmd))
        .map(|(pid, _, cmd)| (*pid, format!("{pid}: {}", wicket_agent::clip(cmd, 80))))
        .collect()
}

/// Whether a command (its program's base name, and its first argument's) is wicket's own part of a
/// box: the init, the entrypoint and the forwarder.
fn wicket_runtime(base: &str, second: &str) -> bool {
    matches!(base, "docker-init" | "tini" | "wicket-fwd" | "wicket-entry") || (matches!(base, "bash" | "sh") && second == "wicket-entry")
}

/// What still runs in a box once its harness's session is over (#293): everything but wicket's own
/// parts (the init, the entrypoint, the forwarder), the harness included. `pid: command` each.
pub fn left_running(procs: &[(u32, u32, String)]) -> Vec<String> {
    leftovers(procs, &|_| false, &[]).into_iter().map(|(_, c)| c).collect()
}

/// Pushes an activation's trees as the agent's next bundle and commits it in the ledger. Returns the
/// manifest, or None if this activation was superseded (its push is refused; the objects it wrote
/// are left for the store's collection, `crate::storegc`).
pub fn push(
    ledger: &std::sync::Mutex<Ledger>,
    agent: &AgentRow,
    generation: i64,
    trees: &[(String, PathBuf, &[&str])],
) -> Result<Option<StateManifest>> {
    for (_, p, _) in trees {
        std::fs::create_dir_all(p)?;
    }
    let src: Vec<TreeSrc> = trees.iter().map(|(n, p, x)| TreeSrc { name: n.clone(), path: p.clone(), exclude: x }).collect();
    let seq = agent.head_seq + 1;
    let to = bundle::PushTo { agent: &agent.id, generation, seq, session_id: &agent.session_id };
    let (local, written) = local_store()?;
    let shared = shared_store()?;
    // Held until the head is committed: no collection deletes what this push writes or reuses (#258).
    let by = format!("the push of agent {}", agent.id);
    let _held = (local.writing(&by)?, shared.as_ref().map(|s| s.writing(&by)).transpose()?);
    let stores = bundle::Stores { local: &local, shared: shared.as_ref(), written: Some(&written) };
    // The ledger's bundle size is what it restores to (its objects are shared with other bundles).
    // A tree with a name that isn't UTF-8 isn't hibernated (#258: no format rule for such names, and
    // nothing renamed silently): the error names the file, and the agent stays as it is.
    let (m, key) = match bundle::push_tree(stores, &to, &src) {
        Ok(pushed) => pushed,
        Err(e) if bundle::unrepresentable(&e) => {
            anyhow::bail!("agent {}'s state can't be hibernated: {e} (rename the file to hibernate it)", agent.id)
        }
        Err(e) => return Err(anyhow::Error::from(e).context(format!("pushing agent {}'s state", agent.id))),
    };
    let bytes = m.raw_bytes();
    let l = ledger.lock().expect("ledger");
    if !l.commit_agent_push(&agent.id, generation, agent.head_seq, seq, &key, bytes as i64)? {
        return Ok(None);
    }
    Ok(Some(m))
}

/// #258: the agents whose head is still a version-1 bundle (a manifest key, not a digest), which
/// this build can't read. Builds before it converted them as the reconciler started.
pub fn v1_heads(l: &Ledger) -> Result<Vec<String>> {
    Ok(l.agent_heads()?.into_iter().filter(|(_, h, _)| !bundle::is_tree_head(h)).map(|(a, _, _)| a).collect())
}

/// Refuses to start the control host while any agent's head is a version-1 bundle (#258), naming
/// them: the build before this one converts them when its reconciler starts.
pub fn refuse_v1_heads(l: &Ledger) -> Result<()> {
    let left = v1_heads(l)?;
    if !left.is_empty() {
        bail!(
            "agent(s) {} still have a version-1 hibernation bundle, which this build can't read: run the previous \
             build's reconciler once (`wicket reconcile`), which converts them, then this one",
            left.join(", ")
        );
    }
    Ok(())
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

/// Makes `dest` hold exactly what `src` holds (files, directories and symlinks, never followed),
/// leaving the top-level names in `skip` alone: entries not in `src` are removed, the rest copied.
/// For trees fetched back from a node, where `dest` is wicket's (or the operator's in-place) copy.
pub fn sync_dir(src: &Path, dest: &Path, skip: &[&str]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fn kind(p: &Path) -> Option<std::fs::FileType> {
        std::fs::symlink_metadata(p).ok().map(|m| m.file_type())
    }
    fn walk(src: &Path, dest: &Path, skip: &[&str]) -> Result<()> {
        if kind(dest).is_some_and(|k| !k.is_dir()) {
            std::fs::remove_file(dest)?;
        }
        std::fs::create_dir_all(dest)?;
        if let Ok(m) = std::fs::symlink_metadata(src) {
            std::fs::set_permissions(dest, std::fs::Permissions::from_mode(m.permissions().mode() & 0o7777))?;
        }
        // What the source no longer has goes.
        for e in std::fs::read_dir(dest)?.flatten() {
            let name = e.file_name();
            if skip.iter().any(|s| std::ffi::OsStr::new(s) == name) {
                continue;
            }
            let (d, s) = (e.path(), src.join(&name));
            let same = match (kind(&s), kind(&d)) {
                (Some(a), Some(b)) => a.is_dir() == b.is_dir() && a.is_symlink() == b.is_symlink(),
                _ => false,
            };
            if !same {
                if kind(&d).is_some_and(|k| k.is_dir()) {
                    std::fs::remove_dir_all(&d)?;
                } else {
                    std::fs::remove_file(&d)?;
                }
            }
        }
        for e in std::fs::read_dir(src)?.flatten() {
            let name = e.file_name();
            if skip.iter().any(|s| std::ffi::OsStr::new(s) == name) {
                continue;
            }
            let (s, d) = (e.path(), dest.join(&name));
            let Some(k) = kind(&s) else { continue };
            if k.is_symlink() {
                let _ = std::fs::remove_file(&d);
                std::os::unix::fs::symlink(std::fs::read_link(&s)?, &d)?;
            } else if k.is_dir() {
                walk(&s, &d, &[])?;
            } else if k.is_file() {
                // Never written through: anything at `d` is replaced, not opened.
                let _ = std::fs::remove_file(&d);
                std::fs::copy(&s, &d)?;
            }
        }
        Ok(())
    }
    walk(src, dest, skip).with_context(|| format!("syncing {} into {}", src.display(), dest.display()))
}

/// Puts staged volumes back (the push failed), unless something else is there now.
pub fn unstage_volumes(moved: &[(PathBuf, PathBuf)]) {
    for (home, staged) in moved {
        if !home.exists() {
            let _ = std::fs::rename(staged, home);
        }
    }
}

/// Restores a tree into `dest`, replacing whatever is there.
pub fn restore(m: &StateManifest, name: &str, dest: &Path) -> Result<()> {
    if m.tree(name).is_none() {
        return Ok(());
    }
    if dest.exists() {
        bundle::make_writable(dest)?;
        std::fs::remove_dir_all(dest)?;
    }
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p)?;
    }
    let (local, _) = local_store()?;
    let shared = shared_store()?;
    // Held while it fetches and reads: the cache cap doesn't evict what it has just fetched (#258).
    let _held = local.writing(&format!("the restore of agent {}", m.agent))?;
    let stores = bundle::Stores { local: &local, shared: shared.as_ref(), written: None };
    bundle::restore(stores, m, name, dest).with_context(|| format!("restoring {name}"))?;
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
        Err(e) => return say_err!("[wicket] can't wake {agent}: {e}"),
    };
    let Ok(exe) = wicket_node::reexec::self_exe() else { return };
    let mut c = std::process::Command::new(exe);
    c.args(["wake", agent, "--by", by]).stdin(std::process::Stdio::null());
    if let Ok(l2) = log.try_clone() {
        c.stdout(l2);
    }
    c.stderr(log);
    wicket_node::reexec::detach(&mut c);
    match c.spawn() {
        Ok(_) => {}
        Err(e) => say_err!("[wicket] can't wake {agent}: {e}"),
    }
}

/// An agent named by its id or by any of its runs.
pub fn resolve(l: &Ledger, who: &str) -> Result<AgentRow> {
    if wicket_store::valid_agent_id(who) {
        return l.agent(who)?.ok_or_else(|| wicket_home::exit::not_found(format!("no agent {who}")));
    }
    match l.agent_of_run(who)? {
        Some((id, _)) => Ok(l.agent(&id)?.ok_or_else(|| wicket_home::exit::not_found(format!("no agent {id}")))?),
        None => Err(wicket_home::exit::not_found(format!("{who} is not an agent or a run of one"))),
    }
}

/// Why an agent may not be woken again because its zone's budget is spent, over all its
/// activations: model requests, output or input tokens, or `limits.timeout` (its total time in a
/// box). A wake never resets a budget.
pub fn exhausted(a: &AgentRow) -> Option<String> {
    let m = match wicket_agent::load(&a.manifest) {
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
            Some(format!("its time budget (limits.timeout, {}) is spent over its activations", wicket_core::time::format_duration(t)))
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

/// `wicket wake <agent>` (internal, #249): claims the agent and runs its next activation in the
/// foreground. What [`trigger_wake`] starts, and wicket's own tests run.
pub async fn wake(who: &str, text: Option<String>, by: Option<String>, wait: std::time::Duration) -> Result<()> {
    let (agent, generation, run, first, last_node) = {
        let mut l = Ledger::open(&ledger_path())?;
        let a = resolve(&l, who)?;
        // The wake fence (#153): its last activation's box may still be running on a node cut off
        // from this host, until that box's authority ends. Not woken elsewhere until then, unless
        // the node has confirmed the box stopped.
        if let Some((node, until)) = crate::noderun::fenced_until(&a.run, wicket_feed::now_ms()) {
            let why = format!(
                "its last activation (run {}) may still be running on node {node}, which this host can't confirm stopped, until its authority ends: it can be woken from {}, or as soon as node {node} reports the box stopped",
                a.run,
                crate::noderun::fmt_ms(until)
            );
            l.audit(
                &TenantId(a.tenant.clone()),
                None,
                "agent.wake_refused",
                &serde_json::json!({ "agent": a.id, "by": by, "why": why, "until_ms": until }),
            )?;
            bail!("agent {} can't be woken yet: {why}", a.id);
        }
        // The same fence in the ledger (#446), which `claim_wake` keeps: a run of the agent still
        // recorded running, its authority not ended. It holds where this host's run files don't,
        // as on a standby restored from the state store (#154).
        if a.state != "hibernated" {
            if let Some((r, until)) = l.agent_fenced_until(&a.id, wicket_store::now())? {
                let why = format!(
                    "its activation (run {r}) may still be running on its node, recorded running with authority until {}: it can be woken from then, or once the reconciler finds the box gone",
                    crate::noderun::fmt_ms(until.saturating_mul(1000))
                );
                l.audit(
                    &TenantId(a.tenant.clone()),
                    None,
                    "agent.wake_refused",
                    &serde_json::json!({ "agent": a.id, "by": by, "why": why, "until_ms": until.saturating_mul(1000) }),
                )?;
                bail!("agent {} can't be woken yet: {why}", a.id);
            }
        }
        // Where it last ran (its run before this wake): only a tie-break when placing it.
        let last_node = l.run_node(&a.run)?;
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
        let Some(generation) = l.claim_wake(&a.id, &run.0, wicket_store::now() + BUSY_CLAIM_SECS)? else {
            let a = l.agent(&a.id)?.unwrap_or(a);
            say!("[wicket] agent {} not woken: it is {} (generation {}, run {})", a.id, a.state, a.generation, a.run);
            // Refused (#574): something else has it; 2 is a usage error.
            std::process::exit(wicket_home::exit::Code::Refused as i32);
        };
        let by = by.unwrap_or_else(|| format!("wicket wake by {}", crate::cli_principal()["id"].as_str().unwrap_or("operator")));
        if let Some(t) = &text {
            // The operator running this wake, by its authenticated principal (#253).
            let op = crate::operators::Operator::cli(&a.tenant)?;
            l.add_prompt(&run.0, t, &by, &op.id)?;
        }
        let said: Vec<(String, String)> = l.take_prompts(&run.0)?.into_iter().map(|p| (p.text, p.label)).collect();
        let first = wake_text(&by, &said, l.waiting_messages(&run.0)?);
        l.audit(
            &TenantId(a.tenant.clone()),
            Some(&run),
            "agent.wake",
            &serde_json::json!({ "agent": a.id, "generation": generation, "by": by, "from_run": a.run, "head": a.head, "operator_messages": said.len() }),
        )?;
        (l.agent(&a.id)?.expect("claimed"), generation, run, first, last_node)
    };
    // The agent's state is its bundle, here, so it can wake on any node: bin-packed into the nodes
    // available now, by its zone's limits.
    let node = match place(&agent, &run, generation, last_node.as_deref(), wait).await {
        Ok(n) => n,
        Err(e) => {
            let l = Ledger::open(&ledger_path())?;
            l.release_failed_wake(&agent.id, generation, &format!("wake failed: {e:#}"))?;
            return Err(e);
        }
    };
    let node = node.filter(|n| n != crate::localnode::NAME);
    say!("[wicket] waking agent {} ({}): generation {generation}, run {run}", agent.id, agent.name);
    let res = async {
        let t0 = std::time::Instant::now();
        let state = read_head(agent.head.as_deref().expect("checked"), &agent.id)?;
        if state.session_id != agent.session_id {
            bail!("the bundle's session {} isn't the agent's {}", state.session_id, agent.session_id);
        }
        say!(
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
        image: Some(&image),
        node: node.as_deref(),
        ssh_key: None,
        run_id: Some(run.0.clone()),
        parent_run: None,
        lease: None,
        wrap: None,
        wake: Some(Wake { agent: agent.clone(), generation, state, first }),
        attach: false,
        adopt: None,
        stop: None,
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

/// A node a box could go on: its name, and its size and use as it reported them.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub name: String,
    pub cap: crate::chan::NodeCapacity,
    /// When its room was read (ms): its report's receipt, or the probe. Reservations made since
    /// count against it (#579).
    pub at_ms: i64,
}

/// What the scheduler sees of `c` (#579): its reported room, and from the ledger its labels, taints,
/// and whether its CA covers `need` (the box's inspected hosts) or may be widened to them (#573).
pub fn scheduled_node(l: &Ledger, c: &Candidate, need: &[String]) -> wicket_placement::schedule::Node {
    use wicket_placement::schedule::Coverage;
    let ca = match wicket_node::controlca::active(l, &c.name) {
        None => Coverage::Covers,
        Some(ca) => {
            let missing = wicket_core::splice::uncovered(&ca.hosts, need);
            let policy = l.node_ca_policy(&c.name).unwrap_or(wicket_store::CaHosts::Fixed);
            let (may, kept_out): (Vec<String>, Vec<String>) = missing.into_iter().partition(|h| policy.allows(h));
            match (may.is_empty(), kept_out.is_empty()) {
                (_, false) => Coverage::Refuses(kept_out),
                (false, true) => Coverage::Widens(may),
                (true, true) => Coverage::Covers,
            }
        }
    };
    wicket_placement::schedule::Node {
        name: c.name.clone(),
        vcpus: c.cap.vcpus,
        used_vcpus: c.cap.used_vcpus,
        memory_mib: c.cap.memory_mib,
        used_memory_mib: c.cap.used_memory_mib,
        room_mib: c.cap.room_mib,
        full: c.cap.full,
        labels: l.node_labels(&c.name).unwrap_or_default(),
        taints: l.node_taints(&c.name).unwrap_or_default(),
        ca,
    }
}

/// Chooses a node for `run`'s box among `cands` and reserves what it asks for there, in one
/// transaction under the ledger's write lock (#579 step 2): each candidate's room is what it
/// reported less what reservations made since hold on it (`Ledger::held_on`), so two starts never
/// count the same room. Nothing is reserved when no node may take it.
///
/// With `fifo` (a wake, which may wait), the runs waiting ahead of it (`Ledger::waiting_before`)
/// go first: if one of them fits a node now, nothing is reserved for this one, and `behind` names
/// it. A named node (`--node`) doesn't wait, so it isn't queued.
pub fn bind(l: &Ledger, run: &RunId, ask: &Waiting, cands: &[Candidate], last: Option<&str>, now_ms: i64, fifo: bool) -> Result<Bound> {
    use wicket_placement::schedule::{schedule, Strategy};
    let (req, need) = (&ask.req, &ask.need[..]);
    l.immediate(|l| {
        let mut held = vec![];
        for c in cands {
            held.push(l.held_on(&c.name, c.at_ms, now_ms)?);
        }
        let nodes = |need: &[String]| -> Vec<wicket_placement::schedule::Node> {
            cands
                .iter()
                .zip(&held)
                .map(|(c, (cpu, mib))| {
                    let mut n = scheduled_node(l, c, need);
                    n.used_vcpus += cpu;
                    n.used_memory_mib += mib;
                    n.room_mib = n.room_mib.map(|r| r.saturating_sub(*mib));
                    n
                })
                .collect()
        };
        if fifo {
            for (older, json) in l.waiting_before(&run.0, now_ms)? {
                let Ok(w) = serde_json::from_str::<Waiting>(&json) else { continue };
                if schedule(&w.req, &nodes(&w.need), Strategy::BinPack, None).node.is_some() {
                    let b = Bound { decision: Default::default(), behind: Some(older) };
                    l.record_placement_decision(&run.0, &decision_record(ask, &b, cands.len()), now_ms)?;
                    return Ok(b);
                }
            }
        }
        let d = schedule(req, &nodes(need), Strategy::BinPack, last);
        if let Some(node) = &d.node {
            l.reserve_placement(&run.0, node, req.vcpus, req.memory_mib, now_ms)?;
        }
        let b = Bound { decision: d, behind: None };
        l.record_placement_decision(&run.0, &decision_record(ask, &b, cands.len()), now_ms)?;
        Ok(b)
    })
}

/// The most nodes a decision record names, ranked and refused each: enough to say why, bounded so
/// a large installation's records stay small (#582).
pub const DECISION_NODES: usize = 10;

/// A decision as `wicket why-here` shows it (`placement_decisions`): the request, the node, the
/// ranking and the refusals with every reason (at most [`DECISION_NODES`] of each), or the run it
/// waited behind.
pub fn decision_record(ask: &Waiting, b: &Bound, candidates: usize) -> String {
    let d = &b.decision;
    serde_json::json!({
        "request": ask.req,
        "ca_hosts": ask.need,
        "node": d.node,
        "candidates": candidates,
        "ranked": d.ranked.iter().take(DECISION_NODES).collect::<Vec<_>>(),
        "ranked_more": d.ranked.len().saturating_sub(DECISION_NODES),
        "refused": d.refused.iter().take(DECISION_NODES).map(|(n, why)| serde_json::json!({
            "node": n, "why": why.iter().map(|r| r.to_string()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "refused_more": d.refused.len().saturating_sub(DECISION_NODES),
        "behind": b.behind,
    })
    .to_string()
}

/// What [`bind`] decided: the decision, or the older waiting run it yielded to.
#[derive(Debug, Default)]
pub struct Bound {
    pub decision: wicket_placement::schedule::Decision,
    pub behind: Option<String>,
}

/// A waiting run's request, as `placement_waits` keeps it.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Waiting {
    pub req: wicket_placement::schedule::Request,
    pub need: Vec<String>,
}

/// A node's last report older than this (ms) is not trusted for its room: it is asked (#579).
pub const INDEX_FRESH_MS: i64 = 90_000;

/// Which of `names` placement can read from the ledger (#579): those whose latest health report,
/// received under [`INDEX_FRESH_MS`] ago, carries the node's capacity. The rest (no report, an old
/// one, a node from before it carried capacity) are returned to be asked, as before: a node no run
/// is connected to reports nothing.
pub fn from_index(names: &[String], health: &[(String, i64, String)], now_ms: i64) -> (Vec<Candidate>, Vec<String>) {
    let (mut found, mut ask) = (vec![], vec![]);
    for n in names {
        let cap = health.iter().find(|(node, at, _)| node == n && now_ms - at < INDEX_FRESH_MS).and_then(|(_, at, j)| {
            serde_json::from_str::<wicket_chan::health::NodeHealth>(j).ok().and_then(|h| h.capacity).map(|c| (c, *at))
        });
        match cap {
            Some((cap, at_ms)) => found.push(Candidate { name: n.clone(), cap, at_ms }),
            None => ask.push(n.clone()),
        }
    }
    (found, ask)
}

/// Where a woken agent's box goes: every enrolled, active node (this host's own among them) not held
/// by a capacity lease, its room read from its last report in the ledger ([`from_index`]) or, with
/// none fresh, asked of it (within 10 s); filtered by the box's requests, labels, taints and CA
/// coverage, then bin-packed (`wicket_placement::schedule`).
async fn place(agent: &AgentRow, run: &RunId, generation: i64, last: Option<&str>, wait: std::time::Duration) -> Result<Option<String>> {
    let m = wicket_agent::load(&agent.manifest)?;
    let req = wicket_placement::schedule::Request::of(&m);
    let need = wicket_core::splice::ca_hosts(&m.zone, &[]);
    let ledger = std::sync::Arc::new(std::sync::Mutex::new(Ledger::open(&ledger_path())?));
    crate::localnode::ensure(&ledger).await?;
    let index = || -> Result<(Vec<Candidate>, Vec<String>)> {
        let l = ledger.lock().expect("ledger");
        let leased: Vec<String> = l.leases(wicket_store::LIVE_LEASES)?.into_iter().filter_map(|x| x.node_name).collect();
        let names: Vec<String> =
            l.nodes()?.into_iter().filter(|n| n.status == "active" && !leased.contains(&n.name)).map(|n| n.name).collect();
        Ok(from_index(&names, &l.node_health()?, wicket_feed::now_ms()))
    };
    let ask = |names: Vec<String>| {
        let ledger = ledger.clone();
        async move {
            let probes = names.into_iter().map(|n| {
                let ledger = ledger.clone();
                async move {
                    let r = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        crate::nodecall::Link::connect(&n, &format!("place:{}", std::process::id()), &ledger),
                    )
                    .await;
                    match r {
                        Ok(Ok(link)) => link.capacity.map(|cap| Candidate { name: n, cap, at_ms: wicket_feed::now_ms() }),
                        Ok(Err(e)) => {
                            say!("[wicket] node {n} is not available for the wake: {e:#}");
                            None
                        }
                        Err(_) => {
                            say!("[wicket] node {n} is not available for the wake: no answer within 10 s");
                            None
                        }
                    }
                }
            });
            futures_util::future::join_all(probes).await.into_iter().flatten().collect::<Vec<Candidate>>()
        }
    };
    // Choosing and reserving are one transaction (#579 step 2): nothing is reserved when none fits,
    // and a wake waiting longer goes first.
    let me = Waiting { req: req.clone(), need: need.clone() };
    let decide = |cands: &[Candidate]| bind(&ledger.lock().expect("ledger"), run, &me, cands, last, wicket_feed::now_ms(), true);
    let waiting = serde_json::to_string(&me)?;
    let started = std::time::Instant::now();
    let (indexed, to_probe) = index()?;
    let mut probed = ask(to_probe).await;
    let mut probed_at = std::time::Instant::now();
    let mut cands: Vec<Candidate> = indexed.iter().cloned().chain(probed.iter().cloned()).collect();
    if cands.is_empty() {
        return Ok(None);
    }
    let mut b = decide(&cands)?;
    // A report can be up to 30 s old: it may still count a box that has ended since (one that just
    // hibernated, say). Before waiting or refusing, the nodes read from reports are asked.
    if b.decision.node.is_none() && b.behind.is_none() && !indexed.is_empty() {
        let fresh = ask(indexed.iter().map(|c| c.name.clone()).collect()).await;
        cands = fresh.into_iter().chain(probed.iter().cloned()).collect();
        b = decide(&cands)?;
    }
    let mut told = false;
    loop {
        if let Some(n) = &b.decision.node {
            let _ = ledger.lock().expect("ledger").stop_waiting(&run.0);
            say!(
                "[wicket] placing agent {} on node {n} (best fit of {} it may go on, of {} available{})",
                agent.id,
                b.decision.ranked.len(),
                cands.len(),
                if told { format!(", after {} s in the queue", started.elapsed().as_secs()) } else { String::new() }
            );
            return Ok(Some(n.clone()));
        }
        let why = match &b.behind {
            Some(r) => format!("waiting behind {r}, which waited first and fits"),
            None => b.decision.why_not(),
        };
        if started.elapsed() >= wait {
            let _ = ledger.lock().expect("ledger").stop_waiting(&run.0);
            // No silent overcommit (#377): each node would refuse the box itself.
            bail!(
                "no available node may take agent {} ({} vCPU, {} MiB needed){}: {why}",
                agent.id,
                req.vcpus,
                req.memory_mib,
                if told { format!(" after {} s in the queue", started.elapsed().as_secs()) } else { String::new() }
            );
        }
        {
            let l = ledger.lock().expect("ledger");
            l.wait_for_placement(&run.0, &waiting, wicket_feed::now_ms())?;
            l.renew_agent_claim(&agent.id, generation, wicket_store::now() + BUSY_CLAIM_SECS)?;
        }
        if !told {
            say!(
                "[wicket] queued: no node may take agent {} now ({why}); waiting up to {} s (wicket wake --wait 0 to fail instead)",
                agent.id,
                wait.as_secs()
            );
            told = true;
        }
        tokio::time::sleep(QUEUE_RETRY).await;
        let (indexed, to_probe) = index()?;
        if probed_at.elapsed() >= QUEUE_REPROBE {
            probed = ask(to_probe).await;
            probed_at = std::time::Instant::now();
        }
        cands = indexed.into_iter().chain(probed.iter().cloned()).collect();
        b = decide(&cands)?;
    }
}

/// How often a waiting wake tries again, and how often it asks the nodes with no fresh report.
const QUEUE_RETRY: std::time::Duration = std::time::Duration::from_secs(2);
const QUEUE_REPROBE: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a wake waits for a node by default (`wicket wake --wait`).
pub const QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(1800);

/// `wicket hibernate <run|agent>`: asks the agent's supervisor to hibernate it at the next quiet
/// point, and reports what happened.
pub async fn hibernate(who: &str, wait_secs: u64) -> Result<()> {
    let l = Ledger::open(&ledger_path())?;
    let a = resolve(&l, who)?;
    if a.state == "hibernated" {
        say!("agent {} is already hibernated ({})", a.id, human(a.bundle_bytes as u64));
        return Ok(());
    }
    let before = a.updated_at;
    if !l.want_agent(&a.id, "hibernate")? {
        bail!("agent {} is {}: only an active agent can be hibernated", a.id, a.state);
    }
    say!("asked agent {} ({}) to hibernate at its next quiet point", a.id, a.run);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let Some(now) = l.agent(&a.id)? else { bail!("agent {} is gone", a.id) };
        match now.state.as_str() {
            "hibernated" => {
                say!(
                    "agent {} hibernated: {} stored (generation {}, bundle {})",
                    a.id,
                    human(now.bundle_bytes as u64),
                    now.generation,
                    now.head.unwrap_or_default()
                );
                return Ok(());
            }
            "active"
                if now.want.is_none()
                    && now.updated_at >= before
                    && now.note.as_deref().is_some_and(|n| n.starts_with("not hibernated")) =>
            {
                say!("agent {} goes on running: {}", a.id, now.note.unwrap_or_default());
                return Ok(());
            }
            "ended" | "failed" => bail!("agent {} {}: {}", a.id, now.state, now.note.unwrap_or_default()),
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            say!("agent {} is {} (the request stands: it hibernates when its turn ends)", a.id, now.state);
            return Ok(());
        }
    }
}

/// `wicket agents`.
pub fn list(json: bool) -> Result<()> {
    let l = Ledger::open(&ledger_path())?;
    let rows = l.agents(&TenantId::single().0)?;
    if json {
        say!("{}", serde_json::to_string_pretty(&rows.iter().map(|a| serde_json::json!({
            "id": a.id, "name": a.name, "zone": a.zone, "state": a.state, "generation": a.generation, "run": a.run,
            "session_id": a.session_id, "bundle_bytes": a.bundle_bytes, "head": a.head, "restorable": a.restorable, "note": a.note,
            "workspace": a.workspace, "updated_at": a.updated_at,
            "used": { "requests": a.used_requests, "input_tokens": a.used_input_tokens, "output_tokens": a.used_output_tokens, "secs": a.used_secs },
        })).collect::<Vec<_>>())?);
        return Ok(());
    }
    if rows.is_empty() {
        say!("no agents");
        return Ok(());
    }
    say!("{:<30}  {:<16}  {:<11}  {:>3}  {:<30}  {:>9}  note", "agent", "name", "state", "gen", "run", "bundle");
    for a in rows {
        say!(
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

#[cfg(test)]
mod tests {
    fn cand(name: &str, vcpus: f32, mem: u64, used_cpu: f32, used_mem: u64) -> Candidate {
        Candidate {
            name: name.into(),
            cap: crate::chan::NodeCapacity {
                vcpus,
                memory_mib: mem,
                used_vcpus: used_cpu,
                used_memory_mib: used_mem,
                boxes: 0,
                ..Default::default()
            },
            at_ms: 0,
        }
    }

    /// Wake placement is best fit (the fullest node the box still fits on), among the nodes whose
    /// labels, taints and CA let it on (#579); where it ran before only breaks ties.
    #[test]
    fn a_woken_agent_is_placed_from_the_nodes_last_reports_and_asks_only_the_rest() {
        let now = 10_000_000;
        let report = |cap: Option<crate::chan::NodeCapacity>| {
            serde_json::to_string(&wicket_chan::health::NodeHealth { at_ms: now, capacity: cap, ..Default::default() }).unwrap()
        };
        let cap = cand("x", 4.0, 8192, 1.0, 1024).cap;
        let names: Vec<String> = ["fresh", "stale", "old-node", "silent"].map(String::from).to_vec();
        let health = vec![
            ("fresh".to_string(), now - 30_000, report(Some(cap))),
            ("stale".to_string(), now - INDEX_FRESH_MS, report(Some(cap))),
            ("old-node".to_string(), now - 1_000, report(None)),
            ("unlisted".to_string(), now, report(Some(cap))),
        ];
        let (found, ask) = from_index(&names, &health, now);
        assert_eq!(found, vec![Candidate { name: "fresh".into(), cap, at_ms: now - 30_000 }]);
        assert_eq!(ask, ["stale", "old-node", "silent"], "a stale report, one without capacity, or none: asked");
        // A node's report carries what its Welcome would: the two read the same.
        let h: wicket_chan::health::NodeHealth = serde_json::from_str(&report(Some(cap))).unwrap();
        assert_eq!(h.capacity, Some(cap));
        let before: wicket_chan::health::NodeHealth = serde_json::from_str("{\"at_ms\":1,\"disk\":{\"total_bytes\":0,\"avail_bytes\":0,\"files_total\":0,\"files_avail\":0},\"memory\":{\"total_mib\":0,\"available_mib\":0,\"committed_mib\":0},\"feed_mode\":\"\",\"feed_fresh_until_ms\":null,\"oom_kills\":0,\"last_oom\":null,\"persist_failures\":0,\"last_persist_failure\":null}").unwrap();
        assert_eq!(before.capacity, None, "a node from before it");
    }

    /// #579 step 2: a bind reserves what it chose, so the next bind, reading the same reports,
    /// doesn't count that room again; a box the node has reported counts once, and a released
    /// reservation gives its room back.
    #[test]
    fn two_starts_never_count_the_same_room() {
        use wicket_placement::schedule::Request;
        let l = Ledger::open_in_memory().unwrap();
        let now = 50_000_000;
        // n1 has room for one 2 GiB box, n2 for one more.
        let mut n1 = cand("n1", 4.0, 4096, 0.0, 1024);
        n1.at_ms = now - 10_000;
        let mut n2 = cand("n2", 4.0, 8192, 0.0, 5120);
        n2.at_ms = now - 10_000;
        let cands = [n1.clone(), n2.clone()];
        let req = Request { vcpus: 1.0, memory_mib: 2048, ..Request::default() };
        let run = |r: &str| RunId(r.into());
        let a = bind(&l, &run("run_a"), &Waiting { req: req.clone(), need: vec![] }, &cands, None, now, true).unwrap().decision;
        assert_eq!(a.node.as_deref(), Some("n1"), "bin-packed: n1 has less left");
        assert_eq!(l.placement("run_a").unwrap().unwrap().node, "n1");
        let b = bind(&l, &run("run_b"), &Waiting { req: req.clone(), need: vec![] }, &cands, None, now + 1, true).unwrap().decision;
        assert_eq!(b.node.as_deref(), Some("n2"), "n1's room is run_a's now: {}", b.why_not());
        let c = bind(&l, &run("run_c"), &Waiting { req: req.clone(), need: vec![] }, &cands, None, now + 2, true).unwrap().decision;
        assert_eq!(c.node, None, "both taken");
        assert!(l.placement("run_c").unwrap().is_none(), "nothing reserved when nothing fits");
        assert!(c.why_not().contains("n1 (") && c.why_not().contains("n2 ("), "{}", c.why_not());
        // run_b's start failed: its room is free again.
        l.placement_released("run_b").unwrap();
        assert_eq!(
            bind(&l, &run("run_d"), &Waiting { req: req.clone(), need: vec![] }, &cands, None, now + 3, true)
                .unwrap()
                .decision
                .node
                .as_deref(),
            Some("n2")
        );
        // run_a started; n1's next report counts its box, and its reservation stops counting.
        l.placement_bound("run_a", now + 4).unwrap();
        let mut n1_after = cand("n1", 4.0, 4096, 1.0, 3072);
        n1_after.at_ms = now + 5;
        let e = bind(&l, &run("run_e"), &Waiting { req: req.clone(), need: vec![] }, &[n1_after], None, now + 6, true).unwrap().decision;
        assert_eq!(e.node, None, "full by its own report, not by twice: {}", e.why_not());
        assert!(e.why_not().contains("1024 MiB free"), "{}", e.why_not());
    }

    /// #579 step 2's queue: a run waiting longer goes first when it fits; one that fits nowhere
    /// doesn't hold up a smaller one behind it; a waiter that has gone holds no place; a named node
    /// (not queued) doesn't look.
    #[test]
    fn the_queue_is_first_come_first_served_without_head_of_line_blocking() {
        use wicket_placement::schedule::Request;
        let l = Ledger::open_in_memory().unwrap();
        let now = 70_000_000;
        let mut n1 = cand("n1", 4.0, 4096, 0.0, 2048);
        n1.at_ms = now - 1_000;
        let small = Request { vcpus: 1.0, memory_mib: 1024, ..Request::default() };
        let huge = Request { vcpus: 1.0, memory_mib: 65536, ..Request::default() };
        let wait = |run: &str, req: &Request, at: i64| {
            let w = serde_json::to_string(&Waiting { req: req.clone(), need: vec![] }).unwrap();
            l.wait_for_placement(run, &w, at).unwrap();
        };
        // run_old waits for a small box (it fits n1 now): run_new yields to it.
        wait("run_old", &small, now - 5_000);
        let b = bind(&l, &RunId("run_new".into()), &Waiting { req: small.clone(), need: vec![] }, &[n1.clone()], None, now, true).unwrap();
        assert_eq!((b.decision.node, b.behind.as_deref()), (None, Some("run_old")));
        assert!(l.placement("run_new").unwrap().is_none());
        // A named node isn't queued: it doesn't yield.
        let named =
            bind(&l, &RunId("run_named".into()), &Waiting { req: small.clone(), need: vec![] }, &[n1.clone()], None, now, false).unwrap();
        assert_eq!(named.decision.node.as_deref(), Some("n1"));
        l.placement_released("run_named").unwrap();
        // run_old binds, then a waiter for a huge box (fits nowhere) doesn't block run_new.
        let old =
            bind(&l, &RunId("run_old".into()), &Waiting { req: small.clone(), need: vec![] }, &[n1.clone()], None, now + 1, true).unwrap();
        assert_eq!(old.decision.node.as_deref(), Some("n1"), "first in the queue: nothing ahead");
        l.stop_waiting("run_old").unwrap();
        l.placement_released("run_old").unwrap();
        wait("run_huge", &huge, now - 4_000);
        let b =
            bind(&l, &RunId("run_new".into()), &Waiting { req: small.clone(), need: vec![] }, &[n1.clone()], None, now + 2, true).unwrap();
        assert_eq!(b.decision.node.as_deref(), Some("n1"), "{b:?}");
        // A waiter not seen for WAIT_SEEN_MS has gone: no place held.
        l.placement_released("run_new").unwrap();
        wait("run_gone", &small, now - 20_000);
        let late = now - 20_000 + wicket_store::WAIT_SEEN_MS + 1;
        let b = bind(&l, &RunId("run_late".into()), &Waiting { req: small.clone(), need: vec![] }, &[n1], None, late.max(now + 3), true)
            .unwrap();
        assert_eq!(b.decision.node.as_deref(), Some("n1"), "{b:?}");
        assert_eq!(wicket_core::time::parse_duration("0").unwrap(), std::time::Duration::ZERO, "--wait 0");
    }

    #[test]
    fn a_woken_agent_is_bin_packed_onto_the_fullest_node_it_may_go_on() {
        use wicket_placement::schedule::{schedule, Coverage, Request, Strategy};
        let l = Ledger::open_in_memory().unwrap();
        let cands = [cand("local", 4.0, 8192, 1.0, 1024), cand("n1", 2.0, 2048, 0.0, 512), cand("n2", 2.0, 4096, 1.5, 3000)];
        let pick = |l: &Ledger, req: &Request, last: Option<&str>| {
            let nodes: Vec<_> = cands.iter().map(|c| scheduled_node(l, c, &["api.example.com".to_string()])).collect();
            schedule(req, &nodes, Strategy::BinPack, last)
        };
        let req = |cpu: f32, mib: u64| Request { vcpus: cpu, memory_mib: mib, ..Request::default() };
        assert_eq!(pick(&l, &req(1.0, 1024), None).node.as_deref(), Some("n1"), "n2 has no vCPU, local more room than n1");
        assert_eq!(pick(&l, &req(0.5, 1024), None).node.as_deref(), Some("n2"), "n2 fits and is fullest");
        assert_eq!(pick(&l, &req(1.0, 1024), Some("local")).node.as_deref(), Some("n1"), "a better fit beats where it ran");
        let none = pick(&l, &req(8.0, 65536), None);
        assert_eq!(none.node, None);
        assert!(none.why_not().starts_with("local (3.0 vCPU, 7168 MiB free)"), "{}", none.why_not());

        // n1 is kept for CI: a box goes there only if it tolerates that, and n2 is the GPU node.
        l.set_node_taint("n1", &wicket_core::placement::Taint::parse("dedicated=ci").unwrap()).unwrap();
        l.set_node_label("n2", "gpu", Some("t4")).unwrap();
        assert_eq!(pick(&l, &req(1.0, 1024), None).node.as_deref(), Some("local"), "n1's taint keeps it off");
        let mut ci = req(1.0, 1024);
        ci.tolerations.push(wicket_core::placement::Taint::parse("dedicated").unwrap());
        assert_eq!(pick(&l, &ci, None).node.as_deref(), Some("n1"));
        let mut gpu = req(0.5, 1024);
        gpu.node_selector.insert("gpu".into(), "t4".into());
        let d = pick(&l, &gpu, None);
        assert_eq!((d.node.as_deref(), d.ranked.len()), (Some("n2"), 1), "only n2 has the label");
        // No node CA recorded (this host's own node): nothing to cover.
        assert_eq!(scheduled_node(&l, &cands[0], &["api.example.com".to_string()]).ca, Coverage::Covers);
    }

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
        // Claude Code's processes are its harness's, as its adapter says.
        let claude = |c: &str| wicket_agent::claude::is_runtime(c);
        assert_eq!(quiet(&idle, &claude, &[]), Ok(()));
        assert!(quiet(&idle, &|_| false, &[]).unwrap_err()[0].contains("claude -p"), "another harness's box isn't quiet with claude in it");
        let mut busy = idle.clone();
        busy.push((40, 1, "sleep 600".into()));
        busy.push((41, 9, "/usr/bin/node /workspace/server.js".into()));
        busy.push((42, 9, "bash -c sleep 1000".into()));
        let e = quiet(&busy, &claude, &[]).unwrap_err();
        assert_eq!(e.len(), 3, "{e:?}");
        assert!(e[0].contains("sleep 600"));
        // An ACP agent's own command (#66) is its runtime: as started, or through its interpreter.
        let acp = |argv: &[&str], cmd: &str| {
            let mut p = idle[..3].to_vec();
            p.push((9, 1, cmd.to_string()));
            quiet(&p, &|_| false, &argv.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(acp(&["python3", "/workspace/agent.py"], "python3 /workspace/agent.py"), Ok(()));
        assert_eq!(acp(&["claude-agent-acp"], "node /usr/local/bin/claude-agent-acp"), Ok(()));
        assert_eq!(acp(&["gemini", "--experimental-acp"], "/usr/bin/gemini --experimental-acp"), Ok(()));
        assert!(acp(&["python3", "/workspace/agent.py"], "python3 /workspace/other.py").is_err());
        assert!(acp(&["claude-agent-acp"], "python3 -m http.server").is_err());
    }

    #[test]
    fn what_is_left_is_named_with_its_pid() {
        let procs = vec![
            (1, 0, "/sbin/docker-init -- wicket-entry python3 /workspace/agent.py".to_string()),
            (5, 1, "/bin/bash /usr/local/bin/wicket-entry python3 /workspace/agent.py".to_string()),
            (6, 5, "wicket-fwd --listen 198.18.0.1:3128=/wicket/sock/egress.sock".to_string()),
            (9, 5, "python3 /workspace/agent.py".to_string()),
            (14, 9, "sleep 86399".to_string()),
        ];
        let agent = ["python3".to_string(), "/workspace/agent.py".to_string()];
        // To hibernate, only what isn't the agent runtime is stopped: its pids, to stop them.
        assert_eq!(leftovers(&procs, &|_| false, &agent), vec![(14, "14: sleep 86399".to_string())]);
        // After a finished session the harness lingering is named too; wicket's own parts never.
        assert_eq!(left_running(&procs), vec!["9: python3 /workspace/agent.py".to_string(), "14: sleep 86399".to_string()]);
        assert!(left_running(&procs[..3]).is_empty());
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
            claim_until: None,
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
        let t = wake_text("wicket session by op", &[("carry on".into(), "op".into())], 2);
        assert!(t.contains("woken (wicket session by op)") && t.contains("carry on") && t.contains("2 message(s)"));
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
        assert!(used_bytes(&d) <= 1 << 20);
        assert!(used_bytes(&d) > 16 * 1024);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// #258: this build reads no version-1 hibernation bundles, so the control host refuses to
    /// start while an agent's head is one, naming the agents (the build before converted them).
    #[test]
    fn a_version_one_head_refuses_the_start_and_names_its_agent() {
        use wicket_store::{new_agent_id, Ledger, NewAgent};
        let new_agent = |l: &mut Ledger| {
            let id = new_agent_id();
            l.create_agent(&NewAgent {
                id: &id,
                tenant: "t0",
                zone: "z",
                name: "a",
                run: &format!("run_{id}"),
                session_id: "s",
                manifest: "m",
                image: "img",
                workspace: None,
                claim_until: wicket_store::now() + 30,
            })
            .unwrap();
            id
        };
        let mut l = Ledger::open_in_memory().unwrap();
        // No heads, and version-2 heads only: the control host starts.
        refuse_v1_heads(&l).unwrap();
        let (new, old) = (new_agent(&mut l), new_agent(&mut l));
        let digest = format!("sha256:{}", "ab".repeat(32));
        assert!(l.commit_agent_push(&new, 1, 0, 1, &digest, 10).unwrap());
        refuse_v1_heads(&l).unwrap();
        // A version-1 head (a manifest key): refused, by name.
        assert!(l.commit_agent_push(&old, 1, 0, 1, &format!("a/{old}/m/1.1"), 10).unwrap());
        assert_eq!(v1_heads(&l).unwrap(), vec![old.clone()]);
        let e = refuse_v1_heads(&l).unwrap_err().to_string();
        assert!(e.contains(&old) && !e.contains(&new) && e.contains("version-1"), "{e}");
    }
}
