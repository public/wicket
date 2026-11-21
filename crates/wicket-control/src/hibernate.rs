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

/// Why `wake` would refuse a hibernated agent now, if it would: its last box may still be running
/// (the fence), a run in its chain was revoked, it isn't restorable, it has no state to wake from,
/// or its budget is spent. The checks `wake` makes before it claims, without its records: what a
/// trigger asks before it counts a wake as done (#578).
pub fn would_refuse(l: &Ledger, a: &AgentRow) -> Result<Option<String>> {
    if let Some((node, until)) = crate::noderun::fenced_until(l, &a.run, wicket_feed::now_ms()) {
        return Ok(Some(crate::noderun::fence_refusal(&a.run, &node, until)));
    }
    for (r, _) in l.agent_runs(&a.id)? {
        if let Some((rv, _, rby, why)) = l.revoked_in_chain(&r)? {
            return Ok(Some(format!("{rv}'s identity was revoked by {rby} ({why})")));
        }
    }
    if !a.restorable {
        return Ok(Some(a.note.clone().unwrap_or_else(|| "it is not restorable".into())));
    }
    if a.head.is_none() {
        return Ok(Some("it has never hibernated: there is nothing to wake".into()));
    }
    Ok(exhausted(a))
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
        if let Some((node, until)) = crate::noderun::fenced_until(&l, &a.run, wicket_feed::now_ms()) {
            let why = crate::noderun::fence_refusal(&a.run, &node, until);
            l.audit(
                &TenantId(a.tenant.clone()),
                None,
                "agent.wake_refused",
                &serde_json::json!({ "agent": a.id, "by": by, "why": why, "until_ms": until }),
            )?;
            // Refused (#574), as when another wake holds the claim: of two wakes at once, the loser
            // lands here instead once the winner has started its run.
            return Err(wicket_home::exit::refused(format!("agent {} not woken yet: {why}", a.id)));
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
                return Err(wicket_home::exit::refused(format!("agent {} not woken yet: {why}", a.id)));
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
            // Any room it held (a preemption's) goes back with the wake.
            // Agents it asked to hibernate are asked no more, and room it held goes back, whatever
            // stopped it.
            let _ =
                withdraw_preemptions_for(&l, &run, &wicket_core::TenantId(agent.tenant.clone()), wicket_feed::now_ms(), "the wake failed");
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
        place_wait: None,
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
        protocol: crate::noderun::known_protocol(&c.name),
        // What runs there and the volumes it holds: `OnNodes::fill`.
        ..Default::default()
    }
}

/// What runs on each node, as affinity sees it (#579 step 4): the live service instances and the
/// running boxes, read once per decision.
#[derive(Default)]
pub struct OnNodes {
    instances: Vec<wicket_store::Instance>,
    /// Running boxes, and those being started (reserved, their run not on its node yet).
    boxes: Vec<wicket_store::RunningBox>,
    now_ms: i64,
}

impl OnNodes {
    pub fn read(l: &Ledger, now_ms: i64) -> Result<OnNodes> {
        let mut boxes = l.running_boxes()?;
        boxes.extend(l.boxes_in_flight(now_ms)?);
        Ok(OnNodes { instances: l.live_service_instances()?, boxes, now_ms })
    }

    /// Fills `n`'s services, zones, principals and volumes as `ask` sees them, of its own tenant
    /// only (a shared service's instance too): a box never learns, or is placed by, where another
    /// tenant's boxes run. A node holds one of `ask`'s kept volumes if a box of `ask`'s zone runs
    /// there, or ran there within the volume's retention. `own` (the run deciding) is left out: its
    /// own reservation is no box of another for its affinity.
    pub fn fill(&self, l: &Ledger, n: &mut wicket_placement::schedule::Node, ask: &Waiting, own: &str) {
        let mine = |t: &str| !ask.tenant.is_empty() && t == ask.tenant;
        n.services = self
            .instances
            .iter()
            .filter(|i| i.node == n.name && (mine(&i.tenant) || i.tenant == wicket_store::SHARED_TENANT))
            .map(|i| i.service.clone())
            .collect();
        for b in self.boxes.iter().filter(|b| b.node == n.name && mine(&b.tenant) && b.run != own) {
            n.zones.insert(b.zone.clone());
            n.principals.extend(b.principal.clone());
        }
        let volumes: Vec<String> = ask.req.affinity.iter().filter_map(|a| a.volume.clone()).collect();
        if volumes.is_empty() || !mine(&ask.tenant) {
            return;
        }
        let ran = l.nodes_that_ran(&ask.tenant, &ask.zone).unwrap_or_default();
        let Some((_, running, last_s)) = ran.into_iter().find(|(node, ..)| node == &n.name) else { return };
        let now_s = self.now_ms / 1000;
        for v in volumes {
            // Unknown retention (a manifest from before it was recorded): kept forever, as #377's default.
            let kept = match ask.volume_retention.get(&v).copied().flatten() {
                None => true,
                Some(secs) => running || last_s.saturating_add(secs as i64) > now_s,
            };
            if kept {
                n.volumes.insert(v);
            }
        }
    }
}

/// Chooses a node for `run`'s box among `cands` and reserves what it asks for there, in one
/// transaction under the ledger's write lock (#579 step 2): each candidate's room is what it
/// reported less what reservations made since hold on it (`Ledger::held_on`), so two starts never
/// count the same room. Nothing is reserved when no node may take it.
///
/// With `fifo` (a wake, which may wait), the runs waiting ahead of it go first, in the queue's
/// tenant-fair order (`wicket_placement::schedule::queue_order`): first come, first served across
/// tenants, and within a tenant its own runs fill its places by priority. If one of them fits a node
/// now, nothing is reserved for this one, and `behind` names it (or says only "a run of another
/// tenant"). A named node (`--node`) doesn't wait, so it isn't queued.
///
/// Each node is seen with what runs on it ([`OnNodes`]), for affinity.
pub fn bind(l: &Ledger, run: &RunId, ask: &Waiting, cands: &[Candidate], last: Option<&str>, now_ms: i64, fifo: bool) -> Result<Bound> {
    use wicket_placement::schedule::{ahead, schedule, Strategy, Waiter};
    let req = &ask.req;
    l.immediate(|l| {
        // What reservations hold on each candidate; for this run's own decision, not counting its
        // own reservation (one a preemption held for it).
        let (mut held, mut held_me) = (vec![], vec![]);
        for c in cands {
            held.push(l.held_on(&c.name, c.at_ms, now_ms)?);
            held_me.push(l.held_on_except(&c.name, c.at_ms, now_ms, &run.0)?);
        }
        let on = OnNodes::read(l, now_ms)?;
        let nodes = |w: &Waiting, who: &str| seen(l, cands, &held, &on, w, who);
        if fifo {
            let (me, waiting) = queue(l, run, &ask.tenant, req.priority, now_ms)?;
            let queue: Vec<Waiter> = waiting.iter().map(|(q, _)| q.clone()).collect();
            for older in ahead(&me, &queue) {
                let Some((_, w)) = waiting.iter().find(|(q, _)| q.run == older.run) else { continue };
                if schedule(&w.req, &nodes(w, &older.run), Strategy::BinPack, None).node.is_some() {
                    // Another tenant's run isn't named: only that one waited ahead.
                    let who = if w.tenant == ask.tenant { older.run.clone() } else { ANOTHER_TENANT.to_string() };
                    let b = Bound { decision: Default::default(), behind: Some(who) };
                    l.record_placement_decision(&run.0, &decision_record(ask, &b, cands.len()), now_ms)?;
                    return Ok(b);
                }
            }
        }
        let d = schedule(req, &seen(l, cands, &held_me, &on, ask, &run.0), Strategy::BinPack, last);
        if let Some(node) = &d.node {
            l.reserve_placement(&run.0, node, req.vcpus, req.memory_mib, now_ms)?;
            l.record_placement_owner(&run.0, &ask.tenant, &ask.zone, ask.principal.as_deref())?;
        }
        let b = Bound { decision: d, behind: None };
        l.record_placement_decision(&run.0, &decision_record(ask, &b, cands.len()), now_ms)?;
        Ok(b)
    })
}

/// The candidates as `w` sees them: each one's room less what reservations hold on it (`held`, one
/// per candidate), and what runs on it ([`OnNodes`]).
fn seen(
    l: &Ledger,
    cands: &[Candidate],
    held: &[(f32, u64)],
    on: &OnNodes,
    w: &Waiting,
    own: &str,
) -> Vec<wicket_placement::schedule::Node> {
    cands
        .iter()
        .zip(held)
        .map(|(c, (cpu, mib))| {
            let mut n = scheduled_node(l, c, &w.need);
            on.fill(l, &mut n, w, own);
            n.used_vcpus += cpu;
            n.used_memory_mib += mib;
            n.room_mib = n.room_mib.map(|r| r.saturating_sub(*mib));
            n
        })
        .collect()
}

/// `run` (of `tenant`, asking `priority`) in the queue, and the other live waiters with what they ask.
fn queue(
    l: &Ledger,
    run: &RunId,
    tenant: &str,
    priority: i32,
    now_ms: i64,
) -> Result<(wicket_placement::schedule::Waiter, Vec<(wicket_placement::schedule::Waiter, Waiting)>)> {
    use wicket_placement::schedule::Waiter;
    let mut me = Waiter { run: run.0.clone(), tenant: tenant.to_string(), priority, at_ms: now_ms };
    let mut waiting = vec![];
    for (r, at_ms, json) in l.live_waiters(now_ms)? {
        if r == run.0 {
            me.at_ms = at_ms;
            continue;
        }
        let Ok(w) = serde_json::from_str::<Waiting>(&json) else { continue };
        waiting.push((Waiter { run: r, tenant: w.tenant.clone(), priority: w.req.priority, at_ms }, w));
    }
    Ok((me, waiting))
}

/// What a wake says it waits behind when that run is another tenant's: it isn't named.
pub const ANOTHER_TENANT: &str = "a run of another tenant";

/// Who preemption's requests are by.
pub const PREEMPT_BY: &str = "wicket:preempt";

/// What a box asking `ask` could stop to make room, and the nodes as it sees them, with the boxes
/// asked to stop within [`PREEMPT_DEADLINE`] counted as gone: the running long-lived agents of its
/// own tenant, with recorded terms, not in `spare` (`schedule::preempt` keeps those marked
/// preemptible and of a lower priority).
fn preemptable(
    run: &str,
    ask: &Waiting,
    cands: &[Candidate],
    nodes: &mut [wicket_placement::schedule::Node],
    terms: &[wicket_store::BoxTerms],
    spare: &[String],
    now_ms: i64,
) -> std::collections::BTreeMap<String, Vec<wicket_placement::schedule::Running>> {
    // Gone: asked within the deadline and still running, or ended since, after the node's report
    // (which still counts its box).
    let report_at = |node: &str| cands.iter().find(|c| c.name == node).map_or(i64::MAX, |c| c.at_ms);
    let settling = |b: &wicket_store::BoxTerms| match b.ended_ms {
        None => b.preempted_at_ms.is_some_and(|t| now_ms - t < PREEMPT_DEADLINE.as_millis() as i64),
        Some(end) => report_at(&b.node) <= end,
    };
    for n in nodes.iter_mut() {
        for b in terms.iter().filter(|b| b.node == n.name && settling(b)) {
            n.used_vcpus = (n.used_vcpus - b.vcpus).max(0.0);
            n.used_memory_mib = n.used_memory_mib.saturating_sub(b.memory_mib);
            n.room_mib = n.room_mib.map(|r| r.saturating_add(b.memory_mib));
        }
    }
    let mut running: std::collections::BTreeMap<String, Vec<wicket_placement::schedule::Running>> = Default::default();
    // An agent with a live child is never chosen: hibernating it stops its children.
    let eligible = |b: &&wicket_store::BoxTerms| {
        b.ended_ms.is_none()
            && b.agent.is_some()
            && !b.live_children
            && !settling(b)
            && b.tenant == ask.tenant
            && b.run != run
            && !spare.contains(&b.run)
    };
    for b in terms.iter().filter(eligible) {
        running.entry(b.node.clone()).or_default().push(wicket_placement::schedule::Running {
            run: b.run.clone(),
            vcpus: b.vcpus,
            memory_mib: b.memory_mib,
            priority: b.priority,
            preemptible: b.preemptible,
        });
    }
    running
}

/// When no node may take `run`'s box, stops boxes to make room (#579 step 4), in one transaction
/// under the ledger's write lock.
///
/// - It defers to a run waiting ahead of it ([`wicket_placement::schedule::ahead`]) only if that
///   one fits a node now or could itself make room this way: a run that can't be served doesn't
///   hold preemption up.
/// - Only long-lived agents of `ask`'s own tenant whose manifest marks them preemptible, of a lower
///   priority, are chosen (`wicket_placement::schedule::preempt`: on one node, each one needed).
///   A program, or a run that isn't an agent's, is never stopped.
/// - Each is stopped the normal way an agent stops for room: asked to hibernate at its next quiet
///   point (`Ledger::want_agent`), so it keeps its work and can be woken again; never revoked. Each
///   is audited as `placement.preempted`.
/// - The room is held for `run`: it reserves what it asks for on that node, so another start
///   doesn't take it while the agents hibernate.
///
/// An agent asked within [`PREEMPT_DEADLINE`] counts as gone, so a retry stops nothing more for the
/// same room; one that hasn't stopped by then is given up on ([`settle_preemption`]). The agents in
/// `spare` (given up on in this wait) are never chosen. The start that follows is placed by [`bind`],
/// once the node's report has the room, and the node's admission still decides. A box with no terms
/// recorded (started by an older build) is never stopped. With `dry_run`, it only says what it would
/// stop, and changes nothing.
pub fn preempt_for(
    l: &Ledger,
    run: &RunId,
    ask: &Waiting,
    cands: &[Candidate],
    now_ms: i64,
    spare: &[String],
    dry_run: bool,
) -> Result<Option<wicket_placement::schedule::Preemption>> {
    use wicket_placement::schedule::{ahead, preempt, schedule, Strategy, Waiter};
    if ask.tenant.is_empty() {
        return Ok(None);
    }
    // A dry run only reads: it takes no write lock.
    let work = |l: &Ledger| -> Result<Option<wicket_placement::schedule::Preemption>> {
        let (mut held, mut held_me) = (vec![], vec![]);
        for c in cands {
            held.push(l.held_on(&c.name, c.at_ms, now_ms)?);
            held_me.push(l.held_on_except(&c.name, c.at_ms, now_ms, &run.0)?);
        }
        let on = OnNodes::read(l, now_ms)?;
        let terms = l.preemption_view(now_ms)?;
        let view = |w: &Waiting, who: &str| {
            let mut nodes = seen(l, cands, if who == run.0 { &held_me } else { &held }, &on, w, who);
            let running = preemptable(who, w, cands, &mut nodes, &terms, if who == run.0 { spare } else { &[] }, now_ms);
            (nodes, running)
        };
        let (me, waiting) = queue(l, run, &ask.tenant, ask.req.priority, now_ms)?;
        let others: Vec<Waiter> = waiting.iter().map(|(q, _)| q.clone()).collect();
        for older in ahead(&me, &others) {
            let Some((_, w)) = waiting.iter().find(|(q, _)| q.run == older.run) else { continue };
            let (nodes, running) = view(w, &older.run);
            let served = schedule(&w.req, &nodes, Strategy::BinPack, None).node.is_some()
                || (!w.tenant.is_empty() && preempt(&w.req, &nodes, &running, Strategy::BinPack).is_some());
            if served {
                return Ok(None);
            }
        }
        let (nodes, running) = view(ask, &run.0);
        let Some(p) = preempt(&ask.req, &nodes, &running, Strategy::BinPack) else { return Ok(None) };
        if dry_run {
            return Ok(Some(p));
        }
        let tenant = wicket_core::TenantId(ask.tenant.clone());
        for v in &p.victims {
            let Some(b) = terms.iter().find(|b| &b.run == v) else { continue };
            let Some(agent) = &b.agent else { continue };
            // An operator's own request, if any, stands; preemption's is tagged, so only it is ever
            // withdrawn.
            l.want_agent_if_unasked(agent, PREEMPT_WANT)?;
            l.mark_preempted(v, now_ms, &run.0)?;
            l.audit(
                &tenant,
                Some(&RunId(v.clone())),
                "placement.preempted",
                &serde_json::json!({
                    "run": v, "agent": agent, "node": p.node, "priority": b.priority, "for": run.0,
                    "for_priority": ask.req.priority, "how": "hibernate", "by": PREEMPT_BY,
                }),
            )?;
        }
        // Hold the room for this run while they hibernate.
        l.reserve_placement(&run.0, &p.node, ask.req.vcpus, ask.req.memory_mib, now_ms)?;
        l.record_placement_owner(&run.0, &ask.tenant, &ask.zone, ask.principal.as_deref())?;
        Ok(Some(p))
    };
    if dry_run {
        work(l)
    } else {
        l.immediate(work)
    }
}

/// What preemption asks of an agent: to hibernate, tagged so that only preemption's own request is
/// ever withdrawn (an operator's `wicket hibernate` asks plain `hibernate`).
pub const PREEMPT_WANT: &str = "hibernate:preempt";

/// Preemption asks `v` no more for `for_run` (its request made at `asked_ms`, if given): its mark
/// is cleared if it is still that request's, and its tagged hibernate request withdrawn unless
/// another wake has asked since (one past this one's deadline may have), whose request stands.
fn ask_no_more(l: &Ledger, v: &str, for_run: &str, asked_ms: Option<i64>, now_ms: i64) -> Result<()> {
    l.clear_preempted(v, for_run, asked_ms)?;
    if l.preemption_mark(v, now_ms)?.is_none() {
        if let Some((agent, _)) = l.agent_of_run(v)? {
            l.withdraw_agent_want(&agent, PREEMPT_WANT)?;
        }
    }
    Ok(())
}

/// Gives up on the victims in `left` of `run`'s preemption `p` (#579 step 4): each is asked no
/// more (its pending request withdrawn, and preemption's mark cleared, which its supervisor checks
/// before it hibernates for preemption), the room held for `run` is released, and each is audited as
/// `placement.preempt_abandoned`, with `why`.
#[allow(clippy::too_many_arguments)]
pub fn abandon_preemption(
    l: &Ledger,
    run: &RunId,
    ask: &Waiting,
    p: &wicket_placement::schedule::Preemption,
    left: &[String],
    asked_ms: i64,
    now_ms: i64,
    why: &str,
    release_room: bool,
) -> Result<()> {
    let tenant = wicket_core::TenantId(ask.tenant.clone());
    for v in left {
        ask_no_more(l, v, &run.0, Some(asked_ms), now_ms)?;
        l.audit(
            &tenant,
            Some(&RunId(v.clone())),
            "placement.preempt_abandoned",
            &serde_json::json!({
                "run": v, "node": p.node, "for": run.0, "after_secs": (now_ms - asked_ms) / 1000, "why": why, "by": PREEMPT_BY,
            }),
        )?;
    }
    if release_room {
        l.placement_released(&run.0)?;
    }
    Ok(())
}

/// A wake stops waiting (#579 step 4): placed (`placed`: its new reservation stays), or given up.
/// Every box preemption still asks to stop for it, by the ledger's marks rather than only its
/// pending plan, is asked no more (its tagged request withdrawn, its mark cleared, audited as
/// `placement.preempt_abandoned`); given up, the room it held is released too. Returns the
/// victims given up on.
pub fn end_wait(l: &Ledger, run: &RunId, ask: &Waiting, now_ms: i64, placed: bool) -> Result<Vec<String>> {
    l.immediate(|l| {
        let left = l.preempted_for(&run.0)?;
        let tenant = wicket_core::TenantId(ask.tenant.clone());
        let why = if placed { "the wake was placed without them" } else { "the wake gave up waiting" };
        for v in &left {
            ask_no_more(l, v, &run.0, None, now_ms)?;
            l.audit(
                &tenant,
                Some(&RunId(v.clone())),
                "placement.preempt_abandoned",
                &serde_json::json!({ "run": v, "for": run.0, "why": why, "by": PREEMPT_BY, "at_ms": now_ms }),
            )?;
        }
        if !placed {
            l.placement_released(&run.0)?;
        }
        Ok(left)
    })
}

/// Whether an agent's supervisor hibernates now for a hibernate it was asked (#579 step 4). One
/// asked by an operator or by the agent itself (`for_preemption` false) always does. One asked only by
/// preemption doesn't, with the reason, when preemption no longer asks it (`mark` gone: given up),
/// the request is older than [`PREEMPT_DEADLINE`] (the wake is long gone or gave up), the wake that
/// asked no longer waits nor holds a reservation (it ended, failed or was killed), or the agent
/// has a child running (hibernating ends its run, which stops its children; it may have spawned
/// one since it was chosen). Checked at its quiet point, and again before it hibernates out of a
/// linger.
pub fn preempted_hibernate(
    for_preemption: bool,
    mark: Option<&wicket_store::PreemptMark>,
    live_children: usize,
    now_ms: i64,
) -> std::result::Result<(), &'static str> {
    if !for_preemption {
        return Ok(());
    }
    let Some(m) = mark else { return Err("the wake that asked for room no longer needs it") };
    if now_ms - m.asked_ms >= PREEMPT_DEADLINE.as_millis() as i64 {
        return Err("the request for room is older than the preemption deadline");
    }
    if !m.asker_alive {
        return Err("the wake that asked for room is gone");
    }
    // Its supervisor's own count, or the ledger's (a supervisor that re-attached holds none).
    if live_children.max(m.running_children) > 0 {
        return Err("it has a child running, which hibernating would stop");
    }
    Ok(())
}

/// Who a supervisor's pending hibernate is for (#579 step 4): whether one is asked, whether it is
/// preemption's and no one else's (so it may be declined or withdrawn), and the same carried
/// through a linger for a quiet box. An operator's `wicket hibernate` or the agent's own request
/// always takes precedence: once one is asked, the hibernate is no longer preemption's, in a linger
/// too.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HibAsk {
    /// A hibernate is asked, not yet begun.
    pub asked: bool,
    /// ...and only preemption asked for it.
    pub for_preemption: bool,
    /// A linger for a quiet box hibernates for preemption only.
    pub linger_for_preemption: bool,
    /// A linger for a quiet box is on (for whoever asked).
    pub lingering: bool,
}

impl HibAsk {
    /// A hibernate asked: by preemption (`by_preemption`), or by an operator or the agent.
    pub fn ask(&mut self, by_preemption: bool) {
        // Nothing else asked: no request pending but preemption's, and no linger but its.
        let only_preemption = (!self.asked || self.for_preemption) && (!self.lingering || self.linger_for_preemption);
        self.for_preemption = by_preemption && only_preemption;
        if !by_preemption {
            self.linger_for_preemption = false;
        }
        self.asked = true;
    }

    /// Preemption's pending request is declined or withdrawn: it is asked no more. A linger goes
    /// on, and is checked again before it hibernates ([`HibAsk::linger_over`]).
    pub fn decline(&mut self) {
        debug_assert!(self.for_preemption);
        self.asked = false;
        self.for_preemption = false;
    }

    /// The quiet point takes the request: whether it is preemption's only.
    pub fn take(&mut self) -> bool {
        self.asked = false;
        std::mem::take(&mut self.for_preemption)
    }

    /// The box wasn't quiet: a linger begins, for preemption only if `for_preemption`.
    pub fn linger(&mut self, for_preemption: bool) {
        self.linger_for_preemption = for_preemption && !self.asked;
        self.lingering = true;
    }

    /// A linger for a hibernate ends without hibernating (the agent asked to finish since).
    pub fn linger_ends(&mut self) {
        self.linger_for_preemption = false;
        self.lingering = false;
    }

    /// A turn began during the linger: the hibernate is asked again for its end, still only
    /// preemption's if both the linger and anything asked since were.
    pub fn turn_began_in_linger(&mut self) {
        let lp = std::mem::take(&mut self.linger_for_preemption);
        self.lingering = false;
        self.for_preemption = lp && (!self.asked || self.for_preemption);
        self.asked = true;
    }

    /// The linger is over and it may hibernate now: whether that is for preemption only.
    pub fn linger_over(&mut self) -> bool {
        self.lingering = false;
        std::mem::take(&mut self.linger_for_preemption)
    }
}

/// Withdraws every preemption made for `run` whose victims still run (#579 step 4): what a wake
/// that fails does, whatever stopped it. Each is asked no more and audited as
/// `placement.preempt_abandoned`; the room held for `run` is released.
pub fn withdraw_preemptions_for(l: &Ledger, run: &RunId, tenant: &wicket_core::TenantId, now_ms: i64, why: &str) -> Result<Vec<String>> {
    l.immediate(|l| {
        let left = l.preempted_for(&run.0)?;
        for v in &left {
            ask_no_more(l, v, &run.0, None, now_ms)?;
            l.audit(
                tenant,
                Some(&RunId(v.clone())),
                "placement.preempt_abandoned",
                &serde_json::json!({ "run": v, "for": run.0, "why": why, "by": PREEMPT_BY, "at_ms": now_ms }),
            )?;
        }
        l.placement_released(&run.0)?;
        Ok(left)
    })
}

/// The victims of `p` whose runs still run.
pub fn still_running(l: &Ledger, p: &wicket_placement::schedule::Preemption) -> Result<Vec<String>> {
    let mut left = vec![];
    for v in &p.victims {
        if l.run_status(v)?.as_deref() == Some("running") {
            left.push(v.clone());
        }
    }
    Ok(left)
}

/// What became of a preemption a wake made ([`settle_preemption`]).
#[derive(Debug, PartialEq, Eq)]
pub enum Settled {
    /// Every victim's run has ended: the room shows once the node reports.
    Done,
    /// Some still run, within [`PREEMPT_DEADLINE`]: the room stays held for the wake.
    Waiting,
    /// These didn't stop by the deadline: they are given up on for this wait, their hibernate
    /// request withdrawn, and the room released.
    Abandoned(Vec<String>),
    /// These declined to hibernate (a child running, say): the whole plan is given up on, every
    /// victim's request withdrawn and the room released; only these are spared in this wait.
    Declined(Vec<String>),
    /// Another wake asked these to stop since: the plan is given up on (every request of its
    /// withdrawn and the room released, the later wake's request left standing), and none is spared.
    Taken(Vec<String>),
}

/// Checks on a preemption `run` made on `p.node` at `asked_ms` (#579 step 4). While its victims
/// run, within [`PREEMPT_DEADLINE`], the room stays reserved for `run` (renewed, as a reservation
/// lapses after `RESERVE_SECS`). Past it, an agent that hasn't stopped (a hibernate request is
/// honoured at a quiet point, and may be declined) is given up on: its request is withdrawn, the
/// reservation is released, and each is audited as `placement.preempt_abandoned`. Nothing is ever
/// revoked.
pub fn settle_preemption(
    l: &Ledger,
    run: &RunId,
    ask: &Waiting,
    p: &wicket_placement::schedule::Preemption,
    asked_ms: i64,
    now_ms: i64,
) -> Result<Settled> {
    l.immediate(|l| {
        let left = still_running(l, p)?;
        if left.is_empty() {
            return Ok(Settled::Done);
        }
        // A victim whose supervisor declined (its mark cleared: a child running, say) won't stop,
        // so the plan won't make its room: give up on all of it, not only on the decliners, so no
        // other victim hibernates for room that won't come. Only the decliners are spared in this
        // wait; the others may be chosen again. A victim another wake has asked since (this one's
        // request past its deadline, say) didn't decline: it stops for that wake, whose room it is,
        // so this plan is given up on too, but the victim isn't spared.
        let (mut declined, mut taken, mut rest) = (vec![], vec![], vec![]);
        for v in left {
            match l.preemption_mark(&v, now_ms)? {
                None => declined.push(v),
                Some(m) if m.for_run.as_deref() == Some(run.0.as_str()) && m.asked_ms == asked_ms => rest.push(v),
                Some(_) => taken.push(v),
            }
        }
        if !declined.is_empty() || !taken.is_empty() {
            let others = if declined.is_empty() {
                "another wake asked another of the plan's boxes to stop since"
            } else {
                "another of the plan's boxes declined to hibernate"
            };
            abandon_preemption(l, run, ask, p, &declined, asked_ms, now_ms, "it declined to hibernate", false)?;
            abandon_preemption(l, run, ask, p, &taken, asked_ms, now_ms, "another wake asked it to stop since", false)?;
            abandon_preemption(l, run, ask, p, &rest, asked_ms, now_ms, others, true)?;
            return Ok(if declined.is_empty() { Settled::Taken(taken) } else { Settled::Declined(declined) });
        }
        let left = rest;
        if now_ms - asked_ms < PREEMPT_DEADLINE.as_millis() as i64 {
            l.reserve_placement(&run.0, &p.node, ask.req.vcpus, ask.req.memory_mib, now_ms)?;
            return Ok(Settled::Waiting);
        }
        abandon_preemption(l, run, ask, p, &left, asked_ms, now_ms, "it didn't hibernate by the deadline", true)?;
        Ok(Settled::Abandoned(left))
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
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Waiting {
    pub req: wicket_placement::schedule::Request,
    pub need: Vec<String>,
    /// Whose box it is: what affinity matches it against (#579 step 4). Empty in a row from
    /// before: it matches no other box, and holds no kept volume.
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub zone: String,
    /// Its principal, if known (a woken agent's, from its last identity): what another box's
    /// anti-affinity names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Its kept volumes' retention (s; None: kept forever), for volume affinity.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub volume_retention: std::collections::BTreeMap<String, Option<u64>>,
}

impl Waiting {
    /// What `m`'s box asks for.
    pub fn of(m: &wicket_core::Manifest) -> Waiting {
        Waiting {
            req: wicket_placement::schedule::Request {
                min_protocol: crate::noderun::protocol_needed(&m.zone),
                ..wicket_placement::schedule::Request::of(m)
            },
            need: wicket_core::splice::ca_hosts(&m.zone, &[]),
            tenant: m.tenant.0.clone(),
            zone: m.zone.name.clone(),
            principal: None,
            volume_retention: m
                .zone
                .volumes
                .iter()
                .filter(|v| v.keep)
                .map(|v| (v.name.clone(), v.retention().ok().flatten().map(|d| d.as_secs())))
                .collect(),
        }
    }
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

/// Each placed (paid) node's lease end, by name, from its latest record (#579): an ended one's is
/// when it ended, if that was sooner, so a node whose enrolment outlived its placed node's end counts
/// as past its lease, not as one that was never placed.
pub fn placed_leases(rows: &[wicket_store::PlacedNodeRow]) -> Vec<(String, i64)> {
    let mut latest: std::collections::BTreeMap<&str, &wicket_store::PlacedNodeRow> = Default::default();
    for r in rows {
        let newer = latest.get(r.name.as_str()).is_none_or(|p| (r.created_at, &r.id) >= (p.created_at, &p.id));
        if newer {
            latest.insert(&r.name, r);
        }
    }
    latest
        .into_values()
        .map(|r| {
            let until = match r.status.as_str() {
                "active" => r.lease_until,
                _ => r.ended_at.map_or(r.lease_until, |e| e.min(r.lease_until)),
            };
            (r.name.clone(), until)
        })
        .collect()
}

/// Whether `node` may take a box that runs up to `needs_secs` from `now` (s), by the leases of the
/// placed (paid) nodes in `placed` (name, lease end): one that isn't placed always may; a placed one
/// only if its lease outlasts the box (#579).
pub fn lasts_for(placed: &[(String, i64)], node: &str, now: i64, needs_secs: i64) -> bool {
    placed.iter().filter(|(n, _)| n == node).all(|(_, until)| *until > now.saturating_add(needs_secs))
}

/// Where a woken agent's box goes ([`place_box`]).
async fn place(agent: &AgentRow, run: &RunId, generation: i64, last: Option<&str>, wait: std::time::Duration) -> Result<Option<String>> {
    let m = wicket_agent::load(&agent.manifest)?;
    // The agent is the same principal across its runs: its last run's identity names it.
    let principal = Ledger::open(&ledger_path())?.identity(&agent.run)?.map(|i| i.spiffe_id);
    let who = Placing { what: format!("agent {}", agent.id), claim: Some((agent.id.clone(), generation)), wait_flag: "wicket wake --wait" };
    place_box(&who, &m, principal, run, last, wait).await
}

/// What is being placed ([`place_box`]): how it is named in what wicket says (`agent agt_…`,
/// `run run_…`), the agent claim a wake renews while it waits, and the flag that sets the wait.
pub struct Placing {
    pub what: String,
    pub claim: Option<(String, i64)>,
    pub wait_flag: &'static str,
}

/// Where `m`'s box goes (#579): every enrolled, active node (this host's own among them) not held
/// by a capacity lease, its room read from its last report in the ledger ([`from_index`]) or, with
/// none fresh, asked of it (within 10 s); filtered by the box's requests, labels, taints, CA
/// coverage and affinity, then bin-packed (`wicket_placement::schedule`). With none that may take
/// it now, it waits in the queue for up to `wait` (and may preempt, by its priority). None: no node
/// is available at all.
pub async fn place_box(
    who: &Placing,
    m: &wicket_core::Manifest,
    principal: Option<String>,
    run: &RunId,
    last: Option<&str>,
    wait: std::time::Duration,
) -> Result<Option<String>> {
    let mut me = Waiting::of(m);
    me.principal = principal;
    let what = &who.what;
    let req = me.req.clone();
    let ledger = std::sync::Arc::new(std::sync::Mutex::new(Ledger::open(&ledger_path())?));
    crate::localnode::ensure(&ledger).await?;
    // A placed (paid) node whose lease ends before the box would is left out: it would be stopped at
    // the lease's end, and nothing may hold a paid node past it.
    let needs_secs = m.zone.limits.timeout()?.as_secs() as i64;
    let index = || -> Result<(Vec<Candidate>, Vec<String>)> {
        let l = ledger.lock().expect("ledger");
        let leased: Vec<String> = l.leases(wicket_store::LIVE_LEASES)?.into_iter().filter_map(|x| x.node_name).collect();
        let placed = placed_leases(&l.placed_nodes(&[])?);
        let now = wicket_store::now();
        let names: Vec<String> = l
            .nodes()?
            .into_iter()
            .filter(|n| n.status == "active" && !leased.contains(&n.name) && lasts_for(&placed, &n.name, now, needs_secs))
            .map(|n| n.name)
            .collect();
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
                            say!("[wicket] node {n} is not available for {what}: {e:#}");
                            None
                        }
                        Err(_) => {
                            say!("[wicket] node {n} is not available for {what}: no answer within 10 s");
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
    // #579 step 4: the preemption this wake made and when (ms), the agents it gave up on in this
    // wait, and when it last asked every node for its room before preempting.
    let mut pending: Option<(wicket_placement::schedule::Preemption, i64)> = None;
    let mut spare: Vec<String> = vec![];
    let mut preempt_probed_at: Option<std::time::Instant> = None;
    loop {
        if let Some(n) = &b.decision.node {
            let l = ledger.lock().expect("ledger");
            let _ = l.stop_waiting(&run.0);
            // Agents it asked to hibernate and still running aren't needed now.
            let _ = end_wait(&l, run, &me, wicket_feed::now_ms(), true);
            drop(l);
            say!(
                "[wicket] placing {what} on node {n} (best fit of {} it may go on, of {} available{})",
                b.decision.ranked.len(),
                cands.len(),
                if told { format!(", after {} s in the queue", started.elapsed().as_secs()) } else { String::new() }
            );
            return Ok(Some(n.clone()));
        }
        let why = match &b.behind {
            Some(r) => format!("waiting behind {r}, which goes first (it took an earlier place in line, or it is one of this tenant's of a higher priority) and fits"),
            None => b.decision.why_not(),
        };
        if started.elapsed() >= wait {
            let l = ledger.lock().expect("ledger");
            let _ = l.stop_waiting(&run.0);
            // Room it held for itself after preempting goes back, and agents it asked to hibernate
            // are asked no more.
            let _ = end_wait(&l, run, &me, wicket_feed::now_ms(), false);
            drop(l);
            // No silent overcommit (#377): each node would refuse the box itself.
            bail!(
                "no available node may take {what} ({} vCPU, {} MiB needed){}: {why}",
                req.vcpus,
                req.memory_mib,
                if told { format!(" after {} s in the queue", started.elapsed().as_secs()) } else { String::new() }
            );
        }
        {
            let l = ledger.lock().expect("ledger");
            l.wait_for_placement(&run.0, &waiting, wicket_feed::now_ms())?;
            if let Some((agent, generation)) = &who.claim {
                l.renew_agent_claim(agent, *generation, wicket_store::now() + BUSY_CLAIM_SECS)?;
            }
        }
        // #579 step 4: a preemption it made holds its room while the agents hibernate, and is given
        // up on past the deadline.
        if let Some((p, asked_ms)) = &pending {
            let settled = settle_preemption(&ledger.lock().expect("ledger"), run, &me, p, *asked_ms, wicket_feed::now_ms())?;
            match settled {
                Settled::Waiting => {}
                Settled::Done => {
                    // The node's last report may still count them: ask every node before deciding
                    // to stop more.
                    pending = None;
                    preempt_probed_at = None;
                }
                Settled::Abandoned(left) => {
                    say!(
                        "[wicket] gave up preempting {} for {what}: not hibernated within {} s (audited; the room is released)",
                        left.join(", "),
                        PREEMPT_DEADLINE.as_secs()
                    );
                    spare.extend(left);
                    pending = None;
                }
                Settled::Taken(left) => {
                    say!(
                        "[wicket] gave up preempting for {what}: another wake asked {} to stop since (audited; the room is released)",
                        left.join(", "),
                    );
                    pending = None;
                }
                Settled::Declined(left) => {
                    say!(
                        "[wicket] gave up preempting for {what}: {} declined to hibernate (audited; the room is released)",
                        left.join(", "),
                    );
                    spare.extend(left);
                    pending = None;
                }
            }
        }
        // Nothing fits and nothing ahead of it can be served, so it may stop boxes that yield to it:
        // not while its last preemption is pending, nor with less wait left than a node takes to
        // report the room. It works the plan out from what it knows first; only with one does it ask
        // every node for its room (a report may still count a box that has ended), at most every
        // QUEUE_REPROBE.
        if pending.is_none() && b.behind.is_none() && wait.saturating_sub(started.elapsed()) >= PREEMPT_MIN_LEFT {
            let plan = preempt_for(&ledger.lock().expect("ledger"), run, &me, &cands, wicket_feed::now_ms(), &spare, true)?;
            if plan.is_some() {
                let mut with = cands.clone();
                if preempt_probed_at.is_none_or(|t| t.elapsed() >= QUEUE_REPROBE) {
                    preempt_probed_at = Some(std::time::Instant::now());
                    let fresh = ask(cands.iter().map(|c| c.name.clone()).collect()).await;
                    let again = decide(&fresh)?;
                    if again.decision.node.is_some() {
                        (cands, b) = (fresh, again);
                        continue;
                    }
                    with = if again.behind.is_none() { fresh } else { vec![] };
                }
                let now = wicket_feed::now_ms();
                if !with.is_empty() {
                    if let Some(p) = preempt_for(&ledger.lock().expect("ledger"), run, &me, &with, now, &spare, false)? {
                        say!(
                            "[wicket] preempting {} on node {n} for {what} (priority {} over at most {}): asked to hibernate within {} s, audited; the room is held for it",
                            p.victims.join(", "),
                            req.priority,
                            p.max_priority,
                            PREEMPT_DEADLINE.as_secs(),
                            n = p.node,
                        );
                        pending = Some((p, now));
                    }
                }
            }
        }
        if !told {
            say!(
                "[wicket] queued: no node may take {what} now ({why}); waiting up to {} s ({} 0 to fail instead)",
                wait.as_secs(),
                who.wait_flag
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

/// How long an agent asked to hibernate for room has to stop before the wake gives up on it, and
/// how long it counts as gone meanwhile (so nothing more is stopped for the same room). An agent
/// hibernates at its next quiet point: the end of its turn.
pub const PREEMPT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

/// The least wait left for a wake to stop boxes: a node's report interval, since the room shows only
/// once it reports.
const PREEMPT_MIN_LEFT: std::time::Duration = std::time::Duration::from_secs(30);

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

/// `wicket agents --json`: one object per long-lived agent.
pub fn agents_json(rows: &[wicket_store::AgentRow]) -> serde_json::Value {
    serde_json::Value::Array(
        rows.iter()
            .map(|a| serde_json::json!({
                "id": a.id, "name": a.name, "zone": a.zone, "state": a.state, "generation": a.generation, "run": a.run,
                "session_id": a.session_id, "bundle_bytes": a.bundle_bytes, "head": a.head, "restorable": a.restorable, "note": a.note,
                "workspace": a.workspace, "updated_at": a.updated_at,
                "used": { "requests": a.used_requests, "input_tokens": a.used_input_tokens, "output_tokens": a.used_output_tokens, "secs": a.used_secs },
            }))
            .collect(),
    )
}

/// `wicket agents`.
pub fn list(json: bool) -> Result<()> {
    let l = Ledger::open(&ledger_path())?;
    let rows = l.agents(&TenantId::single().0)?;
    if json {
        say!("{}", serde_json::to_string_pretty(&agents_json(&rows))?);
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
        let a = bind(&l, &run("run_a"), &Waiting { req: req.clone(), need: vec![], ..Default::default() }, &cands, None, now, true)
            .unwrap()
            .decision;
        assert_eq!(a.node.as_deref(), Some("n1"), "bin-packed: n1 has less left");
        assert_eq!(l.placement("run_a").unwrap().unwrap().node, "n1");
        let b = bind(&l, &run("run_b"), &Waiting { req: req.clone(), need: vec![], ..Default::default() }, &cands, None, now + 1, true)
            .unwrap()
            .decision;
        assert_eq!(b.node.as_deref(), Some("n2"), "n1's room is run_a's now: {}", b.why_not());
        let c = bind(&l, &run("run_c"), &Waiting { req: req.clone(), need: vec![], ..Default::default() }, &cands, None, now + 2, true)
            .unwrap()
            .decision;
        assert_eq!(c.node, None, "both taken");
        assert!(l.placement("run_c").unwrap().is_none(), "nothing reserved when nothing fits");
        assert!(c.why_not().contains("n1 (") && c.why_not().contains("n2 ("), "{}", c.why_not());
        // run_b's start failed: its room is free again.
        l.placement_released("run_b").unwrap();
        assert_eq!(
            bind(&l, &run("run_d"), &Waiting { req: req.clone(), need: vec![], ..Default::default() }, &cands, None, now + 3, true)
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
        let e =
            bind(&l, &run("run_e"), &Waiting { req: req.clone(), need: vec![], ..Default::default() }, &[n1_after], None, now + 6, true)
                .unwrap()
                .decision;
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
            let w = serde_json::to_string(&Waiting { req: req.clone(), need: vec![], ..Default::default() }).unwrap();
            l.wait_for_placement(run, &w, at).unwrap();
        };
        // run_old waits for a small box (it fits n1 now): run_new yields to it.
        wait("run_old", &small, now - 5_000);
        let b = bind(
            &l,
            &RunId("run_new".into()),
            &Waiting { req: small.clone(), need: vec![], ..Default::default() },
            std::slice::from_ref(&n1),
            None,
            now,
            true,
        )
        .unwrap();
        assert_eq!((b.decision.node, b.behind.as_deref()), (None, Some("run_old")));
        assert!(l.placement("run_new").unwrap().is_none());
        // A named node isn't queued: it doesn't yield.
        let named = bind(
            &l,
            &RunId("run_named".into()),
            &Waiting { req: small.clone(), need: vec![], ..Default::default() },
            std::slice::from_ref(&n1),
            None,
            now,
            false,
        )
        .unwrap();
        assert_eq!(named.decision.node.as_deref(), Some("n1"));
        l.placement_released("run_named").unwrap();
        // run_old binds, then a waiter for a huge box (fits nowhere) doesn't block run_new.
        let old = bind(
            &l,
            &RunId("run_old".into()),
            &Waiting { req: small.clone(), need: vec![], ..Default::default() },
            std::slice::from_ref(&n1),
            None,
            now + 1,
            true,
        )
        .unwrap();
        assert_eq!(old.decision.node.as_deref(), Some("n1"), "first in the queue: nothing ahead");
        l.stop_waiting("run_old").unwrap();
        l.placement_released("run_old").unwrap();
        wait("run_huge", &huge, now - 4_000);
        let b = bind(
            &l,
            &RunId("run_new".into()),
            &Waiting { req: small.clone(), need: vec![], ..Default::default() },
            std::slice::from_ref(&n1),
            None,
            now + 2,
            true,
        )
        .unwrap();
        assert_eq!(b.decision.node.as_deref(), Some("n1"), "{b:?}");
        // A waiter not seen for WAIT_SEEN_MS has gone: no place held.
        l.placement_released("run_new").unwrap();
        wait("run_gone", &small, now - 20_000);
        let late = now - 20_000 + wicket_store::WAIT_SEEN_MS + 1;
        let b = bind(
            &l,
            &RunId("run_late".into()),
            &Waiting { req: small.clone(), need: vec![], ..Default::default() },
            &[n1],
            None,
            late.max(now + 3),
            true,
        )
        .unwrap();
        assert_eq!(b.decision.node.as_deref(), Some("n1"), "{b:?}");
        assert_eq!(wicket_core::time::parse_duration("0").unwrap(), std::time::Duration::ZERO, "--wait 0");
    }

    /// #579 step 4: a higher priority goes first, however late; within one, first come, first served.
    #[test]
    fn the_queue_serves_a_higher_priority_first() {
        use wicket_placement::schedule::Request;
        let l = Ledger::open_in_memory().unwrap();
        let now = 80_000_000;
        let mut n1 = cand("n1", 4.0, 4096, 0.0, 2048);
        n1.at_ms = now - 1_000;
        let at = |priority| Request { vcpus: 1.0, memory_mib: 1024, priority, ..Request::default() };
        let wait = |run: &str, req: &Request, t: i64| {
            l.wait_for_placement(run, &serde_json::to_string(&Waiting { req: req.clone(), ..Default::default() }).unwrap(), t).unwrap();
        };
        wait("run_low", &at(0), now - 9_000);
        wait("run_high", &at(5), now - 1_000);
        let ask = |p| Waiting { req: at(p), ..Default::default() };
        // run_low waited longest, but run_high ranks above it: run_low yields.
        let b = bind(&l, &RunId("run_low".into()), &ask(0), std::slice::from_ref(&n1), None, now, true).unwrap();
        assert_eq!(b.behind.as_deref(), Some("run_high"));
        let b = bind(&l, &RunId("run_high".into()), &ask(5), std::slice::from_ref(&n1), None, now, true).unwrap();
        assert_eq!((b.decision.node.as_deref(), b.behind), (Some("n1"), None), "nothing ranks above it");
        l.placement_released("run_high").unwrap();
        // A newcomer of a higher priority than every waiter goes first; one of the same waits.
        assert_eq!(bind(&l, &RunId("run_urgent".into()), &ask(9), std::slice::from_ref(&n1), None, now, true).unwrap().behind, None);
        l.placement_released("run_urgent").unwrap();
        assert_eq!(bind(&l, &RunId("run_peer".into()), &ask(5), &[n1], None, now, true).unwrap().behind.as_deref(), Some("run_high"));
    }

    /// #579 step 4 (review): priority counts within a tenant only. Another tenant's run at 1000
    /// doesn't pass this tenant's older one, and a run that waits behind another tenant's isn't told
    /// which run it is.
    #[test]
    fn a_tenants_priority_never_jumps_another_tenants_wait() {
        use wicket_placement::schedule::Request;
        let l = Ledger::open_in_memory().unwrap();
        let now = 81_000_000;
        let mut n1 = cand("n1", 4.0, 4096, 0.0, 2048);
        n1.at_ms = now - 1_000;
        let ask = |tenant: &str, priority| Waiting {
            req: Request { vcpus: 1.0, memory_mib: 1024, priority, ..Request::default() },
            tenant: tenant.into(),
            ..Default::default()
        };
        l.wait_for_placement("run_t0", &serde_json::to_string(&ask("t0", 0)).unwrap(), now - 9_000).unwrap();
        l.wait_for_placement("run_t1", &serde_json::to_string(&ask("t1", 1000)).unwrap(), now - 1_000).unwrap();
        // t1's run, though at 1000, waited later: it yields to t0's, and isn't told its id.
        let b = bind(&l, &RunId("run_t1".into()), &ask("t1", 1000), std::slice::from_ref(&n1), None, now, true).unwrap();
        assert_eq!(b.behind.as_deref(), Some(ANOTHER_TENANT));
        let rec = l.placement_decision("run_t1").unwrap().unwrap().1;
        assert!(!rec.contains("run_t0"), "{rec}");
        // t0's goes first.
        let b = bind(&l, &RunId("run_t0".into()), &ask("t0", 0), std::slice::from_ref(&n1), None, now, true).unwrap();
        assert_eq!((b.decision.node.as_deref(), b.behind), (Some("n1"), None));
        l.placement_released("run_t0").unwrap();
        // Within t0, a later run of a higher priority goes ahead of its own older one, and is named.
        assert_eq!(
            bind(&l, &RunId("run_t0b".into()), &ask("t0", 0), std::slice::from_ref(&n1), None, now, true).unwrap().behind.as_deref(),
            Some("run_t0")
        );
        let b = bind(&l, &RunId("run_t0c".into()), &ask("t0", 5), &[n1], None, now, true).unwrap();
        assert_eq!(b.behind, None, "t0's at 5 takes t0's first place");
    }

    /// #579 step 4 (review): two starts in flight see each other. A box reserved on a node, its run
    /// not on the node yet, keeps a box that must be away from its zone off that node.
    #[test]
    fn a_box_being_started_counts_for_anti_affinity() {
        use wicket_core::placement::AntiAffinity;
        use wicket_placement::schedule::Request;
        let l = Ledger::open_in_memory().unwrap();
        let now = 92_000_000;
        let cands: Vec<Candidate> = ["n1", "n2"]
            .iter()
            .map(|n| {
                let mut c = cand(n, 4.0, 8192, 0.0, 0);
                c.at_ms = now - 1_000;
                c
            })
            .collect();
        let research = Waiting {
            req: Request { vcpus: 1.0, memory_mib: 1024, ..Request::default() },
            tenant: "t0".into(),
            zone: "research".into(),
            ..Default::default()
        };
        let a = bind(&l, &RunId("run_a".into()), &research, &cands, None, now, false).unwrap().decision;
        assert_eq!(a.node.as_deref(), Some("n1"));
        let away = Waiting {
            req: Request {
                vcpus: 1.0,
                memory_mib: 1024,
                anti_affinity: vec![AntiAffinity { zone: Some("research".into()), required: true, ..Default::default() }],
                ..Request::default()
            },
            tenant: "t0".into(),
            zone: "z".into(),
            ..Default::default()
        };
        let b = bind(&l, &RunId("run_b".into()), &away, &cands, None, now + 1, false).unwrap().decision;
        assert_eq!(b.ranked, ["n2"], "run_a is being started on n1: {}", b.why_not());
        // Once run_a's start fails, n1 is no reason.
        l.placement_released("run_a").unwrap();
        l.placement_released("run_b").unwrap();
        assert_eq!(bind(&l, &RunId("run_c".into()), &away, &cands, None, now + 2, false).unwrap().decision.ranked, ["n1", "n2"]);
    }

    /// #579 step 4: a node is seen with its own tenant's boxes and service instances, and the kept
    /// volumes of the zones it ran; affinity places by them.
    #[test]
    fn affinity_sees_what_runs_on_each_node() {
        use wicket_core::placement::{Affinity, AntiAffinity};
        use wicket_placement::schedule::Request;
        let l = Ledger::open_in_memory().unwrap();
        let now = 90_000_000;
        let (t0, t1) = (wicket_core::TenantId("t0".into()), wicket_core::TenantId("t1".into()));
        let cands: Vec<Candidate> = ["n1", "n2", "n3"]
            .iter()
            .map(|n| {
                let mut c = cand(n, 4.0, 8192, 0.0, 0);
                c.at_ms = now - 1_000;
                c
            })
            .collect();
        // n1: t0's research box. n2: t1's research box, and t0's npm-cache instance. n3: ran t0's
        // zone z once (its kept volumes are there).
        let start = |t: &wicket_core::TenantId, run: &str, zone: &str, node: &str| {
            l.run_started(t, &RunId(run.into()), zone, "a").unwrap();
            l.set_run_node(run, node).unwrap();
        };
        start(&t0, "run_r", "research", "n1");
        start(&t1, "run_other", "research", "n2");
        start(&t0, "run_cache", "npm-cache", "n2");
        l.record_service_instance("run_cache", "npm-cache", "n2", "t0", "aa", now / 1000).unwrap();
        start(&t0, "run_past", "z", "n3");
        l.run_ended(&RunId("run_past".into()), "done", "").unwrap();

        let ask = |req: Request| Waiting { req, tenant: "t0".into(), zone: "z".into(), ..Default::default() };
        let base = Request { vcpus: 1.0, memory_mib: 1024, ..Request::default() };
        let place = |r: &str, req: Request| {
            let b = bind(&l, &RunId(r.into()), &ask(req), &cands, None, now, false).unwrap().decision;
            l.placement_released(r).unwrap();
            b
        };
        let away = Request {
            anti_affinity: vec![AntiAffinity { zone: Some("research".into()), required: true, ..Default::default() }],
            ..base.clone()
        };
        let d = place("run_a", away);
        assert_eq!(d.ranked, ["n2", "n3"], "only t0's research box keeps it off: {}", d.why_not());
        let near = Request {
            affinity: vec![Affinity { service: Some("npm-cache".into()), required: true, ..Default::default() }],
            ..base.clone()
        };
        assert_eq!(place("run_b", near).ranked, ["n2"]);
        let vol = Request { affinity: vec![Affinity { volume: Some("data".into()), ..Default::default() }], ..base.clone() };
        assert_eq!(place("run_c", vol.clone()).node.as_deref(), Some("n3"), "preferred: where the zone ran");
        // With a retention shorter than the time since the zone last ran there, the volume is gone.
        let short = Waiting {
            req: vol.clone(),
            tenant: "t0".into(),
            zone: "z".into(),
            volume_retention: [("data".to_string(), Some(60))].into_iter().collect(),
            ..Default::default()
        };
        let ended = l.nodes_that_ran("t0", "z").unwrap()[0].2;
        let later = (ended + 3600) * 1000;
        let d = bind(&l, &RunId("run_cr".into()), &short, &cands, None, later, false).unwrap().decision;
        assert_ne!(d.node.as_deref(), Some("n3"), "its retention deleted it: {:?}", d.ranked);
        l.placement_released("run_cr").unwrap();
        let long = Waiting { volume_retention: [("data".to_string(), Some(86_400))].into_iter().collect(), ..short };
        assert_eq!(bind(&l, &RunId("run_cl".into()), &long, &cands, None, later, false).unwrap().decision.node.as_deref(), Some("n3"));
        l.placement_released("run_cl").unwrap();
        // Another tenant's box of the same zone name is no reason, nor holds its volumes.
        let other = Waiting { req: vol, tenant: "t1".into(), zone: "z".into(), ..Default::default() };
        assert_eq!(bind(&l, &RunId("run_d".into()), &other, &cands, None, now, false).unwrap().decision.node.as_deref(), Some("n1"));
    }

    /// A full node n1 (4 vCPUs, 4096 MiB, all held) with: t0's preemptible agent `agt_batch`
    /// (priority 0), t0's agent `agt_kept` (not preemptible), t1's preemptible agent (priority -5),
    /// a preemptible program of t0's (priority -5, no agent's), and a box without terms.
    fn crowded(l: &mut Ledger, now: i64) -> Candidate {
        let mut n1 = cand("n1", 4.0, 4096, 4.0, 4096);
        n1.at_ms = now - 1_000;
        let mut boxed = |tenant: &str, run: &str, priority: i32, terms: Option<bool>, agent: Option<&str>| {
            let t = wicket_core::TenantId(tenant.into());
            l.run_started(&t, &RunId(run.into()), "z", "a").unwrap();
            l.set_run_node(run, "n1").unwrap();
            if let Some(p) = terms {
                l.record_run_terms(run, 1.0, 1024, priority, p, now).unwrap();
            }
            if let Some(id) = agent {
                l.create_agent(&wicket_store::NewAgent {
                    id,
                    tenant,
                    zone: "z",
                    name: id,
                    run,
                    session_id: "s",
                    manifest: "m",
                    image: "img",
                    workspace: None,
                    claim_until: wicket_store::now() + 30,
                })
                .unwrap();
            }
        };
        boxed("t0", "run_batch", 0, Some(true), Some("agt_batch"));
        boxed("t0", "run_kept", 0, Some(false), Some("agt_kept"));
        boxed("t1", "run_theirs", -5, Some(true), Some("agt_theirs"));
        boxed("t0", "run_prog", -5, Some(true), None);
        boxed("t0", "run_old", -5, None, Some("agt_old"));
        n1
    }

    fn asking(tenant: &str, priority: i32) -> Waiting {
        Waiting {
            req: wicket_placement::schedule::Request { vcpus: 1.0, memory_mib: 1024, priority, ..Default::default() },
            tenant: tenant.into(),
            zone: "z".into(),
            ..Default::default()
        }
    }

    /// #579 step 4 (review): preemption stops only a long-lived agent of its own tenant, marked
    /// preemptible and of a lower priority, by asking it to hibernate: never revoked, so it keeps its
    /// work and wakes again. A program, another tenant's agent, one not preemptible, or one without
    /// terms isn't touched. Each is audited, the room is held for the waking run, and a retry stops
    /// nothing more.
    #[test]
    fn preemption_hibernates_what_yields_and_it_wakes_again() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = 95_000_000;
        let n1 = crowded(&mut l, now);
        assert!(
            preempt_for(&l, &RunId("run_eq".into()), &asking("t0", 0), std::slice::from_ref(&n1), now, &[], false).unwrap().is_none(),
            "an equal priority stops nothing"
        );

        let p = preempt_for(&l, &RunId("run_new".into()), &asking("t0", 5), std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        assert_eq!((p.node.as_str(), p.victims.clone()), ("n1", vec!["run_batch".to_string()]), "not the program, kept, theirs or old");
        for r in ["run_batch", "run_kept", "run_theirs", "run_prog", "run_old"] {
            assert!(l.revoked_in_chain(r).unwrap().is_none(), "{r}: preemption never revokes");
        }
        let batch = l.agent("agt_batch").unwrap().unwrap();
        assert_eq!(batch.want.as_deref(), Some(PREEMPT_WANT), "asked to hibernate, the normal way, tagged as preemption's");
        for a in ["agt_kept", "agt_theirs", "agt_old"] {
            assert_eq!(l.agent(a).unwrap().unwrap().want, None, "{a}");
        }
        let audit: Vec<_> = l.audit_records_after(0, 100).unwrap().into_iter().filter(|a| a.kind == "placement.preempted").collect();
        assert_eq!(audit.len(), 1);
        let body: serde_json::Value = serde_json::from_str(&audit[0].body).unwrap();
        assert_eq!(
            (body["run"].as_str(), body["agent"].as_str(), body["how"].as_str(), body["for"].as_str(), body["priority"].as_i64()),
            (Some("run_batch"), Some("agt_batch"), Some("hibernate"), Some("run_new"), Some(0))
        );
        // The room is held for run_new, not for anyone else.
        assert_eq!(l.placement("run_new").unwrap().unwrap().node, "n1");
        assert_eq!(l.held_on("n1", n1.at_ms, now + 1).unwrap(), (1.0, 1024));
        assert_eq!(l.held_on_except("n1", n1.at_ms, now + 1, "run_new").unwrap(), (0.0, 0));
        // Asked within the settle time, it counts as gone: a retry stops nothing more.
        assert!(preempt_for(&l, &RunId("run_new".into()), &asking("t0", 5), std::slice::from_ref(&n1), now + 2_000, &[], false)
            .unwrap()
            .is_none());
        assert_eq!(l.audit_records_after(0, 100).unwrap().iter().filter(|a| a.kind == "placement.preempted").count(), 1);

        // Its supervisor hibernates it (takes the want, commits its state, ends the run); then a
        // wake claims it as for any hibernated agent.
        assert_eq!(l.take_agent_want("agt_batch", batch.generation).unwrap().as_deref(), Some(PREEMPT_WANT));
        assert!(l.commit_agent_push("agt_batch", batch.generation, 0, 1, "head-1", 10).unwrap());
        l.run_ended(&RunId("run_batch".into()), "hibernated", "").unwrap();
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().state, "hibernated");
        assert!(l.claim_wake("agt_batch", "run_batch2", wicket_store::now() + 60).unwrap().is_some(), "a preempted agent wakes again");
    }

    /// #579 step 4 (review): the room a preemption reserves for a run is the run's own, so its own
    /// reservation never counts against its own anti-affinity: a spread rule (away from its own
    /// zone) still takes the node it preempted for.
    #[test]
    fn a_runs_own_reservation_is_no_neighbour_for_its_affinity() {
        use wicket_core::placement::AntiAffinity;
        let mut l = Ledger::open_in_memory().unwrap();
        let now = 97_000_000;
        let n1 = crowded(&mut l, now);
        let mut spread = asking("t0", 5);
        spread.zone = "w".into();
        spread.req.anti_affinity.push(AntiAffinity { zone: Some("w".into()), required: true, ..Default::default() });
        let p = preempt_for(&l, &RunId("run_w".into()), &spread, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        assert_eq!(p.victims, ["run_batch"]);
        // The victim hibernated; n1 reports the room. The run's own reservation is no box of zone w.
        l.run_ended(&RunId("run_batch".into()), "hibernated", "").unwrap();
        let mut after = cand("n1", 4.0, 4096, 3.0, 3072);
        after.at_ms = now + 10_000;
        let d = bind(&l, &RunId("run_w".into()), &spread, &[after.clone()], None, now + 11_000, true).unwrap().decision;
        assert_eq!(d.node.as_deref(), Some("n1"), "{}", d.why_not());
        // Another run of zone w does see it, and is kept off n1.
        let other = bind(&l, &RunId("run_w2".into()), &spread, &[after], None, now + 12_000, false).unwrap().decision;
        assert!(other.why_not().contains("runs a box of zone w"), "{}", other.why_not());
    }

    /// #579 step 4 (review): an agent asked to hibernate for room gets [`PREEMPT_DEADLINE`]. Until
    /// then the room stays held; once its run ends the preemption is done; past it, an agent still
    /// running is given up on: its request withdrawn, the room released, audited, and the wake
    /// chooses it no more. Nothing is revoked either way.
    #[test]
    fn a_victim_that_doesnt_hibernate_is_given_up_on_by_the_deadline() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = 98_000_000;
        let n1 = crowded(&mut l, now);
        let ask = asking("t0", 5);
        let run = RunId("run_new".into());
        let p = preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        // Within the deadline: waiting, the room renewed (a reservation lapses after RESERVE_SECS).
        let later = now + wicket_store::RESERVE_SECS * 1000 + 1;
        assert_eq!(settle_preemption(&l, &run, &ask, &p, now, later).unwrap(), Settled::Waiting);
        assert_eq!(l.held_on("n1", n1.at_ms, later + 1).unwrap(), (1.0, 1024), "still held past RESERVE_SECS");
        // Past the deadline, still running: given up on.
        let past = now + PREEMPT_DEADLINE.as_millis() as i64 + 1;
        assert_eq!(settle_preemption(&l, &run, &ask, &p, now, past).unwrap(), Settled::Abandoned(vec!["run_batch".into()]));
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want, None, "its hibernate request is withdrawn");
        assert!(l.revoked_in_chain("run_batch").unwrap().is_none());
        assert_eq!(l.placement("run_new").unwrap().unwrap().state, "released");
        let abandoned: Vec<_> =
            l.audit_records_after(0, 100).unwrap().into_iter().filter(|a| a.kind == "placement.preempt_abandoned").collect();
        assert_eq!((abandoned.len(), abandoned[0].run.as_deref()), (1, Some("run_batch")));
        // Spared for the rest of this wait: nothing else yields on n1, so nothing is chosen.
        assert!(preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), past, &["run_batch".to_string()], false).unwrap().is_none());

        // A victim whose run ends in time: done.
        let mut l = Ledger::open_in_memory().unwrap();
        let n1 = crowded(&mut l, now);
        let p = preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        l.run_ended(&RunId("run_batch".into()), "hibernated", "").unwrap();
        assert_eq!(settle_preemption(&l, &run, &ask, &p, now, now + 5_000).unwrap(), Settled::Done);
    }

    /// #579 step 4 (review): an agent with a live child is never preempted. Hibernating an agent
    /// stops its children (its run ends through `stop_children`), so it would take their work too.
    /// Once the child has ended, the agent may be.
    #[test]
    fn an_agent_with_a_live_child_is_never_preempted() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = 99_000_000;
        let n1 = crowded(&mut l, now);
        let t0 = wicket_core::TenantId("t0".into());
        l.run_started(&t0, &RunId("run_child".into()), "z-child", "c").unwrap();
        let identity = |run: &str, parent: Option<&str>| wicket_store::IdentityRow {
            run: run.into(),
            tenant: "t0".into(),
            spiffe_id: format!("spiffe://w.test/t/t0/z/z/a/{run}"),
            zone: "z".into(),
            agent: run.into(),
            parent_run: parent.map(String::from),
            accept_from: vec![],
            jws: "x".into(),
            issued_at: 1,
        };
        l.put_identity(&identity("run_batch", None)).unwrap();
        l.put_identity(&identity("run_child", Some("run_batch"))).unwrap();
        let ask = asking("t0", 5);
        assert!(
            preempt_for(&l, &RunId("run_new".into()), &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().is_none(),
            "run_batch has a live child, and nothing else yields"
        );
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want, None);
        assert_eq!(l.run_status("run_child").unwrap().as_deref(), Some("running"));
        // The child ended: run_batch may be preempted now.
        l.run_ended(&RunId("run_child".into()), "succeeded", "").unwrap();
        let p = preempt_for(&l, &RunId("run_new".into()), &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        assert_eq!(p.victims, ["run_batch"]);
    }

    /// #579 step 4 (review): a victim whose run has ended still counts as gone while the node's
    /// last report predates its end (that report still counts its box), so no second agent is asked
    /// to hibernate for the same room; a report from after its end shows the room itself.
    #[test]
    fn a_victim_that_has_ended_counts_as_gone_until_a_newer_report() {
        let mut l = Ledger::open_in_memory().unwrap();
        // Two preemptible agents on n1, so a second victim exists.
        let now = (wicket_store::now() - 10) * 1000;
        let mut n1 = crowded(&mut l, now);
        let t0 = wicket_core::TenantId("t0".into());
        l.run_started(&t0, &RunId("run_batch2".into()), "z", "a").unwrap();
        l.set_run_node("run_batch2", "n1").unwrap();
        l.record_run_terms("run_batch2", 1.0, 1024, 0, true, now).unwrap();
        l.create_agent(&wicket_store::NewAgent {
            id: "agt_batch2",
            tenant: "t0",
            zone: "z",
            name: "b2",
            run: "run_batch2",
            session_id: "s",
            manifest: "m",
            image: "img",
            workspace: None,
            claim_until: wicket_store::now() + 30,
        })
        .unwrap();
        let ask = asking("t0", 5);
        let run = RunId("run_new".into());
        let p = preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        assert_eq!(p.victims.len(), 1);
        let victim = p.victims[0].clone();
        // It hibernated: its run ended. n1's report is from before that, so still counts its box.
        l.run_ended(&RunId(victim.clone()), "hibernated", "").unwrap();
        l.placement_released(&run.0).unwrap();
        let later = now + 20_000;
        assert!(
            preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), later, &[], false).unwrap().is_none(),
            "the ended victim counts as gone: no second agent is asked"
        );
        let other = if victim == "run_batch" { "agt_batch2" } else { "agt_batch" };
        assert_eq!(l.agent(other).unwrap().unwrap().want, None);
        // A report from after its end: it shows the room (here, the box gone from the node's use).
        n1.at_ms = (wicket_store::now() + 5) * 1000;
        n1.cap.used_vcpus = 3.0;
        n1.cap.used_memory_mib = 3072;
        assert!(preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), later, &[], true).unwrap().is_none(), "it fits: nothing to stop");
    }

    /// #579 step 4 (review): giving up withdraws only preemption's own request. Its supervisor,
    /// which may have taken the request already, finds the mark cleared (`preemption_mark`, through
    /// `preempted_hibernate`) before it hibernates and drops it; an operator's own `wicket hibernate`
    /// is never withdrawn.
    #[test]
    fn giving_up_withdraws_only_preemptions_own_request() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = 98_500_000;
        let n1 = crowded(&mut l, now);
        let ask = asking("t0", 5);
        let run = RunId("run_new".into());
        let p = preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        assert!(l.preemption_pending("run_batch", "run_new", now).unwrap(), "what its supervisor checks");
        let past = now + PREEMPT_DEADLINE.as_millis() as i64 + 1;
        assert!(matches!(settle_preemption(&l, &run, &ask, &p, now, past).unwrap(), Settled::Abandoned(_)));
        assert!(!l.preemption_pending("run_batch", "run_new", now).unwrap(), "its supervisor drops the request it took");
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want, None);

        // An operator asked first: preemption doesn't replace that request, and giving up leaves it.
        let mut l = Ledger::open_in_memory().unwrap();
        let n1 = crowded(&mut l, now);
        assert!(l.want_agent("agt_batch", "hibernate").unwrap());
        let p = preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        assert_eq!(p.victims, ["run_batch"], "it hibernates anyway: the room counts");
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want.as_deref(), Some("hibernate"));
        settle_preemption(&l, &run, &ask, &p, now, past).unwrap();
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want.as_deref(), Some("hibernate"), "the operator's request stands");
    }

    /// #579 step 4 (review): a wake that stops waiting asks its victims no more. Given up (its
    /// `--wait` over), the room it held is released too; placed (anywhere), its new reservation stays.
    #[test]
    fn a_wake_that_stops_waiting_asks_its_victims_no_more() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = 98_700_000;
        let n1 = crowded(&mut l, now);
        let ask = asking("t0", 5);
        let run = RunId("run_new".into());
        preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        assert_eq!(end_wait(&l, &run, &ask, now + 1_000, false).unwrap(), ["run_batch"]);
        assert_eq!(l.placement("run_new").unwrap().unwrap().state, "released", "the room goes back");
        assert!(!l.preemption_pending("run_batch", "run_new", now).unwrap());
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want, None);
        let why: Vec<String> = l
            .audit_records_after(0, 100)
            .unwrap()
            .into_iter()
            .filter(|a| a.kind == "placement.preempt_abandoned")
            .map(|a| serde_json::from_str::<serde_json::Value>(&a.body).unwrap()["why"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(why, ["the wake gave up waiting"]);
        // No preemption pending: giving up still releases what it held.
        l.reserve_placement("run_x", "n1", 1.0, 1024, now).unwrap();
        assert!(end_wait(&l, &RunId("run_x".into()), &ask, now, false).unwrap().is_empty());
        assert_eq!(l.placement("run_x").unwrap().unwrap().state, "released");

        // Placed: the victims are asked no more, and its reservation stays.
        let mut l = Ledger::open_in_memory().unwrap();
        let n1 = crowded(&mut l, now);
        preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        l.reserve_placement("run_new", "n2", 1.0, 1024, now + 2).unwrap();
        assert_eq!(end_wait(&l, &run, &ask, now + 3, true).unwrap(), ["run_batch"]);
        assert_eq!(l.placement("run_new").unwrap().unwrap().state, "reserved");
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want, None);
    }

    /// #579 step 4 (review): the supervisor's decision, before it hibernates for a hibernate it was
    /// asked: an operator's or the agent's own always goes ahead; one only preemption asked for is
    /// declined when preemption gave up (no mark), the mark is stale or its wake is gone, or a child
    /// runs (hibernating would stop it). Checked at the quiet point and again out of a linger.
    #[test]
    fn the_supervisor_hibernates_for_preemption_only_while_it_is_still_wanted() {
        let now = 1_000_000_000;
        let mark =
            |asked_ms, asker_alive| wicket_store::PreemptMark { asked_ms, for_run: Some("run_w".into()), asker_alive, running_children: 0 };
        let fresh = mark(now - 1_000, true);
        assert_eq!(preempted_hibernate(true, Some(&fresh), 0, now), Ok(()), "still wanted");
        // An operator's (or the agent's own) hibernate goes ahead whatever preemption says.
        for m in [None, Some(&fresh)] {
            for kids in [0, 3] {
                assert_eq!(preempted_hibernate(false, m, kids, now), Ok(()), "the operator's request takes precedence");
            }
        }
        assert!(preempted_hibernate(true, None, 0, now).unwrap_err().contains("no longer needs it"), "withdrawn");
        let stale = mark(now - PREEMPT_DEADLINE.as_millis() as i64, true);
        assert!(preempted_hibernate(true, Some(&stale), 0, now).unwrap_err().contains("older than"), "stale");
        assert!(preempted_hibernate(true, Some(&mark(now - 1_000, false)), 0, now).unwrap_err().contains("gone"), "its wake died");
        assert!(preempted_hibernate(true, Some(&fresh), 1, now).unwrap_err().contains("child"), "a child spawned since");
        let seen = wicket_store::PreemptMark { running_children: 1, ..fresh.clone() };
        assert!(preempted_hibernate(true, Some(&seen), 0, now).unwrap_err().contains("child"), "one only the ledger knows of");
    }

    /// #579 step 4 (review): who a pending hibernate is for, through a linger. An operator's or
    /// the agent's own request is never handed back to preemption, so a withdrawal can't drop it.
    #[test]
    fn an_operators_hibernate_is_never_taken_for_preemptions() {
        // Preemption alone, through a linger and a turn that began in it: still preemption's.
        let mut h = HibAsk::default();
        h.ask(true);
        assert!(h.take());
        h.linger(true);
        h.turn_began_in_linger();
        assert_eq!(h, HibAsk { asked: true, for_preemption: true, ..Default::default() });
        h.decline();
        assert_eq!(h, HibAsk::default());

        // An operator asks during preemption's linger: the linger hibernates for the operator.
        for operator_first in [false, true] {
            let mut h = HibAsk::default();
            h.ask(true);
            let for_preemption = h.take();
            h.linger(for_preemption);
            if operator_first {
                h.ask(false);
                h.turn_began_in_linger();
            } else {
                h.ask(false);
            }
            assert!(!h.for_preemption, "the operator's request stands");
            assert!(!h.linger_over(), "and the linger is no longer preemption's");
        }

        // Preemption asks after an operator: still the operator's.
        let mut h = HibAsk::default();
        h.ask(false);
        h.ask(true);
        assert!(!h.take());
        // ...and through a linger begun while another request is already asked.
        let mut h = HibAsk::default();
        h.ask(true);
        let fp = h.take();
        h.ask(false);
        h.linger(fp);
        assert!(!h.linger_over());

        // Preemption asks again during its own linger: still preemption's.
        let mut h = HibAsk::default();
        h.ask(true);
        let fp = h.take();
        h.linger(fp);
        h.ask(true);
        h.turn_began_in_linger();
        assert!(h.for_preemption);

        // Preemption asks during an operator's linger: the linger is the operator's, and so is the
        // hibernate after a turn that began in it.
        let mut h = HibAsk::default();
        h.ask(false);
        let fp = h.take();
        h.linger(fp);
        h.ask(true);
        assert!(!h.for_preemption, "nothing to decline: the operator's hibernate goes ahead");
        h.turn_began_in_linger();
        assert!(!h.for_preemption);

        // Preemption's request declined while its own linger is on: the linger is checked again.
        let mut h = HibAsk::default();
        h.ask(true);
        let fp = h.take();
        h.linger(fp);
        h.ask(true);
        h.decline();
        assert!(!h.asked);
        assert!(h.linger_over(), "the linger re-checks before it hibernates");

        // The agent asks to finish: the linger ends, nothing for preemption is left.
        let mut h = HibAsk::default();
        h.ask(true);
        let fp = h.take();
        h.linger(fp);
        h.linger_ends();
        assert_eq!(h, HibAsk::default());
    }

    /// #579 step 4 (review): the ledger's side of that decision. The mark names the run it is for
    /// and whether that run is alive (waiting, or holding a reservation); a victim that declines
    /// (its mark cleared while it runs) is given up on by the wake at once, not at the deadline.
    #[test]
    fn a_victim_that_declines_is_given_up_on_at_once() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = (wicket_store::now() - 5) * 1000;
        let n1 = crowded(&mut l, now);
        let ask = asking("t0", 5);
        let run = RunId("run_new".into());
        let p = preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        let mark = l.preemption_mark("run_batch", now + 1).unwrap().unwrap();
        assert_eq!((mark.for_run.as_deref(), mark.asker_alive), (Some("run_new"), true), "it holds the room it reserved");
        assert_eq!(preempted_hibernate(true, Some(&mark), 0, now + 1), Ok(()));
        // Its reservation lapses and it doesn't wait: the wake is gone.
        l.placement_released("run_new").unwrap();
        assert!(!l.preemption_mark("run_batch", now + 1).unwrap().unwrap().asker_alive);
        l.reserve_placement("run_new", "n1", 1.0, 1024, now).unwrap();
        // The supervisor declines (a child spawned since, say): it clears the mark.
        assert!(!l.clear_preempted("run_batch", "run_other", None).unwrap(), "another wake's clear leaves this mark");
        assert!(!l.clear_preempted("run_batch", "run_new", Some(now - 1)).unwrap(), "so does an older request's");
        assert!(l.clear_preempted("run_batch", "run_new", Some(now)).unwrap());
        assert_eq!(settle_preemption(&l, &run, &ask, &p, now, now + 2_000).unwrap(), Settled::Declined(vec!["run_batch".into()]));
        assert_eq!(l.placement("run_new").unwrap().unwrap().state, "released");
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want, None);
    }

    /// #579 step 4 (review): one victim declining gives up on the whole plan, so no other victim
    /// hibernates for room that won't come; only the decliner is spared in this wait. And a later
    /// wake's request on a victim stands when an earlier wake gives up on it.
    #[test]
    fn a_decline_gives_up_on_the_whole_plan_and_spares_later_requests() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = (wicket_store::now() - 5) * 1000;
        let n1 = crowded(&mut l, now);
        let t0 = wicket_core::TenantId("t0".into());
        l.run_started(&t0, &RunId("run_batch2".into()), "z", "a").unwrap();
        l.set_run_node("run_batch2", "n1").unwrap();
        l.record_run_terms("run_batch2", 1.0, 1024, 0, true, now).unwrap();
        l.create_agent(&wicket_store::NewAgent {
            id: "agt_batch2",
            tenant: "t0",
            zone: "z",
            name: "agt_batch2",
            run: "run_batch2",
            session_id: "s",
            manifest: "m",
            image: "img",
            workspace: None,
            claim_until: wicket_store::now() + 30,
        })
        .unwrap();
        let mut ask = asking("t0", 5);
        (ask.req.vcpus, ask.req.memory_mib) = (2.0, 2048);
        let run = RunId("run_new".into());
        let p = preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        assert_eq!(p.victims, ["run_batch", "run_batch2"], "both are needed");
        // run_batch's supervisor declines: it clears its own mark.
        assert!(l.clear_preempted("run_batch", "run_new", Some(now)).unwrap());
        assert_eq!(settle_preemption(&l, &run, &ask, &p, now, now + 2_000).unwrap(), Settled::Declined(vec!["run_batch".into()]));
        assert!(l.preemption_mark("run_batch2", now + 2_000).unwrap().is_none(), "the other victim is asked no more");
        assert_eq!(l.agent("agt_batch2").unwrap().unwrap().want, None);
        assert_eq!(l.placement("run_new").unwrap().unwrap().state, "released");
        let why: Vec<String> = l
            .audit_records_after(0, 100)
            .unwrap()
            .into_iter()
            .filter(|a| a.kind == "placement.preempt_abandoned")
            .map(|a| serde_json::from_str::<serde_json::Value>(&a.body).unwrap()["why"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(why, ["it declined to hibernate", "another of the plan's boxes declined to hibernate"]);

        // A later wake asks run_batch2 after run_new's request went past its deadline: run_new
        // giving up on it leaves the later request, its mark and its hibernate request.
        let later = now + PREEMPT_DEADLINE.as_millis() as i64 + 1;
        l.want_agent_if_unasked("agt_batch2", PREEMPT_WANT).unwrap();
        l.mark_preempted("run_batch2", now, "run_new").unwrap();
        l.mark_preempted("run_batch2", later, "run_late").unwrap();
        abandon_preemption(&l, &run, &ask, &p, &["run_batch2".into()], now, later, "it didn't hibernate by the deadline", true).unwrap();
        let m = l.preemption_mark("run_batch2", later).unwrap().unwrap();
        assert_eq!((m.asked_ms, m.for_run.as_deref()), (later, Some("run_late")));
        assert_eq!(l.agent("agt_batch2").unwrap().unwrap().want.as_deref(), Some(PREEMPT_WANT), "the later request stands");
        assert!(end_wait(&l, &run, &ask, later, false).unwrap().is_empty(), "run_new has asked nothing of it since");
        assert_eq!(l.agent("agt_batch2").unwrap().unwrap().want.as_deref(), Some(PREEMPT_WANT));
    }

    /// #579 step 4 (review): a victim another wake has asked since isn't taken for a decline: the
    /// plan is given up on, the later wake's request stands, and the victim isn't spared.
    #[test]
    fn a_victim_another_wake_asked_since_is_no_decline() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = (wicket_store::now() - 5) * 1000;
        let n1 = crowded(&mut l, now);
        let ask = asking("t0", 5);
        let run = RunId("run_new".into());
        let p = preempt_for(&l, &run, &ask, std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        l.mark_preempted("run_batch", now + 1_000, "run_late").unwrap();
        assert_eq!(settle_preemption(&l, &run, &ask, &p, now, now + 2_000).unwrap(), Settled::Taken(vec!["run_batch".into()]));
        let m = l.preemption_mark("run_batch", now + 2_000).unwrap().unwrap();
        assert_eq!(m.for_run.as_deref(), Some("run_late"), "the later request stands");
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want.as_deref(), Some(PREEMPT_WANT));
        assert_eq!(l.placement("run_new").unwrap().unwrap().state, "released");
        let kinds: Vec<(String, String)> = l
            .audit_records_after(0, 100)
            .unwrap()
            .into_iter()
            .filter(|a| a.kind.starts_with("placement.preempt_"))
            .map(|a| (a.kind, serde_json::from_str::<serde_json::Value>(&a.body).unwrap()["why"].as_str().unwrap_or_default().to_string()))
            .collect();
        assert_eq!(kinds, [("placement.preempt_abandoned".to_string(), "another wake asked it to stop since".to_string())]);
    }

    /// #579 (review): a placed node that has ended counts by when it ended, by its latest record, so
    /// an enrolment that outlived it isn't taken for a node that was never placed.
    #[test]
    fn an_ended_placed_node_counts_as_past_its_lease() {
        let row =
            |id: &str, name: &str, created_at: i64, lease_until: i64, status: &str, ended_at: Option<i64>| wicket_store::PlacedNodeRow {
                id: id.into(),
                backend: "b".into(),
                name: name.into(),
                owner: "o".into(),
                api_key_secret: "k".into(),
                created_at,
                lease_until,
                status: status.into(),
                held_by: None,
                ended_at,
                detail: None,
                hourly: None,
            };
        let rows = [
            row("i1", "p1", 10, 5_000, "released", Some(900)),
            row("i2", "p2", 10, 5_000, "active", None),
            // p3 was placed, ended, and placed again: its latest lease counts.
            row("i3", "p3", 10, 1_000, "released", Some(800)),
            row("i4", "p3", 20, 9_000, "active", None),
        ];
        let placed = placed_leases(&rows);
        assert!(!lasts_for(&placed, "p1", 1_000, 60), "ended at 900: past its lease, though its node row may linger");
        assert!(lasts_for(&placed, "p2", 1_000, 60));
        assert!(lasts_for(&placed, "p3", 1_000, 60), "placed again");
        assert!(lasts_for(&placed, "n1", 1_000, 60), "never placed");
    }

    /// #579 (review): a placed node whose lease ends before the box would is no candidate.
    #[test]
    fn a_placed_node_is_a_candidate_only_while_its_lease_outlasts_the_box() {
        let placed = vec![("p1".to_string(), 1_000), ("p2".to_string(), 5_000)];
        assert!(lasts_for(&placed, "n1", 900, 3_600), "not placed: no lease to outlast");
        assert!(!lasts_for(&placed, "p1", 900, 3_600), "its lease ends before the box would");
        assert!(!lasts_for(&placed, "p1", 1_000, 0), "past its lease");
        assert!(lasts_for(&placed, "p2", 900, 3_600));
        assert!(!lasts_for(&placed, "p2", 900, 4_100), "ends exactly then: not outlasted");
    }

    /// #579 step 4 (review): a wake that fails, by any path, withdraws every preemption made for it.
    #[test]
    fn a_failed_wake_withdraws_its_preemptions() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = 98_900_000;
        let n1 = crowded(&mut l, now);
        let run = RunId("run_new".into());
        preempt_for(&l, &run, &asking("t0", 5), std::slice::from_ref(&n1), now, &[], false).unwrap().unwrap();
        assert_eq!(l.preempted_for("run_new").unwrap(), ["run_batch"]);
        let t0 = wicket_core::TenantId("t0".into());
        assert_eq!(withdraw_preemptions_for(&l, &run, &t0, now + 1, "the wake failed").unwrap(), ["run_batch"]);
        assert!(l.preempted_for("run_new").unwrap().is_empty());
        assert!(!l.preemption_pending("run_batch", "run_new", now).unwrap());
        assert_eq!(l.agent("agt_batch").unwrap().unwrap().want, None);
        assert_eq!(l.placement("run_new").unwrap().unwrap().state, "released");
    }

    /// #579 step 4 (review): a re-attach records a box's terms again without forgetting that
    /// preemption asked it to stop.
    #[test]
    fn recording_terms_again_keeps_when_preemption_asked() {
        let l = Ledger::open_in_memory().unwrap();
        let t0 = wicket_core::TenantId("t0".into());
        l.run_started(&t0, &RunId("r".into()), "z", "a").unwrap();
        l.set_run_node("r", "n1").unwrap();
        l.record_run_terms("r", 1.0, 1024, 0, true, 1).unwrap();
        l.mark_preempted("r", 42, "run_x").unwrap();
        l.record_run_terms("r", 1.0, 1024, 0, true, 2).unwrap();
        assert_eq!(l.preemption_view(1).unwrap()[0].preempted_at_ms, Some(42));
    }

    /// #579 step 4 (review): a run waiting ahead defers preemption only if it can be served (it fits
    /// now, or could itself make room); one that can't be served (a label no node has, or another
    /// tenant's that nothing of its own yields to) doesn't hold preemption up; another tenant's that
    /// could make room of its own does.
    #[test]
    fn only_a_waiter_that_can_be_served_defers_preemption() {
        let mut l = Ledger::open_in_memory().unwrap();
        let now = 96_000_000;
        let n1 = crowded(&mut l, now);
        let mut stuck = asking("t0", 900);
        stuck.req.node_selector.insert("gpu".into(), "a100".into());
        l.wait_for_placement("run_stuck", &serde_json::to_string(&stuck).unwrap(), now - 5_000).unwrap();
        // t2 has no box on n1 that would yield to it.
        l.wait_for_placement("run_other", &serde_json::to_string(&asking("t2", 1000)).unwrap(), now - 4_000).unwrap();
        let p = preempt_for(&l, &RunId("run_new".into()), &asking("t0", 5), std::slice::from_ref(&n1), now, &[], false).unwrap();
        assert_eq!(p.map(|p| p.victims), Some(vec!["run_batch".to_string()]), "neither waiter ahead can be served");

        // t1's waiter at 1000 could make room of its own (t1's preemptible agent at -5): it goes first.
        let mut l = Ledger::open_in_memory().unwrap();
        let n1 = crowded(&mut l, now);
        l.wait_for_placement("run_t1", &serde_json::to_string(&asking("t1", 1000)).unwrap(), now - 4_000).unwrap();
        assert!(preempt_for(&l, &RunId("run_new".into()), &asking("t0", 5), &[n1], now, &[], false).unwrap().is_none());

        // A waiter ahead that could make room itself (t0, priority 50) goes first.
        let mut l = Ledger::open_in_memory().unwrap();
        let n1 = crowded(&mut l, now);
        l.wait_for_placement("run_vip", &serde_json::to_string(&asking("t0", 50)).unwrap(), now - 5_000).unwrap();
        assert!(preempt_for(&l, &RunId("run_new".into()), &asking("t0", 5), &[n1], now, &[], false).unwrap().is_none());
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
