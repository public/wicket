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
use wicket_store::sealed::SealedStore;
use wicket_store::{AgentRow, Ledger};

/// How long a holder's claim on an agent lasts without renewal (seconds). The supervisor renews it
/// every few seconds; a waker may take over an agent whose holder let it lapse.
pub const LEASE_SECS: i64 = 30;

/// The claim held across the steps no heartbeat covers (a waker restoring and starting the box, a
/// supervisor pushing the state): long enough for a big bundle, after which a crashed holder's agent
/// can be woken again.
pub const BUSY_LEASE_SECS: i64 = 900;

/// The object store agent state goes to, sealed under `state.key`: the installation's S3-compatible
/// store if `state-store.yaml` puts bundles there (#154), or a directory under wicket's data dir.
pub fn store() -> Result<SealedStore<Box<dyn wicket_store::objects::ObjectStore>>> {
    let inner: Box<dyn wicket_store::objects::ObjectStore> = match crate::statestore::StateStore::load()? {
        Some(s) if s.bundles == crate::statestore::Where::S3 => Box::new(s.open_s3()?),
        _ => Box::new(DirStore::new(data_dir().join("objects"))),
    };
    Ok(SealedStore::new(inner, &state_key()?))
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
    getrandom::getrandom(&mut k).map_err(|e| anyhow::anyhow!("random: {e}"))?;
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
/// command, `agent`: an ACP agent's, #66). Err: what else runs.
pub fn quiet(procs: &[(u32, u32, String)], harness: &dyn Fn(&str) -> bool, agent: &[String]) -> std::result::Result<(), Vec<String>> {
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
        matches!(base, "docker-init" | "tini" | "wicket-fwd" | "wicket-entry")
            || (matches!(base, "bash" | "sh") && second == "wicket-entry")
            || harness(cmd)
            // The agent's own command, as started (a script's interpreter runs it with its path).
            || (!agent0.is_empty() && (line == agent_line || (matches!(base, "node" | "python3" | "python" | "sh" | "bash") && second == agent0)))
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

/// Pushes an activation's trees as the agent's next bundle and commits it in the ledger. Returns the
/// manifest, or None if this activation was superseded (its push is refused; the objects it wrote
/// are orphans for GC).
pub fn push(
    ledger: &std::sync::Mutex<Ledger>,
    agent: &AgentRow,
    generation: i64,
    trees: &[(String, PathBuf, &[&str])],
) -> Result<Option<StateManifest>> {
    let store = store()?;
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

/// Reads a box's typed output file, `<root>/workspace/out/result.json`, without trusting the box:
/// no component under `root` is followed if it is a symlink, the file must be a regular file of
/// at most `max` bytes, and at most `max + 1` bytes are read. Anything else is "no result".
pub fn read_outbox(root: &Path, max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let open_at = |dir: libc::c_int, name: &str, flags: libc::c_int| -> Option<OwnedFd> {
        let c = std::ffi::CString::new(name).ok()?;
        let fd = unsafe { libc::openat(dir, c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
    };
    let c = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()).ok()?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    let mut dir = unsafe { OwnedFd::from_raw_fd(fd) };
    for d in ["workspace", "out"] {
        dir = open_at(dir.as_raw_fd(), d, libc::O_RDONLY | libc::O_DIRECTORY)?;
    }
    // O_NONBLOCK so a FIFO can't block the open; it is then refused as not a regular file.
    let f = open_at(dir.as_raw_fd(), "result.json", libc::O_RDONLY | libc::O_NONBLOCK)?;
    let f = std::fs::File::from(f);
    let m = f.metadata().ok()?;
    if !m.file_type().is_file() || m.len() > max as u64 {
        return None;
    }
    let mut b = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut b).ok()?;
    (b.len() <= max).then_some(b)
}

/// Writes a file wicket owns at `root/rel`, where the tree under `root` may be agent-written:
/// every directory on the way is made a real directory (a symlink there is replaced), and the
/// file itself is created new with `write_new`, mode 0600.
pub fn write_owned(root: &Path, rel: &str, body: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let rel = Path::new(rel);
    anyhow::ensure!(
        rel.components().all(|c| matches!(c, std::path::Component::Normal(_))),
        "{} is not a plain relative path",
        rel.display()
    );
    let mut d = root.to_path_buf();
    real_dirs(std::slice::from_ref(&d))?;
    if let Some(parent) = rel.parent() {
        for c in parent.components() {
            d.push(c);
            real_dirs(std::slice::from_ref(&d))?;
        }
    }
    let p = root.join(rel);
    write_new(&p, &[])?;
    let mut f = std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW).open(&p)?;
    std::fs::File::set_permissions(&f, std::fs::Permissions::from_mode(0o600))?;
    std::io::Write::write_all(&mut f, body)?;
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
    bundle::pull_tree(&store()?, t, dest).with_context(|| format!("restoring {name}"))?;
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
    let Ok(exe) = crate::update::self_exe() else { return };
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
        (l.agent(&a.id)?.expect("claimed"), generation, run, first, last_node)
    };
    // The agent's state is its bundle, here, so it can wake on any node: bin-packed into the nodes
    // available now, by its zone's limits.
    let node = match place(&agent, last_node.as_deref()).await {
        Ok(n) => n,
        Err(e) => {
            let l = Ledger::open(&ledger_path())?;
            l.release_failed_wake(&agent.id, generation, &format!("wake failed: {e:#}"))?;
            return Err(e);
        }
    };
    let node = node.filter(|n| n != crate::localnode::NAME);
    println!("[wicket] waking agent {} ({}): generation {generation}, run {run}", agent.id, agent.name);
    let res = async {
        let t0 = std::time::Instant::now();
        let state = bundle::read_manifest(&store()?, agent.head.as_deref().expect("checked"), &agent.id)?;
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
}

/// Best fit: of the nodes with room for `want` (vCPUs, MiB), the one left with the least memory free
/// once it is placed (then the fewest vCPUs free; then `last`, where the agent ran before; then the
/// name). With room nowhere, the node with the most memory free, and false.
pub fn pick(cands: &[Candidate], want: (f32, u64), last: Option<&str>) -> Option<(String, bool)> {
    let free = |c: &Candidate| (c.cap.vcpus - c.cap.used_vcpus, c.cap.memory_mib as i64 - c.cap.used_memory_mib as i64);
    let fits = |c: &&Candidate| {
        let (cpu, mem) = free(c);
        cpu + 1e-3 >= want.0 && mem >= want.1 as i64
    };
    let key = |c: &Candidate| {
        let (cpu, mem) = free(c);
        (mem - want.1 as i64, ((cpu - want.0) * 1000.0) as i64, Some(c.name.as_str()) != last, c.name.clone())
    };
    if let Some(best) = cands.iter().filter(fits).min_by_key(|c| key(c)) {
        return Some((best.name.clone(), true));
    }
    cands.iter().max_by_key(|c| (free(c).1, std::cmp::Reverse(c.name.clone()))).map(|c| (c.name.clone(), false))
}

/// Where a woken agent's box goes: every enrolled, active node that answers within 10 s (this host's
/// own among them) and isn't held by a capacity lease, bin-packed ([`pick`]).
async fn place(agent: &AgentRow, last: Option<&str>) -> Result<Option<String>> {
    let m = Manifest::from_yaml(&agent.manifest)?;
    let want = (m.zone.limits.cpus, m.zone.limits.memory_bytes().unwrap_or(0) >> 20);
    let ledger = std::sync::Arc::new(std::sync::Mutex::new(Ledger::open(&ledger_path())?));
    crate::localnode::ensure(&ledger).await?;
    let (names, leased) = {
        let l = ledger.lock().expect("ledger");
        let names: Vec<String> = l.nodes()?.into_iter().filter(|n| n.status == "active").map(|n| n.name).collect();
        let leased: Vec<String> = l.leases(wicket_store::LIVE_LEASES)?.into_iter().filter_map(|x| x.node_name).collect();
        (names, leased)
    };
    let probes = names.into_iter().filter(|n| !leased.contains(n)).map(|n| {
        let ledger = ledger.clone();
        async move {
            let r = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                crate::nodecall::Link::connect(&n, &format!("place:{}", std::process::id()), &ledger),
            )
            .await;
            match r {
                Ok(Ok(link)) => link.capacity.map(|cap| Candidate { name: n, cap }),
                Ok(Err(e)) => {
                    println!("[wicket] node {n} is not available for the wake: {e:#}");
                    None
                }
                Err(_) => {
                    println!("[wicket] node {n} is not available for the wake: no answer within 10 s");
                    None
                }
            }
        }
    });
    let cands: Vec<Candidate> = futures_util::future::join_all(probes).await.into_iter().flatten().collect();
    match pick(&cands, want, last) {
        Some((n, true)) => {
            println!("[wicket] placing agent {} on node {n} (best fit of {} available)", agent.id, cands.len());
            Ok(Some(n))
        }
        Some((n, false)) => {
            println!(
                "[wicket] no available node has room for agent {} ({} vCPU, {} MiB free needed): placing it on {n}, the least loaded",
                agent.id, want.0, want.1
            );
            Ok(Some(n))
        }
        None => Ok(None),
    }
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
        bail!("agent {} is {}: only an active agent can be hibernated", a.id, a.state);
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
            "active"
                if now.want.is_none()
                    && now.updated_at >= before
                    && now.note.as_deref().is_some_and(|n| n.starts_with("not hibernated")) =>
            {
                println!("agent {} goes on running: {}", a.id, now.note.unwrap_or_default());
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

/// The bytes `dir` takes on disk (allocated blocks, so a sparse file counts as what it uses).
/// Symlinks aren't followed. What a node measures a box's /tmp with, against its cap.
pub fn used_bytes(dir: &Path) -> u64 {
    fn walk(d: &Path, total: &mut u64) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                walk(&e.path(), total);
            } else {
                use std::os::unix::fs::MetadataExt;
                *total += m.blocks() * 512;
            }
        }
    }
    let mut total = 0;
    walk(dir, &mut total);
    total
}

#[cfg(test)]
mod outbox_tests {
    use super::{read_outbox, write_owned};
    use std::os::unix::fs::symlink;

    fn root(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-outbox-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("workspace/out")).unwrap();
        d
    }

    #[test]
    fn a_plain_result_is_read() {
        let d = root("plain");
        std::fs::write(d.join("workspace/out/result.json"), b"{\"ok\":1}").unwrap();
        assert_eq!(read_outbox(&d, 64).as_deref(), Some(&b"{\"ok\":1}"[..]));
        std::fs::write(d.join("workspace/out/result.json"), vec![b' '; 65]).unwrap();
        assert_eq!(read_outbox(&d, 64), None, "too big");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A box can't make the host read some other file through its outbox.
    #[test]
    fn links_and_special_files_are_not_followed() {
        let d = root("links");
        let secret = d.join("secret.json");
        std::fs::write(&secret, b"{\"token\":\"x\"}").unwrap();
        symlink("../../secret.json", d.join("workspace/out/result.json")).unwrap();
        assert_eq!(read_outbox(&d, 64), None, "file link");
        std::fs::remove_file(d.join("workspace/out/result.json")).unwrap();
        std::fs::create_dir_all(d.join("elsewhere")).unwrap();
        std::fs::copy(&secret, d.join("elsewhere/result.json")).unwrap();
        std::fs::remove_dir(d.join("workspace/out")).unwrap();
        symlink("../elsewhere", d.join("workspace/out")).unwrap();
        assert_eq!(read_outbox(&d, 64), None, "directory link");
        std::fs::remove_file(d.join("workspace/out")).unwrap();
        std::fs::create_dir(d.join("workspace/out")).unwrap();
        symlink("/dev/zero", d.join("workspace/out/result.json")).unwrap();
        assert_eq!(read_outbox(&d, 64), None, "device link");
        std::fs::remove_file(d.join("workspace/out/result.json")).unwrap();
        let fifo = std::ffi::CString::new(d.join("workspace/out/result.json").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(read_outbox(&d, 64), None, "fifo");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Restored state can't redirect wicket's own writes onto a host file.
    #[test]
    fn owned_writes_replace_links() {
        let d = root("owned");
        let victim = d.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let st = d.join("state");
        std::fs::create_dir_all(st.join("claude")).unwrap();
        symlink(&victim, st.join("claude/.credentials.json")).unwrap();
        std::fs::create_dir_all(d.join("vdir")).unwrap();
        symlink(d.join("vdir"), st.join("launcher")).unwrap();
        write_owned(&st, "claude/.credentials.json", b"placeholder").unwrap();
        write_owned(&st, "launcher/file0", b"prompt").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(std::fs::read_dir(d.join("vdir")).unwrap().next().is_none());
        assert_eq!(std::fs::read(st.join("claude/.credentials.json")).unwrap(), b"placeholder");
        assert!(std::fs::symlink_metadata(st.join("launcher")).unwrap().is_dir());
        assert!(write_owned(&st, "../x", b"").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod tests {
    fn cand(name: &str, vcpus: f32, mem: u64, used_cpu: f32, used_mem: u64) -> Candidate {
        Candidate {
            name: name.into(),
            cap: crate::chan::NodeCapacity { vcpus, memory_mib: mem, used_vcpus: used_cpu, used_memory_mib: used_mem, boxes: 0 },
        }
    }

    /// Wake placement is best fit: the fullest node the box still fits on; where it ran before only
    /// breaks ties, and with room nowhere the least loaded node is used.
    #[test]
    fn a_woken_agent_is_bin_packed_onto_the_fullest_node_it_fits() {
        let nodes = [cand("local", 4.0, 8192, 1.0, 1024), cand("n1", 2.0, 2048, 0.0, 512), cand("n2", 2.0, 4096, 1.5, 3000)];
        assert_eq!(pick(&nodes, (1.0, 1024), None), Some(("n1".into(), true)), "n2 has no vCPU, local more room than n1");
        assert_eq!(pick(&nodes, (0.5, 1024), None), Some(("n2".into(), true)), "n2 fits and is fullest");
        assert_eq!(pick(&nodes, (1.0, 1024), Some("local")), Some(("n1".into(), true)), "where it ran before doesn't beat a better fit");
        let twins = [cand("a", 2.0, 2048, 0.0, 0), cand("b", 2.0, 2048, 0.0, 0)];
        assert_eq!(pick(&twins, (1.0, 512), Some("b")), Some(("b".into(), true)), "it breaks a tie");
        assert_eq!(pick(&nodes, (8.0, 65536), None), Some(("local".into(), false)), "no room: the least loaded");
        assert_eq!(pick(&[], (1.0, 1), None), None);
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
        assert!(used_bytes(&d) <= 1 << 20);
        assert!(used_bytes(&d) > 16 * 1024);
        let _ = std::fs::remove_dir_all(&d);
    }
}
