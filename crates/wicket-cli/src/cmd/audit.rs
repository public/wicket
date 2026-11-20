//! `wicket audit`: reading, verifying and exporting the audit log.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Audit { tail, verify, against, issuer_jwk, json, cmd } => {
            if json && cmd.is_some() {
                return Err(wicket_home::exit::usage(
                    "--json lists the audit records: not with export (`wicket audit export --status` shows the sinks)",
                ));
            }
            if let Some(AuditCmd::Compact { yes }) = cmd {
                return compact(yes);
            }
            if let Some(AuditCmd::Export { once, checkpoint, status }) = cmd {
                // The exporter blocks (its own runtime, file and HTTP writes): off the async runtime.
                return std::thread::spawn(move || audit_export_cmd(once, checkpoint, status))
                    .join()
                    .map_err(|_| anyhow::anyhow!("the audit exporter panicked"))?;
            }
            let l = Ledger::open(&ledger_path())?;
            if verify {
                let n = l.verify_audit()?;
                // After a prune (#582) the chain starts at a checkpoint a durable sink acknowledged:
                // its signature, and that it signed the record kept there, are checked first.
                let anchor = match l.audit_anchor()? {
                    Some(a) => {
                        let key = match &issuer_jwk {
                            Some(p) => wicket_identity::verifying_key_from_jwk(&serde_json::from_slice(&std::fs::read(p)?)?)?,
                            None => issuer()?.verifying_key(),
                        };
                        audit_export::verify_anchor(&l, &key)?;
                        Some(a)
                    }
                    None => None,
                };
                println!("audit chain OK: {n} records");
                if let Some(a) = anchor {
                    println!(
                        "  from its anchor at seq {} (a signed checkpoint sink {} acknowledged): {} older record(s) pruned here, kept in the sinks",
                        a.seq, a.sink, a.pruned
                    );
                }
                let (ok, bad) = verify_signed_decisions(&l)?;
                println!("passkey-signed decisions and console actions: {ok} verified offline, {bad} failed");
                let (iok, ibad) = verify_identities_and_messages(&l)?;
                println!("agent identities and signed messages: {iok} verified offline, {ibad} failed");
                for n in l.verify_node_audit()? {
                    let restarts =
                        if n.restarts > 0 { format!(" ({} restart(s): the node's data was wiped)", n.restarts) } else { String::new() };
                    println!("node {} audit chain OK: {} records shipped{restarts}", n.node, n.records);
                }
                let mut against_bad = 0;
                if !against.is_empty() {
                    let key = match &issuer_jwk {
                        Some(p) => wicket_identity::verifying_key_from_jwk(&serde_json::from_slice(&std::fs::read(p)?)?)?,
                        None => issuer()?.verifying_key(),
                    };
                    let mut objs = Vec::new();
                    for p in &against {
                        // `store:<sink>`: what that sink wrote to the state store (#154).
                        match p.to_str().and_then(|s| s.strip_prefix("store:")) {
                            Some(sink) => objs.extend(audit_export::stored_objects(sink)?),
                            None => objs.extend(audit_export::exported_objects(
                                &std::fs::read_to_string(p).with_context(|| p.display().to_string())?,
                            )),
                        }
                    }
                    let a = audit_export::verify_against(&l, &objs, &key)?;
                    println!("against the exported copies: {} signed checkpoint(s) and {} record(s) match", a.checkpoints, a.records);
                    if a.pruned > 0 {
                        println!("  ({} exported from before the local anchor, pruned here by retention: not compared)", a.pruned);
                    }
                    if a.superseded > 0 {
                        println!("  ({} exported before a restore to an earlier point, which discarded them: not compared)", a.superseded);
                    }
                    for p in a.problems.iter().take(20) {
                        println!("  MISMATCH: {p}");
                    }
                    if a.checkpoints == 0 && a.records > 0 {
                        println!("  (no signed checkpoints found: only exported records were compared)");
                    }
                    against_bad = a.problems.len();
                }
                if bad + ibad > 0 {
                    bail!("{} record(s) failed verification", bad + ibad);
                }
                if against_bad > 0 {
                    bail!("the local audit chain does not match its exported copies ({against_bad} problem(s)): it was rewritten or truncated here");
                }
                return Ok(());
            }
            let rows = l.audit_tail(tail)?;
            if json {
                return crate::cmd::print_json(&audit_records_json(rows));
            }
            if rows.is_empty() {
                println!("no audit records yet");
            }
            for (seq, ts, kind, run, body) in rows {
                println!("{seq:>6} {ts} {kind:<9} {} {body}", run.unwrap_or_else(|| "-".into()));
            }
            Ok(())
        }
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

/// `wicket audit --json`: the records, oldest first, as the text lists them.
pub(crate) fn audit_records_json(rows: Vec<wicket_store::AuditRow>) -> serde_json::Value {
    serde_json::Value::Array(rows.into_iter().map(audit_json).collect())
}

/// One record of `wicket audit --json`: its body as the JSON it was written as (a body that isn't
/// JSON, from an older ledger, as a string).
fn audit_json((seq, ts, kind, run, body): wicket_store::AuditRow) -> serde_json::Value {
    let body = serde_json::from_str(&body).unwrap_or(serde_json::Value::String(body));
    serde_json::json!({ "seq": seq, "ts": ts, "kind": kind, "run": run, "body": body })
}

/// `wicket audit compact`: switches the ledger to `auto_vacuum = incremental` with one `VACUUM`
/// (#582), so audit retention gives pruned space back to the file system from then on. The whole
/// file is rewritten under an exclusive lock, so wicket's services must be stopped (a reconcile
/// pass, the console or a run writing would wait past their budget); it needs as much free space
/// again as the file, and takes about a minute per 2.5 GB.
fn compact(yes: bool) -> Result<()> {
    // Nothing else of wicket's may be writing: a VACUUM holds the write lock for about a minute per
    // 2.5 GB, past what the audit writer waits (#582 re-review N3).
    for (role, unit) in [("daemon", "wicketd"), ("console", "wicket-console"), ("reconcile", "wicket-reconcile")] {
        if pid_alive(&crate::update::pidfile(role)) {
            bail!("{unit} is running: stop it first (sudo systemctl stop wicketd wicket-console wicket-reconcile), then run this as the wicket user");
        }
    }
    if std::os::unix::net::UnixStream::connect(crate::daemon::SOCKET_PATH).is_ok() {
        bail!("wicketd is listening on {}: stop it first (sudo systemctl stop wicketd)", crate::daemon::SOCKET_PATH);
    }
    // No reconcile pass meanwhile, on this host: one running now is a reason to stop, not wait.
    let Some(_lock) = crate::reconcile::Lock::try_take()? else {
        bail!("a reconcile pass is running (it holds reconcile.lock): stop wicket-reconcile, or try again once it ends");
    };
    let path = ledger_path();
    let dir = path.parent().unwrap_or(std::path::Path::new("/")).to_path_buf();
    // SQLite's temporary copy goes beside the ledger, not in a small /tmp. Set before any
    // connection of this process opens: it is read when SQLite first needs a temporary file.
    std::env::set_var("SQLITE_TMPDIR", &dir);
    let l = Ledger::open(&path)?;
    if l.auto_vacuum_incremental()? {
        println!("{}: already gives pruned space back (auto_vacuum = incremental): nothing to do", path.display());
        return Ok(());
    }
    let size = l.file_bytes()?;
    let free = free_bytes(&dir)?;
    if free < 2 * size {
        bail!(
            "compacting needs about twice the ledger's size free beside it ({} MB, for the copy and its WAL): {} MB is free in {}",
            2 * size / 1_000_000,
            free / 1_000_000,
            dir.display()
        );
    }
    println!(
        "compacting {} ({} MB): one VACUUM, about a minute per 2.5 GB, holding the ledger exclusively.",
        path.display(),
        size / 1_000_000
    );
    if !yes && !confirm("compact now?")? {
        bail!("not compacted");
    }
    let t = std::time::Instant::now();
    // The exclusive lock is asked for without waiting: another writer (a run, a `wicket` command)
    // refuses it at once. (Opening the ledger above waited at most its 5 s busy timeout.)
    l.compact_exclusively().map_err(|e| {
        anyhow::anyhow!("{e}: another process has the ledger open for writing (a run or a wicket command): stop it and try again")
    })?;
    println!("compacted in {:.1} s: {} MB now", t.elapsed().as_secs_f64(), l.file_bytes()? / 1_000_000);
    Ok(())
}

/// Whether the process a pid file names is running, and is wicket: a pid a stale file names may
/// have been reused by something else since.
fn pid_alive(pidfile: &std::path::Path) -> bool {
    std::fs::read_to_string(pidfile).ok().and_then(|s| s.trim().parse::<i32>().ok()).is_some_and(is_wicket)
}

/// Whether process `pid` runs a wicket binary: its executable's name, or failing that (another
/// user's process, whose `exe` can't be read) its command line's first word. A thread's id isn't a
/// process: `/proc` answers for it too, with its process's executable, but a pid file never names
/// one (a stale file's number may have gone to a thread of some wicket since, #663).
fn is_wicket(pid: i32) -> bool {
    let tgid = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Tgid:").and_then(|v| v.trim().parse::<i32>().ok())));
    if tgid != Some(pid) {
        return false;
    }
    let named = |p: &std::path::Path| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("wicket"));
    if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
        // A binary replaced by an update reads as "<path> (deleted)".
        let exe = std::path::PathBuf::from(exe.to_string_lossy().trim_end_matches(" (deleted)").to_string());
        return named(&exe);
    }
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|c| c.split(|b| *b == 0).next().map(|a| std::path::PathBuf::from(String::from_utf8_lossy(a).into_owned())))
        .is_some_and(|a| named(&a))
}

/// Bytes free on the file system holding `dir`.
fn free_bytes(dir: &std::path::Path) -> Result<i64> {
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: statvfs fills `st`; `c` is a NUL-terminated path.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).context("statvfs");
    }
    Ok((st.f_bavail as i64).saturating_mul(st.f_frsize as i64))
}

#[derive(Subcommand)]
pub enum AuditCmd {
    /// Switch the ledger to giving pruned audit space back (`auto_vacuum = incremental`), with one
    /// VACUUM (#582). Run it as the wicket user with wicketd, the console and the reconciler
    /// stopped: the whole file is rewritten under an exclusive lock (about a minute per 2.5 GB),
    /// and it needs as much free space again beside the ledger. Ledgers made by this build don't
    /// need it.
    Compact {
        /// Don't ask for confirmation at a terminal.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Feed the sinks in the sinks file (`audit-sinks.yaml` in the data dir, or
    /// $WICKET_AUDIT_SINKS) until stopped. Runs alongside `wicket run` and `wicket serve`, which
    /// feed the sinks too; each sink is fed by one process at a time. The only process that writes
    /// to a `path: "-"` (stdout) sink.
    Export {
        /// One pass, then exit (non-zero if a sink failed).
        #[arg(long)]
        once: bool,
        /// Send every sink a checkpoint now.
        #[arg(long)]
        checkpoint: bool,
        /// Show each sink's position and last error.
        #[arg(long)]
        status: bool,
    },
}

pub(crate) fn audit_export_cmd(once: bool, checkpoint: bool, status: bool) -> Result<()> {
    let cfg = audit_export::SinksConfig::load()?
        .with_context(|| format!("no audit sinks configured ({} does not exist)", audit_export::sinks_path().display()))?;
    if status {
        let l = Ledger::open(&ledger_path())?;
        for s in audit_export::status(&l, &cfg, wicket_store::now())? {
            println!("{}", audit_export::status_line(&s, wicket_store::now()));
        }
        return Ok(());
    }
    let issuer = match issuer() {
        Ok(i) => Some(i),
        Err(e) => {
            eprintln!("wicket: no issuer key ({e}): exporting records without checkpoints");
            None
        }
    };
    let mut x = audit_export::Exporter::new(&ledger_path(), cfg, issuer)?;
    x.stdout = true;
    let mut force = checkpoint;
    loop {
        let p = x.pass(force);
        force = false;
        for (sink, e) in &p.failures {
            eprintln!("wicket: audit sink {sink}: {e}");
        }
        if once {
            for sink in &p.busy {
                eprintln!("wicket: audit sink {sink} is fed by another wicket process (see --status); left to it");
            }
        }
        if once {
            if !p.failures.is_empty() {
                bail!("{} sink(s) failed", p.failures.len());
            }
            eprintln!("exported {} record(s) and {} checkpoint(s)", p.records, p.checkpoints);
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Verifies every issued identity (at its issue time) and every stored envelope (at its send time).
pub(crate) fn verify_identities_and_messages(l: &Ledger) -> Result<(usize, usize)> {
    let (mut ok, mut bad) = (0, 0);
    let key = issuer()?.verifying_key();
    // Every document ever issued, rotations included, each at its own issue time (plus current
    // documents from ledgers that predate the history table).
    let mut docs = l.identity_history()?;
    for row in l.identities()? {
        if !docs.iter().any(|(_, j, _)| j == &row.jws) {
            docs.push((row.run.clone(), row.jws.clone(), row.issued_at));
        }
    }
    for (run, jws, at) in docs {
        match wicket_identity::verify_identity(&jws, &key, at) {
            Ok(c) if c.run == run => ok += 1,
            Ok(_) => {
                println!("  identity of {run} issued at {at}: FAILED: names another run");
                bad += 1;
            }
            Err(e) => {
                println!("  identity of {run} issued at {at}: FAILED: {e}");
                bad += 1;
            }
        }
    }
    for (id, env, at) in l.envelopes()? {
        // Each message at the time wicket recorded it: the sender's identity must have been valid then.
        match wicket_identity::verify_envelope(&env, &key, at) {
            Ok((_, p)) if p.get("jti").and_then(|j| j.as_str()) == Some(id.as_str()) => ok += 1,
            Ok(_) => {
                println!("  message {id}: FAILED: id does not match its envelope");
                bad += 1;
            }
            Err(e) => {
                println!("  message {id}: FAILED: {e}");
                bad += 1;
            }
        }
    }
    Ok((ok, bad))
}

/// Re-verifies every passkey-signed record in the audit log (decisions and the console's other
/// actions) from the stored public keys alone: the signature must cover exactly what was recorded.
pub(crate) fn verify_signed_decisions(l: &Ledger) -> Result<(usize, usize)> {
    use crate::webauthn::{decision_challenge, unb64u, Credential, RelyingParty};
    let keys = l.operator_credentials_all(&TenantId::single())?;
    let (mut ok, mut bad) = (0, 0);
    for (seq, _, kind, run, body) in l.audit_tail(usize::MAX >> 1)? {
        let v: serde_json::Value = serde_json::from_str(&body)?;
        let Some(s) = v.get("signed") else { continue };
        let get = |k: &str| s.get(k).and_then(|x| x.as_str()).unwrap_or("");
        let result = (|| -> Result<()> {
            let key = keys.iter().find(|k| k.id == get("credential")).ok_or_else(|| anyhow::anyhow!("unknown credential"))?;
            let rp = RelyingParty { rp_id: get("rp_id").into(), origin: get("origin").into() };
            let signed_json = if kind == "decision" { get("decision_json") } else { get("action_json") };
            let challenge = decision_challenge(&unb64u(get("nonce"))?, signed_json);
            let decided: serde_json::Value = serde_json::from_str(signed_json)?;
            // The record must say what was signed: the same request and decision, or the same action
            // on the same run (and, for a started run, the same manifest bytes).
            let same = |k: &str| decided.get(k) == v.get(k);
            let matches = if kind == "decision" {
                same("request") && same("decision")
            } else {
                same("action")
                    && same("run")
                    && run.as_deref() == decided.get("run").and_then(|r| r.as_str())
                    && (kind != "run.console_start" || (same("manifest_sha256") && same("principal") && same("task")))
                    && (kind != "manifest.saved" || (same("name") && same("sha256") && same("previous_sha256")))
                    && (!kind.starts_with("operator.push_") || (same("device") && same("details") && same("credential")))
            };
            if !matches {
                bail!("record does not match the signed {}", if kind == "decision" { "decision" } else { "action" });
            }
            let cred = Credential { id: unb64u(&key.id)?, x: key.x, y: key.y, sign_count: 0 };
            rp.verify_assertion(
                &challenge,
                &cred,
                &unb64u(get("client_data_json"))?,
                &unb64u(get("authenticator_data"))?,
                &unb64u(get("signature"))?,
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => ok += 1,
            Err(e) => {
                println!("  seq {seq}: FAILED: {e}");
                bad += 1;
            }
        }
    }
    Ok((ok, bad))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #677 third check: a pid file names a running wicket only if the pid runs a wicket binary
    /// (a stale file's pid may be something else's now).
    #[test]
    fn a_pid_counts_only_if_it_is_wickets() {
        assert!(is_wicket(std::process::id() as i32), "this test binary is wicket_cli-…");
        let mut other = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = other.id() as i32;
        // Once it runs sleep (its name says so), whatever the machine's timing.
        let comm = || std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        for _ in 0..250 {
            if comm().trim() == "sleep" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let seen = format!(
            "exe {:?}, cmdline {:?}, comm {:?}",
            std::fs::read_link(format!("/proc/{pid}/exe")),
            std::fs::read(format!("/proc/{pid}/cmdline")).map(|c| String::from_utf8_lossy(&c).into_owned()),
            comm()
        );
        assert!(!is_wicket(pid), "sleep isn't wicket: {seen}");
        let _ = other.kill();
        let _ = other.wait();
        // A thread of this process answers in /proc with this binary, but isn't a process.
        let (tx, rx) = std::sync::mpsc::channel();
        let (go, wait) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            // SAFETY: a plain syscall.
            tx.send(unsafe { libc::gettid() }).unwrap();
            let _ = wait.recv();
        });
        let tid = rx.recv().unwrap();
        assert!(std::fs::read_link(format!("/proc/{tid}/exe")).is_ok(), "a thread's id answers in /proc");
        assert!(!is_wicket(tid), "a thread of wicket isn't a wicket process");
        go.send(()).unwrap();
        t.join().unwrap();
        let dir = std::env::temp_dir().join(format!("wicket-pid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.pid");
        std::fs::write(&f, std::process::id().to_string()).unwrap();
        assert!(pid_alive(&f));
        std::fs::write(&f, "1").unwrap();
        assert_eq!(pid_alive(&f), is_wicket(1));
        let _ = std::fs::remove_file(&f);
        let _ = std::fs::remove_dir(&dir);
    }
}
