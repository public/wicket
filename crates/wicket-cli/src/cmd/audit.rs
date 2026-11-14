//! `wicket audit`: reading, verifying and exporting the audit log.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Audit { tail, verify, against, issuer_jwk, cmd } => {
            if let Some(AuditCmd::Export { once, checkpoint, status }) = cmd {
                // The exporter blocks (its own runtime, file and HTTP writes): off the async runtime.
                return std::thread::spawn(move || audit_export_cmd(once, checkpoint, status))
                    .join()
                    .map_err(|_| anyhow::anyhow!("the audit exporter panicked"))?;
            }
            let l = Ledger::open(&ledger_path())?;
            if verify {
                println!("audit chain OK: {} records", l.verify_audit()?);
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
            for (seq, ts, kind, run, body) in l.audit_tail(tail)? {
                println!("{seq:>6} {ts} {kind:<9} {} {body}", run.unwrap_or_else(|| "-".into()));
            }
            Ok(())
        }
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

#[derive(Subcommand)]
pub enum AuditCmd {
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
        let head = l.audit_head()?.map(|h| h.0).unwrap_or(0);
        for s in &cfg.sinks {
            let c = l.export_cursor(&s.name)?;
            let holder = if c.lease_until >= wicket_store::now() { c.holder.unwrap_or_default() } else { "-".into() };
            println!(
                "{:<16} at {} of {head}  last checkpoint {}  fed by {holder}{}",
                s.name,
                c.seq,
                c.checkpoint_at,
                c.error.map(|e| format!("  error: {e}")).unwrap_or_default()
            );
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
    use wicket_auth::{decision_challenge, unb64u, Credential, RelyingParty};
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
