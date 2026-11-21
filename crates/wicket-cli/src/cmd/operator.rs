//! `wicket serve`, `operator` and `program`: the console, its passkeys, and programs.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Serve { opts, no_bootstrap_link } => serve::serve(opts, !no_bootstrap_link).await,
        Cmd::Program { cmd: ProgramCmd::Digest { dir } } => {
            println!("{}", program::digest_dir(&dir)?);
            Ok(())
        }
        Cmd::Operator { cmd } => {
            let l = Ledger::open(&ledger_path())?;
            match cmd {
                OperatorCmd::List => {
                    for c in l.operator_credentials(&TenantId::single())? {
                        println!("{}  {}  sign count {}", c.id, c.name, c.sign_count);
                    }
                }
                OperatorCmd::EnrolLink { ttl, origin } => {
                    if ttl.is_zero() || ttl > Duration::from_secs(3600) {
                        return Err(wicket_home::exit::usage("--ttl must be more than 0 and at most 1h"));
                    }
                    let token = serve::issue_enrol_link(&l, &TenantId::single(), ttl.as_secs() as i64, &operator())?;
                    let origin = origin.as_deref().map(|o| o.trim_end_matches('/')).unwrap_or("");
                    println!("open within {} (single use) to enrol a passkey:", wicket_core::time::format_duration(ttl));
                    println!("  {origin}/enrol?t={token}");
                    if origin.is_empty() {
                        println!("(prefix the console's origin, e.g. https://console.example.com)");
                    }
                }
                OperatorCmd::Sessions { json } => {
                    let now = wicket_store::now();
                    if json {
                        return crate::cmd::print_json(&sessions_json(&l.console_sessions(&TenantId::single(), now)?));
                    }
                    let ago = |t: i64| wicket_core::time::format_duration(Duration::from_secs((now - t).max(0) as u64)).to_string();
                    for s in l.console_sessions(&TenantId::single(), now)? {
                        println!(
                            "{}  {}  {}  from {}  signed in {} ago, last seen {} ago",
                            &s.id[..16],
                            s.kind,
                            s.credential.as_deref().unwrap_or("-"),
                            s.client,
                            ago(s.created_at),
                            ago(s.last_seen_at)
                        );
                    }
                }
                OperatorCmd::RevokeSession { id, all } => {
                    let t = TenantId::single();
                    let prefix = match (&id, all) {
                        (Some(p), false) if !p.is_empty() => {
                            let n = l.console_sessions(&t, wicket_store::now())?.iter().filter(|s| s.id.starts_with(p.as_str())).count();
                            if n != 1 {
                                bail!("{p:?} matches {n} live sessions (see wicket operator sessions)");
                            }
                            Some(p.as_str())
                        }
                        (None, true) => None,
                        _ => bail!("give a session id (wicket operator sessions) or --all"),
                    };
                    let ids = l.revoke_console_sessions(&t, prefix, &operator())?;
                    l.audit(
                        &t,
                        None,
                        "operator.sessions_revoked",
                        &serde_json::json!({ "sessions": ids, "by": operator(), "via": "host" }),
                    )?;
                    println!("ended {} console session(s)", ids.len());
                }
                OperatorCmd::Reset => {
                    let n = l.reset_operator_credentials(&TenantId::single())?;
                    l.revoke_console_sessions(&TenantId::single(), None, &operator())?;
                    l.audit(
                        &TenantId::single(),
                        None,
                        "operator.reset",
                        &serde_json::json!({ "removed": n, "by": operator(), "via": "host break-glass" }),
                    )?;
                    println!(
                        "revoked {n} passkey(s) (public keys kept for audit verification); enrol a new one with `wicket operator enrol-link`"
                    );
                }
            }
            Ok(())
        }
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

/// `wicket operator sessions --json`, and the console's `/api/sessions` (#713). A session's `id` is
/// the first 16 hex digits of its token's SHA-256, as the text shows it and `revoke-session` takes
/// it: nothing a request could sign in with. A bootstrap session's credential (its enrolment link's
/// id) is left out.
pub(crate) fn sessions_json(rows: &[wicket_store::ConsoleSession]) -> serde_json::Value {
    rows.iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id.get(..16).unwrap_or(&s.id), "kind": s.kind,
                "credential": if s.kind == "operator" { s.credential.clone() } else { None },
                "client": s.client, "created_at": s.created_at, "last_seen_at": s.last_seen_at, "expires_at": s.expires_at,
            })
        })
        .collect()
}

#[derive(Subcommand)]
pub enum OperatorCmd {
    /// List enrolled passkeys.
    List,
    /// Host-only break-glass: revoke every passkey (and every console session), so `wicket serve`
    /// prints a fresh enrolment link.
    Reset,
    /// Print a fresh single-use link that enrols one passkey in the console (the first, another
    /// device, or a replacement after `reset`). A signed-in operator can also make one for another
    /// device of theirs in the console, signed with their passkey (#711).
    EnrolLink {
        /// How long the link stays usable (at most 1h).
        #[arg(long, default_value = "10m", value_parser = wicket_core::time::duration_arg)]
        ttl: std::time::Duration,
        /// The console's origin, to print the whole link (otherwise just its path).
        #[arg(long)]
        origin: Option<String>,
    },
    /// List live console sessions (id, passkey, client address, times).
    Sessions {
        /// Print JSON (docs/reference/cli.md, "Output for scripts"), as the console has them.
        #[arg(long)]
        json: bool,
    },
    /// End console sessions now: one by its id (or a unique prefix of it), or all with --all.
    RevokeSession {
        id: Option<String>,
        #[arg(long, conflicts_with = "id")]
        all: bool,
    },
}

#[derive(Subcommand)]
pub enum ProgramCmd {
    /// Print a program source directory's digest (what a manifest pins to approve that exact code).
    Digest { dir: PathBuf },
}
