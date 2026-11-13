//! `wicket serve`, `operator` and `program`: the console, its passkeys, and programs.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        c @ Cmd::Serve { .. } => {
            let (opts, no_bootstrap_link) = serve_opts(c).expect("a serve command");
            serve::serve(opts, !no_bootstrap_link).await
        }
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
                    let ttl = humantime::parse_duration(&ttl).context("bad --ttl")?;
                    if ttl.is_zero() || ttl > Duration::from_secs(3600) {
                        bail!("--ttl must be more than 0 and at most 1h");
                    }
                    let token = serve::issue_enrol_link(&l, &TenantId::single(), ttl.as_secs() as i64, &operator())?;
                    let origin = origin.as_deref().map(|o| o.trim_end_matches('/')).unwrap_or("");
                    println!("open within {} (single use) to enrol a passkey:", humantime::format_duration(ttl));
                    println!("  {origin}/enrol?t={token}");
                    if origin.is_empty() {
                        println!("(prefix the console's origin, e.g. https://console.example.com)");
                    }
                }
                OperatorCmd::Sessions => {
                    let now = wicket_store::now();
                    let ago = |t: i64| humantime::format_duration(Duration::from_secs((now - t).max(0) as u64)).to_string();
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

#[derive(Subcommand)]
pub enum OperatorCmd {
    /// List enrolled passkeys.
    List,
    /// Host-only break-glass: revoke every passkey (and every console session), so `wicket serve`
    /// prints a fresh enrolment link.
    Reset,
    /// Print a fresh single-use link that enrols one passkey in the console (another device, or a
    /// replacement after `reset`). The only way to add a passkey: a signed-in console session can't.
    EnrolLink {
        /// How long the link stays usable (at most 1h).
        #[arg(long, default_value = "10m")]
        ttl: String,
        /// The console's origin, to print the whole link (otherwise just its path).
        #[arg(long)]
        origin: Option<String>,
    },
    /// List live console sessions (id, passkey, client address, times).
    Sessions,
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
