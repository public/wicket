//! `wicket names` (#575): the names boxes hold or ask for. Internal names need no decision; a
//! public name (on the internet) is an ask only a human decides, here or (later) in the console.

use crate::*;
use wicket_control::names as nm;

#[derive(Subcommand)]
pub enum NamesCmd {
    /// Names: pending asks for public names, and live names (internal and public). --all adds
    /// denied, withdrawn and ended ones.
    List {
        #[arg(long)]
        all: bool,
    },
    /// One name or ask: the label, port, who asked, and, for a public name, what approving it means.
    Show { id: String },
    /// Approve an ask for a public name (`n-…`). A standing name is for the agent that asked (each
    /// later run of it), or --for zone (every agent of its zone), for --lasts.
    Approve {
        id: String,
        /// A standing name's holder: `agent` (the asking agent's principal) or `zone` (its zone).
        #[arg(long = "for", default_value = "agent")]
        bound: String,
        /// A standing name's lifetime (at most 366d), or `forever`: until revoked.
        #[arg(long, default_value = "30d")]
        lasts: String,
        /// Don't ask for confirmation at a terminal (the ask is printed either way).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Deny an ask for a public name.
    Deny { id: String },
    /// Revoke a live name, public or internal: it ends now, whoever holds it.
    Revoke { id: String },
}

fn when(t: i64) -> String {
    wicket_core::time::unix_rfc3339(t)
}

/// A name's words, cleaned for a terminal: a label and a reason are an agent's.
fn c(s: &str, n: usize) -> String {
    wicket_agent::clip(s, n)
}

/// One line for `wicket names list`.
pub fn line(n: &wicket_store::NameRow, now: i64) -> String {
    let state = match (n.status.as_str(), n.expires_at) {
        ("live", Some(e)) if e <= now => format!("lapsed {}", when(e)),
        ("live", Some(e)) => format!("live, until {}", when(e)),
        (s, _) => s.to_string(),
    };
    let held = n.holder.as_deref().map(|h| format!("  held by {h}")).unwrap_or_default();
    format!("{}  {} {}  port {}  {}  {}{held}", n.id, n.kind.as_str(), c(&n.label, 63), n.port, n.scope.as_str(), state)
}

/// The whole ask or name, as a decider sees it.
pub fn show(n: &wicket_store::NameRow) -> String {
    let mut out = format!(
        "name {}: {} {} ({})\n  label:     {}\n  port:      {} (the box's own){}\n  asked by:  {} (run {}, zone {})\n  scope:     {}\n  reason:    {}\n",
        n.id,
        n.kind.as_str(),
        c(&n.label, 63),
        n.status,
        c(&n.label, 63),
        n.port,
        n.service.as_deref().map(|s| format!(", service {}", c(s, 63))).unwrap_or_default(),
        c(&n.principal, 200),
        n.asked_run,
        c(&n.zone, 200),
        match n.scope {
            wicket_store::NameScope::Run => "this run only",
            wicket_store::NameScope::Standing => "every later run of its workload",
        },
        c(&n.reason, 400),
    );
    if n.kind == wicket_store::NameKind::Public {
        out.push_str(&format!("  public:    {}\n", nm::WARNING));
    }
    out
}

pub async fn dispatch(cmd: NamesCmd) -> Result<()> {
    let human = || -> Result<grant::Granter> { Ok(grant::Granter::Human(crate::operators::Operator::cli(&TenantId::single().0)?)) };
    match cmd {
        NamesCmd::List { all } => {
            let l = Ledger::open(&ledger_path())?;
            let t = TenantId::single();
            let now = wicket_store::now();
            let mut rows = l.names_with_status(&t, "pending")?;
            rows.extend(l.names_with_status(&t, "live")?);
            if all {
                for s in ["denied", "withdrawn", "ended"] {
                    rows.extend(l.names_with_status(&t, s)?);
                }
            }
            if rows.is_empty() {
                println!("no names");
            }
            for n in rows {
                println!("{}", line(&n, now));
            }
            Ok(())
        }
        NamesCmd::Show { id } => {
            let l = Ledger::open(&ledger_path())?;
            print!("{}", show(&l.name(&id)?));
            Ok(())
        }
        NamesCmd::Approve { id, bound, lasts, yes } => {
            let l = Ledger::open(&ledger_path())?;
            let n = l.name(&id)?;
            let bound = match bound.as_str() {
                "agent" => wicket_store::StandingBound::Agent,
                "zone" => wicket_store::StandingBound::Zone,
                x => bail!("--for is agent or zone, not {x:?}"),
            };
            let ttl = match lasts.as_str() {
                "forever" => None,
                d => Some(wicket_core::time::parse_duration(d).context("bad --lasts (a duration such as 30d, or forever)")?),
            };
            let terms = nm::terms(bound, ttl)?;
            // What is approved is what wicket recorded, shown before it is decided, and the
            // decision is made on that effect (#369).
            print!("{}", show(&n));
            if n.scope == wicket_store::NameScope::Standing {
                println!(
                    "  for:       {}\n  lasts:     {}",
                    match bound {
                        wicket_store::StandingBound::Agent => format!("{} (each later run of it)", c(&n.principal, 200)),
                        wicket_store::StandingBound::Zone => format!("every agent of zone {}", c(&n.zone, 200)),
                    },
                    ttl.map(|t| wicket_core::time::format_duration(t).to_string()).unwrap_or_else(|| "until revoked".into())
                );
            }
            let shown = wicket_store::name_effect(&n, &terms);
            println!("  effect {shown}");
            if !yes && std::io::stdin().is_terminal() && !confirm(&format!("approve {id} as shown above?"))? {
                bail!("not approved");
            }
            nm::approve(&l, &human()?, &id, &terms, Some(&shown), serde_json::json!({ "via": "cli" }))?;
            println!(
                "approved {id}: the public name {} (port {}). wicket doesn't publish public records yet: it is a record only.",
                c(&n.label, 63),
                n.port
            );
            Ok(())
        }
        NamesCmd::Deny { id } => {
            let l = Ledger::open(&ledger_path())?;
            nm::deny(&l, &human()?, &id, serde_json::json!({ "via": "cli" }))?;
            println!("denied {id}");
            Ok(())
        }
        NamesCmd::Revoke { id } => {
            let l = Ledger::open(&ledger_path())?;
            nm::revoke(&l, &operator(), &id)?;
            println!("revoked {id}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A label, a principal and a reason are a box's words: nothing printed can move the cursor
    /// or hide the rest of the line.
    #[test]
    fn a_name_prints_whole_whatever_it_holds() {
        let n = wicket_store::NameRow {
            id: "n-1".into(),
            tenant: "t0".into(),
            kind: wicket_store::NameKind::Public,
            label: "demo\x1b[2K".into(),
            zone: "work".into(),
            zone_digest: "d".into(),
            principal: "spiffe://w/a\u{202e}b".into(),
            asked_run: "run_w".into(),
            holder: None,
            port: 3000,
            service: Some("http".into()),
            reason: "the demo\r, approve me".into(),
            scope: wicket_store::NameScope::Run,
            status: "pending".into(),
            created_at: 0,
            decided_at: None,
            decided_by: None,
            bound: None,
            expires_at: None,
            effect_sha256: None,
            ended_at: None,
            ended_by: None,
            end_reason: None,
        };
        for out in [show(&n), line(&n, 0)] {
            assert!(!out.contains(['\r', '\x1b', '\u{202e}']), "{out:?}");
        }
        assert!(show(&n).contains(nm::WARNING));
    }
}
