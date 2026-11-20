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
    /// later run of it takes it up when it starts), or --for zone (every agent of its zone), for --lasts.
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

/// The whole ask or name, as a decider sees it: for a public one, its full name under the boxes
/// domain of `public` (this installation's settings, if it has them).
pub fn show(n: &wicket_store::NameRow, public: Option<&wicket_names::PublicConfig>) -> String {
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
            wicket_store::NameScope::Standing => "every later run of its workload: each takes it up when it starts, if no other run holds it",
        },
        c(&n.reason, 400),
    );
    if n.kind == wicket_store::NameKind::Public {
        match public {
            Some(p) => out.push_str(&format!("  name:      {}\n", c(&p.fqdn(&n.label), 253))),
            None => out.push_str("  name:      none: this installation publishes no public names (names.public in wicket.yaml)\n"),
        }
        out.push_str(&format!("  public:    {}\n", nm::WARNING));
    }
    out
}

/// The installation's `names:` settings, as `wicket.yaml` has them now.
fn settings() -> Result<wicket_names::NamesConfig> {
    wicket_agent::acp::names_settings().map_err(anyhow::Error::msg)
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
            let names = settings()?;
            print!("{}", show(&l.name(&id)?, names.public.as_ref()));
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
            let names = settings()?;
            let public = nm::public_settings(&names)?;
            // What is approved is what wicket recorded, shown before it is decided, and the
            // decision is made on that effect (#369).
            print!("{}", show(&n, Some(public)));
            if n.scope == wicket_store::NameScope::Standing {
                println!(
                    "  for:       {}\n  lasts:     {}",
                    match bound {
                        wicket_store::StandingBound::Agent => {
                            format!("{} (this run, then each later run of it)", c(&n.principal, 200))
                        }
                        wicket_store::StandingBound::Zone => format!("every agent of zone {}", c(&n.zone, 200)),
                    },
                    ttl.map(|t| wicket_core::time::format_duration(t).to_string()).unwrap_or_else(|| "until revoked".into())
                );
            }
            let shown = wicket_store::name_effect(&n, &terms, &public.domain());
            println!("  effect {shown}");
            if !yes && std::io::stdin().is_terminal() && !confirm(&format!("approve {id} as shown above?"))? {
                bail!("not approved");
            }
            // The settings as they are now, after the prompt (#716 review, F7): a boxes domain
            // changed meanwhile changes the effect, and the decision on the one shown is refused.
            let names = settings()?;
            nm::approve(&l, &human()?, &id, &terms, &shown, &names, serde_json::json!({ "via": "cli" }))?;
            println!(
                "approved {id}: the public name {} (port {}). wicket doesn't publish public records yet: it is a record only.",
                c(&public.fqdn(&n.label), 253),
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
            domain: None,
        };
        let public: wicket_names::PublicConfig =
            serde_json::from_value(serde_json::json!({ "provider": "noop", "zone": "boxes.example.com", "owner": "a1b2c3d4" })).unwrap();
        for out in [show(&n, Some(&public)), show(&n, None), line(&n, 0)] {
            assert!(!out.contains(['\r', '\x1b', '\u{202e}']), "{out:?}");
        }
        assert!(show(&n, None).contains(nm::WARNING));
        assert!(show(&n, None).contains("publishes no public names"));
        // The full name, as approved (its label as cleaned for the terminal).
        assert!(show(&n, Some(&public)).contains(".boxes.example.com\n"), "{}", show(&n, Some(&public)));
    }
}
