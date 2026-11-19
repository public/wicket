//! `wicket standing`: standing reach (#572), a reach rule an agent asked for once for its workload,
//! approved once by a human for the agent's principal or its zone, and honoured by its later runs.

use crate::*;
use wicket_control::standing as st;

#[derive(Subcommand)]
pub enum StandingCmd {
    /// Standing rules: pending asks, and approved rules (with when they lapse). --all adds denied,
    /// revoked and lapsed ones.
    List {
        #[arg(long)]
        all: bool,
    },
    /// One ask or rule: the rule, who it is for, the ledger's evidence (the requests it covers), and
    /// what it would allow beyond them.
    Show { id: String },
    /// Approve a standing ask (`s-…`), once: the rule as asked, or --narrow to what its evidence
    /// used. For the agent that asked (each later run of it), or --for zone (every agent of its zone).
    Approve {
        id: String,
        /// Who it is for: `agent` (the asking agent's principal) or `zone` (its zone).
        #[arg(long = "for", default_value = "agent")]
        bound: String,
        /// How long it lasts (at most 366d), or `forever`: until revoked.
        #[arg(long, default_value = "30d")]
        lasts: String,
        /// Approve only the methods and paths the evidence shows were asked for.
        #[arg(long)]
        narrow: bool,
        /// Don't ask for confirmation at a terminal (the ask is printed either way).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Deny a standing ask.
    Deny { id: String },
    /// Move an approved rule's lapse to --lasts from now (or `forever`).
    Renew {
        id: String,
        #[arg(long, default_value = "30d")]
        lasts: String,
    },
    /// Revoke an approved rule: it allows nothing from now on (a box's node, once its run publishes
    /// the revocation).
    Revoke { id: String },
}

fn lasts(s: &str) -> Result<Option<std::time::Duration>> {
    match s {
        "forever" => Ok(None),
        d => Ok(Some(wicket_core::time::parse_duration(d).context("bad --lasts (a duration such as 30d, or forever)")?)),
    }
}

fn bound(s: &str) -> Result<wicket_store::StandingBound> {
    match s {
        "agent" => Ok(wicket_store::StandingBound::Agent),
        "zone" => Ok(wicket_store::StandingBound::Zone),
        x => bail!("--for is agent or zone, not {x:?}"),
    }
}

fn rule_text(r: &wicket_core::manifest::ReachRule) -> String {
    format!(
        "{{ host: {}, methods: [{}], paths: [{}]{} }}",
        r.host,
        r.methods.join(", "),
        r.paths.iter().map(|p| format!("'{p}'")).collect::<Vec<_>>().join(", "),
        if r.allow_dangerous { ", allow_dangerous: true" } else { "" }
    )
}

fn when(t: i64) -> String {
    wicket_core::time::unix_rfc3339(t)
}

/// One line for `wicket standing list` and `wicket pending`.
pub fn line(s: &wicket_store::Standing, now: i64) -> String {
    let state = match (s.status.as_str(), s.expires_at) {
        ("approved", Some(e)) if e <= now => format!("lapsed {}", when(e)),
        ("approved", Some(e)) => format!("approved, until {}", when(e)),
        ("approved", None) => "approved, until revoked".into(),
        (st, _) => st.to_string(),
    };
    let to = match s.bound {
        Some(wicket_store::StandingBound::Zone) => format!("zone {}", s.zone),
        _ => s.principal.clone(),
    };
    format!("{}  {}  for {}  {}", s.id, rule_text(&s.rule), wicket_agent::clip(&to, 200), state)
}

/// The whole ask, as the card shows it.
pub fn show(s: &wicket_store::Standing, rule: &wicket_core::manifest::ReachRule) -> String {
    let e = &s.evidence;
    let mut out = format!(
        "standing {}: {}\n  rule:      {}\n  asked by:  {} (run {}, zone {})\n  reason:    {}\n",
        s.id,
        s.status,
        rule_text(rule),
        s.principal,
        s.run,
        s.zone,
        wicket_agent::clip(&s.reason, 400)
    );
    out.push_str(&format!(
        "  evidence:  {} request(s) it covers in the last 14 days ({} granted, {} denied){}\n",
        e.requests,
        e.granted,
        e.denied,
        match (e.first, e.last) {
            (Some(f), Some(l)) => format!(", {} to {}", when(f), when(l)),
            _ => String::new(),
        }
    ));
    for (m, p, n) in &e.ops {
        out.push_str(&format!("             {n} × {m} {}\n", wicket_agent::clip(p, 200)));
    }
    let beyond = st::beyond(s, rule);
    if !beyond.is_empty() {
        out.push_str("  beyond what was asked:\n");
        for b in beyond {
            out.push_str(&format!("             {b}\n"));
        }
    }
    out
}

pub async fn dispatch(c: StandingCmd) -> Result<()> {
    let human = || -> Result<grant::Granter> { Ok(grant::Granter::Human(crate::operators::Operator::cli(&TenantId::single().0)?)) };
    match c {
        StandingCmd::List { all } => {
            let l = Ledger::open(&ledger_path())?;
            let t = TenantId::single();
            let now = wicket_store::now();
            let mut rows = l.standing_with_status(&t, "pending")?;
            rows.extend(l.standing_with_status(&t, "approved")?.into_iter().filter(|s| all || s.live(now)));
            if all {
                rows.extend(l.standing_with_status(&t, "denied")?);
                rows.extend(l.standing_with_status(&t, "revoked")?);
            }
            if rows.is_empty() {
                println!("no standing reach");
            }
            for s in rows {
                println!("{}", line(&s, now));
            }
            Ok(())
        }
        StandingCmd::Show { id } => {
            let l = Ledger::open(&ledger_path())?;
            let s = l.standing(&id)?;
            print!("{}", show(&s, &s.rule));
            Ok(())
        }
        StandingCmd::Approve { id, bound: b, lasts: d, narrow, yes } => {
            let l = Ledger::open(&ledger_path())?;
            let s = l.standing(&id)?;
            let rule = match narrow {
                true => Some(st::narrowed(&s).context("nothing to narrow to: the ask has no evidence (approve it as asked, or deny it)")?),
                false => None,
            };
            let a = st::Approve { rule, bound: bound(&b)?, ttl: lasts(&d)? };
            let shown_rule = a.rule.clone().unwrap_or_else(|| s.rule.clone());
            // What is approved is what wicket recorded, shown before it is decided (#121), and the
            // decision is made on that effect (#369).
            print!("{}", show(&s, &shown_rule));
            let terms = wicket_store::StandingTerms { bound: a.bound, ttl_secs: a.ttl.map(|t| t.as_secs()) };
            let shown = wicket_store::standing_effect(&s, &shown_rule, Some(&terms));
            println!(
                "  for:       {}\n  lasts:     {}\n  effect {shown}",
                match a.bound {
                    wicket_store::StandingBound::Agent => format!("{} (each later run of it)", s.principal),
                    wicket_store::StandingBound::Zone => format!("every agent of zone {}", s.zone),
                },
                a.ttl.map(|t| wicket_core::time::format_duration(t).to_string()).unwrap_or_else(|| "until revoked".into())
            );
            if !yes && std::io::stdin().is_terminal() && !confirm(&format!("approve {id} as shown above?"))? {
                bail!("not approved");
            }
            st::approve(&l, &human()?, &id, &a, Some(&shown), serde_json::json!({ "via": "cli" }))?;
            println!("approved {id}: the agent's later runs are allowed {} without asking", rule_text(&shown_rule));
            Ok(())
        }
        StandingCmd::Deny { id } => {
            let l = Ledger::open(&ledger_path())?;
            st::deny(&l, &human()?, &id, serde_json::json!({ "via": "cli" }))?;
            println!("denied {id}");
            Ok(())
        }
        StandingCmd::Renew { id, lasts: d } => {
            let l = Ledger::open(&ledger_path())?;
            match st::renew(&l, &human()?, &id, lasts(&d)?, serde_json::json!({ "via": "cli" }))? {
                Some(u) => println!("renewed {id}: until {}", when(u)),
                None => println!("renewed {id}: until revoked"),
            }
            Ok(())
        }
        StandingCmd::Revoke { id } => {
            let l = Ledger::open(&ledger_path())?;
            st::revoke(&l, &operator(), &id)?;
            println!("revoked {id}; each run it allowed publishes the revocation to its node");
            Ok(())
        }
    }
}
