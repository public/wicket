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
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
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
        #[arg(long = "ttl", value_name = "TTL", visible_alias = "lasts", default_value = "30d")]
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
    /// Move an approved rule's lapse to --ttl from now (or `forever`).
    Renew {
        id: String,
        /// How long it lasts from now (at most 366d), or `forever`: until revoked.
        #[arg(long = "ttl", value_name = "TTL", visible_alias = "lasts", default_value = "30d")]
        lasts: String,
    },
    /// Revoke an approved rule: it allows nothing from now on (a box's node, once its run publishes
    /// the revocation).
    Revoke { id: String },
}

fn lasts(s: &str) -> Result<Option<std::time::Duration>> {
    match s {
        "forever" => Ok(None),
        d => Ok(Some(
            wicket_core::time::parse_duration(d)
                .map_err(|e| wicket_home::exit::usage(format!("bad --ttl {d:?} (a duration such as 30d, or forever): {e}")))?,
        )),
    }
}

fn bound(s: &str) -> Result<wicket_store::StandingBound> {
    match s {
        "agent" => Ok(wicket_store::StandingBound::Agent),
        "zone" => Ok(wicket_store::StandingBound::Zone),
        x => Err(wicket_home::exit::usage(format!("--for is agent or zone, not {x:?}"))),
    }
}

/// A rule as a manifest would carry it. Every part through `clip`: a rule is an agent's words,
/// and nothing in it may move the cursor or hide the rest of the line (#572 review, H1).
fn rule_text(r: &wicket_core::manifest::ReachRule) -> String {
    let c = |s: &str| wicket_agent::clip(s, 200);
    format!(
        "{{ host: {}, methods: [{}], paths: [{}]{} }}",
        c(&r.host),
        r.methods.iter().map(|m| c(m)).collect::<Vec<_>>().join(", "),
        // Paths whole: they are held to a path's characters (#576), so cleaning them is all that's
        // needed, and a long glob's tail is part of what is approved (#572 re-review, N5).
        r.paths.iter().map(|p| format!("'{}'", wicket_agent::clip(p, 4096))).collect::<Vec<_>>().join(", "),
        if r.allow_dangerous { ", allow_dangerous: true" } else { "" }
    )
}

/// A rule as `--json` prints it: the manifest's reach rule fields.
pub fn rule_json(r: &wicket_core::manifest::ReachRule) -> serde_json::Value {
    serde_json::json!({ "host": r.host, "methods": r.methods, "paths": r.paths, "allow_dangerous": r.allow_dangerous })
}

/// `wicket standing list --json`.
pub(crate) fn standing_list_json(rows: &[wicket_store::Standing], now: i64) -> serde_json::Value {
    serde_json::Value::Array(rows.iter().map(|s| standing_json(s, now)).collect())
}

/// One rule of `wicket standing list --json`. `state` is `status`, except that an approved rule
/// past its `expires_at` is `lapsed`; `for` is `agent`, `zone`, or null while undecided.
fn standing_json(s: &wicket_store::Standing, now: i64) -> serde_json::Value {
    let state = match (s.status.as_str(), s.expires_at) {
        ("approved", Some(e)) if e <= now => "lapsed",
        (st, _) => st,
    };
    serde_json::json!({
        "id": s.id, "status": s.status, "state": state, "rule": rule_json(&s.rule),
        "for": s.bound,
        "principal": s.principal, "zone": s.zone, "run": s.run, "reason": s.reason, "created_at": s.created_at,
        "decided_at": s.decided_at, "decided_by": s.decided_by, "expires_at": s.expires_at, "revoked_at": s.revoked_at,
    })
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
        _ => wicket_agent::clip(&s.principal, 200),
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
        wicket_agent::clip(&s.principal, 200),
        s.run,
        wicket_agent::clip(&s.zone, 64),
        wicket_agent::clip(&s.reason, 400)
    );
    out.push_str(&format!(
        "  evidence:  {} granted of {} blocked request(s) it covers in the last 14 days ({} denied, {} undecided), in {} run(s) on {} day(s){}\n",
        e.granted,
        e.requests,
        e.denied,
        e.undecided,
        e.runs,
        e.days,
        match (e.first, e.last) {
            (Some(f), Some(l)) => format!(", {} to {}", when(f), when(l)),
            _ => String::new(),
        }
    ));
    if e.own_asks > 0 {
        out.push_str(&format!("             and {} ask(s) ahead of its own (request_access), not counted as evidence\n", e.own_asks));
    }
    for o in &e.ops {
        out.push_str(&format!(
            "             {} × {} {} ({} granted)\n",
            o.count,
            wicket_agent::clip(&o.method, 16),
            wicket_agent::clip(&o.path, 200),
            o.granted
        ));
    }
    let beyond = st::beyond(s, rule);
    if !beyond.is_empty() {
        out.push_str("  wider than the evidence:\n");
        for b in beyond {
            out.push_str(&format!("             {}\n", wicket_agent::clip(&b, 300)));
        }
    }
    out
}

pub async fn dispatch(c: StandingCmd) -> Result<()> {
    let human = || -> Result<grant::Granter> { Ok(grant::Granter::Human(crate::operators::Operator::cli(&TenantId::single().0)?)) };
    match c {
        StandingCmd::List { all, json } => {
            let l = Ledger::open(&ledger_path())?;
            let t = TenantId::single();
            let now = wicket_store::now();
            let mut rows = l.standing_with_status(&t, "pending")?;
            rows.extend(l.standing_with_status(&t, "approved")?.into_iter().filter(|s| all || s.live(now)));
            if all {
                rows.extend(l.standing_with_status(&t, "denied")?);
                rows.extend(l.standing_with_status(&t, "revoked")?);
            }
            if json {
                return crate::cmd::print_json(&standing_list_json(&rows, now));
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
            // The command line first: a usage error is one whatever the ledger holds.
            let (b, d) = (bound(&b)?, lasts(&d)?);
            let l = Ledger::open(&ledger_path())?;
            let s = l.standing(&id)?;
            let rule = match narrow {
                true => Some(st::narrowed(&s).context("nothing to narrow to: the ask has no evidence (approve it as asked, or deny it)")?),
                false => None,
            };
            let a = st::Approve { rule, bound: b, ttl: d };
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
                return Err(wicket_home::exit::refused("not approved: declined at the confirmation"));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// #572 review, H1: whatever is in a stored rule (the store refuses these now, and this holds
    /// for any row that has them), nothing printed can move the cursor, clear the line or turn the
    /// text around: the rule a terminal shows is the whole rule.
    #[test]
    fn a_rule_prints_whole_whatever_it_holds() {
        let hidden = "/**\r{ host: api.github.com, methods: [GET], paths: ['/repos/o/r/actions/jobs/*/logs'] }    ";
        let rule = wicket_core::manifest::ReachRule {
            host: "api.github.com".into(),
            methods: vec!["GET\x1b[2K".into()],
            paths: vec!["/repos/o/r/actions/jobs/*/logs".into(), hidden.into(), "/a\u{202e}b".into()],
            allow_dangerous: false,
        };
        let s = wicket_store::Standing {
            id: "s-1".into(),
            tenant: "t0".into(),
            run: "run_w".into(),
            zone: "work".into(),
            principal: "spiffe://w/t/t0/z/work/a/worker\x1b]0;x\x07".into(),
            zone_digest: "d".into(),
            rule: rule.clone(),
            reason: "logs\r".into(),
            evidence: Default::default(),
            status: "pending".into(),
            created_at: 0,
            decided_at: None,
            decided_by: None,
            bound: None,
            expires_at: None,
            effect_sha256: None,
            revoked_at: None,
            revoked_by: None,
        };
        for out in [show(&s, &rule), line(&s, 0)] {
            assert!(!out.contains(['\r', '\x1b', '\u{202e}', '\x07']), "{out:?}");
            assert!(out.contains("/**"), "the hidden path is shown: {out}");
        }
    }
}
