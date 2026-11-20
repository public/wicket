//! The ledger's trace check (#326, #324), which `wicket doctor --invariants` runs: #321's properties, checked on this installation's own
//! ledger after the fact, as `wicket-sim`'s oracle checks them in simulation. Read only.
//!
//! - **Every allowed egress request had a reach rule or a live grant.** Each `allow` (or `spliced`)
//!   egress record, from a node's shipped audit (`node.audit`) or the control host's own (`op`),
//!   names why it was allowed:
//!   - a grant: it must exist, be for that request's method, host and path (exactly, or under its
//!     prefix), at no more than its risk bound, for that run or zone-wide, made before the request,
//!     not past its lifetime then, and not revoked before it (by more than the feed's freshness
//!     window, which a node may still decide on);
//!   - a reach rule, or the box's token: the run's zone must allow the request by reach. The zone is
//!     read where wicket keeps one (a long-lived agent's manifest, a spawned child's in its
//!     parent's run directory); without one, only that the rule exists is checked, and the record
//!     counts as unverified.
//! - **No run's model spend passed its budget.** Per run, the model calls that went through (2xx)
//!   and the output tokens all its calls reported, against its quota grants (`model.requests`,
//!   `model.output_tokens`).
//! - **No node ran past its lease.** A lease's runs ended (or, still running, now is) no later than
//!   the lease's end, and so did the lease, each within `grace` (the reconciler's cadence).
//!
//! - **Work collected before release, and no message delivered twice**: [`check_end_state`], the
//!   checks that read no clock, which #324's simulation also runs over the ledgers it writes.
//!
//! What it can't see: requests the proxies never recorded (an audit write that failed refuses the
//! request), a node's records not yet shipped, and a zone wicket didn't keep. Those are said, not
//! guessed.

use crate::{Ledger, Result};
use rusqlite::{params, OptionalExtension};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Where the check finds the zone a run was started in (its run id, and its agent's id if its start
/// record names one), where wicket kept it: None if it didn't.
pub type ZoneOf<'a> = dyn Fn(&str, Option<&str>) -> Option<wicket_core::ZoneSpec> + 'a;

/// How long after a revocation a node may still decide on the grant: the feed's freshness window
/// (30 s) and clock skew.
const REVOKE_LAG_SECS: i64 = 40;
/// Clock skew allowed between a node's records and the control host's.
const SKEW_SECS: i64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub invariant: &'static str,
    pub run: String,
    pub what: String,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub allows: usize,
    pub by_grant: usize,
    pub by_reach: usize,
    /// Reach allows whose zone wicket didn't keep: only the rule's existence was checked.
    pub unverified: usize,
    /// wicket DNS answers (for HTTP/3): a name resolved to wicket's own synthetic range, not a
    /// request. Checked to be a host the zone reaches (or a grant names) where the zone was kept.
    pub dns_answers: usize,
    pub runs_with_spend: usize,
    pub leases: usize,
    /// The order-free checks' counts ([`check_end_state`]).
    pub end: EndState,
    pub findings: Vec<Finding>,
}

/// One egress or model record: its run, when (Unix seconds, the writer's clock), and its event.
struct Rec {
    run: String,
    ts: i64,
    ev: Value,
}

/// Every proxy event in the ledger: the control host's own `op` records and the ones nodes shipped.
/// The records a node shipped (`node.audit`) of kind `kind`: (run, body).
fn shipped(l: &Ledger, kind: &str) -> Result<Vec<(Option<String>, Value)>> {
    let mut out = vec![];
    for r in l.audit_of_kind("node.audit")? {
        let Ok(outer) = serde_json::from_str::<Value>(&r.body) else { continue };
        if outer["kind"] != kind {
            continue;
        }
        let run = outer["run"].as_str().map(String::from).or(r.run.clone());
        let body = outer["body"].as_str().and_then(|b| serde_json::from_str::<Value>(b).ok()).unwrap_or(Value::Null);
        out.push((run, body));
    }
    Ok(out)
}

fn events(l: &Ledger) -> Result<Vec<Rec>> {
    let mut out = vec![];
    for r in l.audit_of_kind("op")? {
        if let (Some(run), Ok(ev)) = (r.run.clone(), serde_json::from_str::<Value>(&r.body)) {
            out.push(Rec { run, ts: r.ts, ev });
        }
    }
    for r in l.audit_of_kind("node.audit")? {
        let Ok(outer) = serde_json::from_str::<Value>(&r.body) else { continue };
        if outer["kind"] != "op" {
            continue;
        }
        let (Some(run), Some(body)) = (outer["run"].as_str().map(String::from).or(r.run.clone()), outer["body"].as_str()) else { continue };
        let Ok(ev) = serde_json::from_str::<Value>(body) else { continue };
        out.push(Rec { run, ts: outer["ts"].as_i64().unwrap_or(r.ts), ev });
    }
    Ok(out)
}

/// Why an allow record says it was allowed.
#[derive(Debug, PartialEq, Eq)]
enum Why {
    Grant(String),
    Reach(usize),
    Token,
    Other,
}

fn why(detail: &str) -> Why {
    if let Some(rest) = detail.strip_prefix("grant ") {
        return Why::Grant(rest.split_whitespace().next().unwrap_or("").to_string());
    }
    if let Some(i) = detail.find("grant: \"") {
        let rest = &detail[i + 8..];
        return Why::Grant(rest.split('"').next().unwrap_or("").to_string());
    }
    if let Some(rest) = detail.strip_prefix("reach rule ") {
        if let Some(n) = rest.split(|c: char| !c.is_ascii_digit()).next().and_then(|n| n.parse().ok()) {
            return Why::Reach(n);
        }
    }
    if detail.starts_with("the box's token") {
        return Why::Token;
    }
    Why::Other
}

pub fn check(l: &Ledger, zone_of: &ZoneOf<'_>, grace_secs: i64, now: i64) -> Result<Summary> {
    let mut s = Summary::default();
    let recs = events(l)?;
    // Revocations by grant, and each run's start record (its zone's name, reach count, agent).
    let mut revoked: HashMap<String, i64> = HashMap::new();
    for r in l.audit_of_kind("grant.revoked")? {
        if let Some(g) = serde_json::from_str::<Value>(&r.body).ok().and_then(|b| b["grant"].as_str().map(String::from)) {
            revoked.entry(g).and_modify(|t| *t = (*t).min(r.ts)).or_insert(r.ts);
        }
    }
    let mut starts: HashMap<String, Value> = HashMap::new();
    for r in l.audit_of_kind("run.start")? {
        if let (Some(run), Ok(b)) = (r.run, serde_json::from_str::<Value>(&r.body)) {
            starts.entry(run).or_insert(b);
        }
    }
    let mut zones: HashMap<String, Option<(wicket_core::ZoneSpec, wicket_core::CompiledZone)>> = HashMap::new();
    let mut findings = vec![];
    // Model spend per run: calls that went through, output tokens reported.
    let mut spend: HashMap<String, (i64, i64)> = HashMap::new();
    for r in &recs {
        let ev = &r.ev;
        match ev["kind"].as_str() {
            Some("llm") => {
                let e = spend.entry(r.run.clone()).or_default();
                if (200..300).contains(&ev["status"].as_i64().unwrap_or(0)) {
                    e.0 += 1;
                }
                e.1 += ev["output_tokens"].as_i64().unwrap_or(0);
            }
            // A wicket DNS answer (method DNS, h3.rs): the name resolved to wicket's synthetic range,
            // which only wicket's relay answers on, and nothing left the box. wicket answers a name
            // the zone keeps open (reached, or unlisted in a zone that escalates), never one it
            // forbids or hides: that is what is checked.
            Some("egress") if ev["method"] == "DNS" && ev["outcome"] == "allow" => {
                s.dns_answers += 1;
                let host = ev["host"].as_str().unwrap_or("");
                let start = starts.get(&r.run);
                let zone = zones.entry(r.run.clone()).or_insert_with(|| {
                    let spec = zone_of(&r.run, start.and_then(|b| b["agent_id"].as_str()))?;
                    wicket_core::CompiledZone::new(spec.clone()).ok().map(|c| (spec, c))
                });
                if let Some((spec, _)) = zone {
                    let open = wicket_core::host_verdict(spec, host) == wicket_core::HostVerdict::Open;
                    let granted = || l.grants_for_run(&r.run).is_ok_and(|gs| gs.iter().any(|g| g.host.eq_ignore_ascii_case(host)));
                    if !open && !granted() {
                        findings.push(Finding {
                            invariant: "egress",
                            run: r.run.clone(),
                            what: format!(
                                "wicket DNS resolved {host} at {}, a host the run's zone forbids or hides and no grant names",
                                r.ts
                            ),
                        });
                    }
                }
            }
            Some("egress") if matches!(ev["outcome"].as_str(), Some("allow" | "spliced")) => {
                s.allows += 1;
                let (method, host, path) =
                    (ev["method"].as_str().unwrap_or(""), ev["host"].as_str().unwrap_or(""), ev["path"].as_str().unwrap_or(""));
                let what = format!("{method} {host}{path} at {}", r.ts);
                match why(ev["detail"].as_str().unwrap_or("")) {
                    Why::Grant(id) => {
                        s.by_grant += 1;
                        let risk = ev["risk"].as_str().and_then(wicket_core::RiskClass::from_name).map(|r| r.rank()).unwrap_or(0);
                        // A standing rule (#572, `s-…`) allows as a grant does, by its own record.
                        let fault = if id.starts_with("s-") {
                            standing_fault(l, &id, &r.run, starts.get(&r.run), method, host, path, r.ts)?
                        } else {
                            grant_fault(l, &id, &r.run, method, host, path, risk, r.ts, revoked.get(&id).copied())?
                        };
                        if let Some(why) = fault {
                            findings.push(Finding {
                                invariant: "egress",
                                run: r.run.clone(),
                                what: format!("{what}: allowed by grant {id}, {why}"),
                            });
                        }
                    }
                    w @ (Why::Reach(_) | Why::Token) => {
                        s.by_reach += 1;
                        let start = starts.get(&r.run);
                        let zone = zones.entry(r.run.clone()).or_insert_with(|| {
                            let spec = zone_of(&r.run, start.and_then(|b| b["agent_id"].as_str()))?;
                            wicket_core::CompiledZone::new(spec.clone()).ok().map(|c| (spec, c))
                        });
                        match zone {
                            Some((spec, z)) => {
                                let ok = if ev["outcome"] == "spliced" {
                                    // Allowed wholesale: a reach rule for the host with no method or path limits.
                                    spec.reach.iter().any(|q| {
                                        q.methods.is_empty() && q.paths.is_empty() && wicket_core::manifest::host_matches(&q.host, host)
                                    })
                                } else {
                                    let op = wicket_core::Op::egress(
                                        &wicket_core::TenantId::single(),
                                        &wicket_core::RunId(r.run.clone()),
                                        &spec.name,
                                        method,
                                        host,
                                        path,
                                    );
                                    matches!(z.evaluate(&op), wicket_core::Verdict::AllowByReach(_))
                                };
                                if !ok {
                                    findings.push(Finding {
                                        invariant: "egress",
                                        run: r.run.clone(),
                                        what: format!("{what}: allowed by reach, but the run's zone doesn't allow it"),
                                    });
                                }
                            }
                            None => {
                                s.unverified += 1;
                                let rules = start.and_then(|b| b["reach"].as_u64()).map(|n| n as usize);
                                if let (Why::Reach(i), Some(n)) = (&w, rules) {
                                    if *i >= n {
                                        findings.push(Finding {
                                            invariant: "egress",
                                            run: r.run.clone(),
                                            what: format!("{what}: allowed by reach rule {i}, but its zone has {n}"),
                                        });
                                    }
                                }
                            }
                        }
                    }
                    Why::Other => findings.push(Finding {
                        invariant: "egress",
                        run: r.run.clone(),
                        what: format!(
                            "{what}: allowed for a reason this check doesn't know ({})",
                            wicket_core::text::clip(ev["detail"].as_str().unwrap_or(""), 120)
                        ),
                    }),
                }
            }
            _ => {}
        }
    }
    // Spend against each run's quota grants (the largest amount each resource was granted).
    for (run, (calls, output)) in &spend {
        s.runs_with_spend += 1;
        let mut quota: HashMap<String, i64> = HashMap::new();
        for g in l.quota_grants(run)? {
            if let (Some(res), Some(a)) = (g.quota().map(String::from), g.amount) {
                let e = quota.entry(res).or_insert(a);
                *e = (*e).max(a);
            }
        }
        if let Some(n) = quota.get("model.requests").filter(|n| calls > n) {
            findings.push(Finding { invariant: "budget", run: run.clone(), what: format!("{calls} model calls went through, budget {n}") });
        }
        if let Some(n) = quota.get("model.output_tokens").filter(|n| output > n) {
            findings.push(Finding { invariant: "budget", run: run.clone(), what: format!("{output} output tokens, budget {n}") });
        }
    }
    // Leases: neither the lease nor a run on it outlasted its end.
    for lease in l.leases(&[])? {
        let Some(end) = lease.not_after else { continue };
        s.leases += 1;
        if let Some(at) = lease.ended_at.filter(|at| *at > end + grace_secs) {
            findings.push(Finding {
                invariant: "lease",
                run: lease.run.clone(),
                what: format!("lease {} ended at {at}, {}s past its end", lease.id, at - end),
            });
        }
        for (run, status) in l.runs_on_lease(&lease.id)? {
            let at = match l.run_times(&run)?.and_then(|(_, ended)| ended) {
                Some(t) => t,
                None if status == "running" => now,
                None => continue,
            };
            if at > end + grace_secs {
                findings.push(Finding {
                    invariant: "lease",
                    run: run.clone(),
                    what: format!("ran on lease {} until {at}, {}s past its end", lease.id, at - end),
                });
            }
        }
    }
    let end = check_end_state(l)?;
    findings.extend(end.findings.iter().cloned());
    s.end = end;
    s.findings = findings;
    Ok(s)
}

/// Why grant `id` couldn't have allowed `method host path` at `ts` for `run`, if it couldn't.
#[allow(clippy::too_many_arguments)]
fn grant_fault(
    l: &Ledger,
    id: &str,
    run: &str,
    method: &str,
    host: &str,
    path: &str,
    risk: i64,
    ts: i64,
    revoked: Option<i64>,
) -> Result<Option<String>> {
    let Some(g) = l.grant(id)? else { return Ok(Some("which was never issued".into())) };
    let covers = if g.prefix { wicket_core::prefix_covers(&g.path, path) } else { g.path == path };
    let why = if !g.method.eq_ignore_ascii_case(method) || !g.host.eq_ignore_ascii_case(host) || !covers {
        Some(format!("which is for {} {}{}{}", g.method, g.host, g.path, if g.prefix { " (prefix)" } else { "" }))
    } else if g.run.as_deref().is_some_and(|r| r != run) {
        Some(format!("which is for run {}", g.run.as_deref().unwrap_or("")))
    } else if g.max_risk.unwrap_or(0) < risk {
        Some(format!("whose risk bound is below the request's ({} < {risk})", g.max_risk.unwrap_or(0)))
    } else if ts > g.expires_at + SKEW_SECS {
        Some(format!("past its lifetime (ended {})", g.expires_at))
    } else if let Some(at) = revoked.filter(|at| ts > at + REVOKE_LAG_SECS) {
        Some(format!("{}s after it was revoked", ts - at))
    } else if let Some((_, created, _)) = l.grant_provenance(id)?.filter(|(_, c, _)| ts + SKEW_SECS < *c) {
        Some(format!("before it was made ({created})"))
    } else {
        None
    };
    Ok(why)
}

/// Why standing rule `id` (#572) couldn't have allowed `method host path` at `ts` for `run`, if it
/// couldn't: it must have been approved (and not yet revoked, past the feed's window, or lapsed)
/// before the request, its rule must allow the request as a reach rule would, and it must bind the
/// run: the asking agent's principal, or its zone (read from the run's `run.start`; the zone
/// definition's digest isn't on the record, so a rule bound to it is checked by the zone's name).
#[allow(clippy::too_many_arguments)]
fn standing_fault(
    l: &Ledger,
    id: &str,
    run: &str,
    start: Option<&Value>,
    method: &str,
    host: &str,
    path: &str,
    ts: i64,
) -> Result<Option<String>> {
    let s = match l.standing(id) {
        Ok(s) => s,
        Err(crate::StoreError::NoSuchRequest(_)) => return Ok(Some("which was never issued".into())),
        // A ledger that can't be read isn't a rule that was never issued: say so, as an error.
        Err(e) => return Err(e),
    };
    let Some(decided) = s.decided_at.filter(|_| matches!(s.status.as_str(), "approved" | "revoked")) else {
        return Ok(Some(format!("which was never approved (it is {})", s.status)));
    };
    let zone = start.and_then(|b| b["zone"].as_str()).unwrap_or("");
    let agent = start.and_then(|b| b["agent"].as_str()).unwrap_or("");
    let op = wicket_core::Op::egress(&wicket_core::TenantId(s.tenant.clone()), &wicket_core::RunId(run.into()), zone, method, host, path);
    let rule = &s.rule;
    let shown = || format!("{} {}{}", rule.methods.join(","), rule.host, rule.paths.join(","));
    let binds = match s.bound {
        Some(crate::StandingBound::Zone) => zone == s.zone,
        Some(crate::StandingBound::Agent) => s.principal.ends_with(&format!("/t/{}/z/{zone}/a/{agent}", s.tenant)),
        None => false,
    };
    let why = if !rule.allows(&op).unwrap_or(false) {
        Some(format!("which is for {}", shown()))
    } else if !binds {
        Some(format!("which is for {} (bound to its {})", s.principal, s.bound.map(|b| b.as_str()).unwrap_or("nothing")))
    } else if ts + SKEW_SECS < decided {
        Some(format!("before it was approved ({decided})"))
    } else if let Some(end) = s.expires_at.filter(|e| ts > e + SKEW_SECS) {
        Some(format!("past its lifetime (ended {end})"))
    } else {
        s.revoked_at.filter(|at| ts > at + REVOKE_LAG_SECS).map(|at| format!("{}s after it was revoked", ts - at))
    };
    Ok(why)
}

/// What the order-free checks looked at, and found.
#[derive(Debug, Default, Clone)]
pub struct EndState {
    /// Placed nodes (`wicket node create`) that ended: released, or left.
    pub placed_ended: usize,
    /// Fetches of a run's files from its node that failed (`run.fetch_failed`).
    pub fetch_failures: usize,
    /// Messages on the record (accepted or refused), and the pushes nodes shipped.
    pub messages: usize,
    pub pushes: usize,
    /// Messages taken and recorded read whose push to the box was lost (`node.message_push_lost`):
    /// the known loss #324's simulation counts too. Said, not counted as findings.
    pub known_lost: Vec<String>,
    pub findings: Vec<Finding>,
}

/// The checks of #321's invariants that read only what happened and the state the ledger ends in,
/// never when by whose clock, so they hold for any ledger: an installation's, an acceptance run's,
/// or one #324's simulation wrote on its simulated clock (its records' times are the OS's).
///
/// - **Work collected before release** (`collected`). No placed node is released while a run's box
///   runs on it, or while a run's files on it are uncollected (a fetch failed, and nothing was
///   collected since). A run's uncollected files may go only with a node a human released, files and
///   all (`wicket node release`, whose record counts the runs).
/// - **No message delivered twice, and a refusal says so** (`messages`). No message is pushed to
///   a box twice (`node.message_pushed`, shipped by its node), none wicket refused is pushed at
///   all, and every refusal records why.
pub fn check_end_state(l: &Ledger) -> Result<EndState> {
    let mut s = EndState::default();
    let finding = |invariant, run: &str, what: String| Finding { invariant, run: run.to_string(), what };
    // Work collected before release.
    let ended: BTreeMap<String, String> =
        l.placed_nodes(&[])?.into_iter().filter(|n| n.status != "active").map(|n| (n.name, n.status)).collect();
    s.placed_ended = ended.len();
    for (name, status) in ended.iter().filter(|(_, st)| *st == "released") {
        for run in l.running_runs_on_node(name)? {
            s.findings.push(finding("collected", &run, format!("node {name} was {status} while the run's box was running on it")));
        }
    }
    let mut forgot: HashSet<String> = HashSet::new();
    for r in l.audit_of_kind("placement.node_released")? {
        let b: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
        if b["uncollected_runs_lost"].as_u64().unwrap_or(0) > 0 {
            forgot.extend(b["name"].as_str().map(String::from));
        }
    }
    let mut failed: BTreeMap<String, String> = BTreeMap::new();
    for r in l.audit_of_kind("run.fetch_failed")? {
        let b: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
        if let (Some(run), Some(node)) = (r.run, b["node"].as_str()) {
            s.fetch_failures += 1;
            failed.insert(run, node.to_string());
        }
    }
    for (run, node) in &failed {
        // Only files on this host count (#590 review): a taken result or an allowed push leaves
        // them on the node, which must still hold the run.
        if l.files_collected(run)? {
            continue;
        }
        let held: Option<String> =
            l.conn.query_row("SELECT uncollected FROM runs WHERE id = ?1", params![run], |r| r.get(0)).optional()?.flatten();
        match held {
            Some(n) => {
                if let Some(status) = ended.get(&n).filter(|st| *st == "released") {
                    s.findings.push(finding("collected", run, format!("node {n} was {status} with the run's files on it uncollected")));
                }
            }
            None if forgot.contains(node) => {}
            None => s.findings.push(finding(
                "collected",
                run,
                format!("its files on node {node} were never collected (the fetch failed), yet nothing holds the node for them"),
            )),
        }
    }
    // Messages.
    s.messages = l.conn.query_row(
        &format!("SELECT (SELECT count(*) FROM messages WHERE {}) + (SELECT count(*) FROM message_refusals WHERE id NOT IN (SELECT id FROM messages))", crate::PEER),
        [],
        |r| r.get::<_, i64>(0),
    )? as usize;
    let mut st = l.conn.prepare("SELECT id, from_run FROM message_refusals WHERE trim(why) = '' ORDER BY id")?;
    for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (id, from) = row?;
        s.findings.push(finding("messages", &from, format!("message {id} was refused without a reason on its receipt")));
    }
    let mut pushed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (run, b) in shipped(l, "node.message_pushed")? {
        if let Some(id) = b["id"].as_str() {
            s.pushes += 1;
            pushed.entry(id.to_string()).or_default().push(run.unwrap_or_default());
        }
    }
    for (id, runs) in &pushed {
        let refused: Option<String> =
            l.conn.query_row("SELECT why FROM message_refusals WHERE id = ?1", params![id], |r| r.get(0)).optional()?;
        if let Some(why) = refused {
            s.findings.push(finding("messages", &runs[0], format!("message {id} was pushed to a box, but wicket refused it ({why})")));
        }
    }
    for (id, runs) in pushed.iter().filter(|(_, r)| r.len() > 1) {
        s.findings.push(finding(
            "messages",
            &runs[0],
            format!("message {id} was pushed to a box {} times (runs {})", runs.len(), runs.join(", ")),
        ));
    }
    for (run, b) in shipped(l, "node.message_push_lost")? {
        let id = b["id"].as_str().unwrap_or("");
        s.known_lost.push(format!("message {id}, taken for run {}, was never pushed to its box", run.unwrap_or_default()));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MessageMeta, PlacedNodeRow};
    use serde_json::json;
    use wicket_core::{RunId, TenantId};

    fn placed(l: &Ledger, id: &str, name: &str) {
        let n = PlacedNodeRow {
            id: id.into(),
            backend: "vultr".into(),
            name: name.into(),
            owner: "o".into(),
            api_key_secret: "k".into(),
            created_at: 1,
            lease_until: 2,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: None,
        };
        l.record_placed_node(&n).unwrap();
    }

    fn run_on(l: &Ledger, run: &str, node: &str) {
        l.run_started(&TenantId::single(), &RunId(run.into()), "z", "a").unwrap();
        l.set_run_node(run, node).unwrap();
    }

    fn fetch_failed(l: &Ledger, run: &str, node: &str) {
        l.audit(&TenantId::single(), Some(&RunId(run.into())), "run.fetch_failed", &json!({ "node": node, "error": "unreachable" }))
            .unwrap();
        l.set_run_uncollected(run, Some(node)).unwrap();
    }

    fn shipped(l: &Ledger, run: &str, kind: &str, body: Value) {
        let rec = json!({ "kind": kind, "run": run, "ts": 1, "body": body.to_string() });
        l.audit(&TenantId::single(), Some(&RunId(run.into())), "node.audit", &rec).unwrap();
    }

    fn found(l: &Ledger) -> Vec<String> {
        check_end_state(l).unwrap().findings.into_iter().map(|f| format!("{} {}: {}", f.invariant, f.run, f.what)).collect()
    }

    #[test]
    fn a_node_released_with_a_runs_work_on_it_is_found() {
        let l = Ledger::open_in_memory().unwrap();
        placed(&l, "i1", "n1");
        run_on(&l, "r_box", "n1");
        run_on(&l, "r_files", "n1");
        fetch_failed(&l, "r_files", "n1");
        run_on(&l, "r_fetched", "n1");
        fetch_failed(&l, "r_fetched", "n1");
        l.record_collected("r_fetched", "fetched").unwrap();
        l.set_run_uncollected("r_fetched", None).unwrap();
        // A taken result, before the fetch that failed: the files are still on the node (#590 review).
        run_on(&l, "r_outbox", "n1");
        l.record_collected("r_outbox", "outbox").unwrap();
        fetch_failed(&l, "r_outbox", "n1");
        l.run_ended(&RunId("r_outbox".into()), "succeeded", "").unwrap();
        l.run_ended(&RunId("r_files".into()), "failed", "").unwrap();
        l.run_ended(&RunId("r_fetched".into()), "succeeded", "").unwrap();
        // Held, not released: nothing broken.
        assert_eq!(found(&l), Vec::<String>::new());
        assert!(l.placed_node_ended("i1", "released", "test").unwrap());
        let f = found(&l);
        assert_eq!(
            f,
            vec![
                "collected r_box: node n1 was released while the run's box was running on it".to_string(),
                "collected r_files: node n1 was released with the run's files on it uncollected".to_string(),
                "collected r_outbox: node n1 was released with the run's files on it uncollected".to_string(),
            ]
        );
    }

    #[test]
    fn uncollected_files_may_go_only_with_a_node_a_human_released() {
        let l = Ledger::open_in_memory().unwrap();
        placed(&l, "i1", "n1");
        run_on(&l, "r1", "n1");
        fetch_failed(&l, "r1", "n1");
        l.run_ended(&RunId("r1".into()), "failed", "").unwrap();
        // Forgotten, with no human's release on the record.
        l.set_run_uncollected("r1", None).unwrap();
        assert_eq!(found(&l).len(), 1, "{:?}", found(&l));
        assert!(found(&l)[0].contains("never collected"));
        // `wicket node release`, files and all.
        l.placed_node_ended("i1", "released", "released by wicket node release").unwrap();
        l.audit(&TenantId::single(), None, "placement.node_released", &json!({ "id": "i1", "name": "n1", "uncollected_runs_lost": 1 }))
            .unwrap();
        assert_eq!(found(&l), Vec::<String>::new());
        let s = check_end_state(&l).unwrap();
        assert_eq!((s.placed_ended, s.fetch_failures), (1, 1));
    }

    #[test]
    fn a_message_pushed_twice_or_though_refused_is_found() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        l.post_message("m1", &t, "ra", "spiffe://x/b", Some("rb"), "{}", &MessageMeta::default()).unwrap();
        l.post_message("m2", &t, "ra", "spiffe://x/b", Some("rb"), "{}", &MessageMeta::default()).unwrap();
        shipped(&l, "rb", "node.message_pushed", json!({ "id": "m1" }));
        shipped(&l, "rb", "node.message_pushed", json!({ "id": "m2" }));
        assert_eq!(found(&l), Vec::<String>::new());
        // Refused at delivery (the org policy): on the record, and never pushed.
        l.refuse_message("m3", "t", "ra", None, "spiffe://x/b", "the org policy forbids it").unwrap();
        assert_eq!(found(&l), Vec::<String>::new());
        shipped(&l, "rb2", "node.message_pushed", json!({ "id": "m1" }));
        shipped(&l, "rb", "node.message_pushed", json!({ "id": "m3" }));
        l.refuse_message("m4", "t", "ra", None, "spiffe://x/b", " ").unwrap();
        let f = found(&l);
        assert_eq!(f.len(), 3, "{f:?}");
        assert!(f.iter().any(|x| x.contains("m1 was pushed to a box 2 times (runs rb, rb2)")), "{f:?}");
        assert!(f.iter().any(|x| x.contains("m3 was pushed to a box, but wicket refused it")), "{f:?}");
        assert!(f.iter().any(|x| x.contains("m4 was refused without a reason")), "{f:?}");
        // A push lost after the message was taken: the known loss, said, not a finding.
        shipped(&l, "rb", "node.message_push_lost", json!({ "id": "m2" }));
        let s = check_end_state(&l).unwrap();
        assert_eq!((s.findings.len(), s.known_lost.len(), s.pushes), (3, 1, 4));
    }
}
