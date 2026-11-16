//! `wicket doctor --invariants` (#326): #321's properties, checked on this installation's own
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
//! What it can't see: requests the proxies never recorded (an audit write that failed refuses the
//! request), a node's records not yet shipped, and a zone wicket didn't keep. Those are said, not
//! guessed.

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use wicket_store::Ledger;

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
    pub runs_with_spend: usize,
    pub leases: usize,
    pub findings: Vec<Finding>,
}

/// One egress or model record: its run, when (Unix seconds, the writer's clock), and its event.
struct Rec {
    run: String,
    ts: i64,
    ev: Value,
}

/// Every proxy event in the ledger: the control host's own `op` records and the ones nodes shipped.
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

/// The zone a run was started in, where wicket kept it: a spawned child's manifest in its parent's
/// run directory, or a long-lived agent's.
fn zone_of(l: &Ledger, data: &Path, run: &str, agent: Option<&str>) -> Option<wicket_core::ZoneSpec> {
    let child = std::fs::read_dir(data.join("runs"))
        .ok()?
        .flatten()
        .map(|d| d.path().join("children").join(format!("{run}.yaml")))
        .find(|p| p.is_file());
    let yaml = match child {
        Some(p) => std::fs::read_to_string(p).ok()?,
        None => l.agent(agent?).ok()??.manifest,
    };
    wicket_agent::load(&yaml).ok().map(|m| m.zone)
}

pub fn check(l: &Ledger, data: &Path, grace_secs: i64, now: i64) -> Result<Summary> {
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
            Some("egress") if matches!(ev["outcome"].as_str(), Some("allow" | "spliced")) => {
                s.allows += 1;
                let (method, host, path) =
                    (ev["method"].as_str().unwrap_or(""), ev["host"].as_str().unwrap_or(""), ev["path"].as_str().unwrap_or(""));
                let what = format!("{method} {host}{path} at {}", r.ts);
                match why(ev["detail"].as_str().unwrap_or("")) {
                    Why::Grant(id) => {
                        s.by_grant += 1;
                        let risk = ev["risk"].as_str().and_then(wicket_core::RiskClass::from_name).map(|r| r.rank()).unwrap_or(0);
                        if let Some(why) = grant_fault(l, &id, &r.run, method, host, path, risk, r.ts, revoked.get(&id).copied())? {
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
                            let spec = zone_of(l, data, &r.run, start.and_then(|b| b["agent_id"].as_str()))?;
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

/// `wicket doctor --invariants`: the check on this installation's ledger, printed; an error if any
/// invariant was broken.
pub fn doctor(lease_grace: i64) -> Result<()> {
    let l = Ledger::open(&crate::ledger_path())?;
    let s = check(&l, &crate::data_dir(), lease_grace, wicket_store::now())?;
    println!(
        "egress: {} allowed request(s) checked ({} by a grant, {} by reach; {} of those without a kept zone, only their rule's existence checked)",
        s.allows, s.by_grant, s.by_reach, s.unverified
    );
    println!("model spend: {} run(s) checked against their quota grants", s.runs_with_spend);
    println!("leases: {} checked (grace {lease_grace}s)", s.leases);
    if s.findings.is_empty() {
        println!("invariants hold: every allowed egress request had a reach rule or a live grant, no run passed its model budget, no node ran past its lease");
        return Ok(());
    }
    for f in &s.findings {
        println!("BROKEN {} (run {}): {}", f.invariant, f.run, f.what);
    }
    anyhow::bail!("{} invariant violation(s)", s.findings.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wicket_core::{Op, RunId, TenantId};

    const RUN: &str = "run_inv";

    fn ledger() -> Ledger {
        let l = Ledger::open_in_memory().unwrap();
        l.run_started(&TenantId::single(), &RunId(RUN.into()), "z", "a").unwrap();
        l.audit(&TenantId::single(), Some(&RunId(RUN.into())), "run.start", &json!({ "zone": "z", "reach": 1 })).unwrap();
        l
    }

    fn egress(l: &Ledger, method: &str, host: &str, path: &str, outcome: &str, detail: &str) {
        let ev = json!({ "kind": "egress", "method": method, "host": host, "path": path, "risk": "R1ReadScoped", "outcome": outcome, "detail": detail });
        l.audit(&TenantId::single(), Some(&RunId(RUN.into())), "op", &ev).unwrap();
    }

    fn findings(l: &Ledger, data: &Path) -> Vec<String> {
        check(l, data, 600, wicket_store::now()).unwrap().findings.into_iter().map(|f| format!("{}: {}", f.invariant, f.what)).collect()
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-inv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A request a grant answered: granted for GET api.example.com/x.
    fn granted(l: &mut Ledger) -> String {
        let op = Op::egress(&TenantId::single(), &RunId(RUN.into()), "z", "GET", "api.example.com", "/x");
        let (req, _) = l.pending_for(&op, "blocked", None).unwrap();
        let a = wicket_store::Approval {
            uses: Some(5),
            ttl: std::time::Duration::from_secs(600),
            path_prefix: None,
            decided_by: "test".into(),
        };
        l.approve(&req, &a).unwrap()
    }

    #[test]
    fn a_grant_allow_must_match_a_live_grant_for_the_request() {
        let mut l = ledger();
        let d = tmp("grant");
        let g = granted(&mut l);
        egress(&l, "GET", "api.example.com", "/x", "allow", &format!("grant {g} (counted on the node)"));
        assert_eq!(findings(&l, &d), Vec::<String>::new());
        egress(&l, "GET", "api.example.com", "/other", "allow", &format!("grant {g} (counted on the node)"));
        egress(&l, "GET", "api.example.com", "/x", "allow", "grant g-never (counted on the node)");
        egress(&l, "GET", "api.example.com", "/x", "allow", "GrantHold { grant: \"g-held\", until: 1 }");
        let f = findings(&l, &d);
        assert_eq!(f.len(), 3, "{f:?}");
        assert!(f[0].contains("/other") && f[0].contains("which is for GET api.example.com/x"), "{f:?}");
        assert!(f[1].contains("g-never, which was never issued"), "{f:?}");
        assert!(f[2].contains("g-held, which was never issued"), "{f:?}");
        // Used well after its revocation: broken; within the feed's window: not.
        let l = ledger();
        let mut l = l;
        let g = granted(&mut l);
        l.audit(&TenantId::single(), None, "grant.revoked", &json!({ "grant": g, "by": "test" })).unwrap();
        egress(&l, "GET", "api.example.com", "/x", "allow", &format!("grant {g}"));
        assert_eq!(findings(&l, &d), Vec::<String>::new(), "within the window a node may still decide on it");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_reach_allow_is_checked_against_the_zone_when_wicket_kept_it() {
        let l = ledger();
        let d = tmp("reach");
        // No zone kept: only that the rule exists.
        egress(&l, "GET", "example.com", "/", "allow", "reach rule 0 (node)");
        egress(&l, "GET", "example.com", "/", "allow", "reach rule 3 (node)");
        let s = check(&l, &d, 600, wicket_store::now()).unwrap();
        assert_eq!((s.allows, s.by_reach, s.unverified), (2, 2, 2));
        assert_eq!(s.findings.len(), 1, "{:?}", s.findings);
        assert!(s.findings[0].what.contains("reach rule 3, but its zone has 1"));
        // A spawned child's zone, kept in its parent's run directory: decided again here.
        std::fs::create_dir_all(d.join("runs/run_parent/children")).unwrap();
        std::fs::write(
            d.join(format!("runs/run_parent/children/{RUN}.yaml")),
            "task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  reach: [{ host: example.com, methods: [GET], paths: [\"/\"] }]\n",
        )
        .unwrap();
        let l = ledger();
        egress(&l, "GET", "example.com", "/", "allow", "reach rule 0 (node)");
        egress(&l, "POST", "example.com", "/", "allow", "reach rule 0 (node)");
        egress(&l, "GET", "example.org", "/", "allow", "the box's token (node)");
        egress(&l, "CONNECT", "example.com", "/", "spliced", "reach rule 0 allows the host wholesale: not inspected");
        egress(&l, "GET", "example.org", "/", "allow", "because I said so");
        let f = findings(&l, &d);
        assert_eq!(f.len(), 4, "{f:?}");
        assert!(f[0].starts_with("egress: POST example.com/") && f[0].contains("the run's zone doesn't allow it"), "{f:?}");
        assert!(f[1].starts_with("egress: GET example.org/"), "{f:?}");
        assert!(f[2].contains("CONNECT"), "a host spliced wholesale needs a rule without limits: {f:?}");
        assert!(f[3].contains("a reason this check doesn't know"), "{f:?}");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_nodes_shipped_records_are_checked_too() {
        let l = ledger();
        let d = tmp("node");
        let inner = json!({ "kind": "egress", "method": "GET", "host": "x.example", "path": "/", "risk": "R1ReadScoped", "outcome": "allow", "detail": "grant g-nope (counted on the node)" });
        let outer = json!({ "node": "n1", "seq": 1, "ts": wicket_store::now(), "tenant": "default", "run": RUN, "kind": "op", "body": inner.to_string() });
        l.audit(&TenantId::single(), Some(&RunId(RUN.into())), "node.audit", &outer).unwrap();
        let f = findings(&l, &d);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("g-nope, which was never issued"));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn model_calls_that_went_through_stay_within_the_quota() {
        let l = ledger();
        let d = tmp("spend");
        let quotas = [
            wicket_store::Quota { resource: "model.requests", amount: 2 },
            wicket_store::Quota { resource: "model.output_tokens", amount: 100 },
        ];
        l.record_quota_grants(&TenantId::single(), "z", &RunId(RUN.into()), "test", &quotas, 3600).unwrap();
        let llm = |status: u16, out: u64| {
            let ev = json!({ "kind": "llm", "status": status, "output_tokens": out, "input_tokens": 1, "cached_tokens": 0, "requests": 1, "outcome": "ok" });
            l.audit(&TenantId::single(), Some(&RunId(RUN.into())), "op", &ev).unwrap();
        };
        llm(200, 40);
        llm(200, 40);
        llm(429, 0);
        assert_eq!(findings(&l, &d), Vec::<String>::new(), "a refused call isn't a call that went through");
        llm(200, 30);
        let f = findings(&l, &d);
        assert_eq!(f, ["budget: 3 model calls went through, budget 2", "budget: 110 output tokens, budget 100"]);
        let _ = std::fs::remove_dir_all(d);
    }
}
