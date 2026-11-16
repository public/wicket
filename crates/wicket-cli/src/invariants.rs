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
use std::path::Path;
use wicket_store::invariants::Summary;
use wicket_store::Ledger;

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

/// The check (`wicket_store::invariants::check`) on this installation's ledger, with the zones
/// wicket kept under `data`.
pub fn check(l: &Ledger, data: &Path, grace_secs: i64, now: i64) -> Result<Summary> {
    Ok(wicket_store::invariants::check(l, &|run, agent| zone_of(l, data, run, agent), grace_secs, now)?)
}

/// `wicket doctor --invariants`: the check on this installation's ledger, printed; an error if any
/// invariant was broken.
pub fn doctor(lease_grace: i64) -> Result<()> {
    let l = Ledger::open(&crate::ledger_path())?;
    let s = check(&l, &crate::data_dir(), lease_grace, wicket_store::now())?;
    println!(
        "egress: {} allowed request(s) checked ({} by a grant, {} by reach; {} of those without a kept zone, only their rule's existence checked), and {} wicket DNS answer(s)",
        s.allows, s.by_grant, s.by_reach, s.unverified, s.dns_answers
    );
    println!("model spend: {} run(s) checked against their quota grants", s.runs_with_spend);
    println!("leases: {} checked (grace {lease_grace}s)", s.leases);
    println!(
        "collected: {} ended placed node(s) and {} failed fetch(es) checked; messages: {} on the record, {} push(es) to boxes",
        s.end.placed_ended, s.end.fetch_failures, s.end.messages, s.end.pushes
    );
    for k in &s.end.known_lost {
        println!("KNOWN messages: {k}");
    }
    if s.findings.is_empty() {
        println!("invariants hold: every allowed egress request had a reach rule or a live grant, no run passed its model budget, no node ran past its lease, no node was released with work on it uncollected, no message was pushed twice or pushed though refused");
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

    /// A wicket DNS answer (for HTTP/3) is an answer, not a request: counted, and checked against
    /// the zone where it was kept, never "an allow for an unknown reason".
    #[test]
    fn a_dns_answer_is_checked_as_an_answer() {
        let d = tmp("dns");
        let dns = |l: &Ledger, host: &str| {
            let ev = json!({ "kind": "egress", "method": "DNS", "host": host, "path": "", "risk": "-", "outcome": "allow",
                             "detail": "resolved to 198.19.0.7 (wicket DNS, for HTTP/3)" });
            l.audit(&TenantId::single(), Some(&RunId(RUN.into())), "op", &ev).unwrap();
        };
        let l = ledger();
        dns(&l, "example.com");
        let s = check(&l, &d, 600, wicket_store::now()).unwrap();
        assert_eq!((s.allows, s.dns_answers, s.findings.len()), (0, 1, 0), "no zone kept: counted only");
        std::fs::create_dir_all(d.join("runs/run_parent/children")).unwrap();
        std::fs::write(
            d.join(format!("runs/run_parent/children/{RUN}.yaml")),
            "task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  reach: [{ host: example.com, methods: [GET], paths: [\"/\"] }]\n",
        )
        .unwrap();
        // An unlisted host in a zone that escalates is open: wicket answers it (nothing leaves).
        let l = ledger();
        dns(&l, "example.com");
        dns(&l, "exfil.example.org");
        assert_eq!(findings(&l, &d), Vec::<String>::new(), "an escalating zone keeps unlisted hosts open");
        // A zone that hides unlisted hosts, or forbids one, gets no answer for it: one would break.
        std::fs::write(
            d.join(format!("runs/run_parent/children/{RUN}.yaml")),
            "task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  unlisted_hosts: hide\n  reach: [{ host: example.com, methods: [GET], paths: [\"/\"] }]\n  forbid: [{ host: bad.example.com }]\n",
        )
        .unwrap();
        let l = ledger();
        dns(&l, "example.com");
        dns(&l, "exfil.example.org");
        dns(&l, "bad.example.com");
        let f = findings(&l, &d);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|f| f.contains("forbids or hides")), "{f:?}");
        assert!(f[0].contains("resolved exfil.example.org") && f[1].contains("resolved bad.example.com"), "{f:?}");
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
    #[test]
    fn no_run_outlasts_its_lease() {
        let mut l = ledger();
        let d = tmp("lease");
        let now = wicket_store::now();
        let lease = wicket_store::LeaseRow {
            id: "l-inv".into(),
            tenant: "default".into(),
            run: RUN.into(),
            request_id: None,
            provider: "static".into(),
            spec: json!({}),
            hourly_cap: 0,
            reserved: 0,
            duration_secs: 3600,
            created_at: now - 9000,
            not_after: Some(now - 5000),
            status: "active".into(),
            node_id: None,
            node_name: None,
            ssh_target: None,
            host_key: None,
            billed: None,
            ended_at: None,
            detail: None,
        };
        let budget = wicket_store::LeaseBudget { max_hourly: i64::MAX, max_total: i64::MAX };
        l.create_lease(&lease, budget).unwrap().unwrap();
        // As the reconciler does: active once its node is up, with the end its billing sets.
        assert!(l.lease_transition("l-inv", &["pending"], "active", "test").unwrap());
        assert!(l.set_lease_not_after("l-inv", now - 5000).unwrap());
        l.set_run_lease(RUN, "l-inv").unwrap();
        let f = check(&l, &d, 600, now).unwrap().findings;
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].what.contains("ran on lease l-inv until") && f[0].what.contains("5000s past its end"), "{f:?}");
        assert!(check(&l, &d, 6000, now).unwrap().findings.is_empty(), "within the grace");
        let _ = std::fs::remove_dir_all(d);
    }
}
