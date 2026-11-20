//! Decisions on standing reach (#572): a human approves an agent's ask once, for its principal or
//! its zone, as asked, narrowed to the evidence or edited; denies it; revokes or renews an approved
//! rule. Each is on the audit record, and an approval whose record can't be written is undone
//! (fail closed), as a grant's is.
//!
//! Only a human decides: lasting reach is not an agent's to give (`agent_term_refusal` already
//! refuses unbounded terms to agents). Approval is checked against the operator's own authority
//! (`operators.yaml`); the org layer and every ancestor's ceiling still bound the rule where it
//! is enforced, on the box's node, which no grant lifts.

use crate::grant::Granter;
use anyhow::{bail, Context, Result};
use std::time::Duration;
use wicket_core::manifest::ReachRule;
use wicket_core::TenantId;
use wicket_store::{Ledger, Standing, StandingBound, StandingTerms};

/// The longest lifetime an operator may pick (beyond it: until revoked, chosen as such).
pub const MAX_STANDING_TTL: Duration = Duration::from_secs(366 * 24 * 3600);
/// The lifetime the console and the CLI offer first.
pub const DEFAULT_STANDING_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// What an approval approves.
#[derive(Clone, Debug)]
pub struct Approve {
    /// The rule: None for the one asked for.
    pub rule: Option<ReachRule>,
    pub bound: StandingBound,
    /// None: until revoked.
    pub ttl: Option<Duration>,
}

/// The rule narrowed to what the evidence shows a human let through: the method and path pairs
/// its blocked requests were granted for, exactly ([`wicket_core::standing::narrow`]). None if
/// nothing it covers was granted.
pub fn narrowed(s: &Standing) -> Option<ReachRule> {
    wicket_core::standing::narrow(&s.rule.host, s.evidence.ops.iter().map(|o| (o.method.as_str(), o.path.as_str(), o.granted)))
}

/// What `rule` allows beyond the evidence, in words, for the card: each method and path pair of it
/// that no blocked request asked for, globs that cover paths none asked for, and `allow_dangerous`
/// (#572 review, M2: a narrowed rule's pairs are checked too, not assumed).
pub fn beyond(s: &Standing, rule: &ReachRule) -> Vec<String> {
    let mut out = vec![];
    if s.evidence.ops.is_empty() {
        out.push("no blocked request it covers in the last 14 days: all of it is beyond the evidence".into());
    }
    for m in &rule.methods {
        for p in &rule.paths {
            let one = ReachRule {
                host: rule.host.clone(),
                methods: vec![m.clone()],
                paths: vec![p.clone()],
                allow_dangerous: true,
                decode_slash: vec![],
            };
            let asked = s.evidence.ops.iter().any(|o| {
                o.method.eq_ignore_ascii_case(m)
                    && one
                        .allows(&wicket_core::Op::egress(
                            &wicket_core::TenantId::single(),
                            &wicket_core::RunId(String::new()),
                            "",
                            m,
                            &rule.host,
                            &o.path,
                        ))
                        .unwrap_or(false)
            });
            if !asked && !s.evidence.ops.is_empty() {
                out.push(format!("{m} {p}: no request asked for it"));
            }
        }
    }
    for p in rule.paths.iter().filter(|p| p.contains(['*', '?', '[', '{'])) {
        out.push(format!("{p} is a glob: it covers paths no request asked for too"));
    }
    if rule.allow_dangerous {
        out.push("allow_dangerous: R3 and R4 requests (irreversible, external) are allowed too".into());
    }
    out
}

fn check_ttl(ttl: Option<Duration>) -> Result<()> {
    match ttl {
        Some(t) if t.is_zero() => bail!("a standing rule needs a lifetime (or until revoked)"),
        Some(t) if t > MAX_STANDING_TTL => {
            bail!(
                "a standing rule lasts at most {} unless it is approved until revoked",
                wicket_core::time::format_duration(MAX_STANDING_TTL)
            )
        }
        _ => Ok(()),
    }
}

/// The operator's own authority over a rule: every method of it on its host, at the risk it can
/// reach (R4 with `allow_dangerous`, else R2).
fn may_decide(by: &Granter, rule: &ReachRule) -> Result<crate::operators::Operator> {
    let Granter::Human(o) = by else { bail!("standing reach is decided by a human operator, not {}", by.label()) };
    let risk = if rule.allow_dangerous { 4 } else { 2 };
    for m in &rule.methods {
        o.may_decide(&crate::operators::Asked::of_op(m, rule.host.trim_start_matches("*."), Some(risk))).map_err(anyhow::Error::msg)?;
    }
    Ok(o.clone())
}

fn refused(l: &Ledger, by: &Granter, id: &str, decision: &str, why: anyhow::Error) -> anyhow::Error {
    let record = serde_json::json!({ "target": id, "decision": decision, "by": by.label(), "why": format!("{why:#}") });
    match l.audit(&TenantId::single(), None, "decision.refused", &record) {
        Ok(_) => why.context("refused (the refusal is on the audit record)"),
        Err(e) => why.context(format!("refused (the refusal could not be recorded: {e})")),
    }
}

/// `extra`'s fields, merged into an audit record (the console's: how it was decided, and the
/// signed action).
fn merged(mut record: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
    if let (Some(r), serde_json::Value::Object(x)) = (record.as_object_mut(), extra) {
        r.extend(x);
    }
    record
}

/// Approves standing ask `id` as `by`, on the effect `shown` (if the decider was shown one).
/// `extra` goes on the decision's audit record. The rule approved and its effect.
pub fn approve(
    l: &Ledger,
    by: &Granter,
    id: &str,
    a: &Approve,
    shown: Option<&str>,
    extra: serde_json::Value,
) -> Result<(ReachRule, String)> {
    let s = l.standing(id)?;
    let rule = a.rule.clone().unwrap_or_else(|| s.rule.clone());
    let o = match may_decide(by, &rule).and_then(|o| check_ttl(a.ttl).map(|_| o)) {
        Ok(o) => o,
        Err(why) => return Err(refused(l, by, id, "approve", why)),
    };
    let terms = StandingTerms { bound: a.bound, ttl_secs: a.ttl.map(|t| t.as_secs()) };
    let effect = match l.approve_standing(id, &rule, &terms, &o.label, shown) {
        Ok(e) => e,
        Err(e @ wicket_store::StoreError::EffectChanged(..)) => return Err(refused(l, by, id, "approve", e.into())),
        Err(e) => return Err(e.into()),
    };
    let record = serde_json::json!({
        "decision": "approve", "standing": id, "by": o.label, "granter": "human", "granter_identity": o.id,
        "principal": s.principal, "zone": s.zone, "run": s.run, "rule": rule, "asked": s.rule,
        "bound": a.bound.as_str(), "ttl_secs": terms.ttl_secs, "effect_sha256": effect,
        "evidence": { "requests": s.evidence.requests, "granted": s.evidence.granted },
    });
    let record = merged(record, extra);
    if let Err(e) = l.audit(&TenantId::single(), Some(&wicket_core::RunId(s.run.clone())), "decision", &record) {
        let _ = l.revoke_standing(id, "wicket:audit-failed");
        return Err(anyhow::Error::from(e).context("the approval could not be recorded in the audit log, so it was undone"));
    }
    Ok((rule, effect))
}

/// Denies standing ask `id` as `by`; `extra` goes on the audit record.
pub fn deny(l: &Ledger, by: &Granter, id: &str, extra: serde_json::Value) -> Result<()> {
    let s = l.standing(id)?;
    let Granter::Human(o) = by else {
        return Err(refused(l, by, id, "deny", anyhow::anyhow!("standing reach is decided by a human operator")));
    };
    l.deny_standing(id, &o.label)?;
    l.audit(
        &TenantId::single(),
        Some(&wicket_core::RunId(s.run.clone())),
        "decision",
        &merged(
            serde_json::json!({ "decision": "deny", "standing": id, "by": o.label, "granter": "human", "granter_identity": o.id }),
            extra,
        ),
    )?;
    Ok(())
}

/// Revokes approved rule `id`: from now on it allows nothing (on a node, once the box's run
/// publishes the revocation).
pub fn revoke(l: &Ledger, by: &str, id: &str) -> Result<Standing> {
    l.revoke_standing(id, by)?;
    let s = l.standing(id)?;
    l.audit(
        &TenantId::single(),
        None,
        "standing.revoked",
        &serde_json::json!({ "standing": id, "by": by, "rule": s.rule, "bound": s.bound }),
    )?;
    Ok(s)
}

/// Moves approved rule `id`'s lapse to `ttl` from now (None: until revoked); `extra` goes on the
/// audit record.
pub fn renew(l: &Ledger, by: &Granter, id: &str, ttl: Option<Duration>, extra: serde_json::Value) -> Result<Option<i64>> {
    let s = l.standing(id)?;
    if let Err(why) = may_decide(by, &s.rule).and_then(|_| check_ttl(ttl)) {
        return Err(refused(l, by, id, "renew", why));
    }
    let until = ttl.map(|t| wicket_store::now().saturating_add(t.as_secs() as i64));
    l.renew_standing(id, until).context("renewing")?;
    // Recorded, or undone: a renewal is a decision (#572 review, L3).
    let recorded = l.audit(
        &TenantId::single(),
        None,
        "decision",
        &merged(
            serde_json::json!({ "decision": "renew", "standing": id, "by": by.label(), "until": until, "previous_until": s.expires_at }),
            extra,
        ),
    );
    if let Err(e) = recorded {
        l.restore_standing_end(id, s.expires_at)?;
        return Err(anyhow::Error::from(e).context("the renewal could not be recorded in the audit log, so it was undone"));
    }
    Ok(until)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::RunId;

    fn human() -> Granter {
        let p = crate::operators::Policy::default();
        Granter::Human(crate::operators::Operator::new("t0", "unix", "ann", "ann".into(), &p))
    }

    /// A run of the worker agent, with its identity.
    fn worker(l: &Ledger) -> RunId {
        let t = TenantId::single();
        let r = RunId("run_w".into());
        l.run_started(&t, &r, "work", "worker").unwrap();
        l.put_identity(&wicket_store::IdentityRow {
            run: r.0.clone(),
            tenant: t.0.clone(),
            spiffe_id: "spiffe://w.test/t/t0/z/work/a/worker".into(),
            zone: "work".into(),
            agent: "worker".into(),
            parent_run: None,
            accept_from: vec![],
            jws: "jws".into(),
            issued_at: 1,
        })
        .unwrap();
        r
    }

    /// Blocked requests of the worker's (`granted`: approved), then its ask for `rule`.
    fn asked_with(l: &mut Ledger, blocked: &[(&str, &str, bool)], rule: &str) -> String {
        let t = TenantId::single();
        let r = worker(l);
        for (m, p, granted) in blocked {
            let op = wicket_core::Op::egress(&t, &r, "work", m, "api.github.com", p);
            let (rid, _) = l.pending_for(&op, "blocked", None).unwrap();
            if *granted {
                // A grant, as `wicket approve` makes it.
                let a = wicket_store::Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "op".into() };
                l.approve(&rid, &a).unwrap();
            }
        }
        let rule: ReachRule = wicket_core::yaml::from_str(rule).unwrap();
        l.ask_standing(&t, &r, "work", "digest", "spiffe://w.test/t/t0/z/work/a/worker", &rule, "CI logs").unwrap().0
    }

    /// An ask with evidence: job-log reads granted twice and once, in one run.
    fn asked(l: &mut Ledger) -> String {
        let logs = |j: u32| format!("/repos/o/r/actions/jobs/{j}/logs");
        let (a, b) = (logs(1), logs(2));
        asked_with(
            l,
            &[("GET", &a, true), ("GET", &b, true), ("GET", &b, true)],
            "{ host: api.github.com, methods: [GET, POST], paths: ['/repos/o/r/**'] }",
        )
    }

    /// #572: the card's "wider than the evidence" names each method and path pair no request asked
    /// for, and the glob; narrowed, the rule is the granted ops exactly, with nothing beyond it;
    /// approved narrowed, that is what is recorded and audited.
    #[test]
    fn an_operator_approves_a_standing_ask_narrowed_to_its_evidence() {
        let mut l = Ledger::open_in_memory().unwrap();
        let id = asked(&mut l);
        let s = l.standing(&id).unwrap();
        let b = beyond(&s, &s.rule);
        assert!(b.iter().any(|x| x == "POST /repos/o/r/**: no request asked for it"), "{b:?}");
        assert!(b.iter().any(|x| x.starts_with("/repos/o/r/** is a glob")), "{b:?}");
        let n = narrowed(&s).unwrap();
        assert_eq!(n.methods, ["GET"]);
        assert_eq!(n.paths, ["/repos/o/r/actions/jobs/1/logs", "/repos/o/r/actions/jobs/2/logs"]);
        assert!(!n.allow_dangerous);
        assert!(beyond(&s, &n).is_empty(), "{:?}", beyond(&s, &n));
        let a = Approve { rule: Some(n.clone()), bound: StandingBound::Agent, ttl: Some(DEFAULT_STANDING_TTL) };
        let (rule, effect) = approve(&l, &human(), &id, &a, None, serde_json::json!({})).unwrap();
        assert_eq!(rule.paths, n.paths);
        let s = l.standing(&id).unwrap();
        assert_eq!((s.status.as_str(), s.effect_sha256.as_deref()), ("approved", Some(effect.as_str())));
        let audited = l.audit_tail(10).unwrap().into_iter().find(|r| r.2 == "decision").unwrap();
        assert!(audited.4.contains(&format!("\"standing\":\"{id}\"")) && audited.4.contains("\"bound\":\"agent\""), "{}", audited.4);
        // Renewed until revoked, then revoked.
        assert_eq!(renew(&l, &human(), &id, None, serde_json::json!({})).unwrap(), None);
        revoke(&l, "ann", &id).unwrap();
        assert!(l.audit_tail(10).unwrap().iter().any(|r| r.2 == "standing.revoked"));
    }

    /// #572 review, M2: narrowing never makes a pair the evidence lacks (GET /a and DELETE /b
    /// granted isn't GET and DELETE on both), drops allow_dangerous, ignores what wasn't granted,
    /// and stays within a token block's pairs.
    #[test]
    fn narrowing_keeps_only_granted_pairs() {
        let mut l = Ledger::open_in_memory().unwrap();
        let id = asked_with(
            &mut l,
            &[("GET", "/a", true), ("GET", "/a", true), ("DELETE", "/b", true), ("POST", "/c", false)],
            "{ host: api.github.com, methods: [GET, DELETE, POST], paths: ['/**'], allow_dangerous: true }",
        );
        let n = narrowed(&l.standing(&id).unwrap()).unwrap();
        assert_eq!((n.methods.clone(), n.paths.clone(), n.allow_dangerous), (vec!["GET".to_string()], vec!["/a".to_string()], false));
        let op = |m: &str, p: &str| wicket_core::Op::egress(&TenantId::single(), &RunId("run_w".into()), "work", m, "api.github.com", p);
        assert!(n.allows(&op("GET", "/a")).unwrap() && !n.allows(&op("DELETE", "/a")).unwrap() && !n.allows(&op("GET", "/b")).unwrap());
        // Methods granted on exactly the same paths stay together.
        let mut l = Ledger::open_in_memory().unwrap();
        let id = asked_with(
            &mut l,
            &[("GET", "/a", true), ("HEAD", "/a", true)],
            "{ host: api.github.com, methods: [GET, HEAD], paths: ['/**'] }",
        );
        assert_eq!(narrowed(&l.standing(&id).unwrap()).unwrap().methods, ["GET", "HEAD"]);
        // Nothing granted: nothing to narrow to.
        let mut l = Ledger::open_in_memory().unwrap();
        let id = asked_with(&mut l, &[("GET", "/a", false)], "{ host: api.github.com }");
        assert!(narrowed(&l.standing(&id).unwrap()).is_none());
    }

    /// Only a human decides; a lifetime past the cap is refused unless it is "until revoked"; an
    /// approval on another effect than the one shown is refused; each refusal is audited.
    #[test]
    fn standing_reach_is_a_humans_to_give_within_its_bounds() {
        let mut l = Ledger::open_in_memory().unwrap();
        let id = asked(&mut l);
        let ask = wicket_store::CapacityAsk { node: "n".into(), plan: "p".into(), region: "r".into(), hourly: 0, worst: 0 };
        let agent = Granter::Capacity { grant: "g-x".into(), ask };
        let a = Approve { rule: None, bound: StandingBound::Agent, ttl: Some(DEFAULT_STANDING_TTL) };
        assert!(format!("{:#}", approve(&l, &agent, &id, &a, None, serde_json::json!({})).unwrap_err()).contains("human"));
        let long = Approve { ttl: Some(MAX_STANDING_TTL * 2), ..a.clone() };
        assert!(format!("{:#}", approve(&l, &human(), &id, &long, None, serde_json::json!({})).unwrap_err()).contains("at most"));
        assert!(approve(&l, &human(), &id, &a, Some("not-the-effect"), serde_json::json!({})).is_err());
        let refusals = l.audit_tail(20).unwrap().into_iter().filter(|r| r.2 == "decision.refused").count();
        assert_eq!(refusals, 3);
        let forever = Approve { ttl: None, ..a };
        approve(&l, &human(), &id, &forever, None, serde_json::json!({})).unwrap();
        assert_eq!(l.standing(&id).unwrap().expires_at, None);
    }
}
