//! One way to decide a pending request (#256): [`decide`], used by `wicket approve`/`deny`, the
//! console and (with #50) agents.
//!
//! Every request kind is the same record: an access request, a SPAWN beyond the asker's zone, a
//! LINK, a CAPACITY lease and an UPDATE are all a pending row in the ledger's `requests`, and
//! approving one makes one grant (resource, principal, lifetime, uses). What differs is only who
//! decides ([`Granter`]) and what a kind does once approved (a capacity lease is provisioned, or its
//! reservation released). The limits every grant has, such as its lifetime cap, live here, not in
//! each caller.

use crate::capacity;
use anyhow::{bail, Result};
use std::time::Duration;
use wicket_core::TenantId;
use wicket_store::{Approval, Ledger, Request};

/// The longest lifetime a grant may have. Every grant has one; renewal is a new decision.
pub const MAX_TTL: Duration = Duration::from_secs(24 * 3600);

/// The principal deciding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Granter {
    /// A human: `$USER`-style on the CLI, `passkey:<name>` on the console.
    Human(String),
}

impl Granter {
    /// How the decision is recorded (`decided_by`, the audit record's `by`).
    pub fn label(&self) -> String {
        match self {
            Granter::Human(by) => by.clone(),
        }
    }
}

/// What an approval grants, within what was asked.
#[derive(Clone, Debug)]
pub struct Terms {
    /// None: unlimited uses until it expires.
    pub uses: Option<u32>,
    /// Its lifetime: at most [`MAX_TTL`].
    pub ttl: Duration,
    /// Grant every path under this prefix: one that covers the asked path, or (for a prefix ask)
    /// lies within the asked prefix.
    pub prefix: Option<String>,
    /// Usable by any run in the request's zone, not only the one that asked.
    pub zone_wide: bool,
}

/// A decision on one request.
#[derive(Clone, Debug)]
pub enum Verdict {
    Approve(Terms),
    Deny,
}

/// What [`decide`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decided {
    /// The grant made, and the capacity lease the request asked for, if it is a capacity ask:
    /// provisioned by the next reconcile pass (`wicket approve` runs one at once).
    Approved { grant: String, lease: Option<String> },
    /// Denied; a capacity ask's reservation was released at once.
    Denied { lease: Option<String> },
}

/// Decides pending request `id` as `by`. An approval is one grant, which exists only if its
/// decision is on the audit record (otherwise it is revoked again: fail closed). `extra` is merged
/// into the record (the console's signed decision).
pub fn decide(l: &mut Ledger, by: &Granter, id: &str, v: &Verdict, extra: serde_json::Value) -> Result<Decided> {
    match v {
        Verdict::Approve(t) => approve(l, by, id, t, extra),
        Verdict::Deny => deny(l, by, id, extra),
    }
}

/// Whether terms may be granted for `req` at all, whoever grants them.
pub fn check_terms(req: &Request, t: &Terms) -> Result<()> {
    if t.ttl > MAX_TTL {
        bail!("grants last at most {}; renew it with a new decision", humantime::format_duration(MAX_TTL));
    }
    if t.ttl.is_zero() {
        bail!("a grant needs a lifetime");
    }
    if t.uses == Some(0) {
        bail!("a grant needs at least one use");
    }
    if let Some(p) = &t.prefix {
        check_prefix(req, p).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

fn approve(l: &mut Ledger, by: &Granter, id: &str, t: &Terms, extra: serde_json::Value) -> Result<Decided> {
    let req = l.request(id)?;
    check_terms(&req, t)?;
    let lease = capacity::lease_of_request(l, &req)?;
    let label = by.label();
    let a = Approval { uses: t.uses, ttl: t.ttl, path_prefix: t.prefix.clone(), decided_by: label.clone() };
    let gid = if t.zone_wide { l.approve_zone_wide(id, &a)? } else { l.approve(id, &a)? };
    let mut record = serde_json::json!({
        "request": id, "decision": "approve", "grant": gid, "by": label,
        "method": req.method, "host": req.host, "path": req.path,
        "requested_by": req.attribution.iter().flat_map(wicket_proxy::attributed_agents).collect::<Vec<_>>(),
        "agent_identity": crate::verified_identity(l, &req.run, None),
        "uses": t.uses, "ttl_secs": t.ttl.as_secs(), "prefix": t.prefix, "scope_prefix": req.scope_prefix,
        "scope": if t.zone_wide { "zone" } else { "run" }, "run": req.run, "zone": req.zone, "lease": lease,
    });
    merge(&mut record, extra);
    if let Err(e) = l.audit(&TenantId::single(), None, "decision", &record) {
        let _ = l.revoke_grant(&gid);
        return Err(anyhow::Error::from(e).context("the approval could not be recorded in the audit log, so its grant was revoked"));
    }
    Ok(Decided::Approved { grant: gid, lease })
}

fn deny(l: &mut Ledger, by: &Granter, id: &str, extra: serde_json::Value) -> Result<Decided> {
    let label = by.label();
    l.deny(id, &label)?;
    let mut record = serde_json::json!({ "request": id, "decision": "deny", "by": label });
    merge(&mut record, extra);
    l.audit(&TenantId::single(), None, "decision", &record)?;
    let req = l.request(id)?;
    let lease = capacity::lease_of_request(l, &req)?;
    if let Some(lease) = lease.as_deref() {
        l.lease_ended(lease, "denied", &format!("request {id} denied by {label}"), None)?;
    }
    Ok(Decided::Denied { lease })
}

/// Whether a prefix may be granted for `req`: it covers the asked path, or (for a prefix ask) lies
/// within the asked prefix. What the grant covers is what the granter named, never a silent
/// fall-back to the exact path.
fn check_prefix(req: &Request, p: &str) -> std::result::Result<(), String> {
    let within = req.scope_prefix && wicket_core::prefix_covers(&req.path, p);
    if wicket_core::prefix_covers(p, &req.path) || within {
        return Ok(());
    }
    Err(format!("prefix {p} doesn't cover {}'s path {}{}", req.id, req.path, if req.scope_prefix { ", nor lie within it" } else { "" }))
}

fn merge(record: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(r), serde_json::Value::Object(x)) = (record.as_object_mut(), extra) {
        r.extend(x);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::{Op, RunId};

    fn asked(l: &Ledger, path: &str) -> String {
        let op = Op::egress(&TenantId::single(), &RunId("run_a".into()), "z", "GET", "api.example.com", path);
        l.pending_for(&op, "blocked", None).unwrap().0
    }

    fn terms(ttl: u64) -> Terms {
        Terms { uses: Some(1), ttl: Duration::from_secs(ttl), prefix: None, zone_wide: false }
    }

    fn decisions(l: &Ledger) -> Vec<serde_json::Value> {
        l.audit_tail(50).unwrap().into_iter().filter(|r| r.2 == "decision").map(|r| serde_json::from_str(&r.4).unwrap()).collect()
    }

    #[test]
    fn an_approval_is_one_grant_on_the_record() {
        let mut l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "/v1/x");
        let by = Granter::Human("alice@cli".into());
        let Decided::Approved { grant, lease } = decide(&mut l, &by, &id, &Verdict::Approve(terms(600)), serde_json::json!({})).unwrap()
        else {
            panic!("not approved")
        };
        assert_eq!(lease, None);
        assert_eq!(l.grant(&grant).unwrap().unwrap().request_id.as_deref(), Some(id.as_str()));
        assert_eq!(l.request(&id).unwrap().status, "granted");
        let d = decisions(&l);
        assert_eq!(
            (d[0]["decision"].as_str(), d[0]["by"].as_str(), d[0]["grant"].as_str()),
            (Some("approve"), Some("alice@cli"), Some(grant.as_str()))
        );
        // Decided once: a second decision on it is refused.
        assert!(decide(&mut l, &by, &id, &Verdict::Deny, serde_json::json!({})).is_err());
    }

    #[test]
    fn every_grant_has_a_bounded_lifetime_and_a_use() {
        let mut l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "/v1/x");
        let by = Granter::Human("alice@cli".into());
        for (t, why) in [
            (terms(24 * 3600 + 1), "at most 1day"),
            (terms(0), "needs a lifetime"),
            (Terms { uses: Some(0), ..terms(60) }, "at least one use"),
        ] {
            let e = decide(&mut l, &by, &id, &Verdict::Approve(t), serde_json::json!({})).unwrap_err();
            assert!(format!("{e:#}").contains(why), "{e:#} should say {why:?}");
        }
        assert!(decisions(&l).is_empty(), "nothing recorded");
        assert_eq!(l.request(&id).unwrap().status, "pending", "a refused approval decides nothing");
        assert!(decide(&mut l, &by, &id, &Verdict::Approve(terms(24 * 3600)), serde_json::json!({})).is_ok());
    }

    #[test]
    fn a_prefix_must_cover_the_ask() {
        let mut l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "/v1/x/y");
        let by = Granter::Human("alice@cli".into());
        let wide = Terms { prefix: Some("/v2/".into()), ..terms(60) };
        let e = decide(&mut l, &by, &id, &Verdict::Approve(wide), serde_json::json!({})).unwrap_err();
        assert!(format!("{e:#}").contains("doesn't cover"), "{e:#}");
        assert_eq!(l.request(&id).unwrap().status, "pending");
        // Narrower than the path is not covering it either.
        let narrower = Terms { prefix: Some("/v1/x/y/z/".into()), ..terms(60) };
        assert!(decide(&mut l, &by, &id, &Verdict::Approve(narrower), serde_json::json!({})).is_err());
        let ok = Terms { prefix: Some("/v1/".into()), ..terms(60) };
        assert!(decide(&mut l, &by, &id, &Verdict::Approve(ok), serde_json::json!({})).is_ok());
    }

    #[test]
    fn a_prefix_ask_may_be_granted_within_its_prefix() {
        let l = Ledger::open_in_memory().unwrap();
        let op = Op::egress(&TenantId::single(), &RunId("run_a".into()), "z", "GET", "api.example.com", "/items/");
        let (id, _) = l.ask(&op, "pages", true, None).unwrap();
        let req = l.request(&id).unwrap();
        let with = |p: &str| Terms { prefix: Some(p.into()), ..terms(60) };
        assert!(check_terms(&req, &with("/items/a/")).is_ok(), "within the asked prefix");
        assert!(check_terms(&req, &with("/")).is_ok(), "covering it");
        let e = check_terms(&req, &with("/other/")).unwrap_err();
        assert!(format!("{e:#}").contains("nor lie within it"), "{e:#}");
    }

    #[test]
    fn a_denial_is_recorded_with_extra_fields() {
        let mut l = Ledger::open_in_memory().unwrap();
        let id = asked(&l, "/v1/x");
        let by = Granter::Human("passkey:k".into());
        assert_eq!(
            decide(&mut l, &by, &id, &Verdict::Deny, serde_json::json!({ "signed": "s" })).unwrap(),
            Decided::Denied { lease: None }
        );
        assert_eq!(l.request(&id).unwrap().status, "denied");
        let d = decisions(&l);
        assert_eq!((d[0]["decision"].as_str(), d[0]["signed"].as_str()), (Some("deny"), Some("s")));
    }
}
