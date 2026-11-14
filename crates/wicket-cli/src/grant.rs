//! One way to decide a pending request (#256): [`decide`], used by `wicket approve`/`deny`, the
//! console and agents (#50, the gateway's `decide` tool).
//!
//! Every request kind is the same record: an access request, a SPAWN beyond the asker's zone, a
//! LINK, a CAPACITY lease and an UPDATE are all a pending row in the ledger's `requests`, and
//! approving one makes one grant (resource, principal, lifetime, uses). What differs is only who
//! decides ([`Granter`]) and what a kind does once approved (a capacity lease is provisioned, or its
//! reservation released). The limits every grant has, such as its lifetime cap, live here, not in
//! each caller.

use crate::capacity;
use anyhow::{bail, Result};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wicket_core::{CompiledZone, Op, RunId, TenantId};
use wicket_store::{Approval, Ledger, Request};

/// The longest lifetime a grant may have. Every grant has one; renewal is a new decision.
pub const MAX_TTL: Duration = Duration::from_secs(24 * 3600);

/// The principal deciding.
#[derive(Clone, Debug)]
pub enum Granter {
    /// A human: `$USER`-style on the CLI, `passkey:<name>` on the console.
    Human(String),
    /// An agent run (#50): it may decide only its descendants' requests, and approve only what its
    /// own authority covers ([`within_authority`]).
    Agent(AgentAuthority),
}

impl Granter {
    /// How the decision is recorded (`decided_by`, the audit record's `by`).
    pub fn label(&self) -> String {
        match self {
            Granter::Human(by) => by.clone(),
            Granter::Agent(a) => format!("agent:{}", a.run),
        }
    }
}

/// An agent run's own authority, as the control plane issued it: the zone and org layer its token's
/// block 0 was minted from, and when that block ends. Checked here at issuance; a grant the granter
/// signs into its own token (fully at the edge) is a follow-up.
#[derive(Clone)]
pub struct AgentAuthority {
    pub tenant: TenantId,
    pub run: RunId,
    pub zone: Arc<CompiledZone>,
    pub org: Option<Arc<wicket_authz::OrgLayer>>,
    /// When the run's authority ends (Unix seconds).
    pub until: i64,
}

impl std::fmt::Debug for AgentAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentAuthority").field("run", &self.run.0).field("zone", &self.zone.name).field("until", &self.until).finish()
    }
}

/// How far up a spawn chain a request is routed to a granter.
const MAX_CHAIN: usize = 64;

/// Whether the agent `a` may decide `req`, and the chain from the asking run up to `a` (the
/// asking run first). Each rule's refusal names it; a request refused here stays pending for a
/// human. An agent may decide a request when:
/// - it comes from one of its descendants (the ledger's identities, `parent_run` upwards), never
///   its own;
/// - its zone has `escalation.grant`;
/// - it is an HTTP request (SPAWN, LINK, CAPACITY and UPDATE stay with humans), for one path;
/// - the agent's own zone allows it by reach at the request's risk, and its org layer doesn't
///   refuse it: what the agent could do itself, never by one of its own grants.
pub fn within_authority(l: &Ledger, a: &AgentAuthority, req: &Request) -> Result<Vec<String>> {
    if req.tenant != a.tenant.0 {
        bail!("request {} is not in your tenant", req.id);
    }
    let mut chain = vec![req.run.clone()];
    let mut at = l.identity(&req.run)?.and_then(|i| i.parent_run);
    loop {
        match at {
            Some(p) if p == a.run.0 => {
                chain.push(p);
                break;
            }
            Some(p) if chain.len() < MAX_CHAIN && !chain.contains(&p) => {
                at = l.identity(&p)?.and_then(|i| i.parent_run);
                chain.push(p);
            }
            _ => bail!("request {} is not from one of your descendants", req.id),
        }
    }
    if !a.zone.escalation.grant {
        bail!("your zone may not grant requests (escalation.grant: false)");
    }
    let method = req.method.to_ascii_uppercase();
    if !wicket_core::op::HTTP_METHODS.contains(&method.as_str()) {
        bail!("a {} request is decided by a human", req.method);
    }
    if req.scope_prefix {
        bail!("a request for every path under a prefix is decided by a human");
    }
    let mut op = Op::egress(&a.tenant, &RunId(req.run.clone()), &req.zone, &method, &req.host, &req.path);
    if let Some(why) = op.refused_for_agents() {
        bail!("{why}");
    }
    let Some(risk) = wicket_core::RiskClass::from_name(&req.risk) else { bail!("request {} has an unknown risk {}", req.id, req.risk) };
    op.risk = op.risk.max(risk);
    if let Some(why) = a.org.as_ref().and_then(|o| o.refuses_http(&op.host, &op.method, &op.path, op.risk.rank())) {
        bail!("outside your own authority: {why}");
    }
    match a.zone.evaluate(&op) {
        wicket_core::Verdict::AllowByReach(_) => Ok(chain),
        wicket_core::Verdict::NeedsGrant(why) | wicket_core::Verdict::Forbidden(why) => {
            bail!("outside your own reach ({why})")
        }
    }
}

/// What an agent may grant within what it may decide: exactly the asked path, to the asking run
/// only, for a bounded number of uses, ending no later than its own authority.
fn agent_terms(a: &AgentAuthority, req: &Request, t: &Terms) -> Result<()> {
    if t.zone_wide {
        bail!("an agent grants to the asking run only, not its whole zone");
    }
    if t.prefix.is_some() {
        bail!("an agent grants exactly the asked path, not a prefix");
    }
    let Some(uses) = t.uses else { bail!("an agent's grant needs a number of uses") };
    // A push's grant is a window, not a number of uses (#26): a human's.
    if wicket_core::git::grant_terms(&req.method, &req.path, Some(uses), t.ttl.as_secs()) != (Some(uses), t.ttl.as_secs()) {
        bail!("a git push is decided by a human");
    }
    let now = wicket_store::now();
    if a.until <= now {
        bail!("your own authority has ended");
    }
    if now.saturating_add(i64::try_from(t.ttl.as_secs()).unwrap_or(i64::MAX)) > a.until {
        bail!("the grant would outlast your own authority, which ends in {}s", a.until - now);
    }
    Ok(())
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
    /// The grant made, the uses and lifetime it was made with (a git push gets its own window, #26:
    /// [`wicket_core::git::grant_terms`]), and the capacity lease the request asked for, if it is a
    /// capacity ask: provisioned by the next reconcile pass (`wicket approve` runs one at once).
    Approved { grant: String, lease: Option<String>, uses: Option<u32>, ttl: std::time::Duration },
    /// Denied; a capacity ask's reservation was released at once.
    Denied { lease: Option<String> },
}

/// Decides pending request `id` as `by`. An approval is one grant, which exists only if its
/// decision is on the audit record (otherwise it is revoked again: fail closed). `extra` is merged
/// into the record (the console's signed decision).
pub fn decide(l: &mut Ledger, by: &Granter, id: &str, v: &Verdict, extra: serde_json::Value) -> Result<Decided> {
    let mut extra = extra;
    if let Granter::Agent(a) = by {
        let req = l.request(id)?;
        if req.status != "pending" {
            bail!("request {id} is no longer pending (it is {})", req.status);
        }
        let chain = within_authority(l, a, &req)?;
        if let Verdict::Approve(t) = v {
            check_terms(&req, t)?;
            agent_terms(a, &req, t)?;
        }
        merge(&mut extra, serde_json::json!({ "granter": "agent", "chain": chain }));
    }
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
    // What the grant is made with: a push gets its window, whatever was picked (#26).
    let (uses, ttl_secs) = match t.prefix.is_some() || req.scope_prefix {
        true => (t.uses, t.ttl.as_secs()),
        false => wicket_core::git::grant_terms(&req.method, &req.path, t.uses, t.ttl.as_secs()),
    };
    let mut record = serde_json::json!({
        "request": id, "decision": "approve", "grant": gid, "by": label,
        "method": req.method, "host": req.host, "path": req.path,
        "requested_by": req.attribution.iter().flat_map(wicket_proxy::attributed_agents).collect::<Vec<_>>(),
        "agent_identity": crate::verified_identity(l, &req.run, None),
        "uses": uses, "ttl_secs": ttl_secs, "prefix": t.prefix, "scope_prefix": req.scope_prefix,
        "scope": if t.zone_wide { "zone" } else { "run" }, "run": req.run, "zone": req.zone, "lease": lease,
    });
    merge(&mut record, extra);
    if let Err(e) = l.audit(&TenantId::single(), None, "decision", &record) {
        let _ = l.revoke_grant(&gid);
        return Err(anyhow::Error::from(e).context("the approval could not be recorded in the audit log, so its grant was revoked"));
    }
    Ok(Decided::Approved { grant: gid, lease, uses, ttl: std::time::Duration::from_secs(ttl_secs) })
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

/// The `decide` tool's hook for one agent run (#50): verifies the envelope its gateway signed, then
/// decides through [`decide`] as [`Granter::Agent`].
pub struct AgentDecisions {
    pub tenant: TenantId,
    pub run: RunId,
    pub zone: Arc<CompiledZone>,
    pub org: Option<Arc<wicket_authz::OrgLayer>>,
    /// When the run's authority ends (Unix seconds); 0 until its box's authority is set.
    pub until: Arc<AtomicI64>,
    pub ledger: Arc<Mutex<Ledger>>,
    pub issuer: wicket_identity::VerifyingKey,
}

impl AgentDecisions {
    fn authority(&self) -> AgentAuthority {
        AgentAuthority {
            tenant: self.tenant.clone(),
            run: self.run.clone(),
            zone: self.zone.clone(),
            org: self.org.clone(),
            until: self.until.load(Ordering::SeqCst),
        }
    }
}

/// How old a decision envelope may be when it is recorded.
const DECISION_SKEW_SECS: i64 = 60;

impl wicket_proxy::Decisions for AgentDecisions {
    fn decidable(&self) -> std::result::Result<Vec<Request>, String> {
        let a = self.authority();
        let l = self.ledger.lock().map_err(|_| "ledger lock")?;
        let pending = l.pending(&self.tenant).map_err(|e| e.to_string())?;
        Ok(pending.into_iter().filter(|r| r.run != self.run.0 && within_authority(&l, &a, r).is_ok()).collect())
    }

    fn decide(&self, signed: &str) -> std::result::Result<String, String> {
        let now = wicket_store::now();
        let (claims, p) =
            wicket_identity::verify_envelope(signed, &self.issuer, now).map_err(|e| format!("the decision's signature: {e}"))?;
        if claims.run != self.run.0 || claims.tenant != self.tenant.0 || p["run"].as_str() != Some(&self.run.0) {
            return Err("the decision was not signed by this run".into());
        }
        if p["kind"].as_str() != Some(wicket_proxy::DECISION_KIND) {
            return Err("not a decision".into());
        }
        match p["iat"].as_i64() {
            Some(iat) if (now - iat).abs() <= DECISION_SKEW_SECS => {}
            _ => return Err("the decision is stale".into()),
        }
        let id = p["request"].as_str().ok_or("the decision names no request")?;
        let verdict = match p["decision"].as_str() {
            Some("approve") => Verdict::Approve(Terms {
                uses: Some(p["uses"].as_u64().and_then(|u| u32::try_from(u).ok()).ok_or("the decision has no uses")?),
                ttl: Duration::from_secs(p["ttl_secs"].as_u64().ok_or("the decision has no ttl")?),
                prefix: None,
                zone_wide: false,
            }),
            Some("deny") => Verdict::Deny,
            _ => return Err("the decision is neither approve nor deny".into()),
        };
        let mut l = self.ledger.lock().map_err(|_| "ledger lock")?;
        if let Some((r, ..)) = l.revoked_in_chain(&self.run.0).map_err(|e| e.to_string())? {
            return Err(format!("this agent's identity was revoked (revoked: {r})"));
        }
        let extra = serde_json::json!({ "signed": signed, "granter_identity": claims.sub });
        match decide(&mut l, &Granter::Agent(self.authority()), id, &verdict, extra) {
            Ok(Decided::Approved { grant, uses, ttl, .. }) => Ok(format!(
                "approved: {id} is granted as {grant} ({} use(s), for {}s). The asking run may retry its request now.",
                uses.map_or("unlimited".into(), |u| u.to_string()),
                ttl.as_secs()
            )),
            Ok(Decided::Denied { .. }) => Ok(format!("denied: {id}.")),
            Err(e) => match l.request(id).map(|r| r.status) {
                Ok(s) if s == "pending" => Err(format!("{e:#}; {id} stays pending for a human")),
                _ => Err(format!("{e:#}")),
            },
        }
    }
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
        let Decided::Approved { grant, lease, .. } =
            decide(&mut l, &by, &id, &Verdict::Approve(terms(600)), serde_json::json!({})).unwrap()
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

    // ---- agents decide (#50) ----

    /// A parent (`run_p`), its child (`run_c`) and grandchild (`run_g`), and an unrelated run
    /// (`run_x`), with identities in the ledger, and the parent's decide hook.
    struct Tree {
        ledger: Arc<Mutex<Ledger>>,
        issuer: wicket_identity::Issuer,
        key: wicket_identity::AgentKey,
        jws: String,
    }

    const PARENT_ZONE: &str = "name: p\nreach:\n  - { host: api.example.com, methods: [GET], paths: [\"/v1/**\"] }\n";

    impl Tree {
        fn new() -> Tree {
            let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
            let issuer = wicket_identity::Issuer::generate("wicket.test");
            let key = wicket_identity::AgentKey::generate();
            let mut jws = String::new();
            for (run, parent) in [("run_p", None), ("run_c", Some("run_p")), ("run_g", Some("run_c")), ("run_x", None)] {
                let spec = wicket_identity::IdentitySpec {
                    tenant: "t0".into(),
                    zone: "z".into(),
                    agent: run.into(),
                    run: run.into(),
                    parent_run: parent.map(String::from),
                    manifest_sha256: "m".into(),
                    image: "img".into(),
                    node: "local".into(),
                    principal: serde_json::json!({"type": "human", "id": "alice"}),
                    act: None,
                };
                let k = if run == "run_p" { key.public() } else { wicket_identity::AgentKey::generate().public() };
                let doc = issuer.issue(&spec, wicket_store::now(), 3600, &k);
                if run == "run_p" {
                    jws = doc.clone();
                }
                let l = ledger.lock().unwrap();
                l.put_identity(&wicket_store::IdentityRow {
                    run: run.into(),
                    tenant: "t0".into(),
                    spiffe_id: format!("spiffe://wicket.test/{run}"),
                    zone: "z".into(),
                    agent: run.into(),
                    parent_run: parent.map(String::from),
                    accept_from: vec![],
                    jws: doc,
                    issued_at: wicket_store::now(),
                })
                .unwrap();
            }
            Tree { ledger, issuer, key, jws }
        }

        fn hook(&self, zone: &str) -> AgentDecisions {
            let z: wicket_core::ZoneSpec = serde_yaml::from_str(zone).unwrap();
            AgentDecisions {
                tenant: TenantId::single(),
                run: RunId("run_p".into()),
                zone: Arc::new(CompiledZone::new(z).unwrap()),
                org: None,
                until: Arc::new(AtomicI64::new(wicket_store::now() + 3600)),
                ledger: self.ledger.clone(),
                issuer: self.issuer.verifying_key(),
            }
        }

        fn ask(&self, run: &str, method: &str, path: &str) -> String {
            let op = Op::egress(&TenantId::single(), &RunId(run.into()), "z.c", method, "api.example.com", path);
            self.ledger.lock().unwrap().pending_for(&op, "blocked", None).unwrap().0
        }

        /// What the gateway signs for `decide`.
        fn signed(&self, id: &str, decision: &str, uses: u64, ttl: u64) -> String {
            let p = serde_json::json!({
                "jti": "d-1", "iat": wicket_store::now(), "kind": wicket_proxy::DECISION_KIND, "run": "run_p",
                "request": id, "decision": decision, "uses": uses, "ttl_secs": ttl,
            });
            wicket_identity::sign_envelope(&self.key, &self.jws, &p)
        }

        fn status(&self, id: &str) -> String {
            self.ledger.lock().unwrap().request(id).unwrap().status
        }
    }

    use wicket_proxy::Decisions as _;

    #[test]
    fn a_parent_approves_a_descendants_request_within_its_reach() {
        let t = Tree::new();
        let hook = t.hook(PARENT_ZONE);
        let child = t.ask("run_c", "GET", "/v1/items");
        let grandchild = t.ask("run_g", "GET", "/v1/other");
        let mut listed: Vec<String> = hook.decidable().unwrap().into_iter().map(|r| r.id).collect();
        let mut both = vec![child.clone(), grandchild.clone()];
        listed.sort();
        both.sort();
        assert_eq!(listed, both, "both routed to the parent");
        let text = hook.decide(&t.signed(&child, "approve", 2, 60)).unwrap();
        assert!(text.starts_with("approved:"), "{text}");
        assert_eq!(t.status(&child), "granted");
        // The grant is the child's own, for the exact path, with the uses given.
        let mut l = t.ledger.lock().unwrap();
        let op = |run: &str, path: &str| Op::egress(&TenantId::single(), &RunId(run.into()), "z.c", "GET", "api.example.com", path);
        assert!(l.consume_grant(&op("run_x", "/v1/items")).unwrap().is_none(), "another run can't use it");
        assert!(l.consume_grant(&op("run_c", "/v1/items/more")).unwrap().is_none(), "exact path only");
        assert!(l.consume_grant(&op("run_c", "/v1/items")).unwrap().is_some());
        assert!(l.consume_grant(&op("run_c", "/v1/items")).unwrap().is_some());
        assert!(l.consume_grant(&op("run_c", "/v1/items")).unwrap().is_none(), "two uses");
        // Signed by the granter, with the chain, on the record.
        let d = decisions(&l);
        assert_eq!(d[0]["by"], "agent:run_p");
        assert_eq!(d[0]["chain"], serde_json::json!(["run_c", "run_p"]));
        assert!(d[0]["signed"].as_str().is_some_and(|s| wicket_identity::verify_envelope(
            s,
            &t.issuer.verifying_key(),
            wicket_store::now()
        )
        .is_ok()));
        drop(l);
        // A deny within its authority, of a grandchild's request.
        assert!(hook.decide(&t.signed(&grandchild, "deny", 1, 60)).unwrap().starts_with("denied:"));
        assert_eq!(t.status(&grandchild), "denied");
    }

    #[test]
    fn outside_its_reach_a_request_stays_pending_for_a_human() {
        let t = Tree::new();
        let hook = t.hook(PARENT_ZONE);
        let beyond = t.ask("run_c", "GET", "/v2/items");
        let write = t.ask("run_c", "POST", "/v1/items");
        assert!(hook.decidable().unwrap().is_empty(), "nothing routed to the parent");
        for id in [&beyond, &write] {
            for d in ["approve", "deny"] {
                let e = hook.decide(&t.signed(id, d, 1, 60)).unwrap_err();
                assert!(e.contains("outside your own reach") && e.contains("stays pending for a human"), "{e}");
            }
            assert_eq!(t.status(id), "pending");
        }
        // A human still decides it, through the same function.
        let by = Granter::Human("alice@cli".into());
        let mut l = t.ledger.lock().unwrap();
        assert!(decide(&mut l, &by, &beyond, &Verdict::Approve(terms(60)), serde_json::json!({})).is_ok());
    }

    #[test]
    fn only_descendants_requests_and_only_http_ones() {
        let t = Tree::new();
        let hook = t.hook(PARENT_ZONE);
        let own = t.ask("run_p", "GET", "/v1/items");
        let stranger = t.ask("run_x", "GET", "/v1/items");
        for id in [&own, &stranger] {
            let e = hook.decide(&t.signed(id, "approve", 1, 60)).unwrap_err();
            assert!(e.contains("not from one of your descendants"), "{e}");
            assert_eq!(t.status(id), "pending");
        }
        let mut spawn = Op::egress(&TenantId::single(), &RunId("run_c".into()), "z.c", "SPAWN", "wicket.internal", "/zones/x/0");
        spawn.risk = wicket_core::RiskClass::R0Read;
        let sid = t.ledger.lock().unwrap().pending_for(&spawn, "beyond", None).unwrap().0;
        let e = hook.decide(&t.signed(&sid, "approve", 1, 60)).unwrap_err();
        assert!(e.contains("decided by a human"), "{e}");
        let prefix = {
            let op = Op::egress(&TenantId::single(), &RunId("run_c".into()), "z.c", "GET", "api.example.com", "/v1/");
            t.ledger.lock().unwrap().ask(&op, "pages", true, None).unwrap().0
        };
        assert!(hook.decide(&t.signed(&prefix, "approve", 1, 60)).unwrap_err().contains("prefix"));
    }

    #[test]
    fn a_zone_without_grant_decides_nothing() {
        let t = Tree::new();
        let hook = t.hook(&format!("{PARENT_ZONE}escalation: {{ grant: false }}\n"));
        let id = t.ask("run_c", "GET", "/v1/items");
        assert!(hook.decidable().unwrap().is_empty());
        let e = hook.decide(&t.signed(&id, "approve", 1, 60)).unwrap_err();
        assert!(e.contains("escalation.grant: false"), "{e}");
        assert_eq!(t.status(&id), "pending");
    }

    #[test]
    fn an_agents_grant_is_bounded_by_its_own_authority() {
        let t = Tree::new();
        let hook = t.hook(PARENT_ZONE);
        hook.until.store(wicket_store::now() + 120, Ordering::SeqCst);
        let id = t.ask("run_c", "GET", "/v1/items");
        let e = hook.decide(&t.signed(&id, "approve", 1, 600)).unwrap_err();
        assert!(e.contains("outlast your own authority"), "{e}");
        let a = hook.authority();
        let req = t.ledger.lock().unwrap().request(&id).unwrap();
        for (terms, why) in [
            (Terms { zone_wide: true, ..terms(60) }, "asking run only"),
            (Terms { prefix: Some("/v1/".into()), ..terms(60) }, "the asked path"),
            (Terms { uses: None, ..terms(60) }, "number of uses"),
        ] {
            assert!(format!("{:#}", agent_terms(&a, &req, &terms).unwrap_err()).contains(why));
        }
        assert_eq!(t.status(&id), "pending");
        assert!(hook.decide(&t.signed(&id, "approve", 1, 60)).is_ok(), "within it");
        // The first decision wins.
        let e = hook.decide(&t.signed(&id, "deny", 1, 60)).unwrap_err();
        assert!(e.contains("no longer pending") && !e.contains("stays pending"), "{e}");
    }

    #[test]
    fn only_the_runs_own_signed_decision_counts() {
        let t = Tree::new();
        let hook = t.hook(PARENT_ZONE);
        let id = t.ask("run_c", "GET", "/v1/items");
        // A message envelope (what send_message signs), even one whose body reads as a decision.
        let msg = serde_json::json!({
            "jti": "m-1", "iat": wicket_store::now(), "kind": "message", "run": "run_p", "to_run": "run_p",
            "request": id, "decision": "approve", "uses": 1, "ttl_secs": 60,
            "body": { "kind": "decision", "request": id, "decision": "approve" },
        });
        let e = hook.decide(&wicket_identity::sign_envelope(&t.key, &t.jws, &msg)).unwrap_err();
        assert_eq!(e, "not a decision");
        // Signed with another key than the identity's, or by another run.
        let other = wicket_identity::AgentKey::generate();
        let p = serde_json::json!({ "iat": wicket_store::now(), "kind": "decision", "run": "run_p", "request": id, "decision": "approve", "uses": 1, "ttl_secs": 60 });
        assert!(hook.decide(&wicket_identity::sign_envelope(&other, &t.jws, &p)).unwrap_err().contains("signature"));
        let child_jws = t.ledger.lock().unwrap().identity("run_c").unwrap().unwrap().jws;
        assert!(hook.decide(&wicket_identity::sign_envelope(&t.key, &child_jws, &p)).is_err());
        assert_eq!(t.status(&id), "pending");
    }
}
