//! Standing reach (#572): one reach rule, asked for once by an agent for its workload, approved
//! once by a human, and honoured by every later run of the agent's principal (or of its zone)
//! until it lapses or is revoked.
//!
//! One row per ask, through its whole life: `pending`, then `approved` or `denied`; an approved
//! rule may be `revoked`, and lapses at `expires_at` (if set). The rule is a manifest's reach rule
//! ([`ReachRule`]) and matches as one does ([`ReachRule::allows`]), above the zone's reach and
//! within everything else (forbid rules, the org layer, ancestors' ceilings), which the caller
//! decides first.
//!
//! The evidence on an ask is the ledger's, not the agent's: the requests the principal's runs
//! raised that the rule covers ([`Ledger::standing_evidence`]).

use crate::{now, Ledger, Result, StoreError};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wicket_core::manifest::ReachRule;
use wicket_core::{Op, RunId, TenantId};

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS standing (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, run TEXT NOT NULL, zone TEXT NOT NULL, principal TEXT NOT NULL,
  rule TEXT NOT NULL, reason TEXT NOT NULL, evidence TEXT NOT NULL, status TEXT NOT NULL,
  created_at INTEGER NOT NULL, decided_at INTEGER, decided_by TEXT, bound TEXT, expires_at INTEGER,
  effect_sha256 TEXT, revoked_at INTEGER, revoked_by TEXT, zone_digest TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS standing_status ON standing (tenant, status);
"#;

/// How far back the evidence for an ask looks.
pub const EVIDENCE_SECS: i64 = 14 * 24 * 3600;
/// The most distinct ops the evidence lists (it counts them all).
pub const EVIDENCE_OPS: usize = 10;

/// Who an approved rule is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Bound {
    /// The asking agent's principal: every later run of it.
    Agent,
    /// The asking run's zone: every agent of it.
    Zone,
}

impl Bound {
    pub fn as_str(self) -> &'static str {
        match self {
            Bound::Agent => "agent",
            Bound::Zone => "zone",
        }
    }
    fn parse(s: &str) -> Option<Bound> {
        match s {
            "agent" => Some(Bound::Agent),
            "zone" => Some(Bound::Zone),
            _ => None,
        }
    }
}

/// The reason a `requests` row has when the agent asked ahead itself (`request_access`): the
/// prefix of wicket-node's `AGENT_ASKS`, which a test there holds to this.
pub const AGENT_ASKS_PREFIX: &str = "asked by the agent: ";

/// What the ledger shows for an ask: the requests the principal's runs raised in the last
/// [`EVIDENCE_SECS`] that the rule covers. Its blocked traffic (requests its boxes made and were
/// blocked on) is the evidence; its own asks ahead (`request_access`) are counted apart, since an
/// agent could raise as many of those as it liked before asking (#572 review, M6).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Blocked requests the rule covers, and how they were decided.
    pub requests: u64,
    pub granted: u64,
    pub denied: u64,
    /// Not decided (pending, withdrawn).
    pub undecided: u64,
    /// In how many of the principal's runs, and on how many days.
    pub runs: u64,
    pub days: u64,
    pub first: Option<i64>,
    pub last: Option<i64>,
    /// The agent's own asks ahead the rule covers: not evidence, shown apart.
    pub own_asks: u64,
    /// The distinct ops of the blocked requests, most asked first, at most [`EVIDENCE_OPS`].
    pub ops: Vec<EvidenceOp>,
}

/// One op the evidence saw, and how often it was granted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceOp {
    pub method: String,
    pub path: String,
    pub count: u64,
    pub granted: u64,
}

/// One standing rule, asked for or decided.
#[derive(Clone, Debug, Serialize)]
pub struct Standing {
    pub id: String,
    pub tenant: String,
    /// The run that asked.
    pub run: String,
    /// The asking run's zone.
    pub zone: String,
    /// The asking agent's principal (`spiffe://…/z/<zone>/a/<agent>`).
    pub principal: String,
    /// The asking run's zone definition, hashed (`zone_digest`): the rule binds to it, not only to
    /// the zone's name (#572 review, M1).
    pub zone_digest: String,
    pub rule: ReachRule,
    /// The agent's words.
    pub reason: String,
    pub evidence: Evidence,
    /// `pending`, `approved`, `denied` or `revoked`.
    pub status: String,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
    pub bound: Option<Bound>,
    /// When an approved rule lapses (None: until revoked).
    pub expires_at: Option<i64>,
    pub effect_sha256: Option<String>,
    pub revoked_at: Option<i64>,
    pub revoked_by: Option<String>,
}

impl Standing {
    /// Approved, not revoked, not lapsed at `at`.
    pub fn live(&self, at: i64) -> bool {
        self.status == "approved" && self.expires_at.is_none_or(|e| e > at)
    }

    /// Whether it is for a run of `principal` in `zone`, whose zone definition hashes to
    /// `zone_digest`. Bound to the agent: that principal; to the zone: that zone; either way only
    /// with the definition it was approved under, so a manifest that reuses the name with other
    /// reach or forbids (or a recreated agent) doesn't inherit it.
    pub fn binds(&self, principal: Option<&str>, zone: &str, zone_digest: &str) -> bool {
        zone_digest == self.zone_digest
            && match self.bound {
                Some(Bound::Agent) => principal == Some(self.principal.as_str()),
                Some(Bound::Zone) => zone == self.zone,
                None => false,
            }
    }
}

/// What a decision on a standing ask approves, beside its rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingTerms {
    pub bound: Bound,
    /// Its lifetime (None: until revoked).
    pub ttl_secs: Option<u64>,
}

/// The effect a decision on `s` with `rule` and `terms` approves (#369): what the card showed,
/// hashed. A decision made on another one is refused.
pub fn standing_effect(s: &Standing, rule: &ReachRule, terms: Option<&StandingTerms>) -> String {
    let v = serde_json::json!({
        "kind": "standing",
        "id": s.id,
        "principal": s.principal,
        "zone": s.zone,
        "zone_digest": s.zone_digest,
        "rule": rule,
        "evidence": s.evidence,
        "bound": terms.map(|t| t.bound.as_str()),
        "ttl_secs": terms.map(|t| t.ttl_secs),
    });
    hex::encode(Sha256::digest(v.to_string().as_bytes()))
}

/// A new standing ask's id: `s-` and eight characters, as requests' are `r-`.
pub fn new_standing_id() -> String {
    let r = wicket_core::new_request_id();
    format!("s-{}", &r[2..])
}

const COLS: &str = "id, tenant, run, zone, principal, rule, reason, evidence, status, created_at, decided_at, decided_by, bound, expires_at, effect_sha256, revoked_at, revoked_by, zone_digest";

/// A zone definition's digest, as a standing rule binds to it: sha256 of its JSON.
pub fn zone_digest(zone: &wicket_core::ZoneSpec) -> String {
    hex::encode(Sha256::digest(serde_json::to_string(zone).unwrap_or_default().as_bytes()))
}

/// At most this many of a principal's standing asks wait at once (#572 review, L4).
pub const MAX_PENDING: usize = 5;

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(Standing, String, String)> {
    let rule: String = r.get(5)?;
    let evidence: String = r.get(7)?;
    let bound: Option<String> = r.get(12)?;
    Ok((
        Standing {
            id: r.get(0)?,
            tenant: r.get(1)?,
            run: r.get(2)?,
            zone: r.get(3)?,
            principal: r.get(4)?,
            zone_digest: r.get(17)?,
            rule: ReachRule { host: String::new(), methods: vec![], paths: vec![], allow_dangerous: false },
            reason: r.get(6)?,
            evidence: Evidence::default(),
            status: r.get(8)?,
            created_at: r.get(9)?,
            decided_at: r.get(10)?,
            decided_by: r.get(11)?,
            bound: bound.as_deref().and_then(Bound::parse),
            expires_at: r.get(13)?,
            effect_sha256: r.get(14)?,
            revoked_at: r.get(15)?,
            revoked_by: r.get(16)?,
        },
        rule,
        evidence,
    ))
}

fn parse((mut s, rule, evidence): (Standing, String, String)) -> Result<Standing> {
    s.rule = serde_json::from_str(&rule)?;
    s.evidence = serde_json::from_str(&evidence)?;
    Ok(s)
}

impl Ledger {
    /// An agent's ask for standing reach: `rule` for `principal`, asked by `run` in `zone`, with
    /// the ledger's evidence for it. An ask for the same rule by the same principal that is still
    /// pending is that one (false: not new).
    #[allow(clippy::too_many_arguments)]
    pub fn ask_standing(
        &self,
        tenant: &TenantId,
        run: &RunId,
        zone: &str,
        zone_digest: &str,
        principal: &str,
        rule: &ReachRule,
        reason: &str,
    ) -> Result<(String, bool)> {
        let rule = &rule.canonical();
        rule.check_standing().map_err(StoreError::Refused)?;
        let probe = Op::egress(
            tenant,
            run,
            zone,
            rule.methods.first().map(String::as_str).unwrap_or("GET"),
            rule.host.trim_start_matches("*."),
            "/",
        );
        if let Some(why) = probe.refused_for_agents() {
            return Err(StoreError::Refused(why));
        }
        let rule_json = serde_json::to_string(rule)?;
        if let Some(id) = self
            .conn
            .query_row(
                "SELECT id FROM standing WHERE tenant = ?1 AND principal = ?2 AND rule = ?3 AND status = 'pending'",
                params![tenant.0, principal, rule_json],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok((id, false));
        }
        let waiting: i64 = self.conn.query_row(
            "SELECT count(*) FROM standing WHERE tenant = ?1 AND principal = ?2 AND status = 'pending'",
            params![tenant.0, principal],
            |r| r.get(0),
        )?;
        if waiting as usize >= MAX_PENDING {
            return Err(StoreError::Refused(format!(
                "{waiting} of this agent's standing asks are already waiting for a decision (at most {MAX_PENDING}): wait for them"
            )));
        }
        let evidence = self.standing_evidence(tenant, principal, rule, now() - EVIDENCE_SECS)?;
        let id = new_standing_id();
        self.conn.execute(
            "INSERT INTO standing (id, tenant, run, zone, principal, rule, reason, evidence, status, created_at, zone_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10)",
            params![id, tenant.0, run.0, zone, principal, rule_json, reason, serde_json::to_string(&evidence)?, now(), zone_digest],
        )?;
        Ok((id, true))
    }

    /// The requests `principal`'s runs raised since `since` that `rule` covers (whatever their
    /// risk: the evidence is what was needed, not what the rule would allow), as [`Evidence`].
    pub fn standing_evidence(&self, tenant: &TenantId, principal: &str, rule: &ReachRule, since: i64) -> Result<Evidence> {
        let mut st = self.conn.prepare(
            "SELECT r.run, r.zone, r.method, r.host, r.path, r.status, r.created_at, r.reason FROM requests r
             JOIN identities i ON i.run = r.run
             WHERE r.tenant = ?1 AND i.spiffe_id = ?2 AND r.created_at >= ?3 ORDER BY r.created_at",
        )?;
        let rows = st.query_map(params![tenant.0, principal, since], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, String>(7)?,
            ))
        })?;
        let any_risk = ReachRule { allow_dangerous: true, ..rule.clone() };
        let mut e = Evidence::default();
        let mut ops: Vec<EvidenceOp> = vec![];
        let (mut runs, mut days) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
        for row in rows {
            let (run, zone, method, host, path, status, at, reason) = row?;
            let op = Op::egress(tenant, &RunId(run.clone()), &zone, &method, &host, &path);
            if !any_risk.allows(&op).unwrap_or(false) {
                continue;
            }
            if reason.starts_with(AGENT_ASKS_PREFIX) {
                e.own_asks += 1;
                continue;
            }
            e.requests += 1;
            let granted = status == "granted";
            e.granted += granted as u64;
            e.denied += (status == "denied") as u64;
            e.undecided += !matches!(status.as_str(), "granted" | "denied") as u64;
            runs.insert(run);
            days.insert(at.div_euclid(86_400));
            e.first.get_or_insert(at);
            e.last = Some(at);
            match ops.iter_mut().find(|o| o.method == method && o.path == path) {
                Some(o) => {
                    o.count += 1;
                    o.granted += granted as u64;
                }
                None => ops.push(EvidenceOp { method, path, count: 1, granted: granted as u64 }),
            }
        }
        e.runs = runs.len() as u64;
        e.days = days.len() as u64;
        ops.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| (&a.method, &a.path).cmp(&(&b.method, &b.path))));
        ops.truncate(EVIDENCE_OPS);
        e.ops = ops;
        Ok(e)
    }

    /// How often `principal`'s runs asked for `method` on `host` under directory `dir` since
    /// `since`, and when first: what the repeat hint (#572) is given on. Every request counts, in
    /// any state, the one just raised included.
    pub fn asked_before(
        &self,
        tenant: &TenantId,
        principal: &str,
        method: &str,
        host: &str,
        dir: &str,
        since: i64,
    ) -> Result<(u64, Option<i64>)> {
        Ok(self.conn.query_row(
            "SELECT count(*), min(r.created_at) FROM requests r JOIN identities i ON i.run = r.run
             WHERE r.tenant = ?1 AND i.spiffe_id = ?2 AND r.method = ?3 AND r.host = ?4 AND substr(r.path, 1, length(?5)) = ?5
               AND r.created_at >= ?6",
            params![tenant.0, principal, method, host, dir, since],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, Option<i64>>(1)?)),
        )?)
    }

    pub fn standing(&self, id: &str) -> Result<Standing> {
        let r = self
            .conn
            .query_row(&format!("SELECT {COLS} FROM standing WHERE id = ?1"), params![id], row)
            .optional()?
            .ok_or_else(|| StoreError::NoSuchRequest(id.to_string()))?;
        parse(r)
    }

    /// Standing rules of `tenant` in `status` (`pending`, `approved`, …), oldest first. A row
    /// that doesn't read (its rule or evidence unparsable) is left out, not the whole list: one bad
    /// row mustn't make every other rule look gone (#572 review, M4).
    pub fn standing_with_status(&self, tenant: &TenantId, status: &str) -> Result<Vec<Standing>> {
        let mut st =
            self.conn.prepare(&format!("SELECT {COLS} FROM standing WHERE tenant = ?1 AND status = ?2 ORDER BY created_at, id"))?;
        let rows = st.query_map(params![tenant.0, status], row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().filter_map(|r| parse(r).ok()).collect())
    }

    /// Approves a pending ask with `rule` (the asked one, or the operator's narrowed or widened
    /// one) and `terms`. `shown`: the effect the decider was shown ([`standing_effect`]); a
    /// decision on another one is refused. The effect approved, recorded on the row.
    pub fn approve_standing(&self, id: &str, rule: &ReachRule, terms: &StandingTerms, by: &str, shown: Option<&str>) -> Result<String> {
        // What can't reach a node as a token block (#572 review, L1) isn't approved.
        let rule = &rule.canonical();
        rule.check_standing().map_err(StoreError::Refused)?;
        let s = self.standing(id)?;
        if s.status != "pending" {
            return Err(StoreError::NotPending(id.into(), s.status));
        }
        let effect = standing_effect(&s, rule, Some(terms));
        if let Some(shown) = shown.filter(|x| *x != effect) {
            return Err(StoreError::EffectChanged(id.into(), shown.into(), effect));
        }
        let t = now();
        let expires = terms.ttl_secs.map(|s| t.saturating_add(i64::try_from(s).unwrap_or(i64::MAX)));
        let n = self.conn.execute(
            "UPDATE standing SET status = 'approved', rule = ?2, bound = ?3, expires_at = ?4, decided_at = ?5, decided_by = ?6,
                    effect_sha256 = ?7 WHERE id = ?1 AND status = 'pending'",
            params![id, serde_json::to_string(rule)?, terms.bound.as_str(), expires, t, by, effect],
        )?;
        if n != 1 {
            return Err(StoreError::NotPending(id.into(), "decided meanwhile".into()));
        }
        Ok(effect)
    }

    pub fn deny_standing(&self, id: &str, by: &str) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE standing SET status = 'denied', decided_at = ?2, decided_by = ?3 WHERE id = ?1 AND status = 'pending'",
            params![id, now(), by],
        )?;
        if n != 1 {
            return Err(StoreError::NotPending(id.into(), self.standing(id)?.status));
        }
        Ok(())
    }

    /// Revokes an approved rule: no run is allowed by it from now on.
    pub fn revoke_standing(&self, id: &str, by: &str) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE standing SET status = 'revoked', revoked_at = ?2, revoked_by = ?3 WHERE id = ?1 AND status = 'approved'",
            params![id, now(), by],
        )?;
        if n != 1 {
            return Err(StoreError::Refused(format!("{id} is {}, not approved", self.standing(id)?.status)));
        }
        Ok(())
    }

    /// Moves an approved rule's lapse to `until` (None: until revoked). A revoked or lapsed rule
    /// isn't brought back: ask again.
    pub fn renew_standing(&self, id: &str, until: Option<i64>) -> Result<()> {
        let s = self.standing(id)?;
        if !s.live(now()) {
            return Err(StoreError::Refused(format!("{id} is not live ({}): it is asked for again, not renewed", s.status)));
        }
        self.conn.execute("UPDATE standing SET expires_at = ?2 WHERE id = ?1", params![id, until])?;
        Ok(())
    }

    /// The live standing rules for `run`: approved, not lapsed, and bound to its principal (its
    /// identity's) or its zone, under the zone definition `zone_digest` ([`zone_digest`]).
    pub fn standing_for_run(&self, tenant: &TenantId, run: &RunId, zone: &str, zone_digest: &str) -> Result<Vec<Standing>> {
        let principal = self.identity(&run.0)?.map(|i| i.spiffe_id);
        let t = now();
        Ok(self
            .standing_with_status(tenant, "approved")?
            .into_iter()
            .filter(|s| s.live(t) && s.binds(principal.as_deref(), zone, zone_digest))
            .collect())
    }

    /// The first live standing rule that allows `op` for its run (under zone definition
    /// `zone_digest`), if any.
    pub fn standing_allowing(&self, op: &Op, zone_digest: &str) -> Result<Option<Standing>> {
        Ok(self.standing_for_run(&op.tenant, &op.run, &op.zone, zone_digest)?.into_iter().find(|s| s.rule.allows(op).unwrap_or(false)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger() -> Ledger {
        Ledger::open_in_memory().unwrap()
    }

    fn rule(y: &str) -> ReachRule {
        wicket_core::yaml::from_str(y).unwrap()
    }

    /// A run of `agent` in `zone`, with its identity, as a run's start records it.
    fn run(l: &Ledger, id: &str, zone: &str, agent: &str) -> (RunId, String) {
        let t = TenantId::single();
        let r = RunId(id.into());
        l.run_started(&t, &r, zone, agent).unwrap();
        let spiffe = format!("spiffe://wicket.test/t/{}/z/{zone}/a/{agent}", t.0);
        l.conn
            .execute(
                "INSERT INTO identities (run, tenant, spiffe_id, zone, agent, jws, issued_at) VALUES (?1, ?2, ?3, ?4, ?5, '', ?6)",
                params![id, t.0, spiffe, zone, agent, now()],
            )
            .unwrap();
        (r, spiffe)
    }

    const DIGEST: &str = "zone-digest-1";

    /// #572: an ask carries the ledger's evidence (the principal's blocked requests the rule covers,
    /// in all its runs, apart from its own asks ahead); approved for the agent, it allows its later
    /// runs of the same zone definition and nobody else's; revoked, nothing; and the decision is
    /// bound to what was shown.
    #[test]
    fn a_standing_rule_is_asked_once_and_honoured_by_later_runs() {
        let mut l = ledger();
        let t = TenantId::single();
        let (r1, who) = run(&l, "run_a1", "work", "worker");
        let logs =
            |run: &RunId, job: u32| Op::egress(&t, run, "work", "GET", "api.github.com", &format!("/repos/o/r/actions/jobs/{job}/logs"));
        // Three blocked requests for job logs in the first run, one granted, one denied; one for
        // something else; and the agent's own ask ahead, which isn't evidence.
        let (a, _) = l.pending_for(&logs(&r1, 1), "blocked", None).unwrap();
        l.approve(
            &a,
            &crate::Approval { uses: Some(1), ttl: std::time::Duration::from_secs(600), path_prefix: None, decided_by: "op".into() },
        )
        .unwrap();
        let (b, _) = l.pending_for(&logs(&r1, 2), "blocked", None).unwrap();
        l.deny(&b, "op").unwrap();
        l.pending_for(&logs(&r1, 2), "blocked", None).unwrap();
        l.pending_for(&Op::egress(&t, &r1, "work", "POST", "api.github.com", "/repos/o/r/issues"), "blocked", None).unwrap();
        l.ask(&logs(&r1, 9), &format!("{AGENT_ASKS_PREFIX}logs"), false, None).unwrap();
        // Another agent's requests are not this one's evidence.
        let (other, _) = run(&l, "run_b1", "work", "someone");
        l.pending_for(&logs(&other, 9), "blocked", None).unwrap();

        let want = rule("{ host: api.github.com, methods: [GET], paths: ['/repos/o/r/actions/jobs/*/logs'] }");
        let (id, fresh) = l.ask_standing(&t, &r1, "work", DIGEST, &who, &want, "CI logs after every failed run").unwrap();
        assert!(fresh && id.starts_with("s-"), "{id}");
        assert_eq!(l.ask_standing(&t, &r1, "work", DIGEST, &who, &want, "again").unwrap(), (id.clone(), false), "pending: the same ask");
        let s = l.standing(&id).unwrap();
        let e = &s.evidence;
        assert_eq!((e.requests, e.granted, e.denied, e.undecided, e.own_asks, e.runs, e.days), (3, 1, 1, 1, 1, 1, 1));
        assert_eq!(e.ops[0], EvidenceOp { method: "GET".into(), path: "/repos/o/r/actions/jobs/2/logs".into(), count: 2, granted: 0 });
        assert_eq!(e.ops[1].granted, 1);
        assert_eq!(e.ops.len(), 2, "job 9 was the agent's own ask");
        assert_eq!(l.standing_with_status(&t, "pending").unwrap().len(), 1);

        // Approved for the agent, on the effect shown.
        let terms = StandingTerms { bound: Bound::Agent, ttl_secs: Some(30 * 24 * 3600) };
        let shown = standing_effect(&s, &want, Some(&terms));
        let stale = standing_effect(&s, &want, Some(&StandingTerms { bound: Bound::Zone, ..terms.clone() }));
        assert!(matches!(l.approve_standing(&id, &want, &terms, "op", Some(&stale)), Err(StoreError::EffectChanged(..))));
        assert_eq!(l.approve_standing(&id, &want, &terms, "op", Some(&shown)).unwrap(), shown);
        assert!(matches!(l.approve_standing(&id, &want, &terms, "op", None), Err(StoreError::NotPending(..))));

        // A later run of the agent is allowed; its other ops aren't; another agent isn't; nor the
        // same agent under another zone definition (a manifest that reuses the names, M1).
        let (r2, _) = run(&l, "run_a2", "work", "worker");
        assert_eq!(l.standing_allowing(&logs(&r2, 7), DIGEST).unwrap().map(|s| s.id), Some(id.clone()));
        assert!(l.standing_allowing(&logs(&r2, 7), "another-definition").unwrap().is_none(), "another zone definition");
        assert!(l
            .standing_allowing(&Op::egress(&t, &r2, "work", "POST", "api.github.com", "/repos/o/r/actions/jobs/7/logs"), DIGEST)
            .unwrap()
            .is_none());
        assert!(l.standing_allowing(&logs(&other, 7), DIGEST).unwrap().is_none(), "another agent of the zone");
        let (stranger, _) = run(&l, "run_c1", "elsewhere", "worker");
        assert!(l.standing_allowing(&logs(&stranger, 7), DIGEST).unwrap().is_none(), "another zone's agent of the same name");

        // Revoked: nothing, and not renewed.
        l.revoke_standing(&id, "op").unwrap();
        assert!(l.standing_allowing(&logs(&r2, 7), DIGEST).unwrap().is_none());
        assert!(l.renew_standing(&id, None).is_err());
        assert!(l.revoke_standing(&id, "op").is_err(), "once");
    }

    /// Bound to the zone, it is for every agent of the zone (of that definition); lapsed, for
    /// nobody; a rule a manifest couldn't say, or one in wicket's own namespace, or one no node
    /// could be given, isn't asked for; a denial is final; at most a few asks wait; a reordered ask
    /// is the same ask.
    #[test]
    fn a_standing_rule_binds_to_its_zone_lapses_and_is_held_to_a_manifests_rules() {
        let l = ledger();
        let t = TenantId::single();
        let (r1, who) = run(&l, "run_z1", "work", "worker");
        let (other, _) = run(&l, "run_z2", "work", "someone");
        let docs = rule("{ host: docs.example.com, paths: ['/**'] }");
        let (id, _) = l.ask_standing(&t, &r1, "work", DIGEST, &who, &docs, "docs").unwrap();
        l.approve_standing(&id, &docs, &StandingTerms { bound: Bound::Zone, ttl_secs: None }, "op", None).unwrap();
        let get = |run: &RunId| Op::egress(&t, run, "work", "GET", "docs.example.com", "/a/b");
        assert!(l.standing_allowing(&get(&other), DIGEST).unwrap().is_some(), "any agent of the zone");
        assert!(l.standing_allowing(&get(&other), "edited-zone").unwrap().is_none(), "not under another definition of it");
        assert_eq!(l.standing(&id).unwrap().expires_at, None);
        // Lapsed: renewing a live one moves its end; once past, it allows nothing.
        l.renew_standing(&id, Some(now() - 1)).unwrap();
        assert!(l.standing_allowing(&get(&other), DIGEST).unwrap().is_none());
        assert!(l.renew_standing(&id, None).is_err(), "a lapsed rule is asked for again");

        let ask = |r: &ReachRule| l.ask_standing(&t, &r1, "work", DIGEST, &who, r, "x");
        for bad in [
            ReachRule { paths: vec!["x".into()], ..docs.clone() },
            ReachRule { paths: vec!["/a\r{ host: x }".into()], ..docs.clone() },
            rule("{ host: wicket.internal }"),
            rule("{ host: '*.example.com' }"),
        ] {
            assert!(matches!(ask(&bad), Err(StoreError::Refused(_))), "{bad:?}");
        }
        let (id2, _) = ask(&rule("{ host: api.example.com, methods: [POST, GET] }")).unwrap();
        assert_eq!(
            ask(&rule("{ host: api.example.com, methods: [GET, POST, GET] }")).unwrap(),
            (id2.clone(), false),
            "the same rule, reordered"
        );
        l.deny_standing(&id2, "op").unwrap();
        assert!(l.deny_standing(&id2, "op").is_err());
        assert!(l.approve_standing(&id2, &docs, &StandingTerms { bound: Bound::Agent, ttl_secs: None }, "op", None).is_err());
        // At most MAX_PENDING wait at once.
        for i in 0..MAX_PENDING {
            ask(&rule(&format!("{{ host: h{i}.example.com }}"))).unwrap();
        }
        assert!(matches!(ask(&rule("{ host: more.example.com }")), Err(StoreError::Refused(w)) if w.contains("already waiting")));
        // One that doesn't read is left out of the list, not the list with it (M4).
        l.conn.execute("UPDATE standing SET rule = 'not json' WHERE id = ?1", params![id2]).unwrap();
        assert_eq!(l.standing_with_status(&t, "denied").unwrap().len(), 0);
        assert_eq!(l.standing_with_status(&t, "pending").unwrap().len(), MAX_PENDING);
    }
}
