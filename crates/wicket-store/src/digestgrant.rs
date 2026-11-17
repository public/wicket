//! "May this digest run" as a grant on the digest (#258; docs/explanation/store.md).
//!
//! Today four checks answer it: release and CI keys, an operator's UPDATE approval, image pins and
//! program pins. Each becomes one record and one check:
//!
//! - **The record.** A grant row: method [`DIGEST_METHOD`], host [`crate::QUOTA_HOST`]
//!   (`wicket.internal`), path `/digest/sha256:<hex>`, with its action (`run`, `install` or
//!   `mount`) and its scope (the installation, a zone or a node) in `terms`, a lifetime, an
//!   optional number of uses, and who made it (`decided_by`). It answers no request and decides no
//!   op: its method is reserved (`wicket_core::op::RESERVED_METHODS`), so nothing asks for one.
//! - **The check.** [`Ledger::may_use`] finds a live grant covering the digest, the action and the
//!   scope, takes one of its uses if it is counted, and audits the acceptance (`digest.accepted`,
//!   naming the grant) in the same transaction. It is the only answer.
//!
//! Only operators make these grants ([`Ledger::grant_digest`]'s callers check who may, as
//! `grant::decide` does for every grant); a release key becomes a principal holding a standing
//! grant (later steps of #258 move each of today's checks onto this one).

use crate::{now, Ledger, Result, StoreError};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use wicket_core::{new_grant_id, TenantId};

/// The method of a digest grant.
pub const DIGEST_METHOD: &str = "DIGEST";

/// What a digest grant lets its digest do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestAction {
    /// Run as a box's image, or as a program's source.
    Run,
    /// Install as a wicket build (`wicket self update`).
    Install,
    /// Mount, read-only (a volume snapshot).
    Mount,
}

impl DigestAction {
    pub fn as_str(self) -> &'static str {
        match self {
            DigestAction::Run => "run",
            DigestAction::Install => "install",
            DigestAction::Mount => "mount",
        }
    }
}

/// Where a digest grant holds: everywhere in the installation, in one zone, or on one node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind", content = "name")]
pub enum DigestScope {
    Installation,
    Zone(String),
    Node(String),
}

/// A digest grant's terms, as `grants.terms` holds them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terms {
    action: DigestAction,
    scope: DigestScope,
}

/// A digest grant to make.
#[derive(Clone, Debug)]
pub struct NewDigestGrant<'a> {
    pub tenant: &'a TenantId,
    /// `sha256:<64 lowercase hex>`.
    pub digest: &'a str,
    pub action: DigestAction,
    pub scope: DigestScope,
    /// None: any number of uses while it lasts.
    pub uses: Option<u32>,
    /// Unix seconds.
    pub expires_at: i64,
    /// Who made it: the operator (or, later, the CI principal) whose authority covers the scope.
    pub decided_by: &'a str,
}

/// An acceptance: the grant that covered it, and who made that grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DigestUse {
    pub grant: String,
    pub decided_by: String,
    pub scope: DigestScope,
}

/// A live digest grant, as [`Ledger::digest_grants`] lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DigestGrantRow {
    pub id: String,
    pub action: DigestAction,
    pub scope: DigestScope,
    /// None: any number of uses while it lasts.
    pub uses_left: Option<i64>,
}

/// Whether `d` is a digest a grant can name: `sha256:` and 64 lowercase hex digits.
pub fn valid_digest(d: &str) -> bool {
    d.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

fn path_of(digest: &str) -> String {
    format!("/digest/{digest}")
}

impl Ledger {
    /// Records a grant on `g.digest`: its grant id. The caller has checked that whoever makes it
    /// may (only operators make these, #258).
    pub fn grant_digest(&self, g: &NewDigestGrant<'_>) -> Result<String> {
        if !valid_digest(g.digest) {
            return Err(StoreError::Refused(format!("{:?} is not a digest (sha256:<64 hex digits>)", g.digest)));
        }
        if g.expires_at <= now() {
            return Err(StoreError::Refused("a digest grant needs a lifetime that hasn't ended".into()));
        }
        let terms = serde_json::to_string(&Terms { action: g.action, scope: g.scope.clone() }).expect("terms serialise");
        let zone = match &g.scope {
            DigestScope::Zone(z) => z.as_str(),
            _ => "",
        };
        let id = new_grant_id();
        self.conn.execute(
            "INSERT INTO grants (id, tenant, zone, method, host, path, prefix, uses_left, expires_at, request_id, decided_by, created_at, terms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, NULL, ?9, ?10, ?11)",
            params![
                id,
                g.tenant.0,
                zone,
                DIGEST_METHOD,
                crate::QUOTA_HOST,
                path_of(g.digest),
                g.uses.map(i64::from),
                g.expires_at,
                g.decided_by,
                now(),
                terms
            ],
        )?;
        Ok(id)
    }

    /// May `digest` do `action` in `scope`? The one check (#258): the oldest live grant on the
    /// digest for that action whose scope covers `scope` (an installation-wide grant covers every
    /// zone and node), one of its uses taken if it is counted, and the acceptance audited
    /// (`digest.accepted`, naming the grant and `by`, who is using it) in the same transaction.
    /// None: no grant covers it (nothing is recorded; the caller refuses and audits why).
    pub fn may_use(
        &self,
        tenant: &TenantId,
        digest: &str,
        action: DigestAction,
        scope: &DigestScope,
        by: &str,
    ) -> Result<Option<DigestUse>> {
        if !valid_digest(digest) {
            return Ok(None);
        }
        let tx = self.conn.unchecked_transaction()?;
        let rows: Vec<(String, Option<i64>, String, String)> = {
            let mut st = tx.prepare(
                "SELECT id, uses_left, decided_by, terms FROM grants
                 WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND path = ?4 AND revoked = 0 AND expires_at > ?5
                   AND amount IS NULL AND (uses_left IS NULL OR uses_left > 0)
                 ORDER BY created_at, rowid",
            )?;
            let r = st.query_map(params![tenant.0, DIGEST_METHOD, crate::QUOTA_HOST, path_of(digest), now()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, Option<String>>(3)?.unwrap_or_default()))
            })?;
            r.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let found = rows.into_iter().find_map(|(id, uses, decided_by, terms)| {
            let t: Terms = serde_json::from_str(&terms).ok()?;
            let covers = t.action == action && (t.scope == DigestScope::Installation || &t.scope == scope);
            covers.then_some((id, uses, decided_by, t.scope))
        });
        let Some((grant, uses, decided_by, held)) = found else {
            return Ok(None);
        };
        // Conditional, so two uses racing for a grant's last use can't both take it.
        if uses.is_some() && tx.execute("UPDATE grants SET uses_left = uses_left - 1 WHERE id = ?1 AND uses_left > 0", params![grant])? != 1
        {
            return Ok(None);
        }
        let used = DigestUse { grant, decided_by, scope: held };
        let body = serde_json::json!({
            "digest": digest, "action": action.as_str(), "scope": scope, "grant": used.grant,
            "granted_by": used.decided_by, "grant_scope": used.scope, "by": by,
        });
        // Inside the transaction: the record joins it.
        self.audit(tenant, None, "digest.accepted", &body)?;
        tx.commit()?;
        Ok(Some(used))
    }

    /// The live digest grants on `digest`, oldest first.
    pub fn digest_grants(&self, tenant: &TenantId, digest: &str) -> Result<Vec<DigestGrantRow>> {
        let mut st = self.conn.prepare(
            "SELECT id, terms, uses_left FROM grants WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND path = ?4
               AND revoked = 0 AND expires_at > ?5 ORDER BY created_at, rowid",
        )?;
        let r = st.query_map(params![tenant.0, DIGEST_METHOD, crate::QUOTA_HOST, path_of(digest), now()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default(), r.get::<_, Option<i64>>(2)?))
        })?;
        let mut out = vec![];
        for row in r {
            let (id, terms, uses) = row?;
            if let Ok(t) = serde_json::from_str::<Terms>(&terms) {
                out.push(DigestGrantRow { id, action: t.action, scope: t.scope, uses_left: uses });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn grant(l: &Ledger, action: DigestAction, scope: DigestScope, uses: Option<u32>) -> String {
        l.grant_digest(&NewDigestGrant {
            tenant: &TenantId::single(),
            digest: D,
            action,
            scope,
            uses,
            expires_at: now() + 3600,
            decided_by: "operator:alex",
        })
        .unwrap()
    }

    fn accepted(l: &Ledger) -> usize {
        l.audit_tail(100).unwrap().iter().filter(|r| r.2 == "digest.accepted").count()
    }

    /// #258: a digest is accepted only by a live grant for its action whose scope covers the use;
    /// a counted grant is used up; every acceptance is one audit record naming the grant.
    #[test]
    fn a_digest_is_accepted_only_by_a_grant_covering_its_action_and_scope() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let z = DigestScope::Zone("research".into());
        assert_eq!(l.may_use(&t, D, DigestAction::Run, &z, "run_1").unwrap(), None, "no grant: no answer");
        let g = grant(&l, DigestAction::Run, z.clone(), Some(1));
        assert_eq!(l.may_use(&t, D, DigestAction::Install, &DigestScope::Installation, "self update").unwrap(), None, "another action");
        assert_eq!(l.may_use(&t, D, DigestAction::Run, &DigestScope::Zone("other".into()), "run_2").unwrap(), None, "another zone");
        assert_eq!(
            l.may_use(&t, D, DigestAction::Run, &DigestScope::Installation, "run_3").unwrap(),
            None,
            "a zone's grant isn't everywhere"
        );
        let u = l.may_use(&t, D, DigestAction::Run, &z, "run_4").unwrap().unwrap();
        assert_eq!((u.grant.as_str(), u.decided_by.as_str()), (g.as_str(), "operator:alex"));
        assert_eq!(accepted(&l), 1);
        assert_eq!(l.may_use(&t, D, DigestAction::Run, &z, "run_5").unwrap(), None, "its one use is gone");
        // An installation-wide grant covers every zone and node.
        let all = grant(&l, DigestAction::Install, DigestScope::Installation, None);
        for scope in [DigestScope::Installation, DigestScope::Node("pc".into()), z.clone()] {
            assert_eq!(l.may_use(&t, D, DigestAction::Install, &scope, "self update").unwrap().unwrap().grant, all);
        }
        assert_eq!(accepted(&l), 4);
        // Revoked: no longer.
        l.revoke_grant(&all).unwrap();
        assert_eq!(l.may_use(&t, D, DigestAction::Install, &DigestScope::Installation, "self update").unwrap(), None);
        assert_eq!(l.digest_grants(&t, D).unwrap().len(), 1, "the used-up run grant is still listed until it expires");
    }

    /// A digest grant names a digest, has a lifetime, and decides no request or op.
    #[test]
    fn a_digest_grant_names_a_digest_and_answers_nothing_else() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let bad = NewDigestGrant {
            tenant: &t,
            digest: "sha256:XYZ",
            action: DigestAction::Run,
            scope: DigestScope::Installation,
            uses: None,
            expires_at: now() + 60,
            decided_by: "operator:alex",
        };
        assert!(l.grant_digest(&bad).is_err());
        assert!(l.grant_digest(&NewDigestGrant { digest: D, expires_at: now() - 1, ..bad.clone() }).is_err(), "no lifetime");
        assert!(l.may_use(&t, "latest", DigestAction::Run, &DigestScope::Installation, "x").unwrap().is_none());
        grant(&l, DigestAction::Run, DigestScope::Installation, None);
        assert!(wicket_core::op::RESERVED_METHODS.contains(&DIGEST_METHOD), "nothing asks for one");
        assert!(l.quota_amounts("").unwrap().0.is_empty(), "not a quota");
    }
}
