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

/// How long a CI principal's standing grant lasts before the reconciler renews it: a day, the cap
/// every grant has. Revoking the grant, or no longer trusting its key, stops it within a day.
pub const SIGNER_GRANT_SECS: i64 = 24 * 3600;

/// The CI principal of release key `key_id`.
pub fn signer_principal(key_id: &str) -> String {
    format!("release-key:{key_id}")
}

fn signer_path(key_id: &str) -> String {
    format!("/signer/{key_id}")
}

/// A CI principal with a live standing grant: the grant, its release key's id, and the public key
/// (base64url, as the key file holds it).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Signer {
    pub grant: String,
    pub key_id: String,
    pub key: String,
}

/// Whether `d` is a digest a grant can name: `sha256:` and 64 lowercase hex digits.
pub fn valid_digest(d: &str) -> bool {
    d.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

fn path_of(digest: &str) -> String {
    format!("/digest/{digest}")
}

/// The oldest live grant on `digest` for `action` whose scope covers `scope` (an installation-wide
/// grant covers every zone and node), with a use left: (id, uses left, decided by, its scope).
fn covering(
    conn: &rusqlite::Connection,
    tenant: &TenantId,
    digest: &str,
    action: DigestAction,
    scope: &DigestScope,
) -> Result<Option<(String, Option<i64>, String, DigestScope)>> {
    let mut st = conn.prepare(
        "SELECT id, uses_left, decided_by, terms FROM grants
         WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND path = ?4 AND revoked = 0 AND expires_at > ?5
           AND amount IS NULL AND (uses_left IS NULL OR uses_left > 0)
         ORDER BY created_at, rowid",
    )?;
    let rows = st.query_map(params![tenant.0, DIGEST_METHOD, crate::QUOTA_HOST, path_of(digest), now()], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<i64>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?.unwrap_or_default(),
        ))
    })?;
    for row in rows {
        let (id, uses, decided_by, terms) = row?;
        if let Ok(t) = serde_json::from_str::<Terms>(&terms) {
            if t.action == action && (t.scope == DigestScope::Installation || &t.scope == scope) {
                return Ok(Some((id, uses, decided_by, t.scope)));
            }
        }
    }
    Ok(None)
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

    /// Whether a live grant on `digest` lets it do `action` in `scope`, without using or auditing
    /// anything: what a run checks before it records the grant its pin stands for (#258).
    pub fn digest_granted(&self, tenant: &TenantId, digest: &str, action: DigestAction, scope: &DigestScope) -> Result<bool> {
        Ok(valid_digest(digest) && covering(&self.conn, tenant, digest, action, scope)?.is_some())
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
        let Some((grant, uses, decided_by, held)) = covering(&tx, tenant, digest, action, scope)? else {
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

    /// Records that the CI principal of release key `key_id` (`key`, its public key, base64) holds
    /// a standing grant to install what it signs (#258): a grant held by
    /// [`signer_principal`]`(key_id)`, at `/signer/<key id>`, for [`SIGNER_GRANT_SECS`], renewed
    /// by the reconciler while the key stays trusted ([`Ledger::renew_signer`]). A live one is kept
    /// (its id returned). Only operators trust keys (`wicket self trust-key`).
    pub fn trust_signer(&self, tenant: &TenantId, key_id: &str, key: &str, decided_by: &str) -> Result<String> {
        if let Some(s) = self.signers(tenant)?.into_iter().find(|s| s.key_id == key_id) {
            return Ok(s.grant);
        }
        let terms = serde_json::json!({ "action": "install", "scope": DigestScope::Installation, "key": key }).to_string();
        let id = new_grant_id();
        self.conn.execute(
            "INSERT INTO grants (id, tenant, zone, method, host, path, prefix, uses_left, expires_at, request_id, decided_by, created_at, principal, terms)
             VALUES (?1, ?2, '', ?3, ?4, ?5, 0, NULL, ?6, NULL, ?7, ?8, ?9, ?10)",
            params![
                id,
                tenant.0,
                DIGEST_METHOD,
                crate::QUOTA_HOST,
                signer_path(key_id),
                now() + SIGNER_GRANT_SECS,
                decided_by,
                now(),
                signer_principal(key_id),
                terms
            ],
        )?;
        Ok(id)
    }

    /// Whether release key `key_id` has ever had a standing grant, live or not (a key file imported
    /// once stays as its grant left it: revoked or lapsed is not brought back).
    pub fn signer_recorded(&self, tenant: &TenantId, key_id: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM grants WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND path = ?4",
            params![tenant.0, DIGEST_METHOD, crate::QUOTA_HOST, signer_path(key_id)],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Keeps release key `key_id`'s live standing grant live for another [`SIGNER_GRANT_SECS`]
    /// (the reconciler, daily, while the key is still trusted). False: there is none live (revoked
    /// or lapsed), and nothing is brought back.
    pub fn renew_signer(&self, tenant: &TenantId, key_id: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE grants SET expires_at = ?5 WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND path = ?4 AND revoked = 0 AND expires_at > ?6",
            params![tenant.0, DIGEST_METHOD, crate::QUOTA_HOST, signer_path(key_id), now() + SIGNER_GRANT_SECS, now()],
        )?;
        Ok(n > 0)
    }

    /// The CI principals holding a live standing grant: each release key this installation trusts now.
    pub fn signers(&self, tenant: &TenantId) -> Result<Vec<Signer>> {
        let mut st = self.conn.prepare(
            "SELECT id, path, terms FROM grants WHERE tenant = ?1 AND method = ?2 AND host = ?3 AND substr(path, 1, 8) = '/signer/'
               AND revoked = 0 AND expires_at > ?4 ORDER BY created_at, rowid",
        )?;
        let r = st.query_map(params![tenant.0, DIGEST_METHOD, crate::QUOTA_HOST, now()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?.unwrap_or_default()))
        })?;
        let mut out = vec![];
        for row in r {
            let (grant, path, terms) = row?;
            let key = serde_json::from_str::<serde_json::Value>(&terms).ok().and_then(|v| v["key"].as_str().map(String::from));
            if let (Some(key_id), Some(key)) = (path.strip_prefix("/signer/"), key) {
                out.push(Signer { grant, key_id: key_id.to_string(), key });
            }
        }
        Ok(out)
    }

    /// A build `digest` signed by `signer` (its signature verified by the caller, against the key
    /// of the signer's live standing grant): the signer's grant on that one digest (`install`,
    /// installation-wide, one use, minutes), within its standing authority, then the one check,
    /// [`Ledger::may_use`], audited as every acceptance is.
    pub fn accept_signed(&self, tenant: &TenantId, digest: &str, signer: &Signer, by: &str) -> Result<Option<DigestUse>> {
        if !self.signers(tenant)?.iter().any(|s| s.grant == signer.grant) {
            return Ok(None);
        }
        let grant = self.grant_digest(&NewDigestGrant {
            tenant,
            digest,
            action: DigestAction::Install,
            scope: DigestScope::Installation,
            uses: Some(1),
            expires_at: now() + 600,
            decided_by: &signer_principal(&signer.key_id),
        })?;
        self.audit(
            tenant,
            None,
            "digest.granted",
            &serde_json::json!({ "digest": digest, "action": "install", "scope": DigestScope::Installation, "grant": grant,
                                 "by": signer_principal(&signer.key_id), "under": signer.grant, "why": "signed by its release key" }),
        )?;
        self.may_use(tenant, digest, DigestAction::Install, &DigestScope::Installation, by)
    }

    /// An operator's approval of an update to the build with sha256 `sha` (an agent's
    /// `request_update`, approved: [`Ledger::use_update_approval`], used up here) as what it is
    /// (#258): that operator's grant on the build's digest, `install`, one use, then the one check,
    /// [`Ledger::may_use`]. Returns the request and the acceptance; None: no live approval.
    pub fn accept_update_approval(&mut self, tenant: &TenantId, sha: &str, by: &str) -> Result<Option<(String, DigestUse)>> {
        let Some((request, approval)) = self.use_update_approval(sha)? else { return Ok(None) };
        let decided_by: String = self
            .conn
            .query_row("SELECT decided_by FROM grants WHERE id = ?1", params![approval], |r| r.get(0))
            .unwrap_or_else(|_| "operator".into());
        let digest = format!("sha256:{sha}");
        let grant = self.grant_digest(&NewDigestGrant {
            tenant,
            digest: &digest,
            action: DigestAction::Install,
            scope: DigestScope::Installation,
            uses: Some(1),
            expires_at: now() + 600,
            decided_by: &decided_by,
        })?;
        self.audit(
            tenant,
            None,
            "digest.granted",
            &serde_json::json!({ "digest": digest, "action": "install", "scope": DigestScope::Installation, "grant": grant,
                                 "by": decided_by, "under": approval, "request": request, "why": "an operator approved the update" }),
        )?;
        Ok(self.may_use(tenant, &digest, DigestAction::Install, &DigestScope::Installation, by)?.map(|u| (request, u)))
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
        let listed: i64 = l
            .conn
            .query_row(
                "SELECT COUNT(*) FROM grants WHERE method = ?1 AND path = ?2 AND revoked = 0",
                params![DIGEST_METHOD, path_of(D)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(listed, 1, "the used-up run grant is still there until it expires");
    }

    /// #258: a release key is a CI principal with a standing grant: renewed while trusted, never
    /// brought back once revoked; what it signs is its one-use grant on that digest, accepted by
    /// the one check.
    #[test]
    fn a_release_key_is_a_ci_principal_with_a_standing_grant() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        assert!(!l.signer_recorded(&t, "k1").unwrap());
        let g = l.trust_signer(&t, "k1", "KEY", "operator:alex").unwrap();
        assert_eq!(l.trust_signer(&t, "k1", "KEY", "operator:alex").unwrap(), g, "kept, not repeated");
        let s = l.signers(&t).unwrap();
        assert_eq!(s, vec![Signer { grant: g.clone(), key_id: "k1".into(), key: "KEY".into() }]);
        assert!(l.renew_signer(&t, "k1").unwrap());
        // What it signs: accepted, once, by its grant on the digest.
        let u = l.accept_signed(&t, D, &s[0], "self update").unwrap().unwrap();
        assert_eq!(u.decided_by, signer_principal("k1"));
        assert_eq!(l.may_use(&t, D, DigestAction::Install, &DigestScope::Installation, "again").unwrap(), None, "one use");
        // Revoked: it signs nothing more, and renewing doesn't bring it back.
        l.revoke_grant(&g).unwrap();
        assert!(!l.renew_signer(&t, "k1").unwrap());
        assert!(l.signers(&t).unwrap().is_empty());
        assert_eq!(l.accept_signed(&t, D, &s[0], "self update").unwrap(), None);
        assert!(l.signer_recorded(&t, "k1").unwrap(), "recorded: a key file isn't imported again");
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
