//! "May this digest run" (#258): programs. A program's source is accepted by the one check,
//! [`wicket_store::Ledger::may_use`], on a grant on its digest (`run`, scoped to the run's zone).
//!
//! The grant is an operator's: running a manifest that pins the program's digest (the operator's
//! approval of that source, as before) records it, made by the operator running it, for a day,
//! and a later run of the same source in the same zone is accepted by it. A pin that doesn't match
//! the source refuses the run before any grant is looked at; an unpinned program is a development
//! run, warned about and not accepted by a grant (as before).

use anyhow::{bail, Result};
use wicket_core::TenantId;
use wicket_store::{DigestAction, DigestScope, DigestUse, Ledger, NewDigestGrant};

/// How long the grant a pinned run records lasts (every grant has a lifetime, at most a day).
pub const PROGRAM_GRANT_SECS: i64 = 24 * 3600;

/// Accepts program `name`'s source `digest`, pinned by the manifest, to run in `zone`, started by
/// operator `by`: a live grant on the digest if there is one, else the one this pinned run
/// records. Every acceptance is one `digest.accepted` audit record naming the grant.
pub fn accept_program(l: &Ledger, tenant: &TenantId, zone: &str, name: &str, digest: &str, by: &str) -> Result<DigestUse> {
    let scope = DigestScope::Zone(zone.to_string());
    let using = format!("program {name}");
    if let Some(u) = l.may_use(tenant, digest, DigestAction::Run, &scope, &using)? {
        return Ok(u);
    }
    let grant = l.grant_digest(&NewDigestGrant {
        tenant,
        digest,
        action: DigestAction::Run,
        scope: scope.clone(),
        uses: None,
        expires_at: wicket_store::now() + PROGRAM_GRANT_SECS,
        decided_by: by,
    })?;
    l.audit(
        tenant,
        None,
        "digest.granted",
        &serde_json::json!({ "digest": digest, "action": "run", "scope": scope, "grant": grant, "by": by,
                             "why": format!("program {name} is pinned to it in the manifest {by} ran") }),
    )?;
    match l.may_use(tenant, digest, DigestAction::Run, &scope, &using)? {
        Some(u) => Ok(u),
        None => bail!("program {name}: the grant just recorded on {digest} ({grant}) doesn't cover zone {zone}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:abababababababababababababababababababababababababababababababab";

    fn kinds(l: &Ledger, kind: &str) -> usize {
        l.audit_tail(100).unwrap().iter().filter(|r| r.2 == kind).count()
    }

    /// #258: a pinned program's first run records an operator's grant on its digest and is
    /// accepted by it; the next run in that zone is accepted by the same grant; another zone gets
    /// its own. Every acceptance is audited.
    #[test]
    fn a_pinned_program_is_accepted_by_a_grant_on_its_digest() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let first = accept_program(&l, &t, "research", "build", D, "operator:alex").unwrap();
        assert_eq!((first.decided_by.as_str(), &first.scope), ("operator:alex", &DigestScope::Zone("research".into())));
        let again = accept_program(&l, &t, "research", "build", D, "operator:sam").unwrap();
        assert_eq!(again.grant, first.grant, "the same grant");
        let other = accept_program(&l, &t, "ops", "build", D, "operator:alex").unwrap();
        assert_ne!(other.grant, first.grant);
        assert_eq!((kinds(&l, "digest.granted"), kinds(&l, "digest.accepted")), (2, 3));
        // A revoked grant accepts nothing more: the next run records a new one.
        l.revoke_grant(&first.grant).unwrap();
        assert_ne!(accept_program(&l, &t, "research", "build", D, "operator:alex").unwrap().grant, first.grant);
        // Not a digest: refused.
        assert!(accept_program(&l, &t, "research", "build", "latest", "operator:alex").is_err());
    }
}
