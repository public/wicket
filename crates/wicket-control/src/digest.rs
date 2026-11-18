//! "May this digest run" (#258): programs and images. A program's source and a box's pinned image
//! are accepted by the one check, [`wicket_store::Ledger::may_use`], on a grant on their digest
//! (`run`, scoped to the run's zone).
//!
//! The grant is an operator's: running a manifest that pins a digest (the operator's approval of
//! that source or image, as before) records one on the pinned digest, made by the operator running
//! it, for a day, unless one is live. Then the one check is asked about the digest that actually
//! runs: a program whose source isn't what was pinned has no grant, and is refused by the check
//! itself. An unpinned program (a development run) or image (a tag) is not accepted by a grant: it
//! runs as before, and its `run.start` record says it was unpinned.

use anyhow::{bail, Result};
use wicket_core::TenantId;
use wicket_store::{DigestAction, DigestScope, DigestUse, Ledger, NewDigestGrant};

/// How long the grant a pinned run records lasts (every grant has a lifetime, at most a day).
pub const PROGRAM_GRANT_SECS: i64 = 24 * 3600;

/// Accepts program `name`'s source, whose digest is `actual`, pinned by the manifest to `pinned`,
/// to run in `zone`, started by operator `by`: a live grant on `actual` (the one the pin records
/// on `pinned`, when they are one digest). Every acceptance is one `digest.accepted` audit record
/// naming the grant.
pub fn accept_program(l: &Ledger, tenant: &TenantId, zone: &str, name: &str, pinned: &str, actual: &str, by: &str) -> Result<DigestUse> {
    accept(l, tenant, zone, &format!("program {name}"), pinned, actual, by).map_err(|e| {
        if pinned != actual {
            anyhow::anyhow!("program {name} source digest is {actual}, but the approved digest is {pinned}: re-approve the change ({e:#})")
        } else {
            e
        }
    })
}

/// Accepts the image `name`, pinned to `digest`, as a box's image in `zone`, started by operator
/// `by`: as [`accept_program`] does a program's source (its node then checks the box is that image).
pub fn accept_image(l: &Ledger, tenant: &TenantId, zone: &str, name: &str, digest: &str, by: &str) -> Result<DigestUse> {
    accept(l, tenant, zone, &format!("image {name}"), digest, digest, by)
}

fn accept(l: &Ledger, tenant: &TenantId, zone: &str, using: &str, pinned: &str, actual: &str, by: &str) -> Result<DigestUse> {
    let scope = DigestScope::Zone(zone.to_string());
    if let Some(u) = l.may_use(tenant, actual, DigestAction::Run, &scope, using)? {
        return Ok(u);
    }
    if !l.digest_granted(tenant, pinned, DigestAction::Run, &scope)? {
        let grant = l.grant_digest(&NewDigestGrant {
            tenant,
            digest: pinned,
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
            &serde_json::json!({ "digest": pinned, "action": "run", "scope": scope, "grant": grant, "by": by,
                                 "why": format!("{using} is pinned to it in the manifest {by} ran") }),
        )?;
    }
    match l.may_use(tenant, actual, DigestAction::Run, &scope, using)? {
        Some(u) => Ok(u),
        None => bail!("{using}: no grant lets {actual} run in zone {zone}"),
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
        let first = accept_program(&l, &t, "research", "build", D, D, "operator:alex").unwrap();
        assert_eq!((first.decided_by.as_str(), &first.scope), ("operator:alex", &DigestScope::Zone("research".into())));
        let again = accept_program(&l, &t, "research", "build", D, D, "operator:sam").unwrap();
        assert_eq!(again.grant, first.grant, "the same grant");
        let other = accept_program(&l, &t, "ops", "build", D, D, "operator:alex").unwrap();
        assert_ne!(other.grant, first.grant);
        assert_eq!((kinds(&l, "digest.granted"), kinds(&l, "digest.accepted")), (2, 3));
        // A revoked grant accepts nothing more: the next run records a new one.
        l.revoke_grant(&first.grant).unwrap();
        assert_ne!(accept_program(&l, &t, "research", "build", D, D, "operator:alex").unwrap().grant, first.grant);
        // Not a digest: refused.
        assert!(accept_program(&l, &t, "research", "build", "latest", "latest", "operator:alex").is_err());
        // A source that isn't what was pinned: the pin's grant doesn't cover it, so the one check
        // refuses it (#258: no separate pin check).
        let other_src = "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
        let e = accept_program(&l, &t, "research", "build", D, other_src, "operator:alex").unwrap_err().to_string();
        assert!(e.contains("re-approve the change") && e.contains(other_src), "{e}");
    }

    /// #258: a pinned image is accepted the same way, by the same kind of grant on its digest (an
    /// image and a program of one digest share it: a digest is what is granted, not a name).
    #[test]
    fn a_pinned_image_is_accepted_by_a_grant_on_its_digest() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let image = format!("registry.example.com/agent@{D}");
        let u = accept_image(&l, &t, "research", &image, D, "operator:alex").unwrap();
        assert_eq!(accept_image(&l, &t, "research", &image, D, "operator:sam").unwrap().grant, u.grant);
        let rec = l.audit_tail(100).unwrap().into_iter().rfind(|r| r.2 == "digest.accepted").unwrap();
        let body: serde_json::Value = serde_json::from_str(&rec.4).unwrap();
        assert_eq!((body["by"].as_str(), body["grant"].as_str()), (Some(format!("image {image}").as_str()), Some(u.grant.as_str())));
        assert_eq!(kinds(&l, "digest.granted"), 1);
    }
}
