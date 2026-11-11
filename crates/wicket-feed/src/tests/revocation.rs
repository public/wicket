//! Revocation: immediate once the delta applies; at worst one TTL when the node hears nothing.

use super::*;

fn revoke(kind: RevokeKind, id: &str, until: i64) -> Change<ZoneSpec> {
    Change::Revoke { kind, id: id.into(), until }
}

#[test]
fn a_revoked_grant_stops_as_soon_as_the_delta_applies() {
    let (mut cp, mut r) = setup();
    assert!(allowed(&mut r, &granted(), T0 + 1));
    let d = cp.p.commit(vec![revoke(RevokeKind::Grant, "keep-1", T0 + 3_600_000)], T0 + 2).unwrap();
    r.accept(&d, T0 + 2).unwrap();
    assert!(matches!(r.decide(&granted(), T0 + 2), Decision::NeedsGrant(_)));
    assert!(matches!(r.escalate(&Escalation::Lease { zone: "z", grant: "keep-1", ttl_ms: 1_000 }, T0 + 2), Decision::NeedsGrant(_)));
    // Re-adding a revoked id does nothing.
    let d = cp.p.commit(vec![add(grant("keep-1", &granted(), T0 + 3_600_000))], T0 + 3).unwrap();
    r.accept(&d, T0 + 3).unwrap();
    assert!(!allowed(&mut r, &granted(), T0 + 3));
}

#[test]
fn a_revoked_run_is_refused_everything_at_once() {
    let (mut cp, mut r) = setup();
    let d = cp.p.commit(vec![revoke(RevokeKind::Run, "r1", T0 + 3_600_000)], T0 + 2).unwrap();
    r.accept(&d, T0 + 2).unwrap();
    for o in [read(), write(), granted()] {
        assert!(matches!(r.decide(&o, T0 + 2), Decision::Forbidden(_)), "{o:?}");
    }
    assert!(allowed(&mut r, &op("z", "r2", "GET", "api.github.com", "/repos/acme/app"), T0 + 2), "other runs carry on");
    // Still refused while narrow.
    assert!(matches!(r.decide(&read(), T0 + TTL + 1), Decision::Forbidden(_)));
    // Token revocation ids are held for the capability layer.
    let d = cp.p.commit(vec![revoke(RevokeKind::Token, "link-abc", T0 + 3_600_000)], T0 + 3).unwrap();
    r.accept(&d, T0 + 3).unwrap();
    assert!(r.state().unwrap().is_revoked(RevokeKind::Token, "link-abc"));
    assert!(!r.state().unwrap().is_revoked(RevokeKind::Grant, "link-abc"));
}

#[test]
fn a_partitioned_node_stops_honouring_grants_within_one_ttl_of_the_revocation() {
    let (mut cp, mut r) = setup();
    // Statements keep arriving until t_r, then the link is cut, and the revocation is committed.
    for t in [500, 1_000, 1_500] {
        let f = cp.p.statement(T0 + t);
        r.accept(&f, T0 + t).unwrap();
    }
    let t_r = T0 + 1_700;
    let _never_delivered = cp.p.commit(vec![revoke(RevokeKind::Grant, "keep-1", T0 + 3_600_000)], t_r).unwrap();
    // Every statement signed from now on names the revocation's epoch, so none can keep the node
    // fresh without it; the last one the node has expires within one TTL of t_r.
    let after = cp.p.statement(t_r + 1);
    assert_eq!(crate::jws::payload_unverified::<Fresh>(&after.jws).unwrap().epoch, 2);
    let (fresh_until, _) = r.deadlines().unwrap();
    assert!(fresh_until <= t_r + TTL);
    assert!(allowed(&mut r, &granted(), fresh_until - 1), "the node never learned of it");
    assert!(!allowed(&mut r, &granted(), fresh_until), "but stops at fresh_until");
    assert!(allowed(&mut r, &read(), fresh_until), "plain reads continue, narrow");
    // Had the node received a later statement without the delta, it would be lagging: stale at once.
    assert_eq!(r.mode(fresh_until - 100), Mode::Fresh);
    r.accept(&after, fresh_until - 100).unwrap();
    assert_eq!(r.mode(fresh_until - 100), Mode::Narrow);
    assert!(!allowed(&mut r, &granted(), fresh_until - 100));
}

#[test]
fn the_revoked_set_stays_bounded() {
    let (mut cp, mut r) = setup();
    let d = cp.p.commit(vec![revoke(RevokeKind::Grant, "a", T0 + 1_000), revoke(RevokeKind::Run, "b", T0 + 9_000_000)], T0 + 1).unwrap();
    r.accept(&d, T0 + 1).unwrap();
    assert_eq!(r.state().unwrap().revoked_len(), 2);
    // A snapshot after `until` no longer carries the entry; nor the expired grant.
    let mut r2 = cp.replica();
    let frames = cp.p.catch_up(&r2.hello(), T0 + 3_600_001).unwrap();
    feed(&mut r2, frames, T0 + 3_600_001);
    let st = r2.state().unwrap();
    assert_eq!(st.revoked_len(), 1);
    assert!(st.is_revoked(RevokeKind::Run, "b"));
    assert!(st.grants.is_empty(), "keep-1 expired at T0 + 1 h");
}
