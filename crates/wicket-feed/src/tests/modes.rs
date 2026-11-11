//! Mode transitions with an injected clock, and what each mode allows.

use super::*;

fn spawn() -> Escalation<'static> {
    Escalation::Spawn { parent: "z", child: "z2" }
}
fn lease() -> Escalation<'static> {
    Escalation::Lease { zone: "z", grant: "keep-1", ttl_ms: 60_000 }
}
fn approval() -> Escalation<'static> {
    Escalation::Approval { zone: "z" }
}

fn refused_in(d: Decision, mode: Mode) {
    match d {
        Decision::Refused { mode: m, .. } => assert_eq!(m, mode),
        other => panic!("expected a refusal in {mode:?}, got {other:?}"),
    }
}

#[test]
fn fresh_then_narrow_at_ttl_then_closed_at_ttl_plus_window() {
    let (mut cp, mut r) = setup();
    cp.p.commit(vec![Change::PutZone { zone: zone("z2") }], T0).unwrap();
    let frames = cp.p.catch_up(&r.hello(), T0 + 1).unwrap();
    feed(&mut r, frames, T0 + 1);
    let i = r.last_statement().unwrap().issued_at;
    let fresh_until = r.deadlines().unwrap().0;
    assert_eq!(r.deadlines().unwrap(), (i + TTL, i + TTL + WINDOW));

    // Fresh: everything the zone and the grants allow.
    let t = fresh_until - 1;
    assert_eq!(r.mode(t), Mode::Fresh);
    assert_eq!(r.decide(&read(), t), Decision::Allow(Allowed::Reach(0)));
    assert_eq!(r.decide(&write(), t), Decision::Allow(Allowed::Reach(0)));
    assert_eq!(r.decide(&granted(), t), Decision::Allow(Allowed::Grant("keep-1".into())));
    assert!(matches!(r.decide(&evil(), t), Decision::NeedsGrant(_)));
    assert!(matches!(r.decide(&forbidden(), t), Decision::Forbidden(_)));
    assert!(matches!(r.escalate(&lease(), t), Decision::Allow(Allowed::Lease { .. })));
    assert_eq!(r.escalate(&spawn(), t), Decision::Allow(Allowed::Spawn));
    assert_eq!(r.escalate(&approval(), t), Decision::Allow(Allowed::Approval));

    // Narrow from fresh_until: plain reads only.
    let t = fresh_until;
    assert_eq!(r.mode(t), Mode::Narrow);
    assert_eq!(r.decide(&read(), t), Decision::Allow(Allowed::Reach(0)));
    refused_in(r.decide(&write(), t), Mode::Narrow);
    refused_in(r.decide(&granted(), t), Mode::Narrow);
    refused_in(r.decide(&evil(), t), Mode::Narrow);
    assert!(matches!(r.decide(&forbidden(), t), Decision::Forbidden(_)), "forbidden stays forbidden");
    refused_in(r.escalate(&lease(), t), Mode::Narrow);
    refused_in(r.escalate(&spawn(), t), Mode::Narrow);
    refused_in(r.escalate(&approval(), t), Mode::Narrow);
    assert_eq!(r.mode(i + TTL + WINDOW - 1), Mode::Narrow);

    // Closed from narrow_until: nothing.
    let t = i + TTL + WINDOW;
    assert_eq!(r.mode(t), Mode::Closed);
    for o in [read(), write(), granted(), evil(), forbidden()] {
        refused_in(r.decide(&o, t), Mode::Closed);
    }
    refused_in(r.escalate(&spawn(), t), Mode::Closed);

    // A new statement brings it straight back.
    let f = cp.p.statement(t + 10);
    r.accept(&f, t + 10).unwrap();
    assert_eq!(r.mode(t + 10), Mode::Fresh);
    assert!(allowed(&mut r, &granted(), t + 10));
}

#[test]
fn production_defaults() {
    assert_eq!((DEFAULT_TTL_MS, DEFAULT_REFRESH_MS, DEFAULT_NARROW_MS), (30_000, 5_000, 120_000));
    let mut cp = Cp::with(PublisherConfig::default(), T0 + 86_400_000);
    cp.p.commit(vec![Change::PutZone { zone: zone("z") }], T0).unwrap();
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&r.hello(), T0).unwrap();
    feed(&mut r, frames, T0);
    assert!(cp.p.tick(T0 + 4_999).is_none());
    let f = cp.p.tick(T0 + 5_000).expect("a statement every 5 s");
    r.accept(&f, T0 + 5_000).unwrap();
    assert_eq!(r.mode(T0 + 5_000 + 29_999), Mode::Fresh);
    assert_eq!(r.mode(T0 + 5_000 + 30_000), Mode::Narrow);
    assert_eq!(r.mode(T0 + 5_000 + 149_999), Mode::Narrow);
    assert_eq!(r.mode(T0 + 5_000 + 150_000), Mode::Closed);
}

#[test]
fn a_snapshot_alone_vouches_for_nothing() {
    let (mut cp, _) = setup();
    let mut r = cp.replica();
    assert_eq!(r.mode(T0), Mode::Closed, "no state");
    r.accept(&cp.p.key_frame(), T0).unwrap();
    r.accept(&cp.p.snapshot(T0), T0).unwrap();
    assert_eq!(r.mode(T0), Mode::Closed, "state, but no statement");
    refused_in(r.decide(&read(), T0), Mode::Closed);
    r.accept(&cp.p.statement(T0 + 1), T0 + 1).unwrap();
    assert_eq!(r.mode(T0 + 1), Mode::Fresh);
}

#[test]
fn lagging_counts_as_stale() {
    let (mut cp, mut r) = setup();
    let d = cp.p.commit(vec![Change::Revoke { kind: RevokeKind::Grant, id: "keep-1".into(), until: T0 + 3_600_000 }], T0 + 100).unwrap();
    // The statement naming the new epoch arrives before the delta (which may hold a revocation).
    r.accept(&cp.p.statement(T0 + 200), T0 + 200).unwrap();
    assert_eq!(r.mode(T0 + 200), Mode::Narrow);
    refused_in(r.decide(&granted(), T0 + 200), Mode::Narrow);
    assert!(allowed(&mut r, &read(), T0 + 200));
    // It is narrow until the last statement that vouched for its state ends.
    assert_eq!(r.mode(T0 + TTL + WINDOW - 1), Mode::Narrow);
    assert_eq!(r.mode(T0 + TTL + WINDOW), Mode::Closed);
    r.accept(&d, T0 + 300).unwrap();
    assert_eq!(r.mode(T0 + 300), Mode::Fresh);
    assert!(matches!(r.decide(&granted(), T0 + 300), Decision::NeedsGrant(_)));
}

#[test]
fn grant_expiry_is_by_the_node_clock_in_every_mode() {
    let (mut cp, mut r) = setup();
    let short = grant("short", &evil(), T0 + 1_500);
    let d = cp.p.commit(vec![add(short)], T0 + 1).unwrap();
    r.accept(&d, T0 + 1).unwrap();
    assert!(allowed(&mut r, &evil(), T0 + 1_499));
    assert!(matches!(r.decide(&evil(), T0 + 1_500), Decision::NeedsGrant(_)), "expired while still fresh, with no update");
    assert!(matches!(r.escalate(&Escalation::Lease { zone: "z", grant: "short", ttl_ms: 60_000 }, T0 + 1_500), Decision::NeedsGrant(_)));
    // A lease never outlives its grant.
    let Decision::Allow(Allowed::Lease { until, .. }) =
        r.escalate(&Escalation::Lease { zone: "z", grant: "short", ttl_ms: 60_000 }, T0 + 1_000)
    else {
        panic!("lease")
    };
    assert_eq!(until, T0 + 1_500);
}

#[test]
fn use_counts_and_box_binding() {
    let (mut cp, mut r) = setup();
    let merge = |run: &str| op("z", run, "POST", "api.github.com", "/repos/acme/app/merge");
    let twice = Grant { uses: Some(2), ..grant("twice", &evil(), T0 + 3_600_000) };
    let r2_only = Grant { box_id: Some("r2".into()), ..grant("r2-only", &merge("r2"), T0 + 3_600_000) };
    let d = cp.p.commit(vec![add(twice), add(r2_only)], T0 + 1).unwrap();
    r.accept(&d, T0 + 1).unwrap();
    assert!(allowed(&mut r, &evil(), T0 + 2));
    assert!(allowed(&mut r, &evil(), T0 + 3));
    assert!(matches!(r.decide(&evil(), T0 + 4), Decision::NeedsGrant(_)), "uses exhausted");
    assert_eq!(r.uses("twice"), 2);
    // Bound to one box: the same op digest from another box needs its own grant.
    assert!(matches!(r.decide(&merge("r1"), T0 + 5), Decision::NeedsGrant(_)));
    assert_eq!(r.decide(&merge("r2"), T0 + 5), Decision::Allow(Allowed::Grant("r2-only".into())));
    // Unbound grants are for any box in the zone.
    assert!(allowed(&mut r, &op("z", "r2", "POST", "api.github.com", "/repos/acme/app/issues/1/comments"), T0 + 6));
    // And never for another zone: the digest includes the zone.
    assert!(matches!(
        r.decide(&op("z2", "r1", "POST", "api.github.com", "/repos/acme/app/issues/1/comments"), T0 + 6),
        Decision::Forbidden(_)
    ));
}

#[test]
fn unknown_and_invalid_zones_are_forbidden() {
    let (mut cp, mut r) = setup();
    assert!(matches!(r.decide(&op("nope", "r1", "GET", "api.github.com", "/repos/acme/x"), T0 + 1), Decision::Forbidden(_)));
    // A zone whose globs don't compile can't be published, and if one arrives it forbids everything.
    let mut bad = zone("bad");
    bad.reach[0].paths = vec!["/repos/{acme".into()];
    assert!(cp.p.commit(vec![Change::PutZone { zone: bad.clone() }], T0 + 1).is_err());
    let d = Delta {
        feed: NODE.into(),
        version: 1,
        epoch: 2,
        prev: cp.p.state().head.clone(),
        issued_at: T0,
        changes: vec![Change::PutZone { zone: bad }],
    };
    r.accept(&Frame::new(FrameKind::Delta, sign(&cp.feed_key, TYP_DELTA, &d)), T0 + 2).unwrap();
    assert!(matches!(r.decide(&op("bad", "r1", "GET", "api.github.com", "/repos/acme/x"), T0 + 3), Decision::Forbidden(_)));
}

#[test]
fn batched_deltas_apply_atomically() {
    let (mut cp, mut r) = setup();
    for i in 0..10 {
        cp.p.stage(add(grant(&format!("b-{i}"), &read(), T0 + 3_600_000)));
    }
    assert_eq!(cp.p.staged(), 10);
    let d = cp.p.flush(T0 + 1).unwrap().expect("one delta");
    assert!(cp.p.flush(T0 + 2).unwrap().is_none());
    r.accept(&d, T0 + 3).unwrap();
    assert_eq!(r.state().unwrap().epoch, 2);
    assert_eq!(r.state().unwrap().grants.len(), 11);
}

#[test]
fn catch_up_ends_with_a_statement_for_the_epoch_served() {
    // Fix 2: the cached statement is behind (a delta was committed since); a node loading a snapshot
    // could not check it, so catch-up signs a new one and the node is fresh at once.
    let (mut cp, _) = setup();
    let _cached_at_epoch_1 = cp.p.statement(T0 + 100);
    cp.p.commit(vec![add(grant("g", &read(), T0 + 3_600_000))], T0 + 101).unwrap();
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&r.hello(), T0 + 102).unwrap();
    feed(&mut r, frames, T0 + 102);
    assert_eq!(r.last_statement().unwrap().epoch, 2);
    assert_eq!(r.mode(T0 + 102), Mode::Fresh);
}
