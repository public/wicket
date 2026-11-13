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
fn fresh_then_offline_at_ttl_and_offline_until_each_grant_expires() {
    let (mut cp, mut r) = setup();
    cp.p.commit(vec![Change::PutZone { zone: zone("z2") }], T0).unwrap();
    let frames = cp.p.catch_up(&r.hello(), T0 + 1).unwrap();
    feed(&mut r, frames, T0 + 1);
    let i = r.last_statement().unwrap().issued_at;
    let fresh_until = r.fresh_until().unwrap();
    assert_eq!(fresh_until, i + TTL);

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

    // Offline from fresh_until (#153): the same decisions, for as long as what is held is valid,
    // hours after the last statement; nothing new is leased, spawned or approved.
    for t in [fresh_until, fresh_until + 150_000, T0 + 3_599_999] {
        assert_eq!(r.mode(t), Mode::Offline, "{t}");
        assert_eq!(r.decide(&read(), t), Decision::Allow(Allowed::Reach(0)));
        assert_eq!(r.decide(&write(), t), Decision::Allow(Allowed::Reach(0)));
        assert_eq!(r.decide(&granted(), t), Decision::Allow(Allowed::Grant("keep-1".into())));
        assert!(matches!(r.decide(&evil(), t), Decision::NeedsGrant(_)), "the caller queues it");
        assert!(matches!(r.decide(&forbidden(), t), Decision::Forbidden(_)), "forbidden stays forbidden");
        refused_in(r.escalate(&lease(), t), Mode::Offline);
        refused_in(r.escalate(&spawn(), t), Mode::Offline);
        refused_in(r.escalate(&approval(), t), Mode::Offline);
    }
    // The grant ends at its own expiry, offline too.
    assert!(matches!(r.decide(&granted(), T0 + 3_600_000), Decision::NeedsGrant(_)));

    // A new statement brings it straight back to fresh.
    let t = T0 + 3_600_000;
    let f = cp.p.statement(t + 10);
    r.accept(&f, t + 10).unwrap();
    assert_eq!(r.mode(t + 10), Mode::Fresh);
}

#[test]
fn production_defaults() {
    assert_eq!((DEFAULT_TTL_MS, DEFAULT_REFRESH_MS), (30_000, 5_000));
    let mut cp = Cp::with(PublisherConfig::default(), T0 + 86_400_000);
    cp.p.commit(vec![Change::PutZone { zone: zone("z") }], T0).unwrap();
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&r.hello(), T0).unwrap();
    feed(&mut r, frames, T0);
    assert!(cp.p.tick(T0 + 4_999).is_none());
    let f = cp.p.tick(T0 + 5_000).expect("a statement every 5 s");
    r.accept(&f, T0 + 5_000).unwrap();
    assert_eq!(r.mode(T0 + 5_000 + 29_999), Mode::Fresh);
    assert_eq!(r.mode(T0 + 5_000 + 30_000), Mode::Offline);
    // Offline until the feed key's certificate ends (it bounds everything the node holds).
    assert_eq!(r.mode(T0 + 86_399_999), Mode::Offline);
    assert_eq!(r.mode(T0 + 86_400_000), Mode::Closed);
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
fn lagging_refuses_until_caught_up() {
    let (mut cp, mut r) = setup();
    let d = cp.p.commit(vec![Change::Revoke { kind: RevokeKind::Grant, id: "keep-1".into(), until: T0 + 3_600_000 }], T0 + 100).unwrap();
    // The statement naming the new epoch arrives before the delta (which may hold a revocation).
    r.accept(&cp.p.statement(T0 + 200), T0 + 200).unwrap();
    assert_eq!(r.mode(T0 + 200), Mode::Lagging);
    refused_in(r.decide(&granted(), T0 + 200), Mode::Lagging);
    refused_in(r.decide(&read(), T0 + 200), Mode::Lagging);
    // Lagging while that statement is live; then offline on what it holds, like any cut-off node.
    assert_eq!(r.mode(T0 + 200 + TTL - 1), Mode::Lagging);
    assert_eq!(r.mode(T0 + 200 + TTL), Mode::Offline);
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
    let twice = Grant { uses: Some(2), box_id: Some("r1".into()), ..grant("twice", &evil(), T0 + 3_600_000) };
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

/// Use counts are kept on the node holding the box, so a counted grant must name its box: otherwise
/// two nodes could each honour it `uses` times.
#[test]
fn a_counted_grant_must_name_its_box() {
    let (mut cp, mut r) = setup();
    let unbound = Grant { uses: Some(1), ..grant("unbound", &evil(), T0 + 3_600_000) };
    assert!(cp.p.commit(vec![add(unbound.clone())], T0 + 1).is_err(), "the publisher refuses it");
    // One that arrives anyway (e.g. from an older publisher) is never honoured.
    let d = Delta { feed: NODE.into(), version: 1, epoch: 2, prev: cp.p.state().head.clone(), issued_at: T0, changes: vec![add(unbound)] };
    r.accept(&Frame::new(FrameKind::Delta, sign(&cp.feed_key, TYP_DELTA, &d)), T0 + 1).unwrap();
    assert!(matches!(r.decide(&evil(), T0 + 2), Decision::NeedsGrant(_)));
    assert_eq!(r.uses("unbound"), 0);
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
