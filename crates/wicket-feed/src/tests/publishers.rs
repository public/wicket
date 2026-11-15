//! Several publishers on one node's feed (#300): each run on a node, and each link relay, publishes
//! to the node from its own process over its own connection. They sign under one lock (and share
//! the last statement time), but the node can receive their statements in any order.

use super::*;

/// A second publisher on the control plane's feed (another process), as `wicket` keeps one: reopened
/// from the log, and told the last statement time the others signed.
fn other(cp: &Cp, last_issued: i64) -> Publisher<ZoneSpec> {
    let mut p = Publisher::open(cp.dir.path(), NODE, &cp.root.verifying_key(), cp.feed_key.clone(), &cp.cert, cfg()).unwrap();
    p.note_issued(last_issued);
    p
}

#[test]
fn two_publishers_interleaved_on_one_replica_are_never_refused() {
    let (mut cp, mut r) = setup();
    let mut b = other(&cp, cp.p.last_issued());
    for i in 1..=20 {
        // Both sign in the same millisecond, under the shared lock: B's time is bumped past A's.
        let t = T0 + i * 100;
        cp.p.note_issued(b.last_issued());
        let from_a = cp.p.statement(t);
        b.note_issued(cp.p.last_issued());
        let from_b = b.statement(t);
        // B's connection is quicker: the node gets B's (newer) statement first, then A's.
        r.accept(&from_b, t).unwrap_or_else(|e| panic!("round {i}: B's statement refused: {e}"));
        r.accept(&from_a, t).unwrap_or_else(|e| panic!("round {i}: A's statement refused: {e}"));
        assert_eq!(r.mode(t), Mode::Fresh);
        assert_eq!(r.last_statement().unwrap().issued_at, t + 1, "the newer statement stays the one held");
    }
    assert!(r.stats.refused.is_empty(), "{:?}", r.stats.refused);
    assert_eq!(r.stats.superseded, 20);

    // A commits a delta; B (reloading the log, as under the lock) signs for the new epoch, and A's
    // statement for the old epoch, signed before, arrives last: superseded, not a rollback.
    let t = T0 + 5_000;
    cp.p.note_issued(b.last_issued());
    let old_epoch = cp.p.statement(t);
    let d = cp.p.commit(vec![add(grant("g-new", &read(), T0 + 3_600_000))], t).unwrap();
    let mut b = other(&cp, cp.p.last_issued());
    let new_epoch = b.statement(t);
    r.accept(&d, t).unwrap();
    r.accept(&new_epoch, t).unwrap();
    r.accept(&old_epoch, t + 1).expect("an older statement is superseded, not refused");
    assert_eq!(r.last_statement().unwrap().epoch, 2);
    assert_eq!(r.mode(t + 1), Mode::Fresh);
    assert!(r.stats.refused.is_empty(), "{:?}", r.stats.refused);
}

#[test]
fn superseded_statements_never_take_effect_and_replays_are_still_refused() {
    let (mut cp, mut r) = setup();
    let early = cp.p.statement(T0 + 100);
    let late = cp.p.statement(T0 + 200);
    r.accept(&late, T0 + 200).unwrap();
    let held = (r.last_statement().cloned(), r.fresh_until());

    // The statement held, again: a replay.
    assert_eq!(r.accept(&late, T0 + 201).unwrap_err().kind(), "replay");
    // An older one: dropped, and nothing moves back.
    r.accept(&early, T0 + 201).unwrap();
    assert_eq!((r.last_statement().cloned(), r.fresh_until()), held);
    assert_eq!(r.stats.superseded, 1);

    // An older one is still checked in full: forged, expired or forked, it is refused.
    let st = r.state().unwrap();
    let f = Fresh {
        feed: NODE.into(),
        version: 1,
        epoch: st.epoch,
        head: st.head.clone(),
        issued_at: T0 + 150,
        fresh_until: T0 + 150 + TTL,
        narrow_until: 0,
    };
    let forged = Frame::new(FrameKind::Fresh, sign_as(&key(), TYP_FRESH, &kid(&cp.feed_key.verifying_key()), &f));
    assert_eq!(r.accept(&forged, T0 + 201).unwrap_err().kind(), "bad_signature");
    let forked = Fresh { head: "ab".repeat(32), ..f.clone() };
    let forked = Frame::new(FrameKind::Fresh, sign(&cp.feed_key, TYP_FRESH, &forked));
    assert_eq!(r.accept(&forked, T0 + 201).unwrap_err().kind(), "fork");
    assert_eq!(r.accept(&early, T0 + 100 + TTL).unwrap_err().kind(), "expired");
    assert_eq!(r.stats.superseded, 1);
    assert_eq!((r.last_statement().cloned(), r.fresh_until()), held);
}
