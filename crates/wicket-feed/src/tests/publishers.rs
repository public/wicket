//! Several publishers on one node's feed (#300): each run on a node, and each link relay, publishes
//! to the node from its own process over its own connection. They sign under one lock (and share
//! the last statement time), but the node can receive their statements in any order.

use super::*;

/// A second publisher on the control plane's feed (another process), as `wicket` keeps one: reopened
/// from the log, and told the last statement time the others signed.
fn other(cp: &Cp, last_issued: i64) -> Publisher<BoxAuthority> {
    let mut p = cp.open_publisher(cfg());
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

/// Each run commits its own deltas and sends them over its own connection (#324's simulation found
/// this): A commits a delta, B (another run, reloading the log) catches the node up through its
/// connection, carrying A's delta, and A's own copy arrives after. That copy is the delta the node
/// holds, so it is superseded, not refused as a replay; the chain is unchanged.
#[test]
fn a_delta_another_publishers_catch_up_carried_first_is_not_a_replay() {
    let (mut cp, mut r) = setup();
    let t = T0 + 1_000;
    let from_a = cp.p.commit(vec![add(grant("g-a", &read(), T0 + 3_600_000))], t).unwrap();
    let mut b = other(&cp, cp.p.last_issued());
    for f in b.catch_up(&r.hello(), t + 1).unwrap() {
        r.accept(&f, t + 1).unwrap_or_else(|e| panic!("B's catch-up refused: {e}"));
    }
    let (epoch, head) = (r.state().unwrap().epoch, r.state().unwrap().head.clone());
    r.accept(&from_a, t + 2).expect("A's own copy is superseded");
    assert_eq!((r.state().unwrap().epoch, r.state().unwrap().head.clone()), (epoch, head));
    assert!(r.stats.refused.is_empty(), "{:?}", r.stats.refused);
    assert!(r.state().unwrap().grants.contains_key("g-a"));
}

/// Found by the placement simulation (seed 50002077): a node caught up from a snapshot newer than
/// a statement another run signed earlier holds no history for that statement's epoch. Delivered
/// late, the statement is superseded (it never takes effect), not refused as a rollback. A newer
/// statement naming an epoch older than the history held is still a rollback.
#[test]
fn a_late_statement_older_than_the_nodes_history_is_superseded() {
    let mut cp = Cp::new();
    let put = cp.put("r1");
    cp.p.commit(vec![put], T0 - 10).unwrap();
    // Another run signs for the feed's first epoch, then two deltas are committed and signed for.
    let early = cp.p.statement(T0);
    let early_epoch = cp.p.epoch();
    for i in 0..2 {
        cp.p.commit(vec![add(grant(&format!("g-{i}"), &read(), T0 + 3_600_000))], T0 + 1 + i).unwrap();
    }
    // A node that first hears of the feed now: a snapshot at the latest epoch, and a newer statement.
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&r.hello(), T0 + 10).unwrap();
    feed(&mut r, frames, T0 + 10);
    assert_eq!(r.mode(T0 + 10), Mode::Fresh);
    let held = r.state().unwrap().epoch;
    assert!(held > early_epoch);
    let superseded = r.stats.superseded;
    r.accept(&early, T0 + 11).expect("superseded, not a rollback");
    assert_eq!((r.stats.superseded, r.state().unwrap().epoch, r.mode(T0 + 11)), (superseded + 1, held, Mode::Fresh));
    assert!(r.stats.refused.is_empty(), "{:?}", r.stats.refused);
    // Signed after the newest statement held, for that old epoch: still refused.
    let mut f = Fresh { issued_at: r.last_statement().unwrap().issued_at + 1, ..r.last_statement().unwrap().clone() };
    f.epoch = early_epoch;
    let forged = Frame::new(FrameKind::Fresh, sign(&cp.feed_key, TYP_FRESH, &f));
    assert_eq!(r.accept(&forged, T0 + 12).unwrap_err().kind(), "rollback");
}

/// #589 (sim seed 32300607): two runs say hello to a node at one epoch and both catch it up. The
/// one whose frames land second brings a snapshot below the epoch the other's frames took the node
/// to, signed before the statement it holds: superseded, never applied, not a rollback. Before any
/// statement is held, an old snapshot is still a rollback (`a03_old_signed_snapshot`), and so is one
/// signed after the newest statement (`restored_backup_is_refused_until_regenesis`).
#[test]
fn an_overtaken_snapshot_is_superseded() {
    let (mut cp, mut r) = setup();
    let base = r.state().unwrap().epoch;
    // A's catch-up, built on the node's hello, is on its way...
    let a_snapshot = cp.p.snapshot(T0 + 100);
    // ...when B, under the shared lock after it, commits and catches the node up faster.
    let mut b = other(&cp, cp.p.last_issued());
    let d = b.commit(vec![add(grant("g-b", &read(), T0 + 3_600_000))], T0 + 200).unwrap();
    let statement = b.statement(T0 + 300);
    r.accept(&d, T0 + 300).unwrap();
    r.accept(&statement, T0 + 300).unwrap();
    let held = (r.state().unwrap().epoch, r.state().unwrap().head.clone());
    assert_eq!(held.0, base + 1);
    r.accept(&a_snapshot, T0 + 301).expect("an overtaken snapshot is superseded, not refused");
    assert_eq!((r.state().unwrap().epoch, r.state().unwrap().head.clone()), held, "nothing moved back");
    assert_eq!(r.stats.superseded, 1);
    assert!(r.stats.refused.is_empty(), "{:?}", r.stats.refused);
    assert_eq!(r.mode(T0 + 301), Mode::Fresh);
}

/// The review of #589: an overtaken snapshot is superseded only if it is on the node's own chain.
/// One whose head differs from the head the node recorded at its epoch is a fork, whenever it was
/// signed.
#[test]
fn an_overtaken_snapshot_off_the_nodes_chain_is_a_fork() {
    let (mut cp, mut r) = setup();
    let base = r.state().unwrap().epoch;
    let a_snapshot = cp.p.snapshot(T0 + 100);
    let mut forked: Snapshot<BoxAuthority> = jws::payload_unverified(&a_snapshot.jws).unwrap();
    assert_eq!(forked.epoch, base);
    forked.head = "forked".into();
    let forked = Frame::new(FrameKind::Snap, jws::sign(&cp.feed_key, TYP_SNAP, &forked));
    let mut b = other(&cp, cp.p.last_issued());
    let d = b.commit(vec![add(grant("g-b", &read(), T0 + 3_600_000))], T0 + 200).unwrap();
    r.accept(&d, T0 + 300).unwrap();
    r.accept(&b.statement(T0 + 300), T0 + 300).unwrap();
    let held = (r.state().unwrap().epoch, r.state().unwrap().head.clone());
    assert_eq!(r.accept(&forked, T0 + 301).unwrap_err().kind(), "fork");
    assert_eq!((r.state().unwrap().epoch, r.state().unwrap().head.clone()), held, "nothing moved");
    // The honest one is still superseded.
    r.accept(&a_snapshot, T0 + 302).expect("superseded");
    assert_eq!(r.stats.superseded, 1);
}
