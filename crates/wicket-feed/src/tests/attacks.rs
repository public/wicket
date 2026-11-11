//! The 14 kinds of bad update from experiment #60 (RESULTS.md §5.5), plus a stolen online key used
//! past its certificate, a control plane restored from an old backup, and recovery by re-genesis.

use super::*;
use crate::jws::{payload_unverified, tamper};
use serde_json::Value;

/// Asserts `f` is refused as `kind`, and that nothing changed: same epoch and head, still fresh,
/// `keep-1` still honoured, the attacker's op still not allowed.
fn refused(r: &mut Replica<ZoneSpec>, f: Frame, now: i64, kind: &str) {
    let (epoch, head) = (r.state().unwrap().epoch, r.state().unwrap().head.clone());
    let e = r.accept(&f, now).expect_err("must be refused");
    assert_eq!(e.kind(), kind, "{e}");
    assert!(r.stats.refused.get(kind).copied().unwrap_or(0) > 0);
    let st = r.state().unwrap();
    assert_eq!((st.epoch, &st.head), (epoch, &head));
    assert_eq!(r.mode(now), Mode::Fresh);
    assert!(allowed(r, &granted(), now));
    assert!(!allowed(r, &evil(), now));
}

fn delta(cp: &Cp, epoch: u64, prev: &str, feed: &str, changes: Vec<Change<ZoneSpec>>) -> Frame {
    let d = Delta { feed: feed.into(), version: 1, epoch, prev: prev.into(), issued_at: T0, changes };
    Frame::new(FrameKind::Delta, sign(&cp.feed_key, TYP_DELTA, &d))
}

fn statement(key: &SigningKey, kid_: Option<&str>, f: &Fresh) -> Frame {
    let jws = match kid_ {
        Some(k) => sign_as(key, TYP_FRESH, k, f),
        None => sign(key, TYP_FRESH, f),
    };
    Frame::new(FrameKind::Fresh, jws)
}

/// A node at epoch 3 with a statement at T0 + 10.
fn at_epoch_3() -> (Cp, Replica<ZoneSpec>, Vec<Frame>) {
    let (mut cp, mut r) = setup();
    let mut deltas = vec![];
    for i in 0..2 {
        let d = cp.p.commit(vec![add(grant(&format!("g-{i}"), &read(), T0 + 3_600_000))], T0 + i).unwrap();
        r.accept(&d, T0 + 5).unwrap();
        deltas.push(d);
    }
    r.accept(&cp.p.statement(T0 + 10), T0 + 10).unwrap();
    assert_eq!(r.state().unwrap().epoch, 3);
    (cp, r, deltas)
}

fn honest(r: &Replica<ZoneSpec>, issued_at: i64) -> Fresh {
    let st = r.state().unwrap();
    Fresh {
        feed: NODE.into(),
        version: 1,
        epoch: st.epoch,
        head: st.head.clone(),
        issued_at,
        fresh_until: issued_at + TTL,
        narrow_until: issued_at + TTL + WINDOW,
    }
}

#[test]
fn a01_tampered_delta() {
    let (mut cp, mut r, _) = at_epoch_3();
    let d = cp.p.commit(vec![add(grant("ok", &read(), T0 + 3_600_000))], T0 + 20).unwrap();
    let mut p: Value = payload_unverified(&d.jws).unwrap();
    p["changes"][0]["grant"] = serde_json::to_value(grant("evil", &evil(), T0 + 3_600_000)).unwrap();
    refused(&mut r, Frame::new(FrameKind::Delta, tamper(&d.jws, &p)), T0 + 20, "bad_signature");
}

#[test]
fn a02_replayed_old_delta() {
    let (_cp, mut r, deltas) = at_epoch_3();
    refused(&mut r, deltas[0].clone(), T0 + 20, "replay");
}

#[test]
fn a03_old_signed_snapshot() {
    let (mut cp, mut r) = setup();
    let old = cp.p.snapshot(T0); // epoch 1
    for i in 0..2 {
        let d = cp.p.commit(vec![add(grant(&format!("g-{i}"), &read(), T0 + 3_600_000))], T0 + i).unwrap();
        r.accept(&d, T0 + 5).unwrap();
    }
    refused(&mut r, old, T0 + 20, "rollback");
}

#[test]
fn a04_reused_statement() {
    let (mut cp, mut r, _) = at_epoch_3();
    let f = cp.p.statement(T0 + 20);
    r.accept(&f, T0 + 20).unwrap();
    refused(&mut r, f, T0 + 21, "replay");
}

#[test]
fn a05_statement_signed_by_an_attacker_key() {
    let (_cp, mut r, _) = at_epoch_3();
    let f = Fresh { fresh_until: i64::MAX / 2, narrow_until: i64::MAX / 2, ..honest(&r, T0 + 20) };
    refused(&mut r, statement(&key(), None, &f), T0 + 20, "unknown_key");
}

#[test]
fn a06_attacker_statement_with_the_real_kid() {
    let (cp, mut r, _) = at_epoch_3();
    let f = Fresh { fresh_until: i64::MAX / 2, narrow_until: i64::MAX / 2, ..honest(&r, T0 + 20) };
    let real = kid(&cp.feed_key.verifying_key());
    refused(&mut r, statement(&key(), Some(&real), &f), T0 + 20, "bad_signature");
}

#[test]
fn a07_stolen_feed_key_signs_an_hour() {
    let (cp, mut r, _) = at_epoch_3();
    let f = Fresh { fresh_until: T0 + 20 + 3_600_000, narrow_until: T0 + 20 + 3_600_000, ..honest(&r, T0 + 20) };
    refused(&mut r, statement(&cp.feed_key, None, &f), T0 + 20, "too_long");
    let f = Fresh { narrow_until: T0 + 20 + TTL + 3_600_000, ..honest(&r, T0 + 20) };
    refused(&mut r, statement(&cp.feed_key, None, &f), T0 + 20, "too_long");
}

#[test]
fn a08_statement_from_the_future() {
    let (cp, mut r, _) = at_epoch_3();
    let f = honest(&r, T0 + 60_000);
    refused(&mut r, statement(&cp.feed_key, None, &f), T0 + 20, "from_future");
}

#[test]
fn a09_expired_statement() {
    let (cp, mut r, _) = at_epoch_3();
    let f = Fresh { fresh_until: T0 + 15, ..honest(&r, T0 + 11) };
    refused(&mut r, statement(&cp.feed_key, None, &f), T0 + 20, "expired");
}

#[test]
fn a10_forged_feed_key_certificate() {
    let (cp, mut r, _) = at_epoch_3();
    let attacker = key();
    let c = KeyCert::new(&attacker.verifying_key(), 2, i64::MAX, 30_000, 300_000);
    let forged = sign_as(&attacker, TYP_KEY, &kid(&cp.root.verifying_key()), &c);
    refused(&mut r, Frame::new(FrameKind::Key, forged), T0 + 20, "bad_signature");
    let own_kid = sign(&attacker, TYP_KEY, &c);
    refused(&mut r, Frame::new(FrameKind::Key, own_kid), T0 + 20, "unknown_key");
}

#[test]
fn a11_delta_sent_as_a_statement() {
    let (mut cp, mut r, _) = at_epoch_3();
    let d = cp.p.commit(vec![add(grant("x", &read(), T0 + 3_600_000))], T0 + 20).unwrap();
    refused(&mut r, Frame::new(FrameKind::Fresh, d.jws), T0 + 20, "wrong_type");
}

#[test]
fn a12_delta_for_another_node() {
    let (cp, mut r, _) = at_epoch_3();
    let head = r.state().unwrap().head.clone();
    refused(&mut r, delta(&cp, 4, &head, "n2", vec![add(grant("evil", &evil(), i64::MAX))]), T0 + 20, "wrong_audience");
}

#[test]
fn a13_delta_skipping_an_epoch() {
    let (cp, mut r, _) = at_epoch_3();
    let head = r.state().unwrap().head.clone();
    let e = r.accept(&delta(&cp, 5, &head, NODE, vec![]), T0 + 20).unwrap_err();
    assert!(e.wants_catch_up());
    refused(&mut r, delta(&cp, 5, &head, NODE, vec![add(grant("evil", &evil(), i64::MAX))]), T0 + 20, "gap");
}

#[test]
fn a14_delta_on_another_chain() {
    let (cp, mut r, _) = at_epoch_3();
    refused(&mut r, delta(&cp, 4, GENESIS, NODE, vec![add(grant("evil", &evil(), i64::MAX))]), T0 + 20, "fork");
}

#[test]
fn stolen_feed_key_is_useless_past_its_certificate() {
    let mut cp = Cp::with(cfg(), T0 + 5_000);
    cp.p.commit(vec![Change::PutZone { zone: zone("z") }], T0).unwrap();
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&r.hello(), T0).unwrap();
    feed(&mut r, frames, T0);
    assert_eq!(r.mode(T0 + 1), Mode::Fresh);
    // The thief keeps signing statements after the certificate's not_after.
    let f = cp.p.statement(T0 + 5_000);
    assert_eq!(r.accept(&f, T0 + 5_000).unwrap_err().kind(), "key_expired");
    let d = cp.p.commit(vec![add(grant("evil", &evil(), i64::MAX))], T0 + 5_001).unwrap();
    assert_eq!(r.accept(&d, T0 + 5_001).unwrap_err().kind(), "key_expired");
    // And the node is closed from not_after, whatever the statements said.
    assert_eq!(r.mode(T0 + 4_999), Mode::Narrow);
    assert_eq!(r.mode(T0 + 5_000), Mode::Closed);
    // An expired certificate is refused, too.
    let old = cert(&cp.root, &cp.feed_key, 1, T0 + 5_000);
    assert_eq!(r.accept(&Frame::new(FrameKind::Key, old), T0 + 6_000).unwrap_err().kind(), "key_expired");
}

#[test]
fn certificate_versions_never_go_down() {
    let (cp, mut r, _) = at_epoch_3();
    let other = key();
    let same_version = cert(&cp.root, &other, 1, T0 + 86_400_000);
    refused(&mut r, Frame::new(FrameKind::Key, same_version), T0 + 20, "key_rollback");
    let v0 = cert(&cp.root, &cp.feed_key, 0, T0 + 86_400_000);
    refused(&mut r, Frame::new(FrameKind::Key, v0), T0 + 20, "key_rollback");
    // The same certificate again is fine (every catch-up starts with it).
    r.accept(&cp.p.key_frame(), T0 + 20).unwrap();
}

#[test]
fn statement_naming_an_older_epoch_is_checked_against_the_chain() {
    // Fix 1: a statement signed before the deltas the node already applied is fine if its head is
    // on the node's chain; a different head at that epoch is a fork.
    let (mut cp, mut r, _) = at_epoch_3();
    let f_old = cp.p.statement(T0 + 20); // names epoch 3
    let d = cp.p.commit(vec![add(grant("g-x", &read(), T0 + 3_600_000))], T0 + 21).unwrap();
    r.accept(&d, T0 + 22).unwrap();
    r.accept(&f_old, T0 + 23).expect("older epoch on our chain");
    assert_eq!(r.mode(T0 + 24), Mode::Fresh);
    let bad = Fresh { epoch: 3, head: "ab".repeat(32), ..honest(&r, T0 + 30) };
    refused(&mut r, statement(&cp.feed_key, None, &bad), T0 + 30, "fork");
}

#[test]
fn statement_epoch_never_goes_back_from_the_last_statement() {
    let (mut cp, mut r, _) = at_epoch_3();
    // The node accepts a statement naming epoch 4 before the delta arrives (lagging).
    let d4 = cp.p.commit(vec![add(grant("g-4", &read(), T0 + 3_600_000))], T0 + 20).unwrap();
    r.accept(&cp.p.statement(T0 + 21), T0 + 21).unwrap();
    assert_eq!(r.mode(T0 + 22), Mode::Narrow, "lagging counts as stale");
    // A later statement naming epoch 3 again (an old-backup control plane, say) is a rollback.
    let st = r.state().unwrap();
    let f = Fresh {
        feed: NODE.into(),
        version: 1,
        epoch: 3,
        head: st.head.clone(),
        issued_at: T0 + 30,
        fresh_until: T0 + 30 + TTL,
        narrow_until: T0 + 30 + TTL + WINDOW,
    };
    assert_eq!(r.accept(&statement(&cp.feed_key, None, &f), T0 + 30).unwrap_err().kind(), "rollback");
    r.accept(&d4, T0 + 31).unwrap();
    assert_eq!(r.mode(T0 + 32), Mode::Fresh);
}

#[test]
fn restored_backup_is_refused_until_regenesis() {
    let (mut cp, mut r, _) = at_epoch_3();
    // Epochs 4..6 reach the node; then the control plane is restored from a backup of epoch 3,
    // with the same keys.
    for i in 0..3 {
        let d = cp.p.commit(vec![add(grant(&format!("late-{i}"), &read(), T0 + 3_600_000))], T0 + 20 + i).unwrap();
        r.accept(&d, T0 + 25).unwrap();
    }
    let last = cp.p.statement(T0 + 30);
    r.accept(&last, T0 + 30).unwrap();
    assert_eq!(r.state().unwrap().epoch, 6);
    let log = std::fs::read_to_string(cp.p.log_path()).unwrap();
    let backup: String = log.lines().take(3).map(|l| format!("{l}\n")).collect();
    std::fs::write(cp.p.log_path(), backup).unwrap();
    cp.restart(cfg());
    assert_eq!(cp.p.epoch(), 3);
    // Everything the restored control plane serves is refused, and the node decays on schedule.
    let frames = cp.p.catch_up(&r.hello(), T0 + 1_000).unwrap();
    let kinds: Vec<&str> = frames.iter().filter_map(|f| r.accept(f, T0 + 1_000).err()).map(|e| e.kind()).collect();
    assert_eq!(kinds, ["rollback", "rollback"], "snapshot at epoch 3, and its statement");
    for t in [2_000, 2_500] {
        let f = cp.p.statement(T0 + t);
        assert_eq!(r.accept(&f, T0 + t).unwrap_err().kind(), "rollback");
    }
    assert_eq!(r.state().unwrap().epoch, 6);
    assert_eq!(r.mode(T0 + 30 + TTL - 1), Mode::Fresh);
    assert_eq!(r.mode(T0 + 30 + TTL), Mode::Narrow);
    assert_eq!(r.mode(T0 + 30 + TTL + WINDOW), Mode::Closed);
    // The new history diverges from the node's (a different epoch 4): still refused.
    let d4 = cp.p.commit(vec![add(grant("after-restore", &read(), T0 + 3_600_000))], T0 + 3_000).unwrap();
    assert_eq!(r.accept(&d4, T0 + 3_000).unwrap_err().kind(), "replay");

    // Re-genesis: the root certifies version 2; the node accepts the snapshot at the lower epoch.
    let now = T0 + 20_000;
    let v2 = cert(&cp.root, &cp.feed_key, 2, T0 + 86_400_000);
    cp.p.rotate(&cp.root.verifying_key(), cp.feed_key.clone(), &v2).unwrap();
    let frames = cp.p.catch_up(&r.hello(), now).unwrap();
    assert_eq!(frames.iter().map(|f| f.kind).collect::<Vec<_>>(), [FrameKind::Key, FrameKind::Snap, FrameKind::Fresh]);
    feed(&mut r, frames, now);
    assert_eq!(r.state().unwrap().epoch, 4);
    assert_eq!(r.state().unwrap().version, 2);
    assert_eq!(r.mode(now), Mode::Fresh);
    assert!(r.state().unwrap().grants.contains_key("after-restore"));
    assert!(!r.state().unwrap().grants.contains_key("late-2"));
    // Artifacts of the old generation are refused now, even validly signed ones.
    assert_eq!(r.accept(&d4, now).unwrap_err().kind(), "wrong_version");
    assert_eq!(r.accept(&last, now).unwrap_err().kind(), "wrong_version");
    let old_cert = cp.cert.clone();
    assert_eq!(r.accept(&Frame::new(FrameKind::Key, old_cert), now).unwrap_err().kind(), "key_rollback");
    // And the new generation carries on with deltas.
    let d = cp.p.commit(vec![add(grant("v2-a", &read(), T0 + 3_600_000))], now + 1).unwrap();
    r.accept(&d, now + 2).unwrap();
    let frames = cp.p.catch_up(&r.hello(), now + 3).unwrap();
    assert_eq!(frames.iter().map(|f| f.kind).collect::<Vec<_>>(), [FrameKind::Key, FrameKind::Fresh], "on the chain: no deltas to send");
    feed(&mut r, frames, now + 3);
    assert_eq!(r.mode(now + 4), Mode::Fresh);
}
