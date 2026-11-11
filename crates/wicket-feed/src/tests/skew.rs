//! The clock-skew guard: a node's freshness never lasts longer, on its own clock, than the signed TTL.

use super::*;

fn fresh_cp() -> Cp {
    let mut cp = Cp::new();
    cp.p.commit(vec![Change::PutZone { zone: zone("z") }], T0).unwrap();
    cp
}

#[test]
fn a_node_clock_behind_the_control_plane_cannot_stretch_freshness() {
    let mut cp = fresh_cp();
    let mut r = cp.replica();
    // Signed at T0 + 1000 by the control plane; the node's clock reads 1.5 s less on receipt.
    let frames = cp.p.catch_up(&r.hello(), T0 + 1_000).unwrap();
    let receipt = T0 - 500;
    feed(&mut r, frames, receipt);
    let f = r.last_statement().unwrap().clone();
    assert_eq!((f.fresh_until, f.narrow_until), (T0 + 1_000 + TTL, T0 + 1_000 + TTL + WINDOW));
    // Effective deadlines count from receipt, on the node's clock.
    assert_eq!(r.deadlines().unwrap(), (receipt + TTL, receipt + TTL + WINDOW));
    assert_eq!(r.mode(receipt + TTL - 1), Mode::Fresh);
    assert_eq!(r.mode(receipt + TTL), Mode::Narrow, "not at the signed fresh_until, 1.5 s later");
    assert_eq!(r.mode(receipt + TTL + WINDOW), Mode::Closed);
}

#[test]
fn a_statement_from_beyond_the_tolerance_is_refused() {
    let mut cp = fresh_cp();
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&r.hello(), T0 + 5_000).unwrap();
    let (key, snap, fresh) = (&frames[0], &frames[1], &frames[2]);
    r.accept(key, T0).unwrap();
    r.accept(snap, T0).unwrap();
    assert_eq!(r.accept(fresh, T0).unwrap_err().kind(), "from_future", "node 5 s behind");
    assert_eq!(r.mode(T0), Mode::Closed);
    // Just within the tolerance is accepted (and capped as above).
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&r.hello(), T0 + 6_000).unwrap();
    feed(&mut r, frames, T0 + 6_000 - DEFAULT_FUTURE_TOLERANCE_MS);
    assert_eq!(r.mode(T0 + 6_000 - DEFAULT_FUTURE_TOLERANCE_MS), Mode::Fresh);
}

#[test]
fn delivery_delay_or_a_node_clock_ahead_keeps_the_signed_deadline() {
    let mut cp = fresh_cp();
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&r.hello(), T0).unwrap();
    feed(&mut r, frames, T0 + 800);
    assert_eq!(r.deadlines().unwrap(), (T0 + TTL, T0 + TTL + WINDOW));
    assert_eq!(r.mode(T0 + TTL), Mode::Narrow);
}
