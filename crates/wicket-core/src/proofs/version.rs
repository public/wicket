//! Protocol skew and the schema floor (`version`). #322's Lean spec has no counterpart: these are
//! stated here, over every `u32`.

use super::{is_jump, schema_opens, schema_recorded, talk_at};

/// Two peers talk exactly when the other has a version and they are at most the skew apart, and
/// then at the lower version: never one either peer doesn't speak, nor more than the skew below
/// either. No input panics or overflows.
#[kani::proof]
fn peers_talk_within_the_skew_at_the_lower_version() {
    let (ours, theirs, skew): (u32, u32, u32) = kani::any();
    match talk_at(ours, theirs, skew) {
        Some(v) => {
            assert!(theirs != 0);
            assert!(v <= ours && v <= theirs && (v == ours || v == theirs));
            assert!(ours - v <= skew && theirs - v <= skew);
        }
        None => {
            assert!(theirs == 0 || ours.abs_diff(theirs) > skew);
        }
    }
}

/// The handshake is symmetric: whichever side runs it, two versioned peers agree on whether they
/// talk and at what; and a jump is exactly a pair that can't.
#[kani::proof]
fn negotiation_is_symmetric_and_a_jump_is_what_cant_talk() {
    let (a, b, skew): (u32, u32, u32) = kani::any();
    kani::assume(a != 0 && b != 0);
    assert_eq!(talk_at(a, b, skew), talk_at(b, a, skew));
    assert_eq!(is_jump(a, b, skew), talk_at(a, b, skew).is_none());
}

/// A feature introduced at protocol `f` is used on a connection only if both peers speak it: if a
/// connection talks at `v >= f`, both peers are at `f` or later.
#[kani::proof]
fn a_feature_is_used_only_if_both_peers_have_it() {
    let (ours, theirs, skew, f): (u32, u32, u32, u32) = kani::any();
    if let Some(v) = talk_at(ours, theirs, skew) {
        if v >= f {
            assert!(ours >= f && theirs >= f);
        }
    }
}

/// The schema floor only rises: after up to three builds open a ledger (each whose own floor is at
/// most its version), the recorded version and floor never went down, and a later build opens it
/// only if its schema is at least the floor of every build that opened it before.
#[kani::proof]
fn the_schema_floor_only_rises() {
    let mut at: (u32, u32) = kani::any();
    let builds: [(u32, u32); 3] = kani::any();
    let mut highest_floor = 0;
    for b in builds {
        kani::assume(b.1 <= b.0);
        if !schema_opens(b.0, at.1) {
            continue;
        }
        let next = schema_recorded(at, b);
        assert!(next.0 >= at.0 && next.1 >= at.1);
        highest_floor = highest_floor.max(b.1);
        at = next;
    }
    let later: u32 = kani::any();
    if schema_opens(later, at.1) {
        assert!(later >= highest_floor);
    }
}
