//! Host matching (`manifest::host_matches`) and covering (`subset::host_covers`): Wicket/Host.lean.

use super::host_covers;
use crate::manifest::host_matches;
use crate::proofs::any_str;

/// Letters of both cases, the label separator and the wildcard: enough to spell `*.a`, `A.a.`,
/// `*.*`, `a..`.
const HOST: &[u8] = b"aA.*";

/// `hostCovers_sound`: if `host_covers(parent, child)` and the child pattern matches a host, the
/// parent pattern matches it too. Whatever a child zone's host names, its parent's does.
#[kani::proof]
#[kani::unwind(7)]
fn host_covers_sound() {
    let parent = any_str::<4>(HOST);
    let child = any_str::<4>(HOST);
    let host = any_str::<5>(HOST);
    if host_covers(&parent, &child) && host_matches(&child, &host) {
        assert!(host_matches(&parent, &host));
    }
}

/// `*.x` never matches `x` itself, only names with at least one more label (the doc comment of
/// `host_matches`); with `hostCovers_sound`, a wildcard child never widens to the apex.
#[kani::proof]
#[kani::unwind(7)]
fn wildcard_never_matches_its_apex() {
    let suffix = any_str::<3>(HOST);
    let pattern = format!("*.{suffix}");
    assert!(!host_matches(&pattern, &suffix));
    assert!(!host_matches(&pattern, &format!(".{suffix}")));
}
