//! Host matching (`manifest::host_matches`) and covering (`subset::host_covers`): Wicket/Host.lean.

use super::host_covers;
use crate::manifest::host_matches;
use crate::proofs::AnyStr;

/// Letters of both cases, the label separator and the wildcard: enough to spell `*.a`, `A.a.`,
/// `*.*`, `a..`.
const HOST: &[u8] = b"aA.*";

/// `hostCovers_sound`: if `host_covers(parent, child)` and the child pattern matches a host, the
/// parent pattern matches it too. Whatever a child zone's host names, its parent's does.
#[kani::proof]
#[kani::unwind(7)]
fn host_covers_sound() {
    let parent = AnyStr::<4>::new(HOST);
    let child = AnyStr::<4>::new(HOST);
    let host = AnyStr::<5>::new(HOST);
    if host_covers(parent.as_str(), child.as_str()) && host_matches(child.as_str(), host.as_str()) {
        assert!(host_matches(parent.as_str(), host.as_str()));
    }
}

/// `*.x` never matches `x` itself, nor `x.` or `.x`... only names with at least one more label
/// (the doc comment of `host_matches`); with `hostCovers_sound`, a wildcard child never widens to
/// the apex. (Wicket/Host.lean's `hostMatches` definition; no separate theorem.)
#[kani::proof]
#[kani::unwind(7)]
fn wildcard_never_matches_its_apex() {
    let p = AnyStr::<5>::new(HOST);
    let b = p.bytes();
    kani::assume(b.len() >= 2 && b[0] == b'*' && b[1] == b'.');
    let suffix = &p.as_str()[2..];
    assert!(!host_matches(p.as_str(), suffix));
    // `.x` is the apex with an empty label in front: one byte too short to be under it.
    assert!(!host_matches(p.as_str(), &p.as_str()[1..]));
}

/// Matching ignores ASCII case and a trailing dot on the host (`lowerS`, `trimDots` in
/// Wicket/Host.lean, whose `trim_lower_trim` shows the normal form is stable).
#[kani::proof]
#[kani::unwind(7)]
fn matching_ignores_case_and_trailing_dots() {
    let pattern = AnyStr::<3>::new(HOST);
    let host = AnyStr::<4>::new(HOST);
    let mut upper = [0u8; 4];
    let mut dotted = [b'.'; 5];
    let mut i = 0;
    while i < host.bytes().len() {
        upper[i] = host.bytes()[i].to_ascii_uppercase();
        dotted[i] = host.bytes()[i];
        i += 1;
    }
    let n = host.bytes().len();
    // SAFETY: ASCII in, ASCII out.
    let (upper, dotted) = unsafe { (std::str::from_utf8_unchecked(&upper[..n]), std::str::from_utf8_unchecked(&dotted[..n + 1])) };
    let m = host_matches(pattern.as_str(), host.as_str());
    assert_eq!(host_matches(pattern.as_str(), upper), m);
    assert_eq!(host_matches(pattern.as_str(), dotted), m);
}
