//! Which hosts the egress proxy inspects (`splice`, #62): `patterns_overlap` keeps a host inspected
//! when a forbid rule, an injection or the model route could name it. #322's Lean spec has no
//! counterpart. Patterns and hosts of up to five bytes over `a`, `b`, `.` and `*` (so `*.a.b`,
//! `a.b.`, `*.*` and the like), held by value.

use super::patterns_overlap;
use crate::manifest::host_matches;
use crate::proofs::AnyStr;

const PAT: &[u8] = b"ab.*";
const HOST: &[u8] = b"ab.";

/// Sound, as `inspection` needs it: if some host matches both patterns, they overlap, so a host a
/// forbid rule could name is never spliced; and the relation is symmetric. Against an exact host
/// it is exactly matching for a pattern without a trailing dot, and wider for one with one: the
/// overlap trims a pattern's trailing dots, matching doesn't (so `a.` overlaps `a`, which it
/// doesn't match; the safe side, inspecting more).
#[kani::proof]
#[kani::unwind(7)]
fn patterns_that_share_a_host_overlap() {
    let (a, b) = (AnyStr::<5>::new(PAT), AnyStr::<5>::new(PAT));
    let host = AnyStr::<5>::new(HOST);
    let overlap = patterns_overlap(a.as_str(), b.as_str());
    if host_matches(a.as_str(), host.as_str()) && host_matches(b.as_str(), host.as_str()) {
        assert!(overlap);
    }
    assert_eq!(overlap, patterns_overlap(b.as_str(), a.as_str()));
    let matches = host_matches(a.as_str(), host.as_str());
    let with_host = patterns_overlap(a.as_str(), host.as_str());
    if a.bytes().last() != Some(&b'.') {
        assert_eq!(with_host, matches);
    } else {
        assert!(with_host || !matches);
    }
}
