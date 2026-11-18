//! A zone's consent and model lists (`manifest`): `accept_from` (#250, #411) and
//! `zone.llm.models` (#366). #322's Lean spec has no counterpart. Short strings: list entries and
//! senders chosen from a few concrete names of five bytes each (zones `zonea` and `zoneb`,
//! principals `x://a` and `x://b`, and a principal id `zonea` spelt like a zone); model names and
//! patterns over `a`, `b` and `*`.

use super::{accepts, is_principal_entry, model_covers};
use crate::proofs::AnyStr;

// Every name is five bytes, so comparing two is a fixed-length compare: zones `zonea` and `zoneb`,
// principals `x://a` and `x://b`. (With names of different lengths, chosen symbolically, the
// accept_from harnesses took up to 294 s.) Unwound 7: a five-byte compare, and lists of three.
const ZONES: [&str; 2] = ["zonea", "zoneb"];
const PRINCIPALS: [&str; 2] = ["x://a", "x://b"];

fn any_zone() -> &'static str {
    ZONES[usize::from(kani::any::<bool>())]
}

/// A sender's principal id, if known: one of the principals, or `zonea`, an id spelt like a zone.
fn any_principal() -> Option<&'static str> {
    [None, Some("x://a"), Some("x://b"), Some("zonea")][kani::any_where(|&i: &usize| i < 4)]
}

/// Any entry: a zone or a principal.
fn any_entry() -> &'static str {
    if kani::any() {
        any_zone()
    } else {
        PRINCIPALS[usize::from(kani::any::<bool>())]
    }
}

/// `accepts`: an `accept_from` list (up to two entries of either kind) lets a sender in exactly
/// when one entry names it, a zone entry by the sender's zone and a principal entry by its
/// principal id; an empty list refuses everyone, and an entry added never refuses a sender let in
/// before.
#[kani::proof]
#[kani::unwind(7)]
fn accept_from_lets_in_exactly_whom_it_names() {
    let entries = [any_entry(), any_entry(), any_entry()];
    let len: usize = kani::any_where(|&l| l <= 2);
    let (list, more) = (&entries[..len], &entries[..len + 1]);
    let (zone, principal) = (any_zone(), any_principal());
    let got = accepts(list, zone, principal);
    let named = list.iter().any(|e| if is_principal_entry(e) { principal == Some(*e) } else { *e == zone });
    assert_eq!(got, named);
    assert!(!list.is_empty() || !got);
    assert!(!got || accepts(more, zone, principal));
}

/// The two kinds never cross (#250), one: a list of principal entries ignores the sender's zone,
/// and refuses a sender whose principal isn't known.
#[kani::proof]
#[kani::unwind(7)]
fn a_principal_list_ignores_the_senders_zone() {
    let entries = [PRINCIPALS[usize::from(kani::any::<bool>())], PRINCIPALS[usize::from(kani::any::<bool>())]];
    let list = &entries[..kani::any_where(|&l: &usize| l <= 2)];
    let principal = any_principal();
    assert_eq!(accepts(list, ZONES[0], principal), accepts(list, ZONES[1], principal));
    assert!(!accepts(list, any_zone(), None));
}

/// And two: a list of zone entries ignores the sender's principal, known or not.
#[kani::proof]
#[kani::unwind(7)]
fn a_zone_list_ignores_the_senders_principal() {
    let entries = [any_zone(), any_zone()];
    let list = &entries[..kani::any_where(|&l: &usize| l <= 2)];
    let zone = any_zone();
    assert_eq!(accepts(list, zone, any_principal()), accepts(list, zone, None));
}

/// Whether a model pattern is one `check_models` lets a zone list: not empty, and a `*` only as
/// its last byte.
fn valid_pattern(p: &[u8]) -> bool {
    let mut ok = !p.is_empty();
    let mut i = 0;
    while i + 1 < p.len() {
        ok &= p[i] != b'*';
        i += 1;
    }
    ok
}

/// `model_covers`, over the patterns `check_models` accepts: a pattern without `*` covers only
/// itself; and a pattern covering another covers every model that one covers, so a child zone's
/// list a parent's covers (`subset::model_violations`) lets in no model the parent's refuses.
/// (With a `*` inside a pattern this fails: `a**` covers `a*`, which covers `ab`, but `a**`
/// doesn't. `check_models` refuses such patterns.)
#[kani::proof]
#[kani::unwind(5)]
fn a_covered_model_pattern_lets_in_nothing_more() {
    let (p, q) = (AnyStr::<3>::new(b"ab*"), AnyStr::<3>::new(b"ab*"));
    let name = AnyStr::<3>::new(b"ab");
    kani::assume(valid_pattern(p.bytes()) && valid_pattern(q.bytes()));
    if !p.bytes().contains(&b'*') {
        assert_eq!(model_covers(p.as_str(), q.as_str()), p.bytes() == q.bytes());
        assert_eq!(model_covers(p.as_str(), name.as_str()), p.bytes() == name.bytes());
    }
    if model_covers(p.as_str(), q.as_str()) && model_covers(q.as_str(), name.as_str()) {
        assert!(model_covers(p.as_str(), name.as_str()));
    }
}
