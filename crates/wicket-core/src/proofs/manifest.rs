//! A zone's consent and model lists (`manifest`): `accept_from` (#250, #411) and
//! `zone.llm.models` (#366). #322's Lean spec has no counterpart. Short strings: list entries and
//! senders chosen from a few concrete names, so a zone and a principal can look alike; model
//! names and patterns over `a`, `b` and `*`.

use super::{accepts, is_principal_entry, model_covers};
use crate::proofs::AnyStr;

/// Zones, principals and things like both: an entry or a sender is one of these.
const NAMES: [&str; 4] = ["a", "b", "x://a", "x://b"];

fn any_name() -> &'static str {
    NAMES[kani::any_where(|&i: &usize| i < NAMES.len())]
}

/// `accepts`: an `accept_from` list lets a sender in exactly when one entry names it, a zone entry
/// by the sender's zone and a principal entry by its principal id, the two kinds never crossing
/// (#250): a list of principal entries ignores the sender's zone and refuses a sender whose
/// principal isn't known; a list of zone entries ignores the principal. An empty list refuses
/// everyone, and an entry added never refuses a sender let in before. (Unwound 9: the substring
/// search of `is_principal_entry` over a name of five bytes, and lists of up to three.)
#[kani::proof]
#[kani::unwind(9)]
fn accept_from_names_a_zone_or_a_principal_never_crossing() {
    let len: usize = kani::any_where(|&l| l <= 2);
    let list: Vec<String> = (0..len).map(|_| any_name().to_string()).collect();
    let (zone, other_zone) = (any_name(), any_name());
    kani::assume(!is_principal_entry(zone) && !is_principal_entry(other_zone));
    let principal: Option<&str> = if kani::any() { Some(any_name()) } else { None };
    let other_principal: Option<&str> = if kani::any() { Some(any_name()) } else { None };
    let got = accepts(&list, zone, principal);
    let named = list.iter().any(|e| if is_principal_entry(e) { principal == Some(e.as_str()) } else { e == zone });
    assert_eq!(got, named);
    if list.is_empty() {
        assert!(!got);
    }
    if list.iter().all(|e| is_principal_entry(e)) {
        assert_eq!(got, accepts(&list, other_zone, principal));
        assert!(!accepts(&list, zone, None));
    }
    if list.iter().all(|e| !is_principal_entry(e)) {
        assert_eq!(got, accepts(&list, zone, other_principal));
    }
    let mut more = list.clone();
    more.push(any_name().to_string());
    if got {
        assert!(accepts(&more, zone, principal));
    }
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
