//! A zone's consent and model lists (`manifest`): `accept_from` (#250, #411) and
//! `zone.llm.models` (#366). #322's Lean spec has no counterpart. Short strings: list entries and
//! senders chosen from a few concrete names (zones `a` and `b`, principals `x://a` and `x://b`,
//! and a principal id `a` like a zone's name); model names and patterns over `a`, `b` and `*`.

use super::{accepts, is_principal_entry, model_covers};
use crate::proofs::AnyStr;

/// Lists are windows of [`POOL`]: its windows of two hold two zones, two principals, and each mix.
/// Plain `&str`s, no heap: with `String`s (symbolically chosen, then a fixed pool of them) its
/// shard first ran past its hour, then was stopped after 11 minutes (exit 143).
const POOL: [&str; 6] = ["x://a", "x://b", "a", "b", "x://a", "a"];

/// A window of [`POOL`] of up to two entries, and the same window with the pool's next entry.
fn any_list() -> (&'static [&'static str], &'static [&'static str]) {
    let start: usize = kani::any_where(|&s| s < POOL.len());
    let len: usize = kani::any_where(|&l| l <= 2 && start + l < POOL.len());
    (&POOL[start..start + len], &POOL[start..start + len + 1])
}

fn any_zone() -> &'static str {
    if kani::any() {
        "a"
    } else {
        "b"
    }
}

fn any_principal() -> Option<&'static str> {
    [None, Some("a"), Some("x://a"), Some("x://b")][kani::any_where(|&i: &usize| i < 4)]
}

/// `accepts`: an `accept_from` list lets a sender in exactly when one entry names it, a zone entry
/// by the sender's zone and a principal entry by its principal id; an empty list refuses everyone,
/// and an entry added never refuses a sender let in before.
#[kani::proof]
#[kani::unwind(6)]
fn accept_from_lets_in_exactly_whom_it_names() {
    let (list, more) = any_list();
    let (zone, principal) = (any_zone(), any_principal());
    let got = accepts(list, zone, principal);
    let named = list.iter().any(|e| if is_principal_entry(e) { principal == Some(*e) } else { *e == zone });
    assert_eq!(got, named);
    assert!(!list.is_empty() || !got);
    assert!(!got || accepts(more, zone, principal));
}

/// The two kinds never cross (#250): a list of principal entries ignores the sender's zone and
/// refuses a sender whose principal isn't known; a list of zone entries ignores the principal.
#[kani::proof]
#[kani::unwind(6)]
fn accept_from_never_crosses_zones_and_principals() {
    let (list, _) = any_list();
    let (zone, other_zone) = (any_zone(), any_zone());
    let (principal, other_principal) = (any_principal(), any_principal());
    if list.iter().all(|e| is_principal_entry(e)) {
        assert_eq!(accepts(list, zone, principal), accepts(list, other_zone, principal));
        assert!(!accepts(list, zone, None));
    }
    if list.iter().all(|e| !is_principal_entry(e)) {
        assert_eq!(accepts(list, zone, principal), accepts(list, zone, other_principal));
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
