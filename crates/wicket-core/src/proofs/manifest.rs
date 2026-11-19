//! A zone's consent and model lists (`manifest`): `accept_from` (#250, #411) and
//! `zone.llm.models` (#366). #322's Lean spec has no counterpart. Short strings: list entries and
//! senders chosen from a few names of five bytes, held by value (zones `zonea` and `zoneb`,
//! principals `x://a` and `x://b`, and a principal id `zonea` spelt like a zone); model names and
//! patterns over `a`, `b` and `*`.

use super::{accepts, is_principal_entry, model_covers};
use crate::proofs::AnyStr;

/// A name of five bytes, held by value: zones `zonea` and `zoneb`, principals `x://a` and `x://b`.
/// By value, not as a `&'static str` chosen among several, so no read goes through a pointer
/// that could be any of them. (Chosen as `&str`s, of five bytes or of mixed lengths, the
/// accept_from harnesses took 49-294 s.)
#[derive(Clone, Copy)]
struct Name([u8; 5]);

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        // SAFETY: every byte is one of the ASCII names' below.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

const ZONEA: [u8; 5] = *b"zonea";
const ZONEB: [u8; 5] = *b"zoneb";
const PA: [u8; 5] = *b"x://a";
const PB: [u8; 5] = *b"x://b";

fn any_of(names: &[[u8; 5]]) -> Name {
    Name(names[kani::any_where(|&i: &usize| i < names.len())])
}

fn any_zone() -> Name {
    any_of(&[ZONEA, ZONEB])
}

/// Any entry: a zone or a principal.
fn any_entry() -> Name {
    any_of(&[ZONEA, ZONEB, PA, PB])
}

/// A sender's principal id, if known: one of the principals, or `zonea`, an id spelt like a zone.
fn any_principal() -> Option<Name> {
    if kani::any() {
        Some(any_of(&[PA, PB, ZONEA]))
    } else {
        None
    }
}

fn id(p: &Option<Name>) -> Option<&str> {
    p.as_ref().map(AsRef::as_ref)
}

/// `accepts`: an `accept_from` list (up to two entries of either kind) lets a sender in exactly
/// when one entry names it, a zone entry by the sender's zone and a principal entry by its
/// principal id; an empty list refuses everyone, and an entry added never refuses a sender let in
/// before. (Unwound 7: a five-byte compare, and lists of three.)
#[kani::proof]
#[kani::unwind(7)]
fn accept_from_lets_in_exactly_whom_it_names() {
    let entries = [any_entry(), any_entry(), any_entry()];
    let len: usize = kani::any_where(|&l| l <= 2);
    let (list, more) = (&entries[..len], &entries[..len + 1]);
    let (zone, principal) = (any_zone(), any_principal());
    let got = accepts(list, zone.as_ref(), id(&principal));
    let named = list.iter().any(|e| if is_principal_entry(e.as_ref()) { principal.is_some_and(|p| p.0 == e.0) } else { e.0 == zone.0 });
    assert_eq!(got, named);
    assert!(!list.is_empty() || !got);
    assert!(!got || accepts(more, zone.as_ref(), id(&principal)));
}

/// The two kinds never cross (#250), one: a list of principal entries ignores the sender's zone,
/// and refuses a sender whose principal isn't known.
#[kani::proof]
#[kani::unwind(7)]
fn a_principal_list_ignores_the_senders_zone() {
    let entries = [any_of(&[PA, PB]), any_of(&[PA, PB])];
    let list = &entries[..kani::any_where(|&l: &usize| l <= 2)];
    let principal = any_principal();
    assert_eq!(accepts(list, "zonea", id(&principal)), accepts(list, "zoneb", id(&principal)));
    assert!(!accepts(list, any_zone().as_ref(), None));
}

/// And two: a list of zone entries ignores the sender's principal, known or not.
#[kani::proof]
#[kani::unwind(7)]
fn a_zone_list_ignores_the_senders_principal() {
    let entries = [any_zone(), any_zone()];
    let list = &entries[..kani::any_where(|&l: &usize| l <= 2)];
    let (zone, principal) = (any_zone(), any_principal());
    assert_eq!(accepts(list, zone.as_ref(), id(&principal)), accepts(list, zone.as_ref(), None));
}

/// The message rule (#565), `message::relation`: family first, then `accept_from`, then a reply. A
/// peer is accepted exactly when `accepts` lets it in (so exactly when an entry names its zone or
/// principal, `accept_from_lets_in_exactly_whom_it_names`); refused exactly when it is none of the
/// four; and a side that doesn't know the sender's principal (a node cut off from the control host)
/// refuses whatever one that knows it refuses. Lean: `peer_iff`, `refused_iff` and
/// `less_known_allows_no_more` (`Wicket/Message.lean`).
#[kani::proof]
#[kani::unwind(7)]
fn a_message_goes_as_one_relation_wherever_decided() {
    use crate::message::{relation, Facts, Relation};
    let entries = [any_entry(), any_entry()];
    let list = &entries[..kani::any_where(|&l: &usize| l <= 2)];
    let (zone, principal) = (any_zone(), any_principal());
    let (to_child, to_parent, reply) = (kani::any(), kani::any(), kani::any());
    let f = Facts { to_child, to_parent, accept_from: list, sender_zone: zone.as_ref(), sender: id(&principal), reply };
    let got = relation(&f);
    let named = accepts(list, zone.as_ref(), id(&principal));
    assert_eq!(got == Some(Relation::Peer), !to_child && !to_parent && named);
    assert_eq!(got.is_none(), !to_child && !to_parent && !named && !reply);
    let unknown = relation(&Facts { sender: None, ..f });
    assert!(unknown.is_none() || got.is_some());
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
