//! Image pins (`image`, #192): which allowed entry lets a box start a wanted image, and the digest
//! it must then have. #322's Lean spec has no counterpart. On `entry_allows`, `matching`'s rule for
//! an entry over parsed names and pins: names of up to four bytes over `a`, `b`, `:` and `/` (so
//! `a:b`, `a/b:a` and other repositories and tags), and pins `x` or `y` standing for two digests.
//! (A digest's 71 bytes, and `parse`'s strings, are the unit tests' and the Lean oracle's.)

use super::entry_allows;
use crate::proofs::AnyStr;

const NAME: &[u8] = b"ab:/";

fn any_pin() -> Option<&'static str> {
    [None, Some("x"), Some("y")][kani::any_where(|&i: &usize| i < 3)]
}

/// A pin is never allowed by a tag entry, and a pinned image is allowed only by its own digest; a
/// tag is allowed (here) only by a pin for its repository, and then must be that digest; two
/// named images are never matched across repositories.
#[kani::proof]
#[kani::unwind(6)]
fn a_pin_is_allowed_only_by_its_own_digest() {
    let (w_name, a_name) = (AnyStr::<4>::new(NAME), AnyStr::<4>::new(NAME));
    let (w_pin, a_pin) = (any_pin(), any_pin());
    let got = entry_allows(w_name.as_str(), w_pin, a_name.as_str(), a_pin);
    if a_pin.is_none() {
        assert!(got.is_none());
    }
    if let Some(d) = got {
        assert_eq!(Some(d), a_pin);
        if w_pin.is_some() {
            assert_eq!(Some(d), w_pin);
        } else {
            assert!(!a_name.bytes().is_empty());
        }
        if !w_name.bytes().is_empty() && !a_name.bytes().is_empty() {
            assert_eq!(super::repository(w_name.as_str()), super::repository(a_name.as_str()));
        }
    }
}
