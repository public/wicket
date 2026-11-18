//! An approval's blast radius (`effect`, #369): which terms widen what was asked. #322's Lean spec
//! has no counterpart. Over every number of uses and lifetime, either scope, and with or without a
//! prefix. On `terms_widen`, the decision `Effect::widens` makes on those parts (it reads the
//! scope as `scope == "zone"`), not on a whole `Effect` with its strings: this harness or
//! `accept_from`'s ran a CI shard past its hour when they were first written.

use super::{terms_widen, WIDE_TTL_SECS};

/// `Effect::widens`: an approval doesn't widen exactly when it grants one use, for at most an
/// hour, to the asking run alone, for the asked path only; and so each of a prefix, any other
/// number of uses (unlimited included), a longer lifetime, and the whole zone widens it on its
/// own. A request only asked for (no terms) widens only by a prefix.
#[kani::proof]
fn an_approval_widens_unless_it_is_one_use_for_an_hour_for_the_run() {
    let prefix: bool = kani::any();
    let terms: Option<(Option<u32>, u64, bool)> = kani::any();
    let narrow = !prefix
        && match terms {
            None => true,
            Some((uses, ttl, zone)) => uses == Some(1) && ttl <= WIDE_TTL_SECS && !zone,
        };
    assert_eq!(terms_widen(prefix, terms), !narrow);
}
