//! An approval's blast radius (`effect`, #369): which terms widen what was asked. #322's Lean spec
//! has no counterpart. Over every number of uses and lifetime, either scope, and with or without a
//! prefix; the descriptor's other fields don't take part.

use super::{Effect, Terms, WIDE_TTL_SECS};

/// `Effect::widens`: an approval doesn't widen exactly when it grants one use, for at most an
/// hour, to the asking run alone, for the asked path only; and so each of a prefix, any other
/// number of uses (unlimited included), a longer lifetime, and the whole zone widens it on its
/// own. A request only asked for (no terms) widens only by a prefix.
#[kani::proof]
fn an_approval_widens_unless_it_is_one_use_for_an_hour_for_the_run() {
    let terms = if kani::any() {
        let zone: bool = kani::any();
        Some(Terms { uses: kani::any(), ttl_secs: kani::any(), scope: if zone { "zone".into() } else { "run".into() } })
    } else {
        None
    };
    let e = Effect {
        v: 1,
        kind: String::new(),
        tenant: String::new(),
        zone: String::new(),
        run: String::new(),
        requested_by: Vec::new(),
        method: String::new(),
        host: String::new(),
        path: String::new(),
        prefix: kani::any(),
        risk: String::new(),
        args_sha256: None,
        terms,
    };
    let narrow = !e.prefix
        && match &e.terms {
            None => true,
            Some(t) => t.uses == Some(1) && t.ttl_secs <= WIDE_TTL_SECS && t.scope == "run",
        };
    assert_eq!(e.widens(), !narrow);
}
