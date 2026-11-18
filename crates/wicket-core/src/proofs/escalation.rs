//! When a refused request may be asked for (`escalation`): `wicket-authz`'s structural check
//! classes each token check, and its decision turns the failed checks into `NeedsGrant` or
//! `Forbidden` with these. #322's Lean spec has no counterpart: its `needsGrant` is a zone's
//! verdict (Wicket/Zone.lean), not a token's. Over every class and lists of up to four failed
//! checks.

use super::{check_escalatable, needs_grant, Failed};

/// A check that reads the org policy is never escalatable, whatever else it reads; nor is one
/// that must hold for all its alternatives, or one that reads nothing a grant names.
#[kani::proof]
fn an_org_policy_check_is_never_escalatable() {
    let (one, policy, host, risk, approved): (bool, bool, bool, bool, bool) = kani::any();
    let e = check_escalatable(one, policy, host, risk, approved);
    assert_eq!(e, one && !policy && (host || risk || approved));
    if policy || !one {
        assert!(!e);
    }
}

/// Fail-closed, as `Loaded::classify` counts them: a refusal needs a grant exactly when it failed
/// at least one check and every check it failed is a token check known to be escalatable. One
/// node check, one hard check, or one check of unknown class forbids; so does a refusal naming
/// no check.
#[kani::proof]
#[kani::unwind(6)]
fn a_refusal_needs_a_grant_only_if_every_failure_is_escalatable() {
    let all: [Failed; 4] = [any_failed(), any_failed(), any_failed(), any_failed()];
    let failed = &all[..kani::any_where(|&n: &usize| n <= 4)];
    let soft = failed.iter().filter(|f| f.soft()).count();
    let got = needs_grant(failed.len() - soft, soft);
    let every_known_escalatable = failed.iter().all(|f| *f == Failed::Block(Some(true)));
    assert_eq!(got, !failed.is_empty() && every_known_escalatable);
}

fn any_failed() -> Failed {
    match kani::any_where(|&i: &u8| i < 4) {
        0 => Failed::Node,
        1 => Failed::Block(None),
        2 => Failed::Block(Some(false)),
        _ => Failed::Block(Some(true)),
    }
}
