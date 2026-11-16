//! The decision once matching is done (`op::decide`, what `CompiledZone::evaluate` returns):
//! Wicket/Zone.lean's `evaluate`. Matching itself (globset, hosts) is abstracted to one bool per
//! rule here; host matching is checked in `proofs/host.rs`, and the glob semantics by #322's oracle.

use super::{decide, Decision};
use crate::op::RiskClass;

/// Up to this many reach rules: enough for a matching rule before, between and after others.
const RULES: usize = 3;

fn any_risk() -> RiskClass {
    use RiskClass::*;
    match kani::any::<u8>() % 5 {
        0 => R0Read,
        1 => R1ReadScoped,
        2 => R2WriteReversible,
        3 => R3ExternalOrIrreversible,
        _ => R4ExecOrPrivilege,
    }
}

/// Rules as `(matches, allow_dangerous)`, of a symbolic count up to [`RULES`].
fn any_rules() -> ([(bool, bool); RULES], usize) {
    (kani::any(), kani::any_where(|&n: &usize| n <= RULES))
}

fn allows(rule: (bool, bool), risk: RiskClass) -> bool {
    rule.0 && (risk < RiskClass::R3ExternalOrIrreversible || rule.1)
}

/// `forbid_wins`: a request any forbid rule matches is forbidden, whatever the reach rules say;
/// and (forbid before reach) no reach rule is even looked at.
#[kani::proof]
#[kani::unwind(5)]
fn forbid_wins() {
    let (rules, n) = any_rules();
    let mut looked = false;
    let reach = rules[..n].iter().map(|&r| {
        looked = true;
        r
    });
    assert_eq!(decide(|| true, any_risk(), reach), Decision::Forbidden);
    assert!(!looked);
}

/// `allow_iff` (and with it `allow_not_forbidden`): allowed by reach exactly when no forbid rule
/// matches and some reach rule allows the op; and the rule named is the first that does.
#[kani::proof]
#[kani::unwind(5)]
fn allow_iff() {
    let (rules, n) = any_rules();
    let (forbidden, risk): (bool, RiskClass) = (kani::any(), any_risk());
    let rules = &rules[..n];
    let some_allows = rules.iter().any(|&r| allows(r, risk));
    let d = decide(|| forbidden, risk, rules.iter().copied());
    assert_eq!(matches!(d, Decision::AllowByReach(_)), !forbidden && some_allows);
    match d {
        Decision::AllowByReach(i) => {
            assert!(allows(rules[i], risk));
            assert!(!rules[..i].iter().any(|&r| allows(r, risk)));
        }
        Decision::NeedsGrant(Some(i)) => {
            // Named: the first rule that matched, which doesn't allow this risk.
            assert!(rules[i].0 && !allows(rules[i], risk) && !rules[..i].iter().any(|r| r.0));
        }
        Decision::NeedsGrant(None) => {
            assert!(!rules.iter().any(|r| r.0));
        }
        Decision::Forbidden => {
            assert!(forbidden);
        }
    }
}

/// `evaluate_reach_set`: reach rules are a set; reordering or repeating them doesn't change the
/// decision (which rule a verdict names aside). Stated for any two rule lists with the same
/// members.
#[kani::proof]
#[kani::unwind(5)]
fn evaluate_reach_set() {
    let (a, na) = any_rules();
    let (b, nb) = any_rules();
    let (a, b) = (&a[..na], &b[..nb]);
    kani::assume(a.iter().all(|r| b.contains(r)) && b.iter().all(|r| a.contains(r)));
    let (forbidden, risk): (bool, RiskClass) = (kani::any(), any_risk());
    let kind = |d: Decision| match d {
        Decision::Forbidden => 0,
        Decision::AllowByReach(_) => 1,
        Decision::NeedsGrant(_) => 2,
    };
    assert_eq!(kind(decide(|| forbidden, risk, a.iter().copied())), kind(decide(|| forbidden, risk, b.iter().copied())));
}

/// `allow_lower_risk`: allowed at a risk, allowed at any lower one.
#[kani::proof]
#[kani::unwind(5)]
fn allow_lower_risk() {
    let (rules, n) = any_rules();
    let (hi, lo) = (any_risk(), any_risk());
    kani::assume(lo <= hi);
    let forbidden: bool = kani::any();
    if matches!(decide(|| forbidden, hi, rules[..n].iter().copied()), Decision::AllowByReach(_)) {
        assert!(matches!(decide(|| forbidden, lo, rules[..n].iter().copied()), Decision::AllowByReach(_)));
    }
}
