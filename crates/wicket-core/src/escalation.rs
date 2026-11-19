//! When a refused request may be asked for: the parts of `wicket-authz`'s structural check
//! (`structure::classify`) and decision (`Loaded::classify`) that don't need biscuit's types. A
//! token's check is escalatable (a grant could lift it) or hard; a refused request needs a grant
//! only if every check it failed is a known escalatable one, and is forbidden otherwise. Fail-closed:
//! a check of unknown class, a node's own check, or a refusal naming no check at all forbids.
//! Kani checks both (#325, `proofs/escalation.rs`).

/// Whether a token check is escalatable, from what its queries read: a check of kind `one` (it
/// must hold for one alternative, not all) that reads reach or risk (`host`, `risk`, `approved`),
/// and never the org policy (`policy`), which no grant can lift.
pub fn check_escalatable(kind_one: bool, reads_policy: bool, reads_host: bool, reads_risk: bool, reads_approved: bool) -> bool {
    kind_one && !reads_policy && (reads_host || reads_risk || reads_approved)
}

/// A check a refused request failed, as the decision sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failed {
    /// One of the node's own (authorizer) checks.
    Node,
    /// One of the token's checks: whether the structural check classed it escalatable, or None if
    /// its class isn't known (a block or check id the vetting didn't see).
    Block(Option<bool>),
}

impl Failed {
    /// Whether this failure alone could be lifted by a grant.
    pub fn soft(self) -> bool {
        matches!(self, Failed::Block(Some(true)))
    }
}

/// Whether a refusal with `hard` hard and `soft` soft failed checks needs a grant (else it is
/// forbidden): none hard, and at least one soft.
pub fn needs_grant(hard: usize, soft: usize) -> bool {
    hard == 0 && soft > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_escalatable_failures_need_a_grant() {
        assert!(check_escalatable(true, false, true, false, false));
        // Any one of reach or risk is enough (mutation testing, #326: `||` for `&&` survived).
        assert!(check_escalatable(true, false, false, true, false), "risk alone");
        assert!(check_escalatable(true, false, false, false, true), "approved alone");
        assert!(!check_escalatable(true, true, true, true, true), "the org policy is hard");
        assert!(!check_escalatable(false, false, true, false, false), "an all-alternatives check is hard");
        assert!(!check_escalatable(true, false, false, false, false), "nothing escalatable read");
        assert!(Failed::Block(Some(true)).soft());
        assert!(!Failed::Block(Some(false)).soft() && !Failed::Block(None).soft() && !Failed::Node.soft());
        assert!(needs_grant(0, 1) && !needs_grant(0, 0) && !needs_grant(1, 3));
    }
}

#[cfg(kani)]
#[path = "proofs/escalation.rs"]
mod proofs;
