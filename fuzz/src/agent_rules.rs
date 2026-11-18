//! Target 13: `operators.yaml` (#11, #50), and the agents' grant rules in it (#472,
//! `wicket_control::operators::Policy::parse`). The file is the operator's, but every decision
//! reads it, and what it says agents may lift (prefixes, zone-wide, pushes, unbounded grants) is
//! the security boundary of agents' grants.
//!
//! The oracle, besides panics: a policy that reads has agent rules that print as an `agents:`
//! section that reads back as the same rules, and only kinds agents can decide (`http`).

use wicket_control::operators::Policy;

pub fn run(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(p) = Policy::parse(text) else { return };
    let rules = p.agents();
    assert!(rules.kinds.iter().all(|k| k == "http"), "{text:?}: agents may decide only http requests, not {:?}", rules.kinds);
    let printed = rules.as_policy_yaml();
    let back = Policy::parse(&printed).unwrap_or_else(|e| panic!("{text:?}'s rules print as {printed:?}, which doesn't read: {e:#}"));
    assert_eq!(back.agents(), rules, "{text:?}: its rules print as {printed:?}, which reads otherwise");
}
