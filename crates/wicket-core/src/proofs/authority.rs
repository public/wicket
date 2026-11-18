//! An agent's authority (`authority`): Wicket/Grant.lean's `descendantChain` and `agentTerms`.

use super::{agent_term_refusal, descendant_chain, ends_within, GrantRules, GrantShape, TermRefusal, MAX_CHAIN};

/// Runs, as small ids: four of them, with any parent links (cycles and self-parents included).
const RUNS: u8 = 4;

/// `walk_desc`, `descendantChain_desc` and `not_own`: a chain `descendant_chain` returns is the
/// asking run, then its parent, its parent's parent, and so on up to the agent, so the agent is a
/// strict ancestor of the run; and the agent's own request is never one, whatever the parent links
/// (Lean's `not_own` assumes them acyclic; the Rust needs no such assumption since #325).
#[kani::proof]
#[kani::unwind(7)]
fn a_chain_is_a_strict_ancestry() {
    let parents: [Option<u8>; RUNS as usize] = kani::any();
    for p in parents.iter().flatten() {
        kani::assume(*p < RUNS);
    }
    let (target, run): (u8, u8) = (kani::any_where(|&t| t < RUNS), kani::any_where(|&r| r < RUNS));
    let got = descendant_chain(|r: &u8| Ok::<_, ()>(parents[usize::from(*r)]), &target, &run).unwrap();
    if let Some(chain) = got {
        assert!(run != target);
        assert!(chain[0] == run && chain[chain.len() - 1] == target && chain.len() <= MAX_CHAIN + 1);
        let mut k = 0;
        while k + 1 < chain.len() {
            assert_eq!(parents[usize::from(chain[k])], Some(chain[k + 1]));
            k += 1;
        }
    }
}

/// And the converse, for parent links without cycles: a strict descendant's request does reach its
/// ancestor (the walk gives up only on a cycle or past [`MAX_CHAIN`]).
#[kani::proof]
#[kani::unwind(7)]
fn a_descendant_is_found() {
    let parents: [Option<u8>; RUNS as usize] = kani::any();
    // Acyclic: every parent link points to a lower id.
    for (i, p) in parents.iter().enumerate() {
        if let Some(p) = p {
            kani::assume(usize::from(*p) < i);
        }
    }
    let (target, run): (u8, u8) = (kani::any_where(|&t| t < RUNS), kani::any_where(|&r| r < RUNS));
    // `target` is a strict ancestor of `run`.
    let mut at = parents[usize::from(run)];
    let mut ancestor = false;
    for _ in 0..RUNS {
        if let Some(p) = at {
            ancestor |= p == target;
            at = parents[usize::from(p)];
        }
    }
    let got = descendant_chain(|r: &u8| Ok::<_, ()>(parents[usize::from(*r)]), &target, &run).unwrap();
    assert_eq!(got.is_some(), ancestor);
}

/// `agentTerms`' lifetime (`agent_grant_within`'s "before its authority ends",
/// `agent_renewal_within`): an agent's grant or renewal is made only while its authority lasts, and
/// ends no later than it, for every time, lifetime and authority end: no overflow can wrap an end
/// to within it.
#[kani::proof]
fn an_agents_grant_ends_within_its_authority() {
    let (now, ttl, until): (i64, u64, i64) = kani::any();
    if ends_within(now, ttl, until).is_ok() {
        assert!(now < until);
        assert!(i128::from(now) + i128::from(ttl) <= i128::from(until));
    }
    // Complete too: an end that is within it is allowed.
    if now < until && i128::from(now) + i128::from(ttl) <= i128::from(until) {
        assert!(ends_within(now, ttl, until).is_ok());
    }
}

fn any_rules() -> GrantRules {
    GrantRules { prefix: kani::any(), zone_wide: kani::any(), git_push: kani::any(), unbounded: kani::any() }
}

fn any_shape() -> GrantShape {
    GrantShape { zone_wide: kani::any(), prefix: kani::any(), unbounded: kani::any(), git_push: kani::any() }
}

/// `agentTerms`' refusals under the policy's `agents:` rules (#256; the Lean spec has the
/// default only): a default `AgentRules` refuses every refusal-shaped grant `agent_terms` refused
/// before the rules existed (a whole zone, a prefix, no number of uses, a git push), and nothing
/// else.
#[kani::proof]
fn default_agent_rules_refuse_what_agent_terms_did() {
    let shape = any_shape();
    let refused = agent_term_refusal(GrantRules::default(), shape).is_some();
    assert_eq!(refused, shape.zone_wide || shape.prefix || shape.unbounded || shape.git_push);
}

/// And each rule lifts exactly its own refusal: for any rules and shape, a grant is refused
/// exactly when it has a refusal-shaped term whose rule is off, and the refusal named is one of
/// those. So turning one rule on accepts only grants whose sole such term is its own.
#[kani::proof]
fn each_agent_rule_lifts_only_its_refusal() {
    let (r, s) = (any_rules(), any_shape());
    let zone = s.zone_wide && !r.zone_wide;
    let prefix = s.prefix && !r.prefix;
    let unbounded = s.unbounded && !r.unbounded;
    let push = s.git_push && !r.git_push;
    match agent_term_refusal(r, s) {
        None => assert!(!zone && !prefix && !unbounded && !push),
        // The first in `agent_terms`' order.
        Some(TermRefusal::ZoneWide) => assert!(zone),
        Some(TermRefusal::Prefix) => assert!(prefix && !zone),
        Some(TermRefusal::Unbounded) => assert!(unbounded && !zone && !prefix),
        Some(TermRefusal::GitPush) => assert!(push && !zone && !prefix && !unbounded),
    }
}
