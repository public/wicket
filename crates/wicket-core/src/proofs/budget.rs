//! Quota carving and budget slices (`budget`): #322's item 4 (children's carved budgets never
//! exceed their parent's, and the arithmetic doesn't overflow at the limits used), which #340's
//! Lean spec doesn't model yet. Over every `u64`, not bounded inputs: the atomics are read and
//! written sequentially here (loom's test, tests/loom_budget.rs, covers their interleavings).

use super::{Counter, Counts, ModelQuota, Slice, Spent};
use std::sync::atomic::Ordering::SeqCst;

fn any_quota() -> ModelQuota {
    ModelQuota { requests: kani::any(), output_tokens: kani::any(), input_tokens: kani::any() }
}

fn any_counts() -> Counts {
    Counts {
        requests: kani::any(),
        input_total: kani::any(),
        output_tokens: kani::any(),
        reserved_requests: kani::any(),
        reserved_output_tokens: kani::any(),
        reserved_input_tokens: kani::any(),
        prior_requests: kani::any(),
        prior_input_tokens: kani::any(),
        prior_output_tokens: kani::any(),
        inflight_output_tokens: kani::any(),
    }
}

/// A counter holding `c` (input all uncached).
fn counter(c: Counts) -> Counter {
    let k = Counter::default();
    k.requests.store(c.requests, SeqCst);
    k.input_tokens.store(c.input_total, SeqCst);
    k.output_tokens.store(c.output_tokens, SeqCst);
    k.reserved_requests.store(c.reserved_requests, SeqCst);
    k.reserved_output_tokens.store(c.reserved_output_tokens, SeqCst);
    k.reserved_input_tokens.store(c.reserved_input_tokens, SeqCst);
    k.prior_requests.store(c.prior_requests, SeqCst);
    k.prior_input_tokens.store(c.prior_input_tokens, SeqCst);
    k.prior_output_tokens.store(c.prior_output_tokens, SeqCst);
    k.inflight_output_tokens.store(c.inflight_output_tokens, SeqCst);
    k
}

/// Within the budget, exactly (sums in `u128`).
fn within(c: &Counts, q: ModelQuota) -> bool {
    let sum = |p: &[u64]| p.iter().map(|&x| u128::from(x)).sum::<u128>();
    sum(&[c.requests, c.reserved_requests, c.prior_requests]) <= u128::from(q.requests)
        && sum(&[c.output_tokens, c.reserved_output_tokens, c.prior_output_tokens, c.inflight_output_tokens]) <= u128::from(q.output_tokens)
        && q.input_tokens.is_none_or(|m| sum(&[c.input_total, c.reserved_input_tokens, c.prior_input_tokens]) <= u128::from(m))
}

/// A slice never leases a node more than is left: counting up to it, the node takes the run to
/// its budget at most (or nowhere further, if merged reports already took it past). For every
/// share of a limit a slice may add (`part`), and nothing overflows.
#[kani::proof]
fn a_slice_never_exceeds_what_is_left() {
    let (c, q) = (any_counts(), any_quota());
    let s: Slice = c.slice(q, |_| kani::any());
    let past = |slice: u64, own: u64, committed: u64, max: u64| {
        // What the run would have committed with the node at its slice.
        u128::from(committed) - u128::from(own) + u128::from(slice) <= u128::from(max.max(committed))
    };
    assert!(s.requests >= c.requests && past(s.requests, c.requests, c.requests_committed(), q.requests));
    assert!(
        s.output_tokens >= c.output_tokens && s.output_tokens - c.output_tokens <= q.output_tokens.saturating_sub(c.output_committed())
    );
    if let (Some(m), Some(i)) = (q.input_tokens, s.input_tokens) {
        assert!(i >= c.input_total && past(i, c.input_total, c.input_committed(), m));
    }
}

/// The slice renewal rule keeps a node's slice only while it is no more than the next one would be,
/// and otherwise leases the next; for every slice and count (twice what is left of a slice larger
/// than half of `u64::MAX` overflowed before #325).
#[kani::proof]
fn a_renewed_slice_is_the_next_or_no_more_than_it() {
    let any_slice = || Slice { requests: kani::any(), output_tokens: kani::any(), input_tokens: kani::any() };
    let (cur, next) = (any_slice(), any_slice());
    let spent = Spent { requests: kani::any(), output_tokens: kani::any(), ..Spent::default() };
    let kept: bool = kani::any();
    let got = Slice::renewed(kept.then_some(cur), next, spent, kani::any());
    if got != next {
        assert!(kept && got == cur);
        assert!(cur.requests <= next.requests && cur.output_tokens <= next.output_tokens);
    }
}

/// Carving: a child's budget is carved only if it fits in what is left, so a run within its
/// budget stays within it (all three limits), and a refused carve-out changes nothing.
#[kani::proof]
#[kani::unwind(7)]
fn a_carve_out_keeps_the_run_within_its_budget() {
    let (c, q, child) = (any_counts(), any_quota(), any_quota());
    kani::assume(within(&c, q));
    let k = counter(c);
    match k.carve(q, child) {
        Ok(()) => {
            let after = k.counts();
            assert!(within(&after, q));
            // Carved in full: a carve-out that would saturate a counter is refused.
            assert_eq!(after.reserved_requests, c.reserved_requests + child.requests);
            assert_eq!(after.reserved_output_tokens, c.reserved_output_tokens + child.output_tokens);
        }
        Err(_) => assert_eq!(k.counts(), c),
    }
}

/// Children never exceed the parent: whatever two children ask, those carved add up to no more
/// than the parent had left, and the parent's own spending (an admitted request) stays within
/// what the carve-outs left it.
#[kani::proof]
#[kani::unwind(7)]
fn children_never_exceed_the_parent() {
    let (c, q) = (any_counts(), any_quota());
    kani::assume(within(&c, q));
    let (left_r, left_o) = c.remaining(q);
    let k = counter(c);
    let (mut carved_r, mut carved_o) = (0u128, 0u128);
    for _ in 0..2 {
        let child = any_quota();
        if k.carve(q, child).is_ok() {
            carved_r += u128::from(child.requests);
            carved_o += u128::from(child.output_tokens);
        }
    }
    assert!(carved_r <= u128::from(left_r) && carved_o <= u128::from(left_o));
    // A request is admitted only if the run's requests, its children's included, are in budget.
    if k.admit_request() <= q.requests {
        assert!(u128::from(c.requests_committed()) + carved_r < u128::from(q.requests) + 1);
    }
}

/// Merging a node's `Spent` takes each counter to the larger of the two, so a report can't lower
/// a count (replayed, reordered or stale ones included), and `since` never underflows.
#[kani::proof]
fn merging_spent_only_raises_the_counts() {
    let (c, s) = (any_counts(), Spent { requests: kani::any(), input_tokens: kani::any(), output_tokens: kani::any(), ..Spent::default() });
    let k = counter(c);
    k.merge_spent(s);
    let after = k.spent();
    assert_eq!(after.requests, c.requests.max(s.requests));
    assert_eq!(after.output_tokens, c.output_tokens.max(s.output_tokens));
    let base = Spent { requests: kani::any(), ..Spent::default() };
    assert!(s.since(base).requests <= s.requests);
}
