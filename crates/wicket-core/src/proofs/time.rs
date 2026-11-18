//! Durations (`time`): zone timeouts, authority lifetimes and `wicket` flags are parsed term by
//! term, each added with `add_to` (#437: a carry once panicked in `Duration::new`). #322's Lean
//! spec has no counterpart. Over every term and every running total.

use super::add_to;
use std::time::Duration;

const NANOS: u128 = 1_000_000_000;

/// `add_to` never panics, and a sum it makes is exact: the running total plus the term's seconds
/// and nanoseconds, to the nanosecond. It refuses only a sum past the largest `Duration`, or a
/// term whose nanoseconds and the total's don't fit a `u64` together (over 584 years of
/// nanoseconds: refused, never wrapped).
#[kani::proof]
fn adding_a_term_is_exact_or_refused() {
    let (sec, nsec, total_s): (u64, u64, u64) = kani::any();
    let total_ns: u32 = kani::any_where(|&n: &u32| u128::from(n) < NANOS);
    let mut out = Duration::new(total_s, total_ns);
    let want = u128::from(total_s) * NANOS + u128::from(total_ns) + u128::from(sec) * NANOS + u128::from(nsec);
    let largest = u128::from(u64::MAX) * NANOS + (NANOS - 1);
    match add_to(sec, nsec, &mut out) {
        Ok(()) => assert!(out.as_nanos() == want),
        Err(_) => assert!(want > largest || u64::from(total_ns).checked_add(nsec).is_none()),
    }
}
