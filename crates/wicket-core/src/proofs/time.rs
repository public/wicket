//! Durations (`time`): zone timeouts, authority lifetimes and `wicket` flags are parsed term by
//! term, each added with `add_to` (#437: a carry once panicked in `Duration::new`). #322's Lean
//! spec has no counterpart.
//!
//! The bound: any total, a term of any whole seconds, and under a second of nanoseconds, so at
//! most one second carries. Its nanoseconds are built from a `u32`, so their high bits are zero
//! and the solver's divider is narrow; and the result is stated as seconds and nanoseconds, with
//! no multiplication. (Over every `u64` of nanoseconds, with the sum stated in nanoseconds, the
//! harness ran a CI shard past its hour.) Terms of a second or more of nanoseconds are covered by
//! the unit tests and the `time` fuzz target.

use super::add_to;
use std::time::Duration;

const NANOS: u64 = 1_000_000_000;

/// The carry (#437): the sum is the total's seconds plus the term's, plus one if the nanoseconds
/// carry, with the rest of the nanoseconds; refused exactly when those seconds are past the
/// largest `Duration`; and never a panic.
#[kani::proof]
fn a_carried_second_is_added_exactly_or_refused() {
    let (sec, total_s): (u64, u64) = kani::any();
    let nsec = u64::from(kani::any_where(|&n: &u32| u64::from(n) < NANOS));
    let total_ns: u32 = kani::any_where(|&n: &u32| u64::from(n) < NANOS);
    let mut out = Duration::new(total_s, total_ns);
    let ns = u64::from(total_ns) + nsec;
    let (carry, rest) = if ns >= NANOS { (1u128, ns - NANOS) } else { (0, ns) };
    let secs = u128::from(total_s) + u128::from(sec) + carry;
    match add_to(sec, nsec, &mut out) {
        Ok(()) => assert!(u128::from(out.as_secs()) == secs && u64::from(out.subsec_nanos()) == rest),
        Err(_) => assert!(secs > u128::from(u64::MAX)),
    }
}
