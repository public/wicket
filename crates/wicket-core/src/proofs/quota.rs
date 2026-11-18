//! The arithmetic of quota grants (`quota`): the money check's sums and a counted grant's uses.
//! #322's Lean spec has no counterpart yet. Over every `i64`, not bounded inputs: there are no
//! loops but the uses harness's, bounded by its `#[kani::unwind]`.

use super::{money_fits, not_after_for, take_use, token_allows, Money, MoneyOver, SpawnAsk, SpawnLimits};

fn any_money() -> Money {
    Money { hourly: kani::any(), total: kani::any() }
}

/// `money::check`: for any reserved totals, new reservation and limits, a reservation is accepted
/// exactly when both sums stay within their limits (the sums exact: nothing overflows or wraps to
/// within a limit), and a refusal names the limit it goes over, the hourly one first.
#[kani::proof]
fn money_is_accepted_exactly_within_the_limits() {
    let (reserved, new, max) = (any_money(), any_money(), any_money());
    let hourly_fits = i128::from(reserved.hourly) + i128::from(new.hourly) <= i128::from(max.hourly);
    let total_fits = i128::from(reserved.total) + i128::from(new.total) <= i128::from(max.total);
    match money_fits(reserved, new, max) {
        Ok(()) => assert!(hourly_fits && total_fits),
        Err(MoneyOver::Hourly) => assert!(!hourly_fits),
        Err(MoneyOver::Total) => assert!(hourly_fits && !total_fits),
    }
}

/// `Ledger::may_use`: one use of a counted grant takes exactly one use, never takes one below
/// zero, and is never accepted at zero (or below); a grant that isn't counted stays uncounted.
#[kani::proof]
fn a_use_never_takes_a_grant_below_zero() {
    let uses: Option<i64> = kani::any();
    match (uses, take_use(uses)) {
        (None, got) => assert_eq!(got, Some(None)),
        (Some(n), Some(Some(left))) => assert!(n > 0 && left == n - 1 && left >= 0),
        (Some(n), None) => assert!(n <= 0),
        (Some(_), Some(None)) => panic!("a counted grant became uncounted"),
    }
}

/// And used again and again: a grant of `k` uses is accepted exactly `k` times (`k` up to 4).
#[kani::proof]
#[kani::unwind(7)]
fn a_grant_of_k_uses_is_accepted_k_times() {
    let k: i64 = kani::any_where(|&k| (0..=4).contains(&k));
    let mut left = Some(k);
    let mut accepted = 0;
    for _ in 0..6 {
        if let Some(next) = take_use(left) {
            accepted += 1;
            left = next;
        }
        assert!(left.is_some_and(|n| n >= 0));
    }
    assert_eq!(accepted, k);
    assert_eq!(left, Some(0));
}

/// #342: a node's token and the ledger end a grant at the same millisecond. For every grant end
/// `expires_at` (`>= 1`: every grant's, which ends after the epoch) and every clock reading of the
/// node's, the token's `not_after_for(expires_at)` allows a request exactly while the ledger's
/// half-open grant is live (`now_ms < expires_at * 1000`, exact in `i128`).
#[kani::proof]
fn a_token_ends_at_the_ledgers_millisecond() {
    let (expires_at, now_ms): (i64, i64) = kani::any();
    kani::assume(expires_at >= 1);
    let live = i128::from(now_ms) < i128::from(expires_at) * 1000;
    assert_eq!(token_allows(not_after_for(expires_at), now_ms), live);
}

fn any_ask() -> SpawnAsk {
    SpawnAsk { isolation: kani::any(), mem_bytes: kani::any(), cpus_milli: kani::any(), pids: kani::any(), timeout_s: kani::any() }
}

fn any_limits() -> SpawnLimits {
    SpawnLimits {
        min_isolation: kani::any(),
        max_mem_bytes: kani::any(),
        max_cpus_milli: kani::any(),
        max_pids: kani::any(),
        max_timeout_s: kani::any(),
    }
}

/// Whether limits `t` are no looser than `l`: a floor at least as high where `l` has one, a cap
/// at most as high where `l` has one.
fn no_looser(t: &SpawnLimits, l: &SpawnLimits) -> bool {
    let floor = |t: Option<i64>, l: Option<i64>| l.is_none_or(|l| t.is_some_and(|t| t >= l));
    let cap = |t: Option<i64>, l: Option<i64>| l.is_none_or(|l| t.is_some_and(|t| t <= l));
    floor(t.min_isolation, l.min_isolation)
        && cap(t.max_mem_bytes, l.max_mem_bytes)
        && cap(t.max_cpus_milli, l.max_cpus_milli)
        && cap(t.max_pids, l.max_pids)
        && cap(t.max_timeout_s, l.max_timeout_s)
}

/// `OrgLayer::allows_spawn`'s ceiling (`SpawnLimits::admits`), for every ask and limits: no limits
/// admit everything; a spawn that asks for no more than an admitted one (isolation at least as
/// strong, no more of any resource) is admitted too; and limits no looser than others admit
/// nothing those refuse. So a child zone's tighter ceiling never lets through what its parent's
/// refuses.
#[kani::proof]
fn a_spawn_ceiling_admits_what_is_within_it_and_tighter_admits_less() {
    let (l, t, a, b) = (any_limits(), any_limits(), any_ask(), any_ask());
    assert!(SpawnLimits::default().admits(a));
    if l.admits(a) && b.within(&a) {
        assert!(l.admits(b));
    }
    if no_looser(&t, &l) && t.admits(a) {
        assert!(l.admits(a));
    }
}
