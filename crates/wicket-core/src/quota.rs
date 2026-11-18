//! The arithmetic of quota grants (#256): the parts of `wicket-store`'s money check
//! (`money::check`) and its counted grants (`Ledger::may_use`) that don't need the ledger. Kani
//! checks them (#325, `proofs/quota.rs`); #322's Lean spec has no counterpart yet.

/// Which money limit a reservation would go over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoneyOver {
    /// The hourly limit: what live leases and nodes may cost an hour.
    Hourly,
    /// The total limit: what they may cost at worst, over their lifetimes.
    Total,
}

/// Amounts of money, micro-USD: an hourly rate and a total.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Money {
    pub hourly: i64,
    pub total: i64,
}

/// The one spend check's arithmetic: whether `new` fits beside what is `reserved` within `max`,
/// the hourly limit checked first. Exact for every `i64`: the sums are taken in `i128`, so none
/// overflows or wraps to within a limit.
pub fn money_fits(reserved: Money, new: Money, max: Money) -> Result<(), MoneyOver> {
    let over = |r: i64, n: i64, m: i64| i128::from(r) + i128::from(n) > i128::from(m);
    if over(reserved.hourly, new.hourly, max.hourly) {
        return Err(MoneyOver::Hourly);
    }
    if over(reserved.total, new.total, max.total) {
        return Err(MoneyOver::Total);
    }
    Ok(())
}

/// The `not_after` a grant the ledger ends at `expires_at` (Unix seconds) is published with in a
/// node's token (#342; `wicket-authz`'s `Grant::not_after_for`). The ledger's grant is live while
/// `now_ms < expires_at * 1000` (#337: half-open); the token's check is
/// `floor(now_ms / 1000) <= not_after`. So `expires_at - 1`: the two agree at every millisecond
/// (Kani checks it, `proofs/quota.rs`). An `expires_at` of 0 or less, which no grant has, gives 0.
pub fn not_after_for(expires_at: i64) -> u64 {
    u64::try_from(expires_at.saturating_sub(1)).unwrap_or(0)
}

/// A request's time in a node's token (Unix seconds), from the node's clock in ms: floored, and 0
/// before the epoch (`wicket-feed`'s `authz::Request`).
pub fn token_secs(now_ms: i64) -> u64 {
    u64::try_from(now_ms.div_euclid(1000)).unwrap_or(0)
}

/// Whether a token's `not_after` allows a request at `now_ms`: its check, `time <= not_after`.
pub fn token_allows(not_after: u64, now_ms: i64) -> bool {
    token_secs(now_ms) <= not_after
}

/// One use of a grant with `uses_left` (None: not counted). `Some(left)`: accepted, with `left`
/// uses left after it (None again for a grant that isn't counted). None: refused, for a counted
/// grant with no use left (zero, or a count below it that no grant should hold).
pub fn take_use(uses_left: Option<i64>) -> Option<Option<i64>> {
    match uses_left {
        None => Some(None),
        Some(n) if n > 0 => Some(Some(n - 1)),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_fits_exactly_at_the_limits_and_never_overflows() {
        let m = |hourly, total| Money { hourly, total };
        assert_eq!(money_fits(m(1, 10), m(2, 5), m(3, 15)), Ok(()));
        assert_eq!(money_fits(m(1, 10), m(3, 5), m(3, 15)), Err(MoneyOver::Hourly));
        assert_eq!(money_fits(m(1, 10), m(2, 6), m(3, 15)), Err(MoneyOver::Total));
        assert_eq!(money_fits(m(1, 100), m(3, 100), m(3, 15)), Err(MoneyOver::Hourly), "hourly first");
        // A wrapping sum would be negative, within any limit: refused.
        assert_eq!(money_fits(m(i64::MAX, 0), m(1, 0), m(i64::MAX, 0)), Err(MoneyOver::Hourly));
        assert_eq!(money_fits(m(0, i64::MAX), m(0, i64::MAX), m(0, i64::MAX)), Err(MoneyOver::Total));
        // Exact below too: a sum under i64::MIN is within a limit of i64::MIN.
        assert_eq!(money_fits(m(i64::MIN, i64::MIN), m(-1, -1), m(i64::MIN, i64::MIN)), Ok(()));
        assert_eq!(money_fits(m(i64::MAX, i64::MAX), m(i64::MIN, i64::MIN), m(-1, -1)), Ok(()));
    }

    /// #342 (Kani checks every value, proofs/quota.rs): the token allows through the last
    /// millisecond before the ledger's end, never at it.
    #[test]
    fn a_token_ends_at_the_ledgers_millisecond() {
        for e in [1i64, 2, 1_700_000_000, i64::MAX / 1000, i64::MAX] {
            let na = not_after_for(e);
            let ms = i128::from(e) * 1000;
            for now in [ms - 1001, ms - 1000, ms - 1, ms, ms + 1, 0, -1, i128::from(i64::MIN), i128::from(i64::MAX)] {
                let Ok(now) = i64::try_from(now) else { continue };
                assert_eq!(token_allows(na, now), i128::from(now) < ms, "expires_at {e}, now_ms {now}");
            }
        }
        // No grant ends at or before the epoch; such an end gives 0, which allows the first second.
        assert_eq!(not_after_for(0), 0);
        assert_eq!(not_after_for(i64::MIN), 0);
        assert_eq!(token_secs(-1), 0);
        assert_eq!(token_secs(1999), 1);
    }

    #[test]
    fn a_counted_grant_is_used_down_to_zero_and_no_further() {
        assert_eq!(take_use(None), Some(None));
        assert_eq!(take_use(Some(2)), Some(Some(1)));
        assert_eq!(take_use(Some(1)), Some(Some(0)));
        assert_eq!(take_use(Some(0)), None);
        assert_eq!(take_use(Some(-1)), None);
        assert_eq!(take_use(Some(i64::MIN)), None);
        assert_eq!(take_use(Some(i64::MAX)), Some(Some(i64::MAX - 1)));
    }
}

#[cfg(kani)]
#[path = "proofs/quota.rs"]
mod proofs;
