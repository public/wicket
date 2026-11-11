//! Money as whole micro-dollars: exact, and fine enough for per-hour rates like $0.0089.

use std::fmt;
use std::ops::{Add, AddAssign};

/// US dollars, in millionths. Provider rates are sub-cent, bills are whole cents.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct MicroUsd(pub u64);

impl MicroUsd {
    pub const ZERO: MicroUsd = MicroUsd(0);
    const PER_CENT: u64 = 10_000;
    const PER_DOLLAR: u64 = 1_000_000;

    pub fn from_cents(c: u64) -> MicroUsd {
        MicroUsd(c.saturating_mul(Self::PER_CENT))
    }

    /// From a decimal dollar amount as an API or the command line gives it ("0.014", "5", "$1.50"),
    /// without going through a float.
    pub fn parse_dollars(s: &str) -> Option<MicroUsd> {
        let s = s.trim().trim_start_matches('$');
        let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
        if whole.is_empty() && frac.is_empty() || !whole.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()) {
            return None;
        }
        let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
        let mut micros = 0u64;
        for (i, c) in frac.chars().enumerate() {
            let d = c.to_digit(10)? as u64;
            if i < 6 {
                micros += d * 10u64.pow(5 - i as u32);
            } else if d > 0 && i == 6 {
                micros += 1; // round any finer fraction up: a price is never understated
            }
        }
        whole.checked_mul(Self::PER_DOLLAR)?.checked_add(micros).map(MicroUsd)
    }

    /// From a JSON number (Vultr's prices are numbers). Rounded to the nearest micro-dollar, which is
    /// exact for every price with six or fewer decimals.
    pub fn from_dollars_f64(d: f64) -> MicroUsd {
        if !d.is_finite() || d <= 0.0 {
            return MicroUsd::ZERO;
        }
        MicroUsd((d * Self::PER_DOLLAR as f64).round() as u64)
    }

    /// Rounded up to a whole cent, as a provider bills a line.
    pub fn ceil_to_cent(self) -> MicroUsd {
        MicroUsd(self.0.div_ceil(Self::PER_CENT).saturating_mul(Self::PER_CENT))
    }

    pub fn times(self, n: u64) -> MicroUsd {
        MicroUsd(self.0.saturating_mul(n))
    }

    /// `self × num / den`, rounded up.
    pub fn mul_div_ceil(self, num: u64, den: u64) -> MicroUsd {
        if den == 0 {
            return MicroUsd(u64::MAX);
        }
        let v = (self.0 as u128 * num as u128).div_ceil(den as u128);
        MicroUsd(u64::try_from(v).unwrap_or(u64::MAX))
    }
}

impl Add for MicroUsd {
    type Output = MicroUsd;
    fn add(self, o: MicroUsd) -> MicroUsd {
        MicroUsd(self.0.saturating_add(o.0))
    }
}

impl AddAssign for MicroUsd {
    fn add_assign(&mut self, o: MicroUsd) {
        *self = *self + o;
    }
}

impl std::iter::Sum for MicroUsd {
    fn sum<I: Iterator<Item = MicroUsd>>(it: I) -> MicroUsd {
        it.fold(MicroUsd::ZERO, |a, b| a + b)
    }
}

/// `$0.0140`: four decimals, enough for hourly rates; whole cents print as `$0.0100`.
impl fmt::Display for MicroUsd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tenths_of_cents = self.0.div_ceil(100);
        write!(f, "${}.{:04}", tenths_of_cents / 10_000, tenths_of_cents % 10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dollars_parse_exactly_and_round_up_below_a_micro_dollar() {
        assert_eq!(MicroUsd::parse_dollars("0.014"), Some(MicroUsd(14_000)));
        assert_eq!(MicroUsd::parse_dollars("$5"), Some(MicroUsd(5_000_000)));
        assert_eq!(MicroUsd::parse_dollars(".5"), Some(MicroUsd(500_000)));
        assert_eq!(MicroUsd::parse_dollars("0.0000001"), Some(MicroUsd(1)));
        assert_eq!(MicroUsd::parse_dollars("1.2.3"), None);
        assert_eq!(MicroUsd::parse_dollars("-1"), None);
        assert_eq!(MicroUsd::parse_dollars(""), None);
        assert_eq!(MicroUsd::from_dollars_f64(0.0595), MicroUsd(59_500));
    }

    #[test]
    fn lines_round_up_to_the_cent() {
        assert_eq!(MicroUsd(8_900).ceil_to_cent(), MicroUsd::from_cents(1));
        assert_eq!(MicroUsd::from_cents(3).ceil_to_cent(), MicroUsd::from_cents(3));
        assert_eq!(MicroUsd(0).ceil_to_cent(), MicroUsd(0));
        assert_eq!(MicroUsd(14_000).to_string(), "$0.0140");
        assert_eq!(MicroUsd::from_cents(150).to_string(), "$1.5000");
    }
}
