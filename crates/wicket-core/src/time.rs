//! Durations and times as people write and read them (#437): `30m`, `1h 30m`, `24h`, `7d` in
//! manifests, operator files and CLI flags, and `2026-11-12T19:05:05Z` in what wicket prints.
//!
//! The spellings, the output and the error messages are humantime 2.4's, which wicket used until
//! it was declared unmaintained (RUSTSEC-2026-0542), restated here (humantime is MIT or
//! Apache-2.0): the tests below pin what it did. A duration's terms may be spaced or not (`1h30m`),
//! a number may have a fraction (`1.5h`), and whitespace between a number and its unit is
//! allowed (`5 minutes`). Times are UTC.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Why a duration didn't parse.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DurationError {
    /// A character no duration has, at this byte offset.
    InvalidCharacter(usize),
    /// A number was expected at this byte offset.
    NumberExpected(usize),
    /// A unit that isn't one (or none), after `value`.
    UnknownUnit {
        unit: String,
        value: u64,
    },
    /// Too large, or finer than a nanosecond.
    NumberOverflow,
    Empty,
}

impl std::error::Error for DurationError {}

impl fmt::Display for DurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DurationError::InvalidCharacter(offset) => write!(f, "invalid character at {offset}"),
            DurationError::NumberExpected(offset) => write!(f, "expected number at {offset}"),
            DurationError::UnknownUnit { unit, value } if unit.is_empty() => {
                write!(f, "time unit needed, for example {value}sec or {value}ms")
            }
            DurationError::UnknownUnit { unit, .. } => write!(
                f,
                "unknown time unit {unit:?}, supported units: ns, us/µs, ms, sec, min, hours, days, weeks, months, years (and few variations)"
            ),
            DurationError::NumberOverflow => f.write_str(
                "number is too large or cannot be represented without a lack of precision (values below 1ns are not supported)",
            ),
            DurationError::Empty => f.write_str("value was empty"),
        }
    }
}

#[derive(Clone, Copy)]
enum Unit {
    Nanosecond,
    Microsecond,
    Millisecond,
    Second,
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl Unit {
    fn of(s: &str) -> Option<Unit> {
        Some(match s {
            "nanos" | "nsec" | "ns" => Unit::Nanosecond,
            "usec" | "us" | "µs" => Unit::Microsecond,
            "millis" | "msec" | "ms" => Unit::Millisecond,
            "seconds" | "second" | "secs" | "sec" | "s" => Unit::Second,
            "minutes" | "minute" | "min" | "mins" | "m" => Unit::Minute,
            "hours" | "hour" | "hr" | "hrs" | "h" => Unit::Hour,
            "days" | "day" | "d" => Unit::Day,
            "weeks" | "week" | "wk" | "wks" | "w" => Unit::Week,
            "months" | "month" | "M" => Unit::Month,
            "years" | "year" | "yr" | "yrs" | "y" => Unit::Year,
            _ => return None,
        })
    }
}

/// A month: 30.44 days.
const MONTH_SECS: u64 = 2_630_016;
/// A year: 365.25 days.
const YEAR_SECS: u64 = 31_557_600;

fn mul(a: u64, b: u64) -> Result<u64, DurationError> {
    a.checked_mul(b).ok_or(DurationError::NumberOverflow)
}

/// `a / b`, exactly (a fraction finer than the unit's nanosecond or second can't be).
fn div_exact(a: u64, b: u64) -> Result<u64, DurationError> {
    match a % b {
        0 => Ok(a / b),
        _ => Err(DurationError::NumberOverflow),
    }
}

fn is_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || c == 'µ'
}

struct Parser<'a> {
    iter: std::str::Chars<'a>,
    src: &'a str,
}

impl Parser<'_> {
    fn off(&self) -> usize {
        self.src.len() - self.iter.as_str().len()
    }

    /// The first digit of the next term, skipping whitespace; None at the end.
    fn first_digit(&mut self) -> Result<Option<u64>, DurationError> {
        let off = self.off();
        for c in self.iter.by_ref() {
            match c {
                '0'..='9' => return Ok(Some(u64::from(c) - u64::from('0'))),
                c if c.is_whitespace() => continue,
                _ => return Err(DurationError::NumberExpected(off)),
            }
        }
        Ok(None)
    }

    /// The digits after a `.`: (numerator, denominator).
    fn fraction(&mut self, off: &mut usize) -> Result<(u64, u64), DurationError> {
        let (mut num, mut den, mut zeros) = (0u64, 1u64, true);
        while let Some(c) = self.iter.next() {
            match c {
                '0' => {
                    den = mul(den, 10)?;
                    if !zeros {
                        num = mul(num, 10)?;
                    }
                }
                '1'..='9' => {
                    zeros = false;
                    den = mul(den, 10)?;
                    num = mul(num, 10)?.checked_add(u64::from(c) - u64::from('0')).ok_or(DurationError::NumberOverflow)?;
                }
                c if c.is_whitespace() => {}
                c if is_letter(c) => break,
                _ => return Err(DurationError::InvalidCharacter(*off)),
            }
            *off = self.off();
        }
        if den == 1 {
            // No digits after the `.`.
            return Err(DurationError::InvalidCharacter(*off));
        }
        Ok((num, den))
    }

    /// Adds `n` (and its fraction) of the unit spelt `src[start..end]`.
    fn add(&self, n: u64, frac: Option<(u64, u64)>, start: usize, end: usize, out: &mut Duration) -> Result<(), DurationError> {
        let unit = Unit::of(&self.src[start..end])
            .ok_or_else(|| DurationError::UnknownUnit { unit: self.src[start..end].to_owned(), value: n })?;
        let (sec, nsec) = match unit {
            Unit::Nanosecond => (0, n),
            Unit::Microsecond => (0, mul(n, 1000)?),
            Unit::Millisecond => (0, mul(n, 1_000_000)?),
            Unit::Second => (n, 0),
            Unit::Minute => (mul(n, 60)?, 0),
            Unit::Hour => (mul(n, 3600)?, 0),
            Unit::Day => (mul(n, 86_400)?, 0),
            Unit::Week => (mul(n, 86_400 * 7)?, 0),
            Unit::Month => (mul(n, MONTH_SECS)?, 0),
            Unit::Year => (mul(n, YEAR_SECS)?, 0),
        };
        add_to(sec, nsec, out)?;
        if let Some((n, d)) = frac {
            let (sec, nsec) = match unit {
                Unit::Nanosecond => return Err(DurationError::NumberOverflow),
                Unit::Microsecond => (0, div_exact(mul(n, 1000)?, d)?),
                Unit::Millisecond => (0, div_exact(mul(n, 1_000_000)?, d)?),
                Unit::Second => (0, div_exact(mul(n, 1_000_000_000)?, d)?),
                Unit::Minute => (0, div_exact(mul(n, 60_000_000_000)?, d)?),
                Unit::Hour => (div_exact(mul(n, 3600)?, d)?, 0),
                Unit::Day => (div_exact(mul(n, 86_400)?, d)?, 0),
                Unit::Week => (div_exact(mul(n, 86_400 * 7)?, d)?, 0),
                Unit::Month => (div_exact(mul(n, MONTH_SECS)?, d)?, 0),
                Unit::Year => (div_exact(mul(n, YEAR_SECS)?, d)?, 0),
            };
            add_to(sec, nsec, out)?;
        }
        Ok(())
    }

    fn parse(mut self) -> Result<Duration, DurationError> {
        let mut n = self.first_digit()?.ok_or(DurationError::Empty)?;
        let mut out = Duration::ZERO;
        'terms: loop {
            // The number (digits may be spaced), and a fraction.
            let mut frac = None;
            let mut off = self.off();
            while let Some(c) = self.iter.next() {
                match c {
                    '0'..='9' => {
                        n = n
                            .checked_mul(10)
                            .and_then(|x| x.checked_add(u64::from(c) - u64::from('0')))
                            .ok_or(DurationError::NumberOverflow)?;
                    }
                    c if c.is_whitespace() => {}
                    c if is_letter(c) => break,
                    '.' => {
                        frac = Some(self.fraction(&mut off)?);
                        break;
                    }
                    _ => return Err(DurationError::InvalidCharacter(off)),
                }
                off = self.off();
            }
            // Its unit: letters up to whitespace, or up to the next term's first digit.
            let start = off;
            let mut off = self.off();
            while let Some(c) = self.iter.next() {
                match c {
                    '0'..='9' => {
                        self.add(n, frac, start, off, &mut out)?;
                        n = u64::from(c) - u64::from('0');
                        continue 'terms;
                    }
                    c if c.is_whitespace() => break,
                    c if is_letter(c) => {}
                    _ => return Err(DurationError::InvalidCharacter(off)),
                }
                off = self.off();
            }
            self.add(n, frac, start, off, &mut out)?;
            n = match self.first_digit()? {
                Some(n) => n,
                None => return Ok(out),
            };
        }
    }
}

fn add_to(sec: u64, nsec: u64, out: &mut Duration) -> Result<(), DurationError> {
    let mut sec = sec;
    let mut nsec = u64::from(out.subsec_nanos()).checked_add(nsec).ok_or(DurationError::NumberOverflow)?;
    // `>=`, not humantime's `>`: a carry of exactly one second must be added here, where its
    // overflow is an error, not by `Duration::new`, which panics on it (#437's fuzz target).
    if nsec >= 1_000_000_000 {
        sec = sec.checked_add(nsec / 1_000_000_000).ok_or(DurationError::NumberOverflow)?;
        nsec %= 1_000_000_000;
    }
    sec = out.as_secs().checked_add(sec).ok_or(DurationError::NumberOverflow)?;
    *out = Duration::new(sec, nsec as u32);
    Ok(())
}

/// A duration flag's value, as clap parses it (#574): a duration (`90s`, `10m`, `1h 30m`), or a whole
/// number of seconds. Every duration flag of `wicket` takes it, so a bad value is a usage error.
pub fn duration_arg(s: &str) -> Result<Duration, String> {
    match s.parse::<u64>() {
        Ok(n) => Ok(Duration::from_secs(n)),
        Err(_) => parse_duration(s).map_err(|e| e.to_string()),
    }
}

/// [`duration_arg`] for a flag that also takes `forever`: checked as clap parses it, kept as given.
pub fn duration_or_forever_arg(s: &str) -> Result<String, String> {
    match s {
        "forever" => Ok(s.to_string()),
        d => duration_arg(d).map(|_| s.to_string()).map_err(|e| format!("{e} (a duration such as 30d, or forever)")),
    }
}

/// A duration: one or more `<number><unit>` terms (`30m`, `1h 30m`, `1.5h`, `250ms`), or `0`.
pub fn parse_duration(s: &str) -> Result<Duration, DurationError> {
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    Parser { iter: s.chars(), src: s }.parse()
}

/// A duration, displayed by [`format_duration`].
#[derive(Debug, Clone, Copy)]
pub struct FormattedDuration(Duration);

/// A duration as its largest units, `1day 2h 3m` (a month is 30.44 days, a year 365.25).
pub fn format_duration(d: Duration) -> FormattedDuration {
    FormattedDuration(d)
}

impl fmt::Display for FormattedDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (secs, nanos) = (self.0.as_secs(), self.0.subsec_nanos());
        if secs == 0 && nanos == 0 {
            return f.write_str("0s");
        }
        let ydays = secs % YEAR_SECS;
        let mdays = ydays % MONTH_SECS;
        let day_secs = mdays % 86_400;
        let mut started = false;
        let mut item = |f: &mut fmt::Formatter<'_>, name: &str, value: u64, plural: bool| -> fmt::Result {
            if value > 0 {
                if started {
                    f.write_str(" ")?;
                }
                write!(f, "{value}{name}")?;
                if plural && value > 1 {
                    f.write_str("s")?;
                }
                started = true;
            }
            Ok(())
        };
        item(f, "year", secs / YEAR_SECS, true)?;
        item(f, "month", ydays / MONTH_SECS, true)?;
        item(f, "day", mdays / 86_400, true)?;
        item(f, "h", day_secs / 3600, false)?;
        item(f, "m", day_secs % 3600 / 60, false)?;
        item(f, "s", day_secs % 60, false)?;
        item(f, "ms", u64::from(nanos / 1_000_000), false)?;
        item(f, "us", u64::from(nanos / 1000 % 1000), false)?;
        item(f, "ns", u64::from(nanos % 1000), false)
    }
}

/// Why a time didn't parse.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TimestampError {
    OutOfRange,
    InvalidDigit,
    InvalidFormat,
}

impl std::error::Error for TimestampError {}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TimestampError::OutOfRange => "numeric component is out of range",
            TimestampError::InvalidDigit => "bad character where digit is expected",
            TimestampError::InvalidFormat => "timestamp format is invalid",
        })
    }
}

/// The first second of year 10000: the formats here have four-digit years.
const YEAR_10000: u64 = 253_402_300_800;

/// A time, displayed by [`format_rfc3339_seconds`].
#[derive(Debug, Clone, Copy)]
pub struct Rfc3339Timestamp(SystemTime);

/// A time as `2026-11-12T19:05:05Z` (UTC, whole seconds). Displaying a time before 1970 panics,
/// and one from year 10000 on fails, as humantime's did.
pub fn format_rfc3339_seconds(t: SystemTime) -> Rfc3339Timestamp {
    Rfc3339Timestamp(t)
}

/// Unix seconds as `2026-11-12T19:05:05Z`: what the ledger and the channel keep times as, shown to
/// people. A time before 1970 shows as 1970.
pub fn unix_rfc3339(secs: i64) -> String {
    format_rfc3339_seconds(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs.max(0) as u64)).to_string()
}

/// The civil date of a day since 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

impl fmt::Display for Rfc3339Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.duration_since(UNIX_EPOCH).expect("all times should be after the epoch").as_secs();
        if secs >= YEAR_10000 {
            return Err(fmt::Error);
        }
        let (y, m, d) = civil((secs / 86_400) as i64);
        let s = secs % 86_400;
        write!(f, "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s % 3600 / 60, s % 60)
    }
}

fn two_digits(a: u8, b: u8) -> Result<u64, TimestampError> {
    match ((a as char).to_digit(10), (b as char).to_digit(10)) {
        (Some(a), Some(b)) => Ok(u64::from(a * 10 + b)),
        _ => Err(TimestampError::InvalidDigit),
    }
}

fn is_leap_year(y: u64) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

/// A UTC time written `2026-11-12T19:05:05Z`, with a space for the `T`, without the `Z`, with
/// `+00:00` for it, or with a fraction of a second. A leap second (`:60`) is the second before.
pub fn parse_rfc3339_weak(s: &str) -> Result<SystemTime, TimestampError> {
    if s.len() < "2018-02-14T00:28:07".len() {
        return Err(TimestampError::InvalidFormat);
    }
    let b = s.as_bytes();
    if b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b' ') || b[13] != b':' || b[16] != b':' {
        return Err(TimestampError::InvalidFormat);
    }
    let year = two_digits(b[0], b[1])? * 100 + two_digits(b[2], b[3])?;
    let month = two_digits(b[5], b[6])?;
    let day = two_digits(b[8], b[9])?;
    let hour = two_digits(b[11], b[12])?;
    let minute = two_digits(b[14], b[15])?;
    let mut second = two_digits(b[17], b[18])?;
    if year < 1970 || hour > 23 || minute > 59 || second > 60 {
        return Err(TimestampError::OutOfRange);
    }
    if second == 60 {
        second = 59;
    }
    let leap = is_leap_year(year);
    let (mut ydays, mdays) = match month {
        1 => (0, 31),
        2 if leap => (31, 29),
        2 => (31, 28),
        3 => (59, 31),
        4 => (90, 30),
        5 => (120, 31),
        6 => (151, 30),
        7 => (181, 31),
        8 => (212, 31),
        9 => (243, 30),
        10 => (273, 31),
        11 => (304, 30),
        12 => (334, 31),
        _ => return Err(TimestampError::OutOfRange),
    };
    if day > mdays || day == 0 {
        return Err(TimestampError::OutOfRange);
    }
    ydays += day - 1;
    if leap && month > 2 {
        ydays += 1;
    }
    let leap_years = ((year - 1) - 1968) / 4 - ((year - 1) - 1900) / 100 + ((year - 1) - 1600) / 400;
    let days = (year - 1970) * 365 + leap_years + ydays;
    let time = second + minute * 60 + hour * 3600;

    let mut nanos = 0;
    let mut mult = 100_000_000;
    if b.get(19) == Some(&b'.') {
        for (idx, &c) in b.iter().enumerate().skip(20) {
            if c == b'Z' {
                if idx == b.len() - 1 {
                    break;
                }
                return Err(TimestampError::InvalidDigit);
            } else if c == b'+' {
                // `+00:00`, which must end it.
                if idx == b.len() - 6 {
                    break;
                }
                return Err(TimestampError::InvalidDigit);
            }
            nanos += mult * (c as char).to_digit(10).ok_or(TimestampError::InvalidDigit)?;
            mult /= 10;
        }
    } else if b.len() != 19 && (b.len() > 25 || (b[19] != b'Z' && (&b[19..] != b"+00:00"))) {
        return Err(TimestampError::InvalidFormat);
    }
    let total = time + days * 86_400;
    if total >= YEAR_10000 {
        return Err(TimestampError::OutOfRange);
    }
    Ok(UNIX_EPOCH + Duration::new(total, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    /// An input, and what it parsed to (seconds and nanoseconds) or the error's text.
    type Case = (&'static str, Result<(u64, u32), &'static str>);

    /// Every duration spelling wicket takes (the manifests' limits, operator files, `--ttl`,
    /// `--ca-ttl 24h`, `--every`, `--window`, ...), and the edges of the grammar, with what
    /// humantime 2.4 made of each: seconds and nanoseconds, or its error. Generated from humantime
    /// before it was replaced (#437); the replacement must agree byte for byte.
    /// humantime panicked here: half-seconds that carry into seconds already at their maximum. The
    /// one place the spellings' results differ from humantime's (it panicked; this refuses).
    #[test]
    fn a_carry_past_the_largest_duration_is_refused() {
        let e = parse_duration("18446744073709551615s 500ms 500ms").unwrap_err();
        assert_eq!(e, DurationError::NumberOverflow);
        assert_eq!(parse_duration("1s 500ms 500ms").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("18446744073709551614s 500ms 500ms").unwrap(), Duration::from_secs(u64::MAX));
    }

    #[test]
    fn duration_spellings_are_humantime_s() {
        let cases: &[Case] = &[
("0", Ok((0, 0))),
        ("0s", Ok((0, 0))),
        ("0d", Ok((0, 0))),
        ("1s", Ok((1, 0))),
        ("5s", Ok((5, 0))),
        ("10s", Ok((10, 0))),
        ("30s", Ok((30, 0))),
        ("42s", Ok((42, 0))),
        ("300s", Ok((300, 0))),
        ("3600", Err("time unit needed, for example 3600sec or 3600ms")),
        ("1m", Ok((60, 0))),
        ("2m", Ok((120, 0))),
        ("3m", Ok((180, 0))),
        ("4m", Ok((240, 0))),
        ("5m", Ok((300, 0))),
        ("10m", Ok((600, 0))),
        ("15m", Ok((900, 0))),
        ("20m", Ok((1200, 0))),
        ("25m", Ok((1500, 0))),
        ("30m", Ok((1800, 0))),
        ("1h", Ok((3600, 0))),
        ("2h", Ok((7200, 0))),
        ("3h", Ok((10800, 0))),
        ("8h", Ok((28800, 0))),
        ("24h", Ok((86400, 0))),
        ("72h", Ok((259200, 0))),
        ("7d", Ok((604800, 0))),
        ("5 minutes", Ok((300, 0))),
        ("1h 30m", Ok((5400, 0))),
        ("1h30m", Ok((5400, 0))),
        ("2h 37min", Ok((9420, 0))),
        ("1.5h", Ok((5400, 0))),
        ("0.5s", Ok((0, 500000000))),
        ("1.5m", Ok((90, 0))),
        ("250ms", Ok((0, 250000000))),
        ("1ms 2us 3ns", Ok((0, 1002003))),
        ("90min", Ok((5400, 0))),
        ("1 hour", Ok((3600, 0))),
        ("2 hours", Ok((7200, 0))),
        ("1hr", Ok((3600, 0))),
        ("3hrs", Ok((10800, 0))),
        ("1day", Ok((86400, 0))),
        ("2days", Ok((172800, 0))),
        ("1week", Ok((604800, 0))),
        ("2wks", Ok((1209600, 0))),
        ("1wk", Ok((604800, 0))),
        ("1w", Ok((604800, 0))),
        ("1M", Ok((2630016, 0))),
        ("1month", Ok((2630016, 0))),
        ("2months", Ok((5260032, 0))),
        ("1y", Ok((31557600, 0))),
        ("1yr", Ok((31557600, 0))),
        ("2yrs", Ok((63115200, 0))),
        ("1year", Ok((31557600, 0))),
        ("2years", Ok((63115200, 0))),
        ("1sec", Ok((1, 0))),
        ("2secs", Ok((2, 0))),
        ("1second", Ok((1, 0))),
        ("2seconds", Ok((2, 0))),
        ("1min", Ok((60, 0))),
        ("2mins", Ok((120, 0))),
        ("1minute", Ok((60, 0))),
        ("1nsec", Ok((0, 1))),
        ("1ns", Ok((0, 1))),
        ("1nanos", Ok((0, 1))),
        ("1us", Ok((0, 1000))),
        ("1usec", Ok((0, 1000))),
        ("1µs", Ok((0, 1000))),
        ("1millis", Ok((0, 1000000))),
        ("1msec", Ok((0, 1000000))),
        (" 1h ", Ok((3600, 0))),
        ("1 h", Ok((3600, 0))),
        ("1h  2m", Ok((3720, 0))),
        ("1h,2m", Err("invalid character at 2")),
        ("1.", Err("invalid character at 1")),
        ("", Err("value was empty")),
        (" ", Err("value was empty")),
        ("h", Err("expected number at 0")),
        ("1", Err("time unit needed, for example 1sec or 1ms")),
        ("1x", Err("unknown time unit \"x\", supported units: ns, us/µs, ms, sec, min, hours, days, weeks, months, years (and few variations)")),
        ("1h-", Err("invalid character at 2")),
        ("-1h", Err("expected number at 0")),
        ("+1h", Err("expected number at 0")),
        ("1H", Err("unknown time unit \"H\", supported units: ns, us/µs, ms, sec, min, hours, days, weeks, months, years (and few variations)")),
        ("1S", Err("unknown time unit \"S\", supported units: ns, us/µs, ms, sec, min, hours, days, weeks, months, years (and few variations)")),
        ("10000000000000000000s", Ok((10000000000000000000, 0))),
        ("18446744073709551615s", Ok((18446744073709551615, 0))),
        ("18446744073709551616s", Err("number is too large or cannot be represented without a lack of precision (values below 1ns are not supported)")),
        ("1.5ns", Err("number is too large or cannot be represented without a lack of precision (values below 1ns are not supported)")),
        ("0.0000000001s", Err("number is too large or cannot be represented without a lack of precision (values below 1ns are not supported)")),
        ("1.25us", Ok((0, 1250))),
        ("1.000000001s", Ok((1, 1))),
        ("1 2h", Ok((43200, 0))),
        ("1d2h3m4s", Ok((93784, 0))),
        ("007s", Ok((7, 0))),
        ("1.0M", Ok((2630016, 0))),
        ("0.5d", Ok((43200, 0))),
        ("1e3s", Err("unknown time unit \"e\", supported units: ns, us/µs, ms, sec, min, hours, days, weeks, months, years (and few variations)")),
        ("1_000s", Err("invalid character at 1")),
        ("\u{2003}1s", Ok((1, 0))),
        ("1s\n", Ok((1, 0))),
        ];
        for (s, want) in cases {
            let got = parse_duration(s).map(|d| (d.as_secs(), d.subsec_nanos())).map_err(|e| e.to_string());
            assert_eq!(got, want.map_err(String::from), "{s:?}");
        }
    }

    /// Durations as wicket prints them (`ends in 23h 59m`, `retrying in 500ms`, ...).
    #[test]
    fn durations_print_as_humantime_printed_them() {
        let cases: &[((u64, u32), &str)] = &[
            ((0, 0), "0s"),
            ((1, 0), "1s"),
            ((59, 0), "59s"),
            ((60, 0), "1m"),
            ((61, 0), "1m 1s"),
            ((90, 0), "1m 30s"),
            ((600, 0), "10m"),
            ((1800, 0), "30m"),
            ((3600, 0), "1h"),
            ((3661, 0), "1h 1m 1s"),
            ((86400, 0), "1day"),
            ((90000, 0), "1day 1h"),
            ((604800, 0), "7days"),
            ((2592000, 0), "30days"),
            ((2630016, 0), "1month"),
            ((31557600, 0), "1year"),
            ((63115200, 0), "2years"),
            ((1, 500000000), "1s 500ms"),
            ((0, 1000000), "1ms"),
            ((0, 1000), "1us"),
            ((0, 1), "1ns"),
            ((100000000, 123456789), "3years 2months 18h 39m 28s 123ms 456us 789ns"),
        ];
        for ((s, n), want) in cases {
            assert_eq!(format_duration(Duration::new(*s, *n)).to_string(), *want, "{s}s {n}ns");
        }
    }

    /// Times as wicket prints them (the ledger's, certificates', leases' and snapshots' times).
    #[test]
    fn times_print_as_humantime_printed_them() {
        let cases: &[(u64, &str)] = &[
            (0, "1970-01-01T00:00:00Z"),
            (1, "1970-01-01T00:00:01Z"),
            (951782400, "2000-02-29T00:00:00Z"),
            (1709164800, "2024-02-29T00:00:00Z"),
            (1762974305, "2025-11-12T19:05:05Z"),
            (1794904806, "2026-11-17T08:40:06Z"),
            (4102444800, "2100-01-01T00:00:00Z"),
            (253402300799, "9999-12-31T23:59:59Z"),
        ];
        for (t, want) in cases {
            assert_eq!(format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(*t)).to_string(), *want, "{t}");
        }
    }

    /// `wicket state --at`'s times: what humantime's weak RFC 3339 parser took, and refused.
    #[test]
    fn times_parse_as_humantime_parsed_them() {
        let cases: &[Case] = &[
            ("2026-11-12T19:05:05Z", Ok((1794510305, 0))),
            ("2026-11-12 19:05:05Z", Ok((1794510305, 0))),
            ("2026-11-12T19:05:05", Ok((1794510305, 0))),
            ("2026-11-12T19:05:05+00:00", Ok((1794510305, 0))),
            ("2026-11-12T19:05:05.5Z", Ok((1794510305, 500000000))),
            ("2026-11-12T19:05:05.123456789Z", Ok((1794510305, 123456789))),
            ("2026-11-12T19:05:05.1234567891Z", Ok((1794510305, 123456789))),
            ("2026-11-12T19:05:05.5", Ok((1794510305, 500000000))),
            ("2026-11-12T19:05:05.5+00:00", Ok((1794510305, 500000000))),
            ("2026-02-29T00:00:00Z", Err("numeric component is out of range")),
            ("2024-02-29T00:00:00Z", Ok((1709164800, 0))),
            ("1970-01-01T00:00:00Z", Ok((0, 0))),
            ("1969-12-31T23:59:59Z", Err("numeric component is out of range")),
            ("2026-11-12T24:00:00Z", Err("numeric component is out of range")),
            ("2026-11-12T23:59:60Z", Ok((1794527999, 0))),
            ("2026-11-12", Err("timestamp format is invalid")),
            ("2026-11-12T19:05:05+01:00", Err("timestamp format is invalid")),
            ("2026-11-12T19:05:05.Z", Ok((1794510305, 0))),
            ("2026-11-12t19:05:05Z", Err("timestamp format is invalid")),
            ("2026-13-01T00:00:00Z", Err("numeric component is out of range")),
            ("2026-11-00T00:00:00Z", Err("numeric component is out of range")),
            ("9999-12-31T23:59:59Z", Ok((253402300799, 0))),
            ("2026-11-12T19:05:05ZZ", Ok((1794510305, 0))),
            ("2026-11-12T19:05:05 ", Err("timestamp format is invalid")),
            ("2026-11-12T19:05:05+00:00:00", Err("timestamp format is invalid")),
            ("2026-11-12T19:05:5Z", Err("bad character where digit is expected")),
            ("2026-1x-12T19:05:05Z", Err("bad character where digit is expected")),
        ];
        for (s, want) in cases {
            let got = parse_rfc3339_weak(s)
                .map(|t| t.duration_since(UNIX_EPOCH).unwrap())
                .map(|d| (d.as_secs(), d.subsec_nanos()))
                .map_err(|e| e.to_string());
            assert_eq!(got, want.map_err(String::from), "{s:?}");
        }
    }
}

#[cfg(kani)]
#[path = "proofs/time.rs"]
mod proofs;
