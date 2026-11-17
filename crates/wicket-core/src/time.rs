//! Durations and times as people write and read them (#437): `30m`, `1h 30m`, `24h`, `7d` in
//! manifests, operator files and CLI flags, and `2026-11-12T19:05:05Z` in what wicket prints.
//!
//! The spellings and the output are humantime 2.x's, which wicket used before, kept exactly.

use std::time::{Duration, SystemTime};

pub use humantime::{DurationError, FormattedDuration, Rfc3339Timestamp, TimestampError};

/// A duration: one or more `<number><unit>` terms (`30m`, `1h 30m`, `1.5h`, `250ms`), or `0`.
pub fn parse_duration(s: &str) -> Result<Duration, DurationError> {
    humantime::parse_duration(s)
}

/// A duration as its largest units, `1day 2h 3m` (a month is 30.44 days, a year 365.25).
pub fn format_duration(d: Duration) -> FormattedDuration {
    humantime::format_duration(d)
}

/// A time as `2026-11-12T19:05:05Z` (UTC, whole seconds).
pub fn format_rfc3339_seconds(t: SystemTime) -> Rfc3339Timestamp {
    humantime::format_rfc3339_seconds(t)
}

/// A UTC time written `2026-11-12T19:05:05Z`, with a space for the `T`, without the `Z`, with
/// `+00:00` for it, or with a fraction of a second.
pub fn parse_rfc3339_weak(s: &str) -> Result<SystemTime, TimestampError> {
    humantime::parse_rfc3339_weak(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    /// Every duration spelling wicket takes (the manifests' limits, operator files, `--ttl`,
    /// `--ca-ttl 24h`, `--every`, `--window`, ...), and the edges of the grammar, with what
    /// humantime 2.4 made of each: seconds and nanoseconds, or its error. Generated from humantime
    /// before it was replaced (#437); the replacement must agree byte for byte.
    #[test]
    fn duration_spellings_are_humantime_s() {
        let cases: &[(&str, Result<(u64, u32), &str>)] = &[
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
        let cases: &[(&str, Result<(u64, u32), &str>)] = &[
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
