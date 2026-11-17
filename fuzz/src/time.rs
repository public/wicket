//! Target 10: durations and times as people write them (`wicket_core::time`, #437). Manifests carry
//! durations (`limits.timeout`, `exit_grace`, `authority`), and an agent writes its children's
//! manifests, so `parse_duration` sees an agent's text; `parse_rfc3339_weak` reads `--at` and
//! operator files. The input is tried whole as a duration and as a time; its first eight bytes are
//! also read as a duration's seconds and a time's.
//!
//! The oracle, besides panics:
//! - a duration that parses prints (`format_duration`) as a duration that parses back to itself;
//!   so does any duration;
//! - parsing ignores whitespace around a duration's terms (`"1h 30m"` and `"  1h 30m "` agree),
//!   except for `"0"`, which only parses alone;
//! - a time that parses is before year 10000, and prints (`format_rfc3339_seconds`) as a time that
//!   parses back to the same second; so does any second before year 10000, and that print is in
//!   RFC 3339's form, `YYYY-MM-DDTHH:MM:SSZ`.

use std::time::{Duration, UNIX_EPOCH};
use wicket_core::time::{format_duration, format_rfc3339_seconds, parse_duration, parse_rfc3339_weak};

/// The first second of year 10000.
const YEAR_10000: u64 = 253_402_300_800;

pub fn run(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        duration(s);
        time(s);
    }
    let mut first = [0u8; 8];
    let n = data.len().min(8);
    first[..n].copy_from_slice(&data[..n]);
    let x = u64::from_le_bytes(first);
    let nanos = data.get(8..12).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) % 1_000_000_000);
    round_trip_duration(Duration::new(x, nanos));
    round_trip_time(x % YEAR_10000);
}

fn duration(s: &str) {
    let Ok(d) = parse_duration(s) else { return };
    round_trip_duration(d);
    if s != "0" {
        let padded = format!("  {s}\t ");
        assert_eq!(parse_duration(&padded).ok(), Some(d), "{s:?} parses as {d:?}, {padded:?} doesn't");
    }
}

fn round_trip_duration(d: Duration) {
    let printed = format_duration(d).to_string();
    assert_eq!(parse_duration(&printed).ok(), Some(d), "{d:?} prints as {printed:?}, which doesn't parse back to it");
}

fn time(s: &str) {
    let Ok(t) = parse_rfc3339_weak(s) else { return };
    let since = t.duration_since(UNIX_EPOCH).unwrap_or_else(|_| panic!("{s:?} parsed to a time before 1970"));
    assert!(since.as_secs() < YEAR_10000, "{s:?} parsed past year 9999");
    round_trip_time(since.as_secs());
}

fn round_trip_time(secs: u64) {
    let printed = format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(secs)).to_string();
    let b = printed.as_bytes();
    let form = b.len() == 20
        && b.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        });
    assert!(form, "{secs} prints as {printed:?}, not YYYY-MM-DDTHH:MM:SSZ");
    let back = parse_rfc3339_weak(&printed).map(|t| t.duration_since(UNIX_EPOCH).unwrap());
    assert_eq!(back, Ok(Duration::from_secs(secs)), "{secs} prints as {printed:?}, which doesn't parse back to it");
}
