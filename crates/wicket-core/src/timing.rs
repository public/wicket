//! Where a box start's time goes (#287): named spans on one monotonic clock, kept with the run's
//! record (`ctl/run.json`) and printed with `WICKET_TIMINGS=1`.
//!
//! A span is two `Instant`s and a name pushed onto a list behind a mutex: no I/O and no allocation
//! beyond the name, so recording is always on. Spans another process measured (the node's, on its
//! own clock) are taken in with [`Timings::nest`], placed from an instant of this clock (when the
//! request that started them was sent), so they line up up to the channel's one-way latency.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

/// One timed step: `at_ms` after the start of whatever recorded it, lasting `ms` (0: a moment, such
/// as the box's first output).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Span {
    pub name: String,
    pub at_ms: f64,
    pub ms: f64,
}

/// The spans of one box start, on the clock of whoever records them.
#[derive(Debug)]
pub struct Timings {
    origin: Instant,
    /// The wall clock at `origin`: what timestamps from elsewhere (Docker's, a node's) are placed by.
    origin_wall: SystemTime,
    spans: Mutex<Vec<Span>>,
}

impl Default for Timings {
    fn default() -> Self {
        Timings::new()
    }
}

/// Whether `WICKET_TIMINGS=1` asks for the timings to be printed (they are recorded either way).
pub fn enabled() -> bool {
    std::env::var("WICKET_TIMINGS").is_ok_and(|v| v == "1")
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Milliseconds from `a` to `b` on the wall clock, negative if `b` is earlier.
fn wall_ms(a: SystemTime, b: SystemTime) -> f64 {
    match b.duration_since(a) {
        Ok(d) => ms(d),
        Err(e) => -ms(e.duration()),
    }
}

impl Timings {
    pub fn new() -> Timings {
        Timings { origin: Instant::now(), origin_wall: SystemTime::now(), spans: Mutex::new(Vec::new()) }
    }

    /// Where this clock starts.
    pub fn origin(&self) -> Instant {
        self.origin
    }

    fn push(&self, s: Span) {
        if let Ok(mut v) = self.spans.lock() {
            v.push(s);
        }
    }

    fn offset(&self, t: Instant) -> f64 {
        ms(t.saturating_duration_since(self.origin))
    }

    /// A span from `from` to `to`.
    pub fn record(&self, name: impl Into<String>, from: Instant, to: Instant) {
        self.push(Span { name: name.into(), at_ms: self.offset(from), ms: ms(to.saturating_duration_since(from)) });
    }

    /// A span from `from` to now.
    pub fn since(&self, name: impl Into<String>, from: Instant) {
        self.record(name, from, Instant::now());
    }

    /// A span from now until the returned guard is dropped.
    pub fn span(&self, name: impl Into<String>) -> SpanGuard<'_> {
        SpanGuard { t: self, name: Some(name.into()), from: Instant::now() }
    }

    /// A moment: now.
    pub fn mark(&self, name: impl Into<String>) {
        let now = Instant::now();
        self.record(name, now, now);
    }

    /// A span between two wall-clock times (Docker's timestamps, another host's), placed by this
    /// clock's own wall time at its origin.
    pub fn record_wall(&self, name: impl Into<String>, from: SystemTime, to: SystemTime) {
        self.push(Span { name: name.into(), at_ms: wall_ms(self.origin_wall, from), ms: wall_ms(from, to).max(0.0) });
    }

    /// A moment given as Unix milliseconds.
    pub fn mark_unix_ms(&self, name: impl Into<String>, unix_ms: i64) {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(u64::try_from(unix_ms).unwrap_or(0));
        self.record_wall(name, t, t);
    }

    /// Whether a span of this name has been recorded.
    pub fn has(&self, name: &str) -> bool {
        self.spans.lock().map(|v| v.iter().any(|s| s.name == name)).unwrap_or(false)
    }

    /// Takes in spans measured elsewhere (on another clock, from when it was asked), each named
    /// `prefix` + its own name and placed from `base` on this clock.
    pub fn nest(&self, prefix: &str, base: Instant, spans: &[Span]) {
        let b = self.offset(base);
        for s in spans {
            self.push(Span { name: format!("{prefix}{}", s.name), at_ms: b + s.at_ms, ms: s.ms });
        }
    }

    /// Every span so far, in the order they started.
    pub fn spans(&self) -> Vec<Span> {
        let mut v = self.spans.lock().map(|v| v.clone()).unwrap_or_default();
        v.sort_by(|a, b| a.at_ms.total_cmp(&b.at_ms));
        v
    }
}

/// Records its span when dropped ([`Timings::span`]).
pub struct SpanGuard<'a> {
    t: &'a Timings,
    name: Option<String>,
    from: Instant,
}

impl SpanGuard<'_> {
    /// Ends the span now (as dropping it does).
    pub fn end(self) {}
}

impl Drop for SpanGuard<'_> {
    fn drop(&mut self) {
        if let Some(n) = self.name.take() {
            self.t.since(n, self.from);
        }
    }
}

/// The spans as a table: when each started, how long it took, and its name, indented by how many
/// `.`-separated parts it has past the first (`node.docker.run` under `node`).
pub fn table(spans: &[Span]) -> String {
    let mut out = format!("{:>9}  {:>9}  span\n", "at ms", "ms");
    for s in spans {
        let depth = s.name.split('.').count().saturating_sub(1).min(4);
        out.push_str(&format!("{:>9.1}  {:>9.1}  {}{}\n", s.at_ms, s.ms, "  ".repeat(depth), s.name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn spans_record_their_start_and_length_on_one_clock() {
        let t = Timings::new();
        let a = t.origin() + Duration::from_millis(5);
        t.record("b", a + Duration::from_millis(10), a + Duration::from_millis(30));
        t.record("a", a, a + Duration::from_millis(2));
        let s = t.spans();
        assert_eq!(s.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["a", "b"], "in the order they started");
        assert!((s[0].at_ms - 5.0).abs() < 1e-6 && (s[0].ms - 2.0).abs() < 1e-6);
        assert!((s[1].at_ms - 15.0).abs() < 1e-6 && (s[1].ms - 20.0).abs() < 1e-6);
        // An end before its start is no time, not a negative one.
        t.record("c", a + Duration::from_millis(3), a);
        assert_eq!(t.spans().iter().find(|s| s.name == "c").unwrap().ms, 0.0);
    }

    #[test]
    fn a_guard_records_when_dropped_and_a_mark_takes_no_time() {
        let t = Timings::new();
        {
            let _g = t.span("held");
            std::thread::sleep(Duration::from_millis(2));
        }
        t.span("ended").end();
        t.mark("moment");
        let s = t.spans();
        let held = s.iter().find(|s| s.name == "held").unwrap();
        assert!(held.ms >= 2.0, "{held:?}");
        assert!(t.has("ended") && t.has("moment") && !t.has("other"));
        assert_eq!(s.iter().find(|s| s.name == "moment").unwrap().ms, 0.0);
    }

    #[test]
    fn spans_from_another_clock_nest_under_a_prefix_from_a_base() {
        let t = Timings::new();
        let base = t.origin() + Duration::from_millis(100);
        let theirs = [Span { name: "docker.run".into(), at_ms: 4.0, ms: 50.0 }, Span { name: "total".into(), at_ms: 0.0, ms: 60.0 }];
        t.nest("node.", base, &theirs);
        let s = t.spans();
        assert_eq!(s[0], Span { name: "node.total".into(), at_ms: 100.0, ms: 60.0 });
        assert_eq!(s[1], Span { name: "node.docker.run".into(), at_ms: 104.0, ms: 50.0 });
    }

    #[test]
    fn wall_clock_spans_are_placed_by_the_origins_wall_time() {
        let t = Timings::new();
        let w = t.origin_wall;
        t.record_wall("runtime", w + Duration::from_millis(7), w + Duration::from_millis(19));
        t.record_wall("before", w - Duration::from_millis(3), w - Duration::from_millis(1));
        let unix = wall_ms(SystemTime::UNIX_EPOCH, w) as i64 + 40;
        t.mark_unix_ms("first", unix);
        let s = t.spans();
        let get = |n: &str| s.iter().find(|s| s.name == n).unwrap().clone();
        assert!((get("runtime").at_ms - 7.0).abs() < 1e-6 && (get("runtime").ms - 12.0).abs() < 1e-6);
        assert!((get("before").at_ms + 3.0).abs() < 1e-6, "earlier than the origin: negative");
        assert!((get("first").at_ms - 40.0).abs() < 1.0 && get("first").ms == 0.0);
    }

    #[test]
    fn spans_round_trip_through_json_and_print_as_a_table() {
        let s = vec![Span { name: "node".into(), at_ms: 1.0, ms: 2.5 }, Span { name: "node.docker.run".into(), at_ms: 1.5, ms: 2.0 }];
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Vec<Span>>(&j).unwrap(), s);
        let tab = table(&s);
        assert!(tab.lines().next().unwrap().contains("span"));
        assert!(tab.contains("      1.0        2.5  node\n"), "{tab}");
        assert!(tab.contains("      1.5        2.0      node.docker.run\n"), "{tab}");
    }
}
