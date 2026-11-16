//! Windowed egress caps (#368): at most so many requests and bytes through a zone's egress proxy over
//! a sliding window of at most a day, counted per principal (a long-lived agent over all its
//! activations, else the run), never per session, so a box can't reset them by starting again.
//!
//! - **The spec** is `zone.limits.egress: { window, requests, bytes }` ([`EgressSpec`]).
//! - **History** is a [`Ring`] of [`BUCKETS`] fixed buckets over the window: a sum over the last
//!   window that forgets one bucket at a time, in bounded space. The control host keeps it (in the
//!   ledger, by principal) and is its only writer.
//! - **Leases.** A node is leased an [`EgressSlice`]: totals this activation's own counter
//!   ([`EgressUse`], cumulative) may reach before it is sent more. The node refuses past it, so a
//!   node cut off from its control host spends its slice and nothing more (fail closed). The control
//!   host adds what the node reports to the ring and leases the next slice from what the window has
//!   left ([`EgressSlice::next`]), and the rule for when to renew is [`EgressSlice::renewed`]'s.
//!
//! What counts: each request decided and sent upstream is one request; its bytes are its body's sent
//! upstream and its response body's passed back to the box.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The longest window.
pub const MAX_WINDOW: Duration = Duration::from_secs(24 * 3600);

/// Buckets per window: the history's resolution (a 24 h window forgets 24 min at a time).
pub const BUCKETS: u64 = 60;

/// What part of what the window has left a node is leased at a time.
pub const SLICE_FRACTION: f64 = 0.25;

/// `zone.limits.egress`: the caps, over `window`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressSpec {
    /// The sliding window (`1h`, `24h`): at most [`MAX_WINDOW`].
    pub window: String,
    /// Requests sent upstream within the window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<u64>,
    /// Bytes (request and response bodies) within the window: `500m`, `2g`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
}

/// The caps, read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressCaps {
    pub window_secs: u64,
    pub requests: Option<u64>,
    pub bytes: Option<u64>,
}

impl EgressSpec {
    /// The caps, checked: a window of at least [`BUCKETS`] seconds and at most [`MAX_WINDOW`], and
    /// at least one cap, each at least 1.
    pub fn caps(&self) -> Result<EgressCaps, String> {
        let w = humantime::parse_duration(&self.window).map_err(|_| format!("limits.egress.window {:?} is not a duration", self.window))?;
        if w > MAX_WINDOW || w.as_secs() < BUCKETS {
            return Err(format!("limits.egress.window {:?}: between {BUCKETS}s and 24h", self.window));
        }
        let bytes = match &self.bytes {
            None => None,
            Some(b) => Some(
                crate::subset::parse_bytes(b)
                    .filter(|n| *n >= 1)
                    .ok_or_else(|| format!("limits.egress.bytes {b:?}: a positive size (`500m`, `2g`)"))?,
            ),
        };
        if self.requests == Some(0) {
            return Err("limits.egress.requests: at least 1".into());
        }
        if self.requests.is_none() && bytes.is_none() {
            return Err("limits.egress: give requests, bytes or both".into());
        }
        Ok(EgressCaps { window_secs: w.as_secs(), requests: self.requests, bytes })
    }
}

impl EgressCaps {
    /// Whether these caps are no looser than `parent`'s, for a child zone (#368: a child can't
    /// escape its parent's caps by starting a box of its own): every cap the parent has, the child
    /// has, no higher, over a window no shorter. (A child's own counter is its own; its parent's
    /// counter isn't charged for it.)
    pub fn within(&self, parent: &EgressCaps) -> bool {
        let dim = |c: Option<u64>, p: Option<u64>| match (c, p) {
            (_, None) => true,
            (Some(c), Some(p)) => c <= p,
            (None, Some(_)) => false,
        };
        self.window_secs >= parent.window_secs && dim(self.requests, parent.requests) && dim(self.bytes, parent.bytes)
    }
}

/// An activation's own count, cumulative: what its node reports and journals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressUse {
    pub requests: u64,
    pub bytes: u64,
}

impl EgressUse {
    /// What was counted since `base`.
    pub fn since(self, base: EgressUse) -> EgressUse {
        EgressUse { requests: self.requests.saturating_sub(base.requests), bytes: self.bytes.saturating_sub(base.bytes) }
    }
}

/// A window's history: up to [`BUCKETS`] buckets of `bucket_secs` each, by the bucket's index
/// (Unix seconds / `bucket_secs`), oldest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ring {
    pub bucket_secs: u64,
    pub buckets: Vec<(i64, EgressUse)>,
}

impl Ring {
    pub fn new(caps: &EgressCaps) -> Ring {
        Ring { bucket_secs: (caps.window_secs / BUCKETS).max(1), buckets: vec![] }
    }

    fn index(&self, now: i64) -> i64 {
        now.div_euclid(self.bucket_secs.max(1) as i64)
    }

    /// Forgets buckets that have left the window ending at `now`.
    fn prune(&mut self, now: i64) {
        let oldest = self.index(now) - BUCKETS as i64 + 1;
        self.buckets.retain(|(i, _)| *i >= oldest);
    }

    /// Counts `u` at `now`. A time before the newest bucket (a clock that went back) counts in it.
    pub fn add(&mut self, now: i64, u: EgressUse) {
        if u == EgressUse::default() {
            return;
        }
        self.prune(now);
        let i = self.index(now).max(self.buckets.last().map(|b| b.0).unwrap_or(i64::MIN));
        match self.buckets.last_mut() {
            Some((last, b)) if *last == i => {
                b.requests = b.requests.saturating_add(u.requests);
                b.bytes = b.bytes.saturating_add(u.bytes);
            }
            _ => self.buckets.push((i, u)),
        }
    }

    /// What the window ending at `now` holds.
    pub fn total(&self, now: i64) -> EgressUse {
        let oldest = self.index(now) - BUCKETS as i64 + 1;
        self.buckets.iter().filter(|(i, _)| *i >= oldest).fold(EgressUse::default(), |a, (_, b)| EgressUse {
            requests: a.requests.saturating_add(b.requests),
            bytes: a.bytes.saturating_add(b.bytes),
        })
    }

    /// The caps changed (a woken agent's zone was edited): the history is kept, regrouped into the
    /// new bucket size, so a looser window never forgets what was counted.
    pub fn resized(self, caps: &EgressCaps, now: i64) -> Ring {
        let mut r = Ring::new(caps);
        if r.bucket_secs == self.bucket_secs {
            r.buckets = self.buckets;
            r.prune(now);
            return r;
        }
        // Everything still in the old window is put in the newest bucket: counted for longer,
        // never shorter.
        let kept = self.total(now);
        r.add(now, kept);
        r
    }
}

/// What a node may count up to, of its activation's own cumulative counter, before it is sent more.
/// None in a dimension: that dimension isn't capped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressSlice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

impl EgressSlice {
    /// The slice to lease next: what the activation has counted (`used`) plus `fraction` of what the
    /// window has left after it (`history`, which `used` has already been added to), at least one
    /// request's worth while anything is left, and never more than is left.
    pub fn next(caps: &EgressCaps, history: &Ring, now: i64, used: EgressUse, fraction: f64) -> EgressSlice {
        let t = history.total(now);
        let part = |cap: u64, spent: u64| {
            let left = cap.saturating_sub(spent);
            let p = ((left as f64) * fraction.clamp(0.0, 1.0)) as u64;
            if left > 0 {
                p.max(1).min(left)
            } else {
                0
            }
        };
        EgressSlice {
            requests: caps.requests.map(|c| used.requests.saturating_add(part(c, t.requests))),
            bytes: caps.bytes.map(|c| used.bytes.saturating_add(part(c, t.bytes))),
        }
    }

    /// Whether one more request fits: one request, and some of the byte allowance left.
    pub fn admits(&self, used: EgressUse) -> Result<(), &'static str> {
        if self.requests.is_some_and(|r| used.requests >= r) {
            return Err("requests");
        }
        if self.bytes.is_some_and(|b| used.bytes >= b) {
            return Err("bytes");
        }
        Ok(())
    }

    /// How many more bytes fit (None: uncapped).
    pub fn bytes_left(&self, used: EgressUse) -> Option<u64> {
        self.bytes.map(|b| b.saturating_sub(used.bytes))
    }

    /// The slice to hold next, given the one held (`cur`, None before the first) and the control
    /// host's [`EgressSlice::next`]: `cur` until less than half of it is left in a dimension, or
    /// `next` is lower; else `next`. Few, larger messages, as [`crate::budget::Slice::renewed`].
    pub fn renewed(cur: Option<EgressSlice>, next: EgressSlice, used: EgressUse) -> EgressSlice {
        let low = |c: Option<u64>, n: Option<u64>, u: u64| match (c, n) {
            (Some(c), Some(n)) => n < c || u128::from(c.saturating_sub(u)) * 2 < u128::from(n.saturating_sub(u)),
            (None, None) => false,
            _ => true,
        };
        match cur {
            Some(c) if !low(c.requests, next.requests, used.requests) && !low(c.bytes, next.bytes, used.bytes) => c,
            _ => next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(window: &str, requests: Option<u64>, bytes: Option<&str>) -> EgressSpec {
        EgressSpec { window: window.into(), requests, bytes: bytes.map(String::from) }
    }

    #[test]
    fn a_spec_is_checked() {
        let c = spec("1h", Some(100), Some("1m")).caps().unwrap();
        assert_eq!(c, EgressCaps { window_secs: 3600, requests: Some(100), bytes: Some(1 << 20) });
        for bad in [
            spec("25h", Some(1), None),
            spec("10s", Some(1), None),
            spec("1h", None, None),
            spec("1h", Some(0), None),
            spec("1h", None, Some("0")),
            spec("soon", Some(1), None),
        ] {
            assert!(bad.caps().is_err(), "{bad:?}");
        }
        assert!(spec("24h", None, Some("2g")).caps().is_ok());
    }

    #[test]
    fn a_child_is_never_looser() {
        let p = spec("1h", Some(100), Some("1m")).caps().unwrap();
        assert!(spec("1h", Some(10), Some("1k")).caps().unwrap().within(&p));
        assert!(spec("2h", Some(100), Some("1m")).caps().unwrap().within(&p), "a longer window is tighter");
        assert!(!spec("30m", Some(10), Some("1k")).caps().unwrap().within(&p), "a shorter window forgets sooner");
        assert!(!spec("1h", Some(101), Some("1m")).caps().unwrap().within(&p));
        assert!(!spec("1h", Some(10), None).caps().unwrap().within(&p), "no byte cap is looser");
        let req_only = spec("1h", Some(100), None).caps().unwrap();
        assert!(spec("1h", Some(50), Some("1g")).caps().unwrap().within(&req_only));
    }

    #[test]
    fn the_window_slides_and_stays_bounded() {
        let caps = spec("1h", Some(100), None).caps().unwrap();
        let mut r = Ring::new(&caps);
        assert_eq!(r.bucket_secs, 60);
        let t0 = 1_000_000 * 60;
        r.add(t0, EgressUse { requests: 10, bytes: 5 });
        r.add(t0 + 30, EgressUse { requests: 1, bytes: 0 });
        assert_eq!(r.buckets.len(), 1, "one bucket a minute");
        r.add(t0 + 1800, EgressUse { requests: 5, bytes: 0 });
        assert_eq!(r.total(t0 + 1800).requests, 16);
        // An hour after the first bucket, it has left the window; the later one hasn't.
        assert_eq!(r.total(t0 + 3600).requests, 5);
        assert_eq!(r.total(t0 + 1800 + 3600).requests, 0);
        // A day of a request a second: never more than BUCKETS buckets.
        for s in 0..86_400 {
            r.add(t0 + s, EgressUse { requests: 1, bytes: 1 });
        }
        assert!(r.buckets.len() as u64 <= BUCKETS);
        assert_eq!(r.total(t0 + 86_399).requests, 3600);
        // A clock that goes back counts in the newest bucket, never in a forgotten one.
        r.add(t0, EgressUse { requests: 7, bytes: 0 });
        assert_eq!(r.total(t0 + 86_399).requests, 3607);
    }

    #[test]
    fn slices_never_exceed_what_is_left_and_renew_rarely() {
        let caps = spec("1h", Some(100), Some("1000")).caps().unwrap();
        let mut h = Ring::new(&caps);
        let now = 7_200;
        let s = EgressSlice::next(&caps, &h, now, EgressUse::default(), SLICE_FRACTION);
        assert_eq!(s, EgressSlice { requests: Some(25), bytes: Some(250) });
        assert!(s.admits(EgressUse { requests: 24, bytes: 249 }).is_ok());
        assert_eq!(s.admits(EgressUse { requests: 25, bytes: 0 }), Err("requests"));
        assert_eq!(s.admits(EgressUse { requests: 0, bytes: 250 }), Err("bytes"));
        // The node used 20 requests; the window holds them: the next slice is 20 + a quarter of 80.
        let used = EgressUse { requests: 20, bytes: 100 };
        h.add(now, used);
        let n = EgressSlice::next(&caps, &h, now, used, SLICE_FRACTION);
        assert_eq!(n, EgressSlice { requests: Some(40), bytes: Some(325) });
        // Kept while more than half of it is left; renewed once it runs low.
        assert_eq!(EgressSlice::renewed(Some(s), n, EgressUse { requests: 5, bytes: 10 }), s);
        assert_eq!(EgressSlice::renewed(Some(s), n, used), n);
        // Spent: nothing more, even as a fraction.
        let mut full = Ring::new(&caps);
        full.add(now, EgressUse { requests: 100, bytes: 1000 });
        let z = EgressSlice::next(&caps, &full, now, EgressUse { requests: 100, bytes: 1000 }, SLICE_FRACTION);
        assert_eq!(z, EgressSlice { requests: Some(100), bytes: Some(1000) });
        assert!(z.admits(EgressUse { requests: 100, bytes: 1000 }).is_err());
        // One request left: it is leased, not rounded away.
        let mut one = Ring::new(&caps);
        one.add(now, EgressUse { requests: 99, bytes: 0 });
        assert_eq!(EgressSlice::next(&caps, &one, now, EgressUse::default(), SLICE_FRACTION).requests, Some(1));
        // An hour later the window has room again.
        assert_eq!(
            EgressSlice::next(&caps, &full, now + 3600, EgressUse { requests: 100, bytes: 1000 }, SLICE_FRACTION).requests,
            Some(125)
        );
    }

    #[test]
    fn a_resized_ring_never_forgets_sooner() {
        let one = spec("1h", Some(100), None).caps().unwrap();
        let day = spec("24h", Some(100), None).caps().unwrap();
        let mut r = Ring::new(&one);
        r.add(3600 * 100, EgressUse { requests: 30, bytes: 0 });
        let r = r.resized(&day, 3600 * 100 + 600);
        assert_eq!(r.bucket_secs, 1440);
        assert_eq!(r.total(3600 * 100 + 600).requests, 30);
        assert_eq!(r.total(3600 * 100 + 600 + 84_000).requests, 30, "kept for the new, longer window");
    }
}
