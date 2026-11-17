//! A run's model budget (#152, #256): what its model proxy has counted, what it has carved out for
//! its children, and the slices of it sent to its node, kept in one [`Counter`] that the proxy's
//! calls, a spawn's carve-out and the node's `Spent` reports share across threads.
//!
//! The counter's atomics are std's, or loom's under `cfg(loom)` (#325:
//! `RUSTFLAGS="--cfg loom" cargo test -p wicket-core --test loom_budget`), which explores every
//! interleaving of the critical sections. The arithmetic is checked by Kani (`proofs/budget.rs`):
//! nothing overflows, a slice never exceeds what is left, and a carve-out never takes a run past its
//! budget.
//!
//! Concurrent claims on one budget (a model request, a call's output reservation, a spawn's
//! carve-out) are each checked and made under one lock, [`Counter`]'s `claims`: of two racing for
//! the last of a budget, one goes first and the other sees it. What only raises counts after the
//! fact (a node's `Spent` merged, a call settled) takes no lock. (#325 first had each claim add and
//! then check, lock-free; loom, which models `SeqCst` as acquire/release, found both claims of a
//! race succeeding, and correctness that rests on the hardware's store order is not worth it.)

#[cfg(loom)]
use loom::sync::{
    atomic::{AtomicU64, Ordering::SeqCst},
    Mutex, MutexGuard,
};
#[cfg(not(loom))]
use std::sync::{
    atomic::{AtomicU64, Ordering::SeqCst},
    Mutex, MutexGuard,
};

/// A run's model budget, as its model proxy enforces it (#256): the limits every check reads, and
/// the only ones. On the control host they are the amounts of the run's live quota grants
/// (`model.requests`, `model.output_tokens`, `model.input_tokens`); on a node, its token's zone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModelQuota {
    pub requests: u64,
    pub output_tokens: u64,
    /// Input tokens, cached ones included; None: uncapped.
    pub input_tokens: Option<u64>,
}

impl ModelQuota {
    /// The budget a zone states.
    pub fn of_zone(l: &crate::manifest::LlmSpec) -> ModelQuota {
        ModelQuota { requests: l.max_requests, output_tokens: l.max_output_tokens, input_tokens: l.max_input_tokens }
    }
}

/// A budget slice sent to a node (#152): this activation may count up to these totals of its own
/// (requests; output tokens, in flight included; input tokens, cached ones included) before the
/// control host sends it more. Offline, the node spends its current slice and nothing more.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Slice {
    pub requests: u64,
    pub output_tokens: u64,
    #[serde(default)]
    pub input_tokens: Option<u64>,
}

impl Slice {
    /// `self`, counted from `base` instead of from zero: a slice the control host works out from
    /// what it counted since its node's report `base`, in the node's own counts (#422). A
    /// re-attached supervisor counts the node's spend from its first report (`noderun`'s
    /// `spent_base`), and a node holding a slice below its own count can't spend.
    pub fn offset(self, base: Spent) -> Slice {
        Slice {
            requests: self.requests.saturating_add(base.requests),
            output_tokens: self.output_tokens.saturating_add(base.output_tokens),
            input_tokens: self.input_tokens.map(|i| i.saturating_add(base.input_total())),
        }
    }

    /// [`Slice::renewed`] in the node's counts, for a control host that counts the node's spend
    /// since its report `base` (zero for one that counts it all): `next`, `spent` and `input_total`
    /// are the control host's, `cur` and the result the node's.
    pub fn renewed_from(cur: Option<Slice>, next: Slice, spent: Spent, input_total: u64, base: Spent) -> Slice {
        Slice::renewed(cur, next.offset(base), spent.plus(base), input_total.saturating_add(base.input_total()))
    }

    /// The slice to send a node next (#152), given the one it holds (`cur`, None before the first),
    /// the control host's [`Counter::next_slice`], what it has counted (`spent`, and `input_total`
    /// with cached tokens): `cur` until less than half a slice of it is left, else `next`; and
    /// `next` at once if it is lower than `cur` (what is left of the budget shrank, a spawn's
    /// carve-out). The control host's rule (`noderun::slice_due`), here so the simulation (#324)
    /// runs the same one.
    pub fn renewed(cur: Option<Slice>, next: Slice, spent: Spent, input_total: u64) -> Slice {
        // Twice what is left, in u128: a slice of more than half of u64::MAX can't overflow (#325).
        let low = |cap: u64, next_cap: u64, used: u64| u128::from(cap.saturating_sub(used)) * 2 < u128::from(next_cap.saturating_sub(used));
        match cur {
            Some(cur)
                if !low(cur.requests, next.requests, spent.requests)
                    && !low(cur.output_tokens, next.output_tokens, spent.output_tokens)
                    && !matches!((cur.input_tokens, next.input_tokens), (Some(c), Some(n)) if low(c, n, input_total))
                    && cur.requests <= next.requests
                    && cur.output_tokens <= next.output_tokens
                    && cur.input_tokens.zip(next.input_tokens).is_none_or(|(c, n)| c <= n) =>
            {
                cur
            }
            _ => next,
        }
    }
}

/// What a run's model proxy has counted, as a node reports it to its control host (#152).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Spent {
    pub requests: u64,
    pub input_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_tokens: u64,
    pub output_tokens: u64,
}

impl Spent {
    /// Its input tokens, cached ones included.
    pub fn input_total(&self) -> u64 {
        sum(&[self.input_tokens, self.cache_read_tokens, self.cache_creation_tokens])
    }

    /// `self` and `base` added up, saturating: what was counted since `base`, as counted from zero.
    pub fn plus(self, base: Spent) -> Spent {
        Spent {
            requests: self.requests.saturating_add(base.requests),
            input_tokens: self.input_tokens.saturating_add(base.input_tokens),
            cache_read_tokens: self.cache_read_tokens.saturating_add(base.cache_read_tokens),
            cache_creation_tokens: self.cache_creation_tokens.saturating_add(base.cache_creation_tokens),
            output_tokens: self.output_tokens.saturating_add(base.output_tokens),
        }
    }

    /// What was counted since `base`.
    pub fn since(self, base: Spent) -> Spent {
        Spent {
            requests: self.requests.saturating_sub(base.requests),
            input_tokens: self.input_tokens.saturating_sub(base.input_tokens),
            cache_read_tokens: self.cache_read_tokens.saturating_sub(base.cache_read_tokens),
            cache_creation_tokens: self.cache_creation_tokens.saturating_sub(base.cache_creation_tokens),
            output_tokens: self.output_tokens.saturating_sub(base.output_tokens),
        }
    }
}

/// What a [`Counter`] holds at one moment, each counter read once: every figure derived from one
/// `Counts` agrees with the others (#325: [`Counter::next_slice`] read `requests` twice, and a
/// `Spent` merged in between sent a node more than was left).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub requests: u64,
    /// Input tokens, cached ones included.
    pub input_total: u64,
    pub output_tokens: u64,
    pub reserved_requests: u64,
    pub reserved_output_tokens: u64,
    pub reserved_input_tokens: u64,
    pub prior_requests: u64,
    pub prior_input_tokens: u64,
    pub prior_output_tokens: u64,
    pub inflight_output_tokens: u64,
}

/// A sum that saturates: a count that would pass `u64::MAX` counts as all of any budget.
fn sum(parts: &[u64]) -> u64 {
    parts.iter().fold(0, |a: u64, &b| a.saturating_add(b))
}

/// Whether `parts` add up to more than `max`, exactly (in `u128`: no sum saturates to fit).
fn over(parts: &[u64], max: u64) -> bool {
    parts.iter().map(|&p| u128::from(p)).sum::<u128>() > u128::from(max)
}

impl Counts {
    /// Requests counted (refused ones included), handed to children and made by earlier activations.
    pub fn requests_committed(&self) -> u64 {
        sum(&[self.requests, self.reserved_requests, self.prior_requests])
    }

    /// Output tokens spent, handed to children, spent by earlier activations, or reserved by calls
    /// in flight: what is no longer available to a new call.
    pub fn output_committed(&self) -> u64 {
        sum(&[self.output_tokens, self.reserved_output_tokens, self.prior_output_tokens, self.inflight_output_tokens])
    }

    /// Input tokens (cached ones included) used, handed to children or used by earlier activations.
    pub fn input_committed(&self) -> u64 {
        sum(&[self.input_total, self.reserved_input_tokens, self.prior_input_tokens])
    }

    /// Model requests and output tokens left to spend or hand on.
    pub fn remaining(&self, q: ModelQuota) -> (u64, u64) {
        (q.requests.saturating_sub(self.requests_committed()), q.output_tokens.saturating_sub(self.output_committed()))
    }

    /// Input tokens left to spend or hand on, if the budget caps them.
    pub fn remaining_input(&self, q: ModelQuota) -> Option<u64> {
        Some(q.input_tokens?.saturating_sub(self.input_committed()))
    }

    /// The slice to send next: what this activation has counted plus `part` of each limit, never
    /// past what is left. `part(max)` is the share of `max` a slice adds (any value: Kani checks
    /// every one).
    pub fn slice(&self, q: ModelQuota, part: impl Fn(u64) -> u64) -> Slice {
        let (left_r, left_o) = self.remaining(q);
        Slice {
            requests: self.requests + left_r.min(part(q.requests)),
            output_tokens: self.output_tokens + left_o.min(part(q.output_tokens)),
            input_tokens: q.input_tokens.map(|m| self.input_total + self.remaining_input(q).unwrap_or(0).min(part(m))),
        }
    }
}

/// `fraction` of `max`, rounded up, at least 1: a slice's share of a limit.
pub fn part(max: u64, fraction: f64) -> u64 {
    ((max as f64) * fraction).ceil().max(1.0) as u64
}

/// Why a carve-out was refused: the budget it would have gone past.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Short {
    Requests,
    OutputTokens,
    InputTokens,
}

impl std::fmt::Display for Short {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Short::Requests => "model requests",
            Short::OutputTokens => "output tokens",
            Short::InputTokens => "input tokens",
        })
    }
}

/// A run's model budget counters, shared by its model proxy's calls, its spawns' carve-outs and its
/// node's `Spent` reports. Counters only go up, except a claim given back.
#[derive(Default)]
pub struct Counter {
    /// Held while a claim is checked and made (see the module's documentation).
    claims: Mutex<()>,
    pub requests: AtomicU64,
    /// Uncached input tokens.
    pub input_tokens: AtomicU64,
    pub cache_read_tokens: AtomicU64,
    pub cache_creation_tokens: AtomicU64,
    pub output_tokens: AtomicU64,
    /// Handed to children (#11): carved out of this run's budget.
    pub reserved_requests: AtomicU64,
    pub reserved_output_tokens: AtomicU64,
    pub reserved_input_tokens: AtomicU64,
    /// Spent by the agent's earlier activations (#70).
    pub prior_requests: AtomicU64,
    pub prior_input_tokens: AtomicU64,
    pub prior_output_tokens: AtomicU64,
    /// Output tokens reserved by calls in flight (their `max_tokens`, at most what is left).
    pub inflight_output_tokens: AtomicU64,
}

/// Adds `v` to `a`, saturating; returns what was added.
fn add_sat(a: &AtomicU64, v: u64) -> u64 {
    let mut cur = a.load(SeqCst);
    loop {
        let next = cur.saturating_add(v);
        match a.compare_exchange(cur, next, SeqCst, SeqCst) {
            Ok(_) => return next - cur,
            Err(now) => cur = now,
        }
    }
}

/// Takes `v` from `a`, saturating at 0.
fn sub_sat(a: &AtomicU64, v: u64) {
    let mut cur = a.load(SeqCst);
    while let Err(now) = a.compare_exchange(cur, cur.saturating_sub(v), SeqCst, SeqCst) {
        cur = now;
    }
}

impl std::fmt::Debug for Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Counter").field(&self.counts()).finish()
    }
}

impl Counter {
    /// Held while a claim is checked and made. A panic elsewhere while it was held leaves the
    /// counters consistent (each is one atomic), so a poisoned lock is still taken.
    fn claim(&self) -> MutexGuard<'_, ()> {
        self.claims.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every counter, each read once.
    pub fn counts(&self) -> Counts {
        Counts {
            requests: self.requests.load(SeqCst),
            input_total: self.input_total(),
            output_tokens: self.output_tokens.load(SeqCst),
            reserved_requests: self.reserved_requests.load(SeqCst),
            reserved_output_tokens: self.reserved_output_tokens.load(SeqCst),
            reserved_input_tokens: self.reserved_input_tokens.load(SeqCst),
            prior_requests: self.prior_requests.load(SeqCst),
            prior_input_tokens: self.prior_input_tokens.load(SeqCst),
            prior_output_tokens: self.prior_output_tokens.load(SeqCst),
            inflight_output_tokens: self.inflight_output_tokens.load(SeqCst),
        }
    }

    /// What this activation has counted itself.
    pub fn spent(&self) -> Spent {
        Spent {
            requests: self.requests.load(SeqCst),
            input_tokens: self.input_tokens.load(SeqCst),
            cache_read_tokens: self.cache_read_tokens.load(SeqCst),
            cache_creation_tokens: self.cache_creation_tokens.load(SeqCst),
            output_tokens: self.output_tokens.load(SeqCst),
        }
    }

    /// As [`Counter::spent`], with the output tokens reserved by calls in flight charged in full:
    /// what a node persists (#324).
    pub fn spent_charged(&self) -> Spent {
        let mut s = self.spent();
        s.output_tokens = s.output_tokens.saturating_add(self.inflight_output_tokens.load(SeqCst));
        s
    }

    /// Every input token this activation's calls used: uncached, cache reads and cache writes.
    pub fn input_total(&self) -> u64 {
        sum(&[self.input_tokens.load(SeqCst), self.cache_read_tokens.load(SeqCst), self.cache_creation_tokens.load(SeqCst)])
    }

    /// Takes in what another counter of this activation has seen (#152): the run's node, which
    /// calls the model itself and is the counter of record. Counters only go up.
    pub fn merge_spent(&self, s: Spent) {
        self.requests.fetch_max(s.requests, SeqCst);
        self.input_tokens.fetch_max(s.input_tokens, SeqCst);
        self.cache_read_tokens.fetch_max(s.cache_read_tokens, SeqCst);
        self.cache_creation_tokens.fetch_max(s.cache_creation_tokens, SeqCst);
        self.output_tokens.fetch_max(s.output_tokens, SeqCst);
    }

    /// The slice this activation's node may be sent next (#152): what it has counted plus `fraction` of
    /// the budget, never past what is left of it. From one [`Counts`].
    pub fn next_slice(&self, q: ModelQuota, fraction: f64) -> Slice {
        self.counts().slice(q, |max| part(max, fraction))
    }

    /// Counts one model request, and returns the requests committed with it: the request may go if
    /// that is within the budget (a refused one stays counted).
    pub fn admit_request(&self) -> u64 {
        let _claim = self.claim();
        add_sat(&self.requests, 1);
        self.counts().requests_committed()
    }

    /// Reserves up to `want` output tokens for one call, within `max` committed: what is left, if
    /// less. None when nothing is left. Under the claims lock: a carve-out racing it can't also take
    /// the same tokens.
    pub fn reserve_output(&self, max: u64, want: u64) -> Option<u64> {
        let _claim = self.claim();
        let left = max.saturating_sub(self.counts().output_committed());
        if left == 0 {
            return None;
        }
        Some(add_sat(&self.inflight_output_tokens, want.min(left)))
    }

    /// Settles a call's reservation: releases it and charges what the call used.
    pub fn settle(&self, reserved: u64, input: u64, cache_read: u64, cache_creation: u64, output: u64) {
        sub_sat(&self.inflight_output_tokens, reserved);
        add_sat(&self.input_tokens, input);
        add_sat(&self.cache_read_tokens, cache_read);
        add_sat(&self.cache_creation_tokens, cache_creation);
        add_sat(&self.output_tokens, output);
    }

    /// Carves `child` out of this run's budget `q` for a child it starts (#11, #256), if it still
    /// fits: else says which limit it would pass, and carves nothing. The budget a spawn checked
    /// earlier (`subset::check`) may have been spent since; this is the check that holds.
    pub fn carve(&self, q: ModelQuota, child: ModelQuota) -> Result<(), Short> {
        let _claim = self.claim();
        let c = self.counts();
        // Exact sums (`over`): a count saturated at u64::MAX can't make a carve-out fit.
        if over(&[c.requests, c.reserved_requests, c.prior_requests, child.requests], q.requests) {
            return Err(Short::Requests);
        }
        let output = [c.output_tokens, c.reserved_output_tokens, c.prior_output_tokens, c.inflight_output_tokens, child.output_tokens];
        if over(&output, q.output_tokens) {
            return Err(Short::OutputTokens);
        }
        let input = [c.input_total, c.reserved_input_tokens, c.prior_input_tokens, child.input_tokens.unwrap_or(0)];
        if q.input_tokens.is_some_and(|m| over(&input, m)) {
            return Err(Short::InputTokens);
        }
        add_sat(&self.reserved_requests, child.requests);
        add_sat(&self.reserved_output_tokens, child.output_tokens);
        add_sat(&self.reserved_input_tokens, child.input_tokens.unwrap_or(0));
        Ok(())
    }

    /// Gives a carve-out back: its child didn't start.
    pub fn uncarve(&self, child: ModelQuota) {
        sub_sat(&self.reserved_requests, child.requests);
        sub_sat(&self.reserved_output_tokens, child.output_tokens);
        sub_sat(&self.reserved_input_tokens, child.input_tokens.unwrap_or(0));
    }
}

/// Exact values, so a changed operator or boundary fails here, in the crate's own fast suite: the
/// Kani harnesses and the loom test (which `cargo test` doesn't run) prove the properties, and
/// mutation testing (#326) found nothing else in `cargo test -p wicket-core` that would notice.
#[cfg(test)]
mod tests {
    use super::*;

    const Q: ModelQuota = ModelQuota { requests: 10, output_tokens: 1000, input_tokens: Some(5000) };

    fn counter(c: Counts) -> Counter {
        let k = Counter::default();
        k.requests.store(c.requests, SeqCst);
        k.input_tokens.store(c.input_total, SeqCst);
        k.output_tokens.store(c.output_tokens, SeqCst);
        k.reserved_requests.store(c.reserved_requests, SeqCst);
        k.reserved_output_tokens.store(c.reserved_output_tokens, SeqCst);
        k.reserved_input_tokens.store(c.reserved_input_tokens, SeqCst);
        k.prior_requests.store(c.prior_requests, SeqCst);
        k.prior_input_tokens.store(c.prior_input_tokens, SeqCst);
        k.prior_output_tokens.store(c.prior_output_tokens, SeqCst);
        k.inflight_output_tokens.store(c.inflight_output_tokens, SeqCst);
        k
    }

    const C: Counts = Counts {
        requests: 1,
        input_total: 100,
        output_tokens: 10,
        reserved_requests: 2,
        reserved_output_tokens: 20,
        reserved_input_tokens: 200,
        prior_requests: 3,
        prior_input_tokens: 300,
        prior_output_tokens: 30,
        inflight_output_tokens: 40,
    };

    const S: Spent = Spent { requests: 5, input_tokens: 100, cache_read_tokens: 20, cache_creation_tokens: 3, output_tokens: 50 };
    const B: Spent = Spent { requests: 2, input_tokens: 40, cache_read_tokens: 30, cache_creation_tokens: 1, output_tokens: 10 };

    /// #152, #422: what a node reports, added to and taken from a base, saturating.
    #[test]
    fn spent_adds_and_subtracts_field_by_field_saturating() {
        assert_eq!(S.input_total(), 123, "cached tokens included");
        assert_eq!(Spent { input_tokens: u64::MAX, cache_read_tokens: 1, ..S }.input_total(), u64::MAX);
        assert_eq!(S.plus(B), Spent { requests: 7, input_tokens: 140, cache_read_tokens: 50, cache_creation_tokens: 4, output_tokens: 60 });
        assert_eq!(S.since(B), Spent { requests: 3, input_tokens: 60, cache_read_tokens: 0, cache_creation_tokens: 2, output_tokens: 40 });
        assert_eq!(S.plus(B).since(B), Spent { cache_read_tokens: 20, ..S });
        assert_eq!(Spent { output_tokens: u64::MAX, ..S }.plus(B).output_tokens, u64::MAX);
    }

    /// #152: a node keeps its slice until less than half of it is left, takes a lower one at once,
    /// and gets the first one as it is; in the node's counts when the control host counts from a
    /// base (#422).
    #[test]
    fn a_slice_is_renewed_at_half_and_lowered_at_once() {
        let next = Slice { requests: 10, output_tokens: 100, input_tokens: Some(1000) };
        let cur = Slice { requests: 8, output_tokens: 80, input_tokens: Some(800) };
        let spent = |r, o| Spent { requests: r, output_tokens: o, ..Spent::default() };
        assert_eq!(Slice::renewed(None, next, spent(0, 0), 0), next, "the first slice");
        assert_eq!(Slice::renewed(Some(cur), next, spent(4, 40), 400), cur, "half of what is left or more: kept");
        assert_eq!(Slice::renewed(Some(cur), next, spent(7, 40), 400), next, "requests running low");
        assert_eq!(Slice::renewed(Some(cur), next, spent(4, 70), 400), next, "output running low");
        assert_eq!(Slice::renewed(Some(cur), next, spent(4, 40), 700), next, "input running low");
        let lower = Slice { requests: 6, ..next };
        assert_eq!(Slice::renewed(Some(cur), lower, spent(0, 0), 0), lower, "a lower slice at once");
        // From a base: the node counted `base` before the control host's count began.
        let base = Spent { requests: 100, input_tokens: 1000, output_tokens: 1000, ..Spent::default() };
        let held = cur.offset(base);
        assert_eq!(held, Slice { requests: 108, output_tokens: 1080, input_tokens: Some(1800) });
        assert_eq!(Slice::renewed_from(Some(held), next, spent(4, 40), 400, base), held, "kept, in the node's counts");
        assert_eq!(Slice::renewed_from(Some(held), next, spent(7, 40), 400, base), next.offset(base));
    }

    #[test]
    fn a_zones_quota_is_its_llm_limits() {
        let l: crate::manifest::LlmSpec =
            crate::yaml::from_str("{ max_requests: 7, max_output_tokens: 70, max_input_tokens: 700 }").unwrap();
        assert_eq!(ModelQuota::of_zone(&l), ModelQuota { requests: 7, output_tokens: 70, input_tokens: Some(700) });
    }

    #[test]
    fn committed_and_remaining_add_every_part_once() {
        assert_eq!(C.requests_committed(), 6);
        assert_eq!(C.output_committed(), 100);
        assert_eq!(C.input_committed(), 600);
        assert_eq!(C.remaining(Q), (4, 900));
        assert_eq!(C.remaining_input(Q), Some(4400));
        assert_eq!(C.remaining_input(ModelQuota { input_tokens: None, ..Q }), None);
        // Past the budget: nothing left, never wrapped.
        let over = Counts { requests: 20, output_tokens: 2000, input_total: 9000, ..Counts::default() };
        assert_eq!((over.remaining(Q), over.remaining_input(Q)), ((0, 0), Some(0)));
        // A sum that would pass u64::MAX is all of any budget.
        let huge = Counts { requests: u64::MAX, reserved_requests: 1, ..Counts::default() };
        assert_eq!(huge.requests_committed(), u64::MAX);
    }

    #[test]
    fn a_slice_adds_a_part_of_each_limit_within_what_is_left() {
        let s = C.slice(Q, |max| max / 10);
        assert_eq!(s, Slice { requests: 1 + 1, output_tokens: 10 + 100, input_tokens: Some(100 + 500) });
        // The part is capped by what is left.
        let s = C.slice(Q, |max| max);
        assert_eq!(s, Slice { requests: 1 + 4, output_tokens: 10 + 900, input_tokens: Some(100 + 4400) });
        assert_eq!(C.slice(ModelQuota { input_tokens: None, ..Q }, |m| m).input_tokens, None);
        assert_eq!((part(10, 0.25), part(1000, 0.25), part(0, 0.25), part(3, 0.5)), (3, 250, 1, 2));
    }

    #[test]
    fn a_slice_is_renewed_when_less_than_half_of_it_is_left_or_the_next_is_lower() {
        let s = |r, o, i| Slice { requests: r, output_tokens: o, input_tokens: i };
        let spent = |r, o| Spent { requests: r, output_tokens: o, ..Spent::default() };
        let next = s(12, 1200, Some(12_000));
        assert_eq!(Slice::renewed(None, next, Spent::default(), 0), next, "the first");
        let cur = s(10, 1000, Some(10_000));
        // Renewed once twice what is left of `cur` is less than what `next` would leave:
        // (10 - u) * 2 < 12 - u from u = 9; likewise 801 output and 8001 input tokens.
        assert_eq!(Slice::renewed(Some(cur), next, spent(8, 800), 8000), cur);
        assert_eq!(Slice::renewed(Some(cur), next, spent(9, 0), 0), next);
        assert_eq!(Slice::renewed(Some(cur), next, spent(0, 801), 0), next);
        assert_eq!(Slice::renewed(Some(cur), next, spent(0, 0), 8001), next, "input tokens too");
        // A lower next is taken at once, limit by limit.
        assert_eq!(Slice::renewed(Some(cur), s(9, 1200, Some(12_000)), spent(0, 0), 0), s(9, 1200, Some(12_000)));
        assert_eq!(Slice::renewed(Some(cur), s(12, 999, Some(12_000)), spent(0, 0), 0), s(12, 999, Some(12_000)));
        assert_eq!(Slice::renewed(Some(cur), s(12, 1200, Some(9999)), spent(0, 0), 0), s(12, 1200, Some(9999)));
        assert_eq!(Slice::renewed(Some(cur), cur, spent(0, 0), 0), cur, "the same is kept");
        let uncapped = s(10, 1000, None);
        assert_eq!(Slice::renewed(Some(uncapped), s(12, 1200, None), spent(0, 0), 1 << 40), uncapped);
    }

    #[test]
    fn spent_since_is_per_field_and_saturates() {
        let a = Spent { requests: 5, input_tokens: 50, cache_read_tokens: 6, cache_creation_tokens: 7, output_tokens: 8 };
        let b = Spent { requests: 2, input_tokens: 60, cache_read_tokens: 1, cache_creation_tokens: 2, output_tokens: 3 };
        assert_eq!(a.since(b), Spent { requests: 3, input_tokens: 0, cache_read_tokens: 5, cache_creation_tokens: 5, output_tokens: 5 });
    }

    #[test]
    fn a_counter_reads_what_it_holds() {
        let k = counter(C);
        assert_eq!(k.counts(), C);
        k.cache_read_tokens.store(5, SeqCst);
        k.cache_creation_tokens.store(7, SeqCst);
        assert_eq!(k.input_total(), 112);
        assert_eq!(k.spent(), Spent { requests: 1, input_tokens: 100, cache_read_tokens: 5, cache_creation_tokens: 7, output_tokens: 10 });
        assert_eq!(k.spent_charged().output_tokens, 50, "in flight charged in full");
        assert!(format!("{k:?}").starts_with("Counter(Counts { requests: 1"));
        k.merge_spent(Spent { requests: 9, input_tokens: 1, cache_read_tokens: 6, cache_creation_tokens: 1, output_tokens: 11 });
        assert_eq!(k.spent(), Spent { requests: 9, input_tokens: 100, cache_read_tokens: 6, cache_creation_tokens: 7, output_tokens: 11 });
        // 9 + 2 + 3 committed of 10: nothing more to slice; 11 output tokens + 500 of what is left.
        assert_eq!(k.next_slice(Q, 0.5), Slice { requests: 9, output_tokens: 11 + 500, input_tokens: Some(113 + 2500) });
    }

    #[test]
    fn requests_and_reservations_count_and_stop_at_the_budget() {
        let k = Counter::default();
        assert_eq!(k.admit_request(), 1);
        k.prior_requests.store(4, SeqCst);
        assert_eq!(k.admit_request(), 6);
        assert_eq!(k.requests.load(SeqCst), 2);
        assert_eq!(k.reserve_output(100, 30), Some(30));
        assert_eq!(k.reserve_output(100, 90), Some(70), "lowered to what is left");
        assert_eq!(k.reserve_output(100, 1), None, "nothing left");
        assert_eq!(k.inflight_output_tokens.load(SeqCst), 100);
        k.settle(30, 1, 2, 3, 12);
        assert_eq!(k.inflight_output_tokens.load(SeqCst), 70);
        assert_eq!(k.spent(), Spent { requests: 2, input_tokens: 1, cache_read_tokens: 2, cache_creation_tokens: 3, output_tokens: 12 });
        assert_eq!(k.reserve_output(100, 50), Some(18));
        k.settle(1000, 0, 0, 0, 0);
        assert_eq!(k.inflight_output_tokens.load(SeqCst), 0, "a release saturates at 0");
    }

    #[test]
    fn a_carve_out_fits_exactly_or_names_the_limit_and_takes_nothing() {
        let k = counter(Counts { inflight_output_tokens: 0, ..C });
        // Left: 4 requests, 940 output tokens, 4400 input tokens.
        let child = |r, o, i| ModelQuota { requests: r, output_tokens: o, input_tokens: i };
        assert_eq!(k.carve(Q, child(5, 1, Some(1))), Err(Short::Requests));
        assert_eq!(k.carve(Q, child(1, 941, Some(1))), Err(Short::OutputTokens));
        assert_eq!(k.carve(Q, child(1, 1, Some(4401))), Err(Short::InputTokens));
        assert_eq!(k.counts(), Counts { inflight_output_tokens: 0, ..C }, "a refusal takes nothing");
        assert_eq!(k.carve(Q, child(4, 940, Some(4400))), Ok(()), "exactly what is left fits");
        let c = k.counts();
        assert_eq!((c.reserved_requests, c.reserved_output_tokens, c.reserved_input_tokens), (6, 960, 4600));
        assert_eq!(k.carve(Q, child(0, 0, None)), Ok(()));
        assert_eq!(k.carve(Q, child(1, 0, None)), Err(Short::Requests));
        // Uncapped input: anything fits there.
        assert_eq!(counter(Counts::default()).carve(ModelQuota { input_tokens: None, ..Q }, child(1, 1, Some(u64::MAX))), Ok(()));
        k.uncarve(child(4, 940, Some(4400)));
        let c = k.counts();
        assert_eq!((c.reserved_requests, c.reserved_output_tokens, c.reserved_input_tokens), (2, 20, 200));
        k.uncarve(child(100, 100, None));
        assert_eq!(k.counts().reserved_requests, 0, "saturates at 0");
        assert_eq!(k.counts().reserved_input_tokens, 200, "None gives back no input");
        assert_eq!(
            (Short::Requests.to_string(), Short::OutputTokens.to_string(), Short::InputTokens.to_string()),
            ("model requests".to_string(), "output tokens".to_string(), "input tokens".to_string())
        );
    }
}

#[cfg(kani)]
#[path = "proofs/budget.rs"]
mod proofs;
