//! A run's model budget (#152, #256): what its model proxy has counted, what it has carved out for
//! its children, and the slices of it a node is leased, kept in one [`Counter`] that the proxy's
//! calls, a spawn's carve-out and the node's `Spent` reports share across threads.
//!
//! The counter's atomics are std's, or loom's under `cfg(loom)` (#325:
//! `RUSTFLAGS="--cfg loom" cargo test -p wicket-core --test loom_budget`), which explores every
//! interleaving of the critical sections. The arithmetic is checked by Kani (`proofs/budget.rs`):
//! nothing overflows, a slice never exceeds what is left, and a carve-out never takes a run past its
//! budget.
//!
//! The rule for concurrent claims on one budget is **add, then check**: a model request, an output
//! reservation and a carve-out each add their claim first and then check the total, taking it back
//! if that is over. Of two claims racing for the last of a budget, the later to add sees both, so
//! they can't both succeed; at worst both are refused, which fails closed.

#[cfg(loom)]
use loom::sync::atomic::{AtomicU64, Ordering::SeqCst};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

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
    /// The slice to lease a node next (#152), given the one it holds (`cur`, None before the first),
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
/// `Spent` merged in between leased a node more than was left).
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

    /// The slice to lease next: what this activation has counted plus `part` of each limit, never
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
/// node's `Spent` reports. Counters only go up, except a claim taken back.
#[derive(Debug, Default)]
pub struct Counter {
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

impl Counter {
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

    /// The slice this activation may be leased next (#152): what it has counted plus `fraction` of
    /// the budget, never past what is left of it. From one [`Counts`].
    pub fn next_slice(&self, q: ModelQuota, fraction: f64) -> Slice {
        self.counts().slice(q, |max| part(max, fraction))
    }

    /// Counts one model request, and returns the requests committed with it: the request may go if
    /// that is within the budget (add, then check; a refused one stays counted).
    pub fn admit_request(&self) -> u64 {
        add_sat(&self.requests, 1);
        self.counts().requests_committed()
    }

    /// Reserves up to `want` output tokens for one call, within `max` committed: what is left, if
    /// less. None when nothing is left. Add, then check: a carve-out racing it can't also take the
    /// same tokens.
    pub fn reserve_output(&self, max: u64, want: u64) -> Option<u64> {
        loop {
            let left = max.saturating_sub(self.counts().output_committed());
            if left == 0 {
                return None;
            }
            let take = add_sat(&self.inflight_output_tokens, want.min(left));
            if self.counts().output_committed() <= max {
                return Some(take);
            }
            // Another claim came in between: give this one back and look again.
            sub_sat(&self.inflight_output_tokens, take);
        }
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
    /// fits once added: else takes it back and says which limit it would pass. The budget a spawn
    /// checked earlier (`subset::check`) may have been spent since; this is the check that holds.
    pub fn carve(&self, q: ModelQuota, child: ModelQuota) -> Result<(), Short> {
        let added = [
            add_sat(&self.reserved_requests, child.requests),
            add_sat(&self.reserved_output_tokens, child.output_tokens),
            add_sat(&self.reserved_input_tokens, child.input_tokens.unwrap_or(0)),
        ];
        let c = self.counts();
        let short = if c.requests_committed() > q.requests {
            Some(Short::Requests)
        } else if c.output_committed() > q.output_tokens {
            Some(Short::OutputTokens)
        } else if q.input_tokens.is_some_and(|m| c.input_committed() > m) {
            Some(Short::InputTokens)
        } else {
            None
        };
        match short {
            None => Ok(()),
            Some(s) => {
                self.uncarve(ModelQuota { requests: added[0], output_tokens: added[1], input_tokens: Some(added[2]) });
                Err(s)
            }
        }
    }

    /// Gives a carve-out back: its child didn't start.
    pub fn uncarve(&self, child: ModelQuota) {
        sub_sat(&self.reserved_requests, child.requests);
        sub_sat(&self.reserved_output_tokens, child.output_tokens);
        sub_sat(&self.reserved_input_tokens, child.input_tokens.unwrap_or(0));
    }
}

#[cfg(kani)]
#[path = "proofs/budget.rs"]
mod proofs;
