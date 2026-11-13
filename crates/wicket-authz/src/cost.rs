//! What a request could cost in the generic engine, estimated where a token is made (#183).
//!
//! [`crate::Loaded::decide`] runs every request in the compiled evaluator, which compiles each
//! `.matches()` pattern once. The fork's generic engine, the compiled evaluator's fallback, compiles
//! the pattern on every evaluation and charges for it: `REGEX_COMPILE_STEPS_PER_BYTE` (16) steps per
//! pattern byte, plus one step per 16 bytes of the path (`third_party/biscuit-auth`,
//! `datalog/expression.rs`). The other steps of a request (candidate facts, operators) are a few
//! hundred, and they don't grow with the globs. So a request's generic cost is bounded by
//! `16 x` the bytes of the patterns it can evaluate, plus [`BASE_STEPS`].
//!
//! Which patterns can a request evaluate? Every path pattern sits in a query that binds `host`
//! first: `host("h"), ...` for an exact host, `host($h), $h.ends_with(".sfx"), ...` for `*.sfx`. A
//! query's expressions run only once its predicates match, and stop at the first false one. So a
//! request to host `H` can only pay for the patterns of queries whose host matches `H` (reach and
//! risk alternatives and forbid rules, in every first-party block of the chain). The estimate
//! is the sum of those pattern bytes, maximised over the hosts that matter: each exact host the
//! token names, and one host under each `*.sfx` (the wildcards one host matches are nested
//! suffixes of each other, so the host under the longest of them matches them all).
//!
//! [`mint`](crate::mint) and [`Token::attenuate`](crate::Token::attenuate) refuse a token whose
//! estimate is over [`STEP_BUDGET`]: if such a token ever ran in the generic engine, every
//! request to that host could be cut off by the budget and decided `Forbidden`. The refusal names
//! the host and its pattern bytes. A node's `load` doesn't run the estimate: the step budget is
//! what bounds a token made by other means (a hostile block is cut off with a run-limit error and
//! decided `Forbidden`), so nothing is weakened when a token passes or fails it.
//!
//! The estimate is an upper bound on what the tests measure: the oracle tests assert, for every
//! legitimate token they build, that no request in the generic engine took more steps than it.

use crate::decide::STEP_BUDGET;
use biscuit_auth::builder::{Binary, Op, Rule, Term};
use biscuit_auth::Biscuit;
use std::collections::BTreeMap;

/// Steps charged per byte of a `.matches()` pattern each time the generic engine evaluates it
/// (the fork's `REGEX_COMPILE_STEPS_PER_BYTE`).
pub const STEPS_PER_PATTERN_BYTE: u64 = 16;

/// An allowance for the steps of a request that don't depend on the patterns: candidate facts,
/// operators, and one step per 16 bytes of the path for each `.matches()`. The oracle tests assert
/// that no generic run on a legitimate token they build exceeds [`Estimate::steps`] (on the zone of
/// #183: 9,497 steps measured, 11,048 estimated).
pub const BASE_STEPS: u64 = 1_000;

/// The costliest host of a token in the generic engine.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Estimate {
    /// The host (an exact host the token names, or `*.sfx`); empty if no pattern names a host.
    pub host: String,
    /// The bytes of the path patterns (globset regexes) a request to that host can evaluate.
    pub pattern_bytes: u64,
    /// How many patterns that is.
    pub patterns: usize,
}

impl Estimate {
    /// The steps a request to [`Estimate::host`] can cost in the generic engine, at most.
    pub fn steps(&self) -> u64 {
        BASE_STEPS + STEPS_PER_PATTERN_BYTE * self.pattern_bytes
    }
}

/// The host a query binds: exact, or a `*.sfx` wildcard (its suffix, with the dot); `None` if the
/// query doesn't constrain `host` to a literal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HostKey {
    Exact(String),
    Suffix(String),
    Any,
}

fn host_of(q: &Rule) -> HostKey {
    for p in &q.body {
        if p.name != "host" || p.terms.len() != 1 {
            continue;
        }
        match &p.terms[0] {
            Term::Str(h) => return HostKey::Exact(h.clone()),
            Term::Variable(v) => {
                for e in &q.expressions {
                    if let [Op::Value(Term::Variable(x)), Op::Value(Term::Str(sfx)), Op::Binary(Binary::Suffix)] = e.ops.as_slice() {
                        if x == v {
                            return HostKey::Suffix(sfx.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    HostKey::Any
}

fn patterns(q: &Rule) -> impl Iterator<Item = &str> {
    q.expressions.iter().filter_map(|e| match e.ops.as_slice() {
        [_, Op::Value(Term::Str(pat)), Op::Binary(Binary::Regex)] => Some(pat.as_str()),
        _ => None,
    })
}

/// The costliest host of `tok`'s first-party blocks (see the module docs).
pub fn estimate(tok: &Biscuit) -> Result<Estimate, String> {
    // Per host key: (pattern bytes, patterns).
    let mut by_key: BTreeMap<HostKey, (u64, usize)> = BTreeMap::new();
    for i in 0..tok.block_count() {
        let b = tok.block_datalog(i).map_err(|e| e.to_string())?;
        if b.external_key.is_some() {
            continue;
        }
        for c in &b.checks {
            for q in &c.queries {
                let (bytes, n) = patterns(q).fold((0u64, 0usize), |(b, n), p| (b + p.len() as u64, n + 1));
                if n > 0 {
                    let e = by_key.entry(host_of(q)).or_default();
                    e.0 += bytes;
                    e.1 += n;
                }
            }
        }
    }
    // Candidate hosts: each exact host, and one host under each suffix.
    let candidates: Vec<(String, String)> = by_key
        .keys()
        .filter_map(|k| match k {
            HostKey::Exact(h) => Some((h.clone(), h.clone())),
            HostKey::Suffix(s) => Some((format!("*{s}"), format!("x{s}"))),
            HostKey::Any => None,
        })
        .collect();
    let any = by_key.get(&HostKey::Any).copied().unwrap_or_default();
    let mut worst = Estimate { host: String::new(), pattern_bytes: any.0, patterns: any.1 };
    for (name, host) in candidates {
        let (mut bytes, mut n) = any;
        for (k, (b, m)) in &by_key {
            let hit = match k {
                HostKey::Exact(h) => *h == host,
                HostKey::Suffix(s) => host.ends_with(s.as_str()),
                HostKey::Any => false,
            };
            if hit {
                bytes += b;
                n += m;
            }
        }
        if bytes > worst.pattern_bytes {
            worst = Estimate { host: name, pattern_bytes: bytes, patterns: n };
        }
    }
    Ok(worst)
}

/// Refuses a token whose costliest host could exceed [`STEP_BUDGET`] in the generic engine.
pub fn check(tok: &Biscuit) -> Result<Estimate, String> {
    let e = estimate(tok)?;
    if e.steps() > STEP_BUDGET {
        let host = if e.host.is_empty() { "every host".to_string() } else { format!("host {}", e.host) };
        return Err(format!(
            "{host}: its {} path globs compile to {} pattern bytes, which could cost about {} steps per request in the generic engine (budget {STEP_BUDGET}, {STEPS_PER_PATTERN_BYTE} steps per pattern byte); split or shorten the globs on that host, or drop forbid globs that only restate what reach doesn't allow",
            e.patterns,
            e.pattern_bytes,
            e.steps(),
        ));
    }
    Ok(e)
}
