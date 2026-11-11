/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * fork (wicket experiment biscuit-fast): new file.
 */
//! Build once per token, decide many requests.
//!
//! [`AuthorizerBuilder::prepare`] loads a token into an immutable world: the token's facts (saturated
//! with its own rules), its rules, and every check and policy already translated into one symbol
//! table with its trusted origins resolved. That world is `Send + Sync` and is shared between threads
//! behind an `Arc`.
//!
//! Per request, ambient facts go into an overlay, never into the shared world:
//! - [`PreparedSession`] (generic engine): one per thread. It owns a copy of the symbol table and an
//!   overlay fact set, and resets both (truncate, clear) before each request.
//! - [`crate::datalog::compiled::CompiledAuthorizer`]: a compiled form of the same world that needs no
//!   per-thread copy (see that module).
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::Authorizer;
use crate::builder::{self, CheckKind, Convert, PolicyKind};
use crate::crypto::SerializePrivateKey;
use crate::datalog::{self, run_overlay, ExternFunc, FactSet, FactView, Origin, RuleSet, StepCounter, SymbolTable, TrustedOrigins};
use crate::error;
use crate::time::Instant;
use crate::token::{self, Biscuit};
use crate::AuthorizerBuilder;

/// Limits for prepared authorizers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLimits {
    /// maximum number of facts (token facts, request facts and derived facts)
    pub max_facts: u64,
    /// maximum number of rule iterations
    pub max_iterations: u64,
    /// maximum number of engine steps (fuel): one per candidate fact visited, one per operator
    pub max_steps: u64,
    /// wall-clock limit. `None` makes the outcome deterministic: only facts, iterations and steps
    /// are counted, so a decision never depends on machine load.
    pub max_time: Option<Duration>,
}

impl Default for PreparedLimits {
    fn default() -> Self {
        PreparedLimits { max_facts: 1000, max_iterations: 100, max_steps: datalog::RunLimits::DEFAULT_STEPS, max_time: None }
    }
}

// a far-away deadline for the upstream engine entry points that take a Duration
const NO_TIME_LIMIT: Duration = Duration::from_secs(365 * 24 * 3600);

pub(crate) struct PQuery {
    pub(crate) rule: datalog::Rule,
    pub(crate) trusted: TrustedOrigins,
}

pub(crate) struct PCheck {
    pub(crate) kind: CheckKind,
    /// origin used for the query: `usize::MAX` for the authorizer, else the block index
    pub(crate) origin: usize,
    pub(crate) queries: Vec<PQuery>,
    /// None: an authorizer check
    pub(crate) block: Option<u32>,
    pub(crate) id: u32,
    pub(crate) text: String,
}

impl PCheck {
    pub(crate) fn failed(&self) -> error::FailedCheck {
        match self.block {
            None => error::FailedCheck::Authorizer(error::FailedAuthorizerCheck { check_id: self.id, rule: self.text.clone() }),
            Some(block_id) => error::FailedCheck::Block(error::FailedBlockCheck { block_id, check_id: self.id, rule: self.text.clone() }),
        }
    }
}

pub(crate) struct PPolicy {
    pub(crate) kind: PolicyKind,
    pub(crate) queries: Vec<PQuery>,
}

pub(crate) struct Inner {
    pub(crate) symbols: SymbolTable,
    /// the token's and the authorizer's static facts, saturated with every rule
    pub(crate) facts: FactSet,
    pub(crate) fact_count: usize,
    pub(crate) rules: RuleSet,
    pub(crate) extern_funcs: HashMap<String, ExternFunc>,
    /// authorizer checks, then the authority block's checks (stock evaluation order)
    pub(crate) pre_checks: Vec<PCheck>,
    pub(crate) policies: Vec<PPolicy>,
    /// checks of blocks 1..
    pub(crate) post_checks: Vec<PCheck>,
    /// an error while saturating the token's own facts: every request fails with it
    pub(crate) prepare_error: Option<error::Token>,
    pub(crate) prepare_steps: u64,
    pub(crate) block_count: usize,
}

/// A token loaded once, shareable between threads. Create per-thread [`PreparedSession`]s with
/// [`PreparedAuthorizer::session`], or a compiled form with [`PreparedAuthorizer::compile`].
#[derive(Clone)]
pub struct PreparedAuthorizer {
    pub(crate) inner: Arc<Inner>,
}

impl AuthorizerBuilder {
    /// fork: builds the authorizer for `token` once, for many requests. Ambient (per-request) facts
    /// are passed to [`PreparedSession::authorize`] or the compiled form instead of to the builder.
    pub fn prepare<K: SerializePrivateKey>(self, token: &Biscuit<K>, limits: &PreparedLimits) -> Result<PreparedAuthorizer, error::Token> {
        PreparedAuthorizer::from_authorizer(self.build(token)?, limits)
    }
}

fn queries(
    rules: impl Iterator<Item = datalog::Rule>,
    default: &TrustedOrigins,
    origin: usize,
    pk: &HashMap<usize, Vec<usize>>,
) -> Vec<PQuery> {
    rules
        .map(|rule| {
            let trusted = TrustedOrigins::from_scopes(&rule.scopes, default, origin, pk);
            PQuery { rule, trusted }
        })
        .collect()
}

impl PreparedAuthorizer {
    pub(crate) fn from_authorizer(a: Authorizer, limits: &PreparedLimits) -> Result<Self, error::Token> {
        let Authorizer { authorizer_block_builder, mut world, mut symbols, policies, blocks, public_key_to_block_id: pk, .. } = a;

        let authorizer_scopes: Vec<token::Scope> = authorizer_block_builder.scopes.iter().map(|s| s.convert(&mut symbols)).collect();
        let authorizer_trusted = TrustedOrigins::from_scopes(&authorizer_scopes, &TrustedOrigins::default(), usize::MAX, &pk);

        let mut pre_checks = Vec::new();
        for (i, check) in authorizer_block_builder.checks.iter().enumerate() {
            let c: datalog::Check = check.convert(&mut symbols);
            let text = symbols.print_check(&c);
            pre_checks.push(PCheck {
                kind: c.kind.clone(),
                origin: usize::MAX,
                queries: queries(c.queries.into_iter(), &authorizer_trusted, usize::MAX, &pk),
                block: None,
                id: i as u32,
                text,
            });
        }
        let mut post_checks = Vec::new();
        let block_count = blocks.as_ref().map(|b| b.len()).unwrap_or(0);
        if let Some(blocks) = blocks.as_ref() {
            for (b, block) in blocks.iter().enumerate() {
                let block_trusted = TrustedOrigins::from_scopes(&block.scopes, &TrustedOrigins::default(), b, &pk);
                for (j, check) in block.checks.iter().enumerate() {
                    let pc = PCheck {
                        kind: check.kind.clone(),
                        origin: b,
                        queries: queries(check.queries.iter().cloned(), &block_trusted, b, &pk),
                        block: Some(b as u32),
                        id: j as u32,
                        text: symbols.print_check(check),
                    };
                    if b == 0 {
                        pre_checks.push(pc);
                    } else {
                        post_checks.push(pc);
                    }
                }
            }
        }
        let policies = policies
            .iter()
            .map(|p| PPolicy {
                kind: p.kind.clone(),
                queries: queries(p.queries.iter().map(|q| q.convert(&mut symbols)), &authorizer_trusted, usize::MAX, &pk),
            })
            .collect();

        // saturate the token's own facts once; request facts only ever add to this
        let counter = StepCounter::default();
        let max_time = limits.max_time.unwrap_or(NO_TIME_LIMIT);
        let prepare_error = world
            .run_with_limits(&symbols, limits.max_facts, limits.max_iterations, max_time, counter.budget(limits.max_steps))
            .err()
            .map(error::Token::from);

        let fact_count = world.facts.len();
        Ok(PreparedAuthorizer {
            inner: Arc::new(Inner {
                symbols,
                facts: world.facts,
                fact_count,
                rules: world.rules,
                extern_funcs: world.extern_funcs,
                pre_checks,
                policies,
                post_checks,
                prepare_error,
                prepare_steps: counter.taken(),
                block_count,
            }),
        })
    }

    /// a per-thread session (copies the symbol table once)
    pub fn session(&self) -> PreparedSession {
        PreparedSession {
            inner: self.inner.clone(),
            symbols: self.inner.symbols.clone(),
            overlay: FactSet::default(),
            base_symbols: self.inner.symbols.current_offset(),
            last: RunStats::default(),
        }
    }

    /// facts in the shared world (token facts saturated with the token's rules)
    pub fn base_fact_count(&self) -> usize {
        self.inner.fact_count
    }

    /// steps spent saturating the token's own facts
    pub fn prepare_steps(&self) -> u64 {
        self.inner.prepare_steps
    }

    /// the error hit while saturating the token's own facts, if any
    pub fn prepare_error(&self) -> Option<&error::Token> {
        self.inner.prepare_error.as_ref()
    }
}

/// what the last request used
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunStats {
    pub steps: u64,
    pub iterations: u64,
    pub facts: usize,
    /// compiled form only: true if the request was decided by the generic engine
    pub fallback: bool,
}

/// One thread's handle on a [`PreparedAuthorizer`]: owns a symbol table copy and the overlay.
pub struct PreparedSession {
    inner: Arc<Inner>,
    symbols: SymbolTable,
    overlay: FactSet,
    base_symbols: usize,
    last: RunStats,
}

pub(crate) fn authorizer_origin() -> Origin {
    let mut o = Origin::default();
    o.insert(usize::MAX);
    o
}

impl PreparedSession {
    /// decides one request. `facts` are the ambient facts the stock API would add to the builder.
    pub fn authorize(&mut self, facts: &[builder::Fact], limits: &PreparedLimits) -> Result<usize, error::Token> {
        let start = Instant::now();
        let inner = self.inner.clone();
        if let Some(e) = &inner.prepare_error {
            self.last = RunStats::default();
            return Err(e.clone());
        }
        // reset: drop the previous request's symbols and facts
        self.symbols.truncate(self.base_symbols);
        self.overlay = FactSet::default();
        let origin = authorizer_origin();
        for f in facts {
            f.validate()?;
            let df = if f.parameters.as_ref().is_some_and(|p| !p.is_empty()) {
                f.convert(&mut self.symbols)
            } else {
                datalog::Fact { predicate: f.predicate.convert(&mut self.symbols) }
            };
            if !inner.facts.contains(&origin, &df) {
                self.overlay.insert(&origin, df);
            }
        }
        let time_limit = limits.max_time.map(|d| start + d);
        let counter = StepCounter::default();
        let steps = counter.budget(limits.max_steps);
        let res = self.decide(limits, time_limit, steps);
        self.last = RunStats {
            steps: counter.taken(),
            iterations: res.as_ref().map(|r| r.1).unwrap_or(0),
            facts: inner.fact_count + self.overlay.len(),
            fallback: false,
        };
        res.map(|r| r.0)
    }

    fn decide(
        &mut self,
        limits: &PreparedLimits,
        time_limit: Option<Instant>,
        steps: datalog::StepBudget<'_>,
    ) -> Result<(usize, u64), error::Token> {
        let inner = &*self.inner;
        let iterations = run_overlay(
            &inner.facts,
            inner.fact_count,
            &inner.rules,
            &mut self.overlay,
            &self.symbols,
            &inner.extern_funcs,
            limits.max_facts,
            limits.max_iterations,
            time_limit,
            steps,
        )?;
        let view = FactView { base: &inner.facts, overlay: &self.overlay };
        let symbols = &self.symbols;
        let timed_out = || time_limit.is_some_and(|t| Instant::now() >= t);
        let run_check = |c: &PCheck| -> Result<bool, error::Token> {
            for q in &c.queries {
                let res = match c.kind {
                    CheckKind::One => q.rule.find_match(&view, c.origin, &q.trusted, symbols, &inner.extern_funcs, steps)?,
                    CheckKind::All => q.rule.check_match_all(&view, &q.trusted, symbols, &inner.extern_funcs, steps)?,
                    CheckKind::Reject => !q.rule.find_match(&view, c.origin, &q.trusted, symbols, &inner.extern_funcs, steps)?,
                };
                if timed_out() {
                    return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                }
                if res {
                    return Ok(true);
                }
            }
            Ok(false)
        };

        let mut errors = vec![];
        for c in &inner.pre_checks {
            if !run_check(c)? {
                errors.push(c.failed());
            }
        }
        let mut policy_result: Option<Result<usize, usize>> = None;
        'policies: for (i, p) in inner.policies.iter().enumerate() {
            for q in &p.queries {
                let res = q.rule.find_match(&view, usize::MAX, &q.trusted, symbols, &inner.extern_funcs, steps)?;
                if timed_out() {
                    return Err(error::Token::RunLimit(error::RunLimit::Timeout));
                }
                if res {
                    policy_result = Some(match p.kind {
                        PolicyKind::Allow => Ok(i),
                        PolicyKind::Deny => Err(i),
                    });
                    break 'policies;
                }
            }
        }
        for c in &inner.post_checks {
            if !run_check(c)? {
                errors.push(c.failed());
            }
        }
        finish(policy_result, errors).map(|i| (i, iterations))
    }

    /// what the last request used
    pub fn last_run(&self) -> RunStats {
        self.last
    }
}

pub(crate) fn finish(policy_result: Option<Result<usize, usize>>, errors: Vec<error::FailedCheck>) -> Result<usize, error::Token> {
    match (policy_result, errors.is_empty()) {
        (Some(Ok(i)), true) => Ok(i),
        (None, _) => Err(error::Token::FailedLogic(error::Logic::NoMatchingPolicy { checks: errors })),
        (Some(Ok(i)), _) => {
            Err(error::Token::FailedLogic(error::Logic::Unauthorized { policy: error::MatchedPolicy::Allow(i), checks: errors }))
        }
        (Some(Err(i)), _) => {
            Err(error::Token::FailedLogic(error::Logic::Unauthorized { policy: error::MatchedPolicy::Deny(i), checks: errors }))
        }
    }
}
