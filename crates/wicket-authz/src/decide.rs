//! Loading a token once and deciding requests against it.
//!
//! [`load`] verifies the signatures, checks every block's revocation id, runs the structural check
//! (`structure`), and only then prepares the token in the fork's engine (its own facts saturated once,
//! with the step budget) and compiles it. [`Loaded::decide`] runs one request through the compiled
//! evaluator, which falls back to the fork's generic engine for anything it can't run itself.
//!
//! ## How a denial is classified
//!
//! From the failed checks of a single evaluation: the evaluator reports every check that failed,
//! not just the first, and the structural check has classified each check of the token
//! ([`CheckClass`]). A request is `Forbidden` if any hard check failed (time, box, op kinds, tenant,
//! a forbid rule, spawn/model/message limits, injections, or the authorizer's tenant check), or if
//! evaluation itself failed (a limit hit; fail closed). It `NeedsGrant` if only reach or risk checks
//! failed: a grant from a key those blocks trust could allow it. No second evaluation is needed.
//!
//! ## Limits
//!
//! Deterministic, no wall clock: [`STEP_BUDGET`] steps, 256 facts and 8 rule iterations per request
//! (and the same for saturating the token's own facts at load). See [`STEP_BUDGET`] for how the
//! budget was chosen, and `cost` for the estimate `mint` and `attenuate` check against it.

use crate::generator::request_facts;
use crate::payload::{Action, PublicKey, Request};
use crate::structure::{self, CheckClass, Policy, Vetted};
use crate::token::{biscuit_key, Token};
use crate::AuthzError;
use biscuit_auth::error::{FailedCheck, Logic, Token as TokenError};
use biscuit_auth::{AuthorizerBuilder, AuthorizerLimits, Biscuit, CompiledAuthorizer, PreparedAuthorizer, PreparedLimits, PreparedSession};
use std::time::Duration;

/// Steps (fuel) one request may take.
///
/// Legitimate tokens run in the compiled evaluator, which compiles each `.matches()` pattern once;
/// the tests assert that every request they decide on every legitimate token (every example zone and
/// subset-test zone in oracle 1, the zone of #183, oracle 2's random chains, oracle 3's depth-0..5
/// chains with and without grants, and the chains the property and hostile-token tests build on)
/// was decided there, never by the generic fallback. The most a request took there was 308 steps
/// (oracle 3, 100k requests).
/// The fork's generic engine is the fallback for constructs the compiler doesn't handle and for
/// run-time expression errors, neither of which wicket's blocks produce. It charges 16 steps per
/// pattern byte, because it compiles each pattern on every evaluation, so its cost grows with the
/// globs on one host: 5,242 steps at most on oracle 1's zones, 6,605 on oracle 3's chains (5,597
/// before forbid globs ignored case, #115: a folded letter is a four-byte class), and 9,497 on the
/// zone of #183 (fixture `tests/fixtures/zone-183.yaml`).
///
/// So that the fallback could never decide a legitimate request `Forbidden` for its cost alone,
/// [`crate::mint`] and [`crate::Token::attenuate`] refuse a token whose costliest host could exceed
/// this budget in the generic engine ([`crate::cost`], [`crate::AuthzError::Cost`]). The oracle
/// tests assert that every generic run on a legitimate token stays within that per-token estimate.
///
/// 25,000 is about 80x the compiled maximum, and well above the generic cost of every zone the
/// tests build, while no token that passes the structural check can make a request cost more (a
/// hostile block at every cap, appended by other means, is cut off with a run-limit error, which
/// decides `Forbidden`; asserted by the hostile-token tests). A node's `load` doesn't estimate cost:
/// the budget is what bounds a token it didn't make.
pub const STEP_BUDGET: u64 = 25_000;

/// The most generic-engine steps oracle 3 measured on its fixed chains (6,605), with headroom; its
/// test asserts it, so a change to the fork or the generator that makes those requests costlier
/// shows. It is a measurement over fixed test fixtures, not a limit on zones: oracle 1, over
/// `examples/`, asserts the per-token cost estimate instead ([`crate::cost`]), so adding an example
/// can't trip it (#183). The zone of #183 takes more than this, within its estimate.
pub const MEASURED_MAX_STEPS: u64 = 7_000;

/// The per-request limits.
pub fn limits() -> PreparedLimits {
    PreparedLimits { max_facts: 256, max_iterations: 8, max_steps: STEP_BUDGET, max_time: None }
}

/// The node's own policy: the tenant served must be the token's, and every check in the token must
/// pass. Every ceiling lives in the token.
#[doc(hidden)]
pub const AUTHORIZER: &str = "check if tenant($t), request_tenant($t);\nallow if true;";

fn authorizer() -> AuthorizerBuilder {
    AuthorizerBuilder::new().code(AUTHORIZER).expect("the authorizer's code parses")
}

/// The generic engine over a prepared token, one thread's handle (tests).
#[doc(hidden)]
pub struct GenericSession<'a> {
    session: PreparedSession,
    limits: &'a PreparedLimits,
}

impl GenericSession<'_> {
    pub fn authorize(&mut self, r: &Request) -> (Result<usize, TokenError>, u64) {
        let res = self.session.authorize(&request_facts(r), self.limits);
        (res, self.session.last_run().steps)
    }
}

/// A decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Outside reach or too risky for it: a grant could allow it. The proxy may escalate.
    NeedsGrant(String),
    /// Never allowed by this token, whatever is granted.
    Forbidden(String),
}

/// A token loaded once, for many requests. `Send + Sync`: share it between a node's threads.
pub struct Loaded {
    token: Token,
    prepared: PreparedAuthorizer,
    compiled: CompiledAuthorizer,
    vetted: Vetted,
    ids: Vec<Vec<u8>>,
    limits: PreparedLimits,
}

/// Verifies, checks revocation, checks structure, then prepares and compiles. `revoked` is asked
/// about every block's revocation id; a token with any revoked block is refused.
pub fn load(bytes: &[u8], root: &PublicKey, revoked: &dyn Fn(&[u8]) -> bool) -> Result<Loaded, AuthzError> {
    load_with(bytes, root, revoked, &Policy::default(), limits())
}

/// [`load`] with explicit caps and limits (tests and benchmarks).
pub fn load_with(
    bytes: &[u8],
    root: &PublicKey,
    revoked: &dyn Fn(&[u8]) -> bool,
    policy: &Policy,
    limits: PreparedLimits,
) -> Result<Loaded, AuthzError> {
    if bytes.len() > policy.max_token_bytes {
        return Err(AuthzError::Structure(format!("token is {} bytes (cap {})", bytes.len(), policy.max_token_bytes)));
    }
    let biscuit = Biscuit::from(bytes, biscuit_key(root)?).map_err(|e| AuthzError::Load(e.to_string()))?;
    let ids = biscuit.revocation_identifiers();
    if let Some(i) = ids.iter().position(|id| revoked(id)) {
        return Err(AuthzError::Revoked(i));
    }
    let vetted = structure::check(&biscuit, bytes.len(), policy).map_err(AuthzError::Structure)?;
    let prepared = authorizer().prepare(&biscuit, &limits).map_err(|e| AuthzError::Load(e.to_string()))?;
    if let Some(e) = prepared.prepare_error() {
        return Err(AuthzError::Load(format!("token facts: {e}")));
    }
    let compiled = prepared.compile();
    Ok(Loaded { token: Token(biscuit), prepared, compiled, vetted, ids, limits })
}

impl Loaded {
    pub fn decide(&self, r: &Request) -> Decision {
        if let Action::Http { host, .. } = &r.action {
            if let Some(why) = wicket_core::never_reachable(host) {
                return Decision::Forbidden(why);
            }
        }
        self.classify(self.compiled.authorize(&request_facts(r), &self.limits))
    }

    /// Every block's revocation id, in block order.
    pub fn revocation_ids(&self) -> &[Vec<u8>] {
        &self.ids
    }

    pub fn token(&self) -> &Token {
        &self.token
    }

    /// Whether the compiled evaluator handles this token (otherwise every request uses the generic
    /// engine, with the same results).
    pub fn is_compiled(&self) -> bool {
        self.compiled.is_compiled()
    }

    /// Steps the last request on this thread took.
    pub fn last_steps(&self) -> u64 {
        self.compiled.last_run().steps
    }

    /// Whether the last request on this thread ran in the generic engine instead of the compiled one.
    #[doc(hidden)]
    pub fn last_fell_back(&self) -> bool {
        self.compiled.last_run().fallback
    }

    /// The raw result of the compiled evaluator (tests: the differential against the generic engine).
    #[doc(hidden)]
    pub fn authorize_compiled(&self, r: &Request) -> Result<usize, TokenError> {
        self.compiled.authorize(&request_facts(r), &self.limits)
    }

    /// A session on the fork's generic engine over the same prepared token (tests: the differential).
    #[doc(hidden)]
    pub fn generic_session(&self) -> GenericSession<'_> {
        GenericSession { session: self.prepared.session(), limits: &self.limits }
    }

    /// The raw result of the fork's generic engine through the stock `AuthorizerBuilder` path (a new
    /// authorizer per request), with the same step budget and no effective time limit, and its step
    /// count.
    #[doc(hidden)]
    pub fn authorize_generic(&self, r: &Request) -> (Result<usize, TokenError>, u64) {
        let limits = AuthorizerLimits {
            max_facts: self.limits.max_facts,
            max_iterations: self.limits.max_iterations,
            max_time: Duration::from_secs(3600),
            max_steps: self.limits.max_steps,
        };
        let mut b = authorizer().set_limits(limits);
        for f in request_facts(r) {
            b = match b.fact(f) {
                Ok(b) => b,
                Err(e) => return (Err(e), 0),
            };
        }
        match b.build(&self.token.0) {
            Ok(mut a) => {
                let res = a.authorize();
                (res, a.elapsed_steps())
            }
            Err(e) => (Err(e), 0),
        }
    }

    /// The decision for a raw evaluator result.
    #[doc(hidden)]
    pub fn classify(&self, res: Result<usize, TokenError>) -> Decision {
        let checks = match res {
            Ok(_) => return Decision::Allow,
            Err(TokenError::FailedLogic(Logic::Unauthorized { checks, .. } | Logic::NoMatchingPolicy { checks })) => checks,
            Err(e) => return Decision::Forbidden(format!("evaluation failed: {e}")),
        };
        let mut hard = Vec::new();
        let mut soft = Vec::new();
        for c in &checks {
            match c {
                FailedCheck::Authorizer(a) => hard.push(format!("node: {}", a.rule)),
                FailedCheck::Block(b) => {
                    let class = self.vetted.classes.get(b.block_id as usize).and_then(|v| v.get(b.check_id as usize));
                    let text = format!("block {}: {}", b.block_id, b.rule);
                    match class {
                        Some(CheckClass::Escalatable) => soft.push(text),
                        _ => hard.push(text),
                    }
                }
            }
        }
        if !hard.is_empty() || soft.is_empty() {
            Decision::Forbidden(hard.join("; "))
        } else {
            Decision::NeedsGrant(soft.join("; "))
        }
    }
}
