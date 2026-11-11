//! wicket-authz: a box's authority as a Biscuit token (design §2, "Identity is JWT; authority is
//! Biscuit"; issue #76, design A).
//!
//! - **Block 0** (root key, minted by the control plane): tenant, principal, the zone's ceiling as
//!   checks ([`mint`]).
//! - **Spawn blocks** (first-party, appended by the node that starts a child): the child's ceiling as
//!   checks ([`Token::attenuate`]). Biscuit requires every block's checks to pass, so a child can't
//!   exceed its parent, whatever a block says.
//! - **Grant blocks** (third-party, signed by the approval service or a parent box's grantor key): one
//!   `approved(gid, host, method, path)` rule that holds while the lease is live and the ledger has
//!   uses left ([`grant`], or [`Token::grant_request`] / [`sign_grant`] / [`Token::add_grant`]). A
//!   ceiling's reach and risk checks accept it only from the keys that ceiling lists.
//! - **Load once, decide many** ([`load`], [`Loaded::decide`]): signatures, revocation ids of every
//!   block, a strict structural check (`structure`), then the fork's prepared + compiled evaluator
//!   with a deterministic step budget ([`STEP_BUDGET`]).
//!
//! Everything is behind wicket's own types ([`Ceiling`], [`Grant`], [`Request`], [`Decision`],
//! [`Token`]), so the format can change without touching callers. Block layout and encoding rules
//! are in `generator`; the structural rules in `structure`; how denials are classified in `decide`.

pub mod decide;
pub mod generator;
pub mod payload;
pub mod structure;
pub mod token;

pub use decide::{limits, load, load_with, Decision, Loaded, MEASURED_MAX_STEPS, STEP_BUDGET};
pub use payload::{
    isolation_level, risk_level, Action, Ceiling, Forbid, Grant, Inject, LlmBudget, OpKind, PublicKey, Reach, Request, SpawnLimits,
    MAX_REACH_RISK,
};
pub use structure::Policy;
pub use token::{grant, mint, sign_grant, GrantRequest, SignedGrant, SigningKey, Token};

/// Re-exported for tests and tools that need the token format itself.
#[doc(hidden)]
pub use biscuit_auth;

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    /// A ceiling that can't be encoded (bad host, glob, or over a structural cap).
    #[error("ceiling: {0}")]
    Ceiling(String),
    #[error("encoding: {0}")]
    Encode(String),
    /// Bad bytes, a bad signature or the wrong root key.
    #[error("load: {0}")]
    Load(String),
    /// Block `n`'s revocation id is revoked.
    #[error("block {0} is revoked")]
    Revoked(usize),
    /// The token isn't shaped like what wicket generates.
    #[error("structure: {0}")]
    Structure(String),
}

/// The revocation ids of a token's blocks, in block order (without loading it for decisions).
pub fn revocation_ids(token: &Token) -> Vec<Vec<u8>> {
    token.revocation_ids()
}
