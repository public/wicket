//! wicket's policy feed (#57, research 18 §5.1 architecture A): how a node keeps deciding locally,
//! from signed policy, while the control host is unreachable, and how it fails narrow.
//!
//! This crate is a library only: no sockets, no threads, no timers. Every function that depends on
//! time takes `now` (Unix milliseconds) from the caller, so tests inject the clock. The transport
//! (ssh, later) carries [`Frame`]s, one JSON line each.
//!
//! - **Format** ([`format`]): a pinned **root key** (offline) certifies each node feed's online
//!   **feed key** with a `version`, an expiry and caps on the freshness it may sign ([`KeyCert`]).
//!   The feed key signs a **snapshot**, hash-chained **deltas** (each a batch of changes) and short
//!   **freshness statements**, re-signed on a timer (TUF's timestamp role). All are compact JWS
//!   (Ed25519), with `typ` separating the kinds.
//! - **State** ([`State`]): zone policies (a [`Policy`]: `wicket_core::ZoneSpec` today, compiled once
//!   when applied), grants bound to `Op::digest` with expiry, use count and box, revocations of
//!   grant, run and token ids with an `until` so the set stays bounded, and the epoch.
//! - **Node side** ([`Replica`]): verifies, applies, refuses; persists what it verified; computes the
//!   [`Mode`] and [`Replica::decide`]s ops.
//! - **Control-plane side** ([`Publisher`]): a durable delta log (fsync before publishing),
//!   snapshots, statements and catch-up.
//!
//! # Modes (the fail-narrow rule)
//!
//! | mode | when | allowed |
//! |---|---|---|
//! | [`Mode::Fresh`] | a statement names an epoch the node holds, and its effective `fresh_until` hasn't passed | everything the zone and the live grants allow; leases, spawns, approvals |
//! | [`Mode::Narrow`] | not fresh, but the last statement that vouched for the state held has an open `narrow_until` | only ops the zone allows by reach at risk ≤ R1 (reads); no grants, leases, spawns, approvals or R2+ writes |
//! | [`Mode::Closed`] | no state, a feed key past its certificate, or past `narrow_until` | nothing |
//!
//! In every mode, `Forbidden` stays forbidden, revoked runs are refused, and grant expiry is checked
//! against the node's own clock. A node that has accepted a statement naming an epoch it hasn't
//! reached is *lagging*, and lagging counts as stale, because the missing deltas may hold a
//! revocation.
//!
//! # Bounds (with the defaults)
//!
//! - Revocation of grants, leases and runs: as soon as the delta applies (about 1 ms with push), and
//!   at worst [`DEFAULT_TTL_MS`] (30 s) after it is committed when the node hears nothing at all.
//! - Removing a reach rule, for plain reads on a partitioned node: at worst TTL + narrow window
//!   (150 s).
//! - A partitioned node refuses everything 150 s after the last statement it received was issued.
//!
//! Both bounds also include node-versus-control-plane clock skew, up to
//! [`DEFAULT_FUTURE_TOLERANCE_MS`] (see [`ReplicaConfig`]).

pub mod format;
pub mod jws;
pub mod publisher;
pub mod replica;
pub mod state;
mod store;
pub mod token;

pub use format::{Change, Delta, Frame, FrameKind, Fresh, Grant, Hello, KeyCert, RevokeKind, Revoked, Snapshot, GENESIS, MAX_FRAME_BYTES};
pub use jws::{kid, sha, sign, sign_as, TYP_DELTA, TYP_FRESH, TYP_KEY, TYP_SNAP};
pub use publisher::{PublishError, Publisher, PublisherConfig};
pub use replica::{Allowed, Decision, Escalation, LoadError, Mode, Replica, ReplicaConfig, Stats};
pub use state::{Policy, State, Zone};
pub use token::{BoxAuthority, CompiledAuthority, Issuer, LiveGrant, TokenGrant};

use wicket_core::RiskClass;

/// How long a freshness statement keeps a node fresh: `fresh_until − issued_at`.
pub const DEFAULT_TTL_MS: i64 = 30_000;
/// How often the publisher re-signs a statement. Six per TTL: five can be lost before a node narrows.
pub const DEFAULT_REFRESH_MS: i64 = 5_000;
/// How long a node keeps plain reads after `fresh_until`: `narrow_until − fresh_until`.
pub const DEFAULT_NARROW_MS: i64 = 120_000;
/// How far in the future (by the node's clock) a statement's `issued_at` may be.
pub const DEFAULT_FUTURE_TOLERANCE_MS: i64 = 2_000;
/// How many recent chain heads a node remembers, to check statements naming an older epoch.
pub const HEADS_KEPT: usize = 4096;
/// The riskiest op that may still run, on reach alone, while narrow.
pub const NARROW_MAX_RISK: RiskClass = RiskClass::R1ReadScoped;

/// Why an inbound artifact was refused. [`Refusal::kind`] names the counter it lands in.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("wrong artifact type: {0}")]
    WrongType(String),
    #[error("unknown key {0}")]
    UnknownKey(String),
    #[error("bad signature")]
    BadSignature,
    #[error("the feed key's certificate has expired")]
    KeyExpired,
    #[error("key certificate rollback: {0}")]
    KeyRollback(String),
    #[error("for another node's feed: {0}")]
    WrongAudience(String),
    #[error("made under certificate version {got}, expected {want}")]
    WrongVersion { want: u64, got: u64 },
    #[error("no snapshot held yet")]
    NoBase,
    #[error("replay: {0}")]
    Replay(String),
    #[error("rollback: {0}")]
    Rollback(String),
    #[error("gap: holding epoch {have}, got {got}")]
    Gap { have: u64, got: u64 },
    #[error("fork: {0}")]
    Fork(String),
    #[error("statement already expired")]
    Expired,
    #[error("statement issued in the future")]
    FromFuture,
    #[error("longer than certified: {0}")]
    TooLong(String),
    #[error("could not persist: {0}")]
    Storage(String),
}

impl Refusal {
    pub fn kind(&self) -> &'static str {
        match self {
            Refusal::Malformed(_) => "malformed",
            Refusal::WrongType(_) => "wrong_type",
            Refusal::UnknownKey(_) => "unknown_key",
            Refusal::BadSignature => "bad_signature",
            Refusal::KeyExpired => "key_expired",
            Refusal::KeyRollback(_) => "key_rollback",
            Refusal::WrongAudience(_) => "wrong_audience",
            Refusal::WrongVersion { .. } => "wrong_version",
            Refusal::NoBase => "no_base",
            Refusal::Replay(_) => "replay",
            Refusal::Rollback(_) => "rollback",
            Refusal::Gap { .. } => "gap",
            Refusal::Fork(_) => "fork",
            Refusal::Expired => "expired",
            Refusal::FromFuture => "from_future",
            Refusal::TooLong(_) => "too_long",
            Refusal::Storage(_) => "storage",
        }
    }

    /// Whether the node should reconnect and ask for catch-up from what it holds ([`Replica::hello`]).
    pub fn wants_catch_up(&self) -> bool {
        matches!(self, Refusal::Gap { .. } | Refusal::NoBase | Refusal::WrongVersion { .. })
    }
}

/// The current time in Unix milliseconds, for callers. Nothing in this crate calls it itself.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests;
