//! wicket-core: the types every other crate shares, and the pure decision function.
//!
//! Proof-of-concept scope (see docs/explanation/design.md): a single tenant (`t0`) with tenant ids carried
//! everywhere so multi-tenant mode can be added without changing identifiers; one zone per run;
//! HTTP reach rules; a small GitHub dangerous-pattern list; and a decision that is either allowed by
//! a reach rule, forbidden outright, or needs a grant from the ledger.

pub mod canon;
pub mod link;
pub mod manifest;
pub mod op;
pub mod splice;
pub mod subset;
pub mod text;

pub use canon::{canonical_host, canonical_path, prefix_covers, prefix_dir, CanonError};
pub use manifest::{
    AgentSpec, InjectRule, Isolation, Limits, LlmSpec, Manifest, OnPending, Persist, ProgramSpec, ReachRule, VolumeSpec, ZoneSpec,
};
pub use op::{evaluate, host_verdict, is_public_ip, never_reachable, CompiledZone, HostVerdict, Op, RiskClass, Surface, Verdict};

use serde::{Deserialize, Serialize};
use std::fmt;

/// A tenant. Single-tenant installations use [`TenantId::single`] (`t0`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub String);

impl TenantId {
    pub fn single() -> Self {
        TenantId("t0".into())
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::single()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One run of one agent in one zone (an "activation" in design terms).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(pub String);

impl RunId {
    pub fn new() -> Self {
        RunId(format!("run_{}", ulid::Ulid::new().to_string().to_lowercase()))
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Short, human-typable id for escalation requests, e.g. `r-01jc4x2k`.
pub fn new_request_id() -> String {
    let u = ulid::Ulid::new().to_string().to_lowercase();
    format!("r-{}", &u[u.len() - 8..])
}

/// Short id for grants.
pub fn new_grant_id() -> String {
    let u = ulid::Ulid::new().to_string().to_lowercase();
    format!("g-{}", &u[u.len() - 8..])
}

/// Short id for links between boxes, e.g. `l-01jc4x2k9q`.
pub fn new_link_id() -> String {
    let u = ulid::Ulid::new().to_string().to_lowercase();
    format!("l-{}", &u[u.len() - 10..])
}
