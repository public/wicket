//! wicket-core: the types every other crate shares, and the pure decision function.
//!
//! Proof-of-concept scope (see docs/explanation/design.md): a single tenant (`t0`) with tenant ids carried
//! everywhere so multi-tenant mode can be added without changing identifiers; one zone per run;
//! HTTP reach rules; a small GitHub dangerous-pattern list; and a decision that is either allowed by
//! a reach rule, forbidden outright, or needs a grant from the ledger.

pub mod authority;
pub mod budget;
pub mod canon;
pub mod effect;
pub mod escalation;
pub mod git;
pub mod image;
pub mod link;
pub mod manifest;
pub mod op;
pub mod quota;
pub mod splice;
pub mod subset;
pub mod text;
pub mod time;
pub mod timing;
pub mod version;
pub mod yaml;

pub use canon::{canonical_host, canonical_path, prefix_covers, prefix_dir, CanonError};
pub use manifest::{
    AcpSpec, AgentSpec, Escalation, Harness, InjectRule, Isolation, Limits, LlmSpec, Manifest, ManifestError, ModelRoute, Persist,
    ProgramSpec, ReachRule, RemotePermissionMode, RemoteSpec, VolumeSpec, WildcardSpec, ZoneSpec,
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

/// A new ULID: the time now (ms) and 80 random bits, as `new_ulid()` makes one, but from the
/// OS's randomness (getrandom) instead of rand's thread generator, so the build has one rand (#219).
pub fn new_ulid() -> ulid::Ulid {
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    let mut r = [0u8; 16];
    getrandom::fill(&mut r).expect("the OS's randomness");
    ulid::Ulid::from_parts(ms, u128::from_le_bytes(r))
}

/// One run of one agent in one zone (an "activation" in design terms).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(pub String);

impl RunId {
    pub fn new() -> Self {
        RunId(format!("run_{}", new_ulid().to_string().to_lowercase()))
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

/// Short, human-typable id for requests, e.g. `r-01jc4x2k`.
pub fn new_request_id() -> String {
    let u = new_ulid().to_string().to_lowercase();
    format!("r-{}", &u[u.len() - 8..])
}

/// Short id for grants.
pub fn new_grant_id() -> String {
    let u = new_ulid().to_string().to_lowercase();
    format!("g-{}", &u[u.len() - 8..])
}

/// Short id for links between boxes, e.g. `l-01jc4x2k9q`.
pub fn new_link_id() -> String {
    let u = new_ulid().to_string().to_lowercase();
    format!("l-{}", &u[u.len() - 10..])
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod ulid_tests {
    /// #219: ids made without ulid's rand are ULIDs of the time they were made, and don't repeat.
    #[test]
    fn new_ulids_carry_the_time_and_are_distinct() {
        let before = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let ids: std::collections::HashSet<_> = (0..1000).map(|_| super::new_ulid()).collect();
        let after = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        assert_eq!(ids.len(), 1000);
        assert!(ids.iter().all(|u| (before..=after).contains(&u.timestamp_ms()) && u.random() != 0));
        let r = super::RunId::new();
        assert!(r.0.starts_with("run_") && r.0.len() == 30 && ulid::Ulid::from_string(&r.0[4..]).is_ok(), "{r}");
    }
}
