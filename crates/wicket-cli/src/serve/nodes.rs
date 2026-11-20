//! The console's node views (#573): a node's CA, the same view `wicket node ca` prints
//! ([`crate::enrol::ca_view`]): the hosts its active CA is constrained to and those it was enrolled
//! with, how it may be widened at runtime, what live runs want of it, what the next renewal signs,
//! and its last widenings. Read-only: the policy is set on the host (`wicket node set --ca-hosts`).

use super::State;
use anyhow::{bail, Result};
use serde_json::Value;

/// The GET endpoints here, for an operator's session. None: not one of them.
pub(super) fn get(state: &State, path: &str) -> Option<Result<Value>> {
    let name = path.strip_prefix("/api/nodes/")?.strip_suffix("/ca")?;
    Some(ca(state, name))
}

/// `GET /api/nodes/<name>/ca`. Another tenant's node is not found, as one never enrolled is.
fn ca(state: &State, name: &str) -> Result<Value> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        bail!("no node {name:?}");
    }
    let l = state.ledger()?;
    match crate::enrol::ca_view(&l, name, wicket_store::now())? {
        Some(v) if v["tenant"].as_str() == Some(state.tenant.0.as_str()) => Ok(v),
        _ => bail!("no node {name}"),
    }
}
