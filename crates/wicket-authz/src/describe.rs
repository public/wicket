//! A token, decoded for people (#173): each block's Datalog, whether a third party signed it (and
//! with which public key), and its revocation id. Never the serialized token or a signature: what
//! the console shows a run's authority with.
//!
//! Decoding doesn't verify (the views show what a feed holds; the node verifies before it decides).

use crate::AuthzError;
use biscuit_auth::UnverifiedBiscuit;

/// One block, decoded.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct BlockView {
    pub index: usize,
    /// Its facts, rules and checks, as Datalog source.
    pub source: String,
    /// For a third-party block (a grant), the signing key's public half, as Biscuit prints it.
    pub external_key: Option<String>,
    /// Its revocation id, hex (what a feed's `Revoke { kind: Token }` names).
    pub revocation_id: String,
}

/// Decodes every block of a serialized token.
pub fn describe(bytes: &[u8]) -> Result<Vec<BlockView>, AuthzError> {
    let t = UnverifiedBiscuit::from(bytes).map_err(|e| AuthzError::Load(e.to_string()))?;
    let ids = t.revocation_identifiers();
    let keys = t.external_public_keys();
    (0..t.block_count())
        .map(|i| {
            Ok(BlockView {
                index: i,
                source: t.print_block_source(i).map_err(|e| AuthzError::Load(e.to_string()))?,
                external_key: keys.get(i).cloned().flatten().map(|k| k.to_string()),
                revocation_id: ids.get(i).map(hex::encode).unwrap_or_default(),
            })
        })
        .collect()
}
