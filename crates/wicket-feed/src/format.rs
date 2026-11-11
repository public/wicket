//! The feed's artifacts and wire frames.
//!
//! | artifact | `typ` | signed by | payload |
//! |---|---|---|---|
//! | [`KeyCert`] | `wicket-feed-key+jws` | root key (pinned on the node) | feed key, `version`, `not_after`, caps |
//! | [`Snapshot`] | `wicket-feed-snapshot+jws` | feed key | the whole state at an epoch |
//! | [`Delta`] | `wicket-feed-delta+jws` | feed key | epoch n−1 → n, a batch of [`Change`]s |
//! | [`Fresh`] | `wicket-feed-fresh+jws` | feed key | latest epoch and head, `fresh_until`, `narrow_until` |
//!
//! Every snapshot, delta and statement names the certificate `version` it was made under and the
//! node it is for (`feed`), so artifacts from another generation (before a re-genesis) or from
//! another node's feed are refused outright.

use crate::Refusal;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The chain head before the first delta.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The largest frame [`Frame::parse`] reads: a snapshot of 10,000 grants is about 2.3 MB.
pub const MAX_FRAME_BYTES: usize = 16 << 20;

/// Root-signed certificate for one node feed's online key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCert {
    /// [`crate::kid`] of the feed key.
    pub kid: String,
    /// The feed key's public bytes, base64url.
    pub x: String,
    /// The feed's generation. Raising it is a re-genesis: nodes accept a snapshot at any epoch made
    /// under the new version, and refuse artifacts of older versions.
    pub version: u64,
    /// The key is refused, and the node closed, from this time (Unix ms).
    pub not_after: i64,
    /// Longest `fresh_until − issued_at` the key may sign.
    pub max_ttl_ms: i64,
    /// Longest `narrow_until − fresh_until` the key may sign.
    pub max_narrow_ms: i64,
}

impl KeyCert {
    pub fn new(feed_key: &VerifyingKey, version: u64, not_after: i64, max_ttl_ms: i64, max_narrow_ms: i64) -> KeyCert {
        KeyCert { kid: crate::kid(feed_key), x: B64.encode(feed_key.as_bytes()), version, not_after, max_ttl_ms, max_narrow_ms }
    }

    /// The certified key, checked against its `kid`.
    pub fn key(&self) -> Result<VerifyingKey, Refusal> {
        let bad = || Refusal::Malformed("certificate key".into());
        let x: [u8; 32] = B64.decode(&self.x).ok().and_then(|b| b.try_into().ok()).ok_or_else(bad)?;
        let k = VerifyingKey::from_bytes(&x).map_err(|_| bad())?;
        if crate::kid(&k) != self.kid || self.max_ttl_ms <= 0 || self.max_narrow_ms < 0 {
            return Err(bad());
        }
        Ok(k)
    }
}

/// A grant or lease: lets one op, by wicket-core's [`wicket_core::Op::digest`] (tenant, zone, method,
/// host, path), until `not_after` on the node's clock, at most `uses` times, optionally only for one box.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub zone: String,
    /// `Op::digest` of the op it allows.
    pub op: String,
    /// Human-readable op, for logs.
    #[serde(default)]
    pub what: String,
    /// Unix ms. Checked against the node's clock in every mode.
    pub not_after: i64,
    /// At most this many uses, counted on the node. `None`: unlimited until `not_after`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<u32>,
    /// The box (run id) it is for. `None`: any box in the zone.
    #[serde(default, rename = "box", skip_serializing_if = "Option::is_none")]
    pub box_id: Option<String>,
}

/// What a revocation id names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeKind {
    /// A grant or lease id.
    Grant,
    /// A run (box) id: every op of that run is refused.
    Run,
    /// A token revocation id (a capability chain link, #76).
    Token,
}

/// One change to the replicated state. A [`Delta`] carries a batch of them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[serde(bound(serialize = "P: Serialize", deserialize = "P: serde::de::DeserializeOwned"))]
pub enum Change<P> {
    /// Adds or replaces a zone's policy.
    PutZone {
        zone: P,
    },
    /// Removes a zone, and every grant in it.
    DropZone {
        name: String,
    },
    AddGrant {
        grant: Grant,
    },
    /// Revokes an id. `until` is when the entry may be dropped (the revoked thing's own expiry), so
    /// the revoked set stays bounded.
    Revoke {
        kind: RevokeKind,
        id: String,
        until: i64,
    },
}

/// One revocation, as held in a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoked {
    pub kind: RevokeKind,
    pub id: String,
    pub until: i64,
}

/// The whole state at an epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(bound(serialize = "P: Serialize", deserialize = "P: serde::de::DeserializeOwned"))]
pub struct Snapshot<P> {
    pub feed: String,
    pub version: u64,
    pub epoch: u64,
    pub head: String,
    pub issued_at: i64,
    pub zones: Vec<P>,
    pub grants: Vec<Grant>,
    pub revoked: Vec<Revoked>,
}

/// Epoch `epoch − 1` → `epoch`. Its head is `sha(JWS)`; `prev` is the head before it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(bound(serialize = "P: Serialize", deserialize = "P: serde::de::DeserializeOwned"))]
pub struct Delta<P> {
    pub feed: String,
    pub version: u64,
    pub epoch: u64,
    pub prev: String,
    pub issued_at: i64,
    pub changes: Vec<Change<P>>,
}

/// A freshness statement: "the latest epoch is `epoch` with head `head`; decide normally until
/// `fresh_until`, reads only until `narrow_until`". Re-signed every few seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fresh {
    pub feed: String,
    pub version: u64,
    pub epoch: u64,
    pub head: String,
    pub issued_at: i64,
    pub fresh_until: i64,
    pub narrow_until: i64,
}

/// What a frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameKind {
    Key,
    Snap,
    Delta,
    Fresh,
}

impl FrameKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FrameKind::Key => "key",
            FrameKind::Snap => "snap",
            FrameKind::Delta => "delta",
            FrameKind::Fresh => "fresh",
        }
    }
}

/// One frame on the wire: a line of JSON `{"t": "key|snap|delta|fresh", "jws": "…"}`. Integrity
/// comes from the signature alone, so the transport only has to provide confidentiality.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    #[serde(rename = "t")]
    pub kind: FrameKind,
    pub jws: String,
}

impl Frame {
    pub fn new(kind: FrameKind, jws: String) -> Frame {
        Frame { kind, jws }
    }

    /// Parses one inbound frame. Never panics; anything but a well-formed frame is `Malformed`.
    pub fn parse(bytes: &[u8]) -> Result<Frame, Refusal> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(Refusal::Malformed(format!("frame of {} bytes", bytes.len())));
        }
        serde_json::from_slice(bytes).map_err(|e| Refusal::Malformed(format!("frame: {e}")))
    }

    /// The frame as one line of JSON, with the trailing newline.
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).expect("frame serialises");
        s.push('\n');
        s
    }
}

/// What a node tells the publisher when it connects, so the publisher can choose deltas or a
/// snapshot. `None` fields: the node holds no state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub node: String,
    pub version: Option<u64>,
    pub epoch: Option<u64>,
    pub head: Option<String>,
}

/// Revoked ids by kind, for building snapshots.
pub(crate) type RevokedMap = BTreeMap<(RevokeKind, String), i64>;
