//! The feed's artifacts as compact JWS (EdDSA, Ed25519), over `wicket_identity::jws`, with the `typ`
//! header separating the kinds of artifact so one kind can't be replayed as another.

use crate::Refusal;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wicket_identity::jws;

/// `typ` of a root-signed feed-key certificate.
pub const TYP_KEY: &str = "wicket-feed-key+jws";
/// `typ` of a snapshot.
pub const TYP_SNAP: &str = "wicket-feed-snapshot+jws";
/// `typ` of a delta.
pub const TYP_DELTA: &str = "wicket-feed-delta+jws";
/// `typ` of a freshness statement.
pub const TYP_FRESH: &str = "wicket-feed-fresh+jws";
/// An authority issuing key's certificate, signed by the authority root (#154).
pub const TYP_AUTHZ_KEY: &str = "wicket-authz-key+jws";

/// The key id: the first 8 bytes of sha256 of the public key, in hex (the identity issuer's too).
pub fn kid(k: &VerifyingKey) -> String {
    wicket_identity::key_id(k)
}

/// sha256 of a string, in hex. A delta's chain head is `sha(delta JWS)`.
pub fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// Signs `payload` as a compact JWS of kind `typ`, with the key's own `kid`.
pub fn sign<T: Serialize>(key: &SigningKey, typ: &str, payload: &T) -> String {
    sign_as(key, typ, &kid(&key.verifying_key()), payload)
}

/// As [`sign`] with an explicit `kid` (tests use it to forge headers).
pub fn sign_as<T: Serialize>(key: &SigningKey, typ: &str, kid: &str, payload: &T) -> String {
    let header = Header { alg: "EdDSA".into(), typ: typ.into(), kid: kid.into() };
    // Serialising these types can't fail: plain structs with string keys.
    let h = serde_json::to_vec(&header).expect("header serialises");
    let p = serde_json::to_vec(payload).expect("payload serialises");
    jws::sign(key, &h, &p)
}

/// Verifies `typ`, `kid` and the signature (strict Ed25519), then decodes the payload. Never panics,
/// whatever the input.
pub fn open<T: DeserializeOwned>(jws: &str, typ: &str, want_kid: &str, key: &VerifyingKey) -> Result<T, Refusal> {
    let m = |s: &str| Refusal::Malformed(s.into());
    let parts = jws::split(jws).ok_or_else(|| m("not a compact JWS"))?;
    let hdr: Header =
        serde_json::from_slice(&jws::decode(parts.header).ok_or_else(|| m("header base64"))?).map_err(|_| m("header json"))?;
    if hdr.alg != "EdDSA" {
        return Err(m("alg"));
    }
    if hdr.typ != typ {
        return Err(Refusal::WrongType(format!("expected {typ}, got {}", hdr.typ)));
    }
    if hdr.kid != want_kid {
        return Err(Refusal::UnknownKey(hdr.kid));
    }
    parts.verify(key).map_err(|e| match e {
        jws::BadSignature::Malformed => m("signature"),
        jws::BadSignature::Mismatch => Refusal::BadSignature,
    })?;
    serde_json::from_slice(&jws::decode(parts.payload).ok_or_else(|| m("payload base64"))?)
        .map_err(|e| Refusal::Malformed(format!("payload: {e}")))
}

/// Decodes a JWS payload without verifying it. Only for data the caller already trusts (the
/// publisher's own log) or for tests.
pub fn payload_unverified<T: DeserializeOwned>(jws: &str) -> Option<T> {
    serde_json::from_slice(&jws::decode(jws::split(jws)?.payload)?).ok()
}

/// Replaces a JWS's payload, keeping its header and signature: a tampered artifact (tests).
#[cfg(test)]
pub(crate) fn tamper(jws: &str, payload: &serde_json::Value) -> String {
    let p = jws::split(jws).expect("a compact JWS");
    format!("{}.{}.{}", p.header, jws::encode(serde_json::to_vec(payload).unwrap()), p.signature)
}
