//! Compact JWS (RFC 7515), EdDSA over Ed25519 only: the one implementation behind identity
//! documents, envelopes, node certificates and proofs, audit checkpoints and the policy feed. It
//! knows nothing about headers beyond `alg`: each caller checks its own `typ` and key id, in its own
//! order, and maps failures to its own errors.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// base64url without padding, as every part of a compact JWS is encoded.
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    B64.encode(bytes)
}

/// Decodes one base64url part; None if it isn't base64url.
pub fn decode(part: &str) -> Option<Vec<u8>> {
    B64.decode(part).ok()
}

/// Signs serialised `header` and `payload` JSON: `b64(header).b64(payload).b64(signature)`.
pub fn sign(key: &SigningKey, header: &[u8], payload: &[u8]) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(payload));
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}

/// A compact JWS split into its three parts, still encoded.
#[derive(Debug, Clone, Copy)]
pub struct Parts<'a> {
    pub header: &'a str,
    pub payload: &'a str,
    pub signature: &'a str,
    jws: &'a str,
}

/// Splits a compact JWS: exactly three dot-separated parts, or None.
pub fn split(jws: &str) -> Option<Parts<'_>> {
    let mut it = jws.split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(header), Some(payload), Some(signature), None) => Some(Parts { header, payload, signature, jws }),
        _ => None,
    }
}

/// Why a signature didn't verify.
#[derive(Debug, PartialEq, Eq)]
pub enum BadSignature {
    /// The signature part isn't 64 bytes of base64url.
    Malformed,
    /// Well-formed, but not by this key over these bytes.
    Mismatch,
}

impl Parts<'_> {
    /// Whether `key` signed this header and payload (strict Ed25519: no weak keys, no malleable
    /// signatures). Never panics, whatever the input.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), BadSignature> {
        let sig = decode(self.signature).and_then(|b| Signature::from_slice(&b).ok()).ok_or(BadSignature::Malformed)?;
        let signed = &self.jws.as_bytes()[..self.header.len() + 1 + self.payload.len()];
        key.verify_strict(signed, &sig).map_err(|_| BadSignature::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    #[test]
    fn signs_and_verifies_and_round_trips_its_parts() {
        let jws = sign(&key(), br#"{"alg":"EdDSA"}"#, br#"{"x":1}"#);
        let p = split(&jws).unwrap();
        assert_eq!(decode(p.header).unwrap(), br#"{"alg":"EdDSA"}"#);
        assert_eq!(decode(p.payload).unwrap(), br#"{"x":1}"#);
        assert_eq!(p.verify(&key().verifying_key()), Ok(()));
        assert_eq!(p.verify(&SigningKey::from_bytes(&[8; 32]).verifying_key()), Err(BadSignature::Mismatch));
    }

    #[test]
    fn anything_else_is_refused_without_panicking() {
        for bad in ["", "a", "a.b", "a.b.c.d", "..", "a.b.!!!"] {
            if let Some(p) = split(bad) {
                assert!(p.verify(&key().verifying_key()).is_err(), "{bad}");
            }
        }
        assert!(split("a.b").is_none() && split("a.b.c.d").is_none());
        let jws = sign(&key(), b"{}", b"{}");
        let p = split(&jws).unwrap();
        let short = format!("{}.{}.{}", p.header, p.payload, encode([0u8; 63]));
        assert_eq!(split(&short).unwrap().verify(&key().verifying_key()), Err(BadSignature::Malformed));
        let tampered = format!("{}.{}.{}", p.header, encode(b"{\"x\":2}"), p.signature);
        assert_eq!(split(&tampered).unwrap().verify(&key().verifying_key()), Err(BadSignature::Mismatch));
    }
}
