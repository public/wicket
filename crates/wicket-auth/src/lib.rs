//! Minimal, strict WebAuthn verification for wicket's operator decisions (design §14.1.3).
//!
//! Deliberately narrow: passkeys with ES256 (P-256) only; user presence *and* user verification
//! required; exact RP ID and origin; cross-origin ceremonies rejected; a signature counter that must
//! increase when the authenticator keeps one. Attestation statements are not verified (the PoC
//! trusts whichever authenticator the operator enrols during the bootstrap step).
//!
//! The point of wicket's use: an approval's challenge is `sha256(nonce || decision)`, so the passkey
//! signature covers that exact decision, and the stored (clientDataJSON, authenticatorData,
//! signature) triple can be re-verified offline by anyone holding the operator's public key.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("client data type is {0:?}, expected {1:?}")]
    WrongType(String, &'static str),
    #[error("challenge does not match the one issued")]
    ChallengeMismatch,
    #[error("origin {0:?} does not match {1:?}")]
    OriginMismatch(String, String),
    #[error("cross-origin ceremonies are not accepted")]
    CrossOrigin,
    #[error("RP ID hash does not match")]
    RpIdMismatch,
    #[error("user presence flag missing")]
    NoUserPresence,
    #[error("user verification flag missing (a PIN or biometric is required)")]
    NoUserVerification,
    #[error("only ES256 (P-256) passkeys are accepted")]
    UnsupportedKey,
    #[error("signature does not verify")]
    BadSignature,
    #[error("signature counter went backwards ({0} after {1}): possible cloned authenticator")]
    CounterRegressed(u32, u32),
}

pub type Result<T> = std::result::Result<T, AuthError>;

pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64u(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|_| AuthError::Malformed("base64url"))
}

/// The challenge for a decision: binds a server nonce to the exact decision text.
pub fn decision_challenge(nonce: &[u8], decision: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"wicket-decision-v1\0");
    h.update(nonce);
    h.update([0u8]);
    h.update(decision.as_bytes());
    h.finalize().into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub id: Vec<u8>,
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub sign_count: u32,
}

impl Credential {
    fn key(&self) -> Result<VerifyingKey> {
        let point = EncodedPoint::from_affine_coordinates(&self.x.into(), &self.y.into(), false);
        VerifyingKey::from_encoded_point(&point).map_err(|_| AuthError::UnsupportedKey)
    }
}

pub struct RelyingParty {
    pub rp_id: String,
    pub origin: String,
}

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;

struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    rest: &'a [u8],
}

fn parse_auth_data(a: &[u8]) -> Result<AuthData<'_>> {
    if a.len() < 37 {
        return Err(AuthError::Malformed("authenticator data"));
    }
    Ok(AuthData {
        rp_id_hash: &a[..32],
        flags: a[32],
        sign_count: u32::from_be_bytes([a[33], a[34], a[35], a[36]]),
        rest: &a[37..],
    })
}

impl RelyingParty {
    fn check_client_data(&self, cdj: &[u8], ty: &'static str, challenge: &[u8]) -> Result<()> {
        let v: serde_json::Value = serde_json::from_slice(cdj).map_err(|_| AuthError::Malformed("clientDataJSON"))?;
        let got_ty = v.get("type").and_then(|t| t.as_str()).ok_or(AuthError::Malformed("clientDataJSON type"))?;
        if got_ty != ty {
            return Err(AuthError::WrongType(got_ty.into(), ty));
        }
        let ch = v.get("challenge").and_then(|t| t.as_str()).ok_or(AuthError::Malformed("clientDataJSON challenge"))?;
        if unb64u(ch)? != challenge {
            return Err(AuthError::ChallengeMismatch);
        }
        let origin = v.get("origin").and_then(|t| t.as_str()).ok_or(AuthError::Malformed("clientDataJSON origin"))?;
        if origin != self.origin {
            return Err(AuthError::OriginMismatch(origin.into(), self.origin.clone()));
        }
        if v.get("crossOrigin").and_then(|c| c.as_bool()).unwrap_or(false) {
            return Err(AuthError::CrossOrigin);
        }
        Ok(())
    }

    fn check_flags_and_rp(&self, ad: &AuthData<'_>) -> Result<()> {
        if ad.rp_id_hash != Sha256::digest(self.rp_id.as_bytes()).as_slice() {
            return Err(AuthError::RpIdMismatch);
        }
        if ad.flags & UP == 0 {
            return Err(AuthError::NoUserPresence);
        }
        if ad.flags & UV == 0 {
            return Err(AuthError::NoUserVerification);
        }
        Ok(())
    }

    /// Verifies a `navigator.credentials.create()` response and returns the new credential.
    pub fn verify_registration(&self, challenge: &[u8], client_data_json: &[u8], attestation_object: &[u8]) -> Result<Credential> {
        self.check_client_data(client_data_json, "webauthn.create", challenge)?;
        let att: ciborium::Value = ciborium::de::from_reader(attestation_object).map_err(|_| AuthError::Malformed("attestation object"))?;
        let auth_data = map_get_text(&att, "authData").and_then(|v| v.as_bytes().cloned()).ok_or(AuthError::Malformed("attestation authData"))?;
        let ad = parse_auth_data(&auth_data)?;
        self.check_flags_and_rp(&ad)?;
        if ad.flags & AT == 0 || ad.rest.len() < 18 {
            return Err(AuthError::Malformed("attested credential data"));
        }
        let id_len = u16::from_be_bytes([ad.rest[16], ad.rest[17]]) as usize;
        if ad.rest.len() < 18 + id_len || id_len == 0 || id_len > 1023 {
            return Err(AuthError::Malformed("credential id"));
        }
        let id = ad.rest[18..18 + id_len].to_vec();
        let cose: ciborium::Value = ciborium::de::from_reader(&ad.rest[18 + id_len..]).map_err(|_| AuthError::Malformed("credential public key"))?;
        let int = |k: i64| map_get_int(&cose, k);
        let is = |k: i64, want: i64| int(k).and_then(|v| v.as_integer()).map(|i| i128::from(i) == want as i128).unwrap_or(false);
        if !(is(1, 2) && is(3, -7) && is(-1, 1)) {
            return Err(AuthError::UnsupportedKey);
        }
        let coord = |k: i64| -> Result<[u8; 32]> {
            let b = int(k).and_then(|v| v.as_bytes().cloned()).ok_or(AuthError::UnsupportedKey)?;
            b.try_into().map_err(|_| AuthError::UnsupportedKey)
        };
        let cred = Credential { id, x: coord(-2)?, y: coord(-3)?, sign_count: ad.sign_count };
        cred.key()?; // the point must be on the curve
        Ok(cred)
    }

    /// Verifies a `navigator.credentials.get()` response for `cred`. Returns the new signature
    /// counter, which the caller must store.
    pub fn verify_assertion(&self, challenge: &[u8], cred: &Credential, client_data_json: &[u8], authenticator_data: &[u8], signature_der: &[u8]) -> Result<u32> {
        self.check_client_data(client_data_json, "webauthn.get", challenge)?;
        let ad = parse_auth_data(authenticator_data)?;
        self.check_flags_and_rp(&ad)?;
        let mut msg = authenticator_data.to_vec();
        msg.extend_from_slice(&Sha256::digest(client_data_json));
        let sig = Signature::from_der(signature_der).map_err(|_| AuthError::BadSignature)?;
        cred.key()?.verify(&msg, &sig).map_err(|_| AuthError::BadSignature)?;
        if (ad.sign_count != 0 || cred.sign_count != 0) && ad.sign_count <= cred.sign_count {
            return Err(AuthError::CounterRegressed(ad.sign_count, cred.sign_count));
        }
        Ok(ad.sign_count)
    }
}

fn map_get_text<'a>(v: &'a ciborium::Value, key: &str) -> Option<&'a ciborium::Value> {
    v.as_map()?.iter().find(|(k, _)| k.as_text() == Some(key)).map(|(_, v)| v)
}

fn map_get_int(v: &ciborium::Value, key: i64) -> Option<&ciborium::Value> {
    v.as_map()?.iter().find(|(k, _)| k.as_integer().map(i128::from) == Some(key as i128)).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    const ORIGIN: &str = "http://localhost:8787";

    fn rp() -> RelyingParty {
        RelyingParty { rp_id: "localhost".into(), origin: ORIGIN.into() }
    }

    fn cdj(ty: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        serde_json::json!({ "type": ty, "challenge": b64u(challenge), "origin": origin, "crossOrigin": false }).to_string().into_bytes()
    }

    fn auth_data(flags: u8, count: u32, attested: Option<(&[u8], &SigningKey)>) -> Vec<u8> {
        let mut a = Sha256::digest(b"localhost").to_vec();
        a.push(flags);
        a.extend_from_slice(&count.to_be_bytes());
        if let Some((id, key)) = attested {
            a.extend_from_slice(&[0u8; 16]);
            a.extend_from_slice(&(id.len() as u16).to_be_bytes());
            a.extend_from_slice(id);
            let p = key.verifying_key().to_encoded_point(false);
            let cose = ciborium::Value::Map(vec![
                (1.into(), 2.into()),
                (3.into(), (-7).into()),
                ((-1).into(), 1.into()),
                ((-2).into(), ciborium::Value::Bytes(p.x().unwrap().to_vec())),
                ((-3).into(), ciborium::Value::Bytes(p.y().unwrap().to_vec())),
            ]);
            ciborium::ser::into_writer(&cose, &mut a).unwrap();
        }
        a
    }

    fn register(key: &SigningKey) -> Credential {
        let challenge = [7u8; 32];
        let ad = auth_data(UP | UV | AT, 0, Some((b"cred-1", key)));
        let att = ciborium::Value::Map(vec![
            ("fmt".into(), "none".into()),
            ("attStmt".into(), ciborium::Value::Map(vec![])),
            ("authData".into(), ciborium::Value::Bytes(ad)),
        ]);
        let mut att_bytes = Vec::new();
        ciborium::ser::into_writer(&att, &mut att_bytes).unwrap();
        rp().verify_registration(&challenge, &cdj("webauthn.create", &challenge, ORIGIN), &att_bytes).unwrap()
    }

    fn assert_with(key: &SigningKey, challenge: &[u8], flags: u8, count: u32, origin: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let c = cdj("webauthn.get", challenge, origin);
        let ad = auth_data(flags, count, None);
        let mut msg = ad.clone();
        msg.extend_from_slice(&Sha256::digest(&c));
        let sig: Signature = key.sign(&msg);
        (c, ad, sig.to_der().as_bytes().to_vec())
    }

    #[test]
    fn registration_then_bound_decision_verifies() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let cred = register(&key);
        assert_eq!(cred.id, b"cred-1");
        let ch = decision_challenge(b"nonce-1", r#"{"request":"r-1","decision":"approve","uses":1}"#);
        let (c, ad, sig) = assert_with(&key, &ch, UP | UV, 1, ORIGIN);
        assert_eq!(rp().verify_assertion(&ch, &cred, &c, &ad, &sig), Ok(1));
    }

    #[test]
    fn a_signature_for_one_decision_does_not_approve_another() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let cred = register(&key);
        let signed = decision_challenge(b"n", r#"{"request":"r-1","decision":"approve","uses":1}"#);
        let wanted = decision_challenge(b"n", r#"{"request":"r-1","decision":"approve","uses":1000}"#);
        let (c, ad, sig) = assert_with(&key, &signed, UP | UV, 1, ORIGIN);
        assert_eq!(rp().verify_assertion(&wanted, &cred, &c, &ad, &sig), Err(AuthError::ChallengeMismatch));
    }

    #[test]
    fn rejects_missing_uv_wrong_origin_bad_sig_and_counter_regression() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let mut cred = register(&key);
        let ch = [1u8; 32];
        let (c, ad, sig) = assert_with(&key, &ch, UP, 1, ORIGIN);
        assert_eq!(rp().verify_assertion(&ch, &cred, &c, &ad, &sig), Err(AuthError::NoUserVerification));
        let (c, ad, sig) = assert_with(&key, &ch, UP | UV, 1, "https://evil.example");
        assert!(matches!(rp().verify_assertion(&ch, &cred, &c, &ad, &sig), Err(AuthError::OriginMismatch(_, _))));
        let other = SigningKey::random(&mut rand_core::OsRng);
        let (c, ad, sig) = assert_with(&other, &ch, UP | UV, 1, ORIGIN);
        assert_eq!(rp().verify_assertion(&ch, &cred, &c, &ad, &sig), Err(AuthError::BadSignature));
        cred.sign_count = 5;
        let (c, ad, sig) = assert_with(&key, &ch, UP | UV, 3, ORIGIN);
        assert_eq!(rp().verify_assertion(&ch, &cred, &c, &ad, &sig), Err(AuthError::CounterRegressed(3, 5)));
    }
}
