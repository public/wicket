//! Image signatures (#191): checked host-side against the installation's trust policy before a
//! box starts, never in the box. The image is already identified by its digest, and its node checks
//! the bytes against that digest; a signature binds a trusted key to the digest.
//!
//! A [`Scheme`] is one signature format: where its signatures for a digest live in a registry, and
//! how one is checked against the keys a policy names. Nothing outside this module knows a format.
//! [`cosign`] is the one there is, for signatures made with a key (`cosign sign --key …`): no
//! keyless signing, so no Fulcio certificates, Rekor proofs or TUF root (#191's proposal).
//!
//! Keys are PEM public keys (SPKI): ECDSA P-256, cosign's default, or Ed25519. Both are checked with
//! the RustCrypto crates (`p256`, `ed25519-dalek`) the token format already builds in.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// A public key a trust policy names.
#[derive(Clone, Debug)]
pub enum Key {
    EcdsaP256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl Key {
    /// A PEM public key (`-----BEGIN PUBLIC KEY-----`, SPKI), of either kind.
    pub fn from_pem(pem: &str) -> Result<Key> {
        use p256::pkcs8::DecodePublicKey as _;
        if let Ok(k) = p256::ecdsa::VerifyingKey::from_public_key_pem(pem) {
            return Ok(Key::EcdsaP256(k));
        }
        if let Ok(k) = ed25519_dalek::VerifyingKey::from_public_key_pem(pem) {
            return Ok(Key::Ed25519(k));
        }
        bail!("not a PEM public key of a kind wicket checks (ECDSA P-256 or Ed25519)")
    }

    /// `sha256:<hex>` of the key's SPKI encoding: what the audit names it by.
    pub fn fingerprint(&self) -> String {
        use p256::pkcs8::EncodePublicKey as _;
        let der = match self {
            Key::EcdsaP256(k) => k.to_public_key_der().map(|d| d.as_bytes().to_vec()),
            Key::Ed25519(k) => k.to_public_key_der().map(|d| d.as_bytes().to_vec()),
        }
        .expect("a parsed key encodes");
        format!("sha256:{}", hex::encode(Sha256::digest(der)))
    }

    /// Whether `sig` is this key's signature over `msg`: for P-256, ASN.1 DER over its SHA-256
    /// (either form of `s`, as Go's signers make both); for Ed25519, the 64 bytes, checked strictly.
    pub fn verifies(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            Key::EcdsaP256(k) => {
                use p256::ecdsa::signature::Verifier as _;
                p256::ecdsa::Signature::from_der(sig).is_ok_and(|s| k.verify(msg, &s.normalize_s()).is_ok())
            }
            Key::Ed25519(k) => ed25519_dalek::Signature::from_slice(sig).is_ok_and(|s| k.verify_strict(msg, &s).is_ok()),
        }
    }
}

/// What a signature is checked for: the image's digest, and its repository (`host/repository`).
#[derive(Clone, Copy, Debug)]
pub struct Subject<'a> {
    pub digest: &'a str,
    pub repository: &'a str,
}

/// A signature artifact as a registry holds it: its manifest (and that manifest's digest) and the
/// layers it names, each already checked against its descriptor's digest.
#[derive(Clone, Debug, Default)]
pub struct Artifact {
    pub digest: String,
    pub manifest: Vec<u8>,
    pub layers: Vec<Vec<u8>>,
}

/// A signature that verified: which scheme, the key's [`Key::fingerprint`], and the digest of the
/// artifact that held it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Verified {
    pub scheme: String,
    pub key: String,
    pub signature: String,
}

/// A signature format.
pub trait Scheme: Send + Sync {
    /// Its name, as the audit records it.
    fn name(&self) -> &'static str;
    /// The tag, in the image's own repository, that holds its signatures for `digest`, if it keeps
    /// them under one.
    fn tag(&self, digest: &str) -> Option<String>;
    /// The first of `keys` that signed `subject` in `artifact`; otherwise why none did.
    fn verify(&self, subject: Subject<'_>, artifact: &Artifact, keys: &[Key]) -> Result<Verified>;
}

/// Every scheme wicket checks, in the order they are tried.
pub fn schemes() -> Vec<Box<dyn Scheme>> {
    vec![Box::new(cosign::Cosign)]
}

pub mod cosign {
    //! cosign's signatures made with a key, in its registry format: the tag `sha256-<hex>.sig` in
    //! the image's repository is a manifest whose layers are "simple signing" payloads, each with its
    //! signature (base64) in the `dev.cosignproject.cosign/signature` annotation. A payload names
    //! the digest it signs (`critical.image.docker-manifest-digest`), which must be the image's.
    //! Not yet: the Sigstore bundle cosign 3 attaches as an OCI 1.1 referrer.

    use super::*;
    use base64::Engine as _;

    pub const PAYLOAD_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
    pub const SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
    pub const SIGNATURE_TYPE: &str = "cosign container image signature";

    pub struct Cosign;

    impl Scheme for Cosign {
        fn name(&self) -> &'static str {
            "cosign"
        }

        fn tag(&self, digest: &str) -> Option<String> {
            let hex = crate::oci::hex_of(digest)?;
            Some(format!("sha256-{hex}.sig"))
        }

        fn verify(&self, subject: Subject<'_>, a: &Artifact, keys: &[Key]) -> Result<Verified> {
            let m: serde_json::Value = serde_json::from_slice(&a.manifest).context("the signature's manifest is not JSON")?;
            let descs = m["layers"].as_array().context("the signature's manifest has no layers")?;
            if descs.len() != a.layers.len() {
                bail!("the signature's manifest names {} layers and {} were fetched", descs.len(), a.layers.len());
            }
            let mut why = vec![];
            for (d, payload) in descs.iter().zip(&a.layers) {
                if d["mediaType"] != PAYLOAD_TYPE {
                    continue;
                }
                let Some(sig) = d["annotations"][SIGNATURE_ANNOTATION].as_str() else {
                    why.push("a payload without a signature".to_string());
                    continue;
                };
                let Ok(sig) = base64::engine::general_purpose::STANDARD.decode(sig) else {
                    why.push("a signature that is not base64".to_string());
                    continue;
                };
                // What it signs first: a good signature over another digest is no signature here.
                let p: serde_json::Value = match serde_json::from_slice(payload) {
                    Ok(p) => p,
                    Err(_) => {
                        why.push("a payload that is not JSON".to_string());
                        continue;
                    }
                };
                if p["critical"]["type"] != SIGNATURE_TYPE {
                    why.push(format!("a payload of type {}", p["critical"]["type"]));
                    continue;
                }
                let signed = p["critical"]["image"]["docker-manifest-digest"].as_str().unwrap_or_default();
                if signed != subject.digest {
                    why.push(format!("a signature for {signed:?}"));
                    continue;
                }
                match keys.iter().find(|k| k.verifies(payload, &sig)) {
                    Some(k) => return Ok(Verified { scheme: self.name().into(), key: k.fingerprint(), signature: a.digest.clone() }),
                    None => why.push("a signature by none of the policy's keys".to_string()),
                }
            }
            if why.is_empty() {
                bail!("no cosign signature in {}", a.digest);
            }
            why.dedup();
            bail!("no signature in {} verified: {}", a.digest, why.join("; "))
        }
    }
}

#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    //! Signing for tests: keys from fixed seeds, and cosign signature artifacts made with them.
    use super::*;
    use base64::Engine as _;
    pub use p256::ecdsa::SigningKey as P256Key;

    pub fn p256_key(seed: u8) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("a scalar")
    }

    pub fn ed25519_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    pub fn pem_of_p256(k: &p256::ecdsa::SigningKey) -> String {
        use p256::pkcs8::{EncodePublicKey as _, LineEnding};
        k.verifying_key().to_public_key_pem(LineEnding::LF).unwrap()
    }

    pub fn pem_of_ed25519(k: &ed25519_dalek::SigningKey) -> String {
        use p256::pkcs8::{EncodePublicKey as _, LineEnding};
        k.verifying_key().to_public_key_pem(LineEnding::LF).unwrap()
    }

    /// A cosign payload for `digest` in `repository`.
    pub fn payload(digest: &str, repository: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "critical": {
                "identity": { "docker-reference": repository },
                "image": { "docker-manifest-digest": digest },
                "type": cosign::SIGNATURE_TYPE,
            },
            "optional": null,
        }))
        .unwrap()
    }

    pub fn sign_p256(k: &p256::ecdsa::SigningKey, msg: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        let s: p256::ecdsa::Signature = k.sign(msg);
        s.to_der().as_bytes().to_vec()
    }

    pub fn sign_ed25519(k: &ed25519_dalek::SigningKey, msg: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer as _;
        k.sign(msg).to_bytes().to_vec()
    }

    /// Blobs by digest.
    pub type Blobs = Vec<(String, Vec<u8>)>;

    /// A cosign signature artifact: (its manifest's digest, its manifest, its layers' blobs), for
    /// `payload` signed `sig`.
    pub fn artifact(payload: &[u8], sig: &[u8]) -> (String, Vec<u8>, Blobs) {
        let sha = |b: &[u8]| format!("sha256:{}", hex::encode(Sha256::digest(b)));
        let config = b"{}".to_vec();
        let m = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(&config), "size": config.len() },
            "layers": [{
                "mediaType": cosign::PAYLOAD_TYPE,
                "digest": sha(payload),
                "size": payload.len(),
                "annotations": { cosign::SIGNATURE_ANNOTATION: base64::engine::general_purpose::STANDARD.encode(sig) },
            }],
        }))
        .unwrap();
        (sha(&m), m, vec![(sha(&config), config), (sha(payload), payload.to_vec())])
    }

    /// As [`artifact`], as fetched.
    pub fn fetched(payload: &[u8], sig: &[u8]) -> Artifact {
        let (digest, manifest, _) = artifact(payload, sig);
        Artifact { digest, manifest, layers: vec![payload.to_vec()] }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    const D: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn subject(digest: &str) -> Subject<'_> {
        Subject { digest, repository: "registry.example.com/team/agent" }
    }

    #[test]
    fn keys_parse_from_pem_and_are_named_by_their_spki_digest() {
        let (p, e) = (p256_key(7), ed25519_key(9));
        let kp = Key::from_pem(&pem_of_p256(&p)).unwrap();
        let ke = Key::from_pem(&pem_of_ed25519(&e)).unwrap();
        assert!(matches!(kp, Key::EcdsaP256(_)) && matches!(ke, Key::Ed25519(_)));
        assert!(kp.fingerprint().starts_with("sha256:") && kp.fingerprint().len() == 71);
        assert_ne!(kp.fingerprint(), ke.fingerprint());
        assert_eq!(kp.fingerprint(), Key::from_pem(&pem_of_p256(&p)).unwrap().fingerprint(), "stable");
        assert!(Key::from_pem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n").is_err());
        assert!(Key::from_pem("not a key").is_err());
    }

    #[test]
    fn a_cosign_signature_by_a_listed_key_over_this_digest_verifies() {
        let (p, e) = (p256_key(7), ed25519_key(9));
        let keys = [Key::from_pem(&pem_of_ed25519(&e)).unwrap(), Key::from_pem(&pem_of_p256(&p)).unwrap()];
        let pl = payload(D, "registry.example.com/team/agent");
        for sig in [sign_p256(&p, &pl), sign_ed25519(&e, &pl)] {
            let a = fetched(&pl, &sig);
            let v = cosign::Cosign.verify(subject(D), &a, &keys).unwrap();
            assert_eq!(v.scheme, "cosign");
            assert_eq!(v.signature, a.digest);
            assert!(keys.iter().any(|k| k.fingerprint() == v.key));
        }
        assert_eq!(cosign::Cosign.tag(D).unwrap(), format!("sha256-{}.sig", "a".repeat(64)));
        assert!(cosign::Cosign.tag("latest").is_none());
    }

    #[test]
    fn another_key_digest_type_or_a_tampered_payload_is_refused() {
        let (p, stranger) = (p256_key(7), p256_key(8));
        let keys = [Key::from_pem(&pem_of_p256(&p)).unwrap()];
        let pl = payload(D, "r/x");
        let refused = |a: &Artifact, s: Subject<'_>| format!("{:#}", cosign::Cosign.verify(s, a, &keys).unwrap_err());

        // Signed by a key the policy doesn't name.
        assert!(refused(&fetched(&pl, &sign_p256(&stranger, &pl)), subject(D)).contains("none of the policy's keys"));
        // A good signature, over another digest.
        let other = payload(OTHER, "r/x");
        assert!(refused(&fetched(&other, &sign_p256(&p, &other)), subject(D)).contains("a signature for"));
        // The payload changed after signing (its digest is fine: the fetcher checked it).
        let sig = sign_p256(&p, &pl);
        let tampered = String::from_utf8(pl.clone()).unwrap().replace("r/x", "r/y").into_bytes();
        assert_ne!(tampered, pl);
        assert!(refused(&fetched(&tampered, &sig), subject(D)).contains("none of the policy's keys"));
        // Not a cosign image signature.
        let mut v: serde_json::Value = serde_json::from_slice(&pl).unwrap();
        v["critical"]["type"] = "something else".into();
        let odd = serde_json::to_vec(&v).unwrap();
        assert!(refused(&fetched(&odd, &sign_p256(&p, &odd)), subject(D)).contains("a payload of type"));
        // A signature that isn't one.
        assert!(refused(&fetched(&pl, b"junk"), subject(D)).contains("none of the policy's keys"));
        // Layers that don't match the manifest.
        let mut a = fetched(&pl, &sign_p256(&p, &pl));
        a.layers.clear();
        assert!(refused(&a, subject(D)).contains("names 1 layers and 0 were fetched"));
        // No keys at all.
        let a = fetched(&pl, &sign_p256(&p, &pl));
        assert!(cosign::Cosign.verify(subject(D), &a, &[]).is_err());
    }

    #[test]
    fn a_high_s_p256_signature_verifies_as_go_makes_them() {
        let p = p256_key(7);
        let pl = payload(D, "r/x");
        let s: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&p, &pl[..]);
        let (r, lo) = s.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*lo.as_ref()).to_bytes()).unwrap();
        assert!(high.normalize_s() != high, "the other form of s");
        let keys = [Key::from_pem(&pem_of_p256(&p)).unwrap()];
        cosign::Cosign.verify(subject(D), &fetched(&pl, high.to_der().as_bytes()), &keys).unwrap();
    }
}
