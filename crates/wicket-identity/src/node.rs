//! Node identity (#16, design §3.2 and §8.4): short-lived node certificates from the installation's
//! issuer, and a mutual-authentication handshake that doesn't depend on the transport.
//!
//! **Node certificate.** A JWS (EdDSA, `typ` [`NODE_CERT_TYP`]) signed by the issuer, in the shape of a
//! SPIFFE JWT-SVID: subject `spiffe://<trust domain>/node/<name>`, a serial (`jti`), `iat`/`exp`
//! (24 h by default) and a `cnf` claim (RFC 7800) binding the node's Ed25519 key. The key is made on
//! the node at enrolment and never leaves it; the issuer certifies its public half, so renewing a
//! certificate needs nothing from the node but the channel to deliver it.
//!
//! **Handshake.** Three messages, carried in whatever channel the two ends already have:
//! 1. control host → node: a fresh 32-byte nonce `cn` (in its hello);
//! 2. node → control host: [`NodeProof`]: its own nonce `nn`, its certificate, and a proof signed with
//!    the node key;
//! 3. control host → node: [`ControlProof`]: a proof signed with the issuer key.
//!
//! Each proof is a JWS with `typ` [`PROOF_TYP`] (so it can never pass for a certificate or an agent
//! identity) over the role (`node` or `control`), the node name, both nonces, the certificate's sha256
//! and a channel binding. Both nonces make each proof fresh for this connection; the role stops one
//! side's proof being reflected back as the other's. Each side checks the other against keys it got
//! out of band: the control host checks the certificate against its own issuer key and its `cnf`
//! against the node key it recorded at enrolment; the node checks the control host's proof against the
//! issuer public key installed at enrolment. Validity is checked at the verifier's clock.
//!
//! **Channel binding.** Over ssh (0.0.1) the binding is empty: ssh, with the node's host key pinned,
//! already keeps a third party out of the stream, and the handshake adds who is at each end. A TLS or
//! QUIC transport passes its exporter (RFC 9266 `tls-exporter`) so a proof can't be relayed onto
//! another connection; nothing else changes.

use super::{jws_header, jws_sign, jws_verify, key_id, IdError, Issuer, Result, B64, CLOCK_SKEW};
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const NODE_CERT_TYP: &str = "wicket-node+jwt";
pub const PROOF_TYP: &str = "wicket-node-auth+jwt";
/// The default lifetime of a node certificate.
pub const NODE_CERT_TTL_SECS: i64 = 24 * 3600;

/// `spiffe://<trust domain>/node/<name>`.
pub fn node_spiffe_id(trust_domain: &str, node: &str) -> String {
    format!("spiffe://{trust_domain}/node/{node}")
}

/// What a node certificate asserts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCertClaims {
    /// `spiffe://<trust domain>`.
    pub iss: String,
    /// `spiffe://<trust domain>/node/<name>`.
    pub sub: String,
    pub node: String,
    /// The serial: 16 random bytes, hex.
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    /// `{"jwk": {"kty": "OKP", "crv": "Ed25519", "x": …}}`: the node's key.
    pub cnf: Value,
}

impl NodeCertClaims {
    /// The node key the certificate binds.
    pub fn key(&self) -> Result<VerifyingKey> {
        let x = self.cnf.pointer("/jwk/x").and_then(|x| x.as_str()).ok_or(IdError::Malformed("cnf"))?;
        let b: [u8; 32] = B64.decode(x).ok().and_then(|b| b.try_into().ok()).ok_or(IdError::Malformed("cnf key"))?;
        VerifyingKey::from_bytes(&b).map_err(|_| IdError::Malformed("cnf key"))
    }
}

impl Issuer {
    /// Issues a certificate for node `node` whose key is `key`, valid from `iat` for `ttl_secs`.
    pub fn issue_node_cert(&self, node: &str, key: &VerifyingKey, iat: i64, ttl_secs: i64) -> (String, NodeCertClaims) {
        let mut serial = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut serial);
        let claims = NodeCertClaims {
            iss: self.issuer_id(),
            sub: node_spiffe_id(&self.trust_domain, node),
            node: node.into(),
            jti: hex::encode(serial),
            iat,
            exp: iat + ttl_secs,
            cnf: json!({ "jwk": { "kty": "OKP", "crv": "Ed25519", "x": B64.encode(key.to_bytes()) } }),
        };
        let jws = jws_sign(
            &self.key,
            json!({ "alg": "EdDSA", "typ": NODE_CERT_TYP, "kid": key_id(&self.verifying_key()) }),
            &serde_json::to_value(&claims).expect("claims"),
        );
        (jws, claims)
    }

    fn sign_proof(&self, payload: &Value) -> String {
        jws_sign(&self.key, json!({ "alg": "EdDSA", "typ": PROOF_TYP }), payload)
    }
}

/// Verifies a node certificate: signed by `issuer`, for node `node`, valid at `now` (the verifier's
/// own clock).
pub fn verify_node_cert(jws: &str, issuer: &VerifyingKey, node: &str, now: i64) -> Result<NodeCertClaims> {
    if jws_header(jws)?.get("typ").and_then(|t| t.as_str()) != Some(NODE_CERT_TYP) {
        return Err(IdError::WrongType(NODE_CERT_TYP));
    }
    let (_, payload) = jws_verify(jws, issuer).map_err(|_| IdError::WrongIssuer("the certificate is not signed by this installation".into()))?;
    let c: NodeCertClaims = serde_json::from_value(payload).map_err(|_| IdError::Malformed("node certificate claims"))?;
    let td = c.iss.strip_prefix("spiffe://").ok_or(IdError::Malformed("iss"))?;
    if c.node != node || c.sub != node_spiffe_id(td, node) {
        return Err(IdError::Refused(format!("the certificate is for {}, not node {node}", c.sub)));
    }
    if c.exp <= now {
        return Err(IdError::Expired(c.exp));
    }
    if c.iat > now + CLOCK_SKEW {
        return Err(IdError::Malformed("issued in the future"));
    }
    c.key()?;
    Ok(c)
}

/// The Ed25519 key in an unencrypted PKCS#8 PEM (`openssl genpkey -algorithm ed25519`): what
/// enrolment leaves in the node's `node.key`.
pub fn signing_key_from_pkcs8_pem(pem: &str) -> Result<SigningKey> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    if !pem.contains("-----BEGIN PRIVATE KEY-----") {
        return Err(IdError::Malformed("not a PKCS#8 private key"));
    }
    let der = base64::engine::general_purpose::STANDARD.decode(body.trim()).map_err(|_| IdError::Malformed("node key base64"))?;
    // OneAsymmetricKey v0 for Ed25519 (RFC 8410 §7): a fixed 16-byte prefix, then the 32-byte seed.
    const PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    if der.len() != 48 || der[..16] != PREFIX {
        return Err(IdError::Malformed("not an Ed25519 PKCS#8 key"));
    }
    Ok(SigningKey::from_bytes(&der[16..].try_into().expect("32 bytes")))
}

/// A fresh nonce, base64url.
pub fn nonce() -> String {
    let mut b = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    B64.encode(b)
}

fn check_nonce(n: &str) -> Result<()> {
    match B64.decode(n) {
        Ok(b) if b.len() == 32 => Ok(()),
        _ => Err(IdError::Malformed("nonce")),
    }
}

/// The node's half of the handshake (message 2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeProof {
    /// The node's nonce.
    pub nonce: String,
    /// Its certificate.
    pub cert: String,
    /// A proof signed with the node key.
    pub proof: String,
}

/// The control host's half (message 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlProof {
    /// A proof signed with the issuer key.
    pub proof: String,
}

/// What both proofs sign, apart from the role.
struct Transcript {
    node: String,
    cn: String,
    nn: String,
    cert: String,
    bind: String,
}

impl Transcript {
    fn payload(&self, role: &str) -> Value {
        json!({ "role": role, "node": self.node, "cn": self.cn, "nn": self.nn, "cert": self.cert, "bind": self.bind })
    }

    fn check(&self, proof: &str, key: &VerifyingKey, role: &str) -> Result<()> {
        if jws_header(proof)?.get("typ").and_then(|t| t.as_str()) != Some(PROOF_TYP) {
            return Err(IdError::WrongType(PROOF_TYP));
        }
        let (_, payload) = jws_verify(proof, key)?;
        if payload != self.payload(role) {
            return Err(IdError::BadSignature("the proof is for another connection, node or role"));
        }
        Ok(())
    }
}

fn digest(cert: &str) -> String {
    hex::encode(Sha256::digest(cert.as_bytes()))
}

/// The control host's side of the handshake with node `node`.
pub struct ControlHandshake {
    node: String,
    cn: String,
    bind: String,
    verified: Option<Transcript>,
}

impl ControlHandshake {
    /// Starts a handshake: [`ControlHandshake::nonce`] goes in the hello.
    pub fn new(node: &str, binding: &[u8]) -> ControlHandshake {
        ControlHandshake { node: node.into(), cn: nonce(), bind: B64.encode(binding), verified: None }
    }

    pub fn nonce(&self) -> &str {
        &self.cn
    }

    /// Checks the node's answer: its certificate is this installation's (`issuer`), for this node,
    /// valid at `now`, and binds `enrolled_key` (the key recorded at enrolment); its proof is signed
    /// with that key, for this connection. Returns the certificate's claims; the caller still checks
    /// the serial against its revocations.
    pub fn verify_node(&mut self, p: &NodeProof, issuer: &VerifyingKey, enrolled_key: &VerifyingKey, now: i64) -> Result<NodeCertClaims> {
        check_nonce(&p.nonce)?;
        let claims = verify_node_cert(&p.cert, issuer, &self.node, now)?;
        if &claims.key()? != enrolled_key {
            return Err(IdError::Refused(format!("the certificate binds a key other than node {}'s enrolled key", self.node)));
        }
        let t = Transcript { node: self.node.clone(), cn: self.cn.clone(), nn: p.nonce.clone(), cert: digest(&p.cert), bind: self.bind.clone() };
        t.check(&p.proof, enrolled_key, "node").map_err(|_| IdError::BadSignature("the node's proof does not verify"))?;
        self.verified = Some(t);
        Ok(claims)
    }

    /// The control host's proof, once the node's has verified.
    pub fn prove(&self, issuer: &Issuer) -> Result<ControlProof> {
        let t = self.verified.as_ref().ok_or(IdError::Refused("the node has not proved itself".into()))?;
        Ok(ControlProof { proof: issuer.sign_proof(&t.payload("control")) })
    }
}

/// The node's side of the handshake.
pub struct NodeHandshake {
    t: Transcript,
}

impl NodeHandshake {
    /// Answers the control host's nonce `cn` with the node's certificate and a proof signed with its
    /// key. The node sends its certificate even when it has expired: the control host decides.
    pub fn answer(node: &str, key: &SigningKey, cert: &str, cn: &str, binding: &[u8]) -> Result<(NodeHandshake, NodeProof)> {
        check_nonce(cn)?;
        let t = Transcript { node: node.into(), cn: cn.into(), nn: nonce(), cert: digest(cert), bind: B64.encode(binding) };
        let proof = jws_sign(key, json!({ "alg": "EdDSA", "typ": PROOF_TYP }), &t.payload("node"));
        let p = NodeProof { nonce: t.nn.clone(), cert: cert.into(), proof };
        Ok((NodeHandshake { t }, p))
    }

    /// Checks the control host's proof against this installation's issuer key.
    pub fn verify_control(&self, p: &ControlProof, issuer: &VerifyingKey) -> Result<()> {
        self.t.check(&p.proof, issuer, "control").map_err(|_| IdError::WrongIssuer("the control host did not prove this installation's issuer key".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn setup() -> (Issuer, SigningKey, String) {
        let i = Issuer::generate("test.wicket.example");
        let k = SigningKey::generate(&mut rand_core::OsRng);
        let (cert, _) = i.issue_node_cert("n1", &k.verifying_key(), NOW, 3600);
        (i, k, cert)
    }

    /// The whole exchange, as each end would run it. Returns the node's error or the control host's.
    fn exchange(
        node_cert: &str,
        node_key: &SigningKey,
        control_issuer: &Issuer,
        node_trusts: &VerifyingKey,
        enrolled: &VerifyingKey,
        now: i64,
    ) -> std::result::Result<NodeCertClaims, String> {
        let mut c = ControlHandshake::new("n1", b"");
        let (n, p) = NodeHandshake::answer("n1", node_key, node_cert, c.nonce(), b"").map_err(|e| e.to_string())?;
        let claims = c.verify_node(&p, &control_issuer.verifying_key(), enrolled, now).map_err(|e| format!("control: {e}"))?;
        let cp = c.prove(control_issuer).unwrap();
        n.verify_control(&cp, node_trusts).map_err(|e| format!("node: {e}"))?;
        Ok(claims)
    }

    #[test]
    fn a_node_with_this_installations_certificate_and_its_key_is_accepted_and_accepts_the_control_host() {
        let (i, k, cert) = setup();
        let c = exchange(&cert, &k, &i, &i.verifying_key(), &k.verifying_key(), NOW + 10).unwrap();
        assert_eq!(c.sub, "spiffe://test.wicket.example/node/n1");
        assert_eq!(c.exp, NOW + 3600);
        assert_eq!(c.jti.len(), 32);
    }

    #[test]
    fn wrong_or_expired_certificates_and_wrong_keys_are_refused() {
        let (i, k, cert) = setup();
        let vk = k.verifying_key();
        // Expired, at the control host's clock.
        let e = exchange(&cert, &k, &i, &i.verifying_key(), &vk, NOW + 3600).unwrap_err();
        assert!(e.contains("expired"), "{e}");
        // Another installation's certificate (for the same key and name).
        let other = Issuer::generate("test.wicket.example");
        let (foreign, _) = other.issue_node_cert("n1", &vk, NOW, 3600);
        let e = exchange(&foreign, &k, &i, &i.verifying_key(), &vk, NOW).unwrap_err();
        assert!(e.contains("not signed by this installation"), "{e}");
        // A certificate for another node.
        let (n2, _) = i.issue_node_cert("n2", &vk, NOW, 3600);
        let e = exchange(&n2, &k, &i, &i.verifying_key(), &vk, NOW).unwrap_err();
        assert!(e.contains("not node n1"), "{e}");
        // A valid certificate held by something without the node key (a copied certificate).
        let thief = SigningKey::generate(&mut rand_core::OsRng);
        let e = exchange(&cert, &thief, &i, &i.verifying_key(), &vk, NOW).unwrap_err();
        assert!(e.contains("proof does not verify"), "{e}");
        // A certificate for a key that isn't the one enrolled.
        let (rekeyed, _) = i.issue_node_cert("n1", &thief.verifying_key(), NOW, 3600);
        let e = exchange(&rekeyed, &thief, &i, &i.verifying_key(), &vk, NOW).unwrap_err();
        assert!(e.contains("enrolled key"), "{e}");
        // Not a certificate at all: an agent identity from the same issuer.
        let e = exchange("a.b.c", &k, &i, &i.verifying_key(), &vk, NOW).unwrap_err();
        assert!(e.contains("control"), "{e}");
    }

    #[test]
    fn a_control_host_without_this_installations_issuer_key_is_refused() {
        let (i, k, cert) = setup();
        let impostor = Issuer::generate("test.wicket.example");
        // The impostor can't check the certificate either, but even if it skips that, its proof fails.
        let mut c = ControlHandshake::new("n1", b"");
        let (n, p) = NodeHandshake::answer("n1", &k, &cert, c.nonce(), b"").unwrap();
        c.verify_node(&p, &i.verifying_key(), &k.verifying_key(), NOW).unwrap();
        let e = n.verify_control(&c.prove(&impostor).unwrap(), &i.verifying_key()).unwrap_err().to_string();
        assert!(e.contains("issuer key"), "{e}");
        assert!(n.verify_control(&c.prove(&i).unwrap(), &i.verifying_key()).is_ok());
    }

    #[test]
    fn proofs_are_bound_to_one_connection_one_role_and_one_channel() {
        let (i, k, cert) = setup();
        let vk = k.verifying_key();
        // A node proof recorded on one connection doesn't verify on another (a new control nonce).
        let c1 = ControlHandshake::new("n1", b"");
        let (_, p1) = NodeHandshake::answer("n1", &k, &cert, c1.nonce(), b"").unwrap();
        let mut c2 = ControlHandshake::new("n1", b"");
        assert!(c2.verify_node(&p1, &i.verifying_key(), &vk, NOW).is_err());
        // A control proof from one connection doesn't satisfy another node nonce.
        let mut c = ControlHandshake::new("n1", b"");
        let (_, p) = NodeHandshake::answer("n1", &k, &cert, c.nonce(), b"").unwrap();
        c.verify_node(&p, &i.verifying_key(), &vk, NOW).unwrap();
        let old = c.prove(&i).unwrap();
        let (n_again, _) = NodeHandshake::answer("n1", &k, &cert, c.nonce(), b"").unwrap();
        assert!(n_again.verify_control(&old, &i.verifying_key()).is_err(), "replayed control proof");
        // Reflection: the node's own proof sent back as the control host's.
        let (n, p) = NodeHandshake::answer("n1", &k, &cert, c.nonce(), b"").unwrap();
        assert!(n.verify_control(&ControlProof { proof: p.proof.clone() }, &vk).is_err());
        // Channel binding: a proof made for one channel fails on another.
        let mut cb = ControlHandshake::new("n1", b"exporter-a");
        let (_, pb) = NodeHandshake::answer("n1", &k, &cert, cb.nonce(), b"exporter-b").unwrap();
        assert!(cb.verify_node(&pb, &i.verifying_key(), &vk, NOW).is_err());
        // No proof before the node's verifies; bad nonces are refused.
        assert!(ControlHandshake::new("n1", b"").prove(&i).is_err());
        assert!(NodeHandshake::answer("n1", &k, &cert, "short", b"").is_err());
    }

    #[test]
    fn a_proof_cannot_pass_for_a_certificate() {
        let (i, k, cert) = setup();
        let mut c = ControlHandshake::new("n1", b"");
        let (_, p) = NodeHandshake::answer("n1", &k, &cert, c.nonce(), b"").unwrap();
        c.verify_node(&p, &i.verifying_key(), &k.verifying_key(), NOW).unwrap();
        let cp = c.prove(&i).unwrap();
        assert!(matches!(verify_node_cert(&cp.proof, &i.verifying_key(), "n1", NOW), Err(IdError::WrongType(_))));
        // And an agent identity document from the same issuer isn't a node certificate.
        let doc = i.issue(
            &crate::IdentitySpec {
                tenant: "t".into(),
                zone: "z".into(),
                agent: "a".into(),
                run: "r".into(),
                parent_run: None,
                manifest_sha256: "m".into(),
                image: "i".into(),
                node: "n1".into(),
                principal: json!({}),
                act: None,
            },
            NOW,
            600,
            &k.verifying_key(),
        );
        assert!(matches!(verify_node_cert(&doc, &i.verifying_key(), "n1", NOW), Err(IdError::WrongType(_))));
    }

    #[test]
    fn pkcs8_ed25519_keys_load() {
        // RFC 8410 §10.3's example private key.
        let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n";
        let k = signing_key_from_pkcs8_pem(pem).unwrap();
        assert_eq!(hex::encode(k.to_bytes()), "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842");
        // …whose public key is the RFC's.
        assert_eq!(hex::encode(k.verifying_key().to_bytes()), "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");
        assert!(signing_key_from_pkcs8_pem("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n").is_err());
    }
}
