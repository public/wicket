//! Workload identity (design §3.2).
//!
//! - **The issuer** is the wicket installation: one Ed25519 key, kept outside every box.
//! - **Launch is registration.** When wicket starts an agent it generates a fresh key pair for that
//!   agent instance and issues an *identity document*: a JWS (EdDSA) whose claims are facts wicket
//!   chose (tenant, zone, agent, run, parent run, manifest digest, image, node) and whose `cnf` claim
//!   binds the agent's public key (RFC 7800). Its subject is a SPIFFE-style ID.
//! - **The agent's private key never enters the box.** wicket's gateway holds it and signs on the
//!   agent's behalf; the box proves who it is to wicket by the socket it speaks on.
//! - **Envelopes**: every agent-to-agent message is a JWS signed with the sender's agent key, with
//!   the sender's identity document in its header. Anyone holding the issuer's public key can check
//!   who sent it, offline. The sender field is set by wicket, never by the agent.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

pub use ed25519_dalek::VerifyingKey;

#[derive(Debug, thiserror::Error)]
pub enum IdError {
    #[error("malformed token: {0}")]
    Malformed(&'static str),
    #[error("bad signature: {0}")]
    BadSignature(&'static str),
    #[error("wrong token type: expected {0}")]
    WrongType(&'static str),
    #[error("expired at {0}")]
    Expired(i64),
    #[error("not issued by this installation (issuer {0})")]
    WrongIssuer(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IdError>;

pub const IDENTITY_TYP: &str = "wicket-id+jwt";
/// Tolerated clock difference between signer and verifier, in seconds.
pub const CLOCK_SKEW: i64 = 60;
pub const MESSAGE_TYP: &str = "wicket-msg+jwt";

/// `spiffe://<trust domain>/t/<tenant>/z/<zone>/a/<agent>`.
pub fn spiffe_id(trust_domain: &str, tenant: &str, zone: &str, agent: &str) -> String {
    format!("spiffe://{trust_domain}/t/{tenant}/z/{zone}/a/{agent}")
}

/// What wicket asserts about one agent instance.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentClaims {
    /// Issuer: `spiffe://<trust domain>`.
    pub iss: String,
    /// The agent's SPIFFE-style ID.
    pub sub: String,
    pub tenant: String,
    pub zone: String,
    pub agent: String,
    /// This instance (one activation of the agent).
    pub run: String,
    /// The run that spawned this one, if any.
    pub parent_run: Option<String>,
    /// sha256 of the manifest wicket launched, and the image it ran.
    pub manifest_sha256: String,
    pub image: String,
    /// Where it runs: "local" or the node's ssh target.
    pub node: String,
    pub iat: i64,
    pub exp: i64,
    /// The agent instance's public key (RFC 7800 confirmation), held by wicket. A fresh key with
    /// every re-issue: identities are short-lived and rotated while the agent runs.
    pub cnf: Value,
    /// Who this agent ultimately acts for: the human (or trigger) at the root of the chain, and how
    /// wicket knew it was them. Children inherit it unchanged. (Null in documents issued before
    /// principals existed.)
    #[serde(default)]
    pub principal: Value,
    /// The delegation chain, RFC 8693 style: the current actor's parent, whose own `act` is its
    /// parent, … down to the principal. None for an agent started directly by its principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Value>,
}

/// The facts an identity document asserts, besides issuer, subject, times and key.
#[derive(Clone, Debug)]
pub struct IdentitySpec {
    pub tenant: String,
    pub zone: String,
    pub agent: String,
    pub run: String,
    pub parent_run: Option<String>,
    pub manifest_sha256: String,
    pub image: String,
    pub node: String,
    pub principal: Value,
    pub act: Option<Value>,
}

impl AgentClaims {
    /// The `act` value a child of this agent should carry: this agent, then whatever it acts for.
    pub fn act_for_child(&self) -> Value {
        let mut a = json!({ "sub": self.sub, "run": self.run });
        if let Some(prev) = &self.act {
            a["act"] = prev.clone();
        }
        a
    }

    /// The chain from the principal to this agent, as readable labels: ["alice (cli)", "lead", "fetcher"].
    pub fn chain(&self) -> Vec<String> {
        let mut agents = vec![self.sub.rsplit('/').next().unwrap_or(&self.sub).to_string()];
        let mut cur = self.act.as_ref();
        while let Some(a) = cur {
            if let Some(sub) = a.get("sub").and_then(|s| s.as_str()) {
                agents.push(sub.rsplit('/').next().unwrap_or(sub).to_string());
            }
            cur = a.get("act");
        }
        agents.push(principal_label(&self.principal));
        agents.reverse();
        agents
    }
}

/// "alice (cli, unix user)", "schedule nightly (created by alice)", …
pub fn principal_label(p: &Value) -> String {
    let g = |k: &str| p.get(k).and_then(|x| x.as_str()).unwrap_or("?");
    if p.is_null() {
        return "unknown principal".into();
    }
    match g("type") {
        "human" => format!("{} ({}, {})", g("id"), g("via"), g("assurance")),
        other => format!("{other} {}", g("id")),
    }
}

/// The installation's issuer key.
pub struct Issuer {
    key: SigningKey,
    pub trust_domain: String,
}

impl Issuer {
    pub fn generate(trust_domain: &str) -> Issuer {
        Issuer { key: SigningKey::generate(&mut rand_core::OsRng), trust_domain: trust_domain.into() }
    }

    /// Loads the issuer key from `path` (hex seed, mode 0600), creating it on first use, and
    /// writes the public key next to it (`<path>.pub.json`) for verifiers.
    pub fn load_or_create(path: &Path, trust_domain: &str) -> Result<Issuer> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let issuer = match std::fs::read_to_string(path) {
            Ok(s) => {
                let seed: [u8; 32] =
                    hex::decode(s.trim()).ok().and_then(|b| b.try_into().ok()).ok_or(IdError::Malformed("issuer key file"))?;
                Issuer { key: SigningKey::from_bytes(&seed), trust_domain: trust_domain.into() }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(d) = path.parent() {
                    std::fs::create_dir_all(d)?;
                }
                let i = Issuer::generate(trust_domain);
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
                f.write_all(hex::encode(i.key.to_bytes()).as_bytes())?;
                i
            }
            Err(e) => return Err(e.into()),
        };
        let pubf = path.with_extension("pub.json");
        std::fs::write(&pubf, serde_json::to_vec_pretty(&issuer.public_jwk()).unwrap_or_default())?;
        Ok(issuer)
    }

    pub fn issuer_id(&self) -> String {
        format!("spiffe://{}", self.trust_domain)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn public_jwk(&self) -> Value {
        json!({ "kty": "OKP", "crv": "Ed25519", "x": B64.encode(self.verifying_key().to_bytes()),
                "kid": key_id(&self.verifying_key()), "iss": self.issuer_id() })
    }

    /// Issues a short-lived identity document for an agent instance whose (fresh) public key is `agent`.
    pub fn issue(&self, spec: &IdentitySpec, iat: i64, ttl_secs: i64, agent: &VerifyingKey) -> String {
        let claims = AgentClaims {
            iss: self.issuer_id(),
            sub: spiffe_id(&self.trust_domain, &spec.tenant, &spec.zone, &spec.agent),
            tenant: spec.tenant.clone(),
            zone: spec.zone.clone(),
            agent: spec.agent.clone(),
            run: spec.run.clone(),
            parent_run: spec.parent_run.clone(),
            manifest_sha256: spec.manifest_sha256.clone(),
            image: spec.image.clone(),
            node: spec.node.clone(),
            iat,
            exp: iat + ttl_secs,
            cnf: json!({ "jwk": { "kty": "OKP", "crv": "Ed25519", "x": B64.encode(agent.to_bytes()) } }),
            principal: spec.principal.clone(),
            act: spec.act.clone(),
        };
        jws_sign(
            &self.key,
            json!({ "alg": "EdDSA", "typ": IDENTITY_TYP, "kid": key_id(&self.verifying_key()) }),
            &serde_json::to_value(claims).expect("claims"),
        )
    }
}

/// A key id: the first 16 hex digits of sha256(public key).
pub fn key_id(k: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(k.to_bytes())[..8])
}

/// Parses an issuer public JWK (as written by `Issuer::load_or_create`).
pub fn verifying_key_from_jwk(jwk: &Value) -> Result<VerifyingKey> {
    let x = jwk.get("x").and_then(|x| x.as_str()).ok_or(IdError::Malformed("jwk x"))?;
    let b: [u8; 32] = B64.decode(x).ok().and_then(|b| b.try_into().ok()).ok_or(IdError::Malformed("jwk x"))?;
    VerifyingKey::from_bytes(&b).map_err(|_| IdError::Malformed("jwk key"))
}

/// An agent instance's key pair. Lives in the `wicket run` process, never in the box.
pub struct AgentKey(SigningKey);

impl AgentKey {
    pub fn generate() -> AgentKey {
        AgentKey(SigningKey::generate(&mut rand_core::OsRng))
    }
    pub fn public(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}

/// Verifies an identity document against the issuer's key, valid at time `now` (iat ≤ now ≤ exp).
pub fn verify_identity(jws: &str, issuer: &VerifyingKey, now: i64) -> Result<AgentClaims> {
    let (header, payload) = jws_verify(jws, issuer)?;
    if header.get("typ").and_then(|t| t.as_str()) != Some(IDENTITY_TYP) {
        return Err(IdError::WrongType(IDENTITY_TYP));
    }
    let claims: AgentClaims = serde_json::from_value(payload).map_err(|_| IdError::Malformed("identity claims"))?;
    if claims.exp < now {
        return Err(IdError::Expired(claims.exp));
    }
    if claims.iat > now + CLOCK_SKEW {
        return Err(IdError::Malformed("issued in the future"));
    }
    Ok(claims)
}

/// sha256 of an identity document, for binding decisions to it.
pub fn identity_digest(jws: &str) -> String {
    hex::encode(Sha256::digest(jws.as_bytes()))
}

/// Signs a message from the agent identified by `identity_jws` (whose key is `key`).
/// `payload` should carry at least `to`, `jti` (message id) and `iat`.
pub fn sign_envelope(key: &AgentKey, identity_jws: &str, payload: &Value) -> String {
    jws_sign(&key.0, json!({ "alg": "EdDSA", "typ": MESSAGE_TYP, "wid": identity_jws }), payload)
}

/// Verifies an envelope: the embedded identity against the issuer (valid at `at`, the time the
/// message was sent), then the message against the identity's bound key. Returns the sender's
/// verified claims and the payload. Callers check that `at` is a time they trust (the ledger's
/// record time, or their own clock for something presented to them now), not the sender's say-so.
pub fn verify_envelope(jws: &str, issuer: &VerifyingKey, at: i64) -> Result<(AgentClaims, Value)> {
    let header = jws_header(jws)?;
    if header.get("typ").and_then(|t| t.as_str()) != Some(MESSAGE_TYP) {
        return Err(IdError::WrongType(MESSAGE_TYP));
    }
    let wid = header.get("wid").and_then(|w| w.as_str()).ok_or(IdError::Malformed("envelope without identity"))?;
    let sender = verify_identity(wid, issuer, at)?;
    let x = sender.cnf.pointer("/jwk/x").and_then(|x| x.as_str()).ok_or(IdError::Malformed("cnf"))?;
    let kb: [u8; 32] = B64.decode(x).ok().and_then(|b| b.try_into().ok()).ok_or(IdError::Malformed("cnf key"))?;
    let agent_key = VerifyingKey::from_bytes(&kb).map_err(|_| IdError::Malformed("cnf key"))?;
    let (_, payload) = jws_verify(jws, &agent_key)?;
    Ok((sender, payload))
}

// ---- compact JWS (EdDSA) ----

fn jws_sign(key: &SigningKey, header: Value, payload: &Value) -> String {
    let input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(payload.to_string()));
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}

fn jws_parts(jws: &str) -> Result<(&str, &str, &str)> {
    let mut it = jws.split('.');
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) => Ok((h, p, s)),
        _ => Err(IdError::Malformed("not a compact JWS")),
    }
}

fn decode_json(part: &str) -> Result<Value> {
    let b = B64.decode(part).map_err(|_| IdError::Malformed("base64url"))?;
    serde_json::from_slice(&b).map_err(|_| IdError::Malformed("json"))
}

fn jws_header(jws: &str) -> Result<Value> {
    decode_json(jws_parts(jws)?.0)
}

fn jws_verify(jws: &str, key: &VerifyingKey) -> Result<(Value, Value)> {
    let (h, p, s) = jws_parts(jws)?;
    let header = decode_json(h)?;
    if header.get("alg").and_then(|a| a.as_str()) != Some("EdDSA") {
        return Err(IdError::Malformed("alg must be EdDSA"));
    }
    let sig: [u8; 64] = B64.decode(s).ok().and_then(|b| b.try_into().ok()).ok_or(IdError::Malformed("signature"))?;
    key.verify(format!("{h}.{p}").as_bytes(), &Signature::from_bytes(&sig)).map_err(|_| IdError::BadSignature("does not verify"))?;
    Ok((header, decode_json(p)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(zone: &str, agent: &str, act: Option<Value>) -> IdentitySpec {
        IdentitySpec {
            tenant: "t0".into(),
            zone: zone.into(),
            agent: agent.into(),
            run: "run_a".into(),
            parent_run: None,
            manifest_sha256: "m".into(),
            image: "img".into(),
            node: "local".into(),
            principal: json!({"type": "human", "id": "alice", "via": "cli", "assurance": "unix-user"}),
            act,
        }
    }

    fn issue(i: &Issuer, k: &AgentKey, zone: &str, agent: &str) -> String {
        i.issue(&spec(zone, agent, None), 1000, 3600, &k.public())
    }

    #[test]
    fn the_chain_runs_from_the_human_through_each_parent() {
        let i = Issuer::generate("test.local");
        let lead = verify_identity(&issue(&i, &AgentKey::generate(), "research", "lead"), &i.verifying_key(), 1500).unwrap();
        let child = verify_identity(
            &i.issue(&spec("research", "fetcher", Some(lead.act_for_child())), 1000, 3600, &AgentKey::generate().public()),
            &i.verifying_key(),
            1500,
        )
        .unwrap();
        let grandchild = verify_identity(
            &i.issue(&spec("research", "reader", Some(child.act_for_child())), 1000, 3600, &AgentKey::generate().public()),
            &i.verifying_key(),
            1500,
        )
        .unwrap();
        assert_eq!(grandchild.chain(), vec!["alice (cli, unix-user)", "lead", "fetcher", "reader"]);
        assert_eq!(grandchild.principal["id"], "alice");
    }

    #[test]
    fn short_lived_identities_reject_use_outside_their_window() {
        let i = Issuer::generate("test.local");
        let k = AgentKey::generate();
        let doc = i.issue(&spec("research", "lead", None), 1000, 600, &k.public());
        assert!(verify_identity(&doc, &i.verifying_key(), 1599).is_ok());
        assert!(matches!(verify_identity(&doc, &i.verifying_key(), 1601), Err(IdError::Expired(1600))));
        assert!(verify_identity(&doc, &i.verifying_key(), 900).is_err(), "not before issue (beyond skew)");
        // A message signed with an old key is only valid at a time inside that key's window.
        let env = sign_envelope(&k, &doc, &json!({"jti": "m"}));
        assert!(verify_envelope(&env, &i.verifying_key(), 1200).is_ok());
        assert!(verify_envelope(&env, &i.verifying_key(), 5000).is_err());
    }

    #[test]
    fn identity_documents_verify_and_bind_the_agent_key() {
        let i = Issuer::generate("test.local");
        let k = AgentKey::generate();
        let doc = issue(&i, &k, "research", "explorer");
        let c = verify_identity(&doc, &i.verifying_key(), 1500).unwrap();
        assert_eq!(c.sub, "spiffe://test.local/t/t0/z/research/a/explorer");
        assert_eq!(c.cnf["jwk"]["x"], B64.encode(k.public().to_bytes()));
        assert!(matches!(verify_identity(&doc, &i.verifying_key(), 5000), Err(IdError::Expired(_))));
        // Another installation's issuer, or a forged document, does not verify.
        let other = Issuer::generate("test.local");
        assert!(verify_identity(&doc, &other.verifying_key(), 1500).is_err());
        let forged = other.issue(&spec("research", "explorer", None), 1000, 3600, &k.public());
        assert!(verify_identity(&forged, &i.verifying_key(), 1500).is_err());
    }

    #[test]
    fn a_claim_cannot_be_edited_without_breaking_the_signature() {
        let i = Issuer::generate("test.local");
        let doc = issue(&i, &AgentKey::generate(), "research", "explorer");
        let (h, p, s) = jws_parts(&doc).unwrap();
        let mut claims = decode_json(p).unwrap();
        claims["zone"] = "prod".into();
        let tampered = format!("{h}.{}.{s}", B64.encode(claims.to_string()));
        assert!(matches!(verify_identity(&tampered, &i.verifying_key(), 1500), Err(IdError::BadSignature(_))));
    }

    #[test]
    fn envelopes_prove_the_sender_and_reject_spoofing() {
        let i = Issuer::generate("test.local");
        let (ka, kb) = (AgentKey::generate(), AgentKey::generate());
        let (a, b) = (issue(&i, &ka, "research", "alice"), issue(&i, &kb, "ops", "bob"));
        let msg = json!({"to": "run_b", "jti": "m-1", "iat": 1200, "body": {"x": 1}});
        let env = sign_envelope(&ka, &a, &msg);
        let (sender, payload) = verify_envelope(&env, &i.verifying_key(), 1500).unwrap();
        assert_eq!((sender.agent.as_str(), sender.zone.as_str()), ("alice", "research"));
        assert_eq!(payload, msg);
        // Claiming to be bob (bob's identity in the header) while signing with alice's key fails.
        let spoof = sign_envelope(&ka, &b, &msg);
        assert!(matches!(verify_envelope(&spoof, &i.verifying_key(), 1500), Err(IdError::BadSignature(_))));
        // An identity document is not an envelope.
        assert!(matches!(verify_envelope(&a, &i.verifying_key(), 1500), Err(IdError::WrongType(_))));
    }

    #[test]
    fn issuer_key_is_created_once_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wicket-id-test-{}", std::process::id()));
        let path = dir.join("root.key");
        let a = Issuer::load_or_create(&path, "t.local").unwrap();
        let b = Issuer::load_or_create(&path, "t.local").unwrap();
        assert_eq!(a.verifying_key(), b.verifying_key());
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let jwk: Value = serde_json::from_slice(&std::fs::read(path.with_extension("pub.json")).unwrap()).unwrap();
        assert_eq!(verifying_key_from_jwk(&jwk).unwrap(), a.verifying_key());
        let _ = std::fs::remove_dir_all(dir);
    }
}
