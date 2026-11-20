//! Operators as message senders (#252): a human sends and receives the same signed envelopes an
//! agent does.
//!
//! An operator has no box and no run, so wicket issues it a short-lived *operator identity
//! document* for each message it sends, bound to a fresh key, as it does for an agent instance. Its
//! JWS type ([`OPERATOR_TYP`]) and its envelope header field (`oid`, where an agent's is `wid`) are
//! its own: nothing that checks an agent's identity or envelope ([`super::verify_identity`],
//! [`super::verify_envelope`]) accepts an operator's, so an operator's message can't pass for an
//! agent's signed decision or report. Readers that take either use [`verify_any_envelope`].
//!
//! The document asserts only what wicket knew when the operator acted: its principal id
//! (`spiffe://<td>/t/<tenant>/op/<via>/<name>`) and how it was authenticated (`via`: `unix` for the
//! CLI's peer credentials, `passkey` for the console). It grants nothing.

use super::*;

/// The JWS `typ` of an operator identity document.
pub const OPERATOR_TYP: &str = "wicket-operator+jwt";

/// What wicket asserts about an operator sending a message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorClaims {
    /// Issuer: `spiffe://<trust domain>`.
    pub iss: String,
    /// The operator's principal id ([`operator_id`]).
    pub sub: String,
    pub tenant: String,
    /// How wicket knew them: `unix` or `passkey`.
    pub via: String,
    pub name: String,
    pub iat: i64,
    pub exp: i64,
    /// The key this document binds (RFC 7800), held by wicket for the one message it signs.
    pub cnf: Value,
}

/// Who signed an envelope: an agent instance or an operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sender {
    Agent(Box<AgentClaims>),
    Operator(OperatorClaims),
}

impl Sender {
    /// The sender's principal id.
    pub fn principal(&self) -> &str {
        match self {
            Sender::Agent(c) => &c.sub,
            Sender::Operator(c) => &c.sub,
        }
    }
}

impl Issuer {
    /// Issues a short-lived identity document for operator `via/name` of `tenant`, binding `key`.
    pub fn issue_operator(&self, tenant: &str, via: &str, name: &str, iat: i64, ttl_secs: i64, key: &VerifyingKey) -> String {
        let claims = OperatorClaims {
            iss: self.issuer_id(),
            sub: operator_id(&self.trust_domain, tenant, via, name),
            tenant: tenant.to_string(),
            via: id_segment(via),
            name: id_segment(name),
            iat,
            exp: iat + ttl_secs,
            cnf: json!({ "jwk": { "kty": "OKP", "crv": "Ed25519", "x": B64.encode(key.to_bytes()) } }),
        };
        jws_sign(
            &self.key,
            json!({ "alg": "EdDSA", "typ": OPERATOR_TYP, "kid": key_id(&self.verifying_key()) }),
            &serde_json::to_value(claims).expect("claims"),
        )
    }
}

/// Verifies an operator identity document against the issuer's key, valid at `now`: its type, its
/// times, and that its subject is the operator id its own tenant, via and name make in the
/// issuer's trust domain.
pub fn verify_operator(jws: &str, issuer: &VerifyingKey, now: i64) -> Result<OperatorClaims> {
    let (header, payload) = jws_verify(jws, issuer)?;
    if header.get("typ").and_then(|t| t.as_str()) != Some(OPERATOR_TYP) {
        return Err(IdError::WrongType(OPERATOR_TYP));
    }
    let c: OperatorClaims = serde_json::from_value(payload).map_err(|_| IdError::Malformed("operator claims"))?;
    let td = c.iss.strip_prefix("spiffe://").ok_or(IdError::Malformed("iss"))?;
    if c.sub != operator_id(td, &c.tenant, &c.via, &c.name) {
        return Err(IdError::Malformed("operator subject"));
    }
    if c.exp < now {
        return Err(IdError::Expired(c.exp));
    }
    if c.iat > now + CLOCK_SKEW {
        return Err(IdError::Malformed("issued in the future"));
    }
    Ok(c)
}

/// Signs a message from the operator identified by `identity_jws` (whose key is `key`), as
/// [`sign_envelope`] does for an agent.
pub fn sign_operator_envelope(key: &AgentKey, identity_jws: &str, payload: &Value) -> String {
    jws_sign(&key.0, json!({ "alg": "EdDSA", "typ": MESSAGE_TYP, "oid": identity_jws }), payload)
}

/// Verifies an envelope from an agent ([`verify_envelope`]) or an operator, at `at`.
pub fn verify_any_envelope(jws: &str, issuer: &VerifyingKey, at: i64) -> Result<(Sender, Value)> {
    let header = jws_header(jws)?;
    if header.get("typ").and_then(|t| t.as_str()) != Some(MESSAGE_TYP) {
        return Err(IdError::WrongType(MESSAGE_TYP));
    }
    let Some(oid) = header.get("oid") else {
        return verify_envelope(jws, issuer, at).map(|(c, p)| (Sender::Agent(Box::new(c)), p));
    };
    if header.get("wid").is_some() {
        return Err(IdError::Malformed("envelope with two identities"));
    }
    let oid = oid.as_str().ok_or(IdError::Malformed("envelope without identity"))?;
    let sender = verify_operator(oid, issuer, at)?;
    let x = sender.cnf.pointer("/jwk/x").and_then(|x| x.as_str()).ok_or(IdError::Malformed("cnf"))?;
    let kb: [u8; 32] = B64.decode(x).ok().and_then(|b| b.try_into().ok()).ok_or(IdError::Malformed("cnf key"))?;
    let key = VerifyingKey::from_bytes(&kb).map_err(|_| IdError::Malformed("cnf key"))?;
    let (_, payload) = jws_verify(jws, &key)?;
    Ok((Sender::Operator(sender), payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_doc(i: &Issuer, k: &AgentKey) -> String {
        let spec = IdentitySpec {
            tenant: "t0".into(),
            zone: "research".into(),
            agent: "lead".into(),
            run: "run_a".into(),
            parent_run: None,
            manifest_sha256: "m".into(),
            image: "img".into(),
            node: "local".into(),
            principal: Value::Null,
            act: None,
        };
        i.issue(&spec, 1000, 600, &k.public())
    }

    #[test]
    fn an_operators_envelope_verifies_as_an_operators_and_never_as_an_agents() {
        let i = Issuer::generate("test.local");
        let k = AgentKey::generate();
        let doc = i.issue_operator("t0", "unix", "alice", 1000, 120, &k.public());
        let c = verify_operator(&doc, &i.verifying_key(), 1050).unwrap();
        assert_eq!(c.sub, "spiffe://test.local/t/t0/op/unix/alice");
        let env = sign_operator_envelope(&k, &doc, &json!({ "jti": "m-1", "to": "x" }));
        let (s, p) = verify_any_envelope(&env, &i.verifying_key(), 1050).unwrap();
        assert_eq!((s.principal(), p["jti"].as_str()), ("spiffe://test.local/t/t0/op/unix/alice", Some("m-1")));
        // Not an agent's envelope, nor an agent's identity, nor the other way round.
        assert!(verify_envelope(&env, &i.verifying_key(), 1050).is_err());
        assert!(matches!(verify_identity(&doc, &i.verifying_key(), 1050), Err(IdError::WrongType(_))));
        let ak = AgentKey::generate();
        let adoc = agent_doc(&i, &ak);
        assert!(matches!(verify_operator(&adoc, &i.verifying_key(), 1050), Err(IdError::WrongType(_))));
        // An agent's own envelope still reads as an agent's.
        let aenv = sign_envelope(&ak, &adoc, &json!({ "jti": "m-2" }));
        assert!(matches!(verify_any_envelope(&aenv, &i.verifying_key(), 1050).unwrap().0, Sender::Agent(_)));
        // An agent's document under `oid` is refused (wrong type), as is a key the document doesn't bind.
        let forged = sign_operator_envelope(&ak, &adoc, &json!({ "jti": "m-3" }));
        assert!(verify_any_envelope(&forged, &i.verifying_key(), 1050).is_err());
        let wrong_key = sign_operator_envelope(&AgentKey::generate(), &doc, &json!({ "jti": "m-4" }));
        assert!(verify_any_envelope(&wrong_key, &i.verifying_key(), 1050).is_err());
        // Outside its window, or from another installation.
        assert!(matches!(verify_any_envelope(&env, &i.verifying_key(), 1121), Err(IdError::Expired(1120))));
        assert!(verify_any_envelope(&env, &Issuer::generate("test.local").verifying_key(), 1050).is_err());
    }

    #[test]
    fn an_operator_document_names_only_the_operator_its_fields_make() {
        let i = Issuer::generate("test.local");
        let k = AgentKey::generate();
        // A document whose sub was edited fails its signature; one issued with odd characters is normalised.
        let doc = i.issue_operator("t0", "passkey", "Alice's laptop", 1000, 120, &k.public());
        assert_eq!(verify_operator(&doc, &i.verifying_key(), 1000).unwrap().sub, "spiffe://test.local/t/t0/op/passkey/Alice-s-laptop");
        let claims = OperatorClaims {
            iss: i.issuer_id(),
            sub: "spiffe://test.local/t/t0/op/unix/root".into(),
            tenant: "t0".into(),
            via: "unix".into(),
            name: "alice".into(),
            iat: 1000,
            exp: 1100,
            cnf: json!({}),
        };
        let bad = jws_sign(&i.key, json!({ "alg": "EdDSA", "typ": OPERATOR_TYP }), &serde_json::to_value(claims).unwrap());
        assert!(matches!(verify_operator(&bad, &i.verifying_key(), 1000), Err(IdError::Malformed("operator subject"))));
    }
}
