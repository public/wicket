//! The effect a request asks for and an approval grants (#369): one canonical descriptor that the
//! human (or an agent with grant rights) approves, that the decision record and a passkey sign, and
//! that the grant is then usable for only.
//!
//! A descriptor names who asks (tenant, zone, run and the agent's reported identity), the effect
//! (its kind, method, canonical host, path or prefix, and risk class), the grant's terms (uses, lifetime, run
//! or zone-wide) and, for the request kinds whose outcome depends on more than the target, the
//! sha256 of the arguments the decision was made on ([`args_sha256`]): a spawn's zone, task and
//! image, a link's names, a capacity lease's spec, an update's artifact. Its canonical JSON
//! ([`Effect::canonical`]) has sorted keys and no whitespace, so two parties that build it from
//! the same request and terms hash it the same way ([`Effect::sha256`]).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

/// What a request asks for, and once decided, what its grant may be used for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    /// The descriptor's version.
    pub v: u32,
    /// `access` (egress), or the reserved request kind in lower case: `spawn`, `link`,
    /// `capacity`, `update`, ...
    pub kind: String,
    pub tenant: String,
    pub zone: String,
    /// The run that asked: the principal's instance the grant is bound to (unless zone-wide).
    pub run: String,
    /// The agents that reportedly asked inside the box (subagents), as the request records them.
    pub requested_by: Vec<String>,
    pub method: String,
    /// Canonical host (lower case, no trailing dot).
    pub host: String,
    /// The canonical path, or with `prefix` the segment prefix it covers.
    pub path: String,
    pub prefix: bool,
    /// The risk class it was asked at: the riskiest the grant covers (#119).
    pub risk: String,
    /// The sha256 of the decided-on arguments ([`args_sha256`]), for the kinds that have them.
    pub args_sha256: Option<String>,
    /// The grant's terms; `None` while the request is only asked for.
    pub terms: Option<Terms>,
}

/// The terms an approval grants an effect on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terms {
    /// Uses; `None` is unlimited within the lifetime.
    pub uses: Option<u32>,
    pub ttl_secs: u64,
    /// `run` (only the asking run may use it) or `zone` (any run in the zone).
    pub scope: String,
}

impl Effect {
    /// The descriptor's canonical JSON: what is hashed and signed.
    pub fn canonical(&self) -> String {
        canonical_json(&serde_json::to_value(self).expect("an effect serializes"))
    }

    /// The hex sha256 of [`Effect::canonical`].
    pub fn sha256(&self) -> String {
        hex::encode(sha2::Sha256::digest(self.canonical().as_bytes()))
    }

    /// Whether these terms widen what was asked for (#369's blast radius): a prefix, more than
    /// one use (or unlimited), a lifetime over an hour, or every run in the zone.
    pub fn widens(&self) -> bool {
        self.prefix || self.terms.as_ref().is_some_and(|t| t.uses != Some(1) || t.ttl_secs > WIDE_TTL_SECS || t.scope == "zone")
    }
}

/// A lifetime longer than this widens a grant (#369).
pub const WIDE_TTL_SECS: u64 = 3600;

/// The request kind a method names: `access` for HTTP methods, the reserved method in lower case
/// otherwise.
pub fn kind_of(method: &str) -> String {
    if crate::op::RESERVED_METHODS.contains(&method.to_ascii_uppercase().as_str()) {
        method.to_ascii_lowercase()
    } else {
        "access".into()
    }
}

/// JSON with object keys sorted (recursively) and no whitespace: one spelling for one value.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(&m[k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// The hex sha256 of arguments' canonical JSON: what a descriptor binds a decision to.
pub fn args_sha256(args: &Value) -> String {
    hex::encode(sha2::Sha256::digest(canonical_json(args).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn effect() -> Effect {
        Effect {
            v: 1,
            kind: "spawn".into(),
            tenant: "t".into(),
            zone: "z".into(),
            run: "run_a".into(),
            requested_by: vec![],
            method: "SPAWN".into(),
            host: "wicket.internal".into(),
            path: "/zones/child/worker".into(),
            prefix: false,
            risk: "R4ExecOrPrivilege".into(),
            args_sha256: Some(args_sha256(&json!({ "task": "build", "image": "x" }))),
            terms: Some(Terms { uses: Some(1), ttl_secs: 600, scope: "run".into() }),
        }
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_depth() {
        assert_eq!(
            canonical_json(&json!({ "b": 1, "a": { "d": [2, { "f": 1, "e": 0 }], "c": "x" } })),
            r#"{"a":{"c":"x","d":[2,{"e":0,"f":1}]},"b":1}"#
        );
        // The same arguments in any key order hash the same; any changed value doesn't.
        assert_eq!(args_sha256(&json!({ "task": "build", "image": "x" })), args_sha256(&json!({ "image": "x", "task": "build" })));
        assert_ne!(args_sha256(&json!({ "task": "build", "image": "x" })), args_sha256(&json!({ "task": "build", "image": "y" })));
    }

    #[test]
    fn every_field_is_in_the_hash() {
        let base = effect().sha256();
        let changes: Vec<fn(&mut Effect)> = vec![
            |e| e.run = "run_b".into(),
            |e| e.zone = "other".into(),
            |e| e.path = "/zones/child/other".into(),
            |e| e.prefix = true,
            |e| e.risk = "R1ReadScoped".into(),
            |e| e.method = "LINK".into(),
            |e| e.requested_by = vec!["sub".into()],
            |e| e.args_sha256 = None,
            |e| e.terms.as_mut().unwrap().uses = Some(2),
            |e| e.terms.as_mut().unwrap().ttl_secs = 601,
            |e| e.terms.as_mut().unwrap().scope = "zone".into(),
            |e| e.terms = None,
        ];
        for (i, f) in changes.iter().enumerate() {
            let mut e = effect();
            f(&mut e);
            assert_ne!(e.sha256(), base, "change {i}");
        }
        assert_eq!(effect().sha256(), base);
    }

    #[test]
    fn what_widens() {
        assert!(!effect().widens());
        let wide = |f: &dyn Fn(&mut Effect)| {
            let mut e = effect();
            f(&mut e);
            e.widens()
        };
        assert!(wide(&|e| e.prefix = true));
        assert!(wide(&|e| e.terms.as_mut().unwrap().uses = Some(2)));
        assert!(wide(&|e| e.terms.as_mut().unwrap().uses = None));
        assert!(wide(&|e| e.terms.as_mut().unwrap().ttl_secs = WIDE_TTL_SECS + 1));
        assert!(!wide(&|e| e.terms.as_mut().unwrap().ttl_secs = WIDE_TTL_SECS));
        assert!(wide(&|e| e.terms.as_mut().unwrap().scope = "zone".into()));
        assert_eq!(kind_of("GET"), "access");
        assert_eq!(kind_of("SPAWN"), "spawn");
    }
}
