//! What a token says, in wicket's own types: one [`Ceiling`] per chain link (the root zone, then each
//! spawn), [`Grant`]s from approvers, and the [`Request`] a node decides. Nothing here depends on the
//! token format; `generator` turns these into Biscuit blocks.

use crate::AuthzError;
use serde::{Deserialize, Serialize};
use wicket_core::manifest::{Isolation, ZoneSpec};
use wicket_core::RiskClass;

/// The kinds of operation a box can ask for. A ceiling lists the kinds it allows at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpKind {
    /// An HTTP(S) request through the egress proxy or MCP gateway.
    Http,
    /// Starting a child box.
    Spawn,
    /// A model request through the LLM proxy.
    Llm,
    /// A message from another box.
    Msg,
}

impl OpKind {
    pub const ALL: [OpKind; 4] = [OpKind::Http, OpKind::Spawn, OpKind::Llm, OpKind::Msg];

    /// The string the `op` fact carries.
    pub fn as_str(self) -> &'static str {
        match self {
            OpKind::Http => "http",
            OpKind::Spawn => "spawn",
            OpKind::Llm => "llm",
            OpKind::Msg => "msg",
        }
    }
}

/// An Ed25519 public key, raw 32 bytes: the root key, the approval service's, or a box's grantor key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "hex_32")] pub [u8; 32]);

impl PublicKey {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(k: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(k))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// What a box may reach over HTTP: as a wicket-core reach rule, with path globs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reach {
    /// Exact host, or `*.example.com` (one or more labels under example.com, never example.com).
    pub host: String,
    /// Upper-case methods.
    pub methods: Vec<String>,
    /// Path globs, matched exactly as wicket-core matches them (`*` within a segment, `**` across).
    pub paths: Vec<String>,
    /// Requests rated R3 or higher are allowed by this rule without a grant.
    pub allow_dangerous: bool,
}

/// Hosts or paths refused outright: no grant can open them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Forbid {
    pub host: String,
    pub paths: Vec<String>,
}

/// A credential the egress proxy may inject: `host|header|secret`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Inject {
    pub host: String,
    pub header: String,
    pub secret: String,
}

impl Inject {
    /// The value the `inject` fact carries.
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.host, self.header, self.secret)
    }
}

/// What a spawn may start: images, an isolation floor and resource ceilings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnLimits {
    pub images: Vec<String>,
    /// 1 = runc, 2 = gVisor ([`isolation_level`]).
    pub min_isolation: i64,
    pub mem_bytes: i64,
    pub cpus_milli: i64,
    pub pids: i64,
    pub timeout_s: i64,
}

/// Model budget: a request is allowed while both counters are below their limit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmBudget {
    pub max_requests: i64,
    pub max_output_tokens: i64,
}

/// One link's ceiling. A token's authority is the intersection of every link's ceiling: Biscuit
/// requires every block's checks to pass, so a link can only narrow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ceiling {
    pub zone: String,
    /// This box and its descendants: `b0/b1` admits `b0/b1` and `b0/b1/...`.
    pub box_prefix: String,
    /// Unix seconds; requests at or before it are inside.
    pub not_after: u64,
    pub ops: Vec<OpKind>,
    pub reach: Vec<Reach>,
    pub forbid: Vec<Forbid>,
    pub inject: Vec<Inject>,
    pub spawn: SpawnLimits,
    pub llm: LlmBudget,
    /// Zones whose boxes may message this one.
    pub accept_from: Vec<String>,
    /// Keys whose grants this link's reach and risk checks accept: the approval service, plus (for
    /// spawn links) the parent box's grantor key. Never the box's own key.
    pub grant_keys: Vec<PublicKey>,
}

/// wicket's isolation strength as an integer (higher is stronger).
pub fn isolation_level(i: Isolation) -> i64 {
    match i {
        Isolation::Runc => 1,
        Isolation::Gvisor => 2,
    }
}

impl Ceiling {
    /// The ceiling for a zone, the common case: reach, forbid rules, injections, images, limits, the
    /// model budget and `accept_from` come from the zone. Op kinds: all four, except `llm` for a zone
    /// without a model route. Host patterns and methods are normalised the way wicket-core compares
    /// them (lower-case hosts, upper-case methods). `spawn.images` is the zone's `images` only: a box
    /// may also start boxes from its own image, which the zone doesn't name, so the caller adds it.
    pub fn from_zone(zone: &ZoneSpec, box_prefix: &str, not_after: u64, grant_keys: Vec<PublicKey>) -> Result<Ceiling, AuthzError> {
        let bad = |m: String| AuthzError::Ceiling(format!("zone {}: {m}", zone.name));
        let mem = wicket_core::subset::parse_bytes(&zone.limits.memory).ok_or_else(|| bad(format!("memory {:?}", zone.limits.memory)))?;
        let timeout = zone.limits.timeout().map_err(|e| bad(e.to_string()))?;
        let ops = OpKind::ALL.into_iter().filter(|k| *k != OpKind::Llm || zone.llm.is_some()).collect();
        let c = Ceiling {
            zone: zone.name.clone(),
            box_prefix: box_prefix.to_string(),
            not_after,
            ops,
            reach: zone
                .reach
                .iter()
                .map(|r| Reach {
                    host: r.host.to_ascii_lowercase(),
                    methods: r.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                    paths: r.paths.clone(),
                    allow_dangerous: r.allow_dangerous,
                })
                .collect(),
            forbid: zone.forbid.iter().map(|f| Forbid { host: f.host.to_ascii_lowercase(), paths: f.paths.clone() }).collect(),
            inject: zone
                .inject
                .iter()
                .map(|i| Inject { host: i.host.to_ascii_lowercase(), header: i.header.clone(), secret: i.secret.clone() })
                .collect(),
            spawn: SpawnLimits {
                images: zone.images.clone(),
                min_isolation: isolation_level(zone.isolation),
                mem_bytes: i64::try_from(mem).map_err(|_| bad("memory too large".into()))?,
                cpus_milli: (f64::from(zone.limits.cpus) * 1000.0).round() as i64,
                pids: i64::from(zone.limits.pids),
                timeout_s: i64::try_from(timeout.as_secs()).map_err(|_| bad("timeout too large".into()))?,
            },
            llm: match &zone.llm {
                Some(l) => LlmBudget {
                    max_requests: i64::try_from(l.max_requests).unwrap_or(i64::MAX),
                    max_output_tokens: i64::try_from(l.max_output_tokens).unwrap_or(i64::MAX),
                },
                None => LlmBudget { max_requests: 0, max_output_tokens: 0 },
            },
            accept_from: zone.accept_from.clone(),
            grant_keys,
        };
        c.validate()?;
        Ok(c)
    }

    /// What every ceiling must satisfy before it is encoded: hosts are well-formed, every glob
    /// compiles with wicket's options, and nothing exceeds the structural caps a node enforces.
    pub fn validate(&self) -> Result<(), AuthzError> {
        let bad = |m: String| Err(AuthzError::Ceiling(format!("zone {}: {m}", self.zone)));
        let host_ok = |h: &str| !h.is_empty() && !h.contains(['/', '|']) && h == h.to_ascii_lowercase();
        if self.box_prefix.is_empty() || self.box_prefix.ends_with('/') {
            return bad(format!("box prefix {:?}", self.box_prefix));
        }
        for r in &self.reach {
            if !host_ok(&r.host) {
                return bad(format!("reach host {:?}", r.host));
            }
            for p in &r.paths {
                crate::generator::path_regex(p)?;
            }
        }
        for f in &self.forbid {
            if !host_ok(&f.host) {
                return bad(format!("forbid host {:?}", f.host));
            }
            for p in &f.paths {
                crate::generator::path_regex(p)?;
            }
        }
        Ok(())
    }
}

/// A grant: one exact request (host, method, path) a box may make while the lease is live and its
/// ledger entry has uses left. Signed as a third-party block by the approver's key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub gid: String,
    /// The one box it is for (not its descendants).
    pub box_id: String,
    /// The box's epoch: a restarted box doesn't inherit its predecessor's grants.
    pub epoch: i64,
    pub host: String,
    pub method: String,
    pub path: String,
    /// Unix seconds.
    pub not_after: u64,
    /// Who approved, e.g. `human:alex@acme` or `box:b0/b1`.
    pub approver: String,
    /// The approved op's digest (wicket-core `Op::digest`), for audit.
    pub digest: Vec<u8>,
}

/// One request as the node sees it. Every field comes from the node (transport identity, its clock,
/// its ledger), never from the box's own claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// Unix seconds.
    pub time: u64,
    pub tenant: String,
    pub box_id: String,
    pub epoch: i64,
    pub action: Action,
    /// From the node's ledger: (grant id, uses left), for this token's grants only. Each is a fact,
    /// and a request may have at most 256 facts in all: passing a whole ledger could make a request
    /// fail closed.
    pub uses_left: Vec<(String, i64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Http {
        host: String,
        method: String,
        path: String,
        risk: RiskClass,
        /// The credential the proxy would inject, as [`Inject::key`].
        inject: Option<String>,
    },
    Spawn {
        image: String,
        isolation: i64,
        mem_bytes: i64,
        cpus_milli: i64,
        pids: i64,
        timeout_s: i64,
    },
    Llm {
        used_requests: i64,
        used_output_tokens: i64,
    },
    Msg {
        /// The sender's zone.
        from: String,
    },
}

impl Action {
    pub fn kind(&self) -> OpKind {
        match self {
            Action::Http { .. } => OpKind::Http,
            Action::Spawn { .. } => OpKind::Spawn,
            Action::Llm { .. } => OpKind::Llm,
            Action::Msg { .. } => OpKind::Msg,
        }
    }

    /// The HTTP action for a wicket-core op (host, method, path and risk as classified there).
    pub fn from_op(op: &wicket_core::Op, inject: Option<String>) -> Action {
        Action::Http { host: op.host.clone(), method: op.method.clone(), path: op.path.clone(), risk: op.risk, inject }
    }
}

/// A risk class as the integer the `risk` fact carries (R0 = 0 … R4 = 4).
pub fn risk_level(r: RiskClass) -> i64 {
    match r {
        RiskClass::R0Read => 0,
        RiskClass::R1ReadScoped => 1,
        RiskClass::R2WriteReversible => 2,
        RiskClass::R3ExternalOrIrreversible => 3,
        RiskClass::R4ExecOrPrivilege => 4,
    }
}

/// The highest risk reach alone allows (R2); above it a rule needs `allow_dangerous`, or a grant.
pub const MAX_REACH_RISK: i64 = 2;
