//! Authored policy in Cedar, compiled into wicket's tokens at mint (#51).
//!
//! The human-authored layers are Cedar: the **org policy** (`<data dir>/policy/org.cedar`, with the
//! groups its zones are in in `org-entities.json`), a ceiling and forbids over every zone, and each
//! **zone's policy**, generated from its manifest ([`zone::cedar`]). Both are validated strictly
//! against [`schema::SCHEMA`] and kept as separate policy sets: Cedar ORs a set's permits, so one set
//! would let the org's permits widen a zone.
//!
//! At mint, each layer is compiled ([`compile::compile`]) into the box's Biscuit token: the zone
//! layer into block 0's zone checks (which grants can lift), the org layer into hard checks of its
//! own and `reject if` forbids (which nothing lifts), with the org policy's [`version`] as a fact.
//! Nodes evaluate Biscuit only; no Cedar engine runs at the edge. A spawn needs no conversion: the
//! parent attenuates its token on the node, and block 0's checks carry over.
//!
//! Budgets, use counts and output limits aren't policy: they stay leased counters.

pub mod compile;
pub mod schema;
pub mod zone;

pub use compile::{CompileError, Layer, MintCtx};
use sha2::Digest;
use std::collections::BTreeSet;
use wicket_authz::{Ceiling, OrgLayer, PublicKey};
use wicket_core::ZoneSpec;

/// The compiler's revision: part of every policy version, so a changed compiler is a new version.
pub const COMPILER: &str = "wicket-policy/1";

/// The installation's org policy.
#[derive(Clone, Debug)]
pub struct OrgPolicy {
    pub text: String,
    pub entities: String,
    set: cedar_policy::PolicySet,
    ents: cedar_policy::Entities,
}

impl OrgPolicy {
    /// From Cedar text and Cedar entities JSON (`[]` for none), both checked against the schema.
    pub fn parse(text: &str, entities: &str) -> Result<OrgPolicy, CompileError> {
        let set = compile::parse(text)?;
        let ents = cedar_policy::Entities::from_json_str(entities, Some(&schema::schema()))
            .map_err(|e| CompileError::Cedar(format!("org entities: {e}")))?;
        Ok(OrgPolicy { text: text.into(), entities: entities.into(), set, ents })
    }

    /// The version every token minted under it records: a hash of the policy, its entities, the
    /// schema and the compiler.
    pub fn version(&self) -> String {
        version(&self.text, &self.entities)
    }

    /// The groups `zone` is in (transitively).
    pub fn groups_of(&self, zone: &str) -> BTreeSet<String> {
        let uid: cedar_policy::EntityUid = format!("Zone::{}", zone::lit(zone)).parse().expect("a zone uid");
        self.ents
            .ancestors(&uid)
            .map(|a| a.filter(|u| u.type_name().to_string() == "Group").map(|u| u.id().unescaped().to_string()).collect())
            .unwrap_or_default()
    }

    pub fn policy_set(&self) -> &cedar_policy::PolicySet {
        &self.set
    }

    pub fn entities(&self) -> &cedar_policy::Entities {
        &self.ents
    }

    /// The org layer for a box.
    pub fn layer(&self, mint: &MintCtx) -> Result<OrgLayer, CompileError> {
        let l = compile::compile(&self.set, mint)?;
        Ok(OrgLayer { version: self.version(), http: l.http, forbid: l.forbid, spawn: l.spawn, msg_from: l.msg_from, inject: l.inject })
    }
}

/// A policy version: 16 hex digits.
pub fn version(text: &str, entities: &str) -> String {
    let mut h = sha2::Sha256::new();
    for part in [COMPILER, schema::SCHEMA, text, entities] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(&h.finalize()[..8])
}

/// A zone's Cedar policy set, and the layer compiled from it.
pub fn zone_layer(zone: &ZoneSpec, base: &Ceiling) -> Result<(String, Layer), CompileError> {
    let text = zone::cedar(zone, base);
    let set = compile::parse(&text)?;
    // A zone's policy names no principal: its own boxes are its principals.
    let mint = MintCtx { zone: zone.name.clone(), tenant: String::new(), principal: String::new(), depth: 0, groups: BTreeSet::new() };
    let layer = compile::compile(&set, &mint)?;
    Ok((text, layer))
}

/// A box's ceiling, compiled from Cedar: the zone layer from the zone's policy and, if the
/// installation has one, the org layer (block 0 only: pass `org` for a top-level box).
pub fn ceiling(
    zone: &ZoneSpec,
    box_prefix: &str,
    not_after: u64,
    grant_keys: Vec<PublicKey>,
    org: Option<(&OrgPolicy, &MintCtx)>,
) -> Result<Ceiling, CompileError> {
    let base = Ceiling::from_zone(zone, box_prefix, not_after, grant_keys).map_err(|e| CompileError::Cedar(e.to_string()))?;
    let (_, layer) = zone_layer(zone, &base)?;
    let mut c = zone::ceiling_fields(&layer, &base)?;
    c.org = match org {
        Some((p, mint)) => Some(p.layer(mint)?),
        None => None,
    };
    c.validate().map_err(|e| CompileError::Cedar(e.to_string()))?;
    Ok(c)
}
