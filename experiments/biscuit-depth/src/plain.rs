//! The fallback: Ed25519-signed JSON records chained by hash, with a hand-written evaluator that
//! intersects every link (so a widening link can't widen) and a hand-written mint-time narrowing check
//! (for readable errors).
//!
//! Wire format: for each link, u16 BE payload length || payload (JSON) || 64-byte signature. The
//! signature covers the payload, and the payload's `prev` is SHA-256(previous payload || previous sig).
//! Link 0 is signed by the root key; zone links by a node key the verifier knows from the feed; grant
//! links by any key, honoured only where a zone link lists it in `grant_keys`.

use crate::model::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Body {
    Zone(Ceiling),
    Grant(Grant),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub v: u8,
    pub prev: String,
    /// Key id ("root", a node id) for zone links; the hex public key for grant links.
    pub signer: String,
    #[serde(flatten)]
    pub body: Body,
}

pub struct Verified {
    pub records: Vec<Record>,
    /// SHA-256 of each link: its revocation id.
    pub ids: Vec<[u8; 32]>,
}

pub fn link_hash(payload: &[u8], sig: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(payload);
    h.update(sig);
    h.finalize().into()
}

pub fn append(chain: &mut Vec<u8>, prev: &mut [u8; 32], signer_id: &str, body: Body, key: &SigningKey) {
    let rec = Record { v: 1, prev: hex::encode(*prev), signer: signer_id.into(), body };
    let payload = serde_json::to_vec(&rec).unwrap();
    let sig = key.sign(&payload).to_bytes();
    chain.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    chain.extend_from_slice(&payload);
    chain.extend_from_slice(&sig);
    *prev = link_hash(&payload, &sig);
}

/// The last link's hash: what a new link (or a grant) binds to.
pub fn last_hash(chain: &[u8]) -> [u8; 32] {
    let mut i = 0;
    let mut h = [0u8; 32];
    while i < chain.len() {
        let n = u16::from_be_bytes([chain[i], chain[i + 1]]) as usize;
        h = link_hash(&chain[i + 2..i + 2 + n], &chain[i + 2 + n..i + 2 + n + 64]);
        i += 2 + n + 64;
    }
    h
}

pub struct Trust {
    pub root: VerifyingKey,
    pub nodes: HashMap<String, VerifyingKey>,
}

pub fn verify(chain: &[u8], trust: &Trust) -> Result<Verified, String> {
    let mut i = 0;
    let mut prev = [0u8; 32];
    let mut records = Vec::new();
    let mut ids = Vec::new();
    while i < chain.len() {
        if i + 2 > chain.len() {
            return Err("truncated".into());
        }
        let n = u16::from_be_bytes([chain[i], chain[i + 1]]) as usize;
        if i + 2 + n + 64 > chain.len() {
            return Err("truncated".into());
        }
        let payload = &chain[i + 2..i + 2 + n];
        let sig = Signature::from_bytes(chain[i + 2 + n..i + 2 + n + 64].try_into().unwrap());
        let rec: Record = serde_json::from_slice(payload).map_err(|e| format!("link {}: {e}", records.len()))?;
        if rec.prev != hex::encode(prev) {
            return Err(format!("link {}: broken hash chain", records.len()));
        }
        let key = match (&rec.body, records.len()) {
            (Body::Zone(_), 0) if rec.signer == "root" => trust.root,
            (Body::Zone(_), k) if k > 0 => *trust.nodes.get(&rec.signer).ok_or_else(|| format!("link {k}: unknown node key {}", rec.signer))?,
            (Body::Grant(_), k) if k > 0 => {
                let b: [u8; 32] = hex::decode(&rec.signer).map_err(|e| e.to_string())?.try_into().map_err(|_| "bad key".to_string())?;
                VerifyingKey::from_bytes(&b).map_err(|e| e.to_string())?
            }
            _ => return Err("link 0 must be a root-signed zone record".into()),
        };
        key.verify(payload, &sig).map_err(|_| format!("link {}: bad signature", records.len()))?;
        prev = link_hash(payload, &sig.to_bytes());
        ids.push(prev);
        records.push(rec);
        i += 2 + n + 64;
    }
    if records.is_empty() {
        return Err("empty".into());
    }
    Ok(Verified { records, ids })
}

pub fn revoked(v: &Verified, list: &HashSet<[u8; 32]>) -> bool {
    v.ids.iter().any(|id| list.contains(id))
}

fn grant_live(g: &Grant, r: &Request) -> bool {
    r.time <= g.not_after && r.box_id == g.box_id && r.epoch == g.epoch && r.uses_left.iter().any(|(id, n)| id == &g.gid && *n > 0)
}

fn reach_hit(x: &Reach, host: &str, method: &str, path: &str) -> bool {
    host_matches(&x.host, host) && x.methods.iter().any(|m| m == method) && path_matches(&x.path, path)
}

/// Whether the request passes one zone link's ceiling, given the chain's live grants.
fn permits(c: &Ceiling, r: &Request, grants: &[(&str, &Grant)], tenant_ok: bool) -> bool {
    if !tenant_ok || r.time > c.not_after {
        return false;
    }
    if !(r.box_id == c.box_prefix || (r.box_id.starts_with(&c.box_prefix) && r.box_id.as_bytes().get(c.box_prefix.len()) == Some(&b'/'))) {
        return false;
    }
    if !c.ops.iter().any(|o| o == r.op.kind()) {
        return false;
    }
    match &r.op {
        Op::Http { host, method, path, risk, inject } => {
            let granted = grants.iter().any(|(k, g)| c.grant_keys.iter().any(|gk| gk == k) && g.host == *host && g.method == *method && g.path == *path);
            if !granted && !c.reach.iter().any(|x| reach_hit(x, host, method, path)) {
                return false;
            }
            if c.forbid.iter().any(|f| host_matches(&f.host, host) && f.path_prefix.as_ref().is_none_or(|p| path.starts_with(p.as_str()))) {
                return false;
            }
            if *risk > c.max_risk && !granted && !c.dangerous_ok.iter().any(|x| reach_hit(x, host, method, path)) {
                return false;
            }
            if let Some(k) = inject {
                if !c.inject.iter().any(|i| i == k) {
                    return false;
                }
            }
            true
        }
        Op::Spawn { image, isolation, mem, cpus, pids, secs } => {
            let s = &c.spawn;
            s.images.iter().any(|i| i == image) && *isolation >= s.min_isolation && *mem <= s.mem_bytes && *cpus <= s.cpus_milli && *pids <= s.pids && *secs <= s.timeout_s
        }
        Op::Llm { used_requests, used_tokens } => *used_requests < c.llm.max_requests && *used_tokens < c.llm.max_output_tokens,
        Op::Msg { from } => c.accept_from.iter().any(|z| z == from),
    }
}

pub fn authorize(v: &Verified, r: &Request) -> bool {
    let grants: Vec<(&str, &Grant)> = v
        .records
        .iter()
        .filter_map(|rec| match &rec.body {
            Body::Grant(g) if grant_live(g, r) => Some((rec.signer.as_str(), g)),
            _ => None,
        })
        .collect();
    // The tenant is fixed by the root record's zone (the authority).
    let tenant_ok = r.tenant == "acme";
    let mut any = false;
    for rec in &v.records {
        if let Body::Zone(c) = &rec.body {
            any = true;
            if !permits(c, r, &grants, tenant_ok) {
                return false;
            }
        }
    }
    any
}

/// Mint-time narrowing check (a cut-down subset.rs): every way `child` exceeds `parent`.
pub fn narrows(child: &Ceiling, parent: &Ceiling) -> Result<(), Vec<String>> {
    let mut v = Vec::new();
    if child.not_after > parent.not_after {
        v.push("expiry later than parent".into());
    }
    if !(child.box_prefix == parent.box_prefix || child.box_prefix.starts_with(&format!("{}/", parent.box_prefix))) {
        v.push("box outside parent subtree".into());
    }
    for o in &child.ops {
        if !parent.ops.contains(o) {
            v.push(format!("op {o}"));
        }
    }
    let covers = |p: &Reach, c: &Reach| {
        let host = match (p.host.strip_prefix("*."), c.host.strip_prefix("*.")) {
            (_, None) => host_matches(&p.host, &c.host),
            (Some(ps), Some(cs)) => cs == ps || cs.ends_with(&format!(".{ps}")),
            (None, Some(_)) => false,
        };
        let path = match (&p.path, &c.path) {
            (PathPat::Any, _) => true,
            (PathPat::Prefix(pp), PathPat::Prefix(cp) | PathPat::OneSegment(cp)) => cp.starts_with(pp.as_str()),
            (PathPat::OneSegment(pp), PathPat::OneSegment(cp)) => pp == cp,
            _ => false,
        };
        host && path && c.methods.iter().all(|m| p.methods.contains(m))
    };
    for (i, c) in child.reach.iter().enumerate() {
        if !parent.reach.iter().any(|p| covers(p, c)) {
            v.push(format!("reach {i} ({} {:?})", c.host, c.methods));
        }
    }
    for (i, c) in child.dangerous_ok.iter().enumerate() {
        if !parent.dangerous_ok.iter().any(|p| covers(p, c)) {
            v.push(format!("dangerous_ok {i}"));
        }
    }
    if child.max_risk > parent.max_risk {
        v.push("max_risk".into());
    }
    let (cs, ps) = (&child.spawn, &parent.spawn);
    if cs.images.iter().any(|i| !ps.images.contains(i)) {
        v.push("images".into());
    }
    if cs.min_isolation < ps.min_isolation || cs.mem_bytes > ps.mem_bytes || cs.cpus_milli > ps.cpus_milli || cs.pids > ps.pids || cs.timeout_s > ps.timeout_s {
        v.push("spawn limits".into());
    }
    if child.llm.max_requests > parent.llm.max_requests || child.llm.max_output_tokens > parent.llm.max_output_tokens {
        v.push("llm budget".into());
    }
    if child.accept_from.iter().any(|z| !parent.accept_from.contains(z)) {
        v.push("accept_from".into());
    }
    if child.inject.iter().any(|z| !parent.inject.contains(z)) {
        v.push("inject".into());
    }
    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}

pub struct PlainKeys {
    pub root: SigningKey,
    pub node: SigningKey,
    pub approver: SigningKey,
}

impl PlainKeys {
    pub fn new() -> PlainKeys {
        let mut rng = rand::rngs::OsRng;
        PlainKeys { root: SigningKey::generate(&mut rng), node: SigningKey::generate(&mut rng), approver: SigningKey::generate(&mut rng) }
    }
    pub fn trust(&self) -> Trust {
        Trust { root: self.root.verifying_key(), nodes: HashMap::from([("node-lon-1".to_string(), self.node.verifying_key())]) }
    }
}

pub fn plain_ceilings(t0: u64, depth: usize, k: &PlainKeys) -> Vec<Ceiling> {
    (0..=depth).map(|l| level(t0, l, vec![hex::encode(k.approver.verifying_key().to_bytes())])).collect()
}

pub fn mint(cs: &[Ceiling], grant: Option<&Grant>, k: &PlainKeys) -> Vec<u8> {
    let mut chain = Vec::new();
    let mut prev = [0u8; 32];
    append(&mut chain, &mut prev, "root", Body::Zone(cs[0].clone()), &k.root);
    for c in &cs[1..] {
        append(&mut chain, &mut prev, "node-lon-1", Body::Zone(c.clone()), &k.node);
    }
    if let Some(g) = grant {
        let id = hex::encode(k.approver.verifying_key().to_bytes());
        append(&mut chain, &mut prev, &id, Body::Grant(g.clone()), &k.approver);
    }
    chain
}
