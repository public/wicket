//! Design B: data-only blocks. Biscuit carries the signatures, the append-only chain, third-party
//! blocks and revocation ids; wicket's own code reads one typed fact per block and intersects them.
//!
//! Layout (no rules, checks or scopes anywhere):
//! - block 0, root-signed: `tenant("acme")`, `principal("trigger:…")`, `zone("<canonical JSON>")`;
//! - spawn block, first-party: exactly `zone("<canonical JSON>")`;
//! - grant block, third-party (approval service or a parent's grantor key): exactly
//!   `grant("<canonical JSON>")`.
//!
//! Design C (hybrid) keeps design A's checks and rules and adds the same JSON next to them as
//! `zone_spec(…)` and `grant(…)`, so the two encodings can be compared on every token.
//!
//! The file has three sections, counted separately in RESULTS.md §5: generator, extractor, evaluator.

use crate::model::*;
use biscuit_auth::builder::{fact, string};
use biscuit_auth::{Biscuit, BlockBuilder, KeyPair};
use serde::{de::DeserializeOwned, Serialize};
use wicket_core::manifest::{ForbidRule, UnlistedHosts};
use wicket_core::{CompiledZone, Op as WOp, ReachRule, RiskClass, RunId, Surface, TenantId, Verdict, ZoneSpec};

// ===== generator ================================================================================

/// The canonical encoding: serde_json's compact output of the typed value, fields in declaration
/// order. The extractor re-serializes what it parsed and refuses anything that differs.
pub fn canon<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serializable")
}

/// Which encoding a token uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// Design B: data facts only.
    Data,
    /// Design C: design A's Datalog plus the data facts.
    Hybrid,
}

impl Form {
    fn zone_pred(self) -> &'static str {
        match self {
            Form::Data => "zone",
            // In A's blocks `zone("<name>")` already names the zone.
            Form::Hybrid => "zone_spec",
        }
    }
}

pub fn zone_fact(c: &Ceiling, form: Form) -> biscuit_auth::builder::Fact {
    // Built with typed terms, never by formatting Datalog: a JSON string can't inject clauses.
    fact(form.zone_pred(), &[string(&canon(c))])
}

pub fn grant_fact(g: &Grant) -> biscuit_auth::builder::Fact {
    fact("grant", &[string(&canon(g))])
}

/// A spawn block for `c` in the given form.
pub fn zone_block(c: &Ceiling, form: Form) -> BlockBuilder {
    let b = match form {
        Form::Data => BlockBuilder::new(),
        Form::Hybrid => BlockBuilder::new().code(crate::bisc::compile(c, false, "acme").0).expect("A code"),
    };
    b.fact(zone_fact(c, form)).expect("zone fact")
}

pub fn mint(cs: &[Ceiling], grant: Option<(&Grant, &KeyPair)>, root: &KeyPair, form: Form) -> Biscuit {
    let b = match form {
        Form::Data => Biscuit::builder()
            .fact(fact("tenant", &[string("acme")]))
            .and_then(|b| b.fact(fact("principal", &[string(&format!("trigger:{}", cs[0].zone))])))
            .expect("authority facts"),
        Form::Hybrid => Biscuit::builder().code(crate::bisc::compile(&cs[0], true, "acme").0).expect("authority code"),
    };
    let mut tok = b.fact(zone_fact(&cs[0], form)).expect("zone fact").build(root).expect("mint");
    for c in &cs[1..] {
        tok = tok.append(zone_block(c, form)).expect("append");
    }
    if let Some((g, signer)) = grant {
        tok = append_grant(&tok, g, signer, form);
    }
    tok
}

pub fn append_zone(tok: &Biscuit, c: &Ceiling, form: Form) -> Biscuit {
    tok.append(zone_block(c, form)).expect("append")
}

/// The third-party flow, as in design A: request bound to the last signature, signed by the approver.
pub fn append_grant(tok: &Biscuit, g: &Grant, signer: &KeyPair, form: Form) -> Biscuit {
    let b = match form {
        Form::Data => BlockBuilder::new(),
        Form::Hybrid => BlockBuilder::new().code(crate::bisc::grant_code(g)).expect("grant code"),
    };
    let b = b.fact(grant_fact(g)).expect("grant fact");
    let req = tok.third_party_request().expect("3p request");
    let block = req.create_block(&signer.private(), b).expect("3p block");
    tok.append_third_party(signer.public(), block).expect("append 3p")
}

// ===== extractor ================================================================================

/// Size caps, checked before anything is compiled. They bound the per-token and per-request cost
/// (§4), the way design A's lint caps and fuel do.
#[derive(Clone, Debug)]
pub struct Caps {
    pub max_token_bytes: usize,
    pub max_blocks: usize,
    pub max_zone_bytes: usize,
    pub max_grant_bytes: usize,
    pub max_reach: usize,
    pub max_forbid: usize,
    pub max_list: usize,
    pub max_str: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            max_token_bytes: 32 * 1024,
            max_blocks: 16,
            max_zone_bytes: 8 * 1024,
            max_grant_bytes: 1024,
            max_reach: 64,
            max_forbid: 32,
            max_list: 32,
            max_str: 256,
        }
    }
}

/// One zone block, ready to decide: the ceiling and its reach/forbid compiled by wicket-core.
pub struct ZoneBlock {
    pub c: Ceiling,
    /// reach + forbid as a wicket `CompiledZone`.
    reach: CompiledZone,
    /// `dangerous_ok` as a second `CompiledZone` (reach only).
    ok: CompiledZone,
}

/// A token as design B sees it, once per token.
pub struct Chain {
    pub tenant: String,
    pub zones: Vec<ZoneBlock>,
    /// (signer's hex public key, grant).
    pub grants: Vec<(String, Grant)>,
    pub ids: Vec<Vec<u8>>,
}

fn one_str<'a>(f: &'a fork::builder::Fact, what: &str) -> Result<&'a str, String> {
    match f.predicate.terms.as_slice() {
        [fork::builder::Term::Str(s)] => Ok(s.as_str()),
        _ => Err(format!("{what}: must have exactly one string term")),
    }
}

fn parse_canon<T: Serialize + DeserializeOwned>(s: &str, max: usize, what: &str) -> Result<T, String> {
    if s.len() > max {
        return Err(format!("{what}: {} bytes, cap {max}", s.len()));
    }
    let v: T = serde_json::from_str(s).map_err(|e| format!("{what}: {e}"))?;
    if canon(&v) != s {
        return Err(format!("{what}: not in canonical form"));
    }
    Ok(v)
}

fn str_ok(s: &str, caps: &Caps) -> bool {
    !s.is_empty() && s.len() <= caps.max_str && !s.chars().any(|c| c.is_control())
}

fn host_ok(h: &str, caps: &Caps) -> bool {
    str_ok(h, caps) && !h.contains('/') && h == h.to_ascii_lowercase() && !h[h.strip_prefix("*.").map_or(0, |_| 2)..].contains('*')
}

fn path_ok(p: &PathPat, caps: &Caps) -> bool {
    let lit = match p {
        PathPat::Any => return true,
        PathPat::Prefix(x) | PathPat::OneSegment(x) => x,
    };
    // Literal prefixes only: no glob metacharacters, so the glob built from them means what it says.
    str_ok(lit, caps) && lit.starts_with('/') && lit.ends_with('/') && !lit.contains(['*', '?', '[', ']', '{', '}', '\\'])
}

fn reach_ok(r: &Reach, caps: &Caps) -> bool {
    host_ok(&r.host, caps) && !r.methods.is_empty() && r.methods.len() <= 8 && r.methods.iter().all(|m| str_ok(m, caps) && m.chars().all(|c| c.is_ascii_uppercase())) && path_ok(&r.path, caps)
}

/// Field-level validation of a parsed ceiling: shapes and caps, not semantics.
pub fn validate(c: &Ceiling, caps: &Caps) -> Result<(), String> {
    let lists = [c.ops.len(), c.accept_from.len(), c.inject.len(), c.grant_keys.len(), c.spawn.images.len(), c.dangerous_ok.len()];
    if c.reach.len() > caps.max_reach || c.forbid.len() > caps.max_forbid || lists.iter().any(|n| *n > caps.max_list) {
        return Err("zone: a list is over its cap".into());
    }
    if !str_ok(&c.zone, caps) || !str_ok(&c.box_prefix, caps) {
        return Err("zone: bad name or box".into());
    }
    if !c.ops.iter().all(|o| ["http", "spawn", "llm", "msg"].contains(&o.as_str())) {
        return Err("zone: unknown op".into());
    }
    if !c.reach.iter().chain(&c.dangerous_ok).all(|r| reach_ok(r, caps)) {
        return Err("zone: bad reach entry".into());
    }
    let fpath = |p: &Option<String>| p.as_ref().is_none_or(|x| path_ok(&PathPat::Prefix(x.clone()), caps));
    if !c.forbid.iter().all(|f| host_ok(&f.host, caps) && fpath(&f.path_prefix)) {
        return Err("zone: bad forbid entry".into());
    }
    let strs = c.accept_from.iter().chain(&c.inject).chain(&c.spawn.images);
    if !strs.into_iter().all(|s| str_ok(s, caps)) {
        return Err("zone: bad string".into());
    }
    if !c.grant_keys.iter().all(|k| k.len() == 64 && k.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
        return Err("zone: grant keys must be 64 lowercase hex digits".into());
    }
    Ok(())
}

fn validate_grant(g: &Grant, caps: &Caps) -> Result<(), String> {
    let ok = [&g.gid, &g.box_id, &g.host, &g.method, &g.path, &g.approver, &g.digest].iter().all(|s| str_ok(s, caps)) && g.path.starts_with('/');
    if ok {
        Ok(())
    } else {
        Err("grant: bad field".into())
    }
}

/// The globs wicket would write for each model path form.
pub fn glob(p: &PathPat) -> String {
    match p {
        PathPat::Any => "/**".into(),
        PathPat::Prefix(x) => format!("{x}**"),
        PathPat::OneSegment(x) => format!("{x}*"),
    }
}

fn spec(name: &str, reach: &[Reach], forbid: &[Forbid]) -> ZoneSpec {
    ZoneSpec {
        name: name.into(),
        isolation: Default::default(),
        reach: reach.iter().map(|r| ReachRule { host: r.host.clone(), methods: r.methods.clone(), paths: vec![glob(&r.path)], allow_dangerous: false }).collect(),
        unlisted_hosts: UnlistedHosts::Escalate,
        forbid: forbid
            .iter()
            .map(|f| ForbidRule { host: f.host.clone(), paths: vec![f.path_prefix.as_ref().map_or("/**".into(), |p| format!("{p}**"))] })
            .collect(),
        inject: vec![],
        llm: None,
        volumes: vec![],
        images: vec![],
        accept_from: vec![],
        limits: Default::default(),
    }
}

pub fn compile_block(c: Ceiling) -> Result<ZoneBlock, String> {
    let reach = CompiledZone::new(spec(&c.zone, &c.reach, &c.forbid)).map_err(|e| e.to_string())?;
    let ok = CompiledZone::new(spec(&c.zone, &c.dangerous_ok, &[])).map_err(|e| e.to_string())?;
    Ok(ZoneBlock { c, reach, ok })
}

/// Once per token, after `Biscuit::from` verified every signature. Fail closed: any block that
/// isn't exactly the expected shape refuses the whole token; nothing is skipped.
pub fn extract(tok: &fork::Biscuit, token_bytes: usize, form: Form, caps: &Caps) -> Result<Chain, String> {
    if token_bytes > caps.max_token_bytes {
        return Err(format!("token is {token_bytes} bytes"));
    }
    let n = tok.block_count();
    if n > caps.max_blocks {
        return Err(format!("{n} blocks"));
    }
    let zp = form.zone_pred();
    let mut tenant = None;
    let mut zones = Vec::new();
    let mut grants = Vec::new();
    for i in 0..n {
        let at = |m: String| format!("block {i}: {m}");
        let b = tok.block_datalog(i).map_err(|e| at(e.to_string()))?;
        if form == Form::Data && (!b.rules.is_empty() || !b.checks.is_empty() || !b.scopes.is_empty()) {
            return Err(at("rules, checks and scopes are not allowed".into()));
        }
        let mut zone = None;
        let mut grant = None;
        for f in &b.facts {
            let name = f.predicate.name.as_str();
            if name == zp {
                if b.external_key.is_some() || zone.is_some() {
                    return Err(at(format!("unexpected {zp} fact")));
                }
                zone = Some(one_str(f, zp).map_err(at)?);
            } else if name == "grant" {
                if b.external_key.is_none() || grant.is_some() {
                    return Err(at("unexpected grant fact".into()));
                }
                grant = Some(one_str(f, "grant").map_err(at)?);
            } else if form == Form::Data && i == 0 && name == "tenant" && tenant.is_none() {
                tenant = Some(one_str(f, "tenant").map_err(at)?.to_string());
            } else if form == Form::Data && i == 0 && name == "principal" {
                one_str(f, "principal").map_err(at)?;
            } else if form == Form::Data {
                return Err(at(format!("fact not allowed: {name}")));
            } else if i == 0 && name == "tenant" {
                // Hybrid: A's other facts are the lint's business; the tenant is read for the cross-check.
                tenant = Some(one_str(f, "tenant").map_err(at)?.to_string());
            }
        }
        match (&b.external_key, zone, grant) {
            (None, Some(z), None) => {
                let c: Ceiling = parse_canon(z, caps.max_zone_bytes, zp).map_err(at)?;
                validate(&c, caps).map_err(at)?;
                zones.push(compile_block(c).map_err(at)?);
            }
            (Some(_), None, Some(g)) if i > 0 => {
                let g: Grant = parse_canon(g, caps.max_grant_bytes, "grant").map_err(at)?;
                validate_grant(&g, caps).map_err(at)?;
                let key = tok.block_external_key(i).map_err(|e| at(e.to_string()))?.expect("external key");
                grants.push((key.print().trim_start_matches("ed25519/").to_ascii_lowercase(), g));
            }
            (None, None, _) => return Err(at(format!("a first-party block needs exactly one {zp} fact"))),
            _ => return Err(at("a third-party block needs exactly one grant fact".into())),
        }
    }
    let tenant = tenant.ok_or("block 0: no tenant fact")?;
    Ok(Chain { tenant, zones, grants, ids: tok.revocation_identifiers() })
}

// ===== evaluator ================================================================================

/// How a zone block matches HTTP reach and forbid entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Matcher {
    /// wicket-core's `CompiledZone` (globs `/**`, `/x/**`, `/x/*`): the design under test.
    Wicket,
    /// The model's own prefix matching, exactly what design A's Datalog encodes.
    Model,
}

/// The request in wicket-core's form, built once per request like A's facts. Risk is decided by the
/// model's integer (`max_risk`), so the op carries R0 and `CompiledZone` answers reach and forbid only.
pub fn wicket_op(r: &Request) -> WOp {
    let (method, host, path) = match &r.op {
        Op::Http { host, method, path, .. } => (method.clone(), host.clone(), path.clone()),
        _ => (String::new(), String::new(), String::new()),
    };
    WOp { tenant: TenantId(r.tenant.clone()), run: RunId("r".into()), zone: String::new(), surface: Surface::Egress, method, host, path, risk: RiskClass::R0Read, effects: vec![] }
}

fn grant_live(g: &Grant, r: &Request) -> bool {
    r.time <= g.not_after && r.box_id == g.box_id && r.epoch == g.epoch && r.uses_left.iter().any(|(id, n)| id == &g.gid && *n > 0)
}

fn reach_hit(x: &Reach, host: &str, method: &str, path: &str) -> bool {
    host_matches(&x.host, host) && x.methods.iter().any(|m| m == method) && path_matches(&x.path, path)
}

impl ZoneBlock {
    /// Whether the request passes this block, given the chain's grants. A grant counts here only if
    /// this block trusts its signer: that is the whole of "a grant widens within the parent's ceiling".
    fn permits(&self, r: &Request, op: &WOp, grants: &[(String, Grant)], m: Matcher) -> bool {
        let c = &self.c;
        if r.time > c.not_after {
            return false;
        }
        let b = &r.box_id;
        if !(b == &c.box_prefix || (b.starts_with(&c.box_prefix) && b.as_bytes().get(c.box_prefix.len()) == Some(&b'/'))) {
            return false;
        }
        if !c.ops.iter().any(|o| o == r.op.kind()) {
            return false;
        }
        match &r.op {
            Op::Http { host, method, path, risk, inject } => {
                let (in_reach, forbidden) = match m {
                    Matcher::Model => (
                        c.reach.iter().any(|x| reach_hit(x, host, method, path)),
                        c.forbid.iter().any(|f| host_matches(&f.host, host) && f.path_prefix.as_ref().is_none_or(|p| path.starts_with(p.as_str()))),
                    ),
                    Matcher::Wicket => match self.reach.evaluate(op) {
                        Verdict::AllowByReach(_) => (true, false),
                        Verdict::Forbidden(_) => (false, true),
                        Verdict::NeedsGrant(_) => (false, false),
                    },
                };
                if forbidden {
                    return false;
                }
                let granted = || grants.iter().any(|(k, g)| c.grant_keys.iter().any(|gk| gk == k) && grant_live(g, r) && g.host == *host && g.method == *method && g.path == *path);
                if !in_reach && !granted() {
                    return false;
                }
                if *risk > c.max_risk {
                    let ok = match m {
                        Matcher::Model => c.dangerous_ok.iter().any(|x| reach_hit(x, host, method, path)),
                        Matcher::Wicket => matches!(self.ok.evaluate(op), Verdict::AllowByReach(_)),
                    };
                    if !ok && !granted() {
                        return false;
                    }
                }
                inject.as_ref().is_none_or(|k| c.inject.iter().any(|i| i == k))
            }
            Op::Spawn { image, isolation, mem, cpus, pids, secs } => {
                let s = &c.spawn;
                s.images.iter().any(|i| i == image) && *isolation >= s.min_isolation && *mem <= s.mem_bytes && *cpus <= s.cpus_milli && *pids <= s.pids && *secs <= s.timeout_s
            }
            Op::Llm { used_requests, used_tokens } => *used_requests < c.llm.max_requests && *used_tokens < c.llm.max_output_tokens,
            Op::Msg { from } => c.accept_from.iter().any(|z| z == from),
        }
    }
}

impl Chain {
    /// Allowed only if every zone block allows it. A chain with no zone block allows nothing.
    pub fn allows(&self, r: &Request, op: &WOp, m: Matcher) -> bool {
        r.tenant == self.tenant && !self.zones.is_empty() && self.zones.iter().all(|z| z.permits(r, op, &self.grants, m))
    }
}
