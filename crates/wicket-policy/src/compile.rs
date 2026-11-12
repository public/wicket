//! Cedar → what a token checks (#51).
//!
//! A policy set is read from Cedar's JSON form (`Policy::to_json`) after strict validation against
//! [`crate::schema`]. Every condition is a boolean formula over a fixed set of atoms, put in
//! disjunctive normal form:
//!
//! - **Decided at mint** (the principal's attributes and memberships, known when the token is
//!   minted): folded to true or false, and gone from the token. A later block can't claim them.
//! - **Decided at the edge** (the request's): each maps onto one shape a node's structural check
//!   accepts (`wicket_authz::structure`): host equality, `like "*suffix"` or inequality; a path glob
//!   (`path_matches.contains`), a `like` on the path; risk and spawn limits compared with integers;
//!   images, sending zones and injected credentials by name.
//!
//! Anything else is a compile error naming the construct: an unknown attribute, a negated path or
//! image, `like` with a wildcard inside a host, `has`, `if`, extension functions, templates. Permits
//! become a check's alternatives (first-party blocks can't hold rules), forbids `reject if` checks.

use crate::schema::METHODS;
use serde_json::Value;
use std::collections::BTreeSet;
use wicket_authz::{HostPat, HttpMatch, PathPat, SpawnMatch};

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("policy {id}: {msg}")]
    Unsupported { id: String, msg: String },
    #[error("{0}")]
    Cedar(String),
}

/// What a box is when its token is minted: what conditions on the principal are decided with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintCtx {
    pub zone: String,
    pub tenant: String,
    pub principal: String,
    /// 0 for a top-level box, one more per spawn link.
    pub depth: i64,
    /// Every group the box's zone is in (transitively), from the org's entities.
    pub groups: BTreeSet<String>,
}

/// One layer of compiled policy (org or zone): per action kind, `None` if it isn't constrained
/// (some permit applies unconditionally), else the alternatives (`Some(vec![])`: never allowed).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layer {
    pub http: Option<Vec<HttpMatch>>,
    pub forbid: Vec<HttpMatch>,
    pub spawn: Option<Vec<SpawnMatch>>,
    pub msg_from: Option<Vec<String>>,
    pub inject: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Spawn,
    Message,
    Inject,
}

/// A request-time atom.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Atom {
    HostEq(String),
    HostSuffix(String),
    PathGlob(String, bool),
    PathLike(String),
    /// `context.<attr> <op> n`, op in <=, >= (normalised).
    Int(String, Cmp, i64),
    /// `resource == T::"id"` (or one of a set).
    Resource(Vec<String>),
    /// `context.host == s` / `context.header == s` (inject).
    Ctx(String, String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmp {
    Le,
    Ge,
}

#[derive(Clone, Debug)]
struct Lit {
    atom: Atom,
    neg: bool,
}

/// A boolean formula, before DNF.
#[derive(Clone, Debug)]
enum F {
    Const(bool),
    Lit(Lit),
    And(Box<F>, Box<F>),
    Or(Box<F>, Box<F>),
    Not(Box<F>),
}

struct Cx<'a> {
    id: String,
    mint: &'a MintCtx,
}

impl Cx<'_> {
    fn err<T>(&self, msg: impl Into<String>) -> Result<T, CompileError> {
        Err(CompileError::Unsupported { id: self.id.clone(), msg: msg.into() })
    }
}

/// `{"Var": "resource"}.attr` → ("resource", "attr").
fn attr(v: &Value) -> Option<(&str, &str)> {
    let d = v.get(".")?;
    let var = d.get("left")?.get("Var")?.as_str()?;
    Some((var, d.get("attr")?.as_str()?))
}

fn value(v: &Value) -> Option<&Value> {
    v.get("Value")
}

fn string(v: &Value) -> Option<&str> {
    value(v)?.as_str()
}

fn long(v: &Value) -> Option<i64> {
    value(v)?.as_i64()
}

/// An entity literal `{"__entity": {"type": T, "id": I}}` (in a `Value`) → (T, I).
fn entity(v: &Value) -> Option<(String, String)> {
    let e = value(v)?.get("__entity")?;
    Some((e.get("type")?.as_str()?.to_string(), e.get("id")?.as_str()?.to_string()))
}

/// A `like` pattern as text (`*` a wildcard, `\*` a literal star).
fn pattern(p: &Value) -> Option<String> {
    let mut out = String::new();
    for el in p.as_array()? {
        match el {
            Value::String(w) if w == "Wildcard" => out.push('*'),
            _ => {
                let lit = el.get("Literal")?.as_str()?;
                if lit == "*" {
                    out.push_str("\\*");
                } else {
                    out.push_str(lit);
                }
            }
        }
    }
    Some(out)
}

/// Cedar `like` on a string we know (mint time).
fn like(s: &str, pat: &str) -> bool {
    regex::Regex::new(&wicket_authz::generator::like_regex(pat)).is_ok_and(|r| r.is_match(s))
}

fn int_cmp(cx: &Cx, op: &str, n: i64, attr_name: &str) -> Result<F, CompileError> {
    let lit = |c, n| F::Lit(Lit { atom: Atom::Int(attr_name.to_string(), c, n), neg: false });
    Ok(match op {
        "<=" => lit(Cmp::Le, n),
        "<" => lit(Cmp::Le, n.checked_sub(1).ok_or(()).or_else(|_| cx.err("integer underflow"))?),
        ">=" => lit(Cmp::Ge, n),
        ">" => lit(Cmp::Ge, n.checked_add(1).ok_or(()).or_else(|_| cx.err("integer overflow"))?),
        "==" => F::And(Box::new(lit(Cmp::Le, n)), Box::new(lit(Cmp::Ge, n))),
        "!=" => F::Or(Box::new(lit(Cmp::Le, n.saturating_sub(1))), Box::new(lit(Cmp::Ge, n.saturating_add(1)))),
        _ => return cx.err(format!("`{op}` on context.{attr_name}")),
    })
}

/// A mint-time comparison on the principal's attributes.
fn principal_attr(cx: &Cx, name: &str) -> Result<Value, CompileError> {
    Ok(match name {
        "zone" => Value::from(cx.mint.zone.clone()),
        "tenant" => Value::from(cx.mint.tenant.clone()),
        "principal" => Value::from(cx.mint.principal.clone()),
        "depth" => Value::from(cx.mint.depth),
        _ => return cx.err(format!("principal.{name} isn't in the schema")),
    })
}

/// `principal in T::"id"` / `principal == T::"id"` at mint.
fn principal_is(cx: &Cx, ty: &str, id: &str, membership: bool) -> Result<bool, CompileError> {
    Ok(match ty {
        "Zone" => cx.mint.zone == id && membership,
        "Group" => membership && cx.mint.groups.contains(id),
        // Boxes are minted, not named: no policy can know one's id.
        "Box" => return cx.err("a policy can't name a Box: name its zone or a group"),
        _ => return cx.err(format!("principal in {ty}")),
    })
}

fn formula(cx: &Cx, e: &Value) -> Result<F, CompileError> {
    let obj = e.as_object().ok_or(()).or_else(|_| cx.err("expression"))?;
    let (op, arg) = obj.iter().next().ok_or(()).or_else(|_| cx.err("empty expression"))?;
    let bin = |k: &str| arg.get(k).ok_or(()).or_else(|_| cx.err(format!("`{op}` without {k}")));
    match op.as_str() {
        "Value" => match arg.as_bool() {
            Some(b) => Ok(F::Const(b)),
            None => cx.err("a literal that isn't a boolean, used as a condition"),
        },
        "&&" => Ok(F::And(Box::new(formula(cx, bin("left")?)?), Box::new(formula(cx, bin("right")?)?))),
        "||" => Ok(F::Or(Box::new(formula(cx, bin("left")?)?), Box::new(formula(cx, bin("right")?)?))),
        "!" => Ok(F::Not(Box::new(formula(cx, bin("arg")?)?))),
        "==" | "!=" | "<" | "<=" | ">" | ">=" => {
            let (l, r) = (bin("left")?, bin("right")?);
            let neg = op == "!=";
            match attr(l) {
                Some(("principal", a)) => {
                    let have = principal_attr(cx, a)?;
                    let want = value(r).ok_or(()).or_else(|_| cx.err("principal compared with a non-literal"))?;
                    let b = match (op.as_str(), have.as_i64(), want.as_i64()) {
                        ("==", ..) => have == *want,
                        ("!=", ..) => have != *want,
                        ("<", Some(h), Some(w)) => h < w,
                        ("<=", Some(h), Some(w)) => h <= w,
                        (">", Some(h), Some(w)) => h > w,
                        (">=", Some(h), Some(w)) => h >= w,
                        _ => return cx.err(format!("principal.{a} {op} a non-integer")),
                    };
                    Ok(F::Const(b))
                }
                Some(("resource", "host")) if op == "==" || op == "!=" => {
                    let h = string(r).ok_or(()).or_else(|_| cx.err("resource.host compared with a non-string"))?;
                    Ok(F::Lit(Lit { atom: Atom::HostEq(h.to_ascii_lowercase()), neg }))
                }
                Some(("context", a @ ("risk" | "isolation" | "memory" | "cpus_milli" | "pids" | "timeout_s"))) => {
                    let n = long(r).ok_or(()).or_else(|_| cx.err(format!("context.{a} compared with a non-integer")))?;
                    int_cmp(cx, op, n, a)
                }
                Some(("context", a @ ("host" | "header"))) if op == "==" || op == "!=" => {
                    let s = string(r).ok_or(()).or_else(|_| cx.err(format!("context.{a} compared with a non-string")))?;
                    Ok(F::Lit(Lit { atom: Atom::Ctx(a.to_string(), s.to_string()), neg }))
                }
                None if l.get("Var").and_then(Value::as_str) == Some("resource") && (op == "==" || op == "!=") => {
                    let (_, id) = entity(r).ok_or(()).or_else(|_| cx.err("resource compared with a non-entity"))?;
                    Ok(F::Lit(Lit { atom: Atom::Resource(vec![id]), neg }))
                }
                _ => cx.err(format!("`{op}` on {}", serde_json::to_string(l).unwrap_or_default())),
            }
        }
        "like" => {
            let pat = pattern(bin("pattern")?).ok_or(()).or_else(|_| cx.err("like pattern"))?;
            match attr(bin("left")?) {
                Some(("principal", a)) => {
                    let have = principal_attr(cx, a)?;
                    Ok(F::Const(have.as_str().is_some_and(|s| like(s, &pat))))
                }
                Some(("resource", "host")) => {
                    let lit = pat.strip_prefix('*').unwrap_or(&pat);
                    if lit.contains('*') {
                        return cx.err(format!("resource.host like {pat:?}: only \"*suffix\" or an exact host"));
                    }
                    Ok(F::Lit(Lit {
                        atom: if pat.starts_with('*') {
                            Atom::HostSuffix(lit.to_ascii_lowercase())
                        } else {
                            Atom::HostEq(lit.to_ascii_lowercase())
                        },
                        neg: false,
                    }))
                }
                Some(("resource", "path")) => Ok(F::Lit(Lit { atom: Atom::PathLike(pat), neg: false })),
                _ => cx.err("like on anything but the principal, resource.host or resource.path"),
            }
        }
        "contains" => {
            let (l, r) = (bin("left")?, bin("right")?);
            match attr(l) {
                Some(("resource", a @ ("path_matches" | "path_matches_any_case"))) => {
                    let g = string(r).ok_or(()).or_else(|_| cx.err(format!("resource.{a}.contains a non-string")))?;
                    wicket_authz::generator::path_regex(g)
                        .map_err(|e| CompileError::Unsupported { id: cx.id.clone(), msg: e.to_string() })?;
                    Ok(F::Lit(Lit { atom: Atom::PathGlob(g.to_string(), a == "path_matches_any_case"), neg: false }))
                }
                _ => cx.err("contains on anything but resource.path_matches(_any_case)"),
            }
        }
        "in" => {
            let (l, r) = (bin("left")?, bin("right")?);
            let var = l.get("Var").and_then(Value::as_str);
            let targets: Vec<(String, String)> = match (entity(r), r.get("Set").and_then(Value::as_array)) {
                (Some(e), _) => vec![e],
                (None, Some(set)) => {
                    set.iter().map(|v| entity(v).ok_or(())).collect::<Result<_, _>>().or_else(|_| cx.err("`in` a set of non-entities"))?
                }
                _ => return cx.err("`in` something that isn't an entity or a set of them"),
            };
            match var {
                Some("principal") => {
                    let mut any = false;
                    for (ty, id) in &targets {
                        any |= principal_is(cx, ty, id, true)?;
                    }
                    Ok(F::Const(any))
                }
                Some("resource") => Ok(F::Lit(Lit { atom: Atom::Resource(targets.into_iter().map(|(_, id)| id).collect()), neg: false })),
                _ => cx.err("`in` on anything but the principal or the resource"),
            }
        }
        other => cx.err(format!("`{other}` isn't in what wicket compiles (it would have to be decided at the edge)")),
    }
}

/// Negation pushed to the literals.
fn nnf(f: F, neg: bool) -> F {
    match (f, neg) {
        (F::Const(b), n) => F::Const(b != n),
        (F::Lit(mut l), n) => {
            l.neg ^= n;
            F::Lit(l)
        }
        (F::Not(x), n) => nnf(*x, !n),
        (F::And(a, b), false) => F::And(Box::new(nnf(*a, false)), Box::new(nnf(*b, false))),
        (F::Or(a, b), false) => F::Or(Box::new(nnf(*a, false)), Box::new(nnf(*b, false))),
        (F::And(a, b), true) => F::Or(Box::new(nnf(*a, true)), Box::new(nnf(*b, true))),
        (F::Or(a, b), true) => F::And(Box::new(nnf(*a, true)), Box::new(nnf(*b, true))),
    }
}

/// The most conjunctions one policy may expand to.
const MAX_CONJ: usize = 64;

/// DNF of a negation-normal formula: conjunctions of literals (constants folded).
fn dnf(cx: &Cx, f: &F) -> Result<Vec<Vec<Lit>>, CompileError> {
    Ok(match f {
        F::Const(true) => vec![vec![]],
        F::Const(false) => vec![],
        F::Lit(l) => vec![vec![l.clone()]],
        F::Or(a, b) => {
            let mut v = dnf(cx, a)?;
            v.extend(dnf(cx, b)?);
            if v.len() > MAX_CONJ {
                return cx.err(format!("expands to more than {MAX_CONJ} alternatives"));
            }
            v
        }
        F::And(a, b) => {
            let (x, y) = (dnf(cx, a)?, dnf(cx, b)?);
            if x.len() * y.len() > MAX_CONJ {
                return cx.err(format!("expands to more than {MAX_CONJ} alternatives"));
            }
            let mut v = vec![];
            for p in &x {
                for q in &y {
                    v.push(p.iter().chain(q).cloned().collect());
                }
            }
            v
        }
        F::Not(_) => unreachable!("negation normal form"),
    })
}

/// One compiled conjunction, for one action kind.
fn http_match(cx: &Cx, methods: Option<Vec<String>>, conj: &[Lit]) -> Result<HttpMatch, CompileError> {
    let mut m = HttpMatch { methods, ..Default::default() };
    for l in conj {
        match (&l.atom, l.neg) {
            (Atom::HostEq(h), false) => m.hosts.push(HostPat::Exact(h.clone())),
            (Atom::HostEq(h), true) => m.not_hosts.push(h.clone()),
            (Atom::HostSuffix(s), false) => m.hosts.push(HostPat::Suffix(s.clone())),
            (Atom::PathGlob(g, false), false) => m.paths.push(PathPat::Glob(g.clone())),
            (Atom::PathGlob(g, true), false) => m.paths.push(PathPat::GlobAnyCase(g.clone())),
            (Atom::PathLike(p), false) => m.paths.push(PathPat::Like(p.clone())),
            (Atom::Int(a, c, n), neg) if a == "risk" => {
                // !(risk <= n) is risk >= n + 1, and the other way round.
                let (c, n) = match (c, neg) {
                    (c, false) => (*c, *n),
                    (Cmp::Le, true) => (Cmp::Ge, n.saturating_add(1)),
                    (Cmp::Ge, true) => (Cmp::Le, n.saturating_sub(1)),
                };
                match c {
                    Cmp::Le => m.max_risk = Some(m.max_risk.map_or(n, |x| x.min(n))),
                    Cmp::Ge => m.min_risk = Some(m.min_risk.map_or(n, |x| x.max(n))),
                }
            }
            (a, true) => return cx.err(format!("a negated condition on {a:?} can't be checked at the edge")),
            (a, false) => return cx.err(format!("{a:?} on an HTTP action")),
        }
    }
    Ok(m)
}

fn spawn_match(cx: &Cx, scope: Option<Vec<String>>, conj: &[Lit]) -> Result<SpawnMatch, CompileError> {
    let mut m = SpawnMatch { images: scope, ..Default::default() };
    for l in conj {
        match (&l.atom, l.neg) {
            (Atom::Resource(ids), false) => {
                m.images = Some(match m.images.take() {
                    Some(have) => have.into_iter().filter(|i| ids.contains(i)).collect(),
                    None => ids.clone(),
                })
            }
            (Atom::Int(a, c, n), neg) => {
                let (c, n) = match (c, neg) {
                    (c, false) => (*c, *n),
                    (Cmp::Le, true) => (Cmp::Ge, n.saturating_add(1)),
                    (Cmp::Ge, true) => (Cmp::Le, n.saturating_sub(1)),
                };
                let tighter_max = |x: Option<i64>| Some(x.map_or(n, |x| x.min(n)));
                match (a.as_str(), c) {
                    ("isolation", Cmp::Ge) => m.min_isolation = Some(m.min_isolation.map_or(n, |x| x.max(n))),
                    ("memory", Cmp::Le) => m.max_mem_bytes = tighter_max(m.max_mem_bytes),
                    ("cpus_milli", Cmp::Le) => m.max_cpus_milli = tighter_max(m.max_cpus_milli),
                    ("pids", Cmp::Le) => m.max_pids = tighter_max(m.max_pids),
                    ("timeout_s", Cmp::Le) => m.max_timeout_s = tighter_max(m.max_timeout_s),
                    _ => return cx.err(format!("context.{a} bounded the wrong way for a spawn (isolation >=, limits <=)")),
                }
            }
            (a, _) => return cx.err(format!("{a:?} on spawn")),
        }
    }
    Ok(m)
}

/// The resource names a conjunction allows (message: zones; inject: one credential).
fn names(cx: &Cx, scope: Option<Vec<String>>, conj: &[Lit], kind: &str) -> Result<Option<Vec<String>>, CompileError> {
    let mut out = scope;
    for l in conj {
        match (&l.atom, l.neg) {
            (Atom::Resource(ids), false) => {
                out = Some(match out.take() {
                    Some(have) => have.into_iter().filter(|i| ids.contains(i)).collect(),
                    None => ids.clone(),
                })
            }
            (Atom::Ctx(..), false) if kind == "inject" => {}
            (a, _) => return cx.err(format!("{a:?} on {kind}")),
        }
    }
    Ok(out)
}

/// The action kinds (and HTTP methods) a policy's scope covers.
fn scope_actions(cx: &Cx, a: &Value) -> Result<Vec<String>, CompileError> {
    let all: Vec<String> = METHODS.iter().map(|m| m.to_string()).chain(["spawn", "message", "inject"].map(String::from)).collect();
    let id = |e: &Value| -> Option<String> { (e.get("type")?.as_str()? == "Action").then(|| e.get("id")?.as_str().map(String::from))? };
    Ok(match a.get("op").and_then(Value::as_str) {
        Some("All") => all,
        Some("==") => vec![id(a.get("entity").unwrap_or(&Value::Null)).ok_or(()).or_else(|_| cx.err("action"))?],
        Some("in") => match (a.get("entities"), a.get("entity")) {
            (Some(Value::Array(es)), _) => es.iter().map(|e| id(e).ok_or(())).collect::<Result<_, _>>().or_else(|_| cx.err("action"))?,
            // wicket's schema has no action groups: `in` one action is that action.
            (None, Some(e)) => vec![id(e).ok_or(()).or_else(|_| cx.err("action"))?],
            _ => return cx.err("action scope"),
        },
        _ => return cx.err("action scope"),
    })
}

/// The principal scope, decided at mint.
fn scope_principal(cx: &Cx, p: &Value) -> Result<bool, CompileError> {
    let e = |v: &Value| -> Option<(String, String)> { Some((v.get("type")?.as_str()?.to_string(), v.get("id")?.as_str()?.to_string())) };
    match p.get("op").and_then(Value::as_str) {
        Some("All") => Ok(true),
        Some(op @ ("in" | "==")) => {
            let (ty, id) = p.get("entity").and_then(e).ok_or(()).or_else(|_| cx.err("principal scope"))?;
            principal_is(cx, &ty, &id, op == "in" || ty == "Zone")
        }
        Some("is") => Ok(p.get("entity_type").and_then(Value::as_str) == Some("Box")),
        _ => cx.err("principal scope (templates aren't compiled: link them first)"),
    }
}

/// The resource scope: names, or None for any.
fn scope_resource(cx: &Cx, r: &Value) -> Result<Option<Vec<String>>, CompileError> {
    let id = |v: &Value| -> Option<String> { v.get("id")?.as_str().map(String::from) };
    match r.get("op").and_then(Value::as_str) {
        Some("All") => Ok(None),
        Some("==") => Ok(Some(vec![r.get("entity").and_then(id).ok_or(()).or_else(|_| cx.err("resource scope"))?])),
        Some("in") => match r.get("entities") {
            Some(Value::Array(es)) => {
                Ok(Some(es.iter().map(|v| id(v).ok_or(())).collect::<Result<_, _>>().or_else(|_| cx.err("resource scope"))?))
            }
            _ => Ok(Some(vec![r.get("entity").and_then(id).ok_or(()).or_else(|_| cx.err("resource scope"))?])),
        },
        Some("is") => Ok(None),
        _ => cx.err("resource scope"),
    }
}

/// Compiles a validated policy set into a [`Layer`], for a box described by `mint`.
pub fn compile(set: &cedar_policy::PolicySet, mint: &MintCtx) -> Result<Layer, CompileError> {
    if set.templates().next().is_some() {
        return Err(CompileError::Cedar("templates aren't compiled: link them into static policies first".into()));
    }
    #[derive(Default)]
    struct Acc {
        http: Vec<HttpMatch>,
        http_all: bool,
        forbid: Vec<HttpMatch>,
        spawn: Vec<SpawnMatch>,
        spawn_all: bool,
        msg: BTreeSet<String>,
        msg_all: bool,
        inject: BTreeSet<String>,
        inject_all: bool,
    }
    let (mut acc, mut scratch) = (Acc::default(), Acc::default());
    for p in set.policies() {
        let id = p.annotation("id").map(String::from).unwrap_or_else(|| p.id().to_string());
        let cx = Cx { id, mint };
        let j = p.to_json().map_err(|e| CompileError::Cedar(e.to_string()))?;
        let permit = j.get("effect").and_then(Value::as_str) == Some("permit");
        // A policy whose principal scope doesn't hold for this box is still compiled (and refused
        // if it can't be), so a construct outside the fragment fails at check, not at some box's mint.
        let applies = scope_principal(&cx, &j["principal"])?;
        let a: &mut Acc = if applies { &mut acc } else { &mut scratch };
        let actions = scope_actions(&cx, &j["action"])?;
        let res_scope = scope_resource(&cx, &j["resource"])?;
        let mut f = F::Const(true);
        for c in j.get("conditions").and_then(Value::as_array).into_iter().flatten() {
            let body = formula(&cx, &c["body"])?;
            let body = if c["kind"] == "unless" { F::Not(Box::new(body)) } else { body };
            f = F::And(Box::new(f), Box::new(body));
        }
        let conjs = dnf(&cx, &nnf(f, false))?;
        let methods: Vec<String> = actions.iter().filter(|a| METHODS.contains(&a.as_str())).cloned().collect();
        let all_methods = methods.len() == METHODS.len();
        let has = |k: &str| actions.iter().any(|a| a == k);
        if !methods.is_empty() {
            let ms = (!all_methods).then(|| methods.clone());
            for c in &conjs {
                let m = http_match(&cx, ms.clone(), c)?;
                if permit {
                    if m == HttpMatch::default() {
                        a.http_all = true;
                    }
                    a.http.push(m);
                } else {
                    a.forbid.push(m);
                }
            }
        }
        for (kind, k) in [(Kind::Spawn, "spawn"), (Kind::Message, "message"), (Kind::Inject, "inject")] {
            if !has(k) {
                continue;
            }
            if !permit && !conjs.is_empty() {
                return cx.err(format!("a forbid on {k}: write it as a narrower permit (only HTTP forbids reach the edge)"));
            }
            for c in &conjs {
                match kind {
                    Kind::Spawn => {
                        let m = spawn_match(&cx, res_scope.clone(), c)?;
                        a.spawn_all |= m == SpawnMatch::default();
                        a.spawn.push(m);
                    }
                    Kind::Message => match names(&cx, res_scope.clone(), c, "message")? {
                        Some(z) => a.msg.extend(z),
                        None => a.msg_all = true,
                    },
                    Kind::Inject => {
                        let secret = names(&cx, res_scope.clone(), c, "inject")?;
                        let ctx = |want: &str| {
                            c.iter().find_map(|l| match (&l.atom, l.neg) {
                                (Atom::Ctx(a, s), false) if a == want => Some(s.clone()),
                                _ => None,
                            })
                        };
                        match (secret, ctx("host"), ctx("header")) {
                            (None, None, None) => a.inject_all = true,
                            (Some(ss), Some(h), Some(hd)) => {
                                for s in ss {
                                    a.inject.insert(format!("{}|{hd}|{s}", h.to_ascii_lowercase()));
                                }
                            }
                            _ => {
                                return cx
                                    .err("an inject permit names its secret, context.host and context.header exactly (or none of them)")
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(Layer {
        http: (!acc.http_all).then_some(acc.http),
        forbid: acc.forbid,
        spawn: (!acc.spawn_all).then_some(acc.spawn),
        msg_from: (!acc.msg_all).then(|| acc.msg.into_iter().collect()),
        inject: (!acc.inject_all).then(|| acc.inject.into_iter().collect()),
    })
}

/// Parses and strictly validates Cedar text against wicket's schema. Strict validation is what
/// keeps evaluation from erroring at the edge (Cedar skips a policy whose condition errors, which
/// for a forbid would fail open).
pub fn parse(text: &str) -> Result<cedar_policy::PolicySet, CompileError> {
    let set: cedar_policy::PolicySet = text.parse().map_err(|e: cedar_policy::ParseErrors| CompileError::Cedar(format!("{e:?}")))?;
    let v = cedar_policy::Validator::new(crate::schema::schema());
    let r = v.validate(&set, cedar_policy::ValidationMode::Strict);
    if !r.validation_passed() {
        let errs: Vec<String> = r.validation_errors().map(|e| e.to_string()).collect();
        return Err(CompileError::Cedar(format!("the policy doesn't validate against wicket's schema: {}", errs.join("; "))));
    }
    Ok(set)
}
