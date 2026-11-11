/*
 * Copyright (c) 2019 Geoffroy Couprie <contact@geoffroycouprie.com> and Contributors to the Eclipse Foundation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * fork (wicket experiment biscuit-fast): new file.
 */
//! A compiled form of a [`PreparedAuthorizer`], shared between threads without per-thread copies.
//!
//! Compilation (once per token) turns the prepared world into flat arrays:
//! - every term becomes a 16-byte copyable value; strings stay symbol indices, sets and byte strings
//!   are interned so that index equality is value equality;
//! - every predicate gets a dense slot; the token's facts are stored per slot with their origin as a
//!   64-bit mask (bit i = block i, bit 63 = authorizer), so scope filtering is one AND;
//! - each query lists, per body predicate, the token facts it can see (scope and constants
//!   pre-filtered), and its variables are renumbered into a small fixed array;
//! - expressions become a postfix program over a fixed-size stack; `||`/`&&` closures become jumps;
//!   `.matches()` patterns are compiled once.
//!
//! Per request, ambient facts are interned into a thread-local scratch overlay that is reused, so a
//! decision allocates nothing once warm. Rules run semi-naively over the overlay only (the token's
//! own facts were saturated when preparing).
//!
//! Semantics follow the generic engine. Whatever the compiler does not support (arrays, maps, closures
//! with parameters, FFI, string concatenation, more than 62 blocks, …) makes the token use the generic
//! engine. At run time, any expression error (type error, overflow, …) or unsupported value makes that
//! one request fall back to the generic engine, so errors are reported exactly as there.
//!
//! Limits are deterministic: one step per candidate fact visited and per operator, as upstream, and
//! `.matches()` costs 1 + input length / 16 steps.
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};
use std::convert::TryInto;
use std::hash::{BuildHasherDefault, Hasher};

use regex::Regex;

use super::{Binary, Expression, Op, Origin, Predicate, Rule, SymbolIndex, Term, TrustedOrigins, Unary};
use crate::builder::{self, CheckKind, PolicyKind};
use crate::error;
use crate::token::authorizer::prepared::{finish, Inner, PQuery, PreparedAuthorizer, PreparedLimits, RunStats};

// ------------------------------------------------------------------------------------------------
// small fast hasher for the symbol and slot maps

#[derive(Default, Clone, Copy)]
struct Fx(u64);
impl Hasher for Fx {
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            self.add(u64::from_le_bytes(c.try_into().unwrap()));
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut b = [0u8; 8];
            b[..rest.len()].copy_from_slice(rest);
            self.add(u64::from_le_bytes(b) ^ (rest.len() as u64) << 56);
        }
    }
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64)
    }
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64)
    }
    fn write_u64(&mut self, i: u64) {
        self.add(i)
    }
    fn finish(&self) -> u64 {
        self.0
    }
}
impl Fx {
    #[inline]
    fn add(&mut self, w: u64) {
        self.0 = (self.0.rotate_left(5) ^ w).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}
type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<Fx>>;

// ------------------------------------------------------------------------------------------------
// values

type Mask = u64;
const AUTHORIZER: Mask = 1 << 63;
/// symbol indices of per-request strings start here (base symbols are < 2^32 in practice)
const OVERLAY_STR: u64 = 1 << 48;
const MAX_VARS: usize = 32;
const MAX_STACK: usize = 16;
const MAX_ARITY: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum V {
    Int(i64),
    Str(u64),
    Date(u64),
    Bool(bool),
    Null,
    /// interned byte string (base pool, then per-request)
    Bytes(u32),
    /// interned set (token constants only)
    Set(u32),
}

fn origin_mask(o: &Origin) -> Option<Mask> {
    let mut m = 0;
    for &i in &o.inner {
        if i == usize::MAX {
            m |= AUTHORIZER;
        } else if i < 63 {
            m |= 1 << i;
        } else {
            return None;
        }
    }
    Some(m)
}

fn trusted_mask(t: &TrustedOrigins) -> Mask {
    let mut m = 0;
    for i in t.ids() {
        if i == usize::MAX {
            m |= AUTHORIZER;
        } else if i < 63 {
            m |= 1 << i;
        }
        // ids >= 63 can't be fact origins: compilation refuses tokens with that many blocks
    }
    m
}

// ------------------------------------------------------------------------------------------------
// program

#[derive(Clone, Copy, Debug)]
enum Arg {
    Var(u8),
    Const(V),
}

#[derive(Debug)]
struct CPred {
    slot: u32,
    args: Box<[Arg]>,
    /// visible token facts (origin mask, offset in `base_vals`), scope and constants pre-filtered
    base: Box<[(Mask, u32)]>,
}

#[derive(Clone, Copy, Debug)]
enum Un {
    Negate,
    Parens,
    Length,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bin {
    Lt,
    Gt,
    Le,
    Ge,
    Eq,
    Ne,
    HEq,
    HNe,
    Contains,
    Prefix,
    Suffix,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
}

#[derive(Clone, Copy, Debug)]
enum COp {
    Push(V),
    Var(u8),
    Un(Un),
    Bin(Bin),
    /// `.matches()` with a constant pattern: index into `regexes`
    Regex(u32),
    /// `left || <closure>`: if left is true, skip the closure's ops
    LazyOr(u32),
    LazyAnd(u32),
}

#[derive(Debug)]
struct CQuery {
    body: Box<[CPred]>,
    exprs: Box<[Box<[COp]>]>,
    trusted: Mask,
}

#[derive(Debug)]
struct CRule {
    q: CQuery,
    head_slot: u32,
    head: Box<[Arg]>,
    origin: Mask,
}

#[derive(Debug)]
struct CCheck {
    kind: CheckKind,
    queries: Box<[CQuery]>,
}

#[derive(Debug)]
struct CPolicy {
    kind: PolicyKind,
    queries: Box<[CQuery]>,
}

#[derive(Debug)]
struct Program {
    /// predicate name -> slot per arity
    names: FxMap<Box<str>, [u32; MAX_ARITY]>,
    arity: Vec<u8>,
    base_vals: Vec<V>,
    base_count: usize,
    /// every token fact per slot (for de-duplicating request and derived facts)
    base_by_slot: Vec<Vec<(Mask, u32)>>,
    rules: Vec<CRule>,
    pre: Vec<CCheck>,
    policies: Vec<CPolicy>,
    post: Vec<CCheck>,
    symbols: FxMap<Box<str>, u64>,
    /// symbol strings by index: default symbols (< 1024), then the table's own (>= 1024)
    sym_low: Vec<Box<str>>,
    sym_high: Vec<Box<str>>,
    sets: Vec<Box<[V]>>,
    bytes: Vec<Box<[u8]>>,
    bytes_idx: FxMap<Box<[u8]>, u32>,
    regexes: Vec<Option<Regex>>,
}

const NO_SLOT: u32 = u32::MAX;

/// A compiled [`PreparedAuthorizer`]: immutable and `Send + Sync`; share it behind an `Arc`.
pub struct CompiledAuthorizer {
    prepared: PreparedAuthorizer,
    prog: Option<Box<Program>>,
    why_not: Option<String>,
}

// ------------------------------------------------------------------------------------------------
// compilation

struct Compiler<'a> {
    inner: &'a Inner,
    p: Program,
    sets_idx: HashMap<BTreeSet<Term>, u32>,
    regex_idx: HashMap<SymbolIndex, u32>,
}

type CResult<T> = Result<T, String>;

impl<'a> Compiler<'a> {
    fn slot(&mut self, name: SymbolIndex, arity: usize) -> CResult<u32> {
        if arity >= MAX_ARITY {
            return Err(format!("predicate arity {arity}"));
        }
        let s = self.inner.symbols.get_symbol(name).ok_or("unknown predicate symbol")?;
        let entry = self.p.names.entry(s.into()).or_insert([NO_SLOT; MAX_ARITY]);
        if entry[arity] == NO_SLOT {
            entry[arity] = self.p.arity.len() as u32;
            self.p.arity.push(arity as u8);
            self.p.base_by_slot.push(Vec::new());
        }
        Ok(entry[arity])
    }

    fn value(&mut self, t: &Term) -> CResult<V> {
        Ok(match t {
            Term::Integer(i) => V::Int(*i),
            Term::Str(s) => V::Str(*s),
            Term::Date(d) => V::Date(*d),
            Term::Bool(b) => V::Bool(*b),
            Term::Null => V::Null,
            Term::Bytes(b) => V::Bytes(intern_bytes(&mut self.p, b)),
            Term::Set(s) => {
                if let Some(i) = self.sets_idx.get(s) {
                    return Ok(V::Set(*i));
                }
                let elems = s.iter().map(|t| self.value(t)).collect::<CResult<Vec<_>>>()?;
                if elems.iter().any(|e| matches!(e, V::Set(_))) {
                    return Err("nested set".into());
                }
                let i = self.p.sets.len() as u32;
                self.p.sets.push(elems.into());
                self.sets_idx.insert(s.clone(), i);
                V::Set(i)
            }
            Term::Variable(_) => return Err("variable in a fact".into()),
            Term::Array(_) | Term::Map(_) => return Err("arrays and maps".into()),
        })
    }

    fn args(&mut self, p: &Predicate, vars: &HashMap<u32, u8>) -> CResult<Box<[Arg]>> {
        p.terms
            .iter()
            .map(|t| match t {
                Term::Variable(v) => Ok(Arg::Var(vars[v])),
                t => self.value(t).map(Arg::Const),
            })
            .collect()
    }

    fn query(&mut self, rule: &Rule, trusted: &TrustedOrigins) -> CResult<(CQuery, HashMap<u32, u8>)> {
        let trusted = trusted_mask(trusted);
        let mut vars: HashMap<u32, u8> = HashMap::new();
        for p in &rule.body {
            for t in &p.terms {
                if let Term::Variable(v) = t {
                    let n = vars.len();
                    vars.entry(*v).or_insert(n as u8);
                }
            }
        }
        if vars.len() > MAX_VARS {
            return Err("too many variables".into());
        }
        let mut body = Vec::new();
        for p in &rule.body {
            let slot = self.slot(p.name, p.terms.len())?;
            let args = self.args(p, &vars)?;
            let base = self.p.base_by_slot[slot as usize]
                .iter()
                .filter(|(m, off)| {
                    m & !trusted == 0
                        && args.iter().enumerate().all(|(k, a)| match a {
                            Arg::Const(c) => self.p.base_vals[*off as usize + k] == *c,
                            Arg::Var(_) => true,
                        })
                })
                .copied()
                .collect();
            body.push(CPred { slot, args, base });
        }
        let exprs = rule.expressions.iter().map(|e| self.expr(e, &vars)).collect::<CResult<Vec<_>>>()?;
        Ok((CQuery { body: body.into(), exprs: exprs.into(), trusted }, vars))
    }

    fn expr(&mut self, e: &Expression, vars: &HashMap<u32, u8>) -> CResult<Box<[COp]>> {
        let mut out = Vec::new();
        self.ops(&e.ops, vars, &mut out)?;
        // the stack must end with exactly one value and never exceed MAX_STACK
        let mut depth: i32 = 0;
        let mut max = 0;
        for op in &out {
            depth += match op {
                COp::Push(_) | COp::Var(_) => 1,
                COp::Un(_) => 0,
                COp::Bin(_) => -1,
                COp::Regex(_) => 0,
                // pops the left value; the closure body (or the skip) pushes one back
                COp::LazyOr(_) | COp::LazyAnd(_) => -1,
            };
            max = max.max(depth);
            if depth < 0 {
                return Err("invalid stack".into());
            }
        }
        if max as usize > MAX_STACK {
            return Err("expression too deep".into());
        }
        Ok(out.into())
    }

    fn ops(&mut self, ops: &[Op], vars: &HashMap<u32, u8>, out: &mut Vec<COp>) -> CResult<()> {
        let mut i = 0;
        while i < ops.len() {
            match &ops[i] {
                Op::Value(Term::Variable(v)) => out.push(COp::Var(*vars.get(v).ok_or("expression variable not bound by the body")?)),
                Op::Value(t) => {
                    let v = self.value(t)?;
                    out.push(COp::Push(v));
                }
                Op::Unary(Unary::Negate) => out.push(COp::Un(Un::Negate)),
                Op::Unary(Unary::Parens) => out.push(COp::Un(Un::Parens)),
                Op::Unary(Unary::Length) => out.push(COp::Un(Un::Length)),
                Op::Unary(u) => return Err(format!("unary {u:?}")),
                Op::Closure(params, body) => {
                    let lazy = match ops.get(i + 1) {
                        Some(Op::Binary(Binary::LazyOr)) if params.is_empty() => true,
                        Some(Op::Binary(Binary::LazyAnd)) if params.is_empty() => false,
                        _ => return Err("closure".into()),
                    };
                    let at = out.len();
                    out.push(COp::LazyOr(0));
                    let mut inner = Vec::new();
                    self.ops(body, vars, &mut inner)?;
                    // the closure body runs on its own stack upstream: it must leave exactly one value
                    let mut d: i32 = 0;
                    for op in &inner {
                        d += match op {
                            COp::Push(_) | COp::Var(_) => 1,
                            COp::Bin(_) | COp::LazyOr(_) | COp::LazyAnd(_) => -1,
                            _ => 0,
                        };
                        if d < 0 {
                            return Err("invalid closure stack".into());
                        }
                    }
                    if d != 1 {
                        return Err("invalid closure stack".into());
                    }
                    let n = inner.len() as u32;
                    out[at] = if lazy { COp::LazyOr(n) } else { COp::LazyAnd(n) };
                    out.extend(inner);
                    i += 1; // the LazyOr/LazyAnd op itself
                }
                Op::Binary(Binary::Regex) => match out.pop() {
                    Some(COp::Push(V::Str(sym))) => {
                        let idx = match self.regex_idx.get(&sym) {
                            Some(i) => *i,
                            None => {
                                let pat = self.inner.symbols.get_symbol(sym).ok_or("unknown symbol")?;
                                // upstream: an invalid pattern never matches
                                let re = Regex::new(pat).ok();
                                let i = self.p.regexes.len() as u32;
                                self.p.regexes.push(re);
                                self.regex_idx.insert(sym, i);
                                i
                            }
                        };
                        out.push(COp::Regex(idx));
                    }
                    _ => return Err("regex with a non-constant pattern".into()),
                },
                Op::Binary(b) => out.push(COp::Bin(match b {
                    Binary::LessThan => Bin::Lt,
                    Binary::GreaterThan => Bin::Gt,
                    Binary::LessOrEqual => Bin::Le,
                    Binary::GreaterOrEqual => Bin::Ge,
                    Binary::Equal => Bin::Eq,
                    Binary::NotEqual => Bin::Ne,
                    Binary::HeterogeneousEqual => Bin::HEq,
                    Binary::HeterogeneousNotEqual => Bin::HNe,
                    Binary::Contains => Bin::Contains,
                    Binary::Prefix => Bin::Prefix,
                    Binary::Suffix => Bin::Suffix,
                    Binary::Add => Bin::Add,
                    Binary::Sub => Bin::Sub,
                    Binary::Mul => Bin::Mul,
                    Binary::Div => Bin::Div,
                    Binary::And => Bin::And,
                    Binary::Or => Bin::Or,
                    Binary::BitwiseAnd => Bin::BitAnd,
                    Binary::BitwiseOr => Bin::BitOr,
                    Binary::BitwiseXor => Bin::BitXor,
                    b => return Err(format!("binary {b:?}")),
                })),
            }
            i += 1;
        }
        Ok(())
    }

    fn queries(&mut self, qs: &[PQuery]) -> CResult<Box<[CQuery]>> {
        qs.iter().map(|q| self.query(&q.rule, &q.trusted).map(|x| x.0)).collect()
    }
}

fn intern_bytes(p: &mut Program, b: &[u8]) -> u32 {
    if let Some(i) = p.bytes_idx.get(b) {
        return *i;
    }
    let i = p.bytes.len() as u32;
    p.bytes.push(b.into());
    p.bytes_idx.insert(b.into(), i);
    i
}

fn compile(inner: &Inner) -> CResult<Program> {
    if inner.block_count > 62 {
        return Err("more than 62 blocks".into());
    }
    if !inner.extern_funcs.is_empty() {
        return Err("extern functions".into());
    }
    let mut c = Compiler {
        inner,
        p: Program {
            names: FxMap::default(),
            arity: Vec::new(),
            base_vals: Vec::new(),
            base_count: inner.fact_count,
            base_by_slot: Vec::new(),
            rules: Vec::new(),
            pre: Vec::new(),
            policies: Vec::new(),
            post: Vec::new(),
            symbols: FxMap::default(),
            sym_low: Vec::new(),
            sym_high: Vec::new(),
            sets: Vec::new(),
            bytes: Vec::new(),
            bytes_idx: FxMap::default(),
            regexes: Vec::new(),
        },
        sets_idx: HashMap::new(),
        regex_idx: HashMap::new(),
    };
    for (i, s) in inner.symbols.indexed() {
        c.p.symbols.entry(s.into()).or_insert(i);
        if i >= 1024 {
            debug_assert_eq!(c.p.sym_high.len() as u64, i - 1024);
            c.p.sym_high.push(s.into());
        } else {
            c.p.sym_low.push(s.into());
        }
    }
    // the token's facts, already saturated with its own rules
    for (origin, fact) in inner.facts.iter_all() {
        let m = origin_mask(origin).ok_or("block id >= 63")?;
        let slot = c.slot(fact.predicate.name, fact.predicate.terms.len())?;
        let off = c.p.base_vals.len() as u32;
        for t in &fact.predicate.terms {
            let v = c.value(t)?;
            c.p.base_vals.push(v);
        }
        c.p.base_by_slot[slot as usize].push((m, off));
    }
    // rules (a stable order: by origin, then as stored)
    let mut rules: Vec<(&TrustedOrigins, usize, &Rule)> =
        inner.rules.inner.iter().flat_map(|(scope, rs)| rs.iter().map(move |(o, r)| (scope, *o, r))).collect();
    rules.sort_by_key(|(_, o, _)| *o);
    for (scope, origin, rule) in rules {
        let (q, vars) = c.query(rule, scope)?;
        let head_slot = c.slot(rule.head.name, rule.head.terms.len())?;
        let head = c.args(&rule.head, &vars)?;
        let origin = if origin == usize::MAX {
            AUTHORIZER
        } else if origin < 63 {
            1 << origin
        } else {
            return Err("block id >= 63".into());
        };
        c.p.rules.push(CRule { q, head_slot, head, origin });
    }
    for pc in &inner.pre_checks {
        let queries = c.queries(&pc.queries)?;
        c.p.pre.push(CCheck { kind: pc.kind.clone(), queries });
    }
    for pp in &inner.policies {
        let queries = c.queries(&pp.queries)?;
        c.p.policies.push(CPolicy { kind: pp.kind.clone(), queries });
    }
    for pc in &inner.post_checks {
        let queries = c.queries(&pc.queries)?;
        c.p.post.push(CCheck { kind: pc.kind.clone(), queries });
    }
    Ok(c.p)
}

impl PreparedAuthorizer {
    /// fork: compiles the prepared world for the fast path (once per token)
    pub fn compile(&self) -> CompiledAuthorizer {
        let (prog, why_not) = if self.inner.prepare_error.is_some() {
            (None, Some("prepare error".to_string()))
        } else {
            match compile(&self.inner) {
                Ok(p) => (Some(Box::new(p)), None),
                Err(e) => (None, Some(e)),
            }
        };
        CompiledAuthorizer { prepared: self.clone(), prog, why_not }
    }
}

// ------------------------------------------------------------------------------------------------
// evaluation

/// Per-thread scratch space, reused across requests.
#[derive(Default)]
struct Scratch {
    vals: Vec<V>,
    /// overlay facts per slot: (origin mask, offset in `vals`)
    facts: Vec<Vec<(Mask, u32)>>,
    used: Vec<u32>,
    strbuf: String,
    strs: Vec<(u32, u32)>,
    bytes: Vec<Box<[u8]>>,
    pending: Vec<(u32, Mask, u32)>,
    pending_vals: Vec<V>,
    /// facts that no rule or check reads (counted for max_facts only)
    unread: usize,
    count: usize,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
    static LAST: Cell<RunStats> = Cell::new(RunStats::default());
}

/// why the fast path stopped
enum Stop {
    /// an expression error or a value the fast path does not handle: use the generic engine
    Fallback,
    Limit(error::RunLimit),
}

#[derive(Clone, Copy)]
struct Env {
    vals: [V; MAX_VARS],
    bound: u32,
}

struct Ctx<'a> {
    p: &'a Program,
    sc: &'a Scratch,
    steps: u64,
    max_steps: u64,
    /// rules: overlay offsets >= this are new in the previous iteration
    delta: u32,
}

impl Ctx<'_> {
    #[inline(always)]
    fn step(&mut self) -> Result<(), Stop> {
        self.steps += 1;
        if self.steps > self.max_steps {
            Err(Stop::Limit(error::RunLimit::TooManySteps))
        } else {
            Ok(())
        }
    }

    #[inline]
    fn str(&self, i: u64) -> Option<&str> {
        if i >= OVERLAY_STR {
            let (s, l) = *self.sc.strs.get((i - OVERLAY_STR) as usize)?;
            Some(&self.sc.strbuf[s as usize..(s + l) as usize])
        } else {
            self.p.symbols_by_index(i)
        }
    }

    #[inline]
    fn bytes(&self, i: u32) -> &[u8] {
        let n = self.p.bytes.len();
        if (i as usize) < n {
            &self.p.bytes[i as usize]
        } else {
            &self.sc.bytes[i as usize - n]
        }
    }

    #[inline(always)]
    fn unify(args: &[Arg], vals: &[V], env: &mut Env) -> bool {
        for (a, v) in args.iter().zip(vals) {
            match a {
                Arg::Const(c) => {
                    if c != v {
                        return false;
                    }
                }
                Arg::Var(x) => {
                    let bit = 1u32 << x;
                    if env.bound & bit != 0 {
                        if env.vals[*x as usize] != *v {
                            return false;
                        }
                    } else {
                        env.vals[*x as usize] = *v;
                        env.bound |= bit;
                    }
                }
            }
        }
        true
    }

    /// Enumerates the bindings of `q`'s body from predicate `k` on; calls `f` on each complete
    /// binding with the union of the matched facts' origins and whether one was new (rules).
    /// Returns true as soon as `f` does.
    fn join<F>(&mut self, q: &CQuery, k: usize, env: &mut Env, mask: Mask, new: bool, f: &mut F) -> Result<bool, Stop>
    where
        F: FnMut(&mut Self, &Env, Mask, bool) -> Result<bool, Stop>,
    {
        if k == q.body.len() {
            return f(self, env, mask, new);
        }
        let p = &q.body[k];
        let arity = p.args.len();
        for &(m, off) in p.base.iter() {
            self.step()?;
            let saved = env.bound;
            let vals = &self.p.base_vals[off as usize..off as usize + arity];
            if Self::unify(&p.args, vals, env) && self.join(q, k + 1, env, mask | m, new, f)? {
                env.bound = saved;
                return Ok(true);
            }
            env.bound = saved;
        }
        let list = &self.sc.facts[p.slot as usize];
        for &(m, off) in list.iter() {
            if m & !q.trusted != 0 {
                continue;
            }
            self.step()?;
            let saved = env.bound;
            let vals = &self.sc.vals[off as usize..off as usize + arity];
            if Self::unify(&p.args, vals, env) && self.join(q, k + 1, env, mask | m, new || off >= self.delta, f)? {
                env.bound = saved;
                return Ok(true);
            }
            env.bound = saved;
        }
        Ok(false)
    }

    /// evaluates one expression: Some(true/false), or Stop::Fallback for a non-boolean result
    fn eval(&mut self, ops: &[COp], env: &Env) -> Result<bool, Stop> {
        let mut st = [V::Null; MAX_STACK];
        let mut sp = 0usize;
        let mut pc = 0usize;
        while pc < ops.len() {
            match ops[pc] {
                COp::Push(v) => {
                    st[sp] = v;
                    sp += 1;
                }
                COp::Var(x) => {
                    st[sp] = env.vals[x as usize];
                    sp += 1;
                }
                COp::Un(u) => {
                    self.step()?;
                    st[sp - 1] = self.unary(u, st[sp - 1])?;
                }
                COp::Bin(b) => {
                    self.step()?;
                    sp -= 1;
                    st[sp - 1] = self.binary(b, st[sp - 1], st[sp])?;
                }
                COp::Regex(i) => {
                    self.step()?;
                    let r = match st[sp - 1] {
                        V::Str(s) => {
                            let extra = self.str(s).ok_or(Stop::Fallback)?.len() as u64 / 16;
                            self.steps += extra;
                            let s = self.str(s).ok_or(Stop::Fallback)?;
                            if self.steps > self.max_steps {
                                return Err(Stop::Limit(error::RunLimit::TooManySteps));
                            }
                            match &self.p.regexes[i as usize] {
                                Some(re) => re.is_match(s),
                                None => false,
                            }
                        }
                        _ => return Err(Stop::Fallback),
                    };
                    st[sp - 1] = V::Bool(r);
                }
                COp::LazyOr(skip) | COp::LazyAnd(skip) => {
                    self.step()?;
                    let or = matches!(ops[pc], COp::LazyOr(_));
                    sp -= 1;
                    match st[sp] {
                        V::Bool(b) if b == or => {
                            // short-circuit: the closure is not applied
                            st[sp] = V::Bool(b);
                            sp += 1;
                            pc += skip as usize;
                        }
                        V::Bool(_) => {
                            // applying the closure costs a step; its body follows inline
                            self.step()?;
                        }
                        _ => return Err(Stop::Fallback),
                    }
                }
            }
            pc += 1;
        }
        match st[0] {
            V::Bool(b) if sp == 1 => Ok(b),
            // upstream: a non-boolean result is an error
            _ => Err(Stop::Fallback),
        }
    }

    #[inline]
    fn unary(&self, u: Un, v: V) -> Result<V, Stop> {
        Ok(match (u, v) {
            (Un::Negate, V::Bool(b)) => V::Bool(!b),
            (Un::Parens, v) => v,
            (Un::Length, V::Str(s)) => V::Int(self.str(s).ok_or(Stop::Fallback)?.len() as i64),
            (Un::Length, V::Bytes(b)) => V::Int(self.bytes(b).len() as i64),
            (Un::Length, V::Set(s)) => V::Int(self.p.sets[s as usize].len() as i64),
            _ => return Err(Stop::Fallback),
        })
    }

    /// upstream `Binary::evaluate`, for the values the fast path represents. Anything that is an
    /// error upstream, or that would create a new value (string concatenation, set union), falls back.
    fn binary(&self, b: Bin, l: V, r: V) -> Result<V, Stop> {
        use Bin::*;
        use V::*;
        Ok(match (b, l, r) {
            (Lt, Int(i), Int(j)) => Bool(i < j),
            (Gt, Int(i), Int(j)) => Bool(i > j),
            (Le, Int(i), Int(j)) => Bool(i <= j),
            (Ge, Int(i), Int(j)) => Bool(i >= j),
            (Add, Int(i), Int(j)) => Int(i.checked_add(j).ok_or(Stop::Fallback)?),
            (Sub, Int(i), Int(j)) => Int(i.checked_sub(j).ok_or(Stop::Fallback)?),
            (Mul, Int(i), Int(j)) => Int(i.checked_mul(j).ok_or(Stop::Fallback)?),
            (Div, Int(i), Int(j)) => Int(i.checked_div(j).ok_or(Stop::Fallback)?),
            (BitAnd, Int(i), Int(j)) => Int(i & j),
            (BitOr, Int(i), Int(j)) => Int(i | j),
            (BitXor, Int(i), Int(j)) => Int(i ^ j),
            (Lt, Date(i), Date(j)) => Bool(i < j),
            (Gt, Date(i), Date(j)) => Bool(i > j),
            (Le, Date(i), Date(j)) => Bool(i <= j),
            (Ge, Date(i), Date(j)) => Bool(i >= j),
            (Prefix, Str(s), Str(p)) => Bool(self.str(s).ok_or(Stop::Fallback)?.starts_with(self.str(p).ok_or(Stop::Fallback)?)),
            (Suffix, Str(s), Str(p)) => Bool(self.str(s).ok_or(Stop::Fallback)?.ends_with(self.str(p).ok_or(Stop::Fallback)?)),
            (Contains, Str(s), Str(p)) => Bool(self.str(s).ok_or(Stop::Fallback)?.contains(self.str(p).ok_or(Stop::Fallback)?)),
            (And, Bool(i), Bool(j)) => Bool(i & j),
            (Or, Bool(i), Bool(j)) => Bool(i | j),
            // sets: membership and inclusion (interned, so index equality is set equality)
            (Contains, Set(s), Set(t)) => {
                let s = &self.p.sets[s as usize];
                Bool(self.p.sets[t as usize].iter().all(|x| s.contains(x)))
            }
            (Contains, Set(s), x @ (Int(_) | Date(_) | Bool(_) | Str(_) | Bytes(_))) => Bool(self.p.sets[s as usize].contains(&x)),
            // equality of two values of the same type (strict and heterogeneous)
            (Eq | HEq, x, y) if same_type(x, y) => Bool(x == y),
            (Ne | HNe, x, y) if same_type(x, y) => Bool(x != y),
            // heterogeneous equality across types (null included)
            (HEq, _, _) => Bool(false),
            (HNe, _, _) => Bool(true),
            _ => return Err(Stop::Fallback),
        })
    }
}

#[inline]
fn same_type(a: V, b: V) -> bool {
    std::mem::discriminant(&a) == std::mem::discriminant(&b)
}

impl Program {
    #[inline]
    fn symbols_by_index(&self, i: u64) -> Option<&str> {
        if i >= 1024 {
            self.sym_high.get((i - 1024) as usize).map(|s| &**s)
        } else {
            self.sym_low.get(i as usize).map(|s| &**s)
        }
    }
}

/// shorthand
fn rl(e: error::RunLimit) -> error::Token {
    error::Token::RunLimit(e)
}

enum Mode {
    /// evaluate everything, report every failed check (upstream behaviour)
    Report,
    /// stop at the first failed check or deny
    Decide,
}

impl CompiledAuthorizer {
    /// true if the token was compiled (false: every request uses the generic engine)
    pub fn is_compiled(&self) -> bool {
        self.prog.is_some()
    }

    /// why the token was not compiled
    pub fn not_compiled_reason(&self) -> Option<&str> {
        self.why_not.as_deref()
    }

    /// what the last request on this thread used
    pub fn last_run(&self) -> RunStats {
        LAST.with(|l| l.get())
    }

    /// decides one request; same result and errors as [`crate::PreparedSession::authorize`]
    pub fn authorize(&self, facts: &[builder::Fact], limits: &PreparedLimits) -> Result<usize, error::Token> {
        self.run(facts, limits, Mode::Report)
    }

    /// decides one request, stopping at the first failed check (no list of failed checks)
    pub fn allows(&self, facts: &[builder::Fact], limits: &PreparedLimits) -> bool {
        self.run(facts, limits, Mode::Decide).is_ok()
    }

    fn generic(&self, facts: &[builder::Fact], limits: &PreparedLimits) -> Result<usize, error::Token> {
        let mut s = self.prepared.session();
        let r = s.authorize(facts, limits);
        let mut st = s.last_run();
        st.fallback = true;
        LAST.with(|l| l.set(st));
        r
    }

    fn run(&self, facts: &[builder::Fact], limits: &PreparedLimits, mode: Mode) -> Result<usize, error::Token> {
        let inner = &*self.prepared.inner;
        if let Some(e) = &inner.prepare_error {
            LAST.with(|l| l.set(RunStats::default()));
            return Err(e.clone());
        }
        let p = match &self.prog {
            Some(p) => p,
            None => return self.generic(facts, limits),
        };
        let res = SCRATCH.with(|sc| {
            let mut sc = sc.borrow_mut();
            if !load_facts(p, &mut sc, facts)? {
                return Ok(None);
            }
            match decide(p, inner, &mut sc, limits, mode) {
                Ok(r) => Ok(Some(r)),
                Err(e) => Err(e),
            }
        });
        match res {
            Ok(Some((_, st))) if st.fallback => self.generic(facts, limits),
            Ok(Some((r, st))) => {
                LAST.with(|l| l.set(st));
                r
            }
            Ok(None) => self.generic(facts, limits),
            Err(e) => Err(e),
        }
    }
}

/// Interns the request facts into the scratch overlay. Ok(false): something the fast path does not
/// represent (sets, arrays, maps, parameters): use the generic engine.
fn load_facts(p: &Program, sc: &mut Scratch, facts: &[builder::Fact]) -> Result<bool, error::Token> {
    // reset
    for &s in &sc.used {
        sc.facts[s as usize].clear();
    }
    sc.used.clear();
    if sc.facts.len() < p.arity.len() {
        sc.facts.resize_with(p.arity.len(), Vec::new);
    }
    sc.vals.clear();
    sc.strbuf.clear();
    sc.strs.clear();
    sc.bytes.clear();
    sc.unread = 0;
    sc.count = 0;
    let mut tmp = [V::Null; MAX_ARITY];
    for f in facts {
        if f.parameters.as_ref().is_some_and(|p| !p.is_empty()) {
            f.validate()?;
            return Ok(false);
        }
        let terms = &f.predicate.terms;
        if terms.len() >= MAX_ARITY {
            return Ok(false);
        }
        for (k, t) in terms.iter().enumerate() {
            tmp[k] = match t {
                builder::Term::Integer(i) => V::Int(*i),
                builder::Term::Date(d) => V::Date(*d),
                builder::Term::Bool(b) => V::Bool(*b),
                builder::Term::Null => V::Null,
                builder::Term::Str(s) => V::Str(intern_str(p, sc, s)),
                builder::Term::Bytes(b) => V::Bytes(match p.bytes_idx.get(b.as_slice()) {
                    Some(i) => *i,
                    None => match sc.bytes.iter().position(|x| **x == **b) {
                        Some(i) => (p.bytes.len() + i) as u32,
                        None => {
                            sc.bytes.push(b.as_slice().into());
                            (p.bytes.len() + sc.bytes.len() - 1) as u32
                        }
                    },
                }),
                _ => return Ok(false),
            };
        }
        let vals = &tmp[..terms.len()];
        let slot = p.names.get(f.predicate.name.as_str()).map(|a| a[terms.len()]).unwrap_or(NO_SLOT);
        if slot == NO_SLOT {
            // nothing reads it; it only counts towards max_facts
            sc.unread += 1;
            continue;
        }
        if exists(p, sc, slot, AUTHORIZER, vals) {
            continue;
        }
        push_fact(sc, slot, AUTHORIZER, vals);
    }
    Ok(true)
}

#[inline]
fn intern_str(p: &Program, sc: &mut Scratch, s: &str) -> u64 {
    if let Some(i) = p.symbols.get(s) {
        return *i;
    }
    for (k, &(st, l)) in sc.strs.iter().enumerate() {
        if &sc.strbuf[st as usize..(st + l) as usize] == s {
            return OVERLAY_STR + k as u64;
        }
    }
    let st = sc.strbuf.len() as u32;
    sc.strbuf.push_str(s);
    sc.strs.push((st, s.len() as u32));
    OVERLAY_STR + (sc.strs.len() - 1) as u64
}

fn exists(p: &Program, sc: &Scratch, slot: u32, mask: Mask, vals: &[V]) -> bool {
    let n = vals.len();
    p.base_by_slot[slot as usize].iter().any(|&(m, off)| m == mask && &p.base_vals[off as usize..off as usize + n] == vals)
        || sc.facts[slot as usize].iter().any(|&(m, off)| m == mask && &sc.vals[off as usize..off as usize + n] == vals)
}

fn push_fact(sc: &mut Scratch, slot: u32, mask: Mask, vals: &[V]) {
    let off = sc.vals.len() as u32;
    sc.vals.extend_from_slice(vals);
    let list = &mut sc.facts[slot as usize];
    if list.is_empty() {
        sc.used.push(slot);
    }
    list.push((mask, off));
    sc.count += 1;
}

type Decided = (Result<usize, error::Token>, RunStats);

fn decide(p: &Program, inner: &Inner, sc: &mut Scratch, limits: &PreparedLimits, mode: Mode) -> Result<Decided, error::Token> {
    let mut steps = 0u64;
    let mut iterations = 0u64;
    // ---- rules: semi-naive over the overlay; the token's own facts are already saturated
    if !p.rules.is_empty() {
        let mut delta = 0u32;
        loop {
            sc.pending.clear();
            sc.pending_vals.clear();
            let mut pending = std::mem::take(&mut sc.pending);
            let mut pending_vals = std::mem::take(&mut sc.pending_vals);
            let r = {
                let mut cx = Ctx { p, sc: &*sc, steps, max_steps: limits.max_steps, delta };
                let mut r = Ok(());
                for rule in &p.rules {
                    // a rule can only derive something new from a fact that is new
                    let touches_delta =
                        rule.q.body.iter().any(|b| cx.sc.facts[b.slot as usize].last().is_some_and(|&(_, off)| off >= delta));
                    if !touches_delta {
                        continue;
                    }
                    let mut env = Env { vals: [V::Null; MAX_VARS], bound: 0 };
                    let res = cx.join(&rule.q, 0, &mut env, 0, false, &mut |cx: &mut Ctx, env: &Env, mask: Mask, new: bool| {
                        if !new {
                            return Ok(false);
                        }
                        for e in rule.q.exprs.iter() {
                            if !cx.eval(e, env)? {
                                return Ok(false);
                            }
                        }
                        let mask = mask | rule.origin;
                        let start = pending_vals.len() as u32;
                        for a in rule.head.iter() {
                            pending_vals.push(match a {
                                Arg::Const(c) => *c,
                                Arg::Var(x) => env.vals[*x as usize],
                            });
                        }
                        let vals = &pending_vals[start as usize..];
                        let dup = exists(cx.p, cx.sc, rule.head_slot, mask, vals)
                            || pending.iter().any(|&(s, m, o)| {
                                s == rule.head_slot && m == mask && &pending_vals[o as usize..o as usize + vals.len()] == vals
                            });
                        if dup {
                            pending_vals.truncate(start as usize);
                        } else {
                            pending.push((rule.head_slot, mask, start));
                        }
                        Ok(false)
                    });
                    if let Err(e) = res {
                        r = Err(e);
                        break;
                    }
                }
                steps = cx.steps;
                r
            };
            match r {
                Ok(()) => {}
                Err(Stop::Fallback) => return Ok(fallback_marker()),
                Err(Stop::Limit(l)) => return Ok((Err(rl(l)), stats(steps, iterations, p, sc))),
            }
            if pending.is_empty() {
                sc.pending = pending;
                sc.pending_vals = pending_vals;
                break;
            }
            delta = sc.vals.len() as u32;
            for &(slot, mask, o) in &pending {
                let n = p.arity[slot as usize] as usize;
                let vals: [V; MAX_ARITY] = {
                    let mut t = [V::Null; MAX_ARITY];
                    t[..n].copy_from_slice(&pending_vals[o as usize..o as usize + n]);
                    t
                };
                push_fact(sc, slot, mask, &vals[..n]);
            }
            sc.pending = pending;
            sc.pending_vals = pending_vals;
            iterations += 1;
            if iterations >= limits.max_iterations {
                return Ok((Err(rl(error::RunLimit::TooManyIterations)), stats(steps, iterations, p, sc)));
            }
            if p.base_count + sc.count + sc.unread >= limits.max_facts as usize {
                return Ok((Err(rl(error::RunLimit::TooManyFacts)), stats(steps, iterations, p, sc)));
            }
        }
    }

    // ---- checks and policies, in upstream order
    let mut cx = Ctx { p, sc: &*sc, steps, max_steps: limits.max_steps, delta: u32::MAX };
    let mut errors = Vec::new();
    let run_check = |cx: &mut Ctx, c: &CCheck| -> Result<bool, Stop> {
        for q in c.queries.iter() {
            let res = match c.kind {
                CheckKind::One => exists_match(cx, q)?,
                CheckKind::Reject => !exists_match(cx, q)?,
                CheckKind::All => all_match(cx, q)?,
            };
            if res {
                return Ok(true);
            }
        }
        Ok(false)
    };
    let early = matches!(mode, Mode::Decide);
    let outcome: Result<Result<usize, error::Token>, Stop> = (|| {
        for (c, pc) in p.pre.iter().zip(&inner.pre_checks) {
            if !run_check(&mut cx, c)? {
                if early {
                    return Ok(Err(early_deny()));
                }
                errors.push(pc.failed());
            }
        }
        let mut policy: Option<Result<usize, usize>> = None;
        'policies: for (i, pol) in p.policies.iter().enumerate() {
            for q in pol.queries.iter() {
                if exists_match(&mut cx, q)? {
                    policy = Some(match pol.kind {
                        PolicyKind::Allow => Ok(i),
                        PolicyKind::Deny => Err(i),
                    });
                    break 'policies;
                }
            }
        }
        if early && !matches!(policy, Some(Ok(_))) {
            return Ok(Err(early_deny()));
        }
        for (c, pc) in p.post.iter().zip(&inner.post_checks) {
            if !run_check(&mut cx, c)? {
                if early {
                    return Ok(Err(early_deny()));
                }
                errors.push(pc.failed());
            }
        }
        Ok(finish(policy, std::mem::take(&mut errors)))
    })();
    let steps = cx.steps;
    match outcome {
        Ok(r) => Ok((r, stats(steps, iterations, p, sc))),
        Err(Stop::Fallback) => Ok(fallback_marker()),
        Err(Stop::Limit(l)) => Ok((Err(rl(l)), stats(steps, iterations, p, sc))),
    }
}

fn early_deny() -> error::Token {
    error::Token::FailedLogic(error::Logic::NoMatchingPolicy { checks: Vec::new() })
}

fn fallback_marker() -> Decided {
    (Err(error::Token::InternalError), RunStats { fallback: true, ..RunStats::default() })
}

fn stats(steps: u64, iterations: u64, p: &Program, sc: &Scratch) -> RunStats {
    RunStats { steps, iterations, facts: p.base_count + sc.count + sc.unread, fallback: false }
}

fn exists_match(cx: &mut Ctx, q: &CQuery) -> Result<bool, Stop> {
    let mut env = Env { vals: [V::Null; MAX_VARS], bound: 0 };
    cx.join(q, 0, &mut env, 0, false, &mut |cx: &mut Ctx, env: &Env, _, _| {
        for e in q.exprs.iter() {
            if !cx.eval(e, env)? {
                return Ok(false);
            }
        }
        Ok(true)
    })
}

/// `check all`: every binding satisfies the expressions, and there is at least one
fn all_match(cx: &mut Ctx, q: &CQuery) -> Result<bool, Stop> {
    let mut env = Env { vals: [V::Null; MAX_VARS], bound: 0 };
    let mut found = false;
    let failed = cx.join(q, 0, &mut env, 0, false, &mut |cx: &mut Ctx, env: &Env, _, _| {
        found = true;
        for e in q.exprs.iter() {
            if !cx.eval(e, env)? {
                return Ok(true);
            }
        }
        Ok(false)
    })?;
    Ok(found && !failed)
}
