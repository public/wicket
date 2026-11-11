//! The structural lint wicket would run once per token, before loading it (biscuit-depth §4):
//! - first-party blocks: facts `tenant`/`principal`/`zone` only, no rules, checks over the fixed
//!   ambient vocabulary only, no `.matches()` and no other operator outside a small list;
//! - third-party blocks: only `approved(...) <- …` rules over `time`, `box`, `epoch`, `uses_left`,
//!   plus `approval(...)` facts, and only from keys some first-party block trusts;
//! - size caps on the token, blocks, checks, queries, expressions and constants.
//!
//! It uses the fork's `Biscuit::block_datalog`, which returns each block in builder types.

use fork::builder::{Binary, CheckKind, Expression, Op, Predicate, Rule, Scope, Term, Unary};
use fork::public_keys::PublicKeyData;
use fork::Biscuit;

#[derive(Clone, Debug)]
pub struct Policy {
    pub max_token_bytes: usize,
    pub max_blocks: usize,
    pub max_checks_per_block: usize,
    pub max_queries_per_check: usize,
    pub max_preds_per_query: usize,
    pub max_ops_per_expr: usize,
    pub max_set_len: usize,
    pub max_str_len: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_token_bytes: 32 * 1024,
            max_blocks: 16,
            max_checks_per_block: 32,
            max_queries_per_check: 32,
            max_preds_per_query: 8,
            max_ops_per_expr: 64,
            max_set_len: 64,
            max_str_len: 1024,
        }
    }
}

/// Ambient facts a first-party check may read (name, arity).
const AMBIENT: &[(&str, usize)] = &[
    ("time", 1),
    ("box", 1),
    ("op", 1),
    ("host", 1),
    ("method", 1),
    ("path", 1),
    ("path_depth", 1),
    ("risk", 1),
    ("inject", 1),
    ("spawn", 6),
    ("llm_used", 2),
    ("msg_from", 1),
];
/// What a grant rule's body may read.
const GRANT_BODY: &[(&str, usize)] = &[("time", 1), ("box", 1), ("epoch", 1), ("uses_left", 2)];

fn has(list: &[(&str, usize)], p: &Predicate) -> bool {
    list.iter().any(|(n, a)| *n == p.name && *a == p.terms.len())
}

fn scalar(t: &Term, p: &Policy) -> Result<(), String> {
    match t {
        Term::Variable(_) | Term::Integer(_) | Term::Date(_) | Term::Bool(_) => Ok(()),
        Term::Str(s) if s.len() <= p.max_str_len => Ok(()),
        Term::Bytes(b) if b.len() <= p.max_str_len => Ok(()),
        _ => Err(format!("term not allowed: {t:?}")),
    }
}

fn expr_ops(ops: &[Op], p: &Policy, count: &mut usize) -> Result<(), String> {
    for op in ops {
        *count += 1;
        if *count > p.max_ops_per_expr {
            return Err("expression too long".into());
        }
        match op {
            Op::Value(Term::Set(s)) => {
                if s.len() > p.max_set_len {
                    return Err("set too large".into());
                }
                for t in s {
                    scalar(t, p)?;
                }
            }
            Op::Value(t) => scalar(t, p)?,
            Op::Unary(Unary::Negate | Unary::Parens) => {}
            Op::Unary(u) => return Err(format!("operator not allowed: {u:?}")),
            Op::Binary(
                Binary::LessThan
                | Binary::GreaterThan
                | Binary::LessOrEqual
                | Binary::GreaterOrEqual
                | Binary::Equal
                | Binary::NotEqual
                | Binary::HeterogeneousEqual
                | Binary::HeterogeneousNotEqual
                | Binary::Contains
                | Binary::Prefix
                | Binary::Suffix
                | Binary::And
                | Binary::Or
                | Binary::LazyAnd
                | Binary::LazyOr,
            ) => {}
            Op::Binary(b) => return Err(format!("operator not allowed: {b:?}")),
            Op::Closure(params, body) if params.is_empty() => expr_ops(body, p, count)?,
            Op::Closure(..) => return Err("closures with parameters not allowed".into()),
        }
    }
    Ok(())
}

fn exprs(es: &[Expression], p: &Policy) -> Result<(), String> {
    for e in es {
        expr_ops(&e.ops, p, &mut 0)?;
    }
    Ok(())
}

fn query(q: &Rule, p: &Policy, trusted: &mut Vec<PublicKeyData>) -> Result<(), String> {
    if q.body.len() > p.max_preds_per_query {
        return Err("query has too many predicates".into());
    }
    let mut approved = false;
    for pred in &q.body {
        if pred.name == "approved" && pred.terms.len() == 4 {
            approved = true;
        } else if !has(AMBIENT, pred) {
            return Err(format!("predicate outside the fixed vocabulary: {}/{}", pred.name, pred.terms.len()));
        }
        for t in &pred.terms {
            scalar(t, p)?;
        }
    }
    // Only a grant escape may widen what the query trusts, and only to named keys.
    if approved {
        if q.scopes.is_empty() {
            return Err("approved(...) without a trusting clause".into());
        }
        for s in &q.scopes {
            match s {
                Scope::PublicKey(k) => trusted.push(k.clone()),
                _ => return Err("only `trusting <key>` scopes are allowed".into()),
            }
        }
    } else if !q.scopes.is_empty() {
        return Err("scopes are only allowed on grant escapes".into());
    }
    exprs(&q.expressions, p)
}

pub fn lint(tok: &Biscuit, token_bytes: usize, p: &Policy) -> Result<(), String> {
    if token_bytes > p.max_token_bytes {
        return Err(format!("token is {token_bytes} bytes"));
    }
    let n = tok.block_count();
    if n > p.max_blocks {
        return Err(format!("{n} blocks"));
    }
    let mut trusted: Vec<PublicKeyData> = Vec::new();
    let mut third_party = Vec::new();
    for i in 0..n {
        let b = tok.block_datalog(i).map_err(|e| e.to_string())?;
        if b.external_key.is_some() {
            third_party.push((i, b));
            continue;
        }
        let at = |m: String| format!("block {i}: {m}");
        if !b.scopes.is_empty() {
            return Err(at("block-level scopes not allowed".into()));
        }
        if !b.rules.is_empty() {
            return Err(at("first-party blocks may not carry rules".into()));
        }
        for f in &b.facts {
            let ok_name = f.predicate.name == "zone" || (i == 0 && (f.predicate.name == "tenant" || f.predicate.name == "principal"));
            if !ok_name || f.predicate.terms.len() != 1 || !matches!(f.predicate.terms[0], Term::Str(_)) {
                return Err(at(format!("fact not allowed: {}", f.predicate.name)));
            }
        }
        if b.checks.len() > p.max_checks_per_block {
            return Err(at(format!("{} checks", b.checks.len())));
        }
        for c in &b.checks {
            if c.kind == CheckKind::All {
                return Err(at("`check all` not allowed".into()));
            }
            if c.queries.len() > p.max_queries_per_check {
                return Err(at("check has too many alternatives".into()));
            }
            for q in &c.queries {
                query(q, p, &mut trusted).map_err(at)?;
            }
        }
    }
    for (i, b) in third_party {
        let at = |m: String| format!("block {i} (third-party): {m}");
        let key = b.external_key.as_ref().unwrap();
        if !trusted.contains(key) {
            return Err(at("signed by a key no first-party block trusts".into()));
        }
        if !b.scopes.is_empty() || !b.checks.is_empty() {
            return Err(at("only rules and approval facts allowed".into()));
        }
        for f in &b.facts {
            if f.predicate.name != "approval" || f.predicate.terms.len() != 3 {
                return Err(at(format!("fact not allowed: {}", f.predicate.name)));
            }
            for t in &f.predicate.terms {
                scalar(t, p).map_err(at)?;
            }
        }
        if b.rules.len() > p.max_checks_per_block {
            return Err(at("too many rules".into()));
        }
        for r in &b.rules {
            if r.head.name != "approved" || r.head.terms.len() != 4 || !r.scopes.is_empty() {
                return Err(at("only approved/4 rules without scopes".into()));
            }
            if r.body.len() > p.max_preds_per_query {
                return Err(at("rule body too long".into()));
            }
            for pred in &r.body {
                if !has(GRANT_BODY, pred) {
                    return Err(at(format!("grant rule reads {}/{}", pred.name, pred.terms.len())));
                }
                for t in &pred.terms {
                    scalar(t, p).map_err(at)?;
                }
            }
            for t in &r.head.terms {
                scalar(t, p).map_err(at)?;
            }
            exprs(&r.expressions, p).map_err(at)?;
        }
    }
    Ok(())
}
