//! The structural check: run on every token before anything evaluates it.
//!
//! Biscuit lets whoever holds a token append blocks of arbitrary Datalog. Narrowing is guaranteed by
//! Biscuit's semantics whatever a block says, but cost is not: a hostile block could burn the step
//! budget on every request, or (with a regex Biscuit can't compile) make a `reject if` silently
//! never match. So a node refuses, before loading, any token that isn't shaped like what wicket
//! generates (`generator`):
//!
//! **First-party blocks** (block 0, root-signed, and spawn blocks appended by nodes):
//! - facts: only `zone(<string>)`; block 0 also `tenant(<string>)` and `principal(<string>)`;
//! - no rules, no block-level scopes, no `check all`;
//! - checks read only the fixed request vocabulary ([`AMBIENT`]), plus `approved/4` in a grant escape;
//! - a grant escape (`approved($g, $h, $m, $p)`) must bind `$h`, `$m` and `$p` to the request's
//!   `host`, `method` and `path` in the same query (a ceiling binds what it approves), and carries
//!   only `trusting <public key>` scopes; no other query has scopes;
//! - expressions are one of a few shapes ([`expression`]): a variable compared with a literal,
//!   `$v.starts_with/ends_with(<literal>)`, `<set literal>.contains($v)` (optionally negated) and
//!   `$p.matches(<string literal>)` on a variable bound by `path`. The pattern is at most
//!   [`Policy::max_regex_len`] bytes, must compile with Biscuit's regex engine under a small size
//!   limit, and a block has at most [`Policy::max_regexes_per_block`] of them.
//!
//! **Third-party blocks** (grants):
//! - signed by a key some first-party grant escape trusts (a key no block trusts is refused, so a
//!   leaf can't approve itself);
//! - only `approved(<literals>) <- time($t), box(<literal>), epoch(<literal>), uses_left(<gid>, $n)`
//!   rules (head and gid literal, the same gid in both), with `$t <= <date>` and `$n > <int>`, and
//!   `approval/3` facts; no checks, no scopes.
//!
//! **Caps** ([`Policy`]): token bytes, blocks, checks per block, alternatives per check, predicates
//! per query, set sizes, string lengths and regexes. The block cap (16) is the deepest chain wicket
//! plans for, with room to spare: the design target and the experiments use spawn depth 5 (block 0
//! plus five spawn blocks) plus a grant block; 16 allows ten more links or grants. The compiled
//! evaluator supports up to 62 blocks.
//!
//! The check also classifies every check, which `decide` uses to tell "forbidden" from "needs a
//! grant" ([`CheckClass`]).

use biscuit_auth::builder::{Binary, CheckKind, Expression, Op, Predicate, Rule, Scope, Term, Unary};
use biscuit_auth::public_keys::PublicKeyData;
use biscuit_auth::Biscuit;
use std::collections::HashSet;

/// Structural caps.
#[derive(Clone, Debug)]
pub struct Policy {
    pub max_token_bytes: usize,
    pub max_blocks: usize,
    pub max_checks_per_block: usize,
    pub max_queries_per_check: usize,
    pub max_preds_per_query: usize,
    pub max_exprs_per_query: usize,
    pub max_set_len: usize,
    pub max_str_len: usize,
    pub max_regex_len: usize,
    pub max_regexes_per_block: usize,
    pub max_grant_rules: usize,
    pub max_grant_facts: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_token_bytes: 64 * 1024,
            max_blocks: 16,
            max_checks_per_block: 64,
            max_queries_per_check: 64,
            max_preds_per_query: 8,
            max_exprs_per_query: 8,
            max_set_len: 64,
            max_str_len: 1024,
            max_regex_len: 256,
            max_regexes_per_block: 128,
            max_grant_rules: 4,
            max_grant_facts: 4,
        }
    }
}

/// Request facts a first-party check may read (name, arity).
pub const AMBIENT: &[(&str, usize)] = &[
    ("time", 1),
    ("request_tenant", 1),
    ("box", 1),
    ("op", 1),
    ("host", 1),
    ("method", 1),
    ("path", 1),
    ("risk", 1),
    ("inject", 1),
    ("spawn", 6),
    ("llm_used", 2),
    ("msg_from", 1),
];

/// How a failed check is reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckClass {
    /// A bound no grant can lift: time, box, op kinds, tenant, forbid rules, limits, injections.
    Hard,
    /// Reach or risk: a check one of whose alternatives reads `host`, `risk` or `approved`. Failing
    /// only these means a grant could allow the request.
    Escalatable,
}

/// What the structural check learned about a token it accepted.
#[derive(Clone, Debug)]
pub struct Vetted {
    /// Per block, per check.
    pub classes: Vec<Vec<CheckClass>>,
    /// Block 0 carries an org layer (its `policy` fact, #51).
    pub org: bool,
    /// The earliest hard expiry any first-party block sets (`check if time($t), $t <= <date>`, Unix
    /// seconds): the token allows nothing after it (#153). None if no block bounds time that way.
    pub not_after: Option<u64>,
}

/// The date a check bounds time by, if it is exactly `check if time($t), $t <= <date>`.
fn expiry(c: &biscuit_auth::builder::Check) -> Option<u64> {
    let [q] = c.queries.as_slice() else { return None };
    let ([pred], [e]) = (q.body.as_slice(), q.expressions.as_slice()) else { return None };
    let [Term::Variable(v)] = pred.terms.as_slice() else { return None };
    if pred.name != "time" || c.kind != CheckKind::One {
        return None;
    }
    match e.ops.as_slice() {
        [Op::Value(Term::Variable(a)), Op::Value(Term::Date(d)), Op::Binary(Binary::LessOrEqual)] if a == v => Some(*d),
        _ => None,
    }
}

fn has(list: &[(&str, usize)], p: &Predicate) -> bool {
    list.iter().any(|(n, a)| *n == p.name && *a == p.terms.len())
}

fn literal(t: &Term, p: &Policy) -> Result<(), String> {
    match t {
        Term::Integer(_) | Term::Date(_) | Term::Bool(_) => Ok(()),
        Term::Str(s) if s.len() <= p.max_str_len => Ok(()),
        Term::Bytes(b) if b.len() <= p.max_str_len => Ok(()),
        _ => Err(format!("term not allowed: {t:?}")),
    }
}

fn scalar(t: &Term, p: &Policy) -> Result<(), String> {
    match t {
        Term::Variable(_) => Ok(()),
        t => literal(t, p),
    }
}

fn var(op: &Op) -> Option<&str> {
    match op {
        Op::Value(Term::Variable(v)) => Some(v),
        _ => None,
    }
}

/// A comparison's literal must have the type of what it's compared with: a date for a variable
/// bound by `time`, never a date otherwise (comparing a date with an integer is an evaluation error,
/// not a narrowing anyone meant).
fn typed(v: &str, lit: &Term, time_vars: &HashSet<&str>) -> Result<(), String> {
    match (time_vars.contains(v), lit) {
        (true, Term::Date(_)) | (false, Term::Integer(_) | Term::Str(_) | Term::Bool(_) | Term::Bytes(_)) => Ok(()),
        _ => Err(format!("${v} compared with {lit:?}: wrong type")),
    }
}

/// Variables bound by `time` and `path`.
struct Vars<'a> {
    time: HashSet<&'a str>,
    path: HashSet<&'a str>,
}

/// The expression shapes wicket generates.
fn expression(e: &Expression, p: &Policy, vars: &Vars<'_>, regexes: &mut usize) -> Result<(), String> {
    use Binary::*;
    let bad = || Err(format!("expression not allowed: {:?}", e.ops));
    match e.ops.as_slice() {
        [a, Op::Value(lit), Op::Binary(
            LessThan | GreaterThan | LessOrEqual | GreaterOrEqual | Equal | NotEqual | HeterogeneousEqual | HeterogeneousNotEqual,
        )] if var(a).is_some() => {
            literal(lit, p)?;
            typed(var(a).unwrap_or_default(), lit, &vars.time)
        }
        [a, Op::Value(Term::Str(s)), Op::Binary(Prefix | Suffix)] if var(a).is_some() => literal(&Term::Str(s.clone()), p),
        [Op::Value(Term::Set(set)), b, Op::Binary(Contains)]
        | [Op::Value(Term::Set(set)), b, Op::Binary(Contains), Op::Unary(Unary::Negate)]
            if var(b).is_some() =>
        {
            if set.len() > p.max_set_len {
                return Err("set too large".into());
            }
            set.iter().try_for_each(|t| literal(t, p))
        }
        [a, Op::Value(Term::Str(pat)), Op::Binary(Regex)] if var(a).is_some_and(|v| vars.path.contains(v)) => {
            *regexes += 1;
            if pat.len() > p.max_regex_len {
                return Err(format!("regex longer than {} bytes", p.max_regex_len));
            }
            // A pattern Biscuit can't compile never matches: in a `reject if` that would silently
            // drop a forbid rule. Refuse it, and anything that compiles to a large program.
            regex::RegexBuilder::new(pat).size_limit(1 << 16).build().map_err(|e| format!("regex refused: {e}"))?;
            Ok(())
        }
        _ => bad(),
    }
}

/// One query of a first-party check. Adds the keys a grant escape trusts to `trusted`.
fn query(q: &Rule, p: &Policy, trusted: &mut Vec<PublicKeyData>, regexes: &mut usize) -> Result<(), String> {
    if q.body.len() > p.max_preds_per_query || q.expressions.len() > p.max_exprs_per_query {
        return Err("query too long".into());
    }
    let mut approved = None;
    let mut bound: Vec<(&str, &str)> = Vec::new();
    for pred in &q.body {
        if pred.name == "approved" && pred.terms.len() == 4 {
            if approved.is_some() {
                return Err("more than one approved(...) in a query".into());
            }
            approved = Some(pred);
        } else if !has(AMBIENT, pred) && !(pred.name == "policy" && pred.terms.len() == 1) {
            return Err(format!("predicate outside the fixed vocabulary: {}/{}", pred.name, pred.terms.len()));
        }
        for t in &pred.terms {
            scalar(t, p)?;
        }
        if let [Term::Variable(v)] = pred.terms.as_slice() {
            bound.push((pred.name.as_str(), v.as_str()));
        }
    }
    let of = |name: &str| bound.iter().filter(|(n, _)| *n == name).map(|(_, v)| *v).collect::<HashSet<&str>>();
    let vars = Vars { time: of("time"), path: of("path") };
    match approved {
        Some(a) => {
            // approved($g, $h, $m, $p) with host($h), method($m), path($p) in the same query.
            let ok = match a.terms.as_slice() {
                [Term::Variable(_), Term::Variable(h), Term::Variable(m), Term::Variable(pa)] => {
                    bound.contains(&("host", h)) && bound.contains(&("method", m)) && bound.contains(&("path", pa))
                }
                _ => false,
            };
            if !ok {
                return Err("approved(...) must bind the request's host, method and path".into());
            }
            if q.scopes.is_empty() {
                return Err("approved(...) without a trusting clause".into());
            }
            for s in &q.scopes {
                match s {
                    Scope::PublicKey(k) => trusted.push(k.clone()),
                    _ => return Err("only `trusting <key>` scopes are allowed".into()),
                }
            }
        }
        None if !q.scopes.is_empty() => return Err("scopes are only allowed on grant escapes".into()),
        None => {}
    }
    for e in &q.expressions {
        expression(e, p, &vars, regexes)?;
    }
    Ok(())
}

/// A check's class follows from its shape. A hostile block can shape a hard bound to read `host` and
/// so turn a `Forbidden` into a `NeedsGrant`; that only changes whether the proxy offers to escalate,
/// never what is allowed (a grant must still pass every block).
///
/// A check that reads `policy` is the org layer's (#51): hard, whatever else it reads.
fn classify(queries: &[Rule], kind: &CheckKind) -> CheckClass {
    let reads = |n: &str| queries.iter().any(|q| q.body.iter().any(|pr| pr.name == n));
    if *kind == CheckKind::One && !reads("policy") && (reads("host") || reads("risk") || reads("approved")) {
        CheckClass::Escalatable
    } else {
        CheckClass::Hard
    }
}

/// A grant rule: `approved(<lit>, <lit>, <lit>, <lit>) <- time($t), box(<lit>), epoch(<lit>), uses_left(<gid>, $n)`.
fn grant_rule(r: &Rule, p: &Policy) -> Result<(), String> {
    if r.head.name != "approved" || r.head.terms.len() != 4 || !r.scopes.is_empty() {
        return Err("only approved/4 rules without scopes".into());
    }
    for t in &r.head.terms {
        if !matches!(t, Term::Str(_)) {
            return Err("a grant must name a literal grant id, host, method and path".into());
        }
        literal(t, p)?;
    }
    let mut names: Vec<&str> = r.body.iter().map(|b| b.name.as_str()).collect();
    names.sort_unstable();
    if names != ["box", "epoch", "time", "uses_left"] {
        return Err(format!("a grant rule reads exactly time, box, epoch and uses_left, not {names:?}"));
    }
    let (mut time, mut uses) = (None, None);
    for b in &r.body {
        match (b.name.as_str(), b.terms.as_slice()) {
            ("time", [Term::Variable(v)]) => time = Some(v.as_str()),
            ("box", [Term::Str(s)]) => literal(&Term::Str(s.clone()), p)?,
            ("epoch", [Term::Integer(_)]) => {}
            ("uses_left", [gid @ Term::Str(_), Term::Variable(v)]) if *gid == r.head.terms[0] => uses = Some(v.as_str()),
            _ => return Err(format!("grant rule predicate not allowed: {}/{}", b.name, b.terms.len())),
        }
    }
    // Exactly `$t <= <date>` and `$n > <int>`: the lease's expiry and its uses.
    let mut shapes: Vec<&str> = Vec::new();
    for e in &r.expressions {
        let shape = match e.ops.as_slice() {
            [Op::Value(Term::Variable(v)), Op::Value(Term::Date(_)), Op::Binary(Binary::LessOrEqual)] if Some(v.as_str()) == time => {
                "expiry"
            }
            [Op::Value(Term::Variable(v)), Op::Value(Term::Integer(_)), Op::Binary(Binary::GreaterThan)] if Some(v.as_str()) == uses => {
                "uses"
            }
            _ => return Err(format!("grant rule expression not allowed: {:?}", e.ops)),
        };
        shapes.push(shape);
    }
    shapes.sort_unstable();
    if shapes != ["expiry", "uses"] {
        return Err("a grant rule bounds exactly its expiry and its uses".into());
    }
    Ok(())
}

/// Checks `tok` (whose serialized form is `token_bytes` long) against `p`.
pub fn check(tok: &Biscuit, token_bytes: usize, p: &Policy) -> Result<Vetted, String> {
    if token_bytes > p.max_token_bytes {
        return Err(format!("token is {token_bytes} bytes (cap {})", p.max_token_bytes));
    }
    let n = tok.block_count();
    if n > p.max_blocks {
        return Err(format!("{n} blocks (cap {})", p.max_blocks));
    }
    let mut org = false;
    let mut trusted: Vec<PublicKeyData> = Vec::new();
    let mut third_party = Vec::new();
    let mut classes = Vec::with_capacity(n);
    let mut not_after: Option<u64> = None;
    for i in 0..n {
        let b = tok.block_datalog(i).map_err(|e| e.to_string())?;
        if b.external_key.is_some() {
            if i == 0 {
                return Err("block 0 is third-party".into());
            }
            classes.push(Vec::new());
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
        let mut zones = 0;
        for f in &b.facts {
            let name = f.predicate.name.as_str();
            zones += usize::from(name == "zone");
            org |= i == 0 && name == "policy";
            // `policy`: the org policy's version, block 0 only (#51).
            let ok_name = name == "zone" || (i == 0 && (name == "tenant" || name == "principal" || name == "policy"));
            let ok_terms = matches!(f.predicate.terms.as_slice(), [Term::Str(s)] if s.len() <= p.max_str_len);
            if !ok_name || !ok_terms {
                return Err(at(format!("fact not allowed: {name}/{}", f.predicate.terms.len())));
            }
        }
        if zones > 1 || b.facts.len() > 4 {
            return Err(at("too many facts".into()));
        }
        if b.checks.len() > p.max_checks_per_block {
            return Err(at(format!("{} checks (cap {})", b.checks.len(), p.max_checks_per_block)));
        }
        let mut regexes = 0;
        let mut cls = Vec::with_capacity(b.checks.len());
        for c in &b.checks {
            if c.kind == CheckKind::All {
                return Err(at("`check all` not allowed".into()));
            }
            if c.queries.len() > p.max_queries_per_check {
                return Err(at(format!("check has {} alternatives (cap {})", c.queries.len(), p.max_queries_per_check)));
            }
            for q in &c.queries {
                query(q, p, &mut trusted, &mut regexes).map_err(at)?;
            }
            cls.push(classify(&c.queries, &c.kind));
            if let Some(d) = expiry(c) {
                not_after = Some(not_after.map_or(d, |n| n.min(d)));
            }
        }
        if regexes > p.max_regexes_per_block {
            return Err(at(format!("{regexes} regexes (cap {})", p.max_regexes_per_block)));
        }
        classes.push(cls);
    }
    for (i, b) in third_party {
        let at = |m: String| format!("block {i} (third-party): {m}");
        let key = b.external_key.as_ref().expect("third-party");
        if !trusted.contains(key) {
            return Err(at("signed by a key no first-party block trusts".into()));
        }
        if !b.scopes.is_empty() || !b.checks.is_empty() {
            return Err(at("only grant rules and approval facts allowed".into()));
        }
        if b.facts.len() > p.max_grant_facts || b.rules.len() > p.max_grant_rules {
            return Err(at("too many facts or rules".into()));
        }
        for f in &b.facts {
            if f.predicate.name != "approval" || f.predicate.terms.len() != 3 {
                return Err(at(format!("fact not allowed: {}/{}", f.predicate.name, f.predicate.terms.len())));
            }
            for t in &f.predicate.terms {
                literal(t, p).map_err(at)?;
            }
        }
        for r in &b.rules {
            grant_rule(r, p).map_err(at)?;
        }
    }
    Ok(Vetted { classes, org, not_after })
}
