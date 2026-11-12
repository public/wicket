//! Ceilings and grants as Biscuit blocks, and requests as facts.
//!
//! **No value is ever written into Datalog text.** Each block's source is assembled from fixed
//! fragments and placeholder names (`{p0}`, `{p1}`, …); every value (strings, sets, dates, integers,
//! regexes, keys) is passed as a parameter to `code_with_params`, so a zone name or path can't inject
//! clauses. Lists are `Term::Set`s, so an empty list is an empty set, never the `{}` literal (which
//! Biscuit parses as an empty map).
//!
//! ## Block layout
//!
//! Every ceiling block, root-signed (block 0) or appended by a node (spawn blocks), holds a `zone`
//! fact and these checks, in this order:
//!
//! | check | passes when | class |
//! |---|---|---|
//! | `check if time($t), $t <= not_after` | the link hasn't expired | hard |
//! | `check if box(prefix) or box($b), $b.starts_with(prefix/)` | the box is this link's box or a descendant | hard |
//! | `check if op($o), ops.contains($o)` | the op kind is allowed | hard |
//! | reach: `check if op($o), $o != "http" or <host, method, path> … or <approved>` | some reach rule matches, or a trusted grant | escalatable |
//! | risk: `check if op($o), $o != "http" or risk($r), $r <= 2 or <dangerous rule> … or <approved>` | low risk, or an `allow_dangerous` rule matches, or a trusted grant | escalatable |
//! | per forbid path: `reject if host…, path($p), $p.matches(re)` | not forbidden | hard |
//! | spawn, llm, msg limits (`check if op($o), $o != "spawn" or spawn(…), …`) | within limits | hard |
//! | `reject if inject($k), !inject.contains($k)` | only this link's injections | hard |
//!
//! Block 0 also holds `tenant` and `principal` facts and `check if request_tenant(tenant)`.
//!
//! Reach and risk together allow an HTTP request iff some reach rule matches it and (its risk is at
//! most R2, or some matching rule has `allow_dangerous`): wicket-core's order-independent reach
//! semantics (`CompiledZone::evaluate`).
//!
//! Paths are matched with `$p.matches(re)` where `re` is globset's own regex for the glob, built with
//! wicket's options (`literal_separator(true)`), so a token matches exactly what wicket-core matches.
//! globset's regexes run on bytes (`(?-u)`), Biscuit's on strings; [`path_regex`] drops the `(?-u)`
//! flag and [`path_term`] passes the path's bytes as Latin-1 characters (identical for ASCII), so a
//! `\xHH` byte escape or a one-byte `?` means the same on both sides.
//!
//! A grant is a third-party block signed by the approver:
//! `approved(gid, host, method, path) <- time($t), $t <= exp, box(b), epoch(e), uses_left(gid, $n), $n > 0;`
//! and `approval(gid, approver, digest)`. A ceiling's reach and risk checks accept `approved` only
//! `trusting` the keys that ceiling lists, so a grant never reaches past any link that doesn't trust
//! its signer, and never past a forbid rule (those are `reject if` checks, which no grant satisfies).

use crate::payload::*;
use crate::AuthzError;
use biscuit_auth::builder::{fact, Fact, Term};
use biscuit_auth::public_keys::PublicKeyData;
use biscuit_auth::{Algorithm, BiscuitBuilder, BlockBuilder};
use std::collections::{BTreeSet, HashMap};

/// The `.matches()` pattern for a path glob: globset's regex with wicket's options, minus the
/// leading `(?-u)` (see the module docs).
pub fn path_regex(glob: &str) -> Result<String, AuthzError> {
    let g = globset::GlobBuilder::new(glob)
        .literal_separator(true)
        .build()
        .map_err(|e| AuthzError::Ceiling(format!("invalid path glob {glob:?}: {e}")))?;
    let re = g.regex();
    let re = re.strip_prefix("(?-u)").ok_or_else(|| AuthzError::Ceiling(format!("unexpected regex for {glob:?}: {re}")))?;
    if re.len() > crate::structure::Policy::default().max_regex_len {
        return Err(AuthzError::Ceiling(format!("path glob {glob:?} is too long")));
    }
    Ok(re.to_string())
}

/// A path as the `path` fact (and a grant's path) carries it: its bytes as Latin-1 characters, so
/// the regex sees one character per byte, as globset does. ASCII paths are unchanged.
pub fn path_term(path: &str) -> String {
    if path.is_ascii() {
        path.to_string()
    } else {
        path.bytes().map(char::from).collect()
    }
}

/// Datalog source with its parameters. Only placeholder names are ever formatted into the text.
#[derive(Default)]
pub(crate) struct Code {
    text: String,
    params: HashMap<String, Term>,
    keys: HashMap<String, PublicKeyData>,
}

impl Code {
    fn push(&mut self, fragment: &str) {
        self.text.push_str(fragment);
    }
    /// A placeholder for `t`.
    fn p(&mut self, t: Term) -> String {
        let name = format!("p{}", self.params.len());
        self.params.insert(name.clone(), t);
        format!("{{{name}}}")
    }
    fn s(&mut self, v: &str) -> String {
        self.p(Term::Str(v.to_string()))
    }
    fn i(&mut self, v: i64) -> String {
        self.p(Term::Integer(v))
    }
    fn set<'a>(&mut self, items: impl IntoIterator<Item = &'a str>) -> String {
        self.p(Term::Set(items.into_iter().map(|s| Term::Str(s.to_string())).collect::<BTreeSet<_>>()))
    }
    fn key(&mut self, k: &PublicKey) -> String {
        let name = format!("k{}", self.keys.len());
        self.keys.insert(name.clone(), PublicKeyData::from_bytes(Algorithm::Ed25519, k.0.to_vec()));
        format!("{{{name}}}")
    }

    pub(crate) fn block(self) -> Result<BlockBuilder, AuthzError> {
        BlockBuilder::new().code_with_params(&self.text, self.params, self.keys).map_err(|e| AuthzError::Encode(e.to_string()))
    }

    pub(crate) fn authority(self) -> Result<BiscuitBuilder, AuthzError> {
        biscuit_auth::Biscuit::builder().code_with_params(&self.text, self.params, self.keys).map_err(|e| AuthzError::Encode(e.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

/// `host(...)` for an exact host, `host($h), $h.ends_with(".sfx")` for `*.sfx`.
fn host_q(c: &mut Code, host: &str) -> String {
    match host.strip_prefix("*.") {
        Some(sfx) => format!("host($h), $h.ends_with({})", c.s(&format!(".{sfx}"))),
        None => format!("host({})", c.s(host)),
    }
}

/// One alternative per (rule, path): host, method and path.
fn reach_alternatives(c: &mut Code, rules: &[&Reach]) -> Result<String, AuthzError> {
    let mut out = String::new();
    for r in rules {
        for glob in &r.paths {
            let host = host_q(c, &r.host);
            let methods = c.set(r.methods.iter().map(String::as_str));
            let re = c.s(&path_regex(glob)?);
            out.push_str(&format!("\n  or {host}, method($m), {methods}.contains($m), path($p), $p.matches({re})"));
        }
    }
    Ok(out)
}

/// The grant escape: an `approved` fact for exactly this host, method and path, from a block signed
/// by one of the ceiling's grant keys.
fn escape(c: &mut Code, keys: &[PublicKey]) -> String {
    if keys.is_empty() {
        return String::new();
    }
    let ks: Vec<String> = keys.iter().map(|k| c.key(k)).collect();
    format!("\n  or host($h), method($m), path($p), approved($g, $h, $m, $p) trusting {}", ks.join(", "))
}

/// Block 0's extra content.
pub(crate) struct AuthorityInfo<'a> {
    pub tenant: &'a str,
    pub principal: &'a str,
}

/// The Datalog for one ceiling (see the module docs for the layout).
pub(crate) fn ceiling_code(ceiling: &Ceiling, authority: Option<&AuthorityInfo<'_>>) -> Result<Code, AuthzError> {
    ceiling.validate()?;
    let mut c = Code::default();
    if let Some(a) = authority {
        let (t, p) = (c.s(a.tenant), c.s(a.principal));
        let rt = c.s(a.tenant);
        c.push(&format!("tenant({t});\nprincipal({p});\ncheck if request_tenant({rt});\n"));
    }
    let zone = c.s(&ceiling.zone);
    c.push(&format!("zone({zone});\n"));

    let exp = c.p(Term::Date(ceiling.not_after));
    c.push(&format!("check if time($t), $t <= {exp};\n"));
    let (bx, sub) = (c.s(&ceiling.box_prefix), c.s(&format!("{}/", ceiling.box_prefix)));
    c.push(&format!("check if box({bx}) or box($b), $b.starts_with({sub});\n"));
    let ops = c.set(ceiling.ops.iter().map(|k| k.as_str()));
    c.push(&format!("check if op($o), {ops}.contains($o);\n"));

    // reach
    let http = c.s(OpKind::Http.as_str());
    let all: Vec<&Reach> = ceiling.reach.iter().collect();
    let alts = reach_alternatives(&mut c, &all)?;
    let esc = escape(&mut c, &ceiling.grant_keys);
    c.push(&format!("check if op($o), $o != {http}{alts}{esc};\n"));
    // risk
    let http = c.s(OpKind::Http.as_str());
    let max = c.i(MAX_REACH_RISK);
    let dangerous: Vec<&Reach> = ceiling.reach.iter().filter(|r| r.allow_dangerous).collect();
    let alts = reach_alternatives(&mut c, &dangerous)?;
    let esc = escape(&mut c, &ceiling.grant_keys);
    c.push(&format!("check if op($o), $o != {http}\n  or risk($r), $r <= {max}{alts}{esc};\n"));
    // forbid
    for f in &ceiling.forbid {
        for glob in &f.paths {
            let host = host_q(&mut c, &f.host);
            // Forbids ignore ASCII case, as in wicket-core (`ForbidRule::paths`, #115).
            let re = c.s(&path_regex(&wicket_core::manifest::fold_case_glob(glob))?);
            c.push(&format!("reject if {host}, path($p), $p.matches({re});\n"));
        }
    }
    // spawn
    let s = &ceiling.spawn;
    let kind = c.s(OpKind::Spawn.as_str());
    let images = c.set(s.images.iter().map(String::as_str));
    let (iso, mem, cpu, pids, secs) = (c.i(s.min_isolation), c.i(s.mem_bytes), c.i(s.cpus_milli), c.i(s.pids), c.i(s.timeout_s));
    c.push(&format!(
        "check if op($o), $o != {kind}\n  or spawn($i, $iso, $mem, $cpu, $pids, $secs), {images}.contains($i), $iso >= {iso}, $mem <= {mem}, $cpu <= {cpu}, $pids <= {pids}, $secs <= {secs};\n"
    ));
    // llm
    let kind = c.s(OpKind::Llm.as_str());
    let (r, k) = (c.i(ceiling.llm.max_requests), c.i(ceiling.llm.max_output_tokens));
    c.push(&format!("check if op($o), $o != {kind}\n  or llm_used($r, $k), $r < {r}, $k < {k};\n"));
    // msg
    let kind = c.s(OpKind::Msg.as_str());
    let from = c.set(ceiling.accept_from.iter().map(String::as_str));
    c.push(&format!("check if op($o), $o != {kind}\n  or msg_from($z), {from}.contains($z);\n"));
    // inject
    let keys: Vec<String> = ceiling.inject.iter().map(Inject::key).collect();
    let inject = c.set(keys.iter().map(String::as_str));
    c.push(&format!("reject if inject($k), !{inject}.contains($k);\n"));
    if let (Some(org), Some(_)) = (&ceiling.org, authority) {
        org_code(&mut c, org)?;
    }
    Ok(c)
}

/// One HTTP conjunction's predicates and expressions (after `op` and with `$h`, `$m`, `$p`, `$r`).
fn http_match(c: &mut Code, m: &HttpMatch) -> Result<String, AuthzError> {
    let mut parts = vec![];
    if !m.hosts.is_empty() || !m.not_hosts.is_empty() {
        parts.push("host($h)".to_string());
    }
    for h in &m.hosts {
        parts.push(match h {
            HostPat::Exact(x) => format!("$h == {}", c.s(x)),
            HostPat::Suffix(x) => format!("$h.ends_with({})", c.s(x)),
        });
    }
    for x in &m.not_hosts {
        parts.push(format!("$h != {}", c.s(x)));
    }
    if let Some(ms) = &m.methods {
        let set = c.set(ms.iter().map(String::as_str));
        parts.push(format!("method($m), {set}.contains($m)"));
    }
    if !m.paths.is_empty() {
        parts.push("path($p)".to_string());
    }
    for p in &m.paths {
        let re = match p {
            PathPat::Glob(g) => path_regex(g)?,
            PathPat::Like(l) => like_regex(l),
        };
        parts.push(format!("$p.matches({})", c.s(&re)));
    }
    if m.max_risk.is_some() || m.min_risk.is_some() {
        parts.push("risk($r)".to_string());
    }
    if let Some(n) = m.max_risk {
        parts.push(format!("$r <= {}", c.i(n)));
    }
    if let Some(n) = m.min_risk {
        parts.push(format!("$r >= {}", c.i(n)));
    }
    Ok(parts.join(", "))
}

/// A Cedar `like` pattern as an anchored regex: `*` is any run of characters (`/` included), `\*` a
/// literal star, everything else itself.
pub fn like_regex(pat: &str) -> String {
    let mut out = String::from("^");
    let mut chars = pat.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if chars.peek() == Some(&'*') => {
                chars.next();
                out.push_str("\\*");
            }
            '*' => out.push_str(".*"),
            ch => out.push_str(&regex::escape(&ch.to_string())),
        }
    }
    out.push('$');
    out
}

/// The org layer's checks (#51), in block 0. Each reads the `policy` fact, which classes it hard:
/// a grant can't lift the org ceiling.
fn org_code(c: &mut Code, org: &OrgLayer) -> Result<(), AuthzError> {
    let v = c.s(&org.version);
    c.push(&format!("policy({v});\n"));
    if let Some(alts) = &org.http {
        let http = c.s(OpKind::Http.as_str());
        let mut q = format!("check if policy($v), op($o), $o != {http}");
        for a in alts {
            let m = http_match(c, a)?;
            q.push_str(&format!("\n  or op($o){}{m}", if m.is_empty() { "" } else { ", " }));
        }
        c.push(&format!("{q};\n"));
    }
    for f in &org.forbid {
        let http = c.s(OpKind::Http.as_str());
        let m = http_match(c, f)?;
        c.push(&format!("reject if policy($v), op({http}){}{m};\n", if m.is_empty() { "" } else { ", " }));
    }
    if let Some(alts) = &org.spawn {
        let kind = c.s(OpKind::Spawn.as_str());
        let mut q = format!("check if policy($v), op($o), $o != {kind}");
        for a in alts {
            let mut parts = vec!["spawn($i, $iso, $mem, $cpu, $pids, $secs)".to_string()];
            if let Some(imgs) = &a.images {
                parts.push(format!("{}.contains($i)", c.set(imgs.iter().map(String::as_str))));
            }
            for (var, cmp, v) in [
                ("$iso", ">=", a.min_isolation),
                ("$mem", "<=", a.max_mem_bytes),
                ("$cpu", "<=", a.max_cpus_milli),
                ("$pids", "<=", a.max_pids),
                ("$secs", "<=", a.max_timeout_s),
            ] {
                if let Some(v) = v {
                    parts.push(format!("{var} {cmp} {}", c.i(v)));
                }
            }
            q.push_str(&format!("\n  or {}", parts.join(", ")));
        }
        c.push(&format!("{q};\n"));
    }
    if let Some(from) = &org.msg_from {
        let kind = c.s(OpKind::Msg.as_str());
        let set = c.set(from.iter().map(String::as_str));
        c.push(&format!("check if policy($v), op($o), $o != {kind}\n  or msg_from($z), {set}.contains($z);\n"));
    }
    if let Some(keys) = &org.inject {
        let set = c.set(keys.iter().map(String::as_str));
        c.push(&format!("reject if policy($v), inject($k), !{set}.contains($k);\n"));
    }
    Ok(())
}

/// A spawn block for `ceiling`, unchecked (tests: tokens over the caps, built to show that a node
/// refuses them).
#[doc(hidden)]
pub fn ceiling_block(ceiling: &Ceiling) -> Result<BlockBuilder, AuthzError> {
    ceiling_code(ceiling, None)?.block()
}

/// The Datalog for one grant (a third-party block).
pub(crate) fn grant_code(g: &Grant) -> Code {
    let mut c = Code::default();
    let gid = c.s(&g.gid);
    let (h, m, p) = (c.s(&g.host.to_ascii_lowercase()), c.s(&g.method.to_ascii_uppercase()), c.s(&path_term(&g.path)));
    let exp = c.p(Term::Date(g.not_after));
    let (b, e, zero) = (c.s(&g.box_id), c.i(g.epoch), c.i(0));
    let (a, d) = (c.s(&g.approver), c.p(Term::Bytes(g.digest.clone())));
    c.push(&format!(
        "approved({gid}, {h}, {m}, {p}) <- time($t), $t <= {exp}, box({b}), epoch({e}), uses_left({gid}, $n), $n > {zero};\napproval({gid}, {a}, {d});\n"
    ));
    c
}

/// The node's ambient facts for one request. Built from typed terms, never parsed.
pub fn request_facts(r: &Request) -> Vec<Fact> {
    let s = |v: &str| Term::Str(v.to_string());
    let mut f = vec![
        fact("time", &[Term::Date(r.time)]),
        fact("request_tenant", &[s(&r.tenant)]),
        fact("box", &[s(&r.box_id)]),
        fact("epoch", &[Term::Integer(r.epoch)]),
        fact("op", &[s(r.action.kind().as_str())]),
    ];
    match &r.action {
        Action::Http { host, method, path, risk, inject } => {
            f.push(fact("host", &[s(host)]));
            f.push(fact("method", &[s(method)]));
            f.push(fact("path", &[s(&path_term(path))]));
            f.push(fact("risk", &[Term::Integer(risk_level(*risk))]));
            if let Some(k) = inject {
                f.push(fact("inject", &[s(k)]));
            }
        }
        Action::Spawn { image, isolation, mem_bytes, cpus_milli, pids, timeout_s } => f.push(fact(
            "spawn",
            &[
                s(image),
                Term::Integer(*isolation),
                Term::Integer(*mem_bytes),
                Term::Integer(*cpus_milli),
                Term::Integer(*pids),
                Term::Integer(*timeout_s),
            ],
        )),
        Action::Llm { used_requests, used_output_tokens } => {
            f.push(fact("llm_used", &[Term::Integer(*used_requests), Term::Integer(*used_output_tokens)]))
        }
        Action::Msg { from } => f.push(fact("msg_from", &[s(from)])),
    }
    for (g, n) in &r.uses_left {
        f.push(fact("uses_left", &[s(g), Term::Integer(*n)]));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_text_holds_no_values() {
        let c = Ceiling {
            zone: "z\"); allow if true; //".into(),
            box_prefix: "b0".into(),
            not_after: 1,
            ops: vec![],
            reach: vec![Reach { host: "*.evil\"".into(), methods: vec![], paths: vec!["/a/**".into()], allow_dangerous: true }],
            forbid: vec![],
            inject: vec![],
            spawn: SpawnLimits { images: vec![], min_isolation: 2, mem_bytes: 1, cpus_milli: 1, pids: 1, timeout_s: 1 },
            llm: LlmBudget { max_requests: 0, max_output_tokens: 0 },
            accept_from: vec![],
            grant_keys: vec![PublicKey([7; 32])],
            org: None,
        };
        let code = ceiling_code(&c, Some(&AuthorityInfo { tenant: "t", principal: "p" })).unwrap();
        // Nothing but fixed fragments and placeholders: no quote, digit literal or brace other than
        // a placeholder.
        let stripped = regex::Regex::new(r"\{[pk][0-9]+\}").unwrap().replace_all(code.text(), "");
        assert!(!stripped.contains(['"', '{', '}']), "{stripped}");
        assert!(!stripped.chars().any(|ch| ch.is_ascii_digit()), "{stripped}");
        code.block().unwrap();
        let g = Grant {
            gid: "g\"".into(),
            box_id: "b0".into(),
            epoch: 1,
            host: "h".into(),
            method: "GET".into(),
            path: "/".into(),
            not_after: 5,
            approver: "a".into(),
            digest: vec![1, 2],
        };
        let gc = grant_code(&g);
        let stripped = regex::Regex::new(r"\{[pk][0-9]+\}").unwrap().replace_all(gc.text(), "");
        assert!(!stripped.contains(['"', '{', '}']) && !stripped.chars().any(|ch| ch.is_ascii_digit()), "{stripped}");
    }

    #[test]
    fn path_regexes_are_globsets_own() {
        for g in ["/**", "/a/*", "/repos/{issues,pulls}/*", "/x?y", "/caf\u{e9}/**", "**/z", "/a/**/b"] {
            let ours = path_regex(g).unwrap();
            let theirs = globset::GlobBuilder::new(g).literal_separator(true).build().unwrap();
            assert_eq!(format!("(?-u){ours}"), theirs.regex());
        }
    }
}
