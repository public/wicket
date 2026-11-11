//! The Biscuit encoding: ceilings and grants compiled to Datalog blocks, request facts, authorization.

use crate::model::*;
use biscuit_auth::builder::{date, fact, int, string, Fact};
use biscuit_auth::{AuthorizerBuilder, AuthorizerLimits, Biscuit, BlockBuilder, KeyPair, PublicKey};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn q(s: &str) -> String {
    format!("{s:?}")
}

fn set(items: &[String]) -> String {
    format!("{{{}}}", items.iter().map(|s| q(s)).collect::<Vec<_>>().join(", "))
}

fn host_q(h: &str) -> String {
    match h.strip_prefix("*.") {
        Some(sfx) => format!("host($h), $h.ends_with({})", q(&format!(".{sfx}"))),
        None => format!("host({})", q(h)),
    }
}

fn path_q(p: &PathPat, regex: bool) -> Option<String> {
    if regex {
        return match p {
            PathPat::Any => None,
            PathPat::Prefix(x) => Some(format!("path($p), $p.matches({})", q(&format!("^{x}")))),
            PathPat::OneSegment(x) => Some(format!("path($p), $p.matches({})", q(&format!("^{x}[^/]+$")))),
        };
    }
    match p {
        PathPat::Any => None,
        PathPat::Prefix(x) => Some(format!("path($p), $p.starts_with({})", q(x))),
        PathPat::OneSegment(x) => Some(format!("path($p), $p.starts_with({}), path_depth({})", q(x), path_depth(x) + 1)),
    }
}

fn reach_q(r: &Reach, regex: bool) -> String {
    let mut parts = vec![host_q(&r.host)];
    if r.methods.len() == 1 {
        parts.push(format!("method({})", q(&r.methods[0])));
    } else {
        parts.push(format!("method($m), {}.contains($m)", set(&r.methods)));
    }
    parts.extend(path_q(&r.path, regex));
    parts.join(", ")
}

/// The grant escape: a request that exactly matches an `approved` fact from a trusted signer.
fn escape(c: &Ceiling) -> String {
    if c.grant_keys.is_empty() {
        return String::new();
    }
    let keys: Vec<String> = c.grant_keys.iter().map(|k| format!("ed25519/{k}")).collect();
    format!("\n  or host($h), method($m), path($p), approved($g, $h, $m, $p) trusting {}", keys.join(", "))
}

/// Compile one ceiling to a block. Returns (code, number of checks).
pub fn compile(c: &Ceiling, authority: bool, tenant: &str) -> (String, usize) {
    let mut out = String::new();
    let mut n = 0;
    let mut chk = |out: &mut String, s: String| {
        out.push_str(&s);
        out.push_str(";\n");
        n += 1;
    };
    if authority {
        out.push_str(&format!("tenant({});\nprincipal(\"trigger:{}\");\n", q(tenant), c.zone));
    }
    out.push_str(&format!("zone({});\n", q(&c.zone)));
    chk(&mut out, format!("check if time($t), $t <= {}", rfc3339(c.not_after)));
    chk(&mut out, format!("check if box($b), $b == {} || $b.starts_with({})", q(&c.box_prefix), q(&format!("{}/", c.box_prefix))));
    chk(&mut out, format!("check if op($o), {}.contains($o)", set(&c.ops)));
    let reach: Vec<String> = c.reach.iter().map(|r| format!("\n  or {}", reach_q(r, c.regex_paths))).collect();
    chk(&mut out, format!("check if op($o), $o != \"http\"{}{}", reach.concat(), escape(c)));
    for f in &c.forbid {
        let mut s = format!("reject if {}", host_q(&f.host));
        if let Some(p) = &f.path_prefix {
            s.push_str(&format!(", path($p), $p.starts_with({})", q(p)));
        }
        chk(&mut out, s);
    }
    let ok: Vec<String> = c.dangerous_ok.iter().map(|r| format!("\n  or {}", reach_q(r, c.regex_paths))).collect();
    chk(&mut out, format!("check if op($o), $o != \"http\"\n  or risk($r), $r <= {}{}{}", c.max_risk, ok.concat(), escape(c)));
    let s = &c.spawn;
    chk(
        &mut out,
        format!(
            "check if op($o), $o != \"spawn\"\n  or spawn($i, $iso, $mem, $cpu, $pids, $secs), {}.contains($i), $iso >= {}, $mem <= {}, $cpu <= {}, $pids <= {}, $secs <= {}",
            set(&s.images),
            s.min_isolation,
            s.mem_bytes,
            s.cpus_milli,
            s.pids,
            s.timeout_s
        ),
    );
    chk(&mut out, format!("check if op($o), $o != \"llm\"\n  or llm_used($r, $k), $r < {}, $k < {}", c.llm.max_requests, c.llm.max_output_tokens));
    if c.accept_from.is_empty() {
        chk(&mut out, "check if op($o), $o != \"msg\"".into());
    } else {
        chk(&mut out, format!("check if op($o), $o != \"msg\"\n  or msg_from($z), {}.contains($z)", set(&c.accept_from)));
    }
    if c.inject.is_empty() {
        chk(&mut out, "reject if inject($k)".into());
    } else {
        chk(&mut out, format!("reject if inject($k), !{}.contains($k)", set(&c.inject)));
    }
    (out, n)
}

/// A grant as a third-party block: a rule that yields `approved` only while the lease is live, so an
/// expired or used-up lease drops out without invalidating the rest of the chain.
pub fn grant_code(g: &Grant) -> String {
    format!(
        "approved({gid}, {h}, {m}, {p}) <- time($t), $t <= {exp}, box({b}), epoch({e}), uses_left({gid}, $n), $n > 0;\napproval({gid}, {a}, hex:{d});\n",
        gid = q(&g.gid),
        h = q(&g.host),
        m = q(&g.method),
        p = q(&g.path),
        exp = rfc3339(g.not_after),
        b = q(&g.box_id),
        e = g.epoch,
        a = q(&g.approver),
        d = g.digest
    )
}

pub struct Keys {
    pub root: KeyPair,
    pub approver: KeyPair,
    /// One grantor key per box (index = depth); a child's block trusts its parent's.
    pub grantor: Vec<KeyPair>,
}

impl Keys {
    pub fn new(max_depth: usize) -> Keys {
        Keys { root: KeyPair::new(), approver: KeyPair::new(), grantor: (0..=max_depth).map(|_| KeyPair::new()).collect() }
    }
}

pub fn hexkey(k: &PublicKey) -> String {
    k.print().trim_start_matches("ed25519/").to_string()
}

pub fn ceilings(t0: u64, depth: usize, keys: &Keys) -> Vec<Ceiling> {
    (0..=depth)
        .map(|l| {
            let mut gk = vec![hexkey(&keys.approver.public())];
            if l > 0 {
                gk.push(hexkey(&keys.grantor[l - 1].public()));
            }
            level(t0, l, gk)
        })
        .collect()
}

pub struct Chain {
    pub token: Biscuit,
    pub checks: usize,
    pub codes: Vec<String>,
}

/// Size variant: a spawn block keeps only the statements that differ from its parent's block
/// (anything identical is already enforced by the parent).
pub fn compile_diff(c: &Ceiling, parent: &Ceiling) -> (String, usize) {
    let (mine, _) = compile(c, false, "acme");
    let (theirs, _) = compile(parent, parent.box_prefix == "b0", "acme");
    let have: std::collections::HashSet<&str> = theirs.split(";\n").collect();
    let kept: Vec<&str> = mine.split(";\n").filter(|s| !s.is_empty() && (s.starts_with("zone(") || !have.contains(s))).collect();
    let n = kept.iter().filter(|s| s.starts_with("check") || s.starts_with("reject")).count();
    (kept.iter().map(|s| format!("{s};\n")).collect(), n)
}

pub fn mint(cs: &[Ceiling], grant: Option<(&Grant, &KeyPair)>, root: &KeyPair) -> Chain {
    mint_with(cs, grant, root, false)
}

pub fn mint_with(cs: &[Ceiling], grant: Option<(&Grant, &KeyPair)>, root: &KeyPair, diff: bool) -> Chain {
    let (code, mut checks) = compile(&cs[0], true, "acme");
    let mut codes = vec![code.clone()];
    let mut token = Biscuit::builder().code(&code).expect("authority code").build(root).expect("mint");
    for (i, c) in cs.iter().enumerate().skip(1) {
        let (code, n) = if diff { compile_diff(c, &cs[i - 1]) } else { compile(c, false, "acme") };
        checks += n;
        token = token.append(BlockBuilder::new().code(&code).expect("block code")).expect("append");
        codes.push(code);
    }
    if let Some((g, signer)) = grant {
        let code = grant_code(g);
        token = append_grant(&token, &code, signer);
        codes.push(code);
    }
    Chain { token, checks, codes }
}

/// The third-party flow: the node makes a request bound to the token's last signature; the approver
/// signs a block; the node appends it.
pub fn append_grant(token: &Biscuit, code: &str, signer: &KeyPair) -> Biscuit {
    let req = token.third_party_request().expect("3p request");
    let block = req.create_block(&signer.private(), BlockBuilder::new().code(code).expect("grant code")).expect("3p block");
    token.append_third_party(signer.public(), block).expect("append 3p")
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

pub fn request_facts(r: &Request) -> Vec<Fact> {
    let mut f = vec![
        fact("time", &[date(&t(r.time))]),
        fact("request_tenant", &[string(&r.tenant)]),
        fact("node", &[string(&r.node)]),
        fact("box", &[string(&r.box_id)]),
        fact("epoch", &[int(r.epoch)]),
        fact("op", &[string(r.op.kind())]),
    ];
    match &r.op {
        Op::Http { host, method, path, risk, inject } => {
            f.push(fact("host", &[string(host)]));
            f.push(fact("method", &[string(method)]));
            f.push(fact("path", &[string(path)]));
            f.push(fact("path_depth", &[int(path_depth(path))]));
            f.push(fact("risk", &[int(*risk)]));
            if let Some(k) = inject {
                f.push(fact("inject", &[string(k)]));
            }
        }
        Op::Spawn { image, isolation, mem, cpus, pids, secs } => {
            f.push(fact("spawn", &[string(image), int(*isolation), int(*mem), int(*cpus), int(*pids), int(*secs)]));
        }
        Op::Llm { used_requests, used_tokens } => f.push(fact("llm_used", &[int(*used_requests), int(*used_tokens)])),
        Op::Msg { from } => f.push(fact("msg_from", &[string(from)])),
    }
    for (g, n) in &r.uses_left {
        f.push(fact("uses_left", &[string(g), int(*n)]));
    }
    f
}

/// The node's static authorizer: tenant binding and a single allow. Every ceiling lives in the token.
pub fn base_authorizer(limits: AuthorizerLimits) -> AuthorizerBuilder {
    AuthorizerBuilder::new()
        .code("check if tenant($t), request_tenant($t);\nallow if true;")
        .expect("authorizer code")
        .set_limits(limits)
}

pub fn generous() -> AuthorizerLimits {
    AuthorizerLimits { max_facts: 1000, max_iterations: 100, max_time: Duration::from_millis(50) }
}

pub struct Outcome {
    pub ok: bool,
    pub err: Option<String>,
    pub facts: usize,
    pub iterations: u64,
    pub exec: Option<Duration>,
}

pub fn authorize(base: &AuthorizerBuilder, token: &Biscuit, r: &Request) -> Outcome {
    let mut b = base.clone();
    for f in request_facts(r) {
        b = b.fact(f).expect("fact");
    }
    let mut a = match b.build(token) {
        Ok(a) => a,
        Err(e) => return Outcome { ok: false, err: Some(format!("build: {e}")), facts: 0, iterations: 0, exec: None },
    };
    let res = a.authorize();
    Outcome { ok: res.is_ok(), err: res.err().map(|e| e.to_string()), facts: a.fact_count(), iterations: a.iterations(), exec: a.execution_time() }
}

/// Fast path used in timing loops: returns only allow/deny.
#[inline]
pub fn authorize_fast(base: &AuthorizerBuilder, token: &Biscuit, facts: &[Fact]) -> bool {
    let mut b = base.clone();
    for f in facts {
        b = b.fact(f.clone()).expect("fact");
    }
    match b.build(token) {
        Ok(mut a) => a.authorize().is_ok(),
        Err(_) => false,
    }
}
