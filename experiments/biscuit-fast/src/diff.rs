//! Differential test: random ceilings, chains, grants, holder blocks and requests, decided by stock
//! 6.0.0 and by every fork path. Any decision that differs is printed.
//!
//! DIFF_CHAINS (default 2000) chains × DIFF_REQS (default 50) requests, seed DIFF_SEED (default 59).

use crate::bisc;
use crate::fk;
use crate::model::*;
use biscuit_auth::builder as sb;
use biscuit_auth::{BlockBuilder, KeyPair};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use std::time::Instant;

fn env(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn pick<'a, T>(rng: &mut StdRng, v: &'a [T]) -> &'a T {
    v.choose(rng).unwrap()
}

fn subset<T: Clone>(rng: &mut StdRng, v: &[T], p_keep: f64, nonempty: bool) -> Vec<T> {
    let mut out: Vec<T> = v.iter().filter(|_| rng.gen_bool(p_keep)).cloned().collect();
    if nonempty && out.is_empty() && !v.is_empty() {
        out.push(pick(rng, v).clone());
    }
    out
}

const HOSTS: &[&str] = &["api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "githubusercontent.com", "crates.io", "static.crates.io", "index.crates.io", "docs.rs", "pypi.org", "registry.npmjs.org", "vault.internal", "example.com"];
const METHODS: &[&str] = &["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"];
const PATHS: &[&str] = &["/repos/acme/api/pulls/7", "/repos/acme/api/pulls/7/merge", "/repos/acme/infra/issues", "/repos/acme/secrets-vault/key", "/repos/acme/scratch/a", "/repos/other/x/issues", "/tokio/latest", "/tokio/a/b", "/simple/requests/", "/api/v1/crates/serde", "/", "/x"];
const IMAGES: &[&str] = &["img:agent", "img:rust", "img:py", "img:evil"];

fn rand_reach(rng: &mut StdRng) -> Reach {
    let host = if rng.gen_bool(0.2) { "*.githubusercontent.com".to_string() } else { pick(rng, HOSTS).to_string() };
    let methods: Vec<String> = subset(rng, METHODS, 0.4, true).into_iter().map(String::from).collect();
    let path = match rng.gen_range(0..4) {
        0 => PathPat::Any,
        1 => PathPat::Prefix(pick(rng, &["/repos/acme/", "/repos/acme/api/", "/simple/", "/api/v1/"]).to_string()),
        2 => PathPat::OneSegment("/tokio/".into()),
        _ => PathPat::Prefix("/repos/".into()),
    };
    Reach { host, methods, path }
}

/// A random ceiling at `lvl`: the scenario's, with each dimension perturbed with probability P.
const P: f64 = 0.1;
fn rand_ceiling(rng: &mut StdRng, t0: u64, lvl: usize, gk: Vec<String>) -> Ceiling {
    let mut c = level(t0, lvl, gk);
    let gib = 1i64 << 30;
    if rng.gen_bool(P) {
        c.ops = subset(rng, &c.ops, 0.8, true);
    }
    if rng.gen_bool(P) {
        c.reach = subset(rng, &c.reach, 0.7, false);
    }
    for r in c.reach.iter_mut() {
        if rng.gen_bool(P / 2.0) {
            r.methods = subset(rng, &r.methods, 0.6, true);
        }
    }
    if rng.gen_bool(P) {
        c.reach.push(rand_reach(rng));
    }
    if rng.gen_bool(P) {
        c.forbid = subset(rng, &[Forbid { host: "*.internal".into(), path_prefix: None }, Forbid { host: "api.github.com".into(), path_prefix: Some("/repos/acme/secrets-vault/".into()) }, Forbid { host: "pypi.org".into(), path_prefix: None }], 0.6, false);
    }
    if rng.gen_bool(P) {
        c.max_risk = rng.gen_range(0..=3);
    }
    if rng.gen_bool(P) {
        c.dangerous_ok = subset(rng, &c.dangerous_ok, 0.7, false);
        c.dangerous_ok.push(rand_reach(rng));
    }
    if rng.gen_bool(P) {
        c.spawn.images = subset(rng, &c.spawn.images, 0.8, false);
        c.spawn.min_isolation = rng.gen_range(1..=2);
    }
    if rng.gen_bool(P) {
        c.spawn.mem_bytes = *pick(rng, &[gib / 4, gib, 4 * gib, 8 * gib]);
        c.spawn.cpus_milli = *pick(rng, &[250, 1000, 4000]);
        c.spawn.pids = *pick(rng, &[64, 512, 2048]);
        c.spawn.timeout_s = *pick(rng, &[900, 6 * 3600, 8 * 3600]);
    }
    if rng.gen_bool(P) {
        c.llm.max_requests = *pick(rng, &[0, 1000, 3000]);
        c.llm.max_output_tokens = *pick(rng, &[1_000_000, 4_000_000]);
    }
    if rng.gen_bool(P) {
        c.accept_from = subset(rng, &["ops".to_string(), "ci".into(), "dev".into()], 0.5, false);
    }
    if rng.gen_bool(P) {
        c.inject = subset(rng, &[GH_INJECT.to_string(), "pypi.org|Authorization|pypi-token".into()], 0.7, false);
    }
    if rng.gen_bool(P) {
        c.not_after = t0 + rng.gen_range(1..=9) * 3600;
    }
    if rng.gen_bool(0.03) {
        c.box_prefix = "b0/b1/bx".into();
    }
    c
}

struct Case {
    tok: biscuit_auth::Biscuit,
    leaf: usize,
    cs: Vec<Ceiling>,
    grant: Option<Grant>,
}

fn rand_chain(rng: &mut StdRng, t0: u64, keys: &bisc::Keys, attacker: &KeyPair) -> Case {
    let leaf = rng.gen_range(0..=5);
    let cs: Vec<Ceiling> = (0..=leaf)
        .map(|l| {
            let mut gk = vec![bisc::hexkey(&keys.approver.public())];
            if l > 0 {
                gk.push(bisc::hexkey(&keys.grantor[l - 1].public()));
            }
            rand_ceiling(rng, t0, l, gk)
        })
        .collect();
    let mut tok = bisc::mint(&cs, None, &keys.root).token;
    let mut grant = None;
    if rng.gen_bool(0.75) {
        let mut g = leaf_grant(t0 + 600, leaf);
        g.host = pick(rng, &["api.github.com", "api.github.com", "docs.rs", "example.com"]).to_string();
        g.method = pick(rng, METHODS).to_string();
        g.path = pick(rng, PATHS).to_string();
        g.not_after = t0 + rng.gen_range(0..=7200);
        if rng.gen_bool(0.15) {
            g.box_id = "b0/b1/b9".into();
        }
        if rng.gen_bool(0.1) {
            g.epoch = 4;
        }
        let signer = match rng.gen_range(0..10) {
            0..=4 => &keys.approver,
            5..=6 if leaf > 0 => &keys.grantor[leaf - 1],
            7 => &keys.grantor[leaf],
            _ => attacker,
        };
        tok = bisc::append_grant(&tok, &bisc::grant_code(&g), signer);
        grant = Some(g);
    }
    if rng.gen_bool(0.2) {
        let code = match rng.gen_range(0..9) {
            0 => "check if true;".to_string(),
            1 => r#"approved("g-7f3a", "api.github.com", "GET", "/repos/other/x/issues");"#.into(),
            2 => "approved($g, $h, $m, $p) <- host($h), method($m), path($p), uses_left($g, $n);".into(),
            3 => r#"check if op($o), $o != "http" or method("GET");"#.into(),
            4 => r#"check if op($o), $o != "spawn";"#.into(),
            5 => format!("check if time($t), $t <= {};", rfc3339(t0 + rng.gen_range(0..=9) * 3600)),
            6 => r#"reject if host($h), $h.ends_with(".org");"#.into(),
            7 => r#"check all method($m), {"GET", "HEAD"}.contains($m);"#.into(),
            _ => r#"check if risk($r), $r < 2 or op($o), $o != "http";"#.into(),
        };
        tok = tok.append(BlockBuilder::new().code(&code).unwrap()).unwrap();
    }
    Case { tok, leaf, cs, grant }
}

/// A scenario request (A–D at the leaf), with 0–3 random mutations (0 or 1 two times in three).
fn rand_request(rng: &mut StdRng, t0: u64, case: &Case) -> Request {
    let sc = scenarios(t0 + 600, case.leaf);
    let mut r = pick(rng, &sc).1.clone();
    if let (Some(g), true) = (&case.grant, rng.gen_bool(0.3)) {
        r.op = Op::Http { host: g.host.clone(), method: g.method.clone(), path: g.path.clone(), risk: rng.gen_range(0..=4), inject: Some(GH_INJECT.into()) };
    }
    let k = [0, 0, 1, 1, 2, 3][rng.gen_range(0..6)];
    for _ in 0..k {
        match rng.gen_range(0..12) {
            0 => {
                let mut ends: Vec<u64> = case.cs.iter().map(|c| c.not_after).collect();
                if let Some(g) = &case.grant {
                    ends.push(g.not_after);
                }
                r.time = pick(rng, &ends) + rng.gen_range(0..=1);
            }
            1 => r.time = t0 + rng.gen_range(0..=10 * 3600),
            2 => r.tenant = "other".into(),
            3 => {
                r.box_id = match rng.gen_range(0..3) {
                    0 => box_id(rng.gen_range(0..=case.leaf)),
                    1 => format!("{}/b6", box_id(case.leaf)),
                    _ => "b0/b1/b9".into(),
                }
            }
            4 => r.epoch = 4,
            5 => {
                r.uses_left = match rng.gen_range(0..3) {
                    0 => vec![("g-7f3a".into(), 0)],
                    1 => vec![],
                    _ => vec![("g-7f3a".into(), 2), ("g-other".into(), 1)],
                }
            }
            6..=8 => {
                if let Op::Http { host, method, path, risk, inject } = &mut r.op {
                    match rng.gen_range(0..5) {
                        0 => *host = pick(rng, HOSTS).to_string(),
                        1 => *method = pick(rng, METHODS).to_string(),
                        2 => *path = pick(rng, PATHS).to_string(),
                        3 => *risk = rng.gen_range(0..=4),
                        _ => *inject = pick(rng, &[None, Some("pypi.org|Authorization|pypi-token".to_string())]).clone(),
                    }
                } else {
                    r.op = Op::Http { host: pick(rng, HOSTS).to_string(), method: pick(rng, METHODS).to_string(), path: pick(rng, PATHS).to_string(), risk: rng.gen_range(0..=4), inject: Some(GH_INJECT.into()) };
                }
            }
            9 => {
                r.op = Op::Spawn {
                    image: pick(rng, IMAGES).to_string(),
                    isolation: rng.gen_range(1..=2),
                    mem: *pick(rng, &[256 << 20, 1 << 30, 9 << 30]),
                    cpus: *pick(rng, &[250, 1000, 5000]),
                    pids: *pick(rng, &[64, 512, 4096]),
                    secs: *pick(rng, &[900, 6 * 3600, 9 * 3600]),
                }
            }
            10 => r.op = Op::Llm { used_requests: *pick(rng, &[0, 999, 2999, 3000]), used_tokens: *pick(rng, &[0, 3_999_999, 4_000_000]) },
            _ => r.op = Op::Msg { from: pick(rng, &["ops", "ci", "x"]).to_string() },
        }
    }
    r
}

/// Ill-typed variants: the same fact name with a term of the wrong type (expressions then fail).
fn ill_typed(rng: &mut StdRng, s: &mut Vec<sb::Fact>, f: &mut Vec<fork::builder::Fact>) -> &'static str {
    let (name, st, ft): (&str, sb::Term, fork::builder::Term) = match rng.gen_range(0..4) {
        0 => ("time", sb::int(5), fork::builder::int(5)),
        1 => ("risk", sb::string("high"), fork::builder::string("high")),
        2 => ("path_depth", sb::string("2"), fork::builder::string("2")),
        _ => ("method", sb::int(1), fork::builder::int(1)),
    };
    s.retain(|x| x.predicate.name != name);
    f.retain(|x| x.predicate.name != name);
    s.push(sb::fact(name, &[st]));
    f.push(fork::builder::fact(name, &[ft]));
    name
}

#[derive(Default)]
struct Tally {
    same: u64,
    diff: u64,
    limit: u64,
}

pub fn run() {
    let chains = env("DIFF_CHAINS", 2000);
    let per = env("DIFF_REQS", 50);
    let seed = env("DIFF_SEED", 59);
    let mut rng = StdRng::seed_from_u64(seed);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let t0 = now - now % 60;
    println!("differential test: {chains} random chains × {per} random requests, seed {seed}");
    println!("engines: stock 6.0.0 (reference) vs upstream main (build per request), step 1 (wall-clock limits), step 2 and step 3 (fuel {:?})\n", fk::fuel());
    let base = bisc::base_authorizer(bisc::generous());
    let fbase = fk::base_builder();
    let mut keys = bisc::Keys::new(5);
    let mut attacker = KeyPair::new();
    let names = ["upstream main", "step 1", "step 2", "step 3"];
    let mut tallies: Vec<Tally> = (0..4).map(|_| Tally::default()).collect();
    let (mut allows, mut denies, mut total, mut illtyped) = (0u64, 0u64, 0u64, 0u64);
    let mut shown = 0;
    let start = Instant::now();
    let mut lint_reject = 0;
    let mut fallbacks = 0u64;
    let mut compiled_chains = 0u64;
    let mut why_not: std::collections::BTreeMap<String, u64> = Default::default();
    for ci in 0..chains {
        if ci % 100 == 0 {
            keys = bisc::Keys::new(5);
            attacker = KeyPair::new();
        }
        let case = rand_chain(&mut rng, t0, &keys, &attacker);
        let ftok = fk::load(&case.tok, &keys.root.public());
        if crate::lint::lint(&ftok, case.tok.to_vec().unwrap().len(), &crate::lint::Policy::default()).is_err() {
            lint_reject += 1;
        }
        let p1 = fk::prepare(&ftok, &fk::wall());
        let mut s1 = p1.session();
        let p2 = fk::prepare(&ftok, &fk::fuel());
        let mut s2 = p2.session();
        let c3 = p2.compile();
        compiled_chains += c3.is_compiled() as u64;
        if let Some(w) = c3.not_compiled_reason() {
            *why_not.entry(w.to_string()).or_default() += 1;
        }
        for _ in 0..per {
            let r = rand_request(&mut rng, t0, &case);
            let mut sf = bisc::request_facts(&r);
            let mut ff = fk::request_facts(&r);
            let bad = if rng.gen_bool(0.02) { Some(ill_typed(&mut rng, &mut sf, &mut ff)) } else { None };
            illtyped += bad.is_some() as u64;
            let want = bisc::authorize_fast(&base, &case.tok, &sf);
            if want {
                allows += 1;
            } else {
                denies += 1;
            }
            total += 1;
            let got = [
                fk::authorize_main(&fbase, &ftok, &ff),
                s1.authorize(&ff, &fk::wall()),
                s2.authorize(&ff, &fk::fuel()),
                c3.authorize(&ff, &fk::fuel()),
            ];
            fallbacks += c3.last_run().fallback as u64;
            for (k, g) in got.iter().enumerate() {
                let t = &mut tallies[k];
                if g.is_ok() == want {
                    t.same += 1;
                } else {
                    let is_limit = matches!(g, Err(fork::error::Token::RunLimit(_)));
                    if is_limit {
                        t.limit += 1;
                    }
                    t.diff += 1;
                    if shown < 20 {
                        shown += 1;
                        println!("DIVERGENCE [{}] chain {ci} (leaf {}): stock {} / fork {:?}{}\n  request: {:?}\n  blocks:\n{}", names[k], case.leaf, if want { "allow" } else { "deny" }, g, bad.map(|b| format!(" (ill-typed {b})")).unwrap_or_default(), r, (0..case.tok.block_count()).map(|i| case.tok.print_block_source(i).unwrap()).collect::<Vec<_>>().join("\n---\n"));
                    }
                }
            }
        }
        if (ci + 1) % 500 == 0 {
            println!("... {} chains, {total} requests, {:.0} s", ci + 1, start.elapsed().as_secs_f64());
        }
    }
    println!("\n{total} requests ({allows} allowed, {denies} denied by stock; {illtyped} with an ill-typed fact); {lint_reject} of {chains} chains would be rejected by the lint (decided anyway)\n");
    println!("step 3: {compiled_chains} of {chains} chains compiled (not compiled: {why_not:?}); {fallbacks} requests fell back to the generic engine (expression errors)\n");
    println!("| fork path | same decision | different | of which run limits |\n|---|---|---|---|");
    for (k, t) in tallies.iter().enumerate() {
        println!("| {} | {} | {} | {} |", names[k], t.same, t.diff, t.limit);
    }
    println!("\nelapsed {:.0} s", start.elapsed().as_secs_f64());
}
