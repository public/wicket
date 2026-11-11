//! Differential test: the same random ceilings, grants and holder blocks, minted in each design's
//! form, decided by each design. Design A (the fork's compiled evaluator, step 3) is the reference.
//!
//! The generator is biscuit-fast's (src/diff.rs there), with three changes:
//! - each holder block has a design-B equivalent (a narrower zone, or a malformed block where design
//!   A's block is hostile Datalog);
//! - the request paths include four canonical edge paths (`/tokio/`, `/tokio/latest/`, `/repos/acme/`,
//!   `/simple/`) where a glob and a prefix may disagree;
//! - no ill-typed request facts: design B's requests are typed, so there is nothing to mistype.
//!
//! DIFF_CHAINS (default 2000) chains × DIFF_REQS (default 50) requests, seed DIFF_SEED (default 76).

use crate::bisc;
use crate::correct::{append_grant_d, append_narrow_d, mint_d, top};
use crate::designs::{self, Design, Loaded};
use crate::fk;
use crate::model::*;
use crate::zf::{self, Matcher};
use biscuit_auth::{Biscuit, BlockBuilder, KeyPair};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use std::collections::BTreeMap;
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

const HOSTS: &[&str] = crate::correct::UNIVERSE_HOSTS;
const METHODS: &[&str] = crate::correct::UNIVERSE_METHODS;
const PATHS: &[&str] = &[
    "/repos/acme/api/pulls/7",
    "/repos/acme/api/pulls/7/merge",
    "/repos/acme/infra/issues",
    "/repos/acme/secrets-vault/key",
    "/repos/acme/scratch/a",
    "/repos/other/x/issues",
    "/tokio/latest",
    "/tokio/a/b",
    "/simple/requests/",
    "/api/v1/crates/serde",
    "/",
    "/x",
    // edge paths (new here)
    "/tokio/",
    "/tokio/latest/",
    "/repos/acme/",
    "/simple/",
];
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

/// A holder block: design A's Datalog, and what design B appends instead.
struct Holder {
    kind: usize,
    code: String,
    /// The equivalent narrower zone, or None where design A's block is hostile (B refuses those).
    zone: Option<Ceiling>,
}

fn rand_holder(rng: &mut StdRng, t0: u64) -> Holder {
    let kind = rng.gen_range(0..9);
    let t = t0 + rng.gen_range(0..=9) * 3600;
    let mut z = top(t0);
    let code = match kind {
        0 => "check if true;".to_string(),
        1 => r#"approved("g-7f3a", "api.github.com", "GET", "/repos/other/x/issues");"#.into(),
        2 => "approved($g, $h, $m, $p) <- host($h), method($m), path($p), uses_left($g, $n);".into(),
        3 => {
            z.reach.iter_mut().for_each(|x| x.methods = vec!["GET".into()]);
            r#"check if op($o), $o != "http" or method("GET");"#.into()
        }
        4 => {
            z.ops.retain(|o| o != "spawn");
            r#"check if op($o), $o != "spawn";"#.into()
        }
        5 => {
            z.not_after = t;
            format!("check if time($t), $t <= {};", rfc3339(t))
        }
        6 => {
            z.forbid = vec![Forbid { host: "*.org".into(), path_prefix: None }];
            r#"reject if host($h), $h.ends_with(".org");"#.into()
        }
        7 => {
            z.ops = vec!["http".into()];
            z.reach.iter_mut().for_each(|x| x.methods = vec!["GET".into(), "HEAD".into()]);
            r#"check all method($m), {"GET", "HEAD"}.contains($m);"#.into()
        }
        _ => {
            z.max_risk = 1;
            r#"check if risk($r), $r < 2 or op($o), $o != "http";"#.into()
        }
    };
    Holder { kind, code, zone: if kind == 1 || kind == 2 { None } else { Some(z) } }
}

struct Case {
    leaf: usize,
    cs: Vec<Ceiling>,
    grant: Option<Grant>,
    signer: &'static str,
    holder: Option<Holder>,
    toks: Vec<(Design, Biscuit)>,
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
    let mut grant = None;
    let mut signer_key = None;
    let mut signer = "none";
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
        let (k, name) = match rng.gen_range(0..10) {
            0..=4 => (&keys.approver, "approver"),
            5..=6 if leaf > 0 => (&keys.grantor[leaf - 1], "parent grantor"),
            7 => (&keys.grantor[leaf], "leaf's own grantor"),
            _ => (attacker, "attacker"),
        };
        signer_key = Some(k);
        signer = name;
        grant = Some(g);
    }
    let holder = if rng.gen_bool(0.2) { Some(rand_holder(rng, t0)) } else { None };
    let toks = [Design::A, Design::B, Design::C]
        .iter()
        .map(|&d| {
            let mut tok = mint_d(d, &cs, None, &keys.root);
            if let (Some(g), Some(k)) = (&grant, signer_key) {
                tok = append_grant_d(d, &tok, g, k);
            }
            if let Some(h) = &holder {
                tok = match (&h.zone, d) {
                    (Some(z), _) => append_narrow_d(d, &tok, &h.code, z),
                    // Hostile Datalog: A and C get it as is; B's version is the same intent as data,
                    // a grant fact in a first-party block (kind 1) or a block with a rule (kind 2).
                    (None, Design::B) if h.kind == 1 => {
                        let g = Grant { host: "api.github.com".into(), method: "GET".into(), path: "/repos/other/x/issues".into(), ..leaf_grant(t0 + 600, leaf) };
                        tok.append(BlockBuilder::new().fact(zf::grant_fact(&g)).unwrap()).unwrap()
                    }
                    (None, _) => tok.append(BlockBuilder::new().code(&h.code).unwrap()).unwrap(),
                };
            }
            (d, tok)
        })
        .collect();
    Case { leaf, cs, grant, signer, holder, toks }
}

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

fn first_word(e: &str) -> String {
    // "extract: block 6: rules, checks…" → "extract: rules, checks…" (drop block numbers for grouping)
    let s = e.split(": ").filter(|p| !p.starts_with("block ")).collect::<Vec<_>>().join(": ");
    s.chars().take(90).collect()
}

pub fn run() {
    let chains = env("DIFF_CHAINS", 2000);
    let per = env("DIFF_REQS", 50);
    let seed = env("DIFF_SEED", 76);
    let mut rng = StdRng::seed_from_u64(seed);
    let t0 = crate::t0();
    println!("differential test: {chains} random chains × {per} random requests, seed {seed}");
    println!("reference: design A, the fork's compiled evaluator (step 3) with fuel {:?}, decided whether or not the lint accepts the token\n", fk::fuel());
    let mut keys = bisc::Keys::new(5);
    let mut attacker = KeyPair::new();
    let start = Instant::now();
    let (mut total, mut a_allow) = (0u64, 0u64);
    // decision comparisons on tokens both designs loaded
    let (mut b_same, mut b_diff, mut bm_same, mut bm_diff, mut c_same, mut c_diff) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut b_diff_kinds: BTreeMap<String, u64> = BTreeMap::new();
    let mut refused: BTreeMap<String, (u64, u64)> = BTreeMap::new(); // reason -> (chains, requests A allowed on them)
    let mut a_lint_reject = 0u64;
    let mut a_lint_why: BTreeMap<String, u64> = BTreeMap::new();
    let mut not_narrowing = 0u64;
    let mut shown = 0;
    for ci in 0..chains {
        if ci % 100 == 0 {
            keys = bisc::Keys::new(5);
            attacker = KeyPair::new();
        }
        let case = rand_chain(&mut rng, t0, &keys, &attacker);
        let froot = fk::root_pk(&keys.root.public());
        if (1..case.cs.len()).any(|l| crate::plain::narrows(&case.cs[l], &case.cs[l - 1]).is_err()) {
            not_narrowing += 1;
        }
        // A: decide every token (as biscuit-fast did); record the lint separately.
        let abytes = case.toks[0].1.to_vec().unwrap();
        let ftok = fork::Biscuit::from(&abytes, froot.clone()).unwrap();
        if let Err(e) = crate::lint::lint(&ftok, abytes.len(), &designs::lint_policy(Design::A)) {
            a_lint_reject += 1;
            *a_lint_why.entry(first_word(&e)).or_default() += 1;
        }
        let a = fk::prepare(&ftok, &fk::fuel()).compile();
        let bl = designs::load(Design::B, &case.toks[1].1.to_vec().unwrap(), &froot);
        let cl = designs::load(Design::C, &case.toks[2].1.to_vec().unwrap(), &froot);
        let bchain = match &bl {
            Ok(Loaded::B(ch, _)) => Some(ch),
            _ => None,
        };
        let creason = cl.as_ref().err().map(|e| format!("C: {}", first_word(e)));
        let breason = bl.as_ref().err().map(|e| format!("B: {}", first_word(e)));
        for r in [&breason, &creason].into_iter().flatten() {
            refused.entry(r.clone()).or_default().0 += 1;
        }
        for _ in 0..per {
            let r = rand_request(&mut rng, t0, &case);
            let want = a.authorize(&fk::request_facts(&r), &fk::fuel()).is_ok();
            total += 1;
            a_allow += want as u64;
            let op = zf::wicket_op(&r);
            if let Some(ch) = bchain {
                for (m, same, diff) in [(Matcher::Wicket, &mut b_same, &mut b_diff), (Matcher::Model, &mut bm_same, &mut bm_diff)] {
                    let got = ch.allows(&r, &op, m);
                    if got == want {
                        *same += 1;
                    } else {
                        *diff += 1;
                        if m == Matcher::Wicket {
                            let model_agrees = ch.allows(&r, &op, Matcher::Model) == want;
                            let path = if let Op::Http { path, .. } = &r.op { path.as_str() } else { "-" };
                            let k = format!("{} (A {}, B {}, path {path})", if model_agrees { "matcher: wicket glob vs A's prefix" } else { "evaluator" }, if want { "allow" } else { "deny" }, if got { "allow" } else { "deny" });
                            *b_diff_kinds.entry(k).or_default() += 1;
                        }
                        if shown < 12 {
                            shown += 1;
                            println!("DIVERGENCE [{m:?}] chain {ci} (leaf {}, grant signer {}, holder {:?}): A {} / B {}\n  request: {:?}", case.leaf, case.signer, case.holder.as_ref().map(|h| h.kind), if want { "allow" } else { "deny" }, if got { "allow" } else { "deny" }, r);
                        }
                    }
                }
            } else if want {
                refused.get_mut(breason.as_ref().unwrap()).unwrap().1 += 1;
            }
            match &cl {
                Ok(l) => {
                    if l.decide(&r).is_ok() == want {
                        c_same += 1;
                    } else {
                        c_diff += 1;
                    }
                }
                Err(_) => {
                    if want {
                        refused.get_mut(creason.as_ref().unwrap()).unwrap().1 += 1;
                    }
                }
            }
        }
        if (ci + 1) % 500 == 0 {
            println!("... {} chains, {total} requests, {:.0} s", ci + 1, start.elapsed().as_secs_f64());
        }
    }
    let cm = designs::C_MISMATCH.load(std::sync::atomic::Ordering::Relaxed);
    let cn = designs::C_DECISIONS.load(std::sync::atomic::Ordering::Relaxed);
    println!("\n{total} requests: design A allowed {a_allow}, denied {}.", total - a_allow);
    println!("{not_narrowing} of {chains} chains have a link wider than its parent somewhere (plain::narrows); all were decided by intersection.");
    println!("design A's lint would reject {a_lint_reject} of {chains} chains (decided anyway): {a_lint_why:?}\n");
    println!("## Decisions on tokens the design loaded\n\n| design | same as A | different |\n|---|---|---|");
    println!("| B, CompiledZone | {b_same} | {b_diff} |");
    println!("| B, model matcher | {bm_same} | {bm_diff} |");
    println!("| C (decides with A) | {c_same} | {c_diff} |");
    println!("\nC's built-in cross-check (B's decision next to A's on C tokens): {cm} disagreements in {cn} decisions.");
    println!("\n## B (CompiledZone) disagreements by cause\n");
    for (k, v) in &b_diff_kinds {
        println!("- {v}: {k}");
    }
    println!("\n## Tokens refused at load (B: extractor; C: lint + extractor)\n\n| reason | chains | requests design A allowed on them |\n|---|---|---|");
    for (k, (c, a)) in &refused {
        println!("| {k} | {c} | {a} |");
    }
    println!("\nelapsed {:.0} s", start.elapsed().as_secs_f64());
}
