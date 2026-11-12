//! The three oracles:
//! 1. a single-block token decides as wicket-core's `CompiledZone::evaluate`, on every example
//!    manifest and the subset tests' zones;
//! 2. a multi-block token decides as the intersection of each block's `CompiledZone`, on random chains;
//! 3. the compiled evaluator decides as the fork's generic engine (stock `AuthorizerBuilder` path),
//!    failed checks included, on random chains, grants and requests of every kind.

mod common;
use common::*;
use std::time::Instant;
use wicket_authz::*;
use wicket_core::{CompiledZone, RiskClass, ZoneSpec};

#[test]
fn oracle1_single_block_equals_compiled_zone() {
    let keys = Keys::new(0);
    let zones = all_zones();
    assert_eq!(zones.len(), example_zones().len() + 7 + 32);
    let (mut checked, mut kinds, mut max_steps, mut max_generic) = (0usize, [0usize; 3], 0u64, 0u64);
    let start = Instant::now();
    for z in &zones {
        let c = Ceiling::from_zone(z, "b0", T0 + 3600, vec![keys.approver.public()]).unwrap_or_else(|e| panic!("{}: {e}", z.name));
        let tok = mint(&keys.root, TENANT, "trigger:t", &c).unwrap();
        let l = load_ok(&tok, &keys);
        assert!(l.is_compiled(), "zone {} isn't compiled", z.name);
        let cz = CompiledZone::new(z.clone()).unwrap();
        let mut generic = l.generic_session();
        let (hosts, paths) = probes(&[z]);
        for h in &hosts {
            for p in &paths {
                for m in METHODS {
                    let o = op(&z.name, m, h, p);
                    let want = kind_of_verdict(&cz.evaluate(&o));
                    let got = l.decide(&http_request("b0", &o));
                    assert!(wicket_core::never_reachable(h).is_some() || !l.last_fell_back());
                    max_steps = max_steps.max(l.last_steps());
                    if checked % 8 == 0 && wicket_core::never_reachable(h).is_none() {
                        // The generic engine (the compiled evaluator's fallback) on a sample.
                        let (res, steps) = generic.authorize(&http_request("b0", &o));
                        assert_eq!(l.classify(res), got);
                        max_generic = max_generic.max(steps);
                    }
                    assert_eq!(
                        kind_of(&got),
                        want,
                        "zone {}: {m} {h}{p} (risk {:?}): token {got:?}, zone {:?}",
                        z.name,
                        o.risk,
                        cz.evaluate(&o)
                    );
                    kinds[want as usize] += 1;
                    checked += 1;
                }
            }
        }
    }
    println!("oracle 1: {checked} decisions on {} zones in {:?}: {kinds:?} (allow, forbidden, needs grant); max steps: compiled {max_steps}, generic {max_generic}", zones.len(), start.elapsed());
    assert!(max_generic <= MEASURED_MAX_STEPS, "a legitimate request took {max_generic} steps (measured max {MEASURED_MAX_STEPS})");
    assert!(kinds.iter().all(|&k| k > 1000), "too few of some kind: {kinds:?}");
}

/// #111: a child `subset::check` proves within its parent adds no authority, as Biscuit decides it:
/// the child's ceiling alone decides as the chain parent → child on every probe. The wider #111
/// cases (classes that match `/` under a parent `*`) must show a probe where they differ, so the
/// probes can see the bug the subset check had.
#[test]
fn proved_subsets_decide_as_their_chain() {
    use wicket_core::subset;
    let keys = Keys::new(1);
    let parents = subset_cases::parents();
    let (mut proved, mut checked) = (0, 0);
    for c in subset_cases::children() {
        let p = parents.iter().find(|p| p.key == c.parent).unwrap();
        let bounds = subset::Bounds {
            zone: &p.zone,
            images: p.images.clone(),
            llm_remaining: p.llm_remaining,
            llm_input_remaining: None,
            time_remaining: p.time_remaining,
            child_slots: p.child_slots,
        };
        let within = subset::check(&subset::Ask { zone: &c.zone, image: &c.image, max_children: c.max_children }, &bounds).is_ok();
        let ceiling = |z: &ZoneSpec, b: &str| Ceiling::from_zone(z, b, T0 + 3600, vec![keys.approver.public()]).unwrap();
        let alone = load_ok(&mint(&keys.root, TENANT, "trigger:t", &ceiling(&c.zone, &box_id(1))).unwrap(), &keys);
        let chain = load_ok(&mint_chain(&[ceiling(&p.zone, &box_id(0)), ceiling(&c.zone, &box_id(1))], &keys), &keys);
        let (hosts, paths) = probes(&[&p.zone, &c.zone]);
        let mut differs = None;
        for h in &hosts {
            for path in &paths {
                for m in METHODS {
                    let o = op(&c.zone.name, m, h, path);
                    let (a, b) =
                        (kind_of(&alone.decide(&http_request(&box_id(1), &o))), kind_of(&chain.decide(&http_request(&box_id(1), &o))));
                    checked += 1;
                    if a != b && differs.is_none() {
                        differs = Some(format!("{m} {h}{path}: alone {a}, chain {b}"));
                    }
                }
            }
        }
        if within {
            proved += 1;
            assert!(differs.is_none(), "{} is proved within {}, but {}", c.name, c.parent, differs.unwrap());
        }
        if c.name.starts_with("g-") && !c.within {
            assert!(!within, "{} must not be proved within {}", c.name, c.parent);
            assert!(differs.is_some(), "{}: no probe shows the extra reach", c.name);
        }
    }
    println!("proved subsets: {proved} children, {checked} decisions");
    assert!(proved >= 10, "only {proved} children proved within");
}

// --- oracle 2 ------------------------------------------------------------------------------------

const HOSTS: [&str; 6] = ["api.github.com", "*.github.com", "github.com", "docs.rs", "*.example.com", "api.example.com"];
const GLOBS: [&str; 12] = [
    "/**",
    "/repos/acme/**",
    "/repos/acme/*",
    "/repos/acme/api/**",
    "/repos/*/issues",
    "/repos/acme/{api,web}/**",
    "/tokio/*",
    "/v1/*/items/**",
    "/repos/acme/scratch/**",
    "/a?c/**",
    "**/merge",
    "/repos/acme/api/pulls/*/merge",
];

fn random_rule(rng: &mut Rng) -> wicket_core::ReachRule {
    let methods: Vec<String> = METHODS.iter().filter(|_| rng.chance(50)).map(|m| m.to_string()).collect();
    let paths: Vec<String> = (0..rng.below(3)).map(|_| rng.pick(&GLOBS).to_string()).collect();
    wicket_core::ReachRule { host: rng.pick(&HOSTS).to_string(), methods, paths, allow_dangerous: rng.chance(30) }
}

fn random_forbid(rng: &mut Rng) -> wicket_core::manifest::ForbidRule {
    let paths: Vec<String> = (0..1 + rng.below(2)).map(|_| rng.pick(&GLOBS[1..]).to_string()).collect();
    wicket_core::manifest::ForbidRule { host: rng.pick(&HOSTS).to_string(), paths }
}

fn random_zone(rng: &mut Rng, name: &str) -> ZoneSpec {
    let mut z =
        wicket_core::Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone: {{ name: {name}, llm: {{}} }}\n")).unwrap().zone;
    for _ in 0..2 + rng.below(5) {
        z.reach.push(random_rule(rng));
    }
    for _ in 0..rng.below(3) {
        z.forbid.push(random_forbid(rng));
    }
    z
}

/// A child of `parent`, mostly narrower (rules, methods or paths dropped, forbids added, dangerous
/// flags cleared) and sometimes wider (a random new rule): the token must intersect either way.
fn random_child(rng: &mut Rng, parent: &ZoneSpec, name: &str) -> ZoneSpec {
    let mut z = parent.clone();
    z.name = name.into();
    z.forbid.clear();
    z.reach.retain(|_| rng.chance(80));
    for r in &mut z.reach {
        r.methods.retain(|_| rng.chance(85));
        if rng.chance(15) {
            r.paths = vec![rng.pick(&GLOBS).to_string()];
        }
        r.allow_dangerous &= rng.chance(70);
    }
    if rng.chance(25) {
        z.reach.push(random_rule(rng));
    }
    if rng.chance(30) {
        z.forbid.push(random_forbid(rng));
    }
    z
}

#[test]
fn oracle2_chain_equals_intersection_of_zones() {
    let keys = Keys::new(0);
    let mut rng = Rng(76);
    let (mut checked, mut kinds) = (0usize, [0usize; 3]);
    let start = Instant::now();
    for chain in 0..120 {
        let depth = 1 + rng.below(4);
        let mut zones = vec![random_zone(&mut rng, &format!("c{chain}-0"))];
        for i in 1..=depth {
            let child = random_child(&mut rng, &zones[i - 1], &format!("c{chain}-{i}"));
            zones.push(child);
        }
        let compiled: Vec<CompiledZone> = zones.iter().map(|z| CompiledZone::new(z.clone()).unwrap()).collect();
        let cs: Vec<Ceiling> = zones
            .iter()
            .enumerate()
            .map(|(i, z)| Ceiling::from_zone(z, &box_id(i), T0 + 3600, vec![keys.approver.public()]).unwrap())
            .collect();
        let tok = mint_chain(&cs, &keys);
        let l = load_ok(&tok, &keys);
        assert!(l.is_compiled(), "chain {chain} isn't compiled");
        let zr: Vec<&ZoneSpec> = zones.iter().collect();
        let (hosts, paths) = probes(&zr);
        for _ in 0..150 {
            // Half the requests aim at one of the leaf's reach rules, so that enough are allowed.
            let leaf = &zones[depth];
            let o = match leaf.reach.get(rng.below(leaf.reach.len() + 1)) {
                Some(rule) if rng.chance(50) && !rule.methods.is_empty() && !rule.paths.is_empty() => {
                    let p = paths_for(rng.pick(&rule.paths));
                    op("z", rng.pick(&rule.methods), &rule.host.replace("*.", "a."), rng.pick(&p[..3]))
                }
                _ => op("z", rng.pick(&METHODS), rng.pick(&hosts), rng.pick(&paths)),
            };
            let want = intersect(&compiled, &o);
            let got = l.decide(&http_request(&box_id(depth), &o));
            assert_eq!(
                kind_of(&got),
                want,
                "chain {chain}: {} {}{} (risk {:?}): token {got:?}; zones {zones:#?}",
                o.method,
                o.host,
                o.path,
                o.risk
            );
            kinds[want as usize] += 1;
            checked += 1;
        }
    }
    println!("oracle 2: {checked} decisions on 120 random chains in {:?}: {kinds:?} (allow, forbidden, needs grant)", start.elapsed());
    assert!(kinds.iter().all(|&k| k > 500), "too few of some kind: {kinds:?}");
}

// --- oracle 3 ------------------------------------------------------------------------------------

/// A random request against the depth-`leaf` chain of `common::level`: every op kind, times around
/// the expiries, boxes in and out of the subtree, epochs and ledger states around the grant.
fn random_request(rng: &mut Rng, leaf: usize) -> Request {
    let hosts =
        ["api.github.com", "x.githubusercontent.com", "crates.io", "static.crates.io", "docs.rs", "a.internal", "pypi.org", "evil.com"];
    let paths = [
        "/repos/acme/api/pulls/7",
        "/repos/acme/api/pulls/7/merge",
        "/repos/acme/scratch/x",
        "/repos/acme/secrets-vault/k",
        "/repos/other/x",
        "/api/v1/crates/serde",
        "/tokio/latest",
        "/tokio/latest/x",
        "/simple/foo/",
        "/",
    ];
    let risks = [
        RiskClass::R0Read,
        RiskClass::R1ReadScoped,
        RiskClass::R2WriteReversible,
        RiskClass::R3ExternalOrIrreversible,
        RiskClass::R4ExecOrPrivilege,
    ];
    let action = match rng.below(10) {
        0 => Action::Spawn {
            image: rng.pick(&["img:agent", "img:rust", "img:py", "img:evil"]).to_string(),
            isolation: 1 + rng.below(2) as i64,
            mem_bytes: (64i64 << 20) << rng.below(8),
            cpus_milli: 100 * (1 + rng.below(40)) as i64,
            pids: 16 << rng.below(8),
            timeout_s: 600 * (1 + rng.below(40)) as i64,
        },
        1 => Action::Llm { used_requests: rng.below(3500) as i64, used_output_tokens: rng.below(4_500_000) as i64 },
        2 => Action::Msg { from: rng.pick(&["ops", "other", ""]).to_string() },
        _ => Action::Http {
            host: rng.pick(&hosts).to_string(),
            method: rng.pick(&METHODS).to_string(),
            path: rng.pick(&paths).to_string(),
            risk: *rng.pick(&risks),
            inject: match rng.below(4) {
                0 => None,
                1 => Some("api.github.com|Authorization|other".into()),
                _ => Some(GH_INJECT.into()),
            },
        },
    };
    let box_id = match rng.below(6) {
        0 => box_id(leaf.saturating_sub(1)),
        1 => format!("{}/kid", box_id(leaf)),
        2 => "b0/b9".into(),
        _ => box_id(leaf),
    };
    Request {
        time: T0 + [0, 600, 1500, 1501, 2 * 3600, 3 * 3600, 6 * 3600 + 1, 9 * 3600][rng.below(8)],
        tenant: if rng.chance(95) { TENANT.into() } else { "other".into() },
        box_id,
        epoch: 2 + rng.below(3) as i64,
        action,
        uses_left: match rng.below(4) {
            0 => vec![],
            1 => vec![("g-7f3a".into(), 0)],
            _ => vec![("g-7f3a".into(), 1 + rng.below(3) as i64)],
        },
    }
}

/// The tokens oracle 3 runs on: chains of depth 0..=5, without a grant, with the leaf's grant from
/// the approver, and with a grant from the parent's grantor.
fn oracle3_tokens() -> Vec<(usize, Loaded)> {
    let mut tokens = Vec::new();
    for depth in 0..=5 {
        let keys = Keys::new(5);
        let cs = ceilings(depth, &keys);
        let plain = mint_chain(&cs, &keys);
        let mut variants = vec![plain.clone(), grant(&plain, &keys.approver, &leaf_grant(depth)).unwrap()];
        if depth > 0 {
            let g = Grant { method: "POST".into(), path: "/repos/acme/api/issues".into(), ..leaf_grant(depth) };
            variants.push(grant(&plain, &keys.grantor[depth - 1], &g).unwrap());
        }
        for t in variants {
            let l = load_ok(&t, &keys);
            assert!(l.is_compiled(), "depth {depth} isn't compiled");
            tokens.push((depth, l));
        }
    }
    tokens
}

fn same(
    i: usize,
    l: &Loaded,
    r: &Request,
    fast: &Result<usize, biscuit_auth::error::Token>,
    slow: Result<usize, biscuit_auth::error::Token>,
) {
    assert_eq!(fast.is_ok(), slow.is_ok(), "request {i}: compiled {fast:?}, generic {slow:?}; {r:?}");
    if let (Err(a), Err(b)) = (fast, &slow) {
        assert_eq!(a, b, "request {i}: different failures; {r:?}");
    }
    assert_eq!(l.classify(fast.clone()), l.classify(slow), "request {i}");
}

/// Compiled vs generic engine on `n` random requests; every `stock_every`-th request also through
/// the stock `AuthorizerBuilder` path (a new authorizer per request, about 1 ms each at depth 5).
fn differential(n: usize, stock_every: usize) {
    let tokens = oracle3_tokens();
    let mut sessions: Vec<_> = tokens.iter().map(|(_, l)| l.generic_session()).collect();
    let mut rng = Rng(3);
    let start = Instant::now();
    let (mut allowed, mut stock, mut max_generic, mut max_compiled, mut max_stock) = (0usize, 0usize, 0u64, 0u64, 0u64);
    for i in 0..n {
        let k = i % tokens.len();
        let (depth, l) = &tokens[k];
        let r = random_request(&mut rng, *depth);
        let fast = l.authorize_compiled(&r);
        assert!(!l.last_fell_back(), "request {i} ran in the generic engine: the comparison would be generic vs generic");
        max_compiled = max_compiled.max(l.last_steps());
        let (slow, steps) = sessions[k].authorize(&r);
        max_generic = max_generic.max(steps);
        same(i, l, &r, &fast, slow);
        if i % stock_every == 0 {
            let (slow, steps) = l.authorize_generic(&r);
            max_stock = max_stock.max(steps);
            same(i, l, &r, &fast, slow);
            stock += 1;
        }
        allowed += usize::from(fast.is_ok());
    }
    println!(
        "oracle 3: {n} requests ({stock} also through AuthorizerBuilder) on {} tokens in {:?}: {allowed} allowed; max steps per request: compiled {max_compiled}, generic {max_generic}, AuthorizerBuilder {max_stock} (budget {STEP_BUDGET})",
        tokens.len(),
        start.elapsed()
    );
    assert!(allowed > n / 50 && allowed < n / 2, "allowed {allowed} of {n}");
    assert!(max_compiled <= 1_000, "a legitimate request took {max_compiled} compiled steps");
    assert!(
        max_generic.max(max_stock) <= MEASURED_MAX_STEPS,
        "a legitimate request took {} steps (measured max {MEASURED_MAX_STEPS})",
        max_generic.max(max_stock)
    );
}

/// Random requests against the generic engine (the prepared session the compiled evaluator falls
/// back to), one in 20 also through the stock AuthorizerBuilder path. 25k by default, to keep a
/// debug `cargo test` short (the generic engine compiles every regex on every evaluation, about
/// 0.4 ms a request); set `WICKET_AUTHZ_DIFF_REQUESTS` for more.
#[test]
fn oracle3_compiled_equals_generic_engine() {
    let n = std::env::var("WICKET_AUTHZ_DIFF_REQUESTS").ok().and_then(|s| s.parse().ok()).unwrap_or(25_000);
    differential(n, 20);
}

/// 100k requests, every one through both the generic engine and the AuthorizerBuilder path (a few
/// minutes): `cargo test -p wicket-authz --test oracles -- --ignored`. Run on every change to the
/// fork or rebase onto upstream.
#[test]
#[ignore]
fn oracle3_compiled_equals_authorizer_builder_100k() {
    differential(100_000, 1);
}

/// #143: npm's scoped-package form (`/@scope%2fname`) is decided on its decoded path, and the
/// zone, the compiled token and the generic engine agree on it, as on the unencoded spelling: a
/// forbid on `/@scope/**` blocks both, a reach rule allows both.
#[test]
fn npm_scoped_paths_decide_alike_in_every_oracle() {
    let keys = Keys::new(0);
    let z = wicket_core::Manifest::from_yaml(
        "task: t\nagent: { name: a }\nzone:\n  name: npm\n  llm: {}\n  reach:\n    - { host: registry.npmjs.org, methods: [GET], paths: [\"/**\"] }\n    - { host: npm.internal.example, methods: [GET], paths: [\"/@acme/**\"] }\n  forbid:\n    - { host: registry.npmjs.org, paths: [\"/@evil/**\", \"/@types/secret\"] }\n",
    )
    .unwrap()
    .zone;
    let c = Ceiling::from_zone(&z, "b0", T0 + 3600, vec![keys.approver.public()]).unwrap();
    let l = load_ok(&mint(&keys.root, TENANT, "trigger:t", &c).unwrap(), &keys);
    let cz = CompiledZone::new(z.clone()).unwrap();
    let mut generic = l.generic_session();
    let names = ["@types%2fnode", "@types%2Fsecret", "@evil%2fpkg", "@acme%2flib", "@babel%2fcore", "@eslint-community%2feslint-utils"];
    let mut kinds = [0usize; 3];
    for h in ["registry.npmjs.org", "npm.internal.example"] {
        for name in names {
            for tail in ["", "/", "/1.0.0", "/-/x-1.0.0.tgz"] {
                let raw = format!("/{name}{tail}");
                let decoded = wicket_core::canonical_path(&raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
                let plain = raw.replacen("%2f", "/", 1).replacen("%2F", "/", 1);
                assert_eq!(decoded, plain.as_str(), "{raw}");
                for m in METHODS {
                    let o = op(&z.name, m, h, &decoded);
                    let want = kind_of_verdict(&cz.evaluate(&o));
                    assert_eq!(want, kind_of_verdict(&cz.evaluate(&op(&z.name, m, h, &plain))), "{m} {h}{raw}");
                    let got = l.decide(&http_request("b0", &o));
                    assert_eq!(kind_of(&got), want, "{m} {h}{raw}: token {got:?}");
                    let (res, _) = generic.authorize(&http_request("b0", &o));
                    assert_eq!(l.classify(res), got, "{m} {h}{raw}: generic engine");
                    kinds[want as usize] += 1;
                }
            }
        }
    }
    assert!(kinds.iter().all(|&k| k > 0), "every kind decided: {kinds:?}");
}
