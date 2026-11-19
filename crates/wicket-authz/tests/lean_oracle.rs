//! The Lean spec as an oracle (#322): wicket-core's decisions, on this crate's fixtures (the example
//! manifests' zones and the subset tests' parents and children, with `oracles.rs`'s probes) and on
//! generated cases, must be the spec's (verification/lean, `Oracle.lean`). Any divergence fails,
//! with the case.
//!
//! Ignored by default: it needs the pinned Lean toolchain (`ci/lean.sh` installs it and runs this).
//! `LAKE` names the `lake` binary (default: `lake` on `PATH`).

mod common;
use common::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use wicket_authz::{load, mint, Ceiling, Loaded};
use wicket_core::manifest::{ForbidRule, Isolation, OnOutputFull, ReachRule, UnlistedHosts};
use wicket_core::{subset, CompiledZone, ZoneSpec};

/// A finite `f32` as `m × 2^e`, exactly; `null` if not finite.
fn f32_json(x: f32) -> Value {
    if !x.is_finite() {
        return Value::Null;
    }
    let bits = x.to_bits();
    let (sign, exp, mant) = (bits >> 31, (bits >> 23) & 0xff, i64::from(bits & 0x7f_ffff));
    let (m, e) = if exp == 0 { (mant, -149) } else { (mant | 0x80_0000, i64::from(exp) - 150) };
    json!({ "m": if sign == 1 { -m } else { m }, "e": e })
}

fn zone_json(z: &ZoneSpec) -> Value {
    let ms = |d: Result<Duration, _>| d.ok().map(|d: Duration| d.as_millis() as u64);
    json!({
        "name": z.name,
        "isolation": match z.isolation { Isolation::Runc => 1, Isolation::Gvisor => 2 },
        "reach": z.reach.iter().map(|r| json!({
            "host": r.host, "methods": r.methods, "paths": r.paths, "dangerous": r.allow_dangerous,
        })).collect::<Vec<_>>(),
        "forbid": z.forbid.iter().map(|f| json!({ "host": f.host, "paths": f.paths })).collect::<Vec<_>>(),
        "hide": z.unlisted_hosts == UnlistedHosts::Hide,
        "wildcards_forbid": z.wildcards.forbid,
        "max_names": z.wildcards.max_names,
        "inject": z.inject.iter().map(|i| json!([i.host, i.header, i.format, i.secret])).collect::<Vec<_>>(),
        "llm": z.llm.as_ref().map(|l| json!({
            "provider": l.provider, "secret": l.secret, "upstream": l.upstream, "server_tools": l.allow_server_tools,
            "max_requests": l.max_requests, "max_output": l.max_output_tokens, "max_input": l.max_input_tokens,
            "models": l.models,
        })),
        "escalation": { "request": z.escalation.request, "grant": z.escalation.grant },
        "limits": {
            "memory": subset::parse_bytes(&z.limits.memory),
            "cpus": f32_json(z.limits.cpus),
            "pids": z.limits.pids,
            "output": subset::parse_bytes(&z.limits.output),
            "stop_on_full": z.limits.on_output_full == OnOutputFull::Stop,
            "timeout_ms": ms(z.limits.timeout()),
            "authority_ms": ms(z.limits.authority()),
        },
        "accept_from": z.accept_from,
    })
}

/// The cases, and what wicket-core decided for each (as the oracle prints it).
#[derive(Default)]
struct Cases {
    zones: Vec<Value>,
    cases: Vec<Value>,
    rust: Vec<String>,
    /// What each case is, for a failure message.
    what: Vec<String>,
}

impl Cases {
    fn zone(&mut self, z: &ZoneSpec) -> usize {
        self.zones.push(zone_json(z));
        self.zones.len() - 1
    }

    fn push(&mut self, case: Value, rust: String, what: String) {
        self.cases.push(case);
        self.rust.push(rust);
        self.what.push(what);
    }

    /// One request against a compiled zone (zone index `zi`).
    fn eval(&mut self, zi: usize, cz: &CompiledZone, m: &str, h: &str, p: &str) {
        let o = op(&cz.name, m, h, p);
        let rust = ["allow", "forbidden", "needs_grant"][kind_of_verdict(&cz.evaluate(&o)) as usize].to_string();
        let case = json!({ "kind": "eval", "zone": zi, "op": {
            "method": o.method, "host": o.host, "path": o.path, "risk": o.risk.rank(),
            "unreachable": wicket_core::never_reachable(&o.host).is_some(),
        }});
        self.push(case, rust, format!("zone {}: {m} {h}{p} (risk {:?})", cz.name, o.risk));
    }

    fn check(&mut self, parent: &ZoneSpec, child: &ZoneSpec, b: &subset::Bounds<'_>, ask: &subset::Ask<'_>, what: &str) {
        let images_ok = wicket_core::image::matching(ask.image, &b.images).is_some()
            && child.images.iter().all(|i| wicket_core::image::matching(i, &b.images).is_some());
        let (pi, ci) = (self.zone(parent), self.zone(child));
        let rust = subset::check(ask, b).is_ok().to_string();
        let case = json!({ "kind": "check", "parent": pi, "child": ci, "max_children": ask.max_children, "bounds": {
            "images_ok": images_ok, "llm_remaining": b.llm_remaining.map(|(r, t)| json!([r, t])),
            "llm_input_remaining": b.llm_input_remaining, "time_remaining_ms": b.time_remaining.as_millis() as u64,
            "child_slots": b.child_slots,
        }});
        self.push(case, rust, format!("check {what}"));
        let rust = subset::reach_within(parent, child).is_ok().to_string();
        self.push(json!({ "kind": "reach_within", "outer": pi, "inner": ci }), rust, format!("reach_within {what}"));
    }

    /// Whether zone `zi`'s boxes may call `model` (#366).
    fn model(&mut self, zi: usize, z: &ZoneSpec, model: &str) {
        let rust = z.llm.as_ref().is_some_and(|l| l.allows_model(model)).to_string();
        let what = format!("zone {} ({:?}) calls {model}", z.name, z.llm.as_ref().and_then(|l| l.models.clone()));
        self.push(json!({ "kind": "model", "zone": zi, "model": model }), rust, what);
    }

    /// `manifest::accepts` (#250, #411).
    fn accepts(&mut self, list: &[String], zone: &str, principal: Option<&str>) {
        let rust = wicket_core::manifest::accepts(list, zone, principal).to_string();
        let case = json!({ "kind": "accepts", "list": list, "zone": zone, "principal": principal });
        self.push(case, rust, format!("accepts({list:?}, {zone:?}, {principal:?})"));
    }

    /// One request against a token of one block per zone (block 0, then spawn blocks appended as a
    /// node's `derive_child` appends them), decided by the token.
    fn chain(&mut self, zis: &[usize], l: &Loaded, depth: usize, m: &str, h: &str, p: &str) {
        let o = op("z", m, h, p);
        let rust = ["allow", "forbidden", "needs_grant"][kind_of(&l.decide(&http_request(&box_id(depth), &o))) as usize].to_string();
        let case = json!({ "kind": "chain", "zones": zis, "op": {
            "method": o.method, "host": o.host, "path": o.path, "risk": o.risk.rank(),
            "unreachable": wicket_core::never_reachable(&o.host).is_some(),
        }});
        self.push(case, rust, format!("chain {zis:?}: {m} {h}{p} (risk {:?})", o.risk));
    }
}

// --- generators ------------------------------------------------------------------------------

/// A glob in the spec's language: segments of literals, `*` and `?`, or `**`.
fn gen_glob(rng: &mut Rng) -> String {
    let n = 1 + rng.below(4);
    let mut segs: Vec<String> = Vec::new();
    for _ in 0..n {
        if rng.chance(20) {
            segs.push("**".into());
        } else {
            let len = rng.below(4);
            segs.push((0..len).map(|_| *rng.pick(&["a", "b", "A", "*", "?", ".", "-", "ab", "**"])).collect());
        }
    }
    let lead = if rng.chance(92) { "/" } else { "" };
    let tail = if rng.chance(10) { "/" } else { "" };
    format!("{lead}{}{tail}", segs.join("/"))
}

fn gen_path(rng: &mut Rng) -> String {
    let n = rng.below(5);
    let segs: Vec<String> =
        (0..n).map(|_| (0..rng.below(4)).map(|_| *rng.pick(&["a", "b", "A", "B", ".", "-", "\u{e9}"])).collect()).collect();
    let tail = if rng.chance(15) { "/" } else { "" };
    format!("/{}{tail}", segs.join("/"))
}

const HOSTS: [&str; 9] = ["a.test", "b.a.test", "c.b.a.test", "A.test", "b.test", "x.a.test", "a.test.", "test", "B.A.TEST"];
const HOST_PATTERNS: [&str; 9] = ["a.test", "*.a.test", "*.test", "*.b.a.test", "A.TEST", "*.A.test", "b.a.test", "*.", "*.c.b.a.test"];

fn gen_rule(rng: &mut Rng) -> ReachRule {
    let ms = ["GET", "HEAD", "POST", "put", "DELETE"];
    let mut methods: Vec<String> = (0..1 + rng.below(3)).map(|_| rng.pick(&ms).to_string()).collect();
    methods.dedup();
    ReachRule {
        host: rng.pick(&HOST_PATTERNS).to_string(),
        methods,
        paths: (0..1 + rng.below(2)).map(|_| gen_glob(rng)).collect(),
        allow_dangerous: rng.chance(30),
    }
}

fn gen_forbid(rng: &mut Rng) -> ForbidRule {
    ForbidRule { host: rng.pick(&HOST_PATTERNS).to_string(), paths: (0..1 + rng.below(2)).map(|_| gen_glob(rng)).collect() }
}

fn base_zone() -> ZoneSpec {
    wicket_core::Manifest::from_yaml("task: t\nagent: { name: a }\nzone:\n  name: g\n  limits: { memory: 1g, cpus: 1, timeout: 30m }\n")
        .unwrap()
        .zone
}

fn gen_zone(rng: &mut Rng, base: &ZoneSpec) -> ZoneSpec {
    let mut z = base.clone();
    z.reach = (0..1 + rng.below(3)).map(|_| gen_rule(rng)).collect();
    z.forbid = (0..rng.below(3)).map(|_| gen_forbid(rng)).collect();
    z
}

/// A child of `p`: mostly narrowings of its rules (so some are admitted), sometimes fresh ones.
fn gen_child(rng: &mut Rng, p: &ZoneSpec) -> ZoneSpec {
    let mut c = p.clone();
    c.name = "c".into();
    c.reach = Vec::new();
    for r in &p.reach {
        if !rng.chance(80) {
            continue;
        }
        c.reach.push({
            let mut r = r.clone();
            if rng.chance(50) {
                let mut paths = Vec::new();
                for g in &r.paths {
                    // Under the rule, beside it (a string prefix, not a segment prefix), or anything.
                    let stem = g.trim_end_matches("/**");
                    paths.push(match rng.below(4) {
                        0 => format!("{stem}/x"),
                        1 => format!("{stem}x*"),
                        2 => format!("{stem}/*/x"),
                        _ => gen_glob(rng),
                    });
                }
                r.paths = paths;
            }
            if rng.chance(20) {
                r.host = rng.pick(&HOST_PATTERNS).to_string();
            }
            if rng.chance(20) {
                r.allow_dangerous = !r.allow_dangerous;
            }
            r
        });
    }
    if rng.chance(30) {
        c.reach.push(gen_rule(rng));
    }
    if rng.chance(70) {
        c.forbid.clone_from(&p.forbid);
    }
    if rng.chance(40) {
        c.forbid.push(gen_forbid(rng));
    }
    c
}

const MODELS: [&str; 6] = ["claude-opus-4-5", "claude-opus-4-5-x", "claude-sonnet-4-5", "claude-", "claude", "gpt-x"];
const MODEL_PATTERNS: [&str; 9] =
    ["claude-*", "claude-opus-*", "claude-sonnet-*", "claude-opus-4-5", "claude-sonnet-4-5", "c*", "*", "gpt-x", "claude-opus-4-5*"];
const SENDERS: [&str; 6] = ["g", "ops", "dev", "other", "spiffe://acc.test/t/t0/z/ops/a/x", "spiffe://acc.test/t/t0/z/dev/a/y"];

/// A model list (#366): any model, or one to three of `MODEL_PATTERNS`.
fn gen_models(rng: &mut Rng, none_pct: u64) -> Option<Vec<String>> {
    if rng.chance(none_pct) {
        return None;
    }
    let mut ms: Vec<String> = (0..1 + rng.below(3)).map(|_| rng.pick(&MODEL_PATTERNS).to_string()).collect();
    ms.dedup();
    Some(ms)
}

/// An `accept_from` list of zone and principal entries.
fn gen_accept(rng: &mut Rng) -> Vec<String> {
    let mut a: Vec<String> = (0..rng.below(4)).map(|_| rng.pick(&SENDERS).to_string()).collect();
    a.dedup();
    a
}

/// A zone with a model route, whose models and `accept_from` vary, and a child of it that narrows
/// or widens them.
fn gen_route_pair(rng: &mut Rng) -> (ZoneSpec, ZoneSpec) {
    let mut p = wicket_core::Manifest::from_yaml(
        "task: t\nagent: { name: a }\nzone:\n  name: g\n  llm: { max_requests: 10, max_output_tokens: 1000 }\n  limits: { memory: 1g, cpus: 1, timeout: 30m }\n",
    )
    .unwrap()
    .zone;
    p.llm.as_mut().unwrap().models = gen_models(rng, 25);
    p.accept_from = gen_accept(rng);
    let mut c = p.clone();
    c.name = "c".into();
    c.llm.as_mut().unwrap().models = gen_models(rng, 15);
    c.accept_from = gen_accept(rng);
    (p, c)
}

fn gen_canon(rng: &mut Rng) -> String {
    let alphabet = [
        "/", "/", "a", "b", ".", "..", "%", "%2F", "%2f", "%2E", "%41", "%7E", "%20", "%C3%A9", "%e9", ";", "\\", "?", "?x=1", "@",
        "@s%2fn", "-", "\u{e9}", "%2",
    ];
    let n = rng.below(7);
    let body: String = (0..n).map(|_| *rng.pick(&alphabet)).collect();
    if rng.chance(90) {
        format!("/{body}")
    } else {
        body
    }
}

// --- running the spec ------------------------------------------------------------------------

fn lean_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../verification/lean")
}

fn run_lean(file: &Path) -> Vec<String> {
    let lake = std::env::var("LAKE").unwrap_or_else(|_| "lake".into());
    let built = Command::new(&lake).arg("build").current_dir(lean_dir()).status().unwrap_or_else(|e| panic!("{lake}: {e}"));
    assert!(built.success(), "lake build failed");
    let out = Command::new(&lake)
        .args(["env", "lean", "--run", "Oracle.lean"])
        .arg(file)
        .current_dir(lean_dir())
        .output()
        .unwrap_or_else(|e| panic!("{lake}: {e}"));
    assert!(out.status.success(), "the oracle failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The decisions follow the marker; anything before it is what compiling Oracle.lean printed.
    let (before, decisions) = stdout
        .split_once(
            "--- decisions
",
        )
        .unwrap_or_else(|| panic!("the oracle printed no decisions: {stdout}"));
    for l in before.lines() {
        eprintln!("lean oracle: Oracle.lean printed before its decisions: {l}");
    }
    decisions.lines().map(String::from).collect()
}

#[test]
#[ignore = "needs the pinned Lean toolchain: ci/lean.sh"]
fn rust_decides_as_the_lean_spec() {
    let mut c = Cases::default();

    // 1. The fixtures: every zone oracle 1 uses, on its probes (a deterministic sample of them).
    let zones = all_zones();
    let mut rng = Rng(322);
    for z in &zones {
        let Ok(cz) = CompiledZone::new(z.clone()) else { continue };
        let zi = c.zone(z);
        let (hosts, paths) = probes(&[z]);
        for h in &hosts {
            for p in &paths {
                for m in ["GET", "POST", "DELETE"] {
                    if rng.chance(25) {
                        c.eval(zi, &cz, m, h, p);
                    }
                }
            }
        }
    }
    let fixture_evals = c.cases.len();

    // 2. The subset tests' parents and children: `check` and `reach_within`.
    let parents = subset_cases::parents();
    for ch in subset_cases::children() {
        let p = parents.iter().find(|p| p.key == ch.parent).unwrap();
        let b = subset::Bounds {
            zone: &p.zone,
            images: p.images.clone(),
            llm_remaining: p.llm_remaining,
            llm_input_remaining: None,
            time_remaining: p.time_remaining,
            child_slots: p.child_slots,
        };
        let ask = subset::Ask { zone: &ch.zone, image: &ch.image, max_children: ch.max_children };
        c.check(&p.zone, &ch.zone, &b, &ask, &format!("{} in {}", ch.name, ch.parent));
    }
    // Every zone pair among the fixtures, for reach_within.
    for (i, outer) in zones.iter().enumerate().step_by(3) {
        for inner in zones.iter().skip(i % 5).step_by(7) {
            let (oi, ii) = (c.zone(outer), c.zone(inner));
            let rust = subset::reach_within(outer, inner).is_ok().to_string();
            c.push(
                json!({ "kind": "reach_within", "outer": oi, "inner": ii }),
                rust,
                format!("reach_within {} ⊇ {}", outer.name, inner.name),
            );
        }
    }
    let fixtures = c.cases.len();

    // 3. Generated: globs against paths (one rule, both as reach and as forbid), hosts, canonical
    // paths, and parent/child zones.
    let base = base_zone();
    let mut rng = Rng(0x322);
    let mut skipped = 0;
    for _ in 0..1500 {
        let mut z = base.clone();
        z.reach =
            vec![ReachRule { host: "a.test".into(), methods: vec!["GET".into()], paths: vec![gen_glob(&mut rng)], allow_dangerous: false }];
        if rng.chance(40) {
            z.forbid = vec![ForbidRule { host: "a.test".into(), paths: vec![gen_glob(&mut rng)] }];
        }
        let Ok(cz) = CompiledZone::new(z.clone()) else {
            skipped += 1;
            continue;
        };
        let zi = c.zone(&z);
        for _ in 0..8 {
            let p = gen_path(&mut rng);
            c.eval(zi, &cz, "GET", "a.test", &p);
        }
    }
    for pat in HOST_PATTERNS {
        for h in HOSTS.iter().chain(&["xa.test", "a.test..", ".a.test", "b.a.test.", "c.b.a.test."]) {
            let rust = wicket_core::manifest::host_matches(pat, h).to_string();
            c.push(json!({ "kind": "host", "pattern": pat, "host": h }), rust, format!("host_matches({pat:?}, {h:?})"));
        }
    }
    for _ in 0..3000 {
        let pq = gen_canon(&mut rng);
        let rust = match wicket_core::canonical_path(&pq) {
            Ok(p) => serde_json::to_string(&p.to_string()).unwrap(),
            Err(_) => "null".into(),
        };
        c.push(json!({ "kind": "canon", "path": pq }), rust, format!("canonical_path({pq:?})"));
    }
    // #257 4a: what a path-prefix grant covers, on every pair of canonical paths of up to 4 bytes
    // over `/`, two letters and `.` (the containment itself is Kani's and canon.rs's).
    let mut paths = vec![String::new()];
    let mut canon_paths = vec![];
    for _ in 0..4 {
        paths = paths.iter().flat_map(|s| ["/", "a", "b", "."].map(|x| format!("{s}{x}"))).collect();
        canon_paths.extend(paths.iter().filter(|p| wicket_core::canonical_path(p).is_ok_and(|c| c == p.as_str())).cloned());
    }
    for pre in &canon_paths {
        for path in &canon_paths {
            let rust = wicket_core::prefix_covers(pre, path).to_string();
            c.push(json!({ "kind": "prefix_covers", "prefix": pre, "path": path }), rust, format!("prefix_covers({pre:?}, {path:?})"));
        }
    }
    let mut admitted = 0;
    for i in 0..3000 {
        let p = gen_zone(&mut rng, &base);
        let ch = gen_child(&mut rng, &p);
        if CompiledZone::new(p.clone()).is_err() || CompiledZone::new(ch.clone()).is_err() {
            skipped += 1;
            continue;
        }
        let b = subset::Bounds {
            zone: &p,
            images: vec!["img".into()],
            llm_remaining: None,
            llm_input_remaining: None,
            time_remaining: Duration::from_secs(3600),
            child_slots: 2,
        };
        let ask = subset::Ask { zone: &ch, image: "img", max_children: 0 };
        admitted += usize::from(subset::check(&ask, &b).is_ok());
        c.check(&p, &ch, &b, &ask, &format!("generated pair {i}: parent {:?}, child {:?}", p.reach, ch.reach));
        // And the child's decisions on a few requests (with its forbids).
        if let Ok(cz) = CompiledZone::new(ch.clone()) {
            let zi = c.zone(&ch);
            for _ in 0..4 {
                let (h, p) = (rng.pick(&HOSTS).to_string(), gen_path(&mut rng));
                c.eval(zi, &cz, rng.pick(&["GET", "POST", "PUT"]), &h, &p);
            }
        }
    }

    // 4. The model allowlist and accept_from (#366, #411): generated parents and children through
    // `check`, every zone's models, and `accepts` on generated lists.
    let mut routes_admitted = 0;
    for i in 0..600 {
        let (p, ch) = gen_route_pair(&mut rng);
        let b = subset::Bounds {
            zone: &p,
            images: vec!["img".into()],
            llm_remaining: None,
            llm_input_remaining: None,
            time_remaining: Duration::from_secs(3600),
            child_slots: 2,
        };
        let ask = subset::Ask { zone: &ch, image: "img", max_children: 0 };
        routes_admitted += usize::from(subset::check(&ask, &b).is_ok());
        let what = format!(
            "route pair {i}: models {:?} in {:?}, accept_from {:?} in {:?}",
            ch.llm.as_ref().and_then(|l| l.models.clone()),
            p.llm.as_ref().and_then(|l| l.models.clone()),
            ch.accept_from,
            p.accept_from
        );
        c.check(&p, &ch, &b, &ask, &what);
        for z in [&p, &ch] {
            let zi = c.zone(z);
            for m in MODELS.iter().chain(&MODEL_PATTERNS[..3]) {
                c.model(zi, z, m);
            }
            for _ in 0..3 {
                let pr = match rng.below(4) {
                    0 => None,
                    _ => Some(rng.pick(&SENDERS[3..]).to_string()),
                };
                c.accepts(&z.accept_from, rng.pick(&SENDERS[..4]), pr.as_deref());
            }
        }
    }

    // 5. Tokens (#164): block 0 and spawn blocks appended to it, decided by the token, against the
    // spec's chain of zones. Half the children are admitted by `check`, as a node requires.
    let keys = Keys::new(0);
    let mut chains = 0;
    let mut node_admitted = 0;
    for _ in 0..250 {
        let depth = 1 + rng.below(3);
        let mut zs = vec![gen_zone(&mut rng, &base)];
        for i in 1..=depth {
            let mut ch = gen_child(&mut rng, &zs[i - 1]);
            ch.name = format!("z{i}");
            zs.push(ch);
        }
        if zs.iter().any(|z| CompiledZone::new(z.clone()).is_err()) {
            skipped += 1;
            continue;
        }
        let Ok(cs) = zs
            .iter()
            .enumerate()
            .map(|(i, z)| Ceiling::from_zone(z, &box_id(i), T0 + 3600, vec![keys.approver.public()]))
            .collect::<Result<Vec<_>, _>>()
        else {
            skipped += 1;
            continue;
        };
        let Ok(mut tok) = mint(&keys.root, TENANT, "trigger:z0", &cs[0]) else {
            skipped += 1;
            continue;
        };
        let mut ok = true;
        for c in &cs[1..] {
            match tok.attenuate(c) {
                Ok(t) => tok = t,
                Err(_) => ok = false,
            }
        }
        let Ok(l) = (if ok { load(&tok.to_bytes().unwrap(), &keys.root.public(), &never_revoked) } else { continue }) else {
            skipped += 1;
            continue;
        };
        chains += 1;
        let leaf = &zs[depth];
        let parent = &zs[depth - 1];
        let pb = subset::Bounds {
            zone: parent,
            images: vec!["img".into()],
            llm_remaining: None,
            llm_input_remaining: None,
            time_remaining: Duration::from_secs(3600),
            child_slots: 2,
        };
        node_admitted += usize::from(subset::check(&subset::Ask { zone: leaf, image: "img", max_children: 0 }, &pb).is_ok());
        let zis: Vec<usize> = zs.iter().map(|z| c.zone(z)).collect();
        for _ in 0..12 {
            // Half aim at one of the leaf's rules, so that enough are allowed.
            let (m, h, p) = match leaf.reach.get(rng.below(leaf.reach.len() + 1)) {
                Some(r) if rng.chance(50) && !r.methods.is_empty() => {
                    (r.methods[0].clone(), r.host.replace("*.", "x."), gen_path(&mut rng))
                }
                _ => (rng.pick(&["GET", "POST", "PUT"]).to_string(), rng.pick(&HOSTS).to_string(), gen_path(&mut rng)),
            };
            c.chain(&zis, &l, depth, &m, &h, &p);
        }
    }

    // 8. The decisions moved into wicket-core's pure functions (#325), each against its definition in
    // Wicket/Decisions.lean.
    let decisions_from = c.cases.len();
    decisions(&mut c, &mut rng);
    let decisions = c.cases.len() - decisions_from;

    // 9. Standing reach (#572): asks narrowed to generated evidence, and what the rules decide.
    let standing_from = c.cases.len();
    standing(&mut c, &mut rng);
    let standing = c.cases.len() - standing_from;
    // 10. Who may send whom a message (#565): `message::relation` on generated facts.
    let relations_from = c.cases.len();
    relations(&mut c, &mut rng);
    let relations = c.cases.len() - relations_from;
    // 11. A node CA's name constraints (#573): permitting, covering, and what a widened CA is
    // signed for.
    let node_ca_from = c.cases.len();
    node_ca(&mut c, &mut rng);
    let node_ca = c.cases.len() - node_ca_from;

    let file = Path::new(env!("CARGO_TARGET_TMPDIR")).join("lean-oracle-cases.json");
    std::fs::write(&file, serde_json::to_vec(&json!({ "zones": c.zones, "cases": c.cases })).unwrap()).unwrap();
    let lean = run_lean(&file);
    assert_eq!(lean.len(), c.cases.len(), "the oracle printed {} decisions for {} cases", lean.len(), c.cases.len());

    let mut divergent = Vec::new();
    let mut unsupported = 0;
    for (i, l) in lean.iter().enumerate() {
        if l == "unsupported" {
            unsupported += 1;
            continue;
        }
        if *l != c.rust[i] {
            divergent.push(format!("{}: wicket-core {}, the spec {l}\n    case {}", c.what[i], c.rust[i], c.cases[i]));
        }
    }
    println!(
        "lean oracle: {} cases ({fixture_evals} fixture decisions, {} more fixture cases, {} generated); {unsupported} outside the spec's language; {skipped} generated zones that don't compile; {admitted} generated children admitted",
        c.cases.len(),
        fixtures - fixture_evals,
        c.cases.len() - fixtures
    );
    assert!(admitted > 50, "too few generated children admitted ({admitted}) to test the check");
    println!("lean oracle: {routes_admitted} of 600 route children admitted; {chains} token chains, {node_admitted} of their leaves admitted by check");
    assert!(routes_admitted > 50 && routes_admitted < 550, "route children admitted: {routes_admitted} of 600");
    assert!(chains > 100, "too few token chains ({chains})");
    println!("lean oracle: {standing} cases of standing reach (narrowing to evidence, a rule's decisions)");
    println!("lean oracle: {relations} cases of the message rule");
    println!("lean oracle: {node_ca} cases of node CA name constraints");
    println!("lean oracle: {decisions} cases of wicket-core's pure decisions (is_public_ip, the token's end, agents' terms, escalation, uses, money, spawn)");
    assert!(
        divergent.is_empty(),
        "{} divergences from the Lean spec:\n{}",
        divergent.len(),
        divergent.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}

/// The cases of section 8: `op::is_public_ip`, `quota::not_after_for`/`token_allows`,
/// `authority::agent_term_refusal`, `escalation`, `quota::take_use`, `quota::money_fits` and
/// `quota::SpawnLimits::admits`, on edges and generated values.
fn decisions(c: &mut Cases, rng: &mut Rng) {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use wicket_core::authority::{agent_term_refusal, GrantRules, GrantShape, TermRefusal};
    use wicket_core::escalation::{check_escalatable, needs_grant, Failed};
    use wicket_core::quota::{money_fits, not_after_for, take_use, token_allows, Money, MoneyOver, SpawnAsk, SpawnLimits};

    // The SSRF guard. IPv4: first octets that start a special block, or any; IPv6: the special
    // prefixes (and the IPv4 forms behind them), or any.
    let octets: [u32; 14] = [0, 10, 100, 127, 168, 169, 172, 192, 198, 203, 224, 240, 255, 8];
    for _ in 0..3000 {
        let low = rng.next() as u32;
        let a = if rng.chance(70) { (rng.pick(&octets) << 24) | (low & 0x00ff_ffff) } else { low };
        let rust = wicket_core::op::is_public_ip(&IpAddr::V4(Ipv4Addr::from(a))).to_string();
        c.push(json!({ "kind": "public_ip", "v": 4, "addr": a.to_string() }), rust, format!("is_public_ip({})", Ipv4Addr::from(a)));
    }
    let tops: [u128; 12] = [
        0,
        0x0000_0000,
        0x0064_ff9b,
        0x0100_0000,
        0x2001_0000,
        0x2001_01ff,
        0x2001_0db8,
        0x2002_0000,
        0xfc00_0000,
        0xfe80_0000,
        0xfec0_0000,
        0xff02_0000,
    ];
    for _ in 0..3000 {
        let r = (u128::from(rng.next()) << 64) | u128::from(rng.next());
        let a = match rng.below(4) {
            0 => r,
            1 => (rng.pick(&tops) << 96) | (r & ((1u128 << 96) - 1)),
            // An IPv4-mapped or -compatible address.
            2 => (if rng.chance(50) { 0xffffu128 << 32 } else { 0 }) | u128::from(rng.next() as u32),
            // The top 32 bits and then zeros up to a /64: the discard and Teredo-like shapes.
            _ => (rng.pick(&tops) << 96) | (u128::from(rng.next() as u16) << 80),
        };
        let rust = wicket_core::op::is_public_ip(&IpAddr::V6(Ipv6Addr::from(a))).to_string();
        c.push(json!({ "kind": "public_ip", "v": 6, "addr": a.to_string() }), rust, format!("is_public_ip({})", Ipv6Addr::from(a)));
    }

    // The token's end: grant ends and clock readings around the boundary, and anywhere.
    let ends: [i64; 9] = [1, 2, 1_700_000_000, 4_294_967_295, i64::MAX / 1000, i64::MAX, 0, -5, i64::MIN];
    for _ in 0..2000 {
        let e = if rng.chance(50) { *rng.pick(&ends) } else { (rng.next() >> 24) as i64 };
        let near = i128::from(e) * 1000 + i128::from(rng.below(4001) as i64 - 2000);
        let now = if rng.chance(70) { near.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64 } else { rng.next() as i64 };
        let rust = token_allows(not_after_for(e), now).to_string();
        c.push(json!({ "kind": "token_end", "expires_at": e, "now_ms": now }), rust, format!("token_allows(not_after_for({e}), {now})"));
    }

    // Agents' terms and escalation: every combination.
    for bits in 0u32..256 {
        let b = |i: u32| bits & (1 << i) != 0;
        let rules = GrantRules { zone_wide: b(0), prefix: b(1), unbounded: b(2), git_push: b(3) };
        let shape = GrantShape { zone_wide: b(4), prefix: b(5), unbounded: b(6), git_push: b(7) };
        let rust = match agent_term_refusal(rules, shape) {
            None => "none",
            Some(TermRefusal::ZoneWide) => "zone_wide",
            Some(TermRefusal::Prefix) => "prefix",
            Some(TermRefusal::Unbounded) => "unbounded",
            Some(TermRefusal::GitPush) => "git_push",
        };
        let j = |zw: bool, p: bool, u: bool, g: bool| json!({ "zone_wide": zw, "prefix": p, "unbounded": u, "git_push": g });
        c.push(
            json!({ "kind": "agent_terms", "rules": j(b(0), b(1), b(2), b(3)), "shape": j(b(4), b(5), b(6), b(7)) }),
            rust.to_string(),
            format!("agent_term_refusal({rules:?}, {shape:?})"),
        );
    }
    for bits in 0u32..32 {
        let b = |i: u32| bits & (1 << i) != 0;
        let rust = check_escalatable(b(0), b(1), b(2), b(3), b(4)).to_string();
        c.push(
            json!({ "kind": "escalatable", "one": b(0), "policy": b(1), "host": b(2), "risk": b(3), "approved": b(4) }),
            rust,
            format!("check_escalatable({bits:05b})"),
        );
    }
    let kinds = [
        ("node", Failed::Node),
        ("soft", Failed::Block(Some(true))),
        ("hard", Failed::Block(Some(false))),
        ("unknown", Failed::Block(None)),
    ];
    for _ in 0..300 {
        let picked: Vec<&(&str, Failed)> = (0..rng.below(5)).map(|_| rng.pick(&kinds)).collect();
        let soft = picked.iter().filter(|(_, f)| f.soft()).count();
        let rust = needs_grant(picked.len() - soft, soft).to_string();
        let names: Vec<&str> = picked.iter().map(|(n, _)| *n).collect();
        c.push(json!({ "kind": "needs_grant", "failed": names }), rust, format!("needs_grant of {names:?}"));
    }

    // Counted uses.
    let uses: [Option<i64>; 8] = [None, Some(i64::MIN), Some(-1), Some(0), Some(1), Some(2), Some(i64::MAX), Some(1_000_000)];
    for _ in 0..200 {
        let u = if rng.chance(60) { *rng.pick(&uses) } else { Some(rng.next() as i64) };
        let rust = match take_use(u) {
            None => "refused".to_string(),
            Some(None) => "uncounted".to_string(),
            Some(Some(n)) => n.to_string(),
        };
        c.push(json!({ "kind": "take_use", "uses_left": u }), rust, format!("take_use({u:?})"));
    }

    // Money: amounts at the edges of i64 (where a sum would overflow), and anywhere.
    let edge: [i64; 7] = [0, 1, -1, i64::MAX, i64::MIN, i64::MAX / 2, 1_000_000];
    let amount = |rng: &mut Rng| if rng.chance(40) { *rng.pick(&edge) } else { (rng.next() >> rng.below(64)) as i64 };
    for _ in 0..1000 {
        let (rh, rt, nh, nt, mh, mt) = (amount(rng), amount(rng), amount(rng), amount(rng), amount(rng), amount(rng));
        let rust = match money_fits(Money { hourly: rh, total: rt }, Money { hourly: nh, total: nt }, Money { hourly: mh, total: mt }) {
            Ok(()) => "fits",
            Err(MoneyOver::Hourly) => "hourly",
            Err(MoneyOver::Total) => "total",
        };
        c.push(
            json!({ "kind": "money", "rh": rh, "rt": rt, "nh": nh, "nt": nt, "mh": mh, "mt": mt }),
            rust.to_string(),
            format!("money_fits({rh}, {rt}, {nh}, {nt}, {mh}, {mt})"),
        );
    }

    // The spawn ceiling: small values, so asks fall on both sides of limits.
    let small = |rng: &mut Rng| rng.below(7) as i64 - 1;
    for _ in 0..1000 {
        let lim = |rng: &mut Rng| if rng.chance(30) { None } else { Some(small(rng)) };
        let l = SpawnLimits {
            min_isolation: lim(rng),
            max_mem_bytes: lim(rng),
            max_cpus_milli: lim(rng),
            max_pids: lim(rng),
            max_timeout_s: lim(rng),
        };
        let a = SpawnAsk { isolation: small(rng), mem_bytes: small(rng), cpus_milli: small(rng), pids: small(rng), timeout_s: small(rng) };
        let rust = l.admits(a).to_string();
        c.push(
            json!({ "kind": "spawn", "min_isolation": l.min_isolation, "max_mem": l.max_mem_bytes, "max_cpus": l.max_cpus_milli,
                    "max_pids": l.max_pids, "max_timeout": l.max_timeout_s, "isolation": a.isolation, "mem": a.mem_bytes,
                    "cpus": a.cpus_milli, "pids": a.pids, "timeout": a.timeout_s }),
            rust,
            format!("{l:?}.admits({a:?})"),
        );
    }
}

/// The cases of section 9: `standing::narrow` on generated evidence (methods in either case, paths
/// with and without glob metacharacters, counts of 0 to 3, sometimes more distinct paths than a rule
/// may have pairs), and `ReachRule::allows` for each narrowed rule and generated rules, on requests
/// for the evidence's paths and others, at every risk the methods give.
fn standing(c: &mut Cases, rng: &mut Rng) {
    use wicket_core::standing::narrow;
    let methods = ["GET", "HEAD", "POST", "DELETE", "get", "PUT"];
    let paths = ["/a", "/b", "/a/b", "/b/a", "/c*", "/[x]", "/a?", "/", "/a/b/c"];
    let probes = ["/a", "/b", "/a/b", "/b/a", "/c", "/cd", "/x", "/a/", "/", "/a/b/c", "/A"];
    let rule_json = |r: &ReachRule| json!({ "host": r.host, "methods": r.methods, "paths": r.paths, "dangerous": r.allow_dangerous });
    let mut narrowed = 0;
    for i in 0..2000 {
        let wide = i % 10 == 0;
        let ops: Vec<(String, String, u64)> = (0..rng.below(if wide { 24 } else { 7 }))
            .map(|k| {
                let m = rng.pick(&methods).to_string();
                let p = if wide { format!("/p{k}") } else { rng.pick(&paths).to_string() };
                (m, p, rng.below(4) as u64)
            })
            .collect();
        let host = *rng.pick(&["a.test", "A.Test"]);
        let got = narrow(host, ops.iter().map(|(m, p, n)| (m.as_str(), p.as_str(), *n)));
        let rust = match &got {
            None => "none".to_string(),
            Some(r) => serde_json::to_string(&json!([r.host, r.methods, r.paths, r.allow_dangerous])).unwrap(),
        };
        c.push(json!({ "kind": "narrow", "host": host, "ops": ops }), rust, format!("narrow({host:?}, {ops:?})"));
        let rule = match got {
            Some(r) => {
                narrowed += 1;
                r
            }
            None => gen_rule(rng),
        };
        for _ in 0..4 {
            let m = *rng.pick(&methods);
            let p = if rng.chance(50) && !ops.is_empty() { rng.pick(&ops).1.clone() } else { rng.pick(&probes).to_string() };
            let o = op("z", m, "a.test", &p);
            let Ok(allowed) = rule.allows(&o) else { continue };
            let case = json!({ "kind": "rule_allows", "rule": rule_json(&rule), "op": {
                "method": o.method, "host": o.host, "path": o.path, "risk": o.risk.rank(),
                "unreachable": wicket_core::never_reachable(&o.host).is_some(),
            }});
            c.push(case, allowed.to_string(), format!("{rule:?}.allows({m} a.test{p}, risk {:?})", o.risk));
        }
    }
    assert!(narrowed > 1000, "too few asks narrowed ({narrowed} of 2000)");
}

/// The cases of section 10: `message::relation` on every combination of family and reply, generated
/// `accept_from` lists, and senders whose zone and principal (known or not) are listed or not.
fn relations(c: &mut Cases, rng: &mut Rng) {
    use wicket_core::message::{relation, Facts};
    let zones = ["g", "ops", "dev", "other"];
    let principals = [None, Some("spiffe://acc.test/t/t0/z/ops/a/x"), Some("spiffe://acc.test/t/t0/z/dev/a/y"), Some("ops")];
    let mut peers = 0;
    for i in 0..3000 {
        let accept_from = gen_accept(rng);
        let (zone, principal) = (*rng.pick(&zones), *rng.pick(&principals));
        let (to_child, to_parent, reply) = (i & 1 != 0 && rng.chance(50), i & 2 != 0 && rng.chance(50), rng.chance(40));
        let f = Facts { to_child, to_parent, accept_from: &accept_from, sender_zone: zone, sender: principal, reply };
        let got = relation(&f);
        peers += usize::from(got == Some(wicket_core::message::Relation::Peer));
        let rust = got.map_or("none", |r| r.as_str()).to_string();
        let case = json!({ "kind": "relation", "to_child": to_child, "to_parent": to_parent, "accept_from": accept_from,
            "zone": zone, "principal": principal, "reply": reply });
        c.push(
            case,
            rust,
            format!("relation(child {to_child}, parent {to_parent}, {accept_from:?}, {zone}, {principal:?}, reply {reply})"),
        );
    }
    assert!(peers > 300, "too few peers accepted ({peers} of 3000)");
}

/// The cases of section 11: `splice::subtree_permits` on every pair of subtrees and hosts below,
/// coverage by generated lists, and `splice::widen` on generated operator's hosts and runs' wants
/// (sometimes over the cap).
fn node_ca(c: &mut Cases, rng: &mut Rng) {
    use wicket_core::splice::{subtree_permits, uncovered, widen};
    const SUBTREES: [&str; 14] = [
        "a.test",
        "b.a.test",
        ".a.test",
        ".test",
        "test",
        "*",
        "A.Test",
        ".b.a.test",
        "ab.test",
        "x.b.a.test",
        ".A.TEST",
        "b.test",
        ".",
        "",
    ];
    const NAMES: [&str; 12] =
        ["a.test", "b.a.test", "x.b.a.test", "ab.test", "test", "A.TEST.", "a.test..", ".a.test", "b.test", "xa.test", "*", "c.ab.test"];
    for s in SUBTREES {
        for h in NAMES.iter().chain(&SUBTREES) {
            let rust = subtree_permits(s, h).to_string();
            c.push(json!({ "kind": "subtree_permits", "subtree": s, "host": h }), rust, format!("subtree_permits({s:?}, {h:?})"));
        }
    }
    let pick = |rng: &mut Rng, n: usize| -> Vec<String> { (0..rng.below(n)).map(|_| rng.pick(&SUBTREES[..12]).to_string()).collect() };
    for _ in 0..1500 {
        let permitted = pick(rng, 4);
        let need = rng.pick(&SUBTREES[..12]).to_string();
        let rust = uncovered(&permitted, std::slice::from_ref(&need)).is_empty().to_string();
        c.push(json!({ "kind": "covered", "permitted": permitted, "need": need }), rust, format!("covered({permitted:?}, {need:?})"));
    }
    for _ in 0..1500 {
        let base: Vec<String> = pick(rng, 3).into_iter().filter(|s| s != "*" || rng.chance(10)).collect();
        let wants: Vec<(String, String)> =
            (0..rng.below(9)).map(|_| (rng.pick(&["r1", "r2", "r3"]).to_string(), rng.pick(&SUBTREES[..12]).to_string())).collect();
        let max = rng.below(7);
        let (hosts, dropped) = widen(&base, &wants, max);
        let rust = serde_json::to_string(&json!([hosts, dropped])).unwrap();
        c.push(json!({ "kind": "widen", "base": base, "wants": wants, "max": max }), rust, format!("widen({base:?}, {wants:?}, {max})"));
    }
}
