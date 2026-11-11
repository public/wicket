#![allow(dead_code)]
mod bisc;
mod correct;
mod designs;
mod diff;
mod fk;
mod hostile;
mod lint;
mod model;
mod perf;
mod plain;
mod stats;
mod zf;

use designs::Design;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn t0() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    now - now % 60
}

pub fn scale(n: usize) -> usize {
    let s: f64 = std::env::var("ITER_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1.0);
    ((n as f64) * s).max(20.0) as usize
}

fn designs_arg(default: &[Design]) -> Vec<Design> {
    match std::env::args().nth(2) {
        Some(a) => a.split(',').map(|s| Design::parse(s).unwrap_or_else(|| panic!("unknown design {s}"))).collect(),
        None => default.to_vec(),
    }
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "correct" => {
            let t0 = t0();
            let mut lines = vec![];
            let mut all = true;
            for d in designs_arg(&Design::ALL) {
                let (ok, n) = correct::run(d, t0);
                all &= ok;
                lines.push(format!("{}: {n} checks, {}", d.name(), if ok { "all pass" } else { "SOME FAIL" }));
            }
            println!("\n## Summary\n\n{}\n\n{}", lines.join("\n"), if all { "ALL DESIGNS: ALL PASS" } else { "SOME CHECKS FAILED" });
        }
        "globs" => globs(),
        "mutants" => {
            let t0 = t0();
            let mut lines = vec![];
            for k in 0..designs::MUTANTS.len() as u8 {
                let (ok, n) = correct::run(Design::Mut(k), t0);
                lines.push(format!("- mutant {k} ({}): {}", designs::MUTANTS[k as usize], if ok { format!("NOT CAUGHT ({n} checks pass)") } else { "caught".into() }));
            }
            println!("\n## Summary\n\n{}", lines.join("\n"));
        }
        "diff" => diff::run(),
        "bench" => perf::bench(),
        "sizes" => perf::sizes(),
        "hostile" => hostile::run(),
        _ => eprintln!("usage: biscuit-datablocks correct [a,b,bm,c] | globs | diff | bench | sizes | hostile"),
    }
}

/// Where wicket's glob matcher and design A's prefix encoding disagree, for the three path forms the
/// model uses, on canonical paths (wicket_core::canonical_path accepts each one).
fn globs() {
    use model::{path_matches, PathPat};
    let pats = [PathPat::Any, PathPat::Prefix("/repos/acme/".into()), PathPat::Prefix("/simple/".into()), PathPat::OneSegment("/tokio/".into())];
    let paths = [
        "/", "/x", "/repos", "/repos/", "/repos/acme", "/repos/acme/", "/repos/acme/api", "/repos/acme/api/", "/repos/acme/api/pulls/7", "/simple", "/simple/", "/simple/requests",
        "/simple/requests/", "/tokio", "/tokio/", "/tokio/latest", "/tokio/latest/", "/tokio/a/b",
    ];
    println!("| model pattern | wicket glob | path | A (prefix + path_depth) | B (CompiledZone) |\n|---|---|---|---|---|");
    let (mut n, mut differ) = (0, 0);
    for p in &pats {
        let c = model::Ceiling {
            reach: vec![model::Reach { host: "h.example".into(), methods: vec!["GET".into()], path: p.clone() }],
            forbid: vec![],
            dangerous_ok: vec![],
            ..correct::top(0)
        };
        for path in paths {
            assert!(wicket_core::canonical_path(path).is_ok(), "{path} not canonical");
            let a = path_matches(p, path);
            let r = model::Request {
                time: 0,
                tenant: "acme".into(),
                node: "n".into(),
                box_id: "b0".into(),
                epoch: 0,
                op: model::Op::Http { host: "h.example".into(), method: "GET".into(), path: path.into(), risk: 0, inject: None },
                uses_left: vec![],
            };
            let ch = zf::Chain { tenant: "acme".into(), zones: vec![zf::compile_block(c.clone()).unwrap()], grants: vec![], ids: vec![] };
            let b = ch.allows(&r, &zf::wicket_op(&r), zf::Matcher::Wicket);
            n += 1;
            if a != b {
                differ += 1;
                println!("| {p:?} | `{}` | `{path}` | {a} | {b} |", zf::glob(p));
            }
        }
    }
    println!("\n{differ} of {n} (pattern, path) pairs differ");
}

/// biscuit-fast's three hostile holder blocks (its main.rs `hostile()`), unchanged.
pub fn hostile_datalog() -> Vec<(&'static str, String)> {
    vec![
        ("fact explosion: 40 q() facts, p($a,$b) <- q($a), q($b) (1600 facts)", {
            let mut s: String = (0..40).map(|i| format!("q({i});\n")).collect();
            s.push_str("p($a, $b) <- q($a), q($b);\n");
            s
        }),
        ("iteration chain: 150 rules r_i+1 <- r_i", {
            let mut s = String::from("r0(1);\n");
            for i in 0..150 {
                s.push_str(&format!("r{}($x) <- r{i}($x);\n", i + 1));
            }
            s
        }),
        ("expensive checks: 200 regex checks", (0..200).map(|i| format!("check if path($p), $p.matches(\"^/repos/[a-z]+/api/pulls/[0-9]+$|^x{i}$\");\n")).collect()),
    ]
}
