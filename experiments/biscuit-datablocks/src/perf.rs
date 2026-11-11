//! Speed and size, same method as biscuit-depth and biscuit-fast: n/10 warm-up calls, then n timed
//! calls with `Instant` around each; WARM = the token is loaded and cached, and each request pays the
//! revocation check (every block id against a 10k-entry set) plus the decision, with the request's
//! input (A: Datalog facts; B: a wicket-core `Op`) built beforehand.

use crate::bisc;
use crate::correct::mint_d;
use crate::designs::{self, Design, Loaded};
use crate::fk;
use crate::lint;
use crate::model::*;
use crate::stats::{measure, Stats};
use crate::zf::{self, Form, Matcher};
use std::collections::HashSet;
use std::hint::black_box;

fn row(name: &str, s: &Stats) {
    println!("| {name} | {s} |");
}

fn header(title: &str) {
    println!("\n### {title}\n\n| what | median µs | p99 µs | mean µs | max µs |\n|---|---|---|---|---|");
}

pub fn bench() {
    let t0 = crate::t0();
    let now = t0 + 600;
    let (n_cold, n_warm) = (crate::scale(3000), crate::scale(20000));
    println!("iterations: cold {n_cold}, warm {n_warm}");
    let revset: HashSet<Vec<u8>> = (0..10_000u32)
        .map(|i| {
            let mut v = vec![0u8; 64];
            v[..4].copy_from_slice(&i.to_be_bytes());
            v
        })
        .collect();
    let mut warm: Vec<(String, usize, Vec<(f64, f64)>)> = Vec::new();
    let mut cold: Vec<(String, usize, f64, f64)> = Vec::new();
    for depth in 1..=5 {
        let keys = bisc::Keys::new(5);
        let cs = bisc::ceilings(t0, depth, &keys);
        let grant = leaf_grant(now, depth);
        let froot = fk::root_pk(&keys.root.public());
        let sc = scenarios(now, depth);
        let toks: Vec<(Design, Vec<u8>)> = [Design::A, Design::B, Design::C].iter().map(|&d| (d, mint_d(d, &cs, Some((&grant, &keys.approver)), &keys.root).to_vec().unwrap())).collect();
        println!("\n## depth {depth}: token bytes A {} / B {} / C {}", toks[0].1.len(), toks[1].1.len(), toks[2].1.len());
        let loaded: Vec<Loaded> = toks.iter().map(|(d, b)| designs::load(*d, b, &froot).unwrap_or_else(|e| panic!("{d:?}: {e}"))).collect();
        let ids = fork::Biscuit::from(&toks[0].1, froot.clone()).unwrap().revocation_identifiers();
        let facts: Vec<Vec<fork::builder::Fact>> = sc.iter().map(|(_, r)| fk::request_facts(r)).collect();
        let ops: Vec<wicket_core::Op> = sc.iter().map(|(_, r)| zf::wicket_op(r)).collect();
        let l = fk::fuel();
        let mut go = |label: &str, f: &dyn Fn(usize) -> bool| {
            header(&format!("depth {depth}: WARM, {label}"));
            let mut cells = Vec::new();
            for (i, (name, _)) in sc.iter().enumerate() {
                assert_eq!(f(i), !name.starts_with('B'), "{label} {name} depth {depth}");
                let s = measure(n_warm, || {
                    let rev = ids.iter().any(|x| revset.contains(x));
                    black_box(!rev && f(black_box(i)));
                });
                row(&format!("WARM {name}"), &s);
                cells.push((s.median, s.p99));
            }
            warm.push((label.to_string(), depth, cells));
        };
        let (Loaded::A(a), Loaded::B(b, _), Loaded::C(ca, cb)) = (&loaded[0], &loaded[1], &loaded[2]) else { unreachable!() };
        go("A: checks, compiled evaluator (step 3)", &|i| a.authorize(&facts[i], &l).is_ok());
        go("B: data-only, CompiledZone per block", &|i| b.allows(&sc[i].1, &ops[i], Matcher::Wicket));
        go("B: data-only, model matcher", &|i| b.allows(&sc[i].1, &ops[i], Matcher::Model));
        go("C: decide with A only (release)", &|i| ca.authorize(&facts[i], &l).is_ok());
        go("C: decide with A and cross-check B (debug)", &|i| {
            let x = ca.authorize(&facts[i], &l).is_ok();
            assert_eq!(x, cb.allows(&sc[i].1, &ops[i], Matcher::Wicket));
            x
        });

        header(&format!("depth {depth}: once per token (COLD)"));
        let mut c = |label: &str, s: Stats| {
            row(label, &s);
            cold.push((label.to_string(), depth, s.median, s.p99));
        };
        let (ab, bb, cbb) = (&toks[0].1, &toks[1].1, &toks[2].1);
        let fa = fork::Biscuit::from(ab, froot.clone()).unwrap();
        let fb = fork::Biscuit::from(bb, froot.clone()).unwrap();
        let fc = fork::Biscuit::from(cbb, froot.clone()).unwrap();
        c("A parse + verify", measure(n_cold, || drop(black_box(fork::Biscuit::from(black_box(ab), froot.clone()).unwrap()))));
        c("A lint", measure(n_cold, || drop(black_box(lint::lint(&fa, ab.len(), &designs::lint_policy(Design::A)).is_ok()))));
        c("A prepare + compile", measure(n_cold, || drop(black_box(fk::prepare(&fa, &l).compile()))));
        c("B parse + verify", measure(n_cold, || drop(black_box(fork::Biscuit::from(black_box(bb), froot.clone()).unwrap()))));
        c("B block_datalog only (all blocks)", measure(n_cold, || {
            for i in 0..fb.block_count() {
                black_box(fb.block_datalog(i).unwrap());
            }
        }));
        let jsons: Vec<String> = cs.iter().map(zf::canon).collect();
        c("B JSON parse + canonical check + validate (all zones)", measure(n_cold, || {
            for j in &jsons {
                let v: Ceiling = serde_json::from_str(j).unwrap();
                assert!(zf::canon(&v) == *j);
                black_box(zf::validate(&v, &zf::Caps::default()).is_ok());
            }
        }));
        c("B CompiledZone build (all zones)", measure(n_cold, || {
            for x in &cs {
                black_box(zf::compile_block(x.clone()).is_ok());
            }
        }));
        c("B extract (all of the above but parse)", measure(n_cold, || drop(black_box(zf::extract(&fb, bb.len(), Form::Data, &zf::Caps::default()).unwrap()))));
        c("B second line: plain::narrows on each link", measure(n_cold, || {
            for k in 1..cs.len() {
                black_box(crate::plain::narrows(&cs[k], &cs[k - 1]).is_ok());
            }
        }));
        c("C parse + verify", measure(n_cold, || drop(black_box(fork::Biscuit::from(black_box(cbb), froot.clone()).unwrap()))));
        c("C lint + extract + prepare + compile", measure(n_cold, || {
            black_box(lint::lint(&fc, cbb.len(), &designs::lint_policy(Design::C)).is_ok());
            black_box(zf::extract(&fc, cbb.len(), Form::Hybrid, &zf::Caps::default()).unwrap());
            black_box(fk::prepare(&fc, &l).compile());
        }));
        for (d, by) in &toks {
            let label = format!("{} COLD A: parse + revocation + gate + compile + decide", match d {
                Design::A => "A",
                Design::B => "B",
                _ => "C",
            });
            let r = &sc[0].1;
            c(&label, measure(n_cold, || {
                let t = designs::load(*d, black_box(by), &froot).unwrap();
                let rev = ids.iter().any(|x| revset.contains(x));
                black_box(!rev && t.decide(r).is_ok());
            }));
        }
        c("request input: A's 13 Datalog facts", measure(n_warm, || drop(black_box(fk::request_facts(black_box(&sc[0].1))))));
        c("request input: B's wicket-core Op", measure(n_warm, || drop(black_box(zf::wicket_op(black_box(&sc[0].1))))));
    }
    println!("\n## Summary: WARM median / p99 µs\n\n| variant | depth | A | B | C | D |\n|---|---|---|---|---|---|");
    for (label, depth, cells) in &warm {
        let c: Vec<String> = cells.iter().map(|(m, p)| format!("{m:.2} / {p:.2}")).collect();
        println!("| {label} | {depth} | {} |", c.join(" | "));
    }
    println!("\n## Summary: once per token, median / p99 µs\n\n| piece | depth | median | p99 |\n|---|---|---|---|");
    for (label, depth, m, p) in &cold {
        println!("| {label} | {depth} | {m:.1} | {p:.1} |");
    }
}

/// Token and block sizes for each design, depth 0–5 (every chain includes the leaf's grant block).
pub fn sizes() {
    let t0 = crate::t0();
    let now = t0 + 600;
    let keys = bisc::Keys::new(5);
    println!("| depth | A bytes | B bytes | C bytes | A base64 | B base64 | C base64 |\n|---|---|---|---|---|---|---|");
    for depth in 0..=5 {
        let cs = bisc::ceilings(t0, depth, &keys);
        let g = leaf_grant(now, depth);
        let s: Vec<usize> = [Design::A, Design::B, Design::C].iter().map(|&d| mint_d(d, &cs, Some((&g, &keys.approver)), &keys.root).to_vec().unwrap().len()).collect();
        let b64 = |n: usize| n.div_ceil(3) * 4;
        println!("| {depth} | {} | {} | {} | {} | {} | {} |", s[0], s[1], s[2], b64(s[0]), b64(s[1]), b64(s[2]));
    }
    println!("\n## Per block at depth 5 (bytes added to the serialized token)\n\n| block | A | B | C |\n|---|---|---|---|");
    let cs = bisc::ceilings(t0, 5, &keys);
    let g = leaf_grant(now, 5);
    let mut per: Vec<Vec<usize>> = vec![];
    for d in [Design::A, Design::B, Design::C] {
        let mut v = vec![];
        let mut prev = 0;
        for k in 0..=5 {
            let n = mint_d(d, &cs[..=k], None, &keys.root).to_vec().unwrap().len();
            v.push(n - prev);
            prev = n;
        }
        let n = mint_d(d, &cs, Some((&g, &keys.approver)), &keys.root).to_vec().unwrap().len();
        v.push(n - prev);
        per.push(v);
    }
    for (k, name) in ["authority (+ framing)", "spawn 1", "spawn 2", "spawn 3", "spawn 4", "spawn 5", "grant (third-party)"].iter().enumerate() {
        println!("| {name} | {} | {} | {} |", per[0][k], per[1][k], per[2][k]);
    }
    println!("\n## Encodings of one spawn zone (level 5)\n");
    let (code, n) = bisc::compile(&cs[5], false, "acme");
    let json = zf::canon(&cs[5]);
    println!("- A: {} bytes of Datalog source, {n} checks", code.len());
    println!("- B: {} bytes of canonical JSON", json.len());
    println!("\n```json\n{json}\n```");
}
