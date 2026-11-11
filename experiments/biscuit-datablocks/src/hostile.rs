//! Attack surface: what a compromised node (it can append any first-party block, or ask a trusted
//! approver nothing) can do to each design. Every hostile block is appended to the depth-5 chain.
//! For each: what the node's load step (parse + gate + compile) does, how long it takes, and what a
//! request then costs if the token loads.

use crate::bisc;
use crate::correct::{append_zone_d, mint_d};
use crate::designs::{self, Design, Loaded};
use crate::fk;
use crate::model::*;
use crate::stats::measure;
use crate::zf::{self, Matcher};
use biscuit_auth::builder::{fact, string};
use biscuit_auth::{Biscuit, BlockBuilder};
use std::hint::black_box;

fn report(label: &str, d: Design, tok: &Biscuit, root: &fork::PublicKey, caps: &zf::Caps, r: &Request) {
    let bytes = tok.to_vec().unwrap();
    let n = crate::scale(200);
    let res = designs::load_with(d, &bytes, root, caps);
    let s = measure(n, || drop(black_box(designs::load_with(d, black_box(&bytes), root, caps).is_ok())));
    let what = match &res {
        Ok(_) => "loaded".to_string(),
        Err(e) => format!("refused: {}", e.chars().take(110).collect::<String>()),
    };
    let per = match &res {
        Ok(l) => {
            let dec = l.decide(r).is_ok();
            let facts = fk::request_facts(r);
            let op = zf::wicket_op(r);
            let sr = match l {
                Loaded::A(c) | Loaded::C(c, _) => measure(crate::scale(2000), || drop(black_box(c.authorize(&facts, &fk::fuel()).is_ok()))),
                Loaded::B(ch, _) => measure(crate::scale(2000), || drop(black_box(ch.allows(r, &op, Matcher::Wicket)))),
            };
            format!("{}, {:.1} / {:.1} µs", if dec { "allowed" } else { "denied" }, sr.median, sr.p99)
        }
        Err(_) => "denied (token refused)".into(),
    };
    println!("| {label} | {} | {} B | {what} | {:.0} / {:.0} µs | {per} |", d.name(), bytes.len(), s.median, s.p99);
}

fn head() {
    println!("| appended block | design | token | load result | load median / p99 | request A: decision, median / p99 |\n|---|---|---|---|---|---|");
}

pub fn run() {
    let t0 = crate::t0();
    let now = t0 + 600;
    let keys = bisc::Keys::new(5);
    let cs = bisc::ceilings(t0, 5, &keys);
    let grant = leaf_grant(now, 5);
    let root = fk::root_pk(&keys.root.public());
    let r = scenarios(now, 5)[0].1.clone();
    let caps = zf::Caps::default();
    let base: Vec<(Design, Biscuit)> = [Design::A, Design::B, Design::C].iter().map(|&d| (d, mint_d(d, &cs, Some((&grant, &keys.approver)), &keys.root))).collect();

    println!("## 1. biscuit-fast's hostile Datalog blocks (§4.2 there), appended in every design\n");
    head();
    for (label, code) in crate::hostile_datalog() {
        for (d, tok) in &base {
            let t = tok.append(BlockBuilder::new().code(&code).unwrap()).unwrap();
            report(label, *d, &t, &root, &caps, &r);
        }
    }

    println!("\n## 2. Hostile data blocks (design B; C refuses the same, since it runs the same extractor)\n");
    head();
    let tb = &base[1].1;
    let zb = |json: &str| tb.append(BlockBuilder::new().fact(fact("zone", &[string(json)])).unwrap()).unwrap();
    let leaf = zf::canon(&cs[5]);
    let big_caps = zf::Caps { max_token_bytes: usize::MAX, ..zf::Caps::default() };
    let pad = |n: usize| leaf.replacen("\"zone\":\"nightly-ci.w5\"", &format!("\"zone\":\"{}\"", "x".repeat(n)), 1);
    let t = zb(&pad(1 << 20));
    report("zone fact with a 1 MiB string", Design::B, &t, &root, &caps, &r);
    report("same, with no token cap (zone cap 8 KiB)", Design::B, &t, &root, &big_caps, &r);
    let nested = leaf.replacen("\"ops\":[\"http\"", &format!("\"ops\":[{}\"http\"{}", "[".repeat(3000), "]".repeat(3000)), 1);
    report("JSON nested 3,000 deep (6 KB)", Design::B, &zb(&nested), &root, &caps, &r);
    let t = tb.append((0..4000).fold(BlockBuilder::new().fact(fact("zone", &[string(&leaf)])).unwrap(), |b, i| b.fact(fact("zone", &[string(&format!("{i}"))])).unwrap())).unwrap();
    report("4,000 extra zone facts in one block", Design::B, &t, &root, &big_caps, &r);
    report("same, under the 32 KiB token cap", Design::B, &t, &root, &caps, &r);
    let t = (0..10).fold(tb.clone(), |t, _| append_zone_d(Design::B, &t, &cs[5]));
    report("10 more copies of the leaf zone (17 blocks)", Design::B, &t, &root, &caps, &r);
    let globby = Ceiling { reach: vec![Reach { host: "api.github.com".into(), methods: vec!["GET".into()], path: PathPat::Prefix("/{a,b}/**/x/".into()) }], ..cs[5].clone() };
    report("a reach path with glob metacharacters", Design::B, &append_zone_d(Design::B, tb, &globby), &root, &caps, &r);
    let upper = Ceiling { reach: vec![Reach { host: "API.github.com".into(), methods: vec!["get".into()], path: PathPat::Any }], ..cs[5].clone() };
    report("an upper-case host and lower-case method", Design::B, &append_zone_d(Design::B, tb, &upper), &root, &caps, &r);

    // The most expensive token the caps allow: as many blocks as fit in 32 KiB, each a leaf zone whose
    // reach starts with wildcard entries that never match (wicket's host_matches allocates per entry),
    // plus a full dangerous_ok list. Identical strings are interned once per token, so repeating one
    // zone fits the most blocks into the byte cap.
    let mut worst = cs[5].clone();
    let dummy = |i: usize| Reach { host: format!("*.d{i:02}.example.com"), methods: vec!["GET".into()], path: PathPat::Prefix("/p/".into()) };
    worst.reach = (0..caps.max_reach - cs[5].reach.len()).map(dummy).chain(cs[5].reach.iter().cloned()).collect();
    worst.dangerous_ok = (0..caps.max_list).map(dummy).collect();
    let mut t = tb.clone();
    let mut k = 0;
    loop {
        let next = append_zone_d(Design::B, &t, &worst);
        if next.to_vec().unwrap().len() > caps.max_token_bytes || next.block_count() > caps.max_blocks {
            break;
        }
        t = next;
        k += 1;
    }
    report(&format!("{k} blocks of {}-entry zones ({} B of JSON each): the costliest token the caps allow", worst.reach.len(), zf::canon(&worst).len()), Design::B, &t, &root, &caps, &r);
    let mut ta = base[0].1.clone();
    for _ in 0..k {
        ta = append_zone_d(Design::A, &ta, &worst);
    }
    report(&format!("the same {k} zones as design A blocks"), Design::A, &ta, &root, &zf::Caps { max_token_bytes: usize::MAX, ..caps.clone() }, &r);

    println!("\n## 3. If B carried wicket-core globs verbatim (a full ZoneSpec), what a hostile glob costs\n");
    println!("| glob | bytes | CompiledZone::new | median / p99 µs | one match median µs |\n|---|---|---|---|---|");
    let globs = [
        "/repos/acme/**".to_string(),
        format!("/{}/**", (0..40).map(|i| format!("{{a{i},b{i}}}")).collect::<Vec<_>>().join("")),
        format!("/{}", "**/".repeat(60)),
        format!("/{}x", "*a".repeat(120)),
        format!("/[{}]/**", (b'a'..=b'z').map(|c| c as char).collect::<String>().repeat(9)),
    ];
    for g in &globs {
        let spec = |g: &str| wicket_core::ZoneSpec {
            reach: vec![wicket_core::ReachRule { host: "h.example".into(), methods: vec!["GET".into()], paths: vec![g.to_string()], allow_dangerous: false }],
            ..serde_yaml_zone()
        };
        let res = wicket_core::CompiledZone::new(spec(g));
        let s = measure(crate::scale(200), || drop(black_box(wicket_core::CompiledZone::new(spec(g)).is_ok())));
        let m = match &res {
            Ok(z) => {
                let op = wicket_core::Op::egress(&wicket_core::TenantId::single(), &wicket_core::RunId("r".into()), "z", "GET", "h.example", &format!("/{}", "ab/".repeat(300)));
                format!("{:.2}", measure(crate::scale(2000), || drop(black_box(z.evaluate(&op)))).median)
            }
            Err(_) => "-".into(),
        };
        let shown: String = g.chars().take(48).collect();
        println!("| `{shown}{}` | {} | {} | {:.0} / {:.0} | {m} |", if g.len() > 48 { "…" } else { "" }, g.len(), res.as_ref().map(|_| "ok".to_string()).unwrap_or_else(|e| format!("error: {}", e.to_string().chars().take(60).collect::<String>())), s.median, s.p99);
    }
}

fn serde_yaml_zone() -> wicket_core::ZoneSpec {
    wicket_core::Manifest::from_yaml("task: t\nagent: { name: a }\nzone: { name: z, llm: {} }\n").unwrap().zone
}
