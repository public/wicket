mod bisc;
mod diff;
mod fk;
mod lint;
mod model;
mod plain;
mod stats;

use biscuit_auth::{AuthorizerLimits, Biscuit, BlockBuilder, KeyPair};
use fk::Engine;
use model::*;
use stats::measure;
use std::collections::HashSet;
use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn t0() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    now - now % 60
}

fn scale(n: usize) -> usize {
    let s: f64 = std::env::var("ITER_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1.0);
    ((n as f64) * s).max(20.0) as usize
}

fn engines_arg(default: &[Engine]) -> Vec<Engine> {
    match std::env::args().nth(2) {
        Some(a) => a.split(',').map(|s| Engine::parse(s).unwrap_or_else(|| panic!("unknown engine {s}"))).collect(),
        None => default.to_vec(),
    }
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "correct" => {
            let mut all = true;
            for e in engines_arg(&Engine::ALL) {
                all &= correct(e);
            }
            println!("\n{}", if all { "ALL ENGINES: ALL PASS" } else { "SOME CHECKS FAILED" });
        }
        "bench" => bench(),
        "limits" => limits(),
        "diff" => diff::run(),
        "profile" => profile(),
        "threads" => threads(),
        _ => eprintln!("usage: biscuit-fast correct|bench|limits|diff|profile|threads [engines]"),
    }
}

struct Built {
    keys: bisc::Keys,
    cs: Vec<Ceiling>,
    grant: Grant,
    chain: bisc::Chain,
}

fn build(t0: u64, depth: usize) -> Built {
    let keys = bisc::Keys::new(5);
    let cs = bisc::ceilings(t0, depth, &keys);
    let grant = leaf_grant(t0 + 600, depth);
    let chain = bisc::mint(&cs, Some((&grant, &keys.approver)), &keys.root);
    Built { keys, cs, grant, chain }
}

// ---------------------------------------------------------------------------------------------
fn check(name: &str, cond: bool, detail: &str) -> bool {
    println!("[{}] {name}{}", if cond { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!("\n       {detail}") });
    cond
}

fn short(e: &Option<String>) -> String {
    let s = e.clone().unwrap_or_else(|| "ok".into());
    if s.len() > 300 {
        format!("{}…", &s[..300])
    } else {
        s
    }
}

struct Outcome {
    ok: bool,
    err: Option<String>,
}

/// Parse with the engine's parser (stock for Stock, the fork otherwise).
fn parses(e: Engine, bytes: &[u8], root: &biscuit_auth::PublicKey) -> Result<(), String> {
    match e {
        Engine::Stock => Biscuit::from(bytes, *root).map(|_| ()).map_err(|e| e.to_string()),
        _ => fork::Biscuit::from(bytes, fk::root_pk(root)).map(|_| ()).map_err(|e| e.to_string()),
    }
}

/// The 45 checks of biscuit-depth §5, with every decision and every parse made by engine `e`.
fn correct(e: Engine) -> bool {
    println!("\n# Correctness: {}\n", e.name());
    let t0 = t0();
    let now = t0 + 600;
    let b = build(t0, 5);
    let root = b.keys.root.public();
    let dec = |t: &Biscuit, r: &Request| -> Outcome {
        let res = fk::load_for(e, t, &root).decide(r);
        Outcome { ok: res.is_ok(), err: res.err() }
    };
    let tok = &b.chain.token;
    let sc = scenarios(now, 5);
    let req = |i: usize| sc[i].1.clone();
    let mut all = true;
    let mut n = 0;
    let mut ok = |name: &str, c: bool, d: &str| {
        n += 1;
        all &= check(name, c, d)
    };

    println!("## Baseline (depth 5, {} checks, grant at leaf)", b.chain.checks);
    for (name, r) in &sc {
        let o = dec(tok, r);
        let want = !name.starts_with('B');
        ok(&format!("{name}: {}", if o.ok { "allowed" } else { "denied" }), o.ok == want, &if o.ok { String::new() } else { short(&o.err) });
    }

    println!("\n## A holder can't widen");
    let widen = |code: &str| tok.append(BlockBuilder::new().code(code).unwrap()).unwrap();
    let t = widen("check if true;");
    let o = dec(&t, &req(1));
    ok("appending `check if true` does not admit B (outside reach)", !o.ok, &short(&o.err));
    let t = widen(r#"approved("g-x", "api.github.com", "GET", "/repos/other/x/issues");"#);
    let o = dec(&t, &req(1));
    ok("a forged `approved` fact in a holder block is not trusted", !o.ok, &short(&o.err));
    let t = widen("approved($g, $h, $m, $p) <- host($h), method($m), path($p), uses_left($g, $n);");
    let o = dec(&t, &req(1));
    ok("a holder rule deriving `approved` is not trusted", !o.ok, &short(&o.err));
    let attacker = KeyPair::new();
    let t = bisc::append_grant(tok, r#"approved("g-x", "api.github.com", "GET", "/repos/other/x/issues");"#, &attacker);
    let o = dec(&t, &req(1));
    ok("a third-party approval signed by an untrusted key is ignored", !o.ok, &short(&o.err));
    let leaf_self = bisc::append_grant(tok, r#"approved("g-x", "api.github.com", "POST", "/repos/acme/api/issues");"#, &b.keys.grantor[5]);
    let mut r = req(0);
    r.op = Op::Http { host: "api.github.com".into(), method: "POST".into(), path: "/repos/acme/api/issues".into(), risk: 1, inject: Some(GH_INJECT.into()) };
    let o = dec(&leaf_self, &r);
    ok("a box can't self-grant (no block trusts the leaf's own grantor key)", !o.ok, &short(&o.err));
    let ep = fork::BlockBuilder::new().code("allow if true;");
    let es = BlockBuilder::new().code("allow if true;");
    let is_err = if e == Engine::Stock { es.is_err() } else { ep.is_err() };
    ok("a block can't carry an allow policy (parse error)", is_err, "");
    let t = widen(&format!("check if time($t), $t <= {};", rfc3339(t0 + 48 * 3600)));
    let mut r = req(0);
    r.time = b.cs[5].not_after + 1;
    let o = dec(&t, &r);
    ok("a later expiry in a new block does not extend the leaf's", !o.ok, &short(&o.err));
    let mut r = req(0);
    r.tenant = "other-tenant".into();
    let o = dec(tok, &r);
    ok("a request served for another tenant is refused (authorizer tenant check)", !o.ok, &short(&o.err));

    println!("\n## A node can narrow");
    let t = widen(r#"check if op($o), $o != "http" or method("GET");"#);
    ok("after appending `method GET only`: A still allowed", dec(&t, &req(0)).ok, "");
    let o = dec(&t, &req(2));
    ok("after appending `method GET only`: C (granted PUT) now denied", !o.ok, &short(&o.err));
    let t = widen(r#"check if op($o), $o != "spawn";"#);
    ok("after appending `no spawn`: D denied", !dec(&t, &req(3)).ok, "");

    println!("\n## Expiry and lease state");
    let mut r = req(0);
    r.time = b.cs[5].not_after;
    ok("A at exactly the leaf expiry: allowed", dec(tok, &r).ok, "");
    r.time += 1;
    let o = dec(tok, &r);
    ok("A one second after the leaf expiry: denied", !o.ok, &short(&o.err));
    let mut r = req(2);
    r.time = b.grant.not_after + 1;
    let o = dec(tok, &r);
    ok("C after the grant's expiry: denied", !o.ok, &short(&o.err));
    let mut r = req(0);
    r.time = b.grant.not_after + 1;
    ok("A after the grant's expiry: still allowed (an expired lease doesn't kill the chain)", dec(tok, &r).ok, "");
    let mut r = req(2);
    r.uses_left = vec![("g-7f3a".into(), 0)];
    ok("C with uses_left = 0 (ledger): denied", !dec(tok, &r).ok, "");
    let mut r = req(2);
    r.uses_left.clear();
    ok("C with no ledger entry: denied", !dec(tok, &r).ok, "");
    let mut r = req(2);
    r.epoch = 4;
    ok("C in a later box epoch: denied", !dec(tok, &r).ok, "");
    let child = tok.append(BlockBuilder::new().code(&bisc::compile(&Ceiling { box_prefix: format!("{}/b6", box_id(5)), ..b.cs[5].clone() }, false, "acme").0).unwrap()).unwrap();
    let mut r = req(2);
    r.box_id = format!("{}/b6", box_id(5));
    ok("C from the leaf's child b6 (inherits the grant block): denied", !dec(&child, &r).ok, "");
    let mut r = req(0);
    r.box_id = format!("{}/b6", box_id(5));
    ok("A from b6: allowed", dec(&child, &r).ok, "");
    let mut r = req(0);
    r.box_id = "b0/b1/b9".into();
    ok("A presented for a box outside the chain's subtree: denied", !dec(tok, &r).ok, "");

    println!("\n## Agent grants (#50): signed by the parent box's grantor key");
    let parent_only = bisc::mint(&b.cs, None, &b.keys.root).token;
    let g = |m: &str, p: &str, risk: i64, key: &KeyPair| {
        let gr = Grant { method: m.into(), path: p.into(), ..b.grant.clone() };
        let t = bisc::append_grant(&parent_only, &bisc::grant_code(&gr), key);
        let mut r = req(0);
        r.op = Op::Http { host: "api.github.com".into(), method: m.into(), path: p.into(), risk, inject: Some(GH_INJECT.into()) };
        dec(&t, &r)
    };
    let o = g("POST", "/repos/acme/api/issues", 1, &b.keys.grantor[4]);
    ok("parent (b4) grants POST /repos/acme/api/issues (within b4, outside leaf): allowed", o.ok, &short(&o.err));
    let o = g("POST", "/repos/acme/infra/issues", 1, &b.keys.grantor[4]);
    ok("parent (b4) grants POST /repos/acme/infra/issues (outside b4's own reach): denied", !o.ok, &short(&o.err));
    let o = g("PUT", "/repos/acme/api/pulls/7/merge", 3, &b.keys.grantor[4]);
    ok("parent (b4) grants a risk-3 PUT it couldn't do itself: denied", !o.ok, &short(&o.err));
    let o = g("PUT", "/repos/acme/api/pulls/7/merge", 3, &b.keys.approver);
    ok("the human approval service grants the same PUT: allowed", o.ok, &short(&o.err));

    println!("\n## Revocation ids identify every block; revoking one kills its subtree");
    let keys = bisc::Keys::new(5);
    let cs3 = bisc::ceilings(t0, 3, &keys);
    let p3 = bisc::mint(&cs3, None, &keys.root).token;
    let kid = |name: &str| {
        let mut c = level(t0, 4, vec![bisc::hexkey(&keys.approver.public()), bisc::hexkey(&keys.grantor[3].public())]);
        c.box_prefix = format!("{}/{name}", box_id(3));
        p3.append(BlockBuilder::new().code(&bisc::compile(&c, false, "acme").0).unwrap()).unwrap()
    };
    let (c1, c2) = (kid("b4a"), kid("b4b"));
    // For fork engines the ids come from the fork's parse of the same bytes.
    let ids = |t: &Biscuit| -> Vec<Vec<u8>> {
        match e {
            Engine::Stock => t.revocation_identifiers(),
            _ => fk::load(t, &keys.root.public()).revocation_identifiers(),
        }
    };
    let (i1, i2, ip) = (ids(&c1), ids(&c2), ids(&p3));
    let same_as_stock = i1 == c1.revocation_identifiers() && ip == p3.revocation_identifiers();
    ok(
        "siblings share the revocation ids of their common prefix (blocks 0-3) and differ at block 4",
        i1[..4] == i2[..4] && i1[4] != i2[4] && ip[..] == i1[..4] && same_as_stock,
        "",
    );
    let rev = |t: &Biscuit, list: &HashSet<Vec<u8>>| ids(t).iter().any(|id| list.contains(id));
    let only_c1: HashSet<Vec<u8>> = [i1[4].clone()].into();
    ok("revoking c1's own block: c1 revoked, c2 and parent not", rev(&c1, &only_c1) && !rev(&c2, &only_c1) && !rev(&p3, &only_c1), "");
    let sub: HashSet<Vec<u8>> = [ip[2].clone()].into();
    ok("revoking b2's spawn block: b2's whole subtree (b3, c1, c2) revoked", rev(&c1, &sub) && rev(&c2, &sub) && rev(&p3, &sub), "");
    let gid = match e {
        Engine::Stock => tok.revocation_identifiers(),
        _ => fk::load(tok, &root).revocation_identifiers(),
    };
    ok("the third-party grant block has its own id (revoke one lease without the zone)", gid.len() == 7 && gid[6] != gid[5], "");

    println!("\n## Tampering");
    let bytes = tok.to_vec().unwrap();
    let mut accepted = 0;
    for i in 0..bytes.len() {
        let mut x = bytes.clone();
        x[i] ^= 0x01;
        if parses(e, &x, &root).is_ok() {
            accepted += 1;
        }
    }
    ok(&format!("flipping each of the {} bytes in turn: {accepted} variants parse", bytes.len()), accepted == 0, "");
    {
        use prost::Message;
        let pb = biscuit_auth::format::schema::Biscuit::decode(bytes.as_slice()).unwrap();
        let mut drop_last = pb.clone();
        drop_last.blocks.pop();
        let res = parses(e, &drop_last.encode_to_vec(), &root);
        ok("dropping the last block (the node holds only this token's proof): rejected", res.is_err(), &format!("{:?}", res.err()));
        let mut drop_mid = pb.clone();
        drop_mid.blocks.remove(2);
        let res = parses(e, &drop_mid.encode_to_vec(), &root);
        ok("removing a middle spawn block (block 3): rejected", res.is_err(), &format!("{:?}", res.err()));
        let mut swap = pb.clone();
        swap.blocks.swap(1, 2);
        let res = parses(e, &swap.encode_to_vec(), &root);
        ok("reordering two spawn blocks: rejected", res.is_err(), &format!("{:?}", res.err()));
    }
    let other = KeyPair::new();
    ok("the token under the wrong root key fails", parses(e, &bytes, &other.public()).is_err(), "");
    let req3 = c1.third_party_request().unwrap();
    let blk = req3.create_block(&keys.approver.private(), BlockBuilder::new().code(&bisc::grant_code(&leaf_grant(now, 4))).unwrap()).unwrap();
    let res = c2.append_third_party(keys.approver.public(), blk).and_then(|t| t.to_vec()).map_err(|e| e.to_string()).and_then(|v| parses(e, &v, &keys.root.public()));
    ok("a third-party block made for chain c1 can't be moved to sibling c2", res.is_err(), &format!("{:?}", res.err()));
    let sealed_ok = match e {
        Engine::Stock => tok.seal().unwrap().append(BlockBuilder::new()).is_err(),
        _ => fk::load(tok, &root).seal().unwrap().append(fork::BlockBuilder::new()).is_err(),
    };
    ok("a sealed token can't be attenuated further", sealed_ok, "");

    println!("\n## Fallback (plain records) checks");
    let pk2 = plain::PlainKeys::new();
    let pcs = plain::plain_ceilings(t0, 5, &pk2);
    let pc = plain::mint(&pcs, Some(&b.grant), &pk2);
    let trust = pk2.trust();
    let v = plain::verify(&pc, &trust).unwrap();
    let res: Vec<bool> = sc.iter().map(|(_, r)| plain::authorize(&v, r)).collect();
    ok("plain: A allowed, B denied, C granted, D allowed", res == [true, false, true, true], &format!("{res:?}"));
    let mut wide = pc.clone();
    let mut prev = plain::last_hash(&wide);
    let mut w = pcs[5].clone();
    w.reach.push(Reach { host: "api.github.com".into(), methods: vec!["GET".into()], path: PathPat::Any });
    w.box_prefix = box_id(5);
    plain::append(&mut wide, &mut prev, "node-lon-1", plain::Body::Zone(w.clone()), &pk2.node);
    let v = plain::verify(&wide, &trust).unwrap();
    ok("plain: a widening link signed by a node key doesn't admit B (intersection)", !plain::authorize(&v, &sc[1].1), "");
    ok("plain: the mint-time narrowing check names the widening", plain::narrows(&w, &pcs[5]).is_err(), &format!("{:?}", plain::narrows(&w, &pcs[5]).err()));
    let mut accepted = 0;
    for i in 0..pc.len() {
        let mut x = pc.clone();
        x[i] ^= 0x01;
        if plain::verify(&x, &trust).is_ok() {
            accepted += 1;
        }
    }
    ok(&format!("plain: flipping each of the {} bytes: {accepted} variants verify", pc.len()), accepted == 0, "");
    let mut narrow_ok = true;
    for d in 1..=5 {
        narrow_ok &= plain::narrows(&pcs[d], &pcs[d - 1]).is_ok();
    }
    ok("plain: every scenario level narrows its parent (hand-written check)", narrow_ok, "");

    println!("\n{}: {n} checks, {}", e.name(), if all { "ALL PASS" } else { "SOME CHECKS FAILED" });
    all
}

// ---------------------------------------------------------------------------------------------
fn row(name: &str, s: &stats::Stats) {
    println!("| {name} | {s} |");
}

fn header(title: &str) {
    println!("\n### {title}\n\n| what | median µs | p99 µs | mean µs | max µs |\n|---|---|---|---|---|");
}

fn bench_variants() -> Vec<String> {
    std::env::var("BENCH").unwrap_or_else(|_| "stock,main,s1,s2,s3,plain".into()).split(',').map(String::from).collect()
}

/// Same method as biscuit-depth: n/10 warm-up calls, then n timed calls (Instant around each).
/// WARM = the verified token is cached; per request: revocation check + decision with pre-built facts.
fn bench() {
    let t0 = t0();
    let now = t0 + 600;
    let (n_cold, n_warm) = (scale(3000), scale(20000));
    let vs = bench_variants();
    let want = |v: &str| vs.iter().any(|x| x == v);
    println!("iterations: cold {n_cold}, warm {n_warm}; variants {vs:?}");
    let revset: HashSet<Vec<u8>> = (0..10_000u32).map(|i| { let mut v = vec![0u8; 64]; v[..4].copy_from_slice(&i.to_be_bytes()); v }).collect();
    let mut summary: Vec<(String, usize, Vec<(f64, f64)>)> = Vec::new();

    for depth in 1..=5 {
        let b = build(t0, depth);
        let bytes = b.chain.token.to_vec().unwrap();
        let root = b.keys.root.public();
        let froot = fk::root_pk(&root);
        let tok = &b.chain.token;
        let ftok = fk::load(tok, &root);
        let ids = tok.revocation_identifiers();
        println!("\n## depth {depth}: {} blocks, {} checks, {} bytes", tok.block_count(), b.chain.checks, bytes.len());
        let sc = scenarios(now, depth);
        let mut go = |label: &str, f: &mut dyn FnMut(&Request, &[biscuit_auth::builder::Fact], &[fork::builder::Fact]) -> bool| {
            header(&format!("depth {depth}: WARM, {label}"));
            let mut cells = Vec::new();
            for (name, r) in &sc {
                let facts = bisc::request_facts(r);
                let ffacts = fk::request_facts(r);
                assert_eq!(f(r, &facts, &ffacts), !name.starts_with('B'), "{label} {name} depth {depth}");
                let s = measure(n_warm, || {
                    let rev = ids.iter().any(|i| revset.contains(i));
                    black_box(!rev && f(r, &facts, &ffacts));
                });
                row(&format!("WARM {name}"), &s);
                cells.push((s.median, s.p99));
            }
            summary.push((label.to_string(), depth, cells));
        };
        if want("stock") {
            let base = bisc::base_authorizer(bisc::generous());
            go("stock 6.0.0 (build per request)", &mut |_, facts, _| bisc::authorize_fast(&base, tok, facts));
        }
        if want("main") {
            let base = fk::base_builder();
            go("upstream main (build per request)", &mut |_, _, ff| fk::authorize_main(&base, &ftok, ff).is_ok());
        }
        if want("s1") {
            let l = fk::wall();
            let mut s = fk::prepare(&ftok, &l).session();
            go("step 1: prepared, per-thread session, overlay", &mut |_, _, ff| s.authorize(ff, &l).is_ok());
        }
        if want("s2") {
            let l = fk::fuel();
            let mut s = fk::prepare(&ftok, &l).session();
            go("step 2: as step 1, fuel only", &mut |_, _, ff| s.authorize(ff, &l).is_ok());
        }
        if want("s3") {
            let l = fk::fuel();
            let c = fk::prepare(&ftok, &l).compile();
            go("step 3: compiled, shared", &mut |_, _, ff| c.authorize(ff, &l).is_ok());
            if want("s3x") {
                go("step 3: compiled, decision only (early exit)", &mut |_, _, ff| c.allows(ff, &l));
            }
        }
        if want("plain") && matches!(depth, 1 | 3 | 5) {
            let pk = plain::PlainKeys::new();
            let cs = plain::plain_ceilings(t0, depth, &pk);
            let chain = plain::mint(&cs, Some(&leaf_grant(now, depth)), &pk);
            let v = plain::verify(&chain, &pk.trust()).unwrap();
            let revset32: HashSet<[u8; 32]> = (0..10_000u32).map(|i| { let mut v = [0u8; 32]; v[..4].copy_from_slice(&i.to_be_bytes()); v }).collect();
            header(&format!("depth {depth}: WARM, plain records"));
            let mut cells = Vec::new();
            for (name, r) in &sc {
                assert_eq!(plain::authorize(&v, r), !name.starts_with('B'));
                let s = measure(n_warm, || { black_box(!plain::revoked(&v, &revset32) && plain::authorize(&v, black_box(r))); });
                row(&format!("WARM {name}"), &s);
                cells.push((s.median, s.p99));
            }
            summary.push(("plain records".into(), depth, cells));
        }
        if want("cold") {
            header(&format!("depth {depth}: once per token and COLD (fork)"));
            let l = fk::fuel();
            row("fork parse + verify (Biscuit::from)", &measure(n_cold, || { black_box(fork::Biscuit::from(black_box(&bytes), froot.clone()).unwrap()); }));
            row("prepare (build + translate + saturate)", &measure(n_cold, || { black_box(fk::prepare(&ftok, &l)); }));
            let p = fk::prepare(&ftok, &l);
            row("compile a prepared token", &measure(n_cold, || { black_box(p.compile()); }));
            row("structural lint", &measure(n_cold, || { black_box(lint::lint(&ftok, bytes.len(), &lint::Policy::default()).is_ok()); }));
            let ffacts = fk::request_facts(&sc[0].1);
            row("COLD A: parse+verify+revocation+lint+prepare+compile+decide", &measure(n_cold, || {
                let t = fork::Biscuit::from(black_box(&bytes), froot.clone()).unwrap();
                let rev = t.revocation_identifiers().iter().any(|i| revset.contains(i));
                let ok = lint::lint(&t, bytes.len(), &lint::Policy::default()).is_ok();
                let c = fk::prepare(&t, &l).compile();
                black_box(!rev && ok && c.authorize(&ffacts, &l).is_ok());
            }));
            row("building the request facts (fork builder types)", &measure(n_warm, || { black_box(fk::request_facts(black_box(&sc[0].1))); }));
        }
    }

    println!("\n## Summary: WARM median / p99 µs\n\n| variant | depth | A | B | C | D |\n|---|---|---|---|---|---|");
    for (label, depth, cells) in &summary {
        let c: Vec<String> = cells.iter().map(|(m, p)| format!("{m:.1} / {p:.1}")).collect();
        println!("| {label} | {depth} | {} |", c.join(" | "));
    }
}

// ---------------------------------------------------------------------------------------------
fn limits() {
    let t0 = t0();
    let now = t0 + 600;
    println!("## Fuel used per request (fork, deterministic limits {:?})\n", fk::fuel());
    println!("| depth | scenario | decision | step 2 steps | step 3 steps | step 3 on the compiled path | facts | iterations | stock 6.0.0 Datalog µs |\n|---|---|---|---|---|---|---|---|---|");
    let mut max_steps = 0;
    for depth in 1..=5 {
        let b = build(t0, depth);
        let ftok = fk::load(&b.chain.token, &b.keys.root.public());
        let l = fk::fuel();
        let p = fk::prepare(&ftok, &l);
        let mut s = p.session();
        let c = p.compile();
        if let Some(why) = c.not_compiled_reason() {
            println!("| {depth} | not compiled: {why} | | | | | | | |");
        }
        for (name, r) in scenarios(now, depth) {
            let ff = fk::request_facts(&r);
            let d2 = s.authorize(&ff, &l).is_ok();
            let st = s.last_run();
            let d3 = c.authorize(&ff, &l).is_ok();
            let ct = c.last_run();
            assert_eq!(d2, d3);
            max_steps = max_steps.max(st.steps).max(ct.steps);
            let o = bisc::authorize(&bisc::base_authorizer(bisc::generous()), &b.chain.token, &r);
            println!("| {depth} | {name} | {} | {} | {} | {} | {} | {} | {:.1} |", if d3 { "allow" } else { "deny" }, st.steps, ct.steps, c.is_compiled() && !ct.fallback, st.facts, st.iterations, o.exec.map(|d| d.as_nanos() as f64 / 1000.0).unwrap_or(-1.0));
        }
        println!("| {depth} | (prepare: saturating the token's own facts) | | {} | | | {} | | |", p.prepare_steps(), p.base_fact_count());
    }
    println!("\nmost steps any legitimate request used: {max_steps}; limit {} ({}x headroom)", fk::FUEL_STEPS, fk::FUEL_STEPS / max_steps.max(1));

    println!("\n## Same decision whatever the load: a request at the limit\n");
    let b = build(t0, 5);
    let ftok = fk::load(&b.chain.token, &b.keys.root.public());
    let r = scenarios(now, 5)[0].1.clone();
    let ff = fk::request_facts(&r);
    let p = fk::prepare(&ftok, &fk::fuel());
    let c = p.compile();
    let _ = c.authorize(&ff, &fk::fuel());
    let need = c.last_run().steps;
    for (label, steps) in [("max_steps = steps used - 1", need - 1), ("max_steps = steps used", need)] {
        let l = fork::PreparedLimits { max_steps: steps, ..fk::fuel() };
        let res: Vec<String> = (0..5).map(|_| match c.authorize(&ff, &l) { Ok(_) => "allowed".into(), Err(e) => e.to_string().chars().take(60).collect() }).collect();
        println!("- step 3, request A, {label} ({steps}): {:?} (5 runs)", res);
    }

    println!("\n## Regex cost calibration\n");
    let pat = "^/repos/[a-z]+/api/pulls/[0-9]+$|^x7$";
    let s = measure(scale(500), || { black_box(regex_compile(pat)); });
    println!("- Regex::new for a {}-byte hostile pattern: median {:.1} µs, p99 {:.1} µs", pat.len(), s.median, s.p99);
    let l = fk::fuel();
    let mut sess = p.session();
    let ff = fk::request_facts(&scenarios(now, 5)[1].1);
    let sb = measure(scale(2000), || { black_box(sess.authorize(&ff, &l).is_ok()); });
    let _ = sess.authorize(&ff, &l);
    let st = sess.last_run().steps;
    println!("- step 2 engine: request B uses {st} steps in {:.1} µs median: {:.0} ns per step", sb.median, sb.median * 1000.0 / st as f64);
    println!("- so one regex compile ≈ {:.0} steps; the fork charges 16 steps per pattern byte = {} steps for this pattern", s.median * 1000.0 / (sb.median * 1000.0 / st as f64), pat.len() * 16);

    println!("\n## Hostile holder blocks (appended to the depth-5 chain, request A)\n");
    let n = scale(200);
    let pol = lint::Policy::default();
    for (label, code) in hostile() {
        let t = b.chain.token.append(BlockBuilder::new().code(&code).unwrap()).unwrap();
        let bytes = t.to_vec().unwrap();
        println!("### {label} (token {} bytes)\n", bytes.len());
        let r = scenarios(now, 5)[0].1.clone();
        let facts = bisc::request_facts(&r);
        for (ln, lim) in [("stock 6.0.0, defaults (1000 facts, 100 iterations, 1 ms)", AuthorizerLimits::default()), ("stock 6.0.0, max_time 50 ms", bisc::generous())] {
            let base = bisc::base_authorizer(lim);
            let o = bisc::authorize(&base, &t, &r);
            let s = measure(n, || { black_box(bisc::authorize_fast(&base, &t, &facts)); });
            println!("- {ln}: {} — per request median {:.0} µs, p99 {:.0} µs", if o.ok { "allowed".into() } else { format!("denied: {}", short(&o.err)) }, s.median, s.p99);
        }
        let ft = fk::load(&t, &b.keys.root.public());
        let ff = fk::request_facts(&r);
        let l = fk::fuel();
        let sp = measure(n, || { black_box(fk::prepare(&ft, &l)); });
        let p = fk::prepare(&ft, &l);
        println!("- fork prepare (once per token) under fuel: {} — median {:.0} µs, p99 {:.0} µs, {} steps", p.prepare_error().map(|e| format!("error: {e}")).unwrap_or("ok".into()), sp.median, sp.p99, p.prepare_steps());
        let mut sess = p.session();
        let res = sess.authorize(&ff, &l);
        let s2 = measure(n, || { black_box(sess.authorize(&ff, &l).is_ok()); });
        println!("- step 2 per request: {} — median {:.1} µs, p99 {:.1} µs, {} steps", res.map(|_| "allowed".to_string()).unwrap_or_else(|e| format!("denied: {}", short(&Some(e.to_string())))), s2.median, s2.p99, sess.last_run().steps);
        let sc_ = measure(n, || { black_box(p.compile()); });
        let c = p.compile();
        let res = c.authorize(&ff, &l);
        let s3 = measure(n, || { black_box(c.authorize(&ff, &l).is_ok()); });
        println!("- step 3: compile {:.0} µs median{}; per request: {} — median {:.1} µs, p99 {:.1} µs, {} steps", sc_.median, if c.is_compiled() { "" } else { " (not compiled: prepare error)" }, res.map(|_| "allowed".to_string()).unwrap_or_else(|e| format!("denied: {}", short(&Some(e.to_string())))), s3.median, s3.p99, c.last_run().steps);
        let lr = lint::lint(&ft, bytes.len(), &pol);
        let sl = measure(n, || { black_box(lint::lint(&ft, bytes.len(), &pol).is_ok()); });
        println!("- structural lint: {} — median {:.1} µs, p99 {:.1} µs\n", lr.err().map(|e| format!("rejected: {e}")).unwrap_or("accepted".into()), sl.median, sl.p99);
    }

    println!("## Lint on the legitimate chains and on the correctness suite's holder blocks\n");
    for depth in 0..=5 {
        let b = build(t0, depth);
        let ft = fk::load(&b.chain.token, &b.keys.root.public());
        let len = b.chain.token.to_vec().unwrap().len();
        let s = measure(scale(2000), || { black_box(lint::lint(&ft, len, &pol).is_ok()); });
        println!("- depth {depth}: {} — median {:.1} µs, p99 {:.1} µs", lint::lint(&ft, len, &pol).err().unwrap_or("accepted".into()), s.median, s.p99);
    }
    let tok = &b.chain.token;
    for code in [
        "check if true;",
        r#"approved("g-x", "api.github.com", "GET", "/repos/other/x/issues");"#,
        "approved($g, $h, $m, $p) <- host($h), method($m), path($p), uses_left($g, $n);",
        r#"check if op($o), $o != "http" or method("GET");"#,
        r#"check if path($p), $p.matches("^/repos/.*");"#,
        r#"check if resource($r);"#,
    ] {
        let t = tok.append(BlockBuilder::new().code(code).unwrap()).unwrap();
        let ft = fk::load(&t, &b.keys.root.public());
        println!("- appended `{code}`: {}", lint::lint(&ft, t.to_vec().unwrap().len(), &pol).err().unwrap_or("accepted".into()));
    }
    let attacker = KeyPair::new();
    let t = bisc::append_grant(tok, r#"approved("g-x", "api.github.com", "GET", "/repos/other/x/issues");"#, &attacker);
    let ft = fk::load(&t, &b.keys.root.public());
    println!("- third-party grant from an untrusted key: {}", lint::lint(&ft, t.to_vec().unwrap().len(), &pol).err().unwrap_or("accepted".into()));
}

fn regex_compile(p: &str) -> bool {
    // biscuit-auth evaluates `.matches()` with `Regex::new(pattern)` on every evaluation.
    regex::Regex::new(p).is_ok()
}

pub fn hostile() -> Vec<(&'static str, String)> {
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

// ---------------------------------------------------------------------------------------------
/// Hot loop for callgrind: PROFILE_VARIANT = s1 | s2 | s3 | main, PROFILE_REQ = 0..3.
fn profile() {
    let t0 = t0();
    let now = t0 + 600;
    let b = build(t0, 5);
    let ftok = fk::load(&b.chain.token, &b.keys.root.public());
    let ri: usize = std::env::var("PROFILE_REQ").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let r = scenarios(now, 5)[ri].1.clone();
    let ff = fk::request_facts(&r);
    let n = scale(20000);
    let l = fk::fuel();
    let v = std::env::var("PROFILE_VARIANT").unwrap_or_else(|_| "s3".into());
    let start = Instant::now();
    match v.as_str() {
        "main" => {
            let base = fk::base_builder();
            for _ in 0..n {
                black_box(fk::authorize_main(&base, &ftok, &ff).is_ok());
            }
        }
        "s1" | "s2" => {
            let l = if v == "s1" { fk::wall() } else { l };
            let mut s = fk::prepare(&ftok, &l).session();
            for _ in 0..n {
                black_box(s.authorize(&ff, &l).is_ok());
            }
        }
        _ => {
            let c = fk::prepare(&ftok, &l).compile();
            for _ in 0..n {
                black_box(c.authorize(&ff, &l).is_ok());
            }
        }
    }
    println!("{v}: {n} decisions in {:?}", start.elapsed());
}

/// The compiled authorizer is shared by reference between threads: same decisions, no copies.
fn threads() {
    let t0 = t0();
    let now = t0 + 600;
    let b = build(t0, 5);
    let ftok = fk::load(&b.chain.token, &b.keys.root.public());
    let l = fk::fuel();
    let c = std::sync::Arc::new(fk::prepare(&ftok, &l).compile());
    let sc: Vec<(bool, Vec<fork::builder::Fact>)> = scenarios(now, 5).iter().map(|(n, r)| (!n.starts_with('B'), fk::request_facts(r))).collect();
    let sc = std::sync::Arc::new(sc);
    let n = scale(50_000);
    for threads in [1usize, 2, 3] {
        let start = Instant::now();
        let hs: Vec<_> = (0..threads)
            .map(|_| {
                let c = c.clone();
                let sc = sc.clone();
                let l = l.clone();
                std::thread::spawn(move || {
                    let mut wrong = 0;
                    for i in 0..n {
                        let (want, f) = &sc[i % 4];
                        if c.authorize(f, &l).is_ok() != *want {
                            wrong += 1;
                        }
                    }
                    wrong
                })
            })
            .collect();
        let wrong: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
        let el = start.elapsed();
        println!("{threads} thread(s) sharing one CompiledAuthorizer: {} decisions, {wrong} wrong, {:.0} decisions/s", n * threads, (n * threads) as f64 / el.as_secs_f64());
    }
    let _ = Duration::from_secs(0);
}
