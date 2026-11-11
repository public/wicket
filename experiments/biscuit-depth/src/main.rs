mod bisc;
mod model;
mod plain;
mod stats;

use biscuit_auth::{AuthorizerLimits, Biscuit, BlockBuilder, KeyPair};
use model::*;
use stats::measure;
use std::collections::HashSet;
use std::hint::black_box;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn t0() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    now - now % 60
}

fn scale(n: usize) -> usize {
    let s: f64 = std::env::var("ITER_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1.0);
    ((n as f64) * s).max(20.0) as usize
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "show" => show(),
        "correct" => correct(),
        "bench" => bench(),
        "limits" => limits(),
        "profile" => profile(),
        _ => eprintln!("usage: biscuit-depth show|correct|bench|limits"),
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
fn show() {
    let t0 = t0();
    let b = build(t0, 5);
    println!("# Depth-5 chain, generated Datalog (as compiled)\n");
    for (i, c) in b.chain.codes.iter().enumerate() {
        let kind = if i == 0 {
            "authority (root key)".to_string()
        } else if i <= 5 {
            format!("spawn block {i} (box {})", box_id(i))
        } else {
            "third-party grant block (approver key)".to_string()
        };
        println!("## block {i}: {kind}\n```datalog\n{c}```\n");
    }
    println!("## as printed back by biscuit-auth (block 0 and block 6)\n```\n{}\n---\n{}\n```", b.chain.token.print_block_source(0).unwrap(), b.chain.token.print_block_source(6).unwrap());
    println!("\n# Sizes\n");
    println!("| depth | blocks | checks | raw bytes | base64 chars | plain raw | plain base64 |");
    println!("|---|---|---|---|---|---|---|");
    for d in 0..=5 {
        let b = build(t0, d);
        let raw = b.chain.token.to_vec().unwrap();
        let b64 = b.chain.token.to_base64().unwrap();
        let pk = plain::PlainKeys::new();
        let pc = plain::mint(&plain::plain_ceilings(t0, d, &pk), Some(&leaf_grant(t0 + 600, d)), &pk);
        let pb64 = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &pc);
        println!("| {d} | {} | {} | {} | {} | {} | {} |", b.chain.token.block_count(), b.chain.checks, raw.len(), b64.len(), pc.len(), pb64.len());
    }
    println!("\n# Size variant: spawn blocks keep only statements that differ from the parent's\n");
    println!("| depth | checks | raw bytes | base64 chars | all scenarios still decide the same |");
    println!("|---|---|---|---|---|");
    for d in 0..=5 {
        let keys = bisc::Keys::new(5);
        let cs = bisc::ceilings(t0, d, &keys);
        let g = leaf_grant(t0 + 600, d);
        let full = bisc::mint(&cs, Some((&g, &keys.approver)), &keys.root);
        let dif = bisc::mint_with(&cs, Some((&g, &keys.approver)), &keys.root, true);
        let base = bisc::base_authorizer(bisc::generous());
        let same = scenarios(t0 + 600, d).iter().all(|(_, r)| bisc::authorize(&base, &full.token, r).ok == bisc::authorize(&base, &dif.token, r).ok);
        println!("| {d} | {} | {} | {} | {same} |", dif.checks, dif.token.to_vec().unwrap().len(), dif.token.to_base64().unwrap().len());
    }
    // Per-block growth: serialize prefixes.
    println!("\n# Per-block size (depth-5 chain)\n");
    let keys = bisc::Keys::new(5);
    let cs = bisc::ceilings(t0, 5, &keys);
    let mut prev = 0usize;
    for d in 0..=5 {
        let c = bisc::mint(&cs[..=d], None, &keys.root);
        let n = c.token.to_vec().unwrap().len();
        println!("block {d}: token {n} bytes (+{})", n - prev);
        prev = n;
    }
    let full = bisc::mint(&cs, Some((&leaf_grant(t0 + 600, 5), &keys.approver)), &keys.root);
    let n = full.token.to_vec().unwrap().len();
    println!("grant block: token {n} bytes (+{})", n - prev);
    let sealed = full.token.seal().unwrap().to_vec().unwrap().len();
    println!("sealed depth-5 token: {sealed} bytes");
}

// ---------------------------------------------------------------------------------------------
fn check(name: &str, cond: bool, detail: &str) -> bool {
    println!("[{}] {name}{}", if cond { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!("\n       {detail}") });
    cond
}

fn short(e: &Option<String>) -> String {
    let s = e.clone().unwrap_or_else(|| "ok".into());
    if s.len() > 900 {
        format!("{}…", &s[..900])
    } else {
        s
    }
}

fn correct() {
    let t0 = t0();
    let now = t0 + 600;
    let b = build(t0, 5);
    let base = bisc::base_authorizer(bisc::generous());
    let tok = &b.chain.token;
    let sc = scenarios(now, 5);
    let req = |i: usize| sc[i].1.clone();
    let mut all = true;
    let mut ok = |name: &str, c: bool, d: &str| all &= check(name, c, d);

    println!("## Baseline (depth 5, {} checks, grant at leaf)", b.chain.checks);
    for (name, r) in &sc {
        let o = bisc::authorize(&base, tok, r);
        let want = !name.starts_with('B');
        ok(&format!("{name}: {}", if o.ok { "allowed" } else { "denied" }), o.ok == want, &if o.ok { String::new() } else { short(&o.err) });
    }

    println!("\n## A holder can't widen");
    let widen = |code: &str| tok.append(BlockBuilder::new().code(code).unwrap()).unwrap();
    let t = widen("check if true;");
    let o = bisc::authorize(&base, &t, &req(1));
    ok("appending `check if true` does not admit B (outside reach)", !o.ok, &short(&o.err));
    let t = widen(r#"approved("g-x", "api.github.com", "GET", "/repos/other/x/issues");"#);
    let o = bisc::authorize(&base, &t, &req(1));
    ok("a forged `approved` fact in a holder block is not trusted", !o.ok, &short(&o.err));
    let t = widen("approved($g, $h, $m, $p) <- host($h), method($m), path($p), uses_left($g, $n);");
    let o = bisc::authorize(&base, &t, &req(1));
    ok("a holder rule deriving `approved` is not trusted", !o.ok, &short(&o.err));
    let attacker = KeyPair::new();
    let t = bisc::append_grant(tok, r#"approved("g-x", "api.github.com", "GET", "/repos/other/x/issues");"#, &attacker);
    let o = bisc::authorize(&base, &t, &req(1));
    ok("a third-party approval signed by an untrusted key is ignored", !o.ok, &short(&o.err));
    let leaf_self = bisc::append_grant(tok, r#"approved("g-x", "api.github.com", "POST", "/repos/acme/api/issues");"#, &b.keys.grantor[5]);
    let mut r = req(0);
    r.op = Op::Http { host: "api.github.com".into(), method: "POST".into(), path: "/repos/acme/api/issues".into(), risk: 1, inject: Some(GH_INJECT.into()) };
    let o = bisc::authorize(&base, &leaf_self, &r);
    ok("a box can't self-grant (no block trusts the leaf's own grantor key)", !o.ok, &short(&o.err));
    let e = BlockBuilder::new().code("allow if true;");
    ok("a block can't carry an allow policy (parse error)", e.is_err(), &format!("{:?}", e.err().map(|e| e.to_string())));
    let t = widen(&format!("check if time($t), $t <= {};", rfc3339(t0 + 48 * 3600)));
    let mut r = req(0);
    r.time = b.cs[5].not_after + 1;
    let o = bisc::authorize(&base, &t, &r);
    ok("a later expiry in a new block does not extend the leaf's", !o.ok, &short(&o.err));
    let mut r = req(0);
    r.tenant = "other-tenant".into();
    let o = bisc::authorize(&base, tok, &r);
    ok("a request served for another tenant is refused (authorizer tenant check)", !o.ok, &short(&o.err));

    println!("\n## A node can narrow");
    let t = widen(r#"check if op($o), $o != "http" or method("GET");"#);
    ok("after appending `method GET only`: A still allowed", bisc::authorize(&base, &t, &req(0)).ok, "");
    let o = bisc::authorize(&base, &t, &req(2));
    ok("after appending `method GET only`: C (granted PUT) now denied", !o.ok, &short(&o.err));
    let t = widen(r#"check if op($o), $o != "spawn";"#);
    ok("after appending `no spawn`: D denied", !bisc::authorize(&base, &t, &req(3)).ok, "");

    println!("\n## Expiry and lease state");
    let mut r = req(0);
    r.time = b.cs[5].not_after;
    ok("A at exactly the leaf expiry: allowed", bisc::authorize(&base, tok, &r).ok, "");
    r.time += 1;
    let o = bisc::authorize(&base, tok, &r);
    ok("A one second after the leaf expiry: denied", !o.ok, &short(&o.err));
    let mut r = req(2);
    r.time = b.grant.not_after + 1;
    let o = bisc::authorize(&base, tok, &r);
    ok("C after the grant's expiry: denied", !o.ok, &short(&o.err));
    let mut r = req(0);
    r.time = b.grant.not_after + 1;
    ok("A after the grant's expiry: still allowed (an expired lease doesn't kill the chain)", bisc::authorize(&base, tok, &r).ok, "");
    let mut r = req(2);
    r.uses_left = vec![("g-7f3a".into(), 0)];
    ok("C with uses_left = 0 (ledger): denied", !bisc::authorize(&base, tok, &r).ok, "");
    let mut r = req(2);
    r.uses_left.clear();
    ok("C with no ledger entry: denied", !bisc::authorize(&base, tok, &r).ok, "");
    let mut r = req(2);
    r.epoch = 4;
    ok("C in a later box epoch: denied", !bisc::authorize(&base, tok, &r).ok, "");
    // The leaf spawns b6: its chain carries the leaf's grant block, which must not apply to b6.
    let child = tok.append(BlockBuilder::new().code(&bisc::compile(&Ceiling { box_prefix: format!("{}/b6", box_id(5)), ..b.cs[5].clone() }, false, "acme").0).unwrap()).unwrap();
    let mut r = req(2);
    r.box_id = format!("{}/b6", box_id(5));
    ok("C from the leaf's child b6 (inherits the grant block): denied", !bisc::authorize(&base, &child, &r).ok, "");
    let mut r = req(0);
    r.box_id = format!("{}/b6", box_id(5));
    ok("A from b6: allowed", bisc::authorize(&base, &child, &r).ok, "");
    let mut r = req(0);
    r.box_id = "b0/b1/b9".into();
    ok("A presented for a box outside the chain's subtree: denied", !bisc::authorize(&base, tok, &r).ok, "");

    println!("\n## Agent grants (#50): signed by the parent box's grantor key");
    let parent_only = {
        let keys = &b.keys;
        let cs = &b.cs;
        bisc::mint(cs, None, &keys.root).token
    };
    let g = |m: &str, p: &str, risk: i64, key: &KeyPair| {
        let gr = Grant { method: m.into(), path: p.into(), ..b.grant.clone() };
        let t = bisc::append_grant(&parent_only, &bisc::grant_code(&gr), key);
        let mut r = req(0);
        r.op = Op::Http { host: "api.github.com".into(), method: m.into(), path: p.into(), risk, inject: Some(GH_INJECT.into()) };
        bisc::authorize(&base, &t, &r)
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
    let (i1, i2, ip) = (c1.revocation_identifiers(), c2.revocation_identifiers(), p3.revocation_identifiers());
    for (k, id) in i1.iter().enumerate() {
        println!("       c1 block {k}: {}…  shared with c2: {}", &hex::encode(id)[..16], i2.get(k) == Some(id));
    }
    ok("siblings share the revocation ids of their common prefix (blocks 0-3) and differ at block 4", i1[..4] == i2[..4] && i1[4] != i2[4] && ip[..] == i1[..4], "");
    let rev = |t: &Biscuit, list: &HashSet<Vec<u8>>| t.revocation_identifiers().iter().any(|id| list.contains(id));
    let only_c1: HashSet<Vec<u8>> = [i1[4].clone()].into();
    ok("revoking c1's own block: c1 revoked, c2 and parent not", rev(&c1, &only_c1) && !rev(&c2, &only_c1) && !rev(&p3, &only_c1), "");
    let sub: HashSet<Vec<u8>> = [ip[2].clone()].into();
    ok("revoking b2's spawn block: b2's whole subtree (b3, c1, c2) revoked", rev(&c1, &sub) && rev(&c2, &sub) && rev(&p3, &sub), "");
    let gid = tok.revocation_identifiers();
    ok("the third-party grant block has its own id (revoke one lease without the zone)", gid.len() == 7 && gid[6] != gid[5], "");

    println!("\n## Tampering");
    let bytes = tok.to_vec().unwrap();
    let pk = b.keys.root.public();
    let mut accepted = 0;
    for i in 0..bytes.len() {
        let mut x = bytes.clone();
        x[i] ^= 0x01;
        if Biscuit::from(&x, pk).is_ok() {
            accepted += 1;
        }
    }
    ok(&format!("flipping each of the {} bytes in turn: {accepted} variants parse", bytes.len()), accepted == 0, "");
    {
        use prost::Message;
        let pb = biscuit_auth::format::schema::Biscuit::decode(bytes.as_slice()).unwrap();
        let mut drop_last = pb.clone();
        drop_last.blocks.pop();
        let res = Biscuit::from(drop_last.encode_to_vec(), pk);
        ok("dropping the last block (the node holds only this token's proof): rejected", res.is_err(), &format!("{:?}", res.err().map(|e| e.to_string())));
        let mut drop_mid = pb.clone();
        drop_mid.blocks.remove(2);
        let res = Biscuit::from(drop_mid.encode_to_vec(), pk);
        ok("removing a middle spawn block (block 3): rejected", res.is_err(), &format!("{:?}", res.err().map(|e| e.to_string())));
        let mut swap = pb.clone();
        swap.blocks.swap(1, 2);
        let res = Biscuit::from(swap.encode_to_vec(), pk);
        ok("reordering two spawn blocks: rejected", res.is_err(), &format!("{:?}", res.err().map(|e| e.to_string())));
        // Truncating with the parent's own token (which a node holding the parent does have) just
        // yields the parent's chain: it never exceeds what that node already held.
    }
    let other = KeyPair::new();
    ok("the token under the wrong root key fails", Biscuit::from(&bytes, other.public()).is_err(), "");
    // Transplant: a grant block made for one chain appended to a sibling.
    let req3 = c1.third_party_request().unwrap();
    let blk = req3.create_block(&keys.approver.private(), BlockBuilder::new().code(&bisc::grant_code(&leaf_grant(now, 4))).unwrap()).unwrap();
    let res = c2.append_third_party(keys.approver.public(), blk).and_then(|t| t.to_vec()).and_then(|v| Biscuit::from(v, keys.root.public()));
    ok("a third-party block made for chain c1 can't be moved to sibling c2", res.is_err(), &format!("{:?}", res.err().map(|e| e.to_string())));
    let sealed = tok.seal().unwrap();
    ok("a sealed token can't be attenuated further", sealed.append(BlockBuilder::new()).is_err(), "");

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

    println!("\n{}", if all { "ALL PASS" } else { "SOME CHECKS FAILED" });
}

// ---------------------------------------------------------------------------------------------
fn row(name: &str, s: &stats::Stats) {
    println!("| {name} | {s} |");
}

fn header(title: &str) {
    println!("\n### {title}\n\n| what | median µs | p99 µs | mean µs | max µs |\n|---|---|---|---|---|");
}

fn bench() {
    let t0 = t0();
    let now = t0 + 600;
    let (n_mint, n_cold, n_warm) = (scale(2000), scale(3000), scale(20000));
    println!("iterations: mint {n_mint}, cold {n_cold}, warm {n_warm}");
    let base = bisc::base_authorizer(bisc::generous());

    // A revocation list of 10k ids, as the feed would carry.
    let revset: HashSet<Vec<u8>> = (0..10_000u32).map(|i| { let mut v = vec![0u8; 64]; v[..4].copy_from_slice(&i.to_be_bytes()); v }).collect();

    header("Ed25519 primitives (ed25519-dalek 2, reference)");
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = sk.verifying_key();
    let msg = vec![7u8; 400];
    let sig = ed25519_dalek::Signer::sign(&sk, &msg);
    row("sign 400 B", &measure(n_mint, || { black_box(ed25519_dalek::Signer::sign(&sk, black_box(&msg))); }));
    row("verify 400 B", &measure(n_mint, || { black_box(ed25519_dalek::Verifier::verify(&vk, black_box(&msg), &sig).is_ok()); }));

    for depth in 1..=5 {
        let b = build(t0, depth);
        let bytes = b.chain.token.to_vec().unwrap();
        let root_pk = b.keys.root.public();
        println!("\n## depth {depth}: {} blocks, {} checks, {} bytes ({} base64)", b.chain.token.block_count(), b.chain.checks, bytes.len(), b.chain.token.to_base64().unwrap().len());

        header(&format!("depth {depth}: mint and attenuate (Biscuit)"));
        let code0 = &b.chain.codes[0];
        row("mint authority block (parse Datalog + sign)", &measure(n_mint, || { black_box(Biscuit::builder().code(code0).unwrap().build(&b.keys.root).unwrap()); }));
        let parent = bisc::mint(&b.cs[..depth], None, &b.keys.root).token;
        let code_last = &b.chain.codes[depth];
        row(&format!("append spawn block {depth} (parse + sign)"), &measure(n_mint, || { black_box(parent.append(BlockBuilder::new().code(code_last).unwrap()).unwrap()); }));
        let prebuilt = BlockBuilder::new().code(code_last).unwrap();
        row(&format!("append spawn block {depth} (pre-parsed builder)"), &measure(n_mint, || { black_box(parent.append(prebuilt.clone()).unwrap()); }));
        let leaf = bisc::mint(&b.cs, None, &b.keys.root).token;
        let gcode = bisc::grant_code(&b.grant);
        row("3p: node makes request (bound to last sig)", &measure(n_mint, || { black_box(leaf.third_party_request().unwrap().serialize().unwrap()); }));
        let rq = leaf.third_party_request().unwrap().serialize().unwrap();
        row("3p: approver signs grant block", &measure(n_mint, || {
            let r = biscuit_auth::ThirdPartyRequest::deserialize(&rq).unwrap();
            black_box(r.create_block(&b.keys.approver.private(), BlockBuilder::new().code(&gcode).unwrap()).unwrap().serialize().unwrap());
        }));
        let blk = biscuit_auth::ThirdPartyRequest::deserialize(&rq).unwrap().create_block(&b.keys.approver.private(), BlockBuilder::new().code(&gcode).unwrap()).unwrap();
        row("3p: node appends grant block", &measure(n_mint, || { black_box(leaf.append_third_party(b.keys.approver.public(), blk.clone()).unwrap()); }));
        row("serialize token (to_vec)", &measure(n_mint, || { black_box(b.chain.token.to_vec().unwrap()); }));

        header(&format!("depth {depth}: per-request verification (Biscuit)"));
        row("parse + verify signatures only (Biscuit::from)", &measure(n_cold, || { black_box(Biscuit::from(black_box(&bytes), root_pk).unwrap()); }));
        let tok = &b.chain.token;
        row("revocation ids + lookup in 10k set", &measure(n_cold, || { black_box(tok.revocation_identifiers().iter().any(|i| revset.contains(i))); }));
        for (name, r) in scenarios(now, depth) {
            let facts = bisc::request_facts(&r);
            let expect = bisc::authorize(&base, tok, &r).ok;
            assert_eq!(expect, !name.starts_with('B'), "{name} at depth {depth}");
            row(&format!("COLD {name}: parse+verify+revocation+authorize"), &measure(n_cold, || {
                let t = Biscuit::from(black_box(&bytes), root_pk).unwrap();
                let rev = t.revocation_identifiers().iter().any(|i| revset.contains(i));
                black_box(!rev && bisc::authorize_fast(&base, &t, &facts));
            }));
            let ids = tok.revocation_identifiers();
            row(&format!("WARM {name}: cached token, revocation+authorize"), &measure(n_warm, || {
                let rev = ids.iter().any(|i| revset.contains(i));
                black_box(!rev && bisc::authorize_fast(&base, tok, &facts));
            }));
            // Where WARM time goes: building the authorizer (decode blocks, load facts) vs Datalog.
            let mut execs = Vec::with_capacity(n_warm / 4);
            let mut builds = Vec::with_capacity(n_warm / 4);
            for _ in 0..n_warm / 4 {
                let s = std::time::Instant::now();
                let mut bb = base.clone();
                for f in &facts {
                    bb = bb.fact(f.clone()).unwrap();
                }
                let mut a = bb.build(tok).unwrap();
                builds.push(s.elapsed().as_nanos() as f64 / 1000.0);
                let _ = black_box(a.authorize());
                execs.push(a.execution_time().unwrap().as_nanos() as f64 / 1000.0);
            }
            row(&format!("  of which: builder clone + facts + build({name})"), &stats::from_samples(builds));
            row(&format!("  of which: Datalog run+checks, as counted against RunLimits.max_time ({name})"), &stats::from_samples(execs));
        }
    }

    header("depth 5: regex path patterns instead of prefixes (WARM)");
    {
        let keys = bisc::Keys::new(5);
        let mut cs = bisc::ceilings(t0, 5, &keys);
        for c in cs.iter_mut() {
            c.regex_paths = true;
        }
        let g = leaf_grant(now, 5);
        let chain = bisc::mint(&cs, Some((&g, &keys.approver)), &keys.root);
        for (name, r) in scenarios(now, 5).into_iter().take(2) {
            let facts = bisc::request_facts(&r);
            assert_eq!(bisc::authorize(&base, &chain.token, &r).ok, !name.starts_with('B'));
            row(&format!("WARM {name} (regex paths)"), &measure(n_warm / 4, || { black_box(bisc::authorize_fast(&base, &chain.token, &facts)); }));
        }
    }

    // ------------------------------------------------------------------ fallback
    for depth in [1usize, 3, 5] {
        let pk = plain::PlainKeys::new();
        let cs = plain::plain_ceilings(t0, depth, &pk);
        let g = leaf_grant(now, depth);
        let chain = plain::mint(&cs, Some(&g), &pk);
        let trust = pk.trust();
        let revset32: HashSet<[u8; 32]> = (0..10_000u32).map(|i| { let mut v = [0u8; 32]; v[..4].copy_from_slice(&i.to_be_bytes()); v }).collect();
        header(&format!("depth {depth}: fallback, plain signed JSON records ({} bytes)", chain.len()));
        row("mint whole chain (serialize + sign every link)", &measure(n_mint / 2, || { black_box(plain::mint(&cs, Some(&g), &pk)); }));
        let mut prefix = plain::mint(&cs[..depth], None, &pk);
        let mut prev = plain::last_hash(&prefix);
        row(&format!("append spawn link {depth} (serialize + sign)"), &measure(n_mint, || {
            let mut c = prefix.clone();
            let mut p = prev;
            plain::append(&mut c, &mut p, "node-lon-1", plain::Body::Zone(cs[depth].clone()), &pk.node);
            black_box(c);
        }));
        plain::append(&mut prefix, &mut prev, "node-lon-1", plain::Body::Zone(cs[depth].clone()), &pk.node);
        row(&format!("mint-time narrowing check, link {depth} vs parent"), &measure(n_warm, || { black_box(plain::narrows(black_box(&cs[depth]), &cs[depth - 1]).is_ok()); }));
        row("parse + verify only", &measure(n_cold, || { black_box(plain::verify(black_box(&chain), &trust).unwrap()); }));
        let v = plain::verify(&chain, &trust).unwrap();
        for (name, r) in scenarios(now, depth) {
            assert_eq!(plain::authorize(&v, &r), !name.starts_with('B'), "plain {name} {depth}");
            row(&format!("COLD {name}"), &measure(n_cold, || {
                let v = plain::verify(black_box(&chain), &trust).unwrap();
                black_box(!plain::revoked(&v, &revset32) && plain::authorize(&v, &r));
            }));
            row(&format!("WARM {name}"), &measure(n_warm, || { black_box(!plain::revoked(&v, &revset32) && plain::authorize(&v, black_box(&r))); }));
        }
    }
}

// ---------------------------------------------------------------------------------------------
fn limits() {
    let t0 = t0();
    let now = t0 + 600;
    println!("## World size per request (generous limits)\n\n| depth | scenario | facts | iterations | min max_facts | min max_iterations | run time µs |\n|---|---|---|---|---|---|---|");
    for depth in 1..=5 {
        let b = build(t0, depth);
        for (name, r) in scenarios(now, depth) {
            let o = bisc::authorize(&bisc::base_authorizer(bisc::generous()), &b.chain.token, &r);
            let want = !name.starts_with('B');
            let fails_on_limit = |lim: AuthorizerLimits| {
                let o2 = bisc::authorize(&bisc::base_authorizer(lim), &b.chain.token, &r);
                o2.ok != want || o2.err.as_deref().is_some_and(|e| e.contains("too many") || e.contains("spent too much"))
            };
            let mut mf = 1u64;
            while fails_on_limit(AuthorizerLimits { max_facts: mf, ..bisc::generous() }) && mf < 2000 {
                mf += 1;
            }
            let mut mi = 1u64;
            while fails_on_limit(AuthorizerLimits { max_iterations: mi, ..bisc::generous() }) && mi < 200 {
                mi += 1;
            }
            println!("| {depth} | {name} | {} | {} | {mf} | {mi} | {:.1} |", o.facts, o.iterations, o.exec.map(|d| d.as_nanos() as f64 / 1000.0).unwrap_or(-1.0));
        }
    }

    println!("\n## What happens at each limit (depth 5, request A)\n");
    let b = build(t0, 5);
    let r = scenarios(now, 5)[0].1.clone();
    let o = bisc::authorize(&bisc::base_authorizer(bisc::generous()), &b.chain.token, &r);
    for (label, lim) in [
        ("max_facts = facts - 1", AuthorizerLimits { max_facts: o.facts as u64 - 1, ..bisc::generous() }),
        ("max_facts = facts", AuthorizerLimits { max_facts: o.facts as u64, ..bisc::generous() }),
        ("max_iterations = 1", AuthorizerLimits { max_iterations: 1, ..bisc::generous() }),
        ("max_time = 1 µs", AuthorizerLimits { max_time: Duration::from_micros(1), ..bisc::generous() }),
        ("defaults (1000 facts, 100 iterations, 1 ms)", AuthorizerLimits::default()),
    ] {
        let o = bisc::authorize(&bisc::base_authorizer(lim), &b.chain.token, &r);
        println!("- {label}: {}", if o.ok { "allowed".into() } else { format!("denied: {}", short(&o.err)) });
    }

    println!("\n## Hostile holder blocks: an appended block that tries to exhaust the verifier\n");
    let n = scale(200);
    for (label, code) in [
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
        ("expensive checks: 200 regex checks", {
            (0..200).map(|i| format!("check if path($p), $p.matches(\"^/repos/[a-z]+/api/pulls/[0-9]+$|^x{i}$\");\n")).collect()
        }),
    ] {
        let t = b.chain.token.append(BlockBuilder::new().code(&code).unwrap()).unwrap();
        for (ln, lim) in [("defaults", AuthorizerLimits::default()), ("max_facts 1000, max_iterations 100, max_time 50ms", bisc::generous())] {
            let base = bisc::base_authorizer(lim);
            let o = bisc::authorize(&base, &t, &r);
            let facts = bisc::request_facts(&r);
            let s = measure(n, || { black_box(bisc::authorize_fast(&base, &t, &facts)); });
            println!("- {label} [{ln}]: {} — time to decide median {:.0} µs, p99 {:.0} µs, token {} bytes", if o.ok { "allowed".into() } else { format!("denied: {}", short(&o.err)) }, s.median, s.p99, t.to_vec().unwrap().len());
        }
    }
}

// ---------------------------------------------------------------------------------------------
/// Hot loop for `perf record`, plus what a pre-built authorizer would cost if biscuit-auth let a
/// node add request facts to an authorizer that already holds the token (it doesn't in 6.0.0).
fn profile() {
    let t0 = t0();
    let now = t0 + 600;
    let b = build(t0, 5);
    let base = bisc::base_authorizer(bisc::generous());
    let r = scenarios(now, 5)[0].1.clone();
    let facts = bisc::request_facts(&r);
    let n = scale(20000);
    if std::env::var("PROFILE_LOOP").is_ok() {
        for _ in 0..n {
            black_box(bisc::authorize_fast(&base, &b.chain.token, &facts));
        }
        return;
    }
    header("depth 5, request A: pieces of the WARM path");
    row("AuthorizerBuilder clone (static policies)", &measure(n, || { black_box(base.clone()); }));
    row("clone + add 13 request facts", &measure(n, || {
        let mut bb = base.clone();
        for f in &facts {
            bb = bb.fact(f.clone()).unwrap();
        }
        black_box(bb);
    }));
    let mut bb = base.clone();
    for f in &facts {
        bb = bb.fact(f.clone()).unwrap();
    }
    row("build(token) alone (decode + translate 7 blocks)", &measure(n, || { black_box(bb.clone().build(&b.chain.token).unwrap()); }));
    let built = bb.clone().build(&b.chain.token).unwrap();
    row("clone of a built Authorizer (token + facts loaded)", &measure(n, || { black_box(built.clone()); }));
    row("clone built Authorizer + authorize (projected path with an add-facts API)", &measure(n, || {
        let mut a = built.clone();
        black_box(a.authorize().is_ok());
    }));
}
