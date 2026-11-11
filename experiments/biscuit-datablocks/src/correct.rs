//! biscuit-depth's 45 property checks, ported to each design, plus checks that only make sense for
//! data blocks. Tokens are minted by stock 6.0.0 (as in biscuit-depth and biscuit-fast) and every
//! parse and decision is made by the design's node pipeline (designs::load / decide).

use crate::bisc;
use crate::designs::{self, Design, C_DECISIONS, C_MISMATCH};
use crate::fk;
use crate::model::*;
use crate::zf::{self, Form};
use biscuit_auth::builder::{fact, int, string};
use biscuit_auth::{Biscuit, BlockBuilder, KeyPair};
use std::collections::HashSet;
use std::sync::atomic::Ordering;

pub const UNIVERSE_HOSTS: &[&str] = &["api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "githubusercontent.com", "crates.io", "static.crates.io", "index.crates.io", "docs.rs", "pypi.org", "registry.npmjs.org", "vault.internal", "example.com"];
pub const UNIVERSE_METHODS: &[&str] = &["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"];

/// A ceiling that allows every request the tests and the differential generate. Design B narrows by
/// appending `top()` with one dimension changed, where design A appends a single check.
pub fn top(t0: u64) -> Ceiling {
    let all = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    Ceiling {
        zone: "holder".into(),
        box_prefix: "b0".into(),
        not_after: t0 + 100 * 86400,
        ops: all(&["http", "spawn", "llm", "msg"]),
        reach: UNIVERSE_HOSTS.iter().map(|h| Reach { host: h.to_string(), methods: all(UNIVERSE_METHODS), path: PathPat::Any }).collect(),
        forbid: vec![],
        max_risk: 4,
        dangerous_ok: vec![],
        spawn: SpawnLimits { images: all(&["img:agent", "img:rust", "img:py", "img:evil"]), min_isolation: 0, mem_bytes: i64::MAX, cpus_milli: i64::MAX, pids: i64::MAX, timeout_s: i64::MAX },
        llm: LlmBudget { max_requests: i64::MAX, max_output_tokens: i64::MAX },
        accept_from: all(&["ops", "ci", "dev", "x"]),
        inject: all(&[GH_INJECT, "pypi.org|Authorization|pypi-token"]),
        // No grant escape: like design A's holder checks, a narrowing block doesn't honour grants.
        grant_keys: vec![],
        regex_paths: false,
    }
}

pub fn mint_d(d: Design, cs: &[Ceiling], grant: Option<(&Grant, &KeyPair)>, root: &KeyPair) -> Biscuit {
    match d.form() {
        None => bisc::mint(cs, grant, root).token,
        Some(f) => zf::mint(cs, grant, root, f),
    }
}

pub fn append_zone_d(d: Design, tok: &Biscuit, c: &Ceiling) -> Biscuit {
    match d.form() {
        None => tok.append(BlockBuilder::new().code(bisc::compile(c, false, "acme").0).unwrap()).unwrap(),
        Some(f) => zf::append_zone(tok, c, f),
    }
}

pub fn append_grant_d(d: Design, tok: &Biscuit, g: &Grant, signer: &KeyPair) -> Biscuit {
    match d.form() {
        None => bisc::append_grant(tok, &bisc::grant_code(g), signer),
        Some(f) => zf::append_grant(tok, g, signer, f),
    }
}

/// A holder narrowing: design A appends `check`; B appends the equivalent zone; C appends both in one block.
pub fn append_narrow_d(d: Design, tok: &Biscuit, check: &str, zone: &Ceiling) -> Biscuit {
    let b = match d.form() {
        None => BlockBuilder::new().code(check).unwrap(),
        Some(Form::Data) => BlockBuilder::new().fact(zf::zone_fact(zone, Form::Data)).unwrap(),
        Some(Form::Hybrid) => BlockBuilder::new().code(check).unwrap().fact(zf::zone_fact(zone, Form::Hybrid)).unwrap(),
    };
    tok.append(b).unwrap()
}

fn raw(tok: &Biscuit, b: BlockBuilder) -> Biscuit {
    tok.append(b).unwrap()
}

fn check(name: &str, cond: bool, detail: &str) -> bool {
    println!("[{}] {name}{}", if cond { "PASS" } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!("\n       {detail}") });
    cond
}

fn short(e: &Option<String>) -> String {
    let s = e.clone().unwrap_or_else(|| "ok".into());
    if s.len() > 200 {
        format!("{}…", &s[..200])
    } else {
        s
    }
}

struct Outcome {
    ok: bool,
    err: Option<String>,
}

pub fn run(d: Design, t0: u64) -> (bool, usize) {
    C_MISMATCH.store(0, Ordering::Relaxed);
    C_DECISIONS.store(0, Ordering::Relaxed);
    println!("\n# Correctness: {}\n", d.name());
    let now = t0 + 600;
    let keys = bisc::Keys::new(5);
    let cs = bisc::ceilings(t0, 5, &keys);
    let grant = leaf_grant(now, 5);
    let froot = fk::root_pk(&keys.root.public());
    let tok = mint_d(d, &cs, Some((&grant, &keys.approver)), &keys.root);
    let loads = |t: &Biscuit, root: &fork::PublicKey| designs::load(d, &t.to_vec().unwrap(), root);
    let dec = |t: &Biscuit, r: &Request| -> Outcome {
        match loads(t, &froot) {
            Ok(l) => {
                let res = l.decide(r);
                Outcome { ok: res.is_ok(), err: res.err() }
            }
            Err(e) => Outcome { ok: false, err: Some(format!("refused at load: {e}")) },
        }
    };
    let sc = scenarios(now, 5);
    let req = |i: usize| sc[i].1.clone();
    let mut all = true;
    let mut n = 0;
    let mut ok = |name: &str, c: bool, det: &str| {
        n += 1;
        all &= check(name, c, det)
    };
    let is_b = d.form().is_some();

    println!("## Baseline (depth 5, grant at leaf; token {} bytes)", tok.to_vec().unwrap().len());
    for (name, r) in &sc {
        let o = dec(&tok, r);
        let want = !name.starts_with('B');
        ok(&format!("{name}: {}", if o.ok { "allowed" } else { "denied" }), o.ok == want, &if o.ok { String::new() } else { short(&o.err) });
    }

    println!("\n## A holder can't widen");
    let o = dec(&raw(&tok, BlockBuilder::new().code("check if true;").unwrap()), &req(1));
    ok("appending `check if true` does not admit B (outside reach)", !o.ok, &short(&o.err));
    let forged = if is_b {
        let g = Grant { host: "api.github.com".into(), method: "GET".into(), path: "/repos/other/x/issues".into(), ..grant.clone() };
        raw(&tok, BlockBuilder::new().fact(zf::grant_fact(&g)).unwrap())
    } else {
        raw(&tok, BlockBuilder::new().code(r#"approved("g-x", "api.github.com", "GET", "/repos/other/x/issues");"#).unwrap())
    };
    let o = dec(&forged, &req(1));
    ok(if is_b { "a forged grant fact in a first-party (holder) block is not trusted" } else { "a forged `approved` fact in a holder block is not trusted" }, !o.ok, &short(&o.err));
    let o = dec(&raw(&tok, BlockBuilder::new().code("approved($g, $h, $m, $p) <- host($h), method($m), path($p), uses_left($g, $n);").unwrap()), &req(1));
    ok("a holder rule deriving `approved` is not trusted", !o.ok, &short(&o.err));
    let attacker = KeyPair::new();
    let bad = Grant { host: "api.github.com".into(), method: "GET".into(), path: "/repos/other/x/issues".into(), ..grant.clone() };
    let o = dec(&append_grant_d(d, &tok, &bad, &attacker), &req(1));
    ok("a third-party approval signed by an untrusted key is ignored", !o.ok, &short(&o.err));
    let selfg = Grant { method: "POST".into(), path: "/repos/acme/api/issues".into(), ..grant.clone() };
    let mut r = req(0);
    r.op = Op::Http { host: "api.github.com".into(), method: "POST".into(), path: "/repos/acme/api/issues".into(), risk: 1, inject: Some(GH_INJECT.into()) };
    let o = dec(&append_grant_d(d, &tok, &selfg, &keys.grantor[5]), &r);
    ok("a box can't self-grant (no block trusts the leaf's own grantor key)", !o.ok, &short(&o.err));
    ok("a block can't carry an allow policy (parse error)", BlockBuilder::new().code("allow if true;").is_err(), "");
    let later = Ceiling { not_after: t0 + 48 * 3600, ..top(t0) };
    let t = append_narrow_d(d, &tok, &format!("check if time($t), $t <= {};", rfc3339(t0 + 48 * 3600)), &later);
    let mut r = req(0);
    r.time = cs[5].not_after + 1;
    let o = dec(&t, &r);
    ok("a later expiry in a new block does not extend the leaf's", !o.ok, &short(&o.err));
    let mut r = req(0);
    r.tenant = "other-tenant".into();
    let o = dec(&tok, &r);
    ok("a request served for another tenant is refused", !o.ok, &short(&o.err));

    println!("\n## A node can narrow{}", if is_b { " (B: by appending a narrower zone)" } else { "" });
    let get_only = {
        let mut c = top(t0);
        c.reach.iter_mut().for_each(|x| x.methods = vec!["GET".into()]);
        c
    };
    let t = append_narrow_d(d, &tok, r#"check if op($o), $o != "http" or method("GET");"#, &get_only);
    let o = dec(&t, &req(0));
    ok("after appending `method GET only`: A still allowed", o.ok, &short(&o.err));
    let o = dec(&t, &req(2));
    ok("after appending `method GET only`: C (granted PUT) now denied", !o.ok, &short(&o.err));
    let no_spawn = Ceiling { ops: vec!["http".into(), "llm".into(), "msg".into()], ..top(t0) };
    let t = append_narrow_d(d, &tok, r#"check if op($o), $o != "spawn";"#, &no_spawn);
    ok("after appending `no spawn`: D denied", !dec(&t, &req(3)).ok, "");

    println!("\n## Expiry and lease state");
    let mut r = req(0);
    r.time = cs[5].not_after;
    ok("A at exactly the leaf expiry: allowed", dec(&tok, &r).ok, "");
    r.time += 1;
    let o = dec(&tok, &r);
    ok("A one second after the leaf expiry: denied", !o.ok, &short(&o.err));
    let mut r = req(2);
    r.time = grant.not_after + 1;
    let o = dec(&tok, &r);
    ok("C after the grant's expiry: denied", !o.ok, &short(&o.err));
    let mut r = req(0);
    r.time = grant.not_after + 1;
    ok("A after the grant's expiry: still allowed (an expired lease doesn't kill the chain)", dec(&tok, &r).ok, "");
    let mut r = req(2);
    r.uses_left = vec![("g-7f3a".into(), 0)];
    ok("C with uses_left = 0 (ledger): denied", !dec(&tok, &r).ok, "");
    let mut r = req(2);
    r.uses_left.clear();
    ok("C with no ledger entry: denied", !dec(&tok, &r).ok, "");
    let mut r = req(2);
    r.epoch = 4;
    ok("C in a later box epoch: denied", !dec(&tok, &r).ok, "");
    let child = append_zone_d(d, &tok, &Ceiling { box_prefix: format!("{}/b6", box_id(5)), ..cs[5].clone() });
    let mut r = req(2);
    r.box_id = format!("{}/b6", box_id(5));
    ok("C from the leaf's child b6 (inherits the grant block): denied", !dec(&child, &r).ok, "");
    let mut r = req(0);
    r.box_id = format!("{}/b6", box_id(5));
    ok("A from b6: allowed", dec(&child, &r).ok, "");
    let mut r = req(0);
    r.box_id = "b0/b1/b9".into();
    ok("A presented for a box outside the chain's subtree: denied", !dec(&tok, &r).ok, "");

    println!("\n## Agent grants (#50): signed by the parent box's grantor key");
    let parent_only = mint_d(d, &cs, None, &keys.root);
    let g = |m: &str, p: &str, risk: i64, key: &KeyPair| {
        let gr = Grant { method: m.into(), path: p.into(), ..grant.clone() };
        let t = append_grant_d(d, &parent_only, &gr, key);
        let mut r = req(0);
        r.op = Op::Http { host: "api.github.com".into(), method: m.into(), path: p.into(), risk, inject: Some(GH_INJECT.into()) };
        dec(&t, &r)
    };
    let o = g("POST", "/repos/acme/api/issues", 1, &keys.grantor[4]);
    ok("parent (b4) grants POST /repos/acme/api/issues (within b4, outside leaf): allowed", o.ok, &short(&o.err));
    let o = g("POST", "/repos/acme/infra/issues", 1, &keys.grantor[4]);
    ok("parent (b4) grants POST /repos/acme/infra/issues (outside b4's own reach): denied", !o.ok, &short(&o.err));
    let o = g("PUT", "/repos/acme/api/pulls/7/merge", 3, &keys.grantor[4]);
    ok("parent (b4) grants a risk-3 PUT it couldn't do itself: denied", !o.ok, &short(&o.err));
    let o = g("PUT", "/repos/acme/api/pulls/7/merge", 3, &keys.approver);
    ok("the human approval service grants the same PUT: allowed", o.ok, &short(&o.err));
    let o = g("GET", "/repos/acme/secrets-vault/key", 0, &keys.approver);
    ok("an approval can't reach a path only the authority block forbids (forbids have no grant escape)", !o.ok, &short(&o.err));

    println!("\n## Revocation ids identify every block; revoking one kills its subtree");
    let k3 = bisc::Keys::new(5);
    let cs3 = bisc::ceilings(t0, 3, &k3);
    let p3 = mint_d(d, &cs3, None, &k3.root);
    let kid = |name: &str| {
        let mut c = level(t0, 4, vec![bisc::hexkey(&k3.approver.public()), bisc::hexkey(&k3.grantor[3].public())]);
        c.box_prefix = format!("{}/{name}", box_id(3));
        append_zone_d(d, &p3, &c)
    };
    let (c1, c2) = (kid("b4a"), kid("b4b"));
    let ids = |t: &Biscuit| fk::load(t, &k3.root.public()).revocation_identifiers();
    let (i1, i2, ip) = (ids(&c1), ids(&c2), ids(&p3));
    ok("siblings share the revocation ids of their common prefix (blocks 0-3) and differ at block 4", i1[..4] == i2[..4] && i1[4] != i2[4] && ip[..] == i1[..4] && i1 == c1.revocation_identifiers(), "");
    let rev = |t: &Biscuit, list: &HashSet<Vec<u8>>| ids(t).iter().any(|id| list.contains(id));
    let only_c1: HashSet<Vec<u8>> = [i1[4].clone()].into();
    ok("revoking c1's own block: c1 revoked, c2 and parent not", rev(&c1, &only_c1) && !rev(&c2, &only_c1) && !rev(&p3, &only_c1), "");
    let sub: HashSet<Vec<u8>> = [ip[2].clone()].into();
    ok("revoking b2's spawn block: b2's whole subtree (b3, c1, c2) revoked", rev(&c1, &sub) && rev(&c2, &sub) && rev(&p3, &sub), "");
    let gid = fk::load(&tok, &keys.root.public()).revocation_identifiers();
    ok("the third-party grant block has its own id (revoke one lease without the zone)", gid.len() == 7 && gid[6] != gid[5], "");

    println!("\n## Tampering");
    let bytes = tok.to_vec().unwrap();
    let mut accepted = 0;
    for i in 0..bytes.len() {
        let mut x = bytes.clone();
        x[i] ^= 0x01;
        if designs::load(d, &x, &froot).is_ok() {
            accepted += 1;
        }
    }
    ok(&format!("flipping each of the {} bytes in turn: {accepted} variants load", bytes.len()), accepted == 0, "");
    {
        use prost::Message;
        let pb = biscuit_auth::format::schema::Biscuit::decode(bytes.as_slice()).unwrap();
        let mut drop_last = pb.clone();
        drop_last.blocks.pop();
        let res = designs::load(d, &drop_last.encode_to_vec(), &froot);
        ok("dropping the last block: rejected", res.is_err(), &format!("{:?}", res.err()));
        let mut drop_mid = pb.clone();
        drop_mid.blocks.remove(2);
        let res = designs::load(d, &drop_mid.encode_to_vec(), &froot);
        ok("removing a middle spawn block (block 3): rejected", res.is_err(), &format!("{:?}", res.err()));
        let mut swap = pb.clone();
        swap.blocks.swap(1, 2);
        let res = designs::load(d, &swap.encode_to_vec(), &froot);
        ok("reordering two spawn blocks: rejected", res.is_err(), &format!("{:?}", res.err()));
    }
    let other = KeyPair::new();
    ok("the token under the wrong root key fails", designs::load(d, &bytes, &fk::root_pk(&other.public())).is_err(), "");
    let req3 = c1.third_party_request().unwrap();
    let gb = match d.form() {
        None => BlockBuilder::new().code(bisc::grant_code(&leaf_grant(now, 4))).unwrap(),
        Some(Form::Data) => BlockBuilder::new().fact(zf::grant_fact(&leaf_grant(now, 4))).unwrap(),
        Some(Form::Hybrid) => BlockBuilder::new().code(bisc::grant_code(&leaf_grant(now, 4))).unwrap().fact(zf::grant_fact(&leaf_grant(now, 4))).unwrap(),
    };
    let blk = req3.create_block(&k3.approver.private(), gb).unwrap();
    let r3 = fk::root_pk(&k3.root.public());
    let res = c2.append_third_party(k3.approver.public(), blk).and_then(|t| t.to_vec()).map_err(|e| e.to_string()).and_then(|v| designs::load(d, &v, &r3).map(|_| ()));
    ok("a third-party block made for chain c1 can't be moved to sibling c2", res.is_err(), &format!("{:?}", res.err()));
    ok("a sealed token can't be attenuated further", fk::load(&tok, &keys.root.public()).seal().unwrap().append(fork::BlockBuilder::new()).is_err(), "");

    println!("\n## Intersection and grant trust under a hostile but well-formed block");
    let mut wide = cs[5].clone();
    wide.reach.push(Reach { host: "api.github.com".into(), methods: vec!["GET".into()], path: PathPat::Any });
    let o = dec(&append_zone_d(d, &tok, &wide), &req(1));
    ok("a well-formed zone block wider than the leaf doesn't admit B (intersection)", !o.ok, &short(&o.err));
    let mut trusts = cs[5].clone();
    trusts.grant_keys.push(bisc::hexkey(&attacker.public()));
    let t = append_grant_d(d, &append_zone_d(d, &tok, &trusts), &bad, &attacker);
    let o = dec(&t, &req(1));
    ok("a holder block trusting an attacker key, plus a grant that key signed: denied by the other blocks", !o.ok, &short(&o.err));
    let mut wide_box = cs[5].clone();
    wide_box.box_prefix = "b0".into();
    wide_box.not_after += 3600;
    let mut r = req(0);
    r.box_id = "b0/b1/b9".into();
    let o = dec(&append_zone_d(d, &tok, &wide_box), &r);
    ok("a block naming a wider box and a later expiry doesn't admit another subtree", !o.ok, &short(&o.err));
    ok("the scenario's levels each narrow their parent (plain::narrows, the second line at load)", (1..=5).all(|l| crate::plain::narrows(&cs[l], &cs[l - 1]).is_ok()), "");
    ok("the second line names the widening in the wider block", crate::plain::narrows(&wide, &cs[5]).is_err(), &format!("{:?}", crate::plain::narrows(&wide, &cs[5]).err()));

    if is_b {
        let form = d.form().unwrap();
        let zp = if form == Form::Data { "zone" } else { "zone_spec" };
        println!("\n## Data blocks: the extractor refuses anything that isn't exactly one canonical fact");
        let refused = |t: &Biscuit, what: &str, ok: &mut dyn FnMut(&str, bool, &str)| {
            let res = loads(t, &froot);
            ok(&format!("{what}: refused at load"), res.is_err(), &res.err().unwrap_or_default());
        };
        let leaf_json = zf::canon(&cs[5]);
        let with = |b: BlockBuilder| -> BlockBuilder {
            if form == Form::Hybrid {
                b.code(bisc::compile(&cs[5], false, "acme").0).unwrap()
            } else {
                b
            }
        };
        refused(&raw(&tok, with(BlockBuilder::new()).fact(fact(zp, &[string(&leaf_json.replacen(',', ", ", 1))])).unwrap()), "non-canonical JSON (one extra space)", &mut ok);
        refused(&raw(&tok, with(BlockBuilder::new()).fact(fact(zp, &[string(&leaf_json.replacen('{', r#"{"admin":true,"#, 1))])).unwrap()), "an unknown field", &mut ok);
        refused(&raw(&tok, with(BlockBuilder::new()).fact(fact(zp, &[string(&leaf_json.replacen('{', r#"{"zone":"x","#, 1))])).unwrap()), "a duplicated key", &mut ok);
        refused(&raw(&tok, with(BlockBuilder::new()).fact(fact(zp, &[string(&format!("{}}}", &leaf_json[..leaf_json.find(",\"grant_keys\":").unwrap()]))])).unwrap()), "a missing field", &mut ok);
        refused(&raw(&tok, with(BlockBuilder::new()).fact(fact(zp, &[string(&leaf_json)])).unwrap().fact(fact(zp, &[string(&zf::canon(&wide))])).unwrap()), "two zone facts in one block", &mut ok);
        refused(&raw(&tok, with(BlockBuilder::new()).fact(fact(zp, &[int(42)])).unwrap()), "a zone fact with an integer term", &mut ok);
        refused(&raw(&tok, BlockBuilder::new().code(r#"check if op($o), $o != "http" or method("GET");"#).unwrap()), "narrowing with a Datalog check and no zone fact", &mut ok);
        let r3p = tok.third_party_request().unwrap();
        let zb = r3p.create_block(&keys.approver.private(), BlockBuilder::new().fact(fact(zp, &[string(&zf::canon(&wide))])).unwrap()).unwrap();
        refused(&tok.append_third_party(keys.approver.public(), zb).unwrap(), "a zone fact in a third-party block signed by a trusted key", &mut ok);
        let empty = raw(&tok, BlockBuilder::new());
        refused(&empty, "an empty block", &mut ok);
        let big = Ceiling { reach: (0..65).map(|i| Reach { host: format!("h{i}.example.com"), methods: vec!["GET".into()], path: PathPat::Any }).collect(), ..cs[5].clone() };
        refused(&append_zone_d(d, &tok, &big), "a zone over the reach cap (65 entries)", &mut ok);
    }
    if d == Design::C {
        let (m, n_) = (C_MISMATCH.load(Ordering::Relaxed), C_DECISIONS.load(Ordering::Relaxed));
        ok(&format!("C: B's decision agreed with A's on all {n_} decisions made above ({m} disagreements)"), m == 0, "");
    }
    println!("\n{}: {n} checks, {}", d.name(), if all { "ALL PASS" } else { "SOME CHECKS FAILED" });
    (all, n)
}
