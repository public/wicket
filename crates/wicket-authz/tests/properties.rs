//! Properties of the token, ported from experiment #59 (biscuit-depth's checks), plus #76's: an
//! approval can't reach a path only block 0 forbids, empty lists encode, and the Datalog traps of
//! research 23. The chain is #59's depth-5 chain (`common::level`) with a grant at the leaf.
//!
//! Where the structural check refuses a hostile token at load, the test also shows that Biscuit's
//! own semantics (the stock `AuthorizerBuilder` path, with no structural check) would not have let it
//! widen either: the structural check bounds cost, narrowing comes from Biscuit.

mod common;
use biscuit_auth::{AuthorizerBuilder, BlockBuilder};
use common::*;
use std::collections::HashSet;
use wicket_authz::*;
use wicket_core::RiskClass;

struct Fixture {
    keys: Keys,
    cs: Vec<Ceiling>,
    /// The chain without a grant.
    parent_only: Token,
    /// With the approver's grant for the leaf (C: PUT merge).
    tok: Token,
}

fn fixture() -> Fixture {
    let keys = Keys::new(5);
    let cs = ceilings(5, &keys);
    let parent_only = mint_chain(&cs, &keys);
    let tok = grant(&parent_only, &keys.approver, &leaf_grant(5)).unwrap();
    Fixture { keys, cs, parent_only, tok }
}

fn req(i: usize) -> Request {
    scenarios(5)[i].1.clone()
}

fn decide(t: &Token, k: &Keys, r: &Request) -> Decision {
    decide_compiled(&load_ok(t, k), r)
}

fn is_grant(d: &Decision) -> bool {
    matches!(d, Decision::NeedsGrant(_))
}
fn is_forbidden(d: &Decision) -> bool {
    matches!(d, Decision::Forbidden(_))
}

/// Biscuit's own verdict, without wicket's structural check: the stock AuthorizerBuilder path, with
/// generous limits (the stock default is a 1 ms wall clock, which a debug build can hit).
fn stock_allows(t: &Token, r: &Request) -> bool {
    let limits = biscuit_auth::AuthorizerLimits {
        max_facts: 1000,
        max_iterations: 100,
        max_time: std::time::Duration::from_secs(60),
        max_steps: 10_000_000,
    };
    let mut b = AuthorizerBuilder::new().code(wicket_authz::decide::AUTHORIZER).unwrap().set_limits(limits);
    for f in wicket_authz::generator::request_facts(r) {
        b = b.fact(f).unwrap();
    }
    b.build(t.biscuit()).map(|mut a| a.authorize().is_ok()).unwrap_or(false)
}

fn append_raw(t: &Token, code: &str) -> Token {
    Token::from_biscuit(t.biscuit().append(BlockBuilder::new().code(code).unwrap()).unwrap())
}

fn http_req(method: &str, path: &str, risk: RiskClass) -> Request {
    Request { action: http(method, "api.github.com", path, risk), ..base_request(5) }
}

#[test]
fn baseline() {
    let f = fixture();
    let l = load_ok(&f.tok, &f.keys);
    assert!(l.is_compiled());
    assert_eq!(decide_compiled(&l, &req(0)), Decision::Allow, "A: in reach");
    assert!(is_grant(&decide_compiled(&l, &req(1))), "B: outside reach needs a grant");
    assert_eq!(decide_compiled(&l, &req(2)), Decision::Allow, "C: granted");
    assert_eq!(decide_compiled(&l, &req(3)), Decision::Allow, "D: spawn within limits");
    assert!(is_grant(&decide(&f.parent_only, &f.keys, &req(2))), "C without the grant");
}

#[test]
fn a_holder_cant_widen() {
    let f = fixture();
    let k = &f.keys;
    // The stock path agrees with `decide` on the baseline, so its denials below aren't vacuous.
    assert!(stock_allows(&f.tok, &req(0)) && stock_allows(&f.tok, &req(2)) && !stock_allows(&f.tok, &req(1)));
    // `check if true` is not in wicket's vocabulary (refused); Biscuit wouldn't admit B anyway.
    let t = append_raw(&f.tok, "check if true;");
    assert!(load_err(&t, k).contains("expression not allowed"));
    assert!(!stock_allows(&t, &req(1)));
    // A forged approved fact, or a rule deriving one, in a holder block.
    let t = append_raw(&f.tok, r#"approved("g-x", "api.github.com", "GET", "/repos/other/x/issues");"#);
    assert!(load_err(&t, k).contains("fact not allowed"));
    assert!(!stock_allows(&t, &req(1)));
    let t = append_raw(&f.tok, "approved($g, $h, $m, $p) <- host($h), method($m), path($p), uses_left($g, $n);");
    assert!(load_err(&t, k).contains("rules"));
    assert!(!stock_allows(&t, &req(1)));
    // A well-formed grant from a key no block trusts, and the leaf approving itself.
    let other = Grant { method: "GET".into(), path: "/repos/other/x/issues".into(), ..leaf_grant(5) };
    let t = grant(&f.tok, &SigningKey::generate(), &other).unwrap();
    assert!(load_err(&t, k).contains("no first-party block trusts"));
    assert!(!stock_allows(&t, &req(1)));
    let own = Grant { method: "POST".into(), path: "/repos/acme/api/issues".into(), ..leaf_grant(5) };
    let t = grant(&f.parent_only, &k.grantor[5], &own).unwrap();
    assert!(load_err(&t, k).contains("no first-party block trusts"), "a leaf approving itself");
    assert!(!stock_allows(&t, &http_req("POST", "/repos/acme/api/issues", RiskClass::R1ReadScoped)));
    // A node appends a block trusting its own key, then approves with it: the block passes the
    // structural check, but no other block trusts that key, so B still needs a grant.
    let evil = SigningKey::generate();
    let mut c = f.cs[5].clone();
    c.grant_keys = vec![evil.public()];
    let t = grant(&f.tok.attenuate(&c).unwrap(), &evil, &other).unwrap();
    assert!(is_grant(&decide(&t, k, &req(1))));
    // A block can't carry a policy at all.
    assert!(BlockBuilder::new().code("allow if true;").is_err());
    // A later expiry in a new block doesn't extend the leaf's.
    let mut c = f.cs[5].clone();
    c.not_after += 48 * 3600;
    let t = f.tok.attenuate(&c).unwrap();
    let mut r = req(0);
    r.time = f.cs[5].not_after + 1;
    assert!(is_forbidden(&decide(&t, k, &r)));
    // Wider reach in a new block doesn't admit B.
    let mut c = f.cs[5].clone();
    c.reach.push(common::r("api.github.com", &["GET"], &["/**"], true));
    let t = f.tok.attenuate(&c).unwrap();
    assert!(is_grant(&decide(&t, k, &req(1))));
    // Another tenant.
    let mut r = req(0);
    r.tenant = "other-tenant".into();
    assert!(is_forbidden(&decide(&f.tok, k, &r)));
}

#[test]
fn a_node_can_narrow() {
    let f = fixture();
    let k = &f.keys;
    let mut c = f.cs[5].clone();
    c.reach[0].methods = vec!["GET".into()];
    c.grant_keys.clear();
    let t = f.tok.attenuate(&c).unwrap();
    let l = load_ok(&t, k);
    assert_eq!(decide_compiled(&l, &req(0)), Decision::Allow, "A still allowed");
    assert!(is_grant(&decide_compiled(&l, &req(2))), "C (granted PUT) no longer allowed: the new block trusts no grant");
    // Hand-written narrowing within the vocabulary passes the structural check. It has no grant
    // escape, so nothing can lift it: C is now forbidden.
    let t = append_raw(&f.tok, r#"check if op($o), $o != "http" or method("GET");"#);
    let l = load_ok(&t, k);
    assert_eq!(decide_compiled(&l, &req(0)), Decision::Allow);
    assert!(is_forbidden(&decide_compiled(&l, &req(2))));
    let mut c = f.cs[5].clone();
    c.ops.retain(|o| *o != OpKind::Spawn);
    assert!(is_forbidden(&decide(&f.tok.attenuate(&c).unwrap(), k, &req(3))), "no spawn");
}

#[test]
fn expiry_and_leases() {
    let f = fixture();
    let k = &f.keys;
    let l = load_ok(&f.tok, k);
    let leaf_exp = f.cs[5].not_after;
    let g = leaf_grant(5);
    let at = |i: usize, time: u64| Request { time, ..req(i) };
    assert_eq!(decide_compiled(&l, &at(0, leaf_exp)), Decision::Allow, "A at the leaf's expiry");
    assert!(is_forbidden(&decide_compiled(&l, &at(0, leaf_exp + 1))), "A after it");
    assert!(is_grant(&decide_compiled(&l, &at(2, g.not_after + 1))), "C after the grant's expiry");
    assert_eq!(decide_compiled(&l, &at(0, g.not_after + 1)), Decision::Allow, "an expired lease doesn't end the chain");
    assert_eq!(decide_compiled(&l, &at(2, g.not_after)), Decision::Allow, "C at the grant's expiry");
    let mut r = req(2);
    r.uses_left = vec![("g-7f3a".into(), 0)];
    assert!(is_grant(&decide_compiled(&l, &r)), "C with no uses left");
    r.uses_left.clear();
    assert!(is_grant(&decide_compiled(&l, &r)), "C with no ledger entry");
    r.uses_left = vec![("g-other".into(), 5)];
    assert!(is_grant(&decide_compiled(&l, &r)), "C with another grant's uses");
    let mut r = req(2);
    r.epoch = 4;
    assert!(is_grant(&decide_compiled(&l, &r)), "C in a later box epoch");
    // The leaf spawns b6: its chain carries the leaf's grant, which isn't b6's.
    let mut c = f.cs[5].clone();
    c.box_prefix = format!("{}/b6", box_id(5));
    let child = load_ok(&f.tok.attenuate(&c).unwrap(), k);
    let mut r = req(2);
    r.box_id = format!("{}/b6", box_id(5));
    assert!(is_grant(&decide_compiled(&child, &r)), "C from b6");
    r.action = req(0).action;
    assert_eq!(decide_compiled(&child, &r), Decision::Allow, "A from b6");
    let mut r = req(0);
    r.box_id = "b0/b1/b9".into();
    assert!(is_forbidden(&decide_compiled(&l, &r)), "a box outside the chain's subtree");
    let mut r = req(0);
    r.box_id = format!("{}x", box_id(5));
    assert!(is_forbidden(&decide_compiled(&l, &r)), "a box whose id only starts with the leaf's");
}

#[test]
fn agent_grants_from_the_parent() {
    let f = fixture();
    let k = &f.keys;
    let g = |m: &str, p: &str, risk: RiskClass, key: &SigningKey| {
        let gr = Grant { method: m.into(), path: p.into(), ..leaf_grant(5) };
        decide(&grant(&f.parent_only, key, &gr).unwrap(), k, &http_req(m, p, risk))
    };
    assert_eq!(g("POST", "/repos/acme/api/issues", RiskClass::R1ReadScoped, &k.grantor[4]), Decision::Allow, "within b4, outside the leaf");
    assert!(is_grant(&g("POST", "/repos/acme/infra/issues", RiskClass::R1ReadScoped, &k.grantor[4])), "outside b4's own reach");
    assert!(
        is_grant(&g("PUT", "/repos/acme/api/pulls/7/merge", RiskClass::R3ExternalOrIrreversible, &k.grantor[4])),
        "a risk b4 can't take itself"
    );
    assert_eq!(
        g("PUT", "/repos/acme/api/pulls/7/merge", RiskClass::R3ExternalOrIrreversible, &k.approver),
        Decision::Allow,
        "the approval service"
    );
    // The grandparent's key isn't trusted by the leaf's block.
    assert!(is_grant(&g("POST", "/repos/acme/api/issues", RiskClass::R1ReadScoped, &k.grantor[3])));
}

#[test]
fn an_approval_cant_reach_what_block_0_forbids() {
    let f = fixture();
    let k = &f.keys;
    let path = "/repos/acme/secrets-vault/key";
    let gr = Grant { method: "GET".into(), path: path.into(), ..leaf_grant(5) };
    let t = grant(&f.parent_only, &k.approver, &gr).unwrap();
    assert!(is_forbidden(&decide(&t, k, &http_req("GET", path, RiskClass::R1ReadScoped))));
    // At depth 0, where reach alone covers /repos/acme/**.
    let t0 = mint_chain(&f.cs[..1], k);
    let gr = Grant { box_id: box_id(0), ..gr };
    let t = grant(&t0, &k.approver, &gr).unwrap();
    let r = Request { box_id: box_id(0), ..http_req("GET", path, RiskClass::R1ReadScoped) };
    assert!(is_forbidden(&decide(&t, k, &r)));
    // And a forbidden host.
    let gr = Grant { host: "vault.internal".into(), path: "/x".into(), ..gr };
    let t = grant(&t0, &k.approver, &gr).unwrap();
    let r = Request { action: http("GET", "vault.internal", "/x", RiskClass::R1ReadScoped), ..r };
    assert!(is_forbidden(&decide(&t, k, &r)));
}

#[test]
fn empty_lists_encode_as_empty_sets() {
    let keys = Keys::new(1);
    let mut c = level(0, vec![]);
    c.reach = vec![common::r("api.github.com", &[], &["/**"], false), common::r("docs.rs", &["GET"], &["/**"], false)];
    c.forbid.clear();
    c.inject.clear();
    c.spawn.images.clear();
    c.accept_from.clear();
    let mut child = c.clone();
    child.ops.clear();
    for (cs, msg) in [(vec![c.clone()], "root"), (vec![c, child], "child with no ops")] {
        let t = mint_chain(&cs, &keys);
        let l = load_ok(&t, &keys);
        let b = base_request(0);
        let d = |a: Action| decide_compiled(&l, &Request { action: a, ..b.clone() });
        let docs =
            Action::Http { host: "docs.rs".into(), method: "GET".into(), path: "/x".into(), risk: RiskClass::R1ReadScoped, inject: None };
        if cs.len() == 1 {
            assert_eq!(d(docs), Decision::Allow, "{msg}");
            let gh = Action::Http {
                host: "api.github.com".into(),
                method: "GET".into(),
                path: "/x".into(),
                risk: RiskClass::R1ReadScoped,
                inject: None,
            };
            assert!(is_grant(&d(gh)), "{msg}: no methods");
            assert!(is_forbidden(&d(http("GET", "docs.rs", "/x", RiskClass::R1ReadScoped))), "{msg}: no injections");
            assert!(is_forbidden(&d(Action::Msg { from: "ops".into() })), "{msg}: nobody may message");
            assert!(is_forbidden(&d(scenarios(0)[3].1.action.clone())), "{msg}: no images");
        } else {
            assert!(is_forbidden(&d(docs)), "{msg}");
        }
    }
}

#[test]
fn revocation_by_subtree() {
    let keys = Keys::new(5);
    let cs3 = ceilings(3, &keys);
    let p3 = mint_chain(&cs3, &keys);
    let kid = |name: &str| {
        let mut c = level(4, vec![keys.approver.public(), keys.grantor[3].public()]);
        c.box_prefix = format!("{}/{name}", box_id(3));
        p3.attenuate(&c).unwrap()
    };
    let (c1, c2) = (kid("b4a"), kid("b4b"));
    let (i1, i2, ip) = (revocation_ids(&c1), revocation_ids(&c2), revocation_ids(&p3));
    assert!(i1[..4] == i2[..4] && i1[4] != i2[4] && ip[..] == i1[..4], "siblings share their common prefix's ids");
    let try_load = |t: &Token, list: &HashSet<Vec<u8>>| load(&t.to_bytes().unwrap(), &keys.root.public(), &|id| list.contains(id));
    let only_c1: HashSet<Vec<u8>> = [i1[4].clone()].into();
    assert!(matches!(try_load(&c1, &only_c1), Err(AuthzError::Revoked(4))));
    assert!(try_load(&c2, &only_c1).is_ok() && try_load(&p3, &only_c1).is_ok());
    let b2: HashSet<Vec<u8>> = [ip[2].clone()].into();
    for t in [&c1, &c2, &p3] {
        assert!(matches!(try_load(t, &b2), Err(AuthzError::Revoked(2))), "b2's subtree");
    }
    // A grant block has its own id: revoking it ends the lease, not the zone.
    let g = grant(&c1, &keys.approver, &leaf_grant(4)).unwrap();
    let ig = revocation_ids(&g);
    assert_eq!(ig.len(), 6);
    let lease: HashSet<Vec<u8>> = [ig[5].clone()].into();
    assert!(matches!(try_load(&g, &lease), Err(AuthzError::Revoked(5))));
    assert!(try_load(&c1, &lease).is_ok());
    assert_eq!(load_ok(&g, &keys).revocation_ids(), &ig[..]);
}

#[test]
fn tampering() {
    use prost::Message;
    let f = fixture();
    let bytes = f.tok.to_bytes().unwrap();
    let pk = f.keys.root.public();
    // Flipping a bit anywhere: a sample of positions across the whole token (every position takes
    // too long in a debug build; the experiment flipped all of them).
    let mut accepted = 0;
    let mut tried = 0;
    for i in (0..bytes.len()).step_by(7) {
        let mut x = bytes.clone();
        x[i] ^= 0x01;
        tried += 1;
        if load(&x, &pk, &never_revoked).is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 0, "{accepted} of {tried} flipped tokens loaded");
    let pb = biscuit_auth::format::schema::Biscuit::decode(bytes.as_slice()).unwrap();
    let mut drop_last = pb.clone();
    drop_last.blocks.pop();
    assert!(Token::from_bytes(&drop_last.encode_to_vec(), &pk).is_err(), "dropping the last block");
    let mut drop_mid = pb.clone();
    drop_mid.blocks.remove(2);
    assert!(Token::from_bytes(&drop_mid.encode_to_vec(), &pk).is_err(), "removing a middle block");
    let mut swap = pb.clone();
    swap.blocks.swap(1, 2);
    assert!(Token::from_bytes(&swap.encode_to_vec(), &pk).is_err(), "reordering blocks");
    assert!(load(&bytes, &SigningKey::generate().public(), &never_revoked).is_err(), "wrong root key");
    // A grant made for one chain can't be moved to a sibling.
    let mut c = f.cs[5].clone();
    c.box_prefix = format!("{}/x", box_id(4));
    let sibling = mint_chain(&f.cs[..5], &f.keys).attenuate(&c).unwrap();
    let signed = sign_grant(f.parent_only.grant_request().unwrap(), &f.keys.approver, &leaf_grant(5)).unwrap();
    let moved = sibling.add_grant(&f.keys.approver.public(), signed).and_then(|t| t.to_bytes()).and_then(|b| Token::from_bytes(&b, &pk));
    assert!(moved.is_err(), "a grant transplanted to a sibling");
    let sealed = f.tok.biscuit().seal().unwrap();
    assert!(sealed.append(BlockBuilder::new()).is_err(), "a sealed token can't be attenuated");
}

/// Research 23's Datalog traps.
#[test]
fn datalog_traps() {
    let f = fixture();
    let k = &f.keys;
    // Facts in a non-authority block are invisible to other blocks' checks: a holder block saying
    // the request's path is in reach doesn't make block 0 agree.
    let t = append_raw(&f.tok, r#"path("/repos/acme/api/x"); host("api.github.com"); method("GET");"#);
    assert!(load_err(&t, k).contains("fact not allowed"));
    assert!(!stock_allows(&t, &req(1)));
    // A narrower rule with the same name in a child block doesn't narrow (first-party rules are
    // refused; the grant's own rule still yields `approved`).
    let t = append_raw(&f.tok, r#"approved($g, $h, $m, $p) <- approved($g, $h, $m, $p), method("GET");"#);
    assert!(load_err(&t, k).contains("rules"));
    assert!(stock_allows(&t, &req(2)), "Biscuit: the narrower rule didn't narrow");
    // A ceiling written as a check matches any fact in scope: an escape that doesn't bind the
    // request's host, method and path would accept any grant from that key for any request.
    let key = k.approver.public().to_hex();
    let loose = format!("check if approved($g, $h, $m, $p) trusting ed25519/{key};");
    let t = append_raw(&f.tok, &loose);
    assert!(load_err(&t, k).contains("must bind"));
    // Injection through string-built Datalog: a zone name full of Datalog is one string.
    let mut c = f.cs[5].clone();
    c.zone = r#"x"); check if false; zone("y"#.into();
    let t = f.tok.attenuate(&c).unwrap();
    let b = t.biscuit().block_datalog(7).unwrap();
    assert_eq!(b.facts.len(), 1);
    assert_eq!(b.facts[0].predicate.terms, vec![biscuit_auth::builder::Term::Str(c.zone.clone())]);
    assert_eq!(decide(&t, k, &req(0)), Decision::Allow);
    // Comparing time, a date, with an integer: refused at load (it is an evaluation error).
    assert!(stock_allows(&f.tok, &req(0)));
    let t = append_raw(&f.tok, "check if time($t), $t <= 1900000000;");
    assert!(load_err(&t, k).contains("wrong type"));
    assert!(!stock_allows(&t, &req(0)));
}

#[test]
fn grant_request_round_trip() {
    let f = fixture();
    let req_bytes = f.parent_only.grant_request().unwrap().to_bytes().unwrap();
    let back = GrantRequest::from_bytes(&req_bytes).unwrap();
    let signed = sign_grant(back, &f.keys.approver, &leaf_grant(5)).unwrap();
    assert!(!signed.to_bytes().unwrap().is_empty());
    let t = f.parent_only.add_grant(&f.keys.approver.public(), signed).unwrap();
    assert_eq!(decide(&t, &f.keys, &req(2)), Decision::Allow);
    // Appended under the wrong key name: refused.
    let signed = sign_grant(f.parent_only.grant_request().unwrap(), &f.keys.approver, &leaf_grant(5)).unwrap();
    assert!(f.parent_only.add_grant(&f.keys.grantor[4].public(), signed).is_err());
}

#[test]
fn non_ascii_paths_match_byte_for_byte() {
    // `?` is one byte to wicket-core's matcher; the token sees the path's bytes as characters.
    let keys = Keys::new(0);
    let mut c = level(0, vec![]);
    c.reach = vec![common::r("h.example", &["GET"], &["/a?/x", "/caf\u{e9}/**"], false)];
    c.forbid.clear();
    c.inject.clear();
    let zone = wicket_core::Manifest::from_yaml("task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  reach: [{ host: h.example, methods: [GET], paths: [\"/a?/x\", \"/caf\u{e9}/**\"] }]\n").unwrap().zone;
    let cz = wicket_core::CompiledZone::new(zone).unwrap();
    let l = load_ok(&mint_chain(&[c], &keys), &keys);
    for p in ["/ab/x", "/a\u{e9}/x", "/a\u{e9}\u{e9}/x", "/caf\u{e9}/y", "/cafe/y", "/caf\u{e8}/y"] {
        let o = op("z", "GET", "h.example", p);
        let r = Request { box_id: "b0".into(), action: Action::from_op(&o, None), ..base_request(0) };
        assert_eq!(kind_of(&decide_compiled(&l, &r)), kind_of_verdict(&cz.evaluate(&o)), "{p}");
    }
}

/// #153: a node stops a box when its token expires, so a loaded token says when: the earliest
/// expiry of its first-party blocks, whichever block sets it. Grants (third-party) don't shorten it.
#[test]
fn a_loaded_token_reports_its_earliest_block_expiry() {
    let keys = Keys::new(3);
    let mut cs = ceilings(2, &keys);
    cs[0].not_after = 5_000;
    cs[1].not_after = 4_000;
    cs[2].not_after = 4_500;
    assert_eq!(load_ok(&mint_chain(&cs[..1], &keys), &keys).not_after(), Some(5_000));
    assert_eq!(load_ok(&mint_chain(&cs, &keys), &keys).not_after(), Some(4_000));
}
