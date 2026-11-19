//! Standing grants (#572): a reach rule above a box's ceilings, approved once for an agent's later
//! runs. Its block allows what the same reach rule would in a manifest (its methods, its path
//! globs, and a reach rule's risk unless `allow_dangerous`), never past a forbid rule, and a
//! block looser than the generator writes is refused at load.

use crate::common::*;
use biscuit_auth::{BlockBuilder, PrivateKey};
use wicket_authz::*;
use wicket_core::RiskClass;

/// The depth-5 chain with a standing grant on api.github.com, gid g-7f3a: `rule`.
fn standing(rule: &StandingRule) -> Loaded {
    let keys = Keys::new(5);
    let chain = mint_chain(&ceilings(5, &keys), &keys);
    let tok = grant_standing(&chain, &keys.approver, &leaf_grant(5), rule).unwrap();
    let l = load_ok(&tok, &keys);
    assert!(l.is_compiled(), "a standing grant mustn't push the token onto the generic engine");
    l
}

fn logs() -> StandingRule {
    StandingRule { methods: vec!["GET".into()], paths: vec!["/repos/other/*/actions/jobs/*/logs".into()], allow_dangerous: false }
}

fn req(method: &str, path: &str, risk: RiskClass) -> Request {
    Request { action: http(method, "api.github.com", path, risk), ..base_request(5) }
}

fn needs(l: &Loaded, r: &Request) -> bool {
    matches!(decide_compiled(l, r), Decision::NeedsGrant(_))
}

#[test]
fn a_standing_grant_allows_what_its_rule_would() {
    let l = standing(&logs());
    let get = |p: &str| req("GET", p, RiskClass::R0Read);
    // Outside every ceiling's reach: needs the grant, and the grant allows it.
    for p in ["/repos/other/app/actions/jobs/1/logs", "/repos/other/web/actions/jobs/22/logs"] {
        assert_eq!(decide_compiled(&l, &get(p)), Decision::Allow, "{p}");
        assert!(!l.last_fell_back(), "{p} was decided by the generic engine");
    }
    // `*` is one segment; another method, host or path isn't covered.
    assert!(needs(&l, &get("/repos/other/app/actions/jobs/1/logs/x")));
    assert!(needs(&l, &get("/repos/other/a/b/actions/jobs/1/logs")));
    assert!(needs(&l, &get("/repos/other/app/actions/runs/1")));
    assert!(needs(&l, &req("POST", "/repos/other/app/actions/jobs/1/logs", RiskClass::R2WriteReversible)));
    let elsewhere =
        Request { action: http("GET", "uploads.github.com", "/repos/other/app/actions/jobs/1/logs", RiskClass::R0Read), ..base_request(5) };
    assert!(needs(&l, &elsewhere));
    // A reach rule's risk: an R3 read of the same path isn't allowed without allow_dangerous.
    assert!(needs(&l, &req("GET", "/repos/other/app/actions/jobs/1/logs", RiskClass::R3ExternalOrIrreversible)));
    // Past its end: nothing.
    let late = Request { time: leaf_grant(5).not_after + 1, ..get("/repos/other/app/actions/jobs/1/logs") };
    assert!(needs(&l, &late));
}

#[test]
fn a_dangerous_standing_grant_reaches_r4_but_never_a_forbidden_path() {
    let rule = StandingRule { methods: vec!["PUT".into(), "DELETE".into()], paths: vec!["/repos/**".into()], allow_dangerous: true };
    let l = standing(&rule);
    assert_eq!(decide_compiled(&l, &req("PUT", "/repos/other/app/pulls/7/merge", RiskClass::R4ExecOrPrivilege)), Decision::Allow);
    assert_eq!(decide_compiled(&l, &req("DELETE", "/repos/other/app", RiskClass::R4ExecOrPrivilege)), Decision::Allow);
    // A forbid rule is a `reject if`, which no grant satisfies.
    assert!(matches!(
        decide_compiled(&l, &req("PUT", "/repos/acme/secrets-vault/x", RiskClass::R4ExecOrPrivilege)),
        Decision::Forbidden(_)
    ));
}

#[test]
fn a_standing_grant_is_held_to_its_caps() {
    let keys = Keys::new(5);
    let chain = mint_chain(&ceilings(5, &keys), &keys);
    let g = leaf_grant(5);
    let too_many = StandingRule {
        methods: vec!["GET".into(), "HEAD".into()],
        paths: (0..9).map(|i| format!("/p{i}/**")).collect(),
        allow_dangerous: false,
    };
    assert!(grant_standing(&chain, &keys.approver, &g, &too_many).is_err(), "18 rules");
    let none = StandingRule { methods: vec![], ..logs() };
    assert!(grant_standing(&chain, &keys.approver, &g, &none).is_err());
    let wild = Grant { host: "*.github.com".into(), ..g };
    assert!(grant_standing(&chain, &keys.approver, &wild, &logs()).is_err(), "an exact host only");
}

/// A standing block written by other means than the generator: a rule looser than wicket's is
/// refused at load, whoever signed it.
#[test]
fn a_loose_standing_rule_is_refused() {
    let keys = Keys::new(5);
    let t = mint_chain(&ceilings(2, &keys), &keys);
    let evil = PrivateKey::new();
    let evil_pub = PublicKey(evil.public().to_bytes().try_into().unwrap());
    let mut c = level(3, vec![evil_pub]);
    c.box_prefix = box_id(2);
    let t = t.attenuate(&c).unwrap();
    let raw = |code: &str| {
        let req = t.biscuit().third_party_request().unwrap();
        let blk = req.create_block(&evil, BlockBuilder::new().code(code).unwrap()).unwrap();
        Token::from_biscuit(t.biscuit().append_third_party(evil.public(), blk).unwrap())
    };
    let bounds = r#"time($t), $t <= 2030-01-01T00:00:00Z, box("b0/b1/b2"), epoch(3), uses_left("g", $n), $n > 0"#;
    let ok = format!(r#"approved("g", "h", "GET", $p) <- path($p), $p.matches("^/a/[^/]*$"), risk($r), $r <= 2, {bounds};"#);
    assert!(load_ok(&raw(&ok), &keys).is_compiled());
    let refused = |code: String, why: &str| {
        let e = load_err(&raw(&code), &keys);
        assert!(e.contains(why), "{code}: {e}");
    };
    // Its risk read but not bounded, or bounded above a reach rule's.
    refused(format!(r#"approved("g", "h", "GET", $p) <- path($p), $p.matches("^/a/.*$"), risk($r), {bounds};"#), "risk");
    refused(format!(r#"approved("g", "h", "GET", $p) <- path($p), $p.matches("^/a/.*$"), risk($r), $r <= 4, {bounds};"#), "not allowed");
    // A pattern on something other than the request's path; one Biscuit can't compile.
    refused(format!(r#"approved("g", "h", "GET", $p) <- path($p), host($h), $h.matches("^a$"), {bounds};"#), "exactly");
    refused(format!(r#"approved("g", "h", "GET", $p) <- path($p), $p.matches("(unclosed"), {bounds};"#), "regex refused");
}
