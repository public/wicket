//! Path-prefix grants (#257 4a): what the control host's ledger covers with a prefix grant, a node
//! now covers too: the directory itself and every path under it, whole segments only. Decided by
//! the compiled evaluator. A prefix that isn't canonical, or a grant rule looser than the generator
//! writes, is refused before anything evaluates it.

use crate::common::*;
use biscuit_auth::{BlockBuilder, PrivateKey};
use wicket_authz::*;
use wicket_core::RiskClass;

/// The depth-5 chain with a prefix grant on `PUT api.github.com/repos/acme/api/pulls/`, gid g-7f3a.
fn prefixed() -> (Keys, Loaded) {
    let keys = Keys::new(5);
    let cs = ceilings(5, &keys);
    let chain = mint_chain(&cs, &keys);
    let g = Grant { path: "/repos/acme/api/pulls/".into(), ..leaf_grant(5) };
    let tok = grant_prefix(&chain, &keys.approver, &g).unwrap();
    let l = load_ok(&tok, &keys);
    assert!(l.is_compiled(), "a prefix grant mustn't push the token onto the generic engine");
    (keys, l)
}

fn put(path: &str) -> Request {
    Request { action: http("PUT", "api.github.com", path, RiskClass::R4ExecOrPrivilege), ..base_request(5) }
}

#[test]
fn a_prefix_grant_covers_its_directory_and_what_is_under_it() {
    let (_, l) = prefixed();
    for p in ["/repos/acme/api/pulls", "/repos/acme/api/pulls/", "/repos/acme/api/pulls/7/merge", "/repos/acme/api/pulls/8"] {
        assert_eq!(decide_compiled(&l, &put(p)), Decision::Allow, "{p}");
        assert!(!l.last_fell_back(), "{p} was decided by the generic engine");
    }
}

#[test]
fn a_prefix_grant_covers_nothing_outside_it() {
    let (_, l) = prefixed();
    // A sibling sharing the prefix's letters, the parent, another case, another repository.
    for p in [
        "/repos/acme/api/pullsx/7",
        "/repos/acme/api",
        "/repos/acme/api/",
        "/repos/acme/api-x/pulls/7",
        "/repos/acme/api/Pulls/7",
        "/repos/acme/Api/pulls/7",
    ] {
        assert!(matches!(decide_compiled(&l, &put(p)), Decision::NeedsGrant(_)), "{p} was allowed");
        assert!(!l.last_fell_back(), "{p}");
    }
    // Another method, no uses left, past the grant's end.
    let del =
        Request { action: http("DELETE", "api.github.com", "/repos/acme/api/pulls/7", RiskClass::R4ExecOrPrivilege), ..base_request(5) };
    assert!(matches!(decide_compiled(&l, &del), Decision::NeedsGrant(_)));
    let spent = Request { uses_left: vec![("g-7f3a".into(), 0)], ..put("/repos/acme/api/pulls/7") };
    assert!(matches!(decide_compiled(&l, &spent), Decision::NeedsGrant(_)), "no uses left");
    let late = Request { time: leaf_grant(5).not_after + 1, ..put("/repos/acme/api/pulls/7") };
    assert!(matches!(decide_compiled(&l, &late), Decision::NeedsGrant(_)), "after the grant's end");
}

#[test]
fn a_prefix_grant_must_be_canonical() {
    let keys = Keys::new(5);
    let chain = mint_chain(&ceilings(5, &keys), &keys);
    for p in
        ["/repos/acme/api/pulls", "/repos/acme/../x/", "/repos//acme/", "/repos/%2e%2e/", "/repos/%2E/", "/repos/a%2fb/", "repos/acme/"]
    {
        let g = Grant { path: p.into(), ..leaf_grant(5) };
        assert!(grant_prefix(&chain, &keys.approver, &g).is_err(), "{p} was accepted as a prefix");
    }
    // The root covers a whole host, and is canonical.
    assert!(grant_prefix(&chain, &keys.approver, &Grant { path: "/".into(), ..leaf_grant(5) }).is_ok());
}

/// A grant block written by other means than the generator: a prefix rule looser than wicket's is
/// refused at load, whoever signed it.
#[test]
fn a_loose_prefix_rule_is_refused() {
    let keys = Keys::new(5);
    let cs = ceilings(2, &keys);
    let t = mint_chain(&cs, &keys);
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
    let ok = format!(r#"approved("g", "h", "GET", $p) <- path($p), $p.starts_with("/a/b/"), {bounds};"#);
    assert!(load_ok(&raw(&ok), &keys).is_compiled());
    let refused = |code: String, why: &str| {
        let e = load_err(&raw(&code), &keys);
        assert!(e.contains(why), "{code}: {e}");
    };
    for pre in ["/a/b", "/a/../", "/a//b/", "/a/%2e/", "a/b/", "/a/%2E%2E/"] {
        refused(
            format!(r#"approved("g", "h", "GET", $p) <- path($p), $p.starts_with("{pre}"), {bounds};"#),
            "canonical path ending in '/'",
        );
    }
    // No prefix bound, or the path bound to something other than the request's path.
    refused(format!(r#"approved("g", "h", "GET", $p) <- path($p), {bounds};"#), "its prefix");
    refused(format!(r#"approved("g", "h", "GET", $p) <- host($p), $p.starts_with("/a/"), {bounds};"#), "exactly");
    refused(format!(r#"approved("g", "h", $m, $p) <- path($p), method($m), $p.starts_with("/a/"), {bounds};"#), "literal");
    refused(format!(r#"approved("g", "h", "GET", $p) <- path($p), $p.ends_with("/a/"), {bounds};"#), "expression not allowed");
}
