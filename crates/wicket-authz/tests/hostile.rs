//! Hostile tokens: everything outside wicket's block shapes is refused at load, before any
//! evaluation; and the step budget bounds the cost of whatever the structural check lets through.

mod common;
use biscuit_auth::{BlockBuilder, PrivateKey};
use common::*;
use std::time::Instant;
use wicket_authz::*;

fn chain() -> (Keys, Token) {
    let keys = Keys::new(5);
    let cs = ceilings(2, &keys);
    let t = mint_chain(&cs, &keys);
    // The legitimate chain the hostile blocks are appended to runs compiled, every request (#183).
    let l = load_ok(&t, &keys);
    assert!(l.is_compiled());
    for (_, r) in scenarios(2) {
        decide_compiled(&l, &r);
    }
    (keys, t)
}

fn append_raw(t: &Token, code: &str) -> Token {
    Token::from_biscuit(t.biscuit().append(BlockBuilder::new().code(code).unwrap()).unwrap())
}

fn third_party_raw(t: &Token, code: &str, key: &PrivateKey) -> Token {
    let req = t.biscuit().third_party_request().unwrap();
    let blk = req.create_block(key, BlockBuilder::new().code(code).unwrap()).unwrap();
    Token::from_biscuit(t.biscuit().append_third_party(key.public(), blk).unwrap())
}

#[test]
fn refused_at_load() {
    let (keys, t) = chain();
    let refused = |code: &str, why: &str| {
        let e = load_err(&append_raw(&t, code), &keys);
        assert!(e.contains(why), "{code}: {e}");
    };
    refused(r#"ok($x) <- host($x);"#, "rules");
    refused(r#"check if secret($x);"#, "vocabulary");
    refused(r#"check if host($h), node($n);"#, "vocabulary");
    refused(r#"check if spawn($a, $b);"#, "vocabulary");
    refused(r#"check all host($h), $h == "a";"#, "check all");
    refused(r#"check if host($h), $h.length() > 3;"#, "expression not allowed");
    refused(r#"check if host($h), $h.matches("a.*");"#, "expression not allowed");
    refused(r#"check if path($p), $p.matches($p);"#, "expression not allowed");
    refused(r#"check if path($p), [1, 2].contains(1);"#, "expression not allowed");
    refused(r#"check if path($p), $p.matches("(?-u)^/.*$");"#, "regex refused");
    refused(r#"check if path($p), $p.matches("(a{100}){100}");"#, "regex refused");
    refused(r#"check if host($h), $h == $h;"#, "not allowed");
    refused(r#"check if host($h) trusting previous;"#, "scopes");
    refused(r#"check if risk($r), $r <= 2025-01-01T00:00:00Z;"#, "wrong type");
    refused(r#"tenant("other");"#, "fact not allowed");
    refused(r#"zone("a"); zone("b");"#, "too many facts");
    let long = format!("check if path($p), $p.matches(\"^/{}$\");", "a".repeat(300));
    refused(&long, "regex longer");
    // Block-level scope.
    let b = BlockBuilder::new().code("check if host(\"a\");").unwrap().scope(biscuit_auth::builder::Scope::Previous);
    let e = load_err(&Token::from_biscuit(t.biscuit().append(b).unwrap()), &keys);
    assert!(e.contains("scopes"), "{e}");
    // Too many checks, alternatives and regexes in one block.
    refused(&"check if host(\"a\");\n".repeat(65), "checks");
    let alts = vec!["host(\"a\")"; 65].join(" or ");
    refused(&format!("check if {alts};"), "alternatives");
    let re = vec!["path($p), $p.matches(\"^/a$\")"; 60].join(" or ");
    refused(&format!("check if {re};\ncheck if {re};\ncheck if {re};"), "regexes");
}

#[test]
fn too_many_blocks_or_bytes() {
    let keys = Keys::new(20);
    let mut cs = ceilings(5, &keys);
    // 16 blocks load; a 17th is refused, both when attenuating and (appended by other means) at load.
    let mut t = mint_chain(&cs, &keys);
    while t.block_count() < 16 {
        t = t.attenuate(&cs[5]).unwrap();
    }
    load_ok(&t, &keys);
    assert!(matches!(t.attenuate(&cs[5]), Err(AuthzError::Structure(e)) if e.contains("17 blocks")));
    let raw = Token::from_biscuit(t.biscuit().append(wicket_authz::generator::ceiling_block(&cs[5]).unwrap()).unwrap());
    assert!(load_err(&raw, &keys).contains("17 blocks"));
    // Token bytes: blocks with many long, distinct globs (Biscuit interns repeated strings), until
    // the token is over the cap. One glob per host, so that no host's globs are over the cost
    // estimate (`cost`, #183) before the token is over the byte cap.
    let mut t = mint_chain(&cs, &keys);
    let base = cs[5].reach.clone();
    for j in 0.. {
        cs[5].reach = base.clone();
        cs[5].reach.extend(
            (0..56).map(|i| r(&format!("h{j}-{i}.example"), &["GET"], &[&format!("/repos/acme/{}-{j}-{i}/**", "x".repeat(180))], false)),
        );
        match t.attenuate(&cs[5]) {
            Ok(next) => t = next,
            Err(AuthzError::Structure(e)) => {
                assert!(e.contains("bytes"), "{e}");
                let raw = Token::from_biscuit(t.biscuit().append(wicket_authz::generator::ceiling_block(&cs[5]).unwrap()).unwrap());
                assert!(load_err(&raw, &keys).contains("bytes"));
                break;
            }
            Err(e) => panic!("{e}"),
        }
    }
    // A child zone over a per-block cap is refused where it's made.
    cs[5].reach = base;
    cs[5].reach[0].paths = (0..70).map(|i| format!("/repos/acme/p{i}/**")).collect();
    assert!(matches!(mint_chain(&cs[..5], &keys).attenuate(&cs[5]), Err(AuthzError::Structure(e)) if e.contains("alternatives")));
}

#[test]
fn hostile_third_party_blocks() {
    let (keys, t) = chain();
    // A foreign key: well-formed grant, but no block trusts its signer.
    let g = Grant { box_id: box_id(2), ..leaf_grant(2) };
    assert!(load_err(&grant(&t, &SigningKey::generate(), &g).unwrap(), &keys).contains("no first-party block trusts"));
    // A trusted key with hostile content: a key that a spawn block trusts, signing through the raw
    // API.
    let evil = PrivateKey::new();
    let evil_pub = PublicKey(evil.public().to_bytes().try_into().unwrap());
    let mut c = level(3, vec![evil_pub]);
    c.box_prefix = box_id(2);
    let t = t.attenuate(&c).unwrap();
    let ok =
        r#"approved("g", "h", "GET", "/") <- time($t), $t <= 2030-01-01T00:00:00Z, box("b0/b1/b2"), epoch(3), uses_left("g", $n), $n > 0;"#;
    let l = load_ok(&third_party_raw(&t, ok, &evil), &keys);
    assert!(l.is_compiled());
    for (_, r) in scenarios(3) {
        decide_compiled(&l, &r);
    }
    let refused = |code: &str, why: &str| {
        let e = load_err(&third_party_raw(&t, code, &evil), &keys);
        assert!(e.contains(why), "{code}: {e}");
    };
    refused(r#"approved($g, $h, $m, $p) <- host($h), method($m), path($p), uses_left($g, $n);"#, "literal");
    refused(
        r#"approved("g", "h", "GET", "/") <- time($t), box($b), epoch(3), uses_left("g", $n), $n > 0, $t <= 2030-01-01T00:00:00Z;"#,
        "predicate not allowed",
    );
    refused(
        r#"approved("g", "h", "GET", "/") <- time($t), box("b"), epoch(3), uses_left("g", $n), host("h"), $n > 0, $t <= 2030-01-01T00:00:00Z;"#,
        "exactly",
    );
    refused(
        r#"approved("g", "h", "GET", "/") <- time($t), box("b"), epoch(3), uses_left("other", $n), $n > 0, $t <= 2030-01-01T00:00:00Z;"#,
        "predicate not allowed",
    );
    refused(r#"approved("g", "h", "GET", "/") <- time($t), box("b"), epoch(3), uses_left("g", $n), $n > 0;"#, "expiry and its uses");
    refused(
        r#"approved("g", "h", "GET", "/") <- time($t), box("b"), epoch(3), uses_left("g", $n), $n > 0, $t <= 5;"#,
        "expression not allowed",
    );
    refused(r#"other("g") <- time($t), box("b"), epoch(3), uses_left("g", $n);"#, "approved/4");
    refused(r#"check if host("a");"#, "only grant rules");
    refused(r#"approved("g", "h", "GET", "/");"#, "fact not allowed");
    refused(
        r#"approval("g", "a", hex:00); approval("g", "a", hex:00); approval("g", "a", hex:01); approval("g", "a", hex:02); approval("g", "a", hex:03);"#,
        "too many",
    );
}

/// The heaviest kind of request a token can cost that passes the structural check: as many appended
/// blocks at the regex cap as the byte cap allows, on a request with a 4 KB path (the compiled
/// evaluator charges `.matches()` by input length). It is cut off by the step budget and decided
/// `Forbidden`, in both engines.
#[test]
fn the_step_budget_bounds_what_passes() {
    let keys = Keys::new(1);
    let mut cs = ceilings(0, &keys);
    cs[0].reach.push(common::r("h.example", &["GET"], &["/**"], false));
    let mut t = mint_chain(&cs, &keys);
    let alts = vec![r#"path($p), $p.matches("^/a.*b.*c.*d$")"#; 60].join(" or ");
    let block = format!("check if {alts};\ncheck if {alts};");
    loop {
        let next = append_raw(&t, &block);
        if next.block_count() > 16 || next.to_bytes().unwrap().len() > Policy::default().max_token_bytes {
            break;
        }
        t = next;
    }
    let l = load_ok(&t, &keys);
    assert!(l.is_compiled());
    let mut r = base_request(0);
    r.action = Action::Http {
        host: "h.example".into(),
        method: "GET".into(),
        path: format!("/{}", "x".repeat(4000)),
        risk: wicket_core::RiskClass::R1ReadScoped,
        inject: None,
    };
    let start = Instant::now();
    let d = l.decide(&r);
    let took = start.elapsed();
    assert!(matches!(&d, Decision::Forbidden(why) if why.contains("evaluation failed")), "{d:?}");
    assert!(l.last_steps() <= STEP_BUDGET + 300, "{} steps", l.last_steps());
    let (res, steps) = l.generic_session().authorize(&r);
    assert!(res.is_err() && steps <= STEP_BUDGET + 300, "generic: {res:?} after {steps} steps");
    println!("hostile token at the caps: {} bytes, decided {d:?} in {took:?} after {} steps", t.to_bytes().unwrap().len(), l.last_steps());
    // The same token on a short path decides normally (within budget).
    r.action = Action::Http {
        host: "h.example".into(),
        method: "GET".into(),
        path: "/abcd".into(),
        risk: wicket_core::RiskClass::R1ReadScoped,
        inject: None,
    };
    assert_eq!(l.decide(&r), Decision::Allow);
    assert!(l.last_steps() <= STEP_BUDGET);
}
