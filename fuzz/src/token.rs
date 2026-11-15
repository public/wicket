//! Target 3c: Biscuit box tokens, parsed and verified as a node loads them, and decided.
//!
//! A box holds its own token, and Biscuit lets a holder append blocks: so the fuzzer appends
//! blocks to a real chain (the depth-2 chain of wicket-authz's tests, plus a spawn block that trusts
//! a third-party key the fuzzer holds, as `tests/hostile.rs` does). The input is sections separated
//! by `\n%%\n`: `A<datalog>` appends a first-party block, `T<datalog>` a third-party block signed by
//! the trusted key. An input starting with `B` is instead raw token bytes, loaded against the root.
//!
//! The oracle: no panic; and a token that loads decides every probe the same in the compiled
//! evaluator and in the fork's generic engine, except where the generic engine runs out of steps
//! (it then refuses: fail closed, and what the compiled evaluator exists for, #183).

#[path = "../../crates/wicket-authz/tests/common/mod.rs"]
#[allow(dead_code, unused_imports, clippy::all)]
mod common;

use biscuit_auth::{BlockBuilder, PrivateKey};
use common::*;
use std::sync::OnceLock;
use wicket_authz::*;

struct Chain {
    keys: Keys,
    token: Token,
    evil: PrivateKey,
}

fn chain() -> &'static Chain {
    static C: OnceLock<Chain> = OnceLock::new();
    C.get_or_init(|| {
        let keys = Keys::new(5);
        let cs = ceilings(2, &keys);
        let t = mint_chain(&cs, &keys);
        let evil = PrivateKey::from_bytes(&[42; 32], biscuit_auth::Algorithm::Ed25519).expect("key");
        let evil_pub = PublicKey(evil.public().to_bytes().try_into().expect("32 bytes"));
        let mut c = level(3, vec![evil_pub]);
        c.box_prefix = box_id(2);
        let token = t.attenuate(&c).expect("attenuate");
        Chain { keys, token, evil }
    })
}

fn probes() -> Vec<Request> {
    let mut v: Vec<Request> = scenarios(3).into_iter().chain(scenarios(2)).map(|(_, r)| r).collect();
    for (m, h, p) in [("GET", "h", "/"), ("POST", "api.github.com", "/repos/acme/api/issues"), ("DELETE", "api.github.com", "/")] {
        let o = op("z", m, h, p);
        v.push(http_request(&box_id(3), &o));
    }
    v
}

pub fn run(data: &[u8]) {
    let c = chain();
    let root = c.keys.root.public();
    if let Some(raw) = data.strip_prefix(b"B") {
        if let Ok(l) = load(raw, &root, &never_revoked) {
            differential(&l);
        }
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else { return };
    let mut b = c.token.biscuit().clone();
    for section in text.split("\n%%\n") {
        let next = if let Some(code) = section.strip_prefix('A') {
            BlockBuilder::new().code(code).ok().and_then(|blk| b.append(blk).ok())
        } else if let Some(code) = section.strip_prefix('T') {
            (|| {
                let blk = BlockBuilder::new().code(code).ok()?;
                let req = b.third_party_request().ok()?;
                let tp = req.create_block(&c.evil, blk).ok()?;
                b.append_third_party(c.evil.public(), tp).ok()
            })()
        } else {
            None
        };
        match next {
            Some(n) => b = n,
            None => return,
        }
    }
    let Ok(bytes) = Token::from_biscuit(b).to_bytes() else { return };
    if let Ok(l) = load(&bytes, &root, &never_revoked) {
        differential(&l);
    }
}

fn differential(l: &Loaded) {
    for r in probes() {
        let compiled = l.decide(&r);
        let (res, _steps) = l.authorize_generic(&r);
        let generic = l.classify(res);
        let out_of_steps = matches!(&generic, Decision::Forbidden(why) if why.contains("evaluation failed"));
        if out_of_steps {
            continue;
        }
        assert_eq!(kind_of(&compiled), kind_of(&generic), "compiled {compiled:?}, generic {generic:?}, on {r:?}");
    }
}
