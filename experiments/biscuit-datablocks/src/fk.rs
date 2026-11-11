//! The fork side: tokens minted by stock 6.0.0 (bisc.rs, unchanged from biscuit-depth) are serialized
//! and loaded into the fork, which then decides the same requests through each step's API.

use crate::model::*;
use fork::builder::{date, fact, int, string, Fact};
use fork::{AuthorizerBuilder, AuthorizerLimits, Biscuit, CompiledAuthorizer, PreparedAuthorizer, PreparedLimits, PreparedSession};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Which decision path to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    /// crates.io biscuit-auth 6.0.0, build per request (biscuit-depth's method)
    Stock,
    /// the fork's base (upstream main) through the stock API: build per request
    Main,
    /// step 1: token loaded once, per-request overlay, upstream limits (wall clock kept)
    Prepared,
    /// step 2: as step 1, fuel only (no wall clock), regex charged by length
    Fuel,
    /// step 3: compiled world, shared between threads
    Compiled,
}

impl Engine {
    pub const ALL: [Engine; 5] = [Engine::Stock, Engine::Main, Engine::Prepared, Engine::Fuel, Engine::Compiled];
    pub fn name(self) -> &'static str {
        match self {
            Engine::Stock => "stock 6.0.0",
            Engine::Main => "upstream main",
            Engine::Prepared => "step 1 prepared",
            Engine::Fuel => "step 2 fuel",
            Engine::Compiled => "step 3 compiled",
        }
    }
    pub fn parse(s: &str) -> Option<Engine> {
        Some(match s {
            "stock" => Engine::Stock,
            "main" => Engine::Main,
            "s1" | "prepared" => Engine::Prepared,
            "s2" | "fuel" => Engine::Fuel,
            "s3" | "compiled" => Engine::Compiled,
            _ => return None,
        })
    }
}

/// Same as bisc::generous(): 1000 facts, 100 iterations, 50 ms; steps effectively unlimited, as in 6.0.0.
pub fn generous() -> AuthorizerLimits {
    AuthorizerLimits { max_facts: 1000, max_iterations: 100, max_time: Duration::from_millis(50), max_steps: 10_000_000 }
}

pub fn wall() -> PreparedLimits {
    PreparedLimits { max_facts: 1000, max_iterations: 100, max_steps: 10_000_000, max_time: Some(Duration::from_millis(50)) }
}

/// The deterministic limits recommended for wicket (see RESULTS.md §4 for how they were chosen).
pub const FUEL_STEPS: u64 = 4000;
pub fn fuel() -> PreparedLimits {
    PreparedLimits { max_facts: 256, max_iterations: 8, max_steps: FUEL_STEPS, max_time: None }
}

pub fn limits_for(e: Engine) -> PreparedLimits {
    match e {
        Engine::Prepared => wall(),
        _ => fuel(),
    }
}

pub fn root_pk(stock: &biscuit_auth::PublicKey) -> fork::PublicKey {
    fork::PublicKey::from_bytes(&stock.to_bytes(), fork::Algorithm::Ed25519).expect("root key")
}

pub fn load(tok: &biscuit_auth::Biscuit, root: &biscuit_auth::PublicKey) -> Biscuit {
    Biscuit::from(tok.to_vec().unwrap(), root_pk(root)).expect("fork parses a stock token")
}

pub fn base_builder() -> AuthorizerBuilder {
    AuthorizerBuilder::new()
        .code("check if tenant($t), request_tenant($t);\nallow if true;")
        .expect("authorizer code")
        .set_limits(generous())
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// bisc::request_facts, built with the fork's builder types.
pub fn request_facts(r: &Request) -> Vec<Fact> {
    let mut f = vec![
        fact("time", &[date(&t(r.time))]),
        fact("request_tenant", &[string(&r.tenant)]),
        fact("node", &[string(&r.node)]),
        fact("box", &[string(&r.box_id)]),
        fact("epoch", &[int(r.epoch)]),
        fact("op", &[string(r.op.kind())]),
    ];
    match &r.op {
        Op::Http { host, method, path, risk, inject } => {
            f.push(fact("host", &[string(host)]));
            f.push(fact("method", &[string(method)]));
            f.push(fact("path", &[string(path)]));
            f.push(fact("path_depth", &[int(path_depth(path))]));
            f.push(fact("risk", &[int(*risk)]));
            if let Some(k) = inject {
                f.push(fact("inject", &[string(k)]));
            }
        }
        Op::Spawn { image, isolation, mem, cpus, pids, secs } => {
            f.push(fact("spawn", &[string(image), int(*isolation), int(*mem), int(*cpus), int(*pids), int(*secs)]));
        }
        Op::Llm { used_requests, used_tokens } => f.push(fact("llm_used", &[int(*used_requests), int(*used_tokens)])),
        Op::Msg { from } => f.push(fact("msg_from", &[string(from)])),
    }
    for (g, n) in &r.uses_left {
        f.push(fact("uses_left", &[string(g), int(*n)]));
    }
    f
}

/// Per-request build through the stock API (the fork's upstream-main base).
pub fn authorize_main(base: &AuthorizerBuilder, token: &Biscuit, facts: &[Fact]) -> Result<usize, fork::error::Token> {
    let mut b = base.clone();
    for f in facts {
        b = b.fact(f.clone())?;
    }
    b.build(token)?.authorize()
}

pub fn prepare(token: &Biscuit, limits: &PreparedLimits) -> PreparedAuthorizer {
    base_builder().prepare(token, limits).expect("prepare")
}

/// A token loaded for one engine; `decide` runs one request.
pub enum Loaded {
    Stock(biscuit_auth::Biscuit),
    Main(Biscuit),
    Session(PreparedSession, PreparedLimits),
    Compiled(CompiledAuthorizer, PreparedLimits),
}

pub fn load_for(e: Engine, tok: &biscuit_auth::Biscuit, root: &biscuit_auth::PublicKey) -> Loaded {
    match e {
        Engine::Stock => Loaded::Stock(tok.clone()),
        Engine::Main => Loaded::Main(load(tok, root)),
        Engine::Prepared | Engine::Fuel => {
            let l = limits_for(e);
            Loaded::Session(prepare(&load(tok, root), &l).session(), l)
        }
        Engine::Compiled => {
            let l = limits_for(e);
            Loaded::Compiled(prepare(&load(tok, root), &l).compile(), l)
        }
    }
}

impl Loaded {
    pub fn decide(&mut self, r: &Request) -> Result<(), String> {
        match self {
            Loaded::Stock(t) => {
                let o = crate::bisc::authorize(&crate::bisc::base_authorizer(crate::bisc::generous()), t, r);
                if o.ok { Ok(()) } else { Err(o.err.unwrap_or_default()) }
            }
            Loaded::Main(t) => authorize_main(&base_builder(), t, &request_facts(r)).map(|_| ()).map_err(|e| e.to_string()),
            Loaded::Session(s, l) => s.authorize(&request_facts(r), l).map(|_| ()).map_err(|e| e.to_string()),
            Loaded::Compiled(c, l) => c.authorize(&request_facts(r), l).map(|_| ()).map_err(|e| e.to_string()),
        }
    }
}
