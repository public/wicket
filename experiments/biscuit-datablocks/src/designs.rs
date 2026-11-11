//! The three designs as a node would run them: load a token once (parse, verify, structural gate,
//! compile), then decide requests.
//!
//! - A: design A's checks; gate = biscuit-fast's lint; decision = the fork's compiled evaluator (step 3).
//! - B: data-only blocks; gate = zf::extract; decision = zf::Chain::allows with wicket-core's CompiledZone.
//!   `Bm` is the same with the model's prefix matching, to separate encoding from matcher.
//! - C: A's checks plus the data facts; gate = lint (data facts admitted) + extract; decision = A,
//!   with B computed next to it and every disagreement counted (`C_MISMATCH`).

use crate::fk;
use crate::lint;
use crate::model::Request;
use crate::zf::{self, Form, Matcher};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Design {
    A,
    B,
    Bm,
    C,
    /// Design B with a deliberate evaluator bug (see `MUTANTS`), to check the property suite has teeth.
    Mut(u8),
}

/// Typical intersection bugs, simulated by transforming the loaded chain.
pub const MUTANTS: [&str; 6] = [
    "decide with the leaf's zone only",
    "skip the authority block",
    "a grant counts in a block if any block trusts its signer",
    "ignore the box binding",
    "ignore expiry",
    "a grant counts in every block (trust ignored)",
];

fn mutate(k: u8, ch: &mut zf::Chain) {
    match k {
        0 => {
            let last = ch.zones.pop().unwrap();
            ch.zones = vec![last];
        }
        1 => {
            ch.zones.remove(0);
        }
        2 => {
            let all: Vec<String> = ch.zones.iter().flat_map(|z| z.c.grant_keys.clone()).collect();
            ch.zones.iter_mut().for_each(|z| z.c.grant_keys = all.clone());
        }
        3 => ch.zones.iter_mut().for_each(|z| z.c.box_prefix = "b0".into()),
        4 => ch.zones.iter_mut().for_each(|z| z.c.not_after = u64::MAX),
        _ => {
            let signers: Vec<String> = ch.grants.iter().map(|(k, _)| k.clone()).collect();
            ch.zones.iter_mut().for_each(|z| z.c.grant_keys.extend(signers.clone()));
        }
    }
}

impl Design {
    pub const ALL: [Design; 4] = [Design::A, Design::B, Design::Bm, Design::C];
    pub fn name(self) -> &'static str {
        match self {
            Design::A => "A checks (step 3)",
            Design::B => "B data-only (CompiledZone)",
            Design::Bm => "B data-only (model matcher)",
            Design::C => "C hybrid (decide A, cross-check B)",
            Design::Mut(k) => MUTANTS[k as usize],
        }
    }
    pub fn parse(s: &str) -> Option<Design> {
        Some(match s {
            "a" | "A" => Design::A,
            "b" | "B" => Design::B,
            "bm" | "Bm" => Design::Bm,
            "c" | "C" => Design::C,
            _ => return None,
        })
    }
    /// How this design's tokens are minted.
    pub fn form(self) -> Option<Form> {
        match self {
            Design::A => None,
            Design::B | Design::Bm | Design::Mut(_) => Some(Form::Data),
            Design::C => Some(Form::Hybrid),
        }
    }
}

pub static C_MISMATCH: AtomicU64 = AtomicU64::new(0);
pub static C_DECISIONS: AtomicU64 = AtomicU64::new(0);

pub enum Loaded {
    A(fork::CompiledAuthorizer),
    B(zf::Chain, Matcher),
    C(fork::CompiledAuthorizer, zf::Chain),
}

pub fn lint_policy(d: Design) -> lint::Policy {
    lint::Policy { data_facts: d == Design::C, ..lint::Policy::default() }
}

/// Parse and verify `bytes` under `root`, then run the design's gate and compile. Any error refuses
/// the token: every request on it is denied.
pub fn load(d: Design, bytes: &[u8], root: &fork::PublicKey) -> Result<Loaded, String> {
    load_with(d, bytes, root, &zf::Caps::default())
}

pub fn load_with(d: Design, bytes: &[u8], root: &fork::PublicKey, caps: &zf::Caps) -> Result<Loaded, String> {
    // Same cap for every design, checked before parsing.
    if bytes.len() > caps.max_token_bytes {
        return Err(format!("token is {} bytes, cap {}", bytes.len(), caps.max_token_bytes));
    }
    let tok = fork::Biscuit::from(bytes, root.clone()).map_err(|e| format!("parse: {e}"))?;
    match d {
        Design::A => {
            lint::lint(&tok, bytes.len(), &lint_policy(d)).map_err(|e| format!("lint: {e}"))?;
            Ok(Loaded::A(fk::prepare(&tok, &fk::fuel()).compile()))
        }
        Design::B | Design::Bm => {
            let m = if d == Design::B { Matcher::Wicket } else { Matcher::Model };
            Ok(Loaded::B(zf::extract(&tok, bytes.len(), Form::Data, caps).map_err(|e| format!("extract: {e}"))?, m))
        }
        Design::Mut(k) => {
            let mut ch = zf::extract(&tok, bytes.len(), Form::Data, caps).map_err(|e| format!("extract: {e}"))?;
            mutate(k, &mut ch);
            Ok(Loaded::B(ch, Matcher::Wicket))
        }
        Design::C => {
            lint::lint(&tok, bytes.len(), &lint_policy(d)).map_err(|e| format!("lint: {e}"))?;
            let chain = zf::extract(&tok, bytes.len(), Form::Hybrid, caps).map_err(|e| format!("extract: {e}"))?;
            Ok(Loaded::C(fk::prepare(&tok, &fk::fuel()).compile(), chain))
        }
    }
}

impl Loaded {
    pub fn decide(&self, r: &Request) -> Result<(), String> {
        match self {
            Loaded::A(c) => c.authorize(&fk::request_facts(r), &fk::fuel()).map(|_| ()).map_err(|e| e.to_string()),
            Loaded::B(ch, m) => {
                if ch.allows(r, &zf::wicket_op(r), *m) {
                    Ok(())
                } else {
                    Err("denied by a zone block".into())
                }
            }
            Loaded::C(c, ch) => {
                let a = c.authorize(&fk::request_facts(r), &fk::fuel()).map(|_| ()).map_err(|e| e.to_string());
                let b = ch.allows(r, &zf::wicket_op(r), Matcher::Wicket);
                C_DECISIONS.fetch_add(1, Ordering::Relaxed);
                if a.is_ok() != b {
                    C_MISMATCH.fetch_add(1, Ordering::Relaxed);
                }
                a
            }
        }
    }
}
