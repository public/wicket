//! The simulated scenario (#324): a control host, one node and two box stubs, with faults from a
//! seed, checked against #321's invariants.
//!
//! - `seeds`: a fixed set of seeds, or `WICKET_SIM_SEEDS=<n>` seeds from `WICKET_SIM_FROM`
//!   (default 0): CI runs the fixed set on pull requests and more nightly (`ci/sim.sh`).
//! - `replay`: one seed, `WICKET_SIM_SEED=<seed>`, with its plan and whole trace printed: what a
//!   failing seed's report says to run.
//! - `deterministic`: one seed, run twice, gives the same trace.

use std::path::PathBuf;

/// The seeds every pull request runs.
const FIXED: [u64; 8] = [1, 2, 3, 5, 8, 13, 21, 34];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wicket-sim")
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

#[test]
fn seeds() {
    let seeds: Vec<u64> = match env_u64("WICKET_SIM_SEEDS") {
        Some(n) => {
            let from = env_u64("WICKET_SIM_FROM").unwrap_or(0);
            (from..from + n).collect()
        }
        None => FIXED.to_vec(),
    };
    let mut failed = vec![];
    for seed in seeds {
        let r = wicket_sim::run(seed, &dir());
        println!(
            "seed {seed}: {} faults, {} grant actions, {} decisions, {} model calls, hash {:016x}{}",
            r.plan.faults.len(),
            r.stats.grant_actions,
            r.stats.allowed_reach + r.stats.allowed_grant + r.stats.needs_grant + r.stats.forbidden + r.stats.refused,
            r.stats.model_ok + r.stats.model_refused,
            r.hash,
            if r.ok() { "" } else { " FAILED" }
        );
        if !r.ok() {
            eprintln!("{r}");
            failed.push(seed);
        }
    }
    assert!(
        failed.is_empty(),
        "{} seed(s) broke an invariant:\n{}",
        failed.len(),
        failed.iter().map(|s| format!("  {}", wicket_sim::replay_command(*s))).collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn replay() {
    let Some(seed) = env_u64("WICKET_SIM_SEED") else {
        return;
    };
    let r = wicket_sim::run_with(seed, &dir(), true);
    for line in &r.trace {
        println!("{line}");
    }
    println!("{r}");
    assert!(r.ok(), "seed {seed} broke an invariant");
}

#[test]
fn deterministic() {
    let a = wicket_sim::run_with(7, &dir().join("a"), true);
    let b = wicket_sim::run_with(7, &dir().join("b"), true);
    if a.hash != b.hash {
        let at = a.trace.iter().zip(&b.trace).position(|(x, y)| x != y).unwrap_or(a.trace.len().min(b.trace.len()));
        panic!("seed 7 ran differently twice, from trace line {at}:\n  {:?}\n  {:?}", a.trace.get(at), b.trace.get(at));
    }
    assert!(a.stats.allowed_grant > 0 && a.stats.model_ok > 0, "the scenario exercised grants and the budget: {:?}", a.stats);
}
