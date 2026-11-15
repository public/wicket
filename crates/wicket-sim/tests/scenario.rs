//! The simulated scenario (#324): a control host, one node and two box stubs, with faults from a
//! seed, checked against #321's invariants.
//!
//! - `seeds`: a fixed set of seeds, or `WICKET_SIM_SEEDS=<n>` seeds from `WICKET_SIM_FROM`
//!   (default 0): CI runs the fixed set on pull requests and more nightly (`ci/sim.sh`).
//! - `replay`: one seed, `WICKET_SIM_SEED=<seed>`, with its plan and whole trace printed: what a
//!   failing seed's report says to run.
//! - `deterministic`: one seed, run twice, gives the same trace.
//! - `without_the_spend_journal_a_crashed_node_overspends`: the bug this found, still found.

use std::path::PathBuf;
use wicket_sim::trace::{replay_command, SCENARIOS};
use wicket_sim::Options;

/// The seeds every pull request runs.
const FIXED: [u64; 8] = [1, 2, 3, 5, 8, 13, 21, 34];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wicket-sim")
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// The scenarios a run covers: all of them, or `WICKET_SIM_SCENARIO`'s.
fn scenarios() -> Vec<&'static str> {
    match std::env::var("WICKET_SIM_SCENARIO") {
        Ok(s) => vec![SCENARIOS.iter().copied().find(|x| *x == s).unwrap_or_else(|| panic!("no scenario {s:?}: one of {SCENARIOS:?}"))],
        Err(_) => SCENARIOS.to_vec(),
    }
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
    for scenario in scenarios() {
        for &seed in &seeds {
            let r = wicket_sim::run_scenario(scenario, seed, &dir(), false);
            println!("seed {seed}: {scenario}: hash {:016x}{}; {}", r.hash, if r.ok() { "" } else { " FAILED" }, r.stats);
            if !r.ok() {
                eprintln!("{r}");
                failed.push(replay_command(scenario, seed));
            }
        }
    }
    assert!(
        failed.is_empty(),
        "{} seed(s) broke an invariant:\n{}",
        failed.len(),
        failed.iter().map(|c| format!("  {c}")).collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn replay() {
    let Some(seed) = env_u64("WICKET_SIM_SEED") else {
        return;
    };
    let mut ok = true;
    for scenario in scenarios() {
        let r = wicket_sim::run_scenario(scenario, seed, &dir(), true);
        for line in &r.trace {
            println!("{line}");
        }
        println!("{r}");
        ok &= r.ok();
    }
    assert!(ok, "seed {seed} broke an invariant");
}

#[test]
fn deterministic() {
    for scenario in scenarios() {
        let a = wicket_sim::run_scenario(scenario, 7, &dir().join("a"), true);
        let b = wicket_sim::run_scenario(scenario, 7, &dir().join("b"), true);
        if a.hash != b.hash {
            let at = a.trace.iter().zip(&b.trace).position(|(x, y)| x != y).unwrap_or(a.trace.len().min(b.trace.len()));
            panic!("{scenario}: seed 7 ran differently twice, from trace line {at}:\n  {:?}\n  {:?}", a.trace.get(at), b.trace.get(at));
        }
    }
    let a = wicket_sim::run_with(7, &dir().join("a"), Options { keep_trace: true, ..Options::default() });
    assert!(a.stats.allowed_grant > 0 && a.stats.model_ok > 0, "the scenario exercised grants and the budget: {:?}", a.stats);
}

/// What the simulation found first (#324): a node whose spend file was written only once a second,
/// with calls in flight not counted, restarted counting from less than its upstream had billed,
/// and spent past the run's budget. Seed 8 crashes the node mid-call: without the journal it
/// overspends; with it (the `seeds` test), it doesn't.
#[test]
fn without_the_spend_journal_a_crashed_node_overspends() {
    let r = wicket_sim::run_with(8, &dir().join("no-journal"), Options { spend_journal: false, ..Options::default() });
    assert!(
        r.violations.iter().any(|v| v.contains("output tokens billed, budget")),
        "seed 8 without the journal no longer overspends: {r}"
    );
    assert!(r.violations.iter().all(|v| v.contains("billed, budget")), "and breaks nothing else: {r}");
}
