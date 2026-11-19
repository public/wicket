//! The simulated scenarios (#324), each with faults from a seed, checked against #321's invariants:
//! `feed` (the first slice: a control host, one node and two box stubs; grants and model budgets),
//! `placement` (placed nodes' leases, the reconciler, the money limit and release, several runs
//! on one node), `messages` (principals, held messages, wake and receipts) and `update` (an
//! install's restart and a self update's re-exec under long-lived runs).
//!
//! - `seeds_<scenario>_<part>`: each scenario for a fixed set of seeds, in parts, or
//!   `WICKET_SIM_SEEDS=<n>` seeds from
//!   `WICKET_SIM_FROM` (default 0): CI runs the fixed set on pull requests and more nightly
//!   (`ci/sim.sh`). `WICKET_SIM_SCENARIO=<name>` runs one scenario only.
//! - `replay`: one seed, `WICKET_SIM_SEED=<seed>` (and `WICKET_SIM_SCENARIO`), with its plan and
//!   whole trace printed: what a failing seed's report says to run.
//! - `deterministic`: seed 7 of each scenario, run twice, gives the same trace.
//! - `without_…` and `a_relayed_message_…`: what the simulation found, still found with its fix
//!   turned off (or, for the known relay loss, not yet fixed).
//! - `published_with_not_after_at_expires_at_a_node_allows_past_the_grants_lifetime`: #342's
//!   expiry boundary, held by the strict oracle.
//! - `a_node_that_decided_hosts_its_ca_cannot_cover_would_honour_their_grants`: #257's slice 3,
//!   no forwarded egress: such a host is spliced or refused, never decided.

use std::path::PathBuf;
use wicket_sim::trace::{replay_command, SCENARIOS};
use wicket_sim::Options;

/// The seeds every pull request runs.
const FIXED: [u64; 11] = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144];

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

/// The `seeds` tests, one per scenario and part: part `p` of `n` runs every `n`th seed from the
/// `p`th, so a scenario's parts together run its seeds once, and nextest runs them at once (one
/// test of them all was the pull requests' slowest, #460). The slower a scenario, the more parts.
macro_rules! seeds {
    ($($name:ident: $scenario:literal, $part:literal of $parts:literal;)*) => {
        $(#[test]
        fn $name() {
            seeds($scenario, $part, $parts);
        })*
        /// The tests above cover every scenario, each part of it once.
        #[test]
        fn seeds_cover_every_scenario_and_part() {
            let mut have: Vec<(&str, usize, usize)> = vec![$(($scenario, $part, $parts)),*];
            have.sort();
            for s in SCENARIOS {
                let parts: Vec<_> = have.iter().filter(|h| h.0 == s).collect();
                assert!(!parts.is_empty(), "no seeds test for {s}");
                let n = parts[0].2;
                assert_eq!(parts.iter().map(|h| (h.1, h.2)).collect::<Vec<_>>(), (0..n).map(|p| (p, n)).collect::<Vec<_>>(), "{s}");
            }
            assert!(have.iter().all(|h| SCENARIOS.contains(&h.0)));
        }
    };
}

seeds! {
    seeds_feed_0: "feed", 0 of 3;
    seeds_feed_1: "feed", 1 of 3;
    seeds_feed_2: "feed", 2 of 3;
    seeds_placement_0: "placement", 0 of 6;
    seeds_placement_1: "placement", 1 of 6;
    seeds_placement_2: "placement", 2 of 6;
    seeds_placement_3: "placement", 3 of 6;
    seeds_placement_4: "placement", 4 of 6;
    seeds_placement_5: "placement", 5 of 6;
    seeds_messages_0: "messages", 0 of 11;
    seeds_messages_1: "messages", 1 of 11;
    seeds_messages_2: "messages", 2 of 11;
    seeds_messages_3: "messages", 3 of 11;
    seeds_messages_4: "messages", 4 of 11;
    seeds_messages_5: "messages", 5 of 11;
    seeds_messages_6: "messages", 6 of 11;
    seeds_messages_7: "messages", 7 of 11;
    seeds_messages_8: "messages", 8 of 11;
    seeds_messages_9: "messages", 9 of 11;
    seeds_messages_10: "messages", 10 of 11;
    seeds_update_0: "update", 0 of 1;
}

/// Part `part` of `parts` of `scenario`'s seeds (none when `WICKET_SIM_SCENARIO` names another
/// scenario).
fn seeds(scenario: &'static str, part: usize, parts: usize) {
    if !scenarios().contains(&scenario) {
        return;
    }
    let seeds: Vec<u64> = match env_u64("WICKET_SIM_SEEDS") {
        Some(n) => {
            let from = env_u64("WICKET_SIM_FROM").unwrap_or(0);
            (from..from + n).collect()
        }
        None => FIXED.to_vec(),
    };
    let mut failed = vec![];
    // Each scenario names its seeds' directories (`seed-<n>`, `placement-<n>`, `messages-<n>`), so
    // the parts share this one.
    for &seed in seeds.iter().skip(part).step_by(parts) {
        let r = wicket_sim::run_scenario(scenario, seed, &dir().join("seeds"), false);
        println!("seed {seed}: {scenario}: hash {:016x}{}; {}", r.hash, if r.ok() { "" } else { " FAILED" }, r.stats);
        for k in &r.known {
            println!("  KNOWN {k}");
        }
        if !r.ok() {
            eprintln!("{r}");
            failed.push(replay_command(scenario, seed));
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
        let r = wicket_sim::run_scenario(scenario, seed, &dir().join("replay"), true);
        for line in &r.trace {
            println!("{line}");
        }
        println!("{r}");
        ok &= r.ok();
    }
    assert!(ok, "seed {seed} broke an invariant");
}

/// Seed 7 of `scenario`, run twice, gives the same trace (none when `WICKET_SIM_SCENARIO` names
/// another scenario). One test per scenario, so nextest runs them at once (#460's reason).
fn deterministic(scenario: &'static str) {
    if !scenarios().contains(&scenario) {
        return;
    }
    // The two runs at once, each on a thread of its own: nothing is shared between them, so a
    // difference is the scenario's own (and one test of them in turn was a slow one).
    let (a, b) = std::thread::scope(|s| {
        let b = s.spawn(|| wicket_sim::run_scenario(scenario, 7, &dir().join("b"), true));
        let a = wicket_sim::run_scenario(scenario, 7, &dir().join("a"), true);
        (a, b.join().expect("the second run"))
    });
    if a.hash != b.hash {
        let at = a.trace.iter().zip(&b.trace).position(|(x, y)| x != y).unwrap_or(a.trace.len().min(b.trace.len()));
        panic!("{scenario}: seed 7 ran differently twice, from trace line {at}:\n  {:?}\n  {:?}", a.trace.get(at), b.trace.get(at));
    }
}

#[test]
fn deterministic_feed() {
    deterministic("feed");
    let a = wicket_sim::run_with(7, &dir().join("stats"), Options { keep_trace: true, ..Options::default() });
    assert!(a.stats.allowed_grant > 0 && a.stats.model_ok > 0, "the scenario exercised grants and the budget: {:?}", a.stats);
}

#[test]
fn deterministic_placement() {
    deterministic("placement");
}

#[test]
fn deterministic_messages() {
    deterministic("messages");
}

#[test]
fn deterministic_update() {
    deterministic("update");
}

/// The `deterministic_*` tests cover every scenario.
#[test]
fn deterministic_covers_every_scenario() {
    assert_eq!(SCENARIOS, ["feed", "placement", "messages", "update"], "add a deterministic_<scenario> test for each new scenario");
}

/// The update scenario's bugs (#475, #487, #529), each found again with its fix turned off: the
/// seed breaks the invariant the fix protects, and nothing else.
fn update_without(seed: u64, options: wicket_sim::update::Options, expect: &str) {
    let r = wicket_sim::update::run(seed, &dir().join("update-without"), options);
    assert!(!r.ok() && r.violations.iter().all(|v| v.contains(expect)), "update seed {seed}: expected only {expect:?}: {r}");
}

/// #475: without the expand rule, and with an install leaving supervisors on the old build (no
/// #477 handover), an old supervisor takes the new build's prompts as something else and drops them.
#[test]
fn without_the_expand_rule_and_the_handover_an_old_supervisor_drops_prompts() {
    let o = wicket_sim::update::Options { expand_safe: false, hand_over_on_start: false, ..Default::default() };
    update_without(0, o, "an old build's supervisor dropped a new-schema prompt");
}

/// #487: a SIGHUP drain that never returns leaves the daemon refusing every command.
#[test]
fn without_a_drain_that_returns_the_cli_is_never_answered() {
    let o = wicket_sim::update::Options { drain_returns: false, ..Default::default() };
    update_without(1, o, "the CLI got no answer within");
}

/// #529: an install's restarted wicketd hands the local run over while the local serve is still the
/// old build, and the new supervisor's re-attach loses the box.
#[test]
fn without_the_serve_moved_first_an_install_stops_the_local_box() {
    let o = wicket_sim::update::Options { serve_first_on_start: false, ..Default::default() };
    update_without(0, o, "re-attached to the local node's serve on the old build");
}

/// #529, in a self update: the old order (stop the supervisors, then re-exec the serve) lets the
/// reconciler service re-attach in between. A race: seed 19 is one of 8 of seeds 0-199.
#[test]
fn without_the_serve_moved_first_a_self_update_can_stop_the_local_box() {
    let o = wicket_sim::update::Options { serve_first_on_update: false, ..Default::default() };
    update_without(19, o, "re-attached to the local node's serve on the old build");
}

/// #529: without `KillMode=process` on the reconciler unit, install.sh's restart of it SIGTERMs
/// the supervisors its passes started, and each ends its box.
#[test]
fn without_killmode_process_the_reconcilers_restart_stops_boxes() {
    let o = wicket_sim::update::Options { reconcile_keeps_children: false, ..Default::default() };
    update_without(10, o, "SIGTERMed by the unit's restart");
}

/// What the simulation found first (#324): a node whose spend file was written only once a second,
/// with calls in flight not counted, restarted counting from less than its upstream had billed,
/// and spent past the run's budget. Seed 8 crashes the node mid-call: without the journal it
/// overspends; with it (the `seeds_*` tests), it doesn't.
#[test]
fn without_the_spend_journal_a_crashed_node_overspends() {
    let r = wicket_sim::run_with(8, &dir().join("no-journal"), Options { spend_journal: false, ..Options::default() });
    assert!(
        r.violations.iter().any(|v| v.contains("output tokens billed, budget")),
        "seed 8 without the journal no longer overspends: {r}"
    );
    assert!(r.violations.iter().all(|v| v.contains("billed, budget")), "and breaks nothing else: {r}");
}

/// What the placement scenario found (#324), each still found with its fix turned off: the seeds
/// that found them, run without the fix, break the invariant it restored. Each test has its own
/// directory (`name`): a run clears its directory first.
fn placement_without(name: &str, seed: u64, options: wicket_sim::placement::Options, expect: &str) {
    let r = wicket_sim::placement::run(seed, &dir().join(format!("without-{name}")), options);
    assert!(r.violations.iter().any(|v| v.contains(expect)), "placement seed {seed} no longer finds {expect:?}: {r}");
}

/// `wicket run --node` started boxes on a placed node past its lease, each run then holding it.
/// (Since #395 the node refuses such a start too: both halves of the lease guard are off here.)
#[test]
fn without_the_lease_check_runs_start_on_a_node_past_its_lease() {
    let o = wicket_sim::placement::Options { refuse_past_lease: false, start_by: false, ..Default::default() };
    placement_without("lease", 2, o, "past its lease");
}

/// A run whose fetch failed left its files on its node, and the reconciler released the node with them.
#[test]
fn without_the_uncollected_hold_a_node_is_released_with_a_runs_files() {
    let o = wicket_sim::placement::Options { hold_uncollected: false, ..Default::default() };
    placement_without("uncollected", 2, o, "work on it uncollected");
}

/// Trace validation (#324): the ledger check `wicket doctor --invariants` runs on real ledgers
/// finds, in the ledger the placement scenario's control host wrote, the release the oracle saw.
#[test]
fn the_ledger_check_finds_a_node_released_with_a_runs_files() {
    let o = wicket_sim::placement::Options { hold_uncollected: false, ..Default::default() };
    let r = wicket_sim::placement::run(2, &dir().join("ledger-uncollected"), o);
    assert!(r.violations.iter().any(|v| v.contains("work on it uncollected")), "the oracle: {r}");
    assert!(r.violations.iter().any(|v| v.starts_with("the ledger's trace check: collected")), "the ledger's check: {r}");
}

/// A reconciler pass listed a node `place create` had just made, before it was recorded, and
/// destroyed it as having no lease. (Seed 20 found it; since #256 an acquire no longer lists the
/// provider's nodes before it creates, which moved the race, and seed 4 is the first that finds it.)
#[test]
fn without_the_grace_the_reconciler_destroys_a_node_just_placed() {
    let o = wicket_sim::placement::Options { young_grace: false, ..Default::default() };
    placement_without("grace", 4, o, "before its lease ends");
}

/// #494, #495 (the nightly run): a run started on a placed node shortly before its lease ended,
/// and its box held the node past it (#294). The node billed hours past its worst case, nothing
/// reserved them, and the next `node create`'s spend check passed on what was reserved: owned nodes
/// were committed past the money limit's total. With the held node's billing reserved, both seeds
/// refuse that create; without it, both still break the limit.
#[test]
fn a_held_nodes_billing_counts_against_the_money_limit() {
    for seed in [32_200_164, 32_200_188] {
        let r = wicket_sim::placement::run(seed, &dir().join(format!("held-{seed}")), Default::default());
        assert!(r.ok(), "placement seed {seed}: {r}");
        assert!(
            !r.stats.contains("held: 0,") && !r.stats.contains("creates_refused: 0,"),
            "seed {seed} holds a node and refuses a create: {r}"
        );
        let o = wicket_sim::placement::Options { reserve_held: false, ..Default::default() };
        placement_without(&format!("held-{seed}"), seed, o, "over the money limit's");
    }
}

/// The known loss the messages scenario found (#324, see `wicket_sim::messages::run`): a relayed
/// `await_message` answer lost with the node's channel after the control host recorded the message
/// read. Seed 13 still loses one; when this fails, the loss is fixed: make `strict_relay` the
/// default and drop this test.
#[test]
fn a_relayed_message_whose_answer_is_cut_off_is_still_lost() {
    let o = wicket_sim::messages::Options { strict_relay: true, ..Default::default() };
    let r = wicket_sim::messages::run(13, &dir().join("strict"), o);
    assert!(r.violations.iter().any(|v| v.contains("its receipt says read")), "seed 13 no longer loses a relayed message: {r}");
    assert!(r.violations.iter().all(|v| v.contains("its receipt says read")), "and breaks nothing else: {r}");
}

/// #342: a node honoured a grant up to 999 ms past the ledger's `expires_at` (#333's observation,
/// #337's F1): the token's check is `time <= not_after` in whole seconds, and the grant was
/// published with `not_after = expires_at`. The oracle is strict (live while `now < expires_at`,
/// in ms): published as before, seed 1 allows by a grant past its lifetime; published with
/// `expires_at - 1` (the `seeds_*` tests), no seed does.
#[test]
fn published_with_not_after_at_expires_at_a_node_allows_past_the_grants_lifetime() {
    let r = wicket_sim::run_with(1, &dir().join("grant-end"), Options { grant_end_fix: false, ..Options::default() });
    assert!(r.violations.iter().any(|v| v.contains("past its lifetime")), "seed 1 no longer allows past a grant's end: {r}");
    assert!(r.violations.iter().all(|v| v.contains("past its lifetime")), "and breaks nothing else: {r}");
}

/// #257, slice 3: the control host publishes every grant, one on a host the node's CA can't cover
/// included, and decides nothing; the node splices such a host if the box's token allows it
/// wholesale and refuses it otherwise. The `seeds_*` tests check that no such host is allowed but
/// spliced. A node that decided those hosts from the feed instead (as if it could terminate them)
/// would honour the published grant: the oracle finds it.
#[test]
fn a_node_that_decided_hosts_its_ca_cannot_cover_would_honour_their_grants() {
    let r = wicket_sim::run_with(1, &dir().join("uncovered"), Options { refuse_uncovered: false, ..Options::default() });
    assert!(r.violations.iter().any(|v| v.contains("outside the node's CA, and was decided")), "seed 1 no longer shows it: {r}");
    assert!(r.violations.iter().all(|v| v.contains("outside the node's CA")), "and breaks nothing else: {r}");
    let ok = wicket_sim::run(1, &dir().join("uncovered-ok"));
    assert!(ok.ok() && ok.stats.spliced > 0 && ok.stats.uncovered_refused > 0, "both ways exercised: {:?}", ok.stats);
}

/// The placement seeds the nightly run filed (#395–#399), each its own regression test through
/// [`nightly_placement_seed`]: they hold with the fixes.
fn nightly_placement_seed(seed: u64) {
    let r = wicket_sim::placement::run(seed, &dir().join(format!("nightly-{seed}")), Default::default());
    assert!(r.ok(), "placement seed {seed} breaks an invariant again: {r}");
}

/// #395: a run's box started on its node 3 s past the node's lease (checked when the run began).
#[test]
fn placement_seed_32000006_starts_no_box_past_a_lease() {
    nightly_placement_seed(32_000_006);
}

/// #396: the same race, around control-host crashes.
#[test]
fn placement_seed_32000129_starts_no_box_past_a_lease() {
    nightly_placement_seed(32_000_129);
}

/// #397: a node billed past its lease with nothing on it: the stand-in node still answered for a
/// box its supervisor had fetched and forgotten, so the supervisor re-attached after a control-host
/// crash fetched again, failed, and held the node for files that were gone.
#[test]
fn placement_seed_32000134_releases_a_node_whose_work_was_collected() {
    nightly_placement_seed(32_000_134);
}

/// #398: the start race on a partitioned node.
#[test]
fn placement_seed_32000183_starts_no_box_past_a_lease() {
    nightly_placement_seed(32_000_183);
}

/// #399: as #397, with the crash between the fetch and the run's end.
#[test]
fn placement_seed_32000274_releases_a_node_whose_work_was_collected() {
    nightly_placement_seed(32_000_274);
}

/// #395: with only the check when the run begins (no `BoxStart::start_by`), the start races it and
/// a box starts on a node past its lease.
#[test]
fn without_the_start_by_a_box_starts_past_its_nodes_lease() {
    let o = wicket_sim::placement::Options { start_by: false, ..Default::default() };
    placement_without("start-by", 32_000_006, o, "started on node");
}

/// Found by the fresh-seed sweep after #395–#399: a run's statement, signed before another run's
/// and delivered late, named an epoch older than the history its node held (the node had been
/// caught up from a later snapshot) and was refused as a rollback. It is superseded.
#[test]
fn placement_seed_50002077_takes_a_late_statement_as_superseded() {
    nightly_placement_seed(50_002_077);
}
