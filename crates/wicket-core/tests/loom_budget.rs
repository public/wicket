//! The run's budget counter under every interleaving (#325): loom runs each model below in every
//! order its threads' atomic operations can take, and checks the budget in each. Built only with
//! `--cfg loom`:
//!
//!   RUSTFLAGS="--cfg loom" cargo test -p wicket-core --test loom_budget --release
//!
//! (ci/kani.sh runs it after the Kani harnesses). The threads are what share a run's counter: its
//! node's `Spent` reports (merged as they arrive, `noderun`), the slice leased to the node
//! (`slice_due`), its model calls (admitted, and reserving output) and its spawns' carve-outs.
#![cfg(loom)]

use loom::sync::atomic::Ordering::SeqCst;
use loom::sync::Arc;
use loom::thread;
use wicket_core::budget::{Counter, ModelQuota, Spent};

const Q: ModelQuota = ModelQuota { requests: 10, output_tokens: 100, input_tokens: None };

fn counter(requests: u64, output_tokens: u64) -> Arc<Counter> {
    let c = Counter::default();
    c.requests.store(requests, SeqCst);
    c.output_tokens.store(output_tokens, SeqCst);
    Arc::new(c)
}

/// Two node reports, the later one first, merged while a slice is leased: the counts end at the
/// larger report (none lowers them), and the slice never leases more than the budget. Before #325
/// `next_slice` read `requests` twice; a report merged in between leased 8 + 3 = 11 of 10.
#[test]
fn merged_reports_and_a_lease_stay_within_the_budget() {
    loom::model(|| {
        let c = counter(6, 40);
        let reports =
            [Spent { requests: 8, output_tokens: 70, ..Spent::default() }, Spent { requests: 7, output_tokens: 50, ..Spent::default() }];
        let merges: Vec<_> = reports
            .into_iter()
            .map(|s| {
                let c = c.clone();
                thread::spawn(move || c.merge_spent(s))
            })
            .collect();
        let slice = c.next_slice(Q, 0.25);
        for m in merges {
            m.join().unwrap();
        }
        assert_eq!((c.requests.load(SeqCst), c.output_tokens.load(SeqCst)), (8, 70), "the larger report wins");
        assert!(slice.requests <= Q.requests && slice.output_tokens <= Q.output_tokens, "{slice:?}");
    });
}

/// A model request and a spawn's carve-out racing for the last of the request budget: they can't
/// both have it.
#[test]
fn a_request_and_a_carve_out_cant_both_take_the_last_of_the_budget() {
    loom::model(|| {
        let c = counter(7, 0);
        let child = ModelQuota { requests: 3, ..ModelQuota::default() };
        let spawn = {
            let c = c.clone();
            thread::spawn(move || c.carve(Q, child).is_ok())
        };
        let admitted = c.admit_request() <= Q.requests;
        let carved = spawn.join().unwrap();
        assert!(!(admitted && carved), "7 + 1 + 3 of 10");
        if carved {
            // The carve-out holds: what the run's own call counted doesn't eat into it.
            assert_eq!(c.reserved_requests.load(SeqCst), 3);
        }
    });
}

/// The same race with the check and the carve-out apart, as `spawn` made them before #325
/// (`subset::check` against `remaining()`, then `fetch_add`): loom finds the order in which both
/// take the last of the budget.
#[test]
#[should_panic(expected = "both took the last of it")]
fn checking_then_carving_loses_the_race() {
    loom::model(|| {
        let c = counter(7, 0);
        let spawn = {
            let c = c.clone();
            thread::spawn(move || {
                let fits = c.counts().remaining(Q).0 >= 3;
                if fits {
                    c.reserved_requests.fetch_add(3, SeqCst);
                }
                fits
            })
        };
        let admitted = c.admit_request() <= Q.requests;
        let carved = spawn.join().unwrap();
        assert!(!(admitted && carved), "both took the last of it");
    });
}

/// A model call reserving output and a carve-out of output tokens: whatever the order, what is
/// committed stays within the budget (the call takes less, or nothing, if the child got there
/// first).
#[test]
fn an_output_reservation_and_a_carve_out_stay_within_the_budget() {
    loom::model(|| {
        let c = counter(0, 60);
        let child = ModelQuota { output_tokens: 30, ..ModelQuota::default() };
        let spawn = {
            let c = c.clone();
            thread::spawn(move || c.carve(Q, child).is_ok())
        };
        let took = c.reserve_output(Q.output_tokens, 30).unwrap_or(0);
        let carved = spawn.join().unwrap();
        assert!(60 + took + if carved { 30 } else { 0 } <= Q.output_tokens, "took {took}, carved {carved}");
        assert!(c.counts().output_committed() <= Q.output_tokens);
    });
}

/// Two children carved at once from what is left: they never add up to more than it.
#[test]
fn two_carve_outs_never_exceed_the_parent() {
    loom::model(|| {
        let c = counter(4, 0);
        let child = ModelQuota { requests: 4, ..ModelQuota::default() };
        let other = {
            let c = c.clone();
            thread::spawn(move || c.carve(Q, child).is_ok())
        };
        let mine = c.carve(Q, child).is_ok();
        let theirs = other.join().unwrap();
        assert!(!(mine && theirs), "4 + 4 + 4 of 10");
        assert!(c.counts().requests_committed() <= Q.requests);
    });
}
