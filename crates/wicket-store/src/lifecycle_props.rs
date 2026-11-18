//! Store-level properties of an agent's activations and its messages (#326), over seeded random
//! sequences of what supervisors, reconcilers and nodes do:
//!
//! - **RunLifecycle's `ActiveHasRun`** (#474, #478): after any sequence of start, wake, a run lost
//!   (by the reconciler, or a re-attach that failed: both [`Ledger::run_lost`]), a claim lapsing,
//!   hibernation and a supervisor's own end, no agent is `active` without a running run or a claim
//!   that hasn't lapsed.
//! - **In-flight messages** (#445, #451, #453, #454): over sends, takes (`await_message`), reads (the
//!   node says the box had it), requeues (an answer that never reached the node) and reconnects or
//!   takeovers (everything in flight given again), each take hands out the oldest waiting message,
//!   every message is read exactly once, and after a last takeover nothing is left in flight.
//!
//! A small seeded generator stands in for a property-testing crate; a failure names its seed and step.

use crate::*;

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) % n
    }
}

const SEEDS: u64 = 300;
const STEPS: usize = 50;
const AGENT: &str = "agt_prop";

/// RunLifecycle.tla's `ActiveHasRun`, on the ledger: an active agent has a running run or an
/// unlapsed claim.
fn active_has_run(l: &Ledger) -> std::result::Result<(), String> {
    let Some(a) = l.agent(AGENT).unwrap() else { return Ok(()) };
    if a.state != "active" {
        return Ok(());
    }
    let claimed = a.claim_until.is_some_and(|c| c >= now());
    let running = l.run_status(&a.run).unwrap().as_deref() == Some("running");
    if claimed || running {
        Ok(())
    } else {
        Err(format!(
            "agent active at generation {} with run {} {:?} and claim {:?}",
            a.generation,
            a.run,
            l.run_status(&a.run).unwrap(),
            a.claim_until
        ))
    }
}

/// Run `run` is lost: it ends as `lost`, and if it was the active agent's current activation the
/// agent ends with it (hibernated when it has a head, else ended), which `run_lost` returns; an
/// earlier activation's run leaves the agent as it was.
fn lose(l: &Ledger, run: &str, seed: u64, step: usize) {
    let before = l.agent(AGENT).unwrap().unwrap();
    let got = l.run_lost(run, "prop: lost").unwrap();
    let after = l.agent(AGENT).unwrap().unwrap();
    assert_eq!(l.run_status(run).unwrap().as_deref(), Some("lost"), "seed {seed} step {step}: {run} ends as lost");
    if before.state == "active" && before.run == run {
        let want = if before.head.is_some() { "hibernated" } else { "ended" };
        assert_eq!((got.as_deref(), after.state.as_str()), (Some(want), want), "seed {seed} step {step}: its agent ends with it");
        assert!(after.claim_until.is_none(), "seed {seed} step {step}: and its claim with it");
    } else {
        assert_eq!(got, None, "seed {seed} step {step}: not the active agent's activation");
        assert_eq!(after.state, before.state, "seed {seed} step {step}: the agent is left alone");
    }
}

/// #474: whatever happens to an agent's runs, an active agent always has a live run or claim.
#[test]
fn no_agent_is_active_without_a_live_run_or_claim() {
    let t = TenantId::single();
    for seed in 0..SEEDS {
        let mut rng = Rng::new(seed);
        let mut l = Ledger::open_in_memory().unwrap();
        let mut runs: Vec<String> = vec![];
        let mut seq = 0i64;
        for step in 0..STEPS {
            let a = l.agent(AGENT).unwrap();
            let start = |l: &mut Ledger, runs: &mut Vec<String>| -> String {
                let run = format!("run_{}", runs.len());
                l.run_started(&t, &RunId(run.clone()), "z", "a").unwrap();
                runs.push(run.clone());
                run
            };
            match (rng.below(7), &a) {
                // Its first activation.
                (_, None) => {
                    let run = start(&mut l, &mut runs);
                    l.create_agent(&NewAgent {
                        id: AGENT,
                        tenant: &t.0,
                        zone: "z",
                        name: "w",
                        run: &run,
                        session_id: "s",
                        manifest: "m",
                        image: "i",
                        workspace: None,
                        claim_until: now() + 30,
                    })
                    .unwrap();
                }
                // A wake: of a hibernated agent, or a takeover of a lapsed claim.
                (0, Some(_)) => {
                    let run = format!("run_{}", runs.len());
                    if let Some(g) = l.claim_wake(AGENT, &run, now() + 30).unwrap() {
                        l.run_started(&t, &RunId(run.clone()), "z", "a").unwrap();
                        runs.push(run);
                        l.set_agent_state(AGENT, g, "active", None).unwrap();
                    }
                }
                // The current activation's run is lost: by the reconciler, or a re-attach failing.
                (1, Some(a)) => lose(&l, &a.run.clone(), seed, step),
                // An earlier activation's run is lost.
                (2, Some(_)) if !runs.is_empty() => {
                    let r = runs[rng.below(runs.len() as u64) as usize].clone();
                    if l.run_status(&r).unwrap().as_deref() == Some("running") {
                        lose(&l, &r, seed, step);
                    }
                }
                // The holder's claim lapses (its supervisor stopped renewing).
                (3, Some(_)) => {
                    l.conn.execute("UPDATE agents SET claim_until = ?2 WHERE id = ?1", params![AGENT, now() - 100]).unwrap();
                }
                // The holder renews it.
                (4, Some(a)) if a.state == "active" => {
                    l.renew_agent_claim(AGENT, a.generation, now() + 30).unwrap();
                }
                // It hibernates (its push commits).
                (5, Some(a)) if a.state == "active" => {
                    if l.commit_agent_push(AGENT, a.generation, seq, seq + 1, &format!("head-{seq}"), 10).unwrap() {
                        seq += 1;
                    }
                }
                // Its supervisor ends the session: the run ends, then the agent.
                (6, Some(a)) if a.state == "active" => {
                    l.run_ended(&RunId(a.run.clone()), "ended", "session closed").unwrap();
                    l.set_agent_state(AGENT, a.generation, "ended", Some("its session closed")).unwrap();
                }
                _ => {}
            }
            if let Err(e) = active_has_run(&l) {
                panic!("seed {seed} step {step}: {e}");
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum M {
    Waiting,
    InFlight,
    Read,
}

/// #445, #451, #453, #454: every message is handed out oldest first, read exactly once, and none
/// stays in flight once a takeover has given everything back.
#[test]
fn every_message_is_read_exactly_once_and_none_stays_in_flight() {
    let t = TenantId::single();
    let run = "run_box";
    for seed in 0..SEEDS {
        let mut rng = Rng::new(seed);
        let mut l = Ledger::open_in_memory().unwrap();
        // Insertion order is the inbox order (one priority; created_at, then rowid).
        let mut model: Vec<(String, M)> = vec![];
        let mut reads: std::collections::BTreeMap<String, u32> = Default::default();
        let take = |l: &mut Ledger, model: &mut Vec<(String, M)>, ctx: &str| {
            let want = model.iter().position(|(_, m)| *m == M::Waiting);
            let got = l.take_message_in_flight(run).unwrap().map(|m| m.id);
            assert_eq!(got, want.map(|i| model[i].0.clone()), "{ctx}: the oldest waiting message");
            if let Some(i) = want {
                model[i].1 = M::InFlight;
            }
        };
        for step in 0..STEPS {
            let ctx = format!("seed {seed} step {step}");
            match rng.below(6) {
                0 | 1 => {
                    let id = format!("m-{}", model.len());
                    l.add_message(&id, &t, "run_peer", run, "e.n.v").unwrap();
                    model.push((id, M::Waiting));
                }
                2 => take(&mut l, &mut model, &ctx),
                // The node says the box had one: read, once. Also one waiting again: a takeover
                // gives back what the box may already have had (#445), and its node says so.
                3 if !model.is_empty() => {
                    let i = rng.below(model.len() as u64) as usize;
                    let ok = l.message_read(run, &model[i].0).unwrap();
                    assert_eq!(ok, model[i].1 != M::Read, "{ctx}: read of {} ({:?})", model[i].0, model[i].1);
                    if ok {
                        model[i].1 = M::Read;
                        *reads.entry(model[i].0.clone()).or_default() += 1;
                    }
                }
                // An answer that never reached the node: that one is given again.
                4 if !model.is_empty() => {
                    let i = rng.below(model.len() as u64) as usize;
                    let ok = l.requeue_message(run, &model[i].0).unwrap();
                    assert_eq!(ok, model[i].1 == M::InFlight, "{ctx}: requeue of {} ({:?})", model[i].0, model[i].1);
                    if ok {
                        model[i].1 = M::Waiting;
                    }
                }
                // A reconnect or a takeover: everything in flight is given again.
                _ => {
                    let n = l.requeue_in_flight(run).unwrap();
                    let inflight = model.iter().filter(|(_, m)| *m == M::InFlight).count();
                    assert_eq!(n, inflight, "{ctx}: everything in flight, given again");
                    for (_, m) in model.iter_mut().filter(|(_, m)| *m == M::InFlight) {
                        *m = M::Waiting;
                    }
                }
            }
            assert_eq!(l.waiting_messages(run).unwrap() as usize, model.iter().filter(|(_, m)| *m == M::Waiting).count(), "{ctx}");
        }
        // A last takeover, and the box reads everything it is given: each message once, none left.
        l.requeue_in_flight(run).unwrap();
        for (_, m) in model.iter_mut().filter(|(_, m)| *m == M::InFlight) {
            *m = M::Waiting;
        }
        while let Some(m) = l.take_message_in_flight(run).unwrap() {
            assert!(l.message_read(run, &m.id).unwrap(), "seed {seed}: {} read once", m.id);
            assert!(!l.message_read(run, &m.id).unwrap(), "seed {seed}: and only once");
            *reads.entry(m.id).or_default() += 1;
        }
        for (id, _) in &model {
            assert_eq!(reads.get(id), Some(&1), "seed {seed}: {id} read exactly once");
        }
        let left: i64 = l
            .conn
            .query_row("SELECT COUNT(*) FROM messages WHERE to_run = ?1 AND delivered_at IS NULL", params![run], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0, "seed {seed}: nothing left in flight or waiting");
    }
}
