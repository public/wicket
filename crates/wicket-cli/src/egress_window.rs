//! Windowed egress caps on the control host (#368, `wicket_core::window`): the principal's history
//! over the window, which the node's reports are added to and its slices leased from.
//!
//! - **Keyed by principal**, not session or activation: `agent:<id>` for a long-lived agent (every
//!   activation counts against one window, so hibernating and waking resets nothing), `run:<id>`
//!   for any other run.
//! - **Kept in the ledger** (`egress_windows`), as JSON: the window's [`Ring`], and the run whose
//!   node last reported with what it had counted, so a supervisor that re-attaches to the same run
//!   doesn't count the node's next report twice, and a new activation's count starts from zero.
//! - **Leased** to the node as [`EgressSlice`]s ([`Window::next_slice`]): what the window has left
//!   is all a node may ever be leased, and a node that hears nothing spends its slice and stops.

use std::sync::{Arc, Mutex};
use wicket_core::window::{EgressCaps, EgressSlice, EgressUse, Ring, SLICE_FRACTION};
use wicket_store::Ledger;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct Stored {
    ring: Ring,
    run: String,
    seen: EgressUse,
}

/// One principal's window, for one activation's run.
pub struct Window {
    caps: EgressCaps,
    key: String,
    run: String,
    ledger: Arc<Mutex<Ledger>>,
    state: Mutex<Stored>,
}

/// The ledger key of a principal's window.
pub fn key(agent: Option<&str>, run: &str) -> String {
    match agent {
        Some(a) => format!("agent:{a}"),
        None => format!("run:{run}"),
    }
}

impl Window {
    /// The window for `key`, as the ledger has it, for this activation's `run`.
    pub fn open(ledger: Arc<Mutex<Ledger>>, key: String, run: &str, caps: EgressCaps, now: i64) -> anyhow::Result<Window> {
        let stored: Option<Stored> = {
            let l = ledger.lock().map_err(|_| anyhow::anyhow!("ledger lock"))?;
            l.egress_window(&key)?.and_then(|s| serde_json::from_str(&s).ok())
        };
        let mut st = match stored {
            Some(s) => {
                Stored { ring: s.ring.resized(&caps, now), seen: if s.run == run { s.seen } else { EgressUse::default() }, run: run.into() }
            }
            None => Stored { ring: Ring::new(&caps), run: run.into(), seen: EgressUse::default() },
        };
        st.run = run.into();
        Ok(Window { caps, key, run: run.into(), ledger, state: Mutex::new(st) })
    }

    /// Takes in the node's count (cumulative for this activation): what is new is added to the
    /// window at `now`, and the window is saved. Counts only go up.
    pub fn report(&self, used: EgressUse, now: i64) {
        let mut st = self.state.lock().expect("window");
        let delta = used.since(st.seen);
        if delta == EgressUse::default() {
            return;
        }
        st.ring.add(now, delta);
        st.seen = EgressUse { requests: st.seen.requests.max(used.requests), bytes: st.seen.bytes.max(used.bytes) };
        let body = serde_json::to_string(&*st).unwrap_or_default();
        drop(st);
        if let Ok(l) = self.ledger.lock() {
            if let Err(e) = l.put_egress_window(&self.key, &body) {
                eprintln!("[wicket] {}: saving its egress window: {e}", self.run);
            }
        }
    }

    /// What this activation's node has reported.
    pub fn seen(&self) -> EgressUse {
        self.state.lock().expect("window").seen
    }

    /// The slice to lease the node next (its count so far, plus part of what the window has left).
    pub fn next_slice(&self, now: i64) -> EgressSlice {
        let st = self.state.lock().expect("window");
        EgressSlice::next(&self.caps, &st.ring, now, st.seen, slice_fraction())
    }

    /// What the window holds now.
    #[cfg(test)]
    pub fn total(&self, now: i64) -> EgressUse {
        self.state.lock().expect("window").ring.total(now)
    }
}

/// The fraction of what a window has left leased at a time: `WICKET_NODE_EGRESS_SLICE`, default
/// [`SLICE_FRACTION`].
fn slice_fraction() -> f64 {
    std::env::var("WICKET_NODE_EGRESS_SLICE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|f| *f > 0.0 && *f <= 1.0)
        .unwrap_or(SLICE_FRACTION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> EgressCaps {
        EgressCaps { window_secs: 3600, requests: Some(100), bytes: None }
    }

    #[test]
    fn a_window_outlives_its_activations_and_counts_each_report_once() {
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let k = key(Some("agt_x"), "run_a");
        let now = 1_000_000;
        let w = Window::open(ledger.clone(), k.clone(), "run_a", caps(), now).unwrap();
        assert_eq!(w.next_slice(now).requests, Some(25));
        w.report(EgressUse { requests: 20, bytes: 0 }, now);
        w.report(EgressUse { requests: 20, bytes: 0 }, now + 1);
        assert_eq!(w.total(now + 1).requests, 20, "a repeated report counts once");
        // The same run's supervisor re-attaches: the node's count goes on from what was seen.
        let again = Window::open(ledger.clone(), k.clone(), "run_a", caps(), now + 2).unwrap();
        again.report(EgressUse { requests: 30, bytes: 0 }, now + 2);
        assert_eq!(again.total(now + 2).requests, 30);
        // A new activation (woken): its node counts from zero, and the window keeps the old count.
        let woken = Window::open(ledger.clone(), k.clone(), "run_b", caps(), now + 10).unwrap();
        assert_eq!(woken.seen(), EgressUse::default());
        assert_eq!(woken.total(now + 10).requests, 30, "waking resets nothing");
        assert_eq!(woken.next_slice(now + 10).requests, Some(17), "a quarter of the 70 left");
        woken.report(EgressUse { requests: 70, bytes: 0 }, now + 11);
        assert_eq!(woken.next_slice(now + 11).requests, Some(70), "nothing more is leased");
        // Another principal's window is its own.
        let other = Window::open(ledger, key(None, "run_c"), "run_c", caps(), now).unwrap();
        assert_eq!(other.total(now).requests, 0);
        // An hour on, the window has room again.
        assert_eq!(woken.next_slice(now + 11 + 3600).requests, Some(70 + 25));
    }
}
