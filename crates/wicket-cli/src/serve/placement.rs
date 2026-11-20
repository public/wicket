//! The console's view of why a run went where it did (#579): the placement decision recorded when
//! its node was chosen (`placement_decisions`), as `wicket why-here` reads it.
//!
//! - **Read-only.** Nothing is decided or reserved here.
//! - **Named fields only.** The record is placement's own (the request, the node, the ranking and
//!   every refusal); the view adds the run's status and node and the same plain-words explanation
//!   `wicket why-here` prints. No token, secret or key is ever in it.

use super::State;
use anyhow::{Context, Result};
use serde_json::{json, Value};

/// The GET endpoint here (`/api/runs/<run>/placement`), for an operator's session. None: not it.
pub(super) fn get(state: &State, path: &str) -> Option<Result<Value>> {
    let run = path.strip_prefix("/api/runs/")?.strip_suffix("/placement")?;
    Some(view(state, run))
}

/// A run's placement: `decision` (the record, with `run` and `at_ms`) and `text` (what `wicket
/// why-here` prints), or `decision: null` with `why` none is recorded. An unknown run is an error.
fn view(state: &State, run: &str) -> Result<Value> {
    crate::run::check_run_id(run)?;
    let l = state.ledger()?;
    let status = l.run_status(run)?.with_context(|| format!("no run {run}"))?;
    let node = l.run_node(run)?;
    let mut out = json!({ "run": run, "status": status, "node": node });
    match l.placement_decision(run)? {
        Some((at_ms, record)) => {
            out["decision"] = wicket_control::whyhere::record_json(run, at_ms, &record)?;
            out["text"] = json!(wicket_control::whyhere::explain(run, at_ms, &record, wicket_feed::now_ms())?);
        }
        None => {
            out["decision"] = Value::Null;
            out["why"] = json!(format!("no placement decision is recorded: {}", wicket_control::whyhere::NO_DECISION));
        }
    }
    Ok(out)
}
