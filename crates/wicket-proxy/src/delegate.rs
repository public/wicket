//! Delegation (#252): `spawn` hands a child a brief and returns a handle; the child's report on
//! each brief comes back to its parent as a message (with a receipt); the parent continues the
//! same child by name, with its context intact, once its turn has ended (`continue_child`).
//!
//! What holds:
//! - a brief and a report are messages: data, signed by wicket with the sender's identity. They
//!   grant nothing. A continued child keeps the zone it was spawned with, within its parent's
//!   (#256): continuing it changes no authority;
//! - only the principal that delegated may continue a child (its parent): anyone else is refused,
//!   on the record (`delegation.refused`);
//! - every step is audited: `delegation.started` (at spawn), `delegation.reported`,
//!   `delegation.continued`, `delegation.refused`, `delegation.ended`.

use crate::{Recipient, RunCtx, Sent};
use serde_json::{json, Value};

/// A child run's delegation id: one per child, the same wherever it was started (the control host
/// or its parent's node, #164), so a handle given before the control host has adopted it holds.
pub fn delegation_id(child_run: &str) -> String {
    format!("d-{}", child_run.strip_prefix("run_").unwrap_or(child_run))
}

/// What `spawn` returns for an agent (#252): how to address the child (its principal), and its
/// delegation, which `continue_child` and `delegations` take.
pub fn handle(principal: &str, child_run: &str, name: &str) -> Value {
    json!({ "principal": principal, "delegation": delegation_id(child_run), "run": child_run, "name": name })
}

/// The most of a turn's result a report carries: a report is a message, bounded like one.
const MAX_REPORT_CHARS: usize = 12 * 1024;

impl RunCtx {
    /// The end of one of this run's top-level turns (#252). If the run is a delegated child with a
    /// brief it hasn't reported on, and it has read that brief, the turn's result goes to its
    /// parent as a `report` message, and the delegation is `reported`. None: nothing to report.
    pub fn report_turn(&self, result: Option<&str>, is_error: bool) -> Option<Result<Sent, String>> {
        let d = {
            let l = self.ledger.lock().ok()?;
            let d = l.delegation_of_child(&self.run.0).ok().flatten().filter(|d| d.state == "working")?;
            // A continuation's turn is the one after the child read its brief: a turn that ended
            // before then (another message's) isn't a report on it.
            if let Some(m) = &d.brief_message {
                if l.receipt(m).ok().flatten().is_none_or(|r| r.state != "read") {
                    return None;
                }
            }
            d
        };
        let report: Option<String> = result.map(|r| {
            let n = r.chars().count();
            if n > MAX_REPORT_CHARS {
                let tail: String = r.chars().skip(n - MAX_REPORT_CHARS).collect();
                format!("[… {} characters cut]\n{tail}", n - MAX_REPORT_CHARS)
            } else {
                r.to_string()
            }
        });
        let body = json!({
            "delegation": d.id, "turn": d.turn, "status": if is_error { "turn_failed" } else { "turn_ended" }, "report": report,
            "note": if d.parent_run.is_empty() {
                "the agent's turn on this brief ended; its session stays open. `wicket message continue` with this delegation (or its name) gives it another brief, with its context intact."
            } else {
                "the child's turn on this brief ended; its session stays open. continue_child with this delegation (or its name) to give it another brief, with its context intact."
            },
        });
        // To the parent run's principal; a human's delegation (#252) has no parent run, and its
        // report goes to the operator's inbox.
        let sent = match d.parent_run.as_str() {
            "" => self.send_message(&Recipient::Principal(&d.parent_principal), "report", body),
            _ => self.send_message(&Recipient::Parent, "report", body),
        };
        let l = self.ledger.lock().ok()?;
        Some(match sent {
            Ok(s) => {
                let _ = l.delegation_reported(&d.id, &s.id);
                let _ = l.audit(
                    &self.tenant,
                    Some(&self.run),
                    "delegation.reported",
                    &json!({ "delegation": d.id, "turn": d.turn, "message": s.id, "to": s.to, "is_error": is_error }),
                );
                Ok(s)
            }
            Err(e) => {
                let _ = l.audit(
                    &self.tenant,
                    Some(&self.run),
                    "delegation.report_failed",
                    &json!({ "delegation": d.id, "turn": d.turn, "error": e }),
                );
                Err(e)
            }
        })
    }

    /// This run ended (#252): its delegation can't be continued, and `final_message` (its
    /// `run_finished`) is its last report.
    pub fn end_delegation(&self, final_message: Option<&str>) {
        let Ok(l) = self.ledger.lock() else { return };
        if let Ok(Some(d)) = l.delegation_of_child(&self.run.0) {
            if d.state != "ended" {
                let _ = l.delegation_ended(&self.run.0, final_message);
                let _ = l.audit(
                    &self.tenant,
                    Some(&self.run),
                    "delegation.ended",
                    &json!({ "delegation": d.id, "turn": d.turn, "message": final_message }),
                );
            }
        }
    }
}
