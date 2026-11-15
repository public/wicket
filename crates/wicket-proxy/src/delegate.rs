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

use crate::{Recipient, RunCtx, SendError, SendOpts, Sent};
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
            "note": "the child's turn on this brief ended; its session stays open. continue_child with this delegation (or its name) to give it another brief, with its context intact.",
        });
        let sent = self.send_message(&Recipient::Parent, "report", body);
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

/// `continue_child` (#252): another brief for a child this agent delegated to, once its turn on the
/// last one has ended. Sent as a `brief` message; the child's session wakes with it, its context
/// intact. Only the agent that delegated may continue it.
pub fn continue_child(ctx: &RunCtx, args: &Value) -> (String, bool) {
    let Some(cell) = &ctx.identity else { return ("this run has no wicket identity".into(), true) };
    let me = cell.current().claims.sub.clone();
    let Some(child) = args.get("child").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) else {
        return ("`child` is required: the child's name, its principal or its delegation id (from spawn's handle)".into(), true);
    };
    let brief = match args.get("brief") {
        Some(Value::String(s)) if !s.trim().is_empty() => Value::String(s.clone()),
        Some(v @ Value::Object(_)) => v.clone(),
        _ => return ("`brief` is required: what you want the child to do next".into(), true),
    };
    let priority = match args.get("priority").and_then(|v| v.as_str()) {
        None => wicket_store::Priority::Next,
        Some(p) => match wicket_store::Priority::parse(p) {
            Some(p) => p,
            None => return (format!("`priority` is now, next or later, not {p:?}"), true),
        },
    };
    let refuse = |why: &str| {
        if let Ok(l) = ctx.ledger.lock() {
            let _ = l.audit(&ctx.tenant, Some(&ctx.run), "delegation.refused", &json!({ "child": child, "by": me, "why": why }));
        }
        (format!("not continued: {why}"), true)
    };
    let found = match ctx
        .ledger
        .lock()
        .map_err(|_| "ledger lock".to_string())
        .and_then(|l| l.find_delegation(&ctx.tenant.0, child).map_err(|e| e.to_string()))
    {
        Ok(f) => f,
        Err(e) => return (e, true),
    };
    let Some(d) = found.iter().find(|d| d.parent_principal == me).cloned() else {
        return if found.is_empty() {
            refuse(&format!("no child {child:?} was delegated to in this tenant; spawn one"))
        } else {
            // Somebody else's child: never continued, and who it belongs to isn't said.
            refuse(&format!("{child:?} is not your child: only the agent that spawned it may continue it"))
        };
    };
    let live = ctx.ledger.lock().ok().and_then(|l| l.run_status(&d.child_run).ok().flatten());
    if d.state == "ended" || live.as_deref() != Some("running") {
        return (
            format!(
                "not continued: {} ({}) has ended (its run is {}); its context is gone with it. spawn a new child instead.",
                d.name,
                d.id,
                live.unwrap_or_else(|| "unknown".into())
            ),
            true,
        );
    }
    if d.state == "working" {
        return (
            format!(
                "not continued: {} is still working on turn {} of {}. Its report comes to you as a message (await_message); continue it after that. To add to its current brief, send_message to {}.",
                d.name, d.turn, d.id, d.child_principal
            ),
            true,
        );
    }
    let body = json!({ "delegation": d.id, "turn": d.turn + 1, "brief": brief });
    match ctx.send(&Recipient::Principal(&d.child_principal), "brief", body, SendOpts { priority, in_reply_to: None }) {
        Ok(s) => {
            let l = ctx.ledger.lock().expect("ledger");
            if !l.delegation_continued(&d.id, &s.id).unwrap_or(false) {
                let _ = l.withdraw_message(&s.id);
                return (format!("not continued: {} changed meanwhile (reported or ended); look again with delegations", d.id), true);
            }
            let _ = l.audit(
                &ctx.tenant,
                Some(&ctx.run),
                "delegation.continued",
                &json!({ "delegation": d.id, "turn": d.turn + 1, "message": s.id, "child": d.child_principal, "child_run": d.child_run }),
            );
            let receipt = l.receipt(&s.id).ok().flatten();
            (
                format!(
                    "continued {} ({}) with turn {}: brief {} sent to {}, which wakes its session with it. Its report comes to you as a message.\nhandle: {}\nreceipt: {}",
                    d.name,
                    d.id,
                    d.turn + 1,
                    s.id,
                    d.child_principal,
                    handle(&d.child_principal, &d.child_run, &d.name),
                    receipt.map(|r| json!(r).to_string()).unwrap_or_default()
                ),
                false,
            )
        }
        Err(SendError::Refused { id, why, .. }) => (format!("not continued: its brief {id} was refused: {why}"), true),
        Err(e) => (format!("not continued: {e}"), true),
    }
}

/// `delegations` (#252): the children this agent delegated to, newest first, with where each is
/// and its latest report's receipt.
pub fn delegations(ctx: &RunCtx) -> (String, bool) {
    let Some(cell) = &ctx.identity else { return ("this run has no wicket identity".into(), true) };
    let me = cell.current().claims.sub.clone();
    let l = ctx.ledger.lock().expect("ledger");
    let rows = match l.delegations_of(&ctx.tenant.0, &me, 50) {
        Ok(r) => r,
        Err(e) => return (e.to_string(), true),
    };
    let out: Vec<Value> = rows
        .into_iter()
        .map(|d| {
            let receipt = |m: &Option<String>| m.as_deref().and_then(|m| l.receipt(m).ok().flatten()).map(|r| json!(r));
            json!({
                "delegation": d.id, "name": d.name, "principal": d.child_principal, "run": d.child_run,
                "run_status": l.run_status(&d.child_run).ok().flatten(),
                "presence": l.presence(&ctx.tenant.0, &d.child_principal).unwrap_or_else(|_| "offline".into()),
                "state": d.state, "turn": d.turn,
                "report": receipt(&d.report_message), "brief": receipt(&d.brief_message),
                "since": d.updated_at,
            })
        })
        .collect();
    let v = json!({
        "delegations": out,
        "states": "working (on its brief), reported (its turn ended and its report was sent to you: continue_child gives it another brief), ended (its run is over)",
    });
    (serde_json::to_string_pretty(&v).unwrap_or_default(), false)
}
