//! The delegation tools (#252), the control host's: `continue_child`, another brief for a child its
//! parent delegated to, and `delegations`, what this agent has delegated. Moved from
//! `wicket_proxy::delegate` (#257), which keeps the delegation's ids and handles and a run's report
//! on each brief.

use serde_json::{json, Value};
use wicket_proxy::delegate::handle;
use wicket_proxy::{Recipient, RunCtx, SendError, SendOpts};

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
    // An agent's own children: never a human's delegation (no parent run), even of the same principal.
    let Some(d) = found.iter().find(|d| d.parent_principal == me && !d.parent_run.is_empty()).cloned() else {
        return if found.is_empty() {
            refuse(&format!("no child {child:?} was delegated to in this tenant; spawn one"))
        } else {
            // Somebody else's child: never continued, and who it belongs to isn't said.
            refuse(&format!("{child:?} is not your child: only the agent that spawned it may continue it"))
        };
    };
    let live = ctx.ledger.lock().ok().and_then(|l| l.run_status(&d.child_run).ok().flatten());
    if d.state == "ended" || live.as_deref() != Some("running") {
        return refuse(&format!(
            "{} ({}) has ended (its run is {}); its context is gone with it. spawn a new child instead.",
            d.name,
            d.id,
            live.unwrap_or_else(|| "unknown".into())
        ));
    }
    if d.state == "working" {
        return refuse(&format!(
            "{} is still working on turn {} of {}. Its report comes to you as a message (await_message); continue it after that. To add to its current brief, send_message to {}.",
            d.name, d.turn, d.id, d.child_principal
        ));
    }
    let body = json!({ "delegation": d.id, "turn": d.turn + 1, "brief": brief });
    match ctx.send(
        &Recipient::Principal(&d.child_principal),
        "brief",
        body,
        SendOpts { priority, in_reply_to: None, run: Some(&d.child_run) },
    ) {
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
