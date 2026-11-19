//! `request_name` (#575; design in `docs/explanation/box-dns.md`): a box gives one of its ports a
//! stable internal name, `<name>.<zone>.wicket.internal`, that other boxes of its tenant reach it
//! by with `connect(name: …)`.
//!
//! An internal name grants nothing: it is `expose` under a name that is unique in the zone. Whether
//! a box may connect to it stays the link's decision (`wicket_core::link::connect`: a parent, or
//! the target's `accept_from`, or a human). So it needs no approval, only a valid label, a label
//! free in the zone, and room in the workload's limit. It is held by the run that asked and ends
//! with it (`Ledger::run_ended`).
//!
//! Public names (records in a real zone, a host port on the node) need a human's approval and come
//! with the reconciler: until then this tool refuses them.

use serde_json::Value;
use wicket_core::link as policy;
use wicket_proxy::RunCtx;
use wicket_store::{NameAsk, NameScope};

type Reply = (String, bool);

/// The most live internal names one workload (an agent's principal) holds at once, until the
/// installation's config sets it (`names.internal.per_workload`).
pub const INTERNAL_PER_WORKLOAD: usize = 3;

/// The longest reason kept.
const MAX_REASON: usize = 200;

pub fn request_name(ctx: &RunCtx, args: &Value) -> Reply {
    match request_inner(ctx, args) {
        Ok(s) => (s, false),
        Err(e) => (format!("not registered: {e}"), true),
    }
}

fn request_inner(ctx: &RunCtx, args: &Value) -> Result<String, String> {
    let label = args.get("name").and_then(Value::as_str).ok_or("`name` is required")?;
    let port = match args.get("port").and_then(Value::as_u64) {
        Some(p) if (1..=65535).contains(&p) => p as u16,
        _ => return Err("`port` is required: 1-65535".into()),
    };
    match args.get("kind").and_then(Value::as_str).unwrap_or("internal") {
        "internal" => {}
        "public" => return Err("public names aren't available yet: ask for an internal one".into()),
        k => return Err(format!("`kind` is internal, not {k:?}")),
    }
    wicket_names::check_shape(label, false).map_err(|e| e.to_string())?;
    let reason: String = args.get("reason").and_then(Value::as_str).unwrap_or("").chars().take(MAX_REASON).collect();
    let spec = ctx.zone.spec();
    let zone_json = serde_json::to_string(spec).map_err(|e| e.to_string())?;
    let digest = wicket_store::zone_digest(spec);
    let l = ctx.ledger.lock().expect("ledger");
    let principal = l
        .identity(&ctx.run.0)
        .map_err(|e| e.to_string())?
        .filter(|i| i.tenant == ctx.tenant.0)
        .map(|i| i.spiffe_id)
        .ok_or("this box has no identity, so it can't hold a name")?;
    let ask = NameAsk {
        tenant: &ctx.tenant,
        run: &ctx.run,
        zone: &spec.name,
        zone_digest: &digest,
        principal: &principal,
        label,
        port,
        service: None,
        reason: &reason,
        scope: NameScope::Run,
    };
    let n = l.register_internal(&ask, INTERNAL_PER_WORKLOAD, 0).map_err(|e| e.to_string())?;
    let fqdn = format!("{label}.{}.{}", spec.name, policy::DOMAIN);
    // Exposed under the name, so connect finds the port offered (and names the link after it).
    let undo = |l: &wicket_store::Ledger| {
        let _ = l.revoke_name(&n.id, "wicket");
        let _ = l.unexpose(&ctx.run.0, port);
    };
    if let Err(e) = l.expose(&ctx.tenant, &ctx.run.0, port, Some(label), &zone_json) {
        undo(&l);
        return Err(e.to_string());
    }
    // On the record before it takes effect (fail closed).
    let body = serde_json::json!({ "id": n.id, "name": fqdn, "kind": "internal", "port": port, "scope": "run", "reason": reason });
    if let Err(e) = l.audit(&ctx.tenant, Some(&ctx.run), "name.registered", &body) {
        undo(&l);
        return Err(format!("the audit record could not be written ({e})"));
    }
    drop(l);
    ctx.emit(wicket_proxy::Event::Tool { name: "request_name".into(), detail: format!("registered {fqdn} for port {port}") });
    let who = if ctx.zone.accept_from.is_empty() {
        "your parent at once, and other boxes once a human approves".to_string()
    } else {
        format!("your parent and boxes your accept_from lists ({}) at once, others once a human approves", ctx.zone.accept_from.join(", "))
    };
    Ok(format!(
        "registered {fqdn} ({}) for port {port} of this box. Other boxes of your tenant reach it with connect(name: \"{label}.{}\"): {who}. Listen on 127.0.0.1:{port} (or 0.0.0.0). The name is yours until this run ends.",
        n.id, spec.name
    ))
}
