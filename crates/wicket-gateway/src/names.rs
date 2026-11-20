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
//! A public name (`<label>.<boxes domain>`: records in a real zone, a host port on the node) is an
//! ask a human decides (`wicket names approve`, [`wicket_control`'s `names`]): anyone on the
//! internet could connect to the port and read what the box serves. The ask is a ledger row
//! (`Ledger::ask_public`), its id (`n-…`) one `await_grant` waits on. Until the reconciler and the
//! node's listener come (#575 step 4b, 4c), an approved name is a record only.

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
    if args.get("kind").and_then(Value::as_str) == Some("public") {
        return match ask_public(ctx, args) {
            Ok(s) => (s, false),
            Err(e) => (format!("not requested: {e}"), true),
        };
    }
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
        k => return Err(format!("`kind` is internal or public, not {k:?}")),
    }
    wicket_names::check_shape(label, false).map_err(|e| e.to_string())?;
    let reason: String = args.get("reason").and_then(Value::as_str).unwrap_or("").chars().take(MAX_REASON).collect();
    let spec = ctx.zone.spec();
    // The one DNS form of the zone's name (#575 review, M3): what the name is registered, looked
    // up and linked under, and what the box is told.
    let zone =
        wicket_names::zone_part(&spec.name).map_err(|e| format!("this zone's name ({}) can't be part of a DNS name: {e}", spec.name))?;
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
        zone: &zone,
        zone_digest: &digest,
        principal: &principal,
        label,
        port,
        service: None,
        reason: &reason,
        scope: NameScope::Run,
    };
    // This run's name already, if it asks again (to change the port).
    let before = l.internal_name(&ctx.tenant, &zone, label).map_err(|e| e.to_string())?.filter(|n| n.holder.as_deref() == Some(&ctx.run.0));
    // Whether the port is exposed already, by the box itself or by another of this run's names: then
    // it stays as it is (#668 review, F1 and F2). Only an exposure a name made is the names' to take
    // away (`name_exposures`).
    let exposed_before = l.exposed(&ctx.run.0, port).map_err(|e| e.to_string())?.is_some();
    let n = l.register_internal(&ask, INTERNAL_PER_WORKLOAD, 0).map_err(|e| e.to_string())?;
    let fqdn = format!("{label}.{zone}.{}", policy::DOMAIN);
    // On a failure below: a new name goes, a name asked again keeps its old port, and an exposure
    // this call made goes.
    let undo = |l: &wicket_store::Ledger| {
        match &before {
            None => {
                let _ = l.revoke_name(&n.id, "wicket");
            }
            Some(old) => {
                let _ = l.register_internal(&NameAsk { port: old.port, ..ask.clone() }, INTERNAL_PER_WORKLOAD, 0);
            }
        }
        if !exposed_before {
            let _ = l.unexpose(&ctx.run.0, port);
            let _ = l.drop_name_exposure(&ctx.run, port);
        }
    };
    // Exposed under the name if nothing exposed the port, so connect finds it offered.
    if !exposed_before {
        let made = l.expose(&ctx.tenant, &ctx.run.0, port, Some(label), &zone_json).and_then(|_| l.mark_name_exposure(&ctx.run, port));
        if let Err(e) = made {
            undo(&l);
            return Err(e.to_string());
        }
    }
    // On the record before it takes effect (fail closed).
    let body = serde_json::json!({ "id": n.id, "name": fqdn, "kind": "internal", "port": port, "scope": "run", "reason": reason,
        "was_port": before.as_ref().map(|b| b.port) });
    if let Err(e) = l.audit(&ctx.tenant, Some(&ctx.run), "name.registered", &body) {
        undo(&l);
        return Err(format!("the audit record could not be written ({e})"));
    }
    // A move: the port it named before stops being offered, if a name exposed it and no other live
    // name of this run still names it. The box's own exposure stays.
    if let Some(old) = before.as_ref().filter(|b| b.port != port) {
        let others = l.names_on_port(&ctx.run, old.port).unwrap_or(1);
        if others == 0 && l.is_name_exposure(&ctx.run, old.port).unwrap_or(false) {
            let _ = l.unexpose(&ctx.run.0, old.port);
            let _ = l.drop_name_exposure(&ctx.run, old.port);
        }
    }
    drop(l);
    ctx.emit(wicket_proxy::Event::Tool { name: "request_name".into(), detail: format!("registered {fqdn} for port {port}") });
    let who = if ctx.zone.accept_from.is_empty() {
        "your parent at once, and other boxes once a human approves".to_string()
    } else {
        format!("your parent and boxes your accept_from lists ({}) at once, others once a human approves", ctx.zone.accept_from.join(", "))
    };
    Ok(format!(
        "registered {fqdn} ({}) for port {port} of this box. Other boxes of your tenant reach it with connect(name: \"{label}.{zone}\"): {who}. Listen on 127.0.0.1:{port} (or 0.0.0.0). The name is yours until this run ends.",
        n.id
    ))
}

/// A box's ask for a public name: filed for a human, never decided here. The label is checked
/// against the reserved labels and their lookalikes (`wicket_names::check_label`), since a public
/// name is in a real zone beside the console's.
fn ask_public(ctx: &RunCtx, args: &Value) -> Result<String, String> {
    let label = args.get("name").and_then(Value::as_str).ok_or("`name` is required")?;
    let port = match args.get("port").and_then(Value::as_u64) {
        Some(p) if (1..=65535).contains(&p) => p as u16,
        _ => return Err("`port` is required: 1-65535".into()),
    };
    wicket_names::check_label(label, &wicket_names::Rules::default()).map_err(|e| e.to_string())?;
    let service = args.get("service").and_then(Value::as_str).unwrap_or("http");
    wicket_names::check_shape(service, false).map_err(|e| format!("`service`: {e}"))?;
    let scope = match args.get("scope").and_then(Value::as_str).unwrap_or("run") {
        "run" => NameScope::Run,
        "standing" => NameScope::Standing,
        s => return Err(format!("`scope` is run or standing, not {s:?}")),
    };
    let reason: String = args.get("reason").and_then(Value::as_str).unwrap_or("").chars().take(MAX_REASON).collect();
    let spec = ctx.zone.spec();
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
        service: Some(service),
        reason: &reason,
        scope,
    };
    let (id, fresh) = l.ask_public(&ask).map_err(|e| e.to_string())?;
    if fresh {
        let body = serde_json::json!({ "id": id, "label": label, "kind": "public", "port": port, "service": service,
            "scope": scope.as_str(), "reason": reason });
        if let Err(e) = l.audit(&ctx.tenant, Some(&ctx.run), "name.requested", &body) {
            let _ = l.deny_name(&id, "wicket:audit-failed");
            return Err(format!("the audit record could not be written ({e})"));
        }
    }
    drop(l);
    ctx.emit(wicket_proxy::Event::Tool {
        name: "request_name".into(),
        detail: format!("asked for public name {label} (port {port}): {id}"),
    });
    let lasting = match scope {
        NameScope::Run => "for this run",
        NameScope::Standing => "for every later run of your workload",
    };
    Ok(format!(
        "needs approval: request {id} asks a human for the public name {label} (port {port}, {lasting}). Call await_grant with {id}. Until wicket publishes public records (not yet), an approved name is a record only."
    ))
}

#[cfg(test)]
mod tests {
    /// The domain names refuse as a zone is the one links live under (#668 review).
    #[test]
    fn internal_names_and_links_share_one_domain() {
        assert_eq!(wicket_names::label::INTERNAL_DOMAIN, wicket_core::link::DOMAIN);
    }
}
