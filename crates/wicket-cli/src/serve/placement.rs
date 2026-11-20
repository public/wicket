//! The console's view of why a run went where it did (#579): the placement decision recorded when
//! its node was chosen (`placement_decisions`), as `wicket why-here` reads it.
//!
//! - **Read-only.** Nothing is decided or reserved here.
//! - **The console's tenant only.** A run of another tenant is not found, as one that doesn't exist.
//! - **Named fields only.** The view is built field by field from placement's record (the request,
//!   the node, the ranking and every refusal), never by passing the stored record on whole, so a
//!   field added to the record doesn't reach the page by accident. No token, secret or key is in it.

use super::State;
use anyhow::{Context, Result};
use serde_json::{json, Value};

/// The GET endpoint here (`/api/runs/<run>/placement`), for an operator's session. None: not it.
pub(super) fn get(state: &State, path: &str) -> Option<Result<Value>> {
    let run = path.strip_prefix("/api/runs/")?.strip_suffix("/placement")?;
    Some(view(state, run))
}

/// A run's placement: `decision` (named fields of the record, with `at_ms`) and `text` (what `wicket
/// why-here` prints), or `decision: null` with `why` none is recorded. An unknown run, or another
/// tenant's, is an error (not found).
fn view(state: &State, run: &str) -> Result<Value> {
    crate::run::check_run_id(run)?;
    let l = state.ledger()?;
    if l.run_tenant(run)?.as_ref() != Some(&state.tenant) {
        anyhow::bail!("no run {run}");
    }
    let status = l.run_status(run)?.with_context(|| format!("no run {run}"))?;
    let node = l.run_node(run)?.unwrap_or_else(|| crate::localnode::NAME.to_string());
    let mut out = json!({ "run": run, "status": status, "node": node });
    match l.placement_decision(run)? {
        Some((at_ms, record)) => {
            let r: Value = serde_json::from_str(&record)?;
            out["decision"] = decision(&r, at_ms);
            out["text"] = json!(wicket_control::whyhere::explain(run, at_ms, &record, wicket_feed::now_ms())?);
        }
        None => {
            out["decision"] = Value::Null;
            out["why"] = json!(format!("no placement decision is recorded: {}", wicket_control::whyhere::NO_DECISION));
        }
    }
    Ok(out)
}

/// The decision, by named fields (`decision_record`'s): what the box asked for, where it went, the
/// nodes ranked and refused (each with every reason), and the run it waited behind.
fn decision(r: &Value, at_ms: i64) -> Value {
    let q = &r["request"];
    let strings = |v: &Value| -> Vec<String> {
        v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
    };
    let terms = |v: &Value, keys: &[&str]| -> Vec<Value> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .map(|t| {
                        let mut o = serde_json::Map::new();
                        for k in keys {
                            if !t[*k].is_null() {
                                o.insert((*k).to_string(), t[*k].clone());
                            }
                        }
                        Value::Object(o)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    json!({
        "at_ms": at_ms,
        "node": r["node"].as_str(),
        "behind": r["behind"].as_str(),
        "candidates": r["candidates"].as_u64().unwrap_or(0),
        "request": {
            "vcpus": q["vcpus"].as_f64().unwrap_or(0.0),
            "memory_mib": q["memory_mib"].as_u64().unwrap_or(0),
            "priority": q["priority"].as_i64().unwrap_or(0),
            "preemptible": q["preemptible"].as_bool().unwrap_or(false),
            "node_selector": q["node_selector"].as_object().map(|m| {
                m.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), json!(v)))).collect::<serde_json::Map<_, _>>()
            }),
            "tolerations": terms(&q["tolerations"], &["key", "value"]),
            "affinity": terms(&q["affinity"], &["service", "volume", "required"]),
            "anti_affinity": terms(&q["anti_affinity"], &["zone", "principal", "required"]),
        },
        "ca_hosts": strings(&r["ca_hosts"]),
        "ranked": strings(&r["ranked"]),
        "ranked_more": r["ranked_more"].as_u64().unwrap_or(0),
        "refused": r["refused"].as_array().map(|a| a.iter().map(|x| json!({
            "node": x["node"].as_str(),
            "why": strings(&x["why"]),
        })).collect::<Vec<_>>()).unwrap_or_default(),
        "refused_more": r["refused_more"].as_u64().unwrap_or(0),
    })
}
