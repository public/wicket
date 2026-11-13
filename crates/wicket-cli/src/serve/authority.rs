//! The console's read-only views of authority (#173): the installation's Cedar policy and its
//! versions, each run's token decoded block by block, and "explain a decision" for an activity row.
//!
//! - **Read-only.** Nothing here writes: a node's feed is read by replaying its delta log
//!   ([`wicket_feed::read_state`], no publisher opened), and a decision is explained without
//!   recording a grant use ([`wicket_feed::explain`]).
//! - **Never shown:** a serialized token or any signature (blocks are decoded to Datalog; a block's
//!   revocation id, which in Biscuit is its signature, as a fingerprint; the `issuer_cert` JWS is
//!   reported as present, not shown), a secret value (secrets by name only), a
//!   private key. Every view is built from named fields, never by serializing a stored record, so a
//!   field added to a record doesn't reach the page by accident. A test scans every console response
//!   for these (`authority_views_never_carry_a_token_signature_secret_or_key`).
//! - **Views say how fresh they are.** A token is shown as its node's feed holds it now; an
//!   explanation is "against the token as it is now", beside what was recorded when it was decided.

use super::State;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use wicket_core::{Op, RunId, TenantId};
use wicket_feed::{BoxAuthority, RevokeKind};

/// The GET endpoints here, for an operator's session. None: not one of them.
pub(super) fn get(state: &State, path: &str) -> Option<Result<Value>> {
    if path == "/api/policy" {
        return Some(policy(state));
    }
    if let Some(run) = path.strip_prefix("/api/runs/").and_then(|r| r.strip_suffix("/authority")) {
        return Some(run_authority(state, run));
    }
    if let Some(seq) = path.strip_prefix("/api/explain/") {
        return Some(seq.parse::<i64>().context("not an activity record").and_then(|s| explain(state, s)));
    }
    None
}

fn policy_dir(state: &State) -> PathBuf {
    state.data.join("policy")
}

fn read_trim(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// The org policy: the applied version's Cedar and entities, every kept version with when and by
/// whom it was applied, and the running runs by the version they were minted under.
fn policy(state: &State) -> Result<Value> {
    let d = policy_dir(state);
    let installed = read_trim(&d.join("installed"));
    let current = match &installed {
        Some(v) => json!({
            "version": v,
            "cedar": std::fs::read_to_string(d.join("org.cedar")).ok(),
            "entities": std::fs::read_to_string(d.join("org-entities.json")).ok(),
            // A hand edit after `apply` makes every mint refuse (policy.rs): say so.
            "matches_applied": std::fs::read_to_string(d.join("org.cedar")).ok().map(|t| {
                let ents = std::fs::read_to_string(d.join("org-entities.json")).unwrap_or_else(|_| "[]".into());
                wicket_policy::version(&t, &ents) == *v
            }),
        }),
        None => Value::Null,
    };
    let l = state.ledger()?;
    // When each version was applied, from the audit log.
    let mut applied: std::collections::BTreeMap<String, Vec<Value>> = Default::default();
    for (seq, ts, kind, _, body) in l.audit_tail(5000)? {
        if kind == "policy.applied" {
            let b: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            if let Some(v) = b["version"].as_str() {
                applied.entry(v.to_string()).or_default().push(json!({ "seq": seq, "at": ts, "by": b["by"], "previous": b["previous"] }));
            }
        }
    }
    let mut versions = vec![];
    if let Ok(rd) = std::fs::read_dir(d.join("versions")) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(v) = name.strip_suffix(".cedar") else { continue };
            if !v.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            versions.push(json!({
                "version": v,
                "current": installed.as_deref() == Some(v),
                "applied": applied.get(v).cloned().unwrap_or_default(),
                "cedar": std::fs::read_to_string(e.path()).ok(),
            }));
        }
    }
    versions.sort_by_key(|v| std::cmp::Reverse(v["applied"].as_array().and_then(|a| a.last()).and_then(|a| a["at"].as_i64()).unwrap_or(0)));
    let mut runs = vec![];
    for (run, zone, pv) in l.running_policies()? {
        let status = match (&pv, &installed) {
            (_, None) => "no org policy",
            (Some(p), Some(i)) if p == i => "current",
            (_, Some(_)) if l.revoked(&run)?.is_some() => "revoked by a later apply",
            _ => "older version",
        };
        runs.push(json!({ "run": run, "zone": zone, "policy": pv, "status": status }));
    }
    Ok(json!({ "installed": installed, "current": current, "versions": versions, "runs": runs }))
}

/// A run's node's feed state, read without writing, and its entry for the run.
fn feed_entry(state: &State, node: &str, run: &str) -> Result<(wicket_feed::State<BoxAuthority>, bool)> {
    if node.is_empty() || !node.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        bail!("node {node:?}");
    }
    let root = state.authz_root.context("this installation's authority root isn't readable here")?;
    let dir = state.data.join("nodes").join(node).join("feed");
    let st = wicket_feed::read_state::<BoxAuthority>(&dir, node, root).with_context(|| format!("node {node}'s feed"))?;
    let has = st.zones.contains_key(run);
    Ok((st, has))
}

/// A short fingerprint of a revocation id (which is a block's signature, never shown): the first 16
/// hex digits of its SHA-256.
fn fingerprint(revocation_id: &str) -> String {
    use sha2::Digest;
    hex::encode(&sha2::Sha256::digest(revocation_id.as_bytes())[..8])
}

/// Which kind of block `i` is: block 0 is minted from the zone (and the org policy); a third-party
/// block is a grant; any other is a spawn link.
fn block_kind(i: usize, external: bool) -> &'static str {
    match (i, external) {
        (0, _) => "zone",
        (_, true) => "grant",
        _ => "spawn",
    }
}

fn run_authority(state: &State, run: &str) -> Result<Value> {
    crate::run::check_run_id(run)?;
    let l = state.ledger()?;
    let status = l.run_status(run)?.with_context(|| format!("no run {run}"))?;
    let node = l.run_node(run)?.unwrap_or_else(|| crate::localnode::NAME.to_string());
    let policy = l.run_policy(run)?;
    let installed = read_trim(&policy_dir(state).join("installed"));
    let revoked = l.revoked(run)?.map(|(at, by, why)| json!({ "at": at, "by": by, "reason": why }));
    let dir = state.data.join("runs").join(run);
    let auth = crate::noderun::read_authority(&dir);
    let holdings = crate::noderun::read_holdings(&dir);
    let mut out = json!({
        "run": run,
        "status": status,
        "node": node,
        "revoked": revoked,
        "policy": {
            "version": policy,
            "installed": installed,
            "current": policy.is_some() && policy == installed,
        },
        "deadline": auth.as_ref().map(|a| json!({ "until_ms": a.until_ms, "stopped": a.stopped })),
        // What the node holds for the run (#152): secrets by name only, and its budget slice.
        "holdings": holdings.as_ref().map(|h| json!({
            "secrets": h.secrets,
            "slice": h.slice.as_ref().map(|s| json!({ "requests": s.requests, "output_tokens": s.output_tokens, "input_tokens": s.input_tokens })),
            "updated_ms": h.updated_ms,
        })),
    });
    let (st, has) = match feed_entry(state, &node, run) {
        Ok(x) => x,
        Err(e) => {
            out["token"] = json!({ "held": false, "why": format!("{e:#}") });
            return Ok(out);
        }
    };
    out["feed"] = json!({ "epoch": st.epoch, "version": st.version });
    let Some(entry) = st.zones.get(run).filter(|_| has) else {
        out["token"] =
            json!({ "held": false, "why": format!("node {node}'s feed holds no authority for {run} now (an ended run's is dropped)") });
        return Ok(out);
    };
    let spec = &entry.spec;
    let bytes = spec.token_bytes().map_err(anyhow::Error::msg)?;
    let blocks: Vec<Value> = wicket_authz::describe(&bytes)?
        .into_iter()
        .map(|b| {
            json!({
                "index": b.index,
                "kind": block_kind(b.index, b.external_key.is_some()),
                "source": b.source,
                "signed_by": b.external_key,
                // A Biscuit revocation id is the block's signature: shown as a fingerprint only.
                "revocation_fingerprint": fingerprint(&b.revocation_id),
                "revoked": st.is_revoked(RevokeKind::Token, &b.revocation_id),
            })
        })
        .collect();
    let mut grants = vec![];
    for g in &spec.grants {
        let row = l.grant(&g.id)?;
        let prov = l.grant_provenance(&g.id)?;
        grants.push(json!({
            "id": g.id,
            "method": g.method,
            "host": g.host,
            "path": g.path,
            "uses": g.uses,
            "uses_left_on_control_host": row.as_ref().and_then(|r| r.uses_left),
            "expires_at": row.as_ref().map(|r| r.expires_at),
            "revoked": row.as_ref().is_some_and(|r| r.revoked) || st.is_revoked(RevokeKind::Grant, &g.id),
            "approved_by": prov.as_ref().map(|p| p.0.clone()),
            "approved_at": prov.as_ref().map(|p| p.1),
            "reached_node": prov.as_ref().map(|p| !p.2),
        }));
    }
    let base = wicket_authz::Ceiling::from_zone(&spec.zone, "run", 0, vec![]).ok();
    out["token"] = json!({
        "held": true,
        "box_path": spec.box_path,
        "epoch": spec.epoch,
        "zone": spec.zone.name,
        "loads": entry.compiled.as_ref().err().map_or(Value::Bool(true), |e| json!({ "error": e })),
        "issued_by": if spec.issuer_cert.is_some() { "an online issuing key, certified by the authority root" } else { "the authority root" },
        "issuer_until_ms": entry.compiled.as_ref().ok().and_then(|c| c.issuer_until),
        "blocks": blocks,
        "grants": grants,
        "zone_cedar": base.and_then(|b| wicket_policy::zone_layer(&spec.zone, &b).ok()).map(|(text, _)| text),
    });
    Ok(out)
}

/// The decision an activity row records, as one shape: `op` records carry it in their body, a
/// node's (`node.audit`) as a JSON string inside theirs.
fn recorded_decision(kind: &str, body: &str) -> Option<Value> {
    let b: Value = serde_json::from_str(body).ok()?;
    let d = match kind {
        "op" => b,
        "node.audit" => serde_json::from_str(b["body"].as_str()?).ok()?,
        _ => return None,
    };
    (d["kind"] == "egress" && d["host"].is_string() && d["method"].is_string() && d["path"].is_string()).then_some(d)
}

fn explain(state: &State, seq: i64) -> Result<Value> {
    let l = state.ledger()?;
    let r = l.audit_record_at(seq)?.with_context(|| format!("no activity record {seq}"))?;
    let d = recorded_decision(&r.kind, &r.body).context("this record isn't a decision on a request")?;
    let run = r.run.clone().context("this decision names no run")?;
    crate::run::check_run_id(&run)?;
    let s = |k: &str| d[k].as_str().unwrap_or("").to_string();
    let recorded = json!({
        "at": r.ts, "outcome": d["outcome"], "detail": d["detail"], "risk": d["risk"],
        "method": s("method"), "host": s("host"), "path": s("path"),
        "decided_on": if r.kind == "node.audit" { "the box's node" } else { "the control host" },
    });
    let node = l.run_node(&run)?.unwrap_or_else(|| crate::localnode::NAME.to_string());
    let now = match feed_entry(state, &node, &run) {
        Err(e) => json!({ "available": false, "why": format!("{e:#}") }),
        Ok((st, _)) => match st.zones.get(&run) {
            None => json!({ "available": false, "why": format!("node {node}'s feed holds no authority for {run} now") }),
            Some(z) => match &z.compiled {
                Err(e) => json!({ "available": false, "why": format!("its token doesn't load now: {e}") }),
                Ok(c) => {
                    let op = Op::egress(
                        &TenantId(r.tenant.clone()),
                        &RunId(run.clone()),
                        &z.spec.zone.name,
                        &s("method"),
                        &s("host"),
                        &s("path"),
                    );
                    let x = wicket_feed::explain(&z.spec, c, &op, r.ts.saturating_mul(1000));
                    json!({ "available": true, "decision": x.decision, "why": x.why, "zone_says": format!("{:?}", c.zone.evaluate(&op)) })
                }
            },
        },
    };
    Ok(json!({
        "seq": seq,
        "run": run,
        "policy": l.run_policy(&run)?,
        "recorded": recorded,
        // Grants and the token may have changed since: this is its decision as it is now.
        "against_token_now": now,
    }))
}
