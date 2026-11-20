//! Releasing a run's fence as a human decision (#690): the console's passkey path beside root's
//! `wicket node release-fence` (#679).
//!
//! A run is fenced while its box may still be running on its node ([`crate::noderun::fenced_in`]):
//! its agent isn't woken and the run isn't ended. A fence with no known end ([`UNKNOWN_END`]) lasts
//! until the node confirms the box stopped, and a node that will never answer again never does.
//!
//! - **Who decides.** Only a human whose authority (`operators.yaml`) covers `fence` decisions at the
//!   highest risk: the box may still be running, and once released its agent can be woken beside it.
//!   No agent decides it. A refusal is on the audit record (`decision.refused`).
//! - **What is decided.** The fence as shown: the run, its node, and when the fence ends. Its
//!   [`effect`] is bound into the approval, and a release of a fence that changed since it was shown
//!   (its node confirmed the box stopped, or the ledger's hard end moved) is refused.
//! - **The record.** `run.fence_released`, with the operator's label and principal, the reason, the
//!   node and the fence's end, as the CLI's is; the authority record keeps `released_by`.

use crate::grant::Granter;
use crate::noderun::{fenced_in, read_authority, release_fence, UNKNOWN_END};
use anyhow::{bail, Result};
use serde::Serialize;
use sha2::Digest;
use std::path::Path;
use wicket_core::{RunId, TenantId};
use wicket_store::Ledger;

/// A run's fence as an operator is shown it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Fence {
    pub run: String,
    pub tenant: String,
    /// The node its box may still be running on.
    pub node: String,
    /// When the fence ends (Unix ms, skew included); None: not until its node confirms the box
    /// stopped, or an operator releases it.
    pub fenced_until_ms: Option<i64>,
    /// Where the fence's end comes from: `authority` (the run's authority record), `run_record` (its
    /// start and timeout), `ledger` (the ledger's hard end of its authority) or `unknown`.
    pub source: String,
    /// The node as the ledger has it: `active`, `revoked`, or `unknown` (not enrolled any more).
    pub node_status: String,
    /// When the node last reported its health (Unix ms), if it ever did.
    pub node_seen_ms: Option<i64>,
    /// Why the fence exists, in words.
    pub why: String,
    /// What approving releases, bound into the approval ([`effect`]).
    pub effect_sha256: String,
}

/// Run `run`'s fence at `now_ms`, its directory under `runs_dir`; None if it isn't fenced (or there
/// is no such run).
pub fn fence_of(l: &Ledger, runs_dir: &Path, run: &str, now_ms: i64) -> Result<Option<Fence>> {
    crate::run::check_run_id(run)?;
    let dir = runs_dir.join(run);
    let cap_ms = l.run_authority(run)?.map(|(_, cap)| cap.saturating_mul(1000));
    let Some((node, until)) = fenced_in(&dir, now_ms, cap_ms) else { return Ok(None) };
    let tenant = l.run_tenant(run)?.unwrap_or_else(TenantId::single).0;
    // The ledger names a run's node even when its authority record was lost ("its node").
    let node = match node.as_str() {
        "its node" => l.run_node(run)?.unwrap_or(node),
        _ => node,
    };
    let source = match (read_authority(&dir).is_some(), until, cap_ms) {
        (true, _, _) => "authority",
        (false, UNKNOWN_END, _) => "unknown",
        (false, u, Some(cap)) if u == cap.saturating_add(crate::noderun::WAKE_SKEW_MS) => "ledger",
        (false, _, _) => "run_record",
    };
    let fenced_until_ms = (until != UNKNOWN_END).then_some(until);
    let node_row = l.node(&node)?;
    let node_status = node_row.map(|n| n.status).unwrap_or_else(|| "unknown".into());
    let node_seen_ms = l.node_health_at(&node)?;
    let ends = match fenced_until_ms {
        Some(u) => format!("until {}", crate::noderun::fmt_ms(u)),
        None => "until its node confirms the box stopped".into(),
    };
    let from = match source {
        "authority" => "its authority there",
        "run_record" => "its start and timeout (its authority record is missing)",
        "ledger" => "the ledger's hard end of its authority (its run record can't be read)",
        _ => "nothing: its authority record is missing and its run record doesn't say when its authority ends",
    };
    let node_says = match (node_status.as_str(), node_seen_ms) {
        ("revoked", _) => format!("node {node} is revoked and won't confirm it"),
        ("unknown", _) => format!("node {node} is no longer enrolled and won't confirm it"),
        (_, Some(t)) => format!("node {node} last reported {}", crate::noderun::fmt_ms(t)),
        (_, None) => format!("node {node} has never reported its health"),
    };
    let why = format!(
        "run {run}'s box may still be running on node {node}, which hasn't confirmed it stopped; fenced {ends}, from {from}; {node_says}"
    );
    let effect_sha256 = effect(run, &node, fenced_until_ms);
    Ok(Some(Fence { run: run.into(), tenant, node, fenced_until_ms, source: source.into(), node_status, node_seen_ms, why, effect_sha256 }))
}

/// What releasing run `run`'s fence on `node`, ending at `fenced_until_ms`, does: a digest of the
/// fence as shown, so a release is of the fence the operator saw.
pub fn effect(run: &str, node: &str, fenced_until_ms: Option<i64>) -> String {
    let v = serde_json::json!({ "v": 1, "effect": "release_fence", "run": run, "node": node, "fenced_until_ms": fenced_until_ms });
    hex::encode(sha2::Sha256::digest(v.to_string().as_bytes()))
}

/// What a fence release is, as an authority sees it: kind `fence` on the run's node, at R4.
pub fn asked(node: &str) -> crate::operators::Asked {
    crate::operators::Asked { kind: "fence".into(), host: node.into(), risk: Some(4) }
}

/// The human operator `by`, if its authority covers releasing a fence on `node`: Err says why not.
pub fn may_decide(by: &Granter, node: &str) -> Result<crate::operators::Operator> {
    let Granter::Human(o) = by else { bail!("a run's fence is released by a human operator, not {}", by.label()) };
    o.may_decide(&asked(node)).map_err(anyhow::Error::msg)?;
    Ok(o.clone())
}

fn refused(l: &Ledger, by: &Granter, run: &str, why: anyhow::Error) -> anyhow::Error {
    let record = serde_json::json!({ "target": run, "decision": "release_fence", "by": by.label(), "why": format!("{why:#}") });
    match l.audit(&TenantId::single(), Some(&RunId(run.into())), "decision.refused", &record) {
        Ok(_) => why.context("refused (the refusal is on the audit record)"),
        Err(e) => why.context(format!("refused (the refusal could not be recorded: {e})")),
    }
}

/// Releases run `run`'s fence as `by`, for `reason`, on the effect `shown` (if the operator was
/// shown one), at `now_ms`; `extra` goes on the audit record. The fence it released.
#[allow(clippy::too_many_arguments)]
pub fn release(
    l: &Ledger,
    runs_dir: &Path,
    by: &Granter,
    run: &str,
    reason: &str,
    shown: Option<&str>,
    now_ms: i64,
    extra: serde_json::Value,
) -> Result<Fence> {
    if reason.trim().is_empty() {
        bail!("say why: the reason goes on the audit record");
    }
    let Some(f) = fence_of(l, runs_dir, run, now_ms)? else {
        bail!("run {run} isn't fenced: its node confirmed its box stopped, or its authority has ended");
    };
    let o = match may_decide(by, &f.node) {
        Ok(o) => o,
        Err(why) => return Err(refused(l, by, run, why)),
    };
    if let Some(s) = shown.filter(|s| *s != f.effect_sha256) {
        let why = anyhow::anyhow!("run {run}'s fence changed since it was shown (effect {s}, now {}): look again", f.effect_sha256);
        return Err(refused(l, by, run, why));
    }
    release_fence(&runs_dir.join(run), &o.label)?;
    let mut record = serde_json::json!({
        "node": f.node, "by": o.label, "granter": "human", "granter_identity": o.id, "why": reason,
        "fenced_until_ms": f.fenced_until_ms, "source": f.source, "effect_sha256": f.effect_sha256,
    });
    if let (Some(r), serde_json::Value::Object(x)) = (record.as_object_mut(), extra) {
        r.extend(x);
    }
    let tenant = TenantId(f.tenant.clone());
    if let Err(e) = l.audit(&tenant, Some(&RunId(run.into())), "run.fence_released", &record) {
        // Fail closed: a release that isn't on the record is undone.
        undo(&runs_dir.join(run));
        return Err(anyhow::Error::from(e).context("the release could not be recorded, so it was undone"));
    }
    Ok(f)
}

/// Puts back a fence [`release_fence`] lifted, when its release couldn't be audited.
fn undo(run_dir: &Path) {
    if let Some(mut a) = read_authority(run_dir) {
        a.stopped = false;
        a.released_by = None;
        if let Err(e) = crate::noderun::write_authority(run_dir, &a) {
            say_err!("[wicket] putting back {}'s fence: {e:#}", run_dir.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::{Authority, Operator, Scope};

    fn human(authority: Authority) -> Granter {
        Granter::Human(Operator { id: "spiffe://w.test/t/default/op/passkey/laptop".into(), label: "passkey:laptop".into(), authority })
    }

    fn scoped(kinds: &[&str], max_risk: Option<&str>) -> Authority {
        Authority::Scoped(Scope {
            kinds: kinds.iter().map(|k| k.to_string()).collect(),
            hosts: vec![],
            max_risk: max_risk.map(String::from),
        })
    }

    /// #690: a run fenced until its node confirms, on a revoked node, is shown with why; an operator
    /// whose authority doesn't cover `fence` at R4 is refused (on the record); a release of a fence
    /// that changed since it was shown is refused; the release lifts it, audited with the principal.
    #[test]
    fn a_fence_is_shown_and_released_by_an_operator_it_covers() {
        let d = std::env::temp_dir().join(format!("wicket-fence-690-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let run = "run_00000000000000000000fenced";
        std::fs::create_dir_all(d.join(run).join("ctl")).unwrap();
        std::fs::write(d.join(run).join("ctl/run.json"), b"not json").unwrap();
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        l.run_started(&t, &RunId(run.into()), "z", "a").unwrap();
        l.set_run_node(run, "n1").unwrap();

        assert_eq!(fence_of(&l, &d, "run_0000000000000000000000none", 1_000).unwrap(), None, "no run record: not fenced");
        let f = fence_of(&l, &d, run, 1_000).unwrap().expect("fenced");
        assert_eq!((f.node.as_str(), f.fenced_until_ms, f.source.as_str()), ("n1", None, "unknown"));
        assert_eq!(f.node_status, "unknown");
        assert!(f.why.contains("until its node confirms the box stopped") && f.why.contains("node n1 is no longer enrolled"), "{}", f.why);
        assert_eq!(f.effect_sha256, effect(run, "n1", None));

        let release = |by: &Granter, shown: Option<&str>| {
            release(&l, &d, by, run, "n1 was destroyed", shown, 2_000, serde_json::json!({ "via": "test" }))
        };
        let refusals = || l.audit_tail(50).unwrap().into_iter().filter(|r| r.2 == "decision.refused").count();
        for a in [Authority::Nothing, scoped(&["http", "name"], None), scoped(&["fence"], Some("R3"))] {
            let e = release(&human(a), None).unwrap_err();
            assert!(format!("{e:#}").contains("refused (the refusal is on the audit record)"), "{e:#}");
        }
        assert_eq!(refusals(), 3);
        assert!(fence_of(&l, &d, run, 3_000).unwrap().is_some(), "still fenced");
        let e = release(&human(Authority::Anything), Some(&effect(run, "n1", Some(9_000)))).unwrap_err();
        assert!(format!("{e:#}").contains("changed since it was shown"), "{e:#}");
        release(&human(scoped(&["fence"], Some("R4"))), Some(&f.effect_sha256)).unwrap();
        assert!(fence_of(&l, &d, run, 3_000).unwrap().is_none(), "released");
        assert_eq!(read_authority(&d.join(run)).unwrap().released_by.as_deref(), Some("passkey:laptop"));
        let body = l.audit_latest(run, "run.fence_released").unwrap().expect("audited");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["by"], "passkey:laptop");
        assert_eq!(v["granter_identity"], "spiffe://w.test/t/default/op/passkey/laptop");
        assert_eq!((v["why"].as_str(), v["node"].as_str(), v["via"].as_str()), (Some("n1 was destroyed"), Some("n1"), Some("test")));
        assert!(v["fenced_until_ms"].is_null());
        let e = release(&human(Authority::Anything), None).unwrap_err();
        assert!(e.to_string().contains("isn't fenced"), "{e}");

        // A bounded fence from the ledger's hard end, on an enrolled node: said so, with its date.
        let run2 = "run_00000000000000000000capped";
        std::fs::create_dir_all(d.join(run2).join("ctl")).unwrap();
        std::fs::write(d.join(run2).join("ctl/run.json"), b"not json").unwrap();
        l.run_started(&t, &RunId(run2.into()), "z", "a").unwrap();
        l.set_run_authority(run2, 100, 100).unwrap();
        let f = fence_of(&l, &d, run2, 1_000).unwrap().expect("fenced");
        assert_eq!((f.source.as_str(), f.fenced_until_ms), ("ledger", Some(100_000 + crate::noderun::WAKE_SKEW_MS)));
        assert!(f.why.contains("the ledger's hard end"), "{}", f.why);
        let _ = std::fs::remove_dir_all(&d);
    }
}
