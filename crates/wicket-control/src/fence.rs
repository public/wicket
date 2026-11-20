//! Releasing a run's fence without its node (#690): the console's passkey path and root's
//! `wicket node release-fence` (#679), one decision and one audit record.
//!
//! A run is fenced while its box may still be running on its node ([`crate::noderun::fenced_in`]):
//! its agent isn't woken and the run isn't ended. Every box a node runs is fenced while its
//! authority is live, and a fence with no known end ([`UNKNOWN_END`]) lasts until the node confirms
//! the box stopped. A node that will never answer again never does.
//!
//! - **Which fences.** From the console, only one that won't end by itself because its node can't
//!   end it: the node is revoked, no longer enrolled, or hasn't reported for [`silent_after_ms`].
//!   A node that is enrolled and reporting will confirm the box stopped, or still runs it: its fence
//!   is never released there ([`Fence::release_refused`]). Root's break-glass path may release any.
//! - **Who decides.** From the console, a human whose authority (`operators.yaml`) covers `fence` at
//!   the highest risk: the box may still be running, and once released its agent can be woken beside
//!   it. No agent decides it. A refusal is on the audit record (`decision.refused`).
//! - **What is decided.** The fence as shown: the run, its node, the node's status and when it last
//!   reported, and when the fence ends. Its [`effect`] is bound into the release, and a release of a
//!   fence that changed since it was shown is refused.
//! - **The record.** `run.fence_released`, with the decider's label and principal, the reason, and
//!   the fence as released; the authority record keeps `released_by`. A release that can't be
//!   recorded is undone: the authority record is put back as it was.

use crate::grant::Granter;
use crate::noderun::{authority_file, fenced_in, read_authority, release_fence, UNKNOWN_END};
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
    /// stopped, or it is released.
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
    /// Why it can't be released from the console (its node is enrolled and reporting); None: it can.
    pub release_refused: Option<String>,
    /// What releasing it releases, bound into the release ([`effect`]).
    pub effect_sha256: String,
}

/// How long a node may go without reporting its health before its boxes' fences can be released
/// from the console: the feed's TTL (a node's authority lapses without the feed) plus two of the
/// node's report intervals (it reports every 30 s, and the ledger keeps one report per 20 s).
pub fn silent_after_ms() -> i64 {
    crate::noderun::feed_config().ttl_ms + 2 * wicket_chan::health::REPORT_EVERY.as_millis() as i64
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
    let node_status = l.node(&node)?.map(|n| n.status).unwrap_or_else(|| "unknown".into());
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
    let silent = |t: i64| now_ms - t > silent_after_ms();
    let (node_says, release_refused) = match (node_status.as_str(), node_seen_ms) {
        ("revoked", _) => (format!("node {node} is revoked and won't confirm it"), None),
        ("unknown", _) => (format!("node {node} is no longer enrolled and won't confirm it"), None),
        (_, Some(t)) if !silent(t) => (
            format!("node {node} last reported {}", crate::noderun::fmt_ms(t)),
            Some(format!(
                "node {node} is enrolled and reported {} s ago: it confirms the box stopped once it has, or still runs it; its fence is released only once the node is revoked or has been silent for {} s",
                (now_ms - t) / 1000,
                silent_after_ms() / 1000
            )),
        ),
        (_, Some(t)) => (format!("node {node} hasn't reported since {}", crate::noderun::fmt_ms(t)), None),
        (_, None) => (format!("node {node} has never reported its health"), None),
    };
    let why = format!(
        "run {run}'s box may still be running on node {node}, which hasn't confirmed it stopped; fenced {ends}, from {from}; {node_says}"
    );
    let effect_sha256 = effect(run, &node, fenced_until_ms, &node_status, node_seen_ms);
    Ok(Some(Fence {
        run: run.into(),
        tenant,
        node,
        fenced_until_ms,
        source: source.into(),
        node_status,
        node_seen_ms,
        why,
        release_refused,
        effect_sha256,
    }))
}

/// What releasing run `run`'s fence on `node` does, as shown: the fence's end and the node as the
/// ledger had it (its status, and when it last reported). A digest, so a release is of the fence
/// the operator saw, and refused once the node reports again or its status changes.
pub fn effect(run: &str, node: &str, fenced_until_ms: Option<i64>, node_status: &str, node_seen_ms: Option<i64>) -> String {
    let v = serde_json::json!({
        "v": 2, "effect": "release_fence", "run": run, "node": node, "fenced_until_ms": fenced_until_ms,
        "node_status": node_status, "node_seen_ms": node_seen_ms,
    });
    hex::encode(sha2::Sha256::digest(v.to_string().as_bytes()))
}

/// What a fence release is, as an authority sees it: kind `fence` on the run's node, at R4.
pub fn asked(node: &str) -> crate::operators::Asked {
    crate::operators::Asked { kind: "fence".into(), host: node.into(), risk: Some(4) }
}

/// Who releases a fence.
pub enum Decider<'a> {
    /// An operator, from the console: only within its authority, and only a fence its node can't end.
    Operator(&'a Granter),
    /// Root on the control host (`wicket node release-fence`, break-glass): any fence. Its label,
    /// and its operator identity if it can be told.
    Root { label: String, identity: Option<String> },
}

impl Decider<'_> {
    fn label(&self) -> String {
        match self {
            Decider::Operator(g) => g.label(),
            Decider::Root { label, .. } => label.clone(),
        }
    }

    fn identity(&self) -> Option<String> {
        match self {
            Decider::Operator(Granter::Human(o)) => Some(o.id.clone()),
            Decider::Operator(_) => None,
            Decider::Root { identity, .. } => identity.clone(),
        }
    }
}

/// The human operator `by`, if its authority covers releasing a fence on `node`: Err says why not.
pub fn may_decide(by: &Granter, node: &str) -> Result<crate::operators::Operator> {
    let Granter::Human(o) = by else { bail!("a run's fence is released by a human operator, not {}", by.label()) };
    o.may_decide(&asked(node)).map_err(anyhow::Error::msg)?;
    Ok(o.clone())
}

/// Whether `by` may release `f` from the console: its authority, and a fence its node can't end.
pub fn may_release(by: &Granter, f: &Fence) -> Result<()> {
    may_decide(by, &f.node)?;
    if let Some(why) = &f.release_refused {
        bail!("{why}");
    }
    Ok(())
}

fn refused(l: &Ledger, by: &Decider, f: &Fence, why: anyhow::Error) -> anyhow::Error {
    let record = serde_json::json!({
        "target": f.run, "decision": "release_fence", "by": by.label(), "granter_identity": by.identity(), "why": format!("{why:#}"),
    });
    match l.audit(&TenantId(f.tenant.clone()), Some(&RunId(f.run.clone())), "decision.refused", &record) {
        Ok(_) => why.context("refused (the refusal is on the audit record)"),
        Err(e) => why.context(format!("refused (the refusal could not be recorded: {e})")),
    }
}

/// A release asked for.
pub struct Release<'a> {
    pub run: &'a str,
    /// Why, for the audit record.
    pub reason: &'a str,
    /// The effect the decider was shown ([`Fence::effect_sha256`]).
    pub shown: &'a str,
    pub now_ms: i64,
    /// Added to the audit record (`via`, and the console's `signed`).
    pub extra: serde_json::Value,
}

/// Releases a run's fence as `by` decides `r`, the run's directory under `runs_dir`. The fence it
/// released.
pub fn release(l: &Ledger, runs_dir: &Path, by: &Decider, r: Release) -> Result<Fence> {
    if r.reason.trim().is_empty() {
        bail!("say why: the reason goes on the audit record");
    }
    let Some(f) = fence_of(l, runs_dir, r.run, r.now_ms)? else {
        bail!("run {} isn't fenced: its node confirmed its box stopped, or its authority has ended", r.run);
    };
    if let Decider::Operator(g) = by {
        if let Err(why) = may_release(g, &f) {
            return Err(refused(l, by, &f, why));
        }
    }
    if r.shown != f.effect_sha256 {
        let why = anyhow::anyhow!("run {}'s fence changed since it was shown (its node reported, or its end moved): look again", r.run);
        return Err(refused(l, by, &f, why));
    }
    let dir = runs_dir.join(r.run);
    let before = match std::fs::read(authority_file(&dir)) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(anyhow::Error::from(e).context("reading the run's authority record")),
    };
    let label = by.label();
    release_fence(&dir, &label)?;
    let mut record = serde_json::json!({
        "node": f.node, "by": label, "granter": match by { Decider::Operator(_) => "human", Decider::Root { .. } => "root" },
        "granter_identity": by.identity(), "why": r.reason, "fenced_until_ms": f.fenced_until_ms, "source": f.source,
        "node_status": f.node_status, "node_seen_ms": f.node_seen_ms, "effect_sha256": f.effect_sha256,
    });
    if let (Some(rec), serde_json::Value::Object(x)) = (record.as_object_mut(), r.extra) {
        rec.extend(x);
    }
    if let Err(e) = l.audit(&TenantId(f.tenant.clone()), Some(&RunId(r.run.into())), "run.fence_released", &record) {
        // Fail closed: a release that isn't on the record is undone.
        let undone = match undo(&dir, before.as_deref()) {
            Ok(()) => "so it was undone".to_string(),
            Err(u) => format!("and undoing it failed too ({u:#}): the fence is lifted, unrecorded"),
        };
        return Err(anyhow::Error::from(e).context(format!("the release could not be recorded, {undone}")));
    }
    Ok(f)
}

/// Puts run `run_dir`'s authority record back as it was before a release (`before`: its bytes, or
/// None if it had none), when the release couldn't be audited. Removing a record [`release_fence`]
/// created is what keeps the fence: with no record the fence is read from the run record again.
fn undo(run_dir: &Path, before: Option<&[u8]>) -> Result<()> {
    let file = authority_file(run_dir);
    match before {
        Some(b) => {
            let tmp = file.with_extension("json.undo");
            std::fs::write(&tmp, b)?;
            std::fs::File::open(&tmp)?.sync_all()?;
            std::fs::rename(&tmp, &file)?;
        }
        None => std::fs::remove_file(&file)?,
    }
    if let Some(d) = file.parent() {
        std::fs::File::open(d)?.sync_all()?;
    }
    Ok(())
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

    struct Runs(std::path::PathBuf);
    impl Runs {
        fn new(tag: &str) -> Runs {
            let d = std::env::temp_dir().join(format!("wicket-fence-690-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            Runs(d)
        }
        /// A run on `node` whose records can't say when its authority ends.
        fn unreadable(&self, l: &Ledger, run: &str, node: &str) {
            std::fs::create_dir_all(self.0.join(run).join("ctl")).unwrap();
            std::fs::write(self.0.join(run).join("ctl/run.json"), b"not json").unwrap();
            l.run_started(&TenantId::single(), &RunId(run.into()), "z", "a").unwrap();
            l.set_run_node(run, node).unwrap();
        }
    }
    impl Drop for Runs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const RUN: &str = "run_00000000000000000000fenced";
    const NOW: i64 = 1_763_200_000_000;

    fn release_as(l: &Ledger, d: &Path, by: &Granter, shown: &str) -> Result<Fence> {
        let r = Release { run: RUN, reason: "n1 was destroyed", shown, now_ms: NOW, extra: serde_json::json!({ "via": "test" }) };
        release(l, d, &Decider::Operator(by), r)
    }

    /// A ledger with node n1 enrolled and active.
    fn enrolled() -> Ledger {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = l.create_node_token(&TenantId::single(), "n1", 3600).unwrap();
        let now = wicket_store::now();
        let node = wicket_store::NodeRow {
            name: "n1".into(),
            tenant: TenantId::single().0,
            target: "wicket@203.0.113.7".into(),
            host_key: "ssh-ed25519 AAAA".into(),
            host_key_fp: "SHA256:x".into(),
            node_key: "00".repeat(32),
            ssh_key: None,
            hosts: vec![],
            enrolled_at: now,
            status: "active".into(),
            revoked_at: None,
        };
        let ca = wicket_store::NodeCaRow {
            serial: "01".into(),
            node: "n1".into(),
            issued_at: now,
            not_after: now + 3600,
            hosts: vec![],
            status: "active".into(),
        };
        l.enrol_node(&t, &node, &ca).unwrap();
        l
    }

    /// #690: a run fenced until its node confirms, on a node no longer enrolled, is shown with why;
    /// an operator whose authority doesn't cover `fence` at R4 is refused (on the record, under the
    /// run's tenant, with its principal); a release of a fence that changed since it was shown is
    /// refused; the release lifts it, audited with the principal.
    #[test]
    fn a_fence_is_shown_and_released_by_an_operator_it_covers() {
        let d = Runs::new("release");
        let l = Ledger::open_in_memory().unwrap();
        d.unreadable(&l, RUN, "n1");

        assert_eq!(fence_of(&l, &d.0, "run_0000000000000000000000none", NOW).unwrap(), None, "no run record: not fenced");
        let f = fence_of(&l, &d.0, RUN, NOW).unwrap().expect("fenced");
        assert_eq!((f.node.as_str(), f.fenced_until_ms, f.source.as_str()), ("n1", None, "unknown"));
        assert_eq!((f.node_status.as_str(), f.release_refused.as_ref()), ("unknown", None));
        assert!(f.why.contains("until its node confirms the box stopped") && f.why.contains("node n1 is no longer enrolled"), "{}", f.why);
        assert_eq!(f.effect_sha256, effect(RUN, "n1", None, "unknown", None));

        let refusals = || l.audit_tail(50).unwrap().into_iter().filter(|r| r.2 == "decision.refused").collect::<Vec<_>>();
        for a in [Authority::Nothing, scoped(&["http", "name"], None), scoped(&["fence"], Some("R3"))] {
            let e = release_as(&l, &d.0, &human(a), &f.effect_sha256).unwrap_err();
            assert!(format!("{e:#}").contains("refused (the refusal is on the audit record)"), "{e:#}");
        }
        let r = refusals();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].3.as_deref(), Some(RUN));
        assert!(r[0].4.contains("\"granter_identity\":\"spiffe://w.test/t/default/op/passkey/laptop\""), "{}", r[0].4);
        assert!(fence_of(&l, &d.0, RUN, NOW).unwrap().is_some(), "still fenced");
        // Shown another fence: one whose node had reported, say.
        let e = release_as(&l, &d.0, &human(Authority::Anything), &effect(RUN, "n1", None, "unknown", Some(NOW - 1))).unwrap_err();
        assert!(format!("{e:#}").contains("changed since it was shown"), "{e:#}");
        release_as(&l, &d.0, &human(scoped(&["fence"], Some("R4"))), &f.effect_sha256).unwrap();
        assert!(fence_of(&l, &d.0, RUN, NOW).unwrap().is_none(), "released");
        assert_eq!(read_authority(&d.0.join(RUN)).unwrap().released_by.as_deref(), Some("passkey:laptop"));
        let v: serde_json::Value = serde_json::from_str(&l.audit_latest(RUN, "run.fence_released").unwrap().expect("audited")).unwrap();
        assert_eq!((v["by"].as_str(), v["granter"].as_str()), (Some("passkey:laptop"), Some("human")));
        assert_eq!(v["granter_identity"], "spiffe://w.test/t/default/op/passkey/laptop");
        assert_eq!((v["why"].as_str(), v["node"].as_str(), v["via"].as_str()), (Some("n1 was destroyed"), Some("n1"), Some("test")));
        assert_eq!((v["node_status"].as_str(), v["effect_sha256"].as_str()), (Some("unknown"), Some(f.effect_sha256.as_str())));
        assert!(v["fenced_until_ms"].is_null());
        let e = release_as(&l, &d.0, &human(Authority::Anything), &f.effect_sha256).unwrap_err();
        assert!(e.to_string().contains("isn't fenced"), "{e}");

        // A bounded fence from the ledger's hard end: said so, with its date.
        let run2 = "run_00000000000000000000capped";
        d.unreadable(&l, run2, "n1");
        l.set_run_authority(run2, 100, 100).unwrap();
        let f = fence_of(&l, &d.0, run2, 1_000).unwrap().expect("fenced");
        assert_eq!((f.source.as_str(), f.fenced_until_ms), ("ledger", Some(100_000 + crate::noderun::WAKE_SKEW_MS)));
        assert!(f.why.contains("the ledger's hard end"), "{}", f.why);
    }

    /// The review of #690: a healthy node's box (an enrolled node that reported recently, its
    /// authority record live, as every node box has) is fenced but not releasable from the console,
    /// whoever asks; once the node has been silent past [`silent_after_ms`], or is revoked, it is.
    /// Root's path releases it either way.
    #[test]
    fn a_healthy_nodes_fence_isnt_released_from_the_console() {
        let d = Runs::new("healthy");
        let mut l = enrolled();
        d.unreadable(&l, RUN, "n1");
        // The authority record every node box has: live for another hour.
        let a = crate::noderun::AuthorityRecord { node: "n1".into(), until_ms: NOW + 3_600_000, ..Default::default() };
        crate::noderun::write_authority(&d.0.join(RUN), &a).unwrap();
        l.set_node_health("n1", NOW - 10_000, "{}").unwrap();
        let f = fence_of(&l, &d.0, RUN, NOW).unwrap().expect("fenced");
        assert_eq!((f.source.as_str(), f.node_status.as_str()), ("authority", "active"));
        let why = f.release_refused.clone().expect("not releasable");
        assert!(why.contains("node n1 is enrolled and reported 10 s ago"), "{why}");
        let e = release_as(&l, &d.0, &human(Authority::Anything), &f.effect_sha256).unwrap_err();
        assert!(format!("{e:#}").contains("is enrolled and reported"), "{e:#}");
        assert!(fence_of(&l, &d.0, RUN, NOW).unwrap().is_some(), "still fenced");

        // Silent past the threshold: releasable.
        let later = NOW - 10_000 + silent_after_ms() + 1;
        let f2 = fence_of(&l, &d.0, RUN, later).unwrap().unwrap();
        assert_eq!(f2.release_refused, None, "{}", f2.why);
        assert!(f2.why.contains("hasn't reported since"), "{}", f2.why);
        // Revoked: releasable, and not on the effect shown while it was active.
        l.revoke_node("n1").unwrap();
        let f3 = fence_of(&l, &d.0, RUN, NOW).unwrap().unwrap();
        assert_eq!((f3.node_status.as_str(), f3.release_refused.as_ref()), ("revoked", None));
        assert_ne!(f3.effect_sha256, f.effect_sha256);
        let e = release_as(&l, &d.0, &human(Authority::Anything), &f.effect_sha256).unwrap_err();
        assert!(format!("{e:#}").contains("changed since it was shown"), "{e:#}");

        // Root releases a fence whatever its node says.
        let d2 = Runs::new("root");
        let l2 = enrolled();
        d2.unreadable(&l2, RUN, "n1");
        l2.set_node_health("n1", NOW - 10_000, "{}").unwrap();
        let f = fence_of(&l2, &d2.0, RUN, NOW).unwrap().unwrap();
        assert!(f.release_refused.is_some());
        let root = Decider::Root { label: "root".into(), identity: None };
        let r =
            Release { run: RUN, reason: "break glass", shown: &f.effect_sha256, now_ms: NOW, extra: serde_json::json!({ "via": "cli" }) };
        release(&l2, &d2.0, &root, r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&l2.audit_latest(RUN, "run.fence_released").unwrap().unwrap()).unwrap();
        assert_eq!((v["granter"].as_str(), v["via"].as_str(), v["node"].as_str()), (Some("root"), Some("cli"), Some("n1")));
    }

    /// The review of #690: a release whose audit record can't be written is undone and the fence
    /// holds, whether the release created the authority record (removed again) or changed one (put
    /// back byte for byte).
    #[test]
    fn a_release_that_cant_be_recorded_keeps_the_fence() {
        for had_record in [false, true] {
            let d = Runs::new(if had_record { "undo-had" } else { "undo-none" });
            let l = Ledger::open_in_memory().unwrap();
            d.unreadable(&l, RUN, "n1");
            let file = authority_file(&d.0.join(RUN));
            let original = had_record.then(|| {
                let a = crate::noderun::AuthorityRecord { node: "n1".into(), until_ms: NOW + 3_600_000, ..Default::default() };
                crate::noderun::write_authority(&d.0.join(RUN), &a).unwrap();
                std::fs::read(&file).unwrap()
            });
            let f = fence_of(&l, &d.0, RUN, NOW).unwrap().unwrap();
            l.fail_audit_inserts_for_tests().unwrap();
            let e = release_as(&l, &d.0, &human(Authority::Anything), &f.effect_sha256).unwrap_err();
            assert!(format!("{e:#}").contains("could not be recorded, so it was undone"), "{e:#}");
            assert_eq!(std::fs::read(&file).ok(), original, "the authority record is as it was");
            assert_eq!(fence_of(&l, &d.0, RUN, NOW).unwrap().map(|x| x.fenced_until_ms), Some(f.fenced_until_ms), "still fenced");
        }
    }
}
