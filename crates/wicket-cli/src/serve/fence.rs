//! The console's Fenced runs card (#690): runs whose box may still be running on a node that can
//! never end its fence (revoked, or no longer enrolled), so their agent isn't woken and the run isn't
//! ended. An operator releases such a fence here instead of as root on the host.
//!
//! - **Shown:** each such run, its node (enrolled, revoked or gone, and when it last reported), when
//!   the fence ends (or that it doesn't until the node confirms), and why
//!   ([`wicket_control::fence::fence_of`]). An enrolled node's boxes are fenced too (while their
//!   authority is live), and are never listed or released here, whether or not it reports (revoke
//!   the node first); nor is a run with no node on record (its box still starting).
//! - **Release** (`release_fence`) is a passkey-signed action, refused at begin to an operator whose
//!   authority (`operators.yaml`) doesn't cover `fence` at R4 (403) and for any other fence (409). The signed JSON names the run, its node, the node's status and last report,
//!   the fence's end, the reason and the effect; a release of a fence that changed since is refused.
//!   It is audited as `run.fence_released` with the operator's label and principal, the record
//!   `wicket node release-fence` writes too.

use super::{err, str_field, Action, Reply, State, MAX_REASON};
use crate::grant;
use serde_json::{json, Value};
use wicket_control::fence;
use wicket_store::{Ledger, OperatorCredential};

fn runs_dir(state: &State) -> std::path::PathBuf {
    state.data.join("runs")
}

/// The fences of this console's tenant an operator could release, among the running runs and the
/// `recent` ones.
pub(super) fn view(state: &State, l: &Ledger, recent: &[String]) -> anyhow::Result<Vec<Value>> {
    let now = wicket_feed::now_ms();
    let mut seen = std::collections::BTreeSet::new();
    let mut out = vec![];
    for run in l.running_runs()?.into_iter().map(|(r, _)| r).chain(recent.iter().cloned()) {
        if !seen.insert(run.clone()) || wicket_control::run::check_run_id(&run).is_err() {
            continue;
        }
        if let Some(f) = fence::fence_of(l, &runs_dir(state), &run, now)? {
            if f.tenant == state.tenant.0 && f.release_refused.is_none() {
                out.push(json!({ "id": f.run, "fence": f }));
            }
        }
    }
    Ok(out)
}

/// `release_fence`, at begin: what the passkey will sign.
pub(super) fn build_release(state: &State, oc: &OperatorCredential, l: &Ledger, body: &Value) -> Result<(Action, Value), Reply> {
    let bad = |m: &str| err(http::StatusCode::BAD_REQUEST, m);
    let Some(run) = str_field(body, "run") else { return Err(bad("run required")) };
    let reason = str_field(body, "reason").map(str::trim).unwrap_or("");
    if reason.is_empty() {
        return Err(bad("say why: the reason goes on the audit record"));
    }
    if reason.chars().count() > MAX_REASON {
        return Err(bad("the reason is too long"));
    }
    let not_fenced = || err(http::StatusCode::NOT_FOUND, format!("run {run} isn't fenced"));
    let f = match fence::fence_of(l, &runs_dir(state), run, wicket_feed::now_ms()) {
        Ok(Some(f)) if f.tenant == state.tenant.0 => f,
        Ok(_) => return Err(not_fenced()),
        Err(e) => return Err(bad(&format!("{e:#}"))),
    };
    // Told now, before a passkey is asked for; checked again (and a refusal audited) when applied.
    let by = human(state, oc).map_err(|e| err(http::StatusCode::INTERNAL_SERVER_ERROR, e))?;
    if let Err(e) = fence::may_decide(&by, &f.node) {
        return Err(err(http::StatusCode::FORBIDDEN, format!("{e:#}")));
    }
    if let Some(why) = &f.release_refused {
        return Err(err(http::StatusCode::CONFLICT, why.clone()));
    }
    let v = json!({
        "v": 1, "action": "release_fence", "tenant": state.tenant.0, "run": f.run, "node": f.node,
        "node_status": f.node_status, "node_seen_ms": f.node_seen_ms, "fenced_until_ms": f.fenced_until_ms,
        "source": f.source, "why": f.why, "reason": reason, "effect_sha256": f.effect_sha256,
    });
    Ok((Action::ReleaseFence { run: f.run, reason: reason.into(), effect: f.effect_sha256 }, v))
}

#[cfg(test)]
thread_local! {
    /// Tests: the console operator's authority, instead of `operators.yaml`'s.
    pub(super) static AUTHORITY: std::cell::RefCell<Option<crate::operators::Authority>> = const { std::cell::RefCell::new(None) };
}

fn human(state: &State, oc: &OperatorCredential) -> anyhow::Result<grant::Granter> {
    #[allow(unused_mut)]
    let mut o = crate::operators::Operator::console(&state.tenant.0, &oc.name)?;
    #[cfg(test)]
    if let Some(a) = AUTHORITY.with(|a| a.borrow().clone()) {
        o.authority = a;
    }
    Ok(grant::Granter::Human(o))
}

/// Applies a signed `release_fence`.
pub(super) fn apply_release(
    state: &State,
    l: &Ledger,
    oc: &OperatorCredential,
    run: &str,
    reason: &str,
    effect: &str,
    signed: Value,
) -> anyhow::Result<String> {
    let by = human(state, oc)?;
    let r =
        fence::Release { run, reason, shown: effect, now_ms: wicket_feed::now_ms(), extra: json!({ "via": "console", "signed": signed }) };
    let f = fence::release(l, &runs_dir(state), &fence::Decider::Operator(&by), r)?;
    Ok(format!(
        "released run {run}'s fence on node {}: its agent can be woken, and its box may still be running there (signed with {})",
        f.node, oc.name
    ))
}
