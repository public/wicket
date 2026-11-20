//! The console's Fenced runs card (#690): runs whose box may still be running on their node, which
//! hasn't confirmed it stopped, so their agent isn't woken and the run isn't ended. For a node that
//! will never answer again, an operator releases the fence here instead of as root on the host.
//!
//! - **Shown:** each fenced run, its node (enrolled, revoked or gone, and when it last reported),
//!   when the fence ends (or that it doesn't until the node confirms), and why
//!   ([`wicket_control::fence::fence_of`]).
//! - **Release** (`release_fence`) is a passkey-signed action, refused at begin to an operator whose
//!   authority (`operators.yaml`) doesn't cover `fence` at R4. The signed JSON names the run, its
//!   node, the fence's end, the reason and the effect; a release of a fence that changed since is
//!   refused. It is audited as `run.fence_released` with the operator's label and principal, as
//!   `wicket node release-fence` is.

use super::{err, str_field, Action, Reply, State, MAX_REASON};
use crate::grant;
use serde_json::{json, Value};
use wicket_control::fence;
use wicket_store::{Ledger, OperatorCredential};

fn runs_dir(state: &State) -> std::path::PathBuf {
    state.data.join("runs")
}

/// The fenced runs of this console's tenant, among the running runs and the `recent` ones.
pub(super) fn view(state: &State, l: &Ledger, recent: &[String]) -> anyhow::Result<Vec<Value>> {
    let now = wicket_feed::now_ms();
    let mut seen = std::collections::BTreeSet::new();
    let mut out = vec![];
    for run in l.running_runs()?.into_iter().map(|(r, _)| r).chain(recent.iter().cloned()) {
        if !seen.insert(run.clone()) || wicket_control::run::check_run_id(&run).is_err() {
            continue;
        }
        if let Some(f) = fence::fence_of(l, &runs_dir(state), &run, now)? {
            if f.tenant == state.tenant.0 {
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
    let v = json!({
        "v": 1, "action": "release_fence", "tenant": state.tenant.0, "run": f.run, "node": f.node,
        "fenced_until_ms": f.fenced_until_ms, "source": f.source, "node_status": f.node_status, "why": f.why,
        "reason": reason, "effect_sha256": f.effect_sha256,
    });
    Ok((Action::ReleaseFence { run: f.run, reason: reason.into(), effect: f.effect_sha256 }, v))
}

fn human(state: &State, oc: &OperatorCredential) -> anyhow::Result<grant::Granter> {
    Ok(grant::Granter::Human(crate::operators::Operator::console(&state.tenant.0, &oc.name)?))
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
    let extra = json!({ "via": "console", "signed": signed });
    let f = fence::release(l, &runs_dir(state), &human(state, oc)?, run, reason, Some(effect), wicket_feed::now_ms(), extra)?;
    Ok(format!(
        "released run {run}'s fence on node {}: its agent can be woken, and its box may still be running there (signed with {})",
        f.node, oc.name
    ))
}
