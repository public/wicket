//! The console's release of a placed node past its lease (#710), as `wicket node release` does it
//! on the host, through [`wicket_control::noderelease`]:
//!
//! - **`node_release`** is a passkey-signed action. Begin refuses, before any passkey is asked
//!   for: no reason or one too long (400), a node that isn't an active placed node of this
//!   installation (404), a node whose lease hasn't ended (409: the reconciler releases it then),
//!   and an operator whose `operators.yaml` scope doesn't cover `capacity` at R4 (403).
//! - The signed JSON names the node, its lease's end, the runs still running there, its service instances, and
//!   the runs whose files a fetch didn't collect, what releasing it does in words, the reason, and the effect's
//!   sha256 ([`wicket_control::noderelease::PastLease::effect`]).
//! - At finish, the decision is made on that effect: a node whose runs or lease changed since is
//!   refused (and audited). It is audited (`placement.node_release_decided`, with the signed
//!   assertion) **before** the provider is asked, which happens in the background
//!   ([`super::Releaser`]): `placement.node_released`, or `placement.node_release_failed` and the
//!   node is as it was.

use super::{err, str_field, Action, Reply, State, MAX_REASON};
use anyhow::Result;
use http::StatusCode;
use serde_json::{json, Value};
use wicket_control::noderelease as nr;
use wicket_store::{Ledger, OperatorCredential};

/// What the console asks the releaser to do: release `node`, decided as audit record `seq`, by `by`.
pub struct Release {
    pub node: nr::PastLease,
    pub by: String,
    pub seq: i64,
}

/// `node_release`, at begin: what the passkey will sign.
pub(super) fn build(state: &State, l: &Ledger, oc: &OperatorCredential, body: &Value) -> Result<(Action, Value), Reply> {
    let Some(id) = str_field(body, "id") else { return Err(err(StatusCode::BAD_REQUEST, "id required")) };
    let reason = str_field(body, "reason").map(str::trim).unwrap_or("");
    if reason.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "say why it is released: the reason goes on the audit record"));
    }
    if reason.chars().count() > MAX_REASON {
        return Err(err(StatusCode::BAD_REQUEST, "the reason is too long"));
    }
    let n = nr::view(l, id, wicket_store::now())
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, format!("no active placed node {id}")))?;
    if !n.past_lease {
        return Err(err(StatusCode::CONFLICT, format!("{}'s lease hasn't ended: the reconciler releases it then", n.name)));
    }
    // Told now, before a passkey is asked for; checked again (and a refusal audited) when applied.
    let by = super::fence::human(state, oc).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    nr::may_decide(&by).map_err(|e| err(StatusCode::FORBIDDEN, format!("{e:#}")))?;
    let effect_sha256 = n.effect_sha256();
    let v = json!({
        "v": 1, "action": "node_release", "tenant": state.tenant.0, "id": n.id, "name": n.name, "backend": n.backend,
        "lease_until": n.lease_until, "running": n.running, "services": n.services, "uncollected": n.uncollected,
        "consequence": n.consequence(), "reason": reason, "effect": n.effect(), "effect_sha256": effect_sha256,
    });
    Ok((Action::NodeRelease { id: n.id, reason: reason.into(), effect_sha256 }, v))
}

/// `node_release`, at finish: decided on the effect signed, audited, then released in the background.
pub(super) fn apply(
    state: &State,
    l: &Ledger,
    oc: &OperatorCredential,
    id: &str,
    reason: &str,
    effect: &str,
    signed: Value,
) -> Result<String> {
    let by = super::fence::human(state, oc)?;
    let d = nr::Decision {
        by: nr::Decider::Operator { by: &by, console: true },
        shown: effect,
        why: reason,
        extra: json!({ "action": "node_release", "via": "console", "signed": signed }),
    };
    let (n, seq) = nr::decide(l, id, &d, wicket_store::now())?;
    let what = n.consequence();
    let name = n.name.clone();
    let label = by.label();
    if let Err(e) = (state.releaser)(Release { node: n, by: label.clone(), seq }) {
        let _ = l.audit(
            &state.tenant,
            None,
            "placement.node_release_failed",
            &json!({ "id": id, "name": name, "by": label, "decision": seq, "error": format!("{e:#}") }),
        );
        anyhow::bail!("releasing {name}: {e:#} (it is as it was)");
    }
    Ok(format!("releasing {name}: this {what}; the activity log says when it is done (signed with {})", oc.name))
}

/// The real releaser: the provider's API key from the vault now, the release in the background.
pub(super) fn release_in_background(ledger: std::path::PathBuf, r: Release) -> Result<()> {
    let p = crate::nodecreate::release_placer(&r.node.owner, &r.node.api_key_secret)?;
    tokio::spawn(async move {
        let done = match Ledger::open(&ledger) {
            // Its own failures, before or after the destroy, are audited by `release` itself.
            Ok(mut l) => nr::release(&mut l, &p, &r.node, &r.by, r.seq, crate::nodecreate::retire_enrolment, wicket_store::now()).await,
            Err(e) => Err(anyhow::Error::from(e).context("the ledger can't be opened, so nothing was released")),
        };
        match done {
            Ok(said) => tracing::info!("console release: {said}"),
            Err(e) => tracing::warn!("console release of {}: {e:#}", r.node.name),
        }
    });
    Ok(())
}
