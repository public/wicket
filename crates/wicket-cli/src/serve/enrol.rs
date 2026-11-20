//! Enrolling another device from a signed-in passkey (#711), beside the host's
//! `wicket operator enrol-link`, which stays for the first passkey and for recovery.
//!
//! - **`enrol_link`** is a passkey-signed action: a session cookie alone makes no link. The signed
//!   JSON names the passkey making it, the operator it enrols the new device as, and how long the
//!   link lasts (60 s to 10 minutes; 5 by default).
//! - The link is single use and expires, as a host link does (only the hash of its token is kept).
//!   It is shown once, in the answer to `finish`, and audited (`operator.enrol_link_issued`, with
//!   the signed assertion; never the token).
//! - **Never more authority than its maker.** An operator's authority (`operators.yaml`) is keyed by
//!   its passkey's name, so the passkey a console link enrols takes its maker's name, whatever name
//!   the new device asks for: it is the same operator on another device. The link records the
//!   passkey that made it ([`CONSOLE_LINK`]), and a link whose maker was revoked since enrols
//!   nothing.

use super::{err, Action, Reply, State};
use http::StatusCode;
use serde_json::{json, Value};
use wicket_store::{Ledger, OperatorCredential};

/// `created_by` of a link a console passkey made: this, then the passkey's credential id. A host
/// link's is its unix operator (`user@host`), which can't start with it.
pub(super) const CONSOLE_LINK: &str = "passkey-credential:";
/// How long a console link lasts, by default and at most (s).
pub(super) const DEFAULT_TTL: u64 = 300;
pub(super) const MAX_TTL: u64 = 600;
const MIN_TTL: u64 = 60;

/// `enrol_link`, at begin: what the passkey will sign.
pub(super) fn build(state: &State, oc: &OperatorCredential, body: &Value) -> Result<(Action, Value), Reply> {
    let ttl_secs = body.get("ttl_secs").and_then(Value::as_u64).unwrap_or(DEFAULT_TTL);
    if !(MIN_TTL..=MAX_TTL).contains(&ttl_secs) {
        return Err(err(StatusCode::BAD_REQUEST, format!("an enrolment link lasts {MIN_TTL} to {MAX_TTL} seconds")));
    }
    let v = json!({
        "v": 1, "action": "enrol_link", "tenant": state.tenant.0, "credential": oc.id, "name": oc.name,
        // The operator the new device is enrolled as: this passkey's, so the same authority.
        "enrols_as": format!("passkey/{}", oc.name), "ttl_secs": ttl_secs, "uses": 1,
    });
    Ok((Action::EnrolLink { ttl_secs }, v))
}

/// `enrol_link`, at finish: the link, made, audited and returned once.
pub(super) fn apply(state: &State, l: &Ledger, oc: &OperatorCredential, ttl_secs: u64, signed: Value) -> anyhow::Result<Value> {
    let by = format!("{CONSOLE_LINK}{}", oc.id);
    let extra = json!({ "via": "console", "credential": oc.id, "name": oc.name, "enrols_as": format!("passkey/{}", oc.name),
                        "action": "enrol_link", "signed": signed });
    let token = super::issue_enrol_link_with(l, &state.tenant, ttl_secs as i64, &by, extra)?;
    let path = format!("/enrol?t={token}");
    Ok(json!({
        "ok": format!("a link that enrols one device as {} for {} minutes (signed with {}): it is shown only now",
                      oc.name, ttl_secs.div_ceil(60), oc.name),
        "link": format!("{}{path}", state.rp.origin), "path": path, "expires_in_secs": ttl_secs,
    }))
}

/// The name a passkey enrolled with link `link` takes: for a console link, its maker's (refused if
/// the maker's passkey is no longer enrolled); for a host link, what the new device asked for.
pub(super) fn enrolled_name(state: &State, l: &Ledger, link: &str, asked: &str) -> Result<(String, Option<String>), Reply> {
    let by = l.enrol_link_by(&state.tenant, link).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let Some(cred) = by.as_deref().and_then(|b| b.strip_prefix(CONSOLE_LINK)) else { return Ok((asked.to_string(), None)) };
    match super::creds(state).unwrap_or_default().into_iter().find(|c| c.id == cred) {
        Some(maker) => Ok((maker.name, Some(maker.id))),
        None => {
            Err(err(StatusCode::FORBIDDEN, "the passkey that made this enrolment link is no longer enrolled, so the link enrols nothing"))
        }
    }
}
