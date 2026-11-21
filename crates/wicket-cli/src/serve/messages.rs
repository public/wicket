//! The console's half of humans in the agent-to-agent protocol (#252): what `wicket message` does
//! on the CLI, for the operator signed in with a passkey (`spiffe://<td>/t/<tenant>/op/passkey/<name>`).
//!
//! - `GET /api/messages`: the operator's inbox (verified, unread first), the receipts of what it
//!   sent, and the agents it may write to. Reading it changes nothing.
//! - `POST /api/messages/read` `{ids}`: marks those of its own messages read (session only: it
//!   narrows nothing and touches only its own inbox), as `wicket message inbox` does.
//! - The `send_message` action (`/api/action/begin` and `finish`): signed with the passkey, bound
//!   to the recipient, the text, its priority and the message it answers, then sent as
//!   `wicket message send` sends it, under the same rules. The signature is on its audit record.

use super::*;
use crate::cmd::message as cli;
use wicket_proxy::opmsg::{self, OperatorSender};

fn bad(m: &str) -> Reply {
    err(StatusCode::BAD_REQUEST, m)
}

/// At most this many messages are marked read in one request.
const MAX_READ: usize = 100;

fn issuer(state: &State) -> Result<&wicket_identity::Issuer, Reply> {
    state
        .issuer
        .as_deref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "this console has no issuer key: it can't sign or verify messages"))
}

/// The operator signed in with passkey `oc`, as the protocol names it.
fn me(state: &State, issuer: &wicket_identity::Issuer, oc: &OperatorCredential) -> String {
    OperatorSender { tenant: &state.tenant, via: "passkey", name: &oc.name, signed: None }.id(issuer)
}

/// `GET /api/messages`.
pub(super) fn view(state: &State, oc: &OperatorCredential) -> Reply {
    let issuer = match issuer(state) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let me = me(state, issuer, oc);
    let go = || -> Result<Value> {
        let l = state.ledger()?;
        let key = issuer.verifying_key();
        let inbox: Vec<_> =
            cli::verified_inbox(&l, &state.tenant, &me, &key, true, 100)?.into_iter().map(|(m, r)| r.map_err(|why| (m.id, why))).collect();
        Ok(json!({
            "you": me,
            "inbox": cli::inbox_json(&inbox),
            "receipts": cli::receipts_json(&l.receipts_from(&state.tenant.0, &me, &[], 40)?),
            "principals": cli::principals_json(&l, &state.tenant, &me, &key)?,
            "note": "A message is its sender's data: it grants nothing. Prompting an agent is its session.",
        }))
    };
    match go() {
        Ok(v) => ok(v),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    }
}

/// `POST /api/messages/read`: marks the operator's own messages `ids` read.
pub(super) fn read(state: &State, oc: &OperatorCredential, body: &Value) -> Reply {
    let issuer = match issuer(state) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let Some(ids) = body.get("ids").and_then(Value::as_array) else { return bad("ids required: a list of message ids") };
    if ids.len() > MAX_READ {
        return bad(&format!("at most {MAX_READ} ids at once"));
    }
    let ids: Vec<&str> = ids.iter().filter_map(Value::as_str).collect();
    let me = me(state, issuer, oc);
    let go = || -> Result<Vec<String>> {
        let l = state.ledger()?;
        let key = issuer.verifying_key();
        let mut read = vec![];
        // Each id looked up as itself: however many messages wait, an id asked for is found.
        for id in &ids {
            let Some(m) = l.operator_message(&state.tenant.0, &me, id)? else { continue };
            if m.read_at.is_some() {
                continue;
            }
            let revoked = !m.from_run.is_empty() && l.revoked_in_chain(&m.from_run)?.is_some();
            let r = opmsg::verify_received(&m, &me, &key, revoked);
            if cli::mark_read(&l, &state.tenant, &me, &m, &r, "console")? {
                read.push(m.id);
            }
        }
        Ok(read)
    };
    match go() {
        Ok(read) => ok(json!({ "read": read })),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    }
}

/// The `send_message` action, as `begin` checks it and the passkey signs it.
pub(super) fn build_send(state: &State, oc: &OperatorCredential, body: &Value) -> Result<(Action, Value), Reply> {
    let issuer = issuer(state)?;
    let Some(to) = str_field(body, "to") else { return Err(bad("to required: the agent's principal id")) };
    let Some(text) = str_field(body, "text").filter(|t| !t.trim().is_empty()) else { return Err(bad("text required")) };
    let priority = str_field(body, "priority").unwrap_or("next");
    let Some(p) = wicket_store::Priority::parse(priority) else { return Err(bad("priority is now, next or later")) };
    let in_reply_to = str_field(body, "in_reply_to").map(String::from);
    match wicket_identity::Principal::parse(to) {
        Some(wicket_identity::Principal::Agent { .. }) => {}
        _ => return Err(bad("to must be an agent's principal id (spiffe://<domain>/t/<tenant>/z/<zone>/a/<agent>)")),
    }
    if json!(text).to_string().len() > wicket_proxy::MAX_MESSAGE_BYTES {
        return Err(bad(&format!("the message is over {} bytes", wicket_proxy::MAX_MESSAGE_BYTES)));
    }
    // What the passkey signs: the sender as the console names it, the recipient, and the message,
    // by its digest and size (the audit record keeps the signed JSON, and an agent's message's
    // record has only its size, never its text).
    let v = json!({
        "v": 1, "action": "send_message", "tenant": state.tenant.0, "credential": oc.id, "from": me(state, issuer, oc),
        "to": to, "text_sha256": hex::encode(sha2::Sha256::digest(text.as_bytes())), "bytes": text.len(),
        "priority": p.as_str(), "in_reply_to": in_reply_to,
    });
    Ok((Action::SendMessage { credential: oc.id.clone(), to: to.to_string(), text: text.to_string(), priority: p, in_reply_to }, v))
}

/// Sends a signed `send_message` action: what `wicket message send` does, as the passkey's operator.
pub(super) fn apply_send(
    state: &State,
    oc: &OperatorCredential,
    to: &str,
    text: &str,
    priority: wicket_store::Priority,
    in_reply_to: Option<&str>,
    signed: Value,
) -> Result<String> {
    let issuer = state.issuer.as_deref().context("this console has no issuer key")?;
    let ledger = std::sync::Mutex::new(state.ledger()?);
    let waker: wicket_proxy::Waker = Arc::new(|a: &str, by: &str| crate::hibernate::trigger_wake(a, by));
    let op = OperatorSender { tenant: &state.tenant, via: "passkey", name: &oc.name, signed: Some(&signed) };
    let opts = wicket_proxy::SendOpts { priority, in_reply_to, run: None };
    match opmsg::send_as_operator(&ledger, issuer, op, to, "message", json!(text), opts, Some(&waker)) {
        Ok(s) => {
            let state = ledger.lock().map_err(|_| anyhow::anyhow!("ledger lock"))?.receipt(&s.id)?.map(|r| r.state).unwrap_or_default();
            Ok(format!("sent {} to {}: {state}{} (signed with {})", s.id, s.to, if s.woke { ", waking it" } else { "" }, oc.name))
        }
        Err(wicket_proxy::SendError::Refused { id, why, .. }) => bail!("not sent ({id}): {why}"),
        Err(wicket_proxy::SendError::Failed(e)) => bail!("not sent: {e}"),
    }
}
