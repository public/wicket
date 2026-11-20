//! Humans in the agent-to-agent protocol (#252): an operator sends and receives the same signed
//! envelopes an agent does, under the same rules (everything is a principal, design §2).
//!
//! - **An agent writes to an operator** it acts for (its identity's principal, the human at the
//!   root of its chain), or answers one that wrote to it (`in_reply_to`). Any other operator is
//!   refused, with a receipt that says so, as a peer outside `accept_from` is. The message waits in
//!   the operator's inbox ([`wicket_store::Ledger::operator_inbox`]).
//! - **An operator writes to an agent** that acts for it, whose `accept_from` names it, or that
//!   wrote to it (a reply). wicket signs the envelope with a short-lived operator identity
//!   ([`wicket_identity::Issuer::issue_operator`]) bound to a fresh key, as it does an agent's.
//!   Who the operator is comes from how wicket authenticated them (the CLI's peer credentials, the
//!   console's passkey), never from the request.
//!
//! A message grants nothing either way: an operator's authority over an agent is its prompts
//! (`wicket session`) and its decisions, not its messages, which the agent reads as data.

use crate::{route, RunCtx, RunIdentity, SendError, SendOpts, Sent, Waker, MAX_MESSAGE_BYTES};
use serde_json::json;
use std::sync::Mutex;
use wicket_core::TenantId;
use wicket_identity::Principal;
use wicket_store::Ledger;

/// How long an operator's identity document for one message is valid (it signs only that one).
const OPERATOR_IDENTITY_SECS: i64 = 300;

/// Whether the agent whose identity document is `jws` acts for `operator`: its principal (the
/// human at the root of its chain) is that operator. Read from the document wicket issued, so
/// verified against the issuer at its issue time.
fn acts_for(jws: &str, issued_at: i64, issuer: &wicket_identity::VerifyingKey, operator: &str) -> bool {
    wicket_identity::verify_identity(jws, issuer, issued_at)
        .is_ok_and(|c| c.principal.get("sub").and_then(|s| s.as_str()) == Some(operator))
}

/// The longest `in_reply_to` taken: a message id wicket makes (`m-` and a ULID) is 28 bytes.
const MAX_REPLY_ID: usize = 64;

/// Whether this message answers one (`in_reply_to`), checked whatever else lets it go (#252
/// review): it must name a message `other` sent `me` in `tenant`. So the id a recipient is shown is
/// one wicket recorded between those two, never text the sender chose. Err: it names none.
fn reply(l: &Ledger, tenant: &str, in_reply_to: Option<&str>, other: &str, me: &str) -> std::result::Result<bool, SendError> {
    let Some(m) = in_reply_to else { return Ok(false) };
    let shaped = m.len() <= MAX_REPLY_ID && m.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let found = shaped
        && l.message_row(m).map_err(|e| e.to_string())?.is_some_and(|r| {
            r.tenant == tenant && r.to_principal.as_deref() == Some(me) && r.from_principal.as_deref() == Some(other)
        });
    if !found {
        let shown = if shaped { m.to_string() } else { "(not a message id)".into() };
        return Err(format!("in_reply_to {shown} is not a message {other} sent you").into());
    }
    Ok(true)
}

/// [`RunCtx::send`] to an operator: allowed to the one the agent acts for, or as a reply.
#[allow(clippy::too_many_arguments)]
pub(crate) fn agent_to_operator(
    ctx: &RunCtx,
    me: &RunIdentity,
    l: &mut Ledger,
    to: &str,
    kind: &str,
    body: serde_json::Value,
    opts: SendOpts,
    size: usize,
    now: i64,
) -> std::result::Result<Sent, SendError> {
    let td = me.claims.iss.strip_prefix("spiffe://").unwrap_or_default();
    match Principal::parse(to) {
        Some(p @ Principal::Operator { .. }) if p.tenant() == ctx.tenant.0 && p.trust_domain() == td => {}
        _ => return Err(format!("no operator {to} in this tenant").into()),
    }
    let sub = me.claims.sub.as_str();
    let yours = me.claims.principal.get("sub").and_then(|s| s.as_str());
    // The one rule (`message::relation`): the operator it acts for stands where a parent does; an
    // operator has no accept_from, so any other may only be answered.
    let none: &[&str] = &[];
    let facts = wicket_core::message::Facts {
        to_child: false,
        to_parent: yours == Some(to),
        accept_from: none,
        sender_zone: &ctx.zone.name,
        sender: Some(sub),
        reply: reply(l, &ctx.tenant.0, opts.in_reply_to, to, sub)?,
    };
    let relation = match wicket_core::message::relation(&facts) {
        Some(wicket_core::message::Relation::Parent) => "operator",
        Some(r) => r.as_str(),
        None => "",
    };
    let id = format!("m-{}", wicket_core::new_ulid().to_string().to_lowercase());
    if relation.is_empty() {
        let why = match yours {
            Some(y) => format!("{to} is not the operator you act for ({y}): you may write to it, or answer an operator that wrote to you"),
            None => format!("{to} is an operator you don't act for: you may answer an operator that wrote to you"),
        };
        l.refuse_message(&id, &ctx.tenant.0, &ctx.run.0, Some(sub), to, &why).map_err(|e| e.to_string())?;
        l.audit(
            &ctx.tenant,
            Some(&ctx.run),
            "message.refused",
            &json!({ "id": id, "kind": kind, "from": sub, "to": to, "why": "operator", "bytes": size }),
        )
        .map_err(|e| format!("not sent: the audit record could not be written ({e})"))?;
        return Err(SendError::Refused { id, to: to.to_string(), why });
    }
    let payload = json!({
        "jti": id, "iat": now, "kind": kind, "to": to, "body": body,
        "reply_to": sub, "priority": opts.priority.as_str(), "in_reply_to": opts.in_reply_to,
    });
    let env = wicket_identity::sign_envelope(&me.key, &me.jws, &payload);
    let meta = wicket_store::MessageMeta { from_principal: Some(sub), priority: opts.priority, in_reply_to: opts.in_reply_to, operator: false };
    l.post_message(&id, &ctx.tenant, &ctx.run.0, to, None, &env, &meta).map_err(|e| e.to_string())?;
    let audited = l.audit(
        &ctx.tenant,
        Some(&ctx.run),
        "message",
        &json!({
            "id": id, "kind": kind, "from": sub, "to": to, "to_run": null, "relation": relation, "bytes": size,
            "held": false, "priority": opts.priority.as_str(), "in_reply_to": opts.in_reply_to,
        }),
    );
    if let Err(e) = audited {
        let _ = l.withdraw_message(&id);
        return Err(format!("not sent: the audit record could not be written ({e})").into());
    }
    Ok(Sent { id, to: to.to_string(), run: None, woke: false })
}

/// An operator, as wicket authenticated it: `via` (`unix` for the CLI, `passkey` for the console)
/// and its name there.
#[derive(Clone, Copy, Debug)]
pub struct OperatorSender<'a> {
    pub tenant: &'a TenantId,
    pub via: &'a str,
    pub name: &'a str,
    /// What the operator signed to send it, if anything (the console's passkey assertion): kept
    /// on the message's audit record.
    pub signed: Option<&'a serde_json::Value>,
}

impl OperatorSender<'_> {
    /// The operator's principal id in `issuer`'s trust domain.
    pub fn id(&self, issuer: &wicket_identity::Issuer) -> String {
        wicket_identity::operator_id(&issuer.trust_domain, &self.tenant.0, self.via, self.name)
    }
}

/// Sends a signed message from operator `op` to agent `to` (its principal id): allowed when the
/// agent acts for the operator, its `accept_from` names the operator, or it answers a message the
/// agent sent the operator (`in_reply_to`). Otherwise refused on the record, with a receipt that
/// says so. Routed as an agent's message is: to the agent's live run, else held (a hibernated
/// agent is woken by `waker`).
#[allow(clippy::too_many_arguments)]
pub fn send_as_operator(
    ledger: &Mutex<Ledger>,
    issuer: &wicket_identity::Issuer,
    op: OperatorSender,
    to: &str,
    kind: &str,
    body: serde_json::Value,
    opts: SendOpts,
    waker: Option<&Waker>,
) -> std::result::Result<Sent, SendError> {
    let me = op.id(issuer);
    let tenant = op.tenant;
    let size = body.to_string().len();
    if size > MAX_MESSAGE_BYTES {
        return Err(format!("message body is {size} bytes; the limit is {MAX_MESSAGE_BYTES}").into());
    }
    match Principal::parse(to) {
        Some(p @ Principal::Agent { .. }) if p.tenant() == tenant.0 && p.trust_domain() == issuer.trust_domain => {}
        Some(Principal::Operator { .. }) => return Err(format!("{to} is an operator: operators write to agents, not to each other, for now").into()),
        Some(_) => return Err(format!("no agent {to}: none has run as it in this tenant").into()),
        None => {
            return Err(format!(
                "{to:?} is not a principal: name an agent by its identity (spiffe://<domain>/t/<tenant>/z/<zone>/a/<agent>, as `wicket message principals` shows it)"
            )
            .into())
        }
    }
    let now = wicket_store::now();
    let mut l = ledger.lock().map_err(|_| "ledger lock")?;
    let rec = match l.principal_identity(&tenant.0, to).map_err(|e| e.to_string())? {
        Some(r) if r.tenant == tenant.0 => r,
        _ => return Err(format!("no agent {to}: none has run as it in this tenant").into()),
    };
    // The one rule (`message::relation`): an agent that acts for the operator is where a child is;
    // else its accept_from must name the operator's principal (an operator has no zone, and an
    // empty entry, which no manifest may have, names nothing), else it must be a reply.
    let accept_from: Vec<&str> = rec.accept_from.iter().map(String::as_str).filter(|e| !e.is_empty()).collect();
    let facts = wicket_core::message::Facts {
        to_child: acts_for(&rec.jws, rec.issued_at, &issuer.verifying_key(), &me),
        to_parent: false,
        accept_from: &accept_from,
        sender_zone: "",
        sender: Some(&me),
        reply: reply(&l, &tenant.0, opts.in_reply_to, to, &me)?,
    };
    let relation = match wicket_core::message::relation(&facts) {
        Some(wicket_core::message::Relation::Child) => "operator",
        Some(r) => r.as_str(),
        None => "",
    };
    let id = format!("m-{}", wicket_core::new_ulid().to_string().to_lowercase());
    if relation.is_empty() {
        let why = format!("{to} does not accept messages from you ({me}): it doesn't act for you and its accept_from doesn't list you");
        l.refuse_message(&id, &tenant.0, "", Some(&me), to, &why).map_err(|e| e.to_string())?;
        l.audit(tenant, None, "message.refused", &json!({ "id": id, "kind": kind, "from": me, "to": to, "why": "accept_from", "bytes": size }))
            .map_err(|e| format!("not sent: the audit record could not be written ({e})"))?;
        return Err(SendError::Refused { id, to: to.to_string(), why });
    }
    let (to_run, wake) = route(&l, &tenant.0, to, &rec, None, waker.is_some())?;
    let key = wicket_identity::AgentKey::generate();
    let doc = issuer.issue_operator(&tenant.0, op.via, op.name, now, OPERATOR_IDENTITY_SECS, &key.public());
    let payload = json!({
        "jti": id, "iat": now, "kind": kind, "to": to, "body": body,
        "reply_to": me, "priority": opts.priority.as_str(), "in_reply_to": opts.in_reply_to,
    });
    let env = wicket_identity::sign_operator_envelope(&key, &doc, &payload);
    let meta = wicket_store::MessageMeta { from_principal: Some(&me), priority: opts.priority, in_reply_to: opts.in_reply_to, operator: true };
    let routed = l.post_message(&id, tenant, "", to, to_run.as_deref(), &env, &meta).map_err(|e| e.to_string())?;
    let mut rec = json!({
        "id": id, "kind": kind, "from": me, "to": to, "to_run": routed, "relation": relation, "bytes": size,
        "wakes": wake, "held": routed.is_none(), "priority": opts.priority.as_str(), "in_reply_to": opts.in_reply_to,
        "via": op.via,
    });
    if let Some(s) = op.signed {
        rec["signed"] = s.clone();
    }
    let audited = l.audit(tenant, None, "message", &rec);
    if let Err(e) = audited {
        let _ = l.withdraw_message(&id);
        return Err(format!("not sent: the audit record could not be written ({e})").into());
    }
    drop(l);
    if let (Some(agent), Some(w)) = (&wake, waker) {
        w(agent, &format!("a message from {me}"));
    }
    Ok(Sent { id, to: to.to_string(), run: routed, woke: wake.is_some() })
}

/// One message in an operator's inbox, verified: who sent it (as wicket verified it), and its
/// body, which is the sender's data.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Received {
    pub message_id: String,
    pub kind: Option<String>,
    /// The sender's principal id, from its verified envelope.
    pub from: String,
    /// The sender's agent name, zone and run, for an agent (null for an operator).
    pub agent: Option<String>,
    pub zone: Option<String>,
    pub run: Option<String>,
    /// The chain the sender acts for ("alice (cli)", "lead", ...).
    pub acting_for: Vec<String>,
    pub reply_to: serde_json::Value,
    pub priority: String,
    pub in_reply_to: Option<String>,
    pub sent_at: i64,
    pub read_at: Option<i64>,
    pub body: serde_json::Value,
}

/// Verifies a message in operator `me`'s inbox: signed by a sender wicket issued an identity for,
/// valid when wicket recorded it, addressed to `me` with the id it was recorded under, and sent by
/// the run the ledger says sent it. Err says why it is dropped.
pub fn verify_received(
    m: &wicket_store::InboxMessage,
    me: &str,
    issuer: &wicket_identity::VerifyingKey,
    sender_revoked: bool,
) -> std::result::Result<Received, String> {
    let (sender, payload) = wicket_identity::verify_any_envelope(&m.envelope, issuer, m.created_at)
        .map_err(|e| format!("its signature does not verify at the time it was sent ({e})"))?;
    let iat = payload.get("iat").and_then(|v| v.as_i64()).unwrap_or(i64::MIN);
    if (iat - m.created_at).abs() > wicket_identity::CLOCK_SKEW {
        return Err(format!("it claims to be sent at {iat} but was recorded at {}", m.created_at));
    }
    if sender_revoked {
        return Err("the sender's identity has been revoked".into());
    }
    let (agent, zone, run, chain) = match &sender {
        wicket_identity::Sender::Agent(c) if c.run == m.from_run => (Some(c.agent.clone()), Some(c.zone.clone()), Some(c.run.clone()), c.chain()),
        wicket_identity::Sender::Operator(c) if m.from_run.is_empty() => (None, None, None, vec![format!("{} ({})", c.name, c.via)]),
        _ => return Err("its envelope does not match its delivery".into()),
    };
    if payload.get("to").and_then(|v| v.as_str()) != Some(me)
        || payload.get("jti").and_then(|v| v.as_str()) != Some(m.id.as_str())
        || m.from_principal.as_deref().is_some_and(|p| p != sender.principal())
    {
        return Err("its envelope does not match its delivery".into());
    }
    Ok(Received {
        message_id: m.id.clone(),
        kind: payload.get("kind").and_then(|k| k.as_str()).map(String::from),
        from: sender.principal().to_string(),
        agent,
        zone,
        run,
        acting_for: chain,
        reply_to: payload.get("reply_to").cloned().unwrap_or_else(|| json!(sender.principal())),
        priority: m.priority.clone(),
        in_reply_to: m.in_reply_to.clone(),
        sent_at: m.created_at,
        read_at: m.read_at,
        body: payload.get("body").cloned().unwrap_or(serde_json::Value::Null),
    })
}
