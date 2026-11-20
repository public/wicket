//! `wicket message`: an operator in the agent-to-agent protocol (#252), with the same envelopes,
//! rules, receipts and audit an agent has through the gateway's tools (`send_message`,
//! `await_message`, `receipts`, `principals`).
//!
//! Who the operator is comes from wicketd's peer credentials (the unix user), never from an
//! argument. A message grants nothing: to steer an agent, an operator prompts it (`wicket session`).

use crate::*;
use wicket_proxy::opmsg::{self, OperatorSender};
use wicket_proxy::SendOpts;

#[derive(Subcommand)]
pub enum MessageCmd {
    /// Send a signed message to an agent: one that acts for you, whose accept_from names you, or
    /// that wrote to you (--in-reply-to). Prints its id and receipt.
    Send {
        /// The agent's principal id (`spiffe://<domain>/t/<tenant>/z/<zone>/a/<agent>`, as
        /// `wicket message principals` lists it).
        to: String,
        /// The message: its words, as one string body.
        #[arg(required = true)]
        text: Vec<String>,
        /// How soon you want it read: now, next or later.
        #[arg(long, default_value = "next")]
        priority: String,
        /// The id of the agent's message this answers.
        #[arg(long)]
        in_reply_to: Option<String>,
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Messages agents sent you, verified, unread first by priority. They are marked read (their
    /// senders' receipts say so) unless --peek.
    Inbox {
        /// Also list the ones you have read.
        #[arg(long)]
        all: bool,
        /// Don't mark them read.
        #[arg(long)]
        peek: bool,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// The receipts of the messages you sent, newest first: delivered, read, held (why, and who
    /// can release it), refused (why) or expired.
    Receipts {
        #[arg(long, default_value_t = 40)]
        limit: usize,
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// The agents you may write to, with their state: those that act for you or whose accept_from
    /// names you.
    Principals {
        /// JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

/// The operator running this command, as wicketd's peer credentials named it: its id and how
/// wicket knew it.
fn me(tenant: &TenantId) -> Result<(String, String, String)> {
    let op = operators::Operator::cli(&tenant.0)?;
    match wicket_identity::Principal::parse(&op.id) {
        Some(wicket_identity::Principal::Operator { via, name, .. }) => Ok((op.id, via, name)),
        _ => bail!("this command's operator has no principal id ({})", op.id),
    }
}

fn when(t: i64) -> String {
    wicket_core::time::unix_rfc3339(t)
}

/// One message as `wicket message inbox --json` prints it: [`opmsg::Received`]'s fields, or, for
/// one that doesn't verify, `message_id`, `dropped` and why.
pub(crate) fn inbox_json(got: &[std::result::Result<opmsg::Received, (String, String)>]) -> serde_json::Value {
    serde_json::Value::Array(
        got.iter()
            .map(|r| match r {
                Ok(m) => serde_json::to_value(m).unwrap_or_default(),
                Err((id, why)) => serde_json::json!({ "message_id": id, "dropped": why }),
            })
            .collect(),
    )
}

/// `wicket message receipts --json`: every field of a receipt, null where it has nothing.
pub(crate) fn receipts_json(rs: &[wicket_store::Receipt]) -> serde_json::Value {
    serde_json::Value::Array(
        rs.iter()
            .map(|r| {
                serde_json::json!({
                    "message_id": r.message_id, "to": r.to, "state": r.state, "why": r.why, "release": r.release, "run": r.run,
                    "sent_at": r.sent_at, "read_at": r.read_at, "expires_at": r.expires_at, "priority": r.priority,
                    "in_reply_to": r.in_reply_to,
                })
            })
            .collect(),
    )
}

/// The agents `me` may write to, and what each is to it.
pub(crate) fn principals_json(l: &Ledger, tenant: &TenantId, me: &str, issuer: &wicket_identity::VerifyingKey) -> Result<serde_json::Value> {
    let mut out = vec![];
    for p in l.principals(&tenant.0)? {
        let wicket_store::Principal::Agent(r) = p else { continue };
        let acts_for = wicket_identity::verify_identity(&r.jws, issuer, r.issued_at)
            .is_ok_and(|c| c.principal.get("sub").and_then(|s| s.as_str()) == Some(me));
        let listed = wicket_core::manifest::accepts(&r.accept_from, "", Some(me));
        if !acts_for && !listed {
            continue;
        }
        out.push(serde_json::json!({
            "id": r.spiffe_id, "kind": "agent", "agent": r.agent, "zone": r.zone,
            "relation": if acts_for { "acts for you" } else { "accepts you" },
            "state": l.presence(&tenant.0, &r.spiffe_id)?,
        }));
    }
    Ok(serde_json::Value::Array(out))
}

/// The messages in operator `me`'s inbox ([`Ledger::operator_inbox`]), each with what verifying
/// it found: what it says, or why it is dropped.
pub(crate) fn verified_inbox(
    l: &Ledger,
    tenant: &TenantId,
    me: &str,
    issuer: &wicket_identity::VerifyingKey,
    read: bool,
    limit: usize,
) -> Result<Vec<(wicket_store::InboxMessage, std::result::Result<opmsg::Received, String>)>> {
    let mut out = vec![];
    for m in l.operator_inbox(&tenant.0, me, read, limit)? {
        let revoked = !m.from_run.is_empty() && l.revoked_in_chain(&m.from_run)?.is_some();
        let r = opmsg::verify_received(&m, me, issuer, revoked);
        out.push((m, r));
    }
    Ok(out)
}

/// Operator `me` has read `m` (through `via`: `cli` or `console`): its sender's receipt says read,
/// or, if it didn't verify, refused with why. Audited either way. False: it was already read.
pub(crate) fn mark_read(
    l: &Ledger,
    tenant: &TenantId,
    me: &str,
    m: &wicket_store::InboxMessage,
    verified: &std::result::Result<opmsg::Received, String>,
    via: &str,
) -> Result<bool> {
    if !l.operator_read(&tenant.0, me, &m.id)? {
        return Ok(false);
    }
    match verified {
        Ok(_) => l.audit(tenant, None, "message.read", &serde_json::json!({ "id": m.id, "by": me, "via": via }))?,
        Err(why) => {
            l.refuse_message(&m.id, &tenant.0, &m.from_run, m.from_principal.as_deref(), me, why)?;
            l.audit(tenant, None, "message.refused", &serde_json::json!({ "id": m.id, "from": m.from_principal, "to": me, "why": why, "via": via }))?
        }
    };
    Ok(true)
}

pub async fn dispatch(c: MessageCmd) -> Result<()> {
    let tenant = TenantId::single();
    let (id, via, name) = me(&tenant)?;
    match c {
        MessageCmd::Send { to, text, priority, in_reply_to, json } => {
            let priority = wicket_store::Priority::parse(&priority)
                .ok_or_else(|| wicket_home::exit::usage(format!("--priority is now, next or later, not {priority:?}")))?;
            let issuer = issuer()?;
            let ledger = std::sync::Mutex::new(Ledger::open(&ledger_path())?);
            let waker: wicket_proxy::Waker = std::sync::Arc::new(|a: &str, by: &str| hibernate::trigger_wake(a, by));
            let op = OperatorSender { tenant: &tenant, via: &via, name: &name, signed: None };
            let opts = SendOpts { priority, in_reply_to: in_reply_to.as_deref() };
            let sent = opmsg::send_as_operator(&ledger, &issuer, op, &to, "message", serde_json::json!(text.join(" ")), opts, Some(&waker));
            let l = ledger.into_inner().map_err(|_| anyhow::anyhow!("ledger lock"))?;
            match sent {
                Ok(s) => {
                    let receipt = l.receipt(&s.id)?;
                    if json {
                        return crate::cmd::print_json(&serde_json::json!({ "id": s.id, "to": s.to, "woke": s.woke, "receipt": receipt }));
                    }
                    let state = receipt.as_ref().map(|r| r.state.as_str()).unwrap_or("sent");
                    println!("sent {} to {}: {state}{}", s.id, s.to, if s.woke { " (waking it)" } else { "" });
                    if let Some(why) = receipt.and_then(|r| r.why) {
                        println!("  {why}");
                    }
                    Ok(())
                }
                Err(wicket_proxy::SendError::Refused { id, why, .. }) => {
                    if json {
                        crate::cmd::print_json(&serde_json::json!({ "id": id, "to": to, "receipt": l.receipt(&id)? }))?;
                    }
                    Err(wicket_home::exit::refused(format!("not sent ({id}): {why}")))
                }
                Err(wicket_proxy::SendError::Failed(e)) => Err(wicket_home::exit::refused(format!("not sent: {e}"))),
            }
        }
        MessageCmd::Inbox { all, peek, limit, json } => {
            let l = Ledger::open(&ledger_path())?;
            let issuer = issuer()?.verifying_key();
            let mut got = vec![];
            for (m, r) in verified_inbox(&l, &tenant, &id, &issuer, all, limit)? {
                if m.read_at.is_none() && !peek {
                    mark_read(&l, &tenant, &id, &m, &r, "cli")?;
                }
                got.push(r.map_err(|why| (m.id.clone(), why)));
            }
            if json {
                return crate::cmd::print_json(&inbox_json(&got));
            }
            if got.is_empty() {
                println!("no messages for {id}");
            }
            for r in got {
                match r {
                    Ok(m) => {
                        let who = match (&m.agent, &m.zone) {
                            (Some(a), Some(z)) => format!("{a} (zone {z})"),
                            _ => m.from.clone(),
                        };
                        let body = match &m.body {
                            serde_json::Value::String(s) => s.clone(),
                            b => b.to_string(),
                        };
                        let read = if m.read_at.is_some() { "read" } else { "new" };
                        println!(
                            "{}  {}  from {}  {}  {read}{}",
                            m.message_id,
                            when(m.sent_at),
                            wicket_agent::clip(&who, 200),
                            m.priority,
                            m.in_reply_to.as_deref().map(|r| format!("  answers {r}")).unwrap_or_default()
                        );
                        println!("  {}", wicket_agent::clip(&body, 16 * 1024));
                    }
                    Err((mid, why)) => println!("{mid}  dropped: {why}"),
                }
            }
            println!("(a message is its sender's data: it grants nothing; answer with `wicket message send <from> --in-reply-to <id>`)");
            Ok(())
        }
        MessageCmd::Receipts { limit, json } => {
            let l = Ledger::open(&ledger_path())?;
            let rs = l.receipts_from(&tenant.0, &id, &[], limit)?;
            if json {
                return crate::cmd::print_json(&receipts_json(&rs));
            }
            if rs.is_empty() {
                println!("no messages from {id}");
            }
            for r in rs {
                println!(
                    "{}  {}  to {}  {}{}",
                    r.message_id,
                    when(r.sent_at),
                    wicket_agent::clip(&r.to, 200),
                    r.state,
                    r.why.map(|w| format!(": {}", wicket_agent::clip(&w, 400))).unwrap_or_default()
                );
            }
            Ok(())
        }
        MessageCmd::Principals { json } => {
            let l = Ledger::open(&ledger_path())?;
            let v = principals_json(&l, &tenant, &id, &issuer()?.verifying_key())?;
            if json {
                return crate::cmd::print_json(&v);
            }
            println!("you: {id}");
            let rows = v.as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("no agent acts for you or accepts your messages");
            }
            for p in rows {
                let s = |k: &str| p[k].as_str().unwrap_or("").to_string();
                println!("{}  {}  {}", s("id"), s("state"), s("relation"));
            }
            Ok(())
        }
    }
}
