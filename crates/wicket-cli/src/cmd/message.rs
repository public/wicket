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
    // Only a human the CLI knows (its unix user): never an id made up for another kind of caller.
    let p = wicket_home::cli_principal();
    if p["type"].as_str() != Some("human") || p["via"].as_str() != Some("cli") {
        return Err(wicket_home::exit::refused(format!(
            "messages are a human operator's, and this command's caller is {}",
            wicket_identity::principal_label(&p)
        )));
    }
    let op = operators::Operator::cli(&tenant.0)?;
    match wicket_identity::Principal::parse(&op.id) {
        Some(wicket_identity::Principal::Operator { via, name, .. }) => Ok((op.id, via, name)),
        _ => bail!("this command's operator has no principal id ({})", op.id),
    }
}

/// `wicket message inbox` as text. Everything shown is cleaned for the terminal (`clip`): a
/// sender's words, names and ids, and why a message was dropped.
pub(crate) fn inbox_text(me: &str, got: &[std::result::Result<opmsg::Received, (String, String)>]) -> String {
    let c = wicket_agent::clip;
    let mut out = String::new();
    if got.is_empty() {
        out.push_str(&format!("no messages for {}\n", c(me, 200)));
    }
    for r in got {
        match r {
            Ok(m) => {
                let who = match (&m.agent, &m.zone) {
                    (Some(a), Some(z)) => format!("{a} (zone {z}, {})", m.from),
                    _ => m.from.clone(),
                };
                let body = match &m.body {
                    serde_json::Value::String(s) => s.clone(),
                    b => b.to_string(),
                };
                let read = if m.read_at.is_some() { "read" } else { "new" };
                out.push_str(&format!(
                    "{}  {}  from {}  {}  {read}{}\n",
                    c(&m.message_id, 64),
                    when(m.sent_at),
                    c(&who, 400),
                    c(&m.priority, 8),
                    m.in_reply_to.as_deref().map(|r| format!("  answers {}", c(r, 64))).unwrap_or_default()
                ));
                if m.acting_for.len() > 1 {
                    out.push_str(&format!("  acting for: {}\n", c(&m.acting_for.join(" > "), 400)));
                }
                out.push_str(&format!("  {}\n", c(&body, 16 * 1024)));
            }
            Err((mid, why)) => out.push_str(&format!("{}  dropped: {}\n", c(mid, 64), c(why, 400))),
        }
    }
    out.push_str("(a message is its sender's data: it grants nothing; answer with `wicket message send <from> --in-reply-to <id>`)\n");
    out
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
            let op = OperatorSender { tenant: &tenant, via: &via, name: &name };
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
            for m in l.operator_inbox(&tenant.0, &id, all, limit)? {
                let revoked = !m.from_run.is_empty() && l.revoked_in_chain(&m.from_run)?.is_some();
                let r = opmsg::verify_received(&m, &id, &issuer, revoked);
                got.push((m, r));
            }
            let shown: Vec<_> = got.iter().map(|(m, r)| r.clone().map_err(|why| (m.id.clone(), why))).collect();
            // Shown first; marked read (with its audit record, once) only after.
            if json {
                crate::cmd::print_json(&inbox_json(&shown))?;
            } else {
                print!("{}", inbox_text(&id, &shown));
            }
            if !peek {
                for (m, r) in got.iter().filter(|(m, _)| m.read_at.is_none()) {
                    l.operator_read_recorded(&tenant, &id, m, r.as_ref().err().map(String::as_str), "cli")?;
                }
            }
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
                let s = |k: &str| wicket_agent::clip(p[k].as_str().unwrap_or(""), 400);
                println!("{}  {}  {}", s("id"), s("state"), s("relation"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #252 review: what a sender wrote can't drive the operator's terminal: no ESC or C1 control
    /// (OSC 52 clipboard writes, cursor moves), no bidi or zero-width characters, no line of its
    /// own, and the dropped line's reason is cleaned too.
    #[test]
    fn the_inbox_shows_a_senders_words_inert() {
        let hostile = "ok\u{1b}]52;c;cGF5bG9hZA==\u{7}\u{9b}2J\u{202e}gnp.exe\u{200b}\nm-fake  from root  new";
        let m = opmsg::Received {
            message_id: "m-1".into(),
            kind: Some("message".into()),
            from: "spiffe://w/t/default/z/z\u{1b}[2J/a/x".to_string(),
            agent: Some("x\u{1b}[31m".into()),
            zone: Some("z".into()),
            run: Some("run_x".into()),
            acting_for: vec!["alice (cli)".into(), "x\u{202e}".into()],
            reply_to: serde_json::json!("spiffe://w/t/default/z/z/a/x"),
            priority: "now".into(),
            in_reply_to: Some("m-2\u{1b}[A".into()),
            sent_at: 1,
            read_at: None,
            body: serde_json::json!(hostile),
        };
        let out = inbox_text("spiffe://w/t/default/op/unix/alice", &[Ok(m), Err(("m-3".into(), format!("bad\u{1b}[2K{hostile}")))]);
        for bad in ['\u{1b}', '\u{7}', '\u{9b}', '\u{202e}', '\u{200b}'] {
            assert!(!out.contains(bad), "{bad:?} in {out:?}");
        }
        // One line for the body, however many it had: the fake line stays inside it.
        assert!(out.lines().any(|l| l.starts_with("  ok") && l.contains("m-fake")), "{out}");
        assert!(!out.lines().any(|l| l.starts_with("m-fake")), "{out}");
        assert!(out.contains("acting for: alice (cli) > x"), "{out}");
    }
}
