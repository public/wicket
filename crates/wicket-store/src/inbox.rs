//! An operator's inbox (#252): the messages agents sent to a human principal.
//!
//! An operator has no run, so a message to one is recorded for its principal alone (`to_run` is
//! empty, as a held message's is) and stays there: no run of an agent takes it, since an agent's
//! identity never names an operator's principal. The operator reads it over the CLI or the console
//! ([`Ledger::operator_inbox`]); reading marks it read ([`Ledger::operator_read`]), which is what its
//! sender's receipt says from then on. A message an operator hasn't read in
//! [`crate::MESSAGE_HOLD_SECS`] reads as expired, as any held message does.

use crate::{now, receipts::INBOX_ORDER, Ledger, Result, MESSAGE_HOLD_SECS, PEER};
use rusqlite::params;

/// Whether `id` names an operator (`spiffe://<td>/t/<tenant>/op/<via>/<name>`). The store doesn't
/// parse principals otherwise; `wicket_identity::Principal::parse` is the full check.
pub(crate) fn is_operator(id: &str) -> bool {
    let segs: Vec<&str> = id.strip_prefix("spiffe://").unwrap_or("").split('/').collect();
    matches!(segs.as_slice(), [_, "t", _, "op", _, _])
}

/// One message in an operator's inbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxMessage {
    pub id: String,
    /// The sender's run (empty for another operator's message).
    pub from_run: String,
    pub from_principal: Option<String>,
    pub envelope: String,
    /// When wicket recorded it: the time its sender's identity must have been valid.
    pub created_at: i64,
    pub read_at: Option<i64>,
    pub priority: String,
    pub in_reply_to: Option<String>,
}

impl Ledger {
    /// The messages to operator `principal` in `tenant`, unread first by priority then oldest, and
    /// (with `read`) those it has read after them, newest first. At most `limit`. Expired messages
    /// are left out.
    pub fn operator_inbox(&self, tenant: &str, principal: &str, read: bool, limit: usize) -> Result<Vec<InboxMessage>> {
        let sql = format!(
            "SELECT id, from_run, from_principal, envelope, created_at, delivered_at, priority, in_reply_to FROM messages
              WHERE tenant = ?1 AND to_principal = ?2 AND to_run = '' AND {PEER}
                AND (delivered_at IS NOT NULL OR created_at >= ?3) AND (?4 OR delivered_at IS NULL)
              ORDER BY delivered_at IS NOT NULL, CASE WHEN delivered_at IS NULL THEN 0 ELSE -delivered_at END, {INBOX_ORDER}
              LIMIT ?5"
        );
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(params![tenant, principal, now() - MESSAGE_HOLD_SECS, read, limit as i64], |r| {
            Ok(InboxMessage {
                id: r.get(0)?,
                from_run: r.get(1)?,
                from_principal: r.get(2)?,
                envelope: r.get(3)?,
                created_at: r.get(4)?,
                read_at: r.get(5)?,
                priority: r.get::<_, Option<String>>(6)?.unwrap_or_else(|| "next".into()),
                in_reply_to: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Operator `principal` has read message `id`: its sender's receipt says read. False: no such
    /// unread message to it (already read, expired, or someone else's).
    pub fn operator_read(&self, tenant: &str, principal: &str, id: &str) -> Result<bool> {
        let n = self.conn.execute(
            &format!("UPDATE messages SET delivered_at = ?4
              WHERE id = ?1 AND tenant = ?2 AND to_principal = ?3 AND to_run = '' AND {PEER}
                AND delivered_at IS NULL AND created_at >= ?5"),
            params![id, tenant, principal, now(), now() - MESSAGE_HOLD_SECS],
        )?;
        Ok(n == 1)
    }
}

impl Ledger {
    /// [`Ledger::operator_read`] and its audit record in one transaction (#252 review), so a read
    /// is never on the record without its audit, nor audited twice when two inboxes read at once.
    /// `refused`: the message didn't verify, and its receipt says refused, with why. `via`: `cli` or
    /// `console`. False: it was already read (nothing is recorded).
    pub fn operator_read_recorded(
        &self,
        tenant: &wicket_core::TenantId,
        principal: &str,
        m: &InboxMessage,
        refused: Option<&str>,
        via: &str,
    ) -> Result<bool> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let r = (|| -> Result<bool> {
            if !self.operator_read(&tenant.0, principal, &m.id)? {
                return Ok(false);
            }
            match refused {
                None => self.audit(tenant, None, "message.read", &serde_json::json!({ "id": m.id, "by": principal, "via": via }))?,
                Some(why) => {
                    self.refuse_message(&m.id, &tenant.0, &m.from_run, m.from_principal.as_deref(), principal, why)?;
                    self.audit(
                        tenant,
                        None,
                        "message.refused",
                        &serde_json::json!({ "id": m.id, "from": m.from_principal, "to": principal, "why": why, "via": via }),
                    )?
                }
            };
            Ok(true)
        })();
        let _ = self.conn.execute_batch(if r.is_ok() { "COMMIT" } else { "ROLLBACK" });
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MessageMeta, Priority};
    use wicket_core::TenantId;

    const OP: &str = "spiffe://x/t/default/op/unix/alice";
    const AGENT: &str = "spiffe://x/t/default/z/z/a/lead";

    #[test]
    fn operator_ids_are_told_from_agents() {
        assert!(is_operator(OP));
        assert!(!is_operator(AGENT) && !is_operator("run_1") && !is_operator("spiffe://x/t/default/op/unix"));
    }

    /// #252: a message to an operator waits in its inbox, delivered on its receipt, until it reads
    /// it; nobody else's read counts, and its sender's receipt follows.
    #[test]
    fn an_operator_reads_its_inbox_and_its_senders_receipts_follow() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let meta = |p| MessageMeta { from_principal: Some(AGENT), priority: p, in_reply_to: None, operator: false };
        assert_eq!(l.post_message("m-1", &t, "run_lead", OP, None, "e1", &meta(Priority::Later)).unwrap(), None);
        l.post_message("m-2", &t, "run_lead", OP, None, "e2", &meta(Priority::Now)).unwrap();
        l.post_message("m-3", &t, "run_lead", "spiffe://x/t/default/op/unix/bob", None, "e3", &meta(Priority::Next)).unwrap();
        let r = l.receipt("m-1").unwrap().unwrap();
        assert_eq!((r.state.as_str(), r.run, r.why), ("delivered", None, None));
        let ids = |v: Vec<InboxMessage>| v.into_iter().map(|m| m.id).collect::<Vec<_>>();
        assert_eq!(ids(l.operator_inbox(&t.0, OP, false, 10).unwrap()), ["m-2", "m-1"], "by priority, and only its own");
        assert!(!l.operator_read(&t.0, "spiffe://x/t/default/op/unix/bob", "m-1").unwrap(), "someone else's");
        assert!(!l.operator_read("other", OP, "m-1").unwrap(), "another tenant's");
        assert!(l.operator_read(&t.0, OP, "m-1").unwrap());
        assert!(!l.operator_read(&t.0, OP, "m-1").unwrap(), "once");
        let r = l.receipt("m-1").unwrap().unwrap();
        assert!(r.state == "read" && r.read_at.is_some(), "{r:?}");
        assert_eq!(ids(l.operator_inbox(&t.0, OP, false, 10).unwrap()), ["m-2"]);
        assert_eq!(ids(l.operator_inbox(&t.0, OP, true, 10).unwrap()), ["m-2", "m-1"], "read ones after");
        // An agent's run never takes an operator's message.
        assert!(l.take_message("run_lead").unwrap().is_none());
        // Unread past the hold: expired, gone from the inbox, and not readable.
        l.conn.execute("UPDATE messages SET created_at = created_at - ?2 WHERE id = ?1", params!["m-2", MESSAGE_HOLD_SECS + 1]).unwrap();
        assert_eq!(l.receipt("m-2").unwrap().unwrap().state, "expired");
        assert_eq!(ids(l.operator_inbox(&t.0, OP, true, 10).unwrap()), ["m-1"]);
        assert!(!l.operator_read(&t.0, OP, "m-2").unwrap());
    }

    /// #252 review: a read and its audit record go together, once; a refusal says why.
    #[test]
    fn a_read_is_recorded_with_its_audit_once() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let meta = MessageMeta { from_principal: Some(AGENT), ..Default::default() };
        l.post_message("m-1", &t, "run_lead", OP, None, "e1", &meta).unwrap();
        l.post_message("m-2", &t, "run_lead", OP, None, "e2", &meta).unwrap();
        let inbox = l.operator_inbox(&t.0, OP, false, 10).unwrap();
        let kinds = |l: &Ledger| l.audit_tail(10).unwrap().into_iter().map(|r| r.2).collect::<Vec<_>>();
        assert!(l.operator_read_recorded(&t, OP, &inbox[0], None, "cli").unwrap());
        assert!(!l.operator_read_recorded(&t, OP, &inbox[0], None, "console").unwrap(), "once");
        assert!(l.operator_read_recorded(&t, OP, &inbox[1], Some("its signature does not verify"), "cli").unwrap());
        assert_eq!(kinds(&l), ["message.read", "message.refused"]);
        assert_eq!(l.receipt("m-2").unwrap().unwrap().state, "refused");
        // A failed audit leaves the message unread.
        l.post_message("m-3", &t, "run_lead", OP, None, "e3", &meta).unwrap();
        let m3 = l.operator_inbox(&t.0, OP, false, 10).unwrap().remove(0);
        l.fail_audit_inserts_for_tests().unwrap();
        assert!(l.operator_read_recorded(&t, OP, &m3, None, "cli").is_err());
        assert_eq!(l.receipt("m-3").unwrap().unwrap().state, "delivered");
    }
}
