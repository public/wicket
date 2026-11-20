//! The agent-to-agent protocol's record (#252): receipts for every message, refusals, and what
//! discovery reads of a principal's presence.
//!
//! A receipt is never stored as a second copy of the message's state: it is read from the message's
//! own row (where it went, whether it has been read, how old it is) and from `message_refusals`,
//! which records messages wicket refused, at sending (`accept_from`) or at delivery (the org
//! policy, a signature that doesn't verify). Its states:
//!
//! - `delivered`: in the inbox of the recipient's live run, not yet read;
//! - `read`: taken by the recipient (`await_message`, or pushed into its conversation);
//! - `held`: the recipient has no live run (or is hibernated and being woken): why, and who can
//!   release it;
//! - `refused`: wicket did not deliver it, and why;
//! - `expired`: held past [`crate::MESSAGE_HOLD_SECS`] and never read.

use crate::{now, IdentityRow, Ledger, Result, MESSAGE_HOLD_SECS};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS message_refusals (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, from_run TEXT NOT NULL, from_principal TEXT, to_principal TEXT NOT NULL,
  why TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS message_refusals_from ON message_refusals (from_principal, created_at);
-- Every principal the ledger knows (#11, #253 primitive 3): one record, read-only, over the tables
-- each kind is enrolled in. An agent is its latest identity; an operator its console passkey (a CLI
-- operator, known by its unix user alone, has no record yet). No writes go through it.
CREATE VIEW IF NOT EXISTS principals AS
  SELECT 'agent' AS kind, i.tenant AS tenant, i.spiffe_id AS id, NULL AS via, i.agent AS name, i.run AS run
    FROM identities i
   WHERE i.rowid = (SELECT rowid FROM identities j WHERE j.tenant = i.tenant AND j.spiffe_id = i.spiffe_id
                    ORDER BY issued_at DESC, rowid DESC LIMIT 1)
  UNION ALL
  SELECT DISTINCT 'operator', tenant, NULL, 'passkey', name, NULL FROM operator_credentials WHERE revoked = 0;
"#;

/// One principal in the ledger's record ([`Ledger::principals`]).
#[derive(Clone, Debug)]
pub enum Principal {
    /// An agent: its latest identity.
    Agent(IdentityRow),
    /// An operator, enrolled as `via/name` (the id is the trust domain's: `wicket_identity::operator_id`).
    Operator { via: String, name: String },
}

/// How soon a sender wants a message read (#252), where the recipient's harness can act on it:
/// `now` interrupts the running turn, `next` joins it (the default), `later` waits for it to end.
/// The inbox hands out `now` first, then `next`, then `later`, each oldest first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Now,
    #[default]
    Next,
    Later,
}

impl Priority {
    pub fn parse(s: &str) -> Option<Priority> {
        match s {
            "now" => Some(Priority::Now),
            "next" => Some(Priority::Next),
            "later" => Some(Priority::Later),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Priority::Now => "now",
            Priority::Next => "next",
            Priority::Later => "later",
        }
    }
}

/// What a message records besides its envelope (#252): who sent it (its principal: the reply
/// address), its priority, and the message it answers.
#[derive(Clone, Copy, Debug, Default)]
pub struct MessageMeta<'a> {
    pub from_principal: Option<&'a str>,
    pub priority: Priority,
    pub in_reply_to: Option<&'a str>,
    /// Signed by an operator (#252): recorded as [`crate::KIND_OPERATOR_MESSAGE`].
    pub operator: bool,
}

/// A recorded message's addressing, without its envelope: what a reply is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRow {
    pub id: String,
    pub tenant: String,
    pub from_run: String,
    pub from_principal: Option<String>,
    pub to_principal: Option<String>,
    pub created_at: i64,
}

/// A message's receipt, as its sender reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Receipt {
    pub message_id: String,
    /// The recipient principal.
    pub to: String,
    /// `delivered`, `read`, `held`, `refused` or `expired`.
    pub state: String,
    /// Why it is held or refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// A held message: who can release it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// The run it is in the inbox of (delivered, read).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    pub sent_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_at: Option<i64>,
    /// A held message: when it expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub priority: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// Who sent it: its principal (None for a message recorded before #252) and run.
    #[serde(skip)]
    pub from_principal: Option<String>,
    #[serde(skip)]
    pub from_run: String,
    #[serde(skip)]
    pub tenant: String,
}

/// The order the inbox hands messages out in: priority, then the order they were recorded in.
pub(crate) const INBOX_ORDER: &str = "CASE priority WHEN 'now' THEN 0 WHEN 'later' THEN 2 ELSE 1 END, created_at, rowid";

type Raw = (String, String, String, Option<String>, Option<String>, String, i64, Option<i64>, Option<String>, Option<String>);

impl Ledger {
    /// Records that wicket refused message `id` and why (#252): at sending, where nothing was
    /// delivered, or at delivery (the recipient never saw it). Its receipt says `refused` from now on.
    pub fn refuse_message(&self, id: &str, tenant: &str, from_run: &str, from_principal: Option<&str>, to: &str, why: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO message_refusals (id, tenant, from_run, from_principal, to_principal, why, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![id, tenant, from_run, from_principal, to, why, now()],
        )?;
        Ok(())
    }

    /// A recorded message's addressing, if there is one with this id.
    pub fn message_row(&self, id: &str) -> Result<Option<MessageRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, tenant, from_run, from_principal, to_principal, created_at FROM messages WHERE id = ?1",
                params![id],
                |r| {
                    Ok(MessageRow {
                        id: r.get(0)?,
                        tenant: r.get(1)?,
                        from_run: r.get(2)?,
                        from_principal: r.get(3)?,
                        to_principal: r.get(4)?,
                        created_at: r.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// Message `id`'s receipt, if wicket recorded it (sent or refused).
    pub fn receipt(&self, id: &str) -> Result<Option<Receipt>> {
        let raw: Option<Raw> = self
            .conn
            .query_row(
                "SELECT id, tenant, from_run, from_principal, to_principal, to_run, created_at, delivered_at, priority, in_reply_to
                 FROM messages WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
            )
            .optional()?;
        let refusal: Option<(String, String, Option<String>, String, String, i64)> = self
            .conn
            .query_row(
                "SELECT tenant, from_run, from_principal, to_principal, why, created_at FROM message_refusals WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .optional()?;
        Ok(match (raw, refusal) {
            (Some(raw), refused) => Some(self.receipt_of(raw, refused.map(|r| r.4))?),
            (None, Some((tenant, from_run, from_principal, to, why, at))) => Some(Receipt {
                message_id: id.to_string(),
                to,
                state: "refused".into(),
                why: Some(why),
                release: None,
                run: None,
                sent_at: at,
                read_at: None,
                expires_at: None,
                priority: Priority::Next.as_str().into(),
                in_reply_to: None,
                from_principal,
                from_run,
                tenant,
            }),
            (None, None) => None,
        })
    }

    /// The receipts of the newest `limit` messages principal `from` sent in `tenant` (or, for
    /// messages recorded before #252, one of `runs` sent), refused ones included, newest first.
    pub fn receipts_from(&self, tenant: &str, from: &str, runs: &[String], limit: usize) -> Result<Vec<Receipt>> {
        let runs_json = serde_json::Value::from(runs.to_vec()).to_string();
        let mut st = self.conn.prepare(
            "SELECT id, created_at FROM messages WHERE tenant = ?1
               AND (from_principal = ?2 OR (from_principal IS NULL AND from_run IN (SELECT value FROM json_each(?3))))
             UNION SELECT id, created_at FROM message_refusals WHERE tenant = ?1 AND from_principal = ?2
             ORDER BY created_at DESC, id DESC LIMIT ?4",
        )?;
        let ids = st.query_map(params![tenant, from, runs_json, limit as i64], |r| r.get::<_, String>(0))?;
        let ids = ids.collect::<std::result::Result<Vec<_>, _>>()?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(r) = self.receipt(&id)? {
                out.push(r);
            }
        }
        Ok(out)
    }

    fn receipt_of(&self, raw: Raw, refused: Option<String>) -> Result<Receipt> {
        let (id, tenant, from_run, from_principal, to, to_run, at, read_at, priority, in_reply_to) = raw;
        let to = to.unwrap_or_default();
        let running = |r: &str| -> Result<bool> { Ok(!r.is_empty() && self.run_status(r)?.as_deref() == Some("running")) };
        let (state, why, release, run, expires_at) = if let Some(why) = refused {
            ("refused", Some(why), None, None, None)
        } else if read_at.is_some() {
            ("read", None, None, Some(to_run), None)
        } else if at < now() - MESSAGE_HOLD_SECS {
            ("expired", Some(format!("no run of {to} read it within {} days", MESSAGE_HOLD_SECS / 86_400)), None, None, None)
        } else if running(&to_run)? {
            ("delivered", None, None, Some(to_run), None)
        } else if crate::inbox::is_operator(&to) {
            // In the operator's inbox (#252): it has no run to wait for.
            ("delivered", None, None, None, None)
        } else {
            let (why, release) = self.held_why(&tenant, &to)?;
            ("held", Some(why), Some(release), None, Some(at + MESSAGE_HOLD_SECS))
        };
        Ok(Receipt {
            message_id: id,
            to,
            state: state.into(),
            why,
            release,
            run,
            sent_at: at,
            read_at,
            expires_at,
            priority: priority.unwrap_or_else(|| Priority::Next.as_str().into()),
            in_reply_to,
            from_principal,
            from_run,
            tenant,
        })
    }

    /// Why a message to principal `to` is held, and who can release it.
    fn held_why(&self, tenant: &str, to: &str) -> Result<(String, String)> {
        let agent = match self.principal_identity(tenant, to)? {
            Some(i) => match self.agent_of_run(&i.run)? {
                Some((a, _)) => self.agent(&a)?,
                None => None,
            },
            None => None,
        };
        Ok(match agent {
            Some(a) if a.restorable && ["hibernated", "hibernating", "waking"].contains(&a.state.as_str()) => (
                format!("{to} is {}: wicket wakes it to read the message", a.state),
                "wicket itself, by waking it (its operator can also: `wicket session`)".into(),
            ),
            _ => (
                format!("{to} has no live run"),
                format!(
                    "its next run takes it, within {} days: whoever may start {to} (its operator, or the agent that spawned it)",
                    MESSAGE_HOLD_SECS / 86_400
                ),
            ),
        })
    }

    /// What `run` is doing, as its supervisor and gateway report it (#252): `busy` (a turn is
    /// running), `idle` (between turns) or `waiting` (in a wait: `await_message`, `await_grant`).
    /// None clears it.
    pub fn set_run_activity(&self, run: &str, activity: Option<&str>) -> Result<()> {
        self.conn.execute("UPDATE runs SET activity = ?2, activity_at = ?3 WHERE id = ?1", params![run, activity, now()])?;
        Ok(())
    }

    /// Sets `run`'s activity back to `to` if it is still `from`: the end of a wait, unless its
    /// supervisor has said something newer meanwhile.
    pub fn restore_run_activity(&self, run: &str, from: &str, to: Option<&str>) -> Result<()> {
        self.conn
            .execute("UPDATE runs SET activity = ?3, activity_at = ?4 WHERE id = ?1 AND activity = ?2", params![run, from, to, now()])?;
        Ok(())
    }

    /// What `run` is doing, if its supervisor or gateway said.
    pub fn run_activity(&self, run: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT activity FROM runs WHERE id = ?1", params![run], |r| r.get(0)).optional()?.flatten())
    }

    /// Every principal `tenant` has (the `principals` view): each agent that has run, by its latest
    /// identity, and each operator enrolled with a passkey. Agents first, each kind in id order.
    pub fn principals(&self, tenant: &str) -> Result<Vec<Principal>> {
        let mut st = self.conn.prepare("SELECT kind, run, via, name FROM principals WHERE tenant = ?1 ORDER BY kind, id, via, name")?;
        let rows = st.query_map(params![tenant], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, String>(3)?))
        })?;
        let mut out = vec![];
        for row in rows {
            match row? {
                (k, Some(run), _, _) if k == "agent" => {
                    if let Some(i) = self.identity(&run)? {
                        out.push(Principal::Agent(i));
                    }
                }
                (_, _, Some(via), name) => out.push(Principal::Operator { via, name }),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Principal `spiffe_id`'s presence in `tenant` (#252), from what the ledger knows: with a live
    /// run, `busy`, `idle` or `waiting` as it last reported (`running` if it hasn't); else
    /// `hibernated` (a long-lived agent asleep, woken by a message) or `offline`.
    pub fn presence(&self, tenant: &str, spiffe_id: &str) -> Result<String> {
        if let Some(run) = self.live_run_of(tenant, spiffe_id)? {
            return Ok(match self.run_activity(&run)?.as_deref() {
                Some(a @ ("busy" | "idle" | "waiting")) => a.to_string(),
                _ => "running".into(),
            });
        }
        let agent = match self.principal_identity(tenant, spiffe_id)? {
            Some(i) => match self.agent_of_run(&i.run)? {
                Some((a, _)) => self.agent(&a)?,
                None => None,
            },
            None => None,
        };
        Ok(match agent.map(|a| a.state) {
            Some(s) if s == "hibernated" || s == "hibernating" => "hibernated".into(),
            Some(s) if s == "waking" => "running".into(),
            _ => "offline".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::{RunId, TenantId};

    fn row(t: &TenantId, run: &str, sub: &str) -> IdentityRow {
        IdentityRow {
            run: run.into(),
            tenant: t.0.clone(),
            spiffe_id: sub.into(),
            zone: "z".into(),
            agent: "peer".into(),
            parent_run: None,
            accept_from: vec![],
            jws: "j".into(),
            issued_at: now(),
        }
    }

    /// #252: a receipt follows its message: held (and why), delivered, read; refused with its
    /// reason; expired once held past the hold. A sender lists its own receipts, newest first.
    #[test]
    fn receipts_follow_their_messages() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let (me, p) = ("spiffe://x/t/default/z/z/a/me", "spiffe://x/t/default/z/z/a/peer");
        let meta = MessageMeta { from_principal: Some(me), ..Default::default() };
        l.post_message("m-1", &t, "run_s", p, None, "e1", &meta).unwrap();
        let r = l.receipt("m-1").unwrap().unwrap();
        assert_eq!((r.state.as_str(), r.from_principal.as_deref()), ("held", Some(me)));
        assert!(r.why.unwrap().contains("no live run") && r.release.unwrap().contains("next run") && r.expires_at.is_some());
        l.run_started(&t, &RunId("run_1".into()), "z", "peer").unwrap();
        l.put_identity(&row(&t, "run_1", p)).unwrap();
        let r = l.receipt("m-1").unwrap().unwrap();
        assert_eq!((r.state.as_str(), r.run.as_deref()), ("delivered", Some("run_1")));
        assert_eq!(l.take_message("run_1").unwrap().unwrap().id, "m-1");
        let r = l.receipt("m-1").unwrap().unwrap();
        assert!(r.state == "read" && r.read_at.is_some(), "{r:?}");
        l.refuse_message("m-2", &t.0, "run_s", Some(me), p, "its accept_from lists neither you nor your zone").unwrap();
        let r = l.receipt("m-2").unwrap().unwrap();
        assert_eq!((r.state.as_str(), r.why.as_deref()), ("refused", Some("its accept_from lists neither you nor your zone")));
        // Refused at delivery: the refusal wins over its having been taken.
        l.post_message("m-3", &t, "run_s", p, None, "e3", &meta).unwrap();
        l.take_message("run_1").unwrap().unwrap();
        l.refuse_message("m-3", &t.0, "run_s", Some(me), p, "the org policy doesn't accept messages from zone z").unwrap();
        assert_eq!(l.receipt("m-3").unwrap().unwrap().state, "refused");
        l.post_message("m-4", &t, "run_s", p, None, "e4", &meta).unwrap();
        l.run_ended(&RunId("run_1".into()), "succeeded", "{}").unwrap();
        l.conn.execute("UPDATE messages SET created_at = created_at - ?2 WHERE id = ?1", params!["m-4", MESSAGE_HOLD_SECS + 1]).unwrap();
        assert_eq!(l.receipt("m-4").unwrap().unwrap().state, "expired");
        let mine: Vec<String> = l.receipts_from(&t.0, me, &[], 10).unwrap().into_iter().map(|r| r.message_id).collect();
        assert_eq!(mine.len(), 4);
        assert!(mine.contains(&"m-2".to_string()), "refused ones too: {mine:?}");
        assert!(l.receipts_from(&t.0, p, &[], 10).unwrap().is_empty(), "only the sender's");
        assert!(l.receipt("m-none").unwrap().is_none());
    }

    /// #252: the inbox hands out `now` first and `later` last, each in the order recorded.
    #[test]
    fn the_inbox_is_read_by_priority() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let p = "spiffe://x/t/default/z/z/a/peer";
        l.run_started(&t, &RunId("run_1".into()), "z", "peer").unwrap();
        l.put_identity(&row(&t, "run_1", p)).unwrap();
        for (id, pr) in [("m-1", Priority::Later), ("m-2", Priority::Next), ("m-3", Priority::Now), ("m-4", Priority::Next)] {
            l.post_message(id, &t, "run_s", p, None, "e", &MessageMeta { priority: pr, ..Default::default() }).unwrap();
        }
        let order: Vec<String> = std::iter::from_fn(|| l.take_message("run_1").unwrap().map(|m| m.id)).collect();
        assert_eq!(order, ["m-3", "m-2", "m-4", "m-1"]);
    }

    /// #252: presence from what the ledger knows, and one row per principal.
    #[test]
    fn presence_comes_from_runs_and_agents() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let p = "spiffe://x/t/default/z/z/a/peer";
        assert_eq!(l.presence(&t.0, p).unwrap(), "offline");
        l.run_started(&t, &RunId("run_1".into()), "z", "peer").unwrap();
        l.put_identity(&row(&t, "run_1", p)).unwrap();
        assert_eq!(l.presence(&t.0, p).unwrap(), "running");
        for a in ["busy", "idle", "waiting"] {
            l.set_run_activity("run_1", Some(a)).unwrap();
            assert_eq!(l.presence(&t.0, p).unwrap(), a);
        }
        l.restore_run_activity("run_1", "waiting", Some("idle")).unwrap();
        assert_eq!(l.presence(&t.0, p).unwrap(), "idle", "the wait is over");
        l.set_run_activity("run_1", Some("busy")).unwrap();
        l.restore_run_activity("run_1", "waiting", Some("idle")).unwrap();
        assert_eq!(l.presence(&t.0, p).unwrap(), "busy", "newer news wins");
        l.run_ended(&RunId("run_1".into()), "succeeded", "{}").unwrap();
        assert_eq!(l.presence(&t.0, p).unwrap(), "offline");
        l.run_started(&t, &RunId("run_2".into()), "z", "peer").unwrap();
        l.put_identity(&row(&t, "run_2", p)).unwrap();
        l.put_identity(&row(&t, "run_3", "spiffe://x/t/default/z/z/a/other")).unwrap();
        let all = l.principals(&t.0).unwrap();
        assert_eq!(all.len(), 2);
        let agent = |id: &str| {
            all.iter().find_map(|r| match r {
                Principal::Agent(i) if i.spiffe_id == id => Some(i.clone()),
                _ => None,
            })
        };
        assert_eq!(agent(p).unwrap().run, "run_2", "its latest run");
        // Operators enrolled with a passkey are principals too (#253): once each, not once revoked.
        for (id, name) in [("c1", "laptop"), ("c2", "laptop"), ("c3", "phone")] {
            let c = crate::OperatorCredential { id: id.into(), name: name.into(), x: [1; 32], y: [2; 32], sign_count: 0 };
            l.add_operator_credential(&t, &c).unwrap();
        }
        let ops = |l: &Ledger| -> Vec<String> {
            l.principals(&t.0)
                .unwrap()
                .into_iter()
                .filter_map(|r| match r {
                    Principal::Operator { via, name } => Some(format!("{via}/{name}")),
                    Principal::Agent(_) => None,
                })
                .collect()
        };
        assert_eq!(ops(&l), ["passkey/laptop", "passkey/phone"]);
        assert_eq!(l.principals("another").unwrap().len(), 0, "another tenant's none");
        l.reset_operator_credentials(&t).unwrap();
        assert!(ops(&l).is_empty(), "revoked: no longer a principal");
        assert_eq!(l.principals(&t.0).unwrap().len(), 2, "the agents stay");
    }
}
