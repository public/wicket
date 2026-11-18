//! Long-lived agents (#70, design §13): one row per agent, outliving each of its runs (activations).
//!
//! **States** (`state`): `active` (a box runs: a turn, or the agent waiting on its own, #249),
//! `hibernating` (the box has stopped and its state is being pushed), `hibernated` (no box;
//! the state is a bundle in the object store), `waking` (a waker holds the claim and is rebuilding
//! the box), `ended` (the session closed without hibernating: nothing to wake), `failed`.
//!
//! **Fencing.** `generation` counts activations. A wake is a compare-and-set claim that bumps it, so
//! of any number of concurrent wakers exactly one wins. Every activation knows its own generation;
//! its proxies refuse requests once the row's generation has moved past it, and a push of its state
//! commits only while its generation is still current. A box woken twice (a crashed supervisor's
//! box still running, a second waker) can't split the agent's state.

use crate::{now, Ledger, Result};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::Serialize;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, zone TEXT NOT NULL, name TEXT NOT NULL, state TEXT NOT NULL,
  generation INTEGER NOT NULL, run TEXT NOT NULL, session_id TEXT NOT NULL, manifest TEXT NOT NULL,
  image TEXT NOT NULL, workspace TEXT, head TEXT, head_seq INTEGER NOT NULL DEFAULT 0,
  bundle_bytes INTEGER NOT NULL DEFAULT 0, lease_until INTEGER, restorable INTEGER NOT NULL DEFAULT 1,
  want TEXT, note TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  used_requests INTEGER NOT NULL DEFAULT 0, used_input_tokens INTEGER NOT NULL DEFAULT 0,
  used_output_tokens INTEGER NOT NULL DEFAULT 0, used_secs INTEGER NOT NULL DEFAULT 0, claim_until INTEGER
);
CREATE TABLE IF NOT EXISTS agent_runs (
  run TEXT PRIMARY KEY, agent TEXT NOT NULL, generation INTEGER NOT NULL, started_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_runs_agent ON agent_runs (agent, generation);
"#;

/// States in which a box (or a waker) holds the agent.
pub const HELD: &[&str] = &["active", "hibernating", "waking"];

/// A new agent id: `agt_` and 26 lowercase ULID characters.
pub fn new_agent_id() -> String {
    format!("agt_{}", wicket_core::new_ulid().to_string().to_lowercase())
}

/// Whether `id` is an agent id wicket made.
pub fn valid_agent_id(id: &str) -> bool {
    id.len() == 30 && id.starts_with("agt_") && id[4..].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentRow {
    pub id: String,
    pub tenant: String,
    pub zone: String,
    pub name: String,
    pub state: String,
    pub generation: i64,
    /// The current (or last) activation's run.
    pub run: String,
    /// The agent's harness session, resumed on every wake.
    pub session_id: String,
    /// The effective manifest (YAML) the agent was started with; a wake rebuilds from it.
    pub manifest: String,
    pub image: String,
    /// The in-place workspace's host path (`--workspace-dir`), if the agent works in one.
    pub workspace: Option<String>,
    /// The object key of the head state manifest, once the agent has hibernated.
    pub head: Option<String>,
    pub head_seq: i64,
    /// Bytes stored for the head bundle (compressed, all trees).
    pub bundle_bytes: i64,
    /// Until when the current holder's claim is good (wicket's clock). A holder renews it while it
    /// runs; an expired one (its supervisor died) can be claimed by a waker. Column `claim_until`
    /// (schema 7). The old `lease_until` is no longer written: only builds before schema 7 read it,
    /// and none of those may open a ledger at the schema floor (17).
    pub claim_until: Option<i64>,
    /// False once revoked: a sleeping agent that may not be woken again.
    pub restorable: bool,
    /// What an operator asked of the running agent (`hibernate`), taken by its supervisor.
    pub want: Option<String>,
    /// The last lifecycle outcome, for `wicket agents` (e.g. why it stayed idle).
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    /// What the agent has spent of its zone's budget, over all its activations: model requests,
    /// input tokens (cached ones included), output tokens, and seconds in a box. A wake starts from
    /// what is left.
    pub used_requests: i64,
    pub used_input_tokens: i64,
    pub used_output_tokens: i64,
    pub used_secs: i64,
}

/// What an activation has spent, counted from the agent's start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentUsage {
    pub requests: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub secs: i64,
}

const COLS: &str = "id, tenant, zone, name, state, generation, run, session_id, manifest, image, workspace, head, head_seq, \
                    bundle_bytes, claim_until, restorable, want, note, created_at, updated_at, used_requests, used_input_tokens, \
                    used_output_tokens, used_secs";

fn row(r: &rusqlite::Row) -> rusqlite::Result<AgentRow> {
    Ok(AgentRow {
        id: r.get(0)?,
        tenant: r.get(1)?,
        zone: r.get(2)?,
        name: r.get(3)?,
        state: r.get(4)?,
        generation: r.get(5)?,
        run: r.get(6)?,
        session_id: r.get(7)?,
        manifest: r.get(8)?,
        image: r.get(9)?,
        workspace: r.get(10)?,
        head: r.get(11)?,
        head_seq: r.get(12)?,
        bundle_bytes: r.get(13)?,
        claim_until: r.get(14)?,
        restorable: r.get::<_, i64>(15)? != 0,
        want: r.get(16)?,
        note: r.get(17)?,
        created_at: r.get(18)?,
        updated_at: r.get(19)?,
        used_requests: r.get(20)?,
        used_input_tokens: r.get(21)?,
        used_output_tokens: r.get(22)?,
        used_secs: r.get(23)?,
    })
}

/// A new agent's first activation.
pub struct NewAgent<'a> {
    pub id: &'a str,
    pub tenant: &'a str,
    pub zone: &'a str,
    pub name: &'a str,
    pub run: &'a str,
    pub session_id: &'a str,
    pub manifest: &'a str,
    pub image: &'a str,
    pub workspace: Option<&'a str>,
    /// Until when the first activation's claim is good.
    pub claim_until: i64,
}

/// How long past a box's authority wicket allows for the node's clock and its stop (#153, #446): a
/// lapsed claim is taken over this long after its run's authority ends (`noderun::WAKE_SKEW_MS`
/// is the same allowance for the wake fence on the control host's disk).
pub const WAKE_SKEW_SECS: i64 = 30;

/// The runs of the agent in `agents` whose box may still be running at `?4` (Unix seconds),
/// with `?5` [`WAKE_SKEW_SECS`]: recorded `running` (not ended, nor lost once its node confirmed the
/// box gone), with an authority whose end, past its last allowed second, isn't `?5` behind. A
/// subquery of [`Ledger::claim_wake`]; [`Ledger::agent_fenced_until`] states the same condition.
const FENCING_RUNS: &str = "SELECT 1 FROM runs r \
     WHERE (r.id = agents.run OR r.id IN (SELECT run FROM agent_runs WHERE agent = agents.id)) \
     AND r.status = 'running' AND r.authority_until IS NOT NULL AND r.authority_until + 1 + ?5 > ?4";

impl Ledger {
    /// Records a new agent, active in its first run at generation 1.
    pub fn create_agent(&mut self, a: &NewAgent) -> Result<()> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let t = now();
        tx.execute(
            &format!("INSERT INTO agents ({COLS}) VALUES (?1, ?2, ?3, ?4, 'active', 1, ?5, ?6, ?7, ?8, ?9, NULL, 0, 0, ?10, 1, NULL, NULL, ?11, ?11, 0, 0, 0, 0)"),
            params![a.id, a.tenant, a.zone, a.name, a.run, a.session_id, a.manifest, a.image, a.workspace, a.claim_until, t],
        )?;
        tx.execute("INSERT INTO agent_runs (run, agent, generation, started_at) VALUES (?1, ?2, 1, ?3)", params![a.run, a.id, t])?;
        tx.commit()?;
        Ok(())
    }

    pub fn agent(&self, id: &str) -> Result<Option<AgentRow>> {
        Ok(self.conn.query_row(&format!("SELECT {COLS} FROM agents WHERE id = ?1"), params![id], row).optional()?)
    }

    /// Every agent of a tenant, newest first.
    pub fn agents(&self, tenant: &str) -> Result<Vec<AgentRow>> {
        let mut st = self.conn.prepare(&format!("SELECT {COLS} FROM agents WHERE tenant = ?1 ORDER BY created_at DESC, id DESC"))?;
        let r = st.query_map(params![tenant], row)?;
        Ok(r.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Every agent's head, of every tenant: (agent, head, head's sequence number). What the
    /// content-addressed store's collection keeps (#258).
    pub fn agent_heads(&self) -> Result<Vec<(String, String, i64)>> {
        let mut st = self.conn.prepare("SELECT id, head, head_seq FROM agents WHERE head IS NOT NULL ORDER BY id")?;
        let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(r.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// The agent a run was an activation of, and that activation's generation.
    pub fn agent_of_run(&self, run: &str) -> Result<Option<(String, i64)>> {
        Ok(self
            .conn
            .query_row("SELECT agent, generation FROM agent_runs WHERE run = ?1", params![run], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    }

    /// The agent's current generation: the fencing token every proxy compares its own against.
    /// The image an agent's next activation starts from (#192): pinned to the digest its box
    /// started as, so a wake doesn't take whatever a tag points to then.
    pub fn set_agent_image(&self, id: &str, image: &str) -> Result<()> {
        self.conn.execute("UPDATE agents SET image = ?2 WHERE id = ?1", params![id, image])?;
        Ok(())
    }

    pub fn agent_generation(&self, id: &str) -> Result<Option<i64>> {
        Ok(self.conn.query_row("SELECT generation FROM agents WHERE id = ?1", params![id], |r| r.get(0)).optional()?)
    }

    /// Moves the agent to `state`, if `generation` is still current. False: superseded.
    pub fn set_agent_state(&self, id: &str, generation: i64, state: &str, note: Option<&str>) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE agents SET state = ?3, note = COALESCE(?4, note), updated_at = ?5 WHERE id = ?1 AND generation = ?2",
            params![id, generation, state, note, now()],
        )?;
        Ok(n == 1)
    }

    /// Records the session the agent's harness chose (an ACP agent names its own session, #66), so a
    /// wake continues it, if `generation` is still current.
    pub fn set_agent_session(&self, id: &str, generation: i64, session_id: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE agents SET session_id = ?3, updated_at = ?4 WHERE id = ?1 AND generation = ?2",
            params![id, generation, session_id, now()],
        )?;
        Ok(n == 1)
    }

    /// Records the agent's spend so far (totals over its life, never lower than what is recorded),
    /// if `generation` is still current.
    pub fn record_agent_usage(&self, id: &str, generation: i64, u: &AgentUsage) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE agents SET used_requests = MAX(used_requests, ?3), used_input_tokens = MAX(used_input_tokens, ?4), \
             used_output_tokens = MAX(used_output_tokens, ?5), used_secs = MAX(used_secs, ?6) WHERE id = ?1 AND generation = ?2",
            params![id, generation, u.requests, u.input_tokens, u.output_tokens, u.secs],
        )?;
        Ok(n == 1)
    }

    /// The run of agent `id` whose box may still be running at `at` (Unix seconds), and when that
    /// ends for certain (its authority's end plus [`WAKE_SKEW_SECS`]): what keeps
    /// [`Ledger::claim_wake`] from taking over its lapsed claim (#446). None when no run fences it.
    /// The same condition as [`FENCING_RUNS`].
    pub fn agent_fenced_until(&self, id: &str, at: i64) -> Result<Option<(String, i64)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT r.id, r.authority_until + 1 + ?3 FROM agents \
                 JOIN runs r ON (r.id = agents.run OR r.id IN (SELECT run FROM agent_runs WHERE agent = agents.id)) \
                 WHERE agents.id = ?1 AND r.status = 'running' AND r.authority_until IS NOT NULL AND r.authority_until + 1 + ?3 > ?2 \
                 ORDER BY 2 DESC LIMIT 1",
                params![id, at, WAKE_SKEW_SECS],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Renews the holder's claim until `until`, if `generation` is still current.
    pub fn renew_agent_claim(&self, id: &str, generation: i64, until: i64) -> Result<bool> {
        let n =
            self.conn.execute("UPDATE agents SET claim_until = ?3 WHERE id = ?1 AND generation = ?2", params![id, generation, until])?;
        Ok(n == 1)
    }

    /// The wake claim: one conditional update that moves a hibernated agent (or one whose holder's
    /// claim ran out) to `waking`, bumps its generation and names `run` as its activation. Exactly
    /// one of any number of concurrent claims succeeds; the others get None. Revoked agents and
    /// agents with nothing to restore can't be claimed.
    ///
    /// A lapsed claim is taken over only once none of the agent's runs' boxes can still be running
    /// (#446): a control-host outage stops its supervisors, never its boxes, and a box runs on its
    /// node until its authority ends. So a run recorded `running` whose authority (`runs`,
    /// recorded at its box's start and each renewal) hasn't ended, plus [`WAKE_SKEW_SECS`],
    /// fences the takeover ([`Ledger::agent_fenced_until`]). A run its node confirmed stopped
    /// (ended, lost) doesn't.
    pub fn claim_wake(&mut self, id: &str, run: &str, claim_until: i64) -> Result<Option<i64>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let t = now();
        let n = tx.execute(
            &format!(
                "UPDATE agents SET state = 'waking', generation = generation + 1, run = ?2, claim_until = ?3, want = NULL, updated_at = ?4 \
                 WHERE id = ?1 AND restorable = 1 AND head IS NOT NULL \
                 AND (state = 'hibernated' OR (state IN ('active', 'hibernating', 'waking') AND COALESCE(claim_until, 0) < ?4 \
                      AND NOT EXISTS ({FENCING_RUNS})))"
            ),
            params![id, run, claim_until, t, WAKE_SKEW_SECS],
        )?;
        if n != 1 {
            return Ok(None);
        }
        let generation: i64 = tx.query_row("SELECT generation FROM agents WHERE id = ?1", params![id], |r| r.get(0))?;
        tx.execute("INSERT INTO agent_runs (run, agent, generation, started_at) VALUES (?1, ?2, ?3, ?4)", params![run, id, generation, t])?;
        // Whatever was sent to any earlier activation (and not yet read) is now this one's.
        tx.execute(
            "UPDATE messages SET to_run = ?2, taken_at = NULL WHERE delivered_at IS NULL AND to_run IN (SELECT run FROM agent_runs WHERE agent = ?1 AND run != ?2)",
            params![id, run],
        )?;
        // And so is whatever is held for the agent's principal (#250), sent while no run held it.
        tx.execute(
            "UPDATE messages SET to_run = ?2 WHERE delivered_at IS NULL AND to_run = '' AND created_at >= ?3 AND to_principal IN
             (SELECT spiffe_id FROM identities WHERE run IN (SELECT run FROM agent_runs WHERE agent = ?1 AND run != ?2))",
            params![id, run, t - crate::MESSAGE_HOLD_SECS],
        )?;
        // Prompts and notices not yet taken (#253), including those queued for the agent itself
        // while it hibernated (`wicket session <agent> <prompt>`).
        tx.execute(
            &format!("UPDATE messages SET to_run = ?2 WHERE {} AND delivered_at IS NULL AND to_run = ?1", crate::TURNS),
            params![id, run],
        )?;
        tx.commit()?;
        Ok(Some(generation))
    }

    /// The commit point of a push: moves the head to the new state manifest, in one statement that
    /// keeps the note set when hibernation began (why it hibernated, e.g. what wicket stopped), and
    /// checks both the pusher's generation and the head it started from. A stale pusher (a twin, or
    /// a holder that lost its claim) gets false and leaves only orphan objects behind.
    pub fn commit_agent_push(&self, id: &str, generation: i64, from_seq: i64, seq: i64, head: &str, bytes: i64) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE agents SET head = ?5, head_seq = ?4, bundle_bytes = ?6, state = 'hibernated', claim_until = NULL, want = NULL, \
             updated_at = ?7 WHERE id = ?1 AND generation = ?2 AND head_seq = ?3",
            params![id, generation, from_seq, seq, head, bytes, now()],
        )?;
        Ok(n == 1)
    }

    /// A wake that failed after its claim: back to `hibernated` (the head is untouched), so it can be
    /// woken again. Only by the claim's own generation.
    pub fn release_failed_wake(&self, id: &str, generation: i64, why: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE agents SET state = 'hibernated', claim_until = NULL, note = ?3, updated_at = ?4 WHERE id = ?1 AND generation = ?2",
            params![id, generation, why, now()],
        )?;
        Ok(n == 1)
    }

    /// Asks the agent's supervisor for something (`hibernate`). False: the agent isn't held by a box.
    pub fn want_agent(&self, id: &str, want: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE agents SET want = ?2, note = NULL, updated_at = ?3 WHERE id = ?1 AND state = 'active'",
            params![id, want, now()],
        )?;
        Ok(n == 1)
    }

    /// Takes what an operator asked of this activation, once.
    pub fn take_agent_want(&self, id: &str, generation: i64) -> Result<Option<String>> {
        let w: Option<String> = self
            .conn
            .query_row("SELECT want FROM agents WHERE id = ?1 AND generation = ?2", params![id, generation], |r| r.get(0))
            .optional()?
            .flatten();
        if w.is_some() {
            self.conn.execute("UPDATE agents SET want = NULL WHERE id = ?1 AND generation = ?2", params![id, generation])?;
        }
        Ok(w)
    }

    /// Ends `run` as lost (its supervisor gone, and no box of it left to take over), and with it
    /// the agent whose current activation it was (#474): nothing renews that agent's claim again, so
    /// left `active` it would show as running, and messages to it would queue for nobody. An agent
    /// that has hibernated before goes back to `hibernated`, restorable from its last head (what a
    /// takeover of its lapsed claim would have woken it from); one that never did is `ended`. Its
    /// new state, or None when `run` wasn't an agent's current activation.
    pub fn run_lost(&self, run: &str, why: &str) -> Result<Option<String>> {
        let tx = self.conn.unchecked_transaction()?;
        self.run_ended(&wicket_core::RunId(run.to_string()), "lost", why)?;
        let note = format!("its run {run} was lost: {why}");
        let n = tx.execute(
            "UPDATE agents SET state = CASE WHEN head IS NULL THEN 'ended' ELSE 'hibernated' END, claim_until = NULL, \
             want = NULL, note = ?2, updated_at = ?3 \
             WHERE run = ?1 AND state IN ('active', 'waking', 'hibernating') \
             AND generation = (SELECT generation FROM agent_runs WHERE agent_runs.run = ?1 AND agent_runs.agent = agents.id)",
            params![run, note, now()],
        )?;
        let state = match n {
            0 => None,
            _ => tx.query_row("SELECT state FROM agents WHERE run = ?1", params![run], |r| r.get(0)).optional()?,
        };
        tx.commit()?;
        Ok(state)
    }

    /// Revocation covers sleeping agents: a revoked agent is never woken again.
    pub fn agent_not_restorable(&self, id: &str, why: &str) -> Result<()> {
        self.conn.execute("UPDATE agents SET restorable = 0, note = ?2, updated_at = ?3 WHERE id = ?1", params![id, why, now()])?;
        Ok(())
    }

    /// Undelivered peer messages waiting for `run`.
    pub fn waiting_messages(&self, run: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            &format!("SELECT COUNT(*) FROM messages WHERE to_run = ?1 AND {} AND delivered_at IS NULL AND taken_at IS NULL", crate::PEER),
            params![run],
            |r| r.get(0),
        )?)
    }

    /// Prompts and notices queued for `run` and not yet handed to it.
    pub fn waiting_prompts(&self, run: &str) -> Result<i64> {
        Ok(self.conn.query_row(
            &format!("SELECT COUNT(*) FROM messages WHERE to_run = ?1 AND {} AND delivered_at IS NULL", crate::TURNS),
            params![run],
            |r| r.get(0),
        )?)
    }

    /// Every run of an agent, oldest first.
    pub fn agent_runs(&self, id: &str) -> Result<Vec<(String, i64)>> {
        let mut st = self.conn.prepare("SELECT run, generation FROM agent_runs WHERE agent = ?1 ORDER BY generation")?;
        let r = st.query_map(params![id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(r.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(l: &mut Ledger, id: &str) {
        l.create_agent(&NewAgent {
            id,
            tenant: "t0",
            zone: "z",
            name: "a",
            run: "run_1",
            session_id: "s",
            manifest: "m",
            image: "img",
            workspace: None,
            claim_until: now() + 30,
        })
        .unwrap();
    }

    /// #474: a lost run ends its agent's activation: `ended` if the agent never hibernated (its box
    /// never started, say), back to `hibernated` and wakeable if it has a head. A run that is no
    /// longer the agent's activation leaves the agent alone.
    #[test]
    fn a_lost_run_ends_its_agent_or_leaves_it_restorable() {
        let mut l = Ledger::open_in_memory().unwrap();
        agent(&mut l, "agt_a");
        l.run_started(&wicket_core::TenantId::single(), &wicket_core::RunId("run_1".into()), "z", "a").unwrap();
        assert_eq!(l.run_lost("run_1", "node pc has no box for it").unwrap().as_deref(), Some("ended"));
        let a = l.agent("agt_a").unwrap().unwrap();
        assert_eq!((a.state.as_str(), a.claim_until), ("ended", None));
        assert!(a.note.unwrap().contains("its run run_1 was lost: node pc has no box for it"));
        assert_eq!(l.run_status("run_1").unwrap().as_deref(), Some("lost"));
        assert_eq!(l.run_lost("run_1", "again").unwrap(), None, "once");

        // One that hibernated, then was woken into a run that is lost: restorable.
        let mut l = Ledger::open_in_memory().unwrap();
        agent(&mut l, "agt_b");
        assert!(l.commit_agent_push("agt_b", 1, 0, 1, "head-1", 10).unwrap());
        let g = l.claim_wake("agt_b", "run_2", now() + 30).unwrap().unwrap();
        l.set_agent_state("agt_b", g, "active", None).unwrap();
        assert_eq!(l.run_lost("run_1", "stale").unwrap(), None, "an earlier activation's");
        assert_eq!(l.agent("agt_b").unwrap().unwrap().state, "active");
        assert_eq!(l.run_lost("run_2", "its box never started").unwrap().as_deref(), Some("hibernated"));
        assert!(l.claim_wake("agt_b", "run_3", now() + 30).unwrap().is_some(), "woken again from its head");
    }

    #[test]
    fn a_ledger_from_before_schema_7_keeps_its_claims_and_both_columns_are_written() {
        let dir = std::env::temp_dir().join(format!("wicket-store-claim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.db");
        let id = new_agent_id();
        let until = now() + 600;
        {
            // The agents table as schema 6 made it: the claim's end in `lease_until`.
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute_batch(&SCHEMA.replace(", claim_until INTEGER\n", "\n")).unwrap();
            c.execute(
                "INSERT INTO agents (id, tenant, zone, name, state, generation, run, session_id, manifest, image, head, lease_until, \
                 created_at, updated_at) VALUES (?1, 't0', 'z', 'a', 'active', 1, 'run_1', 's', 'm', 'img', 'h', ?2, 0, 0)",
                params![id, until],
            )
            .unwrap();
        }
        let mut l = Ledger::open(&path).unwrap();
        assert_eq!(l.agent(&id).unwrap().unwrap().claim_until, Some(until), "copied over");
        assert_eq!(l.claim_wake(&id, "run_2", now() + 30).unwrap(), None, "its holder's claim is still live");
        assert!(l.renew_agent_claim(&id, 1, until + 60).unwrap());
        l.conn.execute("UPDATE agents SET lease_until = 1 WHERE id = ?1", params![id]).unwrap();
        drop(l);
        assert_eq!(Ledger::open(&path).unwrap().agent(&id).unwrap().unwrap().claim_until, Some(until + 60), "copied only once");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_hibernated_agent_wakes_once_and_a_stale_push_is_refused() {
        let mut l = Ledger::open_in_memory().unwrap();
        let id = new_agent_id();
        assert!(valid_agent_id(&id));
        agent(&mut l, &id);
        // Nothing to restore yet, and its holder's claim is live: no claim.
        assert_eq!(l.claim_wake(&id, "run_2", now() + 30).unwrap(), None);
        assert!(l.commit_agent_push(&id, 1, 0, 1, "a/x/m/1.1", 10).unwrap());
        let a = l.agent(&id).unwrap().unwrap();
        assert_eq!((a.state.as_str(), a.head_seq, a.head.as_deref()), ("hibernated", 1, Some("a/x/m/1.1")));
        // A message for the old run follows the agent to its new one.
        l.add_message("m-1", &wicket_core::TenantId::single(), "run_peer", "run_1", "env").unwrap();
        assert_eq!(l.claim_wake(&id, "run_2", now() + 30).unwrap(), Some(2));
        assert_eq!(l.claim_wake(&id, "run_3", now() + 30).unwrap(), None, "already claimed");
        assert_eq!(l.waiting_messages("run_2").unwrap(), 1);
        assert_eq!(l.agent_of_run("run_2").unwrap(), Some((id.clone(), 2)));
        // Generation 1 is stale now: its state changes and pushes are refused.
        assert!(!l.set_agent_state(&id, 1, "active", None).unwrap());
        assert!(!l.set_agent_session(&id, 1, "acp-old").unwrap());
        assert!(l.set_agent_session(&id, 2, "acp-new").unwrap());
        assert_eq!(l.agent(&id).unwrap().unwrap().session_id, "acp-new");
        assert!(!l.commit_agent_push(&id, 1, 1, 2, "a/x/m/2.1", 10).unwrap());
        assert!(l.set_agent_state(&id, 2, "active", None).unwrap());
        // A push that started from an older head is refused too.
        assert!(!l.commit_agent_push(&id, 2, 0, 2, "a/x/m/2.2", 10).unwrap());
        assert!(l.commit_agent_push(&id, 2, 1, 2, "a/x/m/2.2", 10).unwrap());
        // Spend is recorded by the current generation only, and never goes down.
        let u = AgentUsage { requests: 4, input_tokens: 40, output_tokens: 80, secs: 9 };
        assert!(l.record_agent_usage(&id, 2, &u).unwrap());
        assert!(!l.record_agent_usage(&id, 1, &AgentUsage { requests: 99, ..u }).unwrap());
        assert!(l.record_agent_usage(&id, 2, &AgentUsage { requests: 1, ..u }).unwrap());
        let a = l.agent(&id).unwrap().unwrap();
        assert_eq!((a.used_requests, a.used_input_tokens, a.used_output_tokens, a.used_secs), (4, 40, 80, 9));
        // Revoked: never woken again.
        l.agent_not_restorable(&id, "revoked").unwrap();
        assert_eq!(l.claim_wake(&id, "run_4", now() + 30).unwrap(), None);
    }

    /// #446: a wake right after a control-host outage longer than the claim. The outage stopped the
    /// holder's supervisor, so its claim lapsed, but not its box, which runs on its node until its
    /// authority ends: the lapsed claim isn't taken over until then, or until the run is known
    /// to have ended (its node confirmed the box gone).
    #[test]
    fn a_wake_after_an_outage_waits_for_the_old_boxs_authority() {
        // An agent woken once, in a ledger of its own: run_2 holds it, its box on a node with
        // authority for 5 minutes.
        let activate = || {
            let mut l = Ledger::open_in_memory().unwrap();
            let id = new_agent_id();
            agent(&mut l, &id);
            assert!(l.commit_agent_push(&id, 1, 0, 1, "a/x/m/1.1", 10).unwrap());
            assert_eq!(l.claim_wake(&id, "run_2", now() + 30).unwrap(), Some(2));
            let run = wicket_core::RunId("run_2".into());
            l.run_started(&wicket_core::TenantId::single(), &run, "z", "a").unwrap();
            l.set_run_authority(&run.0, now() + 300, now() + 3600).unwrap();
            (l, id, run)
        };
        let (mut l, id, run) = activate();
        // The outage: no supervisor renews the claim, which lapses; the box runs on.
        assert!(l.renew_agent_claim(&id, 2, now() - 1).unwrap());
        assert_eq!(l.claim_wake(&id, "run_3", now() + 30).unwrap(), None, "its box may still run");
        let (by, until) = l.agent_fenced_until(&id, now()).unwrap().expect("fenced");
        assert_eq!(by, run.0);
        assert!(until >= now() + 300 + WAKE_SKEW_SECS, "until its authority ends, and the skew: {until}");
        let a = l.agent(&id).unwrap().unwrap();
        assert_eq!((a.generation, a.run.as_str()), (2, run.0.as_str()), "nothing changed");
        // Once its node confirmed the box gone (the reconciler ends the run as lost), it wakes.
        l.run_ended(&run, "lost", "its node has no box for it").unwrap();
        assert_eq!(l.agent_fenced_until(&id, now()).unwrap(), None);
        assert_eq!(l.claim_wake(&id, "run_3", now() + 30).unwrap(), Some(3));

        // Or once its authority has ended, past the skew, even with no word from its node.
        let (mut l, id, run) = activate();
        assert!(l.renew_agent_claim(&id, 2, now() - 1).unwrap());
        l.set_run_authority(&run.0, now() - WAKE_SKEW_SECS + 5, now() + 3600).unwrap();
        assert!(l.agent_fenced_until(&id, now()).unwrap().is_some(), "within the skew");
        assert_eq!(l.claim_wake(&id, "run_3b", now() + 30).unwrap(), None);
        l.set_run_authority(&run.0, now() - WAKE_SKEW_SECS - 2, now() + 3600).unwrap();
        assert_eq!(l.agent_fenced_until(&id, now()).unwrap(), None);
        assert_eq!(l.claim_wake(&id, "run_3b", now() + 30).unwrap(), Some(3));

        // A live claim still refuses, whatever the authority.
        let (mut l, id, _) = activate();
        assert_eq!(l.claim_wake(&id, "run_3c", now() + 30).unwrap(), None, "its claim is live");
    }

    #[test]
    fn concurrent_wakers_have_exactly_one_winner() {
        let dir = std::env::temp_dir().join(format!("wicket-agents-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.db");
        let id = new_agent_id();
        {
            let mut l = Ledger::open(&path).unwrap();
            agent(&mut l, &id);
            assert!(l.commit_agent_push(&id, 1, 0, 1, "h", 1).unwrap());
        }
        for round in 0..20 {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
            let wins: Vec<Option<i64>> = (0..8)
                .map(|i| {
                    let (path, id, barrier) = (path.clone(), id.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        let mut l = Ledger::open(&path).unwrap();
                        barrier.wait();
                        l.claim_wake(&id, &format!("run_r{round}w{i}"), now() + 30).unwrap()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect();
            let winners: Vec<i64> = wins.into_iter().flatten().collect();
            assert_eq!(winners.len(), 1, "round {round}: {winners:?}");
            let l = Ledger::open(&path).unwrap();
            let a = l.agent(&id).unwrap().unwrap();
            assert_eq!(a.generation, winners[0]);
            assert!(l.commit_agent_push(&id, a.generation, a.head_seq, a.head_seq + 1, "h", 1).unwrap());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hibernate_is_asked_of_a_held_agent_and_taken_once() {
        let mut l = Ledger::open_in_memory().unwrap();
        let id = new_agent_id();
        agent(&mut l, &id);
        assert!(l.want_agent(&id, "hibernate").unwrap());
        assert_eq!(l.take_agent_want(&id, 2).unwrap(), None, "not this generation's");
        assert_eq!(l.take_agent_want(&id, 1).unwrap().as_deref(), Some("hibernate"));
        assert_eq!(l.take_agent_want(&id, 1).unwrap(), None);
        assert!(l.commit_agent_push(&id, 1, 0, 1, "h", 1).unwrap());
        assert!(!l.want_agent(&id, "hibernate").unwrap(), "nothing holds it");
    }
}
