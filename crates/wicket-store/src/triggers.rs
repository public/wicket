//! Triggers (#578) in the ledger: the triggers themselves, the events they hear, their firings,
//! and runs' claims on work (so an event about a PR reaches the box that owns it).
//!
//! - **`triggers`:** one row per trigger: its owner (a principal), its document
//!   (`wicket_core::trigger::TriggerSpec` as JSON), whether it is `active`, `paused` or `deleted`,
//!   whether it needed and has a human's approval, and its lifetime.
//! - **`trigger_events`:** one row per event a source delivered, unique per (source, delivery id),
//!   so a redelivery is the same event. The raw body isn't kept here, only its sha256: the fields
//!   filters and templates read are.
//! - **`trigger_firings`:** what each matching event became: queued, started, skipped (with why),
//!   failed, or dead-lettered, and what it started or sent. At most one per (trigger, event).
//! - **`work_claims`:** a run's claim on a piece of work (`github.com/acme/app#123`), live while
//!   the run is, and what `owner_of` reads.
//! - **`trigger_cursors`:** how far a source that reads a sequence has read: wicket's own events,
//!   by the audit chain's seq.
//! - **`trigger_causes`:** the triggers that led to each turn a trigger queued (its message id),
//!   so an event of the run that read it knows which triggers caused it, and none fires twice in
//!   one chain.
//!
//! The scheduler, intake and engine that fill these come later (the design's steps 2 to 5).

use crate::{now, Ledger, Result, StoreError};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use wicket_core::trigger::TriggerSpec;

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS triggers (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, owner TEXT NOT NULL, name TEXT NOT NULL, spec TEXT NOT NULL,
  status TEXT NOT NULL, approval TEXT NOT NULL, created_at INTEGER NOT NULL, created_by TEXT NOT NULL,
  until INTEGER, decided_by TEXT, decided_at INTEGER, updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS triggers_name ON triggers (tenant, owner, name) WHERE status != 'deleted';
CREATE TABLE IF NOT EXISTS trigger_events (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, delivery_id TEXT NOT NULL,
  received_at INTEGER NOT NULL, fields TEXT NOT NULL, raw_sha256 TEXT NOT NULL, verified_by TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS trigger_events_delivery ON trigger_events (tenant, source, delivery_id);
CREATE TABLE IF NOT EXISTS trigger_firings (
  id TEXT PRIMARY KEY, trigger TEXT NOT NULL, event TEXT NOT NULL, status TEXT NOT NULL, detail TEXT,
  run TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS trigger_firings_once ON trigger_firings (trigger, event);
CREATE INDEX IF NOT EXISTS trigger_firings_status ON trigger_firings (trigger, status);
CREATE TABLE IF NOT EXISTS work_claims (
  key TEXT NOT NULL, tenant TEXT NOT NULL, run TEXT NOT NULL, claimed_at INTEGER NOT NULL, released_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS work_claims_live ON work_claims (tenant, key) WHERE released_at IS NULL;
CREATE TABLE IF NOT EXISTS trigger_causes (
  message TEXT PRIMARY KEY, trigger TEXT NOT NULL, chain TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS trigger_cursors (
  tenant TEXT NOT NULL, source TEXT NOT NULL, seq INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (tenant, source)
);
"#;

/// How long triggers' settled firings and the events they fired on are kept (as the design keeps
/// raw deliveries): [`Ledger::maintain`] deletes older ones.
pub const TRIGGER_RETENTION_SECS: i64 = 14 * 86400;

/// The most live triggers one owner may keep.
pub const MAX_TRIGGERS_PER_OWNER: usize = 100;

/// What led to an event, as the turns triggers queued record it (#578): every trigger in any chain
/// that reached the run (`ids`, what a trigger may not fire again on), and the longest single chain
/// (`depth`, what the cap counts: four unrelated schedules messaging one agent are four chains of
/// one, not one of four).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Chain {
    pub ids: Vec<String>,
    pub depth: usize,
}

impl Chain {
    /// A stored chain: `{"ids": [...], "depth": n}`, or (as the first version kept them) a list
    /// of ids, as deep as it is long.
    fn parse(s: &str) -> Chain {
        match serde_json::from_str::<serde_json::Value>(s) {
            Ok(serde_json::Value::Array(a)) => {
                let ids: Vec<String> = a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
                Chain { depth: ids.len(), ids }
            }
            Ok(v) => Chain {
                ids: v["ids"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default(),
                depth: v["depth"].as_u64().unwrap_or(0) as usize,
            },
            Err(_) => Chain::default(),
        }
    }
}

/// A firing's states.
pub const FIRING_STATES: &[&str] = &["queued", "started", "skipped", "failed", "dead"];

/// A trigger, as the ledger has it.
#[derive(Clone, Debug, Serialize)]
pub struct Trigger {
    pub id: String,
    pub tenant: String,
    /// The principal it belongs to (an operator's or an agent's id).
    pub owner: String,
    pub name: String,
    pub spec: TriggerSpec,
    /// `active`, `paused`, `done` (a timer that has fired) or `deleted`.
    pub status: String,
    /// `none` (it widened nothing), `pending` (it waits for a human), or `approved`.
    pub approval: String,
    pub created_at: i64,
    pub created_by: String,
    /// When it lapses (None: until deleted).
    pub until: Option<i64>,
    pub decided_by: Option<String>,
    /// When it last changed state: made, approved, paused, resumed or done (not renewed). A
    /// schedule fires only for minutes after it, so a trigger resumed or approved isn't caught up
    /// on the time before.
    pub updated_at: i64,
}

impl Trigger {
    /// Whether it may fire at `at`: active, approved if it needed to be, and not lapsed.
    pub fn live(&self, at: i64) -> bool {
        self.status == "active" && self.approval != "pending" && self.until.is_none_or(|u| u > at)
    }
}

/// An event a source delivered.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TriggerEvent {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub delivery_id: String,
    pub received_at: i64,
    pub fields: serde_json::Value,
    pub raw_sha256: String,
    pub verified_by: String,
}

/// What an event became for a trigger.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Firing {
    pub id: String,
    pub trigger: String,
    pub event: String,
    pub status: String,
    pub detail: Option<String>,
    pub run: Option<String>,
    pub attempts: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

fn id(prefix: &str) -> String {
    let r = wicket_core::new_request_id();
    format!("{prefix}-{}", &r[2..])
}

const COLS: &str = "id, tenant, owner, name, spec, status, approval, created_at, created_by, until, decided_by, updated_at";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(Trigger, String)> {
    Ok((
        Trigger {
            id: r.get(0)?,
            tenant: r.get(1)?,
            owner: r.get(2)?,
            name: r.get(3)?,
            spec: TriggerSpec {
                trigger: String::new(),
                source: wicket_core::trigger::Source::Wicket { kinds: vec![] },
                filter: Default::default(),
                action: wicket_core::trigger::Action { start: None, wake: None, message: None },
                limits: Default::default(),
            },
            status: r.get(5)?,
            approval: r.get(6)?,
            created_at: r.get(7)?,
            created_by: r.get(8)?,
            until: r.get(9)?,
            decided_by: r.get(10)?,
            updated_at: r.get(11)?,
        },
        r.get(4)?,
    ))
}

fn parse((mut t, spec): (Trigger, String)) -> Option<Trigger> {
    t.spec = serde_json::from_str(&spec).ok()?;
    Some(t)
}

impl Ledger {
    /// Keeps a trigger for `owner`, created by `by`. `needs_approval`: it widens something (an
    /// agent's trigger that doesn't only wake or message itself), so it waits for a human before it
    /// fires. A document that doesn't hold to its shape is refused. The trigger's id.
    pub fn create_trigger(
        &self,
        tenant: &str,
        owner: &str,
        spec: &TriggerSpec,
        by: &str,
        needs_approval: bool,
        until: Option<i64>,
    ) -> Result<String> {
        spec.check().map_err(StoreError::Refused)?;
        let tid = id("t");
        let t = now();
        // A spent timer of the same name gives way: it is kept as deleted.
        self.conn.execute(
            "UPDATE triggers SET status = 'deleted', updated_at = ?4 WHERE tenant = ?1 AND owner = ?2 AND name = ?3 AND status = 'done'",
            params![tenant, owner, spec.trigger, t],
        )?;
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO triggers (id, tenant, owner, name, spec, status, approval, created_at, created_by, until, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7, ?8, ?9, ?7)",
            params![
                tid,
                tenant,
                owner,
                spec.trigger,
                serde_json::to_string(spec)?,
                if needs_approval { "pending" } else { "none" },
                t,
                by,
                until
            ],
        )?;
        if n != 1 {
            return Err(StoreError::Refused(format!("{owner} already has a trigger named {}", spec.trigger)));
        }
        Ok(tid)
    }

    pub fn trigger(&self, id: &str) -> Result<Option<Trigger>> {
        let r = self.conn.query_row(&format!("SELECT {COLS} FROM triggers WHERE id = ?1"), params![id], row).optional()?;
        Ok(r.and_then(parse))
    }

    /// `tenant`'s triggers that aren't deleted (of `owner`, if given), oldest first. A row that
    /// doesn't read is left out, not the list with it.
    pub fn triggers(&self, tenant: &str, owner: Option<&str>) -> Result<Vec<Trigger>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM triggers WHERE tenant = ?1 AND status != 'deleted' AND (?2 IS NULL OR owner = ?2) ORDER BY created_at, id"
        ))?;
        let rows = st.query_map(params![tenant, owner], row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().filter_map(parse).collect())
    }

    /// Pauses, resumes or deletes a trigger (`paused`, `active`, `deleted`). A deleted one stays
    /// deleted.
    pub fn set_trigger_status(&self, id: &str, status: &str) -> Result<()> {
        if !matches!(status, "active" | "paused" | "deleted") {
            return Err(StoreError::Refused(format!("a trigger is active, paused or deleted, not {status}")));
        }
        let n = self.conn.execute(
            "UPDATE triggers SET status = ?2, updated_at = ?3 WHERE id = ?1 AND status != 'deleted' AND (status != 'done' OR ?2 = 'deleted')",
            params![id, status, now()],
        )?;
        if n != 1 {
            return Err(StoreError::Refused(format!("no trigger {id}, or it is deleted, or done (a done timer is only removed)")));
        }
        Ok(())
    }

    /// Marks an active or paused trigger `done`: a timer that has fired (or whose time passed). It
    /// fires nothing again, stays listed until removed, and a new trigger of its name replaces it.
    /// False if it was already done or deleted.
    pub fn finish_trigger(&self, id: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE triggers SET status = 'done', updated_at = ?2 WHERE id = ?1 AND status IN ('active', 'paused')",
            params![id, now()],
        )? == 1)
    }

    /// Moves a live trigger's lapse to `until` (None: until removed). Not a change to when it
    /// fires: `updated_at` (the floor a schedule fires after) stays.
    pub fn renew_trigger(&self, id: &str, until: Option<i64>) -> Result<()> {
        // A trigger that had lapsed comes back as a resumed one does: from now, not caught up on
        // the time it was lapsed (its floor, `updated_at`, moves). A live one's floor stays.
        let n = self.conn.execute(
            "UPDATE triggers SET until = ?2, updated_at = CASE WHEN until IS NOT NULL AND until <= ?3 THEN ?3 ELSE updated_at END
             WHERE id = ?1 AND status NOT IN ('deleted', 'done')",
            params![id, until, now()],
        )?;
        if n != 1 {
            return Err(StoreError::Refused(format!("no trigger {id}, or it is deleted")));
        }
        Ok(())
    }

    /// The last minute a time-told trigger recorded an event for (its `slot` field), if any: where
    /// its next pass starts.
    pub fn last_trigger_slot(&self, tenant: &str, trigger: &str) -> Result<Option<i64>> {
        // Its deliveries are `<trigger>@<slot>`: a range over the delivery index ('A' follows '@').
        Ok(self.conn.query_row(
            "SELECT MAX(json_extract(fields, '$.slot')) FROM trigger_events
             WHERE tenant = ?1 AND source IN ('schedule', 'timer') AND delivery_id >= ?2 || '@' AND delivery_id < ?2 || 'A'",
            params![tenant, trigger],
            |r| r.get(0),
        )?)
    }

    /// Counts one more skip on a skipped firing (its `attempts`), with `detail`: the hour's one
    /// record of a trigger over its limit.
    pub fn count_skip(&self, id: &str, detail: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE trigger_firings SET attempts = attempts + 1, detail = ?2, updated_at = ?3 WHERE id = ?1 AND status = 'skipped'",
            params![id, detail, now()],
        )?;
        Ok(())
    }

    /// The newest firing of `trigger` in `status` since `since`, if any.
    pub fn last_firing(&self, trigger: &str, status: &str, since: i64) -> Result<Option<Firing>> {
        Ok(self.firings_where(trigger, Some(status), &format!("AND created_at >= {since} ORDER BY created_at DESC, id DESC"), 1)?.pop())
    }

    /// Deletes triggers' settled firings, and events no firing waits on, last touched before
    /// `before`: what [`Ledger::maintain`] keeps them to. The rows deleted.
    pub fn prune_triggers(&self, before: i64) -> Result<usize> {
        let f = self.conn.execute(
            "DELETE FROM trigger_firings WHERE updated_at < ?1 AND status IN ('started', 'skipped', 'failed', 'dead')",
            params![before],
        )?;
        let e = self.conn.execute(
            "DELETE FROM trigger_events WHERE received_at < ?1 AND id NOT IN (SELECT event FROM trigger_firings)",
            params![before],
        )?;
        let c = self.conn.execute("DELETE FROM trigger_causes WHERE created_at < ?1", params![before])?;
        Ok(f + e + c)
    }

    /// A human's approval of a trigger that waited for one.
    pub fn approve_trigger(&self, id: &str, by: &str) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE triggers SET approval = 'approved', decided_by = ?2, decided_at = ?3, updated_at = ?3 WHERE id = ?1 AND approval = 'pending' AND status != 'deleted'",
            params![id, by, now()],
        )?;
        if n != 1 {
            return Err(StoreError::Refused(format!("trigger {id} isn't waiting for an approval")));
        }
        Ok(())
    }

    /// Records an event a source delivered. A redelivery (the same source and delivery id) is the
    /// event already recorded: its id, and false.
    #[allow(clippy::too_many_arguments)]
    pub fn record_trigger_event(
        &self,
        tenant: &str,
        source: &str,
        kind: &str,
        delivery_id: &str,
        fields: &serde_json::Value,
        raw_sha256: &str,
        verified_by: &str,
    ) -> Result<(String, bool)> {
        if let Some(e) = self
            .conn
            .query_row(
                "SELECT id FROM trigger_events WHERE tenant = ?1 AND source = ?2 AND delivery_id = ?3",
                params![tenant, source, delivery_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok((e, false));
        }
        let eid = id("e");
        self.conn.execute(
            "INSERT INTO trigger_events (id, tenant, source, kind, delivery_id, received_at, fields, raw_sha256, verified_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![eid, tenant, source, kind, delivery_id, now(), fields.to_string(), raw_sha256, verified_by],
        )?;
        Ok((eid, true))
    }

    /// Whether a source already delivered `delivery_id`: what a dry run asks, so it reports only
    /// events not yet recorded.
    pub fn trigger_event_known(&self, tenant: &str, source: &str, delivery_id: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM trigger_events WHERE tenant = ?1 AND source = ?2 AND delivery_id = ?3",
                params![tenant, source, delivery_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Records what led to `message`, queued by `trigger`: `chain` with `trigger` added, one deeper.
    pub fn record_trigger_cause(&self, message: &str, trigger: &str, chain: &Chain) -> Result<()> {
        let mut next = chain.clone();
        if !next.ids.iter().any(|t| t == trigger) {
            next.ids.push(trigger.to_string());
        }
        next.depth += 1;
        let v = serde_json::json!({ "ids": next.ids, "depth": next.depth });
        self.conn.execute(
            "INSERT OR REPLACE INTO trigger_causes (message, trigger, chain, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![message, trigger, v.to_string(), now()],
        )?;
        Ok(())
    }

    /// The triggers that led to what `run` did up to `at`: every trigger in the chains of the
    /// turns triggers queued for it (or for its agent, moved to it when it woke) by then, sorted.
    pub fn trigger_chain(&self, run: &str, at: i64) -> Result<Chain> {
        let mut st = self.conn.prepare(
            "SELECT c.chain FROM trigger_causes c JOIN messages m ON m.id = c.message WHERE m.to_run = ?1 AND c.created_at <= ?2",
        )?;
        let rows = st.query_map(params![run, at], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut out = Chain::default();
        for c in rows.iter().map(|c| Chain::parse(c)) {
            out.ids.extend(c.ids);
            out.depth = out.depth.max(c.depth);
        }
        out.ids.sort();
        out.ids.dedup();
        Ok(out)
    }

    /// Who a run is, as a trigger may filter on it: its zone, its agent's name, and its principal
    /// (None for a run with no identity), from the ledger, not from anything the run wrote. A
    /// long-lived agent's new run is recorded (`agent.wake`) before its `runs` row exists: then
    /// its agent's zone and name, from the agent's row (its principal is the caller's to make).
    pub fn run_scope(&self, run: &str) -> Result<Option<(String, String, Option<String>)>> {
        if let Some(s) = self.run_row_scope(run)? {
            return Ok(Some(s));
        }
        Ok(self
            .conn
            .query_row("SELECT a.zone, a.name FROM agent_runs r JOIN agents a ON a.id = r.agent WHERE r.run = ?1", params![run], |r| {
                Ok((r.get(0)?, r.get(1)?, None))
            })
            .optional()?)
    }

    /// Whether `run` has a runs row.
    pub fn run_exists(&self, run: &str) -> Result<bool> {
        Ok(self.conn.query_row("SELECT 1 FROM runs WHERE id = ?1", params![run], |_| Ok(())).optional()?.is_some())
    }

    fn run_row_scope(&self, run: &str) -> Result<Option<(String, String, Option<String>)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT r.zone, r.agent, i.spiffe_id FROM runs r LEFT JOIN identities i ON i.run = r.id WHERE r.id = ?1",
                params![run],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    /// Audit records after `seq` and up to `upto`, of these kinds, oldest first, at most `limit`:
    /// what the triggers engine reads, without the records no trigger listens to.
    pub fn audit_records_of_kinds(&self, seq: i64, upto: i64, kinds: &[&str], limit: usize) -> Result<Vec<crate::AuditRecord>> {
        let marks = (0..kinds.len()).map(|i| format!("?{}", i + 4)).collect::<Vec<_>>().join(", ");
        let mut st = self.conn.prepare(&format!(
            "SELECT seq, ts, tenant, run, kind, body, prev, hash FROM audit WHERE seq > ?1 AND seq <= ?2 AND kind IN ({marks}) ORDER BY seq LIMIT ?3"
        ))?;
        let mut args: Vec<rusqlite::types::Value> = vec![seq.into(), upto.into(), (limit as i64).into()];
        args.extend(kinds.iter().map(|k| rusqlite::types::Value::Text(k.to_string())));
        let rows = st.query_map(rusqlite::params_from_iter(args), |r| {
            Ok(crate::AuditRecord {
                seq: r.get(0)?,
                ts: r.get(1)?,
                tenant: r.get(2)?,
                run: r.get(3)?,
                kind: r.get(4)?,
                body: r.get(5)?,
                prev: r.get(6)?,
                hash: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Runs `f` inside a savepoint of the caller's transaction: its writes are kept if it returns
    /// Ok and undone if it returns Err, the transaction's other writes kept either way.
    pub fn savepoint<T, E: From<StoreError>>(&self, f: impl FnOnce(&Ledger) -> std::result::Result<T, E>) -> std::result::Result<T, E> {
        self.conn.execute_batch("SAVEPOINT one_trigger").map_err(|e| E::from(e.into()))?;
        let r = f(self);
        let end = if r.is_ok() { "RELEASE one_trigger" } else { "ROLLBACK TO one_trigger; RELEASE one_trigger" };
        match (r, self.conn.execute_batch(end)) {
            (Ok(v), Ok(())) => Ok(v),
            (Ok(_), Err(e)) => Err(E::from(e.into())),
            (Err(e), _) => Err(e),
        }
    }

    /// Makes every firing of `trigger` fail to be recorded, as a store error would: for tests of
    /// what one trigger's error does to the rest.
    #[cfg(feature = "testkit")]
    pub fn fail_firings_for_test(&self, trigger: &str) {
        let t: String = trigger.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
        self.conn
            .execute_batch(&format!(
                "CREATE TEMP TRIGGER fail_{n} BEFORE INSERT ON trigger_firings WHEN NEW.trigger = '{t}' BEGIN SELECT RAISE(ABORT, 'refused for the test'); END;",
                n = t.replace('-', "_")
            ))
            .expect("a temp trigger");
    }

    /// How far a source that reads a sequence (wicket's own events: the audit chain's seq) has
    /// read, if it has started.
    pub fn trigger_cursor(&self, tenant: &str, source: &str) -> Result<Option<i64>> {
        Ok(self
            .conn
            .query_row("SELECT seq FROM trigger_cursors WHERE tenant = ?1 AND source = ?2", params![tenant, source], |r| r.get(0))
            .optional()?)
    }

    /// Moves a source's cursor on to `seq`. It never moves back.
    pub fn set_trigger_cursor(&self, tenant: &str, source: &str, seq: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO trigger_cursors (tenant, source, seq, updated_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (tenant, source) DO UPDATE SET seq = MAX(seq, excluded.seq), updated_at = excluded.updated_at",
            params![tenant, source, seq, now()],
        )?;
        Ok(())
    }

    /// Triggers held back on wicket's own events (an owner that couldn't be checked, #578): each
    /// one's id and the seq it has heard up to, while the shared cursor moves on.
    pub fn trigger_holds(&self, tenant: &str) -> Result<Vec<(String, i64)>> {
        let mut st = self.conn.prepare("SELECT source, seq FROM trigger_cursors WHERE tenant = ?1 AND source LIKE 'held:%'")?;
        let rows = st.query_map(params![tenant], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        Ok(rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|(s, seq)| s.strip_prefix("held:").map(|id| (id.to_string(), seq)))
            .collect())
    }

    /// Holds `trigger` at `seq` (it has heard up to there), or moves its hold on.
    pub fn hold_trigger(&self, tenant: &str, trigger: &str, seq: i64) -> Result<()> {
        self.set_trigger_cursor(tenant, &format!("held:{trigger}"), seq)
    }

    /// Ends `trigger`'s hold: it has caught up.
    pub fn release_trigger_hold(&self, tenant: &str, trigger: &str) -> Result<()> {
        self.conn.execute("DELETE FROM trigger_cursors WHERE tenant = ?1 AND source = ?2", params![tenant, format!("held:{trigger}")])?;
        Ok(())
    }

    /// The newest audit record written before `ts`, if any.
    pub fn audit_seq_before(&self, ts: i64) -> Result<Option<i64>> {
        Ok(self.conn.query_row("SELECT MAX(seq) FROM audit WHERE ts < ?1", params![ts], |r| r.get(0))?)
    }

    pub fn trigger_event(&self, id: &str) -> Result<Option<TriggerEvent>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, source, kind, delivery_id, received_at, fields, raw_sha256, verified_by FROM trigger_events WHERE id = ?1",
                params![id],
                |r| {
                    let fields: String = r.get(5)?;
                    Ok(TriggerEvent {
                        id: r.get(0)?,
                        source: r.get(1)?,
                        kind: r.get(2)?,
                        delivery_id: r.get(3)?,
                        received_at: r.get(4)?,
                        fields: serde_json::from_str(&fields).unwrap_or_default(),
                        raw_sha256: r.get(6)?,
                        verified_by: r.get(7)?,
                    })
                },
            )
            .optional()?)
    }

    /// What `event` becomes for `trigger`: once per pair, so an event a trigger already heard
    /// isn't fired twice (its firing's id, and false).
    pub fn record_firing(&self, trigger: &str, event: &str, status: &str, detail: Option<&str>) -> Result<(String, bool)> {
        if !FIRING_STATES.contains(&status) {
            return Err(StoreError::Refused(format!("a firing is one of {}, not {status}", FIRING_STATES.join(", "))));
        }
        if let Some(f) = self
            .conn
            .query_row("SELECT id FROM trigger_firings WHERE trigger = ?1 AND event = ?2", params![trigger, event], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
        {
            return Ok((f, false));
        }
        let fid = id("f");
        let t = now();
        self.conn.execute(
            "INSERT INTO trigger_firings (id, trigger, event, status, detail, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![fid, trigger, event, status, detail, t],
        )?;
        Ok((fid, true))
    }

    /// Moves a firing on: to `status`, with what it started (`run`) or why (`detail`). A failed
    /// one counts an attempt.
    pub fn update_firing(&self, id: &str, status: &str, detail: Option<&str>, run: Option<&str>) -> Result<()> {
        if !FIRING_STATES.contains(&status) {
            return Err(StoreError::Refused(format!("a firing is one of {}, not {status}", FIRING_STATES.join(", "))));
        }
        self.conn.execute(
            "UPDATE trigger_firings SET status = ?2, detail = COALESCE(?3, detail), run = COALESCE(?4, run), updated_at = ?5,
                    attempts = attempts + (?2 = 'failed') WHERE id = ?1",
            params![id, status, detail, run, now()],
        )?;
        Ok(())
    }

    /// A trigger's firings in `status`, oldest first.
    pub fn firings(&self, trigger: &str, status: Option<&str>) -> Result<Vec<Firing>> {
        self.firings_where(trigger, status, "ORDER BY created_at, id", -1)
    }

    /// A trigger's last `n` firings, newest first: what `wicket trigger show` lists.
    pub fn recent_firings(&self, trigger: &str, n: i64) -> Result<Vec<Firing>> {
        self.firings_where(trigger, None, "ORDER BY created_at DESC, id DESC", n)
    }

    fn firings_where(&self, trigger: &str, status: Option<&str>, order: &str, n: i64) -> Result<Vec<Firing>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT id, trigger, event, status, detail, run, attempts, created_at, updated_at FROM trigger_firings
             WHERE trigger = ?1 AND (?2 IS NULL OR status = ?2) {order} LIMIT ?3"
        ))?;
        let rows = st.query_map(params![trigger, status, n], |r| {
            Ok(Firing {
                id: r.get(0)?,
                trigger: r.get(1)?,
                event: r.get(2)?,
                status: r.get(3)?,
                detail: r.get(4)?,
                run: r.get(5)?,
                attempts: r.get(6)?,
                created_at: r.get(7)?,
                updated_at: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// How many of a trigger's firings since `since` are in `status`: what its hourly limit counts
    /// (started ones) and its queue holds (queued ones, `since` 0).
    pub fn count_firings(&self, trigger: &str, status: &str, since: i64) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM trigger_firings WHERE trigger = ?1 AND status = ?2 AND created_at >= ?3",
            params![trigger, status, since],
            |r| r.get(0),
        )?)
    }

    /// `run`'s claim on a piece of work (`github.com/acme/app#123`). One live claim per key: a
    /// key another live run holds is refused, naming it. The same run claiming again is a no-op.
    pub fn claim_work(&self, tenant: &str, key: &str, run: &str) -> Result<()> {
        if key.is_empty() || key.len() > 256 || key.chars().any(wicket_core::text::is_unsafe) {
            return Err(StoreError::Refused("a work key is 1 to 256 printable characters".into()));
        }
        if let Some(holder) = self.owner_of(tenant, key)? {
            if holder == run {
                return Ok(());
            }
            return Err(StoreError::Refused(format!("{key} is claimed by run {holder}")));
        }
        self.conn
            .execute("INSERT INTO work_claims (key, tenant, run, claimed_at) VALUES (?1, ?2, ?3, ?4)", params![key, tenant, run, now()])?;
        Ok(())
    }

    /// Releases `run`'s claims: one key, or (None) all of them, as its end does.
    pub fn release_work(&self, tenant: &str, run: &str, key: Option<&str>) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE work_claims SET released_at = ?4 WHERE tenant = ?1 AND run = ?2 AND (?3 IS NULL OR key = ?3) AND released_at IS NULL",
            params![tenant, run, key, now()],
        )?)
    }

    /// The run that holds a live claim on `key`, if one does.
    pub fn owner_of(&self, tenant: &str, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT run FROM work_claims WHERE tenant = ?1 AND key = ?2 AND released_at IS NULL", params![tenant, key], |r| {
                r.get(0)
            })
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(y: &str) -> TriggerSpec {
        wicket_core::yaml::from_str(y).unwrap()
    }
    const OWNER: &str = "spiffe://w/t/t0/z/work/a/captain";

    /// #578: a trigger is kept for its owner, unique by name while it isn't deleted; one that
    /// widens waits for a human before it is live; paused or lapsed, it isn't; a document that
    /// doesn't hold to its shape isn't kept.
    #[test]
    fn a_trigger_is_kept_paused_approved_and_lapses() {
        let l = Ledger::open_in_memory().unwrap();
        let morning = spec("trigger: morning\nsource: { schedule: { cron: '0 7 * * 1-5' } }\naction: { wake: self }\n");
        let id = l.create_trigger("t0", OWNER, &morning, "agent:run_c", false, None).unwrap();
        assert!(id.starts_with("t-"));
        let t = l.trigger(&id).unwrap().unwrap();
        assert!(t.live(now()) && t.spec == morning && t.approval == "none");
        assert!(l.create_trigger("t0", OWNER, &morning, "x", false, None).is_err(), "one name per owner");
        l.set_trigger_status(&id, "paused").unwrap();
        assert!(!l.trigger(&id).unwrap().unwrap().live(now()));
        l.set_trigger_status(&id, "active").unwrap();
        l.set_trigger_status(&id, "deleted").unwrap();
        assert!(l.set_trigger_status(&id, "active").is_err(), "deleted stays deleted");
        assert!(l.triggers("t0", None).unwrap().is_empty());
        l.create_trigger("t0", OWNER, &morning, "x", false, None).unwrap();

        let wide = spec(&format!(
            "trigger: triage\nsource: {{ timer: {{ after: 2h }} }}\naction: {{ start: {{ manifest: triage.yaml, sha256: {} }} }}\n",
            "a".repeat(64)
        ));
        let w = l.create_trigger("t0", OWNER, &wide, "agent:run_c", !wide.only_self(), Some(now() + 3600)).unwrap();
        assert!(!l.trigger(&w).unwrap().unwrap().live(now()), "waits for a human");
        l.approve_trigger(&w, "passkey:phone").unwrap();
        assert!(l.trigger(&w).unwrap().unwrap().live(now()));
        assert!(l.approve_trigger(&w, "passkey:phone").is_err(), "once");
        assert!(!l.trigger(&w).unwrap().unwrap().live(now() + 7200), "lapsed");
        assert_eq!(l.triggers("t0", Some(OWNER)).unwrap().len(), 2);

        let bad = TriggerSpec { trigger: "Bad Name".into(), ..morning };
        assert!(matches!(l.create_trigger("t0", OWNER, &bad, "x", false, None), Err(StoreError::Refused(_))));
    }

    /// An event is once per source and delivery id; a firing once per trigger and event; a firing
    /// moves on and counts its failures.
    #[test]
    fn events_and_firings_happen_once() {
        let l = Ledger::open_in_memory().unwrap();
        let fields = serde_json::json!({ "pr": { "number": 12 }, "conclusion": "failure" });
        let (e, fresh) = l.record_trigger_event("t0", "github", "check_suite", "d-1", &fields, "ab", "hmac:gh-hook").unwrap();
        assert!(fresh);
        assert_eq!(
            l.record_trigger_event("t0", "github", "check_suite", "d-1", &fields, "ab", "hmac:gh-hook").unwrap(),
            (e.clone(), false)
        );
        assert_eq!(l.trigger_event(&e).unwrap().unwrap().fields, fields);
        assert!(l.trigger_event_known("t0", "github", "d-1").unwrap());
        assert!(!l.trigger_event_known("t0", "github", "d-2").unwrap());
        assert!(!l.trigger_event_known("t0", "webhook", "d-1").unwrap(), "per source");
        assert_eq!(l.trigger_cursor("t0", "wicket").unwrap(), None);
        l.set_trigger_cursor("t0", "wicket", 7).unwrap();
        l.set_trigger_cursor("t0", "wicket", 5).unwrap();
        assert_eq!(l.trigger_cursor("t0", "wicket").unwrap(), Some(7), "never back");
        l.set_trigger_cursor("t0", "wicket", 9).unwrap();
        assert_eq!(l.trigger_cursor("t0", "wicket").unwrap(), Some(9));
        let (f, fresh) = l.record_firing("t-1", &e, "queued", None).unwrap();
        assert!(fresh);
        assert_eq!(l.record_firing("t-1", &e, "queued", None).unwrap(), (f.clone(), false), "once per trigger and event");
        l.update_firing(&f, "failed", Some("no capacity"), None).unwrap();
        l.update_firing(&f, "started", None, Some("run_x")).unwrap();
        let fs = l.firings("t-1", None).unwrap();
        assert_eq!(
            (fs[0].status.as_str(), fs[0].run.as_deref(), fs[0].attempts, fs[0].detail.as_deref()),
            ("started", Some("run_x"), 1, Some("no capacity"))
        );
        assert!(l.record_firing("t-1", "e-2", "maybe", None).is_err());
        l.record_firing("t-1", "e-3", "queued", None).unwrap();
        assert_eq!(l.count_firings("t-1", "started", 0).unwrap(), 1);
        assert_eq!(l.count_firings("t-1", "queued", 0).unwrap(), 1);
        assert_eq!(l.count_firings("t-1", "started", now() + 10).unwrap(), 0, "only since the time asked");
        let recent = l.recent_firings("t-1", 1).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(l.recent_firings("t-1", 10).unwrap().len(), 2);
    }

    /// A time-told trigger's last recorded minute is its own (not another's whose id it starts
    /// with); an hour's skips count on one firing; old settled rows are pruned, waiting ones kept.
    #[test]
    fn slots_skips_and_pruning() {
        let l = Ledger::open_in_memory().unwrap();
        let ev = |d: &str, slot: i64| {
            l.record_trigger_event("t0", "schedule", "tick", d, &serde_json::json!({ "slot": slot }), "x", "wicket").unwrap().0
        };
        assert_eq!(l.last_trigger_slot("t0", "t-1").unwrap(), None);
        ev("t-1@120", 120);
        let e = ev("t-1@60", 60);
        ev("t-10@999", 999);
        assert_eq!(l.last_trigger_slot("t0", "t-1").unwrap(), Some(120));
        let (f, _) = l.record_firing("t-1", &e, "skipped", Some("over")).unwrap();
        l.count_skip(&f, "over, 2 times").unwrap();
        let got = l.last_firing("t-1", "skipped", 0).unwrap().unwrap();
        assert_eq!((got.attempts, got.detail.as_deref()), (1, Some("over, 2 times")));
        assert!(l.last_firing("t-1", "skipped", now() + 10).unwrap().is_none());
        let (q, _) = l.record_firing("t-1", &ev("t-1@180", 180), "queued", None).unwrap();
        assert_eq!(l.prune_triggers(now() + 10).unwrap(), 4, "the skipped firing and three events no firing waits on");
        assert_eq!(l.firings("t-1", None).unwrap().iter().map(|f| f.id.as_str()).collect::<Vec<_>>(), [q.as_str()]);
        assert_eq!(l.last_trigger_slot("t0", "t-1").unwrap(), Some(180), "a waiting firing's event stays");
    }

    /// A spent timer is done: not live, not paused or resumed, only removed; a new trigger of its
    /// name replaces it.
    #[test]
    fn a_done_trigger_gives_way() {
        let l = Ledger::open_in_memory().unwrap();
        let s: TriggerSpec =
            wicket_core::yaml::from_str("trigger: later\nsource: { timer: { after: 1h } }\naction: { wake: self }\n").unwrap();
        let a = l.create_trigger("t0", "op", &s, "x", false, None).unwrap();
        assert!(l.create_trigger("t0", "op", &s, "x", false, None).is_err(), "the name is taken");
        assert!(l.finish_trigger(&a).unwrap());
        assert!(!l.finish_trigger(&a).unwrap(), "once");
        let t = l.trigger(&a).unwrap().unwrap();
        assert!(t.status == "done" && !t.live(0));
        assert!(l.set_trigger_status(&a, "active").is_err() && l.set_trigger_status(&a, "paused").is_err());
        assert_eq!(l.triggers("t0", None).unwrap().len(), 1, "listed until removed");
        let b = l.create_trigger("t0", "op", &s, "x", false, None).unwrap();
        assert_eq!(l.trigger(&a).unwrap().unwrap().status, "deleted");
        assert_eq!(l.triggers("t0", None).unwrap().iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), [b.as_str()]);
    }

    /// A run recorded before its runs row (a long-lived agent's wake) is scoped from its agent; a
    /// chain's cap counts the longest single chain, while every trigger in any chain stays out;
    /// a lapsed trigger renewed starts from now, a live one's floor stays.
    #[test]
    fn scopes_chains_and_renewals() {
        let mut l = Ledger::open_in_memory().unwrap();
        l.create_agent(&crate::NewAgent {
            id: "agt_x",
            tenant: "t0",
            zone: "rel",
            name: "captain",
            run: "run_1",
            session_id: "s",
            manifest: "m",
            image: "i",
            workspace: None,
            claim_until: 0,
        })
        .unwrap();
        assert_eq!(l.run_scope("run_1").unwrap(), Some(("rel".into(), "captain".into(), None)), "from the agent's row");
        assert_eq!(l.run_scope("run_none").unwrap(), None);
        // Four chains of one (four schedules), queued for one run: depth 1, four members.
        for (i, t) in ["t-a", "t-b", "t-c", "t-d"].iter().enumerate() {
            let m = l.add_prompt("run_1", "hi", "trigger:x", "op").unwrap();
            l.record_trigger_cause(&m, t, &Chain::default()).unwrap();
            assert_eq!(l.trigger_chain("run_1", now() + 10).unwrap().ids.len(), i + 1);
        }
        let c = l.trigger_chain("run_1", now() + 10).unwrap();
        assert_eq!((c.ids.len(), c.depth), (4, 1));
        // A chain grown by one is one deeper; the first version's list form reads as deep as long.
        let m = l.add_prompt("run_1", "hi", "trigger:x", "op").unwrap();
        l.record_trigger_cause(&m, "t-e", &c).unwrap();
        assert_eq!(l.trigger_chain("run_1", now() + 10).unwrap().depth, 2);
        assert_eq!(Chain::parse(r#"["a","b","c"]"#), Chain { ids: vec!["a".into(), "b".into(), "c".into()], depth: 3 });
        let id = l
            .create_trigger("t0", "op", &spec("trigger: t\nsource: { timer: { after: 1h } }\naction: { wake: self }\n"), "x", false, None)
            .unwrap();
        l.conn.execute("UPDATE triggers SET updated_at = 100 WHERE id = ?1", params![id]).unwrap();
        l.renew_trigger(&id, Some(now() + 3600)).unwrap();
        assert_eq!(l.trigger(&id).unwrap().unwrap().updated_at, 100, "live: the floor stays");
        l.conn.execute("UPDATE triggers SET until = 50 WHERE id = ?1", params![id]).unwrap();
        l.renew_trigger(&id, Some(now() + 3600)).unwrap();
        assert!(l.trigger(&id).unwrap().unwrap().updated_at >= now() - 5, "lapsed: from now");
    }

    /// Work is claimed by one live run at a time, released by it (or all of a run's at its end),
    /// and `owner_of` names the holder.
    #[test]
    fn work_is_claimed_by_one_run_at_a_time() {
        let l = Ledger::open_in_memory().unwrap();
        let pr = "github.com/acme/app#123";
        l.claim_work("t0", pr, "run_a").unwrap();
        l.claim_work("t0", pr, "run_a").unwrap();
        assert!(matches!(l.claim_work("t0", pr, "run_b"), Err(StoreError::Refused(w)) if w.contains("run_a")));
        assert_eq!(l.owner_of("t0", pr).unwrap().as_deref(), Some("run_a"));
        l.claim_work("t0", "github.com/acme/app#124", "run_a").unwrap();
        assert_eq!(l.release_work("t0", "run_a", None).unwrap(), 2);
        assert_eq!(l.owner_of("t0", pr).unwrap(), None);
        l.claim_work("t0", pr, "run_b").unwrap();
        assert!(l.claim_work("t0", "a\u{1b}b", "run_b").is_err());
    }
}
