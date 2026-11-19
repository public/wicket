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
"#;

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
    /// `active`, `paused` or `deleted`.
    pub status: String,
    /// `none` (it widened nothing), `pending` (it waits for a human), or `approved`.
    pub approval: String,
    pub created_at: i64,
    pub created_by: String,
    /// When it lapses (None: until deleted).
    pub until: Option<i64>,
    pub decided_by: Option<String>,
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
}

fn id(prefix: &str) -> String {
    let r = wicket_core::new_request_id();
    format!("{prefix}-{}", &r[2..])
}

const COLS: &str = "id, tenant, owner, name, spec, status, approval, created_at, created_by, until, decided_by";

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
            "UPDATE triggers SET status = ?2, updated_at = ?3 WHERE id = ?1 AND status != 'deleted'",
            params![id, status, now()],
        )?;
        if n != 1 {
            return Err(StoreError::Refused(format!("no trigger {id}, or it is deleted")));
        }
        Ok(())
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
        let mut st = self.conn.prepare(
            "SELECT id, trigger, event, status, detail, run, attempts FROM trigger_firings
             WHERE trigger = ?1 AND (?2 IS NULL OR status = ?2) ORDER BY created_at, id",
        )?;
        let rows = st.query_map(params![trigger, status], |r| {
            Ok(Firing {
                id: r.get(0)?,
                trigger: r.get(1)?,
                event: r.get(2)?,
                status: r.get(3)?,
                detail: r.get(4)?,
                run: r.get(5)?,
                attempts: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
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
