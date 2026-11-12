//! The ledger (design §11): the server-side record of authority. Single-use and expiry live here,
//! never in tokens. Every table carries the tenant id so platform mode can partition later.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wicket_core::{new_grant_id, new_request_id, Op, RunId, TenantId};

mod links;
mod node;
pub use links::{ExposeRow, LinkRow};
mod lease;
pub use lease::{new_lease_id, BudgetRefusal, LeaseBudget, LeaseRow, LIVE as LIVE_LEASES};
pub use node::{AuditRecord, GrantRow, NodeAuditSummary};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("no such request {0}")]
    NoSuchRequest(String),
    #[error("request {0} is {1}, not pending")]
    NotPending(String, String),
    #[error("audit chain broken at seq {0}")]
    ChainBroken(i64),
    #[error("join token: {0}")]
    Token(&'static str),
    #[error("node {0}: {1}")]
    Node(String, &'static str),
    #[error("random: {0}")]
    Random(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// One audit entry as `audit_tail` returns it: sequence, timestamp, kind, run, body.
pub type AuditRow = (i64, i64, String, Option<String>, String);

pub struct Ledger {
    conn: Connection,
}

#[derive(Debug, Clone, Serialize)]
pub struct Request {
    pub id: String,
    pub tenant: String,
    pub run: String,
    pub zone: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub risk: String,
    pub reason: String,
    pub status: String,
    pub created_at: i64,
    /// Who inside the box asked, as reported by the agent's event stream (one entry per distinct
    /// asker; each is an attribution object). Untrusted: shown to humans, never used to decide.
    pub attribution: Vec<serde_json::Value>,
    /// The agent asked for every path under `path` (request_access with scope prefix), not one path.
    pub scope_prefix: bool,
}

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: String,
    pub from_run: String,
    pub envelope: String,
    pub created_at: i64,
}

/// The identity document wicket issued for one run, with the fields it is looked up by.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityRow {
    pub run: String,
    pub tenant: String,
    pub spiffe_id: String,
    pub zone: String,
    pub agent: String,
    pub parent_run: Option<String>,
    /// The zone's `accept_from` at launch: who may message this agent besides parent and children.
    pub accept_from: Vec<String>,
    pub jws: String,
    pub issued_at: i64,
}

/// An operator's passkey (ES256 public key; base64url credential id).
#[derive(Debug, Clone, Serialize)]
pub struct OperatorCredential {
    pub id: String,
    pub name: String,
    #[serde(skip)]
    pub x: [u8; 32],
    #[serde(skip)]
    pub y: [u8; 32],
    pub sign_count: u32,
}

/// A console sign-in session (`wicket serve`). The ledger holds only the SHA-256 of the cookie's
/// token (`id`), so reading the ledger does not hand out live sessions; the host lists and revokes
/// sessions here (`wicket operator sessions`, `wicket operator revoke-session`) while the console runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsoleSession {
    pub id: String,
    /// "operator" (signed in with a passkey) or "bootstrap" (opened the one-time enrolment link).
    pub kind: String,
    /// The passkey it signed in with (operator sessions), or the id of the enrolment link it was
    /// opened with (bootstrap sessions).
    pub credential: Option<String>,
    /// The client address it signed in from.
    pub client: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    /// Absolute expiry: no amount of activity extends a session past it.
    pub expires_at: i64,
}

fn console_session_row(r: &rusqlite::Row) -> rusqlite::Result<ConsoleSession> {
    Ok(ConsoleSession {
        id: r.get(0)?,
        kind: r.get(1)?,
        credential: r.get(2)?,
        client: r.get(3)?,
        created_at: r.get(4)?,
        last_seen_at: r.get(5)?,
        expires_at: r.get(6)?,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct RunRow {
    pub id: String,
    pub zone: String,
    pub agent: String,
    pub status: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Approval {
    /// None = unlimited uses until expiry.
    pub uses: Option<u32>,
    pub ttl: Duration,
    /// Grant the whole path prefix instead of the exact path.
    pub path_prefix: Option<String>,
    pub decided_by: String,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, zone TEXT NOT NULL, agent TEXT NOT NULL,
  status TEXT NOT NULL, started_at INTEGER NOT NULL, ended_at INTEGER, detail TEXT, owner TEXT, lease TEXT
);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, run TEXT NOT NULL, zone TEXT NOT NULL, digest TEXT NOT NULL,
  method TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL, risk TEXT NOT NULL, reason TEXT NOT NULL,
  status TEXT NOT NULL, created_at INTEGER NOT NULL, decided_at INTEGER, decided_by TEXT,
  attribution TEXT NOT NULL DEFAULT '[]', scope_prefix INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS requests_pending ON requests (tenant, zone, digest, status);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, zone TEXT NOT NULL, method TEXT NOT NULL, host TEXT NOT NULL,
  path TEXT NOT NULL, prefix INTEGER NOT NULL, uses_left INTEGER, expires_at INTEGER NOT NULL,
  request_id TEXT, decided_by TEXT NOT NULL, created_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
  node TEXT
);
CREATE TABLE IF NOT EXISTS operator_credentials (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, name TEXT NOT NULL, x BLOB NOT NULL, y BLOB NOT NULL,
  sign_count INTEGER NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS identities (
  run TEXT PRIMARY KEY, tenant TEXT NOT NULL, spiffe_id TEXT NOT NULL, zone TEXT NOT NULL, agent TEXT NOT NULL,
  parent_run TEXT, accept_from TEXT NOT NULL DEFAULT '[]', jws TEXT NOT NULL, issued_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS operator_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT NOT NULL, text TEXT NOT NULL, by TEXT NOT NULL,
  created_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS identity_history (
  run TEXT NOT NULL, jws TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_history_run ON identity_history (run, issued_at);
CREATE TABLE IF NOT EXISTS revocations (
  run TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL, by TEXT NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, from_run TEXT NOT NULL, to_run TEXT NOT NULL, envelope TEXT NOT NULL,
  created_at INTEGER NOT NULL, delivered_at INTEGER
);
CREATE INDEX IF NOT EXISTS messages_inbox ON messages (to_run, delivered_at, created_at);
CREATE TABLE IF NOT EXISTS node_tokens (
  hash TEXT PRIMARY KEY, tenant TEXT NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER
);
CREATE TABLE IF NOT EXISTS nodes (
  name TEXT PRIMARY KEY, tenant TEXT NOT NULL, target TEXT NOT NULL, host_key TEXT NOT NULL, host_key_fp TEXT NOT NULL,
  node_key TEXT NOT NULL, ssh_key TEXT, hosts TEXT NOT NULL DEFAULT '[]', enrolled_at INTEGER NOT NULL,
  status TEXT NOT NULL, revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS node_cas (
  serial TEXT PRIMARY KEY, node TEXT NOT NULL, issued_at INTEGER NOT NULL, not_after INTEGER NOT NULL,
  hosts TEXT NOT NULL, status TEXT NOT NULL, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS node_cas_node ON node_cas (node, status);
CREATE TABLE IF NOT EXISTS node_certs (
  serial TEXT PRIMARY KEY, node TEXT NOT NULL, node_key TEXT NOT NULL, issued_at INTEGER NOT NULL,
  not_after INTEGER NOT NULL, status TEXT NOT NULL, revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS node_certs_node ON node_certs (node, issued_at);
CREATE TABLE IF NOT EXISTS console_sessions (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, kind TEXT NOT NULL, credential TEXT, client TEXT NOT NULL,
  created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  revoked_at INTEGER, revoked_by TEXT
);
CREATE TABLE IF NOT EXISTS console_enrol_links (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  created_by TEXT NOT NULL, used_at INTEGER, used_client TEXT
);
CREATE TABLE IF NOT EXISTS leases (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, run TEXT NOT NULL, request_id TEXT, provider TEXT NOT NULL, spec TEXT NOT NULL,
  hourly_cap INTEGER NOT NULL, reserved INTEGER NOT NULL, duration_secs INTEGER NOT NULL, created_at INTEGER NOT NULL,
  not_after INTEGER, status TEXT NOT NULL, node_id TEXT, node_name TEXT, ssh_target TEXT, host_key TEXT, billed INTEGER,
  ended_at INTEGER, detail TEXT
);
CREATE INDEX IF NOT EXISTS leases_status ON leases (tenant, status);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, tenant TEXT NOT NULL, run TEXT,
  kind TEXT NOT NULL, body TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL
);
"#;

impl Ledger {
    pub fn open(path: &Path) -> Result<Ledger> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(links::SCHEMA)?;
        // Ledgers created before passkey revocation existed.
        let _ = conn.execute("ALTER TABLE operator_credentials ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0", []);
        // Ledgers created before requests recorded who asked.
        let _ = conn.execute("ALTER TABLE requests ADD COLUMN attribution TEXT NOT NULL DEFAULT '[]'", []);
        let _ = conn.execute("ALTER TABLE requests ADD COLUMN scope_prefix INTEGER NOT NULL DEFAULT 0", []);
        // Ledgers created before grants could be handed to a node.
        let _ = conn.execute("ALTER TABLE grants ADD COLUMN node TEXT", []);
        // Ledgers created before runs recorded their supervising process.
        let _ = conn.execute("ALTER TABLE runs ADD COLUMN owner TEXT", []);
        let _ = conn.execute("ALTER TABLE runs ADD COLUMN lease TEXT", []);
        Ok(Ledger { conn })
    }

    pub fn open_in_memory() -> Result<Ledger> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(links::SCHEMA)?;
        Ok(Ledger { conn })
    }

    // ---- runs ----

    pub fn run_started(&self, tenant: &TenantId, run: &RunId, zone: &str, agent: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO runs (id, tenant, zone, agent, status, started_at) VALUES (?1, ?2, ?3, ?4, 'running', ?5)",
            params![run.0, tenant.0, zone, agent, now()],
        )?;
        Ok(())
    }

    /// Ends a run. Its still-pending requests are withdrawn: a request belongs to the work that
    /// raised it, and must not be approvable after that work is gone.
    pub fn run_ended(&self, run: &RunId, status: &str, detail: &str) -> Result<usize> {
        self.conn
            .execute("UPDATE runs SET status = ?2, ended_at = ?3, detail = ?4 WHERE id = ?1", params![run.0, status, now(), detail])?;
        let n = self.conn.execute(
            "UPDATE requests SET status = 'withdrawn', decided_at = ?2, decided_by = 'wicket:run-ended' WHERE run = ?1 AND status = 'pending'",
            params![run.0, now()],
        )?;
        self.close_links_of(&run.0)?;
        // A lease nobody has approved yet goes with the run that asked for it.
        self.conn.execute(
            "UPDATE leases SET status = 'withdrawn', detail = 'its run ended before a decision', ended_at = ?2 WHERE run = ?1 AND status = 'pending'",
            params![run.0, now()],
        )?;
        Ok(n)
    }

    // ---- escalation requests ----

    /// Returns the id of the pending request for this op, creating it if needed (deduplicated on the
    /// op digest, so a retrying agent doesn't flood the queue).
    /// Records a pending request for `op`, or returns the existing one. `who` is the attribution of
    /// this ask; when a *different* asker hits an existing request, it is added, so the human sees
    /// everyone a grant would serve.
    pub fn pending_for(&self, op: &Op, reason: &str, who: Option<&serde_json::Value>) -> Result<(String, bool)> {
        let digest = op.digest();
        if let Some((id, attr)) = self
            .conn
            .query_row(
                "SELECT id, attribution FROM requests WHERE tenant = ?1 AND zone = ?2 AND digest = ?3 AND status = 'pending'",
                params![op.tenant.0, op.zone, digest],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if let Some(w) = who {
                let mut list: Vec<serde_json::Value> = serde_json::from_str(&attr).unwrap_or_default();
                if !list.iter().any(|x| same_askers(x, w)) && list.len() < 8 {
                    list.push(w.clone());
                    self.conn.execute(
                        "UPDATE requests SET attribution = ?2 WHERE id = ?1",
                        params![id, serde_json::Value::from(list).to_string()],
                    )?;
                }
            }
            return Ok((id, false));
        }
        let id = new_request_id();
        let attr = serde_json::Value::from(who.cloned().into_iter().collect::<Vec<_>>()).to_string();
        self.conn.execute(
            "INSERT INTO requests (id, tenant, run, zone, digest, method, host, path, risk, reason, status, created_at, attribution)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11, ?12)",
            params![id, op.tenant.0, op.run.0, op.zone, digest, op.method, op.host, op.path, format!("{:?}", op.risk), reason, now(), attr],
        )?;
        Ok((id, true))
    }

    // ---- operator follow-ups to a running agent ----

    /// Queues a follow-up from the operator for a running agent. Operator text is trusted task text
    /// (it comes from the principal), unlike anything an agent or a web page says.
    pub fn add_operator_message(&self, run: &str, text: &str, by: &str) -> Result<i64> {
        self.conn
            .execute("INSERT INTO operator_messages (run, text, by, created_at) VALUES (?1, ?2, ?3, ?4)", params![run, text, by, now()])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Takes every queued follow-up for `run`, oldest first: (text, by). Each is handed out once.
    pub fn take_operator_messages(&mut self, run: &str) -> Result<Vec<(String, String)>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows: Vec<(i64, String, String)> = {
            let mut st = tx.prepare("SELECT id, text, by FROM operator_messages WHERE run = ?1 AND consumed_at IS NULL ORDER BY id")?;
            let r = st.query_map(params![run], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            r.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (id, _, _) in &rows {
            tx.execute("UPDATE operator_messages SET consumed_at = ?2 WHERE id = ?1", params![id, now()])?;
        }
        tx.commit()?;
        Ok(rows.into_iter().map(|(_, t, b)| (t, b)).collect())
    }

    // ---- identities and messages (design §3.2) ----

    /// Replaces a run's current identity document (rotation) and keeps the old one in history.
    pub fn rotate_identity(&self, run: &str, jws: &str, issued_at: i64, expires_at: i64) -> Result<()> {
        self.conn.execute("UPDATE identities SET jws = ?2, issued_at = ?3 WHERE run = ?1", params![run, jws, issued_at])?;
        self.conn.execute(
            "INSERT INTO identity_history (run, jws, issued_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![run, jws, issued_at, expires_at],
        )?;
        Ok(())
    }

    /// Every identity document ever issued (run, jws, issued_at), for offline verification.
    pub fn identity_history(&self) -> Result<Vec<(String, String, i64)>> {
        let mut st = self.conn.prepare("SELECT run, jws, issued_at FROM identity_history ORDER BY issued_at")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Revokes a run's identity: its messages stop being delivered, its requests can't be
    /// approved, and its runner stops the box. Idempotent.
    pub fn revoke(&self, run: &str, by: &str, reason: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "INSERT OR IGNORE INTO revocations (run, revoked_at, by, reason) VALUES (?1, ?2, ?3, ?4)",
            params![run, now(), by, reason],
        )? > 0)
    }

    /// Whether this run or any run it descends from is revoked: a child acts on its parent's
    /// authority, so revoking the parent revokes the subtree. Returns (revoked run, when, by, reason).
    pub fn revoked_in_chain(&self, run: &str) -> Result<Option<(String, i64, String, String)>> {
        let mut cur = Some(run.to_string());
        for _ in 0..32 {
            let Some(r) = cur else { break };
            if let Some((when, by, reason)) = self.revoked(&r)? {
                return Ok(Some((r, when, by, reason)));
            }
            cur = self.identity(&r)?.and_then(|i| i.parent_run);
        }
        Ok(None)
    }

    /// When and why a run's identity was revoked, if it was.
    pub fn revoked(&self, run: &str) -> Result<Option<(i64, String, String)>> {
        Ok(self
            .conn
            .query_row("SELECT revoked_at, by, reason FROM revocations WHERE run = ?1", params![run], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?)
    }

    /// Records the identity document wicket issued for a run.
    pub fn put_identity(&self, id: &IdentityRow) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO identities (run, tenant, spiffe_id, zone, agent, parent_run, accept_from, jws, issued_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id.run,
                id.tenant,
                id.spiffe_id,
                id.zone,
                id.agent,
                id.parent_run,
                serde_json::Value::from(id.accept_from.clone()).to_string(),
                id.jws,
                id.issued_at
            ],
        )?;
        self.conn.execute(
            "INSERT INTO identity_history (run, jws, issued_at, expires_at) VALUES (?1, ?2, ?3, 0)",
            params![id.run, id.jws, id.issued_at],
        )?;
        Ok(())
    }

    pub fn identity(&self, run: &str) -> Result<Option<IdentityRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT run, tenant, spiffe_id, zone, agent, parent_run, accept_from, jws, issued_at FROM identities WHERE run = ?1",
                params![run],
                row_to_identity,
            )
            .optional()?)
    }

    pub fn identities(&self) -> Result<Vec<IdentityRow>> {
        let mut st = self.conn.prepare(
            "SELECT run, tenant, spiffe_id, zone, agent, parent_run, accept_from, jws, issued_at FROM identities ORDER BY issued_at",
        )?;
        let rows = st.query_map([], row_to_identity)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// A run's status ("running", "succeeded", …), if it exists.
    pub fn run_status(&self, run: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT status FROM runs WHERE id = ?1", params![run], |r| r.get(0)).optional()?)
    }

    /// Children started by `run` (from their identity documents).
    pub fn children(&self, run: &str) -> Result<Vec<IdentityRow>> {
        let mut st = self.conn.prepare("SELECT run, tenant, spiffe_id, zone, agent, parent_run, accept_from, jws, issued_at FROM identities WHERE parent_run = ?1 ORDER BY issued_at")?;
        let rows = st.query_map(params![run], row_to_identity)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn add_message(&self, id: &str, tenant: &TenantId, from_run: &str, to_run: &str, envelope: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO messages (id, tenant, from_run, to_run, envelope, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, tenant.0, from_run, to_run, envelope, now()],
        )?;
        Ok(())
    }

    /// Takes the oldest undelivered message for `run`. Marked delivered in the same transaction, so
    /// each message is handed out once. `created_at` is when wicket recorded it: the time its
    /// sender's identity must have been valid.
    pub fn take_message(&mut self, run: &str) -> Result<Option<StoredMessage>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m: Option<StoredMessage> = tx
            .query_row(
                "SELECT id, from_run, envelope, created_at FROM messages WHERE to_run = ?1 AND delivered_at IS NULL ORDER BY created_at, id LIMIT 1",
                params![run],
                |r| Ok(StoredMessage { id: r.get(0)?, from_run: r.get(1)?, envelope: r.get(2)?, created_at: r.get(3)? }),
            )
            .optional()?;
        if let Some(StoredMessage { id, .. }) = &m {
            tx.execute("UPDATE messages SET delivered_at = ?2 WHERE id = ?1", params![id, now()])?;
        }
        tx.commit()?;
        Ok(m)
    }

    /// Every stored envelope (id, envelope, created_at), for offline verification.
    pub fn envelopes(&self) -> Result<Vec<(String, String, i64)>> {
        let mut st = self.conn.prepare("SELECT id, envelope, created_at FROM messages ORDER BY created_at")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// An agent asking ahead for access it needs (request_access), rather than a blocked request.
    /// `prefix` asks for every path under `op.path`. Deduplicated like any pending request.
    pub fn ask(&self, op: &Op, reason: &str, prefix: bool, who: Option<&serde_json::Value>) -> Result<(String, bool)> {
        let digest = format!("{}{}", op.digest(), if prefix { ":prefix" } else { "" });
        if let Some(id) = self
            .conn
            .query_row(
                "SELECT id FROM requests WHERE tenant = ?1 AND zone = ?2 AND digest = ?3 AND status = 'pending'",
                params![op.tenant.0, op.zone, digest],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok((id, false));
        }
        let id = new_request_id();
        let attr = serde_json::Value::from(who.cloned().into_iter().collect::<Vec<_>>()).to_string();
        self.conn.execute(
            "INSERT INTO requests (id, tenant, run, zone, digest, method, host, path, risk, reason, status, created_at, attribution, scope_prefix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11, ?12, ?13)",
            params![id, op.tenant.0, op.run.0, op.zone, digest, op.method, op.host, op.path, format!("{:?}", op.risk), reason, now(), attr, prefix as i64],
        )?;
        Ok((id, true))
    }

    /// The request a grant was made for, if any.
    pub fn request_for_grant(&self, grant: &str) -> Result<Option<Request>> {
        let rid: Option<Option<String>> =
            self.conn.query_row("SELECT request_id FROM grants WHERE id = ?1", params![grant], |r| r.get(0)).optional()?;
        match rid.flatten() {
            Some(rid) => Ok(Some(self.request(&rid)?)),
            None => Ok(None),
        }
    }

    pub fn request(&self, id: &str) -> Result<Request> {
        self.conn
            .query_row("SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at, attribution, scope_prefix FROM requests WHERE id = ?1", params![id], row_to_request)
            .optional()?
            .ok_or_else(|| StoreError::NoSuchRequest(id.to_string()))
    }

    /// The most recent runs, newest first.
    pub fn runs(&self, tenant: &TenantId, limit: usize) -> Result<Vec<RunRow>> {
        let mut st = self.conn.prepare(
            "SELECT id, zone, agent, status, started_at, ended_at FROM runs WHERE tenant = ?1 ORDER BY started_at DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![tenant.0, limit as i64], |r| {
            Ok(RunRow { id: r.get(0)?, zone: r.get(1)?, agent: r.get(2)?, status: r.get(3)?, started_at: r.get(4)?, ended_at: r.get(5)? })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Recently decided requests, newest first.
    pub fn decided(&self, tenant: &TenantId, limit: usize) -> Result<Vec<Request>> {
        let mut st = self.conn.prepare(
            "SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at, attribution, scope_prefix FROM requests
             WHERE tenant = ?1 AND status != 'pending' ORDER BY decided_at DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![tenant.0, limit as i64], row_to_request)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn pending(&self, tenant: &TenantId) -> Result<Vec<Request>> {
        let mut st = self.conn.prepare(
            "SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at, attribution, scope_prefix FROM requests
             WHERE tenant = ?1 AND status = 'pending' ORDER BY created_at",
        )?;
        let rows = st.query_map(params![tenant.0], row_to_request)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Approves a pending request: records the decision and mints a grant no wider than the ask
    /// (exact path unless a narrower-or-equal prefix of the asked path is given).
    pub fn approve(&mut self, id: &str, a: &Approval) -> Result<String> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let req = tx
            .query_row("SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at, attribution, scope_prefix FROM requests WHERE id = ?1", params![id], row_to_request)
            .optional()?
            .ok_or_else(|| StoreError::NoSuchRequest(id.to_string()))?;
        if req.status != "pending" {
            return Err(StoreError::NotPending(id.into(), req.status));
        }
        let (path, prefix) = match &a.path_prefix {
            Some(p) if req.path.starts_with(p.as_str()) => (p.clone(), 1),
            // A prefix ask is granted as asked unless the human narrows it.
            _ if req.scope_prefix => (req.path.clone(), 1),
            _ => (req.path.clone(), 0),
        };
        let gid = new_grant_id();
        let t = now();
        tx.execute(
            "INSERT INTO grants (id, tenant, zone, method, host, path, prefix, uses_left, expires_at, request_id, decided_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                gid,
                req.tenant,
                req.zone,
                req.method,
                req.host,
                path,
                prefix,
                a.uses,
                t + a.ttl.as_secs() as i64,
                req.id,
                a.decided_by,
                t
            ],
        )?;
        tx.execute("UPDATE requests SET status = 'granted', decided_at = ?2, decided_by = ?3 WHERE id = ?1", params![id, t, a.decided_by])?;
        tx.commit()?;
        Ok(gid)
    }

    pub fn deny(&self, id: &str, by: &str) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE requests SET status = 'denied', decided_at = ?2, decided_by = ?3 WHERE id = ?1 AND status = 'pending'",
            params![id, now(), by],
        )?;
        if n == 0 {
            let r = self.request(id)?;
            return Err(StoreError::NotPending(id.into(), r.status));
        }
        Ok(())
    }

    /// Finds a live grant covering the op and consumes one use, atomically. Returns the grant id.
    pub fn consume_grant(&mut self, op: &Op) -> Result<Option<String>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let t = now();
        let found: Option<(String, Option<i64>)> = tx
            .query_row(
                "SELECT id, uses_left FROM grants
                 WHERE tenant = ?1 AND zone = ?2 AND method = ?3 AND host = ?4 AND revoked = 0 AND expires_at > ?5
                   AND node IS NULL
                   AND (uses_left IS NULL OR uses_left > 0)
                   AND ((prefix = 0 AND path = ?6) OR (prefix = 1 AND substr(?6, 1, length(path)) = path))
                 ORDER BY prefix ASC, created_at ASC LIMIT 1",
                params![op.tenant.0, op.zone, op.method, op.host, t, op.path],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((gid, uses)) = found else {
            tx.commit()?;
            return Ok(None);
        };
        if uses.is_some() {
            tx.execute("UPDATE grants SET uses_left = uses_left - 1 WHERE id = ?1", params![gid])?;
        }
        tx.commit()?;
        Ok(Some(gid))
    }

    pub fn denied_recently(&self, op: &Op) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM requests WHERE tenant = ?1 AND zone = ?2 AND digest = ?3 AND status = 'denied' AND decided_at > ?4 ORDER BY decided_at DESC LIMIT 1",
                params![op.tenant.0, op.zone, op.digest(), now() - 600],
                |r| r.get(0),
            )
            .optional()?)
    }

    // ---- operator passkeys ----

    pub fn add_operator_credential(&self, tenant: &TenantId, c: &OperatorCredential) -> Result<()> {
        self.conn.execute(
            "INSERT INTO operator_credentials (id, tenant, name, x, y, sign_count, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![c.id, tenant.0, c.name, c.x.to_vec(), c.y.to_vec(), c.sign_count, now()],
        )?;
        Ok(())
    }

    /// Passkeys that may sign in and decide.
    pub fn operator_credentials(&self, tenant: &TenantId) -> Result<Vec<OperatorCredential>> {
        self.operator_credentials_where(tenant, "AND revoked = 0")
    }

    /// Every passkey ever enrolled, revoked ones included: needed to re-verify old signed decisions.
    pub fn operator_credentials_all(&self, tenant: &TenantId) -> Result<Vec<OperatorCredential>> {
        self.operator_credentials_where(tenant, "")
    }

    fn operator_credentials_where(&self, tenant: &TenantId, filter: &str) -> Result<Vec<OperatorCredential>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT id, name, x, y, sign_count FROM operator_credentials WHERE tenant = ?1 {filter} ORDER BY created_at"
        ))?;
        let rows = st.query_map(params![tenant.0], |r| {
            let x: Vec<u8> = r.get(2)?;
            let y: Vec<u8> = r.get(3)?;
            Ok(OperatorCredential {
                id: r.get(0)?,
                name: r.get(1)?,
                x: x.try_into().unwrap_or([0u8; 32]),
                y: y.try_into().unwrap_or([0u8; 32]),
                sign_count: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn touch_operator_credential(&self, id: &str, sign_count: u32) -> Result<()> {
        self.conn
            .execute("UPDATE operator_credentials SET sign_count = ?2, last_used_at = ?3 WHERE id = ?1", params![id, sign_count, now()])?;
        Ok(())
    }

    /// Host-only break-glass: revoke every operator passkey for a tenant. Public keys are kept, so
    /// decisions they signed can still be verified.
    pub fn reset_operator_credentials(&self, tenant: &TenantId) -> Result<usize> {
        Ok(self.conn.execute("UPDATE operator_credentials SET revoked = 1 WHERE tenant = ?1 AND revoked = 0", params![tenant.0])?)
    }

    // ---- console sessions ----

    pub fn add_console_session(&self, tenant: &TenantId, s: &ConsoleSession) -> Result<()> {
        self.conn.execute(
            "INSERT INTO console_sessions (id, tenant, kind, credential, client, created_at, last_seen_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![s.id, tenant.0, s.kind, s.credential, s.client, s.created_at, s.last_seen_at, s.expires_at],
        )?;
        Ok(())
    }

    /// A session that is neither revoked nor past its absolute expiry at `at` (idle expiry is the
    /// console's to judge, from `last_seen_at`).
    pub fn console_session(&self, tenant: &TenantId, id: &str, at: i64) -> Result<Option<ConsoleSession>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, kind, credential, client, created_at, last_seen_at, expires_at FROM console_sessions
                 WHERE tenant = ?1 AND id = ?2 AND revoked_at IS NULL AND expires_at > ?3",
                params![tenant.0, id, at],
                console_session_row,
            )
            .optional()?)
    }

    /// Live sessions (not revoked, not past absolute expiry), oldest first.
    pub fn console_sessions(&self, tenant: &TenantId, at: i64) -> Result<Vec<ConsoleSession>> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, credential, client, created_at, last_seen_at, expires_at FROM console_sessions
             WHERE tenant = ?1 AND revoked_at IS NULL AND expires_at > ?2 ORDER BY created_at",
        )?;
        let rows = st.query_map(params![tenant.0, at], console_session_row)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn touch_console_session(&self, id: &str, at: i64) -> Result<()> {
        self.conn.execute("UPDATE console_sessions SET last_seen_at = ?2 WHERE id = ?1 AND last_seen_at < ?2", params![id, at])?;
        Ok(())
    }

    /// Revokes live sessions whose id starts with `prefix` (every live session with None). Returns
    /// the ids revoked.
    pub fn revoke_console_sessions(&self, tenant: &TenantId, prefix: Option<&str>, by: &str) -> Result<Vec<String>> {
        let at = now();
        let live = self.console_sessions(tenant, at)?;
        let ids: Vec<String> = live.into_iter().map(|s| s.id).filter(|id| prefix.is_none_or(|p| id.starts_with(p))).collect();
        for id in &ids {
            self.conn.execute(
                "UPDATE console_sessions SET revoked_at = ?2, revoked_by = ?3 WHERE id = ?1 AND revoked_at IS NULL",
                params![id, at, by],
            )?;
        }
        Ok(ids)
    }

    /// Ends one session (sign-out, or rotation at sign-in).
    pub fn end_console_session(&self, id: &str, by: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE console_sessions SET revoked_at = ?2, revoked_by = ?3 WHERE id = ?1 AND revoked_at IS NULL",
            params![id, now(), by],
        )?;
        Ok(())
    }

    /// Forgets sessions that ended (expired or revoked) before `before`.
    pub fn prune_console_sessions(&self, before: i64) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM console_sessions WHERE expires_at < ?1 OR (revoked_at IS NOT NULL AND revoked_at < ?1)",
            params![before],
        )?)
    }

    // ---- console enrolment links ----

    /// Records a host-issued, single-use enrolment link. `id` is the SHA-256 of its token (hex), so
    /// reading the ledger does not hand out usable links.
    pub fn add_enrol_link(&self, tenant: &TenantId, id: &str, expires_at: i64, by: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO console_enrol_links (id, tenant, created_at, expires_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, tenant.0, now(), expires_at, by],
        )?;
        Ok(())
    }

    /// Uses the enrolment link `id` at `at` from `client`, atomically: true only if it exists for
    /// `tenant`, has not been used, and has not expired. A link works at most once.
    pub fn use_enrol_link(&self, tenant: &TenantId, id: &str, at: i64, client: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE console_enrol_links SET used_at = ?3, used_client = ?4
             WHERE tenant = ?1 AND id = ?2 AND used_at IS NULL AND expires_at > ?3",
            params![tenant.0, id, at, client],
        )? == 1)
    }

    // ---- audit ----

    /// Appends a hash-chained audit record: hash = sha256(prev || kind || body).
    pub fn audit(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: &serde_json::Value) -> Result<i64> {
        let body = serde_json::to_string(body)?;
        // Several processes append to one ledger (a run, its children, a link's relay): read the head
        // and append under one write lock, or two appends can chain from the same record.
        let own = self.conn.is_autocommit();
        if own {
            self.conn.execute_batch("BEGIN IMMEDIATE")?;
        }
        let r = self.append_audit(tenant, run, kind, &body);
        if own {
            let _ = self.conn.execute_batch(if r.is_ok() { "COMMIT" } else { "ROLLBACK" });
        }
        r
    }

    fn append_audit(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: &str) -> Result<i64> {
        let prev: String = self
            .conn
            .query_row("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| "0".repeat(64));
        let hash = chain_hash(&prev, kind, body);
        self.conn.execute(
            "INSERT INTO audit (ts, tenant, run, kind, body, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![now(), tenant.0, run.map(|r| r.0.clone()), kind, body, prev, hash],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn audit_tail(&self, n: usize) -> Result<Vec<AuditRow>> {
        let mut st = self.conn.prepare("SELECT seq, ts, kind, run, body FROM audit ORDER BY seq DESC LIMIT ?1")?;
        let rows = st.query_map(params![n as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        let mut v = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        v.reverse();
        Ok(v)
    }

    /// Recomputes the whole chain. Returns the number of records verified.
    pub fn verify_audit(&self) -> Result<i64> {
        let mut st = self.conn.prepare("SELECT seq, kind, body, prev, hash FROM audit ORDER BY seq")?;
        let mut rows = st.query([])?;
        let mut prev = "0".repeat(64);
        let mut n = 0;
        while let Some(r) = rows.next()? {
            let (seq, kind, body, p, h): (i64, String, String, String, String) = (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
            if p != prev || chain_hash(&prev, &kind, &body) != h {
                return Err(StoreError::ChainBroken(seq));
            }
            prev = h;
            n += 1;
        }
        Ok(n)
    }
}

/// An audit record's hash: sha256(prev, 0, kind, 0, body), hex. Nodes chain their own logs the same way.
pub fn chain_hash(prev: &str, kind: &str, body: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update([0u8]);
    h.update(kind.as_bytes());
    h.update([0u8]);
    h.update(body.as_bytes());
    hex::encode(h.finalize())
}

fn row_to_request(r: &rusqlite::Row<'_>) -> rusqlite::Result<Request> {
    Ok(Request {
        id: r.get(0)?,
        tenant: r.get(1)?,
        run: r.get(2)?,
        zone: r.get(3)?,
        method: r.get(4)?,
        host: r.get(5)?,
        path: r.get(6)?,
        risk: r.get(7)?,
        reason: r.get(8)?,
        status: r.get(9)?,
        created_at: r.get(10)?,
        attribution: serde_json::from_str(&r.get::<_, String>(11)?).unwrap_or_default(),
        scope_prefix: r.get::<_, i64>(12)? != 0,
    })
}

fn row_to_identity(r: &rusqlite::Row<'_>) -> rusqlite::Result<IdentityRow> {
    Ok(IdentityRow {
        run: r.get(0)?,
        tenant: r.get(1)?,
        spiffe_id: r.get(2)?,
        zone: r.get(3)?,
        agent: r.get(4)?,
        parent_run: r.get(5)?,
        accept_from: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
        jws: r.get(7)?,
        issued_at: r.get(8)?,
    })
}

/// Whether two attribution objects name the same askers (same agents and calls).
fn same_askers(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    let key = |v: &serde_json::Value| -> Vec<(String, String)> {
        v.get("requesters")
            .and_then(|r| r.as_array())
            .map(|rs| {
                rs.iter()
                    .map(|r| {
                        (
                            r.get("agent").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                            r.get("call").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    key(a) == key(b)
}

/// An enrolled node (design §8, #16): where it is, how it's pinned, and its key.
#[derive(Debug, Clone, Serialize)]
pub struct NodeRow {
    pub name: String,
    pub tenant: String,
    /// The ssh target, e.g. `wicket@203.0.113.7`.
    pub target: String,
    /// The pinned ssh host key, `<type> <base64>`.
    pub host_key: String,
    /// Its SHA256 fingerprint, as `ssh-keygen -l` prints it.
    pub host_key_fp: String,
    /// The node's Ed25519 public key (hex), generated on the node.
    pub node_key: String,
    /// The ssh identity the control host logs in with, if not the default.
    pub ssh_key: Option<String>,
    /// The hosts the node's CA is constrained to.
    pub hosts: Vec<String>,
    pub enrolled_at: i64,
    /// "active" or "revoked".
    pub status: String,
    pub revoked_at: Option<i64>,
}

/// One intermediate CA certificate issued to a node.
#[derive(Debug, Clone, Serialize)]
pub struct NodeCaRow {
    /// Hex, big-endian.
    pub serial: String,
    pub node: String,
    pub issued_at: i64,
    pub not_after: i64,
    /// The permitted DNS subtrees it carries.
    pub hosts: Vec<String>,
    /// "active", "superseded" (replaced by `renew-ca`) or "revoked" (the node was revoked).
    pub status: String,
}

const NODE_COLS: &str = "name, tenant, target, host_key, host_key_fp, node_key, ssh_key, hosts, enrolled_at, status, revoked_at";

fn row_to_node(r: &rusqlite::Row) -> rusqlite::Result<NodeRow> {
    let hosts: String = r.get(7)?;
    Ok(NodeRow {
        name: r.get(0)?,
        tenant: r.get(1)?,
        target: r.get(2)?,
        host_key: r.get(3)?,
        host_key_fp: r.get(4)?,
        node_key: r.get(5)?,
        ssh_key: r.get(6)?,
        hosts: serde_json::from_str(&hosts).unwrap_or_default(),
        enrolled_at: r.get(8)?,
        status: r.get(9)?,
        revoked_at: r.get(10)?,
    })
}

fn row_to_node_ca(r: &rusqlite::Row) -> rusqlite::Result<NodeCaRow> {
    let hosts: String = r.get(4)?;
    Ok(NodeCaRow {
        serial: r.get(0)?,
        node: r.get(1)?,
        issued_at: r.get(2)?,
        not_after: r.get(3)?,
        hosts: serde_json::from_str(&hosts).unwrap_or_default(),
        status: r.get(5)?,
    })
}

/// One node identity certificate (`wicket_identity::node`) issued to a node.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NodeCertRow {
    /// The certificate's `jti`.
    pub serial: String,
    pub node: String,
    /// The node key it binds (hex).
    pub node_key: String,
    pub issued_at: i64,
    pub not_after: i64,
    /// "active" (renewals leave earlier ones active until they expire) or "revoked".
    pub status: String,
}

fn row_to_node_cert(r: &rusqlite::Row) -> rusqlite::Result<NodeCertRow> {
    Ok(NodeCertRow {
        serial: r.get(0)?,
        node: r.get(1)?,
        node_key: r.get(2)?,
        issued_at: r.get(3)?,
        not_after: r.get(4)?,
        status: r.get(5)?,
    })
}

const NODE_CERT_COLS: &str = "serial, node, node_key, issued_at, not_after, status";

/// sha256 of a join token: the ledger stores only this.
fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

/// Node enrolment (#16).
///
/// **Join tokens** are one-time and short-lived. `wicket node token` makes one for an intended node
/// name; the ledger keeps only its sha256, the name and the expiry. The operator redeems it on the
/// control host with `wicket node enrol`: the token is proof that whoever minted it meant *this* name
/// to join, so a typo or a stale command can't enrol (or re-key) a node by accident. It is checked
/// before any remote work and redeemed atomically, together with recording the node, at the end.
impl Ledger {
    /// Makes a join token for node `name`, valid for `ttl_secs`. Returns the token, shown once.
    pub fn create_node_token(&self, tenant: &TenantId, name: &str, ttl_secs: i64) -> Result<String> {
        let mut b = [0u8; 32];
        getrandom::getrandom(&mut b).map_err(|e| StoreError::Random(e.to_string()))?;
        let token = format!("wkt_{}", hex::encode(b));
        let t = now();
        self.conn.execute(
            "INSERT INTO node_tokens (hash, tenant, name, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![token_hash(&token), tenant.0, name, t, t + ttl_secs],
        )?;
        Ok(token)
    }

    /// The node name a token was made for, if it is still redeemable at `at`. Doesn't redeem it.
    pub fn check_node_token(&self, token: &str, at: i64) -> Result<String> {
        let row: Option<(String, i64, Option<i64>)> = self
            .conn
            .query_row("SELECT name, expires_at, used_at FROM node_tokens WHERE hash = ?1", params![token_hash(token)], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        match row {
            None => Err(StoreError::Token("unknown")),
            Some((_, _, Some(_))) => Err(StoreError::Token("already used")),
            Some((_, exp, None)) if exp <= at => Err(StoreError::Token("expired")),
            Some((name, _, None)) => Ok(name),
        }
    }

    /// Redeems `token` for `node.name` and records the node and its first CA certificate, in one
    /// transaction: either all of it happens or none. Refused if the token is unknown, used, expired
    /// or for another name, or if a node of that name is enrolled and not revoked.
    pub fn enrol_node(&mut self, token: &str, node: &NodeRow, ca: &NodeCaRow) -> Result<()> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = tx.execute(
            "UPDATE node_tokens SET used_at = ?2 WHERE hash = ?1 AND name = ?3 AND used_at IS NULL AND expires_at > ?2",
            params![token_hash(token), now(), node.name],
        )?;
        if n != 1 {
            return Err(StoreError::Token("unknown, already used, expired, or for another node name"));
        }
        let existing: Option<String> =
            tx.query_row("SELECT status FROM nodes WHERE name = ?1", params![node.name], |r| r.get(0)).optional()?;
        if existing.as_deref().is_some_and(|s| s != "revoked") {
            return Err(StoreError::Node(node.name.clone(), "is already enrolled (revoke it first)"));
        }
        tx.execute(
            &format!("INSERT OR REPLACE INTO nodes ({NODE_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', NULL)"),
            params![
                node.name,
                node.tenant,
                node.target,
                node.host_key,
                node.host_key_fp,
                node.node_key,
                node.ssh_key,
                serde_json::Value::from(node.hosts.clone()).to_string(),
                node.enrolled_at
            ],
        )?;
        insert_node_ca(&tx, ca)?;
        tx.commit()?;
        Ok(())
    }

    /// Records a renewed CA certificate for an active node; its earlier active ones become "superseded".
    pub fn renew_node_ca(&mut self, ca: &NodeCaRow) -> Result<()> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status: Option<String> = tx.query_row("SELECT status FROM nodes WHERE name = ?1", params![ca.node], |r| r.get(0)).optional()?;
        match status.as_deref() {
            None => return Err(StoreError::Node(ca.node.clone(), "is not enrolled")),
            Some("active") => {}
            Some(_) => return Err(StoreError::Node(ca.node.clone(), "is revoked")),
        }
        tx.execute("UPDATE node_cas SET status = 'superseded' WHERE node = ?1 AND status = 'active'", params![ca.node])?;
        insert_node_ca(&tx, ca)?;
        tx.execute("UPDATE nodes SET hosts = ?2 WHERE name = ?1", params![ca.node, serde_json::Value::from(ca.hosts.clone()).to_string()])?;
        tx.commit()?;
        Ok(())
    }

    /// Marks a node revoked, and its unexpired CA certificates with it. Returns their serials (for the
    /// feed's revocation list). Revoking twice is refused.
    pub fn revoke_node(&mut self, name: &str) -> Result<Vec<String>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let t = now();
        let n =
            tx.execute("UPDATE nodes SET status = 'revoked', revoked_at = ?2 WHERE name = ?1 AND status != 'revoked'", params![name, t])?;
        if n != 1 {
            return Err(StoreError::Node(name.into(), "is not enrolled, or already revoked"));
        }
        let serials = {
            let mut st = tx.prepare(
                "SELECT serial FROM node_cas WHERE node = ?1 AND status != 'revoked' AND not_after > ?2 ORDER BY issued_at, rowid",
            )?;
            let rows = st.query_map(params![name, t], |r| r.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for s in &serials {
            tx.execute("UPDATE node_cas SET status = 'revoked', revoked_at = ?2 WHERE serial = ?1", params![s, t])?;
        }
        tx.execute("UPDATE node_certs SET status = 'revoked', revoked_at = ?2 WHERE node = ?1 AND status != 'revoked'", params![name, t])?;
        tx.commit()?;
        Ok(serials)
    }

    /// Records a node identity certificate issued to an active node. Earlier ones stay valid until
    /// they expire, so a node that lost a renewal on the way still gets in with the one it holds.
    pub fn record_node_cert(&self, c: &NodeCertRow) -> Result<()> {
        let status: Option<String> =
            self.conn.query_row("SELECT status FROM nodes WHERE name = ?1", params![c.node], |r| r.get(0)).optional()?;
        match status.as_deref() {
            None => return Err(StoreError::Node(c.node.clone(), "is not enrolled")),
            Some("active") => {}
            Some(_) => return Err(StoreError::Node(c.node.clone(), "is revoked")),
        }
        self.conn.execute(
            &format!("INSERT INTO node_certs ({NODE_CERT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, 'active')"),
            params![c.serial, c.node, c.node_key, c.issued_at, c.not_after],
        )?;
        Ok(())
    }

    /// A node certificate by serial.
    pub fn node_cert(&self, serial: &str) -> Result<Option<NodeCertRow>> {
        Ok(self
            .conn
            .query_row(&format!("SELECT {NODE_CERT_COLS} FROM node_certs WHERE serial = ?1"), params![serial], row_to_node_cert)
            .optional()?)
    }

    /// A node's identity certificates, newest first.
    pub fn node_certs(&self, node: &str) -> Result<Vec<NodeCertRow>> {
        let mut st =
            self.conn.prepare(&format!("SELECT {NODE_CERT_COLS} FROM node_certs WHERE node = ?1 ORDER BY issued_at DESC, rowid DESC"))?;
        let rows = st.query_map(params![node], row_to_node_cert)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn node(&self, name: &str) -> Result<Option<NodeRow>> {
        Ok(self.conn.query_row(&format!("SELECT {NODE_COLS} FROM nodes WHERE name = ?1"), params![name], row_to_node).optional()?)
    }

    /// The node enrolled most recently under ssh target `target`, if any.
    pub fn node_by_target(&self, target: &str) -> Result<Option<NodeRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {NODE_COLS} FROM nodes WHERE target = ?1 ORDER BY enrolled_at DESC LIMIT 1"),
                params![target],
                row_to_node,
            )
            .optional()?)
    }

    pub fn nodes(&self) -> Result<Vec<NodeRow>> {
        let mut st = self.conn.prepare(&format!("SELECT {NODE_COLS} FROM nodes ORDER BY name"))?;
        let rows = st.query_map([], row_to_node)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// A node's CA certificates, newest first.
    pub fn node_cas(&self, node: &str) -> Result<Vec<NodeCaRow>> {
        let mut st = self.conn.prepare(
            "SELECT serial, node, issued_at, not_after, hosts, status FROM node_cas WHERE node = ?1 ORDER BY issued_at DESC, rowid DESC",
        )?;
        let rows = st.query_map(params![node], row_to_node_ca)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Revoked node CA certificates that haven't expired at `at`: what the feed's revocation list will
    /// carry. (Superseded ones are left to expire: renewal replaces the key on the node.)
    pub fn revoked_node_cas(&self, at: i64) -> Result<Vec<NodeCaRow>> {
        let mut st = self.conn.prepare(
            "SELECT serial, node, issued_at, not_after, hosts, status FROM node_cas WHERE status = 'revoked' AND not_after > ?1 ORDER BY revoked_at",
        )?;
        let rows = st.query_map(params![at], row_to_node_ca)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }
}

fn insert_node_ca(tx: &rusqlite::Transaction, ca: &NodeCaRow) -> Result<()> {
    tx.execute(
        "INSERT INTO node_cas (serial, node, issued_at, not_after, hosts, status) VALUES (?1, ?2, ?3, ?4, ?5, 'active')",
        params![ca.serial, ca.node, ca.issued_at, ca.not_after, serde_json::Value::from(ca.hosts.clone()).to_string()],
    )?;
    Ok(())
}

#[cfg(test)]
mod node_tests {
    use super::*;

    fn node(name: &str) -> NodeRow {
        NodeRow {
            name: name.into(),
            tenant: TenantId::single().0,
            target: "wicket@203.0.113.7".into(),
            host_key: "ssh-ed25519 AAAA".into(),
            host_key_fp: "SHA256:x".into(),
            node_key: "00".repeat(32),
            ssh_key: None,
            hosts: vec!["api.example.com".into()],
            enrolled_at: now(),
            status: "active".into(),
            revoked_at: None,
        }
    }

    fn ca(node: &str, serial: &str) -> NodeCaRow {
        NodeCaRow {
            serial: serial.into(),
            node: node.into(),
            issued_at: now(),
            not_after: now() + 86_400,
            hosts: vec!["api.example.com".into()],
            status: "active".into(),
        }
    }

    #[test]
    fn a_join_token_is_single_use_and_for_one_name() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = l.create_node_token(&TenantId::single(), "n1", 3600).unwrap();
        assert!(t.starts_with("wkt_") && t.len() == 68);
        assert_eq!(l.check_node_token(&t, now()).unwrap(), "n1");
        let stored: String = l.conn.query_row("SELECT hash FROM node_tokens", [], |r| r.get(0)).unwrap();
        assert_ne!(stored, t, "only the hash is stored");
        assert!(l.enrol_node(&t, &node("n2"), &ca("n2", "01")).is_err(), "another name");
        assert!(l.node("n2").unwrap().is_none(), "nothing recorded when refused");
        l.enrol_node(&t, &node("n1"), &ca("n1", "01")).unwrap();
        assert!(matches!(l.check_node_token(&t, now()), Err(StoreError::Token("already used"))));
        let t2 = l.create_node_token(&TenantId::single(), "n1", 3600).unwrap();
        assert!(l.enrol_node(&t2, &node("n1"), &ca("n1", "02")).is_err(), "n1 is enrolled already");
        assert!(l.enrol_node(&t, &node("n1"), &ca("n1", "03")).is_err(), "second use");
        assert!(matches!(l.check_node_token("wkt_nope", now()), Err(StoreError::Token("unknown"))));
    }

    #[test]
    fn a_join_token_expires() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = l.create_node_token(&TenantId::single(), "n1", 60).unwrap();
        assert!(l.check_node_token(&t, now() + 30).is_ok());
        assert!(matches!(l.check_node_token(&t, now() + 61), Err(StoreError::Token("expired"))));
        let gone = l.create_node_token(&TenantId::single(), "n1", 0).unwrap();
        assert!(l.enrol_node(&gone, &node("n1"), &ca("n1", "01")).is_err());
        assert!(l.node("n1").unwrap().is_none());
    }

    #[test]
    fn nodes_are_recorded_renewed_and_revoked_with_their_ca_serials() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = l.create_node_token(&TenantId::single(), "n1", 3600).unwrap();
        l.enrol_node(&t, &node("n1"), &ca("n1", "0a")).unwrap();
        let n = l.node("n1").unwrap().unwrap();
        assert_eq!(
            (n.status.as_str(), n.target.as_str(), n.hosts.clone()),
            ("active", "wicket@203.0.113.7", vec!["api.example.com".to_string()])
        );
        assert_eq!(l.node_by_target("wicket@203.0.113.7").unwrap().unwrap().name, "n1");
        l.renew_node_ca(&ca("n1", "0b")).unwrap();
        let cas = l.node_cas("n1").unwrap();
        assert_eq!(
            cas.iter().map(|c| (c.serial.as_str(), c.status.as_str())).collect::<Vec<_>>(),
            vec![("0b", "active"), ("0a", "superseded")]
        );
        let revoked = l.revoke_node("n1").unwrap();
        assert_eq!(revoked, vec!["0a", "0b"]);
        assert_eq!(l.node("n1").unwrap().unwrap().status, "revoked");
        assert_eq!(l.revoked_node_cas(now()).unwrap().len(), 2);
        assert!(l.revoked_node_cas(now() + 90_000).unwrap().is_empty(), "expired ones drop off the list");
        assert!(l.revoke_node("n1").is_err());
        assert!(l.renew_node_ca(&ca("n1", "0c")).is_err(), "no new CA for a revoked node");
        // Re-enrolling a revoked name takes a fresh token, and keeps the old serials revoked.
        let t2 = l.create_node_token(&TenantId::single(), "n1", 3600).unwrap();
        l.enrol_node(&t2, &node("n1"), &ca("n1", "0d")).unwrap();
        assert_eq!(l.node("n1").unwrap().unwrap().status, "active");
        assert_eq!(l.revoked_node_cas(now()).unwrap().len(), 2);
        assert_eq!(l.nodes().unwrap().len(), 1);
    }

    #[test]
    fn node_certificates_are_recorded_for_active_nodes_and_revoked_with_them() {
        let mut l = Ledger::open_in_memory().unwrap();
        let cert = |serial: &str| NodeCertRow {
            serial: serial.into(),
            node: "n1".into(),
            node_key: "00".repeat(32),
            issued_at: now(),
            not_after: now() + 86_400,
            status: "active".into(),
        };
        assert!(l.record_node_cert(&cert("c0")).is_err(), "not enrolled");
        let t = l.create_node_token(&TenantId::single(), "n1", 3600).unwrap();
        l.enrol_node(&t, &node("n1"), &ca("n1", "0a")).unwrap();
        l.record_node_cert(&cert("c1")).unwrap();
        l.record_node_cert(&cert("c2")).unwrap();
        assert_eq!(l.node_cert("c1").unwrap().unwrap(), cert("c1"));
        assert_eq!(l.node_certs("n1").unwrap().iter().map(|c| c.serial.as_str()).collect::<Vec<_>>(), vec!["c2", "c1"]);
        assert!(l.record_node_cert(&cert("c2")).is_err(), "serials are unique");
        l.revoke_node("n1").unwrap();
        assert!(l.node_certs("n1").unwrap().iter().all(|c| c.status == "revoked"));
        assert!(l.record_node_cert(&cert("c3")).is_err(), "revoked");
        assert!(l.node_cert("nope").unwrap().is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(path: &str) -> Op {
        Op::egress(&TenantId::single(), &RunId("run_t".into()), "z", "POST", "github.com", path)
    }

    #[test]
    fn enrol_links_work_once_before_they_expire() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let at = now();
        l.add_enrol_link(&t, "l1", at + 600, "host").unwrap();
        l.add_enrol_link(&t, "l2", at + 600, "host").unwrap();
        l.add_enrol_link(&t, "old", at - 1, "host").unwrap();
        assert!(!l.use_enrol_link(&TenantId("other".into()), "l1", at, "192.0.2.1").unwrap(), "another tenant's");
        assert!(!l.use_enrol_link(&t, "nope", at, "192.0.2.1").unwrap(), "unknown");
        assert!(!l.use_enrol_link(&t, "old", at, "192.0.2.1").unwrap(), "expired");
        assert!(!l.use_enrol_link(&t, "l2", at + 600, "192.0.2.1").unwrap(), "expired at its expiry");
        assert!(l.use_enrol_link(&t, "l1", at, "192.0.2.1").unwrap());
        assert!(!l.use_enrol_link(&t, "l1", at, "192.0.2.1").unwrap(), "used");
        assert!(l.add_enrol_link(&t, "l1", at + 600, "host").is_err(), "ids are unique");
    }

    #[test]
    fn console_sessions_expire_and_are_revoked_by_prefix() {
        let l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let at = now();
        let s = |id: &str, expires_at| ConsoleSession {
            id: id.into(),
            kind: "operator".into(),
            credential: Some("c".into()),
            client: "192.0.2.1".into(),
            created_at: at,
            last_seen_at: at,
            expires_at,
        };
        l.add_console_session(&t, &s("aa11", at + 100)).unwrap();
        l.add_console_session(&t, &s("aa22", at + 100)).unwrap();
        l.add_console_session(&t, &s("bb33", at + 100)).unwrap();
        assert!(l.console_session(&t, "aa11", at).unwrap().is_some());
        assert!(l.console_session(&t, "aa11", at + 100).unwrap().is_none(), "past its absolute expiry");
        assert!(l.console_session(&TenantId("other".into()), "aa11", at).unwrap().is_none());
        l.touch_console_session("aa11", at + 50).unwrap();
        l.touch_console_session("aa11", at + 10).unwrap();
        assert_eq!(l.console_session(&t, "aa11", at).unwrap().unwrap().last_seen_at, at + 50, "never moves back");
        assert_eq!(l.revoke_console_sessions(&t, Some("aa"), "host").unwrap(), vec!["aa11", "aa22"]);
        assert!(l.console_session(&t, "aa22", at).unwrap().is_none());
        assert_eq!(l.console_sessions(&t, at).unwrap().len(), 1);
        l.end_console_session("bb33", "sign-out").unwrap();
        assert!(l.console_sessions(&t, at).unwrap().is_empty());
        assert_eq!(l.prune_console_sessions(at + 1000).unwrap(), 3);
    }

    #[test]
    fn a_prefix_ask_is_granted_for_the_prefix() {
        let mut l = Ledger::open_in_memory().unwrap();
        let ask = Op::egress(&TenantId::single(), &RunId("run_t".into()), "z", "GET", "news.example.org", "/");
        let (id, fresh) = l.ask(&ask, "need the front page and items", true, None).unwrap();
        assert!(fresh && l.request(&id).unwrap().scope_prefix);
        assert_eq!(l.ask(&ask, "again", true, None).unwrap(), (id.clone(), false), "asking twice is one request");
        l.approve(&id, &Approval { uses: None, ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() }).unwrap();
        let later = Op::egress(&TenantId::single(), &RunId("run_t".into()), "z", "GET", "news.example.org", "/item");
        assert!(l.consume_grant(&later).unwrap().is_some(), "every path under the prefix");
    }

    #[test]
    fn operator_follow_ups_are_taken_once() {
        let mut l = Ledger::open_in_memory().unwrap();
        l.add_operator_message("run_a", "first", "owner").unwrap();
        l.add_operator_message("run_a", "second", "owner").unwrap();
        l.add_operator_message("run_b", "other run", "owner").unwrap();
        let got = l.take_operator_messages("run_a").unwrap();
        assert_eq!(got.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(), vec!["first", "second"]);
        assert!(l.take_operator_messages("run_a").unwrap().is_empty());
    }

    #[test]
    fn messages_are_delivered_once_in_order() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        l.add_message("m-1", &t, "run_a", "run_b", "env1").unwrap();
        l.add_message("m-2", &t, "run_a", "run_b", "env2").unwrap();
        l.add_message("m-3", &t, "run_a", "run_c", "env3").unwrap();
        assert_eq!(l.take_message("run_b").unwrap().unwrap().id, "m-1");
        assert_eq!(l.take_message("run_b").unwrap().unwrap().id, "m-2");
        assert!(l.take_message("run_b").unwrap().is_none());
        assert_eq!(l.envelopes().unwrap().len(), 3);
    }

    #[test]
    fn identities_are_found_by_run_and_parent() {
        let l = Ledger::open_in_memory().unwrap();
        let row = |run: &str, parent: Option<&str>| IdentityRow {
            run: run.into(),
            tenant: "t0".into(),
            spiffe_id: format!("spiffe://x/{run}"),
            zone: "z".into(),
            agent: "a".into(),
            parent_run: parent.map(String::from),
            accept_from: vec!["ops".into()],
            jws: "j".into(),
            issued_at: 1,
        };
        l.put_identity(&row("run_p", None)).unwrap();
        l.put_identity(&row("run_c", Some("run_p"))).unwrap();
        assert_eq!(l.identity("run_c").unwrap().unwrap().parent_run.as_deref(), Some("run_p"));
        assert_eq!(l.identity("run_p").unwrap().unwrap().accept_from, vec!["ops".to_string()]);
        assert_eq!(l.children("run_p").unwrap().len(), 1);
        l.rotate_identity("run_p", "j2", 5, 605).unwrap();
        assert_eq!(l.identity("run_p").unwrap().unwrap().jws, "j2");
        assert_eq!(l.identity_history().unwrap().len(), 3, "both originals and the rotation are kept");
        assert!(l.revoked("run_c").unwrap().is_none());
        assert!(l.revoke("run_c", "owner", "suspected leak").unwrap());
        assert!(!l.revoke("run_c", "owner", "again").unwrap(), "idempotent");
        assert_eq!(l.revoked("run_c").unwrap().unwrap().2, "suspected leak");
        l.revoke("run_p", "owner", "parent compromised").unwrap();
        l.put_identity(&row("run_g", Some("run_c"))).unwrap();
        assert_eq!(l.revoked_in_chain("run_g").unwrap().unwrap().0, "run_c", "nearest revoked ancestor");
        let l2 = Ledger::open_in_memory().unwrap();
        l2.put_identity(&row("run_p", None)).unwrap();
        l2.put_identity(&row("run_c", Some("run_p"))).unwrap();
        l2.revoke("run_p", "owner", "x").unwrap();
        assert_eq!(l2.revoked_in_chain("run_c").unwrap().unwrap().0, "run_p", "revoking a parent revokes its children");
    }

    #[test]
    fn every_distinct_asker_is_recorded_on_a_shared_request() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("/o/r.git/git-receive-pack");
        let who = |agent: &str| serde_json::json!({"basis": "matched", "requesters": [{"agent": agent, "tool": "Bash", "call": "git push", "tool_use_id": "t"}]});
        let (id, _) = l.pending_for(&o, "push", Some(&who("subagent fixer"))).unwrap();
        l.pending_for(&o, "push", Some(&who("subagent fixer"))).unwrap();
        l.pending_for(&o, "push", Some(&who("main agent"))).unwrap();
        let r = l.request(&id).unwrap();
        assert_eq!(r.attribution.len(), 2, "same asker twice counts once; a new asker is added");
        assert_eq!(r.attribution[1]["requesters"][0]["agent"], "main agent");
        let gid = l
            .approve(&id, &Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() })
            .unwrap();
        assert_eq!(l.request_for_grant(&gid).unwrap().unwrap().id, id);
    }

    #[test]
    fn pending_is_deduplicated_and_single_use_grant_is_consumed_once() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("/o/r.git/git-receive-pack");
        let (id, fresh) = l.pending_for(&o, "push", None).unwrap();
        assert!(fresh);
        assert_eq!(l.pending_for(&o, "push", None).unwrap(), (id.clone(), false));
        assert_eq!(l.consume_grant(&o).unwrap(), None);
        l.approve(&id, &Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() }).unwrap();
        assert!(l.consume_grant(&o).unwrap().is_some());
        assert_eq!(l.consume_grant(&o).unwrap(), None, "single use");
        assert!(matches!(l.deny(&id, "owner"), Err(StoreError::NotPending(_, _))));
    }

    #[test]
    fn prefix_grants_never_exceed_the_ask() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("/o/r/contents/docs/a.md");
        let (id, _) = l.pending_for(&o, "x", None).unwrap();
        // A prefix that is not a prefix of the asked path is ignored: the grant stays exact.
        l.approve(&id, &Approval { uses: None, ttl: Duration::from_secs(60), path_prefix: Some("/other".into()), decided_by: "a".into() })
            .unwrap();
        assert!(l.consume_grant(&op("/o/r/contents/docs/b.md")).unwrap().is_none());
        assert!(l.consume_grant(&o).unwrap().is_some());
    }

    #[test]
    fn ending_a_run_withdraws_its_pending_requests() {
        let l = Ledger::open_in_memory().unwrap();
        let (id, _) = l.pending_for(&op("/x"), "x", None).unwrap();
        assert_eq!(l.run_ended(&RunId("run_t".into()), "succeeded", "").unwrap(), 1);
        assert_eq!(l.request(&id).unwrap().status, "withdrawn");
        assert!(l.pending(&TenantId::single()).unwrap().is_empty());
    }

    #[test]
    fn audit_chain_verifies_and_detects_tampering() {
        let l = Ledger::open_in_memory().unwrap();
        for i in 0..5 {
            l.audit(&TenantId::single(), None, "test", &serde_json::json!({ "i": i })).unwrap();
        }
        assert_eq!(l.verify_audit().unwrap(), 5);
        l.conn.execute("UPDATE audit SET body = '{\"i\":99}' WHERE seq = 3", []).unwrap();
        assert!(matches!(l.verify_audit(), Err(StoreError::ChainBroken(3))));
    }

    #[test]
    fn concurrent_appenders_keep_one_chain() {
        let dir = std::env::temp_dir().join(format!("wicket-audit-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.db");
        Ledger::open(&path).unwrap();
        let writers: Vec<_> = (0..4)
            .map(|w| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let l = Ledger::open(&path).unwrap();
                    for i in 0..50 {
                        l.audit(&TenantId::single(), None, "test", &serde_json::json!({ "w": w, "i": i })).unwrap();
                    }
                })
            })
            .collect();
        for t in writers {
            t.join().unwrap();
        }
        let n = Ledger::open(&path).unwrap().verify_audit();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(n.unwrap(), 200);
    }
}
