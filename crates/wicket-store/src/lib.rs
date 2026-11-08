//! The ledger (design §11): the server-side record of authority. Single-use and expiry live here,
//! never in tokens. Every table carries the tenant id so platform mode can partition later.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wicket_core::{new_grant_id, new_request_id, Op, RunId, TenantId};

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
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

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
  status TEXT NOT NULL, started_at INTEGER NOT NULL, ended_at INTEGER, detail TEXT
);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, run TEXT NOT NULL, zone TEXT NOT NULL, digest TEXT NOT NULL,
  method TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL, risk TEXT NOT NULL, reason TEXT NOT NULL,
  status TEXT NOT NULL, created_at INTEGER NOT NULL, decided_at INTEGER, decided_by TEXT
);
CREATE INDEX IF NOT EXISTS requests_pending ON requests (tenant, zone, digest, status);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, zone TEXT NOT NULL, method TEXT NOT NULL, host TEXT NOT NULL,
  path TEXT NOT NULL, prefix INTEGER NOT NULL, uses_left INTEGER, expires_at INTEGER NOT NULL,
  request_id TEXT, decided_by TEXT NOT NULL, created_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS operator_credentials (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, name TEXT NOT NULL, x BLOB NOT NULL, y BLOB NOT NULL,
  sign_count INTEGER NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER,
  revoked INTEGER NOT NULL DEFAULT 0
);
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
        // Ledgers created before passkey revocation existed.
        let _ = conn.execute("ALTER TABLE operator_credentials ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0", []);
        Ok(Ledger { conn })
    }

    pub fn open_in_memory() -> Result<Ledger> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
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
        self.conn.execute(
            "UPDATE runs SET status = ?2, ended_at = ?3, detail = ?4 WHERE id = ?1",
            params![run.0, status, now(), detail],
        )?;
        let n = self.conn.execute(
            "UPDATE requests SET status = 'withdrawn', decided_at = ?2, decided_by = 'wicket:run-ended' WHERE run = ?1 AND status = 'pending'",
            params![run.0, now()],
        )?;
        Ok(n)
    }

    // ---- escalation requests ----

    /// Returns the id of the pending request for this op, creating it if needed (deduplicated on the
    /// op digest, so a retrying agent doesn't flood the queue).
    pub fn pending_for(&self, op: &Op, reason: &str) -> Result<(String, bool)> {
        let digest = op.digest();
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
        self.conn.execute(
            "INSERT INTO requests (id, tenant, run, zone, digest, method, host, path, risk, reason, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11)",
            params![id, op.tenant.0, op.run.0, op.zone, digest, op.method, op.host, op.path, format!("{:?}", op.risk), reason, now()],
        )?;
        Ok((id, true))
    }

    pub fn request(&self, id: &str) -> Result<Request> {
        self.conn
            .query_row("SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at FROM requests WHERE id = ?1", params![id], row_to_request)
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
            "SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at FROM requests
             WHERE tenant = ?1 AND status != 'pending' ORDER BY decided_at DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![tenant.0, limit as i64], row_to_request)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn pending(&self, tenant: &TenantId) -> Result<Vec<Request>> {
        let mut st = self.conn.prepare(
            "SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at FROM requests
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
            .query_row("SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at FROM requests WHERE id = ?1", params![id], row_to_request)
            .optional()?
            .ok_or_else(|| StoreError::NoSuchRequest(id.to_string()))?;
        if req.status != "pending" {
            return Err(StoreError::NotPending(id.into(), req.status));
        }
        let (path, prefix) = match &a.path_prefix {
            Some(p) if req.path.starts_with(p.as_str()) => (p.clone(), 1),
            _ => (req.path.clone(), 0),
        };
        let gid = new_grant_id();
        let t = now();
        tx.execute(
            "INSERT INTO grants (id, tenant, zone, method, host, path, prefix, uses_left, expires_at, request_id, decided_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![gid, req.tenant, req.zone, req.method, req.host, path, prefix, a.uses, t + a.ttl.as_secs() as i64, req.id, a.decided_by, t],
        )?;
        tx.execute(
            "UPDATE requests SET status = 'granted', decided_at = ?2, decided_by = ?3 WHERE id = ?1",
            params![id, t, a.decided_by],
        )?;
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
        let mut st = self.conn.prepare(&format!("SELECT id, name, x, y, sign_count FROM operator_credentials WHERE tenant = ?1 {filter} ORDER BY created_at"))?;
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
        self.conn.execute("UPDATE operator_credentials SET sign_count = ?2, last_used_at = ?3 WHERE id = ?1", params![id, sign_count, now()])?;
        Ok(())
    }

    /// Host-only break-glass: revoke every operator passkey for a tenant. Public keys are kept, so
    /// decisions they signed can still be verified.
    pub fn reset_operator_credentials(&self, tenant: &TenantId) -> Result<usize> {
        Ok(self.conn.execute("UPDATE operator_credentials SET revoked = 1 WHERE tenant = ?1 AND revoked = 0", params![tenant.0])?)
    }

    // ---- audit ----

    /// Appends a hash-chained audit record: hash = sha256(prev || kind || body).
    pub fn audit(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: &serde_json::Value) -> Result<i64> {
        let body = serde_json::to_string(body)?;
        let prev: String = self
            .conn
            .query_row("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| "0".repeat(64));
        let hash = chain_hash(&prev, kind, &body);
        self.conn.execute(
            "INSERT INTO audit (ts, tenant, run, kind, body, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![now(), tenant.0, run.map(|r| r.0.clone()), kind, body, prev, hash],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn audit_tail(&self, n: usize) -> Result<Vec<(i64, i64, String, Option<String>, String)>> {
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

fn chain_hash(prev: &str, kind: &str, body: &str) -> String {
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(path: &str) -> Op {
        Op::egress(&TenantId::single(), &RunId("run_t".into()), "z", "POST", "github.com", path)
    }

    #[test]
    fn pending_is_deduplicated_and_single_use_grant_is_consumed_once() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("/o/r.git/git-receive-pack");
        let (id, fresh) = l.pending_for(&o, "push").unwrap();
        assert!(fresh);
        assert_eq!(l.pending_for(&o, "push").unwrap(), (id.clone(), false));
        assert_eq!(l.consume_grant(&o).unwrap(), None);
        l.approve(&id, &Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "alex".into() }).unwrap();
        assert!(l.consume_grant(&o).unwrap().is_some());
        assert_eq!(l.consume_grant(&o).unwrap(), None, "single use");
        assert!(matches!(l.deny(&id, "alex"), Err(StoreError::NotPending(_, _))));
    }

    #[test]
    fn prefix_grants_never_exceed_the_ask() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("/o/r/contents/docs/a.md");
        let (id, _) = l.pending_for(&o, "x").unwrap();
        // A prefix that is not a prefix of the asked path is ignored: the grant stays exact.
        l.approve(&id, &Approval { uses: None, ttl: Duration::from_secs(60), path_prefix: Some("/other".into()), decided_by: "a".into() }).unwrap();
        assert!(l.consume_grant(&op("/o/r/contents/docs/b.md")).unwrap().is_none());
        assert!(l.consume_grant(&o).unwrap().is_some());
    }

    #[test]
    fn ending_a_run_withdraws_its_pending_requests() {
        let l = Ledger::open_in_memory().unwrap();
        let (id, _) = l.pending_for(&op("/x"), "x").unwrap();
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
}
