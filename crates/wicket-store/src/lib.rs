//! The ledger (design §11): the server-side record of authority. Single-use and expiry live here,
//! never in tokens. Every table carries the tenant id so platform mode can partition later.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wicket_core::{new_grant_id, new_request_id, Op, RunId, TenantId};

mod agents;
mod capgrant;
pub use capgrant::{covers as capacity_covers, CapacityAsk, CapacityGrant, CapacityTerms, CapacityUsed, CAPACITY_GRANT_PATH};
mod delegations;
mod digestgrant;
pub use digestgrant::{
    digest_terms_text, parse_digest_terms, signer_principal, valid_digest, DigestAction, DigestGrantPath, DigestScope, DigestUse,
    NewDigestGrant, Signer, DIGEST_METHOD, SIGNER_GRANT_SECS,
};
mod effect;
pub use delegations::{Delegation, NewDelegation, MAX_BRIEF_RECORD};
pub use effect::{descriptor, requesters, DecisionTerms, EffectUse, EgressSeen, Filed};
pub mod bundle;
pub mod cas;
#[cfg(test)]
mod lifecycle_props;
mod links;
mod nodeca;
pub use nodeca::{CaHosts, CaWant};
pub mod money;
mod node;
#[cfg(test)]
mod previous_build;
#[cfg(test)]
mod props;
mod quota;
mod receipts;
pub use quota::{GrantListing, Quota, QuotaAmounts, MAX_QUOTA_TTL_SECS, MONEY_HOURLY, MONEY_RESERVED, QUOTA_HOST, QUOTA_METHOD};
pub use receipts::{MessageMeta, MessageRow, Principal, Priority, Receipt};
pub mod objects;
pub mod sealed;
pub use agents::{new_agent_id, valid_agent_id, AgentRow, AgentUsage, NewAgent, HELD as AGENT_HELD, WAKE_SKEW_SECS};
pub use links::{ExposeRow, LinkRow};
pub mod invariants;
mod lease;
pub use lease::{new_lease_id, BudgetRefusal, LeaseBudget, LeaseRow, PlacedNodeRow, LEASE_QUOTA_BY, LIVE as LIVE_LEASES};
pub use node::{AuditRecord, GrantRow, NodeAuditSummary};
mod writer;
pub use writer::{AuditWriter, Ticket, WriterConfig};
mod export;
pub use export::{ExportCursor, EXPORT_LEASE_SECS};

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
    #[error("audit writer: {0}")]
    Writer(String),
    #[error("not requested: {0}")]
    Refused(String),
    #[error("request {0} is not the effect that was shown (shown {1}, now {2}): it changed since; look at it again and decide that")]
    EffectChanged(String, String, String),
    #[error("{0}: an egress grant is decided and counted on the box's node, never consumed by the ledger (#257)")]
    EgressGrant(String),
    #[error("this ledger was migrated by a newer wicket (schema {version}), past a step this build (schema {SCHEMA_VERSION}) can't read: roll forward, or restore the snapshot taken before that update")]
    TooNew { version: u32, floor: u32 },
    #[error("this ledger is schema {version}, older than schema {UPGRADES_FROM}, the oldest this build upgrades: open it once with a wicket build that still upgrades it (main at {STEP_THROUGH}), then with this one")]
    TooOld { version: u32 },
}

/// The ledger's schema version (#162). Every migration bumps it, and records what kind it is:
/// - **expand** (a new table, a new column with a default, a new index): older binaries ignore it,
///   so a rollback across it is safe. [`SCHEMA_FLOOR`] stays.
///   An expand step leaves what an older binary reads alone: one that adds rows an older query
///   would mishandle to a table it reads is not one (#475; `previous_build` reads this build's
///   ledger with the previous build's queries).
/// - **contract** (dropping or rewriting anything an older binary reads): [`SCHEMA_FLOOR`] is raised
///   to this version, and binaries below it refuse to open the ledger ([`StoreError::TooNew`]), so
///   `wicket self rollback` refuses to go back across it. A contract step ships only in a release
///   after the one whose expand step made it unnecessary to read the old shape.
///
/// Version 1 is every migration up to #162 (all of them expand steps: `CREATE ... IF NOT EXISTS`
/// and `ADD COLUMN`). Version 2 (expand) adds `runs.authority_until` and `runs.authority_cap`, a
/// running box's renewable authority (#56). Version 3 (expand) adds `grants.amount`: a quota
/// grant's amount (model budget, children, bytes), recorded as a grant (#256). Version 4
/// (expand) adds `messages.to_principal`: messages are addressed to principals, not runs (#250).
/// Version 5 (expand) adds the agent-to-agent protocol's record (#252): `messages.from_principal`
/// (the reply address), `messages.priority`, `messages.in_reply_to`, the `message_refusals` table,
/// and `runs.activity` (busy, idle, waiting) for presence. Version 6 (expand) adds the
/// `delegations` table: what a parent delegated to the children it spawned, and where it is (#252).
/// Version 7 (expand) adds `agents.claim_until`, the wake claim's end, which `agents.lease_until`
/// held before (#349: a claim, not a lease). It is copied over once; `lease_until` was written too
/// while a build before schema 7 could open the ledger, and isn't since the floor passed it.
/// Version 8 (expand) adds `placed_nodes.hourly`: what a node from `wicket node create` costs per
/// hour, for `wicket node list` (#358).
/// Version 9 (expand) adds standing capacity grants (#256): `grants.principal`, `grants.terms` and
/// the `capacity_uses` table.
/// Version 10 (expand) binds approvals to their effect (#369): `requests.args_sha256` and
/// `grants.args_sha256` (the decided-on arguments' hash), `grants.effect_sha256` (the approved
/// descriptor's), and the indexes a run's recent egress (`audit_run`) and its pending requests
/// (`requests_run`) are read by.
/// Version 11 (expand) adds `runs.uncollected`: the node keeping a run's files that a fetch didn't
/// bring back (#300, #324), which holds the node.
/// Version 12 (expand) adds the `node_health` table: each node's latest health report, for
/// `wicket top`, the console and its alerts (#377). Version 13 (expand) adds the `run_collected`
/// table: when and how a run's work was collected, which a cleanup checks before it deletes the
/// run's workspace (#377). Version 14 (expand) adds `runs.stuck_at`: when the parent of a child run
/// whose supervisor runs in its process found it still running after asking it to stop, so the
/// reconciler and `wicket top` show it as stuck (#409). Version 15 (expand) adds `runs.want`: what
/// the agent asked of its own run, `finish` or `hibernate` (#249), recorded when it asks, so a
/// supervisor that re-attaches after a control-host restart still acts on it (#444). Version 16
/// (expand) keeps a message a box was given in flight until the box has had it (#445):
/// `messages.taken_at`, and `operator_messages.stdin_start` and `stdin_end` (where a prompt is in
/// the box's stdin), so a supervisor that takes a run over after a control-host restart gives again
/// what never arrived. Version 17 (expand) gives an agent one inbox (#253): operators' prompts and
/// wicket's notices are rows of `messages` (`kind` `prompt` or `notice`, beside peers' `message`),
/// with `text`, `label` (who it shows as) and `stdin_start`/`stdin_end`; `operator_messages` rows
/// are copied over once, and the table stays, unread, until a contract step drops it.
/// Version 18 (expand) adds the read-only `principals` view (#11, #253): every agent's latest identity
/// and every passkey operator, one record (`Ledger::principals`).
/// Version 19 (contract) drops `operator_messages` (#463), once a ledger from before version 17 has
/// had its rows copied into `messages`. Builds of schema 17 and 18 never read it (version 17 was the
/// expand step that stopped them), so the floor is 17, not 19: a rollback to them stays safe, and only
/// builds from before one inbox, which read prompts from that table, can no longer open the ledger.
/// Version 20 (expand) adds `node_ca_policy` and `node_ca_wants` (#573): how a node's CA may be
/// widened at runtime, and the hosts its boxes want of it. Older builds don't read them, so the
/// floor stays 17.
pub const SCHEMA_VERSION: u32 = 20;
/// The oldest schema whose binaries may open a ledger this build has opened.
pub const SCHEMA_FLOOR: u32 = 17;
/// The oldest ledger schema this build upgrades (#253). An existing ledger older than it is
/// refused ([`StoreError::TooOld`]) and names [`STEP_THROUGH`], a build that upgrades it; the
/// steps for older ledgers are gone, as every column they added is in a ledger of schema 17.
pub const UPGRADES_FROM: u32 = 17;
/// A build that upgrades a ledger of any schema (main just before the upgrade steps went).
pub const STEP_THROUGH: &str = "a3135ea";
// A build can open the ledgers it writes (#325: `version::the_schema_floor_only_rises` assumes it).
const _: () = assert!(SCHEMA_FLOOR <= SCHEMA_VERSION);

/// `messages.kind` (#253): a peer's message (pulled with `await_message`, signed by its sender),
/// an operator's prompt, or a notice from wicket (each pushed as the agent's next turn).
pub const KIND_MESSAGE: &str = "message";
pub const KIND_PROMPT: &str = "prompt";
pub const KIND_NOTICE: &str = "notice";
/// Who a notice is from, as shown.
pub const NOTICE_LABEL: &str = "wicket";
/// The SQL condition for a row that is a turn (a prompt or a notice), and for a peer's message.
pub(crate) const TURNS: &str = "kind IN ('prompt', 'notice')";
pub(crate) const PEER: &str = "kind = 'message'";

/// A prompt or notice taken for a run: its message id, text, who it shows as, and the operator's
/// principal id (None for a notice, and for prompts recorded before #253).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    pub id: String,
    pub text: String,
    pub label: String,
    pub from_principal: Option<String>,
}

/// How long a message waits for its principal to have a live run (#250): a principal that starts
/// within it gets the message; after it, it stays undelivered on the record.
pub const MESSAGE_HOLD_SECS: i64 = 7 * 24 * 3600;

/// A ledger's recorded schema: the newest version that has opened it, and its floor (both 0 for a
/// ledger from before #162).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Schema {
    pub version: u32,
    pub floor: u32,
}

const SCHEMA_META: &str = "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);";

fn read_schema(conn: &Connection) -> Result<Schema> {
    let get = |k: &str| -> Result<u32> {
        Ok(conn.query_row("SELECT value FROM schema_meta WHERE key = ?1", [k], |r| r.get::<_, i64>(0)).optional()?.unwrap_or(0) as u32)
    };
    Ok(Schema { version: get("version")?, floor: get("floor")? })
}

/// Checks this build may open the database, then records its version and floor (never lowering
/// either). Runs before any migration.
fn check_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_META)?;
    let s = read_schema(conn)?;
    if !wicket_core::version::schema_opens(SCHEMA_VERSION, s.floor) {
        return Err(StoreError::TooNew { version: s.version, floor: s.floor });
    }
    // A new ledger has nothing but `schema_meta` yet; an old one (version 0 is one from before #162
    // recorded a schema) has its tables.
    let tables: i64 =
        conn.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name != 'schema_meta'", [], |r| r.get(0))?;
    if s.version < UPGRADES_FROM && tables > 0 {
        return Err(StoreError::TooOld { version: s.version });
    }
    if s.version < SCHEMA_VERSION || s.floor < SCHEMA_FLOOR {
        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('version', ?1), ('floor', ?2)
             ON CONFLICT(key) DO UPDATE SET value = max(value, excluded.value)",
            params![SCHEMA_VERSION, SCHEMA_FLOOR],
        )?;
    }
    Ok(())
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// One audit entry as `audit_tail` returns it: sequence, timestamp, kind, run, body.
pub type AuditRow = (i64, i64, String, Option<String>, String);

pub struct Ledger {
    conn: Connection,
    path: Option<std::path::PathBuf>,
    /// The process's batched audit writer, once started ([`Ledger::start_audit_writer`]).
    writer: Option<AuditWriter>,
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
    /// The sha256 of the arguments it asks with, for the kinds whose effect depends on more than
    /// the target (spawn, link, capacity, update: #369, [`wicket_core::effect::args_sha256`]).
    pub args_sha256: Option<String>,
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
  status TEXT NOT NULL, started_at INTEGER NOT NULL, ended_at INTEGER, detail TEXT, owner TEXT, lease TEXT, node TEXT, policy TEXT,
  authority_until INTEGER, authority_cap INTEGER, activity TEXT, activity_at INTEGER, uncollected TEXT,
  stuck_at INTEGER, want TEXT
);
CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, run TEXT NOT NULL, zone TEXT NOT NULL, digest TEXT NOT NULL,
  method TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL, risk TEXT NOT NULL, reason TEXT NOT NULL,
  status TEXT NOT NULL, created_at INTEGER NOT NULL, decided_at INTEGER, decided_by TEXT,
  attribution TEXT NOT NULL DEFAULT '[]', scope_prefix INTEGER NOT NULL DEFAULT 0, args_sha256 TEXT
);
CREATE INDEX IF NOT EXISTS requests_pending ON requests (tenant, zone, digest, status);
CREATE INDEX IF NOT EXISTS requests_run ON requests (run, status);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, zone TEXT NOT NULL, method TEXT NOT NULL, host TEXT NOT NULL,
  path TEXT NOT NULL, prefix INTEGER NOT NULL, uses_left INTEGER, expires_at INTEGER NOT NULL,
  request_id TEXT, decided_by TEXT NOT NULL, created_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
  node TEXT, max_risk INTEGER, run TEXT, node_epoch INTEGER, amount INTEGER, principal TEXT, terms TEXT, args_sha256 TEXT, effect_sha256 TEXT
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
CREATE TABLE IF NOT EXISTS turn_cancels (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT NOT NULL, by TEXT NOT NULL,
  created_at INTEGER NOT NULL, consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS mode_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT NOT NULL, mode TEXT NOT NULL, by TEXT NOT NULL,
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
  created_at INTEGER NOT NULL, delivered_at INTEGER, to_principal TEXT, from_principal TEXT, priority TEXT, in_reply_to TEXT,
  taken_at INTEGER, kind TEXT NOT NULL DEFAULT 'message', text TEXT, label TEXT, stdin_start INTEGER, stdin_end INTEGER
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
CREATE TABLE IF NOT EXISTS placed_nodes (
  id TEXT PRIMARY KEY, backend TEXT NOT NULL, name TEXT NOT NULL, owner TEXT NOT NULL, api_key_secret TEXT NOT NULL,
  created_at INTEGER NOT NULL, lease_until INTEGER NOT NULL, status TEXT NOT NULL, held_by TEXT, ended_at INTEGER, detail TEXT,
  hourly INTEGER
);
CREATE TABLE IF NOT EXISTS node_health (node TEXT PRIMARY KEY, at_ms INTEGER NOT NULL, health TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run_collected (run TEXT NOT NULL, how TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (run, how));
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, tenant TEXT NOT NULL, run TEXT,
  kind TEXT NOT NULL, body TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_run ON audit (run, seq);
"#;

/// The path and whether it is a prefix that approving `req` with the human's `path_prefix` grants:
/// what [`Ledger::approve`] records, and what the effect descriptor a decision signs names (#369).
/// Prefixes cover whole segments (#119): a prefix given by the human must cover the asked path, or
/// (for a prefix ask) lie within the asked prefix.
pub fn granted_scope(req: &Request, path_prefix: Option<&str>) -> (String, bool) {
    match path_prefix {
        Some(p) if wicket_core::prefix_covers(p, &req.path) => (wicket_core::prefix_dir(p), true),
        Some(p) if req.scope_prefix && wicket_core::prefix_covers(&req.path, p) => (wicket_core::prefix_dir(p), true),
        // A prefix ask is granted as asked unless the human narrows it.
        _ if req.scope_prefix => (wicket_core::prefix_dir(&req.path), true),
        _ => (req.path.clone(), false),
    }
}

/// What a request needs of a grant: the one lookup every request kind's grant is found by
/// ([`Ledger::consume_grant`] for SPAWN and LINK asks, [`Ledger::use_update_approval`] for UPDATE,
/// [`Ledger::grant_covering`] for what an egress grant covers). `None` matches any tenant, zone or
/// run.
struct GrantMatch<'a> {
    tenant: Option<&'a str>,
    zone: Option<&'a str>,
    run: Option<&'a str>,
    method: &'a str,
    host: &'a str,
    path: &'a str,
    /// The op's risk rank: the grant must cover at least it (#119).
    min_risk: i64,
    /// Only an exact-path grant (not a prefix).
    exact: bool,
    /// Only a grant made for a request whose own method, host and path are these.
    answers_request: bool,
}

impl<'a> GrantMatch<'a> {
    /// What `op` needs of a grant: its tenant, zone and run, a path or a prefix covering it, at
    /// least its risk.
    fn for_op(op: &'a Op) -> GrantMatch<'a> {
        GrantMatch {
            tenant: Some(&op.tenant.0),
            zone: Some(&op.zone),
            run: Some(&op.run.0),
            method: &op.method,
            host: &op.host,
            path: &op.path,
            min_risk: op.risk.rank(),
            exact: false,
            answers_request: false,
        }
    }
}

/// The oldest live grant matching `m` (exact paths before prefixes), with its uses left: not
/// revoked or expired, not handed to a node (the node counts its uses then), with a use left, and
/// never a quota grant (#256), which records an amount and decides no op.
fn live_grant(tx: &rusqlite::Transaction<'_>, m: &GrantMatch<'_>) -> Result<Option<(String, Option<i64>)>> {
    Ok(tx
        .query_row(
            // `d`: the prefix ending in '/' (older ledgers stored it without), so it covers whole
            // segments only (#119).
            "SELECT g.id, g.uses_left FROM (SELECT *, CASE WHEN substr(path, -1) = '/' THEN path ELSE path || '/' END AS d FROM grants) g
             LEFT JOIN requests r ON r.id = g.request_id
             WHERE (?1 IS NULL OR g.tenant = ?1) AND (?2 IS NULL OR g.zone = ?2) AND g.method = ?3 AND g.host = ?4
               AND g.revoked = 0 AND g.expires_at > ?5 AND g.amount IS NULL
               AND g.node IS NULL AND (g.run IS NULL OR ?8 IS NULL OR g.run = ?8)
               AND (g.uses_left IS NULL OR g.uses_left > 0)
               AND COALESCE(g.max_risk, 0) >= ?7
               AND ((g.prefix = 0 AND g.path = ?6) OR (?9 = 0 AND g.prefix = 1 AND (?6 || '/' = g.d OR substr(?6, 1, length(g.d)) = g.d)))
               AND (?10 = 0 OR (r.method = ?3 AND r.host = ?4 AND r.path = ?6))
             ORDER BY g.prefix ASC, g.created_at ASC LIMIT 1",
            params![m.tenant, m.zone, m.method, m.host, now(), m.path, m.min_risk, m.run, m.exact as i64, m.answers_request as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Ledger> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        check_schema(&conn)?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(links::SCHEMA)?;
        conn.execute_batch(export::SCHEMA)?;
        conn.execute_batch(agents::SCHEMA)?;
        conn.execute_batch(receipts::SCHEMA)?;
        conn.execute_batch(delegations::SCHEMA)?;
        conn.execute_batch(capgrant::SCHEMA)?;
        conn.execute_batch(nodeca::SCHEMA)?;
        // Indexes a ledger of schema 17 or later has, made here for a new one.
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS messages_held ON messages (to_principal, delivered_at);
             CREATE INDEX IF NOT EXISTS messages_sent ON messages (from_principal, created_at);
             CREATE INDEX IF NOT EXISTS audit_run ON audit (run, seq);
             CREATE INDEX IF NOT EXISTS requests_run ON requests (run, status)",
        )?;
        // Schema 19 (contract, #463): the old table goes (schema 17 copied its rows into `messages`).
        // A build of schema 17 or 18 that opens the ledger again creates it empty, and never reads it.
        conn.execute_batch("DROP TABLE IF EXISTS operator_messages")?;
        conn.execute_batch("CREATE INDEX IF NOT EXISTS messages_turns ON messages (to_run, kind, delivered_at)")?;
        Ok(Ledger { conn, path: Some(path.to_path_buf()), writer: None })
    }

    /// A ledger's recorded schema, read without migrating it (`wicket self rollback` checks it
    /// against the target build's).
    pub fn schema_of(path: &Path) -> Result<Schema> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        let exists: bool = conn
            .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta'", [], |r| r.get::<_, i64>(0))?
            > 0;
        if !exists {
            return Ok(Schema { version: 0, floor: 0 });
        }
        read_schema(&conn)
    }

    /// A consistent copy of the ledger at `to` (SQLite's `VACUUM INTO`), taken while it is in use:
    /// what `wicket self update` keeps before a new build migrates anything.
    pub fn snapshot(&self, to: &Path) -> Result<()> {
        self.conn.execute("VACUUM INTO ?1", [to.to_string_lossy()])?;
        Ok(())
    }

    pub fn open_in_memory() -> Result<Ledger> {
        let conn = Connection::open_in_memory()?;
        check_schema(&conn)?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(links::SCHEMA)?;
        conn.execute_batch(export::SCHEMA)?;
        conn.execute_batch(agents::SCHEMA)?;
        conn.execute_batch(receipts::SCHEMA)?;
        conn.execute_batch(delegations::SCHEMA)?;
        conn.execute_batch(capgrant::SCHEMA)?;
        conn.execute_batch(nodeca::SCHEMA)?;
        Ok(Ledger { conn, path: None, writer: None })
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
        // So are the grants bound to it: nothing else may use them (#127).
        self.conn.execute("UPDATE grants SET revoked = 1 WHERE run = ?1 AND revoked = 0", params![run.0])?;
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
    pub(crate) fn pending_for_unheld(
        &self,
        op: &Op,
        args: Option<&str>,
        reason: &str,
        who: Option<&serde_json::Value>,
    ) -> Result<(String, bool)> {
        let digest = op.digest();
        if let Some((id, attr)) = self
            .conn
            .query_row(
                "SELECT id, attribution FROM requests WHERE tenant = ?1 AND zone = ?2 AND digest = ?3 AND run = ?4 AND status = 'pending'",
                params![op.tenant.0, op.zone, digest, op.run.0],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
        {
            // In wicket's own namespace the reason is wicket's, always the latest it wrote (#117).
            if op.is_reserved() {
                self.conn
                    .execute("UPDATE requests SET reason = ?2, risk = ?3 WHERE id = ?1", params![id, reason, format!("{:?}", op.risk)])?;
            }
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
            "INSERT INTO requests (id, tenant, run, zone, digest, method, host, path, risk, reason, status, created_at, attribution, args_sha256)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11, ?12, ?13)",
            params![id, op.tenant.0, op.run.0, op.zone, digest, op.method, op.host, op.path, format!("{:?}", op.risk), reason, now(), attr, args],
        )?;
        Ok((id, true))
    }

    // ---- prompts and notices: an agent's turns, in its one inbox (#253) ----

    /// Queues a prompt from operator `from` (its authenticated principal id, #11) for `run` (a run,
    /// or a hibernated agent's id until a wake moves it, #249): the agent's next turn. `label` is
    /// who it shows as. Operator text is trusted task text (it comes from the principal), unlike
    /// anything an agent or a web page says: so it is a turn, not a peer's message, and no
    /// `accept_from` applies (an operator's authority is operators.yaml's). Unsigned: wicket
    /// authenticated the operator, and the caller audits the write. Its message id.
    pub fn add_prompt(&self, run: &str, text: &str, label: &str, from: &str) -> Result<String> {
        self.add_turn(run, text, label, Some(from), KIND_PROMPT)
    }

    /// Queues a notice from wicket itself for `run` (a box near its memory limit, #185): a turn,
    /// like a prompt, from no operator.
    pub fn add_notice(&self, run: &str, text: &str) -> Result<String> {
        self.add_turn(run, text, NOTICE_LABEL, None, KIND_NOTICE)
    }

    fn add_turn(&self, run: &str, text: &str, label: &str, from: Option<&str>, kind: &str) -> Result<String> {
        let id = format!("prompt-{}", wicket_core::new_ulid().to_string().to_lowercase());
        self.conn.execute(
            "INSERT INTO messages (id, tenant, from_run, to_run, envelope, created_at, from_principal, kind, text, label)
             VALUES (?1, COALESCE((SELECT tenant FROM runs WHERE id = ?2), (SELECT tenant FROM agents WHERE id = ?2), ''),
                     '', ?2, '', ?3, ?4, ?5, ?6, ?7)",
            params![id, run, now(), from, kind, text, label],
        )?;
        Ok(id)
    }

    /// Takes every prompt and notice queued for `run`, oldest first. Each is handed out once: it is
    /// taken, and counted read, until [`Ledger::requeue_prompts`] gives it again.
    pub fn take_prompts(&mut self, run: &str) -> Result<Vec<Prompt>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows: Vec<Prompt> = {
            let mut st = tx.prepare(&format!(
                "SELECT id, text, label, from_principal FROM messages WHERE to_run = ?1 AND {TURNS} AND delivered_at IS NULL
                 ORDER BY created_at, rowid"
            ))?;
            let r = st.query_map(params![run], |r| {
                Ok(Prompt {
                    id: r.get(0)?,
                    text: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    label: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    from_principal: r.get(3)?,
                })
            })?;
            r.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let t = now();
        for p in &rows {
            tx.execute("UPDATE messages SET taken_at = ?2, delivered_at = ?2 WHERE id = ?1", params![p.id, t])?;
        }
        tx.commit()?;
        Ok(rows)
    }

    /// Where prompt `id`, taken, is in its box's stdin (#445): its bytes from offset `start`
    /// (counted from the run's start) to `end`.
    pub fn set_prompt_stdin(&self, id: &str, start: u64, end: u64) -> Result<()> {
        self.conn.execute(
            &format!("UPDATE messages SET stdin_start = ?2, stdin_end = ?3 WHERE id = ?1 AND {TURNS}"),
            params![id, start as i64, end as i64],
        )?;
        Ok(())
    }

    /// Gives `run` again every prompt taken for it whose bytes its box's node never had: its node
    /// has `stdin_received` bytes of the box's stdin, and the prompt starts at or after that, or
    /// was taken and never written (no offsets, #445). Called by a supervisor that takes the run
    /// over, once its node says how far it got. A prompt the node has part of stays taken: giving
    /// it again would send its start twice. The prompts given again.
    pub fn requeue_prompts(&self, run: &str, stdin_received: u64) -> Result<Vec<String>> {
        let tx = self.conn.unchecked_transaction()?;
        let ids: Vec<String> = {
            let mut st = tx.prepare(&format!(
                "SELECT id FROM messages WHERE to_run = ?1 AND {TURNS} AND delivered_at IS NOT NULL
                   AND (stdin_start IS NULL OR stdin_start >= ?2) ORDER BY created_at, rowid"
            ))?;
            let r = st.query_map(params![run, stdin_received as i64], |r| r.get(0))?;
            r.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for id in &ids {
            tx.execute(
                "UPDATE messages SET delivered_at = NULL, taken_at = NULL, stdin_start = NULL, stdin_end = NULL WHERE id = ?1",
                params![id],
            )?;
        }
        tx.commit()?;
        Ok(ids)
    }

    /// Whether prompt `id` was handed to its run yet (None: there is no such prompt).
    pub fn prompt_taken(&self, id: &str) -> Result<Option<bool>> {
        Ok(self
            .conn
            .query_row(&format!("SELECT delivered_at IS NOT NULL FROM messages WHERE id = ?1 AND {TURNS}"), params![id], |r| r.get(0))
            .optional()?)
    }

    /// Asks `run`'s supervisor to cancel the agent's running turn (#327: `session/cancel` from the
    /// console's session view). The supervisor takes it within a second or so; with no turn running
    /// then, it does nothing.
    pub fn request_turn_cancel(&self, run: &str, by: &str) -> Result<i64> {
        self.conn.execute("INSERT INTO turn_cancels (run, by, created_at) VALUES (?1, ?2, ?3)", params![run, by, now()])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Takes `run`'s cancel requests: who asked, oldest first, of those made within the last
    /// `fresh_secs` (older ones are dropped: a supervisor that was away mustn't cancel a later turn).
    pub fn take_turn_cancels(&mut self, run: &str, fresh_secs: i64) -> Result<Vec<String>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let t = now();
        let by: Vec<String> = {
            let mut st =
                tx.prepare("SELECT by FROM turn_cancels WHERE run = ?1 AND consumed_at IS NULL AND created_at >= ?2 ORDER BY id")?;
            let rows = st.query_map(params![run, t - fresh_secs], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        tx.execute("UPDATE turn_cancels SET consumed_at = ?2 WHERE run = ?1 AND consumed_at IS NULL", params![run, t])?;
        tx.commit()?;
        Ok(by)
    }

    /// Asks `run`'s supervisor to change its driven session's permission mode while it runs (#363),
    /// to `mode` as the manifest spells it. Taken within a second or so, like a turn cancel.
    pub fn request_mode_change(&self, run: &str, mode: &str, by: &str) -> Result<i64> {
        self.conn.execute("INSERT INTO mode_changes (run, mode, by, created_at) VALUES (?1, ?2, ?3, ?4)", params![run, mode, by, now()])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Takes `run`'s mode changes: (mode, who asked), oldest first, of those made within the last
    /// `fresh_secs` (older ones are dropped, as stale cancels are).
    pub fn take_mode_changes(&mut self, run: &str, fresh_secs: i64) -> Result<Vec<(String, String)>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let t = now();
        let asked: Vec<(String, String)> = {
            let mut st =
                tx.prepare("SELECT mode, by FROM mode_changes WHERE run = ?1 AND consumed_at IS NULL AND created_at >= ?2 ORDER BY id")?;
            let rows = st.query_map(params![run, t - fresh_secs], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        tx.execute("UPDATE mode_changes SET consumed_at = ?2 WHERE run = ?1 AND consumed_at IS NULL", params![run, t])?;
        tx.commit()?;
        Ok(asked)
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
        // Messages held for this principal (#250), or left unread by one of its runs that no longer
        // runs, are this run's now.
        self.conn.execute(
            "UPDATE messages SET to_run = ?1 WHERE delivered_at IS NULL AND tenant = ?2 AND to_principal = ?3 AND created_at >= ?4
             AND to_run != ?1 AND (to_run = '' OR to_run NOT IN (SELECT id FROM runs WHERE status = 'running'))",
            params![id.run, id.tenant, id.spiffe_id, now() - MESSAGE_HOLD_SECS],
        )?;
        Ok(())
    }

    /// The identity of the principal `spiffe_id`'s latest run in `tenant`, if it has had one: who
    /// it is, its parent, and what it accepts messages from (#250).
    pub fn principal_identity(&self, tenant: &str, spiffe_id: &str) -> Result<Option<IdentityRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT run, tenant, spiffe_id, zone, agent, parent_run, accept_from, jws, issued_at FROM identities
                 WHERE tenant = ?1 AND spiffe_id = ?2 ORDER BY issued_at DESC, rowid DESC LIMIT 1",
                params![tenant, spiffe_id],
                row_to_identity,
            )
            .optional()?)
    }

    /// The principal `spiffe_id`'s live run in `tenant` (its newest running one), if it has one.
    pub fn live_run_of(&self, tenant: &str, spiffe_id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT i.run FROM identities i JOIN runs r ON r.id = i.run
                 WHERE i.tenant = ?1 AND i.spiffe_id = ?2 AND r.status = 'running' ORDER BY i.issued_at DESC, i.rowid DESC LIMIT 1",
                params![tenant, spiffe_id],
                |r| r.get(0),
            )
            .optional()?)
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

    /// Records the org policy version `run`'s token was minted under (#51; None: no org policy).
    pub fn set_run_policy(&self, run: &str, version: Option<&str>) -> Result<()> {
        self.conn.execute("UPDATE runs SET policy = ?2 WHERE id = ?1", params![run, version])?;
        Ok(())
    }

    /// Records when `run`'s box authority ends (Unix seconds) as its token was minted, and the latest
    /// a renewal may take it to (its hard end: the run's timeout). Every authority has an end.
    pub fn set_run_authority(&self, run: &str, until: i64, cap: i64) -> Result<()> {
        self.conn.execute("UPDATE runs SET authority_until = ?2, authority_cap = ?3 WHERE id = ?1", params![run, until.min(cap), cap])?;
        Ok(())
    }

    /// When `run`'s box authority ends and the latest a renewal may take it to (Unix seconds), if
    /// its box was started with one recorded.
    pub fn run_authority(&self, run: &str) -> Result<Option<(i64, i64)>> {
        Ok(self
            .conn
            .query_row("SELECT authority_until, authority_cap FROM runs WHERE id = ?1", params![run], |r| {
                Ok(r.get::<_, Option<i64>>(0)?.zip(r.get::<_, Option<i64>>(1)?))
            })
            .optional()?
            .flatten())
    }

    /// Renews running `run`'s box authority to end at `until` (Unix seconds): never past its cap,
    /// never unlimited. Its supervisor re-mints the box's token with that end. False if the run
    /// isn't running, has no authority recorded, or `until` is past its cap.
    pub fn renew_run_authority(&self, run: &str, until: i64) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE runs SET authority_until = ?2
             WHERE id = ?1 AND status = 'running' AND authority_until IS NOT NULL AND authority_cap >= ?2",
            params![run, until],
        )? == 1)
    }

    /// The org policy version `run`'s token was minted under (None: none, or no such run).
    pub fn run_policy(&self, run: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT policy FROM runs WHERE id = ?1", params![run], |r| r.get(0)).optional()?.flatten())
    }

    /// Running runs, with their zone and the org policy version their token was minted under.
    pub fn running_policies(&self) -> Result<Vec<(String, String, Option<String>)>> {
        let mut st = self.conn.prepare("SELECT id, zone, policy FROM runs WHERE status = 'running' ORDER BY started_at")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// A run's status ("running", "succeeded", …), if it exists.
    /// When `run` started and (if it has) ended, Unix seconds.
    pub fn run_times(&self, run: &str) -> Result<Option<(i64, Option<i64>)>> {
        Ok(self
            .conn
            .query_row("SELECT started_at, ended_at FROM runs WHERE id = ?1", params![run], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?)
    }

    pub fn run_status(&self, run: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT status FROM runs WHERE id = ?1", params![run], |r| r.get(0)).optional()?)
    }

    /// Children started by `run` (from their identity documents).
    pub fn children(&self, run: &str) -> Result<Vec<IdentityRow>> {
        let mut st = self.conn.prepare("SELECT run, tenant, spiffe_id, zone, agent, parent_run, accept_from, jws, issued_at FROM identities WHERE parent_run = ?1 ORDER BY issued_at")?;
        let rows = st.query_map(params![run], row_to_identity)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Records a message to the principal `to` (#250): for its run `to_run`, or (None) held until
    /// the principal has a live run, which then takes it ([`Ledger::put_identity`] moves held
    /// messages to a principal's new run, for [`MESSAGE_HOLD_SECS`]). A held message is checked
    /// again for a live run in the same transaction, so one started meanwhile isn't missed. Returns
    /// the run it is for, if any yet. `meta` is its reply address, priority and the message it
    /// answers (#252).
    #[allow(clippy::too_many_arguments)]
    pub fn post_message(
        &mut self,
        id: &str,
        tenant: &TenantId,
        from_run: &str,
        to: &str,
        to_run: Option<&str>,
        envelope: &str,
        meta: &MessageMeta,
    ) -> Result<Option<String>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let to_run = match to_run {
            Some(r) => Some(r.to_string()),
            None => tx
                .query_row(
                    "SELECT i.run FROM identities i JOIN runs r ON r.id = i.run
                     WHERE i.tenant = ?1 AND i.spiffe_id = ?2 AND r.status = 'running' ORDER BY i.issued_at DESC, i.rowid DESC LIMIT 1",
                    params![tenant.0, to],
                    |r| r.get::<_, String>(0),
                )
                .optional()?,
        };
        tx.execute(
            "INSERT INTO messages (id, tenant, from_run, to_run, envelope, created_at, to_principal, from_principal, priority, in_reply_to)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                id,
                tenant.0,
                from_run,
                to_run.as_deref().unwrap_or(""),
                envelope,
                now(),
                to,
                meta.from_principal,
                meta.priority.as_str(),
                meta.in_reply_to
            ],
        )?;
        tx.commit()?;
        Ok(to_run)
    }

    /// Records a message for run `to_run` only (tests, and envelopes made outside the gateway).
    pub fn add_message(&self, id: &str, tenant: &TenantId, from_run: &str, to_run: &str, envelope: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO messages (id, tenant, from_run, to_run, envelope, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, tenant.0, from_run, to_run, envelope, now()],
        )?;
        Ok(())
    }

    /// Test support: makes every later insert into the audit table fail, as a full or broken disk
    /// would. Not for production use.
    #[doc(hidden)]
    pub fn fail_audit_inserts_for_tests(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS audit_fail BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'audit disk failure (test)'); END;",
        )?;
        Ok(())
    }

    /// Withdraws an undelivered message (one whose audit record could not be written).
    pub fn withdraw_message(&self, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM messages WHERE id = ?1 AND delivered_at IS NULL", params![id])?;
        Ok(())
    }

    /// Takes the next undelivered message for `run`: the most urgent (#252's priority), then the
    /// oldest. Marked delivered (read, on its receipt) in the same transaction, so each message is
    /// handed out once. `created_at` is when wicket recorded it: the time its sender's identity
    /// must have been valid.
    pub fn take_message(&mut self, run: &str) -> Result<Option<StoredMessage>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m: Option<StoredMessage> = tx
            .query_row(
                &format!(
                    "SELECT id, from_run, envelope, created_at FROM messages WHERE to_run = ?1 AND {PEER} AND delivered_at IS NULL ORDER BY {} LIMIT 1",
                    receipts::INBOX_ORDER
                ),
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

    /// Takes the next message for `run` as [`Ledger::take_message`] does, but in flight (#445): not
    /// read until its box has had it ([`Ledger::message_read`]). It isn't taken again meanwhile, and
    /// a supervisor that takes the run over gives it again ([`Ledger::requeue_in_flight`]).
    pub fn take_message_in_flight(&mut self, run: &str) -> Result<Option<StoredMessage>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let m: Option<StoredMessage> = tx
            .query_row(
                &format!(
                    "SELECT id, from_run, envelope, created_at FROM messages WHERE to_run = ?1 AND {PEER} AND delivered_at IS NULL AND taken_at IS NULL ORDER BY {} LIMIT 1",
                    receipts::INBOX_ORDER
                ),
                params![run],
                |r| Ok(StoredMessage { id: r.get(0)?, from_run: r.get(1)?, envelope: r.get(2)?, created_at: r.get(3)? }),
            )
            .optional()?;
        if let Some(StoredMessage { id, .. }) = &m {
            tx.execute("UPDATE messages SET taken_at = ?2 WHERE id = ?1", params![id, now()])?;
        }
        tx.commit()?;
        Ok(m)
    }

    /// `run`'s box has had message `id` (#445): it is read. False: no such message in flight for
    /// `run` (already read, or someone else's).
    pub fn message_read(&self, run: &str, id: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE messages SET delivered_at = ?3 WHERE id = ?1 AND to_run = ?2 AND kind = 'message' AND delivered_at IS NULL",
            params![id, run, now()],
        )?;
        Ok(n == 1)
    }

    /// Gives `run` again every message taken for it and never read (#445): called by a supervisor
    /// as it takes the run over, when whoever took them is gone. The box's node drops one its box
    /// has had. How many.
    pub fn requeue_in_flight(&self, run: &str) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE messages SET taken_at = NULL WHERE to_run = ?1 AND kind = 'message' AND delivered_at IS NULL AND taken_at IS NOT NULL",
            params![run],
        )?)
    }

    /// Gives `run` message `id` again if it is in flight (#453): its answer never reached the box's
    /// node (the link dropped first). False if it wasn't in flight for `run`.
    pub fn requeue_message(&self, run: &str, id: &str) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE messages SET taken_at = NULL WHERE id = ?1 AND to_run = ?2 AND kind = 'message' AND delivered_at IS NULL AND taken_at IS NOT NULL",
            params![id, run],
        )?;
        Ok(n == 1)
    }

    /// Every stored envelope (id, envelope, created_at), for offline verification.
    pub fn envelopes(&self) -> Result<Vec<(String, String, i64)>> {
        let mut st = self.conn.prepare("SELECT id, envelope, created_at FROM messages WHERE kind = 'message' ORDER BY created_at")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// An agent asking ahead for access it needs (request_access), rather than a blocked request.
    /// `prefix` asks for every path under `op.path`. Deduplicated like any pending request.
    ///
    /// Refuses wicket's own approval namespace and anything but an HTTP method (#117): the agent
    /// writes this op, and a request in that namespace would stand in for one wicket raises.
    pub fn ask(&self, op: &Op, reason: &str, prefix: bool, who: Option<&serde_json::Value>) -> Result<(String, bool)> {
        if let Some(why) = op.refused_for_agents() {
            return Err(StoreError::Refused(why));
        }
        // An exact ask that a pending prefix ask from the run covers waits on that ask (#369).
        if !prefix {
            if let Some(pending) = self.held_by(op, None)? {
                self.merge_attribution(&pending, who)?;
                return Ok((pending, false));
            }
        }
        let digest = format!("{}{}", op.digest(), if prefix { ":prefix" } else { "" });
        if let Some(id) = self
            .conn
            .query_row(
                "SELECT id FROM requests WHERE tenant = ?1 AND zone = ?2 AND digest = ?3 AND run = ?4 AND status = 'pending'",
                params![op.tenant.0, op.zone, digest, op.run.0],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok((id, false));
        }
        let id = new_request_id();
        let attr = serde_json::Value::from(who.cloned().into_iter().collect::<Vec<_>>()).to_string();
        // A prefix covers whole segments: it is kept (and shown) ending in '/' (#119).
        let path = if prefix { wicket_core::prefix_dir(&op.path) } else { op.path.clone() };
        self.conn.execute(
            "INSERT INTO requests (id, tenant, run, zone, digest, method, host, path, risk, reason, status, created_at, attribution, scope_prefix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending', ?11, ?12, ?13)",
            params![id, op.tenant.0, op.run.0, op.zone, digest, op.method, op.host, path, format!("{:?}", op.risk), reason, now(), attr, prefix as i64],
        )?;
        Ok((id, true))
    }

    pub fn request(&self, id: &str) -> Result<Request> {
        self.conn
            .query_row("SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at, attribution, scope_prefix, args_sha256 FROM requests WHERE id = ?1", params![id], row_to_request)
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
            "SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at, attribution, scope_prefix, args_sha256 FROM requests
             WHERE tenant = ?1 AND status != 'pending' ORDER BY decided_at DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![tenant.0, limit as i64], row_to_request)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn pending(&self, tenant: &TenantId) -> Result<Vec<Request>> {
        let mut st = self.conn.prepare(
            "SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at, attribution, scope_prefix, args_sha256 FROM requests
             WHERE tenant = ?1 AND status = 'pending' ORDER BY created_at",
        )?;
        let rows = st.query_map(params![tenant.0], row_to_request)?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Approves a pending request: records the decision and mints a grant no wider than the ask
    /// (exact path unless a narrower-or-equal prefix of the asked path is given).
    ///
    /// The grant is bound to the run that asked: no other run (another box in the same zone, a later
    /// run of it) can use it, and it ends with the run (#127). [`Ledger::approve_shown`] with
    /// `zone_wide` is the wider scope, when the human picks it.
    pub fn approve(&mut self, id: &str, a: &Approval) -> Result<String> {
        Ok(self.approve_scoped(id, a, false, None)?.0)
    }

    /// As [`Ledger::approve`] (or zone-wide), only if the request's effect
    /// descriptor with these terms is `shown` (#369), checked in the transaction that makes the
    /// grant ([`StoreError::EffectChanged`] otherwise). Returns the grant and the descriptor's hash.
    pub fn approve_shown(&mut self, id: &str, a: &Approval, zone_wide: bool, shown: Option<&str>) -> Result<(String, String)> {
        self.approve_scoped(id, a, zone_wide, shown)
    }

    fn approve_scoped(&mut self, id: &str, a: &Approval, zone_wide: bool, shown: Option<&str>) -> Result<(String, String)> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let req = tx
            .query_row("SELECT id, tenant, run, zone, method, host, path, risk, reason, status, created_at, attribution, scope_prefix, args_sha256 FROM requests WHERE id = ?1", params![id], row_to_request)
            .optional()?
            .ok_or_else(|| StoreError::NoSuchRequest(id.to_string()))?;
        if req.status != "pending" {
            return Err(StoreError::NotPending(id.into(), req.status));
        }
        // The effect this grant is for (#369), from the row as it is in this transaction.
        let terms = DecisionTerms { uses: a.uses, ttl_secs: a.ttl.as_secs(), prefix: a.path_prefix.clone(), zone_wide };
        let effect_sha256 = descriptor(&req, Some(&terms)).sha256();
        if let Some(shown) = shown.filter(|s| *s != effect_sha256) {
            return Err(StoreError::EffectChanged(id.into(), shown.into(), effect_sha256));
        }
        let (path, prefix) = granted_scope(&req, a.path_prefix.as_deref());
        let prefix = prefix as i64;
        // The grant covers nothing riskier than what the human was shown (#119): a prefix approved
        // for an R2 write doesn't also cover the R4 operations under it.
        let max_risk = wicket_core::RiskClass::from_name(&req.risk).map(|r| r.rank()).unwrap_or(0);
        // A push is one request in two (#26): its ref discovery and its upload, and git's retries and
        // probes between them. Its grant covers them all for a short window, not a number of uses.
        let (uses, ttl) = wicket_core::git::grant_terms(&req.method, &path, a.uses, a.ttl.as_secs());
        let gid = new_grant_id();
        let t = now();
        tx.execute(
            "INSERT INTO grants (id, tenant, zone, method, host, path, prefix, uses_left, expires_at, request_id, decided_by, created_at, max_risk, run, args_sha256, effect_sha256)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                gid,
                req.tenant,
                req.zone,
                req.method,
                req.host,
                path,
                prefix,
                uses,
                t + ttl as i64,
                req.id,
                a.decided_by,
                t,
                max_risk,
                (!zone_wide).then_some(&req.run),
                req.args_sha256,
                effect_sha256
            ],
        )?;
        tx.execute("UPDATE requests SET status = 'granted', decided_at = ?2, decided_by = ?3 WHERE id = ?1", params![id, t, a.decided_by])?;
        tx.commit()?;
        Ok((gid, effect_sha256))
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

    /// Finds a live grant covering an op in wicket's own approval namespace (a SPAWN or LINK ask, a
    /// capacity request) and consumes one use, atomically. Returns the grant id. A grant bound to a
    /// run covers only that run's ops (#127).
    ///
    /// Never an egress op (one a box makes itself, [`Op::refused_for_agents`] is `None`): since
    /// #257's slice 3 the ledger records an egress grant's issuance, renewals and revocation, and
    /// the run's process publishes it to the box's node, which alone decides and counts its uses.
    /// Such an op is refused with [`StoreError::EgressGrant`].
    pub fn consume_grant(&mut self, op: &Op) -> Result<Option<String>> {
        if op.refused_for_agents().is_none() {
            return Err(StoreError::EgressGrant(format!("{} {}{}", op.method, op.host, op.path)));
        }
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let found = live_grant(&tx, &GrantMatch::for_op(op))?;
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

    /// The live grant that covers `op`, by the lookup [`Ledger::consume_grant`] uses, without
    /// using it: for what an issued grant covers (the console, tests). A grant already handed to a
    /// node isn't found: its uses are counted there.
    pub fn grant_covering(&self, op: &Op) -> Result<Option<String>> {
        let tx = self.conn.unchecked_transaction()?;
        let found = live_grant(&tx, &GrantMatch::for_op(op))?;
        tx.commit()?;
        Ok(found.map(|(gid, _)| gid))
    }

    /// An operator's approval of an agent's `request_update` for the artifact with this sha256
    /// (#162): a live grant made for such a request, found by the same lookup as every other
    /// request kind's ([`Ledger::consume_grant`]), for exactly `UPDATE wicket.internal
    /// /self/<sha256>`, from any run. It is used up here (revoked, whatever uses it had left), so
    /// one approval accepts one update. Returns (request id, grant id). Not an acceptance of its
    /// own (#258): only [`Ledger::accept_update_approval`] calls it, which makes the approval the
    /// operator's grant on the build's digest and asks the one check.
    pub(crate) fn use_update_approval(&mut self, sha256: &str) -> Result<Option<(String, String)>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let path = format!("/self/{sha256}");
        let found = live_grant(
            &tx,
            &GrantMatch {
                tenant: None,
                zone: None,
                run: None,
                method: "UPDATE",
                host: "wicket.internal",
                path: &path,
                min_risk: 0,
                exact: true,
                answers_request: true,
            },
        )?;
        let Some((gid, _)) = found else {
            tx.commit()?;
            return Ok(None);
        };
        let rid: String = tx.query_row("SELECT request_id FROM grants WHERE id = ?1", params![gid], |r| r.get(0))?;
        tx.execute("UPDATE grants SET revoked = 1 WHERE id = ?1", params![gid])?;
        tx.commit()?;
        Ok(Some((rid, gid)))
    }

    pub fn denied_recently(&self, op: &Op) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id FROM requests WHERE tenant = ?1 AND zone = ?2 AND digest = ?3 AND run = ?5 AND status = 'denied' AND decided_at > ?4 ORDER BY decided_at DESC LIMIT 1",
                params![op.tenant.0, op.zone, op.digest(), now() - 600, op.run.0],
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

    /// Starts this process's batched audit writer for this ledger's file (#62), or attaches the one
    /// it already has (`with`). From then on [`audit`](Self::audit) goes through it and waits for its
    /// batch's commit, and [`audit_deferred`](Self::audit_deferred) queues without waiting. A no-op
    /// for an in-memory ledger.
    pub fn start_audit_writer(&mut self, with: Option<AuditWriter>) -> Result<Option<AuditWriter>> {
        if self.writer.is_none() {
            self.writer = match (with, &self.path) {
                (Some(w), _) => Some(w),
                (None, Some(p)) => Some(AuditWriter::start(p, WriterConfig::default())?),
                (None, None) => None,
            };
        }
        Ok(self.writer.clone())
    }

    /// This ledger's audit writer, if one was started.
    pub fn audit_writer(&self) -> Option<AuditWriter> {
        self.writer.clone()
    }

    /// Waits until every audit record queued so far is committed. A no-op without a writer.
    pub fn flush_audit(&self) -> Result<()> {
        match &self.writer {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }

    /// Appends a hash-chained audit record: hash = sha256(prev || kind || body). Durable when it
    /// returns: with a writer it waits for its batch's commit (a shared flush).
    pub fn audit(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: &serde_json::Value) -> Result<i64> {
        let body = serde_json::to_string(body)?;
        let own = self.conn.is_autocommit();
        if let (Some(w), true) = (&self.writer, own) {
            return w.append_str(tenant, run, kind, body);
        }
        // Several processes append to one ledger (a run, its children, a link's relay): read the head
        // and append under one write lock, or two appends can chain from the same record. (Inside a
        // caller's transaction, the record joins it: the writer's connection would wait on its lock.)
        if own {
            self.conn.execute_batch("BEGIN IMMEDIATE")?;
        }
        let r = self.append_audit(tenant, run, kind, &body);
        if own {
            let _ = self.conn.execute_batch(if r.is_ok() { "COMMIT" } else { "ROLLBACK" });
        }
        r
    }

    /// Appends an audit record without waiting for it to reach the disk: with a writer it is queued
    /// and committed with its batch a few milliseconds later. For records nothing waits on, such as
    /// the egress proxy's per-request `op` rows. Without a writer it is [`audit`](Self::audit).
    pub fn audit_deferred(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: &serde_json::Value) -> Result<()> {
        match &self.writer {
            Some(w) if self.conn.is_autocommit() => w.submit(tenant, run, kind, body),
            _ => self.audit(tenant, run, kind, body).map(|_| ()),
        }
    }

    fn append_audit(&self, tenant: &TenantId, run: Option<&RunId>, kind: &str, body: &str) -> Result<i64> {
        let (last, prev): (i64, String) = self
            .conn
            .query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?
            .unwrap_or_else(|| (0, CHAIN_ZERO.to_string()));
        // The record's seq and ts are hashed, so both are fixed here, before the insert.
        let (seq, ts) = (last + 1, now());
        let hash = chain_hash_v2(&prev, &ChainFields { seq, ts, tenant: &tenant.0, run: run.map(|r| r.0.as_str()), kind, body });
        self.conn.execute(
            "INSERT INTO audit (seq, ts, tenant, run, kind, body, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![seq, ts, tenant.0, run.map(|r| r.0.clone()), kind, body, prev, hash],
        )?;
        Ok(seq)
    }

    pub fn audit_tail(&self, n: usize) -> Result<Vec<AuditRow>> {
        let mut st = self.conn.prepare("SELECT seq, ts, kind, run, body FROM audit ORDER BY seq DESC LIMIT ?1")?;
        let rows = st.query_map(params![n as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        let mut v = rows.collect::<std::result::Result<Vec<_>, _>>()?;
        v.reverse();
        Ok(v)
    }

    /// The body of a run's newest audit record of `kind`, if any.
    pub fn audit_latest(&self, run: &str, kind: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT body FROM audit WHERE run = ?1 AND kind = ?2 ORDER BY seq DESC LIMIT 1", params![run, kind], |r| r.get(0))
            .optional()?)
    }

    /// Recomputes the whole chain. Returns the number of records verified.
    pub fn verify_audit(&self) -> Result<i64> {
        let mut st = self.conn.prepare("SELECT seq, ts, tenant, run, kind, body, prev, hash FROM audit ORDER BY seq")?;
        let mut rows = st.query([])?;
        let mut prev = CHAIN_ZERO.to_string();
        let mut n = 0;
        while let Some(r) = rows.next()? {
            let (seq, ts, tenant, run, kind, body, p, h): (i64, i64, String, Option<String>, String, String, String, String) =
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?);
            let f = ChainFields { seq, ts, tenant: &tenant, run: run.as_deref(), kind: &kind, body: &body };
            if p != prev || chain_hash_v2(&prev, &f) != h {
                return Err(StoreError::ChainBroken(seq));
            }
            prev = h;
            n += 1;
        }
        Ok(n)
    }
}

/// The `prev` of a chain's first record.
pub const CHAIN_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// How a record's hash starts (#120): the chain's version. Only v2 is accepted.
pub const CHAIN_V2_PREFIX: &str = "v2:";

/// Every stored field of an audit record, as the chain hashes them.
#[derive(Debug, Clone, Copy)]
pub struct ChainFields<'a> {
    pub seq: i64,
    pub ts: i64,
    pub tenant: &'a str,
    pub run: Option<&'a str>,
    pub kind: &'a str,
    pub body: &'a str,
}

/// A v2 audit record's hash (#120): `v2:` and the hex sha256 of a domain tag and every stored
/// field, each length-prefixed (an absent run is distinct from an empty one). Nodes chain their
/// own logs the same way.
pub fn chain_hash_v2(prev: &str, f: &ChainFields<'_>) -> String {
    fn field(h: &mut Sha256, b: &[u8]) {
        h.update((b.len() as u64).to_be_bytes());
        h.update(b);
    }
    let mut h = Sha256::new();
    h.update(b"wicket.audit.v2\0");
    field(&mut h, prev.as_bytes());
    h.update(f.seq.to_be_bytes());
    h.update(f.ts.to_be_bytes());
    field(&mut h, f.tenant.as_bytes());
    match f.run {
        None => h.update([0u8]),
        Some(r) => {
            h.update([1u8]);
            field(&mut h, r.as_bytes());
        }
    }
    field(&mut h, f.kind.as_bytes());
    field(&mut h, f.body.as_bytes());
    format!("{CHAIN_V2_PREFIX}{}", hex::encode(h.finalize()))
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
        args_sha256: r.get(13)?,
    })
}

pub(crate) fn row_to_identity(r: &rusqlite::Row<'_>) -> rusqlite::Result<IdentityRow> {
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
        getrandom::fill(&mut b).map_err(|e| StoreError::Random(e.to_string()))?;
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

    /// Records the control host's own built-in node (#146): enrolled by the control host itself, so
    /// no join token, and no node CA (it decides nothing itself). Already recorded and active, it takes
    /// the new key and target: the node's directory was made again (lost, or a restore onto a standby,
    /// #154), and the key it had is gone with it.
    pub fn enrol_builtin_node(&self, node: &NodeRow) -> Result<()> {
        self.conn.execute(
            &format!(
                "INSERT INTO nodes ({NODE_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'active', NULL) \
                 ON CONFLICT(name) DO UPDATE SET node_key = excluded.node_key, target = excluded.target, enrolled_at = excluded.enrolled_at \
                 WHERE nodes.status = 'active'"
            ),
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

    /// Records a CA certificate that replaced an active node's CA on the node itself (#416, renewed
    /// over the channel: the old key is gone from the node). Earlier active ones still unexpired
    /// were replaced early, so they are revoked (for the feed's revocation list); expired ones are
    /// superseded. Returns the serials revoked.
    pub fn replace_node_ca(&mut self, ca: &NodeCaRow) -> Result<Vec<String>> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status: Option<String> = tx.query_row("SELECT status FROM nodes WHERE name = ?1", params![ca.node], |r| r.get(0)).optional()?;
        match status.as_deref() {
            None => return Err(StoreError::Node(ca.node.clone(), "is not enrolled")),
            Some("active") => {}
            Some(_) => return Err(StoreError::Node(ca.node.clone(), "is revoked")),
        }
        let t = now();
        let serials = {
            let mut st = tx.prepare(
                "SELECT serial FROM node_cas WHERE node = ?1 AND status = 'active' AND not_after > ?2 ORDER BY issued_at, rowid",
            )?;
            let rows = st.query_map(params![ca.node, t], |r| r.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for s in &serials {
            tx.execute("UPDATE node_cas SET status = 'revoked', revoked_at = ?2 WHERE serial = ?1", params![s, t])?;
        }
        tx.execute("UPDATE node_cas SET status = 'superseded' WHERE node = ?1 AND status = 'active'", params![ca.node])?;
        insert_node_ca(&tx, ca)?;
        // `nodes.hosts` stays what the operator set (enrolment, renew-ca): a CA widened at runtime
        // (#573) adds its boxes' wants to it, which a later renewal prunes.
        tx.commit()?;
        Ok(serials)
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

    /// #416: a CA replaced on the node before its end goes on the revocation list; one replaced
    /// after its end just drops out.
    #[test]
    fn a_ca_replaced_early_is_revoked() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = l.create_node_token(&TenantId::single(), "n1", 3600).unwrap();
        l.enrol_node(&t, &node("n1"), &ca("n1", "0a")).unwrap();
        assert_eq!(l.replace_node_ca(&ca("n1", "0b")).unwrap(), vec!["0a"]);
        let mut expired = ca("n1", "0c");
        expired.not_after = now() - 1;
        l.replace_node_ca(&expired).unwrap();
        assert_eq!(l.replace_node_ca(&ca("n1", "0d")).unwrap(), vec![] as Vec<String>, "0c had ended");
        let st = |s: &str| l.node_cas("n1").unwrap().into_iter().find(|c| c.serial == s).unwrap().status;
        assert_eq!((st("0a"), st("0b"), st("0c"), st("0d")), ("revoked".into(), "revoked".into(), "superseded".into(), "active".into()));
        assert_eq!(l.revoked_node_cas(now()).unwrap().iter().map(|c| c.serial.as_str()).collect::<Vec<_>>(), ["0a", "0b"]);
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
        assert!(l.replace_node_ca(&ca("n1", "0c")).is_err(), "nor a replacement");
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
    fn an_approved_update_request_accepts_its_hash_once() {
        let mut l = Ledger::open_in_memory().unwrap();
        let sha = "ab".repeat(32);
        let mut op = Op::egress(&TenantId::single(), &RunId("run_t".into()), "z", "UPDATE", "wicket.internal", &format!("/self/{sha}"));
        op.risk = wicket_core::RiskClass::R4ExecOrPrivilege;
        let (rid, _) = l.pending_for(&op, "an agent's build", None).unwrap();
        assert_eq!(l.use_update_approval(&sha).unwrap(), None, "asked, not approved");
        let a = Approval { uses: None, ttl: Duration::from_secs(600), path_prefix: None, decided_by: "op".into() };
        let gid = l.approve(&rid, &a).unwrap();
        assert_eq!(l.use_update_approval(&"cd".repeat(32)).unwrap(), None, "another hash");
        assert_eq!(l.use_update_approval(&sha).unwrap(), Some((rid, gid)));
        assert_eq!(l.use_update_approval(&sha).unwrap(), None, "used up, even with uses left");
    }

    /// #258: an approval is accepted as what it is, the operator's one-use `install` grant on the
    /// build's digest, by the one check; used up, as before.
    #[test]
    fn an_approved_update_is_accepted_as_the_operators_grant_on_its_digest() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let sha = "ab".repeat(32);
        let mut op = Op::egress(&t, &RunId("run_t".into()), "z", "UPDATE", "wicket.internal", &format!("/self/{sha}"));
        op.risk = wicket_core::RiskClass::R4ExecOrPrivilege;
        let (rid, _) = l.pending_for(&op, "an agent's build", None).unwrap();
        assert!(l.accept_update_approval(&t, &sha, "self update").unwrap().is_none(), "asked, not approved");
        let a = Approval { uses: None, ttl: Duration::from_secs(600), path_prefix: None, decided_by: "operator:alex".into() };
        l.approve(&rid, &a).unwrap();
        let (req, u) = l.accept_update_approval(&t, &sha, "self update").unwrap().unwrap();
        assert_eq!((req, u.decided_by.as_str(), u.scope), (rid, "operator:alex", DigestScope::Installation));
        assert!(l.accept_update_approval(&t, &sha, "self update").unwrap().is_none(), "used up");
        let digest = format!("sha256:{sha}");
        assert_eq!(l.may_use(&t, &digest, DigestAction::Install, &DigestScope::Installation, "again").unwrap(), None);
    }

    #[test]
    fn a_ledger_records_its_schema_and_refuses_a_build_below_its_floor() {
        let dir = std::env::temp_dir().join(format!("wicket-store-schema-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.db");
        // A ledger from before #162 (no schema recorded), or of any schema before 17: refused, naming
        // a build that upgrades it, and left as it was.
        let old = dir.join("old.db");
        Connection::open(&old).unwrap().execute_batch(SCHEMA).unwrap();
        assert_eq!(Ledger::schema_of(&old).unwrap(), Schema { version: 0, floor: 0 });
        let e = Ledger::open(&old).err().expect("refused");
        assert!(matches!(e, StoreError::TooOld { version: 0 }) && e.to_string().contains(STEP_THROUGH), "{e}");
        assert_eq!(Ledger::schema_of(&old).unwrap(), Schema { version: 0, floor: 0 }, "untouched");
        Connection::open(&old).unwrap().execute("INSERT INTO schema_meta (key, value) VALUES ('version', 16), ('floor', 0)", []).unwrap();
        assert!(matches!(Ledger::open(&old), Err(StoreError::TooOld { version: 16 })));
        // A new ledger, and one of schema 17: opened.
        let l = Ledger::open(&path).unwrap();
        assert_eq!(Ledger::schema_of(&path).unwrap(), Schema { version: SCHEMA_VERSION, floor: SCHEMA_FLOOR });
        // A snapshot is a whole ledger, with the same schema and records.
        l.audit(&TenantId::single(), None, "x", &serde_json::json!({})).unwrap();
        l.snapshot(&dir.join("snap.db")).unwrap();
        drop(l);
        assert_eq!(Ledger::open(&dir.join("snap.db")).unwrap().verify_audit().unwrap(), 1);
        // A newer build's expand step: this build still opens it, and never lowers the version.
        let c = Connection::open(&path).unwrap();
        c.execute("UPDATE schema_meta SET value = ?1 WHERE key = 'version'", [SCHEMA_VERSION + 1]).unwrap();
        Ledger::open(&path).unwrap();
        assert_eq!(Ledger::schema_of(&path).unwrap().version, SCHEMA_VERSION + 1);
        // Its contract step: this build is below the floor, and refuses.
        c.execute("UPDATE schema_meta SET value = ?1 WHERE key = 'floor'", [SCHEMA_VERSION + 1]).unwrap();
        assert!(matches!(Ledger::open(&path), Err(StoreError::TooNew { .. })));
        drop(c);
        std::fs::remove_dir_all(&dir).unwrap();
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

    /// #117: an agent can't file requests in wicket's own approval namespace, or with a method that
    /// isn't HTTP; and when wicket raises one, the reason on it is wicket's.
    #[test]
    fn agents_cannot_ask_in_wickets_namespace() {
        let l = Ledger::open_in_memory().unwrap();
        let (t, r) = (TenantId::single(), RunId("run_t".into()));
        let update = format!("/self/{}", "0f".repeat(32));
        for (m, h, p) in [
            ("SPAWN", "wicket.internal", "/zones/"),
            ("CAPACITY", "wicket.internal", "/capacity/l-1"),
            ("LINK", "wicket.internal", "/links/a/b/80"),
            ("UPDATE", "wicket.internal", update.as_str()),
            ("UPDATE", "api.example.com", "/"),
            ("GET", "wicket.internal", "/"),
            ("GET", "relay.wicket.internal", "/"),
            ("SPAWN", "api.example.com", "/"),
            ("GET\u{1b}[2K", "api.example.com", "/"),
            ("PROPFIND", "api.example.com", "/"),
        ] {
            let e = l.ask(&Op::egress(&t, &r, "z", m, h, p), "please", true, None).unwrap_err();
            assert!(matches!(e, StoreError::Refused(_)), "{m} {h}{p}: {e}");
        }
        assert!(l.pending(&t).unwrap().is_empty());
        // wicket raises a spawn card; a second raise of the same op keeps wicket's latest reason.
        let spawn = Op::egress(&t, &r, "z", "SPAWN", "wicket.internal", "/zones/z.x/0123");
        let (id, _) = l.pending_for(&spawn, "start program x: wicket's list", None).unwrap();
        l.conn.execute("UPDATE requests SET reason = 'harmless' WHERE id = ?1", params![id]).unwrap();
        assert_eq!(l.pending_for(&spawn, "start program x: wicket's list", None).unwrap().0, id);
        assert_eq!(l.request(&id).unwrap().reason, "start program x: wicket's list");
    }

    /// #127: a grant and a pending request belong to the run that asked, not to its zone.
    #[test]
    fn grants_and_requests_bind_to_the_run_that_asked() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let op = |run: &str| Op::egress(&t, &RunId(run.into()), "z", "POST", "api.example.com", "/items");
        let once = Approval { uses: None, ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() };
        // Two boxes in one zone asking for the same thing are two requests, two cards.
        let (a, _) = l.pending_for(&op("run_a"), "a's reason", None).unwrap();
        let (b, _) = l.pending_for(&op("run_b"), "b's reason", None).unwrap();
        assert_ne!(a, b);
        assert_eq!(l.pending_for(&op("run_a"), "again", None).unwrap(), (a.clone(), false));
        // a's grant is a's alone.
        l.approve(&a, &once).unwrap();
        assert!(l.grant_covering(&op("run_b")).unwrap().is_none(), "another box in the zone used a's grant");
        assert!(l.grant_covering(&op("run_later")).unwrap().is_none(), "a later run of the zone used a's grant");
        assert!(l.grant_covering(&op("run_a")).unwrap().is_some());
        // A denial of b's request doesn't stop a from asking.
        l.deny(&b, "owner").unwrap();
        assert!(l.denied_recently(&op("run_b")).unwrap().is_some());
        assert!(l.denied_recently(&op("run_a")).unwrap().is_none());
        // A run-bound grant ends with its run.
        l.run_started(&t, &RunId("run_a".into()), "z", "a").unwrap();
        l.run_ended(&RunId("run_a".into()), "succeeded", "").unwrap();
        assert!(l.grant_covering(&op("run_a")).unwrap().is_none(), "the grant outlived its run");
        // Zone-wide, when the human picks it: any run in the zone, after the asker ends too.
        let (c, _) = l.pending_for(&op("run_c"), "c", None).unwrap();
        l.approve_shown(&c, &once, true, None).unwrap();
        l.run_started(&t, &RunId("run_c".into()), "z", "c").unwrap();
        l.run_ended(&RunId("run_c".into()), "succeeded", "").unwrap();
        assert!(l.grant_covering(&op("run_d")).unwrap().is_some());
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
        assert!(l.grant_covering(&later).unwrap().is_some(), "every path under the prefix");
    }

    /// #453: one message whose answer couldn't be sent is given again; one read, or not in flight,
    /// isn't.
    fn a_message_whose_answer_never_went_is_given_again() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId("t".into());
        l.add_message("m1", &t, "run_p", "run_a", "{}").unwrap();
        assert!(!l.requeue_message("run_a", "m1").unwrap(), "not in flight");
        let m = l.take_message_in_flight("run_a").unwrap().unwrap();
        assert!(!l.requeue_message("run_b", &m.id).unwrap(), "only its own run's");
        assert!(l.requeue_message("run_a", &m.id).unwrap());
        let again = l.take_message_in_flight("run_a").unwrap().unwrap();
        assert_eq!(again.id, m.id);
        assert!(l.message_read("run_a", &m.id).unwrap());
        assert!(!l.requeue_message("run_a", &m.id).unwrap(), "read: never again");
    }

    /// #445: a message taken in flight isn't taken again, isn't read until its box has had it, and
    /// is given again when the supervisor that took it goes; a read one never is.
    #[test]
    fn a_message_in_flight_is_given_again_until_its_box_has_had_it() {
        a_message_whose_answer_never_went_is_given_again();
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId("t".into());
        l.add_message("m1", &t, "run_p", "run_a", "{}").unwrap();
        l.add_message("m2", &t, "run_p", "run_a", "{}").unwrap();
        let first = l.take_message_in_flight("run_a").unwrap().unwrap();
        let second = l.take_message_in_flight("run_a").unwrap().unwrap();
        assert_ne!(first.id, second.id, "one in flight isn't taken again");
        assert!(l.take_message_in_flight("run_a").unwrap().is_none());
        assert_eq!(l.waiting_messages("run_a").unwrap(), 0, "in flight isn't waiting");
        // The box has had the first; the supervisor goes before it had the second.
        assert!(l.message_read("run_a", &first.id).unwrap());
        assert!(!l.message_read("run_a", &first.id).unwrap(), "read once");
        assert!(!l.message_read("run_b", &second.id).unwrap(), "only its own run's");
        assert_eq!(l.requeue_in_flight("run_a").unwrap(), 1);
        let again = l.take_message_in_flight("run_a").unwrap().unwrap();
        assert_eq!(again.id, second.id, "given again");
        assert!(l.take_message_in_flight("run_a").unwrap().is_none(), "the read one never");
    }

    /// #253: one inbox, two deliveries. A peer's message is never taken as a turn, and a prompt
    /// never answers `await_message`, is never read by the node's `MessageRead`, nor requeued with
    /// peers' messages; each kind counts only its own as waiting.
    #[test]
    fn prompts_and_peer_messages_share_the_inbox_but_not_its_deliveries() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        l.add_message("m-1", &t, "run_peer", "run_a", "envelope").unwrap();
        let p = l.add_prompt("run_a", "do the thing", "owner", OWNER).unwrap();
        assert_eq!((l.waiting_messages("run_a").unwrap(), l.waiting_prompts("run_a").unwrap()), (1, 1));
        let taken = l.take_message_in_flight("run_a").unwrap().unwrap();
        assert_eq!(taken.id, "m-1");
        assert!(l.take_message_in_flight("run_a").unwrap().is_none(), "the prompt isn't a peer's message");
        assert!(!l.message_read("run_a", &p).unwrap(), "nor read as one");
        assert_eq!(l.take_prompts("run_a").unwrap().iter().map(|p| p.id.clone()).collect::<Vec<_>>(), vec![p.clone()]);
        assert_eq!(l.requeue_in_flight("run_a").unwrap(), 1, "only the peer's message is given again");
        assert_eq!(l.requeue_prompts("run_a", 0).unwrap(), vec![p.clone()], "and only the prompt by the stdin count");
        assert!(l.envelopes().unwrap().iter().all(|(id, ..)| id == "m-1"), "a prompt has no envelope to verify");
        // The prompt has a receipt, from its operator.
        let r = l.receipt(&p).unwrap().unwrap();
        assert_eq!(r.from_principal.as_deref(), Some(OWNER));
    }

    /// #463: a ledger of schema 17 or 18 still has the old `operator_messages` table (empty: schema
    /// 17 copied it into the inbox); this build drops it, and builds from before one inbox can no
    /// longer open the ledger.
    #[test]
    fn schema_19_drops_the_old_operator_messages_table() {
        let path = std::env::temp_dir().join(format!("wicket-opmsg-{}.db", wicket_core::new_ulid()));
        drop(Ledger::open(&path).unwrap());
        {
            let c = Connection::open(&path).unwrap();
            c.execute("UPDATE schema_meta SET value = 17 WHERE key = 'version'", []).unwrap();
            c.execute_batch("CREATE TABLE operator_messages (id INTEGER PRIMARY KEY, run TEXT NOT NULL)").unwrap();
        }
        let l = Ledger::open(&path).unwrap();
        let old: i64 = l.conn.query_row("SELECT count(*) FROM sqlite_master WHERE name = 'operator_messages'", [], |r| r.get(0)).unwrap();
        assert_eq!(old, 0);
        assert_eq!(Ledger::schema_of(&path).unwrap(), Schema { version: SCHEMA_VERSION, floor: 17 });
        assert!(!wicket_core::version::schema_opens(16, SCHEMA_FLOOR) && wicket_core::version::schema_opens(17, SCHEMA_FLOOR));
        drop(l);
        let _ = std::fs::remove_file(&path);
    }

    /// #445: a prompt whose bytes its node never had is given again by a supervisor that takes the
    /// run over; one the node has, all or part of, isn't.
    #[test]
    fn a_prompt_its_node_never_had_is_given_again() {
        let mut l = Ledger::open_in_memory().unwrap();
        for text in ["had", "part", "never", "untaken"] {
            l.add_prompt("run_a", text, "owner", OWNER).unwrap();
        }
        let ids: Vec<String> = l.take_prompts("run_a").unwrap().into_iter().map(|p| p.id).collect();
        l.set_prompt_stdin(&ids[0], 0, 100).unwrap();
        l.set_prompt_stdin(&ids[1], 100, 200).unwrap();
        l.set_prompt_stdin(&ids[2], 200, 300).unwrap();
        // The node had 150 bytes: the first prompt and half the second.
        assert_eq!(l.requeue_prompts("run_a", 150).unwrap(), vec![ids[2].clone(), ids[3].clone()]);
        let again: Vec<String> = l.take_prompts("run_a").unwrap().into_iter().map(|p| p.text).collect();
        assert_eq!(again, ["never", "untaken"]);
        assert_eq!(l.prompt_taken(&ids[0]).unwrap(), Some(true));
        // Never twice: taken again, nothing is left to take, and the node's count gives back only
        // what it never had.
        assert!(l.take_prompts("run_a").unwrap().is_empty());
        l.set_prompt_stdin(&ids[2], 300, 400).unwrap();
        l.set_prompt_stdin(&ids[3], 400, 500).unwrap();
        assert_eq!(l.requeue_prompts("run_a", 500).unwrap(), Vec::<String>::new());
    }

    const OWNER: &str = "spiffe://test.local/t/t0/op/unix/owner";

    #[test]
    fn prompts_are_taken_once_in_order_from_their_operator() {
        let mut l = Ledger::open_in_memory().unwrap();
        l.add_prompt("run_a", "first", "owner", OWNER).unwrap();
        l.add_notice("run_a", "memory is nearly full").unwrap();
        l.add_prompt("run_a", "second", "owner", OWNER).unwrap();
        l.add_prompt("run_b", "other run", "owner", OWNER).unwrap();
        let got = l.take_prompts("run_a").unwrap();
        assert_eq!(got.iter().map(|p| p.text.as_str()).collect::<Vec<_>>(), vec!["first", "memory is nearly full", "second"]);
        assert_eq!((got[0].label.as_str(), got[0].from_principal.as_deref()), ("owner", Some(OWNER)));
        assert_eq!((got[1].label.as_str(), got[1].from_principal.as_deref()), (NOTICE_LABEL, None), "a notice is from wicket");
        assert!(l.take_prompts("run_a").unwrap().is_empty());
        let id = l.add_prompt("run_a", "third", "owner", OWNER).unwrap();
        assert_eq!(l.prompt_taken(&id).unwrap(), Some(false));
        assert_eq!(l.waiting_prompts("run_a").unwrap(), 1);
        l.take_prompts("run_a").unwrap();
        assert_eq!(l.prompt_taken(&id).unwrap(), Some(true));
        assert_eq!(l.prompt_taken("prompt-nope").unwrap(), None);
        assert_eq!(l.waiting_prompts("run_a").unwrap(), 0);
        // Turn cancels (#327): taken once, for their run only, stale ones dropped.
        l.request_turn_cancel("run_a", "passkey:phone").unwrap();
        l.request_turn_cancel("run_b", "passkey:laptop").unwrap();
        assert_eq!(l.take_turn_cancels("run_a", 30).unwrap(), vec!["passkey:phone".to_string()]);
        assert!(l.take_turn_cancels("run_a", 30).unwrap().is_empty());
        l.conn.execute("UPDATE turn_cancels SET created_at = created_at - 60 WHERE run = 'run_b'", []).unwrap();
        assert!(l.take_turn_cancels("run_b", 30).unwrap().is_empty());
        // Mode changes (#363): the same.
        l.request_mode_change("run_a", "acceptEdits", "alex").unwrap();
        l.request_mode_change("run_a", "default", "alex").unwrap();
        l.request_mode_change("run_b", "plan", "bob").unwrap();
        assert_eq!(l.take_mode_changes("run_a", 30).unwrap(), [("acceptEdits".into(), "alex".into()), ("default".into(), "alex".into())]);
        assert!(l.take_mode_changes("run_a", 30).unwrap().is_empty());
        l.conn.execute("UPDATE mode_changes SET created_at = created_at - 60 WHERE run = 'run_b'", []).unwrap();
        assert!(l.take_mode_changes("run_b", 30).unwrap().is_empty());
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

    /// #250: a message to a principal goes to its live run, or waits for its next one; one left
    /// unread by a run that has ended moves to the principal's next run, never to another's.
    #[test]
    fn a_message_to_a_principal_waits_for_its_next_run() {
        let mut l = Ledger::open_in_memory().unwrap();
        let t = TenantId::single();
        let p = "spiffe://x/t/default/z/z/a/peer";
        let row = |run: &str, sub: &str| IdentityRow {
            run: run.into(),
            tenant: t.0.clone(),
            spiffe_id: sub.into(),
            zone: "z".into(),
            agent: "peer".into(),
            parent_run: None,
            accept_from: vec![],
            jws: "j".into(),
            issued_at: now(),
        };
        // Never run: held.
        assert_eq!(l.post_message("m-1", &t, "run_s", p, None, "e1", &MessageMeta::default()).unwrap(), None);
        l.run_started(&t, &RunId("run_1".into()), "z", "peer").unwrap();
        l.put_identity(&row("run_1", p)).unwrap();
        assert_eq!(l.waiting_messages("run_1").unwrap(), 1, "the held message is its first run's");
        assert_eq!(l.live_run_of(&t.0, p).unwrap().as_deref(), Some("run_1"));
        assert_eq!(l.post_message("m-2", &t, "run_s", p, None, "e2", &MessageMeta::default()).unwrap().as_deref(), Some("run_1"));
        // Another principal's run takes none of it.
        l.run_started(&t, &RunId("run_o".into()), "z", "other").unwrap();
        l.put_identity(&row("run_o", "spiffe://x/t/default/z/z/a/other")).unwrap();
        assert_eq!(l.waiting_messages("run_o").unwrap(), 0);
        // run_1 ends with both unread; the principal's next run gets them, in order.
        assert_eq!(l.take_message("run_1").unwrap().unwrap().id, "m-1");
        l.run_ended(&RunId("run_1".into()), "succeeded", "{}").unwrap();
        assert_eq!(l.live_run_of(&t.0, p).unwrap(), None);
        assert_eq!(l.post_message("m-3", &t, "run_s", p, None, "e3", &MessageMeta::default()).unwrap(), None);
        l.run_started(&t, &RunId("run_2".into()), "z", "peer").unwrap();
        l.put_identity(&row("run_2", p)).unwrap();
        assert_eq!(l.take_message("run_2").unwrap().unwrap().id, "m-2");
        assert_eq!(l.take_message("run_2").unwrap().unwrap().id, "m-3");
        assert!(l.take_message("run_2").unwrap().is_none());
        assert_eq!(l.principal_identity(&t.0, p).unwrap().unwrap().run, "run_2");
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
        let rid: String = l.conn.query_row("SELECT request_id FROM grants WHERE id = ?1", params![gid], |r| r.get(0)).unwrap();
        assert_eq!(rid, id);
    }

    /// #56: a live grant is renewed to a new end with its uses kept; a revoked or expired one isn't.
    /// A running box's authority is renewed up to its cap, never past it, and not once it ended.
    #[test]
    fn grants_and_box_authority_are_renewed_within_their_limits() {
        let mut l = Ledger::open_in_memory().unwrap();
        let (id, _) = l.pending_for(&op("/o/r/issues"), "x", None).unwrap();
        let gid =
            l.approve(&id, &Approval { uses: Some(3), ttl: Duration::from_secs(60), path_prefix: None, decided_by: "op".into() }).unwrap();
        let t = now();
        assert!(l.renew_grant(&gid, t + 3600).unwrap());
        let g = l.grant(&gid).unwrap().unwrap();
        assert_eq!((g.expires_at, g.uses_left, g.run.as_deref()), (t + 3600, Some(3), Some("run_t")));
        assert_eq!(l.grant_for_request(&id).unwrap().unwrap().id, gid);
        l.revoke_grant(&gid).unwrap();
        assert!(!l.renew_grant(&gid, t + 7200).unwrap(), "revoked");
        assert!(l.grant_for_request(&id).unwrap().is_none());
        let (id2, _) = l.pending_for(&op("/o/r/pulls"), "x", None).unwrap();
        let g2 =
            l.approve(&id2, &Approval { uses: Some(1), ttl: Duration::from_secs(60), path_prefix: None, decided_by: "op".into() }).unwrap();
        l.conn.execute("UPDATE grants SET expires_at = ?2 WHERE id = ?1", params![g2, t - 1]).unwrap();
        assert!(!l.renew_grant(&g2, t + 600).unwrap(), "expired: ask again");

        let run = RunId("run_t".into());
        l.run_started(&TenantId::single(), &run, "z", "a").unwrap();
        assert_eq!(l.run_authority("run_t").unwrap(), None);
        assert!(!l.renew_run_authority("run_t", t + 60).unwrap(), "no authority recorded");
        l.set_run_authority("run_t", t + 60, t + 600).unwrap();
        assert_eq!(l.run_authority("run_t").unwrap(), Some((t + 60, t + 600)));
        assert!(!l.renew_run_authority("run_t", t + 601).unwrap(), "past its cap");
        assert!(l.renew_run_authority("run_t", t + 600).unwrap());
        assert_eq!(l.run_authority("run_t").unwrap(), Some((t + 600, t + 600)));
        l.run_ended(&run, "succeeded", "").unwrap();
        assert!(!l.renew_run_authority("run_t", t + 300).unwrap(), "ended");
    }

    #[test]
    fn pending_is_deduplicated_and_single_use_grant_is_consumed_once() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("/o/r/issues");
        let (id, fresh) = l.pending_for(&o, "push", None).unwrap();
        assert!(fresh);
        assert_eq!(l.pending_for(&o, "push", None).unwrap(), (id.clone(), false));
        assert_eq!(l.grant_covering(&o).unwrap(), None);
        l.approve(&id, &Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() }).unwrap();
        assert!(l.grant_covering(&o).unwrap().is_some());
        assert!(l.grant_covering(&o).unwrap().is_some(), "looking a grant up doesn't use it");
        // #257: an egress grant's uses are the node's to count, never the ledger's.
        assert!(matches!(l.consume_grant(&o), Err(StoreError::EgressGrant(_))));
        assert!(matches!(l.deny(&id, "owner"), Err(StoreError::NotPending(_, _))));
        // wicket's own namespace (a spawn beyond its parent): consumed here, once.
        let spawn = Op::egress(&TenantId::single(), &RunId("run_t".into()), "z", "SPAWN", "wicket.internal", "/zones/z.x/0123");
        let (sid, _) = l.pending_for(&spawn, "spawn", None).unwrap();
        l.approve(&sid, &Approval { uses: Some(1), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() }).unwrap();
        assert!(l.consume_grant(&spawn).unwrap().is_some());
        assert_eq!(l.consume_grant(&spawn).unwrap(), None, "single use");
    }

    /// #26: one approval of a push covers its requests for a short window, whatever uses the human
    /// picked, and the window ends: after it the push is asked about afresh.
    #[test]
    fn a_push_grant_covers_a_window_not_a_number_of_uses() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("/o/r.git/git-receive-pack");
        let (id, _) = l.pending_for(&o, "push", None).unwrap();
        let gid = l
            .approve(&id, &Approval { uses: Some(1), ttl: Duration::from_secs(3600), path_prefix: None, decided_by: "owner".into() })
            .unwrap();
        let (uses, expires, created): (Option<i64>, i64, i64) = l
            .conn
            .query_row("SELECT uses_left, expires_at, created_at FROM grants WHERE id = ?1", params![gid], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(uses, None, "not counted");
        assert_eq!(expires - created, wicket_core::git::PUSH_WINDOW_SECS as i64, "the window, not the hour asked for");
        // Discovery, a probe, the upload, a retry: all within the window.
        for _ in 0..4 {
            assert_eq!(l.grant_covering(&o).unwrap().as_deref(), Some(gid.as_str()));
        }
        // A shorter ttl than the window is kept.
        let (id2, _) = l.pending_for(&op("/o/s.git/git-receive-pack"), "push", None).unwrap();
        let g2 = l
            .approve(&id2, &Approval { uses: Some(1), ttl: Duration::from_secs(60), path_prefix: None, decided_by: "owner".into() })
            .unwrap();
        let e2: i64 = l.conn.query_row("SELECT expires_at - created_at FROM grants WHERE id = ?1", params![g2], |r| r.get(0)).unwrap();
        assert_eq!(e2, 60);
        // The window passes: nothing covers the push, and it is asked about again (a new request).
        l.conn.execute("UPDATE grants SET expires_at = ?2 WHERE id = ?1", params![gid, now() - 1]).unwrap();
        assert_eq!(l.grant_covering(&o).unwrap(), None);
        let (again, fresh) = l.pending_for(&o, "push", None).unwrap();
        assert!(fresh && again != id);
    }

    /// #119: a prefix grant covers whole segments, and nothing riskier than what was approved.
    #[test]
    fn prefix_grants_cover_segments_and_carry_a_risk_bound() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = |m: &str, p: &str| Op::egress(&TenantId::single(), &RunId("run_t".into()), "z", m, "api.github.com", p);
        let ask = o("PUT", "/repos/acme/app");
        assert_eq!(ask.risk, wicket_core::RiskClass::R4ExecOrPrivilege, "repo settings");
        let ask = o("PUT", "/repos/acme/app/contents/README.md");
        let (id, _) = l.ask(&ask, "edit docs", true, None).unwrap();
        assert_eq!(l.request(&id).unwrap().path, "/repos/acme/app/contents/README.md/");
        let (id, _) = l.ask(&o("PUT", "/repos/acme/app/contents"), "edit files", true, None).unwrap();
        assert_eq!(l.request(&id).unwrap().path, "/repos/acme/app/contents/", "kept ending in '/'");
        l.approve(&id, &Approval { uses: None, ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() }).unwrap();
        assert!(l.grant_covering(&o("PUT", "/repos/acme/app/contents/src/main.rs")).unwrap().is_some());
        assert!(l.grant_covering(&o("PUT", "/repos/acme/app/contents")).unwrap().is_some(), "the directory itself");
        assert!(l.grant_covering(&o("PUT", "/repos/acme/app/contents-x/a")).unwrap().is_none(), "a sibling");
        // Approved at R2: the R4 workflow edit under the same prefix isn't covered.
        let wf = o("PUT", "/repos/acme/app/contents/.github/workflows/ci.yml");
        assert_eq!(wf.risk, wicket_core::RiskClass::R4ExecOrPrivilege);
        assert!(l.grant_covering(&wf).unwrap().is_none());

        // A raw-prefix grant from an older ledger: segment-bounded too, and without a risk bound it
        // covers nothing.
        let (id, _) = l.ask(&o("GET", "/repos/acme/api"), "read", true, None).unwrap();
        let gid =
            l.approve(&id, &Approval { uses: None, ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() }).unwrap();
        l.conn.execute("UPDATE grants SET path = '/repos/acme/api', max_risk = 1 WHERE id = ?1", params![gid]).unwrap();
        assert!(l.grant_covering(&o("GET", "/repos/acme/api/issues")).unwrap().is_some());
        assert!(l.grant_covering(&o("GET", "/repos/acme/api-secrets/x")).unwrap().is_none());
        l.conn.execute("UPDATE grants SET max_risk = NULL WHERE id = ?1", params![gid]).unwrap();
        assert!(l.grant_covering(&o("GET", "/repos/acme/api/issues")).unwrap().is_none());

        // An exact grant for a fetch's ref discovery doesn't cover the push's (same path, R4).
        let fetch = Op::egress_with_query(
            &TenantId::single(),
            &RunId("run_t".into()),
            "z",
            "GET",
            "github.com",
            "/a/b.git/info/refs",
            "service=git-upload-pack",
        );
        let (id, _) = l.pending_for(&fetch, "fetch", None).unwrap();
        l.approve(&id, &Approval { uses: None, ttl: Duration::from_secs(600), path_prefix: None, decided_by: "owner".into() }).unwrap();
        let push = Op::egress_with_query(
            &TenantId::single(),
            &RunId("run_t".into()),
            "z",
            "GET",
            "github.com",
            "/a/b.git/info/refs",
            "service=git-receive-pack",
        );
        assert_eq!(push.digest(), fetch.digest());
        assert!(l.grant_covering(&push).unwrap().is_none());
        assert!(l.grant_covering(&fetch).unwrap().is_some());
    }

    #[test]
    fn prefix_grants_never_exceed_the_ask() {
        let mut l = Ledger::open_in_memory().unwrap();
        let o = op("/o/r/contents/docs/a.md");
        let (id, _) = l.pending_for(&o, "x", None).unwrap();
        // A prefix that is not a prefix of the asked path is ignored: the grant stays exact.
        l.approve(&id, &Approval { uses: None, ttl: Duration::from_secs(60), path_prefix: Some("/other".into()), decided_by: "a".into() })
            .unwrap();
        assert!(l.grant_covering(&op("/o/r/contents/docs/b.md")).unwrap().is_none());
        assert!(l.grant_covering(&o).unwrap().is_some());
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

    /// #120: the chain covers every stored field, not only kind and body.
    #[test]
    fn audit_chain_covers_seq_ts_tenant_and_run() {
        let edits = [
            "UPDATE audit SET ts = ts + 3600 WHERE seq = 2",
            "UPDATE audit SET tenant = 'other' WHERE seq = 2",
            "UPDATE audit SET run = 'run_b' WHERE seq = 2",
            "UPDATE audit SET run = NULL WHERE seq = 2",
            "UPDATE audit SET run = '' WHERE seq = 2",
            "UPDATE audit SET seq = 9 WHERE seq = 3",
        ];
        for e in edits {
            let l = Ledger::open_in_memory().unwrap();
            for i in 0..3 {
                l.audit(&TenantId::single(), Some(&RunId("run_a".into())), "test", &serde_json::json!({ "i": i })).unwrap();
            }
            assert_eq!(l.verify_audit().unwrap(), 3);
            l.conn.execute(e, []).unwrap();
            assert!(matches!(l.verify_audit(), Err(StoreError::ChainBroken(_))), "{e} went unnoticed");
        }
    }

    /// #120: a record hashed the pre-v2 way (prev, kind and body only) doesn't verify.
    #[test]
    fn a_pre_v2_record_breaks_the_chain() {
        let l = Ledger::open_in_memory().unwrap();
        l.audit(&TenantId::single(), None, "new", &serde_json::json!({})).unwrap();
        let head = l.audit_head().unwrap().unwrap().1;
        assert!(head.starts_with(CHAIN_V2_PREFIX));
        let body = serde_json::json!({ "i": 9 }).to_string();
        let mut h = Sha256::new();
        for part in [head.as_bytes(), b"\0", b"old", b"\0", body.as_bytes()] {
            h.update(part);
        }
        l.conn
            .execute(
                "INSERT INTO audit (ts, tenant, run, kind, body, prev, hash) VALUES (1, 't0', NULL, 'old', ?1, ?2, ?3)",
                params![body, head, hex::encode(h.finalize())],
            )
            .unwrap();
        assert!(matches!(l.verify_audit(), Err(StoreError::ChainBroken(2))));
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
