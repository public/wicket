//! Names for boxes (#575; design in `docs/explanation/box-dns.md`): the names boxes hold, the host
//! ports public names are published on, and the DNS records this installation created.
//!
//! **`names`**: one row per name through its life.
//! - An **internal** name (`<label>.<zone>.wicket.internal`) is registered at once
//!   ([`Ledger::register_internal`]): it grants nothing (links still decide every connection), so
//!   it needs only a free label in its zone and room in the workload's limit.
//! - A **public** name (`<label>.<boxes domain>`) is asked for ([`Ledger::ask_public`]) and
//!   approved by a human ([`Ledger::approve_name`]), bound to the effect that was shown, as standing
//!   reach is (#572).
//! - Status: `pending` (a public ask), `live`, `denied`, or `ended` (released with its run,
//!   revoked, or lapsed; [`NameRow::end_reason`]).
//! - Scope: a `run` name is held by the run that asked and ends with it. A `standing` name is the
//!   workload's: bound to the agent's principal (or, for a public one, its zone if the human chose
//!   so) and to the zone's digest, it is let go when its run ends ([`Ledger::release_run_names`])
//!   and held again by the next run it binds ([`Ledger::claim_standing_names`]), until it lapses or
//!   is revoked. While live it is exclusive whether or not a run holds it.
//! - Labels are unique among live names: an internal one per tenant and zone, a public one per
//!   installation (unique indexes, so a race between two writers can't break it).
//!
//! **`host_ports`**: the host port a public name is published on, per node
//! ([`Ledger::allocate_port`]). `(node, proto, port)` is the key, so two names never share one. A
//! released port is quarantined until the reconciler has seen the name's records gone and frees it
//! ([`Ledger::free_port_after`]), so a cached record for the old name can't reach a new box.
//!
//! **`name_records`**: the records this installation created in a zone, by identity: the ledger
//! half of ownership ([`wicket_names::Owned`]). New records are recorded before a plan is applied
//! and the replaced ones forgotten after ([`Ledger::owned_before_apply`],
//! [`Ledger::owned_after_apply`]).
//!
//! Label rules ([`wicket_names::check_label`]) and limits come from the installation's config;
//! the caller checks the label, the ledger the uniqueness and the counts.

use crate::standing::Bound;
use crate::{now, Ledger, Result, StoreError};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ops::RangeInclusive;
use wicket_core::{RunId, TenantId};
use wicket_names::{Change, Owned, Plan, Record, RecordType, Zone};

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS names (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL,
  zone TEXT NOT NULL, zone_digest TEXT NOT NULL, principal TEXT NOT NULL, asked_run TEXT NOT NULL,
  holder TEXT, port INTEGER NOT NULL, service TEXT, reason TEXT NOT NULL, scope TEXT NOT NULL,
  status TEXT NOT NULL, created_at INTEGER NOT NULL, decided_at INTEGER, decided_by TEXT, bound TEXT,
  expires_at INTEGER, effect_sha256 TEXT, ended_at INTEGER, ended_by TEXT, end_reason TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS names_internal_live ON names (tenant, zone, label) WHERE kind = 'internal' AND status = 'live';
CREATE UNIQUE INDEX IF NOT EXISTS names_public_live ON names (label) WHERE kind = 'public' AND status = 'live';
CREATE INDEX IF NOT EXISTS names_status ON names (tenant, status);
CREATE INDEX IF NOT EXISTS names_holder ON names (holder) WHERE holder IS NOT NULL;
CREATE INDEX IF NOT EXISTS names_principal ON names (tenant, principal, status);
CREATE TABLE IF NOT EXISTS host_ports (
  node TEXT NOT NULL, proto TEXT NOT NULL, port INTEGER NOT NULL, name TEXT, last_name TEXT NOT NULL,
  held_since INTEGER NOT NULL, released_at INTEGER, free_after INTEGER,
  PRIMARY KEY (node, proto, port)
);
CREATE INDEX IF NOT EXISTS host_ports_name ON host_ports (name) WHERE name IS NOT NULL;
CREATE TABLE IF NOT EXISTS name_records (
  zone TEXT NOT NULL, name TEXT NOT NULL, rtype TEXT NOT NULL, value TEXT NOT NULL, ttl INTEGER NOT NULL,
  provider TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (zone, name, rtype, value)
);
"#;

/// Which kind of name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NameKind {
    Internal,
    Public,
}

impl NameKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NameKind::Internal => "internal",
            NameKind::Public => "public",
        }
    }
    fn parse(s: &str) -> Option<NameKind> {
        match s {
            "internal" => Some(NameKind::Internal),
            "public" => Some(NameKind::Public),
            _ => None,
        }
    }
}

/// How long a name lasts: with its run, or for the workload until it lapses or is revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NameScope {
    Run,
    Standing,
}

impl NameScope {
    pub fn as_str(self) -> &'static str {
        match self {
            NameScope::Run => "run",
            NameScope::Standing => "standing",
        }
    }
    fn parse(s: &str) -> Option<NameScope> {
        match s {
            "run" => Some(NameScope::Run),
            "standing" => Some(NameScope::Standing),
            _ => None,
        }
    }
}

/// A box's ask for a name.
#[derive(Clone, Debug)]
pub struct NameAsk<'a> {
    pub tenant: &'a TenantId,
    pub run: &'a RunId,
    pub zone: &'a str,
    /// The asking run's zone definition, hashed ([`crate::zone_digest`]): a standing name binds to it.
    pub zone_digest: &'a str,
    /// The asking agent's principal.
    pub principal: &'a str,
    /// Checked by the caller ([`wicket_names::check_label`]).
    pub label: &'a str,
    /// The box's own port.
    pub port: u16,
    /// The SRV service label (public names).
    pub service: Option<&'a str>,
    /// The agent's words.
    pub reason: &'a str,
    pub scope: NameScope,
}

/// One name, asked for or decided.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NameRow {
    pub id: String,
    pub tenant: String,
    pub kind: NameKind,
    pub label: String,
    pub zone: String,
    pub zone_digest: String,
    pub principal: String,
    /// The run that asked.
    pub asked_run: String,
    /// The run holding it now (None: a standing name between runs, or not live).
    pub holder: Option<String>,
    pub port: u16,
    pub service: Option<String>,
    pub reason: String,
    pub scope: NameScope,
    /// `pending`, `live`, `denied` or `ended`.
    pub status: String,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
    /// Who a standing name is for.
    pub bound: Option<Bound>,
    pub expires_at: Option<i64>,
    pub effect_sha256: Option<String>,
    pub ended_at: Option<i64>,
    pub ended_by: Option<String>,
    /// `run ended`, `revoked` or `lapsed`.
    pub end_reason: Option<String>,
}

impl NameRow {
    /// Live and not lapsed at `at`.
    pub fn live(&self, at: i64) -> bool {
        self.status == "live" && self.expires_at.is_none_or(|e| e > at)
    }

    /// Whether a standing name is for a run of `principal` in `zone`, whose definition hashes to
    /// `zone_digest` (as [`crate::Standing::binds`]).
    pub fn binds(&self, principal: &str, zone: &str, zone_digest: &str) -> bool {
        self.scope == NameScope::Standing
            && zone_digest == self.zone_digest
            && match self.bound {
                Some(Bound::Agent) => principal == self.principal,
                Some(Bound::Zone) => zone == self.zone,
                None => false,
            }
    }
}

/// What a decision on a public ask approves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameTerms {
    /// Who a standing name is for (ignored for a run-scoped one).
    pub bound: Bound,
    /// A standing name's lifetime (None: until revoked).
    pub ttl_secs: Option<u64>,
}

/// The effect a decision on public ask `n` with `terms` approves (#369): what the card showed,
/// hashed. A decision made on another one is refused.
pub fn name_effect(n: &NameRow, terms: &NameTerms) -> String {
    let standing = n.scope == NameScope::Standing;
    let v = serde_json::json!({
        "kind": "name",
        "id": n.id,
        "name": n.kind.as_str(),
        "label": n.label,
        "port": n.port,
        "service": n.service,
        "zone": n.zone,
        "zone_digest": n.zone_digest,
        "principal": n.principal,
        "run": n.asked_run,
        "scope": n.scope.as_str(),
        "bound": standing.then(|| terms.bound.as_str()),
        "ttl_secs": standing.then_some(terms.ttl_secs),
    });
    hex::encode(Sha256::digest(v.to_string().as_bytes()))
}

/// A new name's id: `n-` and eight characters, as requests' are `r-`.
pub fn new_name_id() -> String {
    let r = wicket_core::new_request_id();
    format!("n-{}", &r[2..])
}

/// At most this many of a principal's public asks wait at once.
pub const MAX_PENDING_NAMES: usize = 3;

const COLS: &str = "id, tenant, kind, label, zone, zone_digest, principal, asked_run, holder, port, service, reason, scope, status, \
                    created_at, decided_at, decided_by, bound, expires_at, effect_sha256, ended_at, ended_by, end_reason";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<NameRow> {
    let kind: String = r.get(2)?;
    let scope: String = r.get(12)?;
    let bound: Option<String> = r.get(17)?;
    let bad = |c: usize, s: &str| rusqlite::Error::InvalidColumnType(c, s.to_string(), rusqlite::types::Type::Text);
    Ok(NameRow {
        id: r.get(0)?,
        tenant: r.get(1)?,
        kind: NameKind::parse(&kind).ok_or_else(|| bad(2, &kind))?,
        label: r.get(3)?,
        zone: r.get(4)?,
        zone_digest: r.get(5)?,
        principal: r.get(6)?,
        asked_run: r.get(7)?,
        holder: r.get(8)?,
        port: r.get(9)?,
        service: r.get(10)?,
        reason: r.get(11)?,
        scope: NameScope::parse(&scope).ok_or_else(|| bad(12, &scope))?,
        status: r.get(13)?,
        created_at: r.get(14)?,
        decided_at: r.get(15)?,
        decided_by: r.get(16)?,
        bound: bound.as_deref().and_then(Bound::parse),
        expires_at: r.get(18)?,
        effect_sha256: r.get(19)?,
        ended_at: r.get(20)?,
        ended_by: r.get(21)?,
        end_reason: r.get(22)?,
    })
}

fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        || f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
}

fn taken(label: &str) -> StoreError {
    StoreError::Refused(format!("the name {label:?} is taken"))
}

impl Ledger {
    pub fn name(&self, id: &str) -> Result<NameRow> {
        self.conn
            .query_row(&format!("SELECT {COLS} FROM names WHERE id = ?1"), params![id], row)
            .optional()?
            .ok_or_else(|| StoreError::NoSuchRequest(id.to_string()))
    }

    /// The names of `tenant` in `status`, oldest first.
    pub fn names_with_status(&self, tenant: &TenantId, status: &str) -> Result<Vec<NameRow>> {
        let mut st = self.conn.prepare(&format!("SELECT {COLS} FROM names WHERE tenant = ?1 AND status = ?2 ORDER BY created_at, id"))?;
        let rows = st.query_map(params![tenant.0, status], row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The live names `run` holds.
    pub fn names_held_by(&self, run: &RunId) -> Result<Vec<NameRow>> {
        let mut st =
            self.conn.prepare(&format!("SELECT {COLS} FROM names WHERE holder = ?1 AND status = 'live' ORDER BY created_at, id"))?;
        let rows = st.query_map(params![run.0], row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The live internal name `label` in `zone`, if any.
    pub fn internal_name(&self, tenant: &TenantId, zone: &str, label: &str) -> Result<Option<NameRow>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {COLS} FROM names WHERE tenant = ?1 AND zone = ?2 AND label = ?3 AND kind = 'internal' AND status = 'live'"
                ),
                params![tenant.0, zone, label],
                row,
            )
            .optional()?)
    }

    /// Registers an internal name for the asking run, at once. Refused if the label is live in
    /// the zone for another workload, or the principal already holds `limit` live internal names.
    /// The same label asked again by the same principal is its name: held by this run now (its
    /// port updated), not a new one. `standing_ttl_secs`: a standing name's lifetime.
    pub fn register_internal(&self, ask: &NameAsk<'_>, limit: usize, standing_ttl_secs: u64) -> Result<NameRow> {
        let tx = self.conn.unchecked_transaction()?;
        let t = now();
        if let Some(n) = self.internal_name(ask.tenant, ask.zone, ask.label)? {
            if n.principal != ask.principal || n.zone_digest != ask.zone_digest {
                return Err(taken(ask.label));
            }
            if n.holder.as_deref().is_some_and(|h| h != ask.run.0) {
                return Err(StoreError::Refused(format!(
                    "the name {:?} is held by another run of this agent ({})",
                    ask.label,
                    n.holder.unwrap_or_default()
                )));
            }
            tx.execute("UPDATE names SET holder = ?2, port = ?3 WHERE id = ?1", params![n.id, ask.run.0, ask.port])?;
            tx.commit()?;
            return self.name(&n.id);
        }
        let held: i64 = tx.query_row(
            "SELECT count(*) FROM names WHERE tenant = ?1 AND principal = ?2 AND status = 'live' AND kind = 'internal'",
            params![ask.tenant.0, ask.principal],
            |r| r.get(0),
        )?;
        if held as usize >= limit {
            return Err(StoreError::Refused(format!("this agent holds {held} internal names already (at most {limit})")));
        }
        let id = new_name_id();
        let (bound, expires) = match ask.scope {
            NameScope::Run => (None, None),
            NameScope::Standing => {
                (Some(Bound::Agent.as_str()), Some(t.saturating_add(i64::try_from(standing_ttl_secs).unwrap_or(i64::MAX))))
            }
        };
        let r = tx.execute(
            "INSERT INTO names (id, tenant, kind, label, zone, zone_digest, principal, asked_run, holder, port, service, reason, scope,
                                status, created_at, decided_at, decided_by, bound, expires_at)
             VALUES (?1, ?2, 'internal', ?3, ?4, ?5, ?6, ?7, ?7, ?8, NULL, ?9, ?10, 'live', ?11, ?11, 'wicket:internal', ?12, ?13)",
            params![
                id,
                ask.tenant.0,
                ask.label,
                ask.zone,
                ask.zone_digest,
                ask.principal,
                ask.run.0,
                ask.port,
                ask.reason,
                ask.scope.as_str(),
                t,
                bound,
                expires
            ],
        );
        match r {
            Err(e) if is_unique_violation(&e) => return Err(taken(ask.label)),
            r => r?,
        };
        tx.commit()?;
        self.name(&id)
    }

    /// A box's ask for a public name, for a human to decide. Refused if the label is live for
    /// someone else. The same pending ask (principal, label, port, scope) is that one (false: not
    /// new).
    pub fn ask_public(&self, ask: &NameAsk<'_>) -> Result<(String, bool)> {
        let live: Option<String> = self
            .conn
            .query_row("SELECT principal FROM names WHERE label = ?1 AND kind = 'public' AND status = 'live'", params![ask.label], |r| {
                r.get(0)
            })
            .optional()?;
        if live.is_some() {
            return Err(taken(ask.label));
        }
        if let Some(id) = self
            .conn
            .query_row(
                "SELECT id FROM names WHERE tenant = ?1 AND principal = ?2 AND label = ?3 AND port = ?4 AND scope = ?5
                   AND kind = 'public' AND status = 'pending'",
                params![ask.tenant.0, ask.principal, ask.label, ask.port, ask.scope.as_str()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok((id, false));
        }
        let waiting: i64 = self.conn.query_row(
            "SELECT count(*) FROM names WHERE tenant = ?1 AND principal = ?2 AND status = 'pending'",
            params![ask.tenant.0, ask.principal],
            |r| r.get(0),
        )?;
        if waiting as usize >= MAX_PENDING_NAMES {
            return Err(StoreError::Refused(format!(
                "{waiting} of this agent's asks for public names are already waiting for a decision (at most {MAX_PENDING_NAMES})"
            )));
        }
        let id = new_name_id();
        self.conn.execute(
            "INSERT INTO names (id, tenant, kind, label, zone, zone_digest, principal, asked_run, port, service, reason, scope, status, created_at)
             VALUES (?1, ?2, 'public', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending', ?12)",
            params![id, ask.tenant.0, ask.label, ask.zone, ask.zone_digest, ask.principal, ask.run.0, ask.port, ask.service, ask.reason, ask.scope.as_str(), now()],
        )?;
        Ok((id, true))
    }

    /// Approves a pending public ask with `terms`. `shown`: the effect the human was shown
    /// ([`name_effect`]); a decision on another one is refused. A label someone else took since is
    /// refused too. The asking run holds the name; the effect approved is returned.
    pub fn approve_name(&self, id: &str, terms: &NameTerms, by: &str, shown: Option<&str>) -> Result<String> {
        let n = self.name(id)?;
        if n.status != "pending" {
            return Err(StoreError::NotPending(id.into(), n.status));
        }
        let effect = name_effect(&n, terms);
        if let Some(shown) = shown.filter(|x| *x != effect) {
            return Err(StoreError::EffectChanged(id.into(), shown.into(), effect));
        }
        let t = now();
        let (bound, expires) = match n.scope {
            NameScope::Run => (None, None),
            NameScope::Standing => {
                (Some(terms.bound.as_str()), terms.ttl_secs.map(|s| t.saturating_add(i64::try_from(s).unwrap_or(i64::MAX))))
            }
        };
        let r = self.conn.execute(
            "UPDATE names SET status = 'live', holder = asked_run, decided_at = ?2, decided_by = ?3, bound = ?4, expires_at = ?5, effect_sha256 = ?6
             WHERE id = ?1 AND status = 'pending'",
            params![id, t, by, bound, expires, effect],
        );
        match r {
            Err(e) if is_unique_violation(&e) => Err(taken(&n.label)),
            Ok(0) => Err(StoreError::NotPending(id.into(), self.name(id)?.status)),
            Ok(_) => Ok(effect),
            Err(e) => Err(e.into()),
        }
    }

    /// Denies a pending public ask.
    pub fn deny_name(&self, id: &str, by: &str) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE names SET status = 'denied', decided_at = ?2, decided_by = ?3 WHERE id = ?1 AND status = 'pending'",
            params![id, now(), by],
        )?;
        if n == 0 {
            return Err(StoreError::NotPending(id.into(), self.name(id)?.status));
        }
        Ok(())
    }

    /// Revokes a live name: it ends now, whoever holds it.
    pub fn revoke_name(&self, id: &str, by: &str) -> Result<NameRow> {
        let n = self.conn.execute(
            "UPDATE names SET status = 'ended', holder = NULL, ended_at = ?2, ended_by = ?3, end_reason = 'revoked' WHERE id = ?1 AND status = 'live'",
            params![id, now(), by],
        )?;
        if n == 0 {
            return Err(StoreError::NotPending(id.into(), self.name(id)?.status));
        }
        self.name(id)
    }

    /// `run` ended: its run-scoped names end, and its standing ones are let go for the next run they
    /// bind. Each name it held, as it is now.
    pub fn release_run_names(&self, run: &RunId) -> Result<Vec<NameRow>> {
        let held = self.names_held_by(run)?;
        let tx = self.conn.unchecked_transaction()?;
        let t = now();
        for n in &held {
            match n.scope {
                NameScope::Run => tx.execute(
                    "UPDATE names SET status = 'ended', holder = NULL, ended_at = ?2, ended_by = 'wicket', end_reason = 'run ended' WHERE id = ?1",
                    params![n.id, t],
                )?,
                NameScope::Standing => tx.execute("UPDATE names SET holder = NULL WHERE id = ?1", params![n.id])?,
            };
        }
        tx.commit()?;
        held.iter().map(|n| self.name(&n.id)).collect()
    }

    /// A run of `principal` in `zone` (definition `zone_digest`) started: it holds the live,
    /// unlapsed standing names that bind it and that no run holds. The names it now holds.
    pub fn claim_standing_names(
        &self,
        tenant: &TenantId,
        run: &RunId,
        principal: &str,
        zone: &str,
        zone_digest: &str,
    ) -> Result<Vec<NameRow>> {
        let t = now();
        let mut st = self.conn.prepare(&format!(
            "SELECT {COLS} FROM names WHERE tenant = ?1 AND status = 'live' AND scope = 'standing' AND holder IS NULL AND (principal = ?2 OR zone = ?3)"
        ))?;
        let free = st.query_map(params![tenant.0, principal, zone], row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut claimed = vec![];
        for n in free.into_iter().filter(|n| n.live(t) && n.binds(principal, zone, zone_digest)) {
            if self
                .conn
                .execute("UPDATE names SET holder = ?2 WHERE id = ?1 AND holder IS NULL AND status = 'live'", params![n.id, run.0])?
                == 1
            {
                claimed.push(self.name(&n.id)?);
            }
        }
        Ok(claimed)
    }

    /// Ends the live names whose lifetime is over at `at`. Each one ended.
    pub fn lapse_names(&self, at: i64) -> Result<Vec<NameRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {COLS} FROM names WHERE status = 'live' AND expires_at IS NOT NULL AND expires_at <= ?1"))?;
        let due = st.query_map(params![at], row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut ended = vec![];
        for n in due {
            if self.conn.execute(
                "UPDATE names SET status = 'ended', holder = NULL, ended_at = ?2, ended_by = 'wicket', end_reason = 'lapsed' WHERE id = ?1 AND status = 'live'",
                params![n.id, at],
            )? == 1
            {
                ended.push(self.name(&n.id)?);
            }
        }
        Ok(ended)
    }

    /// The host port name `name` is published on at `node` (`proto`: `tcp`), allocating one from
    /// `range` if it has none there: `prefer` (its port on its last node) if free, else the lowest
    /// free one. A port is free with no row, or released and past its quarantine. Refused when the
    /// range is used up.
    pub fn allocate_port(&self, node: &str, proto: &str, name: &str, range: RangeInclusive<u16>, prefer: Option<u16>) -> Result<u16> {
        if let Some(p) = self.port_of(name, node, proto)? {
            return Ok(p);
        }
        let t = now();
        let tx = self.conn.unchecked_transaction()?;
        let free = |p: u16| -> Result<bool> {
            let r: Option<(Option<String>, Option<i64>)> = tx
                .query_row(
                    "SELECT name, free_after FROM host_ports WHERE node = ?1 AND proto = ?2 AND port = ?3",
                    params![node, proto, p],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            Ok(match r {
                None => true,
                Some((None, Some(after))) => after <= t,
                Some(_) => false,
            })
        };
        let mut pick = prefer.filter(|p| range.contains(p)).map(|p| free(p).map(|f| f.then_some(p))).transpose()?.flatten();
        if pick.is_none() {
            for p in range.clone() {
                if free(p)? {
                    pick = Some(p);
                    break;
                }
            }
        }
        let Some(p) = pick else {
            return Err(StoreError::Refused(format!("node {node} has no free host port in {}-{}", range.start(), range.end())));
        };
        tx.execute(
            "INSERT INTO host_ports (node, proto, port, name, last_name, held_since) VALUES (?1, ?2, ?3, ?4, ?4, ?5)
             ON CONFLICT (node, proto, port) DO UPDATE SET name = ?4, last_name = ?4, held_since = ?5, released_at = NULL, free_after = NULL",
            params![node, proto, p, name, t],
        )?;
        tx.commit()?;
        Ok(p)
    }

    /// The port `name` holds at `node`, if any.
    pub fn port_of(&self, name: &str, node: &str, proto: &str) -> Result<Option<u16>> {
        Ok(self
            .conn
            .query_row("SELECT port FROM host_ports WHERE name = ?1 AND node = ?2 AND proto = ?3", params![name, node, proto], |r| r.get(0))
            .optional()?)
    }

    /// `name` lets go of its ports (on every node): each is quarantined, not free, until
    /// [`Ledger::free_port_after`]. The `(node, proto, port)`s released.
    pub fn release_ports(&self, name: &str) -> Result<Vec<(String, String, u16)>> {
        let mut st = self.conn.prepare("SELECT node, proto, port FROM host_ports WHERE name = ?1")?;
        let held = st.query_map(params![name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        self.conn
            .execute("UPDATE host_ports SET name = NULL, released_at = ?2, free_after = NULL WHERE name = ?1", params![name, now()])?;
        Ok(held)
    }

    /// A released port may be handed out again from `at`: what the reconciler sets once the
    /// records of the name that held it are gone (and twice their TTL has passed). A port held
    /// again since is left.
    pub fn free_port_after(&self, node: &str, proto: &str, port: u16, at: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE host_ports SET free_after = ?4 WHERE node = ?1 AND proto = ?2 AND port = ?3 AND name IS NULL",
            params![node, proto, port, at],
        )?;
        Ok(())
    }

    /// The records this installation created in `zone`, as the plan's ledger half.
    pub fn owned_records(&self, zone: &Zone) -> Result<Vec<Record>> {
        let mut st = self.conn.prepare("SELECT name, rtype, value, ttl FROM name_records WHERE zone = ?1 ORDER BY name, rtype, value")?;
        let rows = st
            .query_map(params![zone.apex()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, u32>(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().filter_map(|(name, t, value, ttl)| Some(Record { name, rtype: rtype(&t)?, value, ttl })).collect())
    }

    /// [`Ledger::owned_records`] as [`Owned`].
    pub fn owned(&self, zone: &Zone) -> Result<Owned> {
        Ok(Owned::new(&self.owned_records(zone)?))
    }

    /// Records a plan's new records as this installation's, before the plan is applied, so a crash
    /// while applying leaves only records the ledger knows of.
    pub fn owned_before_apply(&self, zone: &Zone, provider: &str, plan: &Plan) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let t = now();
        for c in &plan.changes {
            if let Change::Create(r) | Change::Update { to: r, .. } = c {
                tx.execute(
                    "INSERT INTO name_records (zone, name, rtype, value, ttl, provider, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT (zone, name, rtype, value) DO UPDATE SET ttl = ?5, provider = ?6",
                    params![zone.apex(), r.name, r.rtype.to_string(), r.value, r.ttl, provider, t],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Forgets the records a plan deleted or replaced, once it was applied (a value it also wrote
    /// stays).
    pub fn owned_after_apply(&self, zone: &Zone, plan: &Plan) -> Result<()> {
        let written: std::collections::BTreeSet<_> = plan
            .changes
            .iter()
            .filter_map(|c| match c {
                Change::Create(r) | Change::Update { to: r, .. } => Some(r.key()),
                Change::Delete(_) => None,
            })
            .collect();
        let tx = self.conn.unchecked_transaction()?;
        for c in &plan.changes {
            if let Change::Delete(r) | Change::Update { from: r, .. } = c {
                if !written.contains(&r.key()) {
                    tx.execute(
                        "DELETE FROM name_records WHERE zone = ?1 AND name = ?2 AND rtype = ?3 AND value = ?4",
                        params![zone.apex(), r.name, r.rtype.to_string(), r.value],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
}

fn rtype(s: &str) -> Option<RecordType> {
    Some(match s {
        "A" => RecordType::A,
        "AAAA" => RecordType::Aaaa,
        "SRV" => RecordType::Srv,
        "TXT" => RecordType::Txt,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use wicket_names::{plan, Desired, MemoryProvider, OwnerId};

    fn ledger() -> Ledger {
        Ledger::open_in_memory().unwrap()
    }

    fn ask<'a>(t: &'a TenantId, run: &'a RunId, principal: &'a str, label: &'a str, scope: NameScope) -> NameAsk<'a> {
        NameAsk {
            tenant: t,
            run,
            zone: "build",
            zone_digest: "d1",
            principal,
            label,
            port: 3000,
            service: Some("http"),
            reason: "the demo",
            scope,
        }
    }

    const P1: &str = "spiffe://t/z/build/a/one";
    const P2: &str = "spiffe://t/z/build/a/two";

    #[test]
    fn internal_names_are_unique_per_zone_and_limited() {
        let l = ledger();
        let t = TenantId("t".into());
        let (r1, r2) = (RunId("run-1".into()), RunId("run-2".into()));
        let n = l.register_internal(&ask(&t, &r1, P1, "api", NameScope::Run), 2, 3600).unwrap();
        assert_eq!((n.status.as_str(), n.holder.as_deref(), n.kind), ("live", Some("run-1"), NameKind::Internal));
        // Another workload can't take it; the same run asking again gets the same row.
        assert!(matches!(l.register_internal(&ask(&t, &r2, P2, "api", NameScope::Run), 2, 3600), Err(StoreError::Refused(_))));
        let again = l.register_internal(&NameAsk { port: 8080, ..ask(&t, &r1, P1, "api", NameScope::Run) }, 2, 3600).unwrap();
        assert_eq!((again.id.as_str(), again.port), (n.id.as_str(), 8080));
        // Another zone or tenant may use the label.
        l.register_internal(&NameAsk { zone: "other", ..ask(&t, &r2, P2, "api", NameScope::Run) }, 2, 3600).unwrap();
        l.register_internal(&ask(&TenantId("u".into()), &r2, P2, "api", NameScope::Run), 2, 3600).unwrap();
        // The limit is per principal.
        l.register_internal(&ask(&t, &r1, P1, "web", NameScope::Run), 2, 3600).unwrap();
        assert!(
            matches!(l.register_internal(&ask(&t, &r1, P1, "db", NameScope::Run), 2, 3600), Err(StoreError::Refused(m)) if m.contains("at most 2"))
        );
        assert_eq!(l.internal_name(&t, "build", "api").unwrap().unwrap().id, n.id);
    }

    #[test]
    fn run_names_end_with_their_run_and_standing_ones_move_to_the_next() {
        let l = ledger();
        let t = TenantId("t".into());
        let (r1, r2) = (RunId("run-1".into()), RunId("run-2".into()));
        let run_name = l.register_internal(&ask(&t, &r1, P1, "api", NameScope::Run), 5, 3600).unwrap();
        let standing = l.register_internal(&ask(&t, &r1, P1, "web", NameScope::Standing), 5, 3600).unwrap();
        assert_eq!(standing.bound, Some(Bound::Agent));
        assert!(standing.expires_at.is_some());
        let released = l.release_run_names(&r1).unwrap();
        assert_eq!(released.len(), 2);
        let ended = l.name(&run_name.id).unwrap();
        assert_eq!((ended.status.as_str(), ended.end_reason.as_deref()), ("ended", Some("run ended")));
        let between = l.name(&standing.id).unwrap();
        assert_eq!((between.status.as_str(), between.holder), ("live", None));
        // The label stays the workload's while no run holds it.
        assert!(l.register_internal(&ask(&t, &r2, P2, "web", NameScope::Run), 5, 3600).is_err());
        // A run of another zone definition doesn't get it; the next run of the agent does.
        assert!(l.claim_standing_names(&t, &r2, P1, "build", "d2").unwrap().is_empty());
        let claimed = l.claim_standing_names(&t, &r2, P1, "build", "d1").unwrap();
        assert_eq!(
            claimed.iter().map(|n| (n.id.as_str(), n.holder.as_deref())).collect::<Vec<_>>(),
            vec![(standing.id.as_str(), Some("run-2"))]
        );
        // The ended run-scoped label is free again.
        l.register_internal(&ask(&t, &r2, P2, "api", NameScope::Run), 5, 3600).unwrap();
        // Lapse.
        let lapsed = l.lapse_names(now() + 7200).unwrap();
        assert_eq!(lapsed.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(), vec![standing.id.as_str()]);
        assert_eq!(l.name(&standing.id).unwrap().end_reason.as_deref(), Some("lapsed"));
    }

    #[test]
    fn public_names_wait_for_a_human_bound_to_what_was_shown() {
        let l = ledger();
        let t = TenantId("t".into());
        let (r1, r2) = (RunId("run-1".into()), RunId("run-2".into()));
        let (id, new) = l.ask_public(&ask(&t, &r1, P1, "demo", NameScope::Standing)).unwrap();
        assert!(new);
        assert_eq!(l.ask_public(&ask(&t, &r1, P1, "demo", NameScope::Standing)).unwrap(), (id.clone(), false));
        let (other, _) = l.ask_public(&ask(&t, &r2, P2, "demo", NameScope::Run)).unwrap();
        let n = l.name(&id).unwrap();
        assert_eq!((n.status.as_str(), n.holder.as_deref()), ("pending", None));

        let terms = NameTerms { bound: Bound::Agent, ttl_secs: Some(30 * 86_400) };
        let shown = name_effect(&n, &terms);
        let wider = NameTerms { bound: Bound::Zone, ttl_secs: None };
        assert!(matches!(l.approve_name(&id, &wider, "alice", Some(&shown)), Err(StoreError::EffectChanged(..))));
        assert_eq!(l.approve_name(&id, &terms, "alice", Some(&shown)).unwrap(), shown);
        let n = l.name(&id).unwrap();
        assert_eq!((n.status.as_str(), n.holder.as_deref(), n.bound), ("live", Some("run-1"), Some(Bound::Agent)));
        assert!(matches!(l.approve_name(&id, &terms, "alice", None), Err(StoreError::NotPending(..))));

        // The other ask for the label: refused as taken, and new asks too.
        assert!(matches!(l.approve_name(&other, &terms, "alice", None), Err(StoreError::Refused(m)) if m.contains("taken")));
        assert!(matches!(l.ask_public(&ask(&t, &r2, P2, "demo", NameScope::Run)), Err(StoreError::Refused(_))));
        l.deny_name(&other, "alice").unwrap();
        assert_eq!(l.name(&other).unwrap().status, "denied");

        // Revoked: the label is free.
        let r = l.revoke_name(&id, "alice").unwrap();
        assert_eq!((r.status.as_str(), r.end_reason.as_deref(), r.holder), ("ended", Some("revoked"), None));
        assert!(l.ask_public(&ask(&t, &r2, P2, "demo", NameScope::Run)).unwrap().1);
    }

    #[test]
    fn pending_public_asks_are_limited() {
        let l = ledger();
        let t = TenantId("t".into());
        let r = RunId("run-1".into());
        for (i, label) in ["a", "b", "c"].iter().enumerate() {
            l.ask_public(&NameAsk { port: 3000 + i as u16, ..ask(&t, &r, P1, label, NameScope::Run) }).unwrap();
        }
        assert!(matches!(l.ask_public(&ask(&t, &r, P1, "d", NameScope::Run)), Err(StoreError::Refused(m)) if m.contains("at most 3")));
    }

    #[test]
    fn ports_are_unique_per_node_sticky_and_quarantined() {
        let l = ledger();
        let range = 20000..=20002;
        assert_eq!(l.allocate_port("n1", "tcp", "n-a", range.clone(), None).unwrap(), 20000);
        assert_eq!(l.allocate_port("n1", "tcp", "n-a", range.clone(), None).unwrap(), 20000, "a name keeps its port");
        assert_eq!(l.allocate_port("n1", "tcp", "n-b", range.clone(), Some(20000)).unwrap(), 20001, "a held port isn't preferred");
        assert_eq!(l.allocate_port("n2", "tcp", "n-b", range.clone(), Some(20001)).unwrap(), 20001, "the same port on another node");
        assert_eq!(
            l.allocate_port("n1", "tcp", "n-c", range.clone(), Some(30000)).unwrap(),
            20002,
            "a preference outside the range is ignored"
        );
        assert!(matches!(l.allocate_port("n1", "tcp", "n-d", range.clone(), None), Err(StoreError::Refused(_))));

        let released = l.release_ports("n-a").unwrap();
        assert_eq!(released, vec![("n1".to_string(), "tcp".to_string(), 20000)]);
        assert!(l.allocate_port("n1", "tcp", "n-d", range.clone(), None).is_err(), "quarantined until freed");
        l.free_port_after("n1", "tcp", 20000, now() + 3600).unwrap();
        assert!(l.allocate_port("n1", "tcp", "n-d", range.clone(), None).is_err(), "not before its time");
        l.free_port_after("n1", "tcp", 20000, now() - 1).unwrap();
        assert_eq!(l.allocate_port("n1", "tcp", "n-d", range.clone(), None).unwrap(), 20000);
        assert_eq!(l.port_of("n-d", "n1", "tcp").unwrap(), Some(20000));
        // A port held again isn't freed by a late call.
        l.free_port_after("n1", "tcp", 20000, now() - 1).unwrap();
        assert!(l.allocate_port("n1", "tcp", "n-e", range, Some(20000)).is_err());
    }

    /// The ledger's half of ownership, through plans applied to a zone in memory: what the ledger
    /// lists always lets the next plan converge, and records it never created are never touched.
    #[tokio::test]
    async fn owned_records_follow_the_plans() {
        use wicket_names::DnsProvider;
        let l = ledger();
        let zone = Zone::new("boxes.example.com");
        let owner = OwnerId::parse("ourowner1").unwrap();
        let theirs = Record::a(&zone.name("www"), Ipv4Addr::new(203, 0, 113, 1), 300);
        let dns = MemoryProvider::new(zone.clone(), vec![theirs.clone()]);
        let want = |ip: [u8; 4]| {
            let n = zone.name("demo");
            vec![Desired { name: n.clone(), grant: "n-1".into(), records: vec![Record::a(&n, Ipv4Addr::from(ip), 60)], ttl: 60 }]
        };
        for desired in [want([192, 0, 2, 1]), want([192, 0, 2, 1]), want([198, 51, 100, 7]), vec![]] {
            let p = plan(&zone, &owner, &desired, &dns.list(&zone).await.unwrap(), &l.owned(&zone).unwrap()).unwrap();
            l.owned_before_apply(&zone, "memory", &p).unwrap();
            dns.apply(&zone, &p).await.unwrap();
            l.owned_after_apply(&zone, &p).unwrap();
            let again = plan(&zone, &owner, &desired, &dns.list(&zone).await.unwrap(), &l.owned(&zone).unwrap()).unwrap();
            assert!(again.is_empty(), "{again:?}");
            assert!(dns.records().contains(&theirs));
        }
        assert_eq!(dns.records(), vec![theirs]);
        assert!(l.owned_records(&zone).unwrap().is_empty());
    }
}
