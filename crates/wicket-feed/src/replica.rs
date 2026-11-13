//! The node side: a verified replica of one node's feed, its [`Mode`], [`Replica::decide`],
//! and persistence of what was verified.
//!
//! # Acceptance rules
//!
//! - **Key certificate**: signed by the pinned root; not expired; `version` never goes down, and the
//!   same version can't name another key. A higher version is a re-genesis (below).
//! - **Snapshot**: signed by the certified key, for this node, made under the certificate's version.
//!   Under the same version as the state held it must not go below the epoch held (`rollback`), and
//!   at the same epoch must have the same head (`fork`); a same-epoch, same-head snapshot replaces the
//!   persisted base (compaction). Under a **higher** version it is accepted at any epoch: this is the
//!   root-signed re-genesis that recovers a control plane restored from an old backup.
//! - **Delta**: the next epoch exactly (`replay` / `gap`), `prev` equal to the head held (`fork`),
//!   and the same version as the state.
//! - **Freshness statement**: `issued_at` strictly after the last statement's (`replay`), epoch not
//!   below the last statement's under the same version (`rollback`), not issued more than
//!   [`ReplicaConfig::future_tolerance_ms`] in the future, not already expired, TTL within the certificate's cap (`too_long`). A statement naming an epoch the node already holds
//!   (deltas committed after it was signed arrived first) is accepted only if its head equals the
//!   node's recorded head at that epoch (a ring of [`crate::HEADS_KEPT`]): a different head is a
//!   `fork`, an epoch older than the ring a `rollback`.
//!
//! # Effective deadlines (clock-skew guard)
//!
//! A statement keeps the node fresh until `min(fresh_until, receipt + (fresh_until − issued_at))`,
//! capped at the certificate's `not_after`. A node whose clock runs behind the control plane can't stretch
//! freshness past the signed TTL as measured on its own clock.
//!
//! # Persistence
//!
//! With a directory ([`Replica::open`]), every accepted artifact is written durably *before* it is
//! applied: `cert.jws`, `snapshot.jws` (the base), `deltas.jsonl` (applied since the base),
//! `statements.json` (the last statement and the last vouching one, with their receipt times and the
//! `issued_at` floor), and `uses.log` (grant uses). On start the node re-verifies all of it and
//! resumes in whatever mode the signed deadlines allow; replay protection survives the restart. Any
//! file that doesn't verify makes [`Replica::open`] fail: the caller starts again with
//! [`Replica::reset`], which keeps only the use counts and comes up [`Mode::Closed`] until a live
//! statement arrives.

use crate::format::{Delta, Frame, FrameKind, Fresh, Grant, Hello, KeyCert, RevokeKind, Snapshot};
use crate::jws::{kid, open, sha, TYP_DELTA, TYP_FRESH, TYP_KEY, TYP_SNAP};
use crate::state::{Policy, State};
use crate::store::{append_line, lines, read_opt, write_atomic};
use crate::{Refusal, DEFAULT_FUTURE_TOLERANCE_MS, HEADS_KEPT};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use wicket_core::{Op, Verdict, ZoneSpec};

/// The node's mode, from its own clock and the signed deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// A live statement vouches for the state held: decide normally.
    Fresh,
    /// No live statement (the control host is unreachable, #153): the node decides from the
    /// tokens and grants it holds, each until its own expiry. Nothing new can be granted; asks are
    /// queued by the caller.
    Offline,
    /// A live statement names an epoch the node doesn't hold yet: the missing deltas may hold a
    /// revocation, so nothing is allowed until they arrive (catch-up takes milliseconds).
    Lagging,
    /// Nothing vouches for the state: refuse everything.
    Closed,
}

#[derive(Clone, Debug)]
pub struct ReplicaConfig {
    /// How far in the future (node clock) a statement's `issued_at` may be. Keep it small and run NTP.
    pub future_tolerance_ms: i64,
}

impl Default for ReplicaConfig {
    fn default() -> Self {
        ReplicaConfig { future_tolerance_ms: DEFAULT_FUTURE_TOLERANCE_MS }
    }
}

/// What a decision allowed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Allowed {
    /// By the zone's reach rule `n`.
    Reach(usize),
    /// By the ceilings of the box's token (every block's reach), without a grant.
    Ceiling,
    /// By a live grant (one use consumed).
    Grant(String),
    /// A lease on a grant, until (Unix ms).
    Lease {
        grant: String,
        until: i64,
    },
    Spawn,
    Approval,
}

/// The node proxy's answer for one op or escalation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow(Allowed),
    /// Fresh, outside the zone's reach (or too risky for it), and no live grant: escalate.
    NeedsGrant(String),
    /// Never allowed, whatever the mode or the grants.
    Forbidden(String),
    /// Would need fresher policy than the node has.
    Refused {
        mode: Mode,
        why: String,
    },
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow(_))
    }
}

/// Things only a fresh node may do.
#[derive(Clone, Debug)]
pub enum Escalation<'a> {
    /// A lease on a replicated grant, for up to `ttl_ms` (never past the grant's `not_after`).
    Lease { zone: &'a str, grant: &'a str, ttl_ms: i64 },
    /// Starting a box in `child` from a box in `parent`.
    Spawn { parent: &'a str, child: &'a str },
    /// Signing an agent's approval in `zone`.
    Approval { zone: &'a str },
}

/// Counters of accepted and refused frames.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub accepted: BTreeMap<&'static str, u64>,
    pub refused: BTreeMap<&'static str, u64>,
    pub last_refusal: Option<String>,
}

/// Why a persisted replica couldn't be loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{file} does not verify: {why}")]
    Corrupt { file: &'static str, why: String },
}

/// An accepted statement and its effective deadlines.
#[derive(Clone, Debug)]
struct Statement {
    f: Fresh,
    jws: String,
    received_at: i64,
    fresh_until: i64,
}

impl Statement {
    fn new(f: Fresh, jws: String, received_at: i64, cert: &KeyCert) -> Statement {
        let fresh_until = f.fresh_until.min(received_at.saturating_add(f.fresh_until.saturating_sub(f.issued_at))).min(cert.not_after);
        Statement { f, jws, received_at, fresh_until }
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct StoredStatements {
    issued_floor: i64,
    fresh: Option<StoredStatement>,
    vouched: Option<StoredStatement>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredStatement {
    jws: String,
    received_at: i64,
}

const CERT: &str = "cert.jws";
const SNAPSHOT: &str = "snapshot.jws";
const DELTAS: &str = "deltas.jsonl";
const STATEMENTS: &str = "statements.json";
const USES: &str = "uses.log";

struct Cert {
    c: KeyCert,
    key: VerifyingKey,
    jws: String,
}

/// The node's verified copy of its feed. Generic over the zone policy payload.
pub struct Replica<P: Policy> {
    node: String,
    root: VerifyingKey,
    cfg: ReplicaConfig,
    /// What compiling an entry needs (for tokens, their root key).
    ctx: P::Ctx,
    cert: Option<Cert>,
    state: Option<State<P>>,
    /// Chain heads of recent epochs held.
    heads: BTreeMap<u64, String>,
    /// The newest statement accepted.
    fresh: Option<Statement>,
    /// The newest statement whose epoch the node had reached: it vouches for the state held.
    vouched: Option<Statement>,
    /// Every later statement's `issued_at` must be above this.
    issued_floor: i64,
    /// Uses of counted grants on this node.
    used: HashMap<String, u32>,
    dir: Option<PathBuf>,
    pub stats: Stats,
}

/// A verified update, not yet persisted or applied.
enum Plan<P: Policy> {
    None,
    Key(Cert),
    Snap { s: Snapshot<P>, jws: String, keep_heads: bool },
    Delta { d: Delta<P>, jws: String, head: String },
    Fresh(Statement),
}

impl<P: Policy> Replica<P>
where
    P::Ctx: Default,
{
    /// [`Replica::new_with`] for payloads that compile without context ([`wicket_core::ZoneSpec`]).
    pub fn new(node: &str, root: VerifyingKey, cfg: ReplicaConfig) -> Replica<P> {
        Self::new_with(node, root, cfg, P::Ctx::default())
    }

    /// [`Replica::reset_with`] without context.
    pub fn reset(dir: &Path, node: &str, root: VerifyingKey, cfg: ReplicaConfig) -> Result<Replica<P>, LoadError> {
        Self::reset_with(dir, node, root, cfg, P::Ctx::default())
    }

    /// [`Replica::open_with`] without context.
    pub fn open(dir: &Path, node: &str, root: VerifyingKey, cfg: ReplicaConfig) -> Result<Replica<P>, LoadError> {
        Self::open_with(dir, node, root, cfg, P::Ctx::default())
    }
}

impl<P: Policy> Replica<P> {
    /// A replica with no state and no persistence: [`Mode::Closed`] until it has a snapshot and a
    /// live statement. `ctx` is what compiling an entry needs (for tokens, their root key).
    pub fn new_with(node: &str, root: VerifyingKey, cfg: ReplicaConfig, ctx: P::Ctx) -> Replica<P> {
        Replica {
            node: node.into(),
            root,
            cfg,
            ctx,
            cert: None,
            state: None,
            heads: BTreeMap::new(),
            fresh: None,
            vouched: None,
            issued_floor: i64::MIN,
            used: HashMap::new(),
            dir: None,
            stats: Stats::default(),
        }
    }

    /// Discards any persisted feed in `dir` (keeping grant use counts) and starts empty, persisting
    /// from now on. For first start, and after [`Replica::open_with`] found a corrupt file.
    pub fn reset_with(dir: &Path, node: &str, root: VerifyingKey, cfg: ReplicaConfig, ctx: P::Ctx) -> Result<Replica<P>, LoadError> {
        std::fs::create_dir_all(dir)?;
        for f in [STATEMENTS, DELTAS, SNAPSHOT, CERT] {
            match std::fs::remove_file(dir.join(f)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        let mut r = Replica::new_with(node, root, cfg, ctx);
        r.used = load_uses(dir)?;
        r.dir = Some(dir.to_path_buf());
        Ok(r)
    }

    /// Loads and re-verifies the feed persisted in `dir` (creating it if needed), and keeps persisting
    /// there. Fails if any file doesn't verify; nothing from a failed load is trusted.
    pub fn open_with(dir: &Path, node: &str, root: VerifyingKey, cfg: ReplicaConfig, ctx: P::Ctx) -> Result<Replica<P>, LoadError> {
        std::fs::create_dir_all(dir)?;
        let mut r = Replica::new_with(node, root, cfg, ctx);
        r.load(dir)?;
        r.used = load_uses(dir)?;
        r.dir = Some(dir.to_path_buf());
        Ok(r)
    }

    fn load(&mut self, dir: &Path) -> Result<(), LoadError> {
        let corrupt = |file: &'static str| move |e: Refusal| LoadError::Corrupt { file, why: e.to_string() };
        let cert = read_opt(&dir.join(CERT))?;
        let snap = read_opt(&dir.join(SNAPSHOT))?;
        let deltas = read_opt(&dir.join(DELTAS))?;
        let stmts = read_opt(&dir.join(STATEMENTS))?;
        let Some(cert) = cert else {
            if snap.is_some() || deltas.as_deref().is_some_and(|d| !d.is_empty()) || stmts.is_some() {
                return Err(LoadError::Corrupt { file: CERT, why: "missing, but other feed files exist".into() });
            }
            return Ok(());
        };
        let c: KeyCert = open(&cert, TYP_KEY, &kid(&self.root), &self.root).map_err(corrupt(CERT))?;
        let key = c.key().map_err(corrupt(CERT))?;
        self.cert = Some(Cert { c, key, jws: cert });

        let stored: StoredStatements = match &stmts {
            Some(s) => serde_json::from_str(s).map_err(|e| LoadError::Corrupt { file: STATEMENTS, why: e.to_string() })?,
            None => StoredStatements { issued_floor: i64::MIN, ..Default::default() },
        };
        self.issued_floor = stored.issued_floor;

        let Some(snap) = snap else {
            if deltas.as_deref().is_some_and(|d| !d.is_empty()) {
                return Err(LoadError::Corrupt { file: DELTAS, why: "deltas without a snapshot".into() });
            }
            return Ok(());
        };
        let cert_version = self.cert_ref().version;
        #[derive(Deserialize)]
        struct VersionOnly {
            version: u64,
        }
        if crate::jws::payload_unverified::<VersionOnly>(&snap).is_some_and(|s| s.version < cert_version) {
            // Made under an older generation (and maybe an older key): useless after a re-genesis,
            // whether genuine or not. Stay without state until the new generation's snapshot arrives.
            return Ok(());
        }
        let s: Snapshot<P> = self.verify(&snap, TYP_SNAP).map_err(corrupt(SNAPSHOT))?;
        if s.feed != self.node || s.version != cert_version {
            return Err(LoadError::Corrupt { file: SNAPSHOT, why: "wrong feed or version".into() });
        }
        self.heads = BTreeMap::from([(s.epoch, s.head.clone())]);
        self.state = Some(State::from_snapshot(&s, self.ctx.clone()));

        let text = deltas.unwrap_or_default();
        let (complete, _torn) = lines(&text);
        for line in complete {
            let d: Delta<P> = self.verify(line, TYP_DELTA).map_err(corrupt(DELTAS))?;
            let head = self.check_delta(&d, line).map_err(corrupt(DELTAS))?;
            self.apply_delta(&d, head);
        }
        // A torn last line was never fully fsynced, so never relied on: drop it.

        let st = self.state.as_ref().expect("state loaded");
        let (st_version, st_epoch) = (st.version, st.epoch);
        let restore = |file: &'static str, s: &Option<StoredStatement>, vouching: bool| -> Result<Option<Statement>, LoadError> {
            let Some(s) = s else { return Ok(None) };
            let f: Fresh = self.verify(&s.jws, TYP_FRESH).map_err(corrupt(file))?;
            if f.feed != self.node || f.version != cert_version {
                return Err(LoadError::Corrupt { file, why: "wrong feed or version".into() });
            }
            self.check_caps(&f).map_err(corrupt(file))?;
            if f.version == st_version && f.epoch <= st_epoch {
                if let Some(h) = self.heads.get(&f.epoch) {
                    if *h != f.head {
                        return Err(LoadError::Corrupt { file, why: format!("head differs at epoch {}", f.epoch) });
                    }
                }
            } else if vouching {
                // Genuine, but for a state not held: a crash between truncating the deltas and
                // writing a new snapshot leaves the older base. It vouches for nothing now.
                return Ok(None);
            }
            if f.issued_at > self.issued_floor {
                return Err(LoadError::Corrupt { file, why: "issued after the recorded floor".into() });
            }
            Ok(Some(Statement::new(f, s.jws.clone(), s.received_at, &self.cert_ref().clone())))
        };
        let fresh = restore(STATEMENTS, &stored.fresh, false)?;
        let vouched = restore(STATEMENTS, &stored.vouched, true)?;
        (self.fresh, self.vouched) = (fresh, vouched);
        Ok(())
    }

    fn cert_ref(&self) -> &KeyCert {
        &self.cert.as_ref().expect("certificate held").c
    }

    pub fn node(&self) -> &str {
        &self.node
    }

    /// The state held, if any.
    pub fn state(&self) -> Option<&State<P>> {
        self.state.as_ref()
    }

    /// The certificate held, if any.
    pub fn cert(&self) -> Option<&KeyCert> {
        self.cert.as_ref().map(|c| &c.c)
    }

    /// The newest statement accepted.
    pub fn last_statement(&self) -> Option<&Fresh> {
        self.fresh.as_ref().map(|s| &s.f)
    }

    /// Effective `fresh_until` of the statement that vouches for the state held.
    pub fn fresh_until(&self) -> Option<i64> {
        self.vouched.as_ref().map(|s| s.fresh_until)
    }

    /// What to tell the publisher when connecting.
    pub fn hello(&self) -> Hello {
        let st = self.state.as_ref();
        Hello { node: self.node.clone(), version: st.map(|s| s.version), epoch: st.map(|s| s.epoch), head: st.map(|s| s.head.clone()) }
    }

    /// The mode at `now` (node clock).
    pub fn mode(&self, now: i64) -> Mode {
        let (Some(st), Some(cert)) = (&self.state, &self.cert) else { return Mode::Closed };
        if now >= cert.c.not_after || st.version != cert.c.version {
            return Mode::Closed;
        }
        match &self.fresh {
            Some(f) if f.f.version == st.version && now < f.fresh_until && st.epoch >= f.f.epoch => Mode::Fresh,
            Some(f) if f.f.version == st.version && now < f.fresh_until => Mode::Lagging,
            // A statement once vouched for this state (a snapshot alone, maybe replayed, never does).
            _ if self.vouched.as_ref().is_some_and(|v| v.f.version == st.version && v.f.epoch <= st.epoch) => Mode::Offline,
            _ => Mode::Closed,
        }
    }

    /// Parses and accepts one inbound frame (the attacker-reachable entry point).
    pub fn accept_bytes(&mut self, bytes: &[u8], now: i64) -> Result<(), Refusal> {
        match Frame::parse(bytes) {
            Ok(f) => self.accept(&f, now),
            Err(e) => {
                self.count(None, &Err(e.clone()));
                Err(e)
            }
        }
    }

    /// Verifies one frame; if it is acceptable, persists it, then applies it.
    pub fn accept(&mut self, frame: &Frame, now: i64) -> Result<(), Refusal> {
        let r = self.plan(frame, now).and_then(|p| self.commit(p));
        self.count(Some(frame.kind), &r);
        r
    }

    fn count(&mut self, kind: Option<FrameKind>, r: &Result<(), Refusal>) {
        match r {
            Ok(()) => *self.stats.accepted.entry(kind.map_or("?", |k| k.as_str())).or_default() += 1,
            Err(e) => {
                *self.stats.refused.entry(e.kind()).or_default() += 1;
                self.stats.last_refusal = Some(format!("{}: {e}", kind.map_or("?", |k| k.as_str())));
            }
        }
    }

    fn plan(&self, frame: &Frame, now: i64) -> Result<Plan<P>, Refusal> {
        match frame.kind {
            FrameKind::Key => self.plan_key(&frame.jws, now),
            FrameKind::Snap => self.plan_snap(&frame.jws, now),
            FrameKind::Delta => self.plan_delta(&frame.jws, now),
            FrameKind::Fresh => self.plan_fresh(&frame.jws, now),
        }
    }

    /// Verifies an artifact against the certified feed key, without time checks.
    fn verify<T: serde::de::DeserializeOwned>(&self, jws: &str, typ: &str) -> Result<T, Refusal> {
        let Some(c) = &self.cert else { return Err(Refusal::UnknownKey("no certified feed key yet".into())) };
        open(jws, typ, &c.c.kid, &c.key)
    }

    /// As [`Self::verify`], refusing once the certificate has expired: a stolen online key is
    /// useless past its certificate.
    fn verify_live<T: serde::de::DeserializeOwned>(&self, jws: &str, typ: &str, now: i64) -> Result<(T, &KeyCert), Refusal> {
        let Some(c) = &self.cert else { return Err(Refusal::UnknownKey("no certified feed key yet".into())) };
        if c.c.not_after <= now {
            return Err(Refusal::KeyExpired);
        }
        Ok((open(jws, typ, &c.c.kid, &c.key)?, &c.c))
    }

    fn plan_key(&self, jws: &str, now: i64) -> Result<Plan<P>, Refusal> {
        let c: KeyCert = open(jws, TYP_KEY, &kid(&self.root), &self.root)?;
        let key = c.key()?;
        if c.not_after <= now {
            return Err(Refusal::KeyExpired);
        }
        if let Some(cur) = &self.cert {
            if c.version < cur.c.version {
                return Err(Refusal::KeyRollback(format!("version {} < held {}", c.version, cur.c.version)));
            }
            if c.version == cur.c.version {
                if c.kid != cur.c.kid {
                    return Err(Refusal::KeyRollback(format!("version {} already certifies another key", c.version)));
                }
                if c.not_after <= cur.c.not_after {
                    return Ok(Plan::None); // the same certificate again, or an older one: keep ours
                }
            }
        }
        Ok(Plan::Key(Cert { c, key, jws: jws.into() }))
    }

    fn plan_snap(&self, jws: &str, now: i64) -> Result<Plan<P>, Refusal> {
        let (s, cert): (Snapshot<P>, _) = self.verify_live(jws, TYP_SNAP, now)?;
        if s.feed != self.node {
            return Err(Refusal::WrongAudience(s.feed));
        }
        if s.version != cert.version {
            return Err(Refusal::WrongVersion { want: cert.version, got: s.version });
        }
        let mut keep_heads = false;
        if let Some(st) = &self.state {
            if s.version == st.version {
                if s.epoch < st.epoch {
                    return Err(Refusal::Rollback(format!("snapshot epoch {} < held {}", s.epoch, st.epoch)));
                }
                if s.epoch == st.epoch {
                    if s.head != st.head {
                        return Err(Refusal::Fork(format!("snapshot head differs at epoch {}", s.epoch)));
                    }
                    keep_heads = true; // compaction: same state, new base
                }
            }
            // s.version > st.version: a re-genesis, accepted at any epoch.
        }
        if let Some(f) = &self.fresh {
            if f.f.version == s.version && f.f.epoch == s.epoch && f.f.head != s.head {
                return Err(Refusal::Fork("snapshot head differs from the last statement's".into()));
            }
        }
        Ok(Plan::Snap { s, jws: jws.into(), keep_heads })
    }

    /// The chain checks for a delta against the state held; returns its head.
    fn check_delta(&self, d: &Delta<P>, jws: &str) -> Result<String, Refusal> {
        if d.feed != self.node {
            return Err(Refusal::WrongAudience(d.feed.clone()));
        }
        let st = self.state.as_ref().ok_or(Refusal::NoBase)?;
        if d.version != st.version {
            return Err(Refusal::WrongVersion { want: st.version, got: d.version });
        }
        if d.epoch <= st.epoch {
            return Err(Refusal::Replay(format!("delta {} already applied (held {})", d.epoch, st.epoch)));
        }
        if d.epoch != st.epoch.saturating_add(1) {
            return Err(Refusal::Gap { have: st.epoch, got: d.epoch });
        }
        if d.prev != st.head {
            return Err(Refusal::Fork(format!("delta {} prev does not match the head held", d.epoch)));
        }
        let head = sha(jws);
        if let Some(f) = &self.fresh {
            if f.f.version == d.version && f.f.epoch == d.epoch && f.f.head != head {
                return Err(Refusal::Fork("delta differs from the one the last statement names".into()));
            }
        }
        Ok(head)
    }

    fn plan_delta(&self, jws: &str, now: i64) -> Result<Plan<P>, Refusal> {
        let (d, cert): (Delta<P>, _) = self.verify_live(jws, TYP_DELTA, now)?;
        if d.version != cert.version {
            return Err(Refusal::WrongVersion { want: cert.version, got: d.version });
        }
        let head = self.check_delta(&d, jws)?;
        Ok(Plan::Delta { d, jws: jws.into(), head })
    }

    fn check_caps(&self, f: &Fresh) -> Result<(), Refusal> {
        let cert = self.cert_ref();
        let ttl = f.fresh_until.checked_sub(f.issued_at).ok_or(Refusal::Malformed("ttl".into()))?;
        if ttl <= 0 {
            return Err(Refusal::Malformed("deadlines out of order".into()));
        }
        if ttl > cert.max_ttl_ms {
            return Err(Refusal::TooLong(format!("ttl {ttl} ms > certified {}", cert.max_ttl_ms)));
        }
        Ok(())
    }

    fn plan_fresh(&self, jws: &str, now: i64) -> Result<Plan<P>, Refusal> {
        let (f, cert): (Fresh, _) = self.verify_live(jws, TYP_FRESH, now)?;
        if f.feed != self.node {
            return Err(Refusal::WrongAudience(f.feed));
        }
        if f.version != cert.version {
            return Err(Refusal::WrongVersion { want: cert.version, got: f.version });
        }
        if f.issued_at <= self.issued_floor {
            return Err(Refusal::Replay(format!("statement issued_at {} not after {}", f.issued_at, self.issued_floor)));
        }
        if let Some(last) = &self.fresh {
            if f.version == last.f.version && f.epoch < last.f.epoch {
                return Err(Refusal::Rollback(format!("statement epoch {} < the last statement's {}", f.epoch, last.f.epoch)));
            }
        }
        if f.issued_at > now.saturating_add(self.cfg.future_tolerance_ms) {
            return Err(Refusal::FromFuture);
        }
        if f.fresh_until <= now {
            return Err(Refusal::Expired);
        }
        self.check_caps(&f)?;
        // A statement may name an epoch older than the node holds (deltas committed after it was
        // signed arrived first): accept it only if that epoch is on the node's own chain.
        if let Some(st) = &self.state {
            if f.version == st.version && f.epoch <= st.epoch {
                match self.heads.get(&f.epoch) {
                    Some(h) if *h == f.head => {}
                    Some(_) => return Err(Refusal::Fork(format!("statement head differs at epoch {}", f.epoch))),
                    None => {
                        return Err(Refusal::Rollback(format!(
                            "statement epoch {} is older than the history held (epoch {})",
                            f.epoch, st.epoch
                        )))
                    }
                }
            }
        }
        let cert = cert.clone();
        Ok(Plan::Fresh(Statement::new(f, jws.into(), now, &cert)))
    }

    fn commit(&mut self, plan: Plan<P>) -> Result<(), Refusal> {
        let io = |e: std::io::Error| Refusal::Storage(e.to_string());
        match plan {
            Plan::None => Ok(()),
            Plan::Key(c) => {
                if let Some(dir) = &self.dir {
                    write_atomic(&dir.join(CERT), c.jws.as_bytes()).map_err(io)?;
                }
                let regenesis = self.cert.as_ref().is_some_and(|cur| c.c.version > cur.c.version);
                self.cert = Some(c);
                if regenesis {
                    // Statements of the old generation can't vouch for anything any more.
                    self.fresh = None;
                    self.vouched = None;
                    self.persist_statements().map_err(io)?;
                }
                Ok(())
            }
            Plan::Snap { s, jws, keep_heads } => {
                let regenesis = self.state.as_ref().is_some_and(|st| s.version > st.version);
                if let Some(dir) = &self.dir {
                    // Deltas first: a crash in between leaves the old base without deltas (an older
                    // state, so stale or lagging), never the new base with the old deltas.
                    write_atomic(&dir.join(DELTAS), b"").map_err(io)?;
                    write_atomic(&dir.join(SNAPSHOT), jws.as_bytes()).map_err(io)?;
                }
                if !keep_heads {
                    self.heads = BTreeMap::from([(s.epoch, s.head.clone())]);
                }
                if regenesis {
                    self.vouched = None;
                }
                self.state = Some(State::from_snapshot(&s, self.ctx.clone()));
                self.revouch();
                self.persist_statements().map_err(io)
            }
            Plan::Delta { d, jws, head } => {
                if let Some(dir) = &self.dir {
                    append_line(&dir.join(DELTAS), &jws).map_err(io)?;
                }
                self.apply_delta(&d, head);
                self.revouch();
                self.persist_statements().map_err(io)
            }
            Plan::Fresh(s) => {
                let prev = (self.fresh.take(), self.vouched.clone(), self.issued_floor);
                self.issued_floor = s.f.issued_at;
                self.fresh = Some(s);
                self.revouch();
                if let Err(e) = self.persist_statements() {
                    (self.fresh, self.vouched, self.issued_floor) = prev;
                    return Err(io(e));
                }
                Ok(())
            }
        }
    }

    fn apply_delta(&mut self, d: &Delta<P>, head: String) {
        let st = self.state.as_mut().expect("checked");
        st.apply(d, head.clone());
        self.heads.insert(d.epoch, head);
        while self.heads.len() > HEADS_KEPT {
            self.heads.pop_first();
        }
    }

    fn revouch(&mut self) {
        if let (Some(st), Some(f)) = (&self.state, &self.fresh) {
            if f.f.version == st.version && st.epoch >= f.f.epoch {
                self.vouched = Some(f.clone());
            }
        }
    }

    fn persist_statements(&self) -> std::io::Result<()> {
        let Some(dir) = &self.dir else { return Ok(()) };
        let s = |s: &Option<Statement>| s.as_ref().map(|s| StoredStatement { jws: s.jws.clone(), received_at: s.received_at });
        let stored = StoredStatements { issued_floor: self.issued_floor, fresh: s(&self.fresh), vouched: s(&self.vouched) };
        write_atomic(&dir.join(STATEMENTS), &serde_json::to_vec(&stored).expect("serialises"))
    }

    /// Uses recorded for a grant on this node.
    pub fn uses(&self, grant: &str) -> u32 {
        self.used.get(grant).copied().unwrap_or(0)
    }

    /// The checks every decision starts with: the mode (closed refuses), and run revocation.
    pub(crate) fn gate(&self, op: &Op, now: i64) -> Result<(Mode, &State<P>), Decision> {
        let mode = self.mode(now);
        match mode {
            Mode::Closed => {
                return Err(Decision::Refused { mode, why: "closed: no verified state, or the feed key's certificate has expired".into() })
            }
            Mode::Lagging => return Err(Decision::Refused { mode, why: "catching up with the feed".into() }),
            Mode::Fresh | Mode::Offline => {}
        }
        let st = self.state.as_ref().expect("not closed");
        if st.is_revoked(RevokeKind::Run, &op.run.0) {
            return Err(Decision::Forbidden(format!("run {} is revoked", op.run)));
        }
        Ok((mode, st))
    }

    /// Records one use of a counted grant, durably before it is honoured.
    pub(crate) fn record_use(&mut self, id: &str) -> Result<(), String> {
        if let Some(dir) = &self.dir {
            append_line(&dir.join(USES), id).map_err(|e| format!("could not record a use of grant {id}: {e}"))?;
        }
        *self.used.entry(id.to_string()).or_default() += 1;
        Ok(())
    }
}

impl Replica<ZoneSpec> {
    fn live_grant(&self, st: &State<ZoneSpec>, g: &Grant, op: &Op, now: i64) -> bool {
        g.zone == op.zone
            && g.not_after > now
            && !st.is_revoked(RevokeKind::Grant, &g.id)
            && g.box_id.as_ref().is_none_or(|b| *b == op.run.0)
            // A counted grant without a box could be honoured on several nodes, each counting
            // separately: never here (the publisher refuses to publish one; this covers older feeds).
            && (g.uses.is_none() || g.box_id.is_some())
            && g.uses.is_none_or(|max| self.uses(&g.id) < max)
    }

    /// The decision for one op at `now`: the mode, the zone's compiled policy, the live grants
    /// (consuming one use of a counted grant) and the revocations. See the crate docs for the rule.
    pub fn decide(&mut self, op: &Op, now: i64) -> Decision {
        let (mode, st) = match self.gate(op, now) {
            Ok(v) => v,
            Err(d) => return d,
        };
        let refused = |why: String| Decision::Refused { mode, why };
        let Some(zone) = st.zones.get(&op.zone) else { return Decision::Forbidden(format!("unknown zone {}", op.zone)) };
        match zone.evaluate(op) {
            Verdict::Forbidden(r) => Decision::Forbidden(r),
            Verdict::AllowByReach(i) => Decision::Allow(Allowed::Reach(i)),
            Verdict::NeedsGrant(r) => {
                let digest = op.digest();
                let found = st
                    .by_op
                    .get(&digest)
                    .into_iter()
                    .flatten()
                    .filter_map(|id| st.grants.get(id))
                    .find(|g| self.live_grant(st, g, op, now))
                    .map(|g| (g.id.clone(), g.uses.is_some()));
                let Some((id, counted)) = found else { return Decision::NeedsGrant(r) };
                if counted {
                    if let Err(e) = self.record_use(&id) {
                        return refused(e);
                    }
                }
                Decision::Allow(Allowed::Grant(id))
            }
        }
    }
}

impl<P: Policy> Replica<P> {
    /// Whether the node may issue a lease, start a spawn or sign an approval at `now`: only when
    /// fresh, and never for revoked or expired grants.
    pub fn escalate(&self, e: &Escalation<'_>, now: i64) -> Decision {
        let mode = self.mode(now);
        if mode != Mode::Fresh {
            return Decision::Refused { mode, why: format!("{mode:?}: no leases, spawns or approvals until fresh").to_lowercase() };
        }
        let st = self.state.as_ref().expect("fresh");
        let zone_known = |z: &str| st.zones.contains_key(z);
        match *e {
            Escalation::Lease { zone, grant, ttl_ms } => match st.grants.get(grant) {
                Some(g) if g.zone == zone && g.not_after > now && !st.is_revoked(RevokeKind::Grant, grant) => {
                    Decision::Allow(Allowed::Lease { grant: g.id.clone(), until: g.not_after.min(now.saturating_add(ttl_ms.max(1))) })
                }
                _ => Decision::NeedsGrant(format!("no live grant {grant} in zone {zone}")),
            },
            Escalation::Spawn { parent, child } if zone_known(parent) && zone_known(child) => Decision::Allow(Allowed::Spawn),
            Escalation::Spawn { parent, child } => Decision::Forbidden(format!("unknown zone {parent} or {child}")),
            Escalation::Approval { zone } if zone_known(zone) => Decision::Allow(Allowed::Approval),
            Escalation::Approval { zone } => Decision::Forbidden(format!("unknown zone {zone}")),
        }
    }
}

fn load_uses(dir: &Path) -> Result<HashMap<String, u32>, LoadError> {
    let mut used = HashMap::new();
    if let Some(text) = read_opt(&dir.join(USES))? {
        // Unsigned, local and only ever restrictive: a torn last line counts a use of no real grant.
        for id in text.split('\n').filter(|l| !l.is_empty()) {
            *used.entry(id.to_string()).or_default() += 1;
        }
    }
    Ok(used)
}
