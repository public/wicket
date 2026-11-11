//! The feed format (research 18 §5.1, architecture A). Pure: no I/O.
//!
//! - A **root key** (offline in production) certifies one online **feed key** with a version, an
//!   expiry, and the longest freshness TTL and narrow window the feed key may ever sign.
//! - The feed key signs, per node (`feed` = the node's id):
//!   - **snapshots**: the whole replicated state at an epoch, with the chain head at that epoch;
//!   - **deltas**: epoch n-1 → n, carrying `prev` = the head at n-1; head(n) = sha256(delta JWS);
//!   - **freshness statements**: "the latest epoch is N with head H; fresh until T1, narrow until T2",
//!     re-signed every few seconds (the TUF timestamp role).
//! - Every artifact is a compact JWS (EdDSA) whose `typ` separates the kinds.
//!
//! [`Replica`] is the node side: it verifies, applies in order, and refuses gaps, replays, rollbacks,
//! forks, other nodes' feeds, and freshness statements that are reused, expired or too long.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use wicket_core::ZoneSpec;

pub const TYP_KEY: &str = "wicket-feed-key+jws";
pub const TYP_SNAP: &str = "wicket-feed-snapshot+jws";
pub const TYP_DELTA: &str = "wicket-feed-delta+jws";
pub const TYP_FRESH: &str = "wicket-feed-fresh+jws";
/// How many recent chain heads a node remembers.
pub const HEADS_KEPT: usize = 4096;
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

pub fn kid(k: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(k.as_bytes())[..8])
}

pub fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

pub fn key_from_hex(s: &str) -> Option<SigningKey> {
    let b: [u8; 32] = hex::decode(s.trim()).ok()?.try_into().ok()?;
    Some(SigningKey::from_bytes(&b))
}

/// Why an update was refused. `kind()` names the counter it lands in.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    Malformed(String),
    WrongType(String),
    UnknownKey(String),
    BadSignature,
    KeyExpired,
    KeyRollback,
    WrongAudience(String),
    NoBase,
    Replay(String),
    Rollback(String),
    Gap { have: u64, got: u64 },
    Fork(String),
    Expired,
    FromFuture,
    TooLong(String),
}

impl Refusal {
    pub fn kind(&self) -> &'static str {
        match self {
            Refusal::Malformed(_) => "malformed",
            Refusal::WrongType(_) => "wrong_type",
            Refusal::UnknownKey(_) => "unknown_key",
            Refusal::BadSignature => "bad_signature",
            Refusal::KeyExpired => "key_expired",
            Refusal::KeyRollback => "key_rollback",
            Refusal::WrongAudience(_) => "wrong_audience",
            Refusal::NoBase => "no_base",
            Refusal::Replay(_) => "replay",
            Refusal::Rollback(_) => "rollback",
            Refusal::Gap { .. } => "gap",
            Refusal::Fork(_) => "fork",
            Refusal::Expired => "expired",
            Refusal::FromFuture => "from_future",
            Refusal::TooLong(_) => "too_long",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

pub fn sign<T: Serialize>(key: &SigningKey, typ: &str, payload: &T) -> String {
    sign_as(key, typ, &kid(&key.verifying_key()), payload)
}

/// As [`sign`] with an explicit `kid` (tests use it to forge headers).
pub fn sign_as<T: Serialize>(key: &SigningKey, typ: &str, kid: &str, payload: &T) -> String {
    let h = serde_json::to_vec(&Header { alg: "EdDSA".into(), typ: typ.into(), kid: kid.into() }).unwrap();
    let input = format!("{}.{}", B64.encode(h), B64.encode(serde_json::to_vec(payload).unwrap()));
    let sig = key.sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}

/// Decodes a JWS payload without verifying (harness and tests only).
pub fn payload_unverified(jws: &str) -> Option<serde_json::Value> {
    serde_json::from_slice(&B64.decode(jws.split('.').nth(1)?).ok()?).ok()
}

/// Replaces the payload but keeps header and signature (a tampered update).
pub fn tamper(jws: &str, payload: &serde_json::Value) -> String {
    let p: Vec<&str> = jws.split('.').collect();
    format!("{}.{}.{}", p[0], B64.encode(serde_json::to_vec(payload).unwrap()), p[2])
}

/// Verifies `typ`, `kid` and the signature, then decodes the payload.
pub fn open<T: DeserializeOwned>(jws: &str, typ: &str, want_kid: &str, key: &VerifyingKey) -> Result<T, Refusal> {
    let m = |s: &str| Refusal::Malformed(s.into());
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(m("not a compact JWS"));
    }
    let hdr: Header = serde_json::from_slice(&B64.decode(parts[0]).map_err(|_| m("header b64"))?).map_err(|_| m("header json"))?;
    if hdr.alg != "EdDSA" {
        return Err(m("alg"));
    }
    if hdr.typ != typ {
        return Err(Refusal::WrongType(format!("expected {typ}, got {}", hdr.typ)));
    }
    if hdr.kid != want_kid {
        return Err(Refusal::UnknownKey(hdr.kid));
    }
    let sig = Signature::from_slice(&B64.decode(parts[2]).map_err(|_| m("sig b64"))?).map_err(|_| m("sig"))?;
    let signed_len = parts[0].len() + 1 + parts[1].len();
    key.verify_strict(&jws.as_bytes()[..signed_len], &sig).map_err(|_| Refusal::BadSignature)?;
    serde_json::from_slice(&B64.decode(parts[1]).map_err(|_| m("payload b64"))?).map_err(|e| Refusal::Malformed(format!("payload: {e}")))
}

/// Root-signed certificate for the online feed key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyCert {
    pub kid: String,
    pub x: String,
    pub version: u64,
    pub not_after: i64,
    /// Longest `fresh_until - issued_at` this key may sign.
    pub max_ttl_ms: i64,
    /// Longest `narrow_until - fresh_until` this key may sign.
    pub max_narrow_ms: i64,
}

impl KeyCert {
    pub fn new(feed: &VerifyingKey, version: u64, not_after: i64, max_ttl_ms: i64, max_narrow_ms: i64) -> KeyCert {
        KeyCert { kid: kid(feed), x: B64.encode(feed.as_bytes()), version, not_after, max_ttl_ms, max_narrow_ms }
    }
}

/// A grant or lease: lets one op (by wicket-core's `Op::digest`: tenant, zone, method, host, path)
/// until `not_after`, at most `uses` times. Expiry is enforced by the node's clock.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Grant {
    pub id: String,
    pub zone: String,
    pub op: String,
    /// Human-readable op, for logs.
    pub what: String,
    pub not_after: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Change {
    PutZone { zone: ZoneSpec },
    DropZone { name: String },
    AddGrant { grant: Grant },
    /// Revokes a grant id or a run id. `until` is when the entry can be dropped from snapshots (the
    /// revoked thing's own expiry), so revocation lists stay bounded.
    Revoke { id: String, until: i64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub feed: String,
    pub epoch: u64,
    pub head: String,
    pub issued_at: i64,
    pub zones: Vec<ZoneSpec>,
    pub grants: Vec<Grant>,
    pub revoked: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delta {
    pub feed: String,
    pub epoch: u64,
    pub prev: String,
    pub issued_at: i64,
    pub changes: Vec<Change>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fresh {
    pub feed: String,
    pub epoch: u64,
    pub head: String,
    pub issued_at: i64,
    pub fresh_until: i64,
    pub narrow_until: i64,
}

/// The replicated state, identical in structure on the control plane and the node.
#[derive(Clone, Debug)]
pub struct State {
    pub epoch: u64,
    pub head: String,
    pub zones: BTreeMap<String, ZoneSpec>,
    pub grants: HashMap<String, Grant>,
    pub by_op: HashMap<String, BTreeSet<String>>,
    pub revoked: BTreeMap<String, i64>,
}

impl State {
    pub fn genesis() -> State {
        State { epoch: 0, head: GENESIS.into(), zones: BTreeMap::new(), grants: HashMap::new(), by_op: HashMap::new(), revoked: BTreeMap::new() }
    }

    pub fn apply(&mut self, d: &Delta, head: String) {
        for c in &d.changes {
            self.change(c);
        }
        self.epoch = d.epoch;
        self.head = head;
    }

    fn change(&mut self, c: &Change) {
        match c {
            Change::PutZone { zone } => {
                self.zones.insert(zone.name.clone(), zone.clone());
            }
            Change::DropZone { name } => {
                self.zones.remove(name);
                let ids: Vec<String> = self.grants.values().filter(|g| &g.zone == name).map(|g| g.id.clone()).collect();
                ids.iter().for_each(|id| self.drop_grant(id));
            }
            Change::AddGrant { grant } => {
                if !self.revoked.contains_key(&grant.id) {
                    self.by_op.entry(grant.op.clone()).or_default().insert(grant.id.clone());
                    self.grants.insert(grant.id.clone(), grant.clone());
                }
            }
            Change::Revoke { id, until } => {
                self.revoked.insert(id.clone(), *until);
                self.drop_grant(id);
            }
        }
    }

    fn drop_grant(&mut self, id: &str) {
        if let Some(g) = self.grants.remove(id) {
            if let Some(s) = self.by_op.get_mut(&g.op) {
                s.remove(id);
            }
        }
    }

    /// Snapshot at the current epoch, without grants and revocations that have expired.
    pub fn snapshot(&self, feed: &str, now: i64) -> Snapshot {
        let mut grants: Vec<Grant> = self.grants.values().filter(|g| g.not_after > now).cloned().collect();
        grants.sort_by(|a, b| a.id.cmp(&b.id));
        Snapshot {
            feed: feed.into(),
            epoch: self.epoch,
            head: self.head.clone(),
            issued_at: now,
            zones: self.zones.values().cloned().collect(),
            grants,
            revoked: self.revoked.iter().filter(|(_, u)| **u > now).map(|(k, v)| (k.clone(), *v)).collect(),
        }
    }

    pub fn from_snapshot(s: &Snapshot) -> State {
        let mut st = State::genesis();
        st.epoch = s.epoch;
        st.head = s.head.clone();
        st.revoked = s.revoked.clone();
        for z in &s.zones {
            st.zones.insert(z.name.clone(), z.clone());
        }
        for g in &s.grants {
            st.change(&Change::AddGrant { grant: g.clone() });
        }
        st
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// A live freshness statement vouches for the state held: decide normally.
    Fresh,
    /// No live statement, but the last one that vouched for this state allows a narrow window.
    Narrow,
    /// Nothing vouches for the state: refuse everything.
    Closed,
}

/// The node's verified copy of its feed.
pub struct Replica {
    pub node: String,
    root: VerifyingKey,
    pub skew_ms: i64,
    pub key: Option<(KeyCert, VerifyingKey)>,
    pub state: Option<State>,
    /// The newest freshness statement accepted.
    pub fresh: Option<Fresh>,
    /// (fresh_until, narrow_until) of the newest statement whose epoch the node had reached.
    pub vouched: Option<(i64, i64)>,
    /// Chain heads of recent epochs held, to check statements that name an older epoch.
    heads: BTreeMap<u64, String>,
    pub accepted: BTreeMap<String, u64>,
    pub refused: BTreeMap<String, u64>,
    pub last_refusal: Option<String>,
}

impl Replica {
    pub fn new(node: &str, root: VerifyingKey) -> Replica {
        Replica { node: node.into(), root, skew_ms: 0, key: None, state: None, fresh: None, vouched: None, heads: BTreeMap::new(), accepted: BTreeMap::new(), refused: BTreeMap::new(), last_refusal: None }
    }

    pub fn mode(&self, now: i64) -> Mode {
        let Some(st) = &self.state else { return Mode::Closed };
        if let Some(f) = &self.fresh {
            if st.epoch >= f.epoch && now < f.fresh_until {
                return Mode::Fresh;
            }
        }
        match self.vouched {
            Some((_, narrow_until)) if now < narrow_until => Mode::Narrow,
            _ => Mode::Closed,
        }
    }

    /// Accepts one frame (`key`, `snap`, `delta` or `fresh`) and counts the outcome.
    pub fn accept(&mut self, t: &str, jws: &str, now: i64) -> Result<(), Refusal> {
        let r = match t {
            "key" => self.accept_key(jws, now),
            "snap" => self.accept_snap(jws, now),
            "delta" => self.accept_delta(jws, now),
            "fresh" => self.accept_fresh(jws, now),
            _ => Err(Refusal::Malformed(format!("frame type {t}"))),
        };
        match &r {
            Ok(()) => *self.accepted.entry(t.into()).or_default() += 1,
            Err(e) => {
                *self.refused.entry(e.kind().into()).or_default() += 1;
                self.last_refusal = Some(format!("{t}: {e:?}"));
            }
        }
        r
    }

    fn accept_key(&mut self, jws: &str, now: i64) -> Result<(), Refusal> {
        let c: KeyCert = open(jws, TYP_KEY, &kid(&self.root), &self.root)?;
        if c.not_after <= now {
            return Err(Refusal::KeyExpired);
        }
        if let Some((cur, _)) = &self.key {
            if c.version < cur.version || (c.version == cur.version && c.kid != cur.kid) {
                return Err(Refusal::KeyRollback);
            }
        }
        let x: [u8; 32] = B64.decode(&c.x).ok().and_then(|b| b.try_into().ok()).ok_or(Refusal::Malformed("cert key".into()))?;
        let vk = VerifyingKey::from_bytes(&x).map_err(|_| Refusal::Malformed("cert key".into()))?;
        if kid(&vk) != c.kid {
            return Err(Refusal::Malformed("cert kid".into()));
        }
        self.key = Some((c, vk));
        Ok(())
    }

    fn feed_key(&self, now: i64) -> Result<(String, VerifyingKey, KeyCert), Refusal> {
        let Some((c, k)) = &self.key else { return Err(Refusal::UnknownKey("no certified feed key yet".into())) };
        if c.not_after <= now {
            return Err(Refusal::KeyExpired);
        }
        Ok((c.kid.clone(), *k, c.clone()))
    }

    fn revouch(&mut self) {
        if let (Some(st), Some(f)) = (&self.state, &self.fresh) {
            if st.epoch >= f.epoch {
                self.vouched = Some((f.fresh_until, f.narrow_until));
            }
        }
    }

    fn accept_snap(&mut self, jws: &str, now: i64) -> Result<(), Refusal> {
        let (kid, k, _) = self.feed_key(now)?;
        let s: Snapshot = open(jws, TYP_SNAP, &kid, &k)?;
        if s.feed != self.node {
            return Err(Refusal::WrongAudience(s.feed));
        }
        if let Some(st) = &self.state {
            if s.epoch < st.epoch {
                return Err(Refusal::Rollback(format!("snapshot epoch {} < held {}", s.epoch, st.epoch)));
            }
            if s.epoch == st.epoch {
                return if s.head == st.head { Ok(()) } else { Err(Refusal::Fork(format!("snapshot head differs at epoch {}", s.epoch))) };
            }
        }
        if let Some(f) = &self.fresh {
            if f.epoch == s.epoch && f.head != s.head {
                return Err(Refusal::Fork("snapshot head differs from the freshness statement".into()));
            }
        }
        self.state = Some(State::from_snapshot(&s));
        self.heads = BTreeMap::from([(s.epoch, s.head.clone())]);
        self.revouch();
        Ok(())
    }

    fn accept_delta(&mut self, jws: &str, now: i64) -> Result<(), Refusal> {
        let (kid, k, _) = self.feed_key(now)?;
        let d: Delta = open(jws, TYP_DELTA, &kid, &k)?;
        if d.feed != self.node {
            return Err(Refusal::WrongAudience(d.feed));
        }
        let st = self.state.as_mut().ok_or(Refusal::NoBase)?;
        if d.epoch <= st.epoch {
            return Err(Refusal::Replay(format!("delta {} already applied (held {})", d.epoch, st.epoch)));
        }
        if d.epoch > st.epoch + 1 {
            return Err(Refusal::Gap { have: st.epoch, got: d.epoch });
        }
        if d.prev != st.head {
            return Err(Refusal::Fork(format!("delta {} prev does not match held head", d.epoch)));
        }
        let head = sha(jws);
        if let Some(f) = &self.fresh {
            if f.epoch == d.epoch && f.head != head {
                return Err(Refusal::Fork("delta differs from the one the freshness statement names".into()));
            }
        }
        st.apply(&d, head.clone());
        self.heads.insert(d.epoch, head);
        if self.heads.len() > HEADS_KEPT {
            self.heads.pop_first();
        }
        self.revouch();
        Ok(())
    }

    fn accept_fresh(&mut self, jws: &str, now: i64) -> Result<(), Refusal> {
        let (kid, k, cert) = self.feed_key(now)?;
        let f: Fresh = open(jws, TYP_FRESH, &kid, &k)?;
        if f.feed != self.node {
            return Err(Refusal::WrongAudience(f.feed));
        }
        if let Some(last) = &self.fresh {
            if f.issued_at <= last.issued_at {
                return Err(Refusal::Replay(format!("freshness issued_at {} not after {}", f.issued_at, last.issued_at)));
            }
            if f.epoch < last.epoch {
                return Err(Refusal::Rollback(format!("freshness epoch {} < last statement's {}", f.epoch, last.epoch)));
            }
        }
        if f.issued_at > now + self.skew_ms {
            return Err(Refusal::FromFuture);
        }
        if f.fresh_until + self.skew_ms <= now {
            return Err(Refusal::Expired);
        }
        if f.fresh_until - f.issued_at > cert.max_ttl_ms {
            return Err(Refusal::TooLong(format!("ttl {} ms > certified {}", f.fresh_until - f.issued_at, cert.max_ttl_ms)));
        }
        if f.narrow_until < f.fresh_until || f.narrow_until - f.fresh_until > cert.max_narrow_ms {
            return Err(Refusal::TooLong(format!("narrow window {} ms > certified {}", f.narrow_until - f.fresh_until, cert.max_narrow_ms)));
        }
        // A statement may name an epoch older than the node holds (deltas sent after it was
        // signed): accept it only if that epoch is on the node's own chain.
        if let Some(st) = &self.state {
            if f.epoch <= st.epoch {
                match self.heads.get(&f.epoch) {
                    Some(h) if *h == f.head => {}
                    Some(_) => return Err(Refusal::Fork(format!("freshness head differs at epoch {}", f.epoch))),
                    None => return Err(Refusal::Rollback(format!("freshness epoch {} is older than the history held (epoch {})", f.epoch, st.epoch))),
                }
            }
        }
        self.fresh = Some(f);
        self.revouch();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Cp {
        root: SigningKey,
        feed: SigningKey,
        st: State,
        log: Vec<String>,
        last: i64,
    }

    impl Cp {
        fn new() -> Cp {
            Cp { root: SigningKey::from_bytes(&[1; 32]), feed: SigningKey::from_bytes(&[2; 32]), st: State::genesis(), log: vec![], last: 0 }
        }
        fn cert(&self) -> String {
            sign(&self.root, TYP_KEY, &KeyCert::new(&self.feed.verifying_key(), 1, i64::MAX, 30_000, 120_000))
        }
        fn commit(&mut self, changes: Vec<Change>) -> String {
            let d = Delta { feed: "n1".into(), epoch: self.st.epoch + 1, prev: self.st.head.clone(), issued_at: 0, changes };
            let j = sign(&self.feed, TYP_DELTA, &d);
            self.st.apply(&d, sha(&j));
            self.log.push(j.clone());
            j
        }
        fn fresh(&mut self, now: i64) -> String {
            self.last = now.max(self.last + 1);
            let f = Fresh { feed: "n1".into(), epoch: self.st.epoch, head: self.st.head.clone(), issued_at: self.last, fresh_until: self.last + 3000, narrow_until: self.last + 9000 };
            sign(&self.feed, TYP_FRESH, &f)
        }
        fn snap(&self) -> String {
            sign(&self.feed, TYP_SNAP, &self.st.snapshot("n1", 0))
        }
    }

    fn grant(id: &str) -> Change {
        Change::AddGrant { grant: Grant { id: id.into(), zone: "z".into(), op: format!("op-{id}"), what: String::new(), not_after: i64::MAX, uses: None } }
    }

    fn setup() -> (Cp, Replica) {
        let cp = Cp::new();
        let mut r = Replica::new("n1", cp.root.verifying_key());
        r.accept("key", &cp.cert(), 0).unwrap();
        r.accept("snap", &cp.snap(), 0).unwrap();
        (cp, r)
    }

    #[test]
    fn modes_follow_freshness() {
        let (mut cp, mut r) = setup();
        assert_eq!(r.mode(10), Mode::Closed, "a snapshot alone vouches for nothing");
        r.accept("fresh", &cp.fresh(10), 10).unwrap();
        assert_eq!(r.mode(11), Mode::Fresh);
        assert_eq!(r.mode(3010), Mode::Narrow);
        assert_eq!(r.mode(9010), Mode::Closed);
        let d = cp.commit(vec![grant("a")]);
        let f = cp.fresh(20);
        r.accept("fresh", &f, 20).unwrap();
        assert_eq!(r.mode(21), Mode::Narrow, "lagging behind the latest epoch is not fresh");
        r.accept("delta", &d, 22).unwrap();
        assert_eq!(r.mode(23), Mode::Fresh);
        let f_old = cp.fresh(30);
        let d2 = cp.commit(vec![grant("b")]);
        r.accept("delta", &d2, 31).unwrap();
        r.accept("fresh", &f_old, 31).expect("a statement older than the held epoch, on our chain, is fine");
        assert_eq!(r.mode(32), Mode::Fresh);
    }

    #[test]
    fn refusals() {
        let (mut cp, mut r) = setup();
        let d1 = cp.commit(vec![grant("a")]);
        let d2 = cp.commit(vec![grant("b")]);
        assert_eq!(r.accept("delta", &d2, 1).unwrap_err().kind(), "gap");
        r.accept("delta", &d1, 1).unwrap();
        assert_eq!(r.accept("delta", &d1, 1).unwrap_err().kind(), "replay");
        let mut p = payload_unverified(&d2).unwrap();
        p["changes"][0]["grant"]["id"] = "evil".into();
        assert_eq!(r.accept("delta", &tamper(&d2, &p), 1).unwrap_err().kind(), "bad_signature");
        assert_eq!(r.accept("fresh", &d2, 1).unwrap_err().kind(), "wrong_type");
        r.accept("delta", &d2, 1).unwrap();
        let old = sign(&cp.feed, TYP_SNAP, &State::genesis().snapshot("n1", 0));
        assert_eq!(r.accept("snap", &old, 1).unwrap_err().kind(), "rollback");
        let f = cp.fresh(5);
        r.accept("fresh", &f, 5).unwrap();
        assert_eq!(r.accept("fresh", &f, 6).unwrap_err().kind(), "replay");
        let evil = SigningKey::from_bytes(&[9; 32]);
        let forged = Fresh { feed: "n1".into(), epoch: 2, head: cp.st.head.clone(), issued_at: 7, fresh_until: i64::MAX, narrow_until: i64::MAX };
        assert_eq!(r.accept("fresh", &sign(&evil, TYP_FRESH, &forged), 7).unwrap_err().kind(), "unknown_key");
        assert_eq!(r.accept("fresh", &sign_as(&evil, TYP_FRESH, &kid(&cp.feed.verifying_key()), &forged), 7).unwrap_err().kind(), "bad_signature");
        assert_eq!(r.accept("fresh", &sign(&cp.feed, TYP_FRESH, &forged), 7).unwrap_err().kind(), "too_long");
        let other = Fresh { feed: "n2".into(), ..forged.clone() };
        assert_eq!(r.accept("fresh", &sign(&cp.feed, TYP_FRESH, &other), 7).unwrap_err().kind(), "wrong_audience");
        let fork = Delta { feed: "n1".into(), epoch: 3, prev: GENESIS.into(), issued_at: 0, changes: vec![] };
        assert_eq!(r.accept("delta", &sign(&cp.feed, TYP_DELTA, &fork), 7).unwrap_err().kind(), "fork");
        assert_eq!(r.state.as_ref().unwrap().epoch, 2);
        assert!(r.state.as_ref().unwrap().grants.contains_key("b") && !r.state.as_ref().unwrap().grants.contains_key("evil"));
    }
}
