//! The control plane's side of one node's feed.
//!
//! - A durable, append-only delta log (`deltas.jsonl`): every delta is fsynced **before**
//!   [`Publisher::commit`] returns the frame to send, so a crash can only lose deltas no node has
//!   seen. A torn last line (a crash mid-append) is dropped on open.
//! - Changes can be staged and flushed as one delta ([`Publisher::stage`], [`Publisher::flush`]):
//!   batching several changes per delta roughly halves the bytes at 10 changes per delta.
//! - Freshness statements, re-signed on the caller's timer ([`Publisher::tick`]).
//! - Catch-up ([`Publisher::catch_up`]): the key certificate, then the deltas since the node's epoch
//!   if it is on this chain and at most `retain` epochs behind, else a snapshot; then a statement
//!   signed for the occasion. A cached one could be behind the epoch just served, and a node that
//!   just loaded a snapshot can't check an older statement (it has no history before the snapshot),
//!   so it would wait up to a refresh to be fresh.
//! - Re-genesis ([`Publisher::rotate`]): with a root-signed certificate of a higher `version`, every
//!   node gets a snapshot under the new version and accepts it at whatever epoch this log is at. This
//!   is how a control plane restored from an old backup brings its nodes back: they refuse the
//!   shorter history until the root vouches for it.
//!
//! One `Publisher` serves one node (the feed's audience); a control plane keeps one per node. It
//! holds no lock and starts no thread: the caller serialises calls, which also gives the revocation
//! bound its premise (a statement is signed under the same lock that commits deltas).

use crate::format::{Change, Delta, Frame, FrameKind, Fresh, Hello, KeyCert, GENESIS};
use crate::jws::{kid, open, payload_unverified, sha, sign, TYP_DELTA, TYP_FRESH, TYP_KEY, TYP_SNAP};
use crate::state::{Policy, State};
use crate::store::{lines, read_opt};
use crate::{DEFAULT_NARROW_MS, DEFAULT_REFRESH_MS, DEFAULT_TTL_MS};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct PublisherConfig {
    pub ttl_ms: i64,
    pub refresh_ms: i64,
    pub narrow_ms: i64,
    /// Catch-up from deltas only if the node is at most this many epochs behind; else a snapshot.
    pub retain: u64,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        PublisherConfig { ttl_ms: DEFAULT_TTL_MS, refresh_ms: DEFAULT_REFRESH_MS, narrow_ms: DEFAULT_NARROW_MS, retain: 1000 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Invalid(String),
}

const DELTAS: &str = "deltas.jsonl";

/// One node's feed, on the control plane.
pub struct Publisher<P: Policy> {
    feed: String,
    key: SigningKey,
    cert: KeyCert,
    cert_jws: String,
    cfg: PublisherConfig,
    state: State<P>,
    /// heads[e] is the head at epoch e (heads[0] = genesis).
    heads: Vec<String>,
    /// log[e - 1] is delta e, with the version it was made under.
    log: Vec<(u64, String)>,
    /// The epoch at which the current version began: deltas after it are servable to its nodes.
    gen_start: u64,
    path: PathBuf,
    file: File,
    staged: Vec<Change<P>>,
    fresh: Option<(Fresh, String)>,
    last_issued: i64,
}

fn check_cert(root: &VerifyingKey, key: &SigningKey, cert_jws: &str, cfg: &PublisherConfig) -> Result<KeyCert, PublishError> {
    let cert: KeyCert = open(cert_jws, TYP_KEY, &kid(root), root).map_err(|e| PublishError::Invalid(format!("certificate: {e}")))?;
    let certified = cert.key().map_err(|e| PublishError::Invalid(format!("certificate: {e}")))?;
    if certified != key.verifying_key() {
        return Err(PublishError::Invalid("the certificate is for another key".into()));
    }
    if cfg.ttl_ms <= 0 || cfg.ttl_ms > cert.max_ttl_ms || cfg.narrow_ms < 0 || cfg.narrow_ms > cert.max_narrow_ms || cfg.refresh_ms <= 0 {
        return Err(PublishError::Invalid("ttl or narrow window outside the certificate's caps".into()));
    }
    Ok(cert)
}

impl<P: Policy> Publisher<P> {
    /// Opens (or creates) the feed for node `feed` in `dir`, replaying its delta log. `cert_jws` is the
    /// root-signed certificate for `key`; a higher version than the log's is a re-genesis.
    pub fn open(
        dir: &Path,
        feed: &str,
        root: &VerifyingKey,
        key: SigningKey,
        cert_jws: &str,
        cfg: PublisherConfig,
    ) -> Result<Publisher<P>, PublishError> {
        let cert = check_cert(root, &key, cert_jws, &cfg)?;
        std::fs::create_dir_all(dir)?;
        let path = dir.join(DELTAS);
        let mut state = State::genesis(cert.version);
        let mut heads = vec![GENESIS.to_string()];
        let mut log = vec![];
        let mut gen_start = 0;
        let text = read_opt(&path)?.unwrap_or_default();
        let (complete, torn) = lines(&text);
        let bad = |e: u64, why: &str| PublishError::Invalid(format!("delta log, epoch {e}: {why}"));
        for line in complete {
            // Our own log: chain and structure are checked; signatures were made by us.
            let d: Delta<P> = payload_unverified(line).ok_or_else(|| bad(state.epoch + 1, "unreadable"))?;
            if d.feed != feed || d.epoch != state.epoch + 1 || d.prev != state.head {
                return Err(bad(d.epoch, "not a chain for this feed"));
            }
            let last_version = log.last().map_or(0, |(v, _)| *v);
            if d.version < last_version || d.version > cert.version {
                return Err(bad(d.epoch, "version out of order, or above the certificate's"));
            }
            if d.version < cert.version {
                gen_start = d.epoch;
            }
            state.apply(&d, sha(line));
            heads.push(state.head.clone());
            log.push((d.version, line.to_string()));
        }
        if torn.is_some() {
            // Never fsynced in full, so never published: drop it.
            let keep = text.len() - torn.map_or(0, str::len);
            OpenOptions::new().write(true).open(&path)?.set_len(keep as u64)?;
        }
        state.version = cert.version;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        crate::store::sync_dir(&path)?;
        Ok(Publisher {
            feed: feed.into(),
            key,
            cert,
            cert_jws: cert_jws.into(),
            cfg,
            state,
            heads,
            log,
            gen_start,
            path,
            file,
            staged: vec![],
            fresh: None,
            last_issued: i64::MIN,
        })
    }

    /// Switches to a new root-signed certificate (and possibly a new key). The version must not go
    /// down; a higher version is a re-genesis: nodes get a snapshot under it at the current epoch.
    pub fn rotate(&mut self, root: &VerifyingKey, key: SigningKey, cert_jws: &str) -> Result<(), PublishError> {
        let cert = check_cert(root, &key, cert_jws, &self.cfg)?;
        if cert.version < self.cert.version || (cert.version == self.cert.version && cert.kid != self.cert.kid) {
            return Err(PublishError::Invalid("certificate version must rise for a new key".into()));
        }
        if cert.version > self.cert.version {
            self.gen_start = self.state.epoch;
            self.state.version = cert.version;
            self.fresh = None;
        }
        (self.key, self.cert, self.cert_jws) = (key, cert, cert_jws.into());
        Ok(())
    }

    pub fn state(&self) -> &State<P> {
        &self.state
    }

    pub fn epoch(&self) -> u64 {
        self.state.epoch
    }

    pub fn version(&self) -> u64 {
        self.cert.version
    }

    pub fn key_frame(&self) -> Frame {
        Frame::new(FrameKind::Key, self.cert_jws.clone())
    }

    /// Commits a batch of changes as one delta, durably, and returns the frame to push.
    pub fn commit(&mut self, changes: Vec<Change<P>>, now: i64) -> Result<Frame, PublishError> {
        if changes.is_empty() {
            return Err(PublishError::Invalid("a delta needs at least one change".into()));
        }
        for c in &changes {
            if let Change::PutZone { zone } = c {
                zone.compile().map_err(|e| PublishError::Invalid(format!("zone {}: {e}", zone.zone_name())))?;
            }
        }
        let d = Delta {
            feed: self.feed.clone(),
            version: self.cert.version,
            epoch: self.state.epoch + 1,
            prev: self.state.head.clone(),
            issued_at: now,
            changes,
        };
        let jws = sign(&self.key, TYP_DELTA, &d);
        let len = self.file.metadata()?.len();
        let written = self.file.write_all(format!("{jws}\n").as_bytes()).and_then(|()| self.file.sync_data());
        if let Err(e) = written {
            // Don't leave a partial line for the next append to extend.
            let _ = self.file.set_len(len);
            return Err(e.into());
        }
        self.state.apply(&d, sha(&jws));
        self.heads.push(self.state.head.clone());
        self.log.push((d.version, jws.clone()));
        Ok(Frame::new(FrameKind::Delta, jws))
    }

    /// Queues a change for the next [`Publisher::flush`].
    pub fn stage(&mut self, change: Change<P>) {
        self.staged.push(change);
    }

    pub fn staged(&self) -> usize {
        self.staged.len()
    }

    /// Commits every staged change as one delta (call it on a short window, e.g. 100 ms).
    pub fn flush(&mut self, now: i64) -> Result<Option<Frame>, PublishError> {
        if self.staged.is_empty() {
            return Ok(None);
        }
        let changes = std::mem::take(&mut self.staged);
        match self.commit(changes.clone(), now) {
            Ok(f) => Ok(Some(f)),
            Err(e) => {
                self.staged = changes;
                Err(e)
            }
        }
    }

    /// Signs a new statement for the current epoch.
    pub fn statement(&mut self, now: i64) -> Frame {
        let issued_at = now.max(self.last_issued.saturating_add(1));
        self.last_issued = issued_at;
        let fresh_until = issued_at + self.cfg.ttl_ms;
        let f = Fresh {
            feed: self.feed.clone(),
            version: self.cert.version,
            epoch: self.state.epoch,
            head: self.state.head.clone(),
            issued_at,
            fresh_until,
            narrow_until: fresh_until + self.cfg.narrow_ms,
        };
        let jws = sign(&self.key, TYP_FRESH, &f);
        self.fresh = Some((f, jws.clone()));
        Frame::new(FrameKind::Fresh, jws)
    }

    /// A new statement if one is due (every `refresh_ms`), to push to the node.
    pub fn tick(&mut self, now: i64) -> Option<Frame> {
        let due = self.fresh.as_ref().is_none_or(|(f, _)| now >= f.issued_at.saturating_add(self.cfg.refresh_ms));
        due.then(|| self.statement(now))
    }

    /// A signed snapshot of the current state (also worth sending now and then, so nodes can compact
    /// their persisted deltas).
    pub fn snapshot(&mut self, now: i64) -> Frame {
        self.state.prune(now);
        Frame::new(FrameKind::Snap, sign(&self.key, TYP_SNAP, &self.state.snapshot(&self.feed, now)))
    }

    /// The frames that bring a node from what it holds (`hello`) to the current epoch, ending with a
    /// statement that names it.
    pub fn catch_up(&mut self, hello: &Hello, now: i64) -> Result<Vec<Frame>, PublishError> {
        if hello.node != self.feed {
            return Err(PublishError::Invalid(format!("hello from {} on {}'s feed", hello.node, self.feed)));
        }
        let mut frames = vec![self.key_frame()];
        let on_chain = match (hello.version, hello.epoch, &hello.head) {
            (Some(v), Some(e), Some(h)) => {
                v == self.cert.version
                    && e >= self.gen_start
                    && e <= self.state.epoch
                    && self.state.epoch - e <= self.cfg.retain
                    && self.heads.get(e as usize) == Some(h)
            }
            _ => false,
        };
        if on_chain {
            let e = hello.epoch.unwrap_or(0) as usize;
            frames.extend(self.log[e..].iter().map(|(_, jws)| Frame::new(FrameKind::Delta, jws.clone())));
        } else {
            frames.push(self.snapshot(now));
        }
        // Always a newly signed statement: never behind the epoch just served (so a node that just
        // loaded a snapshot is fresh at once), and never one the node already holds.
        frames.push(self.statement(now));
        Ok(frames)
    }

    /// The delta log's path (for operators and tests).
    pub fn log_path(&self) -> &Path {
        &self.path
    }
}
