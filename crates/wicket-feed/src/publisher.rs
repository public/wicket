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
//! - Several publishers on one log (#582 step 3): each run's supervisor process has its own. Under
//!   the caller's lock, [`Publisher::refresh`] applies only the deltas others appended since this
//!   one last read or wrote the log, and [`Publisher::tick`] is due a refresh after the last
//!   statement any of them signed ([`Publisher::note_issued`]), so the node gets one per refresh.
//! - Checkpoints ([`CHECKPOINT`], every [`CHECKPOINT_EVERY`] deltas): the state at an epoch and
//!   where it ends in the log, so opening the feed reads only the deltas kept for catch-up (the last
//!   `retain`, all a publisher keeps in memory) and applies only those after it. One that doesn't
//!   match the log is ignored and the whole log replayed. The log itself stays complete.
//!
//! One `Publisher` serves one node (the feed's audience); a control plane keeps one per node. It
//! holds no lock and starts no thread: the caller serialises calls, which also gives the revocation
//! bound its premise (a statement is signed under the same lock that commits deltas).

use crate::format::{Change, Delta, Frame, FrameKind, Fresh, Hello, KeyCert, Snapshot, GENESIS};
use crate::jws::{kid, open, payload_unverified, sha, sign, TYP_DELTA, TYP_FRESH, TYP_KEY, TYP_SNAP};
use crate::state::{superseded, Policy, State};
use crate::store::{lines, read_opt, write_atomic};
use crate::{DEFAULT_REFRESH_MS, DEFAULT_TTL_MS};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct PublisherConfig {
    pub ttl_ms: i64,
    pub refresh_ms: i64,
    /// Catch-up from deltas only if the node is at most this many epochs behind; else a snapshot.
    /// Also how many deltas a publisher keeps in memory.
    pub retain: u64,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        PublisherConfig { ttl_ms: DEFAULT_TTL_MS, refresh_ms: DEFAULT_REFRESH_MS, retain: 1000 }
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
/// The checkpoint beside the delta log (#582): the state at an epoch, so opening the feed replays
/// only the deltas after it.
pub const CHECKPOINT: &str = "checkpoint.json";
/// A checkpoint is written at every epoch that is a multiple of this, by the publisher that commits
/// it: one per that many deltas for the feed, however many publishers share it.
pub const CHECKPOINT_EVERY: u64 = 64;

/// What [`Publisher::refresh`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refreshed {
    /// Nothing was appended since this publisher last read or wrote the log.
    Current,
    /// This many deltas another publisher appended were applied.
    Applied(u64),
    /// The log can't be followed from here (it was replaced or truncated, or a delta was made
    /// under a newer certificate): open the feed again.
    Reopen,
}

/// A checkpoint: the state at an epoch, and where in the log that epoch ends. It is the
/// publisher's own file, like its log (whose signatures aren't checked on open either); it is used
/// only if its state reads back to its own hash and the deltas it keeps (at least its own epoch's)
/// chain in the log up to its head, so a log replaced or rewritten since, or a damaged file, makes
/// it be ignored, never trusted.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    /// The state, a [`Snapshot`] as JSON, and its [`sha`].
    snap: String,
    sum: String,
    /// The log's byte offset just past delta `snap.epoch`'s line.
    end: u64,
    /// The byte offset and epoch of the first delta kept for catch-up: at most `snap.epoch`.
    tail_from: u64,
    tail_epoch: u64,
    /// [`Publisher`]'s `gen_start`, for `snap.version`.
    gen_start: u64,
}

/// A delta line's chain fields, read without its changes.
#[derive(Deserialize)]
struct Link {
    feed: String,
    version: u64,
    epoch: u64,
    prev: String,
}

/// The deltas kept for catch-up, the last `keep`, with the head at each epoch they span.
struct Tail {
    keep: u64,
    /// `heads[0]` is the head at epoch `base`; `log[i]` is delta `base + 1 + i`, with its version.
    base: u64,
    heads: VecDeque<String>,
    log: VecDeque<(u64, String)>,
    /// The log's byte offset of delta `base + 1`'s line.
    from: u64,
}

impl Tail {
    fn new(keep: u64, base: u64, head: String, from: u64) -> Tail {
        Tail { keep, base, heads: VecDeque::from([head]), log: VecDeque::new(), from }
    }

    fn push(&mut self, version: u64, line: String, head: String) {
        self.log.push_back((version, line));
        self.heads.push_back(head);
        while self.log.len() as u64 > self.keep {
            let (_, l) = self.log.pop_front().expect("a delta");
            self.heads.pop_front();
            self.base += 1;
            self.from += l.len() as u64 + 1;
        }
    }

    fn head(&self, epoch: u64) -> Option<&String> {
        epoch.checked_sub(self.base).and_then(|i| self.heads.get(usize::try_from(i).ok()?))
    }

    /// The deltas after `epoch` (which [`Tail::head`] holds).
    fn after(&self, epoch: u64) -> impl Iterator<Item = &String> {
        self.log.iter().skip(usize::try_from(epoch - self.base).unwrap_or(usize::MAX)).map(|(_, l)| l)
    }
}

/// A feed's state as its files have it, and what a publisher keeps besides.
struct Loaded<P: Policy> {
    state: State<P>,
    tail: Tail,
    gen_start: u64,
    /// The log's length in complete lines (where the next append goes), and whether a torn line
    /// follows.
    end: u64,
    torn: bool,
    /// The epoch of the checkpoint the load started from, if any.
    checkpoint: Option<u64>,
    /// The `issued_at` of the last delta, if any.
    last_at: Option<i64>,
}

fn read_from(path: &Path, offset: u64) -> io::Result<String> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e),
    };
    f.seek(io::SeekFrom::Start(offset))?;
    let mut b = vec![];
    f.read_to_end(&mut b)?;
    String::from_utf8(b).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{} is not UTF-8", path.display())))
}

/// The checkpoint in `dir`, if there is one that reads and is for `feed` (and for `version`, when
/// given). Whether it matches the log is checked as the log is read.
fn read_checkpoint<P: Policy>(dir: &Path, feed: &str, version: Option<u64>) -> Option<(Checkpoint, Snapshot<P>)> {
    let c: Checkpoint = serde_json::from_str(&read_opt(&dir.join(CHECKPOINT)).ok()??).ok()?;
    if sha(&c.snap) != c.sum {
        return None;
    }
    let snap: Snapshot<P> = serde_json::from_str(&c.snap).ok()?;
    let ok = snap.feed == feed
        && version.is_none_or(|v| v == snap.version)
        && c.tail_from < c.end
        && c.tail_epoch >= 1
        && c.tail_epoch <= snap.epoch;
    ok.then_some((c, snap))
}

/// Loads the feed in `dir`: from its checkpoint and the deltas after it when the checkpoint
/// matches the log, else by replaying the whole log. `version`: the certificate's, which no delta
/// may be above (none for read-only views). Every delta is checked to extend the chain.
fn load<P: Policy>(dir: &Path, feed: &str, ctx: P::Ctx, version: Option<u64>, keep: u64) -> Result<Loaded<P>, PublishError> {
    let path = dir.join(DELTAS);
    let keep = keep.max(1);
    if let Some((c, snap)) = read_checkpoint::<P>(dir, feed, version) {
        if let Some(l) = load_from_checkpoint(&path, feed, ctx.clone(), version, keep, c, snap)? {
            return Ok(l);
        }
    }
    let text = read_opt(&path)?.unwrap_or_default();
    let mut l = Loaded {
        state: State::genesis(version.unwrap_or(0), ctx),
        tail: Tail::new(keep, 0, GENESIS.into(), 0),
        gen_start: 0,
        end: 0,
        torn: false,
        checkpoint: None,
        last_at: None,
    };
    apply_lines(&mut l, &text, feed, version)?;
    Ok(l)
}

/// Applies the complete lines of `text` (the log from `l.end` on) to `l`, checking the chain.
/// Entries a later delta replaces or drops aren't compiled (#287): the log holds every run's, most
/// long gone.
fn apply_lines<P: Policy>(l: &mut Loaded<P>, text: &str, feed: &str, version: Option<u64>) -> Result<u64, PublishError> {
    let (complete, torn) = lines(text);
    let bad = |e: u64, why: &str| PublishError::Invalid(format!("delta log, epoch {e}: {why}"));
    let deltas = parse_log::<P>(&complete).map_err(|e| bad(l.state.epoch + e, "unreadable"))?;
    let skip = superseded(&deltas);
    let n = deltas.len() as u64;
    for ((line, d), skip) in complete.iter().copied().zip(deltas).zip(&skip) {
        if d.feed != feed || d.epoch != l.state.epoch + 1 || d.prev != l.state.head {
            return Err(bad(d.epoch, "not a chain for this feed"));
        }
        if let Some(v) = version {
            let last_version = l.tail.log.back().map_or(0, |(v, _)| *v);
            if d.version < last_version || d.version > v {
                return Err(bad(d.epoch, "version out of order, or above the certificate's"));
            }
            if d.version < v {
                l.gen_start = d.epoch;
            }
        } else {
            l.state.version = d.version;
        }
        let head = sha(line);
        l.state.apply_replaying(&d, head.clone(), skip);
        l.tail.push(d.version, line.to_string(), head);
        l.end += line.len() as u64 + 1;
        l.last_at = Some(d.issued_at);
    }
    l.torn = torn.is_some();
    Ok(n)
}

/// [`load`] from checkpoint `c`, or `None` if the log doesn't match it (then the whole log is
/// replayed instead).
fn load_from_checkpoint<P: Policy>(
    path: &Path,
    feed: &str,
    ctx: P::Ctx,
    version: Option<u64>,
    keep: u64,
    c: Checkpoint,
    snap: Snapshot<P>,
) -> Result<Option<Loaded<P>>, PublishError> {
    let text = read_from(path, c.tail_from)?;
    let Some(split) = usize::try_from(c.end - c.tail_from).ok().filter(|s| *s <= text.len() && text.is_char_boundary(*s)) else {
        return Ok(None);
    };
    let (kept, after) = text.split_at(split);
    // The deltas up to the checkpoint, kept for catch-up: each must extend the one before, and the
    // last must be the checkpoint's head.
    let (kept_lines, rest) = lines(kept);
    if rest.is_some() {
        return Ok(None);
    }
    let mut tail: Option<Tail> = None;
    let mut last_version = 0;
    for (i, line) in kept_lines.iter().enumerate() {
        let Some(link) = payload_unverified::<Link>(line) else { return Ok(None) };
        let t = tail.get_or_insert_with(|| Tail::new(keep, c.tail_epoch - 1, link.prev.clone(), c.tail_from));
        let chained = link.feed == feed
            && link.epoch == c.tail_epoch + i as u64
            && Some(&link.prev) == t.heads.back()
            && link.version >= last_version
            && version.is_none_or(|v| link.version <= v);
        if !chained {
            return Ok(None);
        }
        last_version = link.version;
        t.push(link.version, line.to_string(), sha(line));
    }
    // At least the checkpoint's own delta is kept, so there is always a line to check it against.
    let tail = match tail {
        Some(t) if t.heads.back() == Some(&snap.head) && c.tail_epoch + kept_lines.len() as u64 == snap.epoch + 1 => t,
        _ => return Ok(None),
    };
    let mut state = State::from_snapshot(&snap, ctx);
    if let Some(v) = version {
        state.version = v;
    }
    let mut l = Loaded { state, tail, gen_start: c.gen_start, end: c.end, torn: false, checkpoint: Some(snap.epoch), last_at: None };
    apply_lines(&mut l, after, feed, version)?;
    Ok(Some(l))
}

/// One node's feed, on the control plane.
pub struct Publisher<P: Policy> {
    feed: String,
    key: SigningKey,
    cert: KeyCert,
    cert_jws: String,
    cfg: PublisherConfig,
    state: State<P>,
    /// The deltas kept for catch-up, and the heads at their epochs.
    tail: Tail,
    /// The epoch at which the current version began: deltas after it are servable to its nodes.
    gen_start: u64,
    path: PathBuf,
    file: File,
    /// The log's length as this publisher last read or wrote it, and its inode then.
    end: u64,
    ino: u64,
    /// The epoch of the checkpoint loaded on open, if any.
    checkpointed: u64,
    checkpoint_every: u64,
    /// Checkpoints this publisher wrote, and why its last attempt failed, if it did.
    checkpoints: u64,
    checkpoint_error: Option<String>,
    staged: Vec<Change<P>>,
    /// A statement is due at once (none signed yet under a new certificate's version).
    statement_due: bool,
    last_issued: i64,
}

fn check_cert(root: &VerifyingKey, key: &SigningKey, cert_jws: &str, cfg: &PublisherConfig) -> Result<KeyCert, PublishError> {
    let cert: KeyCert = open(cert_jws, TYP_KEY, &kid(root), root).map_err(|e| PublishError::Invalid(format!("certificate: {e}")))?;
    let certified = cert.key().map_err(|e| PublishError::Invalid(format!("certificate: {e}")))?;
    if certified != key.verifying_key() {
        return Err(PublishError::Invalid("the certificate is for another key".into()));
    }
    if cfg.ttl_ms <= 0 || cfg.ttl_ms > cert.max_ttl_ms || cfg.refresh_ms <= 0 {
        return Err(PublishError::Invalid("ttl outside the certificate's cap".into()));
    }
    Ok(cert)
}

/// A delta log's complete lines, parsed (not verified: the log is the publisher's own), or the
/// position of the first that doesn't read (counted from 1).
fn parse_log<P: Policy>(lines: &[&str]) -> Result<Vec<Delta<P>>, u64> {
    lines.iter().enumerate().map(|(i, l)| payload_unverified(l).ok_or(i as u64 + 1)).collect()
}

/// A node feed's state as its files in `dir` have it, read without writing anything: for views
/// (the console, #173) beside the publishers that write it. No key or certificate is needed. It
/// starts from the checkpoint when that matches the log, and only complete lines are applied: a
/// torn last line (one a publisher is writing now) is skipped, never truncated. A log that isn't a
/// chain for `feed` is refused. `ctx` compiles each entry as a node would (for tokens, the
/// authority root), so a token's `compiled` says whether it loads.
pub fn read_state<P: Policy>(dir: &Path, feed: &str, ctx: P::Ctx) -> Result<State<P>, PublishError> {
    Ok(load::<P>(dir, feed, ctx, None, 0)?.state)
}

impl<P: Policy> Publisher<P> {
    /// Opens (or creates) the feed for node `feed` in `dir`: from its checkpoint and the deltas
    /// after it, or, without a checkpoint that matches the log, by replaying the whole log.
    /// `cert_jws` is the root-signed certificate for `key`; a higher version than the log's is a
    /// re-genesis. `ctx` is what compiling an entry needs (for tokens, their root key): every entry
    /// committed is compiled first, as a node will, and refused if it doesn't.
    #[allow(clippy::too_many_arguments)]
    pub fn open_with(
        dir: &Path,
        feed: &str,
        root: &VerifyingKey,
        key: SigningKey,
        cert_jws: &str,
        cfg: PublisherConfig,
        ctx: P::Ctx,
    ) -> Result<Publisher<P>, PublishError> {
        let cert = check_cert(root, &key, cert_jws, &cfg)?;
        std::fs::create_dir_all(dir)?;
        let path = dir.join(DELTAS);
        // Our own log: chain and structure are checked; signatures were made by us.
        let l = load::<P>(dir, feed, ctx, Some(cert.version), cfg.retain)?;
        if l.torn {
            // Never fsynced in full, so never published: drop it.
            OpenOptions::new().write(true).open(&path)?.set_len(l.end)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        crate::store::sync_dir(&path)?;
        let ino = file.metadata()?.ino();
        let mut p = Publisher {
            feed: feed.into(),
            key,
            cert,
            cert_jws: cert_jws.into(),
            cfg,
            state: l.state,
            tail: l.tail,
            gen_start: l.gen_start,
            path,
            file,
            end: l.end,
            ino,
            checkpointed: l.checkpoint.unwrap_or(0),
            checkpoint_every: CHECKPOINT_EVERY,
            checkpoints: 0,
            checkpoint_error: None,
            staged: vec![],
            statement_due: false,
            last_issued: i64::MIN,
        };
        // A long replay is saved, so the next process to open the feed starts from here. (A
        // checkpoint that can't be written is only a slower next open.)
        let behind = p.checkpoint_every > 0 && p.state.epoch >= p.checkpointed + p.checkpoint_every;
        if let Some(at) = l.last_at.filter(|_| behind) {
            p.try_checkpoint(at);
        }
        Ok(p)
    }

    /// Brings this publisher up to date with what other publishers (other processes) appended to
    /// the log since it last read or wrote it, applying only their deltas. Call it under the lock
    /// that serialises publishers on this feed: a torn last line is then a crashed append, and is
    /// dropped as [`Publisher::open_with`] drops it.
    pub fn refresh(&mut self) -> Result<Refreshed, PublishError> {
        let m = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Refreshed::Reopen),
            Err(e) => return Err(e.into()),
        };
        if m.ino() != self.ino || m.len() < self.end {
            return Ok(Refreshed::Reopen);
        }
        if m.len() == self.end {
            return Ok(Refreshed::Current);
        }
        let text = read_from(&self.path, self.end)?;
        let (complete, _) = lines(&text);
        // A delta made under a newer certificate: another process rotated; open again with it.
        let newer = complete.iter().any(|l| payload_unverified::<Link>(l).is_none_or(|k| k.version > self.cert.version));
        if newer {
            return Ok(Refreshed::Reopen);
        }
        let ctx = self.state.ctx.clone();
        let mut l = Loaded {
            state: std::mem::replace(&mut self.state, State::genesis(0, ctx)),
            tail: std::mem::replace(&mut self.tail, Tail::new(0, 0, String::new(), 0)),
            gen_start: self.gen_start,
            end: self.end,
            torn: false,
            checkpoint: None,
            last_at: None,
        };
        let applied = apply_lines(&mut l, &text, &self.feed, Some(self.cert.version));
        (self.state, self.tail, self.gen_start, self.end) = (l.state, l.tail, l.gen_start, l.end);
        let applied = applied?;
        if l.torn {
            self.file.set_len(self.end)?;
        }
        Ok(Refreshed::Applied(applied))
    }

    /// Whether the epoch just committed is due a checkpoint: a multiple of [`CHECKPOINT_EVERY`] (or
    /// of the number set with [`Publisher::set_checkpoint_every`]). Each epoch is committed by one
    /// publisher, so one checkpoint is written per that many deltas, whoever commits them.
    fn checkpoint_due(&self) -> bool {
        self.checkpoint_every > 0 && self.state.epoch.is_multiple_of(self.checkpoint_every)
    }

    /// [`Publisher::checkpoint`], keeping why it failed instead of failing: a checkpoint that
    /// can't be written is only a slower next open, and the next is tried at the next due epoch.
    fn try_checkpoint(&mut self, now: i64) {
        self.checkpoint_error = self.checkpoint(now).err().map(|e| e.to_string());
    }

    /// Why this publisher's last checkpoint couldn't be written, once (for the caller to log).
    pub fn take_checkpoint_error(&mut self) -> Option<String> {
        self.checkpoint_error.take()
    }

    /// How many checkpoints this publisher has written.
    pub fn checkpoints_written(&self) -> u64 {
        self.checkpoints
    }

    /// How many deltas pass between checkpoints (0: none are written).
    pub fn set_checkpoint_every(&mut self, n: u64) {
        self.checkpoint_every = n;
    }

    /// Writes a checkpoint of the current state (without what has expired by `now`), atomically, so
    /// opening the feed replays only the deltas after it. The log itself is unchanged.
    pub fn checkpoint(&mut self, now: i64) -> Result<(), PublishError> {
        let snap =
            serde_json::to_string(&self.state.snapshot(&self.feed, now)).map_err(|e| PublishError::Invalid(format!("checkpoint: {e}")))?;
        let c = Checkpoint {
            sum: sha(&snap),
            snap,
            end: self.end,
            tail_from: self.tail.from,
            tail_epoch: self.tail.base + 1,
            gen_start: self.gen_start,
        };
        let json = serde_json::to_vec(&c).map_err(|e| PublishError::Invalid(format!("checkpoint: {e}")))?;
        write_atomic(&self.path.with_file_name(CHECKPOINT), &json)?;
        self.checkpointed = self.state.epoch;
        self.checkpoints += 1;
        Ok(())
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
            self.statement_due = true;
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
            // Uses are counted on the node that holds the box, so a counted grant must name its box:
            // one box lives on one node, which makes that node's count the only count.
            if let Change::AddGrant { grant } = c {
                if grant.uses.is_some() && grant.box_id.is_none() {
                    return Err(PublishError::Invalid(format!("grant {}: a grant with a use count must name its box", grant.id)));
                }
            }
            if let Change::PutZone { zone } = c {
                let revoked = |k, id: &str| self.state.is_revoked(k, id);
                zone.compile(&self.state.ctx, &revoked).map_err(|e| PublishError::Invalid(format!("zone {}: {e}", zone.zone_name())))?;
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
        let len = self.file.metadata()?.len();
        if len != self.end {
            // Another publisher appended since this one last read the log: a delta now would fork
            // the chain (its epoch and prev are stale). Refused, so a caller that skipped
            // `refresh` fails closed instead of signing on a head the log no longer has.
            return Err(PublishError::Invalid(format!(
                "the delta log is {len} bytes, not the {} this publisher last read: refresh first",
                self.end
            )));
        }
        let jws = sign(&self.key, TYP_DELTA, &d);
        let written = self.file.write_all(format!("{jws}\n").as_bytes()).and_then(|()| self.file.sync_data());
        if let Err(e) = written {
            // Don't leave a partial line for the next append to extend.
            let _ = self.file.set_len(len);
            return Err(e.into());
        }
        self.end = len + jws.len() as u64 + 1;
        let head = sha(&jws);
        self.state.apply(&d, head.clone());
        self.tail.push(d.version, jws.clone(), head);
        if self.checkpoint_due() {
            // The delta is durable: a checkpoint that can't be written is only a slower next open.
            self.try_checkpoint(now);
        }
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
            narrow_until: 0,
        };
        let jws = sign(&self.key, TYP_FRESH, &f);
        self.statement_due = false;
        Frame::new(FrameKind::Fresh, jws)
    }

    /// A new statement if one is due, to push to the node: `refresh_ms` after the last one signed
    /// for this feed, by this publisher or another ([`Publisher::note_issued`]), so the node gets
    /// one per refresh, however many processes publish to it. One is due at once when none has
    /// been signed (that this publisher knows of), and after a rotation to a new version.
    pub fn tick(&mut self, now: i64) -> Option<Frame> {
        let due = self.statement_due || now >= self.last_issued.saturating_add(self.cfg.refresh_ms);
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
                    && self.tail.head(e) == Some(h)
            }
            _ => false,
        };
        if on_chain {
            let e = hello.epoch.unwrap_or(0);
            frames.extend(self.tail.after(e).map(|jws| Frame::new(FrameKind::Delta, jws.clone())));
        } else {
            frames.push(self.snapshot(now));
        }
        // Always a newly signed statement: never behind the epoch just served (so a node that just
        // loaded a snapshot is fresh at once), and never one the node already holds.
        frames.push(self.statement(now));
        Ok(frames)
    }

    /// The latest `issued_at` this publisher has signed a statement with.
    pub fn last_issued(&self) -> i64 {
        self.last_issued
    }

    /// Notes a statement time signed elsewhere for this feed (another process publishing to the
    /// same node), so the next statement is issued after it and no node sees two with one time,
    /// and [`Publisher::tick`] waits a refresh after it.
    pub fn note_issued(&mut self, at: i64) {
        self.last_issued = self.last_issued.max(at);
    }

    /// The delta log's path (for operators and tests).
    pub fn log_path(&self) -> &Path {
        &self.path
    }
}
