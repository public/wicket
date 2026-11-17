//! Garbage collection and the local store's cache cap (#258, store.md's step 4).
//!
//! **Roots** are the digests the ledger holds (each agent's head), given by the caller, and every
//! ref the store keeps, except those the caller drops first (a bundle's ref once its agent's head
//! has moved on). A collection marks everything reachable from them, then deletes the rest of the
//! store's objects.
//!
//! **Pushes in flight.** A push reuses objects it finds already stored (`put_bytes` and
//! [`Cas::send_tree`] skip what the store has), and names what it wrote only at its end (a ref, then
//! the ledger's head). So no time-based grace alone keeps a collection from deleting an old object
//! a push has just reused. Instead, the store keeps locks as objects of its own, `l/push/<id>` and
//! `l/gc`, which work on any backend (put-if-absent, get, delete and list):
//!
//! - a push ([`Cas::writing`]) writes its lock, then waits while a live `l/gc` exists, and keeps
//!   its lock until the push is committed (its ref and the ledger's head written);
//! - a collection writes `l/gc`, then gives up if any live push lock exists, and looks again every
//!   [`CHECK_EVERY`] objects it reads or deletes, stopping when one has appeared.
//!
//! Each side writes its own lock before it reads the other's, so of a push and a collection that
//! overlap, at least one sees the other: no push reuses or writes an object while a collection
//! that hasn't seen it can delete one. A lock whose holder died is ignored once it is stale (an
//! hour after a collection last renewed it, [`GC_STALE_SECS`], or six after a push began,
//! [`PUSH_STALE_SECS`]).
//!
//! **Order of deletion.** Negotiation trusts that a store holding a tree holds everything under it:
//! [`Cas::send_tree`] skips a whole subtree its receiver has, and a wake fetches nothing when the
//! local store has the bundle tree. A collection keeps that true however it ends (stopped for a
//! push, or killed): it deletes a tree before anything the tree names, so it learns which garbage
//! objects are trees by reading their first bytes ([`crate::objects::ObjectStore::get_head`], a
//! ranged read on S3). The cache cap evicts the same way, a tree before its children.
//!
//! **The cache cap.** With a shared store (the state store, `bundles: s3`), the local store is
//! also a cache: once a collection has swept it completely, objects the shared store already holds
//! are evicted, least recently used first ([`crate::objects::Stat::used`]: a directory's
//! modification time, which a read renews), until what is left is under the cap. An object only
//! the local store holds is never evicted, nor anything under it.

use super::{Cas, Digest, Kind, Tree, TREE_MAX};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap};
use std::io::{self, Read};
use std::time::Duration;

const GC_LOCK: &str = "l/gc";
const PUSH_LOCKS: &str = "l/push/";
/// A collection's lock is stale this long after it was last renewed.
pub const GC_STALE_SECS: i64 = 3600;
/// A collection renews its lock this often (as it looks for pushes).
const GC_RENEW_SECS: i64 = 60;
/// A push's lock is stale this long after the push began.
pub const PUSH_STALE_SECS: i64 = 6 * 3600;
/// How many objects a collection reads or deletes between looks for a push that began meanwhile.
pub const CHECK_EVERY: usize = 64;
const TREE_HEADER: &[u8] = b"wicket-tree-v1\n";
/// Enough of an object to decode its first zstd block, whatever it compressed to (a block is at
/// most 128 KiB, stored raw if it doesn't compress), and so to see whether it is a tree.
const PEEK: u64 = 132 << 10;

#[derive(Serialize, Deserialize)]
struct LockBody {
    at: i64,
    by: String,
}

fn put_lock(cas: &Cas, key: &str, by: &str, now: i64) -> io::Result<bool> {
    let body = serde_json::to_vec(&LockBody { at: now, by: by.into() })?;
    cas.inner.put_if_absent(key, &mut body.as_slice())
}

/// A lock's holder and time, or None if it is gone. A body that can't be read counts as live and
/// held by nobody known (a lock is only ever written by wicket, under the store's seal).
fn read_lock(cas: &Cas, key: &str) -> io::Result<Option<(String, i64)>> {
    let Some(mut r) = cas.inner.get(key)? else { return Ok(None) };
    let mut b = vec![];
    if r.by_ref().take(4096).read_to_end(&mut b).is_err() {
        return Ok(Some(("an unreadable lock".into(), i64::MAX)));
    }
    Ok(Some(match serde_json::from_slice::<LockBody>(&b) {
        Ok(l) => (l.by, l.at),
        Err(_) => ("an unreadable lock".into(), i64::MAX),
    }))
}

/// A push's hold on a store: while it lives, no collection of that store deletes anything. Drop it
/// once what the push wrote is named (its ref written, and the ledger's head moved).
pub struct Writing<'a> {
    cas: &'a Cas,
    key: String,
}

impl Drop for Writing<'_> {
    fn drop(&mut self) {
        let _ = self.cas.inner.delete(&self.key);
    }
}

impl Writing<'_> {
    /// Whether the push may go on: no live collection holds the store.
    pub fn ready(&self, now: i64) -> io::Result<bool> {
        Ok(match read_lock(self.cas, GC_LOCK)? {
            Some((_, at)) => at != i64::MAX && now - at >= GC_STALE_SECS,
            None => true,
        })
    }
}

impl Cas {
    /// Begins a push: writes its lock, and returns it without waiting ([`Writing::ready`] says
    /// whether a collection is still under way). [`Cas::writing`] is this and the wait.
    pub fn begin_writing(&self, by: &str, now: i64) -> io::Result<Writing<'_>> {
        let key = format!("{PUSH_LOCKS}{}", wicket_core::new_ulid().to_string().to_ascii_lowercase());
        if !put_lock(self, &key, by, now)? {
            return Err(io::Error::other(format!("push lock {key} already exists")));
        }
        Ok(Writing { cas: self, key })
    }

    /// Holds the store for a push (`by` says who, in a collection's report): writes the push's
    /// lock, then waits until no collection is under way. A collection stops for a push within
    /// [`CHECK_EVERY`] objects, so the wait is short.
    pub fn writing(&self, by: &str) -> io::Result<Writing<'_>> {
        let w = self.begin_writing(by, crate::now())?;
        while !w.ready(crate::now())? {
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(w)
    }
}

/// What a collection does.
pub struct Plan<'a> {
    /// The digests the ledger holds (every agent's head that is a digest).
    pub roots: Vec<Digest>,
    /// Refs to delete before marking, by name and target: what nothing names any more.
    pub drop_ref: &'a dyn Fn(&str, &Digest) -> bool,
    /// Find and report, delete nothing (and take no lock).
    pub dry_run: bool,
    /// Who collects, in the lock.
    pub by: &'a str,
    /// The local store's cache cap: the shared store whose objects it may evict, and the most it
    /// may keep, in bytes as stored.
    pub cap: Option<(&'a Cas, u64)>,
    /// The time (Unix seconds), asked for whenever a lock's age matters.
    pub now: &'a dyn Fn() -> i64,
}

/// What a collection found and did (on a dry run, what it would have done).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// It didn't start: who holds the store.
    pub busy: Option<String>,
    /// It stopped before the end for a push that began meanwhile (what it deleted until then is
    /// reported; the next pass goes on).
    pub stopped: Option<String>,
    /// Refs kept, and those dropped.
    pub refs: usize,
    pub refs_dropped: Vec<String>,
    /// Objects reachable from the roots, and roots or reachable objects the store doesn't have
    /// (for a cache with a shared store behind it, expected).
    pub live: usize,
    pub missing: Vec<Digest>,
    /// Objects the store held, unreachable objects deleted, and their bytes as stored (where the
    /// backend says).
    pub objects: usize,
    pub deleted: Vec<Digest>,
    pub deleted_bytes: u64,
    /// The cache cap: objects evicted (the shared store holds them), and what the store keeps.
    pub evicted: Vec<Digest>,
    pub evicted_bytes: u64,
    pub kept_bytes: Option<u64>,
    /// Over its cap after evicting all it could: the rest only the local store holds.
    pub over_cap: bool,
}

/// The store, held for a collection (its `l/gc` lock), unless a push holds it.
struct Held<'a> {
    cas: &'a Cas,
    plan: &'a Plan<'a>,
    /// None on a dry run.
    since: Option<i64>,
    ops: usize,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if self.since.is_some() {
            let _ = self.cas.inner.delete(GC_LOCK);
        }
    }
}

impl<'a> Held<'a> {
    /// Takes the store's lock, then gives up if a live push holds it (stale push locks are
    /// removed). Err(why) if the store is held.
    fn take(cas: &'a Cas, plan: &'a Plan<'a>) -> io::Result<std::result::Result<Held<'a>, String>> {
        if plan.dry_run {
            return Ok(Ok(Held { cas, plan, since: None, ops: 0 }));
        }
        let now = (plan.now)();
        if !put_lock(cas, GC_LOCK, plan.by, now)? {
            match read_lock(cas, GC_LOCK)? {
                Some((by, at)) if at == i64::MAX || now - at < GC_STALE_SECS => {
                    return Ok(Err(format!("a collection by {by} is under way")));
                }
                _ => {
                    cas.inner.delete(GC_LOCK)?;
                    if !put_lock(cas, GC_LOCK, plan.by, now)? {
                        return Ok(Err("another collection took the store".into()));
                    }
                }
            }
        }
        let mut h = Held { cas, plan, since: Some(now), ops: 0 };
        if let Some(why) = h.pushing()? {
            return Ok(Err(why));
        }
        Ok(Ok(h))
    }

    /// A live push holding the store, if any (renewing this collection's lock first when it is
    /// due, then looking: the renewal is a write before the read, like taking it).
    fn pushing(&mut self) -> io::Result<Option<String>> {
        let Some(since) = self.since else { return Ok(None) };
        let now = (self.plan.now)();
        if now - since >= GC_RENEW_SECS {
            self.cas.inner.delete(GC_LOCK)?;
            if !put_lock(self.cas, GC_LOCK, self.plan.by, now)? {
                self.since = None;
                return Ok(Some("another collection took the store".into()));
            }
            self.since = Some(now);
        }
        for key in self.cas.inner.list_prefix(PUSH_LOCKS)? {
            match read_lock(self.cas, &key)? {
                Some((by, at)) if at == i64::MAX || now - at < PUSH_STALE_SECS => return Ok(Some(format!("a push by {by} is under way"))),
                Some(_) => self.cas.inner.delete(&key)?,
                None => {}
            }
        }
        Ok(None)
    }

    /// Counts one object read or deleted; every [`CHECK_EVERY`], looks for a push.
    fn tick(&mut self) -> io::Result<Option<String>> {
        self.ops += 1;
        if self.ops.is_multiple_of(CHECK_EVERY) {
            return self.pushing();
        }
        Ok(None)
    }
}

/// Whether object `d` is a tree, by its first bytes, or None if the store doesn't have it. An
/// object whose start can't be read counts as not a tree (it is deleted last).
fn is_tree(cas: &Cas, d: &Digest) -> io::Result<Option<bool>> {
    let Some(r) = cas.inner.get_head(&d.key(), PEEK)? else { return Ok(None) };
    let mut head = Vec::with_capacity(TREE_HEADER.len());
    let ok = zstd::stream::read::Decoder::new(r).and_then(|z| z.take(TREE_HEADER.len() as u64).read_to_end(&mut head));
    Ok(Some(ok.is_ok() && head == TREE_HEADER))
}

/// The objects a tree names, by kind.
fn children(t: &Tree) -> impl Iterator<Item = (Digest, bool)> + '_ {
    t.entries().iter().map(|e| (e.digest, e.kind == Kind::Dir))
}

impl Cas {
    /// Collects garbage (see the module's notes): drops the refs `plan` says to, marks what the
    /// roots and the remaining refs reach, deletes every other object, trees first, then (with a
    /// cap) evicts what the shared store holds, least recently used first.
    pub fn collect(&self, plan: &Plan) -> io::Result<Report> {
        let mut rep = Report::default();
        let mut held = match Held::take(self, plan)? {
            Ok(h) => h,
            Err(why) => {
                rep.busy = Some(why);
                return Ok(rep);
            }
        };
        // Refs: drop what nothing names, keep the rest as roots.
        let mut roots: Vec<Digest> = plan.roots.clone();
        for name in self.refs("")? {
            let target = match self.get_ref(&name) {
                Ok(Some(d)) => d,
                // Gone meanwhile, or not a digest: nothing to mark.
                _ => continue,
            };
            if (plan.drop_ref)(&name, &target) {
                if !plan.dry_run {
                    self.delete_ref(&name)?;
                }
                rep.refs_dropped.push(name);
            } else {
                rep.refs += 1;
                roots.push(target);
            }
        }
        // What the store holds, and (for the cap) each object's size and last use, read before the
        // mark reads anything (a read renews an object's use).
        let present: BTreeSet<Digest> = self.objects()?.into_iter().collect();
        rep.objects = present.len();
        let mut stat = HashMap::new();
        if plan.cap.is_some() {
            for d in &present {
                if let Some(s) = self.inner.stat(&d.key())? {
                    stat.insert(*d, s);
                }
            }
        }
        // Mark. A root's kind isn't known: it is a tree if it reads as one.
        let mut live: BTreeSet<Digest> = BTreeSet::new();
        let mut edges: HashMap<Digest, Vec<Digest>> = HashMap::new();
        let mut todo: Vec<(Digest, Option<bool>)> = roots.into_iter().map(|d| (d, None)).collect();
        while let Some((d, tree)) = todo.pop() {
            if !live.insert(d) {
                continue;
            }
            if !present.contains(&d) {
                rep.missing.push(d);
                continue;
            }
            let tree = match tree {
                Some(t) => Some(t),
                None => is_tree(self, &d)?,
            };
            match tree {
                None => rep.missing.push(d),
                Some(false) => {}
                Some(true) => match self.get_tree(&d)? {
                    None => rep.missing.push(d),
                    Some(t) => {
                        let kids: Vec<(Digest, bool)> = children(&t).collect();
                        edges.insert(d, kids.iter().map(|(c, _)| *c).collect());
                        todo.extend(kids.into_iter().map(|(c, t)| (c, Some(t))));
                    }
                },
            }
            if let Some(why) = held.tick()? {
                rep.stopped = Some(why);
                return Ok(rep);
            }
        }
        rep.live = live.len() - rep.missing.len();
        // Sweep: every object nothing live reaches. Trees first, each before the trees it names,
        // then everything else.
        let garbage: Vec<Digest> = present.iter().copied().filter(|d| !live.contains(d)).collect();
        let mut trees: BTreeMap<Digest, Vec<Digest>> = BTreeMap::new();
        let mut rest = vec![];
        for d in &garbage {
            match is_tree(self, d)? {
                Some(true) => {
                    let kids = match self.get_bytes(d, TREE_MAX).ok().flatten().and_then(|b| Tree::decode(&b).ok()) {
                        Some(t) => children(&t).filter(|(_, t)| *t).map(|(c, _)| c).collect(),
                        None => vec![],
                    };
                    trees.insert(*d, kids);
                }
                Some(false) => rest.push(*d),
                None => {}
            }
            if let Some(why) = held.tick()? {
                rep.stopped = Some(why);
                return Ok(rep);
            }
        }
        let order = parents_first(&trees).into_iter().chain(rest);
        for d in order {
            let len = self.inner.stat(&d.key())?.map(|s| s.len);
            if !plan.dry_run {
                self.delete(&d)?;
            }
            rep.deleted_bytes += len.unwrap_or(0);
            rep.deleted.push(d);
            if let Some(why) = held.tick()? {
                rep.stopped = Some(why);
                return Ok(rep);
            }
        }
        // The cache cap, over what is left (all of it live).
        if let Some((shared, cap)) = plan.cap {
            self.evict(&mut held, &mut rep, &live, &edges, &stat, shared, cap)?;
        }
        Ok(rep)
    }

    /// Every object the store holds.
    pub fn objects(&self) -> io::Result<Vec<Digest>> {
        Ok(self
            .inner
            .list_prefix(super::OBJECTS)?
            .iter()
            .filter_map(|k| k.strip_prefix(super::OBJECTS))
            .filter_map(|h| Digest::parse(&format!("sha256:{h}")))
            .collect())
    }

    fn evict(
        &self,
        held: &mut Held,
        rep: &mut Report,
        live: &BTreeSet<Digest>,
        edges: &HashMap<Digest, Vec<Digest>>,
        all: &HashMap<Digest, crate::objects::Stat>,
        shared: &Cas,
        cap: u64,
    ) -> io::Result<()> {
        let stat: HashMap<Digest, crate::objects::Stat> = all.iter().filter(|(d, _)| live.contains(d)).map(|(d, s)| (*d, *s)).collect();
        let mut total: u64 = stat.values().map(|s| s.len).sum();
        // Parents still here, for each object: one is evicted only once none is.
        let mut parents: HashMap<Digest, usize> = HashMap::new();
        for (p, kids) in edges {
            if stat.contains_key(p) {
                for k in kids {
                    *parents.entry(*k).or_default() += 1;
                }
            }
        }
        let mut heap: BinaryHeap<Reverse<(i64, Digest)>> =
            stat.iter().filter(|(d, _)| !parents.contains_key(d)).map(|(d, s)| Reverse((s.used, *d))).collect();
        while total > cap {
            let Some(Reverse((_, d))) = heap.pop() else { break };
            if !shared.has(&d)? {
                continue;
            }
            if !held.plan.dry_run {
                self.delete(&d)?;
            }
            let len = stat[&d].len;
            total -= len;
            rep.evicted_bytes += len;
            rep.evicted.push(d);
            for k in edges.get(&d).into_iter().flatten() {
                if let Some(n) = parents.get_mut(k) {
                    *n -= 1;
                    if *n == 0 {
                        parents.remove(k);
                        if let Some(s) = stat.get(k) {
                            heap.push(Reverse((s.used, *k)));
                        }
                    }
                }
            }
            if let Some(why) = held.tick()? {
                rep.stopped = Some(why);
                break;
            }
        }
        rep.kept_bytes = Some(total);
        rep.over_cap = total > cap && rep.stopped.is_none();
        Ok(())
    }
}

/// Garbage trees in an order that deletes each before any tree it names (edges to trees that
/// aren't garbage are ignored).
fn parents_first(trees: &BTreeMap<Digest, Vec<Digest>>) -> Vec<Digest> {
    let mut parents: BTreeMap<Digest, usize> = trees.keys().map(|d| (*d, 0)).collect();
    for kids in trees.values() {
        for k in kids {
            if let Some(n) = parents.get_mut(k) {
                *n += 1;
            }
        }
    }
    let mut ready: Vec<Digest> = parents.iter().filter(|(_, n)| **n == 0).map(|(d, _)| *d).collect();
    let mut out = vec![];
    while let Some(d) = ready.pop() {
        out.push(d);
        for k in &trees[&d] {
            if let Some(n) = parents.get_mut(k) {
                *n -= 1;
                if *n == 0 {
                    ready.push(*k);
                }
            }
        }
    }
    out
}
