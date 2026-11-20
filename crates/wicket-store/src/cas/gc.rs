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
        self.begin_writing_as(&wicket_core::new_ulid().to_string().to_ascii_lowercase(), by, now)
    }

    /// [`Cas::begin_writing`] with the lock's id given: a ULID in use, so locks list in the order
    /// they were taken; a fixed one in tests, so a collection reads them in the same order each run.
    fn begin_writing_as(&self, id: &str, by: &str, now: i64) -> io::Result<Writing<'_>> {
        let key = format!("{PUSH_LOCKS}{id}");
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
    /// The digests the ledger holds (every agent's head that is a digest), read once the store is
    /// held, so a push committed just before is seen.
    pub roots: &'a dyn Fn() -> io::Result<Vec<Digest>>,
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
        let mut roots: Vec<Digest> = (plan.roots)()?;
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

    #[allow(clippy::too_many_arguments)]
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

#[cfg(test)]
mod tests {
    //! Property tests (#258): a collection runs with pushes interleaved at every operation it makes
    //! on its backend, in an order drawn from a seed. Checked at each step: everything a committed
    //! head, a kept ref or a push in flight reaches is still stored, and every tree stored has
    //! everything under it.
    use super::*;
    use crate::cas::Entry;
    use crate::objects::{DirStore, ObjectStore, Stat};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    fn root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-gc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    type Hook = Arc<Mutex<Option<Box<dyn FnMut() + Send>>>>;

    /// A directory store that runs a hook before each operation: the pushes' turn.
    struct Hooked {
        inner: DirStore,
        hook: Hook,
        running: Arc<AtomicBool>,
    }

    impl Hooked {
        fn turn(&self) {
            if self.running.swap(true, Ordering::SeqCst) {
                return;
            }
            let mut h = self.hook.lock().unwrap().take();
            if let Some(f) = h.as_mut() {
                f();
            }
            *self.hook.lock().unwrap() = h;
            self.running.store(false, Ordering::SeqCst);
        }
    }

    impl ObjectStore for Hooked {
        fn put_if_absent(&self, key: &str, data: &mut dyn Read) -> io::Result<bool> {
            self.turn();
            self.inner.put_if_absent(key, data)
        }
        fn get(&self, key: &str) -> io::Result<Option<Box<dyn Read + Send>>> {
            self.turn();
            self.inner.get(key)
        }
        fn has(&self, key: &str) -> io::Result<bool> {
            self.turn();
            self.inner.has(key)
        }
        fn delete(&self, key: &str) -> io::Result<()> {
            self.turn();
            self.inner.delete(key)
        }
        fn list_prefix(&self, prefix: &str) -> io::Result<Vec<String>> {
            self.turn();
            self.inner.list_prefix(prefix)
        }
        fn stat(&self, key: &str) -> io::Result<Option<Stat>> {
            self.inner.stat(key)
        }
    }

    /// A push in flight, as `bundle::push_tree` and `hibernate::push` make one: its lock, the
    /// subtrees, the bundle tree, its ref, then the ledger's head, then the lock let go.
    struct Push {
        agent: String,
        seq: i64,
        stage: u8,
        lock: Option<Writing<'static>>,
        written: Vec<Digest>,
        bundle: Option<Digest>,
    }

    struct World {
        rng: Rng,
        now: i64,
        heads: BTreeMap<String, (i64, Digest)>,
        pushes: Vec<Push>,
        violations: Vec<String>,
        /// Pushes that don't wait for a collection (to show the check finds what that breaks).
        careless: bool,
        turns: u64,
        /// Push locks taken so far (their names).
        locks: u64,
    }

    const CONTENTS: [&[u8]; 6] = [b"a", b"bb", b"ccc", b"dddd", b"eeeee", b"ffffff"];

    fn file(cas: &Cas, rng: &mut Rng, name: &str) -> Entry {
        let b = CONTENTS[rng.below(CONTENTS.len() as u64) as usize];
        let digest = cas.put_bytes(b).unwrap();
        Entry { name: name.into(), kind: Kind::File, mode: 0o644, mtime: 0, size: b.len() as u64, digest }
    }

    fn dir(cas: &Cas, rng: &mut Rng, depth: u32) -> Digest {
        let mut es = vec![];
        for i in 0..1 + rng.below(3) {
            es.push(file(cas, rng, &format!("f{i}")));
        }
        if depth > 0 {
            for i in 0..rng.below(3) {
                let digest = dir(cas, rng, depth - 1);
                es.push(Entry { name: format!("d{i}"), kind: Kind::Dir, mode: 0o755, mtime: 0, size: 0, digest });
            }
        }
        cas.put_tree(&Tree::new(es).unwrap()).unwrap()
    }

    /// Whether everything `d` reaches is stored (`tree`: what it is, if known).
    fn whole(cas: &Cas, d: &Digest, tree: bool) -> bool {
        if !tree {
            return cas.inner.has(&d.key()).unwrap();
        }
        match cas.get_tree(d) {
            Ok(Some(t)) => t.entries().iter().all(|e| whole(cas, &e.digest, e.kind == Kind::Dir)),
            _ => false,
        }
    }

    impl World {
        /// One step of one push, maybe a new push first.
        fn step(&mut self, cas: &'static Cas) {
            self.now += 1;
            if self.pushes.len() < 2 && self.rng.below(3) == 0 {
                let agent = ["a", "b", "c"][self.rng.below(3) as usize].to_string();
                if !self.pushes.iter().any(|p| p.agent == agent) {
                    let seq = self.heads.get(&agent).map_or(1, |h| h.0 + 1);
                    self.pushes.push(Push { agent, seq, stage: 0, lock: None, written: vec![], bundle: None });
                }
            }
            if self.pushes.is_empty() {
                return;
            }
            let i = self.rng.below(self.pushes.len() as u64) as usize;
            let now = self.now;
            let careless = self.careless;
            // A push lock is named in the order taken, as a ULID would be, but the same each run:
            // a collection reads the locks in name order, and each read is a turn (#663).
            let lock_id = (self.pushes[i].stage == 0).then(|| {
                self.locks += 1;
                format!("{:020}", self.locks)
            });
            let p = &mut self.pushes[i];
            match p.stage {
                0 => {
                    let id = lock_id.expect("a lock id for a push's first step");
                    p.lock = Some(cas.begin_writing_as(&id, &format!("push {}", p.agent), now).unwrap());
                    p.stage = 1;
                }
                1 => {
                    if careless || p.lock.as_ref().unwrap().ready(now).unwrap() {
                        p.stage = 2;
                    }
                }
                2 => {
                    let d = dir(cas, &mut self.rng, 2);
                    p.written.push(d);
                    if self.rng.below(2) == 0 {
                        p.stage = 3;
                    }
                }
                3 => {
                    let es = p
                        .written
                        .iter()
                        .enumerate()
                        .map(|(k, d)| Entry { name: format!("t{k}"), kind: Kind::Dir, mode: 0o755, mtime: 0, size: 0, digest: *d })
                        .collect();
                    p.bundle = Some(cas.put_tree(&Tree::new(es).unwrap()).unwrap());
                    p.stage = 4;
                }
                4 => {
                    cas.set_ref(&format!("agents/{}/{}.1", p.agent, p.seq), p.bundle.as_ref().unwrap()).unwrap();
                    p.stage = 5;
                }
                5 => {
                    self.heads.insert(p.agent.clone(), (p.seq, p.bundle.unwrap()));
                    p.stage = 6;
                }
                _ => {
                    self.pushes.remove(i);
                }
            }
        }

        /// `full`: also every tree the store holds (slow).
        fn check(&mut self, cas: &Cas, when: &str, full: bool) {
            for (a, (_, h)) in &self.heads {
                if !whole(cas, h, true) {
                    self.violations.push(format!("{when}: agent {a}'s head {h} lost an object"));
                }
            }
            for p in &self.pushes {
                for d in p.written.iter().chain(p.bundle.iter()) {
                    if !whole(cas, d, true) {
                        self.violations.push(format!("{when}: agent {a}'s push in flight lost an object of {d}", a = p.agent));
                    }
                }
            }
            for d in cas.objects().unwrap().into_iter().filter(|_| full) {
                if is_tree(cas, &d).unwrap() == Some(true) && !whole(cas, &d, true) {
                    self.violations.push(format!("{when}: tree {d} is stored without all it names"));
                }
            }
        }
    }

    /// Runs `rounds` collections of one store, with pushes interleaved from `seed`; returns the
    /// violations, and what the collections deleted.
    fn run(seed: u64, careless: bool, rounds: usize) -> (Vec<String>, usize) {
        let dirp = root(&format!("prop-{seed}-{careless}"));
        let hook: Hook = Arc::default();
        let gc_cas = Cas::new(Hooked { inner: DirStore::new(&dirp), hook: hook.clone(), running: Arc::default() });
        let push_cas: &'static Cas = Box::leak(Box::new(Cas::new(DirStore::new(&dirp))));
        let world = Arc::new(Mutex::new(World {
            rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
            now: 1_000_000,
            heads: BTreeMap::new(),
            pushes: vec![],
            violations: vec![],
            careless,
            turns: 0,
            locks: 0,
        }));
        {
            let w = world.clone();
            *hook.lock().unwrap() = Some(Box::new(move || {
                let mut w = w.lock().unwrap();
                for _ in 0..w.rng.below(3) {
                    w.step(push_cas);
                }
                w.turns += 1;
                let full = w.turns.is_multiple_of(8);
                w.check(push_cas, "during a collection", full);
            }));
        }
        let mut deleted = 0;
        for _ in 0..rounds {
            let n = world.lock().unwrap().rng.below(20);
            for _ in 0..n {
                world.lock().unwrap().step(push_cas);
            }
            let w2 = world.clone();
            let roots = move || Ok(w2.lock().unwrap().heads.values().map(|h| h.1).collect());
            let w3 = world.clone();
            let drop_ref = move |name: &str, target: &Digest| {
                let w = w3.lock().unwrap();
                let Some((agent, rest)) = name.strip_prefix("agents/").and_then(|r| r.split_once('/')) else { return false };
                let seq: i64 = rest.split('.').next().and_then(|s| s.parse().ok()).unwrap_or(i64::MAX);
                w.heads.get(agent).is_some_and(|(hs, hd)| hd != target && seq <= *hs)
            };
            let w4 = world.clone();
            let now = move || w4.lock().unwrap().now;
            let plan = Plan { roots: &roots, drop_ref: &drop_ref, dry_run: false, by: "test", cap: None, now: &now };
            let rep = gc_cas.collect(&plan).unwrap();
            deleted += rep.deleted.len();
            world.lock().unwrap().check(push_cas, "after a collection", true);
        }
        *hook.lock().unwrap() = None;
        let v = world.lock().unwrap().violations.clone();
        let _ = std::fs::remove_dir_all(&dirp);
        (v, deleted)
    }

    /// Seeds per test (more with `WICKET_GC_SEEDS`).
    fn seeds() -> u64 {
        std::env::var("WICKET_GC_SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(30)
    }

    /// Part `part` of [`PARTS`] of the seeds: every `PARTS`th from `part + 1`, so the parts
    /// together run each seed once, and nextest runs them at once (one test of them all was among
    /// the tests job's slowest).
    fn no_reachable_object_is_deleted(part: u64) {
        let (mut deleted, mut ran) = (0, 0);
        for seed in (1..=seeds()).filter(|s| (s - 1) % PARTS == part) {
            let (v, d) = run(seed, false, 5);
            assert!(v.is_empty(), "seed {seed}: {v:#?}");
            deleted += d;
            ran += 1;
        }
        assert!(deleted > ran, "the collections deleted only {deleted} objects: the property isn't exercised");
    }

    const PARTS: u64 = 3;

    #[test]
    fn no_reachable_object_is_deleted_whatever_the_pushes_do_0() {
        no_reachable_object_is_deleted(0);
    }

    #[test]
    fn no_reachable_object_is_deleted_whatever_the_pushes_do_1() {
        no_reachable_object_is_deleted(1);
    }

    #[test]
    fn no_reachable_object_is_deleted_whatever_the_pushes_do_2() {
        no_reachable_object_is_deleted(2);
    }

    /// The same, with pushes that don't wait for a collection under way: the check finds what that
    /// breaks, so the property above means something. One seed that breaks is the proof: the
    /// seeds after it aren't run.
    #[test]
    fn a_push_that_ignores_the_collection_loses_objects() {
        assert!((1..=seeds()).any(|s| !run(s, true, 5).0.is_empty()), "no seed lost an object without the push lock");
    }

    fn plan_for<'a>(
        roots: &'a dyn Fn() -> io::Result<Vec<Digest>>,
        drop: &'a dyn Fn(&str, &Digest) -> bool,
        now: &'a dyn Fn() -> i64,
    ) -> Plan<'a> {
        Plan { roots, drop_ref: drop, dry_run: false, by: "test", cap: None, now }
    }

    #[test]
    fn a_collection_keeps_roots_and_refs_and_a_dry_run_deletes_nothing() {
        let d = root("basic");
        let cas = Cas::new(DirStore::new(&d));
        let mut rng = Rng(7);
        let head = dir(&cas, &mut rng, 2);
        let snap = cas.put_bytes(b"ledger snapshot").unwrap();
        cas.set_ref("ledger-snapshots/x.db", &snap).unwrap();
        let old = cas.put_bytes(b"an old bundle's file").unwrap();
        let old_tree = cas
            .put_tree(&Tree::new(vec![Entry { name: "f".into(), kind: Kind::File, mode: 0o644, mtime: 0, size: 20, digest: old }]).unwrap())
            .unwrap();
        cas.set_ref("agents/a/1.1", &old_tree).unwrap();
        let orphan = cas.put_bytes(b"a crashed push's file").unwrap();
        let roots = || Ok(vec![head]);
        let drop = |n: &str, _: &Digest| n == "agents/a/1.1";
        let now = || 1;
        let dry = Plan { dry_run: true, ..plan_for(&roots, &drop, &now) };
        let r = cas.collect(&dry).unwrap();
        assert_eq!(r.refs_dropped, vec!["agents/a/1.1".to_string()]);
        let mut got: Vec<Digest> = r.deleted.clone();
        got.sort();
        let mut want = vec![old, old_tree, orphan];
        want.sort();
        assert_eq!(got, want);
        assert!(
            r.deleted.iter().position(|x| *x == old_tree) < r.deleted.iter().position(|x| *x == old),
            "a tree goes before what it names"
        );
        assert!(cas.has(&orphan).unwrap() && cas.get_ref("agents/a/1.1").unwrap().is_some(), "a dry run deletes nothing");
        let r = cas.collect(&plan_for(&roots, &drop, &now)).unwrap();
        assert_eq!(r.deleted.len(), 3);
        assert!(!cas.has(&orphan).unwrap() && !cas.has(&old).unwrap() && cas.get_ref("agents/a/1.1").unwrap().is_none());
        assert!(whole(&cas, &head, true) && cas.has(&snap).unwrap());
        assert_eq!(cas.collect(&plan_for(&roots, &drop, &now)).unwrap().deleted.len(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_collection_waits_for_a_push_and_a_push_for_a_collection() {
        let d = root("locks");
        let cas = Cas::new(DirStore::new(&d));
        cas.put_bytes(b"garbage").unwrap();
        let roots = || Ok(vec![]);
        let drop = |_: &str, _: &Digest| false;
        let t = std::cell::Cell::new(1000);
        let now = || t.get();
        let w = cas.begin_writing("push a", 1000).unwrap();
        let r = cas.collect(&plan_for(&roots, &drop, &now)).unwrap();
        assert_eq!(r.busy.as_deref(), Some("a push by push a is under way"));
        assert_eq!(cas.objects().unwrap().len(), 1);
        // A push's lock that outlived its push is stale after six hours.
        t.set(1000 + PUSH_STALE_SECS);
        std::mem::forget(w);
        let r = cas.collect(&plan_for(&roots, &drop, &now)).unwrap();
        assert!(r.busy.is_none(), "{r:?}");
        assert_eq!(r.deleted.len(), 1);
        assert!(cas.backend().list_prefix(PUSH_LOCKS).unwrap().is_empty(), "the stale lock is removed");
        // A collection's lock holds pushes back until it is let go, or goes stale.
        assert!(put_lock(&cas, GC_LOCK, "gc", 5000).unwrap());
        let w = cas.begin_writing("push b", 5000).unwrap();
        assert!(!w.ready(5000).unwrap());
        assert!(w.ready(5000 + GC_STALE_SECS).unwrap());
        assert_eq!(cas.collect(&plan_for(&roots, &drop, &|| 5001)).unwrap().busy.as_deref(), Some("a collection by gc is under way"));
        drop_lock(&cas);
        assert!(w.ready(5001).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    fn drop_lock(cas: &Cas) {
        cas.backend().delete(GC_LOCK).unwrap();
    }

    #[test]
    fn the_cap_evicts_only_what_the_shared_store_holds_least_recently_used_first() {
        let (dl, ds) = (root("cap-local"), root("cap-shared"));
        let local = Cas::new(DirStore::new(&dl));
        let shared = Cas::new(DirStore::new(&ds));
        let big = |b: u8| vec![b; 4096];
        let f = |cas: &Cas, b: u8, name: &str| {
            let bytes = big(b);
            Entry { name: name.into(), kind: Kind::File, mode: 0o644, mtime: 0, size: 4096, digest: cas.put_bytes(&bytes).unwrap() }
        };
        // Two bundles, both in the shared store; a third only here.
        let t1 = local.put_tree(&Tree::new(vec![f(&local, 1, "x"), f(&local, 2, "y")]).unwrap()).unwrap();
        let t2 = local.put_tree(&Tree::new(vec![f(&local, 3, "x")]).unwrap()).unwrap();
        local.send_tree(&shared, &t1).unwrap();
        local.send_tree(&shared, &t2).unwrap();
        let t3 = local.put_tree(&Tree::new(vec![f(&local, 4, "x")]).unwrap()).unwrap();
        // t2 used most recently.
        let age = |d: &Digest, at: i64| {
            let p = dl.join(d.key());
            let f = std::fs::File::options().write(true).open(p).unwrap();
            f.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(at as u64)).unwrap();
        };
        for d in local.objects().unwrap() {
            age(&d, 100);
        }
        age(&t2, 200);
        let roots = || Ok(vec![t1, t2, t3]);
        let drop = |_: &str, _: &Digest| false;
        let now = || 1;
        let plan = Plan { cap: Some((&shared, 1)), ..plan_for(&roots, &drop, &now) };
        let r = local.collect(&plan).unwrap();
        assert!(r.deleted.is_empty());
        // Everything the shared store holds goes; t3 and its file stay (only here), and t1 went before t2.
        assert!(local.has(&t3).unwrap() && whole(&local, &t3, true));
        assert!(!local.has(&t1).unwrap() && !local.has(&t2).unwrap());
        assert!(r.over_cap);
        let pos = |d: &Digest| r.evicted.iter().position(|x| x == d).unwrap();
        assert!(pos(&t1) < pos(&t2), "least recently used first: {:?}", r.evicted);
        for d in local.objects().unwrap() {
            if is_tree(&local, &d).unwrap() == Some(true) {
                assert!(whole(&local, &d, true), "a tree kept keeps all under it");
            }
        }
        let _ = std::fs::remove_dir_all(&dl);
        let _ = std::fs::remove_dir_all(&ds);
    }
}
