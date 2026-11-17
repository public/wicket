//! Agent state bundles (#70): a hibernated agent's writable trees.
//!
//! **Version 2** (#365, store.md's step 3), what is pushed now: a *bundle tree* in the
//! content-addressed store ([`crate::cas`]). Its entries are the trees (`workspace`, `state`, `tmp`,
//! `volume.<name>`) as directories, each the tree [`Cas::put_dir`] makes of it, and `meta`, a JSON
//! blob (agent, generation, seq, session, and each tree's counts). Files are objects of their own,
//! so a hibernation writes only the files that changed since any earlier one ([`push_tree`]). With a
//! shared store (the state store) the bundle is sent there by negotiation before the ledger's head
//! moves, and a wake fetches what the local store lacks ([`read_head`], [`restore`]). The ledger's
//! head is the bundle tree's digest (`sha256:…`); a write-once ref `agents/<agent>/<seq>.<generation>`
//! names it too, so a push still can't take another push's place.
//!
//! A tree holds directories, regular files and symlinks (stored as links, never followed), with
//! their permission bits and modification times. Sockets, FIFOs and devices are skipped: they mean
//! nothing without the processes that made them. A name that isn't UTF-8 can't be held, and such a
//! tree isn't hibernated ([`unrepresentable`], #258).
//!
//! **Version 1** (one tar + zstd blob per tree and a JSON manifest, before #365) is gone (#258): the
//! control host converted every version-1 head to a bundle tree before this build, and refuses to
//! start while one remains.
//!
//! Not yet: encryption with the agent's data key and a signed manifest (design §13.5).

use crate::cas::{Cas, Digest as CasDigest, DirOpts, Entry as CasEntry, Kind as CasKind, Tree};
use serde::{Deserialize, Serialize};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, BundleError>;

/// One tree of a bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// `workspace`, `state`, `tmp` or `volume.<name>`.
    pub name: String,
    pub digest: String,
    /// The blob's object key (`a/<agent>/p/<sha256 of the blob>`).
    pub blob: String,
    pub files: u64,
    pub raw_bytes: u64,
    pub stored_bytes: u64,
}

/// What a hibernated agent's state is: the head the ledger points at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateManifest {
    pub version: u32,
    pub agent: String,
    pub generation: i64,
    pub seq: i64,
    pub created_at: i64,
    pub session_id: String,
    pub trees: Vec<TreeEntry>,
    /// Version 2: the bundle tree's digest (`sha256:…`). A version-2 tree's `digest` is its
    /// directory's tree digest, its `blob` is empty, and its `stored_bytes` are what this push wrote
    /// for it (the incremental cost: shared with earlier bundles, the rest isn't counted again).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

impl StateManifest {
    pub fn tree(&self, name: &str) -> Option<&TreeEntry> {
        self.trees.iter().find(|t| t.name == name)
    }
    pub fn stored_bytes(&self) -> u64 {
        self.trees.iter().map(|t| t.stored_bytes).sum()
    }
    pub fn raw_bytes(&self) -> u64 {
        self.trees.iter().map(|t| t.raw_bytes).sum()
    }
}

/// Whose bundle a push writes: the agent, the generation pushing it, its sequence number, and the
/// agent's session.
#[derive(Clone, Copy)]
pub struct PushTo<'a> {
    pub agent: &'a str,
    pub generation: i64,
    pub seq: i64,
    pub session_id: &'a str,
}

/// A tree to push: its name, where it is, and top-level names to leave out.
pub struct TreeSrc<'a> {
    pub name: String,
    pub path: PathBuf,
    pub exclude: &'a [&'a str],
}

// ---- version 2: bundle trees in the content-addressed store (#365) ----

/// The version of bundle trees.
pub const TREE_VERSION: u32 = 2;

/// The bundle tree's entry that isn't a tree: its `meta` blob.
const META: &str = "meta";
/// The most a `meta` blob may be.
const META_MAX: u64 = 1 << 20;

/// Where version-2 bundles live: the host's local store, and the shared store (the state store) a
/// bundle must reach before the ledger's head moves, if there is one. `written` counts what the
/// local store's backend writes ([`crate::objects::Counting`]), for the push's cost without a shared
/// store.
#[derive(Clone, Copy)]
pub struct Stores<'a> {
    pub local: &'a Cas,
    pub shared: Option<&'a Cas>,
    pub written: Option<&'a std::sync::atomic::AtomicU64>,
}

impl Stores<'_> {
    /// The store a bundle's head ref is written to: where it has to be for a wake.
    fn home(&self) -> &Cas {
        self.shared.unwrap_or(self.local)
    }

    fn written(&self) -> u64 {
        self.written.map(|w| w.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0)
    }

    /// Makes sure the local store holds tree `d` and everything under it, fetching what it lacks
    /// from the shared store.
    fn fetch(&self, d: &CasDigest) -> Result<()> {
        if let Some(sh) = self.shared {
            if !self.local.has(d)? {
                sh.send_tree(self.local, d)?;
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Meta {
    version: u32,
    agent: String,
    generation: i64,
    seq: i64,
    created_at: i64,
    session_id: String,
    trees: Vec<MetaTree>,
}

#[derive(Serialize, Deserialize)]
struct MetaTree {
    name: String,
    files: u64,
    raw_bytes: u64,
    stored_bytes: u64,
}

/// The write-once ref naming a version-2 bundle (its sequence number and the generation that wrote it).
pub fn bundle_ref(agent: &str, seq: i64, generation: i64) -> String {
    format!("agents/{agent}/{seq}.{generation}")
}

/// Whether a head the ledger holds is a version-2 bundle (a digest), not a version-1 manifest key.
pub fn is_tree_head(head: &str) -> bool {
    CasDigest::parse(head).is_some()
}

/// Whether a push failed because a tree holds what the version-2 format can't (a name that isn't
/// UTF-8): the caller keeps such an agent's state as a version-1 bundle instead.
pub fn unrepresentable(e: &BundleError) -> bool {
    matches!(e, BundleError::Io(io) if io.kind() == io::ErrorKind::InvalidData && io.to_string().contains("isn't a UTF-8 name"))
}

/// The files and symlinks under `root` (not following links, without `exclude`'s top-level names,
/// sockets, FIFOs or devices), and their bytes: the counts a bundle's `meta` records.
fn counts(root: &Path, exclude: &[&str]) -> io::Result<(u64, u64)> {
    fn rec(dir: &Path, exclude: &[&str], n: &mut (u64, u64)) -> io::Result<()> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            if exclude.iter().any(|x| e.file_name() == **x) {
                continue;
            }
            let meta = std::fs::symlink_metadata(e.path())?;
            let ft = meta.file_type();
            if ft.is_dir() {
                rec(&e.path(), &[], n)?;
            } else if ft.is_file() || ft.is_symlink() {
                n.0 += 1;
                n.1 += meta.len();
            }
        }
        Ok(())
    }
    let mut n = (0, 0);
    rec(root, exclude, &mut n)?;
    Ok(n)
}

/// Pushes trees as a version-2 bundle: each into the local store (only files and directories not
/// already there are written), then, with a shared store, everything it lacks of them, then the
/// `meta` blob and the bundle tree, and last the write-once ref. Returns the manifest and the head
/// (the bundle tree's digest); the caller commits the head in the ledger, which is the commit point.
pub fn push_tree(stores: Stores, to: &PushTo, trees: &[TreeSrc]) -> Result<(StateManifest, String)> {
    let PushTo { agent, generation, seq, session_id } = *to;
    let mut entries = Vec::new();
    let mut stats = Vec::new();
    for t in trees {
        let before = stores.written();
        let d = stores.local.put_dir(&t.path, &DirOpts { exclude: t.exclude, plain: false })?;
        let mut stored = stores.written() - before;
        if let Some(sh) = stores.shared {
            stored = stores.local.send_tree(sh, &d)?.0;
        }
        let meta = std::fs::symlink_metadata(&t.path)?;
        let (files, raw) = counts(&t.path, t.exclude)?;
        entries.push(CasEntry {
            name: t.name.clone(),
            kind: CasKind::Dir,
            mode: meta.permissions().mode() & 0o7777,
            mtime: meta.mtime(),
            size: 0,
            digest: d,
        });
        stats.push(MetaTree { name: t.name.clone(), files, raw_bytes: raw, stored_bytes: stored });
    }
    let created_at = crate::now();
    let meta =
        Meta { version: TREE_VERSION, agent: agent.into(), generation, seq, created_at, session_id: session_id.into(), trees: stats };
    let mb = serde_json::to_vec(&meta)?;
    let md = stores.local.put_bytes(&mb)?;
    entries.push(CasEntry { name: META.into(), kind: CasKind::File, mode: 0o600, mtime: 0, size: mb.len() as u64, digest: md });
    let tree = Tree::new(entries)?;
    let bundle = stores.local.put_tree(&tree)?;
    if let Some(sh) = stores.shared {
        stores.local.send_tree(sh, &bundle)?;
    }
    let r = bundle_ref(agent, seq, generation);
    if !stores.home().set_ref(&r, &bundle)? {
        return Err(BundleError::Invalid(format!("state bundle {r} already exists")));
    }
    Ok((manifest_of(meta, &bundle, &tree), bundle.to_string()))
}

/// The manifest a version-2 bundle's `meta` describes (tree digests from `tree`, where it has them).
fn manifest_of(meta: Meta, bundle: &CasDigest, tree: &Tree) -> StateManifest {
    StateManifest {
        version: meta.version,
        agent: meta.agent,
        generation: meta.generation,
        seq: meta.seq,
        created_at: meta.created_at,
        session_id: meta.session_id,
        trees: meta
            .trees
            .into_iter()
            .map(|t| TreeEntry {
                digest: tree.get(&t.name).map(|e| e.digest.to_string()).unwrap_or_default(),
                name: t.name,
                blob: String::new(),
                files: t.files,
                raw_bytes: t.raw_bytes,
                stored_bytes: t.stored_bytes,
            })
            .collect(),
        bundle: Some(bundle.to_string()),
    }
}

/// The bundle tree `d`, from the local store or else the shared one (verified either way).
fn bundle_tree(stores: Stores, d: &CasDigest) -> Result<Tree> {
    if let Some(t) = stores.local.get_tree(d)? {
        return Ok(t);
    }
    match stores.shared {
        Some(sh) => sh.get_tree(d)?.ok_or_else(|| BundleError::Invalid(format!("state bundle {d} is missing"))),
        None => Err(BundleError::Invalid(format!("state bundle {d} is missing"))),
    }
}

/// Reads the head the ledger holds, a bundle tree's digest, from `stores`. Checks it is the agent's,
/// and that its `meta` names exactly its trees. A version-1 head (a manifest key, from before #365)
/// isn't read any more: the control host converts those before this build runs (#258).
pub fn read_head(stores: Stores, head: &str, agent: &str) -> Result<StateManifest> {
    let Some(d) = CasDigest::parse(head) else {
        return Err(BundleError::Invalid(format!("agent {agent}'s head {head:?} is a version-1 bundle, which this build can't read")));
    };
    let t = bundle_tree(stores, &d)?;
    let me =
        t.get(META).filter(|e| e.kind == CasKind::File).ok_or_else(|| BundleError::Invalid(format!("state bundle {d} has no meta")))?;
    let bytes = match stores.local.get_bytes(&me.digest, META_MAX)? {
        Some(b) => b,
        None => stores
            .shared
            .map(|sh| sh.get_bytes(&me.digest, META_MAX))
            .transpose()?
            .flatten()
            .ok_or_else(|| BundleError::Invalid(format!("state bundle {d}'s meta is missing")))?,
    };
    let meta: Meta = serde_json::from_slice(&bytes)?;
    if meta.agent != agent || meta.version != TREE_VERSION {
        return Err(BundleError::Invalid(format!("state bundle {d} is not agent {agent}'s")));
    }
    let mut named: Vec<&str> = meta.trees.iter().map(|t| t.name.as_str()).collect();
    let mut dirs: Vec<&str> = t.entries().iter().filter(|e| e.name != META).map(|e| e.name.as_str()).collect();
    named.sort_unstable();
    dirs.sort_unstable();
    if named != dirs || t.entries().iter().any(|e| e.name != META && e.kind != CasKind::Dir) {
        return Err(BundleError::Invalid(format!("state bundle {d}'s meta doesn't match its trees")));
    }
    Ok(manifest_of(meta, &d, &t))
}

/// Restores tree `name` of a bundle into `dest` (which must not exist yet): checked out of the local
/// store (fetching what it lacks from the shared one), with its root's mode and time. Every object
/// is verified as it is read. On any failure `dest` is removed. A bundle without the tree restores
/// nothing.
pub fn restore(stores: Stores, m: &StateManifest, name: &str, dest: &Path) -> Result<()> {
    if m.tree(name).is_none() {
        return Ok(());
    }
    let Some(b) = m.bundle.as_deref() else {
        return Err(BundleError::Invalid(format!("agent {}'s bundle is version 1, which this build can't read", m.agent)));
    };
    if dest.exists() {
        return Err(BundleError::Invalid(format!("{} already exists", dest.display())));
    }
    let bd = CasDigest::parse(b).ok_or_else(|| BundleError::Invalid(format!("bad bundle digest {b:?}")))?;
    let res = (|| {
        let tree = bundle_tree(stores, &bd)?;
        let e = tree
            .get(name)
            .filter(|e| e.kind == CasKind::Dir)
            .ok_or_else(|| BundleError::Invalid(format!("state bundle {bd} has no tree {name}")))?;
        stores.fetch(&e.digest)?;
        stores.local.checkout(&e.digest, dest)?;
        std::fs::File::open(dest)?
            .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(e.mtime.max(0) as u64))?;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(e.mode))?;
        Ok(())
    })();
    if res.is_err() {
        let _ = make_writable(dest);
        let _ = std::fs::remove_dir_all(dest);
    }
    res
}

/// Makes every directory under `root` writable by its owner, so the tree can be removed.
pub fn make_writable(root: &Path) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(root)?;
    if meta.is_dir() {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode((meta.permissions().mode() & 0o7777) | 0o700))?;
        for e in std::fs::read_dir(root)? {
            make_writable(&e?.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::DirStore;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-bundle-{tag}-{}", std::process::id()));
        let _ = make_writable(&d);
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn rm(d: &Path) {
        let _ = make_writable(d);
        let _ = std::fs::remove_dir_all(d);
    }

    /// A local store that counts what it writes.
    fn counted(root: &Path) -> (Cas, std::sync::Arc<std::sync::atomic::AtomicU64>) {
        let (c, n) = crate::objects::Counting::new(DirStore::new(root));
        (Cas::new(c), n)
    }

    fn sample(src: &Path) {
        std::fs::create_dir_all(src.join("home/.config")).unwrap();
        std::fs::write(src.join("home/.gitconfig"), "[user]\n\tname = a\n").unwrap();
        std::fs::write(src.join("big.bin"), vec![7u8; 256 << 10]).unwrap();
        std::fs::write(src.join("run.sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(src.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();
        std::fs::create_dir_all(src.join("ro")).unwrap();
        std::fs::write(src.join("ro/keep"), "x").unwrap();
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::create_dir_all(src.join("skip")).unwrap();
        std::fs::write(src.join("skip/no"), "left out").unwrap();
        std::fs::set_permissions(src, std::fs::Permissions::from_mode(0o1777)).unwrap();
    }

    fn to(seq: i64) -> PushTo<'static> {
        PushTo { agent: "agt_x", generation: 1, seq, session_id: "s" }
    }

    /// #365: a version-2 bundle round-trips (modes, links, the root's own mode, exclusions), names
    /// its head by digest, and is fenced by its write-once ref.
    #[test]
    fn a_bundle_tree_round_trips_and_is_written_once() {
        let (src, out, root, v1) = (tmp("v2src"), tmp("v2out"), tmp("v2store"), tmp("v2v1"));
        sample(&src);
        let _l = std::os::unix::net::UnixListener::bind(src.join("sock")).unwrap();
        let (local, written) = counted(&root);
        let stores = Stores { local: &local, shared: None, written: Some(&written) };
        let trees = [TreeSrc { name: "tmp".into(), path: src.clone(), exclude: &["skip"] }];
        let (m, head) = push_tree(stores, &to(1), &trees).unwrap();
        assert!(is_tree_head(&head) && m.bundle.as_deref() == Some(head.as_str()));
        assert_eq!((m.version, m.seq, m.generation), (TREE_VERSION, 1, 1));
        let t = m.tree("tmp").unwrap();
        assert_eq!((t.files, t.raw_bytes), (5, 17 + (256 << 10) + 10 + 11 + 1));
        assert!(t.stored_bytes > 0 && t.digest.starts_with("sha256:"));
        assert_eq!(read_head(stores, &head, "agt_x").unwrap(), m);
        assert!(read_head(stores, &head, "agt_y").is_err(), "another agent's bundle");
        restore(stores, &m, "tmp", &out).unwrap();
        assert_eq!(std::fs::read_to_string(out.join("home/.gitconfig")).unwrap(), "[user]\n\tname = a\n");
        assert_eq!(std::fs::read_link(out.join("link")).unwrap(), PathBuf::from("/etc/passwd"));
        assert_eq!(std::fs::metadata(out.join("run.sh")).unwrap().permissions().mode() & 0o7777, 0o755);
        assert_eq!(std::fs::metadata(out.join("ro")).unwrap().permissions().mode() & 0o7777, 0o555);
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777, 0o1777, "the root's own mode");
        assert!(!out.join("sock").exists() && !out.join("skip").exists());
        assert!(restore(stores, &m, "tmp", &out).is_err(), "never over an existing tree");
        // A tree the bundle doesn't have restores nothing.
        restore(stores, &m, "volume.cache", &tmp("v2none")).unwrap();
        assert!(!tmp("v2none").exists());
        // The same seq and generation again: refused, the first stands.
        let e = push_tree(stores, &to(1), &trees).unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        assert_eq!(local.get_ref(&bundle_ref("agt_x", 1, 1)).unwrap().map(|d| d.to_string()), Some(head));
        for d in [src, out, root, v1] {
            rm(&d);
        }
    }

    /// #365: a hibernation writes only what changed since an earlier one: an unchanged tree costs
    /// its bundle tree and meta, one changed small file costs that file and the trees above it.
    #[test]
    fn a_push_writes_only_what_changed() {
        let (src, root) = (tmp("incsrc"), tmp("incstore"));
        sample(&src);
        let (local, written) = counted(&root);
        let stores = Stores { local: &local, shared: None, written: Some(&written) };
        let trees = [TreeSrc { name: "workspace".into(), path: src.clone(), exclude: &[] }];
        let (first, _) = push_tree(stores, &to(1), &trees).unwrap();
        let full = written.load(std::sync::atomic::Ordering::Relaxed);
        let (same, _) = push_tree(stores, &to(2), &trees).unwrap();
        assert_eq!(same.tree("workspace").unwrap().stored_bytes, 0, "nothing of an unchanged tree is written");
        assert_eq!(same.tree("workspace").unwrap().digest, first.tree("workspace").unwrap().digest);
        let after_same = written.load(std::sync::atomic::Ordering::Relaxed) - full;
        assert!(after_same < 1024, "an unchanged push wrote {after_same} bytes");
        std::fs::write(src.join("home/.gitconfig"), "changed").unwrap();
        let (changed, _) = push_tree(stores, &to(3), &trees).unwrap();
        let t = changed.tree("workspace").unwrap();
        assert!(
            t.stored_bytes > 0 && t.stored_bytes < 2048,
            "one small file and two trees cost {} bytes (the first push {full})",
            t.stored_bytes
        );
        assert_ne!(t.digest, first.tree("workspace").unwrap().digest);
        rm(&src);
        rm(&root);
    }

    /// #365: with a shared store, a bundle is there before the head moves, a later push sends only
    /// what the shared store lacks, and another host (an empty local store) wakes from it.
    #[test]
    fn a_shared_store_gets_only_what_it_lacks_and_another_host_restores_from_it() {
        let (src, a, b, sh, out, v1) = (tmp("shsrc"), tmp("sha"), tmp("shb"), tmp("shshared"), tmp("shout"), tmp("shv1"));
        sample(&src);
        let (shared, sent) = counted(&sh);
        let local = Cas::new(DirStore::new(&a));
        let stores = Stores { local: &local, shared: Some(&shared), written: None };
        let trees = [TreeSrc { name: "state".into(), path: src.clone(), exclude: &[] }];
        let (m1, _) = push_tree(stores, &to(1), &trees).unwrap();
        let first = sent.load(std::sync::atomic::Ordering::Relaxed);
        assert!(first > 0 && m1.tree("state").unwrap().stored_bytes > 0);
        assert!(shared.get_ref(&bundle_ref("agt_x", 1, 1)).unwrap().is_some(), "the ref is in the shared store");
        std::fs::write(src.join("run.sh"), "#!/bin/sh\necho changed\n").unwrap();
        let (m2, head2) = push_tree(stores, &to(2), &trees).unwrap();
        let second = sent.load(std::sync::atomic::Ordering::Relaxed) - first;
        assert!(second < 4096, "the second push sent {second} bytes (the first {first})");
        assert!(m2.tree("state").unwrap().stored_bytes < 4096);
        // Another host: nothing local; the bundle comes from the shared store, verified.
        let other = Cas::new(DirStore::new(&b));
        let there = Stores { local: &other, shared: Some(&shared), written: None };
        let read = read_head(there, &head2, "agt_x").unwrap();
        assert_eq!(read, m2);
        restore(there, &read, "state", &out).unwrap();
        assert_eq!(std::fs::read_to_string(out.join("run.sh")).unwrap(), "#!/bin/sh\necho changed\n");
        assert_eq!(std::fs::read(out.join("big.bin")).unwrap().len(), 256 << 10);
        // A tampered object in the shared store doesn't verify, and leaves nothing behind.
        let (other2, out2) = (tmp("shc"), tmp("shout2"));
        let fresh = Cas::new(DirStore::new(&other2));
        let d = crate::cas::Digest::of(&vec![7u8; 256 << 10]);
        let obj = sh.join(format!("o/{}", d.hex()));
        std::fs::remove_file(&obj).unwrap();
        std::fs::write(&obj, zstd::encode_all(&b"not the file"[..], 3).unwrap()).unwrap();
        let s3 = Stores { local: &fresh, shared: Some(&shared), written: None };
        assert!(restore(s3, &read, "state", &out2).is_err());
        assert!(!out2.exists());
        for d in [src, a, b, sh, out, v1, other2] {
            rm(&d);
        }
    }
}
