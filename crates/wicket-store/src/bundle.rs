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
//! **Version 1**, still read (heads pushed before #365): one tar + zstd (-3) blob per tree,
//! content-addressed in an [`ObjectStore`], and a [`StateManifest`] naming them. Pushed now only for a
//! tree the version-2 format can't hold (a name that isn't UTF-8), so such an agent still hibernates.
//!
//! - **What a tree holds.** Directories, regular files and symlinks (stored as links, never
//!   followed), with their permission bits and modification times. Sockets, FIFOs and devices are
//!   skipped: they mean nothing without the processes that made them.
//! - **Tree digest.** SHA-256 over every entry's type, path, mode, size and content (or link target),
//!   in path order. A tree whose digest is unchanged since the previous manifest reuses its blob, so
//!   an unchanged tree costs no upload. It is checked again after unpacking.
//! - **Unpacking** refuses anything but those three entry types, absolute paths and `..`, and any
//!   path that would leave the destination through a symlink.
//!
//! Not yet: encryption with the agent's data key and a signed manifest (design §13.5).

use crate::cas::{Cas, Digest as CasDigest, DirOpts, Entry as CasEntry, Kind as CasKind, Tree};
use crate::objects::ObjectStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const ZSTD_LEVEL: i32 = 3;

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

/// The key a manifest is stored under: its sequence number and the generation that wrote it.
pub fn manifest_key(agent: &str, seq: i64, generation: i64) -> String {
    format!("a/{agent}/m/{seq}.{generation}")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
    Link,
}

struct Item {
    rel: String,
    path: PathBuf,
    kind: Kind,
    meta: std::fs::Metadata,
}

/// Every entry under `root` worth keeping, in path order, the root itself first (as ".").
/// `exclude` lists top-level names to leave out.
fn walk(root: &Path, exclude: &[&str]) -> io::Result<Vec<Item>> {
    fn rec(root: &Path, dir: &Path, exclude: &[&str], out: &mut Vec<Item>) -> io::Result<()> {
        let mut names: Vec<_> = std::fs::read_dir(dir)?.collect::<io::Result<Vec<_>>>()?;
        names.sort_by_key(|e| e.file_name());
        for e in names {
            let path = e.path();
            let rel = path.strip_prefix(root).expect("under root").to_string_lossy().into_owned();
            if dir == root && exclude.contains(&rel.as_str()) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path)?;
            let ft = meta.file_type();
            let kind = if ft.is_dir() {
                Kind::Dir
            } else if ft.is_file() {
                Kind::File
            } else if ft.is_symlink() {
                Kind::Link
            } else {
                continue; // sockets, FIFOs, devices
            };
            out.push(Item { rel, path: path.clone(), kind, meta });
            if kind == Kind::Dir {
                rec(root, &path, exclude, out)?;
            }
        }
        Ok(())
    }
    let meta = std::fs::symlink_metadata(root)?;
    if !meta.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not a directory", root.display())));
    }
    let mut out = vec![Item { rel: ".".into(), path: root.to_path_buf(), kind: Kind::Dir, meta }];
    rec(root, root, exclude, &mut out)?;
    Ok(out)
}

fn digest_line(h: &mut Sha256, kind: Kind, rel: &str, mode: u32, size: u64, content: &str) {
    let k = match kind {
        Kind::Dir => "d",
        Kind::File => "f",
        Kind::Link => "l",
    };
    h.update(format!("{k}\0{rel}\0{:o}\0{size}\0{content}\n", mode & 0o7777).as_bytes());
}

/// Reads through, hashing and counting.
struct HashRead<R> {
    inner: R,
    h: Sha256,
    n: u64,
}

impl<R: Read> Read for HashRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.h.update(&buf[..k]);
        self.n += k as u64;
        Ok(k)
    }
}

/// Counts what passes through a writer.
struct CountWrite<W> {
    inner: W,
    n: u64,
    h: Sha256,
}

impl<W: Write> Write for CountWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let k = self.inner.write(buf)?;
        self.n += k as u64;
        self.h.update(&buf[..k]);
        Ok(k)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// What packing a tree produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packed {
    pub digest: String,
    pub files: u64,
    pub raw_bytes: u64,
    pub stored_bytes: u64,
    /// SHA-256 of the blob itself.
    pub blob_sha256: String,
}

/// Packs `root` as tar + zstd into `out`, computing its tree digest on the way.
pub fn pack_tree(root: &Path, exclude: &[&str], out: impl Write) -> Result<Packed> {
    let items = walk(root, exclude)?;
    let cw = CountWrite { inner: out, n: 0, h: Sha256::new() };
    let enc = zstd::Encoder::new(cw, ZSTD_LEVEL)?;
    let mut b = tar::Builder::new(enc);
    b.follow_symlinks(false);
    let mut h = Sha256::new();
    let (mut files, mut raw) = (0u64, 0u64);
    for it in &items {
        let mode = it.meta.permissions().mode();
        let mut hd = tar::Header::new_gnu();
        hd.set_mode(mode & 0o7777);
        hd.set_mtime(it.meta.mtime().max(0) as u64);
        hd.set_uid(0);
        hd.set_gid(0);
        match it.kind {
            Kind::Dir => {
                hd.set_entry_type(tar::EntryType::Directory);
                hd.set_size(0);
                b.append_data(&mut hd, if it.rel == "." { "./" } else { &it.rel }, io::empty())?;
                digest_line(&mut h, Kind::Dir, &it.rel, mode, 0, "");
            }
            Kind::File => {
                let size = it.meta.len();
                hd.set_entry_type(tar::EntryType::Regular);
                hd.set_size(size);
                let mut r = HashRead { inner: std::fs::File::open(&it.path)?.take(size), h: Sha256::new(), n: 0 };
                b.append_data(&mut hd, &it.rel, &mut r)?;
                if r.n != size {
                    return Err(BundleError::Invalid(format!("{} changed while it was packed", it.rel)));
                }
                digest_line(&mut h, Kind::File, &it.rel, mode, size, &hex::encode(r.h.finalize()));
                files += 1;
                raw += size;
            }
            Kind::Link => {
                let target = std::fs::read_link(&it.path)?;
                hd.set_entry_type(tar::EntryType::Symlink);
                hd.set_size(0);
                b.append_link(&mut hd, &it.rel, &target)?;
                digest_line(&mut h, Kind::Link, &it.rel, 0o777, 0, &target.to_string_lossy());
            }
        }
    }
    let enc = b.into_inner()?;
    let mut cw = enc.finish()?;
    cw.flush()?;
    Ok(Packed { digest: hex::encode(h.finalize()), files, raw_bytes: raw, stored_bytes: cw.n, blob_sha256: hex::encode(cw.h.finalize()) })
}

/// The tree digest of `root`, as [`pack_tree`] computes it.
pub fn tree_digest(root: &Path, exclude: &[&str]) -> Result<String> {
    let mut h = Sha256::new();
    for it in walk(root, exclude)? {
        let mode = it.meta.permissions().mode();
        match it.kind {
            Kind::Dir => digest_line(&mut h, Kind::Dir, &it.rel, mode, 0, ""),
            Kind::File => {
                let mut fh = Sha256::new();
                io::copy(&mut std::fs::File::open(&it.path)?, &mut crate::cas::HashWrite(&mut fh))?;
                digest_line(&mut h, Kind::File, &it.rel, mode, it.meta.len(), &hex::encode(fh.finalize()));
            }
            Kind::Link => digest_line(&mut h, Kind::Link, &it.rel, 0o777, 0, &std::fs::read_link(&it.path)?.to_string_lossy()),
        }
    }
    Ok(hex::encode(h.finalize()))
}

/// Unpacks a blob made by [`pack_tree`] into `dest` (created if needed; should be empty).
pub fn unpack_tree(blob: impl Read, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    let dec = zstd::Decoder::new(blob)?;
    let mut a = tar::Archive::new(dec);
    a.set_preserve_permissions(true);
    a.set_preserve_mtime(true);
    a.set_unpack_xattrs(false);
    a.set_overwrite(true);
    // Directory modes are applied last, deepest first, so a read-only directory doesn't stop its
    // own contents from being written.
    let mut dirs: Vec<(PathBuf, u32)> = Vec::new();
    for e in a.entries()? {
        let mut e = e?;
        let path = e.path()?.into_owned();
        let rel = path.strip_prefix(".").unwrap_or(&path).to_path_buf();
        if rel.is_absolute() || rel.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
            return Err(BundleError::Invalid(format!("bundle entry {} leaves its tree", path.display())));
        }
        let mode = e.header().mode()?;
        match e.header().entry_type() {
            tar::EntryType::Directory => {
                let d = dest.join(&rel);
                if rel.as_os_str().is_empty() {
                    dirs.push((dest.to_path_buf(), mode));
                    continue;
                }
                if !e.unpack_in(dest)? {
                    return Err(BundleError::Invalid(format!("bundle entry {} leaves its tree", path.display())));
                }
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
                dirs.push((d, mode));
            }
            tar::EntryType::Regular | tar::EntryType::Symlink => {
                if !e.unpack_in(dest)? {
                    return Err(BundleError::Invalid(format!("bundle entry {} leaves its tree", path.display())));
                }
            }
            t => return Err(BundleError::Invalid(format!("bundle entry {} has type {t:?}", path.display()))),
        }
    }
    dirs.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
    for (d, mode) in dirs {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode & 0o7777))?;
    }
    Ok(())
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

/// Pushes trees as one bundle: packs each (reusing the previous manifest's blob for a tree whose
/// digest hasn't changed), uploads new blobs and then the manifest, both put-if-absent. Returns the
/// manifest and its key; the caller commits the key in the ledger, which is the commit point.
pub fn push(
    store: &dyn ObjectStore,
    to: &PushTo,
    trees: &[TreeSrc],
    prev: Option<&StateManifest>,
    scratch: &Path,
) -> Result<(StateManifest, String)> {
    let PushTo { agent, generation, seq, session_id } = *to;
    std::fs::create_dir_all(scratch)?;
    let mut out = Vec::new();
    for t in trees {
        let tmp = scratch.join(format!("pack-{}-{}", std::process::id(), t.name));
        let packed = {
            let f = std::fs::File::create(&tmp)?;
            let mut w = io::BufWriter::new(f);
            let p = pack_tree(&t.path, t.exclude, &mut w)?;
            w.flush()?;
            p
        };
        let entry = match prev.and_then(|p| p.tree(&t.name)).filter(|e| e.digest == packed.digest) {
            Some(e) => e.clone(),
            None => {
                let blob = format!("a/{agent}/p/{}", packed.blob_sha256);
                store.put_if_absent(&blob, &mut io::BufReader::new(std::fs::File::open(&tmp)?))?;
                TreeEntry {
                    name: t.name.clone(),
                    digest: packed.digest,
                    blob,
                    files: packed.files,
                    raw_bytes: packed.raw_bytes,
                    stored_bytes: packed.stored_bytes,
                }
            }
        };
        let _ = std::fs::remove_file(&tmp);
        out.push(entry);
    }
    let m = StateManifest {
        version: 1,
        agent: agent.into(),
        generation,
        seq,
        created_at: crate::now(),
        session_id: session_id.into(),
        trees: out,
        bundle: None,
    };
    let key = manifest_key(agent, seq, generation);
    if !store.put_if_absent(&key, &mut &serde_json::to_vec_pretty(&m)?[..])? {
        return Err(BundleError::Invalid(format!("state manifest {key} already exists")));
    }
    Ok((m, key))
}

/// Reads a state manifest and checks it is the agent's.
pub fn read_manifest(store: &dyn ObjectStore, key: &str, agent: &str) -> Result<StateManifest> {
    let mut r = store.get(key)?.ok_or_else(|| BundleError::Invalid(format!("state manifest {key} is missing")))?;
    let mut b = Vec::new();
    r.read_to_end(&mut b)?;
    let m: StateManifest = serde_json::from_slice(&b)?;
    if m.agent != agent || m.version != 1 {
        return Err(BundleError::Invalid(format!("state manifest {key} is not agent {agent}'s")));
    }
    Ok(m)
}

/// Restores one tree into `dest` (which must not exist yet), and verifies both the blob's hash and
/// the unpacked tree's digest. On any failure `dest` is removed.
pub fn pull_tree(store: &dyn ObjectStore, t: &TreeEntry, dest: &Path) -> Result<()> {
    if dest.exists() {
        return Err(BundleError::Invalid(format!("{} already exists", dest.display())));
    }
    let res = (|| {
        let r = store.get(&t.blob)?.ok_or_else(|| BundleError::Invalid(format!("blob {} is missing", t.blob)))?;
        let mut hr = HashRead { inner: r, h: Sha256::new(), n: 0 };
        unpack_tree(&mut hr, dest)?;
        io::copy(&mut hr, &mut io::sink())?; // zstd's trailing bytes
        let sha = hex::encode(hr.h.finalize());
        if !t.blob.ends_with(&format!("/{sha}")) {
            return Err(BundleError::Invalid(format!("tree {}: blob {} does not match its hash", t.name, t.blob)));
        }
        let d = tree_digest(dest, &[])?;
        if d != t.digest {
            return Err(BundleError::Invalid(format!("tree {} does not verify: digest {d}, the manifest says {}", t.name, t.digest)));
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = make_writable(dest);
        let _ = std::fs::remove_dir_all(dest);
    }
    res
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
        let (mut files, mut raw) = (0, 0);
        for i in walk(&t.path, t.exclude)? {
            if i.kind != Kind::Dir {
                files += 1;
                raw += i.meta.len();
            }
        }
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

/// Reads the head the ledger holds: a version-2 bundle (a digest) from `stores`, or a version-1
/// manifest from `v1`. Checks it is the agent's, and that a bundle's `meta` names exactly its trees.
pub fn read_head(stores: Stores, v1: &dyn ObjectStore, head: &str, agent: &str) -> Result<StateManifest> {
    let Some(d) = CasDigest::parse(head) else { return read_manifest(v1, head, agent) };
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

/// Restores tree `name` of a bundle into `dest` (which must not exist yet): a version-2 tree checked
/// out of the local store (fetching what it lacks from the shared one), with its root's mode and
/// time; a version-1 tree unpacked from `v1`. Every object is verified as it is read. On any failure
/// `dest` is removed. A bundle without the tree restores nothing.
pub fn restore(stores: Stores, v1: &dyn ObjectStore, m: &StateManifest, name: &str, dest: &Path) -> Result<()> {
    let Some(t) = m.tree(name) else { return Ok(()) };
    let Some(b) = m.bundle.as_deref() else { return pull_tree(v1, t, dest) };
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

    #[test]
    fn a_tree_round_trips_and_verifies() {
        let (src, out, root) = (tmp("src"), tmp("out"), tmp("store"));
        std::fs::create_dir_all(src.join("home/.config")).unwrap();
        std::fs::write(src.join("home/.gitconfig"), "[user]\n\tname = a\n").unwrap();
        std::fs::write(src.join("run.sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(src.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();
        std::fs::create_dir_all(src.join("ro")).unwrap();
        std::fs::write(src.join("ro/keep"), "x").unwrap();
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o1777)).unwrap();
        // A socket is skipped.
        let _l = std::os::unix::net::UnixListener::bind(src.join("sock")).unwrap();
        std::fs::create_dir_all(src.join("skip")).unwrap();

        let store = DirStore::new(&root);
        let trees = [TreeSrc { name: "tmp".into(), path: src.clone(), exclude: &["skip"] }];
        let (m, key) =
            push(&store, &PushTo { agent: "agt_x", generation: 1, seq: 1, session_id: "s" }, &trees, None, &root.join(".scratch")).unwrap();
        assert_eq!(key, "a/agt_x/m/1.1");
        assert_eq!(read_manifest(&store, &key, "agt_x").unwrap(), m);
        assert!(read_manifest(&store, &key, "agt_y").is_err());
        let t = m.tree("tmp").unwrap();
        assert_eq!(t.files, 3);
        pull_tree(&store, t, &out).unwrap();
        assert_eq!(std::fs::read_to_string(out.join("home/.gitconfig")).unwrap(), "[user]\n\tname = a\n");
        assert_eq!(std::fs::read_link(out.join("link")).unwrap(), PathBuf::from("/etc/passwd"));
        assert_eq!(std::fs::metadata(out.join("run.sh")).unwrap().permissions().mode() & 0o7777, 0o755);
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777, 0o1777);
        assert_eq!(std::fs::metadata(out.join("ro")).unwrap().permissions().mode() & 0o7777, 0o555);
        assert!(!out.join("sock").exists() && !out.join("skip").exists());
        assert_eq!(tree_digest(&out, &[]).unwrap(), t.digest);
        assert!(pull_tree(&store, t, &out).is_err(), "never over an existing tree");

        // Unchanged: the next push reuses the blob. Changed: a new blob.
        let (m2, _) =
            push(&store, &PushTo { agent: "agt_x", generation: 1, seq: 2, session_id: "s" }, &trees, Some(&m), &root.join(".scratch"))
                .unwrap();
        assert_eq!(m2.trees[0].blob, t.blob);
        std::fs::write(src.join("home/.gitconfig"), "changed").unwrap();
        let (m3, _) =
            push(&store, &PushTo { agent: "agt_x", generation: 1, seq: 3, session_id: "s" }, &trees, Some(&m2), &root.join(".scratch"))
                .unwrap();
        assert_ne!(m3.trees[0].blob, t.blob);
        assert!(
            push(&store, &PushTo { agent: "agt_x", generation: 1, seq: 3, session_id: "s" }, &trees, Some(&m2), &root.join(".scratch"))
                .is_err(),
            "a manifest is never replaced"
        );

        // A blob that was tampered with doesn't verify, and leaves nothing behind.
        let blob_path = root.join(&m3.trees[0].blob);
        let mut other = Vec::new();
        pack_tree(&out, &[], &mut other).unwrap();
        std::fs::remove_file(&blob_path).unwrap();
        std::fs::write(&blob_path, &other).unwrap();
        let bad = tmp("bad");
        assert!(pull_tree(&store, &m3.trees[0], &bad).is_err());
        assert!(!bad.exists());
        for d in [src, out, root] {
            let _ = make_writable(&d);
            let _ = std::fs::remove_dir_all(&d);
        }
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
        let v1s = DirStore::new(&v1);
        assert_eq!(read_head(stores, &v1s, &head, "agt_x").unwrap(), m);
        assert!(read_head(stores, &v1s, &head, "agt_y").is_err(), "another agent's bundle");
        restore(stores, &v1s, &m, "tmp", &out).unwrap();
        assert_eq!(std::fs::read_to_string(out.join("home/.gitconfig")).unwrap(), "[user]\n\tname = a\n");
        assert_eq!(std::fs::read_link(out.join("link")).unwrap(), PathBuf::from("/etc/passwd"));
        assert_eq!(std::fs::metadata(out.join("run.sh")).unwrap().permissions().mode() & 0o7777, 0o755);
        assert_eq!(std::fs::metadata(out.join("ro")).unwrap().permissions().mode() & 0o7777, 0o555);
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777, 0o1777, "the root's own mode");
        assert!(!out.join("sock").exists() && !out.join("skip").exists());
        assert!(restore(stores, &v1s, &m, "tmp", &out).is_err(), "never over an existing tree");
        // A tree the bundle doesn't have restores nothing.
        restore(stores, &v1s, &m, "volume.cache", &tmp("v2none")).unwrap();
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
        let v1s = DirStore::new(&v1);
        let read = read_head(there, &v1s, &head2, "agt_x").unwrap();
        assert_eq!(read, m2);
        restore(there, &v1s, &read, "state", &out).unwrap();
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
        assert!(restore(s3, &v1s, &read, "state", &out2).is_err());
        assert!(!out2.exists());
        for d in [src, a, b, sh, out, v1, other2] {
            rm(&d);
        }
    }

    /// #365: heads pushed before version 2 are still read and restored, and a tree whose names the
    /// tree format can't hold is said to be so (its agent is kept as a version-1 bundle).
    #[test]
    fn version_one_heads_still_restore_and_odd_names_are_recognised() {
        let (src, root, v1, out) = (tmp("oldsrc"), tmp("oldcas"), tmp("oldv1"), tmp("oldout"));
        sample(&src);
        let v1s = DirStore::new(&v1);
        let trees = [TreeSrc { name: "tmp".into(), path: src.clone(), exclude: &[] }];
        let (m, key) = push(&v1s, &to(1), &trees, None, &v1.join(".scratch")).unwrap();
        let local = Cas::new(DirStore::new(&root));
        let stores = Stores { local: &local, shared: None, written: None };
        assert!(!is_tree_head(&key));
        let read = read_head(stores, &v1s, &key, "agt_x").unwrap();
        assert_eq!((read.version, read.bundle.as_deref()), (1, None));
        assert_eq!(read, m);
        restore(stores, &v1s, &read, "tmp", &out).unwrap();
        assert_eq!(std::fs::read_to_string(out.join("home/.gitconfig")).unwrap(), "[user]\n\tname = a\n");
        use std::os::unix::ffi::OsStrExt;
        std::fs::write(src.join(std::ffi::OsStr::from_bytes(b"caf\xe9")), "latin-1").unwrap();
        let e = push_tree(stores, &to(2), &trees).unwrap_err();
        assert!(unrepresentable(&e), "{e}");
        for d in [src, root, v1, out] {
            rm(&d);
        }
    }

    #[test]
    fn unpacking_refuses_escapes_and_odd_entries() {
        let mk = |f: &dyn Fn(&mut tar::Builder<Vec<u8>>)| {
            let mut b = tar::Builder::new(Vec::new());
            f(&mut b);
            zstd::encode_all(&b.into_inner().unwrap()[..], 3).unwrap()
        };
        let (dest, victim) = (tmp("esc"), tmp("victim"));
        std::fs::create_dir_all(&victim).unwrap();
        // A symlink pointing out, then a file through it.
        let v = victim.clone();
        let blob = mk(&move |b| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            b.append_link(&mut h, "out", &v).unwrap();
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_mode(0o644);
            b.append_data(&mut h, "out/pwned", &b"x"[..]).unwrap();
        });
        assert!(unpack_tree(&blob[..], &dest).is_err());
        assert!(!victim.join("pwned").exists());
        let _ = std::fs::remove_dir_all(&dest);
        let _ = std::fs::remove_dir_all(&victim);
        // A FIFO.
        let blob = mk(&|b| {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Fifo);
            h.set_size(0);
            b.append_data(&mut h, "fifo", io::empty()).unwrap();
        });
        assert!(unpack_tree(&blob[..], &dest).is_err());
        let _ = std::fs::remove_dir_all(&dest);
    }
}
