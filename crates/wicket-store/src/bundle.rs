//! Agent state bundles (#70): a hibernated agent's writable trees, one tar + zstd (-3) blob per tree,
//! content-addressed in an [`ObjectStore`], and a [`StateManifest`] naming them.
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
                io::copy(&mut std::fs::File::open(&it.path)?, &mut fh)?;
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
