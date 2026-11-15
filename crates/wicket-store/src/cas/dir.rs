//! Trees from directories (#258 step 2): [`Cas::put_dir`] stores a directory as a tree,
//! [`Cas::checkout`] writes one back, and [`dir_digest`] names a directory without storing it.
//!
//! - **What is kept.** Directories, regular files and symlinks (stored as links, never followed),
//!   with their permission bits and modification times (a symlink's are `0777` and 0). Sockets,
//!   FIFOs and devices are left out. A name that isn't UTF-8 is refused: the tree format can't hold
//!   it.
//! - **Plain** ([`DirOpts::plain`]) is for program sources: symlinks and special files are refused,
//!   and a file's mode is `0755` or `0644` by its owner's executable bit, a directory's `0755`, and
//!   every mtime 0. Two checkouts of the same source name the same tree, whenever they were made.
//! - **Checkout** keeps bundle restore's checks: it writes only into a fresh directory, makes only
//!   the three kinds of entry, and never writes through a symlink (it makes every path itself, and
//!   a symlink is only ever a leaf). Every object it reads is verified against its digest, so the
//!   tree it rebuilds is the one asked for; each file's and link's size is checked against its
//!   entry as well.

use super::{invalid, Cas, Digest, Entry, HashWrite, Kind, Tree};
use sha2::{Digest as _, Sha256};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// How a directory becomes a tree.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirOpts<'a> {
    /// Top-level names to leave out.
    pub exclude: &'a [&'a str],
    /// Plain files only, with modes and times normalised (see the module's notes).
    pub plain: bool,
}

/// Where a directory's objects go: into a store, or nowhere (only named).
trait Sink {
    /// The file's digest and length, as read.
    fn file(&self, path: &Path) -> io::Result<(Digest, u64)>;
    fn bytes(&self, b: &[u8]) -> io::Result<Digest>;
    fn tree(&self, t: &Tree) -> io::Result<Digest>;
}

struct Named;

impl Sink for Named {
    fn file(&self, path: &Path) -> io::Result<(Digest, u64)> {
        let mut h = Sha256::new();
        let n = io::copy(&mut std::fs::File::open(path)?, &mut HashWrite(&mut h))?;
        Ok((Digest(h.finalize().into()), n))
    }
    fn bytes(&self, b: &[u8]) -> io::Result<Digest> {
        Ok(Digest::of(b))
    }
    fn tree(&self, t: &Tree) -> io::Result<Digest> {
        Ok(t.digest())
    }
}

impl Sink for Cas {
    fn file(&self, path: &Path) -> io::Result<(Digest, u64)> {
        self.put_file_len(path)
    }
    fn bytes(&self, b: &[u8]) -> io::Result<Digest> {
        self.put_bytes(b)
    }
    fn tree(&self, t: &Tree) -> io::Result<Digest> {
        self.put_tree(t)
    }
}

/// The tree of `dir`, its subtrees and files put into `sink`.
fn build(sink: &dyn Sink, dir: &Path, opts: &DirOpts, top: bool) -> io::Result<Digest> {
    let mut entries = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let path = e.path();
        let name = e.file_name();
        let name =
            name.to_str().ok_or_else(|| invalid(format!("{} isn't a UTF-8 name: a tree can't hold it", path.display())))?.to_string();
        if top && opts.exclude.contains(&name.as_str()) {
            continue;
        }
        let meta = std::fs::symlink_metadata(&path)?;
        let ft = meta.file_type();
        let mode = meta.permissions().mode() & 0o7777;
        let entry = if ft.is_dir() {
            let digest = build(sink, &path, opts, false)?;
            let (mode, mtime) = if opts.plain { (0o755, 0) } else { (mode, meta.mtime()) };
            Entry { name, kind: Kind::Dir, mode, mtime, size: 0, digest }
        } else if ft.is_file() {
            let (digest, size) = sink.file(&path)?;
            if size != meta.len() {
                return Err(invalid(format!("{} changed while it was read", path.display())));
            }
            let (mode, mtime) = if opts.plain { (if mode & 0o100 != 0 { 0o755 } else { 0o644 }, 0) } else { (mode, meta.mtime()) };
            Entry { name, kind: Kind::File, mode, mtime, size, digest }
        } else if opts.plain {
            let what = if ft.is_symlink() { "a symlink" } else { "not a regular file" };
            return Err(invalid(format!("{} is {what}: a plain tree is plain files", path.display())));
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&path)?;
            let t = target.as_os_str().as_bytes();
            Entry { name, kind: Kind::Link, mode: 0o777, mtime: 0, size: t.len() as u64, digest: sink.bytes(t)? }
        } else {
            continue; // sockets, FIFOs, devices
        };
        entries.push(entry);
    }
    sink.tree(&Tree::new(entries)?)
}

fn root_dir(root: &Path) -> io::Result<()> {
    if !std::fs::symlink_metadata(root)?.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not a directory", root.display())));
    }
    Ok(())
}

/// The digest [`Cas::put_dir`] would store `root` under, storing nothing.
pub fn dir_digest(root: &Path, opts: &DirOpts) -> io::Result<Digest> {
    root_dir(root)?;
    build(&Named, root, opts, true)
}

/// The most a symlink's target may be.
const LINK_MAX: u64 = 4096;

impl Cas {
    /// Stores the directory `root` (its contents, not itself) as a tree, with every file and
    /// subtree; returns the tree's digest. Objects already in the store aren't written again.
    pub fn put_dir(&self, root: &Path, opts: &DirOpts) -> io::Result<Digest> {
        root_dir(root)?;
        build(self, root, opts, true)
    }

    /// Writes tree `d` into `dest`, which must not exist or be an empty directory (not a symlink).
    /// On an error `dest` may hold part of the tree: the caller checks out into a scratch directory
    /// and moves it into place once this returns.
    pub fn checkout(&self, d: &Digest, dest: &Path) -> io::Result<()> {
        match std::fs::symlink_metadata(dest) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => std::fs::create_dir(dest)?,
            Err(e) => return Err(e),
            Ok(m) if m.is_dir() && std::fs::read_dir(dest)?.next().is_none() => {}
            Ok(_) => return Err(invalid(format!("{} isn't a fresh directory", dest.display()))),
        }
        // Directory modes and times are applied last, deepest first, so a read-only directory
        // doesn't stop its own contents from being written and writing them doesn't move its time.
        let mut dirs: Vec<(PathBuf, u32, i64)> = Vec::new();
        self.checkout_into(d, dest, &mut dirs)?;
        dirs.sort_by_key(|(p, _, _)| std::cmp::Reverse(p.components().count()));
        for (p, mode, t) in dirs {
            std::fs::File::open(&p)?.set_modified(time(t))?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    }

    fn checkout_into(&self, d: &Digest, dir: &Path, dirs: &mut Vec<(PathBuf, u32, i64)>) -> io::Result<()> {
        let t = self.get_tree(d)?.ok_or_else(|| missing(d))?;
        for e in t.entries() {
            // The name was checked when the tree was decoded: one normal component.
            let p = dir.join(&e.name);
            match e.kind {
                Kind::Dir => {
                    std::fs::create_dir(&p)?;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))?;
                    self.checkout_into(&e.digest, &p, dirs)?;
                    dirs.push((p, e.mode, e.mtime));
                }
                Kind::File => {
                    let r = self.get(&e.digest)?.ok_or_else(|| missing(&e.digest))?;
                    // create_new: never through a symlink, never over anything.
                    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p)?;
                    let n = io::copy(&mut r.take(e.size + 1), &mut f)?;
                    if n != e.size {
                        return Err(invalid(format!("{} is {n} bytes, but its entry says {}", p.display(), e.size)));
                    }
                    f.flush()?;
                    f.set_permissions(std::fs::Permissions::from_mode(e.mode))?;
                    f.set_modified(time(e.mtime))?;
                }
                Kind::Link => {
                    let b = self.get_bytes(&e.digest, LINK_MAX)?.ok_or_else(|| missing(&e.digest))?;
                    if b.len() as u64 != e.size || b.is_empty() || b.contains(&0) {
                        return Err(invalid(format!("{} has a bad symlink target", p.display())));
                    }
                    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&b), &p)?;
                }
            }
        }
        Ok(())
    }
}

fn time(t: i64) -> SystemTime {
    if t >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_secs(t as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_secs(t.unsigned_abs())
    }
}

fn missing(d: &Digest) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("object {d} isn't in the store"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::DirStore;
    use crate::sealed::SealedStore;
    use std::os::unix::fs::symlink;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-casdir-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn set_mtime(p: &Path, t: i64) {
        std::fs::File::open(p).unwrap().set_modified(time(t)).unwrap();
    }

    /// A source tree: files (one executable, one empty), a subdirectory, a read-only directory, a
    /// symlink pointing out, and a FIFO.
    fn sample(src: &Path) {
        std::fs::create_dir_all(src.join("sub/deep")).unwrap();
        std::fs::write(src.join("a.txt"), b"hello").unwrap();
        std::fs::write(src.join("run.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(src.join("run.sh"), std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(src.join("empty"), b"").unwrap();
        std::fs::write(src.join("sub/deep/b.bin"), vec![3u8; 100_000]).unwrap();
        std::fs::write(src.join("sub/same.txt"), b"hello").unwrap();
        symlink("/etc/passwd", src.join("out")).unwrap();
        std::fs::create_dir(src.join("ro")).unwrap();
        std::fs::write(src.join("ro/x"), b"x").unwrap();
        set_mtime(&src.join("a.txt"), 1_700_000_000);
        set_mtime(&src.join("ro"), 1_600_000_000);
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
        let _ = std::process::Command::new("mkfifo").arg(src.join("fifo")).status();
    }

    #[test]
    fn a_directory_round_trips_through_the_store() {
        let d = tmp("round");
        let src = d.join("src");
        sample(&src);
        let cas = Cas::new(SealedStore::sealed_only(DirStore::new(d.join("store")), &[5u8; 32]));
        let opts = DirOpts::default();
        let t = cas.put_dir(&src, &opts).unwrap();
        assert_eq!(t, dir_digest(&src, &opts).unwrap(), "named the same whether stored or not");
        let top = cas.get_tree(&t).unwrap().unwrap();
        let names: Vec<_> = top.entries().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a.txt", "empty", "out", "ro", "run.sh", "sub"], "the FIFO is left out");
        let a = top.get("a.txt").unwrap();
        let mode = std::fs::metadata(src.join("a.txt")).unwrap().permissions().mode() & 0o7777;
        assert_eq!((a.kind, a.mode, a.mtime, a.size), (Kind::File, mode, 1_700_000_000, 5));
        assert_eq!(top.get("run.sh").unwrap().mode, 0o750);
        let out = top.get("out").unwrap();
        assert_eq!((out.kind, out.mode, out.mtime, out.size), (Kind::Link, 0o777, 0, 11));
        assert_eq!(top.get("ro").unwrap().mode, 0o555);

        // Back out, the same tree: contents, modes, times, links (not followed).
        let dest = d.join("dest");
        cas.checkout(&t, &dest).unwrap();
        assert_eq!(dir_digest(&dest, &opts).unwrap(), t);
        assert_eq!(std::fs::read(dest.join("sub/deep/b.bin")).unwrap(), vec![3u8; 100_000]);
        assert_eq!(std::fs::read_link(dest.join("out")).unwrap(), Path::new("/etc/passwd"));
        assert!(std::fs::symlink_metadata(dest.join("out")).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::metadata(dest.join("ro")).unwrap().mtime(), 1_600_000_000);

        // Unchanged files share their objects; a changed one is one new blob and the trees above it.
        let before = cas.backend().list_prefix("o/").unwrap().len();
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(src.join("sub/deep/b.bin"), vec![4u8; 100_000]).unwrap();
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
        let t2 = cas.put_dir(&src, &opts).unwrap();
        assert_ne!(t2, t);
        assert_eq!(cas.backend().list_prefix("o/").unwrap().len(), before + 4, "blob, deep, sub, top");

        // Excluded top-level names are left out (only at the top).
        let ex = cas.put_dir(&src, &DirOpts { exclude: &["sub", "deep"], ..opts }).unwrap();
        assert!(cas.get_tree(&ex).unwrap().unwrap().get("sub").is_none());

        for p in [&src.join("ro"), &dest.join("ro")] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn checkout_writes_only_into_a_fresh_directory() {
        let d = tmp("fresh");
        let src = d.join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("f"), b"f").unwrap();
        let cas = Cas::new(DirStore::new(d.join("store")));
        let t = cas.put_dir(&src, &DirOpts::default()).unwrap();
        // An empty directory is fresh; one with anything in it, a file or a symlink isn't.
        std::fs::create_dir(d.join("empty")).unwrap();
        cas.checkout(&t, &d.join("empty")).unwrap();
        assert!(cas.checkout(&t, &d.join("empty")).is_err());
        std::fs::create_dir(d.join("target")).unwrap();
        symlink(d.join("target"), d.join("link")).unwrap();
        assert!(cas.checkout(&t, &d.join("link")).is_err());
        assert!(std::fs::read_dir(d.join("target")).unwrap().next().is_none(), "nothing written through it");
        assert!(cas.checkout(&t, &src.join("f")).is_err());
        // Not a directory to put.
        assert!(cas.put_dir(&src.join("f"), &DirOpts::default()).is_err());
        assert!(cas.put_dir(&d.join("link"), &DirOpts::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn checkout_refuses_what_its_tree_doesnt_say() {
        let d = tmp("refuse");
        let cas = Cas::new(DirStore::new(d.join("store")));
        let f = cas.put_bytes(b"hello").unwrap();
        let entry = |name: &str, kind, size, digest| Entry {
            name: name.into(),
            kind,
            mode: if kind == Kind::Link { 0o777 } else { 0o644 },
            mtime: 0,
            size,
            digest,
        };
        // A size that isn't the blob's.
        let t = cas.put_tree(&Tree::new(vec![entry("f", Kind::File, 4, f)]).unwrap()).unwrap();
        assert!(cas.checkout(&t, &d.join("a")).is_err());
        // A file entry naming nothing in the store.
        let t = cas.put_tree(&Tree::new(vec![entry("f", Kind::File, 5, Digest::of(b"gone"))]).unwrap()).unwrap();
        assert_eq!(cas.checkout(&t, &d.join("b")).unwrap_err().kind(), io::ErrorKind::NotFound);
        // A directory entry naming a blob, not a tree.
        let t = cas.put_tree(&Tree::new(vec![entry("d", Kind::Dir, 0, f)]).unwrap()).unwrap();
        assert!(cas.checkout(&t, &d.join("c")).is_err());
        // A symlink whose target isn't its size.
        let t = cas.put_tree(&Tree::new(vec![entry("l", Kind::Link, 3, f)]).unwrap()).unwrap();
        assert!(cas.checkout(&t, &d.join("e")).is_err());
        // A blob changed at rest is caught as it is read.
        let t = cas.put_tree(&Tree::new(vec![entry("f", Kind::File, 5, f)]).unwrap()).unwrap();
        std::fs::write(d.join("store/o").join(f.hex()), zstd::encode_all(&b"HELLO"[..], 3).unwrap()).unwrap();
        assert!(cas.checkout(&t, &d.join("g")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn plain_trees_are_named_by_content_and_executable_bit_only() {
        let d = tmp("plain");
        let (a, b) = (d.join("a"), d.join("b"));
        for (p, t, mode) in [(&a, 1_000, 0o700), (&b, 2_000, 0o755)] {
            std::fs::create_dir_all(p.join("lib")).unwrap();
            std::fs::write(p.join("run.sh"), b"echo hi\n").unwrap();
            std::fs::write(p.join("lib/x.py"), b"x = 1\n").unwrap();
            std::fs::set_permissions(p.join("run.sh"), std::fs::Permissions::from_mode(mode)).unwrap();
            set_mtime(&p.join("run.sh"), t);
        }
        std::fs::set_permissions(b.join("lib/x.py"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let plain = DirOpts { plain: true, ..DirOpts::default() };
        let da = dir_digest(&a, &plain).unwrap();
        assert_eq!(da, dir_digest(&b, &plain).unwrap(), "times and other bits don't count");
        assert_ne!(dir_digest(&a, &DirOpts::default()).unwrap(), dir_digest(&b, &DirOpts::default()).unwrap());
        // The executable bit and the content do.
        std::fs::set_permissions(b.join("run.sh"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_ne!(dir_digest(&b, &plain).unwrap(), da);
        std::fs::set_permissions(b.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(b.join("lib/x.py"), b"x = 2\n").unwrap();
        assert_ne!(dir_digest(&b, &plain).unwrap(), da);
        // Symlinks and special files are refused.
        symlink("run.sh", a.join("l")).unwrap();
        assert!(dir_digest(&a, &plain).unwrap_err().to_string().contains("symlink"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_name_a_tree_cant_hold_is_refused() {
        let d = tmp("names");
        std::fs::write(d.join(std::ffi::OsStr::from_bytes(b"bad\xff")), b"").unwrap();
        assert!(dir_digest(&d, &DirOpts::default()).unwrap_err().to_string().contains("UTF-8"));
        std::fs::remove_file(d.join(std::ffi::OsStr::from_bytes(b"bad\xff"))).unwrap();
        std::fs::write(d.join("new\nline"), b"").unwrap();
        assert!(dir_digest(&d, &DirOpts::default()).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
