//! The content-addressed store (#258, docs/explanation/store.md): blobs and trees named by their
//! sha256, and write-once refs that name a digest, over any [`ObjectStore`].
//!
//! - **Objects** are stored under `o/<hex>` as zstd (-3) of their bytes. Every read is verified: a
//!   reader that gets to the end of an object whose bytes don't hash to its name gets an error, not
//!   the end of the file, so a caller that writes to a temporary file and keeps it only once it is
//!   whole never keeps anything unverified.
//! - **Trees** are blobs in a canonical text format ([`Tree`]): one line per entry naming its
//!   content by digest, so a directory is named, checked and shared by one digest.
//! - **Refs** (`r/<name>`) hold `sha256:<hex>\n`, put-if-absent like everything else: a ref is
//!   never rewritten. They name what must outlive the ledger (pre-update ledger snapshots, #167);
//!   everything else is named by a digest the ledger holds.
//! - **Sealing.** Open the store over [`crate::sealed::SealedStore::sealed_only`]: each object is
//!   sealed under its own key (`o/<hex>`, `r/<name>`), and nothing plain is read.
//! - **Directories** become trees with [`Cas::put_dir`] and come back with [`Cas::checkout`].

use crate::objects::{valid_key, ObjectStore};
use sha2::{Digest as _, Sha256};
use std::io::{self, Read};
use std::path::Path;

mod dir;
pub use dir::{dir_digest, DirOpts};

const OBJECTS: &str = "o/";
const REFS: &str = "r/";
const ZSTD_LEVEL: i32 = 3;
/// The most a tree or a ref may be when read.
pub const TREE_MAX: u64 = 64 << 20;
const REF_MAX: u64 = 128;

/// A sha256 digest, written `sha256:<64 hex>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The digest of `bytes`.
    pub fn of(bytes: &[u8]) -> Digest {
        Digest(Sha256::digest(bytes).into())
    }

    /// Its 64 hex digits.
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses `sha256:<64 lowercase hex>`.
    pub fn parse(s: &str) -> Option<Digest> {
        let h = s.strip_prefix("sha256:")?;
        if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return None;
        }
        let mut d = [0u8; 32];
        hex::decode_to_slice(h, &mut d).ok()?;
        Some(Digest(d))
    }

    fn key(&self) -> String {
        format!("{OBJECTS}{}", self.hex())
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl std::str::FromStr for Digest {
    type Err = io::Error;
    fn from_str(s: &str) -> io::Result<Digest> {
        Digest::parse(s).ok_or_else(|| invalid(format!("not a digest: {s:?}")))
    }
}

fn invalid(why: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.into())
}

/// Reads through, hashing.
struct HashRead<R> {
    inner: R,
    h: Sha256,
}

impl<R: Read> Read for HashRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.h.update(&buf[..k]);
        Ok(k)
    }
}

/// Reads through, counting.
struct Counted<'a, R: ?Sized> {
    inner: &'a mut R,
    n: u64,
}

impl<R: Read + ?Sized> Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n += k as u64;
        Ok(k)
    }
}

/// A hasher as an [`io::Write`] sink, for `io::copy` (RustCrypto's hashers stopped implementing it
/// in digest 0.11).
pub(crate) struct HashWrite<'a>(pub(crate) &'a mut Sha256);

impl io::Write for HashWrite<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An object as it is read: decompressed, hashed, and an error at the end unless it is `want`.
struct Verified<R: Read> {
    inner: zstd::stream::read::Decoder<'static, io::BufReader<R>>,
    h: Sha256,
    want: Digest,
    checked: bool,
}

impl<R: Read> Read for Verified<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.checked {
            return Ok(0);
        }
        let k = self.inner.read(buf)?;
        if k == 0 && !buf.is_empty() {
            let got = Digest(std::mem::take(&mut self.h).finalize().into());
            if got != self.want {
                return Err(invalid(format!("object {} reads as {got}", self.want)));
            }
            self.checked = true;
            return Ok(0);
        }
        self.h.update(&buf[..k]);
        Ok(k)
    }
}

/// Reads all of `r`, refusing more than `max` bytes.
fn read_max(r: impl Read, max: u64, what: &str) -> io::Result<Vec<u8>> {
    let mut b = Vec::new();
    r.take(max + 1).read_to_end(&mut b)?;
    if b.len() as u64 > max {
        return Err(invalid(format!("{what} is over {max} bytes")));
    }
    Ok(b)
}

fn ref_key(name: &str) -> io::Result<String> {
    if !valid_key(name) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad ref name {name:?}")));
    }
    Ok(format!("{REFS}{name}"))
}

/// The content-addressed store over a backend.
pub struct Cas {
    inner: Box<dyn ObjectStore>,
}

impl Cas {
    pub fn new(inner: impl ObjectStore + 'static) -> Cas {
        Cas { inner: Box::new(inner) }
    }

    /// The backend, for what a user wrote there before it moved onto the store.
    pub fn backend(&self) -> &dyn ObjectStore {
        &*self.inner
    }

    /// Stores `bytes`; returns their digest.
    pub fn put_bytes(&self, bytes: &[u8]) -> io::Result<Digest> {
        let d = Digest::of(bytes);
        if !self.inner.has(&d.key())? {
            let mut enc = zstd::stream::read::Encoder::new(bytes, ZSTD_LEVEL)?;
            self.inner.put_if_absent(&d.key(), &mut enc)?;
        }
        Ok(d)
    }

    /// Stores the file at `path`; returns its digest. The file is read twice (to name it, then to
    /// store it), and refused if it changed in between.
    pub fn put_file(&self, path: &Path) -> io::Result<Digest> {
        self.put_file_len(path).map(|(d, _)| d)
    }

    /// [`Cas::put_file`], and the file's length as it was stored.
    pub(crate) fn put_file_len(&self, path: &Path) -> io::Result<(Digest, u64)> {
        let mut h = Sha256::new();
        let n = io::copy(&mut std::fs::File::open(path)?, &mut HashWrite(&mut h))?;
        let d = Digest(h.finalize().into());
        if self.inner.has(&d.key())? {
            return Ok((d, n));
        }
        let mut hr = HashRead { inner: io::BufReader::new(std::fs::File::open(path)?), h: Sha256::new() };
        let wrote = {
            let mut enc = zstd::stream::read::Encoder::new(&mut hr, ZSTD_LEVEL)?;
            self.inner.put_if_absent(&d.key(), &mut enc)?
        };
        if Digest(hr.h.finalize().into()) != d {
            if wrote {
                self.inner.delete(&d.key())?;
            }
            return Err(invalid(format!("{} changed while it was stored", path.display())));
        }
        Ok((d, n))
    }

    pub fn has(&self, d: &Digest) -> io::Result<bool> {
        self.inner.has(&d.key())
    }

    /// Copies tree `d` and everything it reaches into `to`, by negotiation: an object `to` already
    /// has is skipped, and so is a whole subtree whose tree `to` has, since a tree is only ever sent
    /// after everything under it (the order kept here). Objects move as stored (compressed), and
    /// each one read from `self` is verified against its digest first. Returns the bytes `to` was
    /// sent (as stored) and the objects written.
    pub fn send_tree(&self, to: &Cas, d: &Digest) -> io::Result<(u64, u64)> {
        let mut sent = (0, 0);
        self.send(to, d, Kind::Dir, &mut sent)?;
        Ok(sent)
    }

    fn send(&self, to: &Cas, d: &Digest, kind: Kind, sent: &mut (u64, u64)) -> io::Result<()> {
        if to.has(d)? {
            return Ok(());
        }
        if kind == Kind::Dir {
            let t = self.get_tree(d)?.ok_or_else(|| invalid(format!("tree {d} is missing")))?;
            for e in t.entries() {
                self.send(to, &e.digest, e.kind, sent)?;
            }
        }
        // Verified as plain bytes first (a corrupt local object must not spread), then copied as stored.
        let mut r = self.get(d)?.ok_or_else(|| invalid(format!("object {d} is missing")))?;
        io::copy(&mut r, &mut io::sink())?;
        let mut raw = self.inner.get(&d.key())?.ok_or_else(|| invalid(format!("object {d} is missing")))?;
        let mut counted = Counted { inner: &mut raw, n: 0 };
        if to.inner.put_if_absent(&d.key(), &mut counted)? {
            sent.0 += counted.n;
            sent.1 += 1;
        }
        Ok(())
    }

    /// Opens object `d` for reading, verified as it is read (see the module's notes), or None.
    pub fn get(&self, d: &Digest) -> io::Result<Option<Box<dyn Read + Send>>> {
        let Some(r) = self.inner.get(&d.key())? else { return Ok(None) };
        let inner = zstd::stream::read::Decoder::new(r)?;
        Ok(Some(Box::new(Verified { inner, h: Sha256::new(), want: *d, checked: false })))
    }

    /// Object `d`'s bytes, verified, refusing more than `max`.
    pub fn get_bytes(&self, d: &Digest, max: u64) -> io::Result<Option<Vec<u8>>> {
        let Some(r) = self.get(d)? else { return Ok(None) };
        read_max(r, max, &format!("object {d}")).map(Some)
    }

    /// Deletes object `d`. Only for an object nothing else reaches: see store.md's garbage
    /// collection.
    pub fn delete(&self, d: &Digest) -> io::Result<()> {
        self.inner.delete(&d.key())
    }

    pub fn put_tree(&self, t: &Tree) -> io::Result<Digest> {
        self.put_bytes(&t.encode())
    }

    /// Tree `d`, decoded and checked, or None. An object that isn't a tree is an error.
    pub fn get_tree(&self, d: &Digest) -> io::Result<Option<Tree>> {
        let Some(b) = self.get_bytes(d, TREE_MAX)? else { return Ok(None) };
        Tree::decode(&b).map(Some)
    }

    /// Points ref `name` at `d`, unless it exists. Ok(false): it already existed (unchanged).
    pub fn set_ref(&self, name: &str, d: &Digest) -> io::Result<bool> {
        self.inner.put_if_absent(&ref_key(name)?, &mut format!("{d}\n").as_bytes())
    }

    /// What ref `name` points at, or None.
    pub fn get_ref(&self, name: &str) -> io::Result<Option<Digest>> {
        let Some(r) = self.inner.get(&ref_key(name)?)? else { return Ok(None) };
        let b = read_max(r, REF_MAX, &format!("ref {name}"))?;
        let s = std::str::from_utf8(&b).ok().and_then(|s| s.strip_suffix('\n'));
        s.and_then(Digest::parse).map(Some).ok_or_else(|| invalid(format!("ref {name} doesn't hold a digest")))
    }

    /// The names of the refs under `prefix`, sorted.
    pub fn refs(&self, prefix: &str) -> io::Result<Vec<String>> {
        let mut out: Vec<String> = self
            .inner
            .list_prefix(&format!("{REFS}{prefix}"))?
            .into_iter()
            .filter_map(|k| k.strip_prefix(REFS).map(String::from))
            .collect();
        out.sort();
        Ok(out)
    }

    pub fn delete_ref(&self, name: &str) -> io::Result<()> {
        self.inner.delete(&ref_key(name)?)
    }
}

/// What a tree entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A regular file; its digest is its content's.
    File,
    /// A directory; its digest is its tree's.
    Dir,
    /// A symlink; its digest is its target's (as a blob). Never followed.
    Link,
}

impl Kind {
    fn letter(self) -> char {
        match self {
            Kind::File => 'f',
            Kind::Dir => 'd',
            Kind::Link => 'l',
        }
    }
}

/// One entry of a [`Tree`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    /// Permission bits (`& 0o7777`); always `0o777` for a symlink.
    pub mode: u32,
    /// Unix seconds; always 0 for a symlink.
    pub mtime: i64,
    /// A file's length or a symlink target's; always 0 for a directory.
    pub size: u64,
    pub digest: Digest,
}

const TREE_HEADER: &str = "wicket-tree-v1\n";

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n != "." && n != ".." && !n.contains(['/', '\0', '\n'])
}

/// A directory: its entries, sorted by name (as bytes), each name once.
///
/// Encoded as `wicket-tree-v1\n` and one line per entry, `<f|d|l> <mode, 4 octal digits> <mtime>
/// <size> <digest> <name>\n`. There is one encoding per tree: [`Tree::decode`] refuses any other.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    entries: Vec<Entry>,
}

impl Tree {
    /// A tree of `entries` (in any order), checked.
    pub fn new(mut entries: Vec<Entry>) -> io::Result<Tree> {
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        for w in entries.windows(2) {
            if w[0].name == w[1].name {
                return Err(invalid(format!("tree entry {:?} twice", w[0].name)));
            }
        }
        for e in &entries {
            let ok = valid_name(&e.name)
                && e.mode <= 0o7777
                && match e.kind {
                    Kind::File => true,
                    Kind::Dir => e.size == 0,
                    Kind::Link => e.mode == 0o777 && e.mtime == 0,
                };
            if !ok {
                return Err(invalid(format!("bad tree entry {:?}", e.name)));
            }
        }
        Ok(Tree { entries })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.binary_search_by(|e| e.name.as_bytes().cmp(name.as_bytes())).ok().map(|i| &self.entries[i])
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut s = String::from(TREE_HEADER);
        for e in &self.entries {
            s.push_str(&format!("{} {:04o} {} {} {} {}\n", e.kind.letter(), e.mode, e.mtime, e.size, e.digest, e.name));
        }
        s.into_bytes()
    }

    /// The digest the tree is stored under.
    pub fn digest(&self) -> Digest {
        Digest::of(&self.encode())
    }

    /// Decodes a tree, refusing anything that isn't the one encoding of a valid tree.
    pub fn decode(b: &[u8]) -> io::Result<Tree> {
        let s = std::str::from_utf8(b).map_err(|_| invalid("a tree isn't UTF-8"))?;
        let body = s.strip_prefix(TREE_HEADER).ok_or_else(|| invalid("not a tree"))?;
        let mut entries = Vec::new();
        for line in body.split_terminator('\n') {
            let bad = || invalid(format!("bad tree line {line:?}"));
            let mut f = line.splitn(6, ' ');
            let mut next = || f.next().ok_or_else(bad);
            let kind = match next()? {
                "f" => Kind::File,
                "d" => Kind::Dir,
                "l" => Kind::Link,
                _ => return Err(bad()),
            };
            let mode = u32::from_str_radix(next()?, 8).map_err(|_| bad())?;
            let mtime = next()?.parse::<i64>().map_err(|_| bad())?;
            let size = next()?.parse::<u64>().map_err(|_| bad())?;
            let digest = Digest::parse(next()?).ok_or_else(bad)?;
            let name = next()?.to_string();
            entries.push(Entry { name, kind, mode, mtime, size, digest });
        }
        let t = Tree::new(entries)?;
        if t.encode() != b {
            return Err(invalid("a tree not in its one encoding"));
        }
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::DirStore;
    use crate::sealed::SealedStore;

    fn root(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-cas-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn read(r: Box<dyn Read + Send>) -> io::Result<Vec<u8>> {
        let mut v = vec![];
        let mut r = r;
        r.read_to_end(&mut v)?;
        Ok(v)
    }

    #[test]
    fn digests_are_written_and_parsed_one_way() {
        let d = Digest::of(b"");
        assert_eq!(d.to_string(), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(Digest::parse(&d.to_string()), Some(d));
        for bad in ["", "sha256:", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", &d.to_string().to_uppercase()] {
            assert!(Digest::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn objects_are_stored_once_by_digest_and_verified_when_read() {
        let d = root("objects");
        let cas = Cas::new(DirStore::new(&d));
        let a = cas.put_bytes(b"hello").unwrap();
        assert_eq!(a, Digest::of(b"hello"));
        assert_eq!(cas.put_bytes(b"hello").unwrap(), a);
        assert!(cas.has(&a).unwrap());
        assert_eq!(read(cas.get(&a).unwrap().unwrap()).unwrap(), b"hello");
        // Compressed at rest.
        let raw = std::fs::read(d.join("o").join(a.hex())).unwrap();
        assert_ne!(raw, b"hello");
        // A file, the same way.
        std::fs::write(d.join("f"), vec![7u8; 300_000]).unwrap();
        let f = cas.put_file(&d.join("f")).unwrap();
        assert_eq!(f, Digest::of(&[7u8; 300_000]));
        assert_eq!(cas.get_bytes(&f, 1 << 20).unwrap().unwrap(), vec![7u8; 300_000]);
        assert!(cas.get_bytes(&f, 1000).is_err(), "over the cap");
        // An object whose bytes aren't its name is an error at its end.
        let z = zstd::encode_all(&b"other"[..], 3).unwrap();
        std::fs::write(d.join("o").join(a.hex()), z).unwrap();
        assert!(read(cas.get(&a).unwrap().unwrap()).is_err());
        let none = Digest::of(b"none");
        assert!(!cas.has(&none).unwrap() && cas.get(&none).unwrap().is_none());
        cas.delete(&f).unwrap();
        assert!(!cas.has(&f).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refs_are_write_once_and_checked() {
        let d = root("refs");
        let cas = Cas::new(SealedStore::sealed_only(DirStore::new(&d), &[9u8; 32]));
        let a = cas.put_bytes(b"one").unwrap();
        let b = cas.put_bytes(b"two").unwrap();
        assert!(cas.set_ref("snaps/x.db", &a).unwrap());
        assert!(!cas.set_ref("snaps/x.db", &b).unwrap(), "never rewritten");
        assert_eq!(cas.get_ref("snaps/x.db").unwrap(), Some(a));
        assert!(cas.set_ref("snaps/y.db", &b).unwrap());
        assert_eq!(cas.refs("snaps/").unwrap(), ["snaps/x.db", "snaps/y.db"]);
        assert!(cas.get_ref("snaps/none").unwrap().is_none());
        for bad in ["../x", "/x", "A", ""] {
            assert!(cas.set_ref(bad, &a).is_err() && cas.get_ref(bad).is_err(), "{bad}");
        }
        // A plain ref planted in the backend isn't one.
        DirStore::new(&d).put_if_absent("r/snaps/z.db", &mut format!("{a}\n").as_bytes()).unwrap();
        assert!(cas.get_ref("snaps/z.db").unwrap().is_none());
        assert_eq!(cas.refs("snaps/").unwrap().len(), 2);
        cas.delete_ref("snaps/x.db").unwrap();
        assert_eq!(cas.refs("").unwrap(), ["snaps/y.db"]);
        // Sealed: nothing at rest is the plaintext.
        assert!(std::fs::read(d.join("sealed/r/snaps/y.db")).unwrap().starts_with(b"WKS1"));
        let _ = std::fs::remove_dir_all(&d);
    }

    fn entry(name: &str, kind: Kind, digest: Digest) -> Entry {
        let (mode, mtime, size) = match kind {
            Kind::File => (0o644, 1_763_150_400, 5),
            Kind::Dir => (0o755, 1_763_150_400, 0),
            Kind::Link => (0o777, 0, 3),
        };
        Entry { name: name.into(), kind, mode, mtime, size, digest }
    }

    #[test]
    fn trees_have_one_encoding() {
        let d = root("trees");
        let cas = Cas::new(DirStore::new(&d));
        let f = cas.put_bytes(b"hello").unwrap();
        let sub = Tree::new(vec![entry("a.rs", Kind::File, f)]).unwrap();
        let s = cas.put_tree(&sub).unwrap();
        let l = cas.put_bytes(b"a.rs").unwrap();
        let t = Tree::new(vec![entry("src", Kind::Dir, s), entry("README", Kind::File, f), entry("link", Kind::Link, l)]).unwrap();
        assert_eq!(t.entries().iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["README", "link", "src"]);
        let td = cas.put_tree(&t).unwrap();
        assert_eq!(td, t.digest());
        assert_eq!(cas.get_tree(&td).unwrap().unwrap(), t);
        assert_eq!(t.get("src").unwrap().digest, s);
        assert!(t.get("nope").is_none());
        let text = String::from_utf8(t.encode()).unwrap();
        assert!(text.starts_with("wicket-tree-v1\nf 0644 1763150400 5 sha256:"), "{text}");
        // Not a tree: a plain blob.
        assert!(cas.get_tree(&f).is_err());
        // Any other spelling of the same tree is refused.
        for other in [
            text.replace(" 0644 ", " 644 "),
            text.replace(" 5 ", " 05 "),
            text.replace("wicket-tree-v1\n", "wicket-tree-v2\n"),
            format!("{text}\n"),
            text.trim_end().to_string(),
        ] {
            assert!(Tree::decode(other.as_bytes()).is_err(), "{other}");
        }
        // Out of order.
        let lines: Vec<&str> = text.lines().collect();
        let swapped = format!("{}\n{}\n{}\n{}\n", lines[0], lines[2], lines[1], lines[3]);
        assert!(Tree::decode(swapped.as_bytes()).is_err());
        // Bad entries.
        for e in [
            entry("..", Kind::File, f),
            entry("a/b", Kind::File, f),
            entry("a\nb", Kind::File, f),
            Entry { mode: 0o644, ..entry("l", Kind::Link, l) },
            Entry { size: 1, ..entry("d", Kind::Dir, s) },
            Entry { mode: 0o10000, ..entry("f", Kind::File, f) },
        ] {
            assert!(Tree::new(vec![e.clone()]).is_err(), "{e:?}");
        }
        assert!(Tree::new(vec![entry("x", Kind::File, f), entry("x", Kind::Dir, s)]).is_err(), "a name twice");
        // A name with a space is fine: it is the last field.
        let sp = Tree::new(vec![entry("a b", Kind::File, f)]).unwrap();
        assert_eq!(Tree::decode(&sp.encode()).unwrap(), sp);
        let _ = std::fs::remove_dir_all(&d);
    }
}
