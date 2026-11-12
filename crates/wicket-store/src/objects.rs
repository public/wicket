//! Object storage for agent state (#70, design §13.5). wicket only ever needs put-if-absent, get,
//! delete and (for garbage collection) a prefix listing, so any S3-compatible store fits later
//! (`If-None-Match: *` on S3, R2 and GCS). Objects are immutable once written: blobs are
//! content-addressed, and a manifest's key names its sequence number and generation. The ledger's
//! pointer to the head manifest is the truth; wakes never list the store.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub trait ObjectStore: Send + Sync {
    /// Writes `key` from `data` unless it exists. Ok(false): it already existed (unchanged).
    fn put_if_absent(&self, key: &str, data: &mut dyn Read) -> io::Result<bool>;
    /// Opens `key` for reading, or None if there is no such object.
    fn get(&self, key: &str) -> io::Result<Option<Box<dyn Read + Send>>>;
    fn delete(&self, key: &str) -> io::Result<()>;
    /// Every key under `prefix` (garbage collection only).
    fn list_prefix(&self, prefix: &str) -> io::Result<Vec<String>>;
}

/// Object keys: relative, `/`-separated, of `[a-z0-9_.-]` segments, no `.` or `..` segment.
pub fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 512
        && key.split('/').all(|s| {
            !s.is_empty() && s != "." && s != ".." && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-".contains(c))
        })
}

fn bad_key(key: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("bad object key {key:?}"))
}

/// A directory as an object store: one file per object, written to a temporary name and then
/// hard-linked into place, which fails if the key exists (an atomic put-if-absent).
#[derive(Clone, Debug)]
pub struct DirStore {
    root: PathBuf,
}

impl DirStore {
    pub fn new(root: impl Into<PathBuf>) -> DirStore {
        DirStore { root: root.into() }
    }

    fn path(&self, key: &str) -> io::Result<PathBuf> {
        if !valid_key(key) {
            return Err(bad_key(key));
        }
        Ok(self.root.join(key))
    }
}

impl ObjectStore for DirStore {
    fn put_if_absent(&self, key: &str, data: &mut dyn Read) -> io::Result<bool> {
        let dest = self.path(key)?;
        if dest.exists() {
            return Ok(false);
        }
        let dir = dest.parent().expect("a key has a parent");
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".tmp-{}-{}", std::process::id(), ulid::Ulid::new()));
        let res = (|| {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            io::copy(data, &mut f)?;
            f.flush()?;
            f.sync_all()?;
            match std::fs::hard_link(&tmp, &dest) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
                Err(e) => Err(e),
            }
        })();
        let _ = std::fs::remove_file(&tmp);
        res
    }

    fn get(&self, key: &str) -> io::Result<Option<Box<dyn Read + Send>>> {
        match std::fs::File::open(self.path(key)?) {
            Ok(f) => Ok(Some(Box::new(io::BufReader::new(f)))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn delete(&self, key: &str) -> io::Result<()> {
        match std::fs::remove_file(self.path(key)?) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    fn list_prefix(&self, prefix: &str) -> io::Result<Vec<String>> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> io::Result<()> {
            let rd = match std::fs::read_dir(dir) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            for e in rd {
                let e = e?;
                let p = e.path();
                if e.file_type()?.is_dir() {
                    walk(root, &p, out)?;
                } else if !e.file_name().to_string_lossy().starts_with(".tmp-") {
                    if let Ok(rel) = p.strip_prefix(root) {
                        out.push(rel.to_string_lossy().into_owned());
                    }
                }
            }
            Ok(())
        }
        let mut out = Vec::new();
        walk(&self.root, &self.root, &mut out)?;
        out.retain(|k| k.starts_with(prefix));
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_if_absent_never_overwrites_and_keys_stay_inside() {
        let root = std::env::temp_dir().join(format!("wicket-objects-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let s = DirStore::new(&root);
        assert!(s.put_if_absent("a/agt_x/p/abc", &mut &b"one"[..]).unwrap());
        assert!(!s.put_if_absent("a/agt_x/p/abc", &mut &b"two"[..]).unwrap());
        let mut got = String::new();
        s.get("a/agt_x/p/abc").unwrap().unwrap().read_to_string(&mut got).unwrap();
        assert_eq!(got, "one");
        assert!(s.get("a/agt_x/p/none").unwrap().is_none());
        for bad in ["../x", "/etc/passwd", "a//b", "a/./b", "A/b", ""] {
            assert!(s.put_if_absent(bad, &mut &b""[..]).is_err(), "{bad}");
        }
        assert_eq!(s.list_prefix("a/agt_x/").unwrap(), vec!["a/agt_x/p/abc".to_string()]);
        s.delete("a/agt_x/p/abc").unwrap();
        s.delete("a/agt_x/p/abc").unwrap();
        assert!(s.list_prefix("").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
