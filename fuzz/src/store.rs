//! Target 5: the store's trees, and `Cas::checkout` (what restores a hibernated agent's state, and
//! whatever else a box's bytes become a tree of).
//!
//! An input starting with `D` is a raw tree object for `Tree::decode`: one that decodes must
//! re-encode to exactly its bytes (one encoding per tree). Otherwise the input describes objects, one
//! per line, which are stored in an in-memory store:
//!
//! - `b<bytes>`: a blob (a file's content, or a symlink's target);
//! - `t<entry>;<entry>;…`: a tree in the store's text format, each entry
//!   `<f|d|l> <mode> <mtime> <size|=> <object index> <name>` (`=`: the object's real size), written
//!   as given (it needn't be valid: the store must refuse it then);
//! - `x<index>`: the object at that index is tampered with in the store (its bytes replaced).
//!
//! The last tree is checked out into a fresh directory beside a sentinel directory. The oracle: no
//! panic; nothing is written outside the target (the sentinel stays empty, and nothing appears
//! beside the target); every file checked out holds the bytes of an object that wasn't tampered
//! with (every object read is verified), and only if checkout succeeded is that required.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use wicket_store::cas::{Cas, Digest, Tree};
use wicket_store::objects::ObjectStore;

/// Objects in memory.
#[derive(Default)]
struct Mem(Mutex<HashMap<String, Vec<u8>>>);

impl ObjectStore for &'static Mem {
    fn put_if_absent(&self, key: &str, data: &mut dyn Read) -> io::Result<bool> {
        let mut m = self.0.lock().unwrap();
        if m.contains_key(key) {
            return Ok(false);
        }
        let mut v = Vec::new();
        data.read_to_end(&mut v)?;
        m.insert(key.to_string(), v);
        Ok(true)
    }
    fn get(&self, key: &str) -> io::Result<Option<Box<dyn Read + Send>>> {
        Ok(self.0.lock().unwrap().get(key).cloned().map(|v| Box::new(io::Cursor::new(v)) as Box<dyn Read + Send>))
    }
    fn delete(&self, key: &str) -> io::Result<()> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
    fn list_prefix(&self, prefix: &str) -> io::Result<Vec<String>> {
        Ok(self.0.lock().unwrap().keys().filter(|k| k.starts_with(prefix)).cloned().collect())
    }
}

fn mem() -> &'static Mem {
    static M: OnceLock<Mem> = OnceLock::new();
    M.get_or_init(Mem::default)
}

fn base() -> &'static Path {
    static B: OnceLock<std::path::PathBuf> = OnceLock::new();
    B.get_or_init(|| crate::util::scratch("store"))
}

pub fn run(data: &[u8]) {
    if let Some(raw) = data.strip_prefix(b"D") {
        if let Ok(t) = Tree::decode(raw) {
            assert_eq!(t.encode(), raw, "a tree decoded from bytes that aren't its one encoding");
            assert_eq!(Tree::decode(&t.encode()).ok().as_ref(), Some(&t));
        }
        return;
    }
    let m = mem();
    m.0.lock().unwrap().clear();
    let cas = Cas::new(m);
    let mut objects: Vec<(Digest, Vec<u8>)> = Vec::new();
    let mut tampered: HashSet<usize> = HashSet::new();
    let mut root = None;
    for line in data.split(|b| *b == b'\n') {
        let Some((&tag, rest)) = line.split_first() else { continue };
        match tag {
            b'b' => {
                let d = cas.put_bytes(rest).expect("put");
                objects.push((d, rest.to_vec()));
            }
            b't' => {
                let Ok(text) = std::str::from_utf8(rest) else { continue };
                let mut s = String::from("wicket-tree-v1\n");
                for e in text.split(';').filter(|e| !e.is_empty()) {
                    let f: Vec<&str> = e.splitn(6, ' ').collect();
                    if f.len() != 6 {
                        continue;
                    }
                    let Some((d, bytes)) = f[4].parse::<usize>().ok().and_then(|i| objects.get(i)) else { continue };
                    let size = if f[3] == "=" { bytes.len().to_string() } else { f[3].to_string() };
                    s.push_str(&format!("{} {} {} {} {} {}\n", f[0], f[1], f[2], size, d, f[5]));
                }
                let d = cas.put_bytes(s.as_bytes()).expect("put");
                objects.push((d, s.into_bytes()));
                root = Some(objects.len() - 1);
            }
            b'x' => {
                let Some(i) = std::str::from_utf8(rest).ok().and_then(|s| s.trim().parse::<usize>().ok()) else { continue };
                let Some((d, bytes)) = objects.get(i) else { continue };
                let mut other = bytes.clone();
                other.push(b'!');
                let z = zstd::encode_all(&other[..], 3).expect("zstd");
                m.0.lock().unwrap().insert(format!("o/{}", d.hex()), z);
                tampered.insert(i);
            }
            _ => {}
        }
    }
    let Some(root) = root else { return };
    let dir = base().join("run");
    reset(&dir);
    std::fs::create_dir_all(dir.join("outside")).expect("sentinel");
    let dest = dir.join("dest");
    let ok = cas.checkout(&objects[root].0, &dest).is_ok();
    // Nothing beside the target, nothing in the sentinel.
    let mut beside: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    beside.sort();
    assert!(beside == ["dest", "outside"] || beside == ["outside"], "checkout wrote beside its target: {beside:?}");
    assert!(std::fs::read_dir(dir.join("outside")).unwrap().next().is_none(), "checkout wrote outside its target");
    if ok {
        let verified: HashSet<&[u8]> =
            objects.iter().enumerate().filter(|(i, _)| !tampered.contains(i)).map(|(_, (_, b))| b.as_slice()).collect();
        walk(&dest, &mut |p| {
            let got = std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            assert!(verified.contains(got.as_slice()), "{} holds bytes no verified object has: {got:?}", p.display());
        });
    }
    reset(&dir);
}

/// Every regular file under `d` (symlinks not followed).
fn walk(d: &Path, f: &mut dyn FnMut(&Path)) {
    let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
    let Ok(rd) = std::fs::read_dir(d) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
        if m.is_dir() {
            walk(&p, f);
        } else if m.is_file() {
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            f(&p);
        }
    }
}

/// Removes `d`, whatever modes the checkout left on what is inside it.
fn reset(d: &Path) {
    if d.exists() {
        walk(d, &mut |_| {});
        std::fs::remove_dir_all(d).unwrap_or_else(|e| panic!("removing {}: {e}", d.display()));
    }
}
