//! Encryption at rest for agent state (#146): [`SealedStore`] wraps an [`ObjectStore`] and seals
//! every object it writes with AES-256-GCM, under a key that stays on the control host.
//!
//! - **Format.** `WKS1`, the key's id (8 bytes: the start of its SHA-256), a random 8-byte nonce
//!   prefix, then chunks of at most [`CHUNK`] bytes of plaintext, each a 4-byte big-endian length and
//!   its ciphertext with the tag. Chunk `i`'s nonce is the prefix and `i`; its associated data is the
//!   object's key, `i` and whether it is the last chunk. So an object can't be read under another
//!   key, nor its chunks reordered, dropped or cut short, without the read failing.
//! - **Keys.** Sealed objects are stored under `sealed/<key>`. Objects written before sealing (plain,
//!   under `<key>`) are still read, so agents hibernated before can wake; anything written from now on
//!   is sealed, and the next hibernation writes the agent's trees sealed again (content-addressed
//!   blobs are re-written under the sealed name, not deduplicated against plain ones).
//! - **What isn't hidden.** Object keys (content hashes, agent ids, sequence numbers) and sizes.
//! - **Another store.** A store that already encrypts at rest itself (S3 with server-side
//!   encryption, say) can be used without this layer; sealing here also keeps the data from whoever
//!   runs that store.

use crate::objects::ObjectStore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use std::io::{self, Read};

/// Plaintext bytes per chunk.
pub const CHUNK: usize = 64 * 1024;
const MAGIC: &[u8; 4] = b"WKS1";
const PREFIX: &str = "sealed/";
const TAG: usize = 16;

/// An object store whose objects are sealed with one 256-bit key.
pub struct SealedStore<S> {
    inner: S,
    raw: [u8; 32],
    kid: [u8; 8],
}

fn kid(key: &[u8; 32]) -> [u8; 8] {
    use sha2::Digest;
    let d = sha2::Sha256::digest(key);
    d[..8].try_into().expect("8 bytes")
}

fn aad(object: &str, i: u32, last: bool) -> Vec<u8> {
    let mut a = Vec::with_capacity(object.len() + 6);
    a.extend_from_slice(object.as_bytes());
    a.push(0);
    a.extend_from_slice(&i.to_be_bytes());
    a.push(last as u8);
    a
}

fn nonce(prefix: &[u8; 8], i: u32) -> Nonce {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(prefix);
    n[8..].copy_from_slice(&i.to_be_bytes());
    Nonce::assume_unique_for_key(n)
}

fn bad(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_string())
}

/// Reads up to `buf.len()` bytes, fewer only at the end.
fn fill(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

impl<S: ObjectStore> SealedStore<S> {
    pub fn new(inner: S, key: &[u8; 32]) -> SealedStore<S> {
        SealedStore { inner, raw: *key, kid: kid(key) }
    }

    /// `data`, sealed for object `object`, as it is read.
    fn sealer<'a>(&self, object: &str, data: &'a mut dyn Read) -> io::Result<Sealer<'a>> {
        let mut prefix = [0u8; 8];
        getrandom::getrandom(&mut prefix).map_err(|e| io::Error::other(format!("random: {e}")))?;
        let mut head = Vec::with_capacity(20);
        head.extend_from_slice(MAGIC);
        head.extend_from_slice(&self.kid);
        head.extend_from_slice(&prefix);
        let mut s = Sealer {
            data,
            key: self.key_clone(),
            object: object.into(),
            prefix,
            i: 0,
            next: vec![0u8; CHUNK],
            next_len: 0,
            out: head,
            pos: 0,
            done: false,
        };
        s.next_len = fill(s.data, &mut s.next)?;
        Ok(s)
    }
}

/// Seals an object as it is read: one chunk of plaintext read ahead, to know which is the last.
struct Sealer<'a> {
    data: &'a mut dyn Read,
    key: LessSafeKey,
    object: String,
    prefix: [u8; 8],
    i: u32,
    next: Vec<u8>,
    next_len: usize,
    out: Vec<u8>,
    pos: usize,
    done: bool,
}

impl Read for Sealer<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.out.len() {
            if self.done {
                return Ok(0);
            }
            let mut chunk = std::mem::replace(&mut self.next, vec![0u8; CHUNK]);
            chunk.truncate(self.next_len);
            self.next_len = if chunk.len() == CHUNK { fill(self.data, &mut self.next)? } else { 0 };
            let last = self.next_len == 0;
            self.key
                .seal_in_place_append_tag(nonce(&self.prefix, self.i), Aad::from(aad(&self.object, self.i, last)), &mut chunk)
                .map_err(|_| io::Error::other("sealing failed"))?;
            self.out.clear();
            self.out.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
            self.out.extend_from_slice(&chunk);
            self.pos = 0;
            self.done = last;
            self.i = self.i.checked_add(1).ok_or_else(|| bad("object too large"))?;
        }
        let n = buf.len().min(self.out.len() - self.pos);
        buf[..n].copy_from_slice(&self.out[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Opens a sealed object as it is read: each chunk is checked before any of it is returned.
struct Opener {
    inner: Box<dyn Read + Send>,
    key: LessSafeKey,
    object: String,
    prefix: [u8; 8],
    i: u32,
    buf: Vec<u8>,
    pos: usize,
    done: bool,
}

impl Opener {
    fn next_chunk(&mut self) -> io::Result<()> {
        let mut len = [0u8; 4];
        if fill(&mut *self.inner, &mut len)? != 4 {
            return Err(bad("sealed object cut short"));
        }
        let len = u32::from_be_bytes(len) as usize;
        if !(TAG..=CHUNK + TAG).contains(&len) {
            return Err(bad("sealed object chunk length out of range"));
        }
        let mut c = vec![0u8; len];
        if fill(&mut *self.inner, &mut c)? != len {
            return Err(bad("sealed object cut short"));
        }
        // The last chunk says so in its associated data: try it as one, then as not.
        let mut opened = None;
        for last in [false, true] {
            let mut t = c.clone();
            if let Ok(p) = self.key.open_in_place(nonce(&self.prefix, self.i), Aad::from(aad(&self.object, self.i, last)), &mut t) {
                opened = Some((p.len(), last));
                c = t;
                break;
            }
        }
        let (n, last) = opened.ok_or_else(|| bad("sealed object fails authentication (tampered, or another key)"))?;
        c.truncate(n);
        if last {
            let mut probe = [0u8; 1];
            if fill(&mut *self.inner, &mut probe)? != 0 {
                return Err(bad("data after a sealed object's last chunk"));
            }
            self.done = true;
        }
        self.buf = c;
        self.pos = 0;
        self.i = self.i.checked_add(1).ok_or_else(|| bad("object too large"))?;
        Ok(())
    }
}

impl Read for Opener {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.buf.len() {
            if self.done {
                return Ok(0);
            }
            self.next_chunk()?;
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<S: ObjectStore> ObjectStore for SealedStore<S> {
    fn put_if_absent(&self, key: &str, data: &mut dyn Read) -> io::Result<bool> {
        let name = format!("{PREFIX}{key}");
        if self.inner.get(&name)?.is_some() {
            return Ok(false);
        }
        let mut sealed = self.sealer(key, data)?;
        self.inner.put_if_absent(&name, &mut sealed)
    }

    fn get(&self, key: &str) -> io::Result<Option<Box<dyn Read + Send>>> {
        let Some(mut r) = self.inner.get(&format!("{PREFIX}{key}"))? else {
            // Written before objects were sealed.
            return self.inner.get(key);
        };
        let mut head = [0u8; 20];
        if fill(&mut *r, &mut head)? != 20 || &head[..4] != MAGIC {
            return Err(bad("not a sealed object"));
        }
        if head[4..12] != self.kid {
            return Err(bad("sealed under another key"));
        }
        let prefix: [u8; 8] = head[12..20].try_into().expect("8 bytes");
        let key2 = self.key_clone();
        Ok(Some(Box::new(Opener { inner: r, key: key2, object: key.into(), prefix, i: 0, buf: vec![], pos: 0, done: false })))
    }

    fn delete(&self, key: &str) -> io::Result<()> {
        self.inner.delete(&format!("{PREFIX}{key}"))?;
        self.inner.delete(key)
    }

    fn list_prefix(&self, prefix: &str) -> io::Result<Vec<String>> {
        let mut out: Vec<String> =
            self.inner.list_prefix(&format!("{PREFIX}{prefix}"))?.into_iter().map(|k| k[PREFIX.len()..].to_string()).collect();
        out.extend(self.inner.list_prefix(prefix)?.into_iter().filter(|k| !k.starts_with(PREFIX)));
        out.sort();
        out.dedup();
        Ok(out)
    }
}

impl<S> SealedStore<S> {
    /// The key again, for a reader that outlives this borrow.
    fn key_clone(&self) -> LessSafeKey {
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &self.raw).expect("a 32-byte key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::DirStore;

    fn store(tag: &str) -> (SealedStore<DirStore>, std::path::PathBuf) {
        let d = std::env::temp_dir().join(format!("wicket-sealed-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        (SealedStore::new(DirStore::new(&d), &[7u8; 32]), d)
    }

    fn read(s: &dyn ObjectStore, k: &str) -> io::Result<Vec<u8>> {
        let mut v = vec![];
        s.get(k)?.expect("present").read_to_end(&mut v)?;
        Ok(v)
    }

    #[test]
    fn objects_are_sealed_at_rest_and_read_back_whole() {
        let (s, d) = store("roundtrip");
        for (k, len) in [("a/empty", 0usize), ("a/small", 10), ("a/exact", CHUNK), ("a/big", 3 * CHUNK + 17)] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert!(s.put_if_absent(k, &mut &data[..]).unwrap());
            assert!(!s.put_if_absent(k, &mut &data[..]).unwrap(), "put-if-absent");
            assert_eq!(read(&s, k).unwrap(), data, "{k}");
            let raw = std::fs::read(d.join("sealed").join(k)).unwrap();
            assert!(raw.starts_with(MAGIC));
            if len >= 10 {
                assert!(!raw.windows(10).any(|w| w == &data[..10]), "{k}: plaintext at rest");
            }
        }
        assert_eq!(s.list_prefix("a/").unwrap(), ["a/big", "a/empty", "a/exact", "a/small"]);
        s.delete("a/small").unwrap();
        assert!(s.get("a/small").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_swapped_cut_or_foreign_objects_are_refused() {
        let (s, d) = store("tamper");
        let data = vec![5u8; 2 * CHUNK + 3];
        s.put_if_absent("x/one", &mut &data[..]).unwrap();
        s.put_if_absent("x/two", &mut &data[..]).unwrap();
        let p = d.join("sealed/x/one");
        let good = std::fs::read(&p).unwrap();
        let reread = |bytes: &[u8]| {
            std::fs::write(&p, bytes).unwrap();
            read(&s, "x/one")
        };
        let mut flipped = good.clone();
        flipped[40] ^= 1;
        assert!(reread(&flipped).is_err(), "a flipped bit");
        assert!(reread(&good[..good.len() - 100]).is_err(), "cut inside a chunk");
        let first = 20 + 4 + CHUNK + TAG;
        assert!(reread(&good[..first]).is_err(), "cut at a chunk boundary");
        assert!(reread(&std::fs::read(d.join("sealed/x/two")).unwrap()).is_err(), "another object's ciphertext");
        let mut extra = good.clone();
        extra.push(0);
        assert!(reread(&extra).is_err(), "trailing bytes");
        assert_eq!(reread(&good).unwrap(), data);
        let other = SealedStore::new(DirStore::new(&d), &[8u8; 32]);
        assert!(read(&other, "x/one").is_err(), "another key");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn objects_written_before_sealing_are_still_read() {
        let (s, d) = store("legacy");
        DirStore::new(&d).put_if_absent("old/blob", &mut &b"plain"[..]).unwrap();
        assert_eq!(read(&s, "old/blob").unwrap(), b"plain");
        assert_eq!(s.list_prefix("old/").unwrap(), ["old/blob"]);
        // Written again from now on: sealed, under its sealed name.
        assert!(s.put_if_absent("old/blob", &mut &b"plain"[..]).unwrap());
        assert!(std::fs::read(d.join("sealed/old/blob")).unwrap().starts_with(MAGIC));
        let _ = std::fs::remove_dir_all(&d);
    }
}
