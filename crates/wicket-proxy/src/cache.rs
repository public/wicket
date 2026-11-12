//! A read-through cache on each node for package registries and images (#139).
//!
//! The egress proxy asks this module about a request only after the request has been decided and
//! allowed, and its audit row written: the cache sits behind the decision, never in front of it. A
//! hit is a decided, audited request like any other; its audit row says it was served from the cache.
//!
//! **What is cached.** Only immutable objects, and only ones whose bytes can be checked:
//!
//! - named by digest in the URL, verified against that digest on the way in and out: OCI blobs
//!   (`/v2/<name>/blobs/sha256:<hex>`), apt indexes and packages fetched `by-hash/SHA256/<hex>`, and
//!   PyPI files (`files.pythonhosted.org/packages/<aa>/<bb>/<rest>/<file>`, whose path is the file's
//!   BLAKE2b-256);
//! - immutable by the registry's own rule, over HTTPS only: crate files on `static.crates.io` and npm
//!   tarballs on the npm registry. Their digest is taken when they are filled (trust on first use,
//!   over the registry's authenticated TLS) and checked on every hit; cargo and npm also check them
//!   against their own indexes.
//!
//! Index and metadata responses are never cached. Neither is anything with a query string, a
//! partial or conditional request, a response that isn't a complete `200`, or one that sets a
//! cookie, is marked private or `no-store`, or carries a content encoding.
//!
//! **Only anonymous requests.** A request that carries a credential (the box's own `Authorization`
//! or `Cookie`, a credential the zone injects for its host, or a swapped placeholder) is never
//! answered from the cache and never fills it.
//!
//! **Shared storage, per-tenant visibility.** Object bytes are stored once per node, by SHA-256, but
//! each tenant has its own index: a tenant gets a hit only for an object it has fetched itself
//! before. Another tenant's fetch of the same object goes upstream at full cost, so the cache's
//! timing never says what another tenant fetched. The node's size limit is shared, with
//! least-recently-used eviction.
//!
//! The store is a directory: `blobs/<aa>/<sha256>`, `tmp/` for fills in progress, and an SQLite index
//! (`index.sqlite`, WAL) that several processes on the node can share.

use crate::BoxBody;
use bytes::Bytes;
use futures_util::StreamExt;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::body::Frame;
use sha2::Digest as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Hosts whose objects the cache can serve but which a zone may allow wholesale: while the cache is
/// on, they are inspected rather than spliced, or the proxy would never see their requests. Their
/// index hosts (`index.crates.io`, the npm registry's metadata) are not cached and may stay spliced
/// (`index.crates.io`; the npm registry serves both from one host).
pub const INSPECTED_HOSTS: &[&str] = &["static.crates.io", "registry.npmjs.org", "registry.yarnpkg.com", "files.pythonhosted.org"];

/// The response headers kept with an object and given back on a hit.
const KEPT_HEADERS: &[&str] = &["content-type", "etag", "last-modified", "cache-control", "content-disposition"];

/// Request headers that make a request uncacheable: credentials, and partial or conditional requests.
const BYPASS_REQUEST: &[&str] =
    &["authorization", "cookie", "proxy-authorization", "range", "if-match", "if-none-match", "if-modified-since", "if-range", "if-unmodified-since"];

/// How the node's cache is set up.
#[derive(Clone, Debug)]
pub struct Config {
    pub dir: PathBuf,
    /// The most the store may hold, in bytes. Objects over a quarter of this are not cached.
    pub max_bytes: u64,
}

impl Config {
    /// The default size limit.
    pub const DEFAULT_MAX: u64 = 8 << 30;

    /// From the environment: `WICKET_CACHE=off` turns the cache off; `WICKET_CACHE_DIR` moves it
    /// from `default_dir`; `WICKET_CACHE_MAX` sets the limit (`512M`, `20G`, or bytes).
    pub fn from_env(default_dir: &Path) -> anyhow::Result<Option<Config>> {
        if matches!(std::env::var("WICKET_CACHE").as_deref(), Ok("off" | "0" | "false" | "no")) {
            return Ok(None);
        }
        let dir = std::env::var_os("WICKET_CACHE_DIR").map(PathBuf::from).unwrap_or_else(|| default_dir.to_path_buf());
        let max_bytes = match std::env::var("WICKET_CACHE_MAX") {
            Ok(v) => parse_size(&v).ok_or_else(|| anyhow::anyhow!("WICKET_CACHE_MAX={v:?}: expected bytes, or a number with K, M or G"))?,
            Err(_) => Self::DEFAULT_MAX,
        };
        Ok(Some(Config { dir, max_bytes }))
    }
}

/// `123`, `512K`, `64M`, `8G` (powers of 1024).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, shift) = match s.char_indices().last()? {
        (i, 'k' | 'K') => (&s[..i], 10),
        (i, 'm' | 'M') => (&s[..i], 20),
        (i, 'g' | 'G') => (&s[..i], 30),
        (i, 't' | 'T') => (&s[..i], 40),
        _ => (s, 0),
    };
    num.trim().parse::<u64>().ok()?.checked_mul(1u64 << shift)
}

/// What an object's bytes are checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trust {
    /// The URL names the object's SHA-256.
    Sha256([u8; 32]),
    /// The URL names the object's BLAKE2b-256 (PyPI).
    Blake2b([u8; 32]),
    /// Immutable by the registry's rule; the digest is taken on the first fill (HTTPS only).
    FirstUse,
}

/// A cacheable object: its kind (for statistics and the audit detail), its identity, and how its
/// bytes are checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub kind: &'static str,
    /// `scheme://host/path`.
    pub id: String,
    pub trust: Trust,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// A crate or package name, or a version: no separators, no dot segments.
fn plain(seg: &str) -> bool {
    !seg.is_empty() && seg != "." && seg != ".." && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.+~".contains(&b))
}

/// Which object, if any, a request names. `path` is the decided (canonical) path; anything with a
/// query is not an object.
pub fn classify(scheme: &str, host: &str, path: &str, query: &str) -> Option<Key> {
    if !query.is_empty() || !matches!(scheme, "http" | "https") {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let id = format!("{scheme}://{host}{path}");
    let segs: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
    let key = |kind: &'static str, trust: Trust| Some(Key { kind, id: id.clone(), trust });
    // Digest-named objects, on any host.
    if let Some((_, tail)) = path.rsplit_once("/blobs/sha256:") {
        if path.starts_with("/v2/") && !tail.contains('/') {
            return key("oci", Trust::Sha256(hex32(tail)?));
        }
    }
    if let [.., "by-hash", "SHA256", h] = segs.as_slice() {
        return key("apt", Trust::Sha256(hex32(h)?));
    }
    match host.as_str() {
        "files.pythonhosted.org" => match segs.as_slice() {
            ["packages", a, b, rest, file] if a.len() == 2 && b.len() == 2 && rest.len() == 60 && plain(file) => {
                key("pypi", Trust::Blake2b(hex32(&format!("{a}{b}{rest}"))?))
            }
            _ => None,
        },
        "static.crates.io" if scheme == "https" => match segs.as_slice() {
            ["crates", name, file] if plain(name) && file.strip_prefix(&format!("{name}-")).is_some_and(|v| v.ends_with(".crate") && plain(v)) => {
                key("crate", Trust::FirstUse)
            }
            _ => None,
        },
        "registry.npmjs.org" | "registry.yarnpkg.com" if scheme == "https" => {
            let (name, file) = match segs.as_slice() {
                [name, "-", file] => (*name, *file),
                [scope, name, "-", file] if scope.starts_with('@') && plain(&scope[1..]) => (*name, *file),
                _ => return None,
            };
            (plain(name) && plain(file) && file.starts_with(&format!("{name}-")) && file.ends_with(".tgz")).then_some(())?;
            key("npm", Trust::FirstUse)
        }
        _ => None,
    }
}

/// Counters since the process started.
#[derive(Default, Debug)]
pub struct Stats {
    pub hits: AtomicU64,
    pub hit_bytes: AtomicU64,
    pub misses: AtomicU64,
    pub fills: AtomicU64,
    pub fill_bytes: AtomicU64,
    /// Fills or hits whose bytes didn't match: never stored, or evicted and refused.
    pub mismatches: AtomicU64,
    pub evicted_bytes: AtomicU64,
}

/// The node's cache.
pub struct Cache {
    dir: PathBuf,
    max_bytes: u64,
    db: Mutex<rusqlite::Connection>,
    pub stats: Stats,
}

/// What to do with one request.
pub enum Lookup {
    /// Not a cacheable request: forward it as usual.
    Bypass,
    /// Served from the cache.
    Hit(Hit),
    /// Forward it, and fill the cache from the response.
    Miss(Fill),
}

/// An object found in the cache, already open.
pub struct Hit {
    cache: Arc<Cache>,
    tenant: String,
    key: Key,
    sha256: [u8; 32],
    size: u64,
    headers: Vec<(String, String)>,
    file: std::fs::File,
}

/// A miss to fill from the upstream response.
pub struct Fill {
    cache: Arc<Cache>,
    tenant: String,
    key: Key,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn boxed(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Box<dyn std::error::Error + Send + Sync> {
    e.into()
}

impl Cache {
    /// Opens (or creates) the store in `cfg.dir`.
    pub fn open(cfg: &Config) -> anyhow::Result<Arc<Cache>> {
        std::fs::create_dir_all(cfg.dir.join("blobs"))?;
        std::fs::create_dir_all(cfg.dir.join("tmp"))?;
        let db = rusqlite::Connection::open(cfg.dir.join("index.sqlite"))?;
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS blobs (sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, used INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS blobs_used ON blobs(used);
             CREATE TABLE IF NOT EXISTS entries (tenant TEXT NOT NULL, key TEXT NOT NULL, sha256 TEXT NOT NULL,
                 headers TEXT NOT NULL, PRIMARY KEY (tenant, key));
             CREATE INDEX IF NOT EXISTS entries_blob ON entries(sha256);",
        )?;
        // Fills a crashed process left behind.
        if let Ok(rd) = std::fs::read_dir(cfg.dir.join("tmp")) {
            let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(24 * 3600);
            for e in rd.flatten() {
                if e.metadata().and_then(|m| m.modified()).is_ok_and(|t| t < stale) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        Ok(Arc::new(Cache { dir: cfg.dir.clone(), max_bytes: cfg.max_bytes, db: Mutex::new(db), stats: Stats::default() }))
    }

    /// The largest object the cache stores.
    pub fn max_object(&self) -> u64 {
        self.max_bytes / 4
    }

    /// Whether `host` is kept inspected (not spliced) so the cache can see its requests.
    pub fn keeps_inspected(&self, host: &str) -> bool {
        INSPECTED_HOSTS.iter().any(|h| h.eq_ignore_ascii_case(host))
    }

    fn blob_path(&self, sha: &str) -> PathBuf {
        self.dir.join("blobs").join(&sha[..2]).join(sha)
    }

    /// The bytes the store holds.
    pub fn used_bytes(&self) -> u64 {
        let db = self.db.lock().unwrap_or_else(|p| p.into_inner());
        db.query_row("SELECT COALESCE(SUM(size), 0) FROM blobs", [], |r| r.get::<_, i64>(0)).map(|n| n as u64).unwrap_or(0)
    }

    /// What to do with an allowed request. `credentialed` is true when the zone or the run attaches a
    /// credential to the host (an injected secret or a swap); `headers` are the box's own.
    pub async fn lookup(
        self: &Arc<Self>,
        tenant: &str,
        method: &str,
        scheme: &str,
        host: &str,
        path: &str,
        query: &str,
        headers: &HeaderMap,
        credentialed: bool,
    ) -> Lookup {
        if method != "GET" || credentialed || BYPASS_REQUEST.iter().any(|h| headers.contains_key(*h)) {
            return Lookup::Bypass;
        }
        let Some(key) = classify(scheme, host, path, query) else { return Lookup::Bypass };
        let me = self.clone();
        let tenant = tenant.to_string();
        let found = tokio::task::spawn_blocking(move || {
            let r = me.find(&tenant, &key);
            (me, tenant, key, r)
        })
        .await;
        let Ok((me, tenant, key, r)) = found else { return Lookup::Bypass };
        match r {
            Ok(Some((sha256, size, headers, file))) => {
                Lookup::Hit(Hit { cache: me, tenant, key, sha256, size, headers, file })
            }
            Ok(None) => {
                me.stats.misses.fetch_add(1, Ordering::Relaxed);
                Lookup::Miss(Fill { cache: me, tenant, key })
            }
            Err(e) => {
                tracing::warn!(error = %e, "cache index unreadable; forwarding");
                Lookup::Bypass
            }
        }
    }

    /// The tenant's entry for `key`, its blob opened. A missing blob file drops the entry.
    #[allow(clippy::type_complexity)]
    fn find(&self, tenant: &str, key: &Key) -> rusqlite::Result<Option<([u8; 32], u64, Vec<(String, String)>, std::fs::File)>> {
        let db = self.db.lock().unwrap_or_else(|p| p.into_inner());
        let row: Option<(String, String, i64)> = db
            .query_row(
                "SELECT e.sha256, e.headers, b.size FROM entries e JOIN blobs b ON b.sha256 = e.sha256 WHERE e.tenant = ?1 AND e.key = ?2",
                rusqlite::params![tenant, key.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map(Some)
            .or_else(|e| if e == rusqlite::Error::QueryReturnedNoRows { Ok(None) } else { Err(e) })?;
        let Some((sha, headers, size)) = row else { return Ok(None) };
        let (Some(digest), Ok(file)) = (hex32(&sha), std::fs::File::open(self.blob_path(&sha))) else {
            db.execute("DELETE FROM entries WHERE tenant = ?1 AND key = ?2", rusqlite::params![tenant, key.id])?;
            return Ok(None);
        };
        db.execute("UPDATE blobs SET used = ?1 WHERE sha256 = ?2", rusqlite::params![now(), sha])?;
        let headers: Vec<(String, String)> = serde_json::from_str(&headers).unwrap_or_default();
        Ok(Some((digest, size as u64, headers, file)))
    }

    /// Drops a tenant's entry (its bytes didn't match), and the blob with it.
    fn evict_entry(&self, tenant: &str, key: &str, sha: &str) {
        let db = self.db.lock().unwrap_or_else(|p| p.into_inner());
        let _ = db.execute("DELETE FROM entries WHERE tenant = ?1 AND key = ?2", rusqlite::params![tenant, key]);
        let _ = db.execute("DELETE FROM entries WHERE sha256 = ?1", rusqlite::params![sha]);
        let _ = db.execute("DELETE FROM blobs WHERE sha256 = ?1", rusqlite::params![sha]);
        let _ = std::fs::remove_file(self.blob_path(sha));
    }

    /// Moves a verified fill into the store and records it for the tenant, then evicts down to the
    /// limit.
    fn commit(&self, tmp: &Path, sha: &str, size: u64, tenant: &str, key: &str, headers: &str) -> anyhow::Result<()> {
        let dest = self.blob_path(sha);
        std::fs::create_dir_all(dest.parent().expect("blob path has a parent"))?;
        std::fs::rename(tmp, &dest)?;
        {
            let mut db = self.db.lock().unwrap_or_else(|p| p.into_inner());
            let tx = db.transaction()?;
            tx.execute(
                "INSERT INTO blobs (sha256, size, used) VALUES (?1, ?2, ?3) ON CONFLICT(sha256) DO UPDATE SET used = excluded.used",
                rusqlite::params![sha, size as i64, now()],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO entries (tenant, key, sha256, headers) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![tenant, key, sha, headers],
            )?;
            tx.commit()?;
        }
        self.evict()
    }

    /// Evicts least-recently-used objects until the store is within its limit.
    pub fn evict(&self) -> anyhow::Result<()> {
        let mut db = self.db.lock().unwrap_or_else(|p| p.into_inner());
        let mut used: i64 = db.query_row("SELECT COALESCE(SUM(size), 0) FROM blobs", [], |r| r.get(0))?;
        if used as u64 <= self.max_bytes {
            return Ok(());
        }
        let tx = db.transaction()?;
        let mut gone = vec![];
        {
            let mut q = tx.prepare("SELECT sha256, size FROM blobs ORDER BY used ASC")?;
            let mut rows = q.query([])?;
            while used as u64 > self.max_bytes {
                let Some(r) = rows.next()? else { break };
                let (sha, size): (String, i64) = (r.get(0)?, r.get(1)?);
                used -= size;
                gone.push((sha, size));
            }
        }
        for (sha, _) in &gone {
            tx.execute("DELETE FROM entries WHERE sha256 = ?1", [sha])?;
            tx.execute("DELETE FROM blobs WHERE sha256 = ?1", [sha])?;
        }
        tx.commit()?;
        drop(db);
        for (sha, size) in gone {
            let _ = std::fs::remove_file(self.blob_path(&sha));
            self.stats.evicted_bytes.fetch_add(size as u64, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl Hit {
    /// For the audit row.
    pub fn describe(&self) -> String {
        format!("served from the node cache ({} object, sha256:{}, {} bytes)", self.key.kind, hex::encode(self.sha256), self.size)
    }

    /// The response: the object's bytes, hashed as they are read. The last chunk is held back until
    /// the whole object has matched its digest; if it doesn't, the body ends in an error (the box
    /// sees a broken transfer, never wrong bytes as a whole object) and the entry is evicted.
    pub fn into_response(self) -> Response<BoxBody> {
        let Hit { cache, tenant, key, sha256, size, headers, file } = self;
        cache.stats.hits.fetch_add(1, Ordering::Relaxed);
        cache.stats.hit_bytes.fetch_add(size, Ordering::Relaxed);
        let mut b = Response::builder().status(StatusCode::OK);
        for (k, v) in &headers {
            b = b.header(k.as_str(), v.as_str());
        }
        b = b.header("content-length", size.to_string()).header("x-wicket-cache", "hit");
        struct S {
            file: tokio::fs::File,
            hash: sha2::Sha256,
            read: u64,
            pending: Option<Bytes>,
            done: bool,
        }
        let st = S { file: tokio::fs::File::from_std(file), hash: sha2::Sha256::new(), read: 0, pending: None, done: false };
        let stream = futures_util::stream::unfold(st, move |mut s| {
            let (cache, tenant, key) = (cache.clone(), tenant.clone(), key.id.clone());
            async move {
                use tokio::io::AsyncReadExt;
                if s.done {
                    return None;
                }
                loop {
                    let mut buf = bytes::BytesMut::with_capacity(256 * 1024);
                    match s.file.read_buf(&mut buf).await {
                        Ok(0) => {
                            s.done = true;
                            let got: [u8; 32] = s.hash.clone().finalize().into();
                            if got == sha256 && s.read == size {
                                return s.pending.take().map(|p| (Ok(Frame::data(p)), s));
                            }
                            cache.stats.mismatches.fetch_add(1, Ordering::Relaxed);
                            let sha = hex::encode(sha256);
                            tracing::warn!(key = %key, "cached object does not match its digest; evicted");
                            tokio::task::spawn_blocking(move || cache.evict_entry(&tenant, &key, &sha));
                            return Some((Err(boxed("cached object failed its digest check")), s));
                        }
                        Ok(_) => {
                            let chunk = buf.freeze();
                            s.hash.update(&chunk);
                            s.read += chunk.len() as u64;
                            if let Some(prev) = s.pending.replace(chunk) {
                                return Some((Ok(Frame::data(prev)), s));
                            }
                        }
                        Err(e) => {
                            s.done = true;
                            return Some((Err(boxed(e)), s));
                        }
                    }
                }
            }
        });
        b.body(BodyExt::boxed(StreamBody::new(stream))).unwrap_or_else(|_| Response::new(crate::full("")))
    }
}

/// A fill in progress: the temporary file and the running digests.
struct Sink {
    file: tokio::fs::File,
    tmp: PathBuf,
    sha: sha2::Sha256,
    blake: Option<blake2::Blake2b<blake2::digest::consts::U32>>,
    len: u64,
    limit: u64,
    expect_len: Option<u64>,
}

impl Drop for Sink {
    fn drop(&mut self) {
        // Committed fills were renamed away; anything left is incomplete.
        let _ = std::fs::remove_file(&self.tmp);
    }
}

impl Fill {
    /// Whether this response may fill the cache.
    fn storable(&self, resp: &Response<BoxBody>) -> bool {
        let h = resp.headers();
        let cc = h.get_all("cache-control").iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join(",").to_ascii_lowercase();
        resp.status() == StatusCode::OK
            && !h.contains_key("set-cookie")
            && !cc.contains("private")
            && !cc.contains("no-store")
            && h.get("content-encoding").is_none_or(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"))
            && h.get("content-range").is_none()
    }

    /// The upstream response, passed through to the box unchanged while its bytes are written to a
    /// temporary file. At its end the object is checked (length, and the digest its URL names) and
    /// only then stored. For an object named by digest, the last chunk is held back until the check:
    /// a mismatch ends the box's transfer in an error, so wrong bytes never pass as the object.
    pub fn wrap(self, resp: Response<BoxBody>) -> Response<BoxBody> {
        if !self.storable(&resp) {
            return resp;
        }
        let expect_len = resp.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
        let limit = self.cache.max_object();
        if expect_len.is_some_and(|n| n > limit) {
            return resp;
        }
        let headers: Vec<(String, String)> = KEPT_HEADERS
            .iter()
            .filter_map(|k| resp.headers().get(*k).and_then(|v| v.to_str().ok()).map(|v| (k.to_string(), v.to_string())))
            .collect();
        let tmp = self.cache.dir.join("tmp").join(format!("{}.part", ulid::Ulid::new()));
        let file = match std::fs::File::create(&tmp) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "cache fill not started");
                return resp;
            }
        };
        let sink = Sink {
            file: tokio::fs::File::from_std(file),
            tmp,
            sha: sha2::Sha256::new(),
            blake: matches!(self.key.trust, Trust::Blake2b(_)).then(blake2::Blake2b::new),
            len: 0,
            limit,
            expect_len,
        };
        let (parts, body) = resp.into_parts();
        struct S {
            inner: BodyStream<BoxBody>,
            sink: Option<Sink>,
            fill: Fill,
            headers: String,
            pending: Option<Bytes>,
            done: bool,
        }
        let st = S {
            inner: BodyStream::new(body),
            sink: Some(sink),
            fill: self,
            headers: serde_json::to_string(&headers).unwrap_or_else(|_| "[]".into()),
            pending: None,
            done: false,
        };
        let stream = futures_util::stream::unfold(st, |mut s| async move {
            use tokio::io::AsyncWriteExt;
            if s.done {
                return None;
            }
            loop {
                match s.inner.next().await {
                    Some(Ok(frame)) => {
                        let data = match frame.into_data() {
                            Ok(d) => d,
                            // Trailers end the body; nothing to store from them.
                            Err(f) => return Some((Ok(f), s)),
                        };
                        if let Some(k) = s.sink.as_mut() {
                            k.len += data.len() as u64;
                            k.sha.update(&data);
                            if let Some(b) = k.blake.as_mut() {
                                blake2::Digest::update(b, &data);
                            }
                            if k.len > k.limit || k.file.write_all(&data).await.is_err() {
                                s.sink = None;
                            }
                        }
                        if let Some(prev) = s.pending.replace(data) {
                            return Some((Ok(Frame::data(prev)), s));
                        }
                    }
                    Some(Err(e)) => {
                        s.done = true;
                        s.sink = None;
                        return Some((Err(e), s));
                    }
                    None => {
                        s.done = true;
                        if let Some(mut k) = s.sink.take() {
                            match s.fill.check(&mut k).await {
                                Check::Store(sha) => s.fill.store(k, sha, s.headers.clone()),
                                Check::Skip => {}
                                Check::Mismatch => return Some((Err(boxed("object failed the digest its URL names")), s)),
                            }
                        }
                        return s.pending.take().map(|p| (Ok(Frame::data(p)), s));
                    }
                }
            }
        });
        Response::from_parts(parts, BodyExt::boxed(StreamBody::new(stream)))
    }

    async fn check(&self, k: &mut Sink) -> Check {
        use tokio::io::AsyncWriteExt;
        if k.expect_len.is_some_and(|n| n != k.len) || k.file.flush().await.is_err() {
            return Check::Skip;
        }
        let sha: [u8; 32] = k.sha.clone().finalize().into();
        let ok = match &self.key.trust {
            Trust::Sha256(want) => *want == sha,
            Trust::Blake2b(want) => k.blake.take().map(|b| <[u8; 32]>::from(blake2::Digest::finalize(b))) == Some(*want),
            Trust::FirstUse => true,
        };
        if !ok {
            self.cache.stats.mismatches.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(key = %self.key.id, "upstream object does not match the digest its URL names; not stored");
            return Check::Mismatch;
        }
        Check::Store(hex::encode(sha))
    }

    fn store(&self, k: Sink, sha: String, headers: String) {
        let (cache, tenant, key) = (self.cache.clone(), self.tenant.clone(), self.key.id.clone());
        let size = k.len;
        cache.stats.fills.fetch_add(1, Ordering::Relaxed);
        cache.stats.fill_bytes.fetch_add(size, Ordering::Relaxed);
        tokio::task::spawn_blocking(move || {
            if let Err(e) = cache.commit(&k.tmp, &sha, size, &tenant, &key, &headers) {
                tracing::warn!(error = %e, key = %key, "cache fill not stored");
            }
            drop(k);
        });
    }
}

enum Check {
    Store(String),
    Skip,
    Mismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("wicket-cache-{tag}-{}", ulid::Ulid::new()))
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("123"), Some(123));
        assert_eq!(parse_size("512K"), Some(512 << 10));
        assert_eq!(parse_size("8G"), Some(8 << 30));
        assert_eq!(parse_size("1x"), None);
        assert_eq!(parse_size(""), None);
    }

    #[test]
    fn objects_are_recognised_and_everything_else_is_not() {
        let sha = "a".repeat(64);
        let k = classify("https", "static.crates.io", "/crates/serde/serde-1.0.200.crate", "").unwrap();
        assert_eq!((k.kind, k.trust), ("crate", Trust::FirstUse));
        assert!(classify("http", "static.crates.io", "/crates/serde/serde-1.0.200.crate", "").is_none(), "first-use trust needs TLS");
        assert!(classify("https", "static.crates.io", "/crates/serde/other-1.0.crate", "").is_none());
        assert!(classify("https", "static.crates.io", "/crates/serde/serde-1.0.200.crate", "x=1").is_none());
        assert_eq!(classify("https", "registry.npmjs.org", "/left-pad/-/left-pad-1.3.0.tgz", "").unwrap().kind, "npm");
        assert_eq!(classify("https", "registry.npmjs.org", "/@types/node/-/node-20.1.0.tgz", "").unwrap().kind, "npm");
        assert!(classify("https", "registry.npmjs.org", "/left-pad", "").is_none(), "metadata is never cached");
        assert!(classify("https", "index.crates.io", "/se/rd/serde", "").is_none());
        let k = classify("https", "ghcr.io", &format!("/v2/org/img/blobs/sha256:{sha}"), "").unwrap();
        assert_eq!(k.trust, Trust::Sha256([0xaa; 32]));
        assert!(classify("https", "ghcr.io", "/v2/org/img/manifests/latest", "").is_none());
        assert!(classify("https", "ghcr.io", "/v2/org/img/blobs/sha256:abc", "").is_none());
        let k = classify("http", "deb.debian.org", &format!("/debian/dists/bookworm/main/binary-amd64/by-hash/SHA256/{sha}"), "").unwrap();
        assert_eq!(k.kind, "apt");
        assert!(classify("http", "deb.debian.org", "/debian/pool/main/c/curl/curl_7.88.1-10_amd64.deb", "").is_none());
        let k = classify(
            "https",
            "files.pythonhosted.org",
            "/packages/94/e7/b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz",
            "",
        )
        .unwrap();
        assert_eq!(k.trust, Trust::Blake2b(hex32("94e7b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2").unwrap()));
        assert!(classify("https", "files.pythonhosted.org", "/packages/94/e7/short/six.tar.gz", "").is_none());
    }

    fn resp(status: u16, body: &'static [u8], extra: &[(&str, &str)]) -> Response<BoxBody> {
        let mut b = Response::builder().status(status).header("content-type", "application/octet-stream");
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        b.body(crate::full(body)).unwrap()
    }

    async fn read(r: Response<BoxBody>) -> Result<Bytes, String> {
        r.into_body().collect().await.map(|c| c.to_bytes()).map_err(|e| e.to_string())
    }

    async fn settle(c: &Cache, want_fills: u64) {
        for _ in 0..200 {
            if c.stats.fills.load(Ordering::Relaxed) >= want_fills && c.used_bytes() > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn look(c: &Arc<Cache>, tenant: &str, path: &str, h: &HeaderMap) -> Lookup {
        c.lookup(tenant, "GET", "https", "static.crates.io", path, "", h, false).await
    }

    #[tokio::test]
    async fn a_fill_is_a_hit_for_its_tenant_only() {
        let dir = tmpdir("tenant");
        let c = Cache::open(&Config { dir: dir.clone(), max_bytes: 1 << 20 }).unwrap();
        let h = HeaderMap::new();
        let p = "/crates/foo/foo-1.0.0.crate";
        let Lookup::Miss(f) = look(&c, "t1", p, &h).await else { panic!("expected a miss") };
        assert_eq!(read(f.wrap(resp(200, b"crate bytes", &[]))).await.unwrap(), Bytes::from_static(b"crate bytes"));
        settle(&c, 1).await;
        let Lookup::Hit(hit) = look(&c, "t1", p, &h).await else { panic!("expected a hit") };
        assert!(hit.describe().contains("crate object"));
        let r = hit.into_response();
        assert_eq!(r.headers()["x-wicket-cache"], "hit");
        assert_eq!(r.headers()["content-type"], "application/octet-stream");
        assert_eq!(read(r).await.unwrap(), Bytes::from_static(b"crate bytes"));
        // Another tenant never sees it: its fetch goes upstream, and its fill shares the bytes.
        let Lookup::Miss(f) = look(&c, "t2", p, &h).await else { panic!("another tenant must miss") };
        read(f.wrap(resp(200, b"crate bytes", &[]))).await.unwrap();
        settle(&c, 2).await;
        assert_eq!(c.used_bytes(), 11, "one copy of the bytes");
        // Credentials and partial or conditional requests bypass it.
        let mut auth = HeaderMap::new();
        auth.insert("authorization", "Bearer x".parse().unwrap());
        assert!(matches!(look(&c, "t1", p, &auth).await, Lookup::Bypass));
        let mut range = HeaderMap::new();
        range.insert("range", "bytes=0-1".parse().unwrap());
        assert!(matches!(look(&c, "t1", p, &range).await, Lookup::Bypass));
        assert!(matches!(c.lookup("t1", "GET", "https", "static.crates.io", p, "", &h, true).await, Lookup::Bypass));
        assert!(matches!(c.lookup("t1", "HEAD", "https", "static.crates.io", p, "", &h, false).await, Lookup::Bypass));
        drop(c);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn only_complete_public_responses_are_stored() {
        let dir = tmpdir("store");
        let c = Cache::open(&Config { dir: dir.clone(), max_bytes: 1 << 20 }).unwrap();
        let h = HeaderMap::new();
        for (i, (status, extra)) in [
            (404, vec![]),
            (200, vec![("set-cookie", "a=b")]),
            (200, vec![("cache-control", "private")]),
            (200, vec![("content-encoding", "gzip")]),
            (200, vec![("content-length", "99")]),
        ]
        .into_iter()
        .enumerate()
        {
            let p = format!("/crates/c{i}/c{i}-1.0.0.crate");
            let Lookup::Miss(f) = look(&c, "t", &p, &h).await else { panic!() };
            let _ = read(f.wrap(resp(status, b"x", &extra))).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(c.used_bytes(), 0);
        assert_eq!(std::fs::read_dir(dir.join("tmp")).unwrap().count(), 0, "no temporary files left");
        drop(c);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_digest_named_object_is_verified_both_ways() {
        let dir = tmpdir("digest");
        let c = Cache::open(&Config { dir: dir.clone(), max_bytes: 1 << 20 }).unwrap();
        let h = HeaderMap::new();
        let good = hex::encode(sha2::Sha256::digest(b"layer"));
        let path = format!("/v2/lib/x/blobs/sha256:{good}");
        let look = |p: String| {
            let c = c.clone();
            let h = h.clone();
            async move { c.lookup("t", "GET", "https", "registry.example", &p, "", &h, false).await }
        };
        // Wrong bytes from upstream: the box's transfer fails, and nothing is stored.
        let Lookup::Miss(f) = look(path.clone()).await else { panic!() };
        assert!(read(f.wrap(resp(200, b"tampered", &[]))).await.is_err());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(c.used_bytes(), 0);
        // Right bytes: stored.
        let Lookup::Miss(f) = look(path.clone()).await else { panic!() };
        assert_eq!(read(f.wrap(resp(200, b"layer", &[]))).await.unwrap(), Bytes::from_static(b"layer"));
        settle(&c, 1).await;
        // Corrupt the stored bytes: the hit fails and is evicted; the next request is a miss.
        std::fs::write(c.blob_path(&good), b"LAYER").unwrap();
        let Lookup::Hit(hit) = look(path.clone()).await else { panic!("expected a hit") };
        assert!(read(hit.into_response()).await.is_err());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(matches!(look(path.clone()).await, Lookup::Miss(_)));
        assert!(c.stats.mismatches.load(Ordering::Relaxed) >= 2);
        drop(c);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn the_store_stays_within_its_limit() {
        let dir = tmpdir("evict");
        // 64 bytes in all; objects of at most 16.
        let c = Cache::open(&Config { dir: dir.clone(), max_bytes: 64 }).unwrap();
        let h = HeaderMap::new();
        let big = format!("/crates/big/big-1.0.0.crate");
        let Lookup::Miss(f) = look(&c, "t", &big, &h).await else { panic!() };
        read(f.wrap(resp(200, b"0123456789abcdef0123", &[]))).await.unwrap();
        static BODIES: [&[u8]; 6] = [b"aaaaaaaaaaaaaaa1", b"aaaaaaaaaaaaaaa2", b"aaaaaaaaaaaaaaa3", b"aaaaaaaaaaaaaaa4", b"aaaaaaaaaaaaaaa5", b"aaaaaaaaaaaaaaa6"];
        for (i, b) in BODIES.iter().enumerate() {
            let p = format!("/crates/c{i}/c{i}-1.0.0.crate");
            let Lookup::Miss(f) = look(&c, "t", &p, &h).await else { panic!() };
            read(f.wrap(resp(200, b, &[]))).await.unwrap();
            settle(&c, i as u64 + 1).await;
            // Distinct `used` stamps: eviction is by least recent use, to the second.
            if i == 1 {
                tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            }
        }
        assert!(c.used_bytes() <= 64, "{} bytes", c.used_bytes());
        assert_eq!(c.stats.fills.load(Ordering::Relaxed), 6, "the oversized object was not stored");
        assert!(matches!(look(&c, "t", "/crates/c0/c0-1.0.0.crate", &h).await, Lookup::Miss(_)), "the oldest went first");
        assert!(matches!(look(&c, "t", "/crates/c5/c5-1.0.0.crate", &h).await, Lookup::Hit(_)));
        drop(c);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
