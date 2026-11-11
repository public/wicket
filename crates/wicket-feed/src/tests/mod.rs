//! Tests. Keys are generated at runtime; time is injected (`T0` and offsets, Unix ms).

mod attacks;
mod fuzz;
mod modes;
mod persistence;
mod revocation;
mod skew;

use crate::*;
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use wicket_core::{Op, RunId, TenantId, ZoneSpec};

pub(crate) const T0: i64 = 1_800_000_000_000;
pub(crate) const NODE: &str = "n1";
/// A scaled-down TTL and window so the arithmetic in tests is easy to read.
pub(crate) const TTL: i64 = 3_000;
pub(crate) const WINDOW: i64 = 6_000;

pub(crate) fn key() -> SigningKey {
    SigningKey::generate(&mut rand_core::OsRng)
}

/// A directory removed when dropped.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!("wicket-feed-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn zone(name: &str) -> ZoneSpec {
    serde_json::from_value(serde_json::json!({
        "name": name,
        "reach": [{"host": "api.github.com", "methods": ["GET", "PUT", "POST"], "paths": ["/repos/acme/**"]}],
        "forbid": [{"host": "evil.example.com"}],
    }))
    .unwrap()
}

pub(crate) fn op(zone: &str, run: &str, method: &str, host: &str, path: &str) -> Op {
    Op::egress(&TenantId::single(), &RunId(run.into()), zone, method, host, path)
}

/// A plain read (R1, allowed by reach).
pub(crate) fn read() -> Op {
    op("z", "r1", "GET", "api.github.com", "/repos/acme/app/issues")
}
/// A write allowed by reach (R2).
pub(crate) fn write() -> Op {
    op("z", "r1", "PUT", "api.github.com", "/repos/acme/app/contents/README.md")
}
/// Posts a comment (R3): needs a grant; `keep-1` grants it.
pub(crate) fn granted() -> Op {
    op("z", "r1", "POST", "api.github.com", "/repos/acme/app/issues/1/comments")
}
/// Adds a webhook (R4): needs a grant nobody has; the attacker's target.
pub(crate) fn evil() -> Op {
    op("z", "r1", "POST", "api.github.com", "/repos/acme/app/hooks")
}
pub(crate) fn forbidden() -> Op {
    op("z", "r1", "GET", "evil.example.com", "/")
}

pub(crate) fn grant(id: &str, o: &Op, not_after: i64) -> Grant {
    Grant {
        id: id.into(),
        zone: o.zone.clone(),
        op: o.digest(),
        what: format!("{} {}{}", o.method, o.host, o.path),
        not_after,
        uses: None,
        box_id: None,
    }
}

pub(crate) fn add(g: Grant) -> Change<ZoneSpec> {
    Change::AddGrant { grant: g }
}

/// The control plane: a root key, a feed key and its certificate, and a publisher.
pub(crate) struct Cp {
    pub(crate) root: SigningKey,
    pub(crate) feed_key: SigningKey,
    pub(crate) cert: String,
    pub(crate) p: Publisher<ZoneSpec>,
    pub(crate) dir: TempDir,
}

pub(crate) fn cfg() -> PublisherConfig {
    PublisherConfig { ttl_ms: TTL, refresh_ms: 500, narrow_ms: WINDOW, retain: 100 }
}

pub(crate) fn cert(root: &SigningKey, feed: &SigningKey, version: u64, not_after: i64) -> String {
    sign(root, TYP_KEY, &KeyCert::new(&feed.verifying_key(), version, not_after, 30_000, 300_000))
}

impl Cp {
    pub(crate) fn new() -> Cp {
        Cp::with(PublisherConfig { ..cfg() }, T0 + 86_400_000)
    }

    pub(crate) fn with(cfg: PublisherConfig, cert_not_after: i64) -> Cp {
        let (root, feed_key, dir) = (key(), key(), TempDir::new());
        let cert = cert(&root, &feed_key, 1, cert_not_after);
        let p = Publisher::open(dir.path(), NODE, &root.verifying_key(), feed_key.clone(), &cert, cfg).unwrap();
        Cp { root, feed_key, cert, p, dir }
    }

    pub(crate) fn replica(&self) -> Replica<ZoneSpec> {
        Replica::new(NODE, self.root.verifying_key(), ReplicaConfig::default())
    }

    /// Reopens the publisher from its log (a control-plane restart).
    pub(crate) fn restart(&mut self, cfg: PublisherConfig) {
        self.p = Publisher::open(self.dir.path(), NODE, &self.root.verifying_key(), self.feed_key.clone(), &self.cert, cfg).unwrap();
    }
}

pub(crate) fn feed(r: &mut Replica<ZoneSpec>, frames: Vec<Frame>, now: i64) {
    for f in frames {
        r.accept(&f, now).unwrap_or_else(|e| panic!("{:?} refused: {e}", f.kind));
    }
}

/// A control plane with zone `z` and grant `keep-1` (for [`granted`]) at epoch 1, and a node that
/// caught up and is fresh at `T0`.
pub(crate) fn setup() -> (Cp, Replica<ZoneSpec>) {
    let mut cp = Cp::new();
    cp.p.commit(vec![Change::PutZone { zone: zone("z") }, add(grant("keep-1", &granted(), T0 + 3_600_000))], T0 - 10).unwrap();
    let mut r = cp.replica();
    let frames = cp.p.catch_up(&r.hello(), T0).unwrap();
    feed(&mut r, frames, T0);
    assert_eq!(r.mode(T0), Mode::Fresh);
    (cp, r)
}

pub(crate) fn allowed(r: &mut Replica<ZoneSpec>, o: &Op, now: i64) -> bool {
    r.decide(o, now).is_allow()
}
