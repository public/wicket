//! Target 3b: the node's feed, as a node runs it (`Replica<BoxAuthority>`, the box tokens the
//! control host publishes). A fresh replica catches up from a real publisher, then takes the input,
//! one step per line:
//!
//! - `R<line>`: a raw frame line, as it arrives on the channel ([`Replica::accept_bytes`]);
//! - `K<json>`, `S<json>`, `D<json>`, `F<json>`: a key certificate, snapshot, delta or statement whose
//!   payload is the JSON given, *signed* (by the root for `K`, by the feed key otherwise), so the
//!   fuzzer reaches what a node does after a signature verifies (the control host is untrusted
//!   too, #323);
//! - `T<n>`: the node's clock moves `n` ms.
//!
//! After every step the node decides a few requests and says its mode. The oracle: no panic; and a
//! raw line (unsigned by anyone the fuzzer holds a key of) never changes the replica's state unless
//! it is one of the real publisher's own frames (the seeds carry some).

use ed25519_dalek::SigningKey;
use std::sync::OnceLock;
use wicket_core::{Op, RunId, TenantId, ZoneSpec};
use wicket_feed::{BoxAuthority, Frame, FrameKind, Publisher, PublisherConfig, Replica, ReplicaConfig};

pub const NODE: &str = "n1";
pub const RUN: &str = "run_a";
pub const T0: i64 = 1_800_000_000_000;

pub fn root() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
pub fn feed_key() -> SigningKey {
    SigningKey::from_bytes(&[8; 32])
}
pub fn authz_root() -> wicket_authz::SigningKey {
    wicket_authz::SigningKey::from_bytes(&[9; 32]).expect("key")
}
pub fn approver() -> wicket_authz::SigningKey {
    wicket_authz::SigningKey::from_bytes(&[10; 32]).expect("key")
}

pub fn zone() -> ZoneSpec {
    wicket_core::Manifest::from_yaml(
        "task: t\nprogram: { name: p, command: [x] }\nzone:\n  name: z\n  escalation: { request: true }\n  reach:\n    - { host: api.example.com, methods: [GET, POST], paths: [\"/v1/**\"] }\n",
    )
    .expect("zone")
    .zone
}

/// A publisher of one run's box authority, at epoch 1, and the frames that catch a node up.
pub fn publisher(dir: &std::path::Path) -> (Publisher<BoxAuthority>, Vec<Frame>) {
    let cert = wicket_feed::KeyCert::new(&feed_key().verifying_key(), 1, T0 + 86_400_000, 30_000);
    let cert_jws = wicket_feed::sign(&root(), wicket_feed::TYP_KEY, &cert);
    let cfg = PublisherConfig { ttl_ms: 3_000, refresh_ms: 500, retain: 100 };
    let mut p =
        Publisher::open_with(dir, NODE, &root().verifying_key(), feed_key(), &cert_jws, cfg, authz_root().public()).expect("publisher");
    let not_after = ((T0 + 3_600_000) / 1000) as u64;
    let issuer = Issuer::root(&authz_root(), &TenantId::single().0, RUN, RUN, 0, &zone(), &[], not_after, vec![approver().public()])
        .expect("issuer");
    p.commit(vec![wicket_feed::format::Change::PutZone { zone: issuer.publish(&approver(), &[]).expect("publish") }], T0 - 10)
        .expect("commit");
    let r = Replica::<BoxAuthority>::new_with(NODE, root().verifying_key(), ReplicaConfig::default(), authz_root().public());
    let frames = p.catch_up(&r.hello(), T0).expect("catch up");
    (p, frames)
}

use wicket_feed::Issuer;

fn catch_up() -> &'static Vec<Frame> {
    static F: OnceLock<Vec<Frame>> = OnceLock::new();
    F.get_or_init(|| publisher(&crate::util::scratch("feed")).1)
}

fn op(method: &str, path: &str) -> Op {
    Op::egress(&TenantId::single(), &RunId(RUN.into()), "z", method, "api.example.com", path)
}

pub fn run(data: &[u8]) {
    let mut r = Replica::<BoxAuthority>::new_with(NODE, root().verifying_key(), ReplicaConfig::default(), authz_root().public());
    let mut now = T0;
    for f in catch_up() {
        let _ = r.accept(f, now);
    }
    let ops = [op("GET", "/v1/a"), op("POST", "/v1/a"), op("DELETE", "/v1/a"), op("GET", "/other")];
    for line in data.split(|b| *b == b'\n') {
        let Some((&tag, rest)) = line.split_first() else { continue };
        match tag {
            b'R' => {
                let before = r.state().map(|s| (s.epoch, s.head.clone()));
                let ok = r.accept_bytes(rest, now).is_ok();
                let after = r.state().map(|s| (s.epoch, s.head.clone()));
                if ok && before != after {
                    // Only the real publisher's frames (signed with the harness's keys) can do that.
                    let f = Frame::parse(rest).expect("accepted, so it parses");
                    assert!(
                        opens(&f),
                        "a raw frame changed the replica's state without a signature from the feed's keys: {:?}",
                        String::from_utf8_lossy(rest)
                    );
                }
            }
            b'K' | b'S' | b'D' | b'F' => {
                let Ok(payload) = serde_json::from_slice::<serde_json::Value>(rest) else { continue };
                let (kind, typ, key) = match tag {
                    b'K' => (FrameKind::Key, wicket_feed::TYP_KEY, root()),
                    b'S' => (FrameKind::Snap, wicket_feed::TYP_SNAP, feed_key()),
                    b'D' => (FrameKind::Delta, wicket_feed::TYP_DELTA, feed_key()),
                    _ => (FrameKind::Fresh, wicket_feed::TYP_FRESH, feed_key()),
                };
                let _ = r.accept(&Frame::new(kind, wicket_feed::sign(&key, typ, &payload)), now);
            }
            b'T' => {
                let n: i64 = std::str::from_utf8(rest).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                now = now.saturating_add(n.clamp(-86_400_000_000, 86_400_000_000));
            }
            _ => continue,
        }
        let _ = r.mode(now);
        for o in &ops {
            let _ = r.decide(o, now);
        }
        let _ = r.hello();
        let _ = r.fresh_until();
    }
}

/// Whether a frame is signed by the harness's own keys (so the fuzzer could only have copied it).
fn opens(f: &Frame) -> bool {
    let vk = if f.kind == FrameKind::Key { root().verifying_key() } else { feed_key().verifying_key() };
    let typ = match f.kind {
        FrameKind::Key => wicket_feed::TYP_KEY,
        FrameKind::Snap => wicket_feed::TYP_SNAP,
        FrameKind::Delta => wicket_feed::TYP_DELTA,
        FrameKind::Fresh => wicket_feed::TYP_FRESH,
    };
    wicket_feed::jws::open::<serde_json::Value>(&f.jws, typ, &wicket_feed::kid(&vk), &vk).is_ok()
}
