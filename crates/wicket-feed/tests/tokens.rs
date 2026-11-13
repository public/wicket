//! The feed carrying boxes' authority as Biscuit token chains (#57 step 4):
//! - decisions through tokens match `CompiledZone` (the `ZoneSpec` feed) on every example and
//!   subset-test zone, fresh and offline;
//! - revoking a spawn block revokes the subtree on the node;
//! - a grant reaches the node, its use count is enforced there (and survives a restart), and
//!   revoking it stops only that grant;
//! - a hostile appended block is refused at load (the delta still applies, so the chain stays in
//!   sync), and the box is forbidden everything.

#[path = "../../wicket-authz/tests/common/mod.rs"]
mod common;

use common::{all_zones, probes, METHODS, TENANT};
use ed25519_dalek::SigningKey as FeedKey;
use std::path::{Path, PathBuf};
use wicket_authz::biscuit_auth::BlockBuilder;
use wicket_authz::{Ceiling, Grant as AuthzGrant, SigningKey, Token};
use wicket_core::{Op, RunId, TenantId, ZoneSpec};
use wicket_feed::*;

const T0: i64 = 1_800_000_000_000;
const NODE: &str = "n1";
const TTL: i64 = 3_000;

fn secs(ms: i64) -> u64 {
    (ms / 1000) as u64
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!("wicket-feed-tokens-{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A control plane: the feed root and key, the authority root and approver, and a publisher of
/// [`BoxAuthority`] records (plus, for the oracle, one of `ZoneSpec`s under the same feed root).
struct Cp {
    root: FeedKey,
    feed_key: FeedKey,
    authz_root: SigningKey,
    approver: SigningKey,
    p: Publisher<BoxAuthority>,
    _dir: TempDir,
}

fn cfg() -> PublisherConfig {
    PublisherConfig { ttl_ms: TTL, refresh_ms: 500, retain: 100 }
}

fn cert(root: &FeedKey, feed: &FeedKey) -> String {
    sign(root, TYP_KEY, &KeyCert::new(&feed.verifying_key(), 1, T0 + 86_400_000, 30_000))
}

impl Cp {
    fn new() -> Cp {
        Cp::new_with_authz_root(SigningKey::generate())
    }

    fn new_with_authz_root(authz_root: SigningKey) -> Cp {
        let (root, feed_key) = (FeedKey::generate(&mut rand_core::OsRng), FeedKey::generate(&mut rand_core::OsRng));
        let dir = TempDir::new("cp");
        let p = Publisher::open_with(
            dir.path(),
            NODE,
            &root.verifying_key(),
            feed_key.clone(),
            &cert(&root, &feed_key),
            cfg(),
            authz_root.public(),
        )
        .unwrap();
        Cp { root, feed_key, authz_root, approver: SigningKey::generate(), p, _dir: dir }
    }

    fn replica(&self) -> Replica<BoxAuthority> {
        Replica::new_with(NODE, self.root.verifying_key(), ReplicaConfig::default(), self.authz_root.public())
    }

    /// A top-level box `run` in `zone`, accepting the approver's grants, valid for an hour.
    fn issue(&self, run: &str, zone: &ZoneSpec) -> Issuer {
        Issuer::root(&self.authz_root, TENANT, "trigger:t", run, 0, zone, &[], secs(T0) + 3600, vec![self.approver.public()]).unwrap()
    }

    fn put(&mut self, a: BoxAuthority, now: i64) -> Frame {
        self.p.commit(vec![Change::PutZone { zone: a }], now).unwrap()
    }
}

fn feed<P: Policy>(r: &mut Replica<P>, frames: Vec<Frame>, now: i64) {
    for f in frames {
        r.accept(&f, now).unwrap_or_else(|e| panic!("{:?} refused: {e}", f.kind));
    }
}

/// Catches `r` up from `p` and makes it fresh at `now`.
fn sync<P: Policy>(p: &mut Publisher<P>, r: &mut Replica<P>, now: i64) {
    let frames = p.catch_up(&r.hello(), now).unwrap();
    feed(r, frames, now);
    assert_eq!(r.mode(now), Mode::Fresh);
}

fn op(zone: &str, run: &str, m: &str, h: &str, p: &str) -> Op {
    Op::egress(&TenantId(TENANT.into()), &RunId(run.into()), zone, m, h, p)
}

/// A decision's kind, ignoring reasons and which reach rule allowed.
fn kind(d: &Decision) -> &'static str {
    match d {
        Decision::Allow(Allowed::Grant(_)) => "grant",
        Decision::Allow(_) => "allow",
        Decision::Forbidden(_) => "forbidden",
        Decision::NeedsGrant(_) => "needs-grant",
        Decision::Refused { .. } => "refused",
    }
}

#[test]
fn token_decisions_match_compiled_zones_fresh_and_offline() {
    let zones = all_zones();
    let mut cp = Cp::new();
    // The oracle: the same zones as `ZoneSpec` entries, decided by `CompiledZone` in the replica.
    let oracle_dir = TempDir::new("oracle");
    let mut zp: Publisher<ZoneSpec> =
        Publisher::open(oracle_dir.path(), NODE, &cp.root.verifying_key(), cp.feed_key.clone(), &cert(&cp.root, &cp.feed_key), cfg())
            .unwrap();
    // Zone names repeat across the example and subset sets: one box per zone index, and the oracle
    // gets each zone under a unique name.
    let mut boxes = vec![];
    for (i, z) in zones.iter().enumerate() {
        let mut z = z.clone();
        z.name = format!("{}-{i}", z.name);
        let run = format!("run-{i}");
        let a = cp.issue(&run, &z).publish(&cp.approver, &[]).unwrap();
        cp.put(a, T0 - 100);
        zp.commit(vec![Change::PutZone { zone: z.clone() }], T0 - 100).unwrap();
        boxes.push((run, z));
    }
    let (mut tr, mut zr) = (cp.replica(), Replica::<ZoneSpec>::new(NODE, cp.root.verifying_key(), ReplicaConfig::default()));
    sync(&mut cp.p, &mut tr, T0);
    sync(&mut zp, &mut zr, T0);
    let offline = T0 + TTL + 1;
    assert_eq!(tr.mode(offline), Mode::Offline);
    let mut counts = std::collections::BTreeMap::<(&str, &str), usize>::new();
    for (run, z) in &boxes {
        let (hosts, paths) = probes(&[z]);
        for h in &hosts {
            for p in &paths {
                for m in METHODS {
                    let o = op(&z.name, run, m, h, p);
                    for (now, mode) in [(T0, "fresh"), (offline, "offline")] {
                        let (want, got) = (zr.decide(&o, now), tr.decide(&o, now));
                        assert_eq!(
                            kind(&got),
                            kind(&want),
                            "{mode} zone {}: {m} {h}{p} ({:?}): token {got:?}, zone {want:?}",
                            z.name,
                            o.risk
                        );
                        *counts.entry((mode, kind(&want))).or_default() += 1;
                    }
                }
            }
        }
    }
    println!("token vs CompiledZone on {} zones: {counts:?}", boxes.len());
    for k in [
        ("fresh", "allow"),
        ("fresh", "forbidden"),
        ("fresh", "needs-grant"),
        ("offline", "allow"),
        ("offline", "forbidden"),
        ("offline", "needs-grant"),
    ] {
        assert!(counts.get(&k).copied().unwrap_or(0) > 500, "too few {k:?}: {counts:?}");
    }
    // A box's token decides only for its own zone and run.
    // (The first zone with a readable rule: not every example zone has reach.)
    let readable = |z: &ZoneSpec| z.reach.iter().find(|r| r.methods.iter().any(|m| m == "GET")).cloned();
    let (run, z) = boxes.iter().find(|(_, z)| readable(z).is_some()).expect("a zone with a readable rule");
    let read = readable(z).expect("a readable rule");
    let other = boxes.iter().find(|(r, _)| r != run).expect("another box");
    let path = common::paths_for(&read.paths[0])[0].clone();
    let host = read.host.replace("*.", "a.");
    assert_eq!(kind(&tr.decide(&op(&z.name, run, "GET", &host, &path), T0)), "allow");
    assert!(
        matches!(tr.decide(&op(&other.1.name, run, "GET", &host, &path), T0), Decision::Forbidden(w) if w.contains("holds authority for zone"))
    );
    assert!(
        matches!(tr.decide(&op(&z.name, "run-unknown", "GET", &host, &path), T0), Decision::Forbidden(w) if w.contains("no authority"))
    );
}

fn zone(name: &str, paths: &[&str]) -> ZoneSpec {
    serde_json::from_value(serde_json::json!({
        "name": name,
        "reach": [{"host": "api.github.com", "methods": ["GET", "PUT", "POST"], "paths": paths}],
        "forbid": [{"host": "evil.example.com"}],
    }))
    .unwrap()
}

fn gh(zone: &str, run: &str, m: &str, path: &str) -> Op {
    op(zone, run, m, "api.github.com", path)
}

#[test]
fn revoking_a_spawn_block_revokes_the_subtree_on_the_node() {
    let mut cp = Cp::new();
    let (zp, zc, zg) = (zone("zp", &["/repos/acme/**"]), zone("zc", &["/repos/acme/app/**"]), zone("zg", &["/repos/acme/app/issues/**"]));
    let keys = vec![cp.approver.public()];
    let parent = cp.issue("p", &zp);
    let child = parent.child("c", 0, &zc, &Ceiling::from_zone(&zc, "p/c", secs(T0) + 3600, keys.clone()).unwrap()).unwrap();
    let grand = child.child("g", 0, &zg, &Ceiling::from_zone(&zg, "p/c/g", secs(T0) + 3600, keys.clone()).unwrap()).unwrap();
    assert_eq!((parent.block_ids().len(), child.block_ids().len(), grand.block_ids().len()), (1, 2, 3));
    assert_eq!(&grand.block_ids()[..2], &child.block_ids()[..], "the grandchild's chain extends the child's");
    // A child can't exceed its parent, whatever its zone says.
    let wide = zone("zw", &["/**"]);
    let wide_child = parent.child("w", 0, &wide, &Ceiling::from_zone(&wide, "p/w", secs(T0) + 3600, keys).unwrap()).unwrap();
    for i in [&parent, &child, &grand, &wide_child] {
        let a = i.publish(&cp.approver, &[]).unwrap();
        cp.put(a, T0 - 100);
    }
    let mut r = cp.replica();
    sync(&mut cp.p, &mut r, T0);
    let issue = "/repos/acme/app/issues/1";
    for (z, run) in [("zp", "p"), ("zc", "c"), ("zg", "g")] {
        assert_eq!(kind(&r.decide(&gh(z, run, "GET", issue), T0)), "allow", "{run}");
    }
    assert_eq!(kind(&r.decide(&gh("zp", "p", "GET", "/repos/acme/web"), T0)), "allow");
    assert_eq!(kind(&r.decide(&gh("zc", "c", "GET", "/repos/acme/web"), T0)), "needs-grant", "narrower than its parent");
    assert_eq!(kind(&r.decide(&gh("zw", "w", "GET", "/repos/acme/web"), T0)), "allow");
    assert_eq!(kind(&r.decide(&gh("zw", "w", "GET", "/orgs/acme"), T0)), "needs-grant", "never wider than its parent");

    // Revoke the child's own link: the child and the grandchild go, the parent stays.
    let link = child.block_ids()[1].clone();
    let rev = cp.p.commit(vec![Change::Revoke { kind: RevokeKind::Token, id: link.clone(), until: T0 + 3_600_000 }], T0 + 10).unwrap();
    r.accept(&rev, T0 + 10).unwrap();
    assert_eq!(kind(&r.decide(&gh("zp", "p", "GET", issue), T0 + 10)), "allow");
    assert_eq!(kind(&r.decide(&gh("zw", "w", "GET", issue), T0 + 10)), "allow", "a sibling subtree is untouched");
    for (z, run) in [("zc", "c"), ("zg", "g")] {
        let d = r.decide(&gh(z, run, "GET", issue), T0 + 10);
        assert!(matches!(&d, Decision::Forbidden(w) if w.contains("revoked")), "{run}: {d:?}");
    }
    // The publisher won't publish a revoked token again (it compiles every entry as a node does)...
    let again = cp.p.commit(vec![Change::PutZone { zone: grand.publish(&cp.approver, &[]).unwrap() }], T0 + 20);
    assert!(matches!(&again, Err(PublishError::Invalid(e)) if e.contains("revoked")), "{again:?}");
    // ...and a node that catches up from a snapshot refuses it at load.
    let mut fresh_node = cp.replica();
    let frames = vec![cp.p.key_frame(), cp.p.snapshot(T0 + 30), cp.p.statement(T0 + 30)];
    feed(&mut fresh_node, frames, T0 + 30);
    assert_eq!(kind(&fresh_node.decide(&gh("zp", "p", "GET", issue), T0 + 30)), "allow");
    let d = fresh_node.decide(&gh("zg", "g", "GET", issue), T0 + 30);
    assert!(matches!(&d, Decision::Forbidden(w) if w.contains("revoked")), "{d:?}");
}

fn authz_grant(gid: &str, method: &str, path: &str, not_after_ms: i64) -> AuthzGrant {
    AuthzGrant {
        gid: gid.into(),
        box_id: String::new(),
        epoch: 0,
        host: "api.github.com".into(),
        method: method.into(),
        path: path.into(),
        not_after: secs(not_after_ms),
        approver: "human:test".into(),
        digest: vec![1, 2, 3],
    }
}

#[test]
fn a_grant_reaches_the_node_and_its_use_count_is_enforced_there() {
    let mut cp = Cp::new();
    let z = zone("z", &["/repos/acme/**"]);
    let issuer = cp.issue("r1", &z);
    cp.put(issuer.publish(&cp.approver, &[]).unwrap(), T0 - 100);
    let dir = TempDir::new("node");
    let open = |cp: &Cp| {
        Replica::<BoxAuthority>::open_with(dir.path(), NODE, cp.root.verifying_key(), ReplicaConfig::default(), cp.authz_root.public())
            .unwrap()
    };
    let mut r = open(&cp);
    sync(&mut cp.p, &mut r, T0);
    let hook = gh("z", "r1", "POST", "/repos/acme/app/hooks"); // R4: needs a grant
    let other = gh("z", "r1", "POST", "/orgs/acme/hooks");
    assert_eq!(kind(&r.decide(&hook, T0)), "needs-grant");

    // Approved with two uses: the control host appends the grant block and ships the whole token.
    let g = LiveGrant { grant: authz_grant("g1", "POST", "/repos/acme/app/hooks", T0 + 600_000), uses: Some(2) };
    let a = issuer.publish(&cp.approver, std::slice::from_ref(&g)).unwrap();
    assert_eq!(a.grants.len(), 1);
    r.accept(&cp.put(a, T0 + 10), T0 + 10).unwrap();
    assert_eq!(r.decide(&hook, T0 + 20), Decision::Allow(Allowed::Grant("g1".into())));
    assert_eq!(kind(&r.decide(&other, T0 + 20)), "needs-grant", "a grant is for exactly one request");
    // Offline (#153): the grant is honoured on the node, its uses counted there.
    assert_eq!(r.decide(&hook, T0 + TTL + 100), Decision::Allow(Allowed::Grant("g1".into())));
    r.accept(&cp.p.statement(T0 + TTL + 200), T0 + TTL + 200).unwrap();
    // The uses survive a node restart's count; the third is refused.
    drop(r);
    let mut r = open(&cp);
    assert_eq!(r.uses("g1"), 2);
    assert_eq!(kind(&r.decide(&hook, T0 + TTL + 400)), "needs-grant", "two uses, then none");
    assert_eq!(r.uses("g1"), 2);

    // A fresh grant (new id, one use) and a revocation of it by grant id: only that grant stops; the
    // token itself still decides.
    let g2 = LiveGrant { grant: authz_grant("g2", "POST", "/repos/acme/app/hooks", T0 + 600_000), uses: Some(1) };
    let now = T0 + TTL + 500;
    r.accept(&cp.put(issuer.publish(&cp.approver, &[g.clone(), g2]).unwrap(), now), now).unwrap();
    let rev = cp.p.commit(vec![Change::Revoke { kind: RevokeKind::Grant, id: "g2".into(), until: T0 + 600_000 }], now).unwrap();
    r.accept(&rev, now).unwrap();
    assert_eq!(kind(&r.decide(&hook, now)), "needs-grant");
    assert_eq!(kind(&r.decide(&gh("z", "r1", "GET", "/repos/acme/app"), now)), "allow");

    // The record can't add authority the token lacks: a listed grant with no block in the token
    // never fires, and neither does a grant for another box.
    let mut forged = issuer.publish(&cp.approver, &[]).unwrap();
    forged.grants.push(TokenGrant {
        id: "g3".into(),
        host: "api.github.com".into(),
        method: "POST".into(),
        path: "/repos/acme/app/hooks".into(),
        uses: None,
    });
    r.accept(&cp.put(forged, now + 1), now + 1).unwrap();
    assert_eq!(kind(&r.decide(&hook, now + 1)), "needs-grant");
    let other_box = cp.issue("r2", &z);
    let g4 = LiveGrant { grant: authz_grant("g4", "POST", "/repos/acme/app/hooks", T0 + 600_000), uses: None };
    let mut a = other_box.publish(&cp.approver, std::slice::from_ref(&g4)).unwrap();
    // r2's token filed under r1: refused at load (the box path isn't r1's)...
    a.run = "r1".into();
    let e = cp.p.commit(vec![Change::PutZone { zone: a.clone() }], now + 2);
    assert!(matches!(&e, Err(PublishError::Invalid(w)) if w.contains("is not run")), "{e:?}");
    // ...and with the box path rewritten too, the token's own box check refuses everything.
    a.box_path = "r1".into();
    r.accept(&cp.put(a, now + 2), now + 2).unwrap();
    for o in [&hook, &gh("z", "r1", "GET", "/repos/acme/app")] {
        let d = r.decide(o, now + 2);
        assert!(matches!(&d, Decision::Forbidden(w) if w.contains("box")), "{d:?}");
    }
    // A grant from a key no block trusts is refused at publish (and would be at load).
    let rogue = SigningKey::generate();
    let a = issuer.publish(&rogue, std::slice::from_ref(&g4)).unwrap();
    let e = cp.p.commit(vec![Change::PutZone { zone: a }], now + 3);
    assert!(matches!(&e, Err(PublishError::Invalid(w)) if w.contains("no first-party block trusts")), "{e:?}");
}

#[test]
fn a_hostile_appended_block_is_refused_at_load() {
    let mut cp = Cp::new();
    let z = zone("z", &["/repos/acme/**"]);
    let issuer = cp.issue("r1", &z);
    cp.put(issuer.publish(&cp.approver, &[]).unwrap(), T0 - 100);
    let mut r = cp.replica();
    sync(&mut cp.p, &mut r, T0);
    let read = gh("z", "r1", "GET", "/repos/acme/app");
    assert_eq!(kind(&r.decide(&read, T0)), "allow");

    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let hostile = [
        (r#"approved("g", "api.github.com", "POST", "/orgs/acme/hooks") <- time($t);"#, "rules"),
        (r#"check if host($h), $h.matches("a.*");"#, "expression not allowed"),
        (r#"check if secret($x);"#, "vocabulary"),
    ];
    for (i, (code, why)) in hostile.iter().enumerate() {
        let t = Token::from_biscuit(issuer.base.biscuit().append(BlockBuilder::new().code(*code).unwrap()).unwrap());
        let mut a = issuer.publish(&cp.approver, &[]).unwrap();
        a.token = b64.encode(t.to_bytes().unwrap());
        // The publisher refuses it...
        let e = cp.p.commit(vec![Change::PutZone { zone: a.clone() }], T0 + 1);
        assert!(matches!(&e, Err(PublishError::Invalid(w)) if w.contains(why)), "{code}: {e:?}");
        // ...so sign it as a compromised control plane would, with the feed key directly. The node
        // applies the delta (refusing a signed delta would desynchronise the chain) but refuses the
        // token at load: the box is forbidden everything.
        let h = r.hello();
        let d = Delta {
            feed: NODE.into(),
            version: h.version.unwrap(),
            epoch: h.epoch.unwrap() + 1,
            prev: h.head.unwrap(),
            issued_at: T0 + 1 + i as i64,
            changes: vec![Change::PutZone { zone: a }],
        };
        r.accept(&Frame::new(FrameKind::Delta, sign(&cp.feed_key, TYP_DELTA, &d)), T0 + 1).unwrap();
        let got = r.decide(&read, T0 + 1);
        assert!(matches!(&got, Decision::Forbidden(w) if w.contains("invalid") && w.contains(why)), "{code}: {got:?}");
        assert_eq!(r.state().unwrap().epoch, d.epoch);
    }
    // A token minted by another root is refused the same way.
    let other = SigningKey::generate();
    let mut a = Issuer::root(&other, TENANT, "t", "r1", 0, &z, &[], secs(T0) + 3600, vec![]).unwrap().publish(&cp.approver, &[]).unwrap();
    a.run = "r1".into();
    let e = cp.p.commit(vec![Change::PutZone { zone: a }], T0 + 10);
    assert!(matches!(&e, Err(PublishError::Invalid(w)) if w.contains("load")), "{e:?}");
}

/// #154: with the authority root offline, an online issuing key the root certified mints block 0;
/// a node loads such a token with its certificate, refuses it without one or with one from another
/// root, and forbids the box everything once the certificate has ended.
#[test]
fn a_token_minted_by_a_certified_issuing_key_loads_until_its_certificate_expires() {
    let seed = [7u8; 32];
    let root = SigningKey::from_bytes(&seed).unwrap();
    // The root's seed signs certificates as an Ed25519 JWS key: the same public key.
    assert_eq!(FeedKey::from_bytes(&seed).verifying_key().to_bytes(), root.public().0);
    let issuing = SigningKey::generate();
    let now = now_ms();
    let z = zone("zp", &["/repos/acme/**"]);
    let mut i = Issuer::root(&issuing, TENANT, "trigger:t", "p", 0, &z, &[], secs(now) + 3600, vec![]).unwrap();
    i.issuer_cert = Some(AuthzKeyCert::sign(&seed, &issuing.public(), now + 3_600_000));
    let a = i.publish(&SigningKey::generate(), &[]).unwrap();
    let load = |a: &BoxAuthority| a.compile(&root.public(), &|_, _| false).map(|_| ()).map_err(|e| e.to_string());
    assert_eq!(load(&a), Ok(()));
    // A child carries its parent's certificate.
    let keys = vec![];
    let zc = zone("zc", &["/repos/acme/app/**"]);
    let c = i.child("c", 0, &zc, &Ceiling::from_zone(&zc, "p/c", secs(now) + 3600, keys).unwrap()).unwrap();
    assert_eq!(load(&c.publish(&SigningKey::generate(), &[]).unwrap()), Ok(()));
    let with = |cert: Option<String>| BoxAuthority { issuer_cert: cert, ..a.clone() };
    assert!(load(&with(None)).is_err(), "the issuing key isn't the root");
    // A certificate for a minute: the box is allowed until then, and forbidden everything after, by
    // the node's clock (the token itself lasts an hour).
    let mut short = Issuer::root(&issuing, TENANT, "trigger:t", "s", 0, &z, &[], secs(now) + 3600, vec![]).unwrap();
    short.issuer_cert = Some(AuthzKeyCert::sign(&seed, &issuing.public(), now + 60_000));
    let mut cp = Cp::new_with_authz_root(root.clone());
    cp.put(short.publish(&SigningKey::generate(), &[]).unwrap(), now - 100);
    let mut r = cp.replica();
    sync(&mut cp.p, &mut r, now);
    let get = gh("zp", "s", "GET", "/repos/acme/app");
    assert_eq!(kind(&r.decide(&get, now)), "allow");
    let later = now + 120_000;
    r.accept(&cp.p.statement(later), later).unwrap();
    let d = r.decide(&get, later);
    assert!(matches!(&d, Decision::Forbidden(w) if w.contains("no longer certified")), "{d:?}");
    assert!(load(&with(Some(AuthzKeyCert::sign(&[8u8; 32], &issuing.public(), now + 3_600_000)))).is_err(), "another root");
    // A record the root minted itself has no certificate, and no new field on the wire.
    let cp = Cp::new();
    let plain = cp.issue("q", &z).publish(&cp.approver, &[]).unwrap();
    assert!(serde_json::to_value(&plain).unwrap().get("issuer_cert").is_none());
}

/// #164: a child's token derived on the node (its parent's base token attenuated, with no feed
/// update) is decided from as a feed entry is, never beyond its parent, never past its parent's
/// authority, only under its parent's box path, and goes when its parent's block is revoked. Once
/// the feed holds the child, the feed's entry decides.
#[test]
fn a_child_derived_on_the_node_is_bounded_by_and_revoked_with_its_parent() {
    let mut cp = Cp::new();
    let (zp, zc) = (zone("zp", &["/repos/acme/**"]), zone("zc", &["/repos/acme/app/**"]));
    let keys = vec![cp.approver.public()];
    let parent = cp.issue("p", &zp);
    cp.put(parent.publish(&cp.approver, &[]).unwrap(), T0 - 100);
    let mut r = cp.replica();
    sync(&mut cp.p, &mut r, T0);
    // The child's ceiling says two hours; its parent's says one.
    let ceiling = |prefix: &str| Ceiling::from_zone(&zc, prefix, secs(T0) + 7200, keys.clone()).unwrap();
    assert!(parent.child("c", 0, &zc, &ceiling("q/c")).is_err(), "a child is bounded to its parent's path");
    let child = parent.child("c", 0, &zc, &ceiling("p/c")).unwrap();
    assert_eq!(kind(&r.decide(&gh("zc", "c", "GET", "/repos/acme/app/x"), T0)), "forbidden", "not held yet");
    r.put_local(child.publish(&cp.approver, &[]).unwrap()).unwrap();
    assert_eq!(kind(&r.decide(&gh("zc", "c", "GET", "/repos/acme/app/x"), T0)), "allow");
    assert_eq!(kind(&r.decide(&gh("zc", "c", "GET", "/repos/acme/web"), T0)), "needs-grant", "narrower than its parent");
    assert!(r.authority_until("c").unwrap() <= r.authority_until("p").unwrap(), "never past its parent's authority");
    // Offline, as fresh: it holds until it expires.
    assert_eq!(kind(&r.decide(&gh("zc", "c", "GET", "/repos/acme/app/x"), T0 + 10 * TTL)), "allow");
    // A record claiming another box path for the same token is forbidden everything.
    let mut forged = child.publish(&cp.approver, &[]).unwrap();
    forged.run = "c2".into();
    forged.box_path = "x/c2".into();
    r.put_local(forged).unwrap();
    assert_eq!(kind(&r.decide(&gh("zc", "c2", "GET", "/repos/acme/app/x"), T0)), "forbidden", "not under its parent's path");
    // A token that doesn't verify is refused outright.
    let mut bad = child.publish(&cp.approver, &[]).unwrap();
    bad.run = "c3".into();
    bad.box_path = "p/c3".into();
    bad.token = cp.issue("other", &zc).publish(&cp.approver, &[]).unwrap().token.replace('A', "B");
    assert!(r.put_local(bad).is_err());
    // Revoking the parent's block 0 takes the child with it.
    let root = parent.block_ids()[0].clone();
    let rev = cp.p.commit(vec![Change::Revoke { kind: RevokeKind::Token, id: root, until: T0 + 3_600_000 }], T0 + 10).unwrap();
    r.accept(&rev, T0 + 10).unwrap();
    let d = r.decide(&gh("zc", "c", "GET", "/repos/acme/app/x"), T0 + 10);
    assert!(matches!(&d, Decision::Forbidden(w) if w.contains("revoked")), "{d:?}");
    // And a child derived after the revocation is refused when it is added.
    assert!(r.put_local(child.publish(&cp.approver, &[]).unwrap()).is_err());
}

/// #164: once the feed holds a box the node derived, the feed's entry decides.
#[test]
fn the_feed_entry_replaces_a_derived_one() {
    let mut cp = Cp::new();
    let (zp, zc) = (zone("zp", &["/repos/acme/**"]), zone("zc", &["/repos/acme/app/**"]));
    let keys = vec![cp.approver.public()];
    let parent = cp.issue("p", &zp);
    cp.put(parent.publish(&cp.approver, &[]).unwrap(), T0 - 100);
    let mut r = cp.replica();
    sync(&mut cp.p, &mut r, T0);
    let child = parent.child("c", 0, &zc, &Ceiling::from_zone(&zc, "p/c", secs(T0) + 3600, keys.clone()).unwrap()).unwrap();
    r.put_local(child.publish(&cp.approver, &[]).unwrap()).unwrap();
    assert_eq!(kind(&r.decide(&gh("zc", "c", "GET", "/repos/acme/web"), T0)), "needs-grant");
    // Adopted by the control host: published in a narrower zone of its own.
    let zn = zone("zc", &["/repos/acme/app/issues/**"]);
    let adopted = Issuer::root(&cp.authz_root, TENANT, "trigger:t", "c", 0, &zn, &[], secs(T0) + 3600, keys).unwrap();
    cp.put(adopted.publish(&cp.approver, &[]).unwrap(), T0 + 1);
    sync(&mut cp.p, &mut r, T0 + 1);
    assert_eq!(kind(&r.decide(&gh("zc", "c", "GET", "/repos/acme/app/x"), T0 + 1)), "needs-grant", "the feed's entry decides");
    assert!(r.local("c").is_some(), "kept until the node drops it");
    r.drop_local("c");
    assert!(r.local("c").is_none());
}

/// #164: deriving a child on the node takes exactly its parent's base token (verified, and the
/// start of the token the feed holds, without its grants): another box's base, a forged one, or
/// the parent's token with its grants is refused, so a child never inherits a grant.
#[test]
fn a_node_derives_a_child_only_from_its_parents_own_base_token() {
    let mut cp = Cp::new();
    let (zp, zc) = (zone("zp", &["/repos/acme/**"]), zone("zc", &["/repos/acme/**"]));
    let keys = vec![cp.approver.public()];
    let parent = cp.issue("p", &zp);
    let other = cp.issue("o", &zp);
    let g = LiveGrant { grant: authz_grant("g1", "POST", "/repos/acme/app/hooks", T0 + 600_000), uses: None };
    let with_grant = parent.publish(&cp.approver, std::slice::from_ref(&g)).unwrap();
    cp.put(with_grant.clone(), T0 - 100);
    cp.put(other.publish(&cp.approver, &[]).unwrap(), T0 - 100);
    let mut r = cp.replica();
    sync(&mut cp.p, &mut r, T0);
    assert_eq!(kind(&r.decide(&gh("zp", "p", "POST", "/repos/acme/app/hooks"), T0)), "grant");
    let ceiling = Ceiling::from_zone(&zc, "p/c", secs(T0) + 3600, keys.clone()).unwrap();
    let base = parent.record().unwrap().token;
    for (bad, why) in [
        (other.record().unwrap().token, "another box's"),
        (with_grant.token.clone(), "with its grants"),
        (base.replace('A', "B"), "forged"),
    ] {
        assert!(r.derive_child("p", &bad, "c", &zc, &ceiling).is_err(), "{why}");
    }
    let wrong_path = Ceiling::from_zone(&zc, "o/c", secs(T0) + 3600, keys).unwrap();
    assert!(r.derive_child("p", &base, "c", &zc, &wrong_path).is_err(), "bounded to its parent's path");
    let rec = r.derive_child("p", &base, "c", &zc, &ceiling).unwrap();
    assert_eq!(rec.box_path, "p/c");
    assert_eq!(kind(&r.decide(&gh("zc", "c", "GET", "/repos/acme/app"), T0)), "allow");
    assert_eq!(kind(&r.decide(&gh("zc", "c", "POST", "/repos/acme/app/hooks"), T0)), "needs-grant", "the parent's grant isn't the child's");
}

/// #173: a view reads a feed's state from its delta log without writing anything: a torn last line
/// (a publisher mid-write) is skipped, not truncated, and the record is there with its token.
#[test]
fn a_feed_is_read_without_writing_and_a_torn_tail_is_skipped() {
    let mut cp = Cp::new();
    let z = zone("z", &["/v1/**"]);
    let a = cp.issue("r1", &z).publish(&cp.approver, &[]).unwrap();
    cp.put(a.clone(), T0);
    let log = cp._dir.path().join("deltas.jsonl");
    let mut text = std::fs::read(&log).unwrap();
    text.extend_from_slice(b"eyJhbGciOiJFZERTQSJ9.half-a-li");
    std::fs::write(&log, &text).unwrap();
    let st = read_state::<BoxAuthority>(cp._dir.path(), NODE, cp.authz_root.public()).unwrap();
    assert_eq!(st.epoch, 1);
    let e = st.zones.get("r1").expect("the run's record");
    assert_eq!(e.spec.token, a.token);
    assert!(e.compiled.is_ok(), "it loads against the authority root");
    assert_eq!(std::fs::read(&log).unwrap(), text, "nothing written, the torn tail kept for its publisher");
    // Another node's log is refused.
    assert!(read_state::<BoxAuthority>(cp._dir.path(), "n2", cp.authz_root.public()).is_err());
    // A token decoded: block 0, its Datalog and revocation id, no third-party signer.
    let blocks = wicket_authz::describe(&a.token_bytes().unwrap()).unwrap();
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].source.contains("/v1/"), "{}", blocks[0].source);
    assert!(blocks[0].external_key.is_none() && blocks[0].revocation_id.len() == 128);
}

/// #192: a zone's pinned images are in block 0 as written (within the node's structural caps, many
/// of them), and a node decides a spawn by the entry that allows it, read-only.
#[test]
fn pinned_images_are_decided_by_the_token_on_the_node() {
    let mut cp = Cp::new();
    let pins: Vec<String> = (0..32).map(|i| format!("tool{i}@sha256:{}", format!("{i:02x}").repeat(32))).collect();
    let mut z = zone("zp", &["/repos/acme/**"]);
    z.images = pins.clone();
    let parent = cp.issue("p", &z);
    cp.put(parent.publish(&cp.approver, &[]).unwrap(), T0 - 100);
    let mut r = cp.replica();
    sync(&mut cp.p, &mut r, T0);
    let peek = |image: &str| r.peek_spawn("p", TENANT, image, 2, 128 << 20, 500, 64, 300, T0);
    assert!(peek(&pins[7]).is_ok(), "{:?}", peek(&pins[7]));
    assert!(peek(&pins[31]).is_ok());
    assert!(peek(&format!("tool7@sha256:{}", "ff".repeat(32))).is_err(), "another digest");
    assert!(peek("tool7:latest").is_err(), "a tag isn't the pinned entry");
    assert!(r.peek_spawn("nobody", TENANT, &pins[0], 2, 1, 1, 1, 1, T0).is_err());
}
