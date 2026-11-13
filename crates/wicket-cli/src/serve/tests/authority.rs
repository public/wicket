//! The console's views of authority (#173): a run's token decoded, the org policy and its versions,
//! "explain a decision"; and that no console response carries a serialized token, a signature, a
//! secret or a private key.

use super::*;
use base64::Engine;
use wicket_feed::{BoxAuthority, Change, Issuer, KeyCert, LiveGrant, Publisher, PublisherConfig};

const RUN: &str = "run_01authz0000000000000000000";
const ZONE: &str = "z-authz";

/// A run with a published token on this host's node: block 0 from its zone and one grant block.
struct Fixture {
    t: T,
    /// The record as the feed holds it (its token included).
    record: BoxAuthority,
    /// Private key material that exists on the host.
    seeds: Vec<[u8; 32]>,
    /// Public keys, which may be shown (third-party blocks name their signer).
    publics: Vec<[u8; 32]>,
    gid: String,
    jws: String,
    op_seq: i64,
}

fn fixture(tag: &str) -> Fixture {
    let mut t = setup(&format!("authority-{tag}"));
    let authz_root = wicket_authz::SigningKey::from_bytes(&[9; 32]).unwrap();
    let approver = wicket_authz::SigningKey::from_bytes(&[10; 32]).unwrap();
    t.state.authz_root = Some(authz_root.public());
    let zone: wicket_core::ZoneSpec = serde_yaml::from_str(&format!(
        "name: {ZONE}\nreach: [{{ host: api.example.com, methods: [GET], paths: ['/v1/**'] }}]\nforbid: [{{ host: api.example.com, paths: ['/admin/**'] }}]\n"
    ))
    .unwrap();
    let now = wicket_store::now();
    let l = t.ledger();
    l.run_started(&TenantId::single(), &RunId(RUN.into()), ZONE, "agent").unwrap();
    l.set_run_node(RUN, crate::localnode::NAME).unwrap();
    let jws = format!("eyJhbGciOiJFZERTQSJ9.{}.{}", "c".repeat(80), "s".repeat(86));
    l.put_identity(&wicket_store::IdentityRow {
        run: RUN.into(),
        tenant: TenantId::single().0,
        spiffe_id: "spiffe://wicket.local/t/agent".into(),
        zone: ZONE.into(),
        agent: "agent".into(),
        parent_run: None,
        accept_from: vec![],
        jws: jws.clone(),
        issued_at: now,
    })
    .unwrap();
    // A human approved a POST under reach: a grant row, and its grant block in the token.
    let mut ledger = t.ledger();
    let op = wicket_core::Op::egress(&TenantId::single(), &RunId(RUN.into()), ZONE, "POST", "api.example.com", "/v1/items");
    let (rid, _) = ledger.pending_for(&op, "write an item", None).unwrap();
    let a = wicket_store::Approval {
        uses: Some(2),
        ttl: std::time::Duration::from_secs(600),
        path_prefix: None,
        decided_by: "passkey:laptop".into(),
    };
    let gid = ledger.approve(&rid, &a).unwrap();
    let issuer = Issuer::root(&authz_root, "t0", "human:op", RUN, 0, &zone, &[], (now + 3600) as u64, vec![approver.public()]).unwrap();
    let grant = wicket_authz::Grant {
        gid: gid.clone(),
        box_id: String::new(),
        epoch: 0,
        host: "api.example.com".into(),
        method: "POST".into(),
        path: "/v1/items".into(),
        not_after: (now + 600) as u64,
        approver: "human:passkey:laptop".into(),
        digest: vec![1, 2, 3],
    };
    let record = issuer.publish(&approver, &[LiveGrant { grant, uses: Some(2) }]).unwrap();
    // This host's node's feed, as a supervisor publishes it.
    let feed_root = wicket_identity::SigningKey::from_bytes(&[7; 32]);
    let feed_key = wicket_identity::SigningKey::from_bytes(&[8; 32]);
    let cert =
        wicket_feed::sign(&feed_root, wicket_feed::TYP_KEY, &KeyCert::new(&feed_key.verifying_key(), 1, now * 1000 + 86_400_000, 30_000));
    let fdir = t.dir.join("nodes").join(crate::localnode::NAME).join("feed");
    let mut p = Publisher::open_with(
        &fdir,
        crate::localnode::NAME,
        &feed_root.verifying_key(),
        feed_key,
        &cert,
        PublisherConfig { ttl_ms: 30_000, refresh_ms: 1000, retain: 100 },
        authz_root.public(),
    )
    .unwrap();
    p.commit(vec![Change::PutZone { zone: record.clone() }], now * 1000).unwrap();
    // What the node holds for it (#152): a secret by name, and a budget slice.
    std::fs::create_dir_all(t.dir.join("runs").join(RUN).join("ctl")).unwrap();
    std::fs::write(
        t.dir.join("runs").join(RUN).join("ctl/holdings.json"),
        json!({ "secrets": ["gh"], "slice": { "requests": 10, "output_tokens": 1000 }, "updated_ms": now * 1000 }).to_string(),
    )
    .unwrap();
    // Two decisions on its requests: the control host's, and its node's (as shipped).
    let d = |path: &str, outcome: &str| json!({ "kind": "egress", "host": "api.example.com", "method": "POST", "path": path, "outcome": outcome, "detail": "recorded detail", "risk": "R2WriteReversible" });
    let op_seq = l.audit(&TenantId::single(), Some(&RunId(RUN.into())), "op", &d("/v1/items", "allow")).unwrap();
    l.audit(
        &TenantId::single(),
        Some(&RunId(RUN.into())),
        "node.audit",
        &json!({ "attributed": true, "body": d("/admin/x", "forbidden").to_string() }),
    )
    .unwrap();
    // An org policy, applied.
    let pdir = t.dir.join("policy");
    std::fs::create_dir_all(pdir.join("versions")).unwrap();
    let cedar = "permit(principal, action, resource);\n";
    let v = wicket_policy::version(cedar, "[]");
    std::fs::write(pdir.join("org.cedar"), cedar).unwrap();
    std::fs::write(pdir.join("org-entities.json"), "[]").unwrap();
    std::fs::write(pdir.join("installed"), &v).unwrap();
    std::fs::write(pdir.join("versions").join(format!("{v}.cedar")), cedar).unwrap();
    l.audit(&TenantId::single(), None, "policy.applied", &json!({ "version": v, "previous": null, "by": "root@host" })).unwrap();
    l.set_run_policy(RUN, Some(&v)).unwrap();
    let seeds = vec![[7; 32], [8; 32], [9; 32], [10; 32]];
    let publics = vec![authz_root.public().0, approver.public().0];
    Fixture { t, record, seeds, publics, gid, jws, op_seq }
}

/// Everything that must never be in a response: the token and any run of its bytes (signatures
/// included) in base64url, base64 and hex, except runs inside a public key (which may be shown); the
/// identity JWS; private keys.
fn needles(f: &Fixture) -> Vec<String> {
    let b = f.record.token_bytes().unwrap();
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let std = base64::engine::general_purpose::STANDARD;
    let public_hex: Vec<String> = f.publics.iter().map(hex::encode).collect();
    let mut v = vec![f.record.token.clone(), std.encode(&b), hex::encode(&b), f.jws.clone(), f.jws.split('.').nth(2).unwrap().to_string()];
    const W: usize = 24;
    for i in 0..b.len().saturating_sub(W) {
        let w = &b[i..i + W];
        let h = hex::encode(w);
        if public_hex.iter().any(|p| p.contains(&h)) {
            continue;
        }
        v.push(h);
        if i % 3 == 0 {
            v.push(url.encode(w));
            v.push(std.encode(w));
        }
    }
    for s in &f.seeds {
        v.push(hex::encode(s));
        v.push(url.encode(s));
        v.push(std.encode(s));
    }
    v
}

fn leaks(body: &str, needles: &[String]) -> Vec<String> {
    needles.iter().filter(|n| body.contains(n.as_str())).map(|n| n.chars().take(16).collect()).collect()
}

async fn get(t: &T, path: &str) -> (StatusCode, Value, String) {
    let c = format!("__Host-wicket_sid={}", t.sid.clone().unwrap());
    let (s, _, body) = super::http::call(&t.state, "GET", path, &[("cookie", &c)], b"").await;
    (s, serde_json::from_str(&body).unwrap_or(Value::Null), body)
}

#[tokio::test]
async fn a_runs_page_shows_its_token_decoded_and_its_holdings() {
    let f = fixture("page");
    let (s, a, _) = get(&f.t, &format!("/api/runs/{RUN}/authority")).await;
    assert_eq!(s, StatusCode::OK, "{a}");
    assert_eq!(a["node"], crate::localnode::NAME);
    assert_eq!(a["policy"]["current"], true);
    let tok = &a["token"];
    assert_eq!(tok["held"], true, "{a}");
    assert_eq!(tok["loads"], true, "{tok}");
    let blocks = tok["blocks"].as_array().unwrap();
    assert_eq!(blocks.iter().map(|b| b["kind"].as_str().unwrap()).collect::<Vec<_>>(), ["zone", "grant"]);
    assert!(blocks[0]["source"].as_str().unwrap().contains("api.example.com"), "{}", blocks[0]["source"]);
    assert!(blocks[1]["signed_by"].as_str().unwrap().contains(&hex::encode(f.publics[1])), "the grant's signer, public");
    assert!(blocks.iter().all(|b| b["revoked"] == false && b["revocation_fingerprint"].as_str().unwrap().len() == 16));
    let g = &tok["grants"][0];
    assert_eq!(
        (g["id"].as_str(), g["method"].as_str(), g["path"].as_str(), g["uses"].as_u64()),
        (Some(f.gid.as_str()), Some("POST"), Some("/v1/items"), Some(2))
    );
    assert_eq!(g["approved_by"], "passkey:laptop");
    assert!(tok["zone_cedar"].as_str().unwrap().contains("permit("));
    assert_eq!(a["holdings"]["secrets"], json!(["gh"]));
    assert_eq!(a["holdings"]["slice"]["requests"], 10);
    // A run that doesn't exist, or a name that isn't a run id.
    assert_eq!(get(&f.t, "/api/runs/run_nope/authority").await.0, StatusCode::NOT_FOUND);
    assert_eq!(get(&f.t, "/api/runs/..%2f..%2fetc/authority").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_decision_is_explained_by_the_block_that_made_it() {
    let f = fixture("explain");
    // Allowed by the grant (no use is spent explaining it).
    let (s, x, _) = get(&f.t, &format!("/api/explain/{}", f.op_seq)).await;
    assert_eq!(s, StatusCode::OK, "{x}");
    assert_eq!(x["recorded"]["outcome"], "allow");
    assert_eq!(x["against_token_now"]["decision"], "allow", "{x}");
    assert!(x["against_token_now"]["why"].as_str().unwrap().contains(&f.gid), "{x}");
    // A node's record of a refusal: a forbid rule, named by its block.
    let (_, x, _) = get(&f.t, &format!("/api/explain/{}", f.op_seq + 1)).await;
    assert_eq!(x["recorded"]["decided_on"], "the box's node");
    assert_eq!(x["against_token_now"]["decision"], "forbidden", "{x}");
    assert!(x["against_token_now"]["why"].as_str().unwrap().contains("block 0"), "{x}");
    // Not a decision (the policy's apply record).
    let (s, _, _) = get(&f.t, &format!("/api/explain/{}", f.op_seq + 2)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_policy_page_shows_the_applied_cedar_its_versions_and_runs() {
    let f = fixture("policy");
    let (s, p, _) = get(&f.t, "/api/policy").await;
    assert_eq!(s, StatusCode::OK, "{p}");
    assert!(p["current"]["cedar"].as_str().unwrap().contains("permit"));
    assert_eq!(p["current"]["matches_applied"], true);
    assert_eq!(p["versions"][0]["current"], true);
    assert_eq!(p["versions"][0]["applied"][0]["by"], "root@host");
    assert_eq!(p["runs"][0]["status"], "current", "{p}");
}

#[tokio::test]
async fn authority_views_never_carry_a_token_signature_secret_or_key() {
    let f = fixture("leak");
    let n = needles(&f);
    // The scanner finds them where they are: in the stored record itself.
    assert!(!leaks(&serde_json::to_string(&f.record).unwrap(), &n).is_empty(), "the scanner must catch the raw record");
    let paths = [
        "/api/me".to_string(),
        "/api/state".into(),
        "/api/policy".into(),
        format!("/api/runs/{RUN}/authority"),
        "/api/runs/run_nope/authority".into(),
        format!("/api/explain/{}", f.op_seq),
        format!("/api/explain/{}", f.op_seq + 1),
        "/api/explain/999999".into(),
        "/api/explain/x".into(),
    ];
    for p in paths {
        let (s, _, body) = get(&f.t, &p).await;
        assert!(leaks(&body, &n).is_empty(), "{p} ({s}) leaks {:?}", leaks(&body, &n));
    }
    // Signed out: the same views refuse, and say nothing.
    for p in ["/api/policy", "/api/runs/run_01authz0000000000000000000/authority", "/api/explain/1"] {
        let (s, _, body) = super::http::call(&f.t.state, "GET", p, &[], b"").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{p}: {body}");
    }
}
