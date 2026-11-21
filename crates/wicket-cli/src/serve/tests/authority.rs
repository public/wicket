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
    let zone: wicket_core::ZoneSpec = wicket_core::yaml::from_str(&format!(
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
    let record = issuer.publish(&approver, &[LiveGrant { grant, uses: Some(2), prefix: false, standing: None }]).unwrap();
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
    // An exact grant says so, and carries no standing rule (#715 review: the view shows what a prefix
    // or standing grant reaches from these).
    assert_eq!((&g["prefix"], &g["standing"]), (&json!(false), &Value::Null));
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

/// The issuer the leak scan's identities are signed with: `verify_signed` checks against it.
static TEST_ISSUER: std::sync::OnceLock<wicket_identity::Issuer> = std::sync::OnceLock::new();

fn verify_signed(l: &wicket_store::Ledger, run: &str) -> Value {
    wicket_home::verified_identity_by(l, run, None, || {
        Ok(TEST_ISSUER.get_or_init(|| wicket_identity::Issuer::generate("wicket.test")).verifying_key())
    })
}

#[tokio::test]
async fn authority_views_never_carry_a_token_signature_secret_or_key() {
    let mut f = fixture("leak");
    super::nodes::enrol(&mut f.t.ledger(), "n1", &TenantId::single().0, &["api.example.com"]);
    let mut n = needles(&f);
    // A node enrolled with keys and a join token of its own (#713 review): only its host key's
    // fingerprint may be shown.
    {
        let mut l = f.t.ledger();
        let tok = l.create_node_token(&TenantId::single(), "n2", 600).unwrap();
        let node = wicket_store::NodeRow {
            name: "n2".into(),
            tenant: TenantId::single().0,
            target: "wicket@node2".into(),
            host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIleakyhostkeyleakyhostkeyleaky".into(),
            host_key_fp: "SHA256:fingerprint-n2".into(),
            node_key: "4e6f64654b65794c65616b4e6f64654b65794c65616b4e6f64654b65794c6561".into(),
            ssh_key: Some("an ssh key leakysshkeyleakysshkey".into()),
            hosts: vec!["api.example.com".into()],
            enrolled_at: wicket_store::now(),
            status: "active".into(),
            revoked_at: None,
        };
        let ca = wicket_store::NodeCaRow {
            serial: "n2-01".into(),
            node: "n2".into(),
            issued_at: wicket_store::now(),
            not_after: wicket_store::now() + 86_400,
            hosts: vec!["api.example.com".into()],
            status: "active".into(),
        };
        l.enrol_node(&tok, &node, &ca).unwrap();
        n.extend([tok, node.host_key.clone(), node.node_key.clone(), "leakysshkey".into()]);
    }
    // A real identity, signed by the issuer this view checks against: shown verified, its document
    // never.
    let signed_run = RunId::new();
    {
        let issuer = TEST_ISSUER.get_or_init(|| wicket_identity::Issuer::generate("wicket.test"));
        let key = wicket_identity::AgentKey::generate();
        let spec = wicket_identity::IdentitySpec {
            tenant: TenantId::single().0,
            zone: ZONE.into(),
            agent: "signed".into(),
            run: signed_run.0.clone(),
            parent_run: None,
            manifest_sha256: "m".into(),
            image: "img".into(),
            node: "local".into(),
            principal: json!({ "type": "human", "id": "alex", "via": "cli" }),
            act: None,
            kind: None,
        };
        let now = wicket_store::now();
        let jws = issuer.issue(&spec, now, 600, &key.public());
        let claims = wicket_identity::verify_identity(&jws, &issuer.verifying_key(), now).unwrap();
        let l = f.t.ledger();
        l.run_started(&TenantId::single(), &signed_run, ZONE, "signed").unwrap();
        l.put_identity(&wicket_store::IdentityRow {
            run: signed_run.0.clone(),
            tenant: TenantId::single().0,
            spiffe_id: claims.sub,
            zone: ZONE.into(),
            agent: "signed".into(),
            parent_run: None,
            accept_from: vec![],
            jws: jws.clone(),
            issued_at: now,
        })
        .unwrap();
        n.push(jws.split('.').nth(2).unwrap().to_string());
        n.push(jws);
    }
    f.t.state.identity = verify_signed;
    // A public name of the run with the token, approved, with a connection its node shipped
    // (#575 review, L6): the names views scanned are real ones, not an empty card.
    let _h = super::names_card::Hooks;
    super::names_card::set_settings(Some(Ok(super::names_card::names_cfg("boxes.example.com"))));
    let nid = {
        let l = f.t.ledger();
        let ask = wicket_store::NameAsk {
            tenant: &TenantId::single(),
            run: &RunId(RUN.into()),
            zone: ZONE,
            zone_digest: "zd",
            principal: "spiffe://wicket.local/t/agent",
            label: "leaky",
            port: 3000,
            service: Some("http"),
            reason: "a demo",
            scope: wicket_store::NameScope::Standing,
        };
        let id = l.ask_public(&ask).unwrap().0;
        let public = super::names_card::names_cfg("boxes.example.com").public.unwrap();
        let terms = wicket_store::NameTerms { bound: wicket_store::StandingBound::Agent, ttl_secs: Some(3600) };
        let shown = wicket_store::name_effect(&l.name(&id).unwrap(), &terms, &public.domain());
        l.approve_name(&id, &terms, "passkey:laptop", Some(&shown), &public).unwrap();
        let conn = json!({ "name": id, "port": 3000, "phase": "start", "conn": "c1", "peer": "192.0.2.9:5000" });
        let outer = json!({ "node": crate::localnode::NAME, "seq": 1, "ts": 1, "tenant": "t0", "run": RUN, "kind": "name.conn", "body": conn.to_string() });
        l.audit(&TenantId::single(), Some(&RunId(RUN.into())), "node.audit", &outer).unwrap();
        id
    };
    let (s, d, body) = get(&f.t, &format!("/api/names/{nid}")).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert!(body.contains("leaky.boxes.example.com"), "the settings reached the handler: {body}");
    assert!(d["connections"].as_array().is_some_and(|c| !c.is_empty()), "{d}");
    // The scanner finds them where they are: in the stored record itself.
    assert!(!leaks(&serde_json::to_string(&f.record).unwrap(), &n).is_empty(), "the scanner must catch the raw record");
    // A placement decision recorded for the run, so the scan sees one.
    f.t.ledger()
        .record_placement_decision(
            RUN,
            &json!({ "request": { "vcpus": 1.0, "memory_mib": 512 }, "ca_hosts": ["api.example.com"], "node": "local",
                     "candidates": 1, "ranked": ["local"], "ranked_more": 0, "refused": [], "refused_more": 0, "behind": null })
            .to_string(),
            wicket_feed::now_ms(),
        )
        .unwrap();
    // The host-only lists the console shows now (#713), each with something in it: a link, a
    // webhook trigger (its URL token never shown), a service; the run's grant, identity and node,
    // and this session, are the fixture's.
    {
        let l = f.t.ledger();
        l.add_link(&wicket_store::LinkRow {
            id: "lk-1".into(),
            tenant: TenantId::single().0,
            from_run: RUN.into(),
            to_run: RUN.into(),
            port: 8080,
            name: "api".into(),
            addr: "10.0.0.2".into(),
            by_run: RUN.into(),
            basis: "child".into(),
            status: "open".into(),
            created_at: 1,
            closed_at: None,
            closed_by: None,
            close_reason: None,
        })
        .unwrap();
        let spec: wicket_core::trigger::TriggerSpec = wicket_core::yaml::from_str(
            "trigger: hook\nsource: { webhook: { verify: { hmac_sha256: hook-key } } }\naction: { wake: agent }\n",
        )
        .unwrap();
        let tid = l.create_trigger("t0", "spiffe://wicket.local/t/t0/op/passkey/laptop", &spec, "passkey:laptop", false, None).unwrap();
        // Its URL's token (what a delivery presents): neither it nor its hash is ever shown.
        let url_token = "hooktoken-0123456789abcdef0123456789abcdef";
        let url_sha = hex::encode(sha2::Sha256::digest(url_token.as_bytes()));
        l.set_trigger_intake(&tid, "local", &url_sha).unwrap();
        n.extend([url_token.to_string(), url_sha]);
        l.add_service("npm-cache", "/data/services/npm-cache/manifest.yaml", &"ab".repeat(32), "t0", "root").unwrap();
    }
    let host_lists = ["/api/grants", "/api/links", "/api/triggers", "/api/nodes", "/api/services", "/api/identities", "/api/sessions"];
    let (_, ids, _) = get(&f.t, "/api/identities").await;
    let signed = ids.as_array().unwrap().iter().find(|i| i["run"] == signed_run.0.as_str()).cloned().unwrap_or_default();
    assert_eq!(signed["identity"]["verified"], true, "the signed identity verifies: {ids}");
    for p in host_lists {
        let (s, v, body) = get(&f.t, p).await;
        assert_eq!(s, StatusCode::OK, "{p}: {body}");
        assert!(v.as_array().is_some_and(|a| !a.is_empty()), "{p} lists something: {body}");
        // A session's token, or its whole hash, is never in a view.
        let sid = f.t.sid.clone().unwrap();
        assert!(!body.contains(&sid) && !body.contains(&super::super::session_id(&sid)), "{p} shows a session token or its hash");
    }
    let paths = [
        "/api/grants".to_string(),
        "/api/links".into(),
        "/api/triggers".into(),
        "/api/nodes".into(),
        "/api/services".into(),
        "/api/identities".into(),
        "/api/sessions".into(),
        "/api/me".to_string(),
        "/api/state".into(),
        "/api/policy".into(),
        "/api/messages".into(),
        format!("/api/runs/{RUN}/authority"),
        "/api/runs/run_nope/authority".into(),
        format!("/api/runs/{RUN}/placement"),
        format!("/api/explain/{}", f.op_seq),
        format!("/api/explain/{}", f.op_seq + 1),
        "/api/explain/999999".into(),
        "/api/explain/x".into(),
        "/api/names".into(),
        format!("/api/names/{nid}"),
        "/api/names/n-nope".into(),
        "/api/nodes/n1/ca".into(),
        "/api/nodes/nope/ca".into(),
    ];
    // The views that answer must answer (an error page would scan clean and prove nothing).
    let answers = [
        "/api/me".to_string(),
        "/api/state".into(),
        "/api/policy".into(),
        format!("/api/runs/{RUN}/authority"),
        format!("/api/runs/{RUN}/placement"),
        format!("/api/explain/{}", f.op_seq),
    ];
    for p in paths {
        let (s, _, body) = get(&f.t, &p).await;
        if answers.contains(&p) {
            assert_eq!(s, StatusCode::OK, "{p}: {body}");
        }
        assert!(leaks(&body, &n).is_empty(), "{p} ({s}) leaks {:?}", leaks(&body, &n));
    }
    // The POST views too (#252): marking messages read answers with ids, never more.
    let r = f.t.post("/api/messages/read", serde_json::json!({ "ids": ["m-1", f.gid] }));
    let body = r.body.to_string();
    assert!(leaks(&body, &n).is_empty(), "/api/messages/read ({}) leaks {:?}", r.status, leaks(&body, &n));
    // The org policy preview (#712), of the applied policy and of another.
    let org = include_str!("../../../../../examples/policy/org.cedar");
    for body in
        [json!({ "cedar": org }), json!({ "cedar": org, "entities": include_str!("../../../../../examples/policy/org-entities.json") })]
    {
        let r = f.t.post("/api/policy/preview", body);
        assert_eq!(r.status, StatusCode::OK, "the preview answered: {:?}", r.body);
        let text = r.body.to_string();
        assert!(leaks(&text, &n).is_empty(), "/api/policy/preview ({}) leaks {:?}", r.status, leaks(&text, &n));
    }
    // Signed out: the same views refuse, and say nothing.
    for p in [
        "/api/policy",
        "/api/runs/run_01authz0000000000000000000/authority",
        "/api/runs/run_01authz0000000000000000000/placement",
        "/api/explain/1",
        "/api/names",
        "/api/names/n-1",
        "/api/nodes/n1/ca",
    ] {
        let (s, _, body) = super::http::call(&f.t.state, "GET", p, &[], b"").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{p}: {body}");
    }
}

/// #713: `wicket authority` and `wicket audit explain` print these views from the host. With a
/// held token, the JSON has the fields the CLI reference lists, and the text names each block and
/// grant.
#[test]
fn the_cli_prints_the_same_views_with_a_held_token() {
    let f = fixture("cli");
    let s = &f.t.state;
    let views = crate::serve::authority::Views { ledger: &s.ledger, data: &s.data, tenant: &s.tenant, authz_root: s.authz_root.as_ref() };
    let a = crate::serve::authority::run_authority(&views, RUN).unwrap();
    assert_eq!((a["token"]["held"].as_bool(), a["feed"]["epoch"].is_u64()), (Some(true), true), "{a}");
    crate::cmd::json_tests::documented_as("`wicket authority --json`", &a);
    let text = crate::cmd::authority::authority_text(&a);
    assert!(text.contains("block 0 (zone)") && text.contains("block 1 (grant), signed by"), "{text}");
    assert!(text.contains(&format!("grant {}  POST api.example.com/v1/items  approved by passkey:laptop", f.gid)), "{text}");
    let x = crate::serve::authority::explain(&views, f.op_seq).unwrap();
    crate::cmd::json_tests::documented_as("`wicket audit explain --json`", &x);
    let text = crate::cmd::authority::explain_text(&x);
    assert!(text.contains("against its token now: allow:"), "{text}");
}

/// #713 review: the host's lists are the console's tenant's. Another tenant's grant, link, trigger,
/// node, service, identity and console session are in none of them.
#[tokio::test]
async fn the_host_lists_are_the_consoles_tenants_only() {
    let f = fixture("tenants");
    let other = TenantId("t9".into());
    let theirs = RunId("run_01other00000000000000000000".into());
    {
        let mut l = f.t.ledger();
        l.run_started(&other, &theirs, "z9", "theirs").unwrap();
        let op = wicket_core::Op::egress(&other, &theirs, "z9", "GET", "their.example", "/x");
        let (rid, _) = l.pending_for(&op, "theirs", None).unwrap();
        let a =
            wicket_store::Approval { uses: Some(1), ttl: std::time::Duration::from_secs(600), path_prefix: None, decided_by: "op".into() };
        l.approve(&rid, &a).unwrap();
        l.add_link(&wicket_store::LinkRow {
            id: "lk-theirs".into(),
            tenant: other.0.clone(),
            from_run: theirs.0.clone(),
            to_run: theirs.0.clone(),
            port: 9,
            name: "theirs".into(),
            addr: "10.9.9.9".into(),
            by_run: theirs.0.clone(),
            basis: "child".into(),
            status: "open".into(),
            created_at: 1,
            closed_at: None,
            closed_by: None,
            close_reason: None,
        })
        .unwrap();
        let spec: wicket_core::trigger::TriggerSpec =
            wicket_core::yaml::from_str("trigger: theirs\nsource: { webhook: { verify: { hmac_sha256: k } } }\naction: { wake: agent }\n")
                .unwrap();
        l.create_trigger("t9", "spiffe://wicket.local/t/t9/op/unix/theirs", &spec, "unix:theirs", false, None).unwrap();
        super::nodes::enrol(&mut l, "n-theirs", "t9", &["their.example"]);
        l.add_service("svc-theirs", "/data/services/theirs.yaml", &"cd".repeat(32), "t9", "root").unwrap();
        l.put_identity(&wicket_store::IdentityRow {
            run: theirs.0.clone(),
            tenant: other.0.clone(),
            spiffe_id: "spiffe://wicket.local/t/t9/z/z9/a/theirs".into(),
            zone: "z9".into(),
            agent: "theirs".into(),
            parent_run: None,
            accept_from: vec![],
            jws: "eyJ0aGVpcnMifQ.dGhlaXJz.dGhlaXJz".into(),
            issued_at: 1,
        })
        .unwrap();
        l.add_console_session(
            &other,
            &wicket_store::ConsoleSession {
                id: "9e".repeat(32),
                kind: "operator".into(),
                credential: Some("cred-theirs".into()),
                client: "192.0.2.99".into(),
                created_at: wicket_store::now(),
                last_seen_at: wicket_store::now(),
                expires_at: wicket_store::now() + 3600,
            },
        )
        .unwrap();
    }
    for p in ["/api/grants", "/api/links", "/api/triggers", "/api/nodes", "/api/services", "/api/identities", "/api/sessions"] {
        let (s, _, body) = get(&f.t, p).await;
        assert_eq!(s, StatusCode::OK, "{p}: {body}");
        for theirs in ["their.example", "lk-theirs", "t9", "n-theirs", "svc-theirs", &theirs.0, "9e9e9e9e", "cred-theirs"] {
            assert!(!body.contains(theirs), "{p} shows another tenant's {theirs}: {body}");
        }
    }
}
