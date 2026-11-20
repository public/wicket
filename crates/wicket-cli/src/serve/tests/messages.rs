//! The console's half of humans in the agent-to-agent protocol (#252): the passkey's operator sends
//! a signed message, reads its inbox, follows its receipts and marks what it read, under the rules
//! `wicket message` follows.

use super::*;

async fn get(t: &T, path: &str) -> (StatusCode, Value) {
    let c = format!("__Host-wicket_sid={}", t.sid.clone().unwrap());
    let (s, _, body) = super::http::call(&t.state, "GET", path, &[("cookie", &c)], b"").await;
    (s, serde_json::from_str(&body).unwrap_or(Value::Null))
}

/// A console with an issuer, and a running agent `worker` that acts for the passkey's operator
/// (`laptop`), as one the console started would. Returns the operator's and the agent's ids, and
/// the agent's key and identity, to write as it.
fn with_agent(t: &mut T) -> (String, String, wicket_identity::AgentKey, String) {
    let issuer = Arc::new(wicket_identity::Issuer::generate("w.test"));
    t.state.issuer = Some(issuer.clone());
    let ten = TenantId::single();
    let me = wicket_identity::operator_id("w.test", &ten.0, "passkey", "laptop");
    let key = wicket_identity::AgentKey::generate();
    let spec = wicket_identity::IdentitySpec {
        tenant: ten.0.clone(),
        zone: "z".into(),
        agent: "worker".into(),
        run: "run_w".into(),
        parent_run: None,
        manifest_sha256: "m".into(),
        image: "img".into(),
        node: "local".into(),
        principal: json!({ "type": "human", "id": "passkey:laptop", "via": "console", "sub": me }),
        act: None,
    };
    let now = wicket_store::now();
    let jws = issuer.issue(&spec, now, 600, &key.public());
    let sub = wicket_identity::spiffe_id("w.test", &ten.0, "z", "worker");
    let l = t.ledger();
    l.run_started(&ten, &RunId("run_w".into()), "z", "worker").unwrap();
    l.put_identity(&wicket_store::IdentityRow {
        run: "run_w".into(),
        tenant: ten.0.clone(),
        spiffe_id: sub.clone(),
        zone: "z".into(),
        agent: "worker".into(),
        parent_run: None,
        accept_from: vec![],
        jws: jws.clone(),
        issued_at: now,
    })
    .unwrap();
    (me, sub, key, jws)
}

#[tokio::test]
async fn the_passkeys_operator_sends_signed_reads_its_inbox_and_marks_it_read() {
    let mut t = setup("messages");
    let (me, worker, key, jws) = with_agent(&mut t);

    // Sending is a signed action, bound to the whole message.
    let b = t.begin(json!({ "action": "send_message", "to": worker, "text": "ship it", "priority": "now" }));
    assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
    assert_eq!((b.body["action"]["from"].as_str(), b.body["action"]["text"].as_str()), (Some(me.as_str()), Some("ship it")));
    let r = t.act(json!({ "action": "send_message", "to": worker, "text": "ship it", "priority": "now" }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(r.body["ok"].as_str().unwrap().contains("delivered"), "{:?}", r.body);
    let m = t.ledger().take_message("run_w").unwrap().expect("in the agent's inbox");
    let (sender, payload) = wicket_identity::verify_any_envelope(&m.envelope, &t.state.issuer.as_ref().unwrap().verifying_key(), m.created_at).unwrap();
    assert_eq!((sender.principal(), payload["body"].as_str(), payload["priority"].as_str()), (me.as_str(), Some("ship it"), Some("now")));
    let rec = t.audit_kinds().into_iter().find(|(k, _)| k == "message").expect("audited").1;
    assert_eq!((rec["via"].as_str(), rec["signed"]["credential"].as_str()), (Some("passkey"), Some(t.cred.as_str())));

    // An agent that doesn't act for it, and whose accept_from doesn't name it, is refused.
    let l = t.ledger();
    l.run_started(&TenantId::single(), &RunId("run_x".into()), "z", "other").unwrap();
    let other = wicket_identity::spiffe_id("w.test", &TenantId::single().0, "z", "other");
    l.put_identity(&wicket_store::IdentityRow {
        run: "run_x".into(),
        tenant: TenantId::single().0,
        spiffe_id: other.clone(),
        zone: "z".into(),
        agent: "other".into(),
        parent_run: None,
        accept_from: vec![],
        jws: "x.y.z".into(),
        issued_at: wicket_store::now(),
    })
    .unwrap();
    drop(l);
    let r = t.act(json!({ "action": "send_message", "to": other, "text": "hi" }));
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert!(r.body["error"].as_str().unwrap().contains("does not accept messages from you"), "{:?}", r.body);
    assert_eq!(t.begin(json!({ "action": "send_message", "to": "run_w", "text": "x" })).status, StatusCode::BAD_REQUEST);

    // The agent answers; the inbox shows it verified, and reading it changes nothing.
    let now = wicket_store::now();
    let payload = json!({ "jti": "m-back", "iat": now, "kind": "message", "to": me, "body": "shipped", "reply_to": worker, "priority": "next", "in_reply_to": m.id });
    let env = wicket_identity::sign_envelope(&key, &jws, &payload);
    let meta = wicket_store::MessageMeta { from_principal: Some(&worker), in_reply_to: Some(&m.id), ..Default::default() };
    t.ledger().post_message("m-back", &TenantId::single(), "run_w", &me, None, &env, &meta).unwrap();
    let (s, v) = get(&t, "/api/messages").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["you"], me);
    assert_eq!((v["inbox"][0]["message_id"].as_str(), v["inbox"][0]["body"].as_str()), (Some("m-back"), Some("shipped")), "{v}");
    assert!(v["inbox"][0]["read_at"].is_null());
    assert_eq!(v["principals"][0]["id"], worker.as_str());
    assert!(v["receipts"].as_array().unwrap().iter().any(|r| r["state"] == "refused"), "{v}");
    assert_eq!(t.ledger().receipt("m-back").unwrap().unwrap().state, "delivered");

    // Marking read: only its own, and once.
    let r = t.post("/api/messages/read", json!({ "ids": ["m-back", "m-nope"] }));
    assert_eq!(r.body["read"], json!(["m-back"]), "{:?}", r.body);
    assert_eq!(t.ledger().receipt("m-back").unwrap().unwrap().state, "read");
    assert_eq!(t.post("/api/messages/read", json!({ "ids": ["m-back"] })).body["read"], json!([]));
    assert_eq!(t.post("/api/messages/read", json!({})).status, StatusCode::BAD_REQUEST);
    assert!(t.audit_kinds().iter().any(|(k, b)| k == "message.read" && b["via"] == "console"));

    // Without a session, none of it.
    assert_eq!(post(&t.state, "/api/messages/read", &anon(), &json!({ "ids": ["m-back"] })).unwrap().status, StatusCode::UNAUTHORIZED);
    assert_eq!(post(&t.state, "/api/action/begin", &anon(), &json!({ "action": "send_message", "to": worker, "text": "x" })).unwrap().status, StatusCode::UNAUTHORIZED);
}

/// A console without an issuer key says so, rather than sending unsigned.
#[tokio::test]
async fn without_an_issuer_messages_are_unavailable() {
    let t = setup("messages-off");
    assert_eq!(get(&t, "/api/messages").await.0, StatusCode::SERVICE_UNAVAILABLE);
    let to = wicket_identity::spiffe_id("w.test", "default", "z", "a");
    assert_eq!(t.begin(json!({ "action": "send_message", "to": to, "text": "x" })).status, StatusCode::SERVICE_UNAVAILABLE);
}
