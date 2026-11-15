//! Console notifications (Web Push) through the console's own routes: who may subscribe, list and
//! remove devices, what the service worker is served with, and the notifier over the real ledger.

use super::http::call;
use super::*;

fn keys() -> (String, String) {
    let k = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    (b64u(k.public_key().to_encoded_point(false).as_bytes()), b64u(&[5u8; 16]))
}

fn cookie(t: &T) -> String {
    format!("__Host-wicket_sid={}", t.sid.as_ref().unwrap())
}

async fn post_as(t: &T, path: &str, body: Value) -> (StatusCode, Value) {
    let c = cookie(t);
    let h = [("x-wicket-csrf", "1"), ("origin", ORIGIN), ("content-type", "application/json"), ("cookie", c.as_str())];
    let (s, _, b) = call(&t.state, "POST", path, &h, body.to_string().as_bytes()).await;
    (s, serde_json::from_str(&b).unwrap_or(Value::Null))
}

/// A recording transport that answers each push with `status(endpoint)`.
fn recorder(t: &mut T, status: fn(&str) -> u16) -> Arc<Mutex<Vec<push::PushRequest>>> {
    let sent: Arc<Mutex<Vec<push::PushRequest>>> = Arc::default();
    let log = sent.clone();
    let transport: push::Transport = Arc::new(move |p: push::PushRequest| {
        let s = status(p.url.as_str());
        log.lock().unwrap().push(p);
        Box::pin(async move { Ok(s) })
    });
    t.state.push = Some(push::Push::open(&t.dir.join("console"), ORIGIN, transport).unwrap());
    sent
}

#[tokio::test]
async fn devices_are_subscribed_listed_and_removed_by_a_signed_in_operator_only() {
    let t = setup("pushapi");
    let (p, a) = keys();
    let sub = json!({ "endpoint": "https://web.push.apple.com/QGh1dGxp", "p256dh": p, "auth": a, "label": "iPhone · Safari" });
    // Without a session: the one 401, for every push route and method.
    for path in ["/api/push", "/api/push/subscribe", "/api/push/remove", "/api/push/details"] {
        for m in ["GET", "POST"] {
            let (s, _, b) = call(&t.state, m, path, &[("x-wicket-csrf", "1"), ("origin", ORIGIN)], sub.to_string().as_bytes()).await;
            assert_eq!((s, b.as_str()), (StatusCode::UNAUTHORIZED, DENIED), "{m} {path}");
        }
    }
    assert_eq!(post(&t.state, "/api/push/subscribe", &anon(), &sub).unwrap().status, StatusCode::UNAUTHORIZED);
    // Signed in: the server's key, and no devices yet.
    let c = cookie(&t);
    let (s, _, b) = call(&t.state, "GET", "/api/push", &[("cookie", c.as_str())], b"").await;
    assert_eq!(s, StatusCode::OK);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["public_key"].as_str().unwrap(), t.state.push.as_ref().unwrap().vapid.public_b64());
    assert_eq!(v["devices"], json!([]));
    // Only known push services, and no arbitrary URL.
    for ep in
        ["https://169.254.169.254/latest", "http://fcm.googleapis.com/x", "https://example.com/push", "https://localhost:8787/api/state"]
    {
        let (s, body) = post_as(&t, "/api/push/subscribe", json!({ "endpoint": ep, "p256dh": p, "auth": a })).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{ep}: {body}");
    }
    let (s, body) = post_as(&t, "/api/push/subscribe", sub.clone()).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let id = body["device"]["id"].as_str().unwrap().to_string();
    let (_, _, b) = call(&t.state, "GET", "/api/push", &[("cookie", c.as_str())], b"").await;
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["devices"][0]["label"], "iPhone · Safari");
    assert_eq!(v["devices"][0]["service"], "web.push.apple.com");
    assert_eq!(v["devices"][0]["details"], false);
    assert!(!b.contains("QGh1dGxp") && !b.contains(&a), "the endpoint and keys aren't shown back");
    // Another operator's session doesn't see or touch it.
    assert!(push_view(&t.state, "someone-else").body["devices"].as_array().unwrap().is_empty());
    assert_eq!(push_post(&t.state, "someone-else", "/api/push/remove", &json!({ "id": id })).status, StatusCode::NOT_FOUND);
    assert_eq!(
        push_post(&t.state, "someone-else", "/api/push/details", &json!({ "id": id, "details": true })).status,
        StatusCode::NOT_FOUND
    );
    // The device's own operator opts in to details, then removes it.
    assert_eq!(post_as(&t, "/api/push/details", json!({ "id": id, "details": true })).await.0, StatusCode::OK);
    assert!(t.state.push.as_ref().unwrap().store.all()[0].details);
    assert_eq!(post_as(&t, "/api/push/remove", json!({ "id": id })).await.0, StatusCode::OK);
    assert_eq!(post_as(&t, "/api/push/remove", json!({ "id": id })).await.0, StatusCode::NOT_FOUND);
    assert!(t.state.push.as_ref().unwrap().store.all().is_empty());
    // Every change is audited, with the device's id (never its endpoint).
    let kinds: Vec<String> = t.audit_kinds().into_iter().map(|(k, _)| k).filter(|k| k.starts_with("operator.push")).collect();
    assert_eq!(kinds, ["operator.push_subscribed", "operator.push_details", "operator.push_removed"]);
    assert!(!t.audit_kinds().iter().any(|(_, b)| b.to_string().contains("QGh1dGxp")));
}

#[tokio::test]
async fn the_service_worker_is_served_at_the_root_under_the_same_csp() {
    let t = setup("pushsw");
    let (s, h, body) = call(&t.state, "GET", "/sw.js", &[], b"").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], "text/javascript; charset=utf-8");
    assert_eq!(h["cache-control"], "no-cache");
    assert_eq!(h["content-security-policy"], web::CSP);
    // Workers fall back to script-src 'self': the CSP needs no change.
    assert!(web::CSP.contains("script-src 'self'") && !web::CSP.contains("worker-src"));
    assert!(body.contains("showNotification") && body.contains("notificationclick") && body.contains("#pending"));
}

#[tokio::test]
async fn new_requests_push_once_per_device_coalesced_and_gone_devices_are_dropped() {
    let mut t = setup("pushnotify");
    let sent = recorder(&mut t, |u| if u.contains("gone") { 410 } else { 201 });
    let (p, a) = keys();
    let store = &t.state.push.as_ref().unwrap().store;
    let live = store.add(&t.cred, "https://fcm.googleapis.com/fcm/send/live", &p, &a, "laptop", true, 0).unwrap();
    store.add(&t.cred, "https://web.push.apple.com/gone", &p, &a, "phone", false, 0).unwrap();
    // A device of a passkey that's no longer enrolled gets nothing.
    store.add("revoked-passkey", "https://updates.push.services.mozilla.com/wpush/v2/x", &p, &a, "", false, 0).unwrap();
    t.running("run_n", "lead");
    let (tn, rn) = (TenantId::single(), RunId("run_n".into()));
    let ask = |path: &str| {
        let op = wicket_core::Op::egress(&tn, &rn, "z", "GET", "api.example.com", path);
        t.ledger().ask(&op, "x", false, None).unwrap().0
    };
    let first = ask("/before-start");
    let mut n = push::Notifier::default();
    assert!(notify_once(&t.state, &mut n, 1000).await.is_empty(), "already waiting at start: no push");
    let r1 = ask("/one");
    let results = notify_once(&t.state, &mut n, 1003).await;
    assert_eq!(results.len(), 2, "one per enrolled passkey's device: {results:?}");
    assert!(notify_once(&t.state, &mut n, 1006).await.is_empty(), "nothing new");
    {
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert!(sent.iter().all(|r| r.url.host_str() != Some("updates.push.services.mozilla.com")));
        let h: HashMap<&str, &str> = sent[0].headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!((h["ttl"], h["urgency"], h["topic"], h["content-encoding"]), ("3600", "high", push::TOPIC, "aes128gcm"));
    }
    // The 410 removed the phone, audited.
    let ids: Vec<String> = t.state.push.as_ref().unwrap().store.all().into_iter().map(|s| s.id).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&live.id));
    assert!(t.audit_kinds().iter().any(|(k, b)| k == "operator.push_removed" && b["by"] == "push service" && b["status"] == 410));
    // A capacity ask (wicket's own) counts too; with two more within 30 s, the laptop gets one push.
    let cap = wicket_core::Op::egress(&tn, &rn, "z", "CAPACITY", "wicket.internal", "/capacity/l-1");
    let (rc, _) = t.ledger().pending_for(&cap, "a gpu node for 2h", None).unwrap();
    assert!(notify_once(&t.state, &mut n, 1010).await.is_empty(), "coalesced");
    let r3 = ask("/three");
    assert!(notify_once(&t.state, &mut n, 1020).await.is_empty(), "coalesced");
    assert_eq!(notify_once(&t.state, &mut n, 1033).await, vec![(live.id.clone(), 201)]);
    assert!(notify_once(&t.state, &mut n, 1070).await.is_empty());
    assert_eq!(sent.lock().unwrap().len(), 3);
    assert_eq!(t.state.push.as_ref().unwrap().store.all().iter().find(|s| s.id == live.id).unwrap().last_success, Some(1033));
    // What the waiting list said, as the laptop (details on) would see it.
    let w = waiting(&t.state).unwrap();
    let mut got: Vec<String> = w.iter().map(|w| w.id.clone()).collect();
    let mut want = vec![first, r1, rc.clone(), r3.clone()];
    got.sort();
    want.sort();
    assert_eq!(got, want, "egress asks and wicket's own capacity ask");
    let of = |id: &str| w.iter().find(|w| w.id == id).unwrap().clone();
    assert_eq!(of(&r3).summary, "lead asks GET api.example.com/three");
    assert_eq!(of(&rc).summary, "lead asks CAPACITY wicket.internal/capacity/l-1");
    let body: Value = serde_json::from_slice(&push::payload(&w, &of(&r3), false)).unwrap();
    assert_eq!(body["body"], "4 requests waiting");
    assert_eq!(body["id"].as_str(), Some(r3.as_str()));
}
