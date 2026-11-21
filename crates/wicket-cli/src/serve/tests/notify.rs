//! Console notifications (Web Push) through the console's own routes: who may subscribe, list and
//! remove devices, what the service worker is served with, and the notifier over the real ledger.

use super::http::call;
use super::*;

pub(super) fn keys() -> (String, String) {
    let k = p256::SecretKey::from_slice(&[0x11; 32]).unwrap();
    use p256::elliptic_curve::sec1::ToSec1Point;
    (b64u(k.public_key().to_sec1_point(false).as_bytes()), b64u(&[5u8; 16]))
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
    let mut t = setup("pushapi");
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
    // Only known push services, and no arbitrary URL: refused before anything is signed.
    for ep in
        ["https://169.254.169.254/latest", "http://fcm.googleapis.com/x", "https://example.com/push", "https://localhost:8787/api/state"]
    {
        let r = t.begin(json!({ "action": "push_subscribe", "endpoint": ep, "p256dh": p, "auth": a }));
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{ep}: {:?}", r.body);
    }
    let r = t.begin(json!({ "action": "push_subscribe", "endpoint": "https://fcm.googleapis.com/x", "p256dh": "AAAA", "auth": a }));
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "a bad key is refused at begin: {:?}", r.body);
    // A session alone (a stolen cookie) can't register a device: refused, and the refusal audited.
    let (s, body) = post_as(&t, "/api/push/subscribe", sub.clone()).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap().contains("signed action"), "{body}");
    assert!(t.state.push.as_ref().unwrap().store.all().is_empty(), "nothing registered");
    let refused = t.audit_kinds().into_iter().find(|(k, _)| k == "operator.push_refused").expect("audited");
    assert_eq!((refused.1["reason"].as_str(), refused.1["credential"].as_str()), (Some("unsigned subscribe"), Some(t.cred.as_str())));
    // Nor can a begun action be finished without the passkey's signature.
    let b = t.begin(json!({ "action": "push_subscribe", "endpoint": sub["endpoint"], "p256dh": p, "auth": a, "label": "iPhone · Safari" }));
    assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
    let signed = &b.body["action"];
    assert_eq!(signed["device"].as_str().unwrap(), push::subscription_id("https://web.push.apple.com/QGh1dGxp"));
    assert_eq!(
        (signed["service"].as_str(), signed["label"].as_str(), signed["details"].as_bool()),
        (Some("web.push.apple.com"), Some("iPhone · Safari"), Some(false))
    );
    assert!(
        !signed.to_string().contains("QGh1dGxp") && !signed.to_string().contains(&a),
        "the signed JSON holds digests, not the endpoint or keys"
    );
    let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
    let mut forged = t.sign(&ch);
    forged["signature"] = json!(b64u(b"not a signature"));
    assert_eq!(t.post("/api/action/finish", forged).status, StatusCode::FORBIDDEN);
    assert!(t.state.push.as_ref().unwrap().store.all().is_empty(), "nothing registered without a valid signature");
    // Signed with the passkey: registered, and audited with the signature.
    let r = t.act(json!({ "action": "push_subscribe", "endpoint": sub["endpoint"], "p256dh": p, "auth": a, "label": "iPhone · Safari" }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let id = push::subscription_id("https://web.push.apple.com/QGh1dGxp");
    let (_, _, b) = call(&t.state, "GET", "/api/push", &[("cookie", c.as_str())], b"").await;
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["devices"][0]["id"], id.as_str());
    assert_eq!(v["devices"][0]["label"], "iPhone · Safari");
    assert_eq!(v["devices"][0]["service"], "web.push.apple.com");
    assert_eq!(v["devices"][0]["details"], false);
    assert!(!b.contains("QGh1dGxp") && !b.contains(&a), "the endpoint and keys aren't shown back");
    // Another operator's session doesn't see or touch it.
    assert!(push_view(&t.state, "someone-else").body["devices"].as_array().unwrap().is_empty());
    assert_eq!(push_post(&t.state, "someone-else", "/api/push/remove", &json!({ "id": id })).status, StatusCode::NOT_FOUND);
    assert_eq!(
        push_post(&t.state, "someone-else", "/api/push/details", &json!({ "id": id, "details": false })).status,
        StatusCode::NOT_FOUND
    );
    // Turning details on with the session alone is refused and audited; only signed is it done.
    let (s, body) = post_as(&t, "/api/push/details", json!({ "id": id, "details": true })).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert!(!t.state.push.as_ref().unwrap().store.all()[0].details);
    assert_eq!(t.begin(json!({ "action": "push_details", "id": id, "details": false })).status, StatusCode::BAD_REQUEST);
    assert_eq!(t.begin(json!({ "action": "push_details", "id": "0000000000000000", "details": true })).status, StatusCode::NOT_FOUND);
    let r = t.act(json!({ "action": "push_details", "id": id, "details": true }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(t.state.push.as_ref().unwrap().store.all()[0].details);
    // Turning them off, and removing the device, only narrow: the session is enough.
    assert_eq!(post_as(&t, "/api/push/details", json!({ "id": id, "details": false })).await.0, StatusCode::OK);
    assert!(!t.state.push.as_ref().unwrap().store.all()[0].details);
    assert_eq!(post_as(&t, "/api/push/remove", json!({ "id": id })).await.0, StatusCode::OK);
    assert_eq!(post_as(&t, "/api/push/remove", json!({ "id": id })).await.0, StatusCode::NOT_FOUND);
    assert!(t.state.push.as_ref().unwrap().store.all().is_empty());
    // A signed action whose device was removed in between is not applied.
    let r = t.act(json!({ "action": "push_subscribe", "endpoint": sub["endpoint"], "p256dh": p, "auth": a }));
    assert_eq!(r.status, StatusCode::OK);
    let b = t.begin(json!({ "action": "push_details", "id": id, "details": true }));
    assert_eq!(post_as(&t, "/api/push/remove", json!({ "id": id })).await.0, StatusCode::OK);
    let a2 = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
    assert_eq!(t.post("/api/action/finish", a2).status, StatusCode::CONFLICT);
    // Every change is audited, with the device's id (never its endpoint); the signed ones with the
    // passkey's signature, which `wicket audit --verify` re-verifies offline.
    let audit = t.audit_kinds();
    let kinds: Vec<&str> = audit.iter().map(|(k, _)| k.as_str()).filter(|k| k.starts_with("operator.push")).collect();
    assert_eq!(
        kinds,
        [
            "operator.push_refused",
            "operator.push_subscribed",
            "operator.push_refused",
            "operator.push_details",
            "operator.push_details",
            "operator.push_removed",
            "operator.push_subscribed",
            "operator.push_removed",
        ]
    );
    let signed: Vec<&Value> = audit.iter().filter(|(_, b)| b.get("signed").is_some()).map(|(_, b)| b).collect();
    assert_eq!(signed.len(), 3);
    assert!(signed.iter().all(|b| b["by"] == "passkey:laptop"));
    let on = audit.iter().filter(|(k, _)| k == "operator.push_details").map(|(_, b)| b).collect::<Vec<_>>();
    assert_eq!((on[0]["details"].as_bool(), on[0]["signed"].is_object()), (Some(true), true));
    assert_eq!((on[1]["details"].as_bool(), on[1].get("signed")), (Some(false), None));
    assert!(!audit.iter().any(|(_, b)| b.to_string().contains("QGh1dGxp")));
    assert_eq!(crate::verify_signed_decisions(&t.ledger()).unwrap(), (3, 0), "re-verifies offline");
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
    assert!(body.contains("pushsubscriptionchange") && body.contains("#notifications"));
}

#[tokio::test]
async fn new_requests_push_once_per_device_coalesced_and_gone_devices_are_dropped() {
    let mut t = setup("pushnotify");
    let sent = recorder(&mut t, |u| if u.contains("gone") { 410 } else { 201 });
    let (p, a) = keys();
    let store = &t.state.push.as_ref().unwrap().store;
    let live = store
        .add(
            &t.cred,
            &push::NewDevice { endpoint: "https://fcm.googleapis.com/fcm/send/live", p256dh: &p, auth: &a, label: "laptop", details: true },
            0,
        )
        .unwrap();
    store
        .add(
            &t.cred,
            &push::NewDevice { endpoint: "https://web.push.apple.com/gone", p256dh: &p, auth: &a, label: "phone", details: false },
            0,
        )
        .unwrap();
    // A device of a passkey that's no longer enrolled gets nothing.
    store
        .add(
            "revoked-passkey",
            &push::NewDevice {
                endpoint: "https://updates.push.services.mozilla.com/wpush/v2/x",
                p256dh: &p,
                auth: &a,
                label: "",
                details: false,
            },
            0,
        )
        .unwrap();
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

/// With the ledger gone, the state store's unread alert is still shown by the health view and the
/// dashboard, and pushed to the devices of the passkeys enrolled at the last read (#635).
#[tokio::test]
async fn the_unread_alert_survives_a_ledger_that_cant_be_opened() {
    let mut t = setup("pushunread");
    let sent = recorder(&mut t, |_| 201);
    let (p, a) = keys();
    t.state
        .push
        .as_ref()
        .unwrap()
        .store
        .add(
            &t.cred,
            &push::NewDevice { endpoint: "https://fcm.googleapis.com/fcm/send/x", p256dh: &p, auth: &a, label: "l", details: true },
            0,
        )
        .unwrap();
    let now = wicket_feed::now_ms();
    let (mut h, mut known) = (push::HealthNotifier::default(), Vec::new());
    notify_health(&t.state, &mut h, &mut known, now).await;
    assert_eq!(known, [t.cred.clone()], "the enrolled passkeys, read while the ledger opens");
    // The ledger goes (a directory where the file was), and the last read was 6 min ago.
    let gone = t.dir.join("gone");
    std::fs::create_dir_all(gone.join("ledger.db")).unwrap();
    t.state.ledger = gone.join("ledger.db");
    *t.state.progress.lock().unwrap() =
        (now - 360_000, true, Some(crate::statesync::Progress { stream: None, audit: vec![], errors: vec![] }));
    let (v, alerts) = health_view(&t.state, now).unwrap();
    assert_eq!(alerts.iter().map(|a| a.key.as_str()).collect::<Vec<_>>(), ["control:state-store/unread"]);
    assert_eq!(v["state_store"]["stale"], true);
    let d = dashboard(&t.state).unwrap();
    assert_eq!(d["ledger_error"], "the ledger can't be read");
    assert!(d["health"]["state_store"]["alerts"][0].as_str().unwrap().contains("haven't been checked for 6 min"));
    let out = notify_health(&t.state, &mut h, &mut known, now).await;
    assert_eq!(out.len(), 1, "pushed to the device of the passkey known before");
    assert_eq!(sent.lock().unwrap().len(), 1);
}

/// Asks for public names are pushed like other asks, and an ask that is stale by the time the
/// notifier looks (here: of a run that isn't running) is swept, not pushed (#696 review).
#[tokio::test]
async fn asks_for_public_names_are_pushed_and_stale_ones_are_not() {
    let t = setup("pushnames");
    let tn = TenantId::single();
    let ask = |run: &str, label: &str| {
        let r = RunId(run.into());
        let a = wicket_store::NameAsk {
            tenant: &tn,
            run: &r,
            zone: "z",
            zone_digest: "zd",
            principal: "spiffe://w.test/t/t0/z/z/a/lead",
            label,
            port: 3000,
            service: Some("http"),
            reason: "asked by the agent: the demo",
            scope: wicket_store::NameScope::Run,
        };
        t.ledger().ask_public(&a).unwrap().0
    };
    t.ledger().run_started(&tn, &RunId("run_live".into()), "z", "lead").unwrap();
    let live = ask("run_live", "demo");
    // Asked for a run that isn't running: the next sweep withdraws it.
    let gone = ask("run_gone", "other");
    let w = waiting(&t.state).unwrap();
    let ids: Vec<&str> = w.iter().map(|w| w.id.as_str()).collect();
    assert_eq!(ids, vec![live.as_str()], "{ids:?}");
    assert_eq!(w[0].summary, "lead asks for the public name demo (port 3000)");
    assert_eq!(t.ledger().name(&gone).unwrap().status, "withdrawn");
}
