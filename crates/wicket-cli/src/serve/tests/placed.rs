//! The console's release of a placed node past its lease (#710).

use super::*;

fn placed(l: &Ledger, id: &str, name: &str, end: i64) {
    l.record_placed_node(&wicket_store::PlacedNodeRow {
        id: id.into(),
        backend: "vultr".into(),
        name: name.into(),
        owner: "example".into(),
        api_key_secret: "vultr-api-key".into(),
        created_at: end - 3600,
        lease_until: end,
        status: String::new(),
        held_by: None,
        ended_at: None,
        detail: None,
        hourly: None,
    })
    .unwrap();
}

#[test]
fn a_node_past_its_lease_is_released_with_a_passkey_on_what_was_shown() {
    let mut t = setup("node-release");
    let released = Arc::new(Mutex::new(Vec::new()));
    let rec = released.clone();
    t.state.releaser = Box::new(move |r| {
        rec.lock().unwrap().push((r.node.id.clone(), r.by.clone(), r.seq));
        Ok(())
    });
    let now = wicket_store::now();
    let l = t.ledger();
    placed(&l, "i-past", "placed-a", now - 60);
    placed(&l, "i-live", "placed-b", now + 3600);
    l.run_started(&TenantId::single(), &RunId("run_busy".into()), "z", "lead").unwrap();
    l.set_run_node("run_busy", "placed-a").unwrap();
    drop(l);
    let begin = |t: &T, id: &str, reason: &str| t.begin(json!({ "action": "node_release", "id": id, "reason": reason }));

    assert_refused(&begin(&t, "i-past", " "), StatusCode::BAD_REQUEST, "say why");
    assert_refused(&begin(&t, "i-past", &"x".repeat(MAX_REASON + 1)), StatusCode::BAD_REQUEST, "too long");
    assert_refused(&begin(&t, "i-nope", "x"), StatusCode::NOT_FOUND, "no active placed node");
    assert_refused(&begin(&t, "i-live", "x"), StatusCode::CONFLICT, "lease hasn't ended");
    fence::AUTHORITY.with(|a| {
        *a.borrow_mut() = Some(crate::operators::Authority::Scoped(crate::operators::Scope {
            kinds: vec!["capacity".into()],
            max_risk: Some("R3".into()),
            ..Default::default()
        }))
    });
    assert_refused(&begin(&t, "i-past", "x"), StatusCode::FORBIDDEN, "up to risk R3");
    fence::AUTHORITY.with(|a| *a.borrow_mut() = None);
    assert!(released.lock().unwrap().is_empty());

    // What the passkey signs: the node, its lease, the runs on it, what releasing does.
    let b = begin(&t, "i-past", "the run is stuck; done with it");
    assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
    let a = &b.body["action"];
    assert_eq!((a["id"].as_str(), a["name"].as_str()), (Some("i-past"), Some("placed-a")), "{a}");
    assert_eq!(a["running"], json!(["run_busy"]));
    assert!(a["consequence"].as_str().unwrap().contains("stops the boxes of run run_busy"), "{a}");
    assert_eq!(a["reason"], "the run is stuck; done with it");

    // The run ended between begin and signing: the node isn't what was shown, so nothing happens.
    t.ledger().run_ended(&RunId("run_busy".into()), "ok", "done").unwrap();
    let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
    let signed = t.sign(&ch);
    let r = t.post("/api/action/finish", signed);
    assert_refused(&r, StatusCode::CONFLICT, "changed after you were shown it");
    assert!(released.lock().unwrap().is_empty());
    assert!(t.audit_kinds().iter().any(|(k, b)| k == "decision.refused" && b["decision"] == "release_node"));

    // Signed on the node as it is now: decided, audited first, then released.
    let r = t.act(json!({ "action": "node_release", "id": "i-past", "reason": "done with it" }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(r.body["ok"].as_str().unwrap().contains("releasing placed-a"), "{:?}", r.body);
    let rel = released.lock().unwrap().clone();
    assert_eq!(rel.len(), 1);
    assert_eq!((rel[0].0.as_str(), rel[0].1.as_str()), ("i-past", "passkey:laptop"));
    let (seq, _, kind, _, body) = t.ledger().audit_tail(1).unwrap().pop().unwrap();
    assert_eq!((seq, kind.as_str()), (rel[0].2, "placement.node_release_decided"));
    let d: Value = serde_json::from_str(&body).unwrap();
    assert_eq!((d["via"].as_str(), d["granter"].as_str(), d["why"].as_str()), (Some("console"), Some("human"), Some("done with it")));
    assert!(d["granter_identity"].as_str().unwrap().ends_with("/op/passkey/laptop"), "{d}");
    assert!(d["signed"]["signature"].is_string());
    assert_eq!(crate::verify_signed_decisions(&t.ledger()).unwrap(), (1, 0), "re-verifies offline");

    // A releaser that can't start (no API key): audited, and the node is as it was.
    t.state.releaser = Box::new(|_| anyhow::bail!("no such secret vultr-api-key"));
    let l = t.ledger();
    placed(&l, "i-past2", "placed-c", now - 60);
    drop(l);
    let r = t.act(json!({ "action": "node_release", "id": "i-past2", "reason": "x" }));
    assert_refused(&r, StatusCode::CONFLICT, "no such secret");
    assert!(t.audit_kinds().iter().any(|(k, b)| k == "placement.node_release_failed" && b["id"] == "i-past2"));
    assert_eq!(t.ledger().placed_node("i-past2").unwrap().unwrap().status, "active");
}
