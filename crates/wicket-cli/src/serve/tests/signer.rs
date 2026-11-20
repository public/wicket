//! #802: every signed console action is signed by the session's own passkey. Another enrolled
//! passkey's signature on the session's challenge is refused and audited, whatever the action, and
//! does nothing.

use super::*;

/// Adds a second passkey, `admin`, and returns its key and credential id.
fn second_passkey(t: &T) -> (SigningKey, String) {
    let key = SigningKey::generate();
    let p = key.verifying_key().to_sec1_point(false);
    let id = b64u(b"cred-2");
    t.ledger()
        .add_operator_credential(
            &TenantId::single(),
            &OperatorCredential {
                id: id.clone(),
                name: "admin".into(),
                x: p.x().unwrap().as_slice().try_into().unwrap(),
                y: p.y().unwrap().as_slice().try_into().unwrap(),
                sign_count: 0,
            },
        )
        .unwrap();
    (key, id)
}

/// Begins `body` as the session, signs its challenge with the other passkey, and finishes it.
fn signed_by_other(t: &mut T, other: &(SigningKey, String), body: Value) -> Reply {
    let b = t.begin(body.clone());
    assert_eq!(b.status, StatusCode::OK, "{body}: {:?}", b.body);
    let allow = b.body["publicKey"]["allowCredentials"].as_array().unwrap();
    assert_eq!(
        allow.iter().map(|a| a["id"].as_str().unwrap()).collect::<Vec<_>>(),
        [t.cred.as_str()],
        "only the session's passkey is offered"
    );
    let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
    let (key, cred) = (std::mem::replace(&mut t.key, other.0.clone()), std::mem::replace(&mut t.cred, other.1.clone()));
    let a = t.sign(&ch);
    t.key = key;
    t.cred = cred;
    t.post("/api/action/finish", a)
}

#[test]
fn another_enrolled_passkey_cant_finish_the_sessions_signed_action() {
    let mut t = setup("signer");
    let other = second_passkey(&t);
    t.running("run_d", "lead");
    let op = wicket_core::Op::egress(&TenantId::single(), &RunId("run_d".into()), "z", "GET", "a.example", "/x");
    let (rid, _) = t.ledger().pending_for(&op, "x", None).unwrap();
    // A run fenced until its node confirms, on a node that isn't enrolled: releasable here.
    let fenced = "run_00000000000000000000fenced";
    std::fs::create_dir_all(t.dir.join("runs").join(fenced).join("ctl")).unwrap();
    std::fs::write(t.dir.join("runs").join(fenced).join("ctl/run.json"), b"not json").unwrap();
    t.ledger().run_started(&TenantId::single(), &RunId(fenced.into()), "z", "lead").unwrap();
    t.ledger().set_run_node(fenced, "n1").unwrap();
    let kinds = [
        ("decide (approve)", json!({ "action": "decide", "id": rid, "decision": "approve" })),
        ("decide (deny)", json!({ "action": "decide", "id": rid, "decision": "deny" })),
        ("revoke", json!({ "action": "revoke", "run": "run_d", "reason": "x" })),
        (
            "capacity_grant",
            json!({ "action": "capacity_grant", "principal": "unix/alex", "plans": "vc2-1c-2gb", "regions": ["lhr"],
                    "max_hourly_usd": "0.05", "max_daily_usd": "1", "nodes": 1, "ttl_secs": 3600 }),
        ),
        (
            "set_secret",
            json!({ "action": "set_secret", "name": "gh", "hosts": ["api.github.com"], "value_salt": "00112233445566778899aabbccddeeff", "value_sha256": super::super::secrets::value_digest("00112233445566778899aabbccddeeff", "v") }),
        ),
        ("release_fence", json!({ "action": "release_fence", "run": fenced, "reason": "n1 was destroyed" })),
    ];
    for (what, body) in kinds {
        let before = t.ledger().audit_tail(1000).unwrap().len();
        let r = signed_by_other(&mut t, &other, body);
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{what}: {:?}", r.body);
        assert!(r.body["error"].as_str().unwrap().contains("the passkey you signed in with"), "{what}: {:?}", r.body);
        let after = t.ledger().audit_tail(1000).unwrap();
        assert_eq!(after.len(), before + 1, "{what}: only the refusal is recorded");
        let (_, _, kind, _, b) = after.last().unwrap();
        assert_eq!(kind, "operator.action_refused", "{what}");
        let b: Value = serde_json::from_str(b).unwrap();
        assert_eq!((b["credential"].as_str(), b["session_credential"].as_str()), (Some(other.1.as_str()), Some(t.cred.as_str())), "{what}");
    }
    // Nothing was done: the request is pending, the run not revoked, no grant, secret or release.
    let l = t.ledger();
    assert_eq!(l.request(&rid).unwrap().status, "pending");
    assert!(l.revoked("run_d").unwrap().is_none());
    assert!(l.capacity_grants(&TenantId::single().0, None, false).unwrap().is_empty());
    drop(l);
    // The session's own passkey still signs.
    let r = t.act(json!({ "action": "decide", "id": rid, "decision": "deny" }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}
