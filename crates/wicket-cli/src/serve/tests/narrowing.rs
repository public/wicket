//! The console's narrowing actions from the host's list (#713): revoking a grant, cutting a link,
//! pausing a trigger and ending one of the operator's own console sessions. Each needs the
//! operator's session (no passkey signature: each only takes something away), goes through its CLI
//! command's function, is audited with the operator and `via: console`, and refuses another
//! tenant's id as one that doesn't exist.

use super::*;

const OTHER: &str = "t9";

fn link(id: &str, tenant: &str) -> wicket_store::LinkRow {
    wicket_store::LinkRow {
        id: id.into(),
        tenant: tenant.into(),
        from_run: "run_a".into(),
        to_run: "run_b".into(),
        port: 8080,
        name: "api".into(),
        addr: "10.0.0.2".into(),
        by_run: "run_a".into(),
        basis: "child".into(),
        status: "open".into(),
        created_at: 1,
        closed_at: None,
        closed_by: None,
        close_reason: None,
    }
}

fn trigger(l: &Ledger, tenant: &str, name: &str) -> String {
    let spec: wicket_core::trigger::TriggerSpec = wicket_core::yaml::from_str(&format!(
        "trigger: {name}\nsource: {{ webhook: {{ verify: {{ hmac_sha256: k }} }} }}\naction: {{ wake: agent }}\n"
    ))
    .unwrap();
    l.create_trigger(tenant, &format!("spiffe://wicket.local/t/{tenant}/op/unix/alex"), &spec, "unix:alex", false, None).unwrap()
}

fn grant(l: &mut Ledger, tenant: &str, run: &str) -> String {
    let t = TenantId(tenant.into());
    let op = wicket_core::Op::egress(&t, &RunId(run.into()), "z", "GET", "api.example.com", "/x");
    let (rid, _) = l.pending_for(&op, "asked", None).unwrap();
    let a = wicket_store::Approval { uses: Some(1), ttl: std::time::Duration::from_secs(600), path_prefix: None, decided_by: "op".into() };
    l.approve(&rid, &a).unwrap()
}

fn last(t: &T, kind: &str) -> Value {
    t.audit_kinds().into_iter().rev().find(|(k, _)| k == kind).map(|(_, b)| b).unwrap_or_else(|| panic!("no {kind} record"))
}

#[test]
fn the_host_lists_narrowing_actions_need_the_session_and_stay_in_the_tenant() {
    let t = setup("narrowing");
    let (gid, theirs_g) = {
        let mut l = t.ledger();
        (grant(&mut l, "t0", "run_a"), grant(&mut l, OTHER, "run_9"))
    };
    {
        let l = t.ledger();
        l.add_link(&link("lk-1", "t0")).unwrap();
        l.add_link(&link("lk-9", OTHER)).unwrap();
    }
    let (tid, theirs_t) = (trigger(&t.ledger(), "t0", "hook"), trigger(&t.ledger(), OTHER, "theirs"));
    // Without a session: refused, and nothing changes.
    for (p, id) in [("/api/grants/revoke", &gid), ("/api/links/cut", &"lk-1".to_string()), ("/api/triggers/pause", &tid)] {
        assert_eq!(post(&t.state, p, &anon(), &json!({ "id": id })).unwrap().status, StatusCode::UNAUTHORIZED, "{p}");
    }
    assert!(!t.ledger().grant(&gid).unwrap().unwrap().revoked);
    // Another tenant's: not found, as one that doesn't exist, and left as it was.
    for (p, id) in [("/api/grants/revoke", &theirs_g), ("/api/links/cut", &"lk-9".to_string()), ("/api/triggers/pause", &theirs_t)] {
        let r = t.post(p, json!({ "id": id }));
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{p}: {:?}", r.body);
    }
    assert!(!t.ledger().grant(&theirs_g).unwrap().unwrap().revoked);
    assert_eq!(t.ledger().link("lk-9").unwrap().unwrap().status, "open");
    assert_eq!(t.ledger().trigger(&theirs_t).unwrap().unwrap().status, "active");
    // The tenant's own: done, and audited with the operator and how.
    let r = t.post("/api/grants/revoke", json!({ "id": gid }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(t.ledger().grant(&gid).unwrap().unwrap().revoked);
    let rec = last(&t, "grant.revoked");
    assert_eq!(
        (rec["grant"].as_str(), rec["by"].as_str(), rec["via"].as_str()),
        (Some(gid.as_str()), Some("passkey:laptop"), Some("console"))
    );
    assert_eq!(t.post("/api/grants/revoke", json!({ "id": gid })).status, StatusCode::CONFLICT, "already revoked");
    let r = t.post("/api/links/cut", json!({ "id": "lk-1" }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(t.ledger().link("lk-1").unwrap().unwrap().status, "closed");
    let rec = last(&t, "link.cut");
    assert_eq!((rec["by"].as_str(), rec["via"].as_str()), (Some("passkey:laptop"), Some("console")));
    let r = t.post("/api/triggers/pause", json!({ "id": tid }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(t.ledger().trigger(&tid).unwrap().unwrap().status, "paused");
    let rec = last(&t, "trigger.paused");
    assert_eq!((rec["by"].as_str(), rec["via"].as_str()), (Some("passkey:laptop"), Some("console")));
    assert!(rec["principal"].as_str().unwrap().ends_with("/op/passkey/laptop"), "{rec}");
    // No id: a bad request.
    assert_eq!(t.post("/api/links/cut", json!({})).status, StatusCode::BAD_REQUEST);
}

#[test]
fn an_operator_ends_only_their_own_console_sessions() {
    let t = setup("end-session");
    let now = wicket_store::now();
    let session = |id: &str, cred: &str, tenant: &str| {
        t.ledger()
            .add_console_session(
                &TenantId(tenant.into()),
                &ConsoleSession {
                    id: id.into(),
                    kind: "operator".into(),
                    credential: Some(cred.into()),
                    client: "192.0.2.1".into(),
                    created_at: now,
                    last_seen_at: now,
                    expires_at: now + 3600,
                },
            )
            .unwrap();
    };
    let (mine, another, theirs) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
    session(&mine, &t.cred, "t0");
    session(&another, "cred-other-passkey", "t0");
    session(&theirs, &t.cred, OTHER);
    let live = |tenant: &str| {
        t.ledger().console_sessions(&TenantId(tenant.into()), wicket_store::now()).unwrap().into_iter().map(|s| s.id).collect::<Vec<_>>()
    };
    // Another passkey's or another tenant's: not found. Too short a prefix, or not hex: a bad
    // request, refused before any session is looked at. All still live.
    for id in [&another[..16], &theirs[..16]] {
        let r = t.post("/api/sessions/end", json!({ "id": id }));
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{id}: {:?}", r.body);
    }
    for id in [&mine[..4], "zzzzzzzzzzzzzzzz"] {
        let r = t.post("/api/sessions/end", json!({ "id": id }));
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{id}: {:?}", r.body);
    }
    // A prefix two of its own share: ambiguous, and neither is ended.
    let twin = format!("{}{}", &mine[..16], "dd".repeat(24));
    session(&twin, &t.cred, "t0");
    let r = t.post("/api/sessions/end", json!({ "id": &mine[..16] }));
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert!(r.body.to_string().contains("ambiguous"), "{:?}", r.body);
    assert!(live("t0").contains(&mine) && live("t0").contains(&twin));
    assert!(live("t0").contains(&another) && live(OTHER).contains(&theirs));
    // One of its own, as the list names it: ended, and audited.
    let r = t.post("/api/sessions/end", json!({ "id": &mine[..17] }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(r.cookie.is_none(), "another session of its own: this one's cookie stays");
    assert!(!live("t0").contains(&mine) && live("t0").contains(&another) && live("t0").contains(&twin));
    let rec = last(&t, "operator.sessions_revoked");
    assert_eq!((&rec["sessions"], rec["by"].as_str(), rec["via"].as_str()), (&json!([mine]), Some("passkey:laptop"), Some("console")));
}

/// Ending the very session the request came with signs it out: its cookie is cleared, and it can do
/// nothing more.
#[test]
fn ending_this_session_signs_it_out() {
    let t = setup("end-this");
    let this = super::super::session_id(t.sid.as_ref().unwrap());
    let r = t.post("/api/sessions/end", json!({ "id": &this[..16] }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(r.cookie.as_deref().is_some_and(|c| c.contains("Max-Age=0")), "cleared: {:?}", r.cookie);
    assert_eq!(t.post("/api/links/cut", json!({ "id": "lk-1" })).status, StatusCode::UNAUTHORIZED, "signed out");
}

/// A bootstrap session (an enrolment link's) can do none of these; nor can a session whose passkey
/// was removed after it signed in. A repeat of one changes nothing and says so, once recorded.
#[test]
fn only_an_enrolled_operator_narrows_and_a_repeat_changes_nothing() {
    let t = setup("narrow-who");
    let token = "be".repeat(32);
    let now = wicket_store::now();
    t.ledger()
        .add_console_session(
            &TenantId::single(),
            &ConsoleSession {
                id: super::super::session_id(&token),
                kind: "bootstrap".into(),
                credential: Some("enrol-link".into()),
                client: "192.0.2.1".into(),
                created_at: now,
                last_seen_at: now,
                expires_at: now + 600,
            },
        )
        .unwrap();
    let boot = Ctx { sid: Some(token), client: LOCAL };
    for p in ["/api/grants/revoke", "/api/links/cut", "/api/triggers/pause", "/api/sessions/end"] {
        assert_eq!(post(&t.state, p, &boot, &json!({ "id": "x" })).unwrap().status, StatusCode::UNAUTHORIZED, "{p}");
    }
    // A repeat: refused, and recorded once.
    t.ledger().add_link(&link("lk-1", "t0")).unwrap();
    let tid = trigger(&t.ledger(), "t0", "hook");
    for (p, id, kind) in [("/api/links/cut", "lk-1".to_string(), "link.cut"), ("/api/triggers/pause", tid.clone(), "trigger.paused")] {
        assert_eq!(t.post(p, json!({ "id": id })).status, StatusCode::OK, "{p}");
        let again = t.post(p, json!({ "id": id }));
        assert_eq!(again.status, StatusCode::CONFLICT, "{p}: {:?}", again.body);
        assert!(again.body.to_string().contains("already"), "{p}: {:?}", again.body);
        assert_eq!(t.audit_kinds().iter().filter(|(k, _)| k == kind).count(), 1, "{kind} once");
    }
    // The passkey removed after signing in: its session can't act (no longer a session of an
    // enrolled passkey, or, between the two reads, refused as one).
    t.ledger().add_link(&link("lk-2", "t0")).unwrap();
    t.ledger().reset_operator_credentials(&TenantId::single()).unwrap();
    let r = t.post("/api/links/cut", json!({ "id": "lk-2" }));
    assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{:?}", r.body);
    assert_eq!(t.ledger().link("lk-2").unwrap().unwrap().status, "open");
}
