//! The console's view of why a run went where it did (#579): the recorded placement decision, as
//! `wicket why-here` reads it, behind an operator's session.

use super::*;

const RUN: &str = "run_01placed000000000000000000";
const OTHER: &str = "run_01placedother0000000000000";
const LOCAL: &str = "run_01placedlocal0000000000000";

async fn get(t: &T, path: &str, sid: Option<&str>) -> (StatusCode, Value) {
    let c = sid.map(|s| format!("__Host-wicket_sid={s}"));
    let headers: Vec<(&str, &str)> = c.as_deref().map(|c| vec![("cookie", c)]).unwrap_or_default();
    let (s, _, body) = super::http::call(&t.state, "GET", path, &headers, b"").await;
    (s, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_runs_placement_says_where_it_went_and_why() {
    let t = setup("placement");
    let l = t.ledger();
    l.run_started(&TenantId::single(), &RunId(RUN.into()), "z", "agent").unwrap();
    l.set_run_node(RUN, "n1").unwrap();
    // Another tenant's run, and one on this host's own node.
    l.run_started(&TenantId("t-other".into()), &RunId(OTHER.into()), "z", "agent").unwrap();
    l.run_started(&TenantId::single(), &RunId(LOCAL.into()), "z", "agent").unwrap();
    let sid = t.sid.clone().unwrap();
    let path = format!("/api/runs/{RUN}/placement");

    // No decision recorded (a node named for it, say): said, not an error.
    let (s, v) = get(&t, &path, Some(&sid)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!((&v["run"], &v["node"], &v["decision"]), (&json!(RUN), &json!("n1"), &Value::Null));
    assert!(v["why"].as_str().unwrap().contains("no placement decision"), "{v}");

    let record = json!({
        "request": { "vcpus": 1.0, "memory_mib": 2048 },
        "ca_hosts": [], "node": "n1", "candidates": 2, "ranked": ["n1"], "ranked_more": 0,
        "refused": [{ "node": "n2", "why": ["0.5 vCPU, 512 MiB free"] }], "refused_more": 0, "behind": null,
    });
    l.record_placement_decision(RUN, &record.to_string(), wicket_feed::now_ms()).unwrap();
    let (s, v) = get(&t, &path, Some(&sid)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["decision"]["node"], "n1");
    assert_eq!(v["decision"]["request"]["memory_mib"], 2048);
    assert!(v["decision"]["at_ms"].as_i64().is_some());
    assert_eq!(v["decision"]["refused"][0]["node"], "n2");
    // Named fields only: a field placement adds to its record later doesn't reach the page.
    let mut extra = record.clone();
    extra["future_secret_field"] = json!("not for the page");
    l.record_placement_decision(RUN, &extra.to_string(), wicket_feed::now_ms() + 1).unwrap();
    let (_, w) = get(&t, &path, Some(&sid)).await;
    assert!(!w.to_string().contains("future_secret_field"), "{w}");
    let text = v["text"].as_str().unwrap();
    assert!(text.contains("on node n1") && text.contains("n2: 0.5 vCPU, 512 MiB free"), "{text}");

    // An operator's session only; an unknown run, or a name that isn't a run id, is not found.
    assert_eq!(get(&t, &path, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(get(&t, "/api/runs/run_nope/placement", Some(&sid)).await.0, StatusCode::NOT_FOUND);
    assert_eq!(get(&t, &format!("/api/runs/{OTHER}/placement"), Some(&sid)).await.0, StatusCode::NOT_FOUND, "another tenant's");
    assert_eq!(get(&t, &format!("/api/runs/{OTHER}/authority"), Some(&sid)).await.0, StatusCode::NOT_FOUND, "the same for its authority");
    let (s, v) = get(&t, &format!("/api/runs/{LOCAL}/placement"), Some(&sid)).await;
    assert_eq!((s, &v["node"]), (StatusCode::OK, &json!(crate::localnode::NAME)), "{v}");
    assert_eq!(get(&t, "/api/runs/..%2f..%2fetc/placement", Some(&sid)).await.0, StatusCode::NOT_FOUND);
}
