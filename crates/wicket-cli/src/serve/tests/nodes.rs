//! The console's node views (#573): a node's CA, its policy, what runs want of it and its widenings.

use super::*;
use wicket_store::{CaHosts, NodeCaRow, NodeRow};

async fn get(t: &T, path: &str) -> (StatusCode, Value) {
    let c = format!("__Host-wicket_sid={}", t.sid.clone().unwrap());
    let (s, _, body) = super::http::call(&t.state, "GET", path, &[("cookie", &c)], b"").await;
    (s, serde_json::from_str(&body).unwrap_or(Value::Null))
}

pub(super) fn enrol(l: &mut Ledger, name: &str, tenant: &str, hosts: &[&str]) {
    let hosts: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
    let node = NodeRow {
        name: name.into(),
        tenant: tenant.into(),
        target: "wicket@203.0.113.7".into(),
        host_key: "ssh-ed25519 AAAA".into(),
        host_key_fp: "SHA256:x".into(),
        node_key: "00".repeat(32),
        ssh_key: None,
        hosts: hosts.clone(),
        enrolled_at: wicket_store::now(),
        status: "active".into(),
        revoked_at: None,
    };
    let ca = NodeCaRow {
        serial: format!("{name}-01"),
        node: name.into(),
        issued_at: wicket_store::now(),
        not_after: wicket_store::now() + 86_400,
        hosts,
        status: "active".into(),
    };
    let tok = l.create_node_token(&TenantId(tenant.into()), name, 600).unwrap();
    l.enrol_node(&tok, &node, &ca).unwrap();
}

#[tokio::test]
async fn a_nodes_ca_shows_its_hosts_policy_wants_and_widenings() {
    let t = setup("node-ca");
    let mut l = t.ledger();
    enrol(&mut l, "n1", &TenantId::single().0, &["api.example.com"]);
    enrol(&mut l, "n2", &TenantId::single().0, &["api.example.com"]);
    enrol(&mut l, "nx", "other", &["api.example.com"]);
    l.set_node_ca_policy("n1", &CaHosts::Allowed(vec!["*.example.org".into()])).unwrap();
    l.run_started(&TenantId::single(), &RunId("run_a".into()), "z", "a").unwrap();
    let now = wicket_store::now();
    l.want_node_ca_hosts("n1", &["a.example.org".into(), "b.example.org".into(), "x.other.com".into()], "run_a", "reach", now).unwrap();
    // Widened at runtime to one of them, as a renewal over the channel records it.
    let widened = NodeCaRow {
        serial: "n1-02".into(),
        node: "n1".into(),
        issued_at: now,
        not_after: now + 86_400,
        hosts: vec!["api.example.com".into(), "a.example.org".into()],
        status: "active".into(),
    };
    l.replace_node_ca(&widened).unwrap();
    let t1 = TenantId::single();
    l.audit(&t1, None, "node.ca_widened", &json!({ "name": "n1", "ca_serial": "n1-02", "added": ["a.example.org"], "removed": [], "wanted_by": [{ "host": "a.example.org", "run": "run_a", "why": "reach" }] })).unwrap();
    l.audit(&t1, None, "node.ca_widened", &json!({ "name": "n2", "ca_serial": "n2-09", "added": ["z.example.org"], "removed": [] }))
        .unwrap();
    drop(l);

    let (s, v) = get(&t, "/api/nodes/n1/ca").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["ca"]["serial"], "n1-02");
    assert_eq!(v["ca"]["hosts"], json!(["api.example.com", "a.example.org"]), "the active CA's hosts, not only nodes.hosts");
    assert_eq!(v["enrolled_hosts"], json!(["api.example.com"]));
    assert_eq!(v["policy"], json!({ "mode": "allowed", "allowed": ["*.example.org"] }));
    let state = |h: &str| v["wants"].as_array().unwrap().iter().find(|w| w["host"] == h).unwrap()["state"].clone();
    assert_eq!(state("a.example.org"), "covered");
    assert_eq!(state("b.example.org"), "at the next renewal");
    assert_eq!(state("x.other.com"), "refused by the node's CA policy");
    assert_eq!(v["next_renewal"]["hosts"], json!(["api.example.com", "a.example.org", "b.example.org"]), "{v}");
    let w = v["widenings"].as_array().unwrap();
    assert_eq!(w.len(), 1, "only this node's: {v}");
    assert_eq!(w[0]["added"], json!(["a.example.org"]));
    assert_eq!(w[0]["wanted_by"][0]["run"], "run_a");

    // The same view as the CLI's.
    let cli = crate::enrol::ca_view(&t.ledger(), "n1", wicket_store::now()).unwrap().unwrap();
    assert_eq!(cli["wants"], v["wants"]);

    // Another tenant's node, a node never enrolled and a name that isn't one are all not found.
    for p in ["/api/nodes/nx/ca", "/api/nodes/nope/ca", "/api/nodes/a%2Fb/ca", "/api/nodes//ca"] {
        assert_eq!(get(&t, p).await.0, StatusCode::NOT_FOUND, "{p}");
    }
    // And nothing without a session.
    let (s, _, _) = super::http::call(&t.state, "GET", "/api/nodes/n1/ca", &[], b"").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
