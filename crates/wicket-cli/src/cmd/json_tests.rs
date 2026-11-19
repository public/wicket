//! #574: every list's `--json`, one test per command. Each checks the fields of what the command
//! prints against the table in docs/reference/cli.md, so the documented shape is the printed one.

use super::keys;
use std::collections::BTreeMap;
use std::time::Duration;
use wicket_core::{RunId, TenantId};

/// The table's rows: the first cell (a command, and which objects of its output) and the fields
/// the second cell names, sorted (what is in parentheses is about a field: its values, or what it
/// holds).
fn documented() -> BTreeMap<String, Vec<String>> {
    let page = include_str!("../../../../docs/reference/cli.md");
    let mut out = BTreeMap::new();
    for line in page.lines().filter(|l| l.starts_with("| `wicket ") || l.starts_with("| a")) {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        let (mut names, mut depth) = (String::new(), 0);
        for c in cells[1].chars() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                c if depth == 0 => names.push(c),
                _ => {}
            }
        }
        let mut fields: Vec<String> = names.split('`').skip(1).step_by(2).map(String::from).collect();
        fields.sort();
        out.insert(cells[0].to_string(), fields);
    }
    out
}

/// `v`'s fields are what the table's row `row` says.
fn documented_as(row: &str, v: &serde_json::Value) {
    let doc = documented();
    let want = doc.get(row).unwrap_or_else(|| panic!("docs/reference/cli.md has no row {row:?}; it has {:?}", doc.keys()));
    assert_eq!(&keys(v), want, "{row}: {v:#}");
}

fn pending_request(l: &mut wicket_store::Ledger, run: &str, path: &str) -> String {
    let op = wicket_core::Op::egress(&TenantId::single(), &RunId(run.into()), "work", "GET", "api.example.com", path);
    let (rid, _) = l.pending_for(&op, "blocked", None).unwrap();
    rid
}

#[test]
fn pending_json_lists_requests_and_standing_asks() {
    let (_d, mut l) = super::test_ledger("pending");
    let t = TenantId::single();
    pending_request(&mut l, "run_a", "/v1/data");
    let rule: wicket_core::manifest::ReachRule =
        wicket_core::yaml::from_str("{ host: ci.example, methods: [GET], paths: ['/jobs/**'] }").unwrap();
    l.ask_standing(&t, &RunId("run_a".into()), "work", "zd", "spiffe://w.test/t/t0/z/work/a/worker", &rule, "logs").unwrap();
    let v = crate::cmd::approve::pending_json(&l).unwrap();
    let a = v.as_array().unwrap();
    assert_eq!(a.len(), 2, "{v:#}");
    assert_eq!((a[0]["kind"].as_str(), a[1]["kind"].as_str()), (Some("request"), Some("standing")));
    assert_eq!(a[0]["host"], "api.example.com");
    documented_as("`wicket pending --json`, a request", &a[0]);
    documented_as("`wicket pending --json`, a standing ask", &a[1]);
    documented_as("a standing `rule`", &a[1]["rule"]);
    // Nothing pending is an empty array, not a sentence.
    let (_d, l) = super::test_ledger("pending-empty");
    assert_eq!(crate::cmd::approve::pending_json(&l).unwrap(), serde_json::json!([]));
}

#[test]
fn links_json() {
    let (_d, l) = super::test_ledger("links");
    l.add_link(&wicket_store::LinkRow {
        id: "lk-1".into(),
        tenant: TenantId::single().0,
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
    })
    .unwrap();
    let rows = l.links(&TenantId::single(), 40).unwrap();
    let v = super::approve::links_json(&rows);
    assert_eq!(v[0]["host"], format!("api.{}", wicket_core::link::DOMAIN));
    documented_as("`wicket links --json`", &v);
}

#[test]
fn grant_list_json() {
    let (_d, mut l) = super::test_ledger("grants");
    let rid = pending_request(&mut l, "run_a", "/v1/data");
    let a = wicket_store::Approval { uses: Some(2), ttl: Duration::from_secs(600), path_prefix: None, decided_by: "op".into() };
    let gid = l.approve(&rid, &a).unwrap();
    let rows = l.grants(&TenantId::single(), false, 40).unwrap();
    let v = super::approve::grants_json(&rows, wicket_store::now());
    assert_eq!((v[0]["id"].as_str(), v[0]["state"].as_str(), v[0]["uses_left"].as_i64()), (Some(gid.as_str()), Some("live"), Some(2)));
    assert_eq!(v[0]["request"], rid.as_str());
    assert!(v[0]["quota"].is_null());
    documented_as("`wicket grant list --json`", &v);
}

#[test]
fn standing_list_json() {
    let (_d, l) = super::test_ledger("standing");
    let rule: wicket_core::manifest::ReachRule =
        wicket_core::yaml::from_str("{ host: ci.example, methods: [GET], paths: ['/jobs/**'] }").unwrap();
    l.ask_standing(&TenantId::single(), &RunId("run_a".into()), "work", "zd", "spiffe://w.test/t/t0/z/work/a/worker", &rule, "logs")
        .unwrap();
    let rows = l.standing_with_status(&TenantId::single(), "pending").unwrap();
    let v = super::standing::standing_list_json(&rows, wicket_store::now());
    assert_eq!((v[0]["state"].as_str(), v[0]["for"].is_null()), (Some("pending"), true), "{v:#}");
    documented_as("`wicket standing list --json`", &v);
}

#[test]
fn audit_json() {
    let (_d, l) = super::test_ledger("audit");
    l.audit(&TenantId::single(), Some(&RunId("run_a".into())), "grant.revoked", &serde_json::json!({ "grant": "g-1" })).unwrap();
    let v = super::audit::audit_records_json(l.audit_tail(40).unwrap());
    // The body is the record's JSON, not a string of it.
    assert_eq!((v[0]["kind"].as_str(), v[0]["body"]["grant"].as_str()), (Some("grant.revoked"), Some("g-1")), "{v:#}");
    documented_as("`wicket audit --json`", &v);
}

#[test]
fn service_list_json() {
    let (_d, l) = super::test_ledger("services");
    l.add_service("npm-cache", "/data/services/npm-cache/manifest.yaml", &"ab".repeat(32), "t0", "root").unwrap();
    let v = super::service::services_json(&l.services().unwrap());
    assert_eq!(v[0]["sha256"].as_str().map(str::len), Some(64), "the whole digest");
    documented_as("`wicket service list --json`", &v);
}

#[test]
fn node_list_json() {
    let (_d, l) = super::test_ledger("nodes");
    l.enrol_builtin_node(&wicket_store::NodeRow {
        name: "local".into(),
        tenant: "t0".into(),
        target: "unix:/x/ctl.sock".into(),
        host_key: String::new(),
        host_key_fp: String::new(),
        node_key: "00".into(),
        ssh_key: None,
        hosts: vec![],
        enrolled_at: 1,
        status: "active".into(),
        revoked_at: None,
    })
    .unwrap();
    let v = wicket_control::enrol::list_json(&l).unwrap();
    assert_eq!((v[0]["name"].as_str(), v[0]["ca"].is_null()), (Some("local"), true), "{v:#}");
    documented_as("`wicket node list --json`", &v);
}

#[test]
fn agents_json() {
    let (_d, mut l) = super::test_ledger("agents");
    l.create_agent(&wicket_store::NewAgent {
        id: "agent_1",
        tenant: "t0",
        zone: "work",
        name: "worker",
        run: "run_a",
        session_id: "s",
        manifest: "m",
        image: "i",
        workspace: None,
        claim_until: 0,
    })
    .unwrap();
    let v = wicket_control::hibernate::agents_json(&l.agents("t0").unwrap());
    documented_as("`wicket agents --json`", &v);
    documented_as("an agent's `used`", &v[0]["used"]);
}

#[test]
fn top_json() {
    use crate::top::{ControlFrame, LeaseLine, NodeLine, RunLine};
    let f = ControlFrame {
        now_ms: 1_000_000,
        nodes: vec![NodeLine { name: "local".into(), status: "active".into(), link: Some((true, 1)), boxes: 1, ..Default::default() }],
        runs: vec![RunLine { run: "run_a".into(), agent: "worker".into(), status: "running".into(), ..Default::default() }],
        pending: 1,
        leases: vec![LeaseLine { id: "lease_1".into(), not_after: Some(1000), ..Default::default() }],
    };
    let v = crate::top::control_json(&f);
    assert_eq!((v["nodes"][0]["connected"].as_bool(), v["leases"][0]["not_after_ms"].as_i64()), (Some(true), Some(1_000_000)));
    documented_as("`wicket top --json`", &v);
    documented_as("`wicket top --json`, each of `nodes`", &v["nodes"]);
    documented_as("`wicket top --json`, each of `runs`", &v["runs"]);
    documented_as("`wicket top --json`, each of `leases`", &v["leases"]);
}
