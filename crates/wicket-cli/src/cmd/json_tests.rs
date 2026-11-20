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

/// A pending ask for the public name `label`, of a running run.
pub(super) fn ask_name(l: &wicket_store::Ledger, label: &str) -> String {
    let t = TenantId::single();
    let r = RunId("run_n".into());
    l.run_started(&t, &r, "work", "worker").unwrap();
    let ask = wicket_store::NameAsk {
        tenant: &t,
        run: &r,
        zone: "work",
        zone_digest: "zd",
        principal: "spiffe://w.test/t/t0/z/work/a/worker",
        label,
        port: 3000,
        service: Some("http"),
        reason: "asked by the agent: the demo",
        scope: wicket_store::NameScope::Run,
    };
    l.ask_public(&ask).unwrap().0
}

#[test]
fn pending_json_lists_requests_standing_asks_and_names() {
    let (_d, mut l) = super::test_ledger("pending");
    let t = TenantId::single();
    pending_request(&mut l, "run_a", "/v1/data");
    let rule: wicket_core::manifest::ReachRule =
        wicket_core::yaml::from_str("{ host: ci.example, methods: [GET], paths: ['/jobs/**'] }").unwrap();
    l.ask_standing(&t, &RunId("run_a".into()), "work", "zd", "spiffe://w.test/t/t0/z/work/a/worker", &rule, "logs").unwrap();
    let nid = ask_name(&l, "demo");
    let v = crate::cmd::approve::pending_json(&l).unwrap();
    let a = v.as_array().unwrap();
    assert_eq!(a.len(), 3, "{v:#}");
    assert_eq!((a[0]["kind"].as_str(), a[1]["kind"].as_str(), a[2]["kind"].as_str()), (Some("request"), Some("standing"), Some("name")));
    assert_eq!(a[0]["host"], "api.example.com");
    assert_eq!((a[2]["id"].as_str(), a[2]["label"].as_str(), a[2]["port"].as_u64()), (Some(nid.as_str()), Some("demo"), Some(3000)));
    documented_as("`wicket pending --json`, a request", &a[0]);
    documented_as("`wicket pending --json`, a standing ask", &a[1]);
    documented_as("a standing `rule`", &a[1]["rule"]);
    documented_as("`wicket pending --json`, an ask for a public name", &a[2]);
    // The text listing has it too, with the commands that decide it.
    let text = crate::cmd::approve::pending_text(&l).unwrap();
    assert!(text.contains(&format!("{nid}  public demo  port 3000")), "{text}");
    assert!(text.contains(&format!("decide: wicket names show {nid}; wicket names approve {nid}; wicket names deny {nid}")), "{text}");
    assert!(!text.contains("no pending requests"), "{text}");
    // Nothing pending is an empty array, not a sentence.
    let (_d, l) = super::test_ledger("pending-empty");
    assert_eq!(crate::cmd::approve::pending_json(&l).unwrap(), serde_json::json!([]));
    assert_eq!(crate::cmd::approve::pending_text(&l).unwrap(), "no pending requests\n");
}

/// `wicket approve` and `deny` send an `n-` or `s-` id to the command that decides it (#696
/// review), as a usage error; any other id is theirs.
#[test]
fn approve_and_deny_redirect_names_and_standing_asks() {
    let msg = |id: &str, verb: &str| crate::cmd::approve::elsewhere(id, verb).map(|e| format!("{e:#}"));
    assert_eq!(
        msg("n-01abc", "approve").as_deref(),
        Some("n-01abc is an ask for a public name: wicket names show n-01abc, then wicket names approve n-01abc")
    );
    assert_eq!(msg("n-01abc", "deny").as_deref(), Some("n-01abc is an ask for a public name: wicket names deny n-01abc"));
    assert_eq!(
        msg("s-01abc", "approve").as_deref(),
        Some("s-01abc is a standing ask: wicket standing show s-01abc, then wicket standing approve s-01abc")
    );
    assert_eq!(msg("s-01abc", "deny").as_deref(), Some("s-01abc is a standing ask: wicket standing deny s-01abc"));
    assert!(msg("r-01abc", "approve").is_none());
    let e = crate::cmd::approve::elsewhere("n-1", "deny").unwrap();
    assert_eq!(wicket_home::exit::status_of(&e), wicket_home::exit::Code::Usage as i32);
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
    let v4: std::net::Ipv4Addr = "1.1.1.1".parse().unwrap();
    l.set_node_addresses("local", wicket_store::AddressChange::Set(v4), wicket_store::AddressChange::Keep, "ann").unwrap();
    let v = wicket_control::enrol::list_json(&l).unwrap();
    assert_eq!((v[0]["name"].as_str(), v[0]["ca"].is_null()), (Some("local"), true), "{v:#}");
    assert_eq!((v[0]["public_ipv4"].as_str(), v[0]["public_ipv6"].is_null()), (Some("1.1.1.1"), true), "{v:#}");
    documented_as("`wicket node list --json`", &v);
    let ca = wicket_control::enrol::ca_view(&l, "local", 2).unwrap().unwrap();
    documented_as("`wicket node ca --json`", &ca);
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
        nodes: vec![NodeLine {
            name: "local".into(),
            status: "active".into(),
            link: Some((true, 1)),
            boxes: 1,
            capacity: Some(crate::chan::NodeCapacity::default()),
            // A report with nothing orphaned and no capacity: the fields are there all the same.
            health: Some(crate::health::NodeHealth { ca_not_after: Some(1000), ..Default::default() }),
        }],
        runs: vec![RunLine {
            run: "run_a".into(),
            agent: "worker".into(),
            status: "running".into(),
            spent: Some(Default::default()),
            ..Default::default()
        }],
        pending: 1,
        leases: vec![LeaseLine { id: "lease_1".into(), not_after: Some(1000), ..Default::default() }],
        progress: None,
        audit: None,
    };
    let v = crate::top::control_json(&f);
    assert_eq!((v["nodes"][0]["connected"].as_bool(), v["leases"][0]["not_after_ms"].as_i64()), (Some(true), Some(1_000_000)));
    documented_as("`wicket top --json`", &v);
    documented_as("`wicket top --json`, each of `nodes`", &v["nodes"]);
    documented_as("`wicket top --json`, each of `runs`", &v["runs"]);
    documented_as("`wicket top --json`, each of `leases`", &v["leases"]);
    let n = &v["nodes"][0];
    documented_as("`wicket top --json`, a node's `capacity`", &n["capacity"]);
    documented_as("`wicket top --json`, a node's `health`", &n["health"]);
    assert_eq!((n["health"]["ca_not_after_ms"].as_i64(), n["health"]["orphaned"].as_array().map(Vec::len)), (Some(1_000_000), Some(0)));
    assert_eq!(keys(&n["health"]["disk"]), ["avail_bytes", "reserve_bytes", "total_bytes"]);
    assert_eq!(keys(&n["health"]["memory"]), ["available_mib", "committed_mib", "total_mib"]);
    documented_as("`wicket top --json`, a run's `spent`", &v["runs"][0]["spent"]);
}
