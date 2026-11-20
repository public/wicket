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
pub(crate) fn documented_as(row: &str, v: &serde_json::Value) {
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

/// #575 step 4d: `wicket names list --json` and `names show --json` print the Names card's shapes.
#[test]
fn names_list_and_show_json() {
    let (_d, l) = super::test_ledger("names");
    let t = TenantId::single();
    let id = ask_name(&l, "demo");
    let cfg: wicket_names::NamesConfig =
        serde_json::from_value(serde_json::json!({ "public": { "provider": "noop", "zone": "boxes.example.com", "owner": "a1b2c3d4" } }))
            .unwrap();
    let settings: crate::names_view::Settings = Ok(cfg);
    let listens = |_: &wicket_store::Ledger, _: &str, _: u16| -> anyhow::Result<Option<String>> { Ok(None) };
    let c = crate::names_view::Ctx { l: &l, settings: &settings, listens: &listens, now: wicket_store::now() };
    let rows = crate::names_view::rows(&c, &l.names_with_status(&t, "pending").unwrap()).unwrap();
    let v = serde_json::Value::from(rows);
    assert_eq!(
        (v[0]["id"].as_str(), v[0]["state"].as_str(), v[0]["name"].as_str()),
        (Some(id.as_str()), Some("pending"), Some("demo.boxes.example.com"))
    );
    documented_as("`wicket names list --json`", &v);
    documented_as("a name's `owner`", &v[0]["owner"]);
    documented_as("a name's `target`", &v[0]["target"]);
    documented_as("a name's `agent`", &v[0]["agent"]);
    // One name, with a record the ledger lists, the last plan's entry and a connection.
    let zone = wicket_names::Zone::new("boxes.example.com");
    let rec = wicket_names::Record::a("demo.boxes.example.com", std::net::Ipv4Addr::new(192, 0, 2, 1), 60);
    l.owned_before_apply(
        &zone,
        "memory",
        &wicket_names::Plan { changes: vec![wicket_names::Change::Create(rec.clone())], conflicts: vec![] },
    )
    .unwrap();
    let plan = serde_json::json!({ "provider": "noop", "waiting": [], "zones": [{ "zone": "boxes.example.com", "applied": false, "error": null,
                                   "conflicts": [{ "name": "demo.boxes.example.com", "records": [rec] }], "changes": [] }] });
    l.audit(&t, None, "name.plan", &plan).unwrap();
    let inner = serde_json::json!({ "name": id, "label": "demo", "port": 30000, "phase": "start", "conn": "c1", "peer": "192.0.2.9:5000" });
    let outer = serde_json::json!({ "node": "n1", "seq": 1, "ts": 1, "tenant": t.0, "run": "run_n", "kind": "name.conn", "body": inner.to_string() });
    l.audit(&t, Some(&RunId("run_n".into())), "node.audit", &outer).unwrap();
    let d = crate::names_view::detail(&c, &l.name(&id).unwrap()).unwrap();
    documented_as("`wicket names show --json`", &d);
    documented_as("a name's `records`, each", &d["records"]);
    documented_as("a name's `plan`", &d["plan"]);
    documented_as("a name's `connections`, each", &d["connections"]);
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
fn lease_list_json() {
    let (_d, mut l) = super::test_ledger("leases");
    let row = wicket_store::LeaseRow {
        id: "l-1".into(),
        tenant: TenantId::single().0,
        run: "run_l".into(),
        request_id: None,
        provider: "static".into(),
        spec: serde_json::json!({}),
        hourly_cap: 0,
        reserved: 0,
        duration_secs: 1800,
        created_at: 0,
        not_after: None,
        status: "pending".into(),
        node_id: None,
        node_name: None,
        ssh_target: None,
        host_key: None,
        billed: None,
        ended_at: None,
        detail: None,
    };
    l.create_lease(&row, wicket_store::LeaseBudget { max_hourly: 0, max_total: 0 }).unwrap().unwrap();
    let v = wicket_control::capacity::list_json(&l).unwrap();
    assert_eq!((v[0]["id"].as_str(), v[0]["status"].as_str(), v[0]["node"].is_null()), (Some("l-1"), Some("pending"), true), "{v:#}");
    let at = v[0]["created_at"].as_i64().unwrap();
    assert!((wicket_store::now() - 60..=wicket_store::now()).contains(&at), "Unix seconds, not ms: {at}");
    documented_as("`wicket lease list --json`", &v);
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

/// #252: an agent acting for operator alice, with a wicket-issued identity, and a message from it
/// in alice's inbox.
fn agent_writes_to_alice(l: &mut wicket_store::Ledger, issuer: &wicket_identity::Issuer) -> (String, String) {
    let t = TenantId::single();
    let alice = wicket_identity::operator_id(&issuer.trust_domain, &t.0, "unix", "alice");
    let key = wicket_identity::AgentKey::generate();
    let spec = wicket_identity::IdentitySpec {
        tenant: t.0.clone(),
        zone: "work".into(),
        agent: "worker".into(),
        run: "run_w".into(),
        parent_run: None,
        manifest_sha256: "m".into(),
        image: "img".into(),
        node: "local".into(),
        principal: serde_json::json!({ "type": "human", "id": "alice", "via": "cli", "sub": alice }),
        act: None,
        kind: None,
    };
    let now = wicket_store::now();
    let jws = issuer.issue(&spec, now, 600, &key.public());
    let claims = wicket_identity::verify_identity(&jws, &issuer.verifying_key(), now).unwrap();
    l.run_started(&t, &RunId("run_w".into()), "work", "worker").unwrap();
    l.put_identity(&wicket_store::IdentityRow {
        run: "run_w".into(),
        tenant: t.0.clone(),
        spiffe_id: claims.sub.clone(),
        zone: "work".into(),
        agent: "worker".into(),
        parent_run: None,
        accept_from: vec![],
        jws: jws.clone(),
        issued_at: now,
    })
    .unwrap();
    let payload = serde_json::json!({ "jti": "m-1", "iat": now, "kind": "message", "to": alice, "body": "done", "reply_to": claims.sub, "priority": "next" });
    let env = wicket_identity::sign_envelope(&key, &jws, &payload);
    let meta = wicket_store::MessageMeta { from_principal: Some(&claims.sub), ..Default::default() };
    l.post_message("m-1", &t, "run_w", &alice, None, &env, &meta).unwrap();
    (alice, claims.sub)
}

#[test]
fn message_inbox_receipts_and_principals_json() {
    let (_d, mut l) = super::test_ledger("message");
    let issuer = wicket_identity::Issuer::generate("w.test");
    let (alice, worker) = agent_writes_to_alice(&mut l, &issuer);
    let t = TenantId::single();
    let m = &l.operator_inbox(&t.0, &alice, false, 10).unwrap()[0];
    let got = vec![wicket_proxy::opmsg::verify_received(m, &alice, &issuer.verifying_key(), false).map_err(|e| (m.id.clone(), e))];
    let v = super::message::inbox_json(&got);
    assert_eq!((v[0]["from"].as_str(), v[0]["body"].as_str()), (Some(worker.as_str()), Some("done")), "{v:#}");
    documented_as("`wicket message inbox --json`", &v);
    let bad = super::message::inbox_json(&[Err(("m-2".into(), "its signature does not verify".into()))]);
    documented_as("`wicket message inbox --json`, a message that doesn't verify", &bad);
    // The agent's receipt for it, as the agent reads it; an operator's own read the same way.
    let v = super::message::receipts_json(&l.receipts_from(&t.0, &worker, &[], 10).unwrap());
    assert_eq!(v[0]["state"], "delivered", "{v:#}");
    documented_as("`wicket message receipts --json`", &v);
    let v = super::message::principals_json(&l, &t, &alice, &issuer.verifying_key()).unwrap();
    assert_eq!((v[0]["id"].as_str(), v[0]["relation"].as_str()), (Some(worker.as_str()), Some("acts for you")), "{v:#}");
    documented_as("`wicket message principals --json`", &v);
    let bob = wicket_identity::operator_id("w.test", &t.0, "unix", "bob");
    assert_eq!(super::message::principals_json(&l, &t, &bob, &issuer.verifying_key()).unwrap(), serde_json::json!([]));
    // An empty accept_from entry (from before manifests refused one) lists no operator: as send decides.
    l.put_identity(&wicket_store::IdentityRow {
        run: "run_e".into(),
        tenant: t.0.clone(),
        spiffe_id: "spiffe://w.test/t/default/z/work/a/empty".into(),
        zone: "work".into(),
        agent: "empty".into(),
        parent_run: None,
        accept_from: vec![String::new()],
        jws: "x.y.z".into(),
        issued_at: wicket_store::now(),
    })
    .unwrap();
    assert_eq!(super::message::principals_json(&l, &t, &bob, &issuer.verifying_key()).unwrap(), serde_json::json!([]));
}

/// #713: `wicket capacity list --json` prints the console's Capacity card, and `--all` adds ended
/// grants with their state.
#[test]
fn capacity_list_json() {
    let (_d, l) = super::test_ledger("capacity");
    let t = TenantId::single();
    let terms = wicket_store::CapacityTerms {
        plans: vec!["vc2-1c-2gb".into()],
        regions: vec!["lhr".into()],
        hourly: 50_000,
        daily: 1_000_000,
        nodes: 2,
    };
    let live = l.issue_capacity_grant(&t.0, "spiffe://w.test/t/t0/op/unix/alex", &terms, 3600, "op").unwrap();
    let gone = l.issue_capacity_grant(&t.0, "spiffe://w.test/t/t0/op/unix/alex", &terms, 3600, "op").unwrap();
    l.revoke_grant(&gone).unwrap();
    let v = serde_json::Value::from(crate::serve::capacity::view_of(&l, &t.0, false).unwrap());
    assert_eq!(v.as_array().map(Vec::len), Some(1), "{v:#}");
    assert_eq!((v[0]["id"].as_str(), v[0]["state"].as_str()), (Some(live.as_str()), Some("live")));
    assert_eq!((v[0]["terms"]["hourly_usd"].as_str(), v[0]["left"]["nodes"].as_u64()), (Some("$0.0500"), Some(2)), "{v:#}");
    documented_as("`wicket capacity list --json`", &v);
    documented_as("a capacity grant's `terms`", &v[0]["terms"]);
    documented_as("a capacity grant's `used` and `left`", &v[0]["used"]);
    documented_as("a capacity grant's `used` and `left`", &v[0]["left"]);
    // The card shows the live one only; the list's --all, both.
    assert_eq!(crate::serve::capacity::view(&l, &t.0).unwrap().len(), 1);
    let all = crate::serve::capacity::view_of(&l, &t.0, true).unwrap();
    assert_eq!(all.iter().map(|g| g["state"].as_str().unwrap()).collect::<Vec<_>>(), vec!["revoked", "live"]);
    let text = super::capacity::line(&v[0]);
    assert!(
        text.contains(&live) && text.contains("2 node(s) at once (left 2)") && text.contains("plans vc2-1c-2gb, regions lhr"),
        "{text}"
    );
}

/// #713: `wicket authority --json` and `wicket audit explain --json` print the console's views of
/// authority, the same fields whether or not the run's node feed can be read.
#[test]
fn authority_and_explain_json() {
    let (d, l) = super::test_ledger("authority");
    let t = TenantId::single();
    let run = RunId::new();
    l.run_started(&t, &run, "work", "worker").unwrap();
    let body = serde_json::json!({ "kind": "egress", "method": "GET", "host": "api.example.com", "path": "/v1", "outcome": "allow", "detail": "reach" });
    let seq = l.audit(&t, Some(&run), "op", &body).unwrap();
    let ledger = d.join("ledger.db");
    let views = crate::serve::authority::Views { ledger: &ledger, data: &d, tenant: &t, authz_root: None };
    let v = crate::serve::authority::run_authority(&views, &run.0).unwrap();
    assert_eq!((v["run"].as_str(), v["token"]["held"].as_bool(), v["feed"].is_null()), (Some(run.0.as_str()), Some(false), true), "{v:#}");
    documented_as("`wicket authority --json`", &v);
    let x = crate::serve::authority::explain(&views, seq).unwrap();
    assert_eq!((x["recorded"]["outcome"].as_str(), x["against_token_now"]["available"].as_bool()), (Some("allow"), Some(false)), "{x:#}");
    documented_as("`wicket audit explain --json`", &x);
    // A record that isn't a decision on a request has nothing to explain.
    let other = l.audit(&t, None, "grant.revoked", &serde_json::json!({ "grant": "g-1" })).unwrap();
    assert!(crate::serve::authority::explain(&views, other).is_err());
    assert!(crate::serve::authority::run_authority(&views, "run_nope").is_err());
}

/// #713 review: `wicket audit explain` explains the tenant's own records only, as `wicket
/// authority` shows its own runs only: another tenant's is not found, as a missing one is.
#[test]
fn explain_is_for_the_tenants_own_records() {
    let (d, l) = super::test_ledger("explain-tenant");
    let (t, other) = (TenantId::single(), TenantId("t9".into()));
    let run = RunId::new();
    let body = serde_json::json!({ "kind": "egress", "method": "GET", "host": "api.example.com", "path": "/v1", "outcome": "allow" });
    let theirs = l.audit(&other, Some(&run), "op", &body).unwrap();
    let ledger = d.join("ledger.db");
    let views = crate::serve::authority::Views { ledger: &ledger, data: &d, tenant: &t, authz_root: None };
    let e = crate::serve::authority::explain(&views, theirs).unwrap_err();
    assert_eq!(format!("{e:#}"), format!("no activity record {theirs}"));
    assert_eq!(wicket_home::exit::status_of(&e), wicket_home::exit::Code::NotFound as i32);
    let e = crate::serve::authority::explain(&views, theirs + 100).unwrap_err();
    assert_eq!(wicket_home::exit::status_of(&e), wicket_home::exit::Code::NotFound as i32);
    // Their tenant's views explain it.
    let views = crate::serve::authority::Views { ledger: &ledger, data: &d, tenant: &other, authz_root: None };
    assert!(crate::serve::authority::explain(&views, theirs).is_ok());
}

/// #713 review: a block's source and signer are cleaned for the terminal, as every other field:
/// the source carries hosts and paths agents asked for (#731).
#[test]
fn authority_text_cleans_what_agents_asked_for() {
    let v = serde_json::json!({ "run": "r", "status": "running", "node": "n", "policy": {}, "token": { "held": true, "loads": true,
        "zone": "z", "epoch": 1, "issued_by": "root", "reach": [], "forbid": [],
        "blocks": [{ "index": 1, "kind": "grant", "signed_by": "k\u{1b}[31m", "revoked": false, "revocation_fingerprint": "f",
                     "source": "right(\"evil\u{1b}[2J.example\", \"/\u{7}x\");\nnext" }], "grants": [] } });
    let text = super::authority::authority_text(&v);
    assert!(!text.contains('\u{1b}') && !text.contains('\u{7}'), "{text:?}");
    assert!(text.contains("evil") && text.contains("      next\n"), "{text}");
}

/// #713: `wicket policy show --json` prints the console's policy view, and `wicket node fences
/// --json` its Agents held on lost servers card.
#[test]
fn policy_show_and_node_fences_json() {
    let (d, l) = super::test_ledger("fences");
    let t = TenantId::single();
    let ledger = d.join("ledger.db");
    let views = crate::serve::authority::Views { ledger: &ledger, data: &d, tenant: &t, authz_root: None };
    let p = crate::serve::authority::policy(&views).unwrap();
    assert!(p["installed"].is_null() && p["current"].is_null(), "{p:#}");
    documented_as("`wicket policy show --json`", &p);
    // A run whose records can't say when its authority ends, on a node no longer enrolled.
    let run = RunId::new();
    std::fs::create_dir_all(d.join("runs").join(&run.0).join("ctl")).unwrap();
    std::fs::write(d.join("runs").join(&run.0).join("ctl/run.json"), b"not json").unwrap();
    l.run_started(&t, &run, "z", "lead").unwrap();
    l.set_run_node(&run.0, "n1").unwrap();
    let rows = serde_json::Value::from(crate::serve::fence::view_in(&d.join("runs"), &t.0, &l, &[]).unwrap());
    assert_eq!((rows[0]["id"].as_str(), rows[0]["fence"]["node"].as_str()), (Some(run.0.as_str()), Some("n1")), "{rows:#}");
    documented_as("`wicket node fences --json`", &rows);
    documented_as("a run's `fence`", &rows[0]["fence"]);
    let text = super::node::fence_line(&rows[0]["fence"]);
    assert!(text.contains("node n1 (unknown, last reported never)") && text.contains("until its node confirms"), "{text}");
    assert!(text.contains(&format!("wicket node release-fence {} --reason", run.0)), "{text}");
    // Another tenant's views list nothing of this one's.
    assert!(crate::serve::fence::view_in(&d.join("runs"), "t9", &l, &[]).unwrap().is_empty());
}

/// #252: a human's delegation, as `wicket message delegations --json` prints it.
#[test]
fn message_delegations_json() {
    let (_d, l) = super::test_ledger("delegations");
    l.record_delegation(&wicket_store::NewDelegation {
        id: "d-1",
        tenant: "default",
        parent_run: "",
        parent_principal: "spiffe://w.test/t/default/op/unix/alice",
        child_run: "run_1",
        child_principal: "spiffe://w.test/t/default/z/work/a/worker",
        name: "worker",
        brief: "the task",
    })
    .unwrap();
    let rows = l.delegations_of("default", "spiffe://w.test/t/default/op/unix/alice", 10).unwrap();
    let v = serde_json::Value::Array(rows.iter().map(super::message::delegation_json).collect());
    assert_eq!((v[0]["state"].as_str(), v[0]["turn"].as_i64()), (Some("working"), Some(1)), "{v:#}");
    documented_as("`wicket message delegations --json` (and `wicket message continue --json`, one)", &v);
}
