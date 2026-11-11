//! The Vultr client and provider against a local mock of API v2 (no real API is called). The mock
//! records every request, so the tests pin the request shapes: paths, query, auth header, bodies.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wicket_placement::boot::{cloud_config, HostKeyPair, NODE_SETUP};
use wicket_placement::envelope::SpendRequest;
use wicket_placement::model::Boot;
use wicket_placement::vultr::{ApiKey, Client, Retry, VultrConfig, VultrProvider};
use wicket_placement::*;

const KEY: &str = "test-key-not-a-real-one";

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    auth: Option<String>,
    body: Value,
}

#[derive(Default)]
struct Mock {
    seen: Vec<Seen>,
    instances: Vec<Value>,
    /// Responses to return before normal handling (status, body).
    injected: VecDeque<(u16, Value)>,
    next_id: u32,
}

type Shared = Arc<Mutex<Mock>>;

fn plans() -> Vec<Value> {
    vec![
        json!({"id": "vc2-1c-1gb", "vcpu_count": 1, "ram": 1024, "disk": 25, "monthly_cost": 5, "type": "vc2", "locations": ["lhr", "ams"]}),
        json!({"id": "vc2-1c-2gb", "vcpu_count": 1, "ram": 2048, "disk": 55, "monthly_cost": 10, "hourly_cost": 0.014, "type": "vc2", "locations": ["lhr"]}),
        json!({"id": "vc2-2c-4gb", "vcpu_count": 2, "ram": 4096, "disk": 80, "monthly_cost": 20, "type": "vc2", "locations": ["lhr"]}),
        json!({"id": "vhp-1c-2gb-amd", "vcpu_count": 1, "ram": 2048, "disk": 50, "monthly_cost": 12, "type": "vhp", "locations": ["lhr"]}),
    ]
}

/// A page of `items` at `cursor` (an offset), `per_page` long, with `meta.links.next` as Vultr gives it.
fn page(field: &str, items: &[Value], q: &[(String, String)]) -> Value {
    let get = |k: &str| q.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
    let per: usize = get("per_page").and_then(|v| v.parse().ok()).unwrap_or(100);
    let at: usize = get("cursor").and_then(|c| c.strip_prefix("c").and_then(|n| n.parse().ok())).unwrap_or(0);
    let chunk: Vec<Value> = items.iter().skip(at).take(per).cloned().collect();
    let next = if at + per < items.len() { format!("c{}", at + per) } else { String::new() };
    json!({ field: chunk, "meta": {"total": items.len(), "links": {"next": next, "prev": ""}} })
}

fn handle(m: &mut Mock, s: &Seen) -> (u16, Value) {
    if let Some(r) = m.injected.pop_front() {
        return r;
    }
    if s.auth.as_deref() != Some(format!("Bearer {KEY}").as_str()) {
        return (401, json!({"error": "Invalid API token.", "status": 401}));
    }
    let tag = s.query.iter().find(|(k, _)| k == "tag").map(|(_, v)| v.clone());
    let segs: Vec<&str> = s.path.trim_start_matches("/v2/").split('/').collect();
    match (s.method.as_str(), segs.as_slice()) {
        ("GET", ["plans"]) => {
            let ty = s.query.iter().find(|(k, _)| k == "type").map(|(_, v)| v.as_str()).unwrap_or("all");
            let all: Vec<Value> = plans().into_iter().filter(|p| ty == "all" || p["type"] == ty).collect();
            (200, page("plans", &all, &s.query))
        }
        ("POST", ["instances"]) => {
            for k in ["region", "plan", "os_id"] {
                if s.body.get(k).is_none() {
                    return (400, json!({"error": format!("Missing {k}"), "status": 400}));
                }
            }
            m.next_id += 1;
            let i = json!({
                "id": format!("cb676a46-66fd-4dfb-b839-{:012}", m.next_id),
                "main_ip": "0.0.0.0", "date_created": "2026-11-11T10:00:00+00:00",
                "status": "pending", "power_status": "running", "server_status": "none",
                "plan": s.body["plan"], "region": s.body["region"], "label": s.body["label"],
                "tags": s.body["tags"], "vcpu_count": 1, "ram": 2048, "os_id": s.body["os_id"],
                "default_password": "placeholder-password",
            });
            m.instances.push(i.clone());
            (202, json!({ "instance": i }))
        }
        ("GET", ["instances"]) => {
            let items: Vec<Value> = m
                .instances
                .iter()
                .filter(|i| tag.as_ref().is_none_or(|t| i["tags"].as_array().is_some_and(|a| a.iter().any(|x| x == t.as_str()))))
                .cloned()
                .collect();
            (200, page("instances", &items, &s.query))
        }
        ("GET", ["instances", id]) => match m.instances.iter_mut().find(|i| i["id"] == *id) {
            Some(i) => {
                // Each poll moves the instance towards ready.
                if i["status"] == "pending" {
                    i["status"] = json!("active");
                } else if i["server_status"] != "ok" {
                    i["server_status"] = json!("ok");
                    i["main_ip"] = json!("203.0.113.50");
                }
                (200, json!({ "instance": i }))
            }
            None => (404, json!({"error": "Invalid instance-id.", "status": 404})),
        },
        ("PATCH", ["instances", id]) => match m.instances.iter().find(|i| i["id"] == *id) {
            Some(i) => (202, json!({ "instance": i })),
            None => (404, json!({"error": "Invalid instance-id.", "status": 404})),
        },
        ("DELETE", ["instances", id]) => {
            let before = m.instances.len();
            m.instances.retain(|i| i["id"] != *id);
            if m.instances.len() < before {
                (204, Value::Null)
            } else {
                (404, json!({"error": "Invalid instance-id.", "status": 404}))
            }
        }
        _ => (404, json!({"error": "Not found", "status": 404})),
    }
}

async fn serve() -> (String, Shared) {
    let state: Shared = Arc::default();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            let (sock, _) = l.accept().await.unwrap();
            let st = st.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let st = st.clone();
                    async move {
                        let method = req.method().to_string();
                        let path = req.uri().path().to_string();
                        let query: Vec<(String, String)> = req
                            .uri()
                            .query()
                            .unwrap_or("")
                            .split('&')
                            .filter(|s| !s.is_empty())
                            .filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
                            .collect();
                        let auth = req.headers().get("authorization").map(|v| v.to_str().unwrap().to_string());
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        let seen = Seen { method, path, query, auth, body };
                        let (status, out) = {
                            let mut m = st.lock().unwrap();
                            let r = handle(&mut m, &seen);
                            m.seen.push(seen);
                            r
                        };
                        let bytes = if out.is_null() { Bytes::new() } else { Bytes::from(out.to_string()) };
                        Ok::<_, std::convert::Infallible>(Response::builder().status(status).body(Full::new(bytes)).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(sock), svc).await;
            });
        }
    });
    (format!("http://{addr}/v2"), state)
}

fn client(base: &str) -> Client {
    Client::with_base(base, ApiKey::new(KEY)).unwrap().with_retry(Retry { attempts: 3, base: Duration::from_millis(1) })
}

fn config() -> VultrConfig {
    VultrConfig { sshkey_ids: vec!["3b8066a7-b438-455a-9688-44afc9a3597f".into()], ..VultrConfig::default() }
}

#[tokio::test]
async fn plans_are_paged_through_and_priced_per_hour() {
    let (base, st) = serve().await;
    let c = client(&base).with_per_page(2);
    let all = c.list_plans("all").await.unwrap();
    assert_eq!(all.len(), 4);
    let q: Vec<Vec<(String, String)>> = st.lock().unwrap().seen.iter().map(|s| s.query.clone()).collect();
    assert_eq!(q.len(), 2);
    assert!(q[0].contains(&("type".into(), "all".into())) && q[0].contains(&("per_page".into(), "2".into())));
    assert!(q[1].contains(&("cursor".into(), "c2".into())));
    // hourly_cost when given; else monthly / 672, rounded up.
    assert_eq!(all[1].hourly_rate(), MicroUsd(14_000));
    assert_eq!(all[0].hourly_rate(), MicroUsd(7_441)); // $5 / 672 h = $0.00744…
    assert_eq!(c.list_plans("vc2").await.unwrap().len(), 3);
}

#[tokio::test]
async fn errors_carry_vultrs_message_and_not_the_key_and_429_is_retried() {
    let (base, st) = serve().await;
    let c = client(&base);
    st.lock().unwrap().injected.push_back((429, json!({"error": "Rate limit exceeded", "status": 429})));
    st.lock().unwrap().injected.push_back((503, json!({"error": "busy", "status": 503})));
    assert_eq!(c.list_instances(None).await.unwrap().len(), 0);
    assert_eq!(st.lock().unwrap().seen.len(), 3);
    // Retries run out.
    for _ in 0..3 {
        st.lock().unwrap().injected.push_back((500, json!({"error": "boom", "status": 500})));
    }
    let e = c.list_instances(None).await.unwrap_err().to_string();
    assert!(e.contains("HTTP 500") && e.contains("boom"), "{e}");
    // A 400 is not retried, and its message is Vultr's.
    st.lock().unwrap().injected.push_back((400, json!({"error": "Invalid plan chosen.", "status": 400})));
    let n = st.lock().unwrap().seen.len();
    let e = c.list_plans("vc2").await.unwrap_err();
    assert_eq!(st.lock().unwrap().seen.len(), n + 1);
    let e = format!("{e} {e:?}");
    assert!(e.contains("Invalid plan chosen."), "{e}");
    // A 5xx after a POST is not retried: the create may have happened.
    st.lock().unwrap().injected.push_back((502, json!({"error": "bad gateway", "status": 502})));
    let n = st.lock().unwrap().seen.len();
    let body = wicket_placement::vultr::CreateInstance {
        region: "lhr".into(),
        plan: "vc2-1c-2gb".into(),
        os_id: 2284,
        label: "n".into(),
        hostname: "n".into(),
        tags: vec![],
        sshkey_id: vec![],
        user_data: None,
        backups: "disabled",
        enable_ipv6: false,
        activation_email: false,
    };
    assert!(c.create_instance(&body).await.unwrap_err().to_string().contains("HTTP 502"));
    assert_eq!(st.lock().unwrap().seen.len(), n + 1);
    // A wrong key: 401, and the key never appears in what we report.
    let bad = Client::with_base(&base, ApiKey::new("wrong-key-value")).unwrap();
    let e = bad.list_instances(None).await.unwrap_err();
    let e = format!("{e} {e:?} {bad:?}", bad = ApiKey::new("wrong-key-value"));
    assert!(e.contains("HTTP 401") && !e.contains("wrong-key-value"), "{e}");
    // Ids that would change the path are refused before any request.
    assert!(c.get_instance("../account").await.is_err());
    assert!(c.delete_instance("a/b").await.is_err());
}

struct Yes(Arc<Mutex<Vec<SpendRequest>>>);

impl SpendApprover for Yes {
    async fn approve(&self, r: &SpendRequest) -> Approval {
        self.0.lock().unwrap().push(r.clone());
        Approval::Approved
    }
}

fn boot() -> Boot {
    let k = HostKeyPair {
        private_openssh: "KEY-PLACEHOLDER\n".into(),
        public: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExamplePlaceholderKeyDataxxxxxxxxxxxxxxxxxxx wicket-node".into(),
    };
    Boot { user_data: cloud_config(NODE_SETUP, &k).unwrap(), host_key: k.public }
}

fn request(key: &str) -> CapacityRequest {
    CapacityRequest {
        resources: Resources { vcpus: 1, memory_mib: 2048 },
        min_isolation: IsolationTier::Gvisor,
        region_hint: Some("lhr".into()),
        plan_hint: None,
        max_hourly: MicroUsd::parse_dollars("0.02"),
        lifetime_secs: 3600,
        idempotency_key: key.into(),
        name: "n1".into(),
        purpose: "live test".into(),
        boot: Some(boot()),
    }
}

#[tokio::test]
async fn acquire_creates_a_tagged_instance_with_cloud_init_and_waits_for_it() {
    use base64::Engine;
    let (base, st) = serve().await;
    let asked = Arc::new(Mutex::new(vec![]));
    let p = Placer::new(
        VultrProvider::new(client(&base), config()),
        Yes(asked.clone()),
        Owner::new("example"),
        MoneyEnvelope { max_hourly: MicroUsd::parse_dollars("0.05").unwrap(), max_total: MicroUsd::parse_dollars("1").unwrap() },
    );
    let n = p.acquire(&request("task-1")).await.unwrap();
    assert_eq!(n.state, NodeState::Pending);
    assert_eq!(n.ssh_target, None); // no address yet
    assert!(n.host_key.as_deref().unwrap().starts_with("ssh-ed25519 "));
    // The cheapest vc2 plan with 2 GB in lhr (the 1 GB plan is too small, vhp is another family).
    assert_eq!(asked.lock().unwrap()[0].plan, "vc2-1c-2gb");
    assert_eq!(asked.lock().unwrap()[0].worst_case, MicroUsd::from_cents(2));

    let created = st.lock().unwrap().seen.iter().find(|s| s.method == "POST").cloned().unwrap();
    assert_eq!(created.path, "/v2/instances");
    let b = &created.body;
    assert_eq!(b["region"], "lhr");
    assert_eq!(b["plan"], "vc2-1c-2gb");
    assert_eq!(b["os_id"], 2284);
    assert_eq!(b["label"], "n1");
    assert_eq!(b["hostname"], "n1");
    assert_eq!(b["backups"], "disabled");
    assert_eq!(b["sshkey_id"], json!(["3b8066a7-b438-455a-9688-44afc9a3597f"]));
    let tags: Vec<String> = serde_json::from_value(b["tags"].clone()).unwrap();
    assert!(tags.contains(&"wicket-owner-example".to_string()));
    assert!(tags.contains(&Owner::new("example").idem_tag("task-1")));
    assert!(tags.iter().any(|t| t.starts_with("wicket-until-")));
    let ud = base64::engine::general_purpose::STANDARD.decode(b["user_data"].as_str().unwrap()).unwrap();
    let ud = String::from_utf8(ud).unwrap();
    assert!(ud.starts_with("#cloud-config\n") && ud.contains("ed25519_public: 'ssh-ed25519 "));
    // Before creating, it looked for an instance with the idempotency tag.
    let first_list = st.lock().unwrap().seen.iter().find(|s| s.method == "GET" && s.path == "/v2/instances").cloned().unwrap();
    assert!(first_list.query.contains(&("tag".into(), Owner::new("example").idem_tag("task-1"))));

    // Wait for it: active, running, installed, with an address.
    let ready = p.provider().wait_active(&n.id, Duration::from_millis(1), Duration::from_secs(5)).await.unwrap();
    assert_eq!(ready.state, NodeState::Active);
    assert_eq!(ready.ssh_target.as_deref(), Some("wicket@203.0.113.50"));
    assert_eq!(ready.created_at, 1_794_391_200);
    assert_eq!(p.next_paid_hour_at(&ready).unwrap() - ready.created_at, 3600 * (1 + (now() - ready.created_at).max(0) / 3600));

    // Same key again, from a fresh placer (a restart): found by tag, nothing created.
    let p2 = Placer::new(
        VultrProvider::new(client(&base), config()),
        Yes(asked.clone()),
        Owner::new("example"),
        MoneyEnvelope { max_hourly: MicroUsd::parse_dollars("0.05").unwrap(), max_total: MicroUsd::parse_dollars("1").unwrap() },
    );
    assert_eq!(p2.acquire(&request("task-1")).await.unwrap().id, n.id);
    assert_eq!(st.lock().unwrap().seen.iter().filter(|s| s.method == "POST").count(), 1);
    assert_eq!(asked.lock().unwrap().len(), 1);

    // The boot host key is scrubbed from the user data.
    p.provider().client().set_user_data(&n.id.0, wicket_placement::boot::SCRUBBED_USER_DATA).await.unwrap();
    let patch = st.lock().unwrap().seen.iter().find(|s| s.method == "PATCH").cloned().unwrap();
    assert_eq!(patch.path, format!("/v2/instances/{}", n.id));
    let ud = base64::engine::general_purpose::STANDARD.decode(patch.body["user_data"].as_str().unwrap()).unwrap();
    assert!(!String::from_utf8(ud).unwrap().contains("ssh_keys"));

    // Release: destroyed, then already gone.
    assert_eq!(p.release(&n.id, ReleaseMode::Now).await.unwrap(), Released::Destroyed);
    let del = st.lock().unwrap().seen.iter().find(|s| s.method == "DELETE").cloned().unwrap();
    assert_eq!(del.path, format!("/v2/instances/{}", n.id));
    assert_eq!(p.release(&n.id, ReleaseMode::Now).await.unwrap(), Released::AlreadyGone);
    assert!(!p.provider().client().delete_instance(&n.id.0).await.unwrap());
    // Every request carried the key as a bearer token, and never in the URL.
    for s in st.lock().unwrap().seen.iter() {
        assert_eq!(s.auth.as_deref(), Some(&*format!("Bearer {KEY}")));
        assert!(!s.query.iter().any(|(_, v)| v.contains(KEY)));
    }
}

#[tokio::test]
async fn listing_is_by_owner_tag_across_pages_and_never_includes_others() {
    let (base, st) = serve().await;
    {
        let mut m = st.lock().unwrap();
        for i in 0..5 {
            m.instances.push(json!({"id": format!("00000000-0000-0000-0000-00000000000{i}"), "plan": "vc2-1c-2gb", "region": "lhr",
                "status": "active", "power_status": "running", "server_status": "ok", "main_ip": format!("203.0.113.{}", 60 + i),
                "date_created": "2026-11-11T10:00:00+00:00", "label": format!("n{i}"),
                "tags": if i == 4 { json!(["control-host"]) } else { json!(["wicket-owner-example", "wicket-until-1794394200"]) }}));
        }
    }
    let p = Placer::new(
        VultrProvider::new(client(&base).with_per_page(2), config()),
        Yes(Arc::default()),
        Owner::new("example"),
        MoneyEnvelope { max_hourly: MicroUsd::ZERO, max_total: MicroUsd::ZERO },
    );
    let owned = p.list().await.unwrap();
    assert_eq!(owned.len(), 4);
    assert!(owned.iter().all(|n| n.state == NodeState::Active && n.lease_until == Some(1_794_394_200)));
    assert_eq!(owned[0].billing.hourly_rate(), MicroUsd(14_000));
    // The control host's instance is invisible to get and can't be released.
    let ctl = NodeId("00000000-0000-0000-0000-000000000004".into());
    assert!(p.get(&ctl).await.unwrap().is_none());
    assert!(matches!(p.release(&ctl, ReleaseMode::Now).await.unwrap_err(), PlacementError::NotOwned(_)));
    assert!(st.lock().unwrap().seen.iter().all(|s| s.method != "DELETE"));
    // The envelope (zero here) refuses a new node, with four nodes already counted.
    let e = p.acquire(&request("new")).await.unwrap_err();
    assert!(matches!(e, PlacementError::Envelope(_)), "{e}");
}

#[tokio::test]
async fn a_vm_zone_gets_no_vultr_offer() {
    let (base, _st) = serve().await;
    let p = Placer::new(
        VultrProvider::new(client(&base), config()),
        Yes(Arc::default()),
        Owner::new("example"),
        MoneyEnvelope { max_hourly: MicroUsd::parse_dollars("1").unwrap(), max_total: MicroUsd::parse_dollars("10").unwrap() },
    );
    let mut r = request("vm");
    r.min_isolation = IsolationTier::Vm;
    assert!(matches!(p.acquire(&r).await.unwrap_err(), PlacementError::NoCapacity(_)));
}

fn now() -> i64 {
    wicket_placement::model::now()
}
