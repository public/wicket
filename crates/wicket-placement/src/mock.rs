//! A local mock of the Vultr API v2 for tests (feature `mock`): plans, instances (create, list by
//! tag with paging, get, tag, delete), the bearer key check, injected responses, and a record of every
//! request. No real API is ever called.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// The API key the mock accepts.
pub const KEY: &str = "test-key-not-a-real-one";

/// A request the mock received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub auth: Option<String>,
    pub body: Value,
}

/// The mock's state: what it holds and what it was asked.
#[derive(Default)]
pub struct Mock {
    pub seen: Vec<Seen>,
    pub instances: Vec<Value>,
    /// Responses to return before normal handling (status, body).
    pub injected: VecDeque<(u16, Value)>,
    pub next_id: u32,
    /// GET /instances/{id} returns the instance with its tags removed (a tag changed after the list).
    pub strip_on_get: bool,
}

pub type Shared = Arc<Mutex<Mock>>;

/// The plans the mock offers.
pub fn plans() -> Vec<Value> {
    vec![
        json!({"id": "vc2-1c-1gb", "vcpu_count": 1, "ram": 1024, "disk": 25, "monthly_cost": 5, "type": "vc2", "locations": ["lhr", "ams"]}),
        json!({"id": "vc2-1c-2gb", "vcpu_count": 1, "ram": 2048, "disk": 55, "monthly_cost": 10, "hourly_cost": 0.014, "type": "vc2", "locations": ["lhr"]}),
        json!({"id": "vc2-2c-4gb", "vcpu_count": 2, "ram": 4096, "disk": 80, "monthly_cost": 20, "type": "vc2", "locations": ["lhr"]}),
        json!({"id": "vhp-1c-2gb-amd", "vcpu_count": 1, "ram": 2048, "disk": 50, "monthly_cost": 12, "type": "vhp", "locations": ["lhr"]}),
    ]
}

/// An instance as `GET /instances` returns it: active and ready, created at 2023-11-14T22:03:20Z.
pub fn instance(id: &str, tags: &[String]) -> Value {
    json!({ "id": id, "main_ip": "203.0.113.60", "date_created": "2023-11-14T22:03:20+00:00", "status": "active",
            "power_status": "running", "server_status": "ok", "plan": "vc2-1c-2gb", "region": "lhr", "label": id,
            "tags": tags, "vcpu_count": 1, "ram": 2048 })
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
                let mut i = i.clone();
                if m.strip_on_get {
                    i["tags"] = json!([]);
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

/// Serves the mock on a loopback port: (base URL ending in `/v2`, its state).
pub async fn serve() -> (String, Shared) {
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
