//! Runs the experiment: starts control-plane and node processes, a proxy that can cut the link or
//! inject frames, and records timelines and numbers into logs/.
//!
//!     harness [bench] [steady] [kill] [kill-prod] [catchup] [revocation] [attacks]

use ed25519_dalek::SigningKey;
use freshness_feed::cp::load_key;
use freshness_feed::feed::{self, kid, now_ms, payload_unverified, sign, sign_as, tamper, Change, Delta, Fresh, Grant, KeyCert, Replica, State, TYP_DELTA, TYP_FRESH, TYP_KEY, TYP_SNAP};
use freshness_feed::node::{Node, Query};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wicket_core::{Op, RunId, TenantId};

fn sleep_ms(ms: i64) {
    if ms > 0 {
        std::thread::sleep(Duration::from_millis(ms as u64));
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn logs() -> PathBuf {
    PathBuf::from("logs")
}

struct Rng(u64);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n.max(1)
    }
}

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(name: &str, args: Vec<String>, log: &str) -> Proc {
    let exe = std::env::current_exe().unwrap().parent().unwrap().join(name);
    let f = std::fs::File::create(logs().join(log)).unwrap();
    Proc(Command::new(exe).args(args).stdout(Stdio::null()).stderr(f).spawn().unwrap())
}

struct Client {
    r: BufReader<TcpStream>,
    w: TcpStream,
}

impl Client {
    fn connect(port: u16) -> Client {
        for _ in 0..400 {
            if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
                s.set_nodelay(true).unwrap();
                return Client { r: BufReader::new(s.try_clone().unwrap()), w: s };
            }
            sleep_ms(25);
        }
        panic!("no server on {port}");
    }
    fn call(&mut self, v: &Value) -> Value {
        self.w.write_all(format!("{v}\n").as_bytes()).unwrap();
        let mut l = String::new();
        self.r.read_line(&mut l).unwrap();
        serde_json::from_str(&l).unwrap_or(Value::Null)
    }
}

#[derive(Clone, Copy)]
struct P {
    ttl: i64,
    refresh: i64,
    grace: i64,
    retain: u64,
}

struct CpProc {
    p: Proc,
    admin: Client,
}

fn start_cp(dir: &Path, prm: P, fp: u16, ap: u16, log: &str) -> CpProc {
    let a = |s: &str| s.to_string();
    let args = vec![
        a("--dir"), dir.display().to_string(), a("--feed"), a("n1"), a("--feed-port"), fp.to_string(), a("--admin-port"), ap.to_string(),
        a("--ttl-ms"), prm.ttl.to_string(), a("--refresh-ms"), prm.refresh.to_string(), a("--grace-ms"), prm.grace.to_string(), a("--retain"), prm.retain.to_string(),
    ];
    let p = spawn("cp", args, log);
    CpProc { p, admin: Client::connect(ap) }
}

impl CpProc {
    fn cmd(&mut self, v: Value) -> Value {
        self.admin.call(&v)
    }
    fn epoch(&mut self) -> u64 {
        self.cmd(json!({"cmd": "stats"}))["epoch"].as_u64().unwrap()
    }
    fn kill(&mut self) {
        let _ = self.p.0.kill();
        let _ = self.p.0.wait();
    }
}

struct NodeProc {
    _p: Proc,
    q: Client,
}

fn start_node(cp_port: u16, root: &Path, push: bool, poll_ms: i64, idle_ms: i64, log: &str) -> NodeProc {
    let qp = free_port();
    let a = |s: &str| s.to_string();
    let args = vec![
        a("--cp"), format!("127.0.0.1:{cp_port}"), a("--root"), root.display().to_string(), a("--node"), a("n1"), a("--query-port"), qp.to_string(),
        a("--push"), a(if push { "on" } else { "off" }), a("--poll-ms"), poll_ms.to_string(), a("--idle-ms"), idle_ms.to_string(),
    ];
    let p = spawn("node", args, log);
    NodeProc { _p: p, q: Client::connect(qp) }
}

impl NodeProc {
    fn status(&mut self) -> Value {
        self.q.call(&json!({"q": "status"}))
    }
    fn ask(&mut self, q: &Value) -> Value {
        self.q.call(q)
    }
    /// Polls status every ms until `pred`; returns the wait in ms.
    fn wait(&mut self, timeout_ms: i64, pred: impl Fn(&Value) -> bool) -> Option<i64> {
        let t0 = now_ms();
        loop {
            if pred(&self.status()) {
                return Some(now_ms() - t0);
            }
            if now_ms() - t0 > timeout_ms {
                return None;
            }
            sleep_ms(1);
        }
    }
}

fn caught(e: u64) -> impl Fn(&Value) -> bool {
    move |s| s["epoch"].as_u64().is_some_and(|x| x >= e) && s["mode"] == "fresh"
}

fn zone(k: usize) -> Value {
    json!({"name": format!("z{k}"), "reach": [
        {"host": "api.github.com", "methods": ["GET", "HEAD"], "paths": [format!("/repos/acme/r{k}/**")]},
        {"host": "api.github.com", "methods": ["PUT"], "paths": [format!("/repos/acme/r{k}/contents/**")]},
        {"host": "pypi.org", "paths": ["/simple/**"]},
        {"host": "files.pythonhosted.org"}],
        "forbid": [{"host": "evil.example"}]})
}

fn digest(zone: &str, method: &str, host: &str, path: &str) -> String {
    Op::egress(&TenantId::single(), &RunId(String::new()), zone, method, host, path).digest()
}

fn grant(id: &str, zone: &str, path: &str, not_after: i64) -> Value {
    json!({"id": id, "zone": zone, "op": digest(zone, "POST", "api.github.com", path), "what": format!("POST api.github.com{path}"), "not_after": not_after})
}

fn op_q(zone: &str, method: &str, host: &str, path: &str) -> Value {
    json!({"q": "op", "zone": zone, "run": "run-a", "method": method, "host": host, "path": path})
}

/// 50 zones in one delta, 1000 grants in deltas of 100, plus `keep-1` for the probes.
fn seed(cp: &mut CpProc, zones: usize, grants: usize) -> u64 {
    let ch: Vec<Value> = (0..zones).map(|k| json!({"op": "put_zone", "zone": zone(k)})).collect();
    cp.cmd(json!({"cmd": "batch", "changes": ch}));
    let na = now_ms() + 3_600_000;
    for start in (0..grants).step_by(100) {
        let ch: Vec<Value> = (start..(start + 100).min(grants))
            .map(|i| {
                let k = i % zones;
                json!({"op": "add_grant", "grant": grant(&format!("s-{i}"), &format!("z{k}"), &format!("/repos/acme/r{k}/issues/{i}/comments"), na)})
            })
            .collect();
        cp.cmd(json!({"cmd": "batch", "changes": ch}));
    }
    cp.cmd(json!({"cmd": "grant", "grant": grant("keep-1", "z0", "/repos/acme/r0/issues/9999/comments", na)}));
    cp.epoch()
}

fn probe_set() -> Vec<(&'static str, Value)> {
    vec![
        ("read_R1", op_q("z0", "GET", "api.github.com", "/repos/acme/r0/readme")),
        ("write_R2", op_q("z0", "PUT", "api.github.com", "/repos/acme/r0/contents/README.md")),
        ("granted_op", op_q("z0", "POST", "api.github.com", "/repos/acme/r0/issues/9999/comments")),
        ("short_grant", op_q("z0", "POST", "api.github.com", "/repos/acme/r0/issues/9998/comments")),
        ("new_lease", json!({"q": "lease", "zone": "z0", "grant": "keep-1", "ttl_ms": 10000})),
        ("spawn", json!({"q": "spawn", "zone": "z0", "child": "z1"})),
        ("approve", json!({"q": "approve", "zone": "z0", "run": "run-a", "method": "POST", "host": "api.github.com", "path": "/repos/acme/r0/pulls", "ttl_ms": 5000})),
        ("forbidden", op_q("z0", "GET", "evil.example", "/")),
    ]
}

fn probe(n: &mut NodeProc) -> (String, Vec<(&'static str, bool, String)>) {
    let mut mode = String::new();
    let out = probe_set()
        .into_iter()
        .map(|(name, q)| {
            let r = n.ask(&q);
            mode = r["mode"].as_str().unwrap_or("").to_string();
            (name, r["allow"].as_bool().unwrap_or(false), r["why"].as_str().unwrap_or("").to_string())
        })
        .collect();
    (mode, out)
}

/// From timeline rows, each probe's value changes as [t_ms, allow, why].
fn transitions(rows: &[(i64, String, Vec<(&'static str, bool, String)>)]) -> Value {
    let mut out = serde_json::Map::new();
    let mut mode_changes = vec![];
    for (i, (t, mode, ps)) in rows.iter().enumerate() {
        if i == 0 || rows[i - 1].1 != *mode {
            mode_changes.push(json!([t, mode]));
        }
        for (j, (name, allow, why)) in ps.iter().enumerate() {
            if i == 0 || rows[i - 1].2[j].1 != *allow {
                out.entry(name.to_string()).or_insert(json!([])).as_array_mut().unwrap().push(json!([t, allow, why]));
            }
        }
    }
    json!({"mode": mode_changes, "probes": out})
}

fn write_json(name: &str, v: &Value) {
    std::fs::write(logs().join(name), serde_json::to_string_pretty(v).unwrap()).unwrap();
}

fn pct(v: &mut [f64]) -> Value {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| v[((v.len() as f64 - 1.0) * q).round() as usize];
    json!({"n": v.len(), "p50": p(0.5), "p90": p(0.9), "p99": p(0.99), "max": v[v.len() - 1], "mean": v.iter().sum::<f64>() / v.len() as f64})
}

// ---------------------------------------------------------------------------------------------
// Kill the control plane: which ops continue, and when they stop. Then restart it.

fn scen_kill(label: &str, prm: P, step: i64) -> Value {
    let dir = logs().join(format!("{label}-cpstate"));
    let _ = std::fs::remove_dir_all(&dir);
    let (fp, ap) = (free_port(), free_port());
    let mut cp = start_cp(&dir, prm, fp, ap, &format!("{label}-cp.log"));
    let mut node = start_node(fp, &dir.join("root.pub"), true, 1000, 3 * prm.refresh, &format!("{label}-node.log"));
    let e = seed(&mut cp, 50, 1000);
    node.wait(30_000, caught(e)).expect("node caught up");
    let t_kill = now_ms() + 300;
    let short_until = t_kill + prm.ttl / 2;
    cp.cmd(json!({"cmd": "grant", "grant": grant("keep-short", "z0", "/repos/acme/r0/issues/9998/comments", short_until)}));
    let e = cp.epoch();
    node.wait(5000, caught(e)).expect("short grant applied");
    let (_, before) = probe(&mut node);
    sleep_ms(t_kill - now_ms());
    let t0 = now_ms();
    cp.kill();
    let st = node.status();
    let fresh_until = st["fresh_until"].as_i64().unwrap();
    let narrow_until = st["vouched"][1].as_i64().unwrap();
    println!("[{label}] killed cp at t0; last freshness: fresh until t0+{} ms, narrow until t0+{} ms", fresh_until - t0, narrow_until - t0);
    let mut rows = vec![];
    let end = narrow_until + (3 * step).max(1000);
    let mut lat = vec![];
    while now_ms() < end {
        let t = now_ms();
        let i = Instant::now();
        let (mode, ps) = probe(&mut node);
        lat.push(i.elapsed().as_secs_f64() * 1e6 / ps.len() as f64);
        rows.push((t - t0, mode, ps));
        sleep_ms(step - (now_ms() - t));
    }
    let down_ms = now_ms() - t0;
    let t_r = now_ms();
    let mut cp2 = start_cp(&dir, prm, fp, ap, &format!("{label}-cp-restart.log"));
    let t_up = now_ms() - t_r;
    let back = node.wait(10_000, |s| s["mode"] == "fresh").expect("fresh again");
    let t_fresh = now_ms() - t_r;
    let t_c = now_ms();
    cp2.cmd(json!({"cmd": "revoke", "id": "keep-1"}));
    cp2.cmd(json!({"cmd": "grant", "grant": grant("keep-2", "z0", "/repos/acme/r0/issues/9997/comments", now_ms() + 3_600_000)}));
    let e2 = cp2.epoch();
    node.wait(5000, caught(e2)).expect("caught up after restart");
    let t_caught = now_ms() - t_c;
    let (_, after) = probe(&mut node);
    let keep2 = node.ask(&op_q("z0", "POST", "api.github.com", "/repos/acme/r0/issues/9997/comments"));
    let tl: Vec<Value> = rows.iter().map(|(t, m, ps)| json!({"t": t, "mode": m, "allow": ps.iter().map(|p| (p.0.to_string(), json!(p.1))).collect::<serde_json::Map<_, _>>()})).collect();
    write_json(&format!("{label}-timeline.json"), &json!(tl));
    let r = json!({
        "params": {"ttl_ms": prm.ttl, "refresh_ms": prm.refresh, "grace_ms": prm.grace, "probe_step_ms": step},
        "last_fresh_until_after_kill_ms": fresh_until - t0, "narrow_until_after_kill_ms": narrow_until - t0,
        "short_grant_not_after_ms": short_until - t0,
        "before_kill": before.iter().map(|p| json!([p.0, p.1])).collect::<Vec<_>>(),
        "timeline": transitions(&rows),
        "probe_latency_us_per_query": pct(&mut lat),
        "restart": {"cp_down_ms": down_ms, "cp_admin_up_ms": t_up, "node_fresh_after_restart_ms": t_fresh, "wait_fresh_ms": back,
                    "revoke_and_grant_to_caught_up_ms": t_caught, "epoch": e2,
                    "after": after.iter().map(|p| json!([p.0, p.1, p.2])).collect::<Vec<_>>(), "keep2_allowed": keep2["allow"]},
        "node_status": node.status(),
    });
    write_json(&format!("{label}.json"), &r);
    r
}

// ---------------------------------------------------------------------------------------------
// A proxy on the node's feed link that can cut it and inject frames.

#[derive(Default)]
struct PxState {
    cut: bool,
    down: Option<TcpStream>,
    socks: Vec<TcpStream>,
    captured: Vec<String>,
}

struct Proxy {
    port: u16,
    st: Arc<Mutex<PxState>>,
}

impl Proxy {
    fn start(up: u16) -> Proxy {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let st = Arc::new(Mutex::new(PxState::default()));
        let st2 = st.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                if st2.lock().unwrap().cut {
                    continue;
                }
                let Ok(u) = TcpStream::connect(("127.0.0.1", up)) else { continue };
                let _ = (c.set_nodelay(true), u.set_nodelay(true));
                {
                    let mut s = st2.lock().unwrap();
                    s.socks.push(c.try_clone().unwrap());
                    s.socks.push(u.try_clone().unwrap());
                    s.down = Some(c.try_clone().unwrap());
                }
                let (mut c2, mut u2) = (c.try_clone().unwrap(), u.try_clone().unwrap());
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut c2, &mut u2);
                    let _ = u2.shutdown(Shutdown::Both);
                });
                let st3 = st2.clone();
                std::thread::spawn(move || {
                    let mut r = BufReader::new(u);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match r.read_line(&mut line) {
                            Ok(0) | Err(_) => break,
                            _ => {}
                        }
                        let mut s = st3.lock().unwrap();
                        s.captured.push(line.trim_end().to_string());
                        if (&c).write_all(line.as_bytes()).is_err() {
                            break;
                        }
                    }
                    let _ = c.shutdown(Shutdown::Both);
                });
            }
        });
        Proxy { port, st }
    }
    fn cut(&self) {
        let mut s = self.st.lock().unwrap();
        s.cut = true;
        for x in s.socks.drain(..) {
            let _ = x.shutdown(Shutdown::Both);
        }
        s.down = None;
    }
    fn restore(&self) {
        self.st.lock().unwrap().cut = false;
    }
    fn inject(&self, t: &str, jws: &str) -> bool {
        let s = self.st.lock().unwrap();
        let line = format!("{}\n", json!({"t": t, "jws": jws}));
        s.down.as_ref().is_some_and(|d| (&*d).write_all(line.as_bytes()).is_ok())
    }
    fn captured(&self, t: &str) -> Vec<String> {
        let s = self.st.lock().unwrap();
        s.captured.iter().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|v| v["t"] == t).map(|v| v["jws"].as_str().unwrap().to_string()).collect()
    }
}

/// Node events from its log after `since` (ms).
fn node_events(log: &str, since: i64) -> Vec<Value> {
    std::fs::read_to_string(logs().join(log)).unwrap_or_default().lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|v| v["ts"].as_i64().unwrap_or(0) >= since).collect()
}

// ---------------------------------------------------------------------------------------------
// Partition the node while updates continue at 10/s; catch up from deltas, then from a snapshot.

fn scen_catchup() -> Value {
    let prm = P { ttl: 3000, refresh: 500, grace: 6000, retain: 150 };
    let dir = logs().join("catchup-cpstate");
    let _ = std::fs::remove_dir_all(&dir);
    let (fp, ap) = (free_port(), free_port());
    let mut cp = start_cp(&dir, prm, fp, ap, "catchup-cp.log");
    let px = Proxy::start(fp);
    let mut node = start_node(px.port, &dir.join("root.pub"), true, 1000, 3 * prm.refresh, "catchup-node.log");
    let e = seed(&mut cp, 50, 1000);
    node.wait(30_000, caught(e)).unwrap();
    cp.cmd(json!({"cmd": "churn", "rate": 10}));
    sleep_ms(3000);
    let mut out = vec![];
    for (label, cut_s) in [("short_gap_deltas", 10), ("long_gap_snapshot", 30)] {
        let e = cp.epoch();
        node.wait(10_000, caught(e)).unwrap();
        let s0 = node.status();
        px.cut();
        let t_cut = now_ms();
        let mut modes = vec![];
        let mut last = String::new();
        while now_ms() - t_cut < cut_s * 1000 {
            let m = node.status()["mode"].as_str().unwrap_or("").to_string();
            if m != last {
                modes.push(json!([now_ms() - t_cut, m]));
                last = m;
            }
            sleep_ms(20);
        }
        let e_cp = cp.epoch();
        let behind = e_cp - s0["epoch"].as_u64().unwrap();
        let b1 = cp.cmd(json!({"cmd": "stats"}));
        let t_r = now_ms();
        px.restore();
        let wait = node.wait(20_000, caught(e_cp)).unwrap();
        let s1 = node.status();
        let b2 = cp.cmd(json!({"cmd": "stats"}));
        let ev = node_events("catchup-node.log", t_r);
        let first = ev.iter().find(|v| v["ev"] == "accepted").and_then(|v| v["ts"].as_i64()).unwrap_or(t_r);
        let done = ev.iter().find(|v| v["ev"] == "accepted" && v["epoch"].as_u64().is_some_and(|x| x >= e_cp)).and_then(|v| v["ts"].as_i64()).unwrap_or(first);
        let d = |k: &str, s: &Value| s["accepted"][k].as_u64().unwrap_or(0);
        let bytes = |s: &Value| s["bytes"].as_object().map(|o| o.values().map(|v| v.as_u64().unwrap()).sum::<u64>()).unwrap_or(0);
        let r = json!({
            "case": label, "cut_s": cut_s, "retain": prm.retain, "epochs_behind": behind, "modes_during_cut": modes,
            "deltas_received": d("delta", &s1) - d("delta", &s0), "snapshots_received": d("snap", &s1) - d("snap", &s0),
            "restore_to_fresh_ms": wait, "first_frame_to_caught_up_ms": done - first, "reconnect_ms": first - t_r,
            "catchup_bytes": bytes(&b2) - bytes(&b1),
        });
        println!("[catchup] {r}");
        out.push(r);
    }
    let r = json!({"cases": out, "refused": node.status()["refused"]});
    write_json("catchup.json", &r);
    r
}

// ---------------------------------------------------------------------------------------------
// Revocation latency: push, polling at two intervals, and a partitioned node (the bound).

fn spin_until_denied(n: &mut NodeProc, q: &Value, t0: Instant, max_ms: u128) -> (f64, String) {
    loop {
        let r = n.ask(q);
        if r["allow"] != true || t0.elapsed().as_millis() > max_ms {
            return (t0.elapsed().as_secs_f64() * 1e3, r["why"].as_str().unwrap_or("").to_string());
        }
    }
}

fn scen_revocation() -> Value {
    let prm = P { ttl: 3000, refresh: 500, grace: 6000, retain: 1000 };
    let dir = logs().join("revocation-cpstate");
    let _ = std::fs::remove_dir_all(&dir);
    let (fp, ap) = (free_port(), free_port());
    let mut cp = start_cp(&dir, prm, fp, ap, "revocation-cp.log");
    seed(&mut cp, 50, 1000);
    let na = now_ms() + 3_600_000;
    let rv = |i: usize| format!("/repos/acme/r1/issues/{}/comments", 50_000 + i);
    let ch: Vec<Value> = (0..200).map(|i| json!({"op": "add_grant", "grant": grant(&format!("rv-{i}"), "z1", &rv(i), na)})).collect();
    cp.cmd(json!({"cmd": "batch", "changes": ch}));
    let e = cp.epoch();
    let root = dir.join("root.pub");
    let mut rng = Rng(now_ms() as u64 | 1);
    let mut results = vec![];
    let mut next = 0usize;
    for (label, push, poll, trials) in [("push", true, 1000, 50), ("poll_1000ms", false, 1000, 30), ("poll_250ms", false, 250, 30)] {
        let mut n = start_node(fp, &root, push, poll, 3 * prm.refresh, &format!("revocation-node-{label}.log"));
        n.wait(20_000, caught(e)).unwrap();
        let mut lat = vec![];
        let mut ack = vec![];
        for _ in 0..trials {
            let i = next;
            next += 1;
            let q = op_q("z1", "POST", "api.github.com", &rv(i));
            assert_eq!(n.ask(&q)["allow"], true, "rv-{i} allowed before revoke");
            sleep_ms(rng.below(poll as u64) as i64 + 20);
            let t0 = Instant::now();
            cp.cmd(json!({"cmd": "revoke", "id": format!("rv-{i}")}));
            ack.push(t0.elapsed().as_secs_f64() * 1e3);
            let (ms, why) = spin_until_denied(&mut n, &q, t0, 20_000);
            assert!(why.contains("needs a grant"), "{why}");
            lat.push(ms);
        }
        let r = json!({"case": label, "poll_ms": if push { Value::Null } else { json!(poll) }, "latency_ms": pct(&mut lat), "admin_ack_ms": pct(&mut ack)});
        println!("[revocation] {r}");
        results.push(r);
    }
    // Partitioned: the node hears nothing; the bound is the freshness TTL.
    let px = Proxy::start(fp);
    let mut n = start_node(px.port, &root, true, 1000, 3 * prm.refresh, "revocation-node-partitioned.log");
    let mut lat = vec![];
    let mut slack = vec![];
    let mut whys = std::collections::BTreeSet::new();
    for _ in 0..10 {
        let e = cp.epoch();
        n.wait(20_000, caught(e)).unwrap();
        sleep_ms(rng.below(prm.refresh as u64) as i64 + 20);
        let i = next;
        next += 1;
        let q = op_q("z1", "POST", "api.github.com", &rv(i));
        px.cut();
        let t0 = Instant::now();
        let t0_ms = now_ms();
        cp.cmd(json!({"cmd": "revoke", "id": format!("rv-{i}")}));
        let fu = n.status()["fresh_until"].as_i64().unwrap();
        let (ms, why) = spin_until_denied(&mut n, &q, t0, 20_000);
        whys.insert(why);
        lat.push(ms);
        slack.push((fu - t0_ms) as f64 - ms);
        px.restore();
    }
    let r = json!({"case": "partitioned", "ttl_ms": prm.ttl, "latency_ms": pct(&mut lat), "deny_minus_fresh_until_ms": pct(&mut slack.iter().map(|x| -x).collect::<Vec<_>>()), "why": whys});
    println!("[revocation] {r}");
    results.push(r);
    let r = json!({"params": {"ttl_ms": prm.ttl, "refresh_ms": prm.refresh}, "cases": results});
    write_json("revocation.json", &r);
    r
}

// ---------------------------------------------------------------------------------------------
// Tampered, replayed, rolled-back and forged updates, injected on the node's feed link.

fn scen_attacks() -> Value {
    let prm = P { ttl: 3000, refresh: 500, grace: 6000, retain: 1000 };
    let dir = logs().join("attacks-cpstate");
    let _ = std::fs::remove_dir_all(&dir);
    let (fp, ap) = (free_port(), free_port());
    let mut cp = start_cp(&dir, prm, fp, ap, "attacks-cp.log");
    let px = Proxy::start(fp);
    let mut node = start_node(px.port, &dir.join("root.pub"), true, 1000, 3 * prm.refresh, "attacks-node.log");
    seed(&mut cp, 5, 20);
    let old_snap = cp.cmd(json!({"cmd": "snapshot"}))["jws"].as_str().unwrap().to_string();
    for i in 0..3 {
        cp.cmd(json!({"cmd": "grant", "grant": grant(&format!("a-{i}"), "z0", &format!("/repos/acme/r0/issues/{}/comments", 7000 + i), now_ms() + 3_600_000)}));
    }
    let e = cp.epoch();
    node.wait(10_000, caught(e)).unwrap();
    sleep_ms(1200); // a few freshness statements
    let feedk = load_key(&dir.join("feed.key")).unwrap();
    let evil = SigningKey::from_bytes(&[7u8; 32]);
    let real_kid = kid(&feedk.verifying_key());
    let root_kid = kid(&load_key(&dir.join("root.key")).unwrap().verifying_key());
    let evil_path = "/repos/acme/r0/hooks";
    let evil_q = op_q("z0", "POST", "api.github.com", evil_path);
    let keep_q = op_q("z0", "POST", "api.github.com", "/repos/acme/r0/issues/9999/comments");
    let evil_change = json!([{"op": "add_grant", "grant": grant("evil", "z0", evil_path, i64::MAX)}]);
    let mut cases = vec![];
    type Mk = Box<dyn Fn(&Value, &Proxy) -> (String, String)>;
    let deltas_of = |px: &Proxy| px.captured("delta");
    let list: Vec<(&str, &str, &str, Mk)> = vec![
        ("tampered delta (adds a grant, signature kept)", "bad_signature", "delta", Box::new(move |s: &Value, px: &Proxy| {
            let last = deltas_of(px).last().unwrap().clone();
            let mut p = payload_unverified(&last).unwrap();
            p["epoch"] = json!(s["epoch"].as_u64().unwrap() + 1);
            p["prev"] = s["head"].clone();
            p["changes"] = evil_change.clone();
            ("delta".into(), tamper(&last, &p))
        })),
        ("replayed old delta", "replay", "delta", Box::new(|_: &Value, px: &Proxy| ("delta".into(), px.captured("delta")[1].clone()))),
        ("rollback to an old signed snapshot", "rollback", "snap", Box::new(move |_: &Value, _: &Proxy| ("snap".into(), old_snap.clone()))),
        ("reused freshness statement", "replay", "fresh", Box::new(|_: &Value, px: &Proxy| {
            let f = px.captured("fresh");
            ("fresh".into(), f[f.len() - 2].clone())
        })),
        ("forged freshness, attacker key", "unknown_key", "fresh", Box::new(move |s: &Value, _: &Proxy| {
            let f = Fresh { feed: "n1".into(), epoch: s["epoch"].as_u64().unwrap(), head: s["head"].as_str().unwrap().into(), issued_at: now_ms(), fresh_until: now_ms() + 3_600_000, narrow_until: now_ms() + 3_600_000 };
            ("fresh".into(), sign(&SigningKey::from_bytes(&[7u8; 32]), TYP_FRESH, &f))
        })),
        ("forged freshness, attacker key under the real kid", "bad_signature", "fresh", {
            let rk = real_kid.clone();
            Box::new(move |s: &Value, _: &Proxy| {
                let f = Fresh { feed: "n1".into(), epoch: s["epoch"].as_u64().unwrap(), head: s["head"].as_str().unwrap().into(), issued_at: now_ms(), fresh_until: now_ms() + 3000, narrow_until: now_ms() + 9000 };
                ("fresh".into(), sign_as(&SigningKey::from_bytes(&[7u8; 32]), TYP_FRESH, &rk, &f))
            })
        }),
        ("over-long freshness signed by the real feed key (stolen online key)", "too_long", "fresh", {
            let fk = feedk.clone();
            Box::new(move |s: &Value, _: &Proxy| {
                let f = Fresh { feed: "n1".into(), epoch: s["epoch"].as_u64().unwrap(), head: s["head"].as_str().unwrap().into(), issued_at: now_ms(), fresh_until: now_ms() + 3_600_000, narrow_until: now_ms() + 3_600_000 };
                ("fresh".into(), sign(&fk, TYP_FRESH, &f))
            })
        }),
        ("freshness from the future (issued 60 s ahead)", "from_future", "fresh", {
            let fk = feedk.clone();
            Box::new(move |s: &Value, _: &Proxy| {
                let t = now_ms() + 60_000;
                let f = Fresh { feed: "n1".into(), epoch: s["epoch"].as_u64().unwrap(), head: s["head"].as_str().unwrap().into(), issued_at: t, fresh_until: t + 3000, narrow_until: t + 9000 };
                ("fresh".into(), sign(&fk, TYP_FRESH, &f))
            })
        }),
        ("expired freshness (new issued_at, already past fresh_until)", "expired", "fresh", {
            let fk = feedk.clone();
            Box::new(move |s: &Value, _: &Proxy| {
                let t = now_ms() - 1;
                let f = Fresh { feed: "n1".into(), epoch: s["epoch"].as_u64().unwrap(), head: s["head"].as_str().unwrap().into(), issued_at: t, fresh_until: t, narrow_until: t + 6000 };
                ("fresh".into(), sign(&fk, TYP_FRESH, &f))
            })
        }),
        ("forged feed-key certificate (attacker signs as root)", "bad_signature", "key", {
            let rk = root_kid.clone();
            Box::new(move |_: &Value, _: &Proxy| {
                let c = KeyCert::new(&evil.verifying_key(), 99, i64::MAX, i64::MAX, i64::MAX);
                ("key".into(), sign_as(&SigningKey::from_bytes(&[8u8; 32]), TYP_KEY, &rk, &c))
            })
        }),
        ("delta relabelled as a freshness statement", "wrong_type", "fresh", Box::new(|_: &Value, px: &Proxy| ("fresh".into(), px.captured("delta").last().unwrap().clone()))),
        ("validly signed delta for another node (n2)", "wrong_audience", "delta", {
            let fk = feedk.clone();
            Box::new(move |s: &Value, _: &Proxy| {
                let d = Delta { feed: "n2".into(), epoch: s["epoch"].as_u64().unwrap() + 1, prev: s["head"].as_str().unwrap().into(), issued_at: now_ms(), changes: vec![] };
                ("delta".into(), sign(&fk, TYP_DELTA, &d))
            })
        }),
        ("validly signed delta skipping an epoch (gap)", "gap", "delta", {
            let fk = feedk.clone();
            Box::new(move |s: &Value, _: &Proxy| {
                let d = Delta { feed: "n1".into(), epoch: s["epoch"].as_u64().unwrap() + 2, prev: s["head"].as_str().unwrap().into(), issued_at: now_ms(), changes: vec![] };
                ("delta".into(), sign(&fk, TYP_DELTA, &d))
            })
        }),
        ("validly signed delta on a different chain (fork)", "fork", "delta", {
            let fk = feedk.clone();
            Box::new(move |s: &Value, _: &Proxy| {
                let d = Delta { feed: "n1".into(), epoch: s["epoch"].as_u64().unwrap() + 1, prev: feed::GENESIS.into(), issued_at: now_ms(), changes: serde_json::from_value(json!([{"op": "add_grant", "grant": grant("evil", "z0", "/repos/acme/r0/hooks", i64::MAX)}])).unwrap() };
                ("delta".into(), sign(&fk, TYP_DELTA, &d))
            })
        }),
    ];
    for (name, kind, _, mk) in &list {
        let s0 = node.status();
        let (t, jws) = mk(&s0, &px);
        let injected = px.inject(&t, &jws);
        sleep_ms(60);
        let s1 = node.status();
        let c = |s: &Value| s["refused"][*kind].as_u64().unwrap_or(0);
        let ev = node.ask(&evil_q);
        let keep = node.ask(&keep_q);
        let ok = injected && c(&s1) == c(&s0) + 1 && s1["epoch"] == s0["epoch"] && ev["allow"] == false && keep["allow"] == true && s1["mode"] == "fresh";
        let r = json!({"case": name, "expected": kind, "refused_as_expected": ok, "last_refusal": s1["last_refusal"], "epoch": s1["epoch"], "mode": s1["mode"], "evil_op_allowed": ev["allow"], "keep_grant_allowed": keep["allow"]});
        println!("[attacks] {r}");
        cases.push(r);
        sleep_ms(400); // a gap makes the node resubscribe (retry 200 ms): let the new link settle
        node.wait(5000, |s| s["mode"] == "fresh").unwrap();
    }
    // The control plane restored from an old backup (its log truncated): the node refuses its
    // snapshot and freshness as rollbacks, and goes narrow then closed on the last good statement.
    let s0 = node.status();
    let held = s0["epoch"].as_u64().unwrap();
    cp.kill();
    let t0 = now_ms();
    let bdir = logs().join("attacks-cpstate-backup");
    let _ = std::fs::remove_dir_all(&bdir);
    std::fs::create_dir_all(&bdir).unwrap();
    for f in ["root.key", "feed.key"] {
        std::fs::copy(dir.join(f), bdir.join(f)).unwrap();
    }
    let log = std::fs::read_to_string(dir.join("deltas.jsonl")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    std::fs::write(bdir.join("deltas.jsonl"), lines[..lines.len() - 3].join("\n") + "\n").unwrap();
    let mut cpb = start_cp(&bdir, prm, fp, ap, "attacks-cp-backup.log");
    let fu = s0["fresh_until"].as_i64().unwrap();
    let mut modes = vec![];
    let mut last = String::new();
    while now_ms() < s0["vouched"][1].as_i64().unwrap() + 500 {
        let m = node.status()["mode"].as_str().unwrap_or("").to_string();
        if m != last {
            modes.push(json!([now_ms() - t0, m]));
            last = m;
        }
        sleep_ms(20);
    }
    let s1 = node.status();
    let backup_epoch = cpb.epoch();
    cpb.kill();
    let mut cp = start_cp(&dir, prm, fp, ap, "attacks-cp-recovered.log");
    let e = cp.epoch();
    let rec = node.wait(10_000, caught(e));
    let r_backup = json!({"case": "control plane restored from an old backup", "node_epoch": held, "backup_epoch": backup_epoch,
        "rollback_refusals": s1["refused"]["rollback"].as_u64().unwrap_or(0) - s0["refused"]["rollback"].as_u64().unwrap_or(0),
        "last_refusal": s1["last_refusal"], "modes_after_kill_ms": modes, "legit_fresh_until_after_kill_ms": fu - t0,
        "epoch_after": s1["epoch"], "recovered_with_real_cp_ms": rec});
    println!("[attacks] {r_backup}");
    let r = json!({"cases": cases, "backup_restore": r_backup, "refused_totals": node.status()["refused"], "accepted_totals": node.status()["accepted"]});
    write_json("attacks.json", &r);
    r
}

// ---------------------------------------------------------------------------------------------
// Steady state: decision latency over the node's socket under 10 updates/s; feed bandwidth.

fn scen_steady() -> Value {
    let prm = P { ttl: 30_000, refresh: 5000, grace: 120_000, retain: 1000 };
    let dir = logs().join("steady-cpstate");
    let _ = std::fs::remove_dir_all(&dir);
    let (fp, ap) = (free_port(), free_port());
    let mut cp = start_cp(&dir, prm, fp, ap, "steady-cp.log");
    let mut node = start_node(fp, &dir.join("root.pub"), true, 1000, 3 * prm.refresh, "steady-node.log");
    let e = seed(&mut cp, 50, 1000);
    node.wait(30_000, caught(e)).unwrap();
    let snap = cp.cmd(json!({"cmd": "snapshot"}))["jws"].as_str().unwrap().len();
    let s0 = cp.cmd(json!({"cmd": "stats"}));
    let t0 = Instant::now();
    cp.cmd(json!({"cmd": "churn", "rate": 10}));
    let classes = [
        ("reach_read", op_q("z3", "GET", "api.github.com", "/repos/acme/r3/pulls/12")),
        ("reach_write", op_q("z3", "PUT", "api.github.com", "/repos/acme/r3/contents/src/lib.rs")),
        ("granted", op_q("z0", "POST", "api.github.com", "/repos/acme/r0/issues/9999/comments")),
        ("needs_grant_denied", op_q("z3", "DELETE", "api.github.com", "/repos/acme/r3")),
        ("forbidden", op_q("z3", "GET", "evil.example", "/x")),
    ];
    let mut lat: Vec<Vec<f64>> = vec![vec![]; classes.len()];
    let mut i = 0;
    let mut wrong = 0;
    while t0.elapsed() < Duration::from_secs(60) {
        let k = i % classes.len();
        let t = Instant::now();
        let r = node.ask(&classes[k].1);
        lat[k].push(t.elapsed().as_secs_f64() * 1e6);
        if r["allow"] != json!(k < 3) {
            wrong += 1;
        }
        i += 1;
        if i % 50 == 0 {
            sleep_ms(1); // leave CPU for the feed; ~25k queries/min
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    let s1 = cp.cmd(json!({"cmd": "stats"}));
    let ns = node.status();
    let per = |k: &str, w: &str| (s1[w][k].as_u64().unwrap_or(0) - s0[w][k].as_u64().unwrap_or(0)) as f64 / secs;
    let total_bps = per("delta", "bytes") + per("fresh", "bytes");
    let r = json!({
        "params": {"zones": 50, "grants": 1000, "update_rate_per_s": 10, "ttl_ms": prm.ttl, "refresh_ms": prm.refresh, "seconds": secs},
        "query_latency_us_over_socket": classes.iter().zip(lat.iter_mut()).map(|((n, _), l)| (n.to_string(), pct(l))).collect::<serde_json::Map<_, _>>(),
        "wrong_answers": wrong,
        "snapshot_bytes": snap,
        "feed": {"delta_frames_per_s": per("delta", "frames"), "delta_bytes_per_s": per("delta", "bytes"),
                 "fresh_frames_per_s": per("fresh", "frames"), "fresh_bytes_per_s": per("fresh", "bytes"),
                 "total_bytes_per_s": total_bps,
                 "avg_delta_frame_bytes": per("delta", "bytes") / per("delta", "frames").max(1e-9),
                 "avg_fresh_frame_bytes": per("fresh", "bytes") / per("fresh", "frames").max(1e-9)},
        "node": {"epoch": ns["epoch"], "cp_epoch": s1["epoch"], "grants": ns["grants"], "refused": ns["refused"], "mode": ns["mode"]},
    });
    println!("[steady] {r}");
    write_json("steady.json", &r);
    r
}

// ---------------------------------------------------------------------------------------------
// In-process costs: signing, verification, apply, decide; sizes.

fn time<F: FnMut()>(n: usize, mut f: F) -> f64 {
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    t.elapsed().as_secs_f64() * 1e9 / n as f64
}

fn zone_spec(k: usize) -> wicket_core::ZoneSpec {
    serde_json::from_value(zone(k)).unwrap()
}

fn g(i: usize, zones: usize) -> Grant {
    let k = i % zones;
    let path = format!("/repos/acme/r{k}/issues/{i}/comments");
    Grant { id: format!("s-{i}"), zone: format!("z{k}"), op: digest(&format!("z{k}"), "POST", "api.github.com", &path), what: format!("POST api.github.com{path}"), not_after: i64::MAX / 2, uses: None }
}

fn scen_bench() -> Value {
    let root = SigningKey::from_bytes(&[1u8; 32]);
    let fk = SigningKey::from_bytes(&[2u8; 32]);
    let cert = sign(&root, TYP_KEY, &KeyCert::new(&fk.verifying_key(), 1, i64::MAX / 2, 30_000, 300_000));
    let mut out = serde_json::Map::new();
    let mk_state = |grants: usize| {
        let mut st = State::genesis();
        let mut changes: Vec<Change> = (0..50).map(|k| Change::PutZone { zone: zone_spec(k) }).collect();
        changes.extend((0..grants).map(|i| Change::AddGrant { grant: g(i, 50) }));
        let d = Delta { feed: "n1".into(), epoch: 1, prev: feed::GENESIS.into(), issued_at: 0, changes };
        let j = sign(&fk, TYP_DELTA, &d);
        st.apply(&d, feed::sha(&j));
        st
    };
    for grants in [1000usize, 10_000] {
        let st = mk_state(grants);
        let snap = st.snapshot("n1", 0);
        let mut jws = String::new();
        let sign_ns = time(5, || jws = sign(&fk, TYP_SNAP, &snap));
        let apply_ns = time(5, || {
            let mut r = Replica::new("n1", root.verifying_key());
            r.accept("key", &cert, 1).unwrap();
            r.accept("snap", &jws, 1).unwrap();
        });
        out.insert(format!("snapshot_{grants}_grants"), json!({"bytes": jws.len(), "sign_ms": sign_ns / 1e6, "verify_and_load_ms": apply_ns / 1e6}));
    }
    // Delta chain: sign and verify+apply cost per one-change delta.
    let mut st = mk_state(1000);
    let n = 2000;
    let mut chain = vec![];
    let sign_ns = time(n, || {
        let i = chain.len();
        let c = if i % 2 == 0 { Change::AddGrant { grant: g(100_000 + i, 50) } } else { Change::Revoke { id: format!("s-{i}"), until: i64::MAX / 2 } };
        let d = Delta { feed: "n1".into(), epoch: st.epoch + 1, prev: st.head.clone(), issued_at: now_ms(), changes: vec![c] };
        let j = sign(&fk, TYP_DELTA, &d);
        st.apply(&d, feed::sha(&j));
        chain.push(j);
    });
    let base = mk_state(1000).snapshot("n1", 0);
    let base_jws = sign(&fk, TYP_SNAP, &base);
    let mut r = Replica::new("n1", root.verifying_key());
    r.accept("key", &cert, 1).unwrap();
    r.accept("snap", &base_jws, 1).unwrap();
    let mut it = chain.iter();
    let verify_ns = time(n, || r.accept("delta", it.next().unwrap(), 1).unwrap());
    let sizes = |c: Vec<Change>| sign(&fk, TYP_DELTA, &Delta { feed: "n1".into(), epoch: 12345, prev: feed::GENESIS.into(), issued_at: now_ms(), changes: c }).len();
    out.insert("delta".into(), json!({
        "sign_us": sign_ns / 1e3, "verify_and_apply_us": verify_ns / 1e3,
        "bytes_1_add_grant": sizes(vec![Change::AddGrant { grant: g(1, 50) }]),
        "bytes_1_revoke": sizes(vec![Change::Revoke { id: "s-1".into(), until: 1 }]),
        "bytes_10_add_grants": sizes((0..10).map(|i| Change::AddGrant { grant: g(i, 50) }).collect()),
        "bytes_put_zone": sizes(vec![Change::PutZone { zone: zone_spec(1) }]),
    }));
    // Freshness.
    let e = r.state.as_ref().unwrap().epoch;
    let head = r.state.as_ref().unwrap().head.clone();
    let mut k = 10i64;
    let mut fj = String::new();
    let fsign = time(1000, || {
        k += 1;
        fj = sign(&fk, TYP_FRESH, &Fresh { feed: "n1".into(), epoch: e, head: head.clone(), issued_at: k, fresh_until: k + 30_000, narrow_until: k + 150_000 });
    });
    let fresh_jws: Vec<String> = (0..1000).map(|i| sign(&fk, TYP_FRESH, &Fresh { feed: "n1".into(), epoch: e, head: head.clone(), issued_at: 100_000 + i, fresh_until: 100_000 + i + 30_000, narrow_until: 100_000 + i + 150_000 })).collect();
    let mut it = fresh_jws.iter();
    let fverify = time(1000, || r.accept("fresh", it.next().unwrap(), 101_000).unwrap());
    out.insert("fresh".into(), json!({"bytes": fj.len(), "sign_us": fsign / 1e3, "verify_us": fverify / 1e3}));
    // Decisions in-process, fresh and narrow.
    let now_fresh = 101_500;
    let now_narrow = 101_000 + 1000 + 30_000 + 10;
    let mut node = Node::new(r);
    let q = |zone: &str, m: &str, h: &str, p: &str| Query { q: "op".into(), zone: zone.into(), run: "run-a".into(), method: m.into(), host: h.into(), path: p.into(), ..Default::default() };
    let classes = [
        ("reach_read", q("z3", "GET", "api.github.com", "/repos/acme/r3/pulls/12")),
        ("reach_write", q("z3", "PUT", "api.github.com", "/repos/acme/r3/contents/src/lib.rs")),
        ("granted", q("z0", "POST", "api.github.com", "/repos/acme/r0/issues/0/comments")),
        ("needs_grant_denied", q("z3", "DELETE", "api.github.com", "/repos/acme/r3")),
        ("forbidden", q("z3", "GET", "evil.example", "/x")),
    ];
    let mut dec = serde_json::Map::new();
    for (name, qq) in &classes {
        let fresh = node.decide(qq, now_fresh);
        let narrow = node.decide(qq, now_narrow);
        let f_ns = time(100_000, || {
            node.decide(qq, now_fresh);
        });
        let n_ns = time(100_000, || {
            node.decide(qq, now_narrow);
        });
        dec.insert(name.to_string(), json!({"fresh_ns": f_ns, "narrow_ns": n_ns, "fresh": [fresh.allow, fresh.why], "narrow": [narrow.allow, narrow.why]}));
    }
    out.insert("decide".into(), json!(dec));
    // wicket-core's evaluate compiles each path glob per call; how much of a decision is that?
    let build = || globset::GlobBuilder::new("/repos/acme/r3/**").literal_separator(true).build().unwrap().compile_matcher();
    let m = build();
    let compile_ns = time(20_000, || {
        std::hint::black_box(build());
    });
    let match_ns = time(200_000, || {
        std::hint::black_box(m.is_match("/repos/acme/r3/pulls/12"));
    });
    out.insert("glob".into(), json!({"compile_ns": compile_ns, "match_ns": match_ns}));
    let r = json!(out);
    println!("[bench] {r}");
    write_json("bench.json", &r);
    r
}

fn main() {
    std::fs::create_dir_all(logs()).unwrap();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let all = args.is_empty() || args.iter().any(|a| a == "all");
    let want = |s: &str| all || args.iter().any(|a| a == s);
    let mut summary = serde_json::Map::new();
    if want("bench") {
        summary.insert("bench".into(), scen_bench());
    }
    if want("attacks") {
        summary.insert("attacks".into(), scen_attacks());
    }
    if want("kill") {
        summary.insert("kill".into(), scen_kill("kill", P { ttl: 3000, refresh: 500, grace: 6000, retain: 1000 }, 50));
    }
    if want("revocation") {
        summary.insert("revocation".into(), scen_revocation());
    }
    if want("catchup") {
        summary.insert("catchup".into(), scen_catchup());
    }
    if want("steady") {
        summary.insert("steady".into(), scen_steady());
    }
    if want("kill-prod") {
        summary.insert("kill-prod".into(), scen_kill("kill-prod", P { ttl: 30_000, refresh: 5000, grace: 120_000, retain: 1000 }, 1000));
    }
    println!("done: {}", summary.keys().cloned().collect::<Vec<_>>().join(", "));
}
