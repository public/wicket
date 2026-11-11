//! The node: a verified replica of its feed, a local decision function with the fail-narrow rule,
//! a feed subscriber (push, or polling), and a line-JSON query socket.
//!
//! Fail-narrow rule (see RESULTS.md):
//! - **fresh** (a live freshness statement names an epoch the node holds): decide normally: zone
//!   reach, grants and leases (expiry by the node's clock, use counts in the node's ledger), and the
//!   node may issue leases, start spawns and sign agent approvals.
//! - **narrow** (no live statement, but the last one that vouched for the held state has a narrow
//!   window still open): only ops the cached zone policy allows by reach with risk ≤ R1. Every grant
//!   and lease is ignored, and no lease, spawn or approval is issued.
//! - **closed** (no state, or the narrow window has ended): refuse everything.

use crate::feed::{now_ms, Grant, Mode, Refusal, Replica};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wicket_core::{evaluate, Op, RiskClass, RunId, TenantId, Verdict};

/// The riskiest op that may still run on reach alone while narrow.
pub const NARROW_MAX_RISK: RiskClass = RiskClass::R1ReadScoped;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Query {
    pub q: String,
    #[serde(default)]
    pub zone: String,
    #[serde(default)]
    pub run: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub grant: String,
    #[serde(default)]
    pub child: String,
    #[serde(default)]
    pub ttl_ms: i64,
    #[serde(default)]
    pub uses: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub allow: bool,
    pub mode: Mode,
    pub epoch: u64,
    pub why: String,
}

pub struct Node {
    pub rep: Replica,
    /// Use counts of grants (the node's ledger).
    used: HashMap<String, u32>,
    /// Grants from agent approvals signed on this node, by op digest.
    local: HashMap<String, Grant>,
    next_local: u64,
}

impl Node {
    pub fn new(rep: Replica) -> Node {
        Node { rep, used: HashMap::new(), local: HashMap::new(), next_local: 0 }
    }

    pub fn decide(&mut self, q: &Query, now: i64) -> Decision {
        let mode = self.rep.mode(now);
        let epoch = self.rep.state.as_ref().map(|s| s.epoch).unwrap_or(0);
        let d = |allow: bool, why: String| Decision { allow, mode, epoch, why };
        if mode == Mode::Closed {
            return d(false, "closed: no state vouched for by a live freshness statement".into());
        }
        let st = self.rep.state.as_ref().unwrap();
        let Some(zone) = st.zones.get(&q.zone) else { return d(false, format!("unknown zone {}", q.zone)) };
        if !q.run.is_empty() && st.revoked.contains_key(&q.run) {
            return d(false, format!("run {} is revoked", q.run));
        }
        let stale = || d(false, format!("{mode:?}: no new leases, spawns or approvals until fresh").to_lowercase());
        match q.q.as_str() {
            "op" => {
                let op = Op::egress(&TenantId::single(), &RunId(q.run.clone()), &q.zone, &q.method, &q.host, &q.path);
                match evaluate(zone, &op) {
                    Verdict::Forbidden(r) => d(false, r),
                    Verdict::AllowByReach(i) if mode == Mode::Fresh || op.risk <= NARROW_MAX_RISK => d(true, format!("reach rule {i}")),
                    Verdict::AllowByReach(_) => d(false, format!("narrow: {:?} needs fresh policy", op.risk)),
                    Verdict::NeedsGrant(r) if mode != Mode::Fresh => d(false, format!("narrow: grants not honoured while stale ({r})")),
                    Verdict::NeedsGrant(r) => {
                        let digest = op.digest();
                        let replicated = st.by_op.get(&digest).into_iter().flatten().filter_map(|id| st.grants.get(id));
                        for g in replicated.chain(self.local.get(&digest)) {
                            let used = self.used.get(&g.id).copied().unwrap_or(0);
                            if g.not_after <= now || g.uses.is_some_and(|u| used >= u) {
                                continue;
                            }
                            self.used.insert(g.id.clone(), used + 1);
                            return d(true, format!("grant {}", g.id));
                        }
                        d(false, format!("needs a grant: {r}"))
                    }
                }
            }
            "lease" if mode == Mode::Fresh => match st.grants.get(&q.grant) {
                Some(g) if g.zone == q.zone && g.not_after > now => d(true, format!("lease on {} until {}", g.id, g.not_after.min(now + q.ttl_ms.max(1)))),
                _ => d(false, format!("no live grant {}", q.grant)),
            },
            "spawn" if mode == Mode::Fresh => match st.zones.contains_key(&q.child) {
                true => d(true, format!("spawn {} from {}", q.child, q.zone)),
                false => d(false, format!("unknown child zone {}", q.child)),
            },
            "approve" if mode == Mode::Fresh => {
                let op = Op::egress(&TenantId::single(), &RunId(q.run.clone()), &q.zone, &q.method, &q.host, &q.path);
                self.next_local += 1;
                let id = format!("l-{}", self.next_local);
                let ttl = if q.ttl_ms > 0 { q.ttl_ms } else { 60_000 };
                let g = Grant { id: id.clone(), zone: q.zone.clone(), op: op.digest(), what: format!("{} {}{}", op.method, op.host, op.path), not_after: now + ttl, uses: Some(q.uses.unwrap_or(1)) };
                self.local.insert(g.op.clone(), g);
                d(true, format!("approved as {id}"))
            }
            "lease" | "spawn" | "approve" => stale(),
            other => d(false, format!("unknown query {other}")),
        }
    }

    pub fn status(&self, now: i64) -> Value {
        let st = self.rep.state.as_ref();
        json!({
            "now": now, "mode": self.rep.mode(now),
            "epoch": st.map(|s| s.epoch), "head": st.map(|s| s.head.clone()),
            "zones": st.map(|s| s.zones.len()), "grants": st.map(|s| s.grants.len()),
            "fresh_epoch": self.rep.fresh.as_ref().map(|f| f.epoch),
            "fresh_until": self.rep.fresh.as_ref().map(|f| f.fresh_until),
            "vouched": self.rep.vouched,
            "accepted": self.rep.accepted, "refused": self.rep.refused, "last_refusal": self.rep.last_refusal,
        })
    }
}

pub struct NodeCfg {
    pub cp: SocketAddr,
    pub query_port: u16,
    pub push: bool,
    pub poll_ms: u64,
    pub retry_ms: u64,
    /// No frame for this long on a push stream = the control plane is gone; reconnect.
    pub idle_ms: u64,
}

pub fn log(ev: Value) {
    let mut ev = ev;
    ev["ts"] = json!(now_ms());
    eprintln!("{ev}");
}

pub fn run(node: Node, cfg: NodeCfg) -> std::io::Result<()> {
    let node = Arc::new(Mutex::new(node));
    let listener = TcpListener::bind(("127.0.0.1", cfg.query_port))?;
    let n = node.clone();
    std::thread::spawn(move || loop {
        feed_once(&n, &cfg);
        std::thread::sleep(Duration::from_millis(if cfg.push { cfg.retry_ms } else { cfg.poll_ms }));
    });
    let n = node.clone();
    std::thread::spawn(move || {
        let mut last = Mode::Closed;
        loop {
            let m = n.lock().unwrap().rep.mode(now_ms());
            if m != last {
                log(json!({"ev": "mode", "from": last, "to": m}));
                last = m;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    log(json!({"ev": "listening", "port": listener.local_addr()?.port()}));
    for s in listener.incoming().flatten() {
        let n = node.clone();
        std::thread::spawn(move || serve_queries(&n, s));
    }
    Ok(())
}

fn serve_queries(node: &Mutex<Node>, s: TcpStream) -> std::io::Result<()> {
    s.set_nodelay(true)?;
    let mut w = s.try_clone()?;
    for line in BufReader::new(s).lines() {
        let line = line?;
        let now = now_ms();
        let out = match serde_json::from_str::<Query>(&line) {
            Ok(q) if q.q == "status" => node.lock().unwrap().status(now),
            Ok(q) => serde_json::to_value(node.lock().unwrap().decide(&q, now)).unwrap(),
            Err(e) => json!({"error": e.to_string()}),
        };
        w.write_all(format!("{out}\n").as_bytes())?; // one write: no per-fragment packets
    }
    Ok(())
}

/// One subscription (push) or one poll. Returns when the stream ends or fails.
fn feed_once(node: &Mutex<Node>, cfg: &NodeCfg) {
    let r = (|| -> std::io::Result<()> {
        let s = TcpStream::connect_timeout(&cfg.cp, Duration::from_millis(500))?;
        s.set_nodelay(true)?;
        s.set_read_timeout(Some(Duration::from_millis(cfg.idle_ms)))?;
        let hello = {
            let n = node.lock().unwrap();
            let st = n.rep.state.as_ref();
            json!({"t": "hello", "node": n.rep.node, "sub": cfg.push, "epoch": st.map(|s| s.epoch), "head": st.map(|s| s.head.clone())})
        };
        (&s).write_all(format!("{hello}\n").as_bytes())?;
        let mut r = BufReader::new(s);
        let mut line = String::new();
        loop {
            line.clear();
            if r.read_line(&mut line)? == 0 {
                return Ok(());
            }
            let f: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => {
                    log(json!({"ev": "refused", "t": "?", "kind": "malformed"}));
                    continue;
                }
            };
            let t = f["t"].as_str().unwrap_or("");
            if t == "end" {
                return Ok(());
            }
            let res = {
                let mut n = node.lock().unwrap();
                let res = n.rep.accept(t, f["jws"].as_str().unwrap_or(""), now_ms());
                (res, n.rep.state.as_ref().map(|s| s.epoch))
            };
            match res {
                (Ok(()), epoch) => log(json!({"ev": "accepted", "t": t, "epoch": epoch, "bytes": line.len()})),
                (Err(e), epoch) => {
                    log(json!({"ev": "refused", "t": t, "kind": e.kind(), "detail": format!("{e:?}"), "epoch": epoch}));
                    if let Refusal::Gap { .. } = e {
                        return Ok(()); // resubscribe from the epoch held
                    }
                }
            }
        }
    })();
    if let Err(e) = r {
        log(json!({"ev": "feed_error", "error": e.to_string()}));
    }
}
