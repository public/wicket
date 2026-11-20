//! Messages (#324, second slice): principals, held messages, wake and receipts (#250, #252, #331),
//! across agent restarts, a hibernated agent's wake, node and control-host crashes and cut-offs.
//!
//! **What is real and what stands in.**
//! - Real, on the control host: the run's MCP gateway ([`wicket_gateway::Gateway`], through
//!   `Gateway::call_tool`, which a box's node asks with a typed `Msg::Call`): `send_message`
//!   (`RunCtx::send`: addressing by principal, `accept_from`, refusals with their receipts,
//!   holding, waking a hibernated agent),
//!   `await_message` (the signed envelope checked, `Ledger::take_message`) and `receipts`; the ledger
//!   ([`wicket_store::Ledger`] on the control host's disk: identities, held messages moved to a
//!   principal's new run by `put_identity`, an agent's wake by `claim_wake`); and identities signed
//!   by [`wicket_identity::Issuer`].
//! - Stand-ins:
//!   - the node follows `wicket-node/src/nodegw.rs`: connected, a box's `send_message` and
//!     `await_message` are asked of its run's gateway on the control host (`call_control`); cut off,
//!     a message to another box on the node is decided and delivered there (`send_local`, with its
//!     receipt, refused if the recipient's `accept_from` doesn't list the sender), kept in the
//!     node's inbox on its disk (`EdgeQueue`), and `await_message` takes from that inbox first. The
//!     channel is one per node here, not one per run as `noderun.rs` has it;
//!   - the control host's supervisors follow `run.rs` and `hibernate.rs`: a run that restarts ends,
//!     and its principal's next run gets a new run id and identity (`put_identity`); the long-lived
//!     agent hibernates (`commit_agent_push`) and is woken by a message (`RunCtx::waker`, then
//!     `claim_wake` and its new run's identity);
//!   - a box stub stands in for an agent: it sends numbered messages to the other principals and
//!     awaits its own, and keeps awaiting after the scenario's sending ends.
//!
//! **Invariants.** Every message wicket accepted (its receipt `delivered` or `held`) reaches its
//! recipient principal exactly once, across restarts, crashes and cut-offs, or is still held for it
//! at the end (its receipt says so); and a refused message's receipt says `refused`, with why, both
//! in the answer to `send_message` and on the record (`Ledger::receipt`), and it never arrives.

use crate::rng::Rng;
use crate::trace::{Report, Trace};
use crate::wire;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use wicket_core::{RunId, TenantId, ZoneSpec};
use wicket_gateway::Gateway;
use wicket_store::{IdentityRow, Ledger};

pub const EPOCH_MS: i64 = crate::EPOCH_MS;
/// Boxes send until here, and only await after it, until [`END_MS`].
pub const SEND_MS: i64 = 60_000;
pub const END_MS: i64 = 100_000;
const TENANT: &str = "t_sim";
const DOMAIN: &str = "sim.local";
const PORT_CTL: u16 = 7100;
const PORT_NODE: u16 = 8100;
/// How long a relayed call waits for the control host's answer.
const RELAY_MS: u64 = 10_000;

/// The principals: agents `a` and `b` (which restarts), `c` (long-lived: it hibernates and is woken
/// by a message), and `d`, which accepts messages from nobody (each to it is refused).
pub const PRINCIPALS: [&str; 4] = ["a", "b", "c", "d"];
/// Those with a box on the node.
const BOXED: [&str; 3] = ["a", "b", "c"];

fn zone_of(p: &str) -> String {
    format!("z{p}")
}

fn accept_from(p: &str) -> Vec<String> {
    match p {
        "d" => vec![],
        _ => BOXED.iter().filter(|q| **q != p).map(|q| zone_of(q)).collect(),
    }
}

fn principal_id(p: &str) -> String {
    format!("spiffe://{DOMAIN}/t/{TENANT}/z/{}/a/{p}", zone_of(p))
}

fn now_ms() -> i64 {
    crate::true_now()
}

fn ms(n: i64) -> Duration {
    Duration::from_millis(n.max(0) as u64)
}

// ---- the plan ----

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// `b`'s run ends; after `down` ms its principal runs again as a new run.
    Restart { down: i64 },
    /// `c` hibernates (a message wakes it).
    Hibernate,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub at: i64,
    pub who: &'static str,
    pub kind: EventKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultKind {
    Partition,
    NodeCrash,
    ControlCrash,
}

#[derive(Clone, Debug)]
pub struct Fault {
    pub at: i64,
    pub dur: i64,
    pub kind: FaultKind,
}

#[derive(Clone, Debug)]
pub struct Plan {
    pub seed: u64,
    pub max_latency_ms: u64,
    pub events: Vec<Event>,
    pub faults: Vec<Fault>,
}

impl Plan {
    pub fn new(seed: u64) -> Plan {
        let mut r = Rng::new(seed ^ 0x6d65_7373_6167_6573);
        let max_latency_ms = r.range(1, 40);
        let mut events = vec![];
        let mut t = r.range_i(2_000, 8_000);
        while t < SEND_MS - 5_000 {
            if r.chance(0.5) {
                events.push(Event { at: t, who: "b", kind: EventKind::Restart { down: r.range_i(200, 6_000) } });
            } else {
                events.push(Event { at: t, who: "c", kind: EventKind::Hibernate });
            }
            t += r.range_i(3_000, 12_000);
        }
        let mut faults = vec![];
        let mut t = r.range_i(1_000, 5_000);
        while t < END_MS - 25_000 {
            let (kind, dur) = match r.range(0, 5) {
                0..=2 => (FaultKind::Partition, r.range_i(300, 10_000)),
                3..=4 => (FaultKind::NodeCrash, r.range_i(50, 3_000)),
                _ => (FaultKind::ControlCrash, r.range_i(50, 3_000)),
            };
            faults.push(Fault { at: t, dur, kind });
            t += dur + r.range_i(500, 8_000);
        }
        Plan { seed, max_latency_ms, events, faults }
    }
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "messages seed {}: link latency 1..={} ms", self.seed, self.max_latency_ms)?;
        for e in &self.events {
            writeln!(f, "  at {} ms: {} {:?}", e.at, e.who, e.kind)?;
        }
        for x in &self.faults {
            writeln!(f, "  fault at {} ms for {} ms: {:?}", x.at, x.dur, x.kind)?;
        }
        Ok(())
    }
}

// ---- the oracle ----

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub sent: u64,
    pub sent_local: u64,
    pub held: u64,
    pub woke: u64,
    pub refused: u64,
    pub not_sent: u64,
    pub received: u64,
    pub restarts: u64,
    pub hibernations: u64,
    pub wakes: u64,
    pub control_starts: u64,
    pub node_starts: u64,
}

/// What a box was told of a message it sent.
#[derive(Clone, Debug)]
struct Sent {
    from: String,
    to: String,
    /// Its id (`m-…` on the record, `m-node-…` delivered by the node).
    id: String,
}

pub struct Oracle {
    pub trace: Trace,
    pub stats: Stats,
    /// By the message's number (`<sender>#<n>`): what its sender was told.
    accepted: BTreeMap<String, Sent>,
    refused: BTreeMap<String, Sent>,
    /// By number: the principals that received it, in order.
    received: BTreeMap<String, Vec<String>>,
    /// Known losses, not counted as violations unless [`Options::strict_relay`]: see [`run`].
    pub known: Vec<String>,
    strict_relay: bool,
}

impl Oracle {
    fn now(&self) -> i64 {
        now_ms()
    }

    fn sent(&mut self, from: &str, to: &str, n: &str, text: &str, is_error: bool) {
        let t = self.now();
        let receipt = text.split_once("receipt: ").and_then(|(_, r)| serde_json::from_str::<Value>(r.trim()).ok());
        let state = receipt.as_ref().and_then(|r| r["state"].as_str()).unwrap_or("");
        let id = receipt.as_ref().and_then(|r| r["message_id"].as_str()).unwrap_or("").to_string();
        let s = Sent { from: from.into(), to: to.into(), id: id.clone() };
        if text.starts_with("refused: ") {
            self.stats.refused += 1;
            self.trace.note(t, format!("{from} -> {to} {n}: refused"));
            let why = receipt.as_ref().and_then(|r| r["why"].as_str()).unwrap_or("");
            if state != "refused" || why.is_empty() || !is_error {
                self.trace.violate(t, format!("{from} -> {to} {n} was refused, but its receipt says {state:?} (why {why:?})"));
            }
            if to != "d" {
                self.trace.violate(t, format!("{from} -> {to} {n} was refused, though {to} accepts {from}: {text}"));
            }
            self.refused.insert(n.into(), s);
        } else if text.starts_with("sent ") && !is_error {
            self.stats.sent += 1;
            if id.starts_with("m-node-") {
                self.stats.sent_local += 1;
            }
            match state {
                "held" => self.stats.held += 1,
                "delivered" => {}
                other => self.trace.violate(t, format!("{from} -> {to} {n} was sent, but its receipt says {other:?}")),
            }
            if text.contains("being woken") {
                self.stats.woke += 1;
            }
            if to == "d" {
                self.trace.violate(t, format!("{from} -> {to} {n} was accepted, though d accepts nobody"));
            }
            self.trace.note(t, format!("{from} -> {to} {n}: sent, {state}"));
            self.accepted.insert(n.into(), s);
        } else {
            self.stats.not_sent += 1;
            self.trace.note(t, format!("{from} -> {to} {n}: not sent"));
        }
    }

    fn received(&mut self, by: &str, n: &str, from: &str) {
        let t = self.now();
        self.stats.received += 1;
        self.trace.note(t, format!("{by} receives {n} from {from}"));
        let got = self.received.entry(n.into()).or_default();
        got.push(by.into());
        if got.len() == 2 {
            self.trace.violate(t, format!("{by} received {n} twice"));
        }
        match (self.accepted.get(n), self.refused.get(n)) {
            (_, Some(_)) => self.trace.violate(t, format!("{by} received {n}, which was refused")),
            (Some(s), _) if s.to != by => self.trace.violate(t, format!("{by} received {n}, sent to {}", s.to)),
            // The receipt can come back after the message (a slow answer).
            _ => {}
        }
    }

    /// At the end, with the control host's ledger and the node's inbox: every accepted message
    /// arrived once, or is still held for its recipient.
    fn check_end(&mut self, t: i64, ledger: &Ledger, node_inbox: &BTreeSet<String>) {
        for (n, s) in self.accepted.clone() {
            if self.received.contains_key(&n) {
                continue;
            }
            let state = if s.id.starts_with("m-node-") {
                if node_inbox.contains(&s.id) {
                    "held on the node".to_string()
                } else {
                    "gone from the node's inbox".to_string()
                }
            } else {
                match ledger.receipt(&s.id) {
                    Ok(Some(r)) => r.state,
                    _ => "not on the record".to_string(),
                }
            };
            // (Without its id: `ulid` makes ids from the OS's clock and randomness, which the
            // trace must not depend on.)
            let lost = format!("{n} ({} -> {}) was accepted and never arrived: its receipt says {state}", s.from, s.to);
            match state.as_str() {
                "held" | "delivered" | "held on the node" => self.trace.note(t, format!("end: {n} ({} -> {}) is {state}", s.from, s.to)),
                // Taken from the inbox and recorded read on the control host, then lost with the
                // relayed answer (a cut-off or crash between them): the known loss (see `run`).
                "read" if !self.strict_relay => {
                    self.trace.note(t, format!("KNOWN {lost}"));
                    self.known.push(lost);
                }
                _ => self.trace.violate(t, lost),
            }
        }
        for (n, s) in self.refused.clone() {
            if s.id.starts_with("m-node-") {
                continue;
            }
            match ledger.receipt(&s.id) {
                Ok(Some(r)) if r.state == "refused" && r.why.as_deref().is_some_and(|w| !w.is_empty()) => {}
                r => self.trace.violate(t, format!("{n} was refused, but its receipt on the record is {r:?}")),
            }
        }
    }
}

// ---- the wire ----

/// Node ↔ control host.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Chan {
    Tool { id: u64, run: String, name: String, args: Value },
    Answer { id: u64, text: String, is_error: bool },
}

/// Box ↔ node: a gateway tool call and its answer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum BoxMsg {
    Hello { run: String },
    Call { name: String, args: Value },
    Answer { text: String, is_error: bool },
}

// ---- shared state ----

/// A message delivered on the node while cut off (`nodegw::LocalMessage`).
#[derive(Clone, Debug)]
struct LocalMessage {
    id: String,
    to_run: String,
    from: String,
    body: Value,
    priority: String,
}

#[derive(Default)]
pub struct NodeDisk {
    /// `edge.json`'s inbox.
    inbox: Vec<LocalMessage>,
    next: u64,
}

#[derive(Default)]
pub struct CtlDisk {
    started: bool,
    /// The plan's events done.
    done: usize,
    /// Each run's principal.
    identities: BTreeMap<String, &'static str>,
    /// Each principal's next run number.
    next_run: BTreeMap<String, u32>,
    /// `c` was woken by a message and its new run is due.
    wake_due: bool,
    /// `c`'s generation (its activation's fence).
    c_generation: i64,
}

pub struct Env {
    pub plan: Plan,
    pub dir: PathBuf,
    pub oracle: Rc<RefCell<Oracle>>,
    pub ctl: Rc<RefCell<CtlDisk>>,
    pub node: Rc<RefCell<NodeDisk>>,
    /// Each principal's live run (what the box finds on its node), None while it is down.
    pub live: Rc<RefCell<BTreeMap<String, Option<String>>>>,
    issuer: wicket_identity::Issuer,
    /// Set by the waker (inside the gateway, which must be `Send`): `c` is to be woken.
    woken: Arc<Mutex<bool>>,
    agent_c: String,
    /// The control host's processes' memory: each live run's gateway, with its identity and key
    /// (gone with a crash; a restarted supervisor gets a fresh identity, as the runner's refresh
    /// gives one).
    gateways: RefCell<BTreeMap<String, Arc<Gateway>>>,
    ledger_conn: RefCell<Option<Arc<Mutex<Ledger>>>>,
}

impl Env {
    fn note(&self, line: impl Into<String>) {
        self.oracle.borrow_mut().trace.note(now_ms(), line);
    }
    /// The control host's ledger: one connection per control-host process (opened again after a
    /// crash), shared by its gateways as each run's own would be.
    fn ledger(&self) -> Arc<Mutex<Ledger>> {
        self.ledger_conn
            .borrow_mut()
            .get_or_insert_with(|| Arc::new(Mutex::new(Ledger::open(&self.ledger_path()).expect("the control host's ledger"))))
            .clone()
    }
    fn ledger_path(&self) -> PathBuf {
        self.dir.join("control").join("ledger.db")
    }
}

// ---- the control host ----

/// Starts a new run for principal `p` (`run.rs`: the run, its identity, which takes the messages
/// held for the principal). For `c` after a wake, `claim_wake` came first.
fn start_run(env: &Env, l: &Ledger, p: &'static str) -> String {
    let n = {
        let mut c = env.ctl.borrow_mut();
        let n = c.next_run.entry(p.to_string()).or_insert(0);
        *n += 1;
        *n
    };
    let run = format!("run_{p}{n}");
    start_run_as(env, l, p, &run);
    run
}

fn start_run_as(env: &Env, l: &Ledger, p: &'static str, run: &str) {
    let (jws, claims, key) = identity(env, run, p);
    l.run_started(&TenantId(TENANT.into()), &RunId(run.into()), &zone_of(p), p).expect("the run recorded");
    l.put_identity(&IdentityRow {
        run: run.into(),
        tenant: TENANT.into(),
        spiffe_id: claims.sub.clone(),
        zone: zone_of(p),
        agent: p.into(),
        parent_run: None,
        accept_from: accept_from(p),
        jws: jws.clone(),
        issued_at: claims.iat,
    })
    .expect("its identity recorded");
    env.ctl.borrow_mut().identities.insert(run.into(), p);
    env.live.borrow_mut().insert(p.into(), Some(run.into()));
    env.note(format!("{p} runs as {run}"));
    let g = gateway(env, run, p, jws, claims, key);
    env.gateways.borrow_mut().insert(run.into(), g);
}

/// A running run's supervisor after a control-host restart: a fresh identity for the same run.
fn reattach(env: &Env, l: &Ledger, run: &str, p: &'static str) {
    let (jws, claims, key) = identity(env, run, p);
    l.put_identity(&IdentityRow {
        run: run.into(),
        tenant: TENANT.into(),
        spiffe_id: claims.sub.clone(),
        zone: zone_of(p),
        agent: p.into(),
        parent_run: None,
        accept_from: accept_from(p),
        jws: jws.clone(),
        issued_at: claims.iat,
    })
    .expect("its identity recorded");
    let g = gateway(env, run, p, jws, claims, key);
    env.gateways.borrow_mut().insert(run.into(), g);
}

fn identity(env: &Env, run: &str, p: &str) -> (String, wicket_identity::AgentClaims, wicket_identity::AgentKey) {
    let key = wicket_identity::AgentKey::generate();
    let spec = wicket_identity::IdentitySpec {
        tenant: TENANT.into(),
        zone: zone_of(p),
        agent: p.into(),
        run: run.into(),
        parent_run: None,
        manifest_sha256: "m".into(),
        image: "img".into(),
        node: "node".into(),
        principal: json!({ "type": "human", "id": "sim", "via": "cli", "assurance": "unix-user" }),
        act: None,
        kind: None,
    };
    let now = wicket_store::now();
    let jws = env.issuer.issue(&spec, now, 3_600, &key.public());
    let claims = wicket_identity::verify_identity(&jws, &env.issuer.verifying_key(), now).expect("its identity verifies");
    (jws, claims, key)
}

/// The run's gateway, as its supervisor makes it (`RunCtx` with its identity).
fn gateway(
    env: &Env,
    run: &str,
    p: &str,
    jws: String,
    claims: wicket_identity::AgentClaims,
    key: wicket_identity::AgentKey,
) -> Arc<Gateway> {
    let zone: ZoneSpec = serde_json::from_value(json!({ "name": zone_of(p), "accept_from": accept_from(p) })).expect("a zone");
    let mut ctx = crate::run_ctx(run, &zone);
    ctx.tenant = TenantId(TENANT.into());
    ctx.ledger = env.ledger();
    ctx.identity =
        Some(Arc::new(wicket_proxy::IdentityCell::new(wicket_proxy::RunIdentity { jws, claims, key, issuer: env.issuer.verifying_key() })));
    if p == "c" {
        let g = env.ctl.borrow().c_generation.max(1);
        ctx.fence = Some(wicket_proxy::Fence { agent: env.agent_c.clone(), generation: g });
    }
    let woken = env.woken.clone();
    ctx.waker = Some(Arc::new(move |_agent: &str, _why: &str| *woken.lock().expect("woken") = true));
    Gateway::new(ctx)
}

async fn control(env: Rc<Env>) -> turmoil::Result {
    env.oracle.borrow_mut().stats.control_starts += 1;
    env.note("control host starts");
    env.gateways.borrow_mut().clear();
    *env.ledger_conn.borrow_mut() = None;
    if env.ctl.borrow().started {
        // The reconciler's adoption: every running run's supervisor again.
        let l = env.ledger();
        let l = l.lock().expect("ledger");
        let live: Vec<(String, &'static str)> = env.ctl.borrow().identities.iter().map(|(r, p)| (r.clone(), *p)).collect();
        for (run, p) in live {
            if l.run_status(&run).ok().flatten().as_deref() == Some("running") {
                reattach(&env, &l, &run, p);
            }
        }
    } else {
        let l = env.ledger();
        let mut l = l.lock().expect("ledger");
        for p in PRINCIPALS {
            start_run(&env, &l, p);
        }
        // `d` has run once (it has an identity) and isn't running.
        let d = env.live.borrow()["d"].clone().expect("d's run");
        l.run_ended(&RunId(d), "succeeded", "").expect("d ended");
        env.live.borrow_mut().insert("d".into(), None);
        // `c` is a long-lived agent: its first run is its first activation.
        let c = env.live.borrow()["c"].clone().expect("c's run");
        l.create_agent(&wicket_store::NewAgent {
            id: &env.agent_c,
            tenant: TENANT,
            zone: &zone_of("c"),
            name: "c",
            run: &c,
            session_id: "s",
            manifest: "m",
            image: "img",
            workspace: None,
            claim_until: wicket_store::now() + 3_600,
        })
        .expect("c's agent");
        env.ctl.borrow_mut().started = true;
    }
    tokio::task::spawn_local(events(env.clone()));
    let listener = turmoil::net::TcpListener::bind(("0.0.0.0", PORT_CTL)).await?;
    loop {
        let (s, _) = listener.accept().await?;
        tokio::task::spawn_local(serve_node(env.clone(), s));
    }
}

/// The plan's restarts and hibernations, and `c`'s wakes.
async fn events(env: Rc<Env>) {
    loop {
        tokio::time::sleep(ms(50)).await;
        let t = now_ms() - EPOCH_MS;
        let woken = std::mem::take(&mut *env.woken.lock().expect("woken"));
        if woken {
            env.ctl.borrow_mut().wake_due = true;
        }
        if env.ctl.borrow().wake_due {
            env.ctl.borrow_mut().wake_due = false;
            wake_c(&env);
        }
        let l = env.ledger();
        let l = l.lock().expect("ledger");
        loop {
            let done = env.ctl.borrow().done;
            let Some(e) = env.plan.events.get(done).cloned() else { break };
            if e.at > t {
                break;
            }
            let run = env.live.borrow().get(e.who).cloned().flatten();
            match e.kind {
                EventKind::Restart { down } => {
                    if let Some(run) = run {
                        l.run_ended(&RunId(run.clone()), "failed", "restarted").expect("ended");
                        env.live.borrow_mut().insert(e.who.into(), None);
                        env.oracle.borrow_mut().stats.restarts += 1;
                        env.note(format!("{} ({run}) restarts", e.who));
                        env.ctl.borrow_mut().done += 1;
                        let env2 = env.clone();
                        let who = e.who;
                        tokio::task::spawn_local(async move {
                            tokio::time::sleep(ms(down)).await;
                            let l = env2.ledger();
                            let l = l.lock().expect("ledger");
                            start_run(&env2, &l, who);
                        });
                        continue;
                    }
                }
                EventKind::Hibernate => {
                    if let Some(run) = run {
                        // `hibernate.rs`: its state pushed, the head moved, the activation ended.
                        let a = l.agent(&env.agent_c).expect("agent").expect("c's agent");
                        let seq = a.head_seq + 1;
                        if l.commit_agent_push(&env.agent_c, a.generation, a.head_seq, seq, &format!("h{seq}"), 1).expect("pushed") {
                            l.run_ended(&RunId(run.clone()), "hibernated", "").expect("ended");
                            env.live.borrow_mut().insert("c".into(), None);
                            env.oracle.borrow_mut().stats.hibernations += 1;
                            env.note(format!("c ({run}) hibernates"));
                        }
                    }
                }
            }
            env.ctl.borrow_mut().done += 1;
        }
    }
}

/// `c` is woken (`claim_wake`, then its new run, as `wicket run --wake` starts it).
fn wake_c(env: &Rc<Env>) {
    let l = env.ledger();
    let mut l = l.lock().expect("ledger");
    let n = {
        let mut c = env.ctl.borrow_mut();
        let n = c.next_run.entry("c".into()).or_insert(0);
        *n += 1;
        *n
    };
    let run = format!("run_c{n}");
    match l.claim_wake(&env.agent_c, &run, wicket_store::now() + 3_600) {
        Ok(Some(g)) => {
            env.ctl.borrow_mut().c_generation = g;
            env.oracle.borrow_mut().stats.wakes += 1;
            env.note(format!("c is woken as {run} (generation {g})"));
            start_run_as(env, &l, "c", &run);
            let _ = l.set_agent_state(&env.agent_c, g, "active", None);
        }
        other => env.note(format!("c's wake claim: {other:?}")),
    }
}

/// The node's channel: its relayed tool calls, each answered by its run's gateway.
async fn serve_node(env: Rc<Env>, s: turmoil::net::TcpStream) {
    let (mut rd, mut wr) = s.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Chan>();
    let _writer = crate::control::AbortOnDrop(tokio::task::spawn_local(async move {
        while let Some(m) = rx.recv().await {
            if wire::write_json(&mut wr, &m).await.is_err() {
                break;
            }
        }
    }));
    let mut calls = vec![];
    while let Ok(Some((wire::KIND_MSG, b))) = wire::read_frame(&mut rd).await {
        let Ok(Chan::Tool { id, run, name, args }) = wire::parse::<Chan>(&b) else { continue };
        let (env, tx) = (env.clone(), tx.clone());
        calls.push(crate::control::AbortOnDrop(tokio::task::spawn_local(async move {
            let live = env.ledger().lock().expect("ledger").run_status(&run).ok().flatten().as_deref() == Some("running");
            let g = env.gateways.borrow().get(&run).cloned();
            let (text, is_error) = match g.filter(|_| live) {
                Some(g) => g.call_tool(&name, args).await,
                None => (format!("run {run} has ended"), true),
            };
            let _ = tx.send(Chan::Answer { id, text, is_error });
        })));
    }
}

// ---- the node ----

struct Node {
    env: Rc<Env>,
    /// The channel to the control host, while it is up: calls out, and their answers by id.
    link: RefCell<Option<mpsc::UnboundedSender<Chan>>>,
    /// A `BTreeMap`: calls in flight fail in one order when the channel drops (a `HashMap`'s
    /// order is random, and so would be the order their boxes are answered in).
    pending: RefCell<BTreeMap<u64, oneshot::Sender<(String, bool)>>>,
    next_call: RefCell<u64>,
}

async fn node(env: Rc<Env>) -> turmoil::Result {
    env.oracle.borrow_mut().stats.node_starts += 1;
    let n =
        Rc::new(Node { env: env.clone(), link: RefCell::new(None), pending: RefCell::new(BTreeMap::new()), next_call: RefCell::new(0) });
    tokio::task::spawn_local(control_link(n.clone()));
    let listener = turmoil::net::TcpListener::bind(("0.0.0.0", PORT_NODE)).await?;
    loop {
        let (s, _) = listener.accept().await?;
        tokio::task::spawn_local(serve_box(n.clone(), s));
    }
}

async fn control_link(n: Rc<Node>) {
    loop {
        if let Ok(s) = turmoil::net::TcpStream::connect(("control", PORT_CTL)).await {
            let (mut rd, mut wr) = s.into_split();
            let (tx, mut rx) = mpsc::unbounded_channel::<Chan>();
            *n.link.borrow_mut() = Some(tx);
            n.env.note("node connected");
            let writer = crate::control::AbortOnDrop(tokio::task::spawn_local(async move {
                while let Some(m) = rx.recv().await {
                    if wire::write_json(&mut wr, &m).await.is_err() {
                        break;
                    }
                }
            }));
            loop {
                // A silent channel is dropped (ssh's keepalive), as a broken one is.
                match tokio::time::timeout(ms(crate::SILENCE_MS as i64 * 2), wire::read_frame(&mut rd)).await {
                    Ok(Ok(Some((wire::KIND_MSG, b)))) => {
                        if let Ok(Chan::Answer { id, text, is_error }) = wire::parse::<Chan>(&b) {
                            if let Some(w) = n.pending.borrow_mut().remove(&id) {
                                let _ = w.send((text, is_error));
                            }
                        }
                    }
                    Ok(Ok(Some(_))) => {}
                    Err(_) if !n.pending.borrow().is_empty() => break,
                    Err(_) => {}
                    _ => break,
                }
            }
            drop(writer);
            *n.link.borrow_mut() = None;
            // Calls in flight fail: their boxes are told the control plane is unreachable.
            n.pending.borrow_mut().clear();
            n.env.note("node's channel drops");
        }
        tokio::time::sleep(ms(200)).await;
    }
}

/// `relay_tool`: the call made on the run's gateway on the control host.
async fn relay(n: &Rc<Node>, run: &str, name: &str, args: Value) -> Result<(String, bool), String> {
    let link = n.link.borrow().clone().ok_or("the control plane is unreachable")?;
    let id = {
        let mut c = n.next_call.borrow_mut();
        *c += 1;
        *c
    };
    let (tx, rx) = oneshot::channel();
    n.pending.borrow_mut().insert(id, tx);
    link.send(Chan::Tool { id, run: run.into(), name: name.into(), args }).map_err(|_| "the control plane is unreachable")?;
    match tokio::time::timeout(Duration::from_millis(RELAY_MS), rx).await {
        Ok(Ok(a)) => Ok(a),
        _ => {
            n.pending.borrow_mut().remove(&id);
            Err("the control plane is unreachable".into())
        }
    }
}

fn principal_of_run(env: &Env, run: &str) -> Option<&'static str> {
    env.ctl.borrow().identities.get(run).copied()
}

async fn serve_box(n: Rc<Node>, s: turmoil::net::TcpStream) {
    let (mut rd, mut wr) = s.into_split();
    let run = match wire::read_frame(&mut rd).await {
        Ok(Some((wire::KIND_MSG, b))) => match wire::parse::<BoxMsg>(&b) {
            Ok(BoxMsg::Hello { run }) => run,
            _ => return,
        },
        _ => return,
    };
    while let Ok(Some((wire::KIND_MSG, b))) = wire::read_frame(&mut rd).await {
        let Ok(BoxMsg::Call { name, args }) = wire::parse::<BoxMsg>(&b) else { return };
        let (text, is_error) = tool(&n, &run, &name, args).await;
        if wire::write_json(&mut wr, &BoxMsg::Answer { text, is_error }).await.is_err() {
            return;
        }
    }
}

/// `nodegw::tool`: decided here cut off, relayed connected.
async fn tool(n: &Rc<Node>, run: &str, name: &str, args: Value) -> (String, bool) {
    let unreachable = |why: String| {
        (format!("the control plane is unreachable ({why}): this needs it. Retry this call in a minute; if it was a wait (await_grant, await_message), call it again."), true)
    };
    match name {
        "send_message" if n.link.borrow().is_none() => send_local(n, run, &args),
        "await_message" => {
            if let Some(m) = take_local(n, run) {
                return (serde_json::to_string(&local_view(&m)).unwrap_or_default(), false);
            }
            if n.link.borrow().is_none() {
                tokio::time::sleep(ms(500)).await;
                return ("no message after 1s. wicket's control host is unreachable from your node, so only messages from boxes on it arrive meanwhile. You may call await_message again.".into(), false);
            }
            relay(n, run, name, args).await.unwrap_or_else(unreachable)
        }
        _ => relay(n, run, name, args).await.unwrap_or_else(unreachable),
    }
}

/// `nodegw::send_local`: a message to a box on this node while cut off.
fn send_local(n: &Rc<Node>, run: &str, args: &Value) -> (String, bool) {
    let env = &n.env;
    let to = args["to"].as_str().unwrap_or("");
    let Some(me) = principal_of_run(env, run) else { return ("not sent: this box holds no authority on its node".into(), true) };
    let Some(p) = PRINCIPALS.iter().copied().find(|p| principal_id(p) == to) else {
        return (format!("not sent: {to} is not a principal"), true);
    };
    let Some(to_run) = env.live.borrow().get(p).cloned().flatten().filter(|_| BOXED.contains(&p)) else {
        return (format!("not sent: {to} isn't running on your node, and wicket's control host is unreachable from it; send it again when it is back"), true);
    };
    let mut d = env.node.borrow_mut();
    d.next += 1;
    let id = format!("m-node-{}", d.next);
    if !accept_from(p).contains(&zone_of(me)) {
        let why = format!("zone {} does not accept messages from zone {} (its accept_from does not list it)", zone_of(p), zone_of(me));
        let receipt = json!({ "message_id": id, "to": to, "state": "refused", "why": why, "verified_by": "node node" });
        return (format!("refused: {id} was not delivered: {why}\nreceipt: {receipt}"), true);
    }
    let priority = args["priority"].as_str().unwrap_or("next").to_string();
    d.inbox.push(LocalMessage {
        id: id.clone(),
        to_run: to_run.clone(),
        from: me.into(),
        body: args["body"].clone(),
        priority: priority.clone(),
    });
    let receipt =
        json!({ "message_id": id, "to": to, "state": "delivered", "run": to_run, "priority": priority, "verified_by": "node node" });
    (format!("sent {id} to {to_run}, delivered by your node (wicket's control host is unreachable, so it is attested by the node, not signed with your identity)\nreceipt: {receipt}"), false)
}

/// `EdgeQueue::take`: the run's most urgent message, then the oldest. A message held for a run
/// that has since ended is its principal's next run's (as `put_identity` moves held ones).
fn take_local(n: &Rc<Node>, run: &str) -> Option<LocalMessage> {
    let p = principal_of_run(&n.env, run)?;
    let mut d = n.env.node.borrow_mut();
    let rank = |m: &LocalMessage| match m.priority.as_str() {
        "now" => 0,
        "later" => 2,
        _ => 1,
    };
    let mine = |m: &LocalMessage| m.to_run == run || principal_of_run(&n.env, &m.to_run) == Some(p);
    let i = d.inbox.iter().enumerate().filter(|(_, m)| mine(m)).min_by_key(|(i, m)| (rank(m), *i)).map(|(i, _)| i)?;
    Some(d.inbox.remove(i))
}

fn local_view(m: &LocalMessage) -> Value {
    json!({ "message_id": m.id, "kind": "message", "from": { "id": principal_id(&m.from), "verified_by": "node node" }, "body": m.body })
}

// ---- the boxes ----

async fn agent_box(env: Rc<Env>, p: &'static str, mut rng: Rng) -> turmoil::Result {
    let start = tokio::time::Instant::now();
    let mut conn: Option<(String, turmoil::net::tcp::OwnedReadHalf, turmoil::net::tcp::OwnedWriteHalf)> = None;
    let mut seq = 0u32;
    while start.elapsed() < ms(END_MS) {
        tokio::time::sleep(ms(rng.range(20, 400) as i64)).await;
        let Some(run) = env.live.borrow().get(p).cloned().flatten() else {
            conn = None;
            continue;
        };
        if conn.as_ref().is_none_or(|c| c.0 != run) {
            let Ok(s) = turmoil::net::TcpStream::connect(("node", PORT_NODE)).await else { continue };
            let (rd, mut wr) = s.into_split();
            if wire::write_json(&mut wr, &BoxMsg::Hello { run: run.clone() }).await.is_err() {
                continue;
            }
            conn = Some((run.clone(), rd, wr));
        }
        let sending = start.elapsed() < ms(SEND_MS) && rng.chance(0.5);
        let (name, args, msg) = if sending {
            let others: Vec<&str> = PRINCIPALS.iter().copied().filter(|q| *q != p).collect();
            let to = others[rng.range(0, others.len() as u64 - 1) as usize];
            seq += 1;
            let n = format!("{p}#{seq}");
            let priority = ["now", "next", "later"][rng.range(0, 2) as usize];
            ("send_message", json!({ "to": principal_id(to), "body": { "n": n }, "priority": priority }), Some((to, n)))
        } else {
            ("await_message", json!({ "timeout_seconds": 1 }), None)
        };
        let (_, rd, wr) = conn.as_mut().expect("connected");
        // An MCP client waits for its answer; a connection that breaks (its node restarted) is
        // dialled again.
        let answer = async {
            wire::write_json(wr, &BoxMsg::Call { name: name.into(), args }).await.ok()?;
            match wire::read_frame(rd).await {
                Ok(Some((wire::KIND_MSG, b))) => match wire::parse::<BoxMsg>(&b) {
                    Ok(BoxMsg::Answer { text, is_error }) => Some((text, is_error)),
                    _ => None,
                },
                _ => None,
            }
        }
        .await;
        let Some((text, is_error)) = answer else {
            conn = None;
            continue;
        };
        let mut o = env.oracle.borrow_mut();
        match msg {
            Some((to, n)) => o.sent(p, to, &n, &text, is_error),
            None => {
                if let Ok(v) = serde_json::from_str::<Value>(&text) {
                    if let Some(n) = v["body"]["n"].as_str() {
                        let from = n.split('#').next().unwrap_or("?").to_string();
                        o.received(p, n, &from);
                    }
                }
            }
        }
    }
    Ok(())
}

// ---- the run ----

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub keep_trace: bool,
    /// Count the known relay loss as a violation (see [`run`]).
    pub strict_relay: bool,
}

/// Runs the messages scenario for `seed`, with the hosts' directories under `dir` (removed after).
///
/// **The known loss (#324).** Connected, a box's `await_message` is relayed to its run's gateway
/// on the control host, which takes the message from the inbox and records it read in one
/// transaction (`Ledger::take_message`) before its answer goes back over the node's channel. A
/// cut-off or crash between the two loses the message: its receipt says `read`, and its recipient
/// never saw it. Fixing it needs the node to acknowledge what it delivered (an offer that is read
/// only once acknowledged, and the node dropping one it has already delivered), across the channel
/// protocol, the store and the node's gateway. Until then each such message is reported in
/// [`Report::known`], not as a violation; [`Options::strict_relay`] counts them, and
/// `tests/scenario.rs` keeps it found.
pub fn run(seed: u64, dir: &Path, options: Options) -> Report {
    let plan = Plan::new(seed);
    let dir = dir.join(format!("messages-{seed}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("control")).expect("the simulation's directory");
    // Its key comes from the OS: it changes bytes, not decisions.
    let issuer = wicket_identity::Issuer::generate(DOMAIN);
    let env = Rc::new(Env {
        plan: plan.clone(),
        dir: dir.clone(),
        oracle: Rc::new(RefCell::new(Oracle {
            trace: Trace::new(EPOCH_MS, options.keep_trace),
            stats: Stats::default(),
            accepted: BTreeMap::new(),
            refused: BTreeMap::new(),
            received: BTreeMap::new(),
            known: vec![],
            strict_relay: options.strict_relay,
        })),
        ctl: Rc::new(RefCell::new(CtlDisk::default())),
        node: Rc::new(RefCell::new(NodeDisk::default())),
        live: Rc::new(RefCell::new(BTreeMap::new())),
        issuer,
        woken: Arc::new(Mutex::new(false)),
        agent_c: "agt_c".into(),
        gateways: RefCell::new(BTreeMap::new()),
        ledger_conn: RefCell::new(None),
    });
    let mut sim = turmoil::Builder::new()
        .epoch(UNIX_EPOCH + Duration::from_millis(EPOCH_MS as u64))
        .simulation_duration(Duration::from_millis((END_MS + 10_000) as u64))
        .min_message_latency(Duration::from_millis(1))
        .max_message_latency(Duration::from_millis(plan.max_latency_ms))
        .rng_seed(seed)
        .build();
    let e = env.clone();
    sim.host("control", move || control(e.clone()));
    let e = env.clone();
    sim.host("node", move || node(e.clone()));
    let mut rngs = Rng::new(seed.rotate_left(29)).fork();
    for p in BOXED {
        sim.client(format!("box_{p}"), agent_box(env.clone(), p, rngs.fork()));
    }
    let mut actions: Vec<(i64, usize, (&str, bool))> = vec![];
    for (i, f) in plan.faults.iter().enumerate() {
        let host = match f.kind {
            FaultKind::Partition => "link",
            FaultKind::NodeCrash => "node",
            FaultKind::ControlCrash => "control",
        };
        actions.push((f.at, 2 * i, (host, true)));
        actions.push((f.at + f.dur, 2 * i + 1, (host, false)));
    }
    actions.sort_by_key(|(t, i, _)| (*t, *i));
    let mut next = 0;
    let mut host_error = None;
    loop {
        let now = sim.elapsed().as_millis() as i64;
        while next < actions.len() && actions[next].0 <= now {
            let (host, start) = actions[next].2;
            env.oracle.borrow_mut().trace.note(EPOCH_MS + now, format!("fault {host} {}", if start { "starts" } else { "ends" }));
            match (host, start) {
                ("link", true) => sim.hold("control", "node"),
                ("link", false) => sim.release("control", "node"),
                (h, true) => sim.crash(h),
                (h, false) => sim.bounce(h),
            }
            next += 1;
        }
        match sim.step() {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => {
                host_error = Some(e.to_string());
                break;
            }
        }
    }
    drop(sim);
    let inbox: BTreeSet<String> = env.node.borrow().inbox.iter().map(|m| m.id.clone()).collect();
    *env.ledger_conn.borrow_mut() = None;
    env.gateways.borrow_mut().clear();
    let ledger = Ledger::open(&env.ledger_path()).expect("the control host's ledger");
    let mut o = env.oracle.borrow_mut();
    o.check_end(EPOCH_MS + END_MS, &ledger, &inbox);
    let checked = crate::trace::check_ledger(&mut o.trace, EPOCH_MS + END_MS, &ledger);
    drop(ledger);
    let _ = std::fs::remove_dir_all(&dir);
    if let Some(e) = host_error {
        o.trace.violations.push(format!("a host failed: {e}"));
    }
    Report {
        scenario: "messages",
        seed,
        plan: plan.to_string(),
        violations: o.trace.violations.clone(),
        hash: o.trace.hash(),
        stats: format!("{:?}, {} known relay losses, {}", o.stats, o.known.len(), crate::trace::ledger_stats(&checked)),
        known: o.known.clone(),
        trace: o.trace.lines().to_vec(),
    }
}
