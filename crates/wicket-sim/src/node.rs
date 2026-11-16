//! The node: the feed's replica, which decides every box request (#257), and each box's model proxy.
//!
//! It follows `wicket-cli/src/nodesrv.rs`:
//! - **The feed**: `Replica::<BoxAuthority>::open_with` on the node's feed directory, so a
//!   restarted node decides from what it verified before the crash, until it catches up. A frame
//!   the replica refuses with a catch-up reason makes it redial and say hello again.
//! - **Decisions**: every egress request is `Replica::decide` on the node's own clock (skewed),
//!   in whatever mode the replica is in. Cut off, the node keeps deciding on the grants it holds.
//!   First `wicket_proxy::decide::route` says whether the node's CA covers the host: one it can't
//!   cover is spliced if the box's token allows it wholesale (`Replica::splice`, the `Decider`'s
//!   splice) and refused otherwise, as the node's egress proxy does since #257's slice 3. Nothing
//!   is forwarded to the control host.
//! - **The model proxy** (`serve_box`'s `Llm::new`): the zone's budget, bounded by the run's slice
//!   (`set_slice`). It restarts from the spend file and the slice on disk (`SPEND_FILE`,
//!   `nodesecrets::Slices`). The spend file is written before each call goes upstream, with calls
//!   in flight charged in full (`Llm::set_journal`), and again by a one-second ticker. Spend is
//!   reported (`Msg::Spent`) on every tick, as `nodesrv` does.
//! - **The upstream** is a stand-in: it bills each call it receives (in the oracle) as it
//!   receives it, then answers after a latency. A crash in between is a call billed and never
//!   settled here, as with a real provider.

use crate::control::AbortOnDrop;
use crate::oracle::OpClass;
use crate::wire::{self, BoxReq, BoxResp, Ctl};
use crate::{true_now, Env, CONTROL_PORT, EPOCH_MS, FORBIDDEN_HOST, GRANT_PATHS, NODE, NODE_CA, NODE_PORT, READ_PATH, RUNS, SILENCE_MS};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use wicket_core::{Op, RunId, TenantId};
use wicket_feed::{BoxAuthority, Replica, ReplicaConfig};
use wicket_proxy::llm::{Llm, Slice, Spent};

/// What the node has on disk besides its replica's directory.
#[derive(Default)]
pub struct Disk {
    /// `SPEND_FILE` per run.
    pub spend: BTreeMap<String, Spent>,
    /// `slices/` per run.
    pub slices: BTreeMap<String, Slice>,
    /// `node-egress.json` per run, and its egress slice (`slices/<run>.egress.json`, #368).
    pub egress: BTreeMap<String, wicket_core::window::EgressUse>,
    pub egress_slices: BTreeMap<String, wicket_core::window::EgressSlice>,
}

struct Node {
    env: Rc<Env>,
    replica: RefCell<Replica<BoxAuthority>>,
    llms: BTreeMap<String, Arc<Llm>>,
    /// Each run's egress counter, when the zone caps egress (#368).
    egress: BTreeMap<String, Arc<wicket_proxy::egress::caps::EgressCounter>>,
}

impl Node {
    /// The node's clock: the true time plus its skew.
    fn now(&self) -> i64 {
        true_now() + self.env.plan.node_skew_ms
    }
}

/// The node's software (`wicket node serve`): started at the beginning, and again after each crash.
pub async fn run(env: Rc<Env>) -> turmoil::Result {
    env.oracle.borrow_mut().stats.node_starts += 1;
    let replica = Replica::<BoxAuthority>::open_with(
        &env.dir.join("node").join("feed"),
        NODE,
        env.feed_root.verifying_key(),
        ReplicaConfig::default(),
        env.authz_root.public(),
    )
    .map_err(|e| e.to_string())?;
    let mut llms = BTreeMap::new();
    for run in RUNS {
        let l = Llm::new(crate::run_ctx(run, &env.zone)).map_err(|e| e.to_string())?;
        let disk = env.node_disk.lock().expect("node disk");
        if let Some(sp) = disk.spend.get(run) {
            l.merge_spent(*sp);
        }
        l.set_slice(disk.slices.get(run).copied());
        drop(disk);
        if env.options.spend_journal {
            let (d, r) = (env.node_disk.clone(), run.to_string());
            l.set_journal(move |s| {
                d.lock().expect("node disk").spend.insert(r.clone(), s);
            });
        }
        llms.insert(run.to_string(), l);
    }
    // As `nodesrv::serve_box`: the count from its journal, the slice as last sent.
    let mut egress = BTreeMap::new();
    if let Some(caps) = env.zone.limits.egress_caps() {
        for run in RUNS {
            let c = wicket_proxy::egress::caps::EgressCounter::new(caps);
            let disk = env.node_disk.lock().expect("node disk");
            if let Some(u) = disk.egress.get(run) {
                c.merge_used(*u);
            }
            c.set_slice(disk.egress_slices.get(run).copied());
            drop(disk);
            let (d, r) = (env.node_disk.clone(), run.to_string());
            c.set_journal(move |u| {
                d.lock().expect("node disk").egress.insert(r.clone(), u);
            });
            egress.insert(run.to_string(), c);
        }
    }
    let node = Rc::new(Node { env: env.clone(), replica: RefCell::new(replica), llms, egress });
    {
        let n = &node;
        let now = n.now();
        let r = n.replica.borrow();
        env.oracle.borrow_mut().note(true_now(), format!("node starts at epoch {:?}, mode {:?}", r.state().map(|s| s.epoch), r.mode(now)));
    }
    tokio::task::spawn_local(spend_file(node.clone()));
    tokio::task::spawn_local(control_link(node.clone()));
    let listener = turmoil::net::TcpListener::bind(("0.0.0.0", NODE_PORT)).await?;
    loop {
        let (s, _) = listener.accept().await?;
        tokio::task::spawn_local(serve_box(node.clone(), s));
    }
}

/// The spend file, written each second the count moved: through the journal, with calls in
/// flight charged in full (`nodesrv` since #324), or without one, as before, what was settled.
async fn spend_file(node: Rc<Node>) {
    let mut t = tokio::time::interval(Duration::from_secs(1));
    loop {
        t.tick().await;
        for (run, l) in &node.llms {
            if node.env.options.spend_journal {
                l.journal();
            } else {
                node.env.node_disk.lock().expect("node disk").spend.insert(run.clone(), l.spent());
            }
        }
    }
}

/// The channel to the control host, redialled whenever it drops or goes silent.
async fn control_link(node: Rc<Node>) {
    loop {
        if let Ok(s) = turmoil::net::TcpStream::connect(("control", CONTROL_PORT)).await {
            link(&node, s).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn link(node: &Rc<Node>, s: turmoil::net::TcpStream) {
    let env = &node.env;
    let (mut rd, mut wr) = s.into_split();
    let hello = node.replica.borrow().hello();
    if wire::write_json(&mut wr, &Ctl::Hello { hello }).await.is_err() {
        return;
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    let _reader = AbortOnDrop(tokio::task::spawn_local(async move {
        while let Ok(Some(f)) = wire::read_frame(&mut rd).await {
            if tx.send(f).is_err() {
                break;
            }
        }
    }));
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut last_rx = tokio::time::Instant::now();
    loop {
        // `biased`: unbiased, `select!` picks among ready branches with tokio's own RNG, which
        // the seed doesn't reach, so a frame and a tick due at the same simulated instant ran in
        // either order (#324). What has arrived is handled before the tick acts on it.
        tokio::select! {
            biased;
            f = rx.recv() => {
                let Some((kind, body)) = f else { return };
                last_rx = tokio::time::Instant::now();
                match kind {
                    wire::KIND_FEED => {
                        let now = node.now();
                        let res = node.replica.borrow_mut().accept_bytes(&body, now);
                        if let Err(e) = res {
                            let mut o = env.oracle.borrow_mut();
                            o.stats.feed_refusals += 1;
                            o.note(true_now(), format!("node refuses a feed frame: {e}"));
                            if e.wants_catch_up() {
                                return;
                            }
                        }
                    }
                    wire::KIND_MSG => {
                        match wire::parse::<Ctl>(&body) {
                            Ok(Ctl::BudgetSlice { run, slice }) => {
                                if let Some(l) = node.llms.get(&run) {
                                    env.node_disk.lock().expect("node disk").slices.insert(run.clone(), slice);
                                    l.set_slice(Some(slice));
                                }
                            }
                            Ok(Ctl::EgressSlice { run, slice }) => {
                                if let Some(c) = node.egress.get(&run) {
                                    env.node_disk.lock().expect("node disk").egress_slices.insert(run.clone(), slice);
                                    c.set_slice(Some(slice));
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => return,
                }
            }
            _ = tick.tick() => {
                if last_rx.elapsed() > Duration::from_millis(SILENCE_MS) {
                    env.oracle.borrow_mut().note(true_now(), "node drops a silent control connection");
                    return;
                }
                for (run, l) in &node.llms {
                    let egress = node.egress.get(run).map(|c| c.used());
                    if wire::write_json(&mut wr, &Ctl::Spent { run: run.clone(), spent: l.spent(), egress }).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// One box's connection: its egress requests and model calls, one at a time.
async fn serve_box(node: Rc<Node>, s: turmoil::net::TcpStream) {
    let (mut rd, mut wr) = s.into_split();
    let run = match wire::read_frame(&mut rd).await {
        Ok(Some((wire::KIND_MSG, b))) => match wire::parse::<BoxReq>(&b) {
            Ok(BoxReq::Hello { run }) if node.llms.contains_key(&run) => run,
            _ => return,
        },
        _ => return,
    };
    let env = node.env.clone();
    while let Ok(Some((wire::KIND_MSG, b))) = wire::read_frame(&mut rd).await {
        let resp = match wire::parse::<BoxReq>(&b) {
            Ok(BoxReq::Egress { method, host, path }) => {
                let class = if host == FORBIDDEN_HOST {
                    OpClass::Forbidden
                } else if (method == "GET" && path == READ_PATH) || host == crate::SPLICED_HOST {
                    OpClass::Reach
                } else {
                    OpClass::NeedsGrant
                };
                let tenant = TenantId(crate::TENANT.into());
                let op = Op::egress(&tenant, &RunId(run.clone()), &env.zone.name, &method, &host, &path);
                let now = node.now();
                // The node's CA, name-constrained to NODE_CA and valid for a day.
                let ca: Vec<String> = NODE_CA.iter().map(|h| h.to_string()).collect();
                let not_after = (EPOCH_MS + 86_400_000) / 1000;
                let route = wicket_proxy::decide::route(&host, Some((&ca[..], not_after)), now / 1000);
                if let (wicket_proxy::decide::Route::Uncovered(why), true) = (&route, env.options.refuse_uncovered) {
                    // A zone that caps egress splices nothing (`Egress::splice_rule`, #368).
                    let spliced = if node.egress.is_empty() { node.replica.borrow().splice(&tenant, &run, &host, now) } else { None };
                    env.oracle.borrow_mut().uncovered(true_now(), &run, &host, &path, spliced);
                    let resp = BoxResp::Egress { allowed: spliced.is_some(), why: format!("{why}: spliced {spliced:?}") };
                    if wire::write_json(&mut wr, &resp).await.is_err() {
                        return;
                    }
                    continue;
                }
                let (d, mode, epoch) = {
                    let mut r = node.replica.borrow_mut();
                    let mode = r.mode(now);
                    let epoch = r.state().map(|s| s.epoch);
                    (r.decide(&op, now), mode, epoch)
                };
                let label = if GRANT_PATHS.contains(&path.as_str()) || class != OpClass::NeedsGrant {
                    path.clone()
                } else {
                    format!("{method} {path}")
                };
                env.oracle.borrow_mut().decided(true_now(), now, &run, class, &label, &d, mode, epoch);
                if let (wicket_proxy::decide::Route::Uncovered(_), true) = (&route, d.is_allow()) {
                    env.oracle.borrow_mut().decided_uncovered(true_now(), &run, &host, &path, &d);
                }
                // An allowed request goes upstream only within the run's egress slice (#368).
                let mut allowed = d.is_allow();
                match (allowed, node.egress.get(&run)) {
                    (true, Some(c)) if env.options.egress_slices => match c.admit(None) {
                        Ok(()) => env.oracle.borrow_mut().egress_sent(true_now(), &run),
                        Err(why) => {
                            env.oracle.borrow_mut().egress_capped(true_now(), &run, &why.0);
                            allowed = false;
                        }
                    },
                    // Without slices held: counted and reported all the same, never refused.
                    (true, Some(c)) => {
                        let u = c.used();
                        c.merge_used(wicket_core::window::EgressUse { requests: u.requests + 1, bytes: u.bytes });
                        c.journal();
                        env.oracle.borrow_mut().egress_sent(true_now(), &run);
                    }
                    (true, None) => env.oracle.borrow_mut().egress_sent(true_now(), &run),
                    (false, _) => {}
                }
                BoxResp::Egress { allowed, why: format!("{d:?}") }
            }
            Ok(BoxReq::Model { max_tokens }) => model_call(&node, &run, max_tokens).await,
            _ => return,
        };
        if wire::write_json(&mut wr, &resp).await.is_err() {
            return;
        }
    }
}

/// One model call through the run's model proxy: admitted and reserved, billed upstream, settled.
async fn model_call(node: &Rc<Node>, run: &str, max_tokens: u64) -> BoxResp {
    let env = &node.env;
    let l = node.llms[run].clone();
    let reserved = match l.sim_begin(max_tokens) {
        Ok(r) => r,
        Err(status) => {
            let mut o = env.oracle.borrow_mut();
            o.stats.model_refused += 1;
            o.note(true_now(), format!("model {run} asks {max_tokens}: refused {status}"));
            return BoxResp::Model { status, output: 0 };
        }
    };
    let (output, latency) = {
        let mut u = env.upstream.borrow_mut();
        (u.range(reserved / 4, reserved), u.range(20, 400))
    };
    {
        let mut o = env.oracle.borrow_mut();
        o.billed(true_now(), run, output);
    }
    tokio::time::sleep(Duration::from_millis(latency)).await;
    l.sim_settle(reserved, 100, output, true);
    env.oracle.borrow_mut().stats.model_ok += 1;
    BoxResp::Model { status: 200, output }
}
