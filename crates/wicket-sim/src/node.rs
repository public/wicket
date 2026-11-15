//! The node: the feed's replica, which decides every box request (#257), and each box's model proxy.
//!
//! It follows `wicket-cli/src/nodesrv.rs`:
//! - **The feed**: `Replica::<BoxAuthority>::open_with` on the node's feed directory, so a
//!   restarted node decides from what it verified before the crash, until it catches up. A frame
//!   the replica refuses with a catch-up reason makes it redial and say hello again.
//! - **Decisions**: every egress request is `Replica::decide` on the node's own clock (skewed),
//!   in whatever mode the replica is in. Cut off, the node keeps deciding on the grants it holds.
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
use crate::{true_now, Env, CONTROL_PORT, FORBIDDEN_HOST, GRANT_PATHS, NODE, NODE_PORT, READ_PATH, RUNS, SILENCE_MS};
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
}

struct Node {
    env: Rc<Env>,
    replica: RefCell<Replica<BoxAuthority>>,
    llms: BTreeMap<String, Arc<Llm>>,
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
    let node = Rc::new(Node { env: env.clone(), replica: RefCell::new(replica), llms });
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
        tokio::select! {
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
                        if let Ok(Ctl::BudgetSlice { run, slice }) = wire::parse::<Ctl>(&body) {
                            if let Some(l) = node.llms.get(&run) {
                                env.node_disk.lock().expect("node disk").slices.insert(run.clone(), slice);
                                l.set_slice(Some(slice));
                            }
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
                    if wire::write_json(&mut wr, &Ctl::Spent { run: run.clone(), spent: l.spent() }).await.is_err() {
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
                } else if method == "GET" && path == READ_PATH {
                    OpClass::Reach
                } else {
                    OpClass::NeedsGrant
                };
                let op = Op::egress(&TenantId(crate::TENANT.into()), &RunId(run.clone()), &env.zone.name, &method, &host, &path);
                let now = node.now();
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
                BoxResp::Egress { allowed: d.is_allow(), why: format!("{d:?}") }
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
