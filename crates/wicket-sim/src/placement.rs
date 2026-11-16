//! Placement (#324, second slice): placed nodes' leases, the reconciler, the money envelope and
//! release, with several runs on one node, on turmoil's simulated network and clock.
//!
//! **What is real and what stands in.**
//! - Real: [`wicket_placement::Placer`] (idempotent `acquire` by tag, the money envelope, the spend
//!   approval, `get` and `release` with their owner and `wicket-protected` checks), the reconciler's
//!   decision [`wicket_placement::reconcile::reconcile`], the billing rules
//!   ([`wicket_placement::BillingModel::vultr`]: per started hour, leases end at minute 50), the
//!   ledger ([`wicket_store::Ledger`] on the control host's disk: runs, their nodes, placed nodes,
//!   audit), and the node's feed ([`wicket_feed::Publisher`] per run, [`wicket_feed::Replica`] on
//!   the node), so several runs publish to one node as #300 has them.
//! - Stand-ins, each following a file in `wicket-cli` (which lives in the CLI binary):
//!   - `node create` follows `nodecreate.rs` (`create`): acquire, then record the placed node
//!     at once, then enrol it. A create the control host's crash interrupted is run again with the
//!     same idempotency key, as its human would.
//!   - `wicket run --node` and its supervisor follow `run.rs` and `noderun.rs`: the run is recorded
//!     on the node, its box started there, its statements published over its own connection (the
//!     shared `feed/issued` time, `noderun::FeedGuard`), and when the box exits its files are
//!     fetched (`fetch_trees`). A fetch that fails is audited `run.fetch_failed`, the run fails, and
//!     the node keeps the files (`NodeCtl::forget` only after a fetch). After a control-host crash
//!     every running run is re-attached (the reconciler's adoption, `wicket attach`).
//!   - The reconciler follows `reconcile.rs`: the machine half (`reconcile_machines`, with no
//!     capacity leases: owned nodes no placed node records are destroyed) and [`placed_pass`] (#294),
//!     every [`PASS_S`] (`wicket reconcile --every 30s`), each pass with its own `Placer`, as
//!     `place::release_placer` makes one.
//!   - The provider ([`Cloud`]) stands in for Vultr as `wicket_placement::mock` does: instances by
//!     tag, created at once and answered after a latency, destroyed on request.
//!   - A node (`m0`..) stands in for `wicket node serve`'s boxes: a box works for its run's time and
//!     writes a file a minute; its files stay on the node until forgotten.
//!
//! **Time.** Leases are hours, so one simulated millisecond is one second here ([`now_s`]): link
//! latencies, timeouts and the reconciler's period are all in seconds of placement time.
//!
//! **Invariants** (checked by the world, outside the simulated network):
//! - no node is used past its lease: no box starts on a node past its lease end, and a node past
//!   its lease that nothing holds (no box running, no work uncollected) is released within
//!   [`GRACE_S`] (#294);
//! - no two runs collide on one node (#300): each run's statements are taken by the node (none
//!   refused as a replay, rollback or fork), and each run's fetch brings back its own whole
//!   workspace;
//! - a node isn't released while a run's box runs on it or a run's work on it is uncollected;
//! - the money envelope holds: owned nodes never bill more per hour than its hourly limit.

use crate::rng::Rng;
use crate::trace::{Report, Trace};
use crate::wire;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use wicket_core::{RunId, TenantId, ZoneSpec};
use wicket_feed::{BoxAuthority, Change, Issuer, Publisher, PublisherConfig, Replica, ReplicaConfig};
use wicket_placement::billing::PoolRules;
use wicket_placement::model::{NodeState, PROTECTED_TAG};
use wicket_placement::reconcile as plan;
use wicket_placement::{
    Approval, BillingModel, CapacityRequest, CreateSpec, IsolationTier, MicroUsd, MoneyEnvelope, NodeHandle, NodeId, Offer, Owner,
    Placement, PlacementError, Placer, Provider, ReleaseMode, Released, Resources, SpendApprover, SpendRequest,
};
use wicket_store::{Ledger, PlacedNodeRow};

/// Placement time 0 (Unix seconds): on the hour, as a provider's billing hours are counted from
/// each node's own creation anyway.
pub const EPOCH_S: i64 = 1_800_000_000;
/// The plan's horizon: creates and runs come before this.
pub const PLAN_S: i64 = 3 * 3600;
/// The simulation ends here, once every lease has ended and the reconciler has had its passes.
pub const END_S: i64 = 6 * 3600;
/// The reconciler's period (`wicket reconcile --every 30s`).
pub const PASS_S: i64 = 30;
/// How long a node past its lease that nothing holds may go on billing: two passes, and the
/// provider's latency.
pub const GRACE_S: i64 = 2 * PASS_S + 120;
/// The machines the provider has.
pub const MACHINES: usize = 4;
/// A node's hourly rate (Vultr's vc2-1c-2gb), and the envelope's hourly limit: three at once.
pub const RATE: MicroUsd = MicroUsd(14_000);
pub const MAX_HOURLY: MicroUsd = MicroUsd(3 * 14_000);
pub const PORT: u16 = 9000;
pub const OWNER: &str = "sim";
pub const BACKEND: &str = "simcloud";
const TENANT: &str = "t_sim";
/// The feed's freshness, in placement time (ms): statements every 30 s, each good for 90.
const FEED_TTL_MS: i64 = 90_000;
const FEED_REFRESH_MS: i64 = 30_000;
/// A supervisor's status poll, its silence limit, and its fetch's limit (seconds).
const POLL_S: i64 = 10;
const SILENCE_S: i64 = 60;
const FETCH_S: i64 = 120;

/// Placement time now (Unix seconds), inside a host.
pub fn now_s() -> i64 {
    EPOCH_S + turmoil::since_epoch().map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// The feed's clock (Unix ms) in placement time.
fn feed_now() -> i64 {
    now_s() * 1000
}

/// `s` seconds of placement time, as a simulated duration.
fn secs(s: i64) -> Duration {
    Duration::from_millis(s.max(0) as u64)
}

fn clock() -> wicket_placement::placer::Clock {
    Arc::new(now_s)
}

// ---- the plan ----

#[derive(Clone, Debug)]
pub struct Create {
    pub at: i64,
    pub name: String,
    pub lifetime_s: i64,
    /// What the human answers the spend approval.
    pub approve: bool,
}

#[derive(Clone, Debug)]
pub struct RunPlan {
    pub at: i64,
    pub run: String,
    /// Which of the creates' nodes (`wicket run --node <name>`).
    pub node: usize,
    pub work_s: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// The control host and machine `m<k>` can't reach each other.
    Partition { machine: usize },
    /// The control host (`place create`, the supervisors, the reconciler) crashes, and restarts.
    ControlCrash,
    /// `wicket node serve` on machine `m<k>` crashes, and restarts; its boxes go on.
    ServeCrash { machine: usize },
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
    /// Link latency, 1..= this many seconds.
    pub max_latency_s: u64,
    /// The provider's API answers in 1..= this many seconds.
    pub cloud_latency_s: u64,
    /// The envelope's total limit.
    pub max_total: MicroUsd,
    pub creates: Vec<Create>,
    pub runs: Vec<RunPlan>,
    pub faults: Vec<Fault>,
}

impl Plan {
    pub fn new(seed: u64) -> Plan {
        let mut r = Rng::new(seed ^ 0x504c_4143_454d_454e);
        let max_latency_s = r.range(1, 20);
        let cloud_latency_s = r.range(1, 15);
        let max_total = RATE.times(r.range(4, 12));
        let n = r.range(2, 4) as usize;
        let creates: Vec<Create> = (0..n)
            .map(|i| Create {
                at: r.range_i(0, 5_400),
                name: format!("p{i}"),
                lifetime_s: r.range_i(1_800, 9_000),
                approve: r.chance(0.85),
            })
            .collect();
        let mut runs: Vec<RunPlan> = (0..r.range(4, 9))
            .map(|j| RunPlan {
                at: r.range_i(0, PLAN_S),
                run: format!("run_{j}"),
                node: r.range(0, n as u64 - 1) as usize,
                work_s: r.range_i(300, 3_600),
            })
            .collect();
        runs.sort_by_key(|x| (x.at, x.run.clone()));
        let mut faults = vec![];
        let mut t = r.range_i(60, 900);
        while t < END_S - 3_600 {
            let (kind, dur) = match r.range(0, 7) {
                // The machines nodes land on, in the order they are created.
                0..=3 => (FaultKind::Partition { machine: r.range(0, n as u64 - 1) as usize }, r.range_i(30, 1_200)),
                4..=5 => (FaultKind::ControlCrash, r.range_i(5, 300)),
                _ => (FaultKind::ServeCrash { machine: r.range(0, n as u64 - 1) as usize }, r.range_i(5, 120)),
            };
            faults.push(Fault { at: t, dur, kind });
            t += dur + r.range_i(60, 1_800);
        }
        Plan { seed, max_latency_s, cloud_latency_s, max_total, creates, runs, faults }
    }
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "placement seed {}: link latency 1..={} s, provider latency 1..={} s, envelope {} per hour, {} total",
            self.seed, self.max_latency_s, self.cloud_latency_s, MAX_HOURLY, self.max_total
        )?;
        for c in &self.creates {
            writeln!(
                f,
                "  at {} s: place create {} for {} s (spend {})",
                c.at,
                c.name,
                c.lifetime_s,
                if c.approve { "approved" } else { "denied" }
            )?;
        }
        for r in &self.runs {
            writeln!(f, "  at {} s: wicket run {} --node {} for {} s", r.at, r.run, self.creates[r.node].name, r.work_s)?;
        }
        for x in &self.faults {
            writeln!(f, "  fault at {} s for {} s: {:?}", x.at, x.dur, x.kind)?;
        }
        Ok(())
    }
}

// ---- the world: the provider's machines, their disks, and the oracle ----

/// A run's box on a machine: it works until `until`, writing a file a minute.
#[derive(Clone, Debug)]
pub struct Boxed {
    pub started: i64,
    pub until: i64,
    pub forgotten: bool,
}

impl Boxed {
    fn running(&self, now: i64) -> bool {
        now < self.until
    }
    fn files(&self, now: i64) -> Vec<String> {
        let n = (now.min(self.until) - self.started) / 60 + 1;
        (0..n).map(|i| format!("f{i}")).collect()
    }
}

#[derive(Default)]
pub struct Machine {
    /// The instance on it, once created.
    pub inst: Option<NodeHandle>,
    pub gone: bool,
    /// Boxes, by run.
    pub boxes: BTreeMap<String, Boxed>,
    /// The last time something held it (a box running, work uncollected).
    pub busy_at: i64,
    /// Reported as billing past its lease.
    pub flagged: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub creates: u64,
    pub creates_refused: u64,
    pub runs: u64,
    pub runs_refused: u64,
    pub fetched: u64,
    pub fetch_failed: u64,
    pub released: u64,
    pub held: u64,
    pub destroyed_unrecorded: u64,
    pub statements: u64,
    pub statements_refused: u64,
    pub control_starts: u64,
}

pub struct World {
    pub machines: Vec<Machine>,
    rng: Rng,
    next_id: u32,
    pub trace: Trace,
    pub stats: Stats,
    /// Runs whose whole workspace a fetch brought back.
    pub collected: BTreeSet<String>,
    max_total: MicroUsd,
    /// The provider's latency bound for this run. (It was a process-wide static: runs in parallel
    /// in one process, as `cargo test` has them, set it for each other, so a seed's run depended
    /// on what else ran beside it.)
    cloud_latency_s: u64,
    /// When the control host (and so the reconciler) last started: a node can't be released while
    /// it is down.
    pub control_up_at: i64,
    pub control_down: bool,
    /// Runs that ended before their box was known to have started.
    pub abandoned: BTreeSet<String>,
}

impl World {
    fn by_id(&self, id: &NodeId) -> Option<usize> {
        self.machines.iter().position(|m| m.inst.as_ref().is_some_and(|n| &n.id == id))
    }

    fn live(&self) -> impl Iterator<Item = &NodeHandle> {
        self.machines.iter().filter(|m| !m.gone).filter_map(|m| m.inst.as_ref())
    }

    fn on_create(&mut self, n: &NodeHandle, now: i64) {
        self.trace.note(
            now,
            format!("cloud creates {} ({}) on {}, lease until {:?}", n.id, n.name, n.ssh_target.as_deref().unwrap_or("?"), n.lease_until),
        );
        let hourly: MicroUsd = self.live().map(|n| n.billing.hourly_rate()).sum();
        if hourly > MAX_HOURLY {
            self.trace.violate(now, format!("owned nodes bill {hourly} per hour, over the envelope's {MAX_HOURLY}"));
        }
        let total: MicroUsd = self.live().map(|n| n.billed_through(n.lease_until.unwrap_or(now).max(now))).sum();
        if total > self.max_total {
            self.trace.violate(now, format!("owned nodes are committed to {total}, over the envelope's {}", self.max_total));
        }
    }

    fn on_destroy(&mut self, k: usize, now: i64) {
        let m = &self.machines[k];
        let name = m.inst.as_ref().map(|n| format!("{} ({})", n.id, n.name)).unwrap_or_default();
        let mut bad = vec![];
        for (run, b) in m.boxes.iter().filter(|(run, _)| !self.abandoned.contains(*run)) {
            if b.running(now) {
                bad.push(format!("node {name} released while run {run}'s box runs on it"));
            } else if !b.forgotten && !self.collected.contains(run) {
                bad.push(format!("node {name} released with run {run}'s work on it uncollected"));
            }
        }
        self.trace.note(now, format!("cloud destroys {name}"));
        // Every node here was made by `place create` for its human, and recorded: it is theirs
        // until its lease ends.
        if let Some(until) = m.inst.as_ref().and_then(|n| n.lease_until).filter(|u| now < *u) {
            bad.push(format!("node {name} destroyed {} s before its lease ends", until - now));
        }
        for b in bad {
            self.trace.violate(now, b);
        }
        let m = &mut self.machines[k];
        m.gone = true;
        m.boxes.clear();
    }

    /// The box for `run` starts on machine `k` (or is there already: an attach), unless the start
    /// reaches the node at or past `start_by` (`nodesrv::start_box_steps`, #395).
    fn on_start(&mut self, k: usize, run: &str, work_s: i64, start_by: Option<i64>, now: i64) -> bool {
        let m = &mut self.machines[k];
        if m.boxes.contains_key(run) {
            return true;
        }
        if let Some(by) = start_by.filter(|by| now >= *by) {
            self.trace.note(now, format!("{run}'s start refused on m{k}: past its node's lease (ended {by})"));
            return false;
        }
        let Some(n) = m.inst.clone() else { return false };
        m.boxes.insert(run.to_string(), Boxed { started: now, until: now + work_s, forgotten: false });
        self.trace.note(now, format!("{run}'s box starts on {} ({})", n.id, n.name));
        if let Some(until) = n.lease_until.filter(|u| now >= *u) {
            self.trace.violate(now, format!("run {run}'s box started on node {} ({}) {} s past its lease", n.id, n.name, now - until));
        }
        true
    }

    /// The periodic check: a node past its lease that nothing holds is released within the grace.
    pub fn check_leases(&mut self, now: i64) {
        let (collected, abandoned) = (&self.collected, &self.abandoned);
        let up_at = self.control_up_at;
        let down = self.control_down;
        let mut found = vec![];
        for m in self.machines.iter_mut().filter(|m| !m.gone) {
            let Some(n) = &m.inst else { continue };
            let held = m
                .boxes
                .iter()
                .filter(|(run, _)| !abandoned.contains(*run))
                .any(|(run, b)| b.running(now) || (!b.forgotten && !collected.contains(run)));
            if held {
                m.busy_at = now;
                continue;
            }
            let Some(until) = n.lease_until else { continue };
            let since = until.max(m.busy_at).max(up_at);
            if !down && now > since + GRACE_S && !m.flagged {
                m.flagged = true;
                found.push(format!("node {} ({}) bills {} s past its lease with nothing on it", n.id, n.name, now - until));
            }
        }
        for f in found {
            self.trace.violate(now, f);
        }
    }

    /// At the end: every run's work came back, or is still on a node that exists.
    fn check_end(&mut self, now: i64, started: &BTreeSet<String>) {
        for run in started {
            if self.collected.contains(run) {
                continue;
            }
            let kept = self.machines.iter().any(|m| !m.gone && m.boxes.get(run).is_some_and(|b| !b.forgotten));
            self.trace.note(now, format!("end: {run} {}", if kept { "uncollected, kept on its node" } else { "uncollected and gone" }));
        }
    }
}

/// The provider: the world's machines behind Vultr's API, as `wicket_placement::mock` has it.
#[derive(Clone)]
pub struct Cloud(pub Arc<Mutex<World>>);

impl Cloud {
    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.0.lock().expect("world")
    }

    /// The provider's answer takes 1 to this run's latency bound seconds.
    async fn lag(&self) {
        let s = {
            let mut w = self.world();
            let max = w.cloud_latency_s;
            w.rng.range(1, max)
        };
        tokio::time::sleep(secs(s as i64)).await;
    }

    fn offer() -> Offer {
        Offer {
            plan: "vc2-1c-2gb".into(),
            region: Some("ams".into()),
            resources: Resources { vcpus: 1, memory_mib: 2048 },
            isolation: IsolationTier::Gvisor,
            billing: BillingModel::vultr(RATE),
        }
    }
}

impl Provider for Cloud {
    fn id(&self) -> &str {
        BACKEND
    }

    async fn offers(&self, _req: &CapacityRequest) -> anyhow::Result<Vec<Offer>> {
        self.lag().await;
        Ok(vec![Cloud::offer()])
    }

    async fn create(&self, spec: &CreateSpec) -> anyhow::Result<NodeHandle> {
        self.lag().await;
        let n = {
            let mut w = self.world();
            let Some(k) = w.machines.iter().position(|m| m.inst.is_none() && !m.gone) else {
                anyhow::bail!("no capacity left in the region");
            };
            w.next_id += 1;
            let now = now_s();
            let n = NodeHandle {
                id: NodeId(format!("inst-{}", w.next_id)),
                backend: BACKEND.into(),
                name: spec.name.clone(),
                ssh_target: Some(format!("m{k}")),
                region: spec.offer.region.clone(),
                plan: Some(spec.offer.plan.clone()),
                isolation: spec.offer.isolation,
                resources: spec.offer.resources,
                billing: spec.offer.billing,
                created_at: now,
                lease_until: Owner::lease_from_tags(&spec.tags),
                host_key: None,
                tags: spec.tags.clone(),
                state: NodeState::Active,
            };
            w.machines[k].inst = Some(n.clone());
            w.machines[k].busy_at = now;
            w.on_create(&n, now);
            n
        };
        // The instance exists from here: the answer takes its time.
        self.lag().await;
        Ok(n)
    }

    async fn get(&self, id: &NodeId) -> anyhow::Result<Option<NodeHandle>> {
        self.lag().await;
        let w = self.world();
        Ok(w.by_id(id).filter(|k| !w.machines[*k].gone).and_then(|k| w.machines[k].inst.clone()))
    }

    async fn list_tagged(&self, tag: &str) -> anyhow::Result<Vec<NodeHandle>> {
        self.lag().await;
        Ok(self.world().live().filter(|n| n.has_tag(tag)).cloned().collect())
    }

    async fn destroy(&self, id: &NodeId) -> anyhow::Result<()> {
        self.lag().await;
        let mut w = self.world();
        if let Some(k) = w.by_id(id).filter(|k| !w.machines[*k].gone) {
            w.on_destroy(k, now_s());
        }
        Ok(())
    }
}

/// The human at `place create`'s spend prompt (`place::TerminalApprover`), answering as planned.
struct PlanApprover(bool);

impl SpendApprover for PlanApprover {
    async fn approve(&self, _req: &SpendRequest) -> Approval {
        if self.0 {
            Approval::Approved
        } else {
            Approval::Denied("the operator said no".into())
        }
    }
}

// ---- the wire between a run's supervisor and its node ----

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Up {
    Hello {
        run: String,
    },
    /// `BoxStart`, with `start_by`: its placed node's lease end, when the run began (#395).
    Start {
        work_s: i64,
        start_by: Option<i64>,
    },
    Status,
    Fetch,
    Forget,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Down {
    Hello { hello: wicket_feed::Hello },
    Started { ok: bool },
    Running,
    Exited,
    Unknown,
    Files { files: Option<Vec<String>> },
    Forgot,
}

// ---- the hosts ----

/// What the control host keeps on disk besides its ledger.
#[derive(Default)]
pub struct CtlDisk {
    /// The creates done (or refused).
    pub creates_done: BTreeSet<usize>,
    /// The runs `wicket run` was asked for.
    pub runs_done: BTreeSet<usize>,
    /// Enrolled nodes: name → its machine (`m<k>`).
    pub enrolled: BTreeMap<String, String>,
    /// Each run's machine.
    pub run_host: BTreeMap<String, String>,
    /// Each run's `BoxStart::start_by`: its placed node's lease end when the run began (#395).
    pub run_start_by: BTreeMap<String, i64>,
    /// `nodes/<name>/feed/issued`, per machine: the last statement time any run signed.
    pub feed_issued: BTreeMap<String, i64>,
}

pub struct Env {
    pub plan: Plan,
    pub dir: PathBuf,
    pub world: Arc<Mutex<World>>,
    pub ctl: Rc<RefCell<CtlDisk>>,
    pub feed_root: ed25519_dalek::SigningKey,
    pub feed_key: ed25519_dalek::SigningKey,
    pub cert: String,
    pub zone: ZoneSpec,
    pub options: Options,
    pub authz_root: wicket_authz::SigningKey,
    pub approver: wicket_authz::SigningKey,
    /// Each run's box token issuer (`Issuer::root`, as the run's supervisor mints it).
    pub issuers: BTreeMap<String, Issuer>,
}

impl Env {
    fn note(&self, line: impl Into<String>) {
        self.world.lock().expect("world").trace.note(now_s(), line);
    }
    fn violate(&self, line: impl Into<String>) {
        self.world.lock().expect("world").trace.violate(now_s(), line);
    }
    fn stat(&self, f: impl FnOnce(&mut Stats)) {
        f(&mut self.world.lock().expect("world").stats);
    }
    fn ledger(&self) -> Ledger {
        Ledger::open(&self.dir.join("control").join("ledger.db")).expect("the control host's ledger")
    }
    fn envelope(&self) -> MoneyEnvelope {
        MoneyEnvelope { max_hourly: MAX_HOURLY, max_total: self.plan.max_total }
    }
    fn cloud(&self) -> Cloud {
        Cloud(self.world.clone())
    }
}

fn machine_index(host: &str) -> usize {
    host.trim_start_matches('m').parse().unwrap_or(usize::MAX)
}

/// A machine's software (`wicket node serve`): its replica of its feed, and its boxes.
async fn machine(env: Rc<Env>, k: usize) -> turmoil::Result {
    let name = format!("m{k}");
    let dir = env.dir.join(&name).join("feed");
    let root = env.feed_root.verifying_key();
    let replica = match Replica::<BoxAuthority>::open_with(&dir, &name, root, ReplicaConfig::default(), env.authz_root.public()) {
        Ok(r) => r,
        Err(_) => Replica::reset_with(&dir, &name, root, ReplicaConfig::default(), env.authz_root.public()).map_err(|e| e.to_string())?,
    };
    let replica = Rc::new(RefCell::new(replica));
    let listener = turmoil::net::TcpListener::bind(("0.0.0.0", PORT)).await?;
    loop {
        let (s, _) = listener.accept().await?;
        tokio::task::spawn_local(serve_run(env.clone(), k, replica.clone(), s));
    }
}

/// One run's connection to its node.
async fn serve_run(env: Rc<Env>, k: usize, replica: Rc<RefCell<Replica<BoxAuthority>>>, s: turmoil::net::TcpStream) {
    let up = |w: &World| !w.machines[k].gone && w.machines[k].inst.is_some();
    if !up(&env.world.lock().expect("world")) {
        return;
    }
    let (mut rd, mut wr) = s.into_split();
    let run = match wire::read_frame(&mut rd).await {
        Ok(Some((wire::KIND_MSG, b))) => match wire::parse::<Up>(&b) {
            Ok(Up::Hello { run }) => run,
            _ => return,
        },
        _ => return,
    };
    let hello = replica.borrow().hello();
    if wire::write_json(&mut wr, &Down::Hello { hello }).await.is_err() {
        return;
    }
    while let Ok(Some((kind, body))) = wire::read_frame(&mut rd).await {
        if !up(&env.world.lock().expect("world")) {
            return;
        }
        if kind == wire::KIND_FEED {
            let res = replica.borrow_mut().accept_bytes(&body, feed_now());
            let mut w = env.world.lock().expect("world");
            w.stats.statements += 1;
            if let Err(e) = res {
                w.stats.statements_refused += 1;
                let now = now_s();
                // Delayed past its life by a cut-off is honest; a replay, rollback or fork of an
                // honest publisher's statement is two runs colliding on one node's feed (#300).
                match e.kind() {
                    "replay" | "rollback" | "fork" => w.trace.violate(now, format!("m{k} refused {run}'s feed frame: {e}")),
                    _ => w.trace.note(now, format!("m{k} refused {run}'s feed frame: {e}")),
                }
                // `nodesrv`: a frame refused for a catch-up reason drops the connection, and the
                // run's supervisor dials again with the node's hello.
                if e.wants_catch_up() {
                    return;
                }
            }
            continue;
        }
        let Ok(req) = wire::parse::<Up>(&body) else { return };
        if matches!(req, Up::Fetch) {
            // The box's trees take their time to send: a second per file.
            let n = env.world.lock().expect("world").machines[k].boxes.get(&run).map_or(0, |b| b.files(b.until).len());
            tokio::time::sleep(secs(n as i64)).await;
        }
        let now = now_s();
        let resp = {
            let mut w = env.world.lock().expect("world");
            match req {
                Up::Start { work_s, start_by } => Down::Started { ok: w.on_start(k, &run, work_s, start_by, now) },
                // A forgotten box is gone from the node (`nodesrv`'s `Msg::Forget` removes it from
                // its boxes): a supervisor that comes back finds nothing (#397). The world keeps it,
                // forgotten, for the invariants.
                Up::Status => match w.machines[k].boxes.get(&run).filter(|b| !b.forgotten) {
                    Some(b) if b.running(now) => Down::Running,
                    Some(_) => Down::Exited,
                    None => Down::Unknown,
                },
                Up::Fetch => {
                    Down::Files { files: w.machines[k].boxes.get(&run).filter(|b| !b.running(now) && !b.forgotten).map(|b| b.files(now)) }
                }
                Up::Forget => {
                    if let Some(b) = w.machines[k].boxes.get_mut(&run) {
                        b.forgotten = true;
                    }
                    Down::Forgot
                }
                Up::Hello { .. } => return,
            }
        };
        if wire::write_json(&mut wr, &resp).await.is_err() {
            return;
        }
    }
}

/// The control host: `place create`, `wicket run --node` and its supervisors, and the reconciler.
async fn control(env: Rc<Env>) -> turmoil::Result {
    env.stat(|s| s.control_starts += 1);
    {
        let mut w = env.world.lock().expect("world");
        w.control_up_at = now_s();
        w.control_down = false;
    }
    env.note("control host starts");
    // The reconciler's adoption: every running run gets a supervisor again (`wicket attach`).
    let running = env.ledger().running_runs().map_err(|e| e.to_string())?;
    for (run, _) in running {
        tokio::task::spawn_local(supervise(env.clone(), run, true));
    }
    tokio::task::spawn_local(creates(env.clone()));
    tokio::task::spawn_local(runs(env.clone()));
    tokio::task::spawn_local(reconciler(env.clone()));
    std::future::pending::<()>().await;
    Ok(())
}

/// `wicket node create`, as the plan has the human run it (and run it again after a crash).
async fn creates(env: Rc<Env>) {
    loop {
        tokio::time::sleep(secs(5)).await;
        let t = now_s() - EPOCH_S;
        let due: Vec<usize> =
            (0..env.plan.creates.len()).filter(|i| env.plan.creates[*i].at <= t && !env.ctl.borrow().creates_done.contains(i)).collect();
        for i in due {
            place_create(&env, i).await;
            env.ctl.borrow_mut().creates_done.insert(i);
        }
    }
}

/// `nodecreate.rs`'s `create`: acquire, record at once, enrol.
async fn place_create(env: &Rc<Env>, i: usize) {
    let c = env.plan.creates[i].clone();
    let placer = Placer::new(env.cloud(), PlanApprover(c.approve), Owner::new(OWNER), env.envelope()).with_clock(clock());
    let req = CapacityRequest {
        resources: Resources { vcpus: 1, memory_mib: 2048 },
        min_isolation: IsolationTier::Gvisor,
        region_hint: Some("ams".into()),
        plan_hint: None,
        max_hourly: None,
        lifetime_secs: c.lifetime_s,
        idempotency_key: format!("place-create:{}", c.name),
        name: c.name.clone(),
        purpose: format!("wicket node create {}", c.name),
        boot: None,
    };
    let n = match placer.acquire(&req).await {
        Ok(n) => n,
        Err(e) => {
            env.stat(|s| s.creates_refused += 1);
            env.note(format!("place create {} refused: {e}", c.name));
            return;
        }
    };
    // Recorded at once, so the reconciler releases it at its lease end whatever happens next.
    let lease_until = n.lease_until.unwrap_or(n.created_at + req.lifetime_secs);
    let ledger = env.ledger();
    ledger
        .record_placed_node(&PlacedNodeRow {
            id: n.id.0.clone(),
            backend: n.backend.clone(),
            name: c.name.clone(),
            owner: OWNER.into(),
            api_key_secret: "vultr".into(),
            created_at: n.created_at,
            lease_until,
            status: String::new(),
            held_by: None,
            ended_at: None,
            detail: None,
            hourly: Some(n.billing.hourly_rate().0 as i64),
        })
        .expect("recorded");
    let _ = ledger.audit(
        &TenantId::single(),
        None,
        "placement.node_created",
        &serde_json::json!({ "backend": n.backend, "id": n.id.0, "name": c.name, "lease_until": n.lease_until }),
    );
    env.stat(|s| s.creates += 1);
    env.note(format!("place create {}: {} until {lease_until}", c.name, n.id));
    // Enrolled once it is up (`bring_up_or_release`).
    if let Some(host) = n.ssh_target {
        env.ctl.borrow_mut().enrolled.insert(c.name.clone(), host);
    }
}

/// `wicket run --node <name>`, as the plan has it.
async fn runs(env: Rc<Env>) {
    loop {
        tokio::time::sleep(secs(5)).await;
        let t = now_s() - EPOCH_S;
        let due: Vec<usize> =
            (0..env.plan.runs.len()).filter(|j| env.plan.runs[*j].at <= t && !env.ctl.borrow().runs_done.contains(j)).collect();
        for j in due {
            let r = env.plan.runs[j].clone();
            let name = env.plan.creates[r.node].name.clone();
            let host = env.ctl.borrow().enrolled.get(&name).cloned();
            env.ctl.borrow_mut().runs_done.insert(j);
            let Some(host) = host else {
                env.stat(|s| s.runs_refused += 1);
                env.note(format!("wicket run {} --node {name}: no such node enrolled", r.run));
                continue;
            };
            let l = env.ledger();
            // `place::refuse_past_lease` (#324): a placed node past its lease takes no new run.
            let now = now_s();
            let past = l.placed_nodes(&["active"]).expect("placed nodes").into_iter().find(|p| p.name == name && p.lease_until <= now);
            if let Some(p) = past.filter(|_| env.options.refuse_past_lease) {
                env.stat(|s| s.runs_refused += 1);
                env.note(format!("wicket run {} --node {name}: refused, past its lease (ended {})", r.run, p.lease_until));
                continue;
            }
            // `refuse_past_lease`'s answer: the lease's end, which the box's start carries (#395).
            if env.options.start_by {
                if let Some(p) = l.placed_nodes(&["active"]).expect("placed nodes").into_iter().find(|p| p.name == name) {
                    env.ctl.borrow_mut().run_start_by.insert(r.run.clone(), p.lease_until);
                }
            }
            l.run_started(&TenantId(TENANT.into()), &RunId(r.run.clone()), "z", "a").expect("run recorded");
            l.set_run_node(&r.run, &name).expect("its node recorded");
            env.ctl.borrow_mut().run_host.insert(r.run.clone(), host);
            env.stat(|s| s.runs += 1);
            env.note(format!("wicket run {} --node {name}", r.run));
            tokio::task::spawn_local(supervise(env.clone(), r.run.clone(), false));
        }
    }
}

/// A run's feed publisher on its node's feed (`noderun::SharedFeed`): one per run, each use
/// under the feed's lock, reloading the delta log first if another run appended to it, and sharing
/// the last statement time (`feed/issued`) with every other run on the same node.
struct Feed {
    p: Publisher<BoxAuthority>,
    /// The delta log's length when last loaded or written.
    len: u64,
    host: String,
}

fn feed_cfg() -> PublisherConfig {
    PublisherConfig { ttl_ms: FEED_TTL_MS, refresh_ms: FEED_REFRESH_MS, retain: 1000 }
}

impl Feed {
    fn load(env: &Env, host: &str) -> Publisher<BoxAuthority> {
        let dir = env.dir.join("control").join("nodes").join(host).join("feed");
        Publisher::<BoxAuthority>::open_with(
            &dir,
            host,
            &env.feed_root.verifying_key(),
            env.feed_key.clone(),
            &env.cert,
            feed_cfg(),
            env.authz_root.public(),
        )
        .expect("the node's feed")
    }

    fn len(p: &Publisher<BoxAuthority>) -> u64 {
        std::fs::metadata(p.log_path()).map(|m| m.len()).unwrap_or(0)
    }

    fn open(env: &Env, host: &str) -> Feed {
        let p = Feed::load(env, host);
        Feed { len: Feed::len(&p), p, host: host.to_string() }
    }

    /// `SharedFeed::lock`, then `f`, then the guard's drop: current, with the shared time noted
    /// first and saved after.
    fn with<T>(&mut self, env: &Env, f: impl FnOnce(&mut Publisher<BoxAuthority>) -> T) -> T {
        if Feed::len(&self.p) != self.len {
            self.p = Feed::load(env, &self.host);
        }
        let last = env.ctl.borrow().feed_issued.get(&self.host).copied().unwrap_or(i64::MIN);
        self.p.note_issued(last);
        let out = f(&mut self.p);
        self.len = Feed::len(&self.p);
        env.ctl.borrow_mut().feed_issued.insert(self.host.clone(), self.p.last_issued());
        out
    }
}

enum Session {
    /// The box exited: fetch its files.
    Exited,
    /// The node lost the box (or is gone).
    Lost,
    /// The connection dropped: dial again.
    Dropped,
}

/// A run's supervisor (`run.rs` with `noderun.rs`): start (or re-attach to) the box, publish to
/// its node, wait for it to exit, fetch its files, end the run.
async fn supervise(env: Rc<Env>, run: String, attach: bool) {
    let Some(host) = env.ctl.borrow().run_host.get(&run).cloned() else { return };
    let work_s = env.plan.runs.iter().find(|r| r.run == run).map(|r| r.work_s).unwrap_or(60);
    let mut feed = Feed::open(&env, &host);
    let mut started = attach;
    let mut failures = 0;
    loop {
        match session(&env, &run, &host, work_s, &mut feed, &mut started).await {
            Session::Exited => break,
            Session::Lost => return end_run(&env, &run, "lost", "its node no longer has its box"),
            // `wicket run --node` reaches its node once to start the box: if it can't, the run
            // fails; only a started box is waited for across cut-offs.
            Session::Dropped if !started => {
                // A box the node started though its answer was lost is the reconciler's box pass's
                // to stop (`judge_box`: its run has ended), not modelled here.
                env.world.lock().expect("world").abandoned.insert(run.clone());
                return end_run(&env, &run, "failed", "its node can't be reached to start its box");
            }
            Session::Dropped => {
                failures += 1;
                // The node was released (its enrolment is gone): nothing will answer again.
                let enrolled = env.ctl.borrow().enrolled.values().any(|h| *h == host);
                if !enrolled && failures > 3 {
                    return end_run(&env, &run, "lost", "its node is gone");
                }
                tokio::time::sleep(secs(POLL_S)).await;
            }
        }
    }
    // `fetch_trees`: the node keeps the files unless they all come back.
    let fetched = fetch(&env, &run, &host).await;
    let expected = {
        let w = env.world.lock().expect("world");
        w.machines[machine_index(&host)].boxes.get(&run).map(|b| b.files(b.until))
    };
    match fetched {
        Some(files) if Some(&files) == expected.as_ref() => {
            env.world.lock().expect("world").collected.insert(run.clone());
            env.stat(|s| s.fetched += 1);
            env.note(format!("{run}: fetched {} files from {host}", files.len()));
            // `run.rs`: the collection is on the ledger before the node may delete the files.
            let _ = env.ledger().record_collected(&run, "fetched");
            forget(&env, &run, &host).await;
            end_run(&env, &run, "succeeded", "")
        }
        Some(files) => {
            env.violate(format!(
                "{run}: the fetch from {host} brought back {} files, not its own {:?}",
                files.len(),
                expected.map(|e| e.len())
            ));
            end_run(&env, &run, "failed", "fetched the wrong files")
        }
        None => {
            env.stat(|s| s.fetch_failed += 1);
            let l = env.ledger();
            let _ = l.audit(
                &TenantId(TENANT.into()),
                Some(&RunId(run.clone())),
                "run.fetch_failed",
                &serde_json::json!({ "node": node_name(&env, &host), "error": "unreachable" }),
            );
            // The run holds its node until they are collected (#324).
            let _ = l.set_run_uncollected(&run, Some(&node_name(&env, &host)));
            env.note(format!("{run}: fetching its files from {host} failed (the node keeps them)"));
            end_run(&env, &run, "failed", &format!("failed (fetching its files from node {host})"))
        }
    }
}

fn node_name(env: &Env, host: &str) -> String {
    env.ctl.borrow().enrolled.iter().find(|(_, h)| *h == host).map(|(n, _)| n.clone()).unwrap_or_else(|| {
        // Released since: the name it was recorded under.
        let w = env.world.lock().expect("world");
        w.machines[machine_index(host)].inst.as_ref().map(|n| n.name.clone()).unwrap_or_default()
    })
}

fn end_run(env: &Env, run: &str, status: &str, detail: &str) {
    let _ = env.ledger().run_ended(&RunId(run.into()), status, detail);
    env.note(format!("{run} ends {status}"));
}

type Conn = (turmoil::net::tcp::OwnedReadHalf, turmoil::net::tcp::OwnedWriteHalf);

async fn dial(run: &str, host: &str) -> Option<(Conn, wicket_feed::Hello)> {
    let s = tokio::time::timeout(secs(SILENCE_S), turmoil::net::TcpStream::connect((host, PORT))).await.ok()?.ok()?;
    let (mut rd, mut wr) = s.into_split();
    wire::write_json(&mut wr, &Up::Hello { run: run.into() }).await.ok()?;
    match tokio::time::timeout(secs(SILENCE_S), wire::read_frame(&mut rd)).await {
        Ok(Ok(Some((wire::KIND_MSG, b)))) => match wire::parse::<Down>(&b) {
            Ok(Down::Hello { hello }) => Some(((rd, wr), hello)),
            _ => None,
        },
        _ => None,
    }
}

async fn call(c: &mut Conn, req: &Up) -> Option<Down> {
    wire::write_json(&mut c.1, req).await.ok()?;
    match tokio::time::timeout(secs(SILENCE_S), wire::read_frame(&mut c.0)).await {
        Ok(Ok(Some((wire::KIND_MSG, b)))) => wire::parse::<Down>(&b).ok(),
        _ => None,
    }
}

async fn session(env: &Rc<Env>, run: &str, host: &str, work_s: i64, feed: &mut Feed, started: &mut bool) -> Session {
    let Some((mut c, hello)) = dial(run, host).await else { return Session::Dropped };
    let frames = match feed.with(env, |p| p.catch_up(&hello, feed_now())) {
        Ok(f) => f,
        Err(e) => {
            env.note(format!("{run}: catch-up refused: {e}"));
            return Session::Dropped;
        }
    };
    for f in frames {
        if wire::write_frame(&mut c.1, wire::KIND_FEED, f.to_line().as_bytes()).await.is_err() {
            return Session::Dropped;
        }
    }
    if !*started {
        // The box's token goes on its node's feed before the box starts (`noderun`'s `PutZone`).
        let record = env.issuers[run].publish(&env.approver, &[]).expect("the box's token");
        let f = match feed.with(env, |p| p.commit(vec![Change::PutZone { zone: record }], feed_now())) {
            Ok(f) => f,
            Err(e) => {
                env.violate(format!("{run}: its token can't be published: {e}"));
                return Session::Lost;
            }
        };
        if wire::write_frame(&mut c.1, wire::KIND_FEED, f.to_line().as_bytes()).await.is_err() {
            return Session::Dropped;
        }
        let start_by = env.ctl.borrow().run_start_by.get(run).copied();
        match call(&mut c, &Up::Start { work_s, start_by }).await {
            Some(Down::Started { ok: true }) => *started = true,
            Some(_) => return Session::Lost,
            None => return Session::Dropped,
        }
    }
    loop {
        tokio::time::sleep(secs(POLL_S)).await;
        if let Some(f) = feed.with(env, |p| p.tick(feed_now())) {
            if wire::write_frame(&mut c.1, wire::KIND_FEED, f.to_line().as_bytes()).await.is_err() {
                return Session::Dropped;
            }
        }
        match call(&mut c, &Up::Status).await {
            Some(Down::Running) => {}
            Some(Down::Exited) => {
                // The box's token leaves the feed at its exit (`noderun`'s `DropZone`).
                if let Ok(f) = feed.with(env, |p| p.commit(vec![Change::DropZone { name: run.to_string() }], feed_now())) {
                    let _ = wire::write_frame(&mut c.1, wire::KIND_FEED, f.to_line().as_bytes()).await;
                }
                return Session::Exited;
            }
            Some(Down::Unknown) => return Session::Lost,
            _ => return Session::Dropped,
        }
    }
}

async fn fetch(env: &Rc<Env>, run: &str, host: &str) -> Option<Vec<String>> {
    let _ = env;
    let get = async {
        let (mut c, _) = dial(run, host).await?;
        match call(&mut c, &Up::Fetch).await? {
            Down::Files { files } => files,
            _ => None,
        }
    };
    tokio::time::timeout(secs(FETCH_S), get).await.ok().flatten()
}

async fn forget(env: &Rc<Env>, run: &str, host: &str) {
    let _ = env;
    if let Some((mut c, _)) = dial(run, host).await {
        let _ = call(&mut c, &Up::Forget).await;
    }
}

/// `wicket reconcile --every 30s`.
async fn reconciler(env: Rc<Env>) {
    loop {
        tokio::time::sleep(secs(PASS_S)).await;
        reconcile_pass(&env).await;
    }
}

/// One pass: the machine half, then the placed nodes' half (#294).
async fn reconcile_pass(env: &Rc<Env>) {
    let now = now_s();
    let mut ledger = env.ledger();
    let owner = Owner::new(OWNER);
    // `place::release_placer`: no spend is approved on this path.
    let placer = Placer::new(env.cloud(), wicket_placement::envelope::DenyAll, owner.clone(), env.envelope()).with_clock(clock());

    // `reconcile_machines`, with no capacity leases: owned nodes no placed node records go.
    let observed = match placer.list().await {
        Ok(o) => o,
        Err(e) => return env.note(format!("reconcile: listing the provider's owned nodes: {e}")),
    };
    let placed: BTreeSet<String> = ledger.placed_nodes(&[]).expect("placed nodes").into_iter().map(|p| p.id).collect();
    let observed: Vec<NodeHandle> = observed.into_iter().filter(|n| !placed.contains(&n.id.0)).collect();
    for a in plan::reconcile(&owner, &[], &observed, now, false, &PoolRules::default()) {
        // `reconcile_machines`: nothing records it, and it is new, so its creator may not have
        // recorded it yet (#324). (No capacity leases here: no lease records any node.)
        if let (plan::Action::Destroy { node, .. }, true) = (&a, env.options.young_grace) {
            if let Some(until) = observed.iter().find(|n| n.id == *node).and_then(|n| plan::too_new_to_judge(n, now)) {
                env.note(format!("reconcile.young {node} until {until}"));
                continue;
            }
        }
        if let plan::Action::Destroy { node, reason } = a {
            match placer.release(&node, ReleaseMode::Now).await {
                Ok(r) => {
                    env.stat(|s| s.destroyed_unrecorded += 1);
                    env.note(format!("reconcile.destroyed {node} {reason:?} ({r:?})"));
                }
                Err(e) => env.note(format!("reconcile: destroying {node}: {e}")),
            }
        }
    }
    for line in placed_pass(env, &mut ledger, &placer, now).await {
        env.note(line);
    }
}

/// `reconcile::placed_pass` (#294): every active placed node past its lease is released if no
/// run holds it, and otherwise kept and flagged.
async fn placed_pass<A: SpendApprover>(env: &Rc<Env>, ledger: &mut Ledger, placer: &Placer<Cloud, A>, now: i64) -> Vec<String> {
    let mut done = vec![];
    let rows = ledger.placed_nodes(&["active"]).expect("placed nodes");
    for row in rows.into_iter().filter(|r| Owner::new(&r.owner) == *placer.owner() && r.backend == placer.provider().id()) {
        if row.lease_until > now {
            continue;
        }
        let mut holders = ledger.running_runs_on_node(&row.name).expect("runs on the node");
        // Runs whose files a fetch didn't bring back hold it too (#300, #324).
        let uncollected = match env.options.hold_uncollected {
            true => ledger.uncollected_runs_on_node(&row.name).expect("uncollected runs"),
            false => vec![],
        };
        for r in uncollected {
            if !holders.contains(&r) {
                holders.push(r);
            }
        }
        holders.sort();
        if !holders.is_empty() {
            let runs = holders.join(",");
            if ledger.set_placed_node_held(&row.id, Some(&runs)).expect("held") {
                env.stat(|s| s.held += 1);
                done.push(format!("reconcile.placed_held {} by {runs}", row.name));
            }
            continue;
        }
        let why = format!("its lease ended at {} and no run is placed on it", row.lease_until);
        let node = match placer.get(&NodeId(row.id.clone())).await {
            Ok(n) => n,
            Err(e) => {
                done.push(format!("reconcile.error reading placed node {}: {e}", row.name));
                continue;
            }
        };
        match placer.release(&NodeId(row.id.clone()), ReleaseMode::Now).await {
            Ok(r) => {
                let gone = r == Released::AlreadyGone || node.is_none();
                ledger.placed_node_ended(&row.id, "released", &why).expect("ended");
                // `place::retire_enrolment`.
                env.ctl.borrow_mut().enrolled.remove(&row.name);
                env.stat(|s| s.released += 1);
                done.push(format!("reconcile.placed_released {}: {why}{}", row.name, if gone { "; already gone" } else { "" }));
            }
            Err(e @ (PlacementError::NotOwned(_) | PlacementError::Protected(_))) => {
                ledger.placed_node_ended(&row.id, "left", &e.to_string()).expect("ended");
                done.push(format!("reconcile.refused {}: {e}", row.name));
            }
            Err(e) => done.push(format!("reconcile.error releasing {}: {e}", row.name)),
        }
    }
    let _ = PROTECTED_TAG;
    done
}

// ---- the run ----

/// How a run is made. Each fix this scenario found (#324) can be turned off, to show it still finds
/// what it fixed (`tests/scenario.rs`).
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub keep_trace: bool,
    /// `wicket run --node` refuses a placed node past its lease (`place::refuse_past_lease`).
    pub refuse_past_lease: bool,
    /// The box's start carries its node's lease end, and the node refuses a start past it
    /// (`BoxStart::start_by`, #395). Off: only the check when the run begins, which races the start.
    pub start_by: bool,
    /// A run whose files a fetch didn't bring back holds its node (`runs.uncollected`).
    pub hold_uncollected: bool,
    /// The machine half leaves a node nothing records alone while it is new
    /// (`reconcile::too_new_to_judge`).
    pub young_grace: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options { keep_trace: false, refuse_past_lease: true, start_by: true, hold_uncollected: true, young_grace: true }
    }
}

/// Runs the placement scenario for `seed`, with the hosts' directories under `dir` (removed after).
pub fn run(seed: u64, dir: &Path, options: Options) -> Report {
    let plan = Plan::new(seed);
    let dir = dir.join(format!("placement-{seed}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the simulation's directory");
    let mut keys = Rng::new(seed ^ 0x6b65_7973).fork();
    let feed_root = ed25519_dalek::SigningKey::from_bytes(&keys.bytes32());
    let feed_key = ed25519_dalek::SigningKey::from_bytes(&keys.bytes32());
    let cert = wicket_feed::sign(
        &feed_root,
        wicket_feed::TYP_KEY,
        &wicket_feed::KeyCert::new(&feed_key.verifying_key(), 1, (EPOCH_S + 2 * END_S) * 1000, FEED_TTL_MS * 4),
    );
    let zone: ZoneSpec = serde_json::from_value(serde_json::json!({ "name": "z" })).expect("a zone");
    let authz_root = wicket_authz::SigningKey::from_bytes(&keys.bytes32()).expect("an authority root");
    let approver = wicket_authz::SigningKey::from_bytes(&keys.bytes32()).expect("an approver key");
    let exp = (EPOCH_S + 2 * END_S) as u64;
    let issuers: BTreeMap<String, Issuer> = plan
        .runs
        .iter()
        .map(|r| {
            let i = Issuer::root(&authz_root, TENANT, "trigger:sim", &r.run, 0, &zone, &[], exp, vec![approver.public()])
                .expect("a box's token");
            (r.run.clone(), i)
        })
        .collect();
    let world = Arc::new(Mutex::new(World {
        machines: (0..MACHINES).map(|_| Machine::default()).collect(),
        rng: Rng::new(seed ^ 0x0063_6c6f_7564),
        next_id: 0,
        trace: Trace::new(EPOCH_S, options.keep_trace),
        stats: Stats::default(),
        collected: BTreeSet::new(),
        max_total: plan.max_total,
        cloud_latency_s: plan.cloud_latency_s,
        control_up_at: EPOCH_S,
        control_down: false,
        abandoned: BTreeSet::new(),
    }));
    let env = Rc::new(Env {
        plan: plan.clone(),
        dir: dir.clone(),
        world: world.clone(),
        ctl: Rc::new(RefCell::new(CtlDisk::default())),
        feed_root,
        feed_key,
        cert,
        zone,
        options,
        authz_root,
        approver,
        issuers,
    });
    let mut sim = turmoil::Builder::new()
        .epoch(UNIX_EPOCH)
        .simulation_duration(Duration::from_millis(END_S as u64 + 1))
        .min_message_latency(Duration::from_millis(1))
        .max_message_latency(Duration::from_millis(plan.max_latency_s))
        .rng_seed(seed)
        .build();
    let e = env.clone();
    sim.host("control", move || control(e.clone()));
    for k in 0..MACHINES {
        let e = env.clone();
        sim.host(format!("m{k}"), move || machine(e.clone(), k));
    }
    // The simulation runs until every client is done: this one is the scenario's length.
    sim.client("operator", async {
        tokio::time::sleep(secs(END_S)).await;
        Ok(())
    });

    let mut actions: Vec<(i64, usize, Action)> = vec![];
    for (n, f) in plan.faults.iter().enumerate() {
        let (start, end) = match &f.kind {
            FaultKind::Partition { machine } => (Action::Hold(*machine), Action::Release(*machine)),
            FaultKind::ControlCrash => (Action::Crash(None), Action::Bounce(None)),
            FaultKind::ServeCrash { machine } => (Action::Crash(Some(*machine)), Action::Bounce(Some(*machine))),
        };
        actions.push((f.at, 2 * n, start));
        actions.push((f.at + f.dur, 2 * n + 1, end));
    }
    actions.sort_by_key(|(t, n, _)| (*t, *n));
    let mut next = 0;
    let mut host_error = None;
    let mut steps = 0u64;
    loop {
        let now = EPOCH_S + sim.elapsed().as_millis() as i64;
        while next < actions.len() && EPOCH_S + actions[next].0 <= now {
            let a = &actions[next].2;
            world.lock().expect("world").trace.note(now, format!("fault {a:?}"));
            let host = |m: Option<usize>| m.map_or("control".to_string(), |k| format!("m{k}"));
            match *a {
                Action::Hold(k) => sim.hold("control", format!("m{k}")),
                Action::Release(k) => sim.release("control", format!("m{k}")),
                Action::Crash(m) => {
                    if m.is_none() {
                        world.lock().expect("world").control_down = true;
                    }
                    sim.crash(host(m))
                }
                Action::Bounce(m) => sim.bounce(host(m)),
            }
            next += 1;
        }
        steps += 1;
        if steps.is_multiple_of(10) {
            world.lock().expect("world").check_leases(now);
        }
        if now >= EPOCH_S + END_S {
            break;
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
    let now = EPOCH_S + sim.elapsed().as_millis() as i64;
    drop(sim);
    let started: BTreeSet<String> = env.ctl.borrow().run_host.keys().cloned().collect();
    let _ = std::fs::remove_dir_all(&dir);
    let mut w = world.lock().expect("world");
    w.check_leases(now);
    w.check_end(now, &started);
    if let Some(e) = host_error {
        w.trace.violations.push(format!("a host failed: {e}"));
    }
    Report {
        scenario: "placement",
        seed,
        plan: plan.to_string(),
        violations: w.trace.violations.clone(),
        known: vec![],
        hash: w.trace.hash(),
        stats: format!("{:?}", w.stats),
        trace: w.trace.lines().to_vec(),
    }
}

#[derive(Debug)]
enum Action {
    Hold(usize),
    Release(usize),
    Crash(Option<usize>),
    Bounce(Option<usize>),
}
