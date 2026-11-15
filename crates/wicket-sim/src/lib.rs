//! Deterministic simulation of wicket's control host, a node and its boxes (#324, first slice).
//!
//! One process runs a control host, one node and two box stubs as [turmoil] hosts, on a simulated
//! network and clock. Faults come from a seed: partitions (a held link, as TCP stalls), node and
//! control-host crashes and restarts, delays, and clock skew. An [`oracle`] checks #321's invariants
//! as the hosts act. A failing seed replays exactly ([`replay_command`]).
//!
//! **What is real and what stands in.** The decisions and the accounting are wicket's own code:
//! - the feed: [`wicket_feed::Publisher`] of [`wicket_feed::BoxAuthority`] records on the control
//!   host, persisted to its directory, and [`wicket_feed::Replica`] on the node, persisted to its
//!   own and reopened after a crash;
//! - the box's authority: Biscuit tokens minted by [`wicket_feed::Issuer`], and grants as their
//!   third-party blocks, published and revoked as `noderun.rs` does;
//! - the decide path: `Replica::<BoxAuthority>::decide`, the node's only decision path (#257);
//! - the model budget: [`wicket_proxy::llm::Llm`] on both sides. On the node it is the box's model
//!   proxy, with its slice; on the control host it is the run's counter, which leases the slices
//!   ([`wicket_proxy::llm::Llm::next_slice`] and [`wicket_proxy::llm::Slice::renewed`], the rule
//!   `noderun::slice_due` uses). Each call goes through the proxy's own admit, reserve and settle
//!   (`Llm::sim_begin`, `Llm::sim_settle`: the `sim` feature's seam).
//!
//! The hosts' run loops are stand-ins, written to follow `wicket-cli`'s `noderun.rs` (control
//! host) and `nodesrv.rs` (node). Those files open unix sockets and docker themselves, and live in
//! the CLI binary. The stand-ins keep what those loops persist: the node's spend file, written
//! before each model call goes upstream and every second, and its slices, written as they arrive. A box stub stands in for the box
//! and its proxies' sockets, and the stand-in upstream bills each call it serves. See [`control`],
//! [`node`] and [`boxes`].
//!
//! The clock: every host reads the simulation's epoch-based time, plus its own skew (the node's is
//! up to ±[`MAX_SKEW_MS`]). wicket-feed takes `now` from its caller, so nothing in it reads the OS
//! clock. Randomness: the plan, the boxes' requests and the upstream's usage come from [`rng::Rng`]
//! seeded by the seed. Keys are derived from it too. Biscuit's per-block ephemeral keys come from
//! the OS, which changes bytes, not decisions: the trace hash checks that ([`Report::hash`]).

pub mod boxes;
pub mod control;
pub mod node;
pub mod oracle;
pub mod placement;
pub mod rng;
pub mod trace;
pub mod wire;

use oracle::Oracle;
use rng::Rng;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};
use wicket_core::ZoneSpec;
use wicket_feed::Issuer;
use wicket_proxy::llm::ModelQuota;

/// The simulation's epoch (Unix ms): time 0 of every run.
pub const EPOCH_MS: i64 = 1_800_000_000_000;
/// How long the boxes keep working (simulated ms). The hosts stop with them.
pub const DURATION_MS: i64 = 60_000;
/// The feed's freshness TTL and refresh, scaled down as in wicket-feed's tests.
pub const TTL_MS: i64 = 3_000;
pub const REFRESH_MS: i64 = 500;
/// The node's clock is off the control host's by at most this much.
pub const MAX_SKEW_MS: i64 = 400;
/// A channel that hears nothing for this long is dropped and redialled (ssh's keepalive).
pub const SILENCE_MS: u64 = 2_000;
/// The node feed's name, the node's name.
pub const NODE: &str = "n1";
pub const TENANT: &str = "t_sim";
/// The boxes' runs.
pub const RUNS: [&str; 2] = ["run_a", "run_b"];
/// The ports the stand-ins listen on: the control host's channel, the node's box sockets.
pub const CONTROL_PORT: u16 = 7000;
pub const NODE_PORT: u16 = 8000;

/// The ops a box makes, by path: reads its zone reaches, three comments that need a grant, a
/// webhook no grant ever covers, and a forbidden host.
pub const READ_PATH: &str = "/repos/acme/app/issues";
pub const GRANT_PATHS: [&str; 3] =
    ["/repos/acme/app/issues/1/comments", "/repos/acme/app/issues/2/comments", "/repos/acme/app/issues/3/comments"];
pub const NEVER_PATH: &str = "/repos/acme/app/hooks";
pub const HOST: &str = "api.github.com";
pub const FORBIDDEN_HOST: &str = "evil.example.com";

/// The command that replays `seed`, printed with every failure.
pub fn replay_command(seed: u64) -> String {
    format!("WICKET_SIM_SEED={seed} cargo test -p wicket-sim --test scenario replay -- --nocapture")
}

/// What the scenario does to the system, all of it from the seed.
#[derive(Clone, Debug)]
pub struct Plan {
    pub seed: u64,
    /// The node's clock, ahead (+) or behind (−) the control host's.
    pub node_skew_ms: i64,
    /// The links' normal latency bound (each message takes 1..= this many ms).
    pub max_latency_ms: u64,
    pub faults: Vec<Fault>,
    pub grants: Vec<GrantAction>,
}

#[derive(Clone, Debug)]
pub struct Fault {
    pub at_ms: i64,
    pub dur_ms: i64,
    pub kind: FaultKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// The control host and the node can't reach each other: their link holds every message, as a
    /// stalled TCP connection would, and delivers it when the link heals.
    Partition,
    /// `wicket node serve` crashes, and restarts after the fault.
    NodeCrash,
    /// The control host crashes, and restarts after the fault.
    ControlCrash,
    /// The control host ↔ node link slows to this many ms per message: delays, and reordering
    /// against the boxes' links.
    Delay { max_ms: u64 },
    /// One box's link to its node holds its messages.
    BoxHold { run: usize },
}

#[derive(Clone, Debug)]
pub struct GrantAction {
    pub at_ms: i64,
    pub run: usize,
    /// Which of [`GRANT_PATHS`].
    pub path: usize,
    pub gid: String,
    pub kind: GrantKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantKind {
    /// Approved, for this many seconds from when the control host publishes it.
    Issue {
        lifetime_s: u64,
    },
    /// Renewed (#56): the same grant, published with a lifetime this many seconds from then.
    Renew {
        lifetime_s: u64,
    },
    Revoke,
}

impl Plan {
    pub fn new(seed: u64) -> Plan {
        let mut r = Rng::new(seed);
        let node_skew_ms = r.range_i(-MAX_SKEW_MS, MAX_SKEW_MS);
        let max_latency_ms = r.range(1, 40);
        let mut faults = vec![];
        let mut t = r.range_i(1_000, 4_000);
        while t < DURATION_MS - 4_000 {
            let (kind, dur) = match r.range(0, 9) {
                0..=2 => (FaultKind::Partition, r.range_i(500, 12_000)),
                3..=4 => (FaultKind::NodeCrash, r.range_i(50, 3_000)),
                5 => (FaultKind::ControlCrash, r.range_i(50, 3_000)),
                6..=7 => (FaultKind::Delay { max_ms: r.range(100, 1_500) }, r.range_i(1_000, 8_000)),
                _ => (FaultKind::BoxHold { run: r.range(0, 1) as usize }, r.range_i(200, 4_000)),
            };
            faults.push(Fault { at_ms: t, dur_ms: dur, kind });
            t += dur + r.range_i(200, 6_000);
        }
        let mut grants = vec![];
        for (run, name) in RUNS.iter().enumerate() {
            for path in 0..GRANT_PATHS.len() {
                if !r.chance(0.8) {
                    continue;
                }
                let gid = format!("g_{name}_{path}");
                let at = r.range_i(0, DURATION_MS - 15_000);
                let lifetime_s = r.range(2, 15);
                grants.push(GrantAction { at_ms: at, run, path, gid: gid.clone(), kind: GrantKind::Issue { lifetime_s } });
                let end = at + lifetime_s as i64 * 1000;
                if r.chance(0.4) {
                    let at = r.range_i(at + 500, end);
                    grants.push(GrantAction {
                        at_ms: at,
                        run,
                        path,
                        gid: gid.clone(),
                        kind: GrantKind::Renew { lifetime_s: r.range(2, 15) },
                    });
                }
                if r.chance(0.5) {
                    grants.push(GrantAction { at_ms: r.range_i(at + 100, end + 3_000), run, path, gid, kind: GrantKind::Revoke });
                }
            }
        }
        grants.sort_by_key(|g| g.at_ms);
        Plan { seed, node_skew_ms, max_latency_ms, faults, grants }
    }
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "seed {}: node clock skew {} ms, link latency 1..={} ms", self.seed, self.node_skew_ms, self.max_latency_ms)?;
        for x in &self.faults {
            writeln!(f, "  fault at {} ms for {} ms: {:?}", x.at_ms, x.dur_ms, x.kind)?;
        }
        for g in &self.grants {
            writeln!(f, "  grant at {} ms: {} ({} {}) {:?}", g.at_ms, g.gid, RUNS[g.run], GRANT_PATHS[g.path], g.kind)?;
        }
        Ok(())
    }
}

/// What one run found.
#[derive(Debug)]
pub struct Report {
    pub seed: u64,
    pub plan: Plan,
    pub violations: Vec<String>,
    /// A hash of the whole trace (every decision, publication, bill): equal for equal seeds.
    pub hash: u64,
    pub stats: oracle::Stats,
    pub billed: BTreeMap<String, oracle::Billed>,
    pub trace: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.violations.is_empty()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.plan)?;
        writeln!(f, "  stats: {:?}", self.stats)?;
        writeln!(f, "  billed: {:?}", self.billed)?;
        writeln!(f, "  trace hash: {:016x}", self.hash)?;
        for v in &self.violations {
            writeln!(f, "  VIOLATION {v}")?;
        }
        if !self.ok() {
            writeln!(f, "  replay: {}", replay_command(self.seed))?;
        }
        Ok(())
    }
}

/// The fraction of the budget leased per slice (`WICKET_NODE_BUDGET_SLICE`'s default).
pub const SLICE_FRACTION: f64 = 0.25;

/// The run's model budget: the zone's, and the amounts of its quota grants (#256).
pub const QUOTA: ModelQuota = ModelQuota { requests: 40, output_tokens: 12_000, input_tokens: None };

/// What every host shares: keys and records made at installation (on disk in production), the
/// plan, the hosts' disks, and the oracle.
pub struct Env {
    pub plan: Plan,
    pub dir: PathBuf,
    pub feed_root: ed25519_dalek::SigningKey,
    pub feed_key: ed25519_dalek::SigningKey,
    pub cert: String,
    pub authz_root: wicket_authz::SigningKey,
    pub approver: wicket_authz::SigningKey,
    pub zone: ZoneSpec,
    pub issuers: BTreeMap<String, Issuer>,
    pub oracle: Rc<RefCell<Oracle>>,
    pub control_disk: Rc<RefCell<control::Disk>>,
    /// Shared with the model proxies' journals, which must be `Send`.
    pub node_disk: std::sync::Arc<std::sync::Mutex<node::Disk>>,
    /// The options the run was made with.
    pub options: Options,
    /// The stand-in upstream's choices (output tokens per call, its latency).
    pub upstream: Rc<RefCell<Rng>>,
}

/// The run's zone: reads on acme's repos by reach, the comment paths by grant, a forbidden host,
/// and a model route with [`QUOTA`].
pub fn zone() -> ZoneSpec {
    serde_json::from_value(serde_json::json!({
        "name": "z",
        "reach": [{"host": HOST, "methods": ["GET"], "paths": ["/repos/acme/**"]}],
        "forbid": [{"host": FORBIDDEN_HOST}],
        "llm": {
            "provider": "anthropic",
            "secret": "model",
            "upstream": "https://api.anthropic.com",
            "max_requests": QUOTA.requests,
            "max_output_tokens": QUOTA.output_tokens,
        },
    }))
    .expect("the zone parses")
}

/// A run's context for its model proxy: the zone, and nothing else the accounting reads.
pub fn run_ctx(run: &str, zone: &ZoneSpec) -> wicket_proxy::RunCtx {
    use std::sync::{Arc, Mutex};
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    wicket_proxy::RunCtx {
        tenant: wicket_core::TenantId(TENANT.into()),
        run: wicket_core::RunId(run.into()),
        zone: Arc::new(wicket_core::CompiledZone::new(zone.clone()).expect("the zone compiles")),
        org: None,
        ledger: Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().expect("an in-memory ledger"))),
        vault: wicket_proxy::vault::Vault::new(std::env::temp_dir().join("wicket-sim-no-vault")),
        events: tx,
        escalate: true,
        attribute: None,
        identity: None,
        spawner: None,
        swaps: vec![],
        boxes: None,
        capacity: None,
        decisions: None,
        fence: None,
        waker: None,
        lifecycle: None,
    }
}

/// The simulation's true time (Unix ms), inside a host: no skew.
pub fn true_now() -> i64 {
    turmoil::since_epoch().map(|d| d.as_millis() as i64).unwrap_or(EPOCH_MS)
}

/// How a run is made.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Keep the whole trace in the report (for a replay).
    pub keep_trace: bool,
    /// The node persists its spend before each model call goes upstream (`Llm::set_journal`, as
    /// `nodesrv` does since #324). Off: only the one-second spend file, as before. The simulation
    /// then finds the overspend that journal fixes (`tests/scenario.rs`).
    pub spend_journal: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options { keep_trace: false, spend_journal: true }
    }
}

/// Runs the scenario for `seed`, with the hosts' directories under `dir` (removed after).
pub fn run(seed: u64, dir: &Path) -> Report {
    run_with(seed, dir, Options::default())
}

/// As [`run`], with `options`.
pub fn run_with(seed: u64, dir: &Path, options: Options) -> Report {
    let keep_trace = options.keep_trace;
    let plan = Plan::new(seed);
    let dir = dir.join(format!("seed-{seed}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the simulation's directory");
    let mut keys = Rng::new(seed).fork();
    let feed_root = ed25519_dalek::SigningKey::from_bytes(&keys.bytes32());
    let feed_key = ed25519_dalek::SigningKey::from_bytes(&keys.bytes32());
    let authz_root = wicket_authz::SigningKey::from_bytes(&keys.bytes32()).expect("an authority root");
    let approver = wicket_authz::SigningKey::from_bytes(&keys.bytes32()).expect("an approver key");
    let cert = wicket_feed::sign(
        &feed_root,
        wicket_feed::TYP_KEY,
        &wicket_feed::KeyCert::new(&feed_key.verifying_key(), 1, EPOCH_MS + 86_400_000, 30_000),
    );
    let zone = zone();
    let mut issuers = BTreeMap::new();
    for run in RUNS {
        let i =
            Issuer::root(&authz_root, TENANT, "trigger:sim", run, 0, &zone, &[], (EPOCH_MS / 1000) as u64 + 3_600, vec![approver.public()])
                .expect("a box's token");
        issuers.insert(run.to_string(), i);
    }
    let mut rngs = Rng::new(seed.rotate_left(17)).fork();
    let env = Rc::new(Env {
        plan: plan.clone(),
        dir: dir.clone(),
        feed_root,
        feed_key,
        cert,
        authz_root,
        approver,
        zone,
        issuers,
        oracle: Rc::new(RefCell::new(Oracle::new(QUOTA, TTL_MS, MAX_SKEW_MS, keep_trace))),
        control_disk: Rc::new(RefCell::new(control::Disk::default())),
        node_disk: Default::default(),
        options,
        upstream: Rc::new(RefCell::new(rngs.fork())),
    });

    let mut sim = turmoil::Builder::new()
        .epoch(UNIX_EPOCH + Duration::from_millis(EPOCH_MS as u64))
        .simulation_duration(Duration::from_millis((DURATION_MS + 30_000) as u64))
        .min_message_latency(Duration::from_millis(1))
        .max_message_latency(Duration::from_millis(plan.max_latency_ms))
        .rng_seed(seed)
        .build();
    let e = env.clone();
    sim.host("control", move || control::run(e.clone()));
    let e = env.clone();
    sim.host("node", move || node::run(e.clone()));
    for (i, run) in RUNS.iter().enumerate() {
        sim.client(*run, boxes::run(env.clone(), i, rngs.fork()));
    }

    // The faults, as timed actions on the simulation.
    let mut actions: Vec<(i64, usize, Action)> = vec![];
    for (n, f) in plan.faults.iter().enumerate() {
        let (start, end) = match &f.kind {
            FaultKind::Partition => (Action::Hold("control", "node"), Action::Release("control", "node")),
            FaultKind::NodeCrash => (Action::Crash("node"), Action::Bounce("node")),
            FaultKind::ControlCrash => (Action::Crash("control"), Action::Bounce("control")),
            FaultKind::Delay { max_ms } => (Action::Latency(*max_ms), Action::Latency(plan.max_latency_ms)),
            FaultKind::BoxHold { run } => (Action::Hold(RUNS[*run], "node"), Action::Release(RUNS[*run], "node")),
        };
        actions.push((f.at_ms, 2 * n, start));
        actions.push((f.at_ms + f.dur_ms, 2 * n + 1, end));
    }
    actions.sort_by_key(|(t, n, _)| (*t, *n));
    let mut next = 0;
    let mut host_error = None;
    loop {
        let now = sim.elapsed().as_millis() as i64;
        while next < actions.len() && actions[next].0 <= now {
            let t = EPOCH_MS + now;
            let a = &actions[next].2;
            env.oracle.borrow_mut().note(t, format!("fault {a:?}"));
            match *a {
                Action::Hold(a, b) => sim.hold(a, b),
                Action::Release(a, b) => sim.release(a, b),
                Action::Crash(h) => sim.crash(h),
                Action::Bounce(h) => sim.bounce(h),
                Action::Latency(ms) => sim.set_link_max_message_latency("control", "node", Duration::from_millis(ms)),
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
    let _ = std::fs::remove_dir_all(&dir);
    let mut o = env.oracle.borrow_mut();
    if let Some(e) = host_error {
        o.violations.push(format!("a host failed: {e}"));
    }
    Report {
        seed,
        plan,
        violations: o.violations.clone(),
        hash: o.hash(),
        stats: o.stats.clone(),
        billed: o.billed.clone(),
        trace: o.trace().to_vec(),
    }
}

#[derive(Debug)]
enum Action {
    Hold(&'static str, &'static str),
    Release(&'static str, &'static str),
    Crash(&'static str),
    Bounce(&'static str),
    Latency(u64),
}

/// Runs `scenario` (one of [`trace::SCENARIOS`]) for `seed`: the first slice's feed and budget
/// scenario ([`run_with`]), [`placement`] or [`messages`].
pub fn run_scenario(scenario: &str, seed: u64, dir: &Path, keep_trace: bool) -> trace::Report {
    match scenario {
        "feed" => {
            let r = run_with(seed, dir, Options { keep_trace, ..Options::default() });
            trace::Report {
                scenario: "feed",
                seed,
                plan: r.plan.to_string(),
                violations: r.violations,
                hash: r.hash,
                stats: format!("{:?}, billed {:?}", r.stats, r.billed),
                trace: r.trace,
            }
        }
        "placement" => placement::run(seed, dir, placement::Options { keep_trace, ..placement::Options::default() }),
        other => panic!("no scenario {other:?}: one of {:?}", trace::SCENARIOS),
    }
}
