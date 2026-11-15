//! `wicket node top` and `wicket top`: a read-only terminal view of what wicket is doing, redrawn
//! every [`REFRESH`] (q or Ctrl-C quits), or one frame with `--once`.
//!
//! - **On a node** (`wicket node top`, as the node's `wicket` user): the node's own status, which
//!   `wicket node serve` answers on its status socket (`ctl/status.sock`, beside the control socket
//!   in the same 0700 directory, [`NodeStatus`]): its identity and CA, its control connections, its
//!   feed, its boxes (state, the node's Llm/budget slice, egress counts, queued asks) and the last
//!   egress decisions, as the run log prints them. To that the viewer adds what it reads itself on the
//!   same machine: load, memory and disk, and each box's CPU and memory from Docker's stats.
//! - **On the control host** (`wicket top`, through wicketd for operators, read-only like `wicket
//!   agents`): every node with what the runs' supervisors last saw of it (`ctl/link.json` beside each
//!   run, [`LinkRecord`]), the running runs and hibernated agents, pending requests and active leases.
//!
//! Nothing here changes anything: the status socket answers one JSON document and closes, and it holds
//! no secrets, request bodies or credentials (names, counts and the clipped decision lines only).
//! Plain ANSI (no TUI framework): the alternate screen, cursor home, clear to end of line. When stdout
//! isn't a terminal, frames are printed as plain text. Every line is cut to the terminal's width.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::path::Path;
use wicket_proxy::llm::{Slice, Spent};

/// How often the view is redrawn.
pub const REFRESH: std::time::Duration = std::time::Duration::from_secs(2);

/// How many egress decisions a node keeps for its view.
pub const RECENT: usize = 10;

/// A node's status, as `wicket node serve` answers it on its status socket.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node: String,
    #[serde(default)]
    pub build: String,
    /// The node's clock (Unix ms).
    pub now_ms: i64,
    /// Its identity (`spiffe://…/node/<name>`) and when its certificate expires (Unix s), or why it
    /// is unusable.
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub identity_until: Option<i64>,
    #[serde(default)]
    pub identity_error: Option<String>,
    /// When its CA certificate expires (Unix s).
    #[serde(default)]
    pub ca_until: Option<i64>,
    pub control: ControlStatus,
    pub feed: FeedStatus,
    pub boxes: Vec<BoxStatus>,
    /// The last egress decisions across its boxes, newest first.
    pub egress: Vec<EgressSeen>,
}

/// The node's control connections: how many are up, and since when (Unix ms) the node has been
/// connected (some are) or cut off (none are); 0: never connected since `serve` started.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ControlStatus {
    pub connections: usize,
    pub since_ms: i64,
}

/// The node's feed replica: its mode (fresh, offline, lagging, closed), epoch, and until when
/// (Unix ms) the last freshness statement vouches for it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FeedStatus {
    pub mode: String,
    #[serde(default)]
    pub epoch: Option<u64>,
    #[serde(default)]
    pub fresh_until_ms: Option<i64>,
}

/// One box on the node.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BoxStatus {
    pub run: String,
    /// Its Docker name (what its stats are read by).
    pub name: String,
    #[serde(default)]
    pub agent: Option<String>,
    pub zone: String,
    /// starting, running, hibernating, stopping or exited.
    pub state: String,
    /// When the node started (or adopted) it (Unix ms).
    pub started_ms: i64,
    pub cpus: f32,
    pub memory_mib: u64,
    /// What its model proxy has counted, and the budget slice it may spend up to.
    pub spent: Spent,
    #[serde(default)]
    pub slice: Option<Slice>,
    /// Egress decisions since this `serve` started: allowed (allowed, spliced or forwarded) and
    /// refused (blocked, denied or stale).
    pub egress_allowed: u64,
    pub egress_refused: u64,
    /// Asks this node holds for its control host: raised while it was unreachable, not yet
    /// delivered (an ask the control host has is in `wicket pending`).
    pub asks: usize,
    /// Its control connection is up.
    pub connected: bool,
}

/// One egress decision, as the run log prints it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EgressSeen {
    pub at_ms: i64,
    pub run: String,
    pub line: String,
}

/// Whether an egress outcome lets the request through, refuses it, or asks a human.
pub fn egress_kind(outcome: &str) -> EgressKind {
    match outcome {
        "allow" | "spliced" | "forwarded" => EgressKind::Allowed,
        "pending" => EgressKind::Asked,
        _ => EgressKind::Refused,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressKind {
    Allowed,
    Refused,
    Asked,
}

/// What `wicket node serve` keeps for its view, beside what it keeps anyway: boxes being started,
/// paused boxes, egress counts per run, the last decisions, and when its control connections last
/// came up or all went. In memory only: a restarted `serve` starts counting again.
#[derive(Default)]
pub struct NodeSeen(std::sync::Mutex<Seen>);

#[derive(Default)]
struct Seen {
    starting: HashMap<String, (String, i64)>,
    paused: std::collections::HashSet<String>,
    egress: HashMap<String, (u64, u64)>,
    recent: std::collections::VecDeque<EgressSeen>,
    connections: usize,
    since_ms: i64,
}

impl NodeSeen {
    fn lock(&self) -> std::sync::MutexGuard<'_, Seen> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A box for `run` in `zone` is being started (until [`NodeSeen::started`]).
    pub fn starting(&self, run: &str, zone: &str, now_ms: i64) {
        self.lock().starting.insert(run.into(), (zone.into(), now_ms));
    }

    pub fn started(&self, run: &str) {
        self.lock().starting.remove(run);
    }

    /// The boxes being started: (run, zone, since ms).
    pub fn being_started(&self) -> Vec<(String, String, i64)> {
        self.lock().starting.iter().map(|(r, (z, t))| (r.clone(), z.clone(), *t)).collect()
    }

    pub fn paused(&self, run: &str, paused: bool) {
        let mut s = self.lock();
        match paused {
            true => s.paused.insert(run.into()),
            false => s.paused.remove(run),
        };
    }

    pub fn is_paused(&self, run: &str) -> bool {
        self.lock().paused.contains(run)
    }

    /// One egress decision for `run`'s box, and its line as the run log prints it.
    pub fn egress(&self, run: &str, outcome: &str, line: String, now_ms: i64) {
        let mut s = self.lock();
        match egress_kind(outcome) {
            EgressKind::Allowed => s.egress.entry(run.into()).or_default().0 += 1,
            EgressKind::Refused => s.egress.entry(run.into()).or_default().1 += 1,
            EgressKind::Asked => {}
        }
        s.recent.push_front(EgressSeen { at_ms: now_ms, run: run.into(), line });
        s.recent.truncate(RECENT);
    }

    /// `run`'s (allowed, refused) egress decisions.
    pub fn counts(&self, run: &str) -> (u64, u64) {
        self.lock().egress.get(run).copied().unwrap_or_default()
    }

    pub fn recent(&self) -> Vec<EgressSeen> {
        self.lock().recent.iter().cloned().collect()
    }

    /// The node now has `n` control connections: the time is kept when it goes from none to some,
    /// or from some to none.
    pub fn connections(&self, n: usize, now_ms: i64) {
        let mut s = self.lock();
        if (s.connections == 0) != (n == 0) {
            s.since_ms = now_ms;
        }
        s.connections = n;
    }

    pub fn control(&self) -> ControlStatus {
        let s = self.lock();
        ControlStatus { connections: s.connections, since_ms: s.since_ms }
    }

    /// Forgets a run whose box is gone.
    pub fn forget(&self, run: &str) {
        let mut s = self.lock();
        s.egress.remove(run);
        s.paused.remove(run);
        s.starting.remove(run);
    }
}

/// The status socket beside a node's control socket.
pub fn status_socket(ctl_socket: &Path) -> std::path::PathBuf {
    ctl_socket.with_file_name("status.sock")
}

/// Reads a node's status from its status socket.
pub async fn read_status(sock: &Path) -> Result<NodeStatus> {
    use tokio::io::AsyncReadExt;
    let fut = async {
        let mut s = tokio::net::UnixStream::connect(sock)
            .await
            .with_context(|| format!("wicket node serve is not answering on {}", sock.display()))?;
        let mut b = vec![];
        (&mut s).take(4 << 20).read_to_end(&mut b).await?;
        serde_json::from_slice::<NodeStatus>(&b).context("the node's status")
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), fut).await.context("the node's status socket did not answer")?
}

/// This machine's load, memory and disk, as the node's view shows them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostStats {
    pub load: [f64; 3],
    pub cpus: usize,
    pub mem_total: u64,
    pub mem_available: u64,
    pub disk_total: u64,
    pub disk_free: u64,
}

impl HostStats {
    /// Read from /proc and the filesystem holding `dir`.
    pub fn read(dir: &Path) -> HostStats {
        let mut h = HostStats { cpus: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1), ..Default::default() };
        if let Ok(s) = std::fs::read_to_string("/proc/loadavg") {
            for (i, v) in s.split_whitespace().take(3).enumerate() {
                h.load[i] = v.parse().unwrap_or(0.0);
            }
        }
        if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
            let kib = |k: &str| {
                s.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok()).unwrap_or(0) << 10
            };
            h.mem_total = kib("MemTotal:");
            h.mem_available = kib("MemAvailable:");
        }
        if let Ok(p) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) {
            // SAFETY: statvfs fills the struct it is given, from a NUL-terminated path.
            let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statvfs(p.as_ptr(), &mut v) } == 0 {
                h.disk_total = v.f_blocks as u64 * v.f_frsize as u64;
                h.disk_free = v.f_bavail as u64 * v.f_frsize as u64;
            }
        }
        h
    }
}

/// One frame of the node's view.
pub struct NodeFrame {
    /// The node's status, or why it couldn't be read.
    pub status: std::result::Result<NodeStatus, String>,
    pub host: HostStats,
    /// Docker's stats, by box name.
    pub stats: HashMap<String, wicket_sandbox::BoxStats>,
    /// The viewer's clock (Unix ms).
    pub now_ms: i64,
}

/// The node's view, `width` columns wide.
pub fn render_node(f: &NodeFrame, width: usize) -> Vec<String> {
    let mut out = vec![];
    let now = f.now_ms;
    let s = match &f.status {
        Ok(s) => s,
        Err(e) => {
            out.push(format!("wicket node top — {}", clock(now)));
            out.push(format!("node: {}", clean(e, 400)));
            out.push(host_line(&f.host));
            return fit_all(out, width);
        }
    };
    out.push(format!("wicket node top — node {} — {}", clean(&s.node, 64), clock(now)));
    let id = match (&s.identity, s.identity_until, &s.identity_error) {
        (_, _, Some(e)) => format!("identity UNUSABLE: {}", clean(e, 120)),
        (Some(id), Some(u), _) => format!("identity {} {}", clean(id, 80), until(u * 1000, now)),
        _ => "identity: no certificate".into(),
    };
    let ca = match s.ca_until {
        Some(u) => format!("CA {}", until(u * 1000, now)),
        None => "CA: none (every host goes to the control host)".into(),
    };
    out.push(format!("{id}   {ca}"));
    let control = match (s.control.connections, s.control.since_ms) {
        (0, 0) => "control: not connected since serve started".to_string(),
        (0, t) => format!("control: CUT OFF since {} ({} ago)", clock(t), dur((now - t) / 1000)),
        (n, t) => format!("control: connected ({n} link{}) since {} ({})", if n == 1 { "" } else { "s" }, clock(t), dur((now - t) / 1000)),
    };
    let feed = match (s.feed.mode.as_str(), s.feed.fresh_until_ms) {
        (m, Some(u)) if u > now => {
            format!("feed {m}, epoch {}, {} left", s.feed.epoch.map_or("-".into(), |e| e.to_string()), dur((u - now) / 1000))
        }
        (m, Some(u)) => format!("feed {m}, epoch {}, stale {}", s.feed.epoch.map_or("-".into(), |e| e.to_string()), dur((now - u) / 1000)),
        (m, None) => format!("feed {m}, nothing vouches for it"),
    };
    out.push(format!("{control}   {feed}"));
    out.push(host_line(&f.host));
    out.push(String::new());
    out.push(format!(
        "{:<12} {:<18} {:<8} {:>6} {:>5} {:>11} {:>5} {:>11} {:>11} {:>8} {:>3}",
        "RUN", "AGENT/ZONE", "STATE", "UP", "CPU%", "MEM/LIMIT", "REQ", "TOK in/out", "SLICE LEFT", "EGR +/-", "ASK"
    ));
    if s.boxes.is_empty() {
        out.push("(no boxes on this node)".into());
    }
    for b in &s.boxes {
        let st = f.stats.get(&b.name);
        let cpu = st.and_then(|x| x.cpu_pct).map_or("-".into(), |c| format!("{c:.1}"));
        let mem = match st {
            Some(x) => format!("{}/{}", bytes(x.memory), bytes(if x.limit > 0 { x.limit } else { b.memory_mib << 20 })),
            None => format!("-/{}", bytes(b.memory_mib << 20)),
        };
        let who = format!("{}/{}", clean(b.agent.as_deref().unwrap_or("-"), 40), clean(&b.zone, 40));
        let state = if b.state == "running" && !b.connected { "running*".to_string() } else { clean(&b.state, 12) };
        out.push(format!(
            "{:<12} {:<18} {:<8} {:>6} {:>5} {:>11} {:>5} {:>11} {:>11} {:>8} {:>3}",
            short_run(&b.run),
            cut(&who, 18),
            cut(&state, 8),
            dur((now - b.started_ms) / 1000),
            cpu,
            mem,
            b.spent.requests,
            format!(
                "{}/{}",
                count(b.spent.input_tokens + b.spent.cache_read_tokens + b.spent.cache_creation_tokens),
                count(b.spent.output_tokens)
            ),
            slice_left(b.slice.as_ref(), &b.spent),
            format!("{}/{}", count(b.egress_allowed), count(b.egress_refused)),
            b.asks,
        ));
    }
    if s.boxes.iter().any(|b| b.state == "running" && !b.connected) {
        out.push("* its control host is not connected: it decides from what the node holds".into());
    }
    out.push(String::new());
    out.push("RECENT EGRESS (newest first)".into());
    if s.egress.is_empty() {
        out.push("(none since serve started)".into());
    }
    for e in s.egress.iter().take(RECENT) {
        out.push(format!("{} {} {}", clock(e.at_ms), short_run(&e.run), clean(&e.line, 600)));
    }
    fit_all(out, width)
}

fn host_line(h: &HostStats) -> String {
    format!(
        "load {:.2} {:.2} {:.2} ({} cpu)   mem {} used of {}   disk {} free of {}",
        h.load[0],
        h.load[1],
        h.load[2],
        h.cpus,
        bytes(h.mem_total.saturating_sub(h.mem_available)),
        bytes(h.mem_total),
        bytes(h.disk_free),
        bytes(h.disk_total)
    )
}

/// What is left of a box's budget slice: requests and output tokens (`-`: no slice; its zone has no
/// budget, or none was leased yet).
fn slice_left(slice: Option<&Slice>, spent: &Spent) -> String {
    match slice {
        Some(s) => format!("{}r/{}", s.requests.saturating_sub(spent.requests), count(s.output_tokens.saturating_sub(spent.output_tokens))),
        None => "-".into(),
    }
}

/// What a run's supervisor on the control host last saw of its node (`ctl/link.json`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LinkRecord {
    pub node: String,
    pub connected: bool,
    /// Since when (Unix ms) it has been connected, or cut off.
    pub since_ms: i64,
    /// What the node last reported the run's box has spent of its model budget.
    #[serde(default)]
    pub spent: Spent,
    /// The node's size and what its boxes were given, at the last connect.
    #[serde(default)]
    pub capacity: Option<crate::chan::NodeCapacity>,
    pub updated_ms: i64,
}

impl LinkRecord {
    pub const FILE: &'static str = "link.json";

    /// Written aside and renamed, in the run's `ctl/` directory.
    pub fn save(&self, run_dir: &Path) {
        let f = run_dir.join("ctl").join(Self::FILE);
        let tmp = f.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec(self).unwrap_or_default()).is_ok() {
            let _ = std::fs::rename(&tmp, &f);
        }
    }

    pub fn load(run_dir: &Path) -> Option<LinkRecord> {
        serde_json::from_slice(&std::fs::read(run_dir.join("ctl").join(Self::FILE)).ok()?).ok()
    }
}

/// One frame of the control host's view.
#[derive(Clone, Debug, Default)]
pub struct ControlFrame {
    pub now_ms: i64,
    pub nodes: Vec<NodeLine>,
    pub runs: Vec<RunLine>,
    pub pending: usize,
    pub leases: Vec<LeaseLine>,
}

#[derive(Clone, Debug, Default)]
pub struct NodeLine {
    pub name: String,
    /// active or revoked.
    pub status: String,
    /// Whether the runs' supervisors are connected to it: Some(connected, since ms), None: no run's
    /// supervisor has talked to it.
    pub link: Option<(bool, i64)>,
    pub boxes: usize,
    pub capacity: Option<crate::chan::NodeCapacity>,
}

#[derive(Clone, Debug, Default)]
pub struct RunLine {
    pub run: String,
    pub node: Option<String>,
    pub agent: String,
    pub zone: String,
    pub status: String,
    pub started_ms: i64,
    pub spent: Option<Spent>,
    pub connected: Option<bool>,
}

#[derive(Clone, Debug, Default)]
pub struct LeaseLine {
    pub id: String,
    pub provider: String,
    pub run: String,
    pub node: Option<String>,
    pub not_after: Option<i64>,
    pub reserved_micro_usd: i64,
}

/// Reads the control host's frame from its ledger and the runs' link records.
pub fn control_frame(l: &wicket_store::Ledger, now_ms: i64) -> Result<ControlFrame> {
    let tenant = wicket_core::TenantId::single();
    let mut f = ControlFrame { now_ms, ..Default::default() };
    let runs_dir = crate::data_dir().join("runs");
    let mut by_node: HashMap<String, (Vec<LinkRecord>, usize)> = HashMap::new();
    let agents = l.agents(&tenant.0)?;
    // A long-lived agent's run on its way to hibernating (or waking) says so.
    let moving: HashMap<&str, &str> = agents
        .iter()
        .filter(|a| matches!(a.state.as_str(), "hibernating" | "waking"))
        .map(|a| (a.run.as_str(), a.state.as_str()))
        .collect();
    for r in l.runs(&tenant, 500)?.into_iter().filter(|r| r.status == "running") {
        let node = l.run_node(&r.id)?;
        let link = crate::run::check_run_id(&r.id).ok().and_then(|_| LinkRecord::load(&runs_dir.join(&r.id)));
        if let Some(n) = &node {
            let e = by_node.entry(n.clone()).or_default();
            e.1 += 1;
            if let Some(k) = &link {
                e.0.push(k.clone());
            }
        }
        let status = moving.get(r.id.as_str()).map_or(r.status, |s| s.to_string());
        f.runs.push(RunLine {
            run: r.id,
            node,
            agent: r.agent,
            zone: r.zone,
            status,
            started_ms: r.started_at * 1000,
            spent: link.as_ref().map(|k| k.spent),
            connected: link.as_ref().map(|k| k.connected),
        });
    }
    for a in agents.iter().filter(|a| a.state == "hibernated") {
        f.runs.push(RunLine {
            run: if a.run.is_empty() { a.id.clone() } else { a.run.clone() },
            node: None,
            agent: a.name.clone(),
            zone: a.zone.clone(),
            status: "hibernated".into(),
            started_ms: a.updated_at * 1000,
            spent: Some(Spent {
                requests: a.used_requests as u64,
                input_tokens: a.used_input_tokens as u64,
                output_tokens: a.used_output_tokens as u64,
                ..Default::default()
            }),
            connected: None,
        });
    }
    let mut names: Vec<(String, String)> = vec![(crate::localnode::NAME.to_string(), "active".to_string())];
    names.extend(l.nodes()?.into_iter().map(|n| (n.name, n.status)));
    for (name, status) in names {
        let (links, boxes) = by_node.remove(&name).unwrap_or_default();
        let freshest = links.iter().max_by_key(|k| k.updated_ms);
        // Connected if any run's supervisor is; else cut off since the latest of them was.
        let link = match links.iter().filter(|k| k.connected).min_by_key(|k| k.since_ms) {
            Some(k) => Some((true, k.since_ms)),
            None => links.iter().map(|k| k.since_ms).max().map(|t| (false, t)),
        };
        f.nodes.push(NodeLine { name, status, link, boxes, capacity: freshest.and_then(|k| k.capacity.clone()) });
    }
    f.pending = l.pending(&tenant)?.len();
    for x in l.leases(&["active"])? {
        f.leases.push(LeaseLine {
            id: x.id,
            provider: x.provider,
            run: x.run,
            node: x.node_name,
            not_after: x.not_after,
            reserved_micro_usd: x.reserved,
        });
    }
    Ok(f)
}

/// The control host's view, `width` columns wide.
pub fn render_control(f: &ControlFrame, width: usize) -> Vec<String> {
    let now = f.now_ms;
    let running = f.runs.iter().filter(|r| r.status != "hibernated").count();
    let mut out = vec![
        format!("wicket top — control host — {}", clock(now)),
        format!(
            "{} running run{}   {} pending request{}   {} active lease{}",
            running,
            plural(running),
            f.pending,
            plural(f.pending),
            f.leases.len(),
            plural(f.leases.len())
        ),
        String::new(),
        format!("{:<16} {:<26} {:>5} {:>10} {:>12}", "NODE", "CONTROL", "BOXES", "CPU", "MEM"),
    ];
    for n in &f.nodes {
        let link = match (n.status.as_str(), n.link) {
            ("revoked", _) => "revoked".to_string(),
            (_, Some((true, t))) => format!("connected {}", dur((now - t) / 1000)),
            (_, Some((false, 0))) => "not connected".into(),
            (_, Some((false, t))) => format!("CUT OFF {} ago", dur((now - t) / 1000)),
            (_, None) => "idle (no runs)".into(),
        };
        let (cpu, mem) = match &n.capacity {
            Some(c) => {
                (format!("{:.1}/{:.0}", c.used_vcpus, c.vcpus), format!("{}/{}", bytes(c.used_memory_mib << 20), bytes(c.memory_mib << 20)))
            }
            None => ("-".into(), "-".into()),
        };
        out.push(format!("{:<16} {:<26} {:>5} {:>10} {:>12}", cut(&clean(&n.name, 64), 16), link, n.boxes, cpu, mem));
    }
    out.push(String::new());
    out.push(format!("{:<12} {:<10} {:<20} {:<10} {:>6} {:>5} {:>11}", "RUN", "NODE", "AGENT/ZONE", "STATUS", "UP", "REQ", "TOK in/out"));
    if f.runs.is_empty() {
        out.push("(no runs)".into());
    }
    for r in &f.runs {
        let status = match (r.status.as_str(), r.connected) {
            ("running", Some(false)) => "cut off".to_string(),
            (s, _) => clean(s, 12),
        };
        let (req, tok) = match &r.spent {
            Some(s) => (
                s.requests.to_string(),
                format!("{}/{}", count(s.input_tokens + s.cache_read_tokens + s.cache_creation_tokens), count(s.output_tokens)),
            ),
            None => ("-".into(), "-".into()),
        };
        out.push(format!(
            "{:<12} {:<10} {:<20} {:<10} {:>6} {:>5} {:>11}",
            short_run(&r.run),
            cut(&clean(r.node.as_deref().unwrap_or("-"), 64), 10),
            cut(&format!("{}/{}", clean(&r.agent, 40), clean(&r.zone, 40)), 20),
            cut(&status, 10),
            if r.status != "hibernated" { dur((now - r.started_ms) / 1000) } else { "-".into() },
            req,
            tok
        ));
    }
    if !f.leases.is_empty() {
        out.push(String::new());
        out.push(format!("{:<28} {:<8} {:<12} {:<14} {:>10} {:>9}", "LEASE", "PROVIDER", "RUN", "NODE", "ENDS IN", "RESERVED"));
        for x in &f.leases {
            out.push(format!(
                "{:<28} {:<8} {:<12} {:<14} {:>10} {:>9}",
                cut(&clean(&x.id, 64), 28),
                cut(&clean(&x.provider, 16), 8),
                short_run(&x.run),
                cut(&clean(x.node.as_deref().unwrap_or("-"), 64), 14),
                x.not_after.map_or("-".into(), |t| dur(t - now / 1000)),
                format!("${:.2}", x.reserved_micro_usd as f64 / 1e6)
            ));
        }
    }
    fit_all(out, width)
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// A run id cut to what tells runs apart on a screen: `run_` and the first 8 characters after it.
pub fn short_run(run: &str) -> String {
    let r = clean(run, 64);
    let body = r.strip_prefix("run_").unwrap_or(&r);
    cut(&format!("run_{}", body.chars().take(8).collect::<String>()), 12)
}

/// Text from a node, a box or the ledger, with terminal escapes, bidi and zero-width characters
/// stripped (#128), and at most `n` characters.
fn clean(s: &str, n: usize) -> String {
    wicket_core::text::clip(s, n)
}

/// At most `n` characters, the last one `…` if cut.
fn cut(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
    t.push('…');
    t
}

fn fit_all(lines: Vec<String>, width: usize) -> Vec<String> {
    lines.into_iter().map(|l| cut(&l, width.max(20))).collect()
}

/// `HH:MM:SSZ` (UTC) of a Unix ms time.
pub fn clock(ms: i64) -> String {
    let s = (ms / 1000).rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}Z", s / 3600, s / 60 % 60, s % 60)
}

/// A duration (seconds) in at most two units: `42s`, `3m05s`, `1h02m`, `2d03h`.
pub fn dur(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m{:02}s", s / 60, s % 60),
        s if s < 86_400 => format!("{}h{:02}m", s / 3600, s / 60 % 60),
        s => format!("{}d{:02}h", s / 86_400, s / 3600 % 24),
    }
}

/// `until 09:00:00Z (in 22h00m)`, or `EXPIRED 2m ago`.
fn until(ms: i64, now: i64) -> String {
    if ms > now {
        format!("until {} (in {})", clock(ms), dur((ms - now) / 1000))
    } else {
        format!("EXPIRED {} ago", dur((now - ms) / 1000))
    }
}

/// A byte count in at most four characters and a unit: `512B`, `412M`, `2.0G`.
pub fn bytes(b: u64) -> String {
    const K: u64 = 1024;
    match b {
        b if b < K => format!("{b}B"),
        b if b < K * K => format!("{}K", b / K),
        b if b < 10 * K * K * K => {
            if b < K * K * K {
                format!("{}M", b / (K * K))
            } else {
                format!("{:.1}G", b as f64 / (K * K * K) as f64)
            }
        }
        b => format!("{}G", b / (K * K * K)),
    }
}

/// A count in at most five characters: `999`, `12.3k`, `4.5M`.
pub fn count(n: u64) -> String {
    match n {
        n if n < 1000 => n.to_string(),
        n if n < 1_000_000 => format!("{:.1}k", n as f64 / 1e3),
        n if n < 1_000_000_000 => format!("{:.1}M", n as f64 / 1e6),
        n => format!("{:.1}G", n as f64 / 1e9),
    }
}

/// The terminal's width (columns): stdout's, else `$COLUMNS`, else 80.
fn width(tty: bool) -> usize {
    if tty {
        // SAFETY: TIOCGWINSZ fills the winsize it is given.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
            return ws.ws_col as usize;
        }
    }
    std::env::var("COLUMNS").ok().and_then(|c| c.parse().ok()).filter(|c| *c > 0).unwrap_or(80)
}

/// The terminal's height (rows), for cutting a frame that doesn't fit.
fn height() -> usize {
    // SAFETY: as in `width`.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_row > 0 {
        return ws.ws_row as usize;
    }
    24
}

/// The terminal in the view's mode while it lives (keys read one at a time, unechoed, Ctrl-C as a
/// key; the alternate screen, cursor hidden), and as it was after.
struct Screen {
    saved: Option<libc::termios>,
}

impl Screen {
    fn enter() -> Screen {
        let mut saved = None;
        if std::io::stdin().is_terminal() {
            // SAFETY: tcgetattr/tcsetattr on stdin, with a termios they filled.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(0, &mut t) } == 0 {
                saved = Some(t);
                t.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
                t.c_cc[libc::VMIN] = 1;
                t.c_cc[libc::VTIME] = 0;
                unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
            }
        }
        print!("\x1b[?1049h\x1b[?25l");
        let _ = std::io::stdout().flush();
        Screen { saved }
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        print!("\x1b[?25h\x1b[?1049l");
        let _ = std::io::stdout().flush();
        if let Some(t) = &self.saved {
            // SAFETY: restoring what tcgetattr gave.
            unsafe { libc::tcsetattr(0, libc::TCSANOW, t) };
        }
    }
}

/// Shows the frames `frame` makes (given the width): one with `once`, else one every [`REFRESH`]
/// until q or Ctrl-C, full-screen at a terminal and as plain text otherwise.
pub async fn show<F, Fut>(once: bool, mut frame: F) -> Result<()>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Vec<String>>,
{
    let tty = std::io::stdout().is_terminal();
    if once || !tty {
        loop {
            let lines = frame(width(tty)).await;
            let mut out = std::io::stdout().lock();
            for l in lines {
                writeln!(out, "{l}")?;
            }
            out.flush()?;
            drop(out);
            if once {
                return Ok(());
            }
            tokio::select! {
                _ = tokio::time::sleep(REFRESH) => println!(),
                _ = tokio::signal::ctrl_c() => return Ok(()),
            }
        }
    }
    let screen = Screen::enter();
    let (tx, mut keys) = tokio::sync::mpsc::unbounded_channel::<u8>();
    if screen.saved.is_some() {
        std::thread::spawn(move || {
            let mut b = [0u8; 1];
            while let Ok(1) = std::io::Read::read(&mut std::io::stdin(), &mut b) {
                if tx.send(b[0]).is_err() {
                    break;
                }
            }
        });
    }
    loop {
        let lines = frame(width(true)).await;
        let mut s = String::from("\x1b[H");
        for l in lines.iter().take(height()) {
            s.push_str(l);
            s.push_str("\x1b[K\r\n");
        }
        s.push_str("\x1b[J");
        {
            let mut out = std::io::stdout().lock();
            out.write_all(s.as_bytes())?;
            out.flush()?;
        }
        let quit = tokio::select! {
            _ = tokio::time::sleep(REFRESH) => false,
            k = keys.recv() => matches!(k, Some(b'q' | b'Q' | 3) | None),
            _ = tokio::signal::ctrl_c() => true,
        };
        if quit {
            break;
        }
    }
    drop(screen);
    Ok(())
}

/// `wicket node top`: this node's view (`--json`: its status once, as the status socket answers).
pub async fn node_top(dir: Option<std::path::PathBuf>, once: bool, json: bool) -> Result<()> {
    let paths = crate::nodesrv::NodePaths::new(dir);
    let sock = status_socket(&paths.socket());
    if json {
        println!("{}", serde_json::to_string_pretty(&read_status(&sock).await?)?);
        return Ok(());
    }
    let docker = wicket_sandbox::Docker::from_env();
    let root = paths.root.clone();
    show(once, move |w| {
        let (sock, docker, root) = (sock.clone(), docker.clone(), root.clone());
        async move {
            let status = read_status(&sock).await.map_err(|e| format!("{e:#}"));
            let names: Vec<String> = match &status {
                Ok(s) => s
                    .boxes
                    .iter()
                    .filter(|b| matches!(b.state.as_str(), "running" | "paused" | "stopping" | "hibernating"))
                    .map(|b| b.name.clone())
                    .collect(),
                Err(_) => vec![],
            };
            let got = futures_util::future::join_all(names.iter().map(|n| docker.stats(n))).await;
            let stats = names.into_iter().zip(got).filter_map(|(n, s)| Some((n, s.ok()??))).collect();
            let f = NodeFrame { status, host: HostStats::read(&root), stats, now_ms: wicket_feed::now_ms() };
            render_node(&f, w)
        }
    })
    .await
}

/// `wicket top`: the control host's view, across its nodes.
pub async fn control_top(once: bool) -> Result<()> {
    show(once, |w| async move {
        let now = wicket_feed::now_ms();
        let f = wicket_store::Ledger::open(&crate::ledger_path()).map_err(anyhow::Error::from).and_then(|l| control_frame(&l, now));
        match f {
            Ok(mut f) => {
                // This host's own node answers its status socket here.
                if let Ok(sock) = crate::localnode::socket() {
                    if let Ok(s) = read_status(&status_socket(&sock)).await {
                        if let Some(n) = f.nodes.iter_mut().find(|n| n.name == crate::localnode::NAME) {
                            n.link = Some((s.control.connections > 0, s.control.since_ms));
                            n.boxes = s.boxes.iter().filter(|b| b.state != "exited").count();
                        }
                    }
                }
                render_control(&f, w)
            }
            Err(e) => fit_all(vec![format!("wicket top — {}", clock(now)), format!("the ledger can't be read: {e:#}")], w),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_763_200_000_000; // 2025-11-15T09:46:40Z

    fn status() -> NodeStatus {
        NodeStatus {
            node: "hyperv1".into(),
            build: "abc".into(),
            now_ms: NOW,
            identity: Some("spiffe://example.org/node/hyperv1".into()),
            identity_until: Some(NOW / 1000 + 22 * 3600),
            identity_error: None,
            ca_until: Some(NOW / 1000 + 3 * 86_400),
            control: ControlStatus { connections: 2, since_ms: NOW - 1_205_000 },
            feed: FeedStatus { mode: "fresh".into(), epoch: Some(42), fresh_until_ms: Some(NOW + 18_000) },
            boxes: vec![
                BoxStatus {
                    run: "run_01JCXYZABCDEFGH".into(),
                    name: "wicket-run-01JCXYZABCDEFGH".into(),
                    agent: Some("coder".into()),
                    zone: "dev".into(),
                    state: "running".into(),
                    started_ms: NOW - 3_725_000,
                    cpus: 1.0,
                    memory_mib: 2048,
                    spent: Spent {
                        requests: 34,
                        input_tokens: 1_000_000,
                        cache_read_tokens: 200_000,
                        cache_creation_tokens: 0,
                        output_tokens: 40_000,
                    },
                    slice: Some(Slice { requests: 100, output_tokens: 100_000, input_tokens: None }),
                    egress_allowed: 120,
                    egress_refused: 3,
                    asks: 1,
                    connected: true,
                },
                BoxStatus {
                    run: "run_01JCAAAABBBBCCCC".into(),
                    name: "wicket-run-01JCAAAABBBBCCCC".into(),
                    agent: None,
                    zone: "ci\u{1b}[2J".into(),
                    state: "running".into(),
                    started_ms: NOW - 42_000,
                    cpus: 0.5,
                    memory_mib: 512,
                    connected: false,
                    ..Default::default()
                },
            ],
            egress: vec![
                EgressSeen {
                    at_ms: NOW - 1000,
                    run: "run_01JCXYZABCDEFGH".into(),
                    line: "[egress] ALLOW   GET api.github.com/repos/x  (read; allowed by the zone)".into(),
                },
                EgressSeen {
                    at_ms: NOW - 9000,
                    run: "run_01JCAAAABBBBCCCC".into(),
                    line: "[egress] BLOCKED POST evil.example/\u{1b}]0;pwn\u{7}  (write; not in the zone)".into(),
                },
            ],
        }
    }

    fn host() -> HostStats {
        HostStats {
            load: [0.12, 0.3, 0.25],
            cpus: 2,
            mem_total: 4 << 30,
            mem_available: 3 << 30,
            disk_total: 100 << 30,
            disk_free: 60 << 30,
        }
    }

    #[test]
    fn the_node_frame_reads_on_an_80_column_console() {
        let mut stats = HashMap::new();
        stats.insert(
            "wicket-run-01JCXYZABCDEFGH".to_string(),
            wicket_sandbox::BoxStats { cpu_pct: Some(12.34), memory: 412 << 20, limit: 2 << 30 },
        );
        let f = NodeFrame { status: Ok(status()), host: host(), stats, now_ms: NOW };
        let got = render_node(&f, 80).join("\n");
        let want = include_str!("top/testdata/node-80.txt");
        assert_eq!(got, want.trim_end_matches('\n'), "got:\n{got}");
        for l in got.lines() {
            assert!(l.chars().count() <= 80, "{l:?} is wider than 80");
            assert!(!l.contains('\u{1b}') && !l.contains('\u{7}'), "an escape survived: {l:?}");
        }
    }

    #[test]
    fn a_node_cut_off_and_one_not_serving_say_so() {
        let mut s = status();
        s.control = ControlStatus { connections: 0, since_ms: NOW - 65_000 };
        s.feed = FeedStatus { mode: "offline".into(), epoch: Some(42), fresh_until_ms: Some(NOW - 30_000) };
        s.identity_until = Some(NOW / 1000 - 120);
        let f = NodeFrame { status: Ok(s), host: host(), stats: HashMap::new(), now_ms: NOW };
        let got = render_node(&f, 200).join("\n");
        assert!(got.contains("control: CUT OFF since 09:45:35Z (1m05s ago)"), "{got}");
        assert!(got.contains("feed offline, epoch 42, stale 30s"), "{got}");
        assert!(got.contains("EXPIRED 2m00s ago"), "{got}");
        let f = NodeFrame {
            status: Err("wicket node serve is not answering on /x/ctl/status.sock".into()),
            host: host(),
            stats: HashMap::new(),
            now_ms: NOW,
        };
        let got = render_node(&f, 80);
        assert_eq!(got[1], "node: wicket node serve is not answering on /x/ctl/status.sock");
    }

    #[test]
    fn the_control_frame_reads_on_an_80_column_console() {
        let cap = crate::chan::NodeCapacity { vcpus: 4.0, memory_mib: 8192, used_vcpus: 1.5, used_memory_mib: 2560, boxes: 2 };
        let f = ControlFrame {
            now_ms: NOW,
            nodes: vec![
                NodeLine {
                    name: "local".into(),
                    status: "active".into(),
                    link: Some((true, NOW - 600_000)),
                    boxes: 1,
                    capacity: Some(cap.clone()),
                },
                NodeLine {
                    name: "hyperv1".into(),
                    status: "active".into(),
                    link: Some((false, NOW - 95_000)),
                    boxes: 1,
                    capacity: Some(cap),
                },
                NodeLine { name: "spare".into(), status: "active".into(), link: None, boxes: 0, capacity: None },
                NodeLine { name: "old".into(), status: "revoked".into(), link: None, boxes: 0, capacity: None },
            ],
            runs: vec![
                RunLine {
                    run: "run_01JCXYZABCDEFGH".into(),
                    node: Some("local".into()),
                    agent: "coder".into(),
                    zone: "dev".into(),
                    status: "running".into(),
                    started_ms: NOW - 3_725_000,
                    spent: Some(Spent { requests: 34, input_tokens: 1_200_000, output_tokens: 40_000, ..Default::default() }),
                    connected: Some(true),
                },
                RunLine {
                    run: "run_01JCAAAABBBBCCCC".into(),
                    node: Some("hyperv1".into()),
                    agent: "reviewer".into(),
                    zone: "ci".into(),
                    status: "running".into(),
                    started_ms: NOW - 42_000,
                    spent: None,
                    connected: Some(false),
                },
                RunLine {
                    run: "run_01JBZZZZ".into(),
                    node: None,
                    agent: "helper".into(),
                    zone: "dev".into(),
                    status: "hibernated".into(),
                    started_ms: 0,
                    spent: Some(Spent { requests: 3, ..Default::default() }),
                    connected: None,
                },
            ],
            pending: 2,
            leases: vec![LeaseLine {
                id: "lease_01JCLLLLLLLLLLLLLLLLLLLL".into(),
                provider: "vultr".into(),
                run: "run_01JCXYZABCDEFGH".into(),
                node: Some("vultr-1".into()),
                not_after: Some(NOW / 1000 + 2280),
                reserved_micro_usd: 120_000,
            }],
        };
        let got = render_control(&f, 80).join("\n");
        let want = include_str!("top/testdata/control-80.txt");
        assert_eq!(got, want.trim_end_matches('\n'), "got:\n{got}");
        assert!(got.lines().all(|l| l.chars().count() <= 80));
    }

    #[test]
    fn units_stay_short() {
        assert_eq!(dur(42), "42s");
        assert_eq!(dur(185), "3m05s");
        assert_eq!(dur(3725), "1h02m");
        assert_eq!(dur(2 * 86_400 + 3 * 3600), "2d03h");
        assert_eq!(dur(-5), "0s");
        assert_eq!(bytes(512), "512B");
        assert_eq!(bytes(412 << 20), "412M");
        assert_eq!(bytes(2 << 30), "2.0G");
        assert_eq!(bytes(146 << 30), "146G");
        assert_eq!(count(999), "999");
        assert_eq!(count(12_345), "12.3k");
        assert_eq!(clock(NOW), "09:46:40Z");
        assert_eq!(short_run("run_01JCXYZABCDEFGH"), "run_01JCXYZA");
        assert_eq!(cut("abcdef", 4), "abc…");
        assert_eq!(egress_kind("spliced"), EgressKind::Allowed);
        assert_eq!(egress_kind("unavailable"), EgressKind::Refused);
        assert_eq!(egress_kind("pending"), EgressKind::Asked);
    }

    #[tokio::test]
    async fn the_status_socket_is_read_whole() {
        let dir = std::env::temp_dir().join(format!("wicket-top-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = status_socket(&dir.join("ctl.sock"));
        assert_eq!(sock, dir.join("status.sock"));
        assert!(read_status(&sock).await.unwrap_err().to_string().contains("not answering"));
        let l = tokio::net::UnixListener::bind(&sock).unwrap();
        let want = status();
        let body = serde_json::to_vec(&want).unwrap();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut c, _) = l.accept().await.unwrap();
            c.write_all(&body).await.unwrap();
        });
        assert_eq!(read_status(&sock).await.unwrap(), want);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
