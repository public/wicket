//! A node's status, as `wicket node serve` answers it on its status socket and `wicket node top`
//! shows it (moved from wicket-cli's `top`, which re-exports it), and the run log's line for an
//! egress decision (from `run`).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use wicket_proxy::llm::{Slice, Spent};
use wicket_proxy::Event;

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
    /// Its health (#377), as it reports it to the control host.
    #[serde(default)]
    pub health: Option<crate::health::NodeHealth>,
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
/// An egress decision's line, as the run log prints it (and `wicket node top` shows it). A node sends
/// these events, and an agent chose the method, host and path: printed only stripped (#128).
pub fn egress_line(ev: &Event) -> Option<String> {
    let Event::Egress { method, host, path, risk, outcome, detail } = ev else { return None };
    let tag = match outcome.as_str() {
        "allow" => "ALLOW  ",
        "pending" => "PENDING",
        "denied" => "DENIED ",
        "forwarded" => "FORWARD",
        "spliced" => "SPLICE ",
        "unavailable" => "STALE  ",
        _ => "BLOCKED",
    };
    let clip = wicket_agent::clip;
    Some(format!("[egress] {tag} {} {}{}  ({}; {})", clip(method, 16), clip(host, 120), clip(path, 120), clip(risk, 24), clip(detail, 240)))
}
