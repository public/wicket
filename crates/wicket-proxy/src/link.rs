//! Links between boxes (issue #6): what a link needs of the boxes it joins ([`BoxOps`]), which the
//! control host implements for boxes on any node. The link tools themselves (`expose`, `connect`,
//! `link`) are the control host's: `wicket_control::gateway::link` (#257).

use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use wicket_core::ZoneSpec;

/// How often a relay checks that its link may stay open.
pub const POLL: Duration = Duration::from_secs(2);

/// What labels do across a link (recorded with every link).
pub const LABELS: &str = "not propagated: wicket has no data-label mechanism yet (design §4.2); deferred";

/// A byte stream into a box. Dropping `guard` ends whatever carries it (e.g. a `docker exec`).
pub struct Stream {
    pub read: Box<dyn AsyncRead + Unpin + Send>,
    pub write: Box<dyn AsyncWrite + Unpin + Send>,
    pub guard: Box<dyn std::any::Any + Send>,
}

pub type Fut<'a, T> = futures_util::future::BoxFuture<'a, T>;

/// What links need from the boxes themselves, supplied by whoever runs them (`wicket run`): each box
/// is reached on its own node.
pub trait BoxOps: Send + Sync {
    /// Whether wicket can link `run`'s box (running, on a node it reaches), and if not, why.
    fn reachable<'a>(&'a self, run: &'a str) -> Fut<'a, Result<(), String>>;
    /// The zone of one of this run's own children, from the record of its spawn.
    fn child_zone(&self, child_run: &str) -> Option<ZoneSpec>;
    /// Rewrites `run`'s box's /etc/hosts.
    fn set_hosts<'a>(&'a self, run: &'a str, text: String) -> Fut<'a, Result<(), String>>;
    /// Listens on the unix socket `sock` in `run`'s box's socket directory (the box sees it as
    /// `/wicket/sock/<sock>`): its connections, as they come.
    fn accept<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, Result<tokio::sync::mpsc::UnboundedReceiver<Stream>, String>>;
    /// Stops that (best effort).
    fn close_accept<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, ()>;
    /// Starts, inside `run`'s box, a listener on `addr:port` that forwards each connection to the
    /// in-box unix socket `sock`.
    fn listen<'a>(&'a self, run: &'a str, addr: Ipv4Addr, port: u16, sock: &'a str) -> Fut<'a, Result<(), String>>;
    /// Stops that listener (best effort; the box may be gone).
    fn unlisten<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, ()>;
    /// A byte stream to 127.0.0.1:`port` inside `run`'s box.
    fn dial<'a>(&'a self, run: &'a str, port: u16) -> Fut<'a, Result<Stream, String>>;
    /// Listens on `sock` in `run`'s box with the node itself dialing `to`'s `port` for each
    /// connection, when both boxes are on one node that does (#164): the bytes never leave it, and
    /// the link outlives the control connection. Ok(false): relay it here instead.
    fn accept_direct<'a>(&'a self, _run: &'a str, _sock: &'a str, _to: &'a str, _port: u16) -> Fut<'a, Result<bool, String>> {
        Box::pin(async { Ok(false) })
    }
}
