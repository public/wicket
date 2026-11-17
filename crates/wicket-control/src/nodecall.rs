//! The control host's calls on a node's boxes (#146): pause and unpause, process lists, the hosts
//! file, `docker exec` streams and link relay sockets, over any authenticated control connection to
//! the node (`chan.rs`). A run's own connection carries them for its box ([`crate::noderun`]); a link
//! relay opens one of its own to reach a box another process runs ([`Link`]).
//!
//! - **How to reach a node** ([`Via`]): over ssh to `wicket node attach` for a remote node, or the
//!   built-in local node's unix socket directly (`localnode.rs`). Nothing else differs.

use crate::chan::{self, Frame, Msg};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
pub use wicket_node::calls::{BoxStream, Calls};

/// How a node is reached.
#[derive(Clone, Debug)]
pub enum Via {
    /// `ssh <pinned> <target> wicket node attach` (this argv, which ends in the remote command).
    Ssh(Vec<String>),
    /// The node's control socket, on this host.
    Unix(PathBuf),
}

pub type Reader = Box<dyn AsyncRead + Unpin + Send>;
pub type Writer = Box<dyn AsyncWrite + Unpin + Send>;

/// An open transport: its two directions, the ssh process if any, and its stderr so far.
pub struct Dialed {
    pub rd: Reader,
    pub wr: Writer,
    pub child: Option<tokio::process::Child>,
    pub errlog: Option<tokio::task::JoinHandle<String>>,
}

impl Via {
    /// How to reach node `name`: the built-in node's socket, or the enrolled node's pinned ssh.
    pub fn for_node(name: &str) -> Result<Via> {
        if name == crate::localnode::NAME {
            return Ok(Via::Unix(crate::localnode::socket()?));
        }
        let n = crate::enrol::resolve_installed(name, None)?;
        if n.name.is_none() {
            bail!("{name} is not an enrolled node");
        }
        Ok(Via::Ssh(Via::attach_argv(&n)))
    }

    /// The ssh command line that joins a node's control socket.
    pub fn attach_argv(n: &crate::node::Node) -> Vec<String> {
        let mut argv = n.ssh_prefix();
        if argv[0] == "ssh" {
            // Notice a dead link in about 15 s rather than minutes (ssh takes an option's first value,
            // so these go before the defaults).
            argv.splice(1..1, ["-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"].map(String::from));
        }
        argv.push("\"$HOME/.local/bin/wicket\" node attach".into());
        argv
    }

    pub async fn dial(&self) -> Result<Dialed> {
        match self {
            Via::Unix(p) => {
                let s = tokio::net::UnixStream::connect(p).await.with_context(|| format!("connecting to {}", p.display()))?;
                let (rd, wr) = s.into_split();
                Ok(Dialed { rd: Box::new(rd), wr: Box::new(wr), child: None, errlog: None })
            }
            Via::Ssh(argv) => {
                let mut child = tokio::process::Command::new(&argv[0])
                    .args(&argv[1..])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()
                    .context("starting the node channel (ssh)")?;
                let wr = child.stdin.take().expect("stdin");
                let rd = child.stdout.take().expect("stdout");
                let mut e = child.stderr.take().expect("stderr");
                let errlog = tokio::spawn(async move {
                    let mut s = String::new();
                    let _ = e.read_to_string(&mut s).await;
                    s
                });
                Ok(Dialed { rd: Box::new(rd), wr: Box::new(wr), child: Some(child), errlog: Some(errlog) })
            }
        }
    }
}

/// A control connection of its own to a node, for calls on boxes other processes run (a link
/// relay's). Authenticated like a run's; it carries no feed and owns no box.
pub struct Link {
    pub calls: Arc<Calls>,
    /// What the node reported when this connection was made: its capacity, and the runs it has.
    pub capacity: Option<crate::chan::NodeCapacity>,
    pub runs: Vec<crate::chan::RunState>,
    /// The node's build (sha256 of its binary), and the protocol version this connection talks.
    pub build: String,
    pub proto: u32,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.task.abort();
        self.calls.set_out(None);
    }
}

impl Link {
    pub async fn connect(node: &str, scope: &str, ledger: &Arc<Mutex<wicket_store::Ledger>>) -> Result<Link> {
        let via = Via::for_node(node)?;
        let issuer = crate::issuer()?;
        let d = via.dial().await?;
        let (mut rd, mut wr, child) = (d.rd, d.wr, d.child);
        let build = crate::nodesrv::build_id()?;
        let hello = |nonce| Msg::Hello {
            node: node.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            build,
            proto: crate::chan::PROTOCOL,
            observer: false,
            nonce,
            scope: scope.into(),
        };
        let authed = crate::nodeauth::control(&mut rd, &mut wr, node, ledger, &issuer, hello)
            .await
            .map_err(|e| anyhow::anyhow!("node {node}: {e}"))?;
        let proto = authed.proto;
        let (capacity, runs, build) = match authed.welcome {
            Msg::Welcome { capacity, runs, build, .. } => (capacity, runs, build),
            _ => (None, vec![], String::new()),
        };
        let calls = Arc::new(Calls::default());
        let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();
        calls.set_out(Some(tx));
        let c = calls.clone();
        let task = tokio::spawn(async move {
            let _child = child;
            let writer = tokio::spawn(async move {
                while let Some(f) = rx.recv().await {
                    if wr.write_all(&f.encode()).await.is_err() {
                        break;
                    }
                }
            });
            while let Ok(Some(f)) = chan::read_frame(&mut rd).await {
                // Feed status, events and the rest are a run's business, not a relay's.
                let _ = c.handle(f);
            }
            writer.abort();
            c.set_out(None);
        });
        Ok(Link { calls, capacity, runs, build, proto, task })
    }
}
