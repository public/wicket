//! The control host's calls on a node's boxes (#146): pause and unpause, process lists, the hosts
//! file, `docker exec` streams and link relay sockets, over any authenticated control connection to
//! the node (`chan.rs`). A run's own connection carries them for its box ([`crate::noderun`]); a link
//! relay opens one of its own to reach a box another process runs ([`Link`]).
//!
//! - **How to reach a node** ([`Via`]): over ssh to `wicket node attach` for a remote node, or the
//!   built-in local node's unix socket directly (`localnode.rs`). Nothing else differs.

use crate::chan::{self, Frame, Msg, Tunnels, CONTROL_TUNNEL_BIT, TUNNEL_BIT};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

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

/// A byte stream into a box (an exec's stdio, or one connection to a link socket).
pub type BoxStream = tokio::io::DuplexStream;

/// Calls in flight on one control connection, and the tunnels they opened.
#[derive(Default)]
pub struct Calls {
    out: Mutex<Option<chan::Out>>,
    pub tunnels: Arc<Tunnels>,
    /// Answers awaited: `BoxCtlDone` by id, `TunnelOpened` by stream.
    pending: Mutex<HashMap<u64, oneshot::Sender<Msg>>>,
    exits: Mutex<HashMap<u64, oneshot::Sender<i32>>>,
    /// Link sockets listened on: where their connections go.
    incoming: Mutex<HashMap<(String, String), mpsc::UnboundedSender<BoxStream>>>,
    next: AtomicU64,
}

impl Calls {
    /// The connection is up (`Some`) or gone (`None`): calls in flight fail, tunnels and link sockets end.
    pub fn set_out(&self, out: Option<chan::Out>) {
        let gone = out.is_none();
        *self.out.lock().expect("out") = out;
        if gone {
            self.tunnels.clear();
            self.pending.lock().expect("pending").clear();
            self.exits.lock().expect("exits").clear();
            self.incoming.lock().expect("incoming").clear();
        }
    }

    pub fn connected(&self) -> bool {
        self.out.lock().expect("out").is_some()
    }

    fn send(&self, f: Frame) -> bool {
        self.out.lock().expect("out").as_ref().is_some_and(|o| o.send(f).is_ok())
    }

    fn id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Takes the frames that answer calls made here; anything else is the caller's.
    pub fn handle(&self, f: Frame) -> Option<Frame> {
        match f {
            Frame::Data { stream, bytes, .. } if stream & TUNNEL_BIT != 0 => {
                self.tunnels.data(stream, bytes);
                None
            }
            Frame::Msg(Msg::Close { stream }) => {
                self.tunnels.close(stream);
                None
            }
            Frame::Msg(m @ Msg::BoxCtlDone { .. }) => {
                let Msg::BoxCtlDone { id, .. } = &m else { unreachable!() };
                if let Some(tx) = self.pending.lock().expect("pending").remove(id) {
                    let _ = tx.send(m);
                }
                None
            }
            Frame::Msg(Msg::TunnelOpened { stream, error }) if stream & CONTROL_TUNNEL_BIT != 0 => {
                if let Some(tx) = self.pending.lock().expect("pending").remove(&stream) {
                    let _ = tx.send(Msg::TunnelOpened { stream, error });
                }
                None
            }
            Frame::Msg(Msg::ExecDone { stream, code }) => {
                if let Some(tx) = self.exits.lock().expect("exits").remove(&stream) {
                    let _ = tx.send(code);
                }
                None
            }
            Frame::Msg(Msg::TunnelOpen { stream, run, target }) if target.starts_with("link:") => {
                let sock = target["link:".len()..].to_string();
                let to = self.incoming.lock().expect("incoming").get(&(run.clone(), sock)).cloned();
                let out = self.out.lock().expect("out").clone();
                match (to, out) {
                    (Some(to), Some(out)) => {
                        let (ours, theirs) = tokio::io::duplex(256 * 1024);
                        let _ = out.send(Frame::Msg(Msg::TunnelOpened { stream, error: None }));
                        self.tunnels.attach(stream, theirs, out);
                        let _ = to.send(ours);
                    }
                    _ => {
                        self.send(Frame::Msg(Msg::TunnelOpened { stream, error: Some(format!("no link socket {target} for run {run}")) }));
                    }
                }
                None
            }
            f => Some(f),
        }
    }

    async fn answer(&self, key: u64, f: Frame, what: &str) -> Result<Msg> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("pending").insert(key, tx);
        if !self.send(f) {
            self.pending.lock().expect("pending").remove(&key);
            bail!("the node is not connected");
        }
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(m)) => Ok(m),
            _ => {
                self.pending.lock().expect("pending").remove(&key);
                bail!("the node did not answer {what}")
            }
        }
    }

    /// `Msg::BoxCtl` on `run`'s box: its output, if any.
    pub async fn ctl(&self, run: &str, what: &str, user: &str, arg: &str) -> Result<Option<String>> {
        let id = self.id();
        let f = Frame::Msg(Msg::BoxCtl { id, run: run.into(), what: what.into(), user: user.into(), arg: arg.into() });
        match self.answer(id, f, what).await? {
            Msg::BoxCtlDone { error: Some(e), .. } => bail!("{e}"),
            Msg::BoxCtlDone { out, .. } => Ok(out),
            _ => bail!("an unexpected answer to {what}"),
        }
    }

    /// Runs `argv` in `run`'s box: its stdio as a stream, and its exit code when it ends.
    pub async fn exec(&self, run: &str, user: &str, argv: &[String], stdin: bool) -> Result<(BoxStream, oneshot::Receiver<i32>)> {
        let stream = TUNNEL_BIT | CONTROL_TUNNEL_BIT | self.id();
        let (etx, erx) = oneshot::channel();
        self.exits.lock().expect("exits").insert(stream, etx);
        let f = Frame::Msg(Msg::Exec { stream, run: run.into(), user: user.into(), argv: argv.to_vec(), stdin });
        // The tunnel exists before the node can send on it.
        let (ours, theirs) = tokio::io::duplex(256 * 1024);
        let out = self.out.lock().expect("out").clone().context("the node is not connected")?;
        self.tunnels.attach(stream, theirs, out);
        match self.answer(stream, f, "an exec").await {
            Ok(Msg::TunnelOpened { error: None, .. }) => Ok((ours, erx)),
            r => {
                self.tunnels.close(stream);
                self.exits.lock().expect("exits").remove(&stream);
                match r {
                    Ok(Msg::TunnelOpened { error: Some(e), .. }) => bail!("{e}"),
                    Err(e) => Err(e),
                    _ => bail!("an unexpected answer to an exec"),
                }
            }
        }
    }

    /// Runs `argv` in `run`'s box to the end: its exit code and stdout.
    pub async fn exec_output(&self, run: &str, user: &str, argv: &[String]) -> Result<(i32, String)> {
        let (mut s, exit) = self.exec(run, user, argv, false).await?;
        let mut out = String::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(30), s.read_to_string(&mut out)).await;
        let code = tokio::time::timeout(std::time::Duration::from_secs(5), exit).await.ok().and_then(|r| r.ok()).unwrap_or(-1);
        Ok((code, out))
    }

    /// Opens tunnel `stream` for a tree transfer (`put`: to the node) and waits for the node's go.
    async fn tree(&self, run: &str, tree: &str, put: bool) -> Result<(u64, BoxStream, oneshot::Receiver<i32>)> {
        let stream = TUNNEL_BIT | CONTROL_TUNNEL_BIT | self.id();
        let (etx, erx) = oneshot::channel();
        self.exits.lock().expect("exits").insert(stream, etx);
        let (ours, theirs) = tokio::io::duplex(1 << 20);
        let out = self.out.lock().expect("out").clone().context("the node is not connected")?;
        self.tunnels.attach(stream, theirs, out);
        let f = match put {
            true => Msg::PutTree { stream, run: run.into(), tree: tree.into() },
            false => Msg::GetTree { stream, run: run.into(), tree: tree.into() },
        };
        match self.answer(stream, Frame::Msg(f), "a tree transfer").await {
            Ok(Msg::TunnelOpened { error: None, .. }) => Ok((stream, ours, erx)),
            r => {
                self.tunnels.close(stream);
                self.exits.lock().expect("exits").remove(&stream);
                match r {
                    Ok(Msg::TunnelOpened { error: Some(e), .. }) => bail!("{e}"),
                    Err(e) => Err(e),
                    _ => bail!("an unexpected answer to a tree transfer"),
                }
            }
        }
    }

    /// Copies local directory `src` (less the top-level names in `exclude`) into `run`'s tree `tree`
    /// on the node.
    pub async fn put_tree(&self, run: &str, tree: &str, src: &std::path::Path, exclude: &[&str]) -> Result<()> {
        let (_, mut s, exit) = self.tree(run, tree, true).await?;
        let mut tar = tokio::process::Command::new("tar");
        tar.arg("-C").arg(src);
        for x in exclude {
            tar.arg(format!("--exclude=./{x}"));
        }
        let mut tar = tar.args(["-cf", "-", "."]).stdout(std::process::Stdio::piped()).kill_on_drop(true).spawn().context("tar")?;
        let mut from = tar.stdout.take().expect("stdout");
        tokio::io::copy(&mut from, &mut s).await.context("sending a tree to the node")?;
        s.shutdown().await?;
        if !tar.wait().await?.success() {
            bail!("archiving {} failed", src.display());
        }
        match tokio::time::timeout(std::time::Duration::from_secs(600), exit).await {
            Ok(Ok(0)) => Ok(()),
            Ok(Ok(c)) => bail!("the node could not unpack {tree} (tar exited {c})"),
            _ => bail!("the node did not finish unpacking {tree}"),
        }
    }

    /// Copies `run`'s tree `tree` on the node into local directory `dest` (made if needed).
    pub async fn get_tree(&self, run: &str, tree: &str, dest: &std::path::Path) -> Result<()> {
        std::fs::create_dir_all(dest)?;
        let (_, mut s, exit) = self.tree(run, tree, false).await?;
        let mut tar = tokio::process::Command::new("tar")
            .arg("-C")
            .arg(dest)
            .args(["--no-same-owner", "-xf", "-"])
            .stdin(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("tar")?;
        let mut to = tar.stdin.take().expect("stdin");
        tokio::io::copy(&mut s, &mut to).await.context("fetching a tree from the node")?;
        drop(to);
        if !tar.wait().await?.success() {
            bail!("unpacking {tree} from the node failed");
        }
        match tokio::time::timeout(std::time::Duration::from_secs(60), exit).await {
            Ok(Ok(0)) => Ok(()),
            Ok(Ok(c)) => bail!("the node could not archive {tree} (tar exited {c})"),
            _ => bail!("the node did not finish archiving {tree}"),
        }
    }

    /// The node may delete `run`'s files (a box it kept after exiting, for its state to be fetched).
    pub fn forget(&self, run: &str) {
        self.send(Frame::Msg(Msg::Forget { run: run.into() }));
    }

    /// Listens on link socket `sock` in `run`'s socket directory: its connections, as they come.
    pub async fn listen(&self, run: &str, sock: &str) -> Result<mpsc::UnboundedReceiver<BoxStream>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.incoming.lock().expect("incoming").insert((run.into(), sock.into()), tx);
        let id = self.id();
        let r = self.answer(id, Frame::Msg(Msg::Listen { id, run: run.into(), sock: sock.into() }), "a listen").await;
        match r {
            Ok(Msg::BoxCtlDone { error: None, .. }) => Ok(rx),
            r => {
                self.incoming.lock().expect("incoming").remove(&(run.into(), sock.into()));
                match r {
                    Ok(Msg::BoxCtlDone { error: Some(e), .. }) => bail!("{e}"),
                    Err(e) => Err(e),
                    _ => bail!("an unexpected answer to a listen"),
                }
            }
        }
    }

    pub fn unlisten(&self, run: &str, sock: &str) {
        self.incoming.lock().expect("incoming").remove(&(run.into(), sock.into()));
        self.send(Frame::Msg(Msg::Unlisten { run: run.into(), sock: sock.into() }));
    }
}

/// A control connection of its own to a node, for calls on boxes other processes run (a link
/// relay's). Authenticated like a run's; it carries no feed and owns no box.
pub struct Link {
    pub calls: Arc<Calls>,
    /// What the node reported when this connection was made: its capacity, and the runs it has.
    pub capacity: Option<crate::chan::NodeCapacity>,
    pub runs: Vec<crate::chan::RunState>,
    /// What the node's build understands ([`crate::chan::FEATURES`]).
    pub features: Vec<String>,
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
            observer: false,
            nonce,
            scope: scope.into(),
        };
        let authed = crate::nodeauth::control(&mut rd, &mut wr, node, ledger, &issuer, hello)
            .await
            .map_err(|e| anyhow::anyhow!("node {node}: {e}"))?;
        let (capacity, runs, features) = match authed.welcome {
            Msg::Welcome { capacity, runs, features, .. } => (capacity, runs, features),
            _ => (None, vec![], vec![]),
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
        Ok(Link { calls, capacity, runs, features, task })
    }
}
