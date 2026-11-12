//! Links between boxes (issue #6) on any nodes (#146): what `wicket_proxy::link` needs from the boxes,
//! done on each box's own node over an authenticated control connection (`nodecall.rs`).
//!
//! - In the connecting box, a `wicket-fwd --listen` on the link's address and port, relaying to the
//!   link's unix socket in the box's socket directory. It runs as the box's user, started with an
//!   exec on its node; the address is already on the box's loopback (`wicket-entry`).
//! - That socket is the node's: each connection to it is relayed to this process as a tunnel over
//!   the node's control channel (`Msg::Listen`).
//! - Into the target box, one exec of `wicket-fwd --dial 127.0.0.1:<port>` per connection, on the
//!   target's node. A socket the box itself creates isn't reachable from the host under gVisor
//!   (`--host-uds=open` lets the box connect out to host sockets, not offer its own), so wicket
//!   reaches in instead; it costs one `docker exec` per connection.
//!
//! A box on this run's own node is reached over the run's own connection; a box on another node over
//! a connection this process opens to it (scope `links:<run>`), so a link between nodes is relayed
//! by the control host. Both boxes need `wicket-fwd` (every image built on wicket's agent image has it).

use crate::nodecall::Calls;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use wicket_core::{Manifest, ZoneSpec};
use wicket_proxy::link::{BoxOps, Stream};

/// The Docker name of a run's box (as `wicket run` names it): `wicket-<run>`, or another prefix from
/// WICKET_BOX_PREFIX (tests name theirs, so they can be told apart and cleaned up).
pub fn box_name(run: &str) -> String {
    let prefix =
        std::env::var("WICKET_BOX_PREFIX").ok().filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    format!("{}-{}", prefix.as_deref().unwrap_or("wicket"), run.replace('_', "-"))
}

pub struct NodeBoxes {
    ledger: Arc<Mutex<wicket_store::Ledger>>,
    /// This run, its node, and its own connection's calls.
    run: String,
    node: String,
    own: Arc<Calls>,
    /// This run's directory (its spawn records are in `children/`).
    dir: PathBuf,
    /// Connections of this process's own to other nodes, opened when first needed.
    others: tokio::sync::Mutex<HashMap<String, Arc<crate::nodecall::Link>>>,
    /// The in-box pid of each link listener, by (run, socket).
    listeners: Mutex<HashMap<(String, String), String>>,
}

impl NodeBoxes {
    pub fn new(ledger: Arc<Mutex<wicket_store::Ledger>>, run: &str, node: &str, own: Arc<Calls>, dir: PathBuf) -> NodeBoxes {
        NodeBoxes { ledger, run: run.into(), node: node.into(), own, dir, others: Default::default(), listeners: Mutex::default() }
    }

    /// The node `run`'s box was placed on.
    fn node_of(&self, run: &str) -> Result<String, String> {
        crate::run::check_run_id(run).map_err(|e| e.to_string())?;
        let l = self.ledger.lock().expect("ledger");
        let node = l.run_node(run).map_err(|e| e.to_string())?.ok_or_else(|| format!("box {run} is not on a node wicket reaches"))?;
        match l.node(&node).map_err(|e| e.to_string())? {
            Some(n) if n.status == "active" => Ok(node),
            Some(n) => Err(format!("box {run}'s node {node} is {}", n.status)),
            None => Err(format!("box {run}'s node {node} is not enrolled")),
        }
    }

    /// The calls that reach `run`'s box.
    async fn calls(&self, run: &str) -> Result<Arc<Calls>, String> {
        let node = self.node_of(run)?;
        if node == self.node {
            return Ok(self.own.clone());
        }
        let mut others = self.others.lock().await;
        if let Some(l) = others.get(&node).filter(|l| l.calls.connected()) {
            return Ok(l.calls.clone());
        }
        let l = crate::nodecall::Link::connect(&node, &format!("links:{}", self.run), &self.ledger).await.map_err(|e| format!("{e:#}"))?;
        let c = l.calls.clone();
        others.insert(node, Arc::new(l));
        Ok(c)
    }
}

type Fut<'a, T> = futures_util::future::BoxFuture<'a, T>;

/// A stream into a box: the two halves, and what ends it when dropped.
fn stream(s: crate::nodecall::BoxStream, guard: Box<dyn std::any::Any + Send>) -> Stream {
    let (r, w) = tokio::io::split(s);
    Stream { read: Box::new(r), write: Box::new(w), guard }
}

impl BoxOps for NodeBoxes {
    fn reachable<'a>(&'a self, run: &'a str) -> Fut<'a, Result<(), String>> {
        // Its node must answer for it: the box is running there (not still starting, or gone).
        Box::pin(async move { self.calls(run).await?.ctl(run, "status", "", "").await.map(|_| ()).map_err(|e| format!("{e:#}")) })
    }

    fn child_zone(&self, child_run: &str) -> Option<ZoneSpec> {
        crate::run::check_run_id(child_run).ok()?;
        let y = std::fs::read_to_string(self.dir.join("children").join(format!("{child_run}.yaml"))).ok()?;
        Manifest::from_yaml(&y).ok().map(|m| m.zone)
    }

    fn set_hosts<'a>(&'a self, run: &'a str, text: String) -> Fut<'a, Result<(), String>> {
        Box::pin(async move { self.calls(run).await?.ctl(run, "hosts", "", &text).await.map(|_| ()).map_err(|e| format!("{e:#}")) })
    }

    fn accept<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, Result<tokio::sync::mpsc::UnboundedReceiver<Stream>, String>> {
        Box::pin(async move {
            let mut rx = self.calls(run).await?.listen(run, sock).await.map_err(|e| format!("{e:#}"))?;
            let (tx, out) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                while let Some(s) = rx.recv().await {
                    if tx.send(stream(s, Box::new(()))).is_err() {
                        break;
                    }
                }
            });
            Ok(out)
        })
    }

    fn close_accept<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            if let Ok(c) = self.calls(run).await {
                c.unlisten(run, sock);
            }
        })
    }

    fn listen<'a>(&'a self, run: &'a str, addr: Ipv4Addr, port: u16, sock: &'a str) -> Fut<'a, Result<(), String>> {
        Box::pin(async move {
            if !wicket_core::link::in_pool(addr) {
                return Err(format!("{addr} is not a link address"));
            }
            // Started in the background; still alive a moment later means it bound. Prints its pid.
            let script = format!(
                "wicket-fwd --listen {addr}:{port}={sock} --bind-timeout 0 </dev/null >/dev/null 2>&1 & p=$!; sleep 0.3; kill -0 $p 2>/dev/null && echo $p"
            );
            let c = self.calls(run).await?;
            let (code, out) = c.exec_output(run, "", &["sh".into(), "-c".into(), script]).await.map_err(|e| format!("{e:#}"))?;
            match out.trim().parse::<u32>() {
                Ok(pid) if code == 0 => {
                    self.listeners.lock().expect("listeners").insert((run.to_string(), sock.to_string()), pid.to_string());
                    Ok(())
                }
                _ => Err(format!(
                    "the listener on {addr}:{port} didn't start (port in use, or an image whose wicket-entry predates links: rebuild it with `wicket image`)"
                )),
            }
        })
    }

    fn unlisten<'a>(&'a self, run: &'a str, sock: &'a str) -> Fut<'a, ()> {
        Box::pin(async move {
            let Some(pid) = self.listeners.lock().expect("listeners").remove(&(run.to_string(), sock.to_string())) else { return };
            if let Ok(c) = self.calls(run).await {
                let _ = c.exec_output(run, "", &["kill".into(), pid]).await;
            }
        })
    }

    fn dial<'a>(&'a self, run: &'a str, port: u16) -> Fut<'a, Result<Stream, String>> {
        Box::pin(async move {
            let c = self.calls(run).await?;
            let argv = ["wicket-fwd".to_string(), "--dial".into(), format!("127.0.0.1:{port}")];
            let (s, exit) = c.exec(run, "", &argv, true).await.map_err(|e| format!("{e:#}"))?;
            Ok(stream(s, Box::new(exit)))
        })
    }
}
