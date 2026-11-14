//! Link relay sockets and file transfers for a box's trees (#146). Split out of `nodesrv.rs` (#220).

use super::*;

/// `Msg::PutTree` (`put`) or `Msg::GetTree`: one of a run's trees as a tar archive on tunnel `stream`.
pub(super) fn transfer(node: &Arc<Node>, gen: u64, tunnels: &Tunnels, stream: u64, run: &str, tree: &str, put: bool) {
    if stream & TUNNEL_BIT == 0 || stream & chan::CONTROL_TUNNEL_BIT == 0 {
        return;
    }
    let out = node.links.lock().expect("links").get(&gen).map(|l| l.out.clone());
    let Some(out) = out else { return };
    let spawned = tree_dir(&node.paths, run, tree).and_then(|d| {
        std::fs::create_dir_all(&d)?;
        let mut c = tokio::process::Command::new("tar");
        c.arg("-C").arg(&d).stderr(std::process::Stdio::null()).kill_on_drop(true);
        if put {
            c.args(["--no-same-owner", "-xf", "-"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null());
        } else {
            c.args(["-cf", "-", "."]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped());
        }
        Ok(c.spawn()?)
    });
    match spawned {
        Err(e) => {
            node.send_to(gen, Frame::Msg(Msg::TunnelOpened { stream, error: Some(format!("{e:#}")) }));
        }
        Ok(mut c) => {
            let rd: Box<dyn tokio::io::AsyncRead + Unpin + Send> = match c.stdout.take() {
                Some(r) => Box::new(r),
                None => Box::new(tokio::io::empty()),
            };
            let wr: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = match c.stdin.take() {
                Some(w) => Box::new(w),
                None => Box::new(tokio::io::sink()),
            };
            node.send_to(gen, Frame::Msg(Msg::TunnelOpened { stream, error: None }));
            tunnels.attach(stream, tokio::io::join(rd, wr), out);
            let n = node.clone();
            tokio::spawn(async move {
                let code = c.wait().await.ok().and_then(|s| s.code()).unwrap_or(-1);
                n.send_to(gen, Frame::Msg(Msg::ExecDone { stream, code }));
            });
        }
    }
}

/// A run's tree on this node: `workspace`, `state`, `tmp` or `volume.<name>`.
pub(super) fn tree_dir(paths: &NodePaths, run: &str, tree: &str) -> Result<PathBuf> {
    crate::run::check_run_id(run)?;
    let dir = paths.runs().join(run);
    let ok = |s: &str| !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c));
    match tree {
        "workspace" | "state" | "tmp" => Ok(dir.join(tree)),
        t => match t.strip_prefix("volume.") {
            Some(v) if ok(v) => Ok(dir.join("volumes").join(v)),
            _ => bail!("no tree {t:?}"),
        },
    }
}

/// `Msg::Listen`: a link's relay socket in a run's socket directory; each connection to it is offered
/// to connection `gen` as a tunnel.
pub(super) fn listen(node: &Arc<Node>, gen: u64, run: &str, sock: &str) -> Result<()> {
    let l = bind_link_socket(node, run, sock)?;
    let (n, run2, target) = (node.clone(), run.to_string(), format!("link:{sock}"));
    let task = tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            let (n, run, target) = (n.clone(), run2.clone(), target.clone());
            tokio::spawn(async move {
                let out = n.links.lock().expect("links").get(&gen).map(|l| (l.out.clone(), l.tunnels.clone()));
                let Some((out, tunnels)) = out else { return };
                let id = TUNNEL_BIT | n.id();
                let (tx, rx) = oneshot::channel();
                n.opens.lock().expect("opens").insert(id, tx);
                if out.send(Frame::Msg(Msg::TunnelOpen { stream: id, run, target })).is_err() {
                    return;
                }
                match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
                    Ok(Ok(None)) => tunnels.attach(id, c, out),
                    _ => {
                        n.opens.lock().expect("opens").remove(&id);
                    }
                }
            });
        }
    });
    if let Some(b) = node.boxes.lock().expect("boxes").get_mut(run) {
        if let Some(old) = b.listeners.insert(sock.to_string(), task) {
            old.abort();
        }
    }
    Ok(())
}

/// A link between two boxes on this node (#164): each connection to `sock` in `run`'s box is dialed
/// into box `to` at `port` here, and the bytes never leave the node, so the link outlives the
/// control connection. Decided here from both boxes' tokens: a connection is taken only while both
/// hold authority on this node (unexpired, unrevoked), and the link closes, its connections with
/// it, as soon as either doesn't (checked every 2 s), or when the control host unlinks it.
pub(super) fn listen_direct(node: &Arc<Node>, run: &str, sock: &str, to: &str, port: u16) -> Result<()> {
    crate::run::check_run_id(to)?;
    if port == 0 {
        bail!("port 0");
    }
    if !node.boxes.lock().expect("boxes").get(to).is_some_and(|b| b.exited.is_none()) {
        bail!("run {to} has no running box on this node");
    }
    let l = bind_link_socket(node, run, sock)?;
    let (n, from, to2) = (node.clone(), run.to_string(), to.to_string());
    let to_held = to2.clone();
    let held = move |n: &Node| {
        let now = (n.clock)();
        let r = n.replica.lock().expect("replica");
        [&from, &to_held].iter().all(|x| r.authority_until(x).is_some_and(|u| u > now))
    };
    let (run2, sock2) = (run.to_string(), sock.to_string());
    let task = tokio::spawn(async move {
        // Dropped with this task (unlinked, or closed here): every connection ends with it.
        let mut conns = tokio::task::JoinSet::new();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tokio::select! {
                a = l.accept() => {
                    let Ok((c, _)) = a else { break };
                    if !held(&n) {
                        break;
                    }
                    let found = n.boxes.lock().expect("boxes").get(&to2).filter(|b| b.exited.is_none()).map(|b| (b.name.clone(), b.user.clone()));
                    let Some((name, user)) = found else { break };
                    let child = n
                        .docker
                        .exec(&name, &user, &["-i"], &["wicket-fwd".to_string(), "--dial".into(), format!("127.0.0.1:{port}")])
                        .stdin(std::process::Stdio::piped())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .kill_on_drop(true)
                        .spawn();
                    let Ok(mut child) = child else { continue };
                    conns.spawn(async move {
                        let (Some(mut w), Some(mut r)) = (child.stdin.take(), child.stdout.take()) else { return };
                        let (mut cr, mut cw) = c.into_split();
                        let up = async {
                            let _ = tokio::io::copy(&mut cr, &mut w).await;
                            drop(w);
                        };
                        let down = async {
                            let _ = tokio::io::copy(&mut r, &mut cw).await;
                            let _ = cw.shutdown().await;
                        };
                        tokio::join!(up, down);
                        let _ = child.wait().await;
                    });
                }
                _ = tick.tick() => if !held(&n) {
                    break;
                },
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
        conns.abort_all();
        eprintln!("[node] {run2}: link socket {sock2} to {to2} closed on this node (a box's authority ended)");
    });
    if let Some(b) = node.boxes.lock().expect("boxes").get_mut(run) {
        if let Some(old) = b.listeners.insert(sock.to_string(), task) {
            old.abort();
        }
    }
    Ok(())
}

/// Binds a link's relay socket in `run`'s socket directory.
pub(super) fn bind_link_socket(node: &Node, run: &str, sock: &str) -> Result<tokio::net::UnixListener> {
    let ok = sock
        .strip_prefix("link-")
        .and_then(|s| s.strip_suffix(".sock"))
        .is_some_and(|id| !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    if !ok {
        bail!("bad link socket name {sock:?}");
    }
    let boxes = node.boxes.lock().expect("boxes");
    let b = boxes.get(run).filter(|b| b.exited.is_none()).with_context(|| format!("run {run} has no running box on this node"))?;
    let path = b.dir.join("sock").join(sock);
    let _ = std::fs::remove_file(&path);
    wicket_proxy::sockpath::bind(&path).with_context(|| format!("listening on {sock}"))
}
