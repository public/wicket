//! A control connection (#57, #146): the handshake, then each frame the control host sends,
//! handled. Split out of `nodesrv.rs` (#220).

use super::*;

pub(super) async fn connection(node: Arc<Node>, stream: UnixStream, gen: u64) -> Result<()> {
    let (mut rd, mut wr) = stream.into_split();
    let hello = tokio::time::timeout(std::time::Duration::from_secs(15), chan::read_frame(&mut rd)).await.context("no hello")??;
    if hello.is_none() {
        // Connected and closed: a check that the node is up (`localnode::ensure`).
        return Ok(());
    }
    let refuse = |why: String| Frame::Msg(Msg::Refused { why }).encode();
    let mut negotiated = 0;
    let (observer, scope) = match hello {
        Some(Frame::Msg(Msg::Hello { node: n, build, version, proto, observer, nonce, scope })) => {
            let why = if n != node.name {
                Some(format!("this is node {}, not {n}", node.name))
            } else {
                match chan::negotiate(chan::PROTOCOL, proto) {
                    Ok(p) => {
                        negotiated = p;
                        None
                    }
                    Err(e) => Some(format!(
                        "the control host (wicket {version}, build {}…) can't talk to this node: {e}; update the older of the two (`wicket self update --nodes {}`, or `wicket node install {}`)",
                        &build[..12.min(build.len())],
                        node.name,
                        node.name
                    )),
                }
            };
            if let Some(why) = why {
                wr.write_all(&refuse(why.clone())).await?;
                bail!("refused a control host: {why}");
            }
            if !observer {
                // Nothing changes here (the current connection keeps the link) until it has proved
                // this installation's issuer key.
                if let Err(e) = crate::nodeauth::node(&mut rd, &mut wr, &node.ident, &node.paths.root, &node.name, &nonce).await {
                    let why = format!("{e:#}");
                    wr.write_all(&refuse(why.clone())).await?;
                    bail!("refused a control host: {why}");
                }
            }
            (observer, scope)
        }
        _ => {
            wr.write_all(&refuse("expected a hello".into())).await?;
            bail!("no hello");
        }
    };
    if observer {
        // Feed frames only, answered on this connection; the control connection is left alone.
        while let Some(f) = chan::read_frame(&mut rd).await? {
            if let Frame::Feed(bytes) = f {
                let r = node.replica.lock().expect("replica").accept_bytes(&bytes, (node.clock)());
                if let Err(e) = &r {
                    eprintln!("[node] feed frame refused (observer): {} ({e})", e.kind());
                }
                wr.write_all(&node.feed_status(r.as_ref().err()).encode()).await?;
            }
        }
        return Ok(());
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<Frame>();
    let (kill_tx, mut kill_rx) = oneshot::channel();
    let tunnels = Arc::new(Tunnels::default());
    {
        // A newer connection with the same scope (the same run reconnecting) replaces the older one;
        // connections for other runs stay.
        let mut links = node.links.lock().expect("links");
        let older: Vec<u64> = links.iter().filter(|(_, l)| l.scope == scope).map(|(g, _)| *g).collect();
        for g in older {
            if let Some(mut old) = links.remove(&g) {
                old.tunnels.clear();
                if let Some(k) = old.kill.take() {
                    let _ = k.send(());
                }
            }
        }
        links.insert(gen, Link { out: tx.clone(), scope: scope.clone(), kill: Some(kill_tx), tunnels: tunnels.clone(), proto: negotiated });
    }
    let writer = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            if wr.write_all(&f.encode()).await.is_err() {
                break;
            }
        }
    });
    let runs: Vec<RunState> = node
        .boxes
        .lock()
        .expect("boxes")
        .iter()
        .map(|(run, b)| RunState {
            run: run.clone(),
            streams: b.streams,
            stdin_received: b.stdin_next,
            stdout_total: b.out[0].end(),
            stderr_total: b.out[1].end(),
            exited: b.exited.clone(),
            stdout_start: b.out[0].start(),
            stderr_start: b.out[1].start(),
            authority_until: node.replica.lock().expect("replica").authority_until(run).unwrap_or(0),
        })
        .collect();
    let feed = node.replica.lock().expect("replica").hello();
    let capacity = Some(node.capacity());
    let _ =
        tx.send(Frame::Msg(Msg::Welcome { node: node.name.clone(), build: node.build.clone(), proto: negotiated, feed, runs, capacity }));
    eprintln!(
        "[node] control host connected{} (protocol {negotiated})",
        if scope.is_empty() { String::new() } else { format!(" ({scope})") }
    );
    let result = loop {
        tokio::select! {
            _ = &mut kill_rx => break Ok(()),
            f = chan::read_frame(&mut rd) => match f {
                Ok(Some(f)) => {
                    if let Err(e) = handle(&node, gen, &tunnels, f).await {
                        break Err(e);
                    }
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e.into()),
            }
        }
    };
    let gone = node.links.lock().expect("links").remove(&gen);
    if let Some(l) = gone {
        l.tunnels.clear();
        let mut a = node.audit_link.lock().expect("audit link");
        if *a == Some(gen) {
            *a = None;
            node.shipped.store(-1, Ordering::SeqCst);
            // Another connection, if any, takes over the audit shipping from its own watermark.
            let next = node.links.lock().expect("links").iter().filter(|(_, l)| l.scope.starts_with("run_")).map(|(g, _)| *g).max();
            if let Some(g) = next {
                node.send_to(g, Frame::Msg(Msg::AuditAsk {}));
            }
        }
        eprintln!(
            "[node] control host disconnected{}; its boxes keep running on the feed held",
            if scope.is_empty() { String::new() } else { format!(" ({scope})") }
        );
    }
    writer.abort();
    result
}

pub(super) async fn handle(node: &Arc<Node>, gen: u64, tunnels: &Tunnels, f: Frame) -> Result<()> {
    match f {
        Frame::Feed(bytes) => {
            let now = (node.clock)();
            let r = node.replica.lock().expect("replica").accept_bytes(&bytes, now);
            if let Err(e) = &r {
                eprintln!("[node] feed frame refused: {} ({e})", e.kind());
                let _ = node.audit.lock().expect("audit").audit(
                    &wicket_core::TenantId::single(),
                    None,
                    "feed.refused",
                    &serde_json::json!({ "kind": e.kind(), "why": e.to_string() }),
                );
            }
            if r.is_ok() {
                if let Ok(f) = wicket_feed::Frame::parse(&bytes) {
                    if matches!(f.kind, wicket_feed::FrameKind::Delta | wicket_feed::FrameKind::Snap) {
                        let epoch = node.replica.lock().expect("replica").state().map(|s| s.epoch);
                        eprintln!(
                            "[node] feed {} applied, epoch {} (at {} ms)",
                            f.kind.as_str(),
                            epoch.unwrap_or(0),
                            wicket_feed::now_ms()
                        );
                    }
                }
            }
            node.send_to(gen, node.feed_status(r.as_ref().err()));
        }
        Frame::Data { stream, offset, bytes } if stream & TUNNEL_BIT != 0 => {
            tunnels.data(stream, bytes);
            let _ = offset;
        }
        Frame::Data { stream, offset, bytes } => {
            let mut boxes = node.boxes.lock().expect("boxes");
            if let Some(b) = boxes.values_mut().find(|b| b.owner == Some(gen) && b.streams[0] == stream) {
                let (fresh, _) = accept_at(&mut b.stdin_next, offset, &bytes);
                if let (Some(s), false) = (&b.stdin, fresh.is_empty()) {
                    s.push(&fresh);
                    b.record.stdin_received = b.stdin_next;
                    let _ = b.record.save(&b.dir);
                }
            }
        }
        Frame::Msg(m) => match m {
            Msg::Start(bs) => {
                let n = node.clone();
                tokio::spawn(async move {
                    let run = bs.run.clone();
                    let (digest, error) = match start_box(&n, Some(gen), *bs).await {
                        Ok(d) => (Some(d), None),
                        Err(e) => (None, Some(format!("{e:#}"))),
                    };
                    if let Some(e) = &error {
                        eprintln!("[node] starting {run} failed: {e}");
                    }
                    n.send_to(gen, Frame::Msg(Msg::Started { run, error, digest }));
                });
            }
            Msg::Resume { run, stdout_from, stderr_from } => {
                let (frames, exited) = {
                    let mut boxes = node.boxes.lock().expect("boxes");
                    let Some(b) = boxes.get_mut(&run) else { return Ok(()) };
                    // The resuming connection owns the box from now on.
                    b.owner = Some(gen);
                    let mut v = vec![];
                    for (i, from) in [(0usize, stdout_from), (1, stderr_from)] {
                        let (at, bytes) = b.out[i].since(from);
                        for (k, c) in bytes.chunks(32 * 1024).enumerate() {
                            v.push(Frame::Data { stream: b.streams[i + 1], offset: at + (k * 32 * 1024) as u64, bytes: c.to_vec() });
                        }
                    }
                    (v, b.exited.clone())
                };
                for f in frames {
                    node.send_to(gen, f);
                }
                // Children this node started for it (#164) that its control host hasn't taken
                // over: before its exit is replayed, so it learns of them whatever happens.
                if node.proto_of(&run) >= chan::EDGE_DECISIONS {
                    for c in node.edge.unadopted(&run) {
                        node.send_to(gen, Frame::Msg(c.msg()));
                    }
                }
                // Asks raised while it was away (#153), with their original time.
                for q in node.queue.of(&run) {
                    let id = node.id();
                    node.requeued.lock().expect("requeued").insert(id, q.id.clone());
                    node.send_to(
                        gen,
                        Frame::Msg(Msg::Ask {
                            id,
                            run: q.run,
                            op: Box::new(q.op),
                            why: q.why,
                            who: q.who,
                            queued: Some((q.id, q.at)),
                            prefix: q.prefix,
                        }),
                    );
                }
                // Tool calls that needed a human while it was away (#164): made now.
                gw::replay(node, &run);
                if let Some((code, result)) = exited {
                    let reason = node.causes.lock().expect("causes").get(&run).cloned();
                    node.send_to(gen, Frame::Msg(Msg::Exited { run, code, result, reason }));
                }
            }
            Msg::Ack { stream, upto } => {
                let mut boxes = node.boxes.lock().expect("boxes");
                for b in boxes.values_mut().filter(|b| b.owner == Some(gen)) {
                    for i in 0..2 {
                        if b.streams[i + 1] == stream {
                            b.out[i].ack(upto);
                        }
                    }
                }
            }
            Msg::StdinClose { run } => {
                if let Some(b) = node.boxes.lock().expect("boxes").get_mut(&run) {
                    if let Some(f) = b.stdin.take() {
                        f.close();
                        b.record.stdin_closed = true;
                        let _ = b.record.save(&b.dir);
                    }
                }
            }
            Msg::Kill { run } => {
                let name = node.boxes.lock().expect("boxes").get(&run).map(|b| b.name.clone());
                if let Some(name) = name {
                    node.stopped.lock().expect("stopped").entry(run.clone()).or_insert_with(|| "its control host stopped it".into());
                    // A paused (idle) box is unpaused first, so it can be killed.
                    let _ = node.docker.unpause(&name).await;
                    let _ = node.docker.kill(&name).await;
                }
            }
            // A child this node started (#164): taken over by its control host, or refused (and
            // then stopped here).
            Msg::Adopted { child, error } => {
                if node.edge.adopted(&child).is_some() {
                    match &error {
                        None => node.audit_note(&child, "node.child_adopted", serde_json::json!({})),
                        Some(e) => {
                            eprintln!("[node] {child}: the control host refused the child this node started ({e}); stopping it");
                            node.audit_note(&child, "node.child_refused", serde_json::json!({ "why": e }));
                            node.stopped.lock().expect("stopped").insert(child.clone(), format!("refused by the control host: {e}"));
                            let name = node.boxes.lock().expect("boxes").get(&child).map(|b| b.name.clone());
                            if let Some(name) = name {
                                let _ = node.docker.kill(&name).await;
                            }
                        }
                    }
                }
            }
            Msg::RunLease { .. } => {}
            Msg::Lease { run, lease } => {
                if let Some(sl) = &lease.slice {
                    if let Err(e) = node.slices.put(&run, sl) {
                        eprintln!("[node] {run}: keeping its budget slice: {e:#}");
                    }
                }
                if let Some(l) = node.llms.lock().expect("llms").get(&run) {
                    l.set_slice(lease.slice);
                }
            }
            Msg::SecretRevoke { run, name } => node.secrets.revoke(&run, &name),
            m @ Msg::SecretFetched { .. } => {
                let Msg::SecretFetched { id, .. } = &m else { unreachable!() };
                if let Some(tx) = node.asks.lock().expect("asks").remove(id) {
                    let _ = tx.send(m);
                }
            }
            Msg::Forget { run } => {
                let b = node.boxes.lock().expect("boxes").remove(&run);
                if let Some(b) = b {
                    b.tasks.iter().for_each(|t| t.abort());
                    // The control host's own node shares the run's directory with the run: that stays.
                    if !node.paths.shares_host() && b.dir.starts_with(node.paths.runs()) {
                        let _ = std::fs::remove_dir_all(&b.dir);
                    }
                }
            }
            m @ Msg::Asked { .. } => {
                let Msg::Asked { id, .. } = &m else { unreachable!() };
                // A queued ask the control host has now taken (raised, found denied, or refused):
                // off the queue. It is idempotent there, so a resend after a flap is harmless.
                if let Some(q) = node.requeued.lock().expect("requeued").remove(id) {
                    // Its request, for `await_grant` on the node-local id (#164).
                    let request = match &m {
                        Msg::Asked { pending: Some((r, _)), .. } | Msg::Asked { denied: Some(r), .. } => Some(r.clone()),
                        _ => None,
                    };
                    if let (Some(r), Some(qa)) = (request, node.queue.get(&q)) {
                        node.edge.raised(&q, &qa.run, &r);
                    }
                    node.queue.remove(&q);
                }
                if let Some(tx) = node.asks.lock().expect("asks").remove(id) {
                    let _ = tx.send(m);
                }
            }
            Msg::AuditFrom { seq } => {
                {
                    let _one = node.shipping.lock().expect("shipping");
                    *node.audit_link.lock().expect("audit link") = Some(gen);
                    node.shipped.store(seq, Ordering::SeqCst);
                }
                node.ship_audit();
            }
            Msg::TunnelOpened { stream, error } => {
                if let Some(tx) = node.opens.lock().expect("opens").remove(&stream) {
                    let _ = tx.send(error);
                }
            }
            Msg::Close { stream } => tunnels.close(stream),
            Msg::BoxCtl { id, run, what, user, arg } => {
                let n = node.clone();
                tokio::spawn(async move {
                    let (out, error) = match box_ctl(&n, &run, &what, &user, &arg).await {
                        Ok(o) => (o, None),
                        Err(e) => (None, Some(format!("{e:#}"))),
                    };
                    n.send_to(gen, Frame::Msg(Msg::BoxCtlDone { id, out, error }));
                });
            }
            Msg::Exec { stream, run, user, argv, stdin } => {
                let out = node.links.lock().expect("links").get(&gen).map(|l| l.out.clone());
                let (Some(out), true) = (out, stream & TUNNEL_BIT != 0 && stream & chan::CONTROL_TUNNEL_BIT != 0) else {
                    return Ok(());
                };
                let found = node
                    .boxes
                    .lock()
                    .expect("boxes")
                    .get(&run)
                    .filter(|b| b.exited.is_none())
                    .map(|b| (b.name.clone(), if user.is_empty() { b.user.clone() } else { user.clone() }));
                let spawned = match found {
                    None => Err(format!("run {run} has no running box on this node")),
                    Some((name, user)) => node
                        .docker
                        .exec(&name, &user, if stdin { &["-i"] } else { &[] }, &argv)
                        .stdin(if stdin { std::process::Stdio::piped() } else { std::process::Stdio::null() })
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .kill_on_drop(true)
                        .spawn()
                        .map_err(|e| format!("docker exec: {e}")),
                };
                match spawned {
                    Err(e) => {
                        node.send_to(gen, Frame::Msg(Msg::TunnelOpened { stream, error: Some(e) }));
                    }
                    Ok(mut c) => {
                        let rd = c.stdout.take().expect("stdout");
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
            Msg::PutTree { stream, run, tree } => transfer(node, gen, tunnels, stream, &run, &tree, true),
            Msg::GetTree { stream, run, tree } => transfer(node, gen, tunnels, stream, &run, &tree, false),
            Msg::Listen { id, run, sock, dial } => {
                let error = match dial {
                    None => listen(node, gen, &run, &sock),
                    Some((to, port)) => listen_direct(node, &run, &sock, &to, port),
                }
                .err()
                .map(|e| format!("{e:#}"));
                node.send_to(gen, Frame::Msg(Msg::BoxCtlDone { id, out: None, error }));
            }
            Msg::Unlisten { run, sock } => {
                if let Some(b) = node.boxes.lock().expect("boxes").get_mut(&run) {
                    if let Some(t) = b.listeners.remove(&sock) {
                        t.abort();
                    }
                    let _ = std::fs::remove_file(b.dir.join("sock").join(&sock));
                }
            }
            Msg::NodeCert { cert } => {
                let now = (node.clock)() / 1000;
                let (serial, error) = match node.ident.install_cert(&node.paths.root, cert.trim(), &node.name, now) {
                    Ok(c) => {
                        eprintln!("[node] identity certificate renewed: {}… until {}", &c.jti[..12], c.exp);
                        (c.jti, None)
                    }
                    Err(e) => {
                        eprintln!("[node] refused a renewed identity certificate: {e:#}");
                        (String::new(), Some(format!("{e:#}")))
                    }
                };
                node.send_to(gen, Frame::Msg(Msg::NodeCertInstalled { serial, error }));
            }
            other => bail!("unexpected message from the control host: {other:?}"),
        },
    }
    Ok(())
}
