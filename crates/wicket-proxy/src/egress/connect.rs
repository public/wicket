//! CONNECT handling (#62, #141): splicing a host through, tunnelling, and forwarding a connection
//! to the control host's egress proxy. Part of [`super::Egress`], split out of `egress.rs` (#220).

use super::*;

impl Egress {
    /// The reach rule that allows `host` wholesale, if this connection may be spliced through (#62):
    /// the decider says so (on a node, only while its policy is fresh, #141), and nothing is swapped
    /// in for the host. Asked at CONNECT and again every few seconds while a spliced connection lasts.
    pub(crate) fn splice_rule(&self, host: &str) -> Option<usize> {
        if self.ctx.swaps.iter().any(|s| host_matches(&s.host, host)) {
            return None;
        }
        if self.model_gate.get().is_some() && host == crate::llm::MODEL_HOST {
            return None;
        }
        // A name under a wildcard is only dialled (so resolved) after a request to it has been
        // decided and allowed (#20): until then its connections are inspected, never spliced, since
        // splicing dials at CONNECT.
        if !self.wildcard_reached(host) {
            return None;
        }
        self.decider.splice(&self.ctx, host)
    }

    /// A CONNECT to a host allowed wholesale: dial it now (a refused dial is the CONNECT's answer),
    /// then relay the box's TLS unmodified (see [`crate::splice`]).
    pub(super) async fn splice_connect(self: Arc<Self>, req: Request<Incoming>, host: String, rule: usize) -> Response<BoxBody> {
        let up = match crate::splice::dial(&self.upstream, &host).await {
            Ok(s) => s,
            Err(e) => {
                let refused = e.kind() == std::io::ErrorKind::PermissionDenied;
                self.ctx.emit(Event::Egress {
                    method: "CONNECT".into(),
                    host: host.clone(),
                    path: "/".into(),
                    risk: "-".into(),
                    outcome: if refused { "forbidden" } else { "error" }.into(),
                    detail: format!("splice-through (reach rule {rule}): {e}"),
                });
                return problem(502, "upstream", "Upstream error", &format!("{host}: {e}"), None);
            }
        };
        let me = self.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => crate::splice::serve(me, upgraded, up, host, rule).await,
                Err(e) => tracing::debug!(error = %e, "upgrade failed"),
            }
        });
        Response::new(full(Bytes::new()))
    }

    pub(super) async fn tunnel(self: Arc<Self>, upgraded: hyper::upgrade::Upgraded, host: String) -> Result<()> {
        self.tunnel_io(TokioIo::new(upgraded), host).await
    }

    /// Terminates the box's TLS for `host` on any byte stream and serves its requests.
    pub(crate) async fn tunnel_io<S>(self: Arc<Self>, io: S, host: String) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let cfg = self.ca.server_config(&host)?;
        let tls = tokio_rustls::TlsAcceptor::from(cfg).accept(io).await?;
        let me = self.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let host = host.clone();
            async move { Ok::<_, hyper::Error>(me.handle(req, host, "https", Via::Tcp).await) }
        });
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await?;
        Ok(())
    }

    /// Tunnels a CONNECT, raw, to the control host's egress proxy for this run (a node's forwarded
    /// host): the control host decides and terminates TLS there. Its answer to the CONNECT is the
    /// box's answer; after a 200 the bytes are piped both ways. Unreachable: a 403 that says so.
    pub(super) async fn forward_connect(self: Arc<Self>, req: Request<Incoming>, host: String, why: String) -> Response<BoxBody> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let unreachable = |me: &Egress| {
            me.ctx.emit(Event::Egress {
                method: "CONNECT".into(),
                host: host.clone(),
                path: "/".into(),
                risk: "-".into(),
                outcome: "unavailable".into(),
                detail: format!("served by the control host ({why}), which is unreachable"),
            });
            problem(
                403,
                "unavailable",
                "Blocked by wicket sandbox: control plane unreachable",
                &format!(
                    "{host} is served by wicket's control host ({why}), which this node can't reach right now; retry later. {}",
                    crate::SANDBOX_FACT
                ),
                None,
            )
        };
        let Some(relay) = self.relay.clone() else { return unreachable(&self) };
        let mut s = match relay.open().await {
            Ok(s) => s,
            Err(_) => return unreachable(&self),
        };
        let connect = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
        if s.write_all(connect.as_bytes()).await.is_err() {
            return unreachable(&self);
        }
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match s.read(&mut byte).await {
                Ok(1) if head.len() < MAX_FORWARDED_HEAD => head.push(byte[0]),
                _ => return unreachable(&self),
            }
        }
        let Some((status, reason, headers)) = parse_head(&head) else { return unreachable(&self) };
        self.ctx.emit(Event::Egress {
            method: "CONNECT".into(),
            host: host.clone(),
            path: "/".into(),
            risk: "-".into(),
            outcome: "forwarded".into(),
            detail: format!("to the control host ({why}): {status}"),
        });
        if status == 200 {
            tokio::spawn(async move {
                if let Ok(up) = hyper::upgrade::on(req).await {
                    let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(up), &mut s).await;
                }
            });
            return Response::new(full(Bytes::new()));
        }
        let len = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse::<usize>().ok()).unwrap_or(0);
        let mut body = vec![0u8; len.min(MAX_FORWARDED_HEAD)];
        if s.read_exact(&mut body).await.is_err() {
            body.clear();
        }
        let mut b = Response::builder().status(status);
        for (k, v) in headers.iter().filter(|(k, _)| k == "content-type" || k.starts_with("x-wicket") || k == "retry-after") {
            b = b.header(k.as_str(), v.as_str());
        }
        let mut resp = b.body(full(body)).unwrap_or_else(|_| unreachable(&self));
        if let Ok(r) = hyper::ext::ReasonPhrase::try_from(reason) {
            resp.extensions_mut().insert(r);
        }
        resp
    }
}

/// A response head: status, reason phrase, and headers with lowercase names.
pub(super) type Head = (u16, String, Vec<(String, String)>);

/// Parses an HTTP/1.1 response head.
pub(super) fn parse_head(head: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.splitn(3, ' ');
    let status = first.nth(1)?.parse().ok()?;
    let reason = first.next().unwrap_or("").to_string();
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
    Some((status, reason, headers))
}
