//! CONNECT handling (#62, #141): splicing a host through, tunnelling, and refusing a host the
//! node's CA can't cover (#257). Part of [`super::Egress`], split out of `egress.rs` (#220).

use super::*;

impl Egress {
    /// The reach rule that allows `host` wholesale, if this connection may be spliced through (#62):
    /// the decider says so (on a node, only while its policy is fresh, #141), and nothing is swapped
    /// in for the host. Asked at CONNECT and again every few seconds while a spliced connection lasts.
    pub(crate) fn splice_rule(&self, host: &str) -> Option<usize> {
        if self.ctx.swaps.iter().any(|s| host_matches(&s.host, host)) {
            return None;
        }
        if self.model_gate.get().is_some_and(|l| l.is_model_host(host)) {
            return None;
        }
        // A zone that caps egress (#368) is counted request by request: nothing is spliced.
        if self.capped() {
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
        self.serve_decrypted(tls, host, hyper::server::conn::http1::Builder::new()).await
    }

    /// Serves the requests of a tunnel to `host` whose TLS is already terminated (`io` carries the
    /// box's plaintext HTTP/1.1), with `http1`'s settings: what [`Self::tunnel_io`] does after the
    /// handshake. Public for the fuzz targets (#323), which feed it raw bytes.
    #[doc(hidden)]
    pub async fn serve_decrypted<S>(self: Arc<Self>, io: S, host: String, http1: hyper::server::conn::http1::Builder) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let me = self.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let host = host.clone();
            async move { Ok::<_, hyper::Error>(me.handle(req, host, "https", Via::Tcp).await) }
        });
        http1.serve_connection(TokioIo::new(io), svc).await?;
        Ok(())
    }

    /// A CONNECT to a host the node's CA can't cover, which the box's token doesn't allow wholesale
    /// (so it can't be spliced either): refused. Since #257's slice 3 the control host decides no
    /// request, so nothing is forwarded to it; an operator who wants the host served by the node
    /// widens its CA.
    pub(super) fn refuse_uncovered(&self, host: &str, why: &str) -> Response<BoxBody> {
        self.ctx.emit(Event::Egress {
            method: "CONNECT".into(),
            host: host.into(),
            path: "/".into(),
            risk: "-".into(),
            outcome: "forbidden".into(),
            detail: format!("not served on this node ({why})"),
        });
        problem(
            403,
            "forbidden",
            "Blocked by wicket box: host not served on this node",
            &format!(
                "{host} can't be reached from this box's node ({why}), and wicket doesn't forward it anywhere else. Retrying won't help; continue without it and tell the user, who can have the node's CA cover it (`wicket node renew-ca <node> --hosts ...`). {}",
                crate::BOX_FACT
            ),
            None,
        )
    }
}
