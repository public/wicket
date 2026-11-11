//! The egress proxy (design §9.1): CONNECT, terminate TLS with the run's CA, canonicalize-or-reject,
//! decide, then forward with client credentials stripped and the zone's credential injected into
//! its one declared header slot.

use crate::ca::RunCa;
use crate::{full, problem, BoxBody, Event, RunCtx, STRIP_REQUEST, STRIP_RESPONSE};
use anyhow::Result;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use wicket_core::{canonical_path, manifest::host_matches, Op, Verdict};

const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

pub struct Egress {
    ctx: RunCtx,
    ca: Arc<RunCa>,
    client: reqwest::Client,
    /// Blocked attempts this run: per request (or host), and in total.
    strikes: std::sync::Mutex<(std::collections::HashMap<String, u32>, u32)>,
}

impl Egress {
    pub fn new(ctx: RunCtx, ca: Arc<RunCa>) -> Result<Arc<Egress>> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(15))
            .build()?;
        Ok(Arc::new(Egress { ctx, ca, client, strikes: Default::default() }))
    }

    /// Serves CONNECT (and plain absolute-form HTTP) on a unix socket until the task is dropped.
    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        let _ = std::fs::remove_file(socket);
        let listener = UnixListener::bind(socket)?;
        loop {
            let (stream, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| me.clone().outer(req));
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).with_upgrades().await;
            });
        }
    }

    async fn outer(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<BoxBody>, hyper::Error> {
        if req.method() == Method::CONNECT {
            let Some(auth) = req.uri().authority().cloned() else {
                return Ok(problem(400, "bad-request", "Bad CONNECT", "CONNECT needs host:port", None));
            };
            let host = auth.host().trim_end_matches('.').to_ascii_lowercase();
            let port = auth.port_u16().unwrap_or(443);
            if port != 443 {
                return Ok(self.refuse(&host, "CONNECT", "/", &format!("only port 443 is proxied (asked for {port})")));
            }
            if host.parse::<std::net::IpAddr>().is_ok() {
                return Ok(self.refuse(&host, "CONNECT", "/", "IP literals are not proxied; use a hostname"));
            }
            if let Some(r) = self.judge_host(&host, "CONNECT") {
                return Ok(r);
            }
            let me = self.clone();
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = me.clone().tunnel(upgraded, host.clone()).await {
                            tracing::debug!(%host, error = %e, "tunnel ended");
                        }
                    }
                    Err(e) => tracing::debug!(error = %e, "upgrade failed"),
                }
            });
            return Ok(Response::new(full(Bytes::new())));
        }
        // Absolute-form plain HTTP request.
        let host = req.uri().host().map(|h| h.to_ascii_lowercase());
        match host {
            Some(h) if req.uri().scheme_str() == Some("http") => {
                if let Some(r) = self.judge_host(&h, req.method().as_str()) {
                    return Ok(r);
                }
                let me = self.clone();
                Ok(me.handle(req, h, "http").await)
            }
            _ => Ok(problem(400, "bad-request", "Not a proxy request", "use CONNECT or an absolute http:// URL", None)),
        }
    }

    async fn tunnel(self: Arc<Self>, upgraded: hyper::upgrade::Upgraded, host: String) -> Result<()> {
        let cfg = self.ca.server_config(&host)?;
        let tls = tokio_rustls::TlsAcceptor::from(cfg).accept(TokioIo::new(upgraded)).await?;
        let me = self.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let host = host.clone();
            async move { Ok::<_, hyper::Error>(me.handle(req, host, "https").await) }
        });
        hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await?;
        Ok(())
    }

    /// Decides about a host before any request to it (and before TLS): never-reachable hosts are
    /// refused, saying so; in zones that hide unlisted hosts, they behave as if they didn't exist.
    fn judge_host(&self, host: &str, method: &str) -> Option<Response<BoxBody>> {
        match self.ctx.zone.host_verdict(host) {
            wicket_core::HostVerdict::Open => None,
            wicket_core::HostVerdict::Forbidden(why) => {
                self.ctx.emit(Event::Egress {
                    method: method.into(),
                    host: host.into(),
                    path: "/".into(),
                    risk: "-".into(),
                    outcome: "forbidden".into(),
                    detail: why.clone(),
                });
                let note = self.strike(&format!("host {host}"));
                Some(problem(403, "forbidden", "Blocked by wicket sandbox: never allowed", &format!(
                    "{why}. This will never be allowed from this sandbox, and no approval can change that. {} Do not retry it; tell the user it is blocked.{note}",
                    crate::SANDBOX_FACT
                ), None))
            }
            wicket_core::HostVerdict::Hidden => {
                self.ctx.emit(Event::Egress {
                    method: method.into(),
                    host: host.into(),
                    path: "/".into(),
                    risk: "-".into(),
                    outcome: "hidden".into(),
                    detail: "not a host this zone can see".into(),
                });
                let note = self.strike(&format!("host {host}"));
                Some(problem(502, "unknown-host", "wicket sandbox: unknown host", &format!(
                    "{host} does not exist as far as this sandbox is concerned: it can only see the hosts its zone names. {} Do not retry it.{note}",
                    crate::SANDBOX_FACT
                ), None))
            }
        }
    }

    /// Counts a blocked attempt and returns a note for the agent once it starts repeating itself: the
    /// point is that an agent at the edge of its sandbox stops and asks, rather than spinning.
    fn strike(&self, key: &str) -> String {
        let (same, total) = {
            let mut s = self.strikes.lock().expect("strikes");
            let same = {
                let n = s.0.entry(key.to_string()).or_insert(0);
                *n += 1;
                *n
            };
            s.1 += 1;
            (same, s.1)
        };
        if total == 10 || (total > 10 && total % 10 == 0) {
            self.ctx
                .emit(Event::Tool { name: "wicket".into(), detail: format!("agent may be stuck: {total} blocked requests in this run") });
        }
        let mut note = String::new();
        if same >= 3 {
            note.push_str(&format!(" This exact request has now been blocked {same} times: stop retrying it."));
        }
        if total >= 10 {
            note.push_str(&format!(" This run has hit the sandbox's limits {total} times. Stop exploring alternatives: tell the user what you need, or call request_access once with a reason."));
        }
        note
    }

    fn refuse(&self, host: &str, method: &str, path: &str, why: &str) -> Response<BoxBody> {
        self.ctx.emit(Event::Egress {
            method: method.into(),
            host: host.into(),
            path: path.into(),
            risk: "-".into(),
            outcome: "forbidden".into(),
            detail: why.into(),
        });
        problem(403, "forbidden", "Blocked by wicket sandbox: malformed request", &format!("{why}. {}", crate::SANDBOX_FACT), None)
    }

    /// Decide and, if allowed, forward one request. `host` is the CONNECT target (or the absolute
    /// URL's host), never a client-supplied Host header.
    async fn handle(self: Arc<Self>, req: Request<Incoming>, host: String, scheme: &str) -> Response<BoxBody> {
        let method = req.method().as_str().to_string();
        // Authority pinning: a Host header that disagrees with the tunnel target is an attack.
        if let Some(h) = req.headers().get(http::header::HOST).and_then(|v| v.to_str().ok()) {
            let h = h.split(':').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase();
            if !h.is_empty() && h != host {
                return self.refuse(&host, &method, "/", &format!("Host header {h:?} does not match the tunnel target"));
            }
        }
        let pq = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        let path = match canonical_path(&pq) {
            Ok(p) => p.to_string(),
            Err(e) => return self.refuse(&host, &method, &pq, &format!("ambiguous path: {e}")),
        };
        let ctx = &self.ctx;
        let query = pq.split_once('?').map(|(_, q)| q).unwrap_or("");
        let op = Op::egress_with_query(&ctx.tenant, &ctx.run, &ctx.zone.name, &method, &host, &path, query);
        let risk = format!("{:?}", op.risk);
        let emit = |outcome: &str, detail: String| {
            ctx.emit(Event::Egress {
                method: method.clone(),
                host: host.clone(),
                path: path.clone(),
                risk: risk.clone(),
                outcome: outcome.into(),
                detail,
            })
        };
        match ctx.zone.evaluate(&op) {
            Verdict::AllowByReach(i) => emit("allow", format!("reach rule {i}")),
            Verdict::Forbidden(why) => {
                emit("forbidden", why.clone());
                let note = self.strike(&op.digest());
                return problem(403, "forbidden", "Blocked by wicket sandbox: never allowed", &format!(
                    "{why}. This will never be allowed from this sandbox, and no approval can change that. {} Do not retry it; tell the user it is blocked.{note}",
                    crate::SANDBOX_FACT
                ), None);
            }
            Verdict::NeedsGrant(why) if !ctx.escalate => {
                emit("forbidden", format!("{why}; this run does not escalate (on_pending: fail)"));
                return problem(
                    403,
                    "forbidden",
                    "Outside this program's reach",
                    &format!("{why}. Programs do not escalate: change the program's approved reach instead."),
                    None,
                );
            }
            Verdict::NeedsGrant(why) => {
                // Who in the box is asking (reported by the agent's own event stream, not proven).
                let who = ctx.attribute.as_ref().and_then(|f| f(&host, &path));
                let mut ledger = ctx.ledger.lock().expect("ledger lock");
                match ledger.consume_grant(&op) {
                    Ok(Some(gid)) => {
                        let approved_for: Vec<String> = ledger
                            .request_for_grant(&gid)
                            .ok()
                            .flatten()
                            .map(|r| r.attribution.iter().flat_map(crate::attributed_agents).collect())
                            .unwrap_or_default();
                        drop(ledger);
                        let mut detail = format!("grant {gid}");
                        if let Some((v, line)) = &who {
                            detail.push_str(&format!("; used by {line}"));
                            let users = crate::attributed_agents(v);
                            // The grant is usable by anything in the box; flag use by someone else.
                            if !approved_for.is_empty() && !users.is_empty() && !users.iter().any(|u| approved_for.contains(u)) {
                                detail.push_str(&format!("; WARNING: approved for {}", approved_for.join(" | ")));
                            }
                        }
                        emit("allow", detail);
                    }
                    Ok(None) => {
                        if let Ok(Some(rid)) = ledger.denied_recently(&op) {
                            drop(ledger);
                            emit("denied", format!("request {rid} was denied"));
                            let note = self.strike(&op.digest());
                            return problem(403, "denied", "Blocked by wicket sandbox: denied by a human", &format!(
                                "A human denied request {rid} for exactly this request. {} Do not retry it; continue without it and tell the user.{note}",
                                crate::SANDBOX_FACT
                            ), None);
                        }
                        let res = ledger.pending_for(&op, &why, who.as_ref().map(|(v, _)| v));
                        drop(ledger);
                        return match res {
                            Ok((rid, fresh)) => {
                                let for_line = who.as_ref().map(|(_, l)| format!("; for {l}")).unwrap_or_default();
                                emit("pending", format!("{rid}{}: {why}{for_line}", if fresh { " (new)" } else { "" }));
                                let note = self.strike(&op.digest());
                                problem(403, "pending-approval", "Blocked by wicket sandbox: needs human approval", &format!(
                                    "{why}. wicket has asked a human to approve request {rid}; until they do, this request fails every time. {} Call await_grant with {rid} to wait, or tell the user that request {rid} is waiting for their approval in wicket (approvals happen in wicket, not in this conversation).{note}",
                                    crate::SANDBOX_FACT
                                ), Some(&rid))
                            }
                            Err(e) => problem(500, "error", "Ledger error", &e.to_string(), None),
                        };
                    }
                    Err(e) => return problem(500, "error", "Ledger error", &e.to_string(), None),
                }
            }
        }
        match self.forward(req, &host, scheme, &pq).await {
            Ok(r) => r,
            Err(e) => problem(502, "upstream", "Upstream error", &e.to_string(), None),
        }
    }

    async fn forward(&self, req: Request<Incoming>, host: &str, scheme: &str, pq: &str) -> Result<Response<BoxBody>> {
        let (parts, body) = req.into_parts();
        // What the box put in Authorization: only ever a placeholder, to be swapped (below) or dropped.
        let box_auth = parts.headers.get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);
        let body = Limited::new(body, MAX_REQUEST_BODY).collect().await.map_err(|e| anyhow::anyhow!("request body: {e}"))?.to_bytes();
        let url = format!("{scheme}://{host}{pq}");
        let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?;
        let mut rb = self.client.request(method, &url);
        for (name, value) in parts.headers.iter() {
            if !STRIP_REQUEST.contains(&name.as_str()) {
                rb = rb.header(name.as_str(), value.as_bytes());
            }
        }
        // Inject the zone's credential for this host into its one declared slot. An optional rule
        // whose secret isn't set sends the request without it (e.g. anonymous reads).
        let mut injected: Vec<String> = Vec::new();
        for rule in &self.ctx.zone.inject {
            if host_matches(&rule.host, host) {
                let secret = match self.ctx.vault.get(&rule.secret) {
                    Ok(s) => s,
                    Err(_) if rule.optional => break,
                    Err(e) => return Err(e),
                };
                let value = render_credential(&rule.format, &secret);
                rb = rb.header(rule.header.as_str(), value.as_str());
                injected.push(secret);
                injected.push(value);
                break;
            }
        }
        if injected.is_empty() {
            if let Some(auth) = &box_auth {
                let presented = auth.strip_prefix("Bearer ").unwrap_or("");
                match self.ctx.swaps.iter().find(|s| host_matches(&s.host, host) && !presented.is_empty() && s.placeholder == presented) {
                    Some(sw) => {
                        let real = match &sw.real {
                            crate::SwapSource::Vault(name) => self.ctx.vault.get(name)?,
                            crate::SwapSource::Value(v) => v.clone(),
                        };
                        rb = rb.header("authorization", format!("Bearer {real}"));
                        injected.push(real);
                        tracing::debug!(host, swap = %sw.name, "credential swapped");
                    }
                    None => tracing::debug!(host, "box-supplied authorization dropped (not a known placeholder)"),
                }
            }
        }
        let resp = rb.body(body).send().await?;
        let status = StatusCode::from_u16(resp.status().as_u16())?;
        let mut out = Response::builder().status(status);
        for (name, value) in resp.headers().iter() {
            if STRIP_RESPONSE.contains(&name.as_str()) {
                continue;
            }
            // Never reflect an injected credential back into the box.
            if injected.iter().any(|s| value.as_bytes().windows(s.len()).any(|w| w == s.as_bytes())) {
                continue;
            }
            out = out.header(name.as_str(), value.as_bytes());
        }
        let stream = resp.bytes_stream().map_ok(Frame::data).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        Ok(out.body(BodyExt::boxed(StreamBody::new(stream)))?)
    }
}

/// Renders an injection format: `{secret}` is the secret itself; `{basic:USER}` is
/// base64("USER:secret"), for HTTP Basic credentials such as git over HTTPS with a token.
pub fn render_credential(format: &str, secret: &str) -> String {
    use base64::Engine;
    let mut out = format.replace("{secret}", secret);
    while let Some(start) = out.find("{basic:") {
        let Some(len) = out[start..].find('}') else { break };
        let user = out[start + 7..start + len].to_string();
        let enc = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}"));
        out.replace_range(start..start + len + 1, &enc);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn credential_formats() {
        assert_eq!(super::render_credential("Bearer {secret}", "tok"), "Bearer tok");
        // base64("x-access-token:tok")
        assert_eq!(super::render_credential("Basic {basic:x-access-token}", "tok"), "Basic eC1hY2Nlc3MtdG9rZW46dG9r");
    }
}
