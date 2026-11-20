//! The request that goes upstream: refused shapes (#130), headers by allowlist, the zone's
//! credential injected into its one slot or a placeholder swapped, and the body readied. Part of
//! [`super::Egress`], split out of `egress.rs` (#220).

use super::*;

/// What became of an inject rule's credential on a request (#415).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Injection {
    /// The request carried it.
    Carried,
    /// The request went without it: an optional rule whose secret isn't set.
    Skipped,
    /// The request was refused for want of it: a required rule's secret isn't set, can't be had, or
    /// isn't bound to the host.
    Failed,
}

impl Egress {
    /// Whether the zone injects a credential into requests for `host`, or swaps one in. What the
    /// zone declares, whether or not its secret is set now (#415): it may be set while the run lasts.
    pub(super) fn credentials_for(&self, host: &str) -> bool {
        self.ctx.zone.inject.iter().any(|r| host_matches(&r.host, host)) || self.ctx.swaps.iter().any(|s| host_matches(&s.host, host))
    }

    /// Notes what became of `rule`'s credential on a request for its host (#415). The secret is read
    /// at each request, so one set, rotated or removed while the run lasts is used, or left out, from
    /// the next. Audited when that changes, not per request: the first request left without it
    /// (`inject.skipped`, the request going without it, #175; `inject.unavailable`, the request
    /// failing), and the first carrying it again (`inject.available`).
    pub(super) fn note_injection(&self, rule: &wicket_core::manifest::InjectRule, now: Injection, why: &str) {
        let before = self.carried.lock().expect("carried").insert(format!("{}\n{}", rule.host, rule.secret), now);
        let kind = match (before, now) {
            (Some(b), n) if b == n => return,
            (None, Injection::Carried) => return,
            (_, Injection::Carried) => "inject.available",
            (_, Injection::Skipped) => "inject.skipped",
            (_, Injection::Failed) => "inject.unavailable",
        };
        let why = match (before, now) {
            (_, Injection::Carried) => "its secret is set".to_string(),
            (Some(Injection::Carried), _) => format!("its secret was removed or is unusable: {why}"),
            _ => why.to_string(),
        };
        tracing::info!(host = %rule.host, secret = %rule.secret, %why, "{kind}");
        if let Ok(l) = self.ctx.ledger.lock() {
            let _ = l.audit_deferred(
                &self.ctx.tenant,
                Some(&self.ctx.run),
                kind,
                &serde_json::json!({ "host": rule.host, "secret": rule.secret, "optional": rule.optional, "why": why }),
            );
        }
    }

    pub(crate) async fn forward<B>(&self, req: Request<B>, host: &str, scheme: &str, pq: &str, via: Via) -> Result<Response<BoxBody>>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        // Over HTTP/3 the request may be re-sent over HTTP/2 if the HTTP/3 connection is gone, so its
        // body is read whole; otherwise it streams.
        let out = self.prepare(req, host, scheme, pq, via != Via::H3).await?;
        if via == Via::H3 && scheme == "https" && !self.upstream.no_h3 {
            if let Some(up) = self.h3_up().await {
                if let Some(r) = up.try_send(host, &out).await {
                    return r.map(|r| self.clean(r, host, &out.method, &out.injected));
                }
            }
        }
        let Outgoing { method, url, headers, body, injected, tripped } = out;
        let body = match body {
            OutBody::Buffered(b) => reqwest::Body::from(b),
            OutBody::Streamed(b) => b,
        };
        let sent = self.client.request(method.clone(), &url).headers(headers).body(body).send().await;
        // A streamed body the tripwire cut off (#362): refused, not an upstream error.
        if let Some(what) = tripped.get() {
            return Err(self.trip(host, what));
        }
        let resp = sent?;
        let mut head = Response::builder().status(StatusCode::from_u16(resp.status().as_u16())?);
        for (name, value) in resp.headers().iter() {
            head = head.header(name, value);
        }
        let stream = resp.bytes_stream().map_ok(Frame::data).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        Ok(self.clean(head.body(BodyExt::boxed(StreamBody::new(stream)))?, host, &method, &injected))
    }

    /// The HTTP/3 upstream (made on first use); None if its UDP socket can't be had.
    pub(super) async fn h3_up(&self) -> Option<Arc<crate::h3::Up>> {
        self.h3_up
            .get_or_init(|| async {
                match crate::h3::Up::new(&self.upstream) {
                    Ok(u) => Some(Arc::new(u)),
                    Err(e) => {
                        tracing::warn!(error = %e, "no HTTP/3 upstream; using HTTP/2");
                        None
                    }
                }
            })
            .await
            .clone()
    }

    /// Drops hop-by-hop response headers, and any that would reflect an injected credential back into
    /// the box. `content-length` stays: the body passes through unchanged (#142), so clients keep
    /// download sizes and progress. From a host a credential was attached to, the body must come
    /// unencoded, and every form of the credential in it is masked as it streams (#362).
    pub(super) fn clean(&self, resp: Response<BoxBody>, host: &str, method: &Method, injected: &[String]) -> Response<BoxBody> {
        let (mut parts, body) = resp.into_parts();
        // wicket never asks an upstream to switch protocols (upgrade headers aren't forwarded), and
        // relays no connection it can't read (#361): a 101 would leave the box's connection
        // half-switched, with nothing deciding what passes over it.
        if parts.status == StatusCode::SWITCHING_PROTOCOLS {
            self.anomaly(
                host,
                "response.upgrade",
                &format!("{host} answered 101 Switching Protocols to a request that asked for no upgrade"),
            );
            return problem(
                502,
                "upstream",
                "Upstream error",
                &format!("refused: {host} switched protocols, and wicket relays only HTTP requests it decides. {}", crate::BOX_FACT),
                None,
            );
        }
        let names: Vec<http::HeaderName> = parts.headers.keys().cloned().collect();
        for name in names {
            if HOP_BY_HOP.contains(&name.as_str()) {
                parts.headers.remove(&name);
            }
        }
        guard_credential(&self.ctx, Response::from_parts(parts, body), host, method, injected)
    }

    /// Audits an anomaly (#362): something the box (or an upstream) did that wicket refused or
    /// masked, kept apart from ordinary refusals.
    fn anomaly(&self, host: &str, kind: &str, why: &str) {
        anomaly(&self.ctx, host, kind, why);
    }

    /// The tripwire went off (#362): audited as an anomaly, counted as a strike, and the error that
    /// refuses the request.
    pub(super) fn trip(&self, host: &str, what: &str) -> anyhow::Error {
        self.anomaly(host, "placeholder.moved", what);
        let note = self.strike(&format!("placeholder {host}"));
        canary::Tripped { what: what.to_string(), note }.into()
    }

    /// The tripwire on the request's URL and headers (#362): this run's placeholders (and any other
    /// run's) appear only as `Authorization: Bearer <placeholder>` to the placeholder's own host.
    fn tripwire(&self, headers: &http::HeaderMap, host: &str, pq: &str, scan: &canary::Scanner) -> Result<()> {
        match placeholder_moved(&self.ctx, scan, headers, host, pq) {
            Some(what) => Err(self.trip(host, &what)),
            None => Ok(()),
        }
    }

    /// A bearer the box presented to a host it holds a placeholder for, that isn't the placeholder
    /// (often a stale or forged one): dropped, and audited once per host per run (#362).
    fn unknown_placeholder(&self, host: &str) {
        let first = self.skipped.lock().expect("skipped").insert(format!("unknown-placeholder\n{host}"));
        if first {
            if let Ok(l) = self.ctx.ledger.lock() {
                let _ = l.audit_deferred(
                    &self.ctx.tenant,
                    Some(&self.ctx.run),
                    "placeholder.unknown",
                    &serde_json::json!({ "host": host, "why": "a bearer that isn't this run's placeholder for the host was dropped" }),
                );
            }
        }
    }

    /// Strips the box's credentials and headers, injects the zone's, and readies the body: streamed
    /// if `stream` (keeping the request's `content-length`), else read whole (bounded). GET and HEAD
    /// are always read, and refused if they carry a body.
    /// The vault secret whose value [`Egress::prepare`] puts on a request to `host` with these
    /// headers: the first inject rule for the host, else the run's swap for the placeholder the box
    /// presented. None for a literal swap, or no credential. For a model call's retry after a 401
    /// (#552).
    pub(crate) fn credential_secret(&self, host: &str, headers: &http::HeaderMap) -> Option<String> {
        if let Some(rule) = self.ctx.zone.inject.iter().find(|r| host_matches(&r.host, host)) {
            return Some(rule.secret.clone());
        }
        let auth = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
        let presented = auth.strip_prefix("Bearer ").unwrap_or("");
        let sw = self.ctx.swaps.iter().find(|s| host_matches(&s.host, host) && !presented.is_empty() && s.placeholder == presented)?;
        match &sw.real {
            crate::SwapSource::Vault(name) => Some(name.clone()),
            crate::SwapSource::Value(_) => None,
        }
    }

    pub(super) async fn prepare<B>(&self, req: Request<B>, host: &str, scheme: &str, pq: &str, stream: bool) -> Result<Outgoing>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (parts, body) = req.into_parts();
        // What the box put in Authorization: only ever a placeholder, to be swapped (below) or dropped.
        let box_auth = parts.headers.get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);
        let url = format!("{scheme}://{host}{pq}");
        // The tripwire (#362). A model call's body is the conversation, which may quote a
        // placeholder (an agent reading its own files): it isn't scanned; its URL and headers are.
        let scan = canary::Scanner::placeholders(self.ctx.swaps.iter().map(|s| s.placeholder.as_str()));
        self.tripwire(&parts.headers, host, pq, &scan)?;
        let scan_body = !self.model_gate.get().is_some_and(|l| l.is_model_call(host, parts.method.as_str(), pq));
        let tripped: Arc<std::sync::OnceLock<String>> = Arc::default();
        // Only allow-listed headers go upstream (#130); credentials are added below, by wicket.
        let mut headers = http::HeaderMap::new();
        for (name, value) in parts.headers.iter() {
            if FORWARD_REQUEST.contains(&name.as_str()) || crate::provider_request_header(host, name.as_str()) {
                headers.append(name.clone(), value.clone());
            }
        }
        let body = if stream && !matches!(parts.method, Method::GET | Method::HEAD) {
            // The length the box declared goes upstream as declared (hyper has already checked it
            // is one well-formed number, and holds the body to it); without one, chunked.
            let length = match parts.headers.get(http::header::CONTENT_LENGTH) {
                None => None,
                Some(v) => Some(
                    v.to_str()
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .ok_or_else(|| anyhow::anyhow!("refused: a malformed content-length"))?,
                ),
            };
            if let Some(n) = length.filter(|n| *n > MAX_STREAMED_BODY) {
                anyhow::bail!("refused: a {n}-byte request body (the limit is {MAX_STREAMED_BODY})");
            }
            if let Some(n) = length {
                headers.insert(http::header::CONTENT_LENGTH, n.into());
            }
            let limited = Limited::new(body, usize::try_from(MAX_STREAMED_BODY).unwrap_or(usize::MAX)).into_data_stream();
            if scan_body {
                OutBody::Streamed(reqwest::Body::wrap_stream(canary::guard_request(limited, scan, tripped.clone())))
            } else {
                OutBody::Streamed(reqwest::Body::wrap_stream(limited))
            }
        } else {
            let body = Limited::new(body, MAX_REQUEST_BODY).collect().await.map_err(|e| anyhow::anyhow!("request body: {e}"))?.to_bytes();
            if matches!(parts.method, Method::GET | Method::HEAD) && !body.is_empty() {
                anyhow::bail!("refused: a {} request with a body", parts.method);
            }
            if scan_body && scan.first(&body).is_some() {
                return Err(self.trip(host, &format!("a credential placeholder in the body of a request to {host}")));
            }
            OutBody::Buffered(body)
        };
        // Inject the zone's credential for this host into its one declared slot. An optional rule
        // whose secret isn't set sends the request without it (e.g. anonymous reads).
        let mut injected: Vec<String> = Vec::new();
        // No credential ever goes over plain HTTP (#129), whatever the check before the decision found
        // (#415: a node that took an optional rule as no credential would have let it through).
        let cleartext = |what: &str| anyhow::anyhow!("refused: wicket never sends {what} for {host} over plain HTTP; use https://{host}/");
        for rule in &self.ctx.zone.inject {
            if host_matches(&rule.host, host) {
                if scheme != "https" {
                    return Err(cleartext("a credential"));
                }
                // The org policy may refuse a credential the zone names (#51): the request is refused.
                if let Some(org) = &self.ctx.org {
                    let key = format!("{}|{}|{}", rule.host.to_ascii_lowercase(), rule.header, rule.secret);
                    if !org.allows_inject(&key) {
                        anyhow::bail!(
                            "refused: the org policy ({}) doesn't allow injecting {} into {} for {host}",
                            org.version,
                            rule.secret,
                            rule.header
                        );
                    }
                }
                // The secret is looked up now, not at the run's start (#415): on a node it is fetched
                // from the control host on its first use (#152), and again once that says it changed.
                // A required rule fails if it can't be had; an optional one falls through to the check below.
                if let Err(e) = self.ctx.vault.ensure(&rule.secret).await {
                    if !rule.optional {
                        self.note_injection(rule, Injection::Failed, &e.to_string());
                        return Err(e);
                    }
                }
                // An optional rule whose secret isn't set (after any fetch) is as if it weren't there (#175).
                if rule.optional && !self.ctx.vault.has(&rule.secret) {
                    self.note_injection(rule, Injection::Skipped, "optional secret not set");
                    continue;
                }
                // Whatever the zone says, a secret goes only to the hosts it is bound to in the vault.
                if let Err(e) = self.ctx.vault.check(&rule.secret, host) {
                    self.note_injection(rule, Injection::Failed, &e.to_string());
                    return Err(e);
                }
                let secret = match self.ctx.vault.get(&rule.secret) {
                    Ok(s) => s,
                    Err(e) if rule.optional => {
                        self.note_injection(rule, Injection::Skipped, &e.to_string());
                        break;
                    }
                    Err(e) => {
                        self.note_injection(rule, Injection::Failed, &e.to_string());
                        return Err(e);
                    }
                };
                self.note_injection(rule, Injection::Carried, "");
                let value = render_credential(&rule.format, &secret);
                headers.insert(http::HeaderName::from_bytes(rule.header.as_bytes())?, http::HeaderValue::from_str(&value)?);
                injected.push(secret);
                injected.push(value);
                break;
            }
        }
        if injected.is_empty() {
            if let Some(auth) = &box_auth {
                let presented = auth.strip_prefix("Bearer ").unwrap_or("");
                match self.ctx.swaps.iter().find(|s| host_matches(&s.host, host) && !presented.is_empty() && s.placeholder == presented) {
                    Some(_) if scheme != "https" => return Err(cleartext("a swapped credential")),
                    Some(sw) => {
                        // On a node, the credential is fetched from the control host on its first use
                        // (#257), as an injected one is.
                        if let crate::SwapSource::Vault(name) = &sw.real {
                            self.ctx.vault.ensure(name).await?;
                        }
                        let real = match &sw.real {
                            crate::SwapSource::Vault(name) => self.ctx.vault.get_for(name, host)?,
                            crate::SwapSource::Value(v) => v.clone(),
                        };
                        headers.insert(http::header::AUTHORIZATION, http::HeaderValue::from_str(&format!("Bearer {real}"))?);
                        injected.push(real);
                        tracing::debug!(host, swap = %sw.name, "credential swapped");
                    }
                    None if self.ctx.swaps.iter().any(|s| s.box_bearers && host_matches(&s.host, host)) && auth.starts_with("Bearer ") => {
                        headers.insert(http::header::AUTHORIZATION, http::HeaderValue::from_str(auth)?);
                        tracing::debug!(host, "the box's own bearer passed (box_bearers)");
                    }
                    None if self.ctx.swaps.iter().any(|s| host_matches(&s.host, host)) => {
                        tracing::debug!(host, "box-supplied authorization dropped (not this run's placeholder)");
                        self.unknown_placeholder(host);
                    }
                    None => tracing::debug!(host, "box-supplied authorization dropped (not a known placeholder)"),
                }
            }
        }
        // What comes back from a host a credential went to is scanned for it (#362), so it must come
        // unencoded.
        if !injected.is_empty() {
            headers.insert(http::header::ACCEPT_ENCODING, http::HeaderValue::from_static("identity"));
        }
        Ok(Outgoing { method: parts.method, url, headers, body, injected, tripped })
    }
}

/// Why a request is refused before any decision, by its method, headers or body framing (#130,
/// design §9.1): methods other than the usual ones (TRACE, and CONNECT inside a tunnel, among them),
/// method-override and URL-rewrite headers, and a body on GET or HEAD.
pub(super) fn refused_shape<B>(req: &Request<B>) -> Option<String> {
    let method = req.method().as_str();
    if !FORWARD_METHODS.contains(&method) {
        return Some(format!("the {method} method is not proxied"));
    }
    if let Some(h) = REFUSE_REQUEST.iter().find(|h| req.headers().contains_key(**h)) {
        return Some(format!("the {h} header is refused: the request must be decided as it will run"));
    }
    if matches!(*req.method(), Method::GET | Method::HEAD) {
        let h = req.headers();
        let length = h.get(http::header::CONTENT_LENGTH).map(|v| v.as_bytes() != b"0").unwrap_or(false);
        if length || h.contains_key(http::header::TRANSFER_ENCODING) {
            return Some(format!("a {method} request with a body is not proxied"));
        }
    }
    None
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

/// A response's content or transfer coding other than identity (and chunked), if it has one.
fn encoded(h: &http::HeaderMap) -> Option<String> {
    let codings = h.get_all(http::header::CONTENT_ENCODING).iter().chain(h.get_all(http::header::TRANSFER_ENCODING).iter());
    for v in codings {
        for c in String::from_utf8_lossy(v.as_bytes()).split(',') {
            let c = c.trim().to_ascii_lowercase();
            if !c.is_empty() && c != "identity" && c != "chunked" {
                return Some(c);
            }
        }
    }
    None
}

/// The checks on an answer from a host a credential was attached to (#362), on both of the model
/// proxy's routes (#552) and every request the egress proxy forwards: the body must come
/// unencoded (or is refused, 502), a header that reflects the credential is dropped, and every
/// form of the credential in the body is masked as it streams, each audited as an anomaly.
pub(crate) fn guard_credential(
    ctx: &RunCtx,
    resp: Response<BoxBody>,
    host: &str,
    method: &Method,
    injected: &[String],
) -> Response<BoxBody> {
    let (mut parts, body) = resp.into_parts();
    let scan = canary::Scanner::secrets(injected);
    if !injected.is_empty() {
        if let Some(enc) = encoded(&parts.headers).filter(|_| *method != Method::HEAD && !matches!(parts.status.as_u16(), 204 | 304)) {
            let why = format!(
                "{host} answered with a {enc}-encoded body, which wicket can't check for the credential it attached to the request"
            );
            anomaly(ctx, host, "response.encoded", &why);
            return problem(
                502,
                "upstream",
                "Upstream error",
                &format!("refused: {why} (it was asked for an unencoded one). {}", crate::BOX_FACT),
                None,
            );
        }
    }
    let names: Vec<http::HeaderName> = parts.headers.keys().cloned().collect();
    for name in names {
        let leaks = parts.headers.get_all(&name).iter().any(|v| scan.first(v.as_bytes()).is_some());
        if leaks {
            parts.headers.remove(&name);
        }
    }
    if scan.is_empty() {
        return Response::from_parts(parts, body);
    }
    let (ledger, tenant, run, h) = (ctx.ledger.clone(), ctx.tenant.clone(), ctx.run.clone(), host.to_string());
    let body = canary::guard_response(body, scan, move || {
        let why = format!("{h} reflected the credential wicket attached to the request; it was masked before the box saw it");
        tracing::warn!(host = %h, "{why}");
        if let Ok(l) = ledger.lock() {
            let _ = l.audit_deferred(
                &tenant,
                Some(&run),
                "anomaly",
                &serde_json::json!({ "anomaly": "secret.reflected", "host": h, "why": why }),
            );
        }
    });
    Response::from_parts(parts, body)
}

/// Audits an anomaly (#362): something the box (or an upstream) did that wicket refused or masked,
/// kept apart from ordinary refusals.
pub(crate) fn anomaly(ctx: &RunCtx, host: &str, anomaly: &str, why: &str) {
    tracing::warn!(host, anomaly, "{why}");
    if let Ok(l) = ctx.ledger.lock() {
        let _ =
            l.audit_deferred(&ctx.tenant, Some(&ctx.run), "anomaly", &serde_json::json!({ "anomaly": anomaly, "host": host, "why": why }));
    }
}

/// What in a request's URL or headers moves a credential placeholder (#362), if anything: this
/// run's placeholders (and any other run's) appear only as `Authorization: Bearer <placeholder>`
/// to the placeholder's own host. The tripwire of both of the model proxy's routes (#552) and of
/// every request the egress proxy forwards.
pub(crate) fn placeholder_moved(ctx: &RunCtx, scan: &canary::Scanner, headers: &http::HeaderMap, host: &str, pq: &str) -> Option<String> {
    let tag = ctx.run.0.replace('_', "-");
    let whose = |seen: &[u8]| {
        let seen = String::from_utf8_lossy(seen);
        match ctx.swaps.iter().find(|s| s.placeholder == seen) {
            Some(s) => format!("the placeholder for {}", s.name),
            None if seen.contains(&tag) => "one of this run's credential placeholders".to_string(),
            None => "another run's credential placeholder".to_string(),
        }
    };
    let decoded = canary::percent_decode(pq);
    for url in [pq.as_bytes(), &decoded] {
        if let Some(r) = scan.first(url) {
            return Some(format!("{} in the URL for {host}", whose(&url[r])));
        }
    }
    for (name, value) in headers {
        if name == http::header::AUTHORIZATION {
            if let Some(p) = value.to_str().ok().and_then(|v| v.strip_prefix("Bearer ")) {
                if ctx.swaps.iter().any(|s| s.placeholder == p && host_matches(&s.host, host)) {
                    continue; // its one slot, on its own host
                }
                if let Some(s) = ctx.swaps.iter().find(|s| s.placeholder == p) {
                    return Some(format!("the placeholder for {} sent to {host}, which isn't its host ({})", s.name, s.host));
                }
            }
        }
        if let Some(r) = scan.first(value.as_bytes()) {
            return Some(format!("{} in the {name} header to {host}", whose(&value.as_bytes()[r])));
        }
    }
    None
}
