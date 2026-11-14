//! The request that goes upstream: refused shapes (#130), headers by allowlist, the zone's
//! credential injected into its one slot or a placeholder swapped, and the body readied. Part of
//! [`super::Egress`], split out of `egress.rs` (#220).

use super::*;

impl Egress {
    /// Whether the zone injects a credential into requests for `host`, or swaps one in.
    pub(super) fn credentials_for(&self, host: &str) -> bool {
        self.ctx.zone.inject.iter().any(|r| host_matches(&r.host, host) && !self.unset_optional(r))
            || self.ctx.swaps.iter().any(|s| host_matches(&s.host, host))
    }

    /// Whether `rule` is optional and its secret isn't in the vault: then it is skipped, as if the
    /// zone didn't have it (#175). The run drops such rules from its zone at start; this covers a
    /// secret removed while the run lasts. Noted in the audit log once per rule, not per request.
    pub(super) fn unset_optional(&self, rule: &wicket_core::manifest::InjectRule) -> bool {
        if !rule.optional || self.ctx.vault.has(&rule.secret) {
            return false;
        }
        let first = self.skipped.lock().expect("skipped").insert(format!("{}\n{}", rule.host, rule.secret));
        if first {
            tracing::info!(host = %rule.host, secret = %rule.secret, "optional secret not set: requests go without it");
            if let Ok(l) = self.ctx.ledger.lock() {
                let _ = l.audit_deferred(
                    &self.ctx.tenant,
                    Some(&self.ctx.run),
                    "inject.skipped",
                    &serde_json::json!({ "host": rule.host, "secret": rule.secret, "why": "optional secret not set" }),
                );
            }
        }
        true
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
                    return r.map(|r| self.clean(r, &out.injected));
                }
            }
        }
        let Outgoing { method, url, headers, body, injected } = out;
        let body = match body {
            OutBody::Buffered(b) => reqwest::Body::from(b),
            OutBody::Streamed(b) => b,
        };
        let resp = self.client.request(method, &url).headers(headers).body(body).send().await?;
        let mut head = Response::builder().status(StatusCode::from_u16(resp.status().as_u16())?);
        for (name, value) in resp.headers().iter() {
            head = head.header(name, value);
        }
        let stream = resp.bytes_stream().map_ok(Frame::data).map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
        Ok(self.clean(head.body(BodyExt::boxed(StreamBody::new(stream)))?, &injected))
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
    /// download sizes and progress.
    pub(super) fn clean(&self, resp: Response<BoxBody>, injected: &[String]) -> Response<BoxBody> {
        let (mut parts, body) = resp.into_parts();
        let names: Vec<http::HeaderName> = parts.headers.keys().cloned().collect();
        for name in names {
            if HOP_BY_HOP.contains(&name.as_str()) {
                parts.headers.remove(&name);
                continue;
            }
            let leaks = parts
                .headers
                .get_all(&name)
                .iter()
                .any(|v| injected.iter().any(|s| v.as_bytes().windows(s.len()).any(|w| w == s.as_bytes())));
            if leaks {
                parts.headers.remove(&name);
            }
        }
        Response::from_parts(parts, body)
    }

    /// Strips the box's credentials and headers, injects the zone's, and readies the body: streamed
    /// if `stream` (keeping the request's `content-length`), else read whole (bounded). GET and HEAD
    /// are always read, and refused if they carry a body.
    pub(super) async fn prepare<B>(&self, req: Request<B>, host: &str, scheme: &str, pq: &str, stream: bool) -> Result<Outgoing>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (parts, body) = req.into_parts();
        // What the box put in Authorization: only ever a placeholder, to be swapped (below) or dropped.
        let box_auth = parts.headers.get(http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).map(String::from);
        let url = format!("{scheme}://{host}{pq}");
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
            let limited = Limited::new(body, usize::try_from(MAX_STREAMED_BODY).unwrap_or(usize::MAX));
            OutBody::Streamed(reqwest::Body::wrap_stream(limited.into_data_stream()))
        } else {
            let body = Limited::new(body, MAX_REQUEST_BODY).collect().await.map_err(|e| anyhow::anyhow!("request body: {e}"))?.to_bytes();
            if matches!(parts.method, Method::GET | Method::HEAD) && !body.is_empty() {
                anyhow::bail!("refused: a {} request with a body", parts.method);
            }
            OutBody::Buffered(body)
        };
        // Inject the zone's credential for this host into its one declared slot. An optional rule
        // whose secret isn't set sends the request without it (e.g. anonymous reads).
        let mut injected: Vec<String> = Vec::new();
        for rule in &self.ctx.zone.inject {
            if host_matches(&rule.host, host) {
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
                // On a node, the secret is fetched from the control host on its first use (#152). A
                // required rule fails if it can't be had; an optional one falls through to the check below.
                if let Err(e) = self.ctx.vault.ensure(&rule.secret).await {
                    if !rule.optional {
                        return Err(e);
                    }
                }
                // An optional rule whose secret isn't set (after any fetch) is as if it weren't there (#175).
                if self.unset_optional(rule) {
                    continue;
                }
                // Whatever the zone says, a secret goes only to the hosts it is bound to in the vault.
                self.ctx.vault.check(&rule.secret, host)?;
                let secret = match self.ctx.vault.get(&rule.secret) {
                    Ok(s) => s,
                    Err(_) if rule.optional => break,
                    Err(e) => return Err(e),
                };
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
                    Some(sw) => {
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
                    None => tracing::debug!(host, "box-supplied authorization dropped (not a known placeholder)"),
                }
            }
        }
        Ok(Outgoing { method: parts.method, url, headers, body, injected })
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
