//! How the console listens: which listen/TLS/origin combinations are allowed, and the HTTP server
//! loop with its bounds (connection caps, handshake/header/body timeouts, header size limits).
//!
//! The rule: **a non-loopback listener serves HTTPS** (certificate files or ACME), or runs with
//! `--behind-tls-terminator` and an `https://` origin, meaning a TLS-terminating proxy in front
//! (whose address may then be trusted for `X-Forwarded-For` with `--trusted-proxy`). Plain HTTP is
//! only for loopback, opened as `http://localhost:PORT`.

use super::acme::{AcmeConfig, LETS_ENCRYPT, LETS_ENCRYPT_STAGING};
use super::limits::{ip_key, Cidr};
use super::tls::ACME_TLS_ALPN;
use super::State;
use anyhow::{bail, Context, Result};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// `wicket serve`'s options, as given on the command line.
#[derive(Clone, Debug, Default)]
pub struct ServeOpts {
    pub listen: String,
    pub origin: Option<String>,
    pub rp_id: Option<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub acme_domain: Option<String>,
    pub acme_contact: Vec<String>,
    pub acme_directory: Option<String>,
    pub acme_staging: bool,
    pub acme_agree_tos: bool,
    pub acme_cache: Option<PathBuf>,
    pub behind_tls_terminator: bool,
    pub trusted_proxy: Vec<String>,
    pub max_connections: usize,
}

#[derive(Clone, Debug)]
pub enum TlsSource {
    Files { cert: PathBuf, key: PathBuf },
    Acme(AcmeConfig),
}

/// A checked serving plan.
#[derive(Clone, Debug)]
pub struct Plan {
    pub addr: SocketAddr,
    /// The browser origin, normalized (`https://console.example.com`).
    pub origin: String,
    pub rp_id: String,
    /// The `Host` every request must carry (the origin's authority).
    pub authority: String,
    pub tls: Option<TlsSource>,
    pub behind_terminator: bool,
    pub trusted: Vec<Cidr>,
    pub hsts: bool,
    pub max_connections: usize,
}

/// An origin as the browser reports it: scheme, lower-case host, port only if not the default.
fn parse_origin(s: &str) -> Result<(String, String, String)> {
    let u: http::Uri = s.parse().with_context(|| format!("--origin {s:?}"))?;
    let scheme = u.scheme_str().unwrap_or("");
    if scheme != "http" && scheme != "https" {
        bail!("--origin {s:?}: must start with https:// (or http://localhost for loopback)");
    }
    let Some(auth) = u.authority() else { bail!("--origin {s:?}: no host") };
    if auth.as_str().contains('@') || !matches!(u.path(), "" | "/") || u.query().is_some() {
        bail!("--origin {s:?}: an origin is scheme://host[:port], nothing else");
    }
    let host = auth.host().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    let default = if scheme == "https" { 443 } else { 80 };
    let authority = match auth.port_u16() {
        Some(p) if p != default => format!("{}:{p}", auth.host().to_ascii_lowercase()),
        _ => auth.host().to_ascii_lowercase(),
    };
    Ok((format!("{scheme}://{authority}"), host, authority))
}

fn is_localhost(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// Checks the options and works out the origin, RP ID and TLS source.
pub fn plan(o: &ServeOpts, data: &Path) -> Result<Plan> {
    let addr: SocketAddr = o.listen.parse().with_context(|| format!("--listen {:?}", o.listen))?;
    let files = match (&o.tls_cert, &o.tls_key) {
        (Some(c), Some(k)) => Some((c.clone(), k.clone())),
        (None, None) => None,
        _ => bail!("--tls-cert and --tls-key go together"),
    };
    if files.is_some() && o.acme_domain.is_some() {
        bail!("use either certificate files (--tls-cert/--tls-key) or ACME (--acme-domain), not both");
    }
    let acme_only = !o.acme_contact.is_empty() || o.acme_directory.is_some() || o.acme_staging || o.acme_cache.is_some();
    if o.acme_domain.is_none() && acme_only {
        bail!("the --acme-* options need --acme-domain");
    }
    let tls = files.is_some() || o.acme_domain.is_some();
    if o.behind_tls_terminator && tls {
        bail!("--behind-tls-terminator means the console itself serves plain HTTP; drop it, or the TLS options");
    }
    if !o.trusted_proxy.is_empty() && !o.behind_tls_terminator {
        bail!("--trusted-proxy applies only with --behind-tls-terminator");
    }
    let trusted =
        o.trusted_proxy.iter().map(|s| s.parse::<Cidr>().with_context(|| format!("--trusted-proxy {s:?}"))).collect::<Result<Vec<_>>>()?;
    if !addr.ip().is_loopback() && !tls && !o.behind_tls_terminator {
        bail!(
            "refusing to listen on {addr} without TLS: give the console a certificate (--acme-domain, or --tls-cert/--tls-key), \
             or put it behind a TLS-terminating proxy (--behind-tls-terminator --origin https://...)"
        );
    }

    let acme = match &o.acme_domain {
        Some(d) => {
            let d = d.to_ascii_lowercase();
            if !super::acme::valid_domain(&d) {
                bail!("--acme-domain {d:?} is not a DNS name");
            }
            if !o.acme_agree_tos {
                bail!(
                    "ACME: pass --acme-agree-tos to accept the CA's terms of service (Let's Encrypt: https://letsencrypt.org/repository/)"
                );
            }
            for c in &o.acme_contact {
                if !c.starts_with("mailto:") {
                    bail!("--acme-contact {c:?}: give a mailto: URI");
                }
            }
            let directory = match (&o.acme_directory, o.acme_staging) {
                (Some(_), true) => bail!("--acme-staging and --acme-directory are alternatives"),
                (Some(u), false) => u.clone(),
                (None, true) => LETS_ENCRYPT_STAGING.into(),
                (None, false) => LETS_ENCRYPT.into(),
            };
            Some(AcmeConfig {
                domain: d,
                contact: o.acme_contact.clone(),
                directory,
                cache: o.acme_cache.clone().unwrap_or_else(|| data.join("acme")),
            })
        }
        None => None,
    };

    let origin = match (&o.origin, &acme) {
        (Some(s), _) => s.clone(),
        (None, Some(a)) if addr.port() == 443 => format!("https://{}", a.domain),
        (None, Some(a)) => format!("https://{}:{}", a.domain, addr.port()),
        (None, None) if files.is_some() && addr.ip().is_loopback() => format!("https://localhost:{}", addr.port()),
        (None, None) if files.is_some() => bail!("with --tls-cert, give the name the certificate is for: --origin https://NAME"),
        (None, None) if o.behind_tls_terminator => bail!("--behind-tls-terminator needs --origin https://... (the proxy's public origin)"),
        (None, None) => format!("http://localhost:{}", addr.port()),
    };
    let (origin, host, authority) = parse_origin(&origin)?;
    let https = origin.starts_with("https://");
    if (tls || o.behind_tls_terminator) && !https {
        bail!("--origin {origin}: with TLS (here or at a proxy) the origin is https://");
    }
    if https && !tls && !o.behind_tls_terminator {
        bail!(
            "--origin {origin}: an https origin needs TLS here (--acme-domain, --tls-cert) or a proxy in front (--behind-tls-terminator)"
        );
    }
    if !https && !is_localhost(&host) {
        bail!("--origin {origin}: plain HTTP is for http://localhost only (WebAuthn needs a secure context)");
    }
    if let Some(a) = &acme {
        if host != a.domain {
            bail!("--origin {origin} is not on the ACME domain {}", a.domain);
        }
    }
    let rp_id = o.rp_id.clone().map(|r| r.to_ascii_lowercase()).unwrap_or_else(|| host.clone());
    if !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
        bail!("--rp-id {rp_id} must be the origin's host ({host}) or a parent domain of it");
    }
    let tls = match (files, acme) {
        (Some((cert, key)), _) => Some(TlsSource::Files { cert, key }),
        (None, Some(a)) => Some(TlsSource::Acme(a)),
        (None, None) => None,
    };
    let max_connections = if o.max_connections == 0 { Limits::default().max_connections } else { o.max_connections };
    Ok(Plan { addr, origin, rp_id, authority, tls, behind_terminator: o.behind_tls_terminator, trusted, hsts: https, max_connections })
}

/// The HTTP server's bounds.
#[derive(Clone, Debug)]
pub struct Limits {
    pub handshake_timeout: Duration,
    /// For a request's head (request line and headers): slowloris.
    pub header_timeout: Duration,
    /// For a request's body.
    pub body_timeout: Duration,
    /// After this a connection is closed (gracefully, after the request in flight), so a client
    /// can't hold one forever, e.g. by reading responses slowly or idling between requests.
    pub conn_lifetime: Duration,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_body: usize,
    pub max_connections: usize,
    /// Concurrent connections from one client address (not applied to trusted proxies).
    pub per_ip_connections: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            handshake_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(10),
            conn_lifetime: Duration::from_secs(120),
            max_header_bytes: 16 * 1024,
            max_headers: 64,
            max_body: 64 * 1024,
            max_connections: 256,
            per_ip_connections: 16,
        }
    }
}

/// Counts open connections per client address.
#[derive(Default)]
struct PerIp(Mutex<HashMap<String, usize>>);

struct PerIpGuard(Arc<PerIp>, String);

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut m = self.0 .0.lock().expect("lock");
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

impl PerIp {
    fn enter(self: &Arc<Self>, ip: IpAddr, max: usize) -> Option<PerIpGuard> {
        let key = ip_key(ip);
        let mut m = self.0.lock().expect("lock");
        let n = m.entry(key.clone()).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(PerIpGuard(self.clone(), key))
    }
}

/// Accepts connections until the listener fails: over-limit connections are closed at once, TLS
/// (if any) is negotiated within the handshake timeout, and ACME validation handshakes are closed
/// after the handshake (they carry no HTTP).
pub async fn run(listener: TcpListener, tls: Option<tokio_rustls::TlsAcceptor>, state: Arc<State>) -> Result<()> {
    let limits = state.limits.clone();
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let per_ip = Arc::new(PerIp::default());
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Out of file descriptors and the like: back off rather than spin.
                tracing::warn!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
        let guard = if state.trusted.iter().any(|c| c.contains(peer.ip())) {
            None
        } else {
            match per_ip.enter(peer.ip(), limits.per_ip_connections) {
                Some(g) => Some(g),
                None => continue,
            }
        };
        let _ = stream.set_nodelay(true);
        let state = state.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = guard;
            match tls {
                None => serve_conn(stream, peer, state).await,
                Some(acceptor) => {
                    let Ok(Ok(s)) = tokio::time::timeout(state.limits.handshake_timeout, acceptor.accept(stream)).await else { return };
                    if s.get_ref().1.alpn_protocol() == Some(ACME_TLS_ALPN) {
                        return;
                    }
                    serve_conn(s, peer, state).await
                }
            }
        });
    }
}

async fn serve_conn<I: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: I, peer: SocketAddr, state: Arc<State>) {
    let limits = state.limits.clone();
    let svc = service_fn(move |req| {
        let state = state.clone();
        async move { Ok::<_, std::convert::Infallible>(super::route(req, &state, peer).await) }
    });
    let mut b = hyper::server::conn::http1::Builder::new();
    b.timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout)
        .max_headers(limits.max_headers)
        .max_buf_size(limits.max_header_bytes.max(8192))
        .half_close(false)
        .keep_alive(true);
    let conn = b.serve_connection(TokioIo::new(io), svc);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        _ = tokio::time::sleep(limits.conn_lifetime) => {
            conn.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(limits.body_timeout, conn).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(listen: &str) -> ServeOpts {
        ServeOpts { listen: listen.into(), ..Default::default() }
    }

    fn data() -> PathBuf {
        PathBuf::from("/nonexistent/wicket")
    }

    #[test]
    fn plain_http_is_loopback_only() {
        let p = plan(&opts("127.0.0.1:8787"), &data()).unwrap();
        assert_eq!(
            (p.origin.as_str(), p.rp_id.as_str(), p.authority.as_str(), p.hsts),
            ("http://localhost:8787", "localhost", "localhost:8787", false)
        );
        assert!(p.tls.is_none());
        for listen in ["0.0.0.0:8787", "[::]:8787", "192.0.2.10:443"] {
            let e = plan(&opts(listen), &data()).unwrap_err().to_string();
            assert!(e.contains("without TLS"), "{listen}: {e}");
        }
        // Not even with an https origin, unless it says a proxy terminates TLS.
        let o = ServeOpts { origin: Some("https://console.example.com".into()), ..opts("0.0.0.0:8787") };
        assert!(plan(&o, &data()).is_err());
        // On loopback, http origins are localhost only, and an https origin needs TLS somewhere.
        for origin in ["http://console.example.com", "https://console.example.com", "http://127.0.0.1:8787"] {
            let o = ServeOpts { origin: Some(origin.into()), ..opts("127.0.0.1:8787") };
            assert!(plan(&o, &data()).is_err(), "{origin}");
        }
    }

    #[test]
    fn a_tls_terminator_needs_an_https_origin_and_is_the_only_forwarded_for_source() {
        let o = ServeOpts {
            behind_tls_terminator: true,
            origin: Some("https://Console.Example.com/".into()),
            trusted_proxy: vec!["10.0.0.5".into()],
            ..opts("0.0.0.0:8787")
        };
        let p = plan(&o, &data()).unwrap();
        assert_eq!(
            (p.origin.as_str(), p.rp_id.as_str(), p.authority.as_str(), p.hsts),
            ("https://console.example.com", "console.example.com", "console.example.com", true)
        );
        assert_eq!(p.trusted, vec!["10.0.0.5".parse().unwrap()]);
        assert!(plan(&ServeOpts { origin: None, ..o.clone() }, &data()).is_err());
        assert!(plan(&ServeOpts { origin: Some("http://console.example.com".into()), ..o.clone() }, &data()).is_err());
        assert!(plan(&ServeOpts { tls_cert: Some("c".into()), tls_key: Some("k".into()), ..o.clone() }, &data()).is_err());
        // Forwarded-for is never believed without a terminator.
        let o = ServeOpts { trusted_proxy: vec!["10.0.0.5".into()], ..opts("127.0.0.1:8787") };
        assert!(plan(&o, &data()).unwrap_err().to_string().contains("--behind-tls-terminator"));
    }

    #[test]
    fn tls_from_files_or_acme() {
        let files = ServeOpts {
            tls_cert: Some("/etc/wicket/cert.pem".into()),
            tls_key: Some("/etc/wicket/key.pem".into()),
            origin: Some("https://console.example.com:8443".into()),
            ..opts("0.0.0.0:8443")
        };
        let p = plan(&files, &data()).unwrap();
        assert_eq!(
            (p.origin.as_str(), p.authority.as_str(), p.hsts),
            ("https://console.example.com:8443", "console.example.com:8443", true)
        );
        assert!(matches!(p.tls, Some(TlsSource::Files { .. })));
        assert!(plan(&ServeOpts { origin: None, ..files.clone() }, &data()).is_err(), "which name the certificate is for");
        assert!(plan(&ServeOpts { tls_key: None, ..files.clone() }, &data()).is_err());
        assert!(plan(&ServeOpts { rp_id: Some("other.example".into()), ..files.clone() }, &data()).is_err());
        assert_eq!(plan(&ServeOpts { rp_id: Some("example.com".into()), ..files.clone() }, &data()).unwrap().rp_id, "example.com");

        let acme = ServeOpts { acme_domain: Some("console.example.com".into()), acme_agree_tos: true, ..opts("[::]:443") };
        let p = plan(&acme, &data()).unwrap();
        assert_eq!(p.origin, "https://console.example.com");
        let Some(TlsSource::Acme(a)) = p.tls else { panic!() };
        assert_eq!((a.directory.as_str(), a.cache), (LETS_ENCRYPT, data().join("acme")));
        let staging = plan(&ServeOpts { acme_staging: true, ..acme.clone() }, &data()).unwrap();
        assert!(matches!(staging.tls, Some(TlsSource::Acme(a)) if a.directory == LETS_ENCRYPT_STAGING));
        assert!(plan(&ServeOpts { acme_agree_tos: false, ..acme.clone() }, &data()).is_err());
        assert!(plan(&ServeOpts { acme_domain: Some("192.0.2.1".into()), ..acme.clone() }, &data()).is_err());
        assert!(plan(&ServeOpts { acme_domain: Some("../etc".into()), ..acme.clone() }, &data()).is_err());
        assert!(plan(&ServeOpts { acme_contact: vec!["ops@example.com".into()], ..acme.clone() }, &data()).is_err());
        assert!(plan(&ServeOpts { origin: Some("https://other.example.com".into()), ..acme.clone() }, &data()).is_err());
        assert!(plan(&ServeOpts { tls_cert: Some("c".into()), tls_key: Some("k".into()), ..acme.clone() }, &data()).is_err());
        assert!(plan(&ServeOpts { acme_staging: true, ..opts("127.0.0.1:8787") }, &data()).is_err());
        assert_eq!(plan(&ServeOpts { listen: "0.0.0.0:8443".into(), ..acme }, &data()).unwrap().origin, "https://console.example.com:8443");
    }
}
