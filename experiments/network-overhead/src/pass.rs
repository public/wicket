//! The #62 fast path for hosts a zone allows wholesale with no credential: decide on the hostname, check
//! that the TLS ClientHello names the same host, then move the encrypted bytes without terminating TLS.
//!
//! - `--mode connect`: the box speaks CONNECT, as it does to wicket's egress proxy today (mediated mode,
//!   splice-through). The SNI must equal the CONNECT host.
//! - `--mode sni`: no CONNECT; the box opens TLS straight to the proxy (a resolver steering the name to
//!   the proxy, or a transparent redirect), and the SNI is the only name. The `filtered`/`direct` shape.
//! - `--copy tokio|splice`: tokio's userspace copy, or splice(2).
//!
//! Also `fwd`: a TCP-to-unix forwarder in place of the box's socat.

use crate::splice::{self, IntoStd};
use crate::{stamps, Endpoint};
use anyhow::{bail, Result};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use wicket_core::{manifest::host_matches, CompiledZone, HostVerdict};

/// Every method: a rule that lists them all, for every path, allows the host wholesale.
const ALL_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Whether wicket would need to see inside requests to `host`: true unless some reach rule allows the
/// host for every path and method, nothing is injected for it and no forbid rule names it.
pub fn needs_inspection(zone: &CompiledZone, host: &str) -> bool {
    let zone = zone.spec();
    let wholesale = zone.reach.iter().any(|r| {
        r.host_matches(host) && r.paths.iter().any(|p| p == "/**") && ALL_METHODS.iter().all(|m| r.methods.iter().any(|x| x.eq_ignore_ascii_case(m)))
    });
    let injected = zone.inject.iter().any(|i| host_matches(&i.host, host));
    let forbid = zone.forbid.iter().any(|f| host_matches(&f.host, host));
    !wholesale || injected || forbid
}

struct Cfg {
    zone: Arc<CompiledZone>,
    connect: bool,
    splice: bool,
    upstream_port: u16,
}

pub async fn run() -> Result<()> {
    let cfg = Arc::new(Cfg {
        zone: crate::zone()?,
        connect: crate::need("--mode")? == "connect",
        splice: crate::arg("--copy").as_deref() == Some("splice"),
        upstream_port: crate::need("--upstream-port")?.parse()?,
    });
    stamps::dump_on_sigterm();
    match Endpoint::parse(&crate::need("--listen")?)? {
        Endpoint::Unix(p) => {
            let _ = std::fs::remove_file(&p);
            let l = tokio::net::UnixListener::bind(&p)?;
            loop {
                let (s, _) = l.accept().await?;
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = conn(s, cfg).await {
                        eprintln!("pass: {e}");
                    }
                });
            }
        }
        Endpoint::Tcp(a) => {
            let l = tokio::net::TcpListener::bind(a).await?;
            loop {
                let (s, _) = l.accept().await?;
                s.set_nodelay(true)?;
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = conn(s, cfg).await {
                        eprintln!("pass: {e}");
                    }
                });
            }
        }
    }
}

/// Reads the CONNECT head; returns the host and any bytes that came after it.
async fn read_connect<S: AsyncRead + Unpin>(s: &mut S) -> Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 2048];
    let end = loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            bail!("eof in CONNECT");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 8192 {
            bail!("CONNECT head too long");
        }
    };
    let head = std::str::from_utf8(&buf[..end])?;
    let line = head.lines().next().unwrap_or("");
    let mut parts = line.split(' ');
    let (Some("CONNECT"), Some(target)) = (parts.next(), parts.next()) else { bail!("not CONNECT: {line:?}") };
    let (host, port) = target.rsplit_once(':').unwrap_or((target, "443"));
    if port != "443" {
        bail!("only port 443");
    }
    Ok((host.trim_end_matches('.').to_ascii_lowercase(), buf[end..].to_vec()))
}

/// Reads until a whole ClientHello has arrived; returns its SNI and every byte read.
async fn peek_sni<S: AsyncRead + Unpin>(s: &mut S, mut buf: Vec<u8>) -> Result<(Option<String>, Vec<u8>)> {
    let mut acc = rustls::server::Acceptor::default();
    let mut fed = 0;
    let mut tmp = [0u8; 4096];
    loop {
        while fed < buf.len() {
            let mut rd = &buf[fed..];
            let n = acc.read_tls(&mut rd)?;
            fed += n;
        }
        match acc.accept() {
            Ok(Some(a)) => return Ok((a.client_hello().server_name().map(str::to_string), buf)),
            Ok(None) => {}
            Err((e, _)) => bail!("not a ClientHello: {e}"),
        }
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            bail!("eof before ClientHello");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn conn<S>(mut s: S, cfg: Arc<Cfg>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + IntoStd + 'static,
{
    let t0 = Instant::now();
    let (connect_host, early) = if cfg.connect {
        let (h, rest) = read_connect(&mut s).await?;
        let ok = h.parse::<std::net::IpAddr>().is_err() && matches!(cfg.zone.host_verdict(&h), HostVerdict::Open) && !needs_inspection(&cfg.zone, &h);
        if !ok {
            s.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n").await?;
            return Ok(());
        }
        s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
        stamps::add("connect_decide", t0.elapsed());
        (Some(h), rest)
    } else {
        (None, Vec::new())
    };
    let t1 = Instant::now();
    let (sni, hello) = peek_sni(&mut s, early).await?;
    let Some(sni) = sni.map(|h| h.trim_end_matches('.').to_ascii_lowercase()) else { bail!("no SNI") };
    match &connect_host {
        // Domain fronting at the TLS layer: the ClientHello must name the host that was decided on.
        Some(h) if *h != sni => bail!("SNI {sni} != CONNECT {h}"),
        Some(_) => {}
        None => {
            if !matches!(cfg.zone.host_verdict(&sni), HostVerdict::Open) || needs_inspection(&cfg.zone, &sni) {
                bail!("{sni}: not a splice-through host");
            }
        }
    }
    stamps::add("sni_peek_check", t1.elapsed());
    // Harness routing: every allowed name goes to the local origin.
    let t2 = Instant::now();
    let mut up = tokio::net::TcpStream::connect(("127.0.0.1", cfg.upstream_port)).await?;
    up.set_nodelay(true)?;
    up.write_all(&hello).await?;
    stamps::add("upstream_connect", t2.elapsed());
    if cfg.splice {
        let (a, b) = (s.into_blocking_fd()?, up.into_blocking_fd()?);
        tokio::task::spawn_blocking(move || splice::bidirectional(a, b)).await?;
    } else {
        let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
    }
    Ok(())
}

/// `fwd --listen tcp:A --to unix:P [--copy splice]`: what socat does in the box, as one process
/// without a fork per connection.
pub async fn fwd() -> Result<()> {
    let Endpoint::Tcp(a) = Endpoint::parse(&crate::need("--listen")?)? else { bail!("fwd listens on tcp") };
    let Endpoint::Unix(to) = Endpoint::parse(&crate::need("--to")?)? else { bail!("fwd forwards to unix") };
    let use_splice = crate::arg("--copy").as_deref() == Some("splice");
    let l = tokio::net::TcpListener::bind(a).await?;
    loop {
        let (mut s, _) = l.accept().await?;
        s.set_nodelay(true)?;
        let to = to.clone();
        tokio::spawn(async move {
            let Ok(mut u) = tokio::net::UnixStream::connect(&to).await else { return };
            if use_splice {
                let (Ok(a), Ok(b)) = (s.into_blocking_fd(), u.into_blocking_fd()) else { return };
                let _ = tokio::task::spawn_blocking(move || splice::bidirectional(a, b)).await;
            } else {
                let _ = tokio::io::copy_bidirectional(&mut s, &mut u).await;
            }
        });
    }
}
