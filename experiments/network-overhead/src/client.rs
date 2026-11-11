//! The client side: a box's HTTPS client, through CONNECT or straight to a TLS endpoint, HTTP/1.1 or h2.

use crate::origin::{stream_body, Body};
use crate::{connect, Endpoint, Io, ORIGIN_HOST};
use anyhow::{bail, Result};
use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone)]
pub struct Target {
    pub ep: Endpoint,
    /// Speak CONNECT first (a proxy); otherwise TLS straight away (the origin, or an SNI proxy).
    pub connect: bool,
    pub tls: Arc<rustls::ClientConfig>,
    pub h2: bool,
}

pub enum Sender {
    H1(hyper::client::conn::http1::SendRequest<Body>),
    H2(hyper::client::conn::http2::SendRequest<Body>),
}

/// Durations of one new connection's phases, ns.
#[derive(Clone, Copy, Default, Debug)]
pub struct Phases {
    pub connect: u64,
    pub proxy_connect: u64,
    pub tls: u64,
    pub ttfb: u64,
    pub total: u64,
}

pub async fn open(t: &Target) -> Result<(Sender, Phases)> {
    let mut ph = Phases::default();
    let t0 = Instant::now();
    let mut s: Box<dyn Io> = connect(&t.ep).await?;
    ph.connect = t0.elapsed().as_nanos() as u64;
    if t.connect {
        let t1 = Instant::now();
        s.write_all(format!("CONNECT {ORIGIN_HOST}:443 HTTP/1.1\r\nHost: {ORIGIN_HOST}:443\r\n\r\n").as_bytes()).await?;
        let mut buf = Vec::new();
        let mut b = [0u8; 512];
        loop {
            let n = s.read(&mut b).await?;
            if n == 0 {
                bail!("proxy closed during CONNECT");
            }
            buf.extend_from_slice(&b[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        if !buf.starts_with(b"HTTP/1.1 200") {
            bail!("CONNECT refused: {}", String::from_utf8_lossy(&buf));
        }
        ph.proxy_connect = t1.elapsed().as_nanos() as u64;
    }
    let t2 = Instant::now();
    let name = rustls::pki_types::ServerName::try_from(ORIGIN_HOST)?;
    let tls = tokio_rustls::TlsConnector::from(t.tls.clone()).connect(name, s).await?;
    ph.tls = t2.elapsed().as_nanos() as u64;
    let alpn_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    if t.h2 && !alpn_h2 {
        bail!("asked for h2, server chose {:?}", tls.get_ref().1.alpn_protocol().map(String::from_utf8_lossy));
    }
    let io = TokioIo::new(tls);
    let sender = if t.h2 {
        let (s, c) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(4 << 20)
            .initial_connection_window_size(8 << 20)
            .handshake(io)
            .await?;
        tokio::spawn(c);
        Sender::H2(s)
    } else {
        let (s, c) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(c);
        Sender::H1(s)
    };
    Ok((sender, ph))
}

/// One request; returns (time to response headers, total, body bytes).
pub async fn request(s: &mut Sender, method: &str, path: &str, upload: u64) -> Result<(u64, u64, u64)> {
    let body: Body = if upload > 0 { stream_body(upload) } else { Empty::<Bytes>::new().map_err(|n| match n {}).boxed() };
    let t0 = Instant::now();
    let resp = match s {
        Sender::H1(s) => {
            s.ready().await?;
            let mut rb = Request::builder().method(method).uri(path).header("host", ORIGIN_HOST);
            if upload > 0 {
                rb = rb.header("content-length", upload.to_string());
            }
            s.send_request(rb.body(body)?).await?
        }
        Sender::H2(s) => {
            s.ready().await?;
            let mut rb = Request::builder().method(method).uri(format!("https://{ORIGIN_HOST}{path}"));
            if upload > 0 {
                rb = rb.header("content-length", upload.to_string());
            }
            s.send_request(rb.body(body)?).await?
        }
    };
    let ttfb = t0.elapsed().as_nanos() as u64;
    if !resp.status().is_success() {
        bail!("status {}", resp.status());
    }
    let mut b = resp.into_body();
    let mut n = 0u64;
    while let Some(f) = b.frame().await {
        if let Some(d) = f?.data_ref() {
            n += d.len() as u64;
        }
    }
    Ok((ttfb, t0.elapsed().as_nanos() as u64, n))
}

/// New connection per request, sequential.
pub async fn lat_new(t: &Target, n: usize, path: &str) -> Result<Vec<Phases>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t0 = Instant::now();
        let (mut s, mut ph) = open(t).await?;
        let (ttfb, _, _) = request(&mut s, "GET", path, 0).await?;
        ph.ttfb = ttfb;
        ph.total = t0.elapsed().as_nanos() as u64;
        out.push(ph);
    }
    Ok(out)
}

/// One kept-alive connection, sequential requests (after `warm` unrecorded ones).
pub async fn lat_keep(t: &Target, n: usize, warm: usize, path: &str) -> Result<Vec<u64>> {
    let (mut s, _) = open(t).await?;
    for _ in 0..warm {
        request(&mut s, "GET", path, 0).await?;
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(request(&mut s, "GET", path, 0).await?.1);
    }
    Ok(out)
}

/// `conc` workers for `dur`; each keeps one connection alive (`keep`) or opens one per request.
/// Returns completed requests and their latencies.
pub async fn rps(t: &Target, conc: usize, dur: Duration, keep: bool, path: &str) -> Result<(u64, Vec<u64>)> {
    let end = Instant::now() + dur;
    let mut tasks = Vec::new();
    for _ in 0..conc {
        let t = t.clone();
        let path = path.to_string();
        tasks.push(tokio::spawn(async move {
            let mut lat = Vec::new();
            let mut conn = None;
            while Instant::now() < end {
                let t0 = Instant::now();
                if conn.is_none() || !keep {
                    conn = Some(open(&t).await?.0);
                }
                request(conn.as_mut().unwrap(), "GET", &path, 0).await?;
                lat.push(t0.elapsed().as_nanos() as u64);
            }
            anyhow::Ok(lat)
        }));
    }
    let mut all = Vec::new();
    for t in tasks {
        all.extend(t.await??);
    }
    Ok((all.len() as u64, all))
}

/// One download of `bytes` on a fresh connection; returns seconds for the request (not the handshake).
pub async fn download(t: &Target, bytes: u64) -> Result<f64> {
    let (mut s, _) = open(t).await?;
    let (_, total, n) = request(&mut s, "GET", &format!("/bytes/{bytes}"), 0).await?;
    if n != bytes {
        bail!("short download: {n} of {bytes}");
    }
    Ok(total as f64 / 1e9)
}

/// One upload of `bytes` on a fresh connection; returns seconds until the response is complete.
pub async fn upload(t: &Target, bytes: u64) -> Result<f64> {
    let (mut s, _) = open(t).await?;
    let (_, total, _) = request(&mut s, "POST", "/upload", bytes).await?;
    Ok(total as f64 / 1e9)
}

/// `probe --ep E [--connect] --ca FILE.der [--h2] --work lat_new|lat_keep|download --n N [--size B]`:
/// one workload, printed as JSON (for running inside a box).
pub async fn probe() -> Result<()> {
    let mut ca = std::fs::read(crate::need("--ca")?)?;
    if ca.starts_with(b"-----") {
        ca = crate::driver::pem_to_der(std::str::from_utf8(&ca)?)?;
    }
    let h2 = crate::flag("--h2");
    let alpn: &[&[u8]] = if h2 { &[b"h2"] } else { &[b"http/1.1"] };
    let t = Target { ep: Endpoint::parse(&crate::need("--ep")?)?, connect: crate::flag("--connect"), tls: crate::client_tls(&ca, alpn)?, h2 };
    let n: usize = crate::arg("--n").map(|n| n.parse()).transpose()?.unwrap_or(100);
    let v = match crate::need("--work")?.as_str() {
        "lat_new" => crate::driver::phases_json(&lat_new(&t, n, "/1k").await?),
        "lat_keep" => crate::driver::stats_ns_unsorted(lat_keep(&t, n, 50, "/1k").await?),
        "download" => {
            let size: u64 = crate::need("--size")?.parse()?;
            let mut v = Vec::new();
            for _ in 0..n {
                v.push(download(&t, size).await?);
            }
            serde_json::json!({ "secs": v, "mb_per_s": v.iter().map(|s| size as f64 / 1e6 / s).collect::<Vec<_>>() })
        }
        w => bail!("unknown work {w}"),
    };
    println!("{}", serde_json::to_string(&v)?);
    Ok(())
}
