//! Re-originating a decided request upstream: HTTP/3 (one pooled quinn connection per host), or
//! HTTP/2 over TLS when the upstream has no HTTP/3 (remembered per host). The response streams back
//! into the box's HTTP/3 stream as it arrives.

use crate::certs;
use anyhow::{anyhow, Context, Result};
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub type Down = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H2Send = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

pub struct Upstream {
    ep: quinn::Endpoint,
    addrs: HashMap<String, SocketAddr>,
    h3: tokio::sync::Mutex<HashMap<String, H3Send>>,
    h2: tokio::sync::Mutex<HashMap<String, H2Send>>,
    no_h3: Mutex<HashSet<String>>,
    tls_h2: Arc<rustls::ClientConfig>,
    h3_timeout: Duration,
}

pub struct Outcome {
    pub proto: &'static str,
    pub status: u16,
    pub bytes: u64,
}

const HOP: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "host"];

impl Upstream {
    pub fn new(addrs: HashMap<String, SocketAddr>, roots_pem: &str) -> Result<Upstream> {
        let tls_h3 = certs::client_config(roots_pem, &[b"h3"])?;
        let tls_h2 = Arc::new(certs::client_config(roots_pem, &[b"h2"])?);
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        let qc = quinn::crypto::rustls::QuicClientConfig::try_from(tls_h3)?;
        let mut cc = quinn::ClientConfig::new(Arc::new(qc));
        let mut t = quinn::TransportConfig::default();
        t.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
        cc.transport_config(Arc::new(t));
        ep.set_default_client_config(cc);
        Ok(Upstream {
            ep,
            addrs,
            h3: Default::default(),
            h2: Default::default(),
            no_h3: Default::default(),
            tls_h2,
            h3_timeout: Duration::from_millis(500),
        })
    }

    fn addr(&self, host: &str) -> Result<SocketAddr> {
        self.addrs.get(host).copied().ok_or_else(|| anyhow!("no upstream address for {host}"))
    }

    async fn h3_conn(&self, host: &str) -> Result<H3Send> {
        let mut g = self.h3.lock().await;
        if let Some(s) = g.get(host) {
            return Ok(s.clone());
        }
        let conn =
            tokio::time::timeout(self.h3_timeout, self.ep.connect(self.addr(host)?, host)?).await.context("h3 connect timed out")??;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        g.insert(host.to_string(), send.clone());
        Ok(send)
    }

    async fn h2_conn(&self, host: &str) -> Result<H2Send> {
        let mut g = self.h2.lock().await;
        if let Some(s) = g.get(host) {
            if s.is_ready() {
                return Ok(s.clone());
            }
        }
        let tcp = tokio::net::TcpStream::connect(self.addr(host)?).await?;
        tcp.set_nodelay(true)?;
        let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        let tls = tokio_rustls::TlsConnector::from(self.tls_h2.clone()).connect(name, tcp).await?;
        let (send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(4 << 20)
            .initial_connection_window_size(8 << 20)
            .handshake(TokioIo::new(tls))
            .await?;
        tokio::spawn(conn);
        g.insert(host.to_string(), send.clone());
        Ok(send)
    }

    /// Sends `req` (body already read) upstream and streams the answer into `down`.
    pub async fn forward(&self, host: &str, req: http::Request<()>, body: Bytes, down: &mut Down) -> Result<Outcome> {
        let pq = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        let uri: http::Uri = format!("https://{host}{pq}").parse()?;
        let mut up = http::Request::builder().method(req.method().clone()).uri(uri);
        for (k, v) in req.headers() {
            if !HOP.contains(&k.as_str()) {
                up = up.header(k, v);
            }
        }
        let skip_h3 = self.no_h3.lock().unwrap().contains(host);
        if !skip_h3 {
            match self.h3_conn(host).await {
                Ok(mut send) => {
                    let r = self.via_h3(&mut send, up.body(())?, body.clone(), down).await;
                    if r.is_err() {
                        self.h3.lock().await.remove(host);
                    }
                    return r;
                }
                Err(e) => {
                    eprintln!("term: {host}: no HTTP/3 upstream ({e:#}); falling back to HTTP/2");
                    self.no_h3.lock().unwrap().insert(host.to_string());
                }
            }
        }
        let send = self.h2_conn(host).await?;
        self.via_h2(send, up.body(())?, body, down).await
    }

    async fn via_h3(&self, send: &mut H3Send, req: http::Request<()>, body: Bytes, down: &mut Down) -> Result<Outcome> {
        let mut s = send.send_request(req).await?;
        if !body.is_empty() {
            s.send_data(body).await?;
        }
        s.finish().await?;
        let resp = s.recv_response().await?;
        let status = resp.status().as_u16();
        down.send_response(strip(resp)).await?;
        let mut bytes = 0;
        while let Some(mut chunk) = s.recv_data().await? {
            let b = chunk.copy_to_bytes(chunk.remaining());
            bytes += b.len() as u64;
            down.send_data(b).await?;
        }
        down.finish().await?;
        Ok(Outcome { proto: "h3", status, bytes })
    }

    async fn via_h2(&self, mut send: H2Send, req: http::Request<()>, body: Bytes, down: &mut Down) -> Result<Outcome> {
        let (parts, ()) = req.into_parts();
        let resp = send.send_request(http::Request::from_parts(parts, Full::new(body))).await?;
        let status = resp.status().as_u16();
        let (rp, mut rb) = resp.into_parts();
        down.send_response(strip(http::Response::from_parts(rp, ()))).await?;
        let mut bytes = 0;
        while let Some(f) = rb.frame().await {
            if let Ok(d) = f?.into_data() {
                bytes += d.len() as u64;
                down.send_data(d).await?;
            }
        }
        down.finish().await?;
        Ok(Outcome { proto: "h2", status, bytes })
    }
}

fn strip(mut r: http::Response<()>) -> http::Response<()> {
    for h in HOP {
        r.headers_mut().remove(*h);
    }
    r
}
