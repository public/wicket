//! Test origins on the host, with certificates from the origin CA (which the box does not trust):
//! HTTP/3 on UDP `h3_addr` plus HTTP/2 on TCP at the same address (names in `h3_names`), and
//! HTTP/2 only on TCP `h2_addr` (names in `h2_names`, no UDP listener: the fallback case).
//! `/bytes/N` streams N bytes; anything else answers a short text naming the protocol and path.

use crate::certs::{self, Ca};
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;

const CHUNK: usize = 64 * 1024;

fn size_of(path: &str) -> Option<u64> {
    path.strip_prefix("/bytes/")?.parse().ok()
}

pub async fn run(ca_out: &str, h3_addr: SocketAddr, h3_names: Vec<String>, h2_addr: SocketAddr, h2_names: Vec<String>) -> Result<()> {
    let ca = Ca::generate("origin CA (h3 spike)")?;
    std::fs::write(ca_out, ca.cert_pem())?;
    let n3: Vec<&str> = h3_names.iter().map(|s| s.as_str()).collect();
    let n2: Vec<&str> = h2_names.iter().map(|s| s.as_str()).collect();

    let tls3 = certs::origin_server_config(&ca, &n3, &[b"h3"])?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls3)?));
    let mut t = quinn::TransportConfig::default();
    t.stream_receive_window((8u32 << 20).into());
    t.receive_window((16u32 << 20).into());
    t.send_window(16 << 20);
    sc.transport_config(Arc::new(t));
    let ep = quinn::Endpoint::server(sc, h3_addr)?;
    tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            tokio::spawn(async move {
                let Ok(c) = inc.await else { return };
                let Ok(mut h): Result<h3::server::Connection<_, Bytes>, _> =
                    h3::server::Connection::new(h3_quinn::Connection::new(c)).await
                else {
                    return;
                };
                while let Ok(Some(r)) = h.accept().await {
                    tokio::spawn(async move {
                        let Ok((req, mut s)) = r.resolve_request().await else { return };
                        while let Ok(Some(_)) = s.recv_data().await {}
                        let path = req.uri().path().to_string();
                        let _ = async {
                            if let Some(n) = size_of(&path) {
                                s.send_response(http::Response::builder().status(200).header("content-length", n).body(())?).await?;
                                let block = Bytes::from(vec![b'x'; CHUNK]);
                                let mut left = n;
                                while left > 0 {
                                    let k = left.min(CHUNK as u64) as usize;
                                    s.send_data(block.slice(..k)).await?;
                                    left -= k as u64;
                                }
                            } else {
                                s.send_response(http::Response::builder().status(200).header("content-type", "text/plain").body(())?)
                                    .await?;
                                s.send_data(Bytes::from(format!("hello over h3 from the origin: {} {}\n", req.method(), path))).await?;
                            }
                            s.finish().await?;
                            anyhow::Ok(())
                        }
                        .await;
                    });
                }
            });
        }
    });

    let tls2a = Arc::new(certs::origin_server_config(&ca, &n3, &[b"h2"])?);
    let tls2b = Arc::new(certs::origin_server_config(&ca, &n2, &[b"h2"])?);
    tokio::spawn(h2_server(h3_addr, tls2a));
    tokio::spawn(h2_server(h2_addr, tls2b));
    eprintln!("origin: h3 udp {h3_addr} {h3_names:?}, h2 tcp {h3_addr} and {h2_addr} {h2_names:?}");
    std::future::pending::<()>().await;
    Ok(())
}

async fn h2_server(addr: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<()> {
    let l = tokio::net::TcpListener::bind(addr).await?;
    let acc = tokio_rustls::TlsAcceptor::from(tls);
    loop {
        let (tcp, _) = l.accept().await?;
        let acc = acc.clone();
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            let Ok(tls) = acc.accept(tcp).await else { return };
            let svc = hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
                let path = req.uri().path().to_string();
                let method = req.method().clone();
                let _ = req.into_body().collect().await;
                type B = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
                let body: B = if let Some(n) = size_of(&path) {
                    let block = Bytes::from(vec![b'x'; CHUNK]);
                    let s = futures_util::stream::unfold(n, move |left| {
                        let block = block.clone();
                        async move {
                            if left == 0 {
                                return None;
                            }
                            let k = left.min(CHUNK as u64) as usize;
                            Some((Ok(hyper::body::Frame::data(block.slice(..k))), left - k as u64))
                        }
                    });
                    StreamBody::new(s).boxed()
                } else {
                    http_body_util::Full::new(Bytes::from(format!("hello over h2 from the origin: {method} {path}\n")))
                        .map_err(|e| match e {})
                        .boxed()
                };
                Ok::<_, std::convert::Infallible>(http::Response::builder().status(200).body(body).unwrap())
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .initial_stream_window_size(4 << 20)
                .initial_connection_window_size(8 << 20)
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}
