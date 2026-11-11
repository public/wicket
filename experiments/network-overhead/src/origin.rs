//! The HTTPS origin: `origin.test` with its own CA, HTTP/1.1 and HTTP/2.
//!
//!   GET  /1k          1,024 bytes
//!   GET  /bytes/N     N bytes, streamed in 64 KiB slices of one static buffer (no per-request allocation)
//!   POST /upload      reads the body, answers with its length

use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

pub const CHUNK: usize = 64 * 1024;
pub static BLOCK: [u8; CHUNK] = [b'x'; CHUNK];

pub type Body = BoxBody<Bytes, Infallible>;

/// A body of `n` bytes from the static block, `CHUNK` at a time.
pub fn stream_body(n: u64) -> Body {
    let s = futures_util::stream::unfold(n, |left| async move {
        if left == 0 {
            return None;
        }
        let k = left.min(CHUNK as u64);
        Some((Ok::<_, Infallible>(Frame::data(Bytes::from_static(&BLOCK[..k as usize]))), left - k))
    });
    StreamBody::new(s).boxed()
}

pub async fn run(listen: SocketAddr, dir: PathBuf) -> Result<()> {
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name.push(DnType::CommonName, "netbench origin CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    let ca_key = KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let mut leaf_params = CertificateParams::new(vec![crate::ORIGIN_HOST.to_string()])?;
    leaf_params.distinguished_name.push(DnType::CommonName, crate::ORIGIN_HOST);
    let leaf_key = KeyPair::generate()?;
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.der().to_vec()), CertificateDer::from(ca.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    std::fs::write(dir.join("origin-ca.der.tmp"), ca.der())?;
    std::fs::rename(dir.join("origin-ca.der.tmp"), dir.join("origin-ca.der"))?;
    std::fs::write(dir.join("origin-ca.pem"), ca.pem())?;
    loop {
        let (s, _) = listener.accept().await?;
        let _ = s.set_nodelay(true);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(s).await else { return };
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), service_fn(handle))
                .await;
        });
    }
}

async fn handle(mut req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();
    let resp = if path == "/1k" {
        Response::builder().header("content-length", "1024").body(Full::new(Bytes::from_static(&BLOCK[..1024])).boxed())
    } else if let Some(n) = path.strip_prefix("/bytes/").and_then(|n| n.parse::<u64>().ok()) {
        Response::builder().header("content-length", n.to_string()).body(stream_body(n))
    } else if path == "/upload" {
        let mut n = 0u64;
        while let Some(f) = req.body_mut().frame().await {
            match f {
                Ok(f) => n += f.data_ref().map(|d| d.len() as u64).unwrap_or(0),
                Err(_) => break,
            }
        }
        Response::builder().body(Full::new(Bytes::from(n.to_string())).boxed())
    } else {
        Response::builder().status(404).body(Full::new(Bytes::new()).boxed())
    };
    Ok(resp.expect("response"))
}
