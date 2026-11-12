//! `h3get URL`: one HTTP/3 GET, printed as one word for ci/smoke.sh: the status code (with
//! wicket's `x-wicket` reason, if any, as `403:forbidden`), `nxdomain` if the host doesn't resolve,
//! or `error`. Resolves with the C library (so through the box's resolver, wicket's DNS) and trusts
//! the CA bundle in `SSL_CERT_FILE` (wicket-entry's, which includes the run's CA).

use anyhow::{anyhow, Context, Result};
use bytes::Buf;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let url = std::env::args().nth(1).unwrap_or_default();
    match get(&url).await {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("h3get: {e:#}");
            println!("error");
        }
    }
}

async fn get(url: &str) -> Result<String> {
    let uri: http::Uri = url.parse()?;
    let host = uri.host().ok_or_else(|| anyhow!("no host in {url}"))?.to_string();
    let addr = match tokio::net::lookup_host((host.as_str(), 443)).await {
        Ok(mut a) => a.find(|a| a.is_ipv4()).ok_or_else(|| anyhow!("no IPv4 address"))?,
        Err(_) => return Ok("nxdomain".into()),
    };
    let mut roots = rustls::RootCertStore::empty();
    let bundle = std::fs::read(std::env::var("SSL_CERT_FILE").unwrap_or_else(|_| "/etc/ssl/certs/ca-certificates.crt".into()))?;
    for c in rustls::pki_types::pem::PemObject::pem_slice_iter(&bundle) {
        let _ = roots.add(c.map_err(|e| anyhow!("{e:?}"))?);
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?)));
    let conn = tokio::time::timeout(Duration::from_secs(15), ep.connect(addr, &host)?).await.context("QUIC handshake timed out")??;
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let mut s = send.send_request(http::Request::get(url).body(())?).await?;
    s.finish().await?;
    let r = tokio::time::timeout(Duration::from_secs(30), s.recv_response()).await.context("no response")??;
    while let Some(mut b) = s.recv_data().await? {
        b.advance(b.remaining());
    }
    Ok(match r.headers().get("x-wicket").and_then(|v| v.to_str().ok()) {
        Some(w) => format!("{}:{w}", r.status().as_u16()),
        None => r.status().as_u16().to_string(),
    })
}
