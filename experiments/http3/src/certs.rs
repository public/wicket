//! Test CAs and per-SNI leaves, as wicket's `RunCa` mints them (crates/wicket-proxy/src/ca.rs), with
//! ALPN `h3` instead of `http/1.1`. Two CAs: the "run CA" the box trusts (the terminator presents
//! leaves from it) and an "origin CA" that only the terminator trusts (the test origins use it).

use anyhow::{bail, Result};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

pub struct Ca {
    cert: Certificate,
    key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ca")
    }
}

impl Ca {
    pub fn generate(name: &str) -> Result<Ca> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(2);
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok(Ca { cert, key, leaves: Mutex::new(HashMap::new()) })
    }

    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    pub fn cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert.der().to_vec())
    }

    /// A leaf for `host` (cached), chain [leaf, CA].
    pub fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(k) = self.leaves.lock().unwrap().get(host) {
            return Ok(k.clone());
        }
        if host.parse::<std::net::IpAddr>().is_ok() {
            bail!("refusing to mint a certificate for an IP literal");
        }
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(1);
        let leaf_key = KeyPair::generate()?;
        let leaf = params.signed_by(&leaf_key, &self.cert, &self.key)?;
        let chain = vec![CertificateDer::from(leaf.der().to_vec()), self.cert_der()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signer = rustls::crypto::ring::sign::any_supported_type(&key)?;
        let ck = Arc::new(CertifiedKey::new(chain, signer));
        self.leaves.lock().unwrap().insert(host.to_string(), ck.clone());
        Ok(ck)
    }
}

/// Mints a leaf for whatever SNI the client sends, if `allow(sni)`; no SNI or a refused name fails the
/// handshake. The terminator additionally checks that the SNI is the name the synthetic address maps to.
pub struct SniMinter {
    pub ca: Arc<Ca>,
    pub allow: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

impl std::fmt::Debug for SniMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SniMinter")
    }
}

impl ResolvesServerCert for SniMinter {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?;
        if !(self.allow)(sni) {
            return None;
        }
        self.ca.leaf(sni).ok()
    }
}

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS 1.3 server config for QUIC, ALPN h3, 0-RTT off (max_early_data_size 0, rustls' default).
pub fn h3_server_config(resolver: Arc<dyn ResolvesServerCert>) -> Result<rustls::ServerConfig> {
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    Ok(cfg)
}

/// A client config trusting exactly `roots` (PEM), with `alpn`.
pub fn client_config(roots_pem: &str, alpn: &[&[u8]]) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile_certs(roots_pem)? {
        roots.add(c)?;
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(cfg)
}

/// Minimal PEM certificate reader (avoids another dependency).
pub fn rustls_pemfile_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    use base64_lite::decode;
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in pem.lines() {
        let l = line.trim();
        if l == "-----BEGIN CERTIFICATE-----" {
            cur = Some(String::new());
        } else if l == "-----END CERTIFICATE-----" {
            if let Some(b) = cur.take() {
                out.push(CertificateDer::from(decode(&b)?));
            }
        } else if let Some(b) = cur.as_mut() {
            b.push_str(l);
        }
    }
    if out.is_empty() {
        bail!("no certificates in PEM");
    }
    Ok(out)
}

mod base64_lite {
    pub fn decode(s: &str) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(s.len() * 3 / 4);
        let (mut acc, mut bits) = (0u32, 0u32);
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => break,
                _ => anyhow::bail!("bad base64"),
            } as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        Ok(out)
    }
}

/// The origins' server config: a fixed leaf per name from the origin CA, with `alpn`.
pub fn origin_server_config(ca: &Ca, names: &[&str], alpn: &[&[u8]]) -> Result<rustls::ServerConfig> {
    #[derive(Debug)]
    struct Fixed(HashMap<String, Arc<CertifiedKey>>);
    impl ResolvesServerCert for Fixed {
        fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            self.0.get(hello.server_name()?).cloned()
        }
    }
    let mut m = HashMap::new();
    for n in names {
        m.insert(n.to_string(), ca.leaf(n)?);
    }
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(m)));
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(cfg)
}
