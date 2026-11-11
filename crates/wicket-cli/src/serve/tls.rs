//! The console's own HTTPS: rustls with TLS 1.3 and TLS 1.2 (ECDHE with AEAD ciphers only), and a
//! certificate resolver that serves either the console's certificate (from files, or from ACME) or,
//! to an ACME server validating a TLS-ALPN-01 challenge (RFC 8737), the challenge certificate.
//!
//! HTTP/2 is not offered (ALPN `http/1.1` only): one HTTP implementation to bound and fuzz, and
//! nothing the console needs from h2.

use anyhow::{anyhow, Context, Result};
use rustls::crypto::ring::cipher_suite as cs;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// The ALPN protocol id of TLS-ALPN-01 validation (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// Holds the certificate the console serves, swappable at run time (renewal, a replaced file), and
/// the TLS-ALPN-01 challenge certificates of in-flight ACME orders, by domain.
#[derive(Debug, Default)]
pub struct CertResolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
    challenges: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertResolver {
    pub fn set(&self, ck: Arc<CertifiedKey>) {
        *self.current.write().expect("lock") = Some(ck);
    }

    pub fn current(&self) -> Option<Arc<CertifiedKey>> {
        self.current.read().expect("lock").clone()
    }

    pub fn set_challenge(&self, domain: &str, ck: Arc<CertifiedKey>) {
        self.challenges.write().expect("lock").insert(domain.to_ascii_lowercase(), ck);
    }

    pub fn clear_challenge(&self, domain: &str) {
        self.challenges.write().expect("lock").remove(&domain.to_ascii_lowercase());
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let acme = hello.alpn().is_some_and(|mut protos| protos.any(|p| p == ACME_TLS_ALPN));
        if acme {
            // Only a challenge certificate, and only for the name being validated. Without an
            // order in flight the handshake fails.
            let name = hello.server_name()?.to_ascii_lowercase();
            return self.challenges.read().expect("lock").get(&name).cloned();
        }
        // Before the first certificate exists (ACME still ordering), handshakes fail.
        self.current()
    }
}

/// The TLS configuration: TLS 1.3 and 1.2; for 1.2 only ECDHE key exchange with AES-GCM or
/// ChaCha20-Poly1305 (forward secrecy and AEAD; no CBC, RSA key exchange, SHA-1 MACs or 3DES);
/// the server's cipher order wins; no client certificates; no 0-RTT data.
pub fn server_config(resolver: Arc<CertResolver>, acme: bool) -> Result<Arc<ServerConfig>> {
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            cs::TLS13_AES_256_GCM_SHA384,
            cs::TLS13_CHACHA20_POLY1305_SHA256,
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ],
        ..rustls::crypto::ring::default_provider()
    };
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    if acme {
        cfg.alpn_protocols.push(ACME_TLS_ALPN.to_vec());
    }
    cfg.ignore_client_order = true;
    cfg.max_early_data_size = 0;
    Ok(Arc::new(cfg))
}

/// A certificate chain and its private key from PEM, checked to belong together.
pub fn certified_key_from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(chain_pem).collect::<Result<_, _>>().map_err(|e| anyhow!("certificate PEM: {e:?}"))?;
    anyhow::ensure!(!chain.is_empty(), "no certificate in the PEM");
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| anyhow!("private key PEM: {e:?}"))?;
    certified_key(chain, &key)
}

pub fn certified_key(chain: Vec<CertificateDer<'static>>, key: &PrivateKeyDer<'_>) -> Result<CertifiedKey> {
    let signing = rustls::crypto::ring::sign::any_supported_type(key).map_err(|e| anyhow!("private key: {e}"))?;
    let ck = CertifiedKey::new(chain, signing);
    ck.keys_match().map_err(|e| anyhow!("the private key does not match the certificate: {e}"))?;
    Ok(ck)
}

/// The leaf certificate's notAfter (unix seconds).
pub fn not_after(ck: &CertifiedKey) -> Result<i64> {
    let leaf = ck.end_entity_cert().map_err(|e| anyhow!("{e}"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|e| anyhow!("certificate: {e}"))?;
    Ok(cert.validity().not_after.timestamp())
}

/// The TLS-ALPN-01 challenge certificate for `domain`: self-signed, for that name only, carrying the
/// critical acmeIdentifier extension with the SHA-256 of the key authorization (RFC 8737 §3).
pub fn challenge_cert(domain: &str, key_auth_digest: &[u8]) -> Result<CertifiedKey> {
    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(key_auth_digest)];
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    certified_key(vec![cert.der().clone()], &der)
}

/// A certificate and key from files (`--tls-cert`, `--tls-key`), re-read when either file changes
/// (checked every minute), so a renewal by another tool (certbot, a secrets manager) is picked up
/// without a restart. A file that fails to load keeps the previous certificate in service.
pub struct FileCert {
    pub cert: PathBuf,
    pub key: PathBuf,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

impl FileCert {
    pub fn load(&self) -> Result<CertifiedKey> {
        let chain = std::fs::read(&self.cert).with_context(|| format!("reading {}", self.cert.display()))?;
        let key = std::fs::read(&self.key).with_context(|| format!("reading {}", self.key.display()))?;
        certified_key_from_pem(&chain, &key).with_context(|| format!("{} and {}", self.cert.display(), self.key.display()))
    }

    pub fn watch(self, resolver: Arc<CertResolver>, every: Duration) {
        tokio::spawn(async move {
            let mut seen = (mtime(&self.cert), mtime(&self.key));
            loop {
                tokio::time::sleep(every).await;
                let now = (mtime(&self.cert), mtime(&self.key));
                if now == seen {
                    continue;
                }
                seen = now;
                match self.load() {
                    Ok(ck) => {
                        resolver.set(Arc::new(ck));
                        tracing::info!("reloaded the console certificate from {}", self.cert.display());
                    }
                    Err(e) => tracing::warn!("keeping the current console certificate: {e:#}"),
                }
            }
        });
    }
}
