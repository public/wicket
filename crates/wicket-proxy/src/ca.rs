//! A per-run certificate authority. Its private key lives only in this process's memory; the
//! sandbox gets the public certificate so its TLS clients trust the egress proxy.

use anyhow::{bail, Result};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

pub struct RunCa {
    cert: Certificate,
    key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl RunCa {
    pub fn generate(run: &str) -> Result<RunCa> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("wicket run CA {run}"));
        dn.push(DnType::OrganizationName, "wicket");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(2);
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok(RunCa { cert, key, leaves: Mutex::new(HashMap::new()) })
    }

    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// A TLS server config presenting a leaf certificate for `host`, signed by this CA (cached).
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        if host.parse::<std::net::IpAddr>().is_ok() {
            bail!("refusing to mint a certificate for an IP literal");
        }
        if let Some(c) = self.leaves.lock().expect("lock").get(host) {
            return Ok(c.clone());
        }
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(1);
        let leaf_key = KeyPair::generate()?;
        let leaf = params.signed_by(&leaf_key, &self.cert, &self.key)?;
        let chain = vec![CertificateDer::from(leaf.der().to_vec()), CertificateDer::from(self.cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        // HTTP/1.1 only, so every request is seen and decided one at a time.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.leaves.lock().expect("lock").insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}
