//! A per-run certificate authority. Its private key lives only in this process's memory; the
//! sandbox gets the public certificate so its TLS clients trust the egress proxy.

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CidrSubnet, DistinguishedName, DnType, GeneralSubtree, IsCa, KeyPair,
    KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::path::Path;
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
        if let Some(c) = self.leaves.lock().expect("lock").get(host) {
            return Ok(c.clone());
        }
        let der = CertificateDer::from(self.cert.der().to_vec());
        let cfg = leaf_config(host, &self.cert, &self.key, &der, OffsetDateTime::now_utc() + Duration::days(1))?;
        self.leaves.lock().expect("lock").insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

/// Something that mints TLS server configs for the egress proxy: a run's own CA, or a node's CA.
pub trait Minter: Send + Sync {
    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>>;
}

impl Minter for RunCa {
    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        RunCa::server_config(self, host)
    }
}

/// A leaf for `host` signed by `issuer`; the chain presented is [leaf, issuer as issued (`issuer_der`)].
fn leaf_config(
    host: &str,
    issuer: &Certificate,
    issuer_key: &KeyPair,
    issuer_der: &CertificateDer<'static>,
    not_after: OffsetDateTime,
) -> Result<Arc<ServerConfig>> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        bail!("refusing to mint a certificate for an IP literal");
    }
    let mut params = CertificateParams::new(vec![host.to_string()])?;
    params.distinguished_name.push(DnType::CommonName, host);
    params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
    params.not_after = not_after;
    let leaf_key = KeyPair::generate()?;
    let leaf = params.signed_by(&leaf_key, issuer, issuer_key)?;
    let chain = vec![CertificateDer::from(leaf.der().to_vec()), issuer_der.clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    // HTTP/1.1 only, so every request is seen and decided one at a time.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// A node's intermediate CA (#85), as `wicket node serve` uses it to terminate TLS for its boxes:
/// the certificate the control host issued (`ca.pem`) and the key that never left the node
/// (`ca.key`). It mints only for hosts inside its own name constraints (read from the certificate),
/// and nothing at all once expired; the node's forwarding rule (`decide::route`) sends everything
/// else to the control host. Leaves are presented with the node CA after them, so a box that trusts
/// the installation root verifies them.
pub struct NodeCa {
    /// The node CA as an rcgen issuer: rebuilt from the certificate's parameters and the node's key.
    issuer: Certificate,
    /// The certificate as issued (what the box's verifier sees).
    der: CertificateDer<'static>,
    key: KeyPair,
    pub not_after: i64,
    /// Permitted DNS subtrees, from the certificate's name constraints.
    pub permitted: Vec<String>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl NodeCa {
    pub fn load(cert_pem: &str, key_pem: &str) -> Result<NodeCa> {
        Self::load_with(cert_pem, key_pem, false)
    }

    /// As [`NodeCa::load`], also taking a CA without DNS name constraints (IP addresses still
    /// excluded): the control host's own node's, which may mint for any name (`*`).
    pub fn load_any(cert_pem: &str, key_pem: &str) -> Result<NodeCa> {
        Self::load_with(cert_pem, key_pem, true)
    }

    fn load_with(cert_pem: &str, key_pem: &str, any: bool) -> Result<NodeCa> {
        use x509_parser::extensions::{GeneralName, ParsedExtension};
        let key = KeyPair::from_pem(key_pem).context("node CA key")?;
        if key.public_key_der() != spki_of(cert_pem)? {
            bail!("the node CA certificate is not for the node CA key");
        }
        let (_, p) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).map_err(|e| anyhow::anyhow!("node CA PEM: {e}"))?;
        let der = p.contents.clone();
        let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow::anyhow!("node CA: {e}"))?;
        let mut permitted = vec![];
        for ext in cert.extensions() {
            if let ParsedExtension::NameConstraints(nc) = ext.parsed_extension() {
                for s in nc.permitted_subtrees.iter().flatten() {
                    if let GeneralName::DNSName(d) = &s.base {
                        permitted.push(d.to_string());
                    }
                }
            }
        }
        if permitted.is_empty() && any {
            permitted.push("*".into());
        }
        if permitted.is_empty() {
            bail!("the node CA has no DNS name constraints: refusing to use it");
        }
        let not_after = cert.validity().not_after.timestamp();
        let issuer = CertificateParams::from_ca_cert_pem(cert_pem).context("node CA certificate")?.self_signed(&key)?;
        Ok(NodeCa { issuer, der: CertificateDer::from(der), key, not_after, permitted, leaves: Mutex::new(HashMap::new()) })
    }

    /// Whether the CA may mint for `host` at `now` (Unix seconds).
    pub fn may_mint(&self, host: &str, now: i64) -> bool {
        now < self.not_after && self.permitted.iter().any(|s| crate::decide::subtree_permits(s, host))
    }
}

impl Minter for NodeCa {
    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if !self.may_mint(host, now) {
            bail!("the node CA may not mint for {host} (expired, or outside its name constraints)");
        }
        if let Some(c) = self.leaves.lock().expect("lock").get(host) {
            return Ok(c.clone());
        }
        // A leaf never outlives its CA; cached leaves are dropped with the process (the CA is renewed
        // daily, and `node serve` reloads it).
        let not_after = (OffsetDateTime::now_utc() + Duration::days(1)).min(OffsetDateTime::from_unix_timestamp(self.not_after)?);
        let cfg = leaf_config(host, &self.issuer, &self.key, &self.der, not_after)?;
        self.leaves.lock().expect("lock").insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

/// The installation's certificate authority: the root that node intermediate CAs chain to (#16, #57).
///
/// - Its key lives on the control host only, next to the identity issuer key (mode 0600), and never
///   reaches a node or a box.
/// - It signs nothing but node intermediates (`issue_node_ca`), so its path length is 1: root, node CA,
///   leaf.
/// - Local runs use a per-run [`RunCa`]. Boxes on enrolled nodes trust this root (for leaves their
///   node's [`NodeCa`] mints) and their run's own [`RunCa`] (for hosts the control host terminates).
pub struct InstallationCa {
    cert: Certificate,
    pem: String,
    key: KeyPair,
}

/// A node intermediate CA certificate as issued, with what the ledger records about it.
#[derive(Clone, Debug)]
pub struct NodeCaCert {
    pub pem: String,
    pub der: Vec<u8>,
    /// Hex, big-endian: what a revocation list names.
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    /// The permitted DNS subtrees, as encoded (`api.example.com`, `.example.org`).
    pub permitted: Vec<String>,
}

/// How long a node intermediate lives unless asked otherwise. Renewal is `wicket node renew-ca`.
pub const NODE_CA_TTL: Duration = Duration::hours(24);

impl InstallationCa {
    /// A fresh root (ECDSA P-256, ten years). Use [`InstallationCa::load_or_create`] for the installation's own.
    pub fn generate() -> Result<InstallationCa> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "wicket installation CA");
        dn.push(DnType::OrganizationName, "wicket");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.serial_number = Some(random_serial()?.into());
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(3650);
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        let pem = cert.pem();
        Ok(InstallationCa { cert, pem, key })
    }

    /// Loads the installation CA from `key_path` (PEM, 0600) and its certificate from
    /// `key_path.with_extension("pem")`, creating both on first use.
    pub fn load_or_create(key_path: &Path) -> Result<InstallationCa> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let cert_path = key_path.with_extension("pem");
        match std::fs::read_to_string(key_path) {
            Ok(key_pem) => {
                let key = KeyPair::from_pem(&key_pem).context("installation CA key")?;
                let pem = std::fs::read_to_string(&cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
                // rcgen signs as an issuer from its parameters (subject, key identifier) and key; the
                // re-signed copy is only that handle, the file on disk stays the certificate.
                let params = CertificateParams::from_ca_cert_pem(&pem).context("installation CA certificate")?;
                let cert = params.self_signed(&key)?;
                if key.public_key_der() != spki_of(&pem)? {
                    bail!("{} does not belong to the key in {}", cert_path.display(), key_path.display());
                }
                Ok(InstallationCa { cert, pem, key })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(d) = key_path.parent() {
                    std::fs::create_dir_all(d)?;
                }
                let ca = InstallationCa::generate()?;
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(key_path)?;
                f.write_all(ca.key.serialize_pem().as_bytes())?;
                std::fs::write(&cert_path, &ca.pem)?;
                Ok(ca)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn cert_pem(&self) -> &str {
        &self.pem
    }

    pub fn cert_der(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert.der().to_vec())
    }

    /// Issues a node's intermediate CA from its certificate signing request.
    ///
    /// - The CSR proves the node holds the private key (its signature is checked); only its public key
    ///   is used. Subject, extensions and lifetime come from here, never from the CSR.
    /// - The key must be ECDSA P-256 (what `openssl` makes on the node and every TLS client accepts).
    /// - Path length 0: the node can mint leaves, not further CAs.
    /// - **Name constraints** (critical): the permitted DNS subtrees are `hosts` (see
    ///   [`permitted_dns_subtrees`]), and every IPv4 and IPv6 address is excluded, so a stolen node CA
    ///   can't mint for an IP literal either.
    pub fn issue_node_ca(&self, csr_pem: &str, node: &str, hosts: &[String], ttl: Duration) -> Result<NodeCaCert> {
        let csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).context("node CA signing request")?;
        if csr.public_key.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
            bail!("the node CA key must be ECDSA P-256");
        }
        // `*`: any DNS name (the control host's own node, #146, which decides every host its boxes
        // reach); IP addresses stay excluded either way.
        let permitted = if hosts == ["*"] { vec!["*".to_string()] } else { permitted_dns_subtrees(hosts)? };
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("wicket node CA {node}"));
        dn.push(DnType::OrganizationName, "wicket");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: permitted.iter().filter(|d| *d != "*").map(|d| GeneralSubtree::DnsName(d.clone())).collect(),
            excluded_subtrees: vec![
                GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
                GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
            ],
        });
        let serial = random_serial()?;
        params.serial_number = Some(serial.clone().into());
        // Seconds only: what the certificate encodes, and what the ledger records.
        let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())?;
        // A few minutes back for clock skew between control host and node.
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + ttl;
        let (nb, na) = (params.not_before.unix_timestamp(), params.not_after.unix_timestamp());
        let cert = params.signed_by(&csr.public_key, &self.cert, &self.key)?;
        Ok(NodeCaCert { pem: cert.pem(), der: cert.der().to_vec(), serial: hex::encode(serial), not_before: nb, not_after: na, permitted })
    }
}

/// The SubjectPublicKeyInfo (DER) of the certificate in `pem`.
fn spki_of(pem: &str) -> Result<Vec<u8>> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow::anyhow!("certificate PEM: {e}"))?;
    let cert = p.parse_x509().map_err(|e| anyhow::anyhow!("certificate: {e}"))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// A random positive 16-byte serial. (rcgen's default is a hash of the public key, which would repeat.)
fn random_serial() -> Result<Vec<u8>> {
    let mut s = vec![0u8; 16];
    getrandom::getrandom(&mut s).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    s[0] &= 0x7f;
    s[0] |= 0x01;
    Ok(s)
}

/// The X.509 permitted DNS subtrees for the hosts a node may serve.
///
/// - `api.example.com` becomes the subtree `api.example.com`. X.509 can't say "exactly this host": a
///   DNS constraint also permits every name under it, so the node CA can mint for `x.api.example.com`
///   too. The egress policy, not the certificate, is the exact per-host gate; the constraint bounds
///   what a stolen node CA is good for.
/// - `*.example.org` becomes `.example.org`: every name under `example.org` (any depth), but not
///   `example.org` itself. List both for both.
/// - IP literals, other wildcards, empty labels and characters outside `[a-z0-9-_]` are refused. At
///   least one host is required: with no DNS subtree at all, DNS names would be unconstrained.
pub fn permitted_dns_subtrees(hosts: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for h in hosts {
        let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
        if h.parse::<std::net::IpAddr>().is_ok() {
            bail!("{h}: node CAs never cover IP addresses");
        }
        let (wild, base) = match h.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, h.as_str()),
        };
        let label_ok = |l: &str| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if base.is_empty() || !base.split('.').all(label_ok) || !base.contains('.') {
            bail!("{h:?} is not a host name or *.domain the node CA can be constrained to");
        }
        let s = if wild { format!(".{base}") } else { base.to_string() };
        if !out.contains(&s) {
            out.push(s);
        }
    }
    if out.is_empty() {
        bail!("a node CA needs at least one host (--hosts)");
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};

    fn hosts(h: &[&str]) -> Vec<String> {
        h.iter().map(|s| s.to_string()).collect()
    }

    /// A node: its CA key (made "on the node") and the issued intermediate.
    fn node_ca(root: &InstallationCa, h: &[&str]) -> (KeyPair, NodeCaCert) {
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
        let cert = root.issue_node_ca(&csr, "n1", &hosts(h), NODE_CA_TTL).unwrap();
        (key, cert)
    }

    /// A leaf for `san` (a host name or an IP literal) minted by the node CA, as a stolen node CA could.
    fn leaf(node_key: &KeyPair, node: &NodeCaCert, san: &str) -> CertificateDer<'static> {
        let issuer = CertificateParams::from_ca_cert_der(&CertificateDer::from(node.der.clone())).unwrap().self_signed(node_key).unwrap();
        let mut p = CertificateParams::new(vec![san.to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, san);
        let k = KeyPair::generate().unwrap();
        CertificateDer::from(p.signed_by(&k, &issuer, node_key).unwrap().der().to_vec())
    }

    /// What a box's TLS client does: verify the chain against wicket's root only.
    fn verify(
        root: &InstallationCa,
        node: &NodeCaCert,
        leaf: &CertificateDer<'static>,
        name: &str,
    ) -> std::result::Result<(), rustls::Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.cert_der()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let v = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build().unwrap();
        let name = ServerName::try_from(name.to_string()).unwrap();
        v.verify_server_cert(leaf, &[CertificateDer::from(node.der.clone())], &name, &[], UnixTime::now()).map(|_| ())
    }

    #[test]
    fn a_real_verifier_enforces_the_node_ca_name_constraints() {
        let root = InstallationCa::generate().unwrap();
        let (k, node) = node_ca(&root, &["api.example.com", "*.example.org"]);
        // Inside the constraints: the chain verifies (so a failure below is the constraint, not the chain).
        for host in ["api.example.com", "x.api.example.com", "www.example.org", "a.b.example.org"] {
            verify(&root, &node, &leaf(&k, &node, host), host).unwrap_or_else(|e| panic!("{host}: {e:?}"));
        }
        // Outside: refused for the name constraint.
        for host in ["evil.example.net", "example.com", "example.org", "api.example.com.evil.example.net"] {
            let e = verify(&root, &node, &leaf(&k, &node, host), host).expect_err(host);
            assert!(format!("{e:?}").contains("NameConstraintViolation"), "{host}: {e:?}");
        }
        // An IP literal is excluded outright.
        let e = verify(&root, &node, &leaf(&k, &node, "203.0.113.7"), "203.0.113.7").expect_err("ip");
        assert!(format!("{e:?}").contains("NameConstraintViolation"), "{e:?}");
        // A different root's node CA doesn't chain at all.
        let other = InstallationCa::generate().unwrap();
        let (k2, foreign) = node_ca(&other, &["api.example.com"]);
        assert!(verify(&root, &foreign, &leaf(&k2, &foreign, "api.example.com"), "api.example.com").is_err());
    }

    #[test]
    fn the_node_ca_encodes_critical_constraints_path_length_zero_and_its_lifetime() {
        use x509_parser::extensions::{GeneralName, ParsedExtension};
        let root = InstallationCa::generate().unwrap();
        let (_, node) = node_ca(&root, &["API.example.com.", "*.example.org", "api.example.com"]);
        assert_eq!(node.permitted, vec![".example.org", "api.example.com"]);
        assert_eq!(node.not_after - node.not_before, NODE_CA_TTL.whole_seconds() + 300);
        assert_eq!(node.serial.len(), 32);
        let (_, cert) = x509_parser::parse_x509_certificate(&node.der).unwrap();
        assert_eq!(cert.validity().not_after.timestamp(), node.not_after);
        assert_eq!(cert.tbs_certificate.raw_serial_as_string().replace(':', ""), node.serial);
        let mut seen = false;
        for ext in cert.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::NameConstraints(nc) => {
                    assert!(ext.critical, "name constraints must be critical");
                    let permitted: Vec<String> = nc
                        .permitted_subtrees
                        .as_ref()
                        .unwrap()
                        .iter()
                        .map(|s| match &s.base {
                            GeneralName::DNSName(d) => d.to_string(),
                            other => panic!("unexpected permitted {other:?}"),
                        })
                        .collect();
                    assert_eq!(permitted, vec![".example.org", "api.example.com"]);
                    let excluded: Vec<Vec<u8>> = nc
                        .excluded_subtrees
                        .as_ref()
                        .unwrap()
                        .iter()
                        .map(|s| match &s.base {
                            GeneralName::IPAddress(b) => b.to_vec(),
                            other => panic!("unexpected excluded {other:?}"),
                        })
                        .collect();
                    assert_eq!(excluded, vec![vec![0u8; 8], vec![0u8; 32]]);
                    seen = true;
                }
                ParsedExtension::BasicConstraints(bc) => {
                    assert!(bc.ca);
                    assert_eq!(bc.path_len_constraint, Some(0));
                }
                _ => {}
            }
        }
        assert!(seen, "no name constraints extension");
    }

    /// A box's TLS client, trusting only the installation root, against a node-minted leaf.
    async fn handshake(root: &InstallationCa, server: Arc<ServerConfig>, name: &str) -> std::result::Result<(), String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.cert_der()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let (a, b) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move { tokio_rustls::TlsAcceptor::from(server).accept(b).await.map(|_| ()) });
        let sn = ServerName::try_from(name.to_string()).unwrap();
        let r = tokio_rustls::TlsConnector::from(Arc::new(client)).connect(sn, a).await.map(|_| ()).map_err(|e| e.to_string());
        let _ = srv.await;
        r
    }

    #[tokio::test]
    async fn a_node_ca_mints_leaves_a_box_trusting_the_root_accepts_and_nothing_outside_its_constraints() {
        let root = InstallationCa::generate().unwrap();
        let (key, cert) = node_ca(&root, &["api.example.com", "*.example.org"]);
        let ca = NodeCa::load(&cert.pem, &key.serialize_pem()).unwrap();
        assert_eq!(ca.permitted, vec![".example.org", "api.example.com"]);
        assert_eq!(ca.not_after, cert.not_after);
        for host in ["api.example.com", "www.example.org"] {
            handshake(&root, Minter::server_config(&ca, host).unwrap(), host).await.unwrap_or_else(|e| panic!("{host}: {e}"));
        }
        // Never minted: outside the constraints, an IP literal, or once expired.
        for host in ["evil.example.net", "example.org", "203.0.113.7"] {
            assert!(Minter::server_config(&ca, host).is_err(), "{host}");
        }
        assert!(ca.may_mint("api.example.com", cert.not_after - 1));
        assert!(!ca.may_mint("api.example.com", cert.not_after));
        // A key that isn't the certificate's is refused.
        let other = KeyPair::generate().unwrap();
        assert!(NodeCa::load(&cert.pem, &other.serialize_pem()).is_err());
    }

    /// #146: the control host's own node's CA may mint for any name (it serves whatever its boxes
    /// reach) but never an IP literal; only `load_any` takes it, so a remote node never would.
    #[tokio::test]
    async fn the_local_node_ca_mints_any_name_and_no_ip() {
        let root = InstallationCa::generate().unwrap();
        let (key, cert) = node_ca(&root, &["*"]);
        assert_eq!(cert.permitted, vec!["*"]);
        assert!(NodeCa::load(&cert.pem, &key.serialize_pem()).is_err(), "a remote node refuses an unconstrained CA");
        let ca = NodeCa::load_any(&cert.pem, &key.serialize_pem()).unwrap();
        for host in ["api.example.com", "evil.example.net", "example.org"] {
            handshake(&root, Minter::server_config(&ca, host).unwrap(), host).await.unwrap_or_else(|e| panic!("{host}: {e}"));
        }
        assert!(Minter::server_config(&ca, "203.0.113.7").is_err());
        assert!(crate::decide::subtree_permits("*", "anything.example"));
    }

    #[test]
    fn host_lists_that_would_leave_names_unconstrained_are_refused() {
        for bad in [&[][..], &["203.0.113.7"], &["*.com"], &["a.*.example.com"], &["localhost"], &["exa mple.com"], &["*"]] {
            assert!(permitted_dns_subtrees(&hosts(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_tampered_or_wrong_key_csr_is_refused() {
        let root = InstallationCa::generate().unwrap();
        let ed = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let csr = CertificateParams::default().serialize_request(&ed).unwrap().pem().unwrap();
        assert!(root.issue_node_ca(&csr, "n1", &hosts(&["api.example.com"]), NODE_CA_TTL).is_err());
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name.push(DnType::CommonName, "node");
        let der = p.serialize_request(&key).unwrap().der().to_vec();
        let mut bad = der.clone();
        let n = bad.len();
        bad[n - 5] ^= 0x01; // inside the signature
        let pem = |d: &[u8]| {
            use base64::Engine;
            let b = base64::engine::general_purpose::STANDARD.encode(d);
            format!("-----BEGIN CERTIFICATE REQUEST-----\n{b}\n-----END CERTIFICATE REQUEST-----\n")
        };
        assert!(root.issue_node_ca(&pem(&der), "n1", &hosts(&["api.example.com"]), NODE_CA_TTL).is_ok());
        assert!(root.issue_node_ca(&pem(&bad), "n1", &hosts(&["api.example.com"]), NODE_CA_TTL).is_err());
    }

    #[test]
    fn the_installation_ca_is_created_once_private_and_reloads_to_the_same_root() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wicket-ca-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("ca.key");
        let a = InstallationCa::load_or_create(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let b = InstallationCa::load_or_create(&path).unwrap();
        assert_eq!(a.cert_pem(), b.cert_pem());
        // A node CA issued by the reloaded root chains to the original root certificate.
        let (k, node) = node_ca(&b, &["api.example.com"]);
        verify(&a, &node, &leaf(&k, &node, "api.example.com"), "api.example.com").unwrap();
        // A certificate that doesn't match the key is refused.
        std::fs::write(path.with_extension("pem"), InstallationCa::generate().unwrap().cert_pem()).unwrap();
        assert!(InstallationCa::load_or_create(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
