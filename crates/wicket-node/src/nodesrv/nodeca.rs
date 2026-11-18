//! The node CA on the node (#416): the one every box here mints from, and its renewal over the
//! control channel.
//!
//! - **One CA for every box.** [`LiveCa`] holds the node CA the node loaded last; each box's egress
//!   proxy mints from it and routes by it (`NodeRouter`), at each connection. Renewed, it is swapped
//!   in place, so a running box's next connection is served by the new CA: nothing restarts. Leaves
//!   minted by the old one stay valid for the connections that have them (until the old CA's end).
//! - **Renewal** ([`Msg::CaRenew`](crate::chan::Msg::CaRenew), protocol 14): the node makes a new
//!   P-256 key and answers with a signing request for it ([`begin`]). The key waits in memory, never
//!   written, until the control host's certificate for it comes ([`install`]): that must be for this
//!   key, signed by the installation root the node was enrolled with (`root.pem`), name-constrained
//!   and unexpired. Only then are `ca.key`, `ca.pem` and `ca-chain.pem` replaced (each written aside
//!   and renamed) and the CA swapped. One renewal at a time: another asked within [`PENDING_SECS`]
//!   is refused (each run's connection to the node may ask), and an unanswered one lapses.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use wicket_proxy::ca::{Minter, NodeCa};

/// How long a renewal's new key waits for its certificate.
pub const PENDING_SECS: i64 = 120;

/// The node CA boxes mint from: swapped in place when it is renewed or reloaded.
#[derive(Default)]
pub struct LiveCa(RwLock<Option<Arc<NodeCa>>>);

impl LiveCa {
    pub fn get(&self) -> Option<Arc<NodeCa>> {
        self.0.read().expect("ca").clone()
    }

    pub fn set(&self, ca: Option<Arc<NodeCa>>) {
        *self.0.write().expect("ca") = ca;
    }
}

impl Minter for LiveCa {
    fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        match self.get() {
            Some(c) => c.server_config(host),
            None => bail!("this node has no usable CA: {host} can't be terminated here"),
        }
    }
}

/// A renewal's new CA key, waiting for its certificate.
pub struct Pending {
    key_pem: String,
    at: i64,
}

/// Starts a renewal: a new CA key (kept in `pending`) and its signing request (PEM).
pub fn begin(pending: &Mutex<Option<Pending>>, name: &str, now: i64) -> Result<String> {
    let mut p = pending.lock().expect("pending");
    if p.as_ref().is_some_and(|p| now - p.at < PENDING_SECS) {
        bail!("another CA renewal is under way on this node");
    }
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::default();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::OrganizationName, "wicket");
    dn.push(rcgen::DnType::CommonName, format!("wicket node CA {name}"));
    params.distinguished_name = dn;
    let csr = params.serialize_request(&key)?.pem()?;
    *p = Some(Pending { key_pem: key.serialize_pem(), at: now });
    Ok(csr)
}

/// Takes the certificate for the pending key (`pem`): checked against the key, the installation
/// root (`root_pem`) and the clock, then written in place of the old CA. Returns the CA and its
/// serial (hex). `any`: the control host's own node, whose CA isn't name-constrained.
pub fn install(
    pending: &Mutex<Option<Pending>>,
    dir: &Path,
    root_pem: &str,
    any: bool,
    pem: &str,
    now: i64,
) -> Result<(Arc<NodeCa>, String)> {
    let key_pem = pending.lock().expect("pending").take().map(|p| p.key_pem).context("no CA renewal is under way on this node")?;
    let ca = if any { NodeCa::load_any(pem, &key_pem) } else { NodeCa::load(pem, &key_pem) }?;
    if ca.not_after <= now {
        bail!("the new node CA certificate has already expired");
    }
    let serial = issued_by(pem, root_pem)?;
    let chain = format!("{}{}", pem.trim_end(), format_args!("\n{root_pem}"));
    let files = [("ca.key", key_pem.as_str()), ("ca.pem", pem), ("ca-chain.pem", chain.as_str())];
    for (f, body) in files {
        write_private(&dir.join(format!("{f}.new")), body)?;
    }
    // Key first: a crash between the renames leaves a pair that doesn't load (refused as unusable),
    // never a certificate for a key that is gone.
    for (f, _) in files {
        std::fs::rename(dir.join(format!("{f}.new")), dir.join(f)).with_context(|| format!("installing {f}"))?;
    }
    let ca = Arc::new(ca);
    Ok((ca, serial))
}

/// The certificate's serial (hex), if it is signed by the root in `root_pem` and names it as issuer.
fn issued_by(pem: &str, root_pem: &str) -> Result<String> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow::anyhow!("node CA PEM: {e}"))?;
    let cert = p.parse_x509().map_err(|e| anyhow::anyhow!("node CA: {e}"))?;
    let (_, rp) = x509_parser::pem::parse_x509_pem(root_pem.as_bytes()).map_err(|e| anyhow::anyhow!("root.pem: {e}"))?;
    let root = rp.parse_x509().map_err(|e| anyhow::anyhow!("root.pem: {e}"))?;
    if cert.issuer() != root.subject() || cert.verify_signature(Some(root.public_key())).is_err() {
        bail!("the new node CA certificate is not signed by this node's installation root");
    }
    Ok(hex::encode(cert.raw_serial()))
}

fn write_private(path: &Path, body: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    std::io::Write::write_all(&mut f, body.as_bytes())?;
    if !body.ends_with('\n') {
        std::io::Write::write_all(&mut f, b"\n")?;
    }
    f.sync_all()?;
    Ok(())
}

/// Why a box can't start here (#416): its zone needs hosts the node CA terminates (its model route,
/// or a reach or inject host inside the CA's name constraints), and the CA has expired. None if it
/// hasn't, or the box needs none of them.
pub fn expired_for(ca: Option<&NodeCa>, zone: &wicket_core::ZoneSpec, node: &str, now: i64) -> Option<String> {
    let ca = ca?;
    if now < ca.not_after {
        return None;
    }
    let covered = |h: &str| {
        let h = h.strip_prefix("*.").map(|d| format!("x.{d}")).unwrap_or_else(|| h.to_string());
        ca.permitted.iter().any(|s| wicket_proxy::decide::subtree_permits(s, &h))
    };
    let needs = zone.llm.is_some() || zone.reach.iter().any(|r| covered(&r.host)) || zone.inject.iter().any(|r| covered(&r.host));
    needs.then(|| {
        format!(
            "node {node}'s CA expired at {}, so it can't serve this box's inspected hosts{}: the control host renews it over \
             the channel (protocol 14), or run `wicket node renew-ca {node}`",
            wicket_core::time::unix_rfc3339(ca.not_after),
            if zone.llm.is_some() { " (its model API among them)" } else { "" }
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_proxy::ca::InstallationCa;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-nodeca-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn err<T>(r: Result<T>) -> String {
        match r {
            Ok(_) => panic!("accepted"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[test]
    fn a_renewal_installs_only_a_certificate_for_its_own_key_from_the_root() {
        let dir = tmp("install");
        let root = InstallationCa::generate().unwrap();
        let pending = Mutex::new(None);
        let now = wicket_store::now();
        let csr = begin(&pending, "n1", now).unwrap();
        assert!(begin(&pending, "n1", now + 1).unwrap_err().to_string().contains("under way"), "one at a time");
        let cert = root.issue_node_ca(&csr, "n1", &["api.example.com".into()], time::Duration::minutes(10)).unwrap();
        // Another root's certificate for the same key is refused, and the pending key is spent.
        let other = InstallationCa::generate().unwrap();
        let foreign = other.issue_node_ca(&csr, "n1", &["api.example.com".into()], time::Duration::minutes(10)).unwrap();
        let e = err(install(&pending, &dir, root.cert_pem(), false, &foreign.pem, now));
        assert!(e.contains("not signed by"), "{e}");
        assert!(!dir.join("ca.pem").exists(), "nothing written");
        assert!(err(install(&pending, &dir, root.cert_pem(), false, &cert.pem, now)).contains("no CA renewal"));
        // A fresh request, and a certificate for some other key: refused.
        let csr2 = begin(&pending, "n1", now).unwrap();
        let e = err(install(&pending, &dir, root.cert_pem(), false, &cert.pem, now));
        assert!(e.contains("not for the node CA key"), "{e}");
        // That spent the request too. An abandoned one lapses.
        begin(&pending, "n1", now).unwrap();
        assert!(begin(&pending, "n1", now + PENDING_SECS - 1).is_err());
        let csr3 = begin(&pending, "n1", now + PENDING_SECS).unwrap();
        assert_ne!(csr2, csr3);
        let good = root.issue_node_ca(&csr3, "n1", &["api.example.com".into()], time::Duration::minutes(10)).unwrap();
        let (ca, serial) = install(&pending, &dir, root.cert_pem(), false, &good.pem, now).unwrap();
        assert_eq!((serial, ca.not_after), (good.serial.clone(), good.not_after));
        // What is on disk loads as the same CA (what a restarted `serve`, or the next box, reads).
        let disk =
            NodeCa::load(&std::fs::read_to_string(dir.join("ca.pem")).unwrap(), &std::fs::read_to_string(dir.join("ca.key")).unwrap())
                .unwrap();
        assert_eq!(disk.not_after, good.not_after);
        assert!(std::fs::read_to_string(dir.join("ca-chain.pem")).unwrap().ends_with(root.cert_pem()));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.join("ca.key")).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_live_ca_is_swapped_under_its_users() {
        let root = InstallationCa::generate().unwrap();
        let live = Arc::new(LiveCa::default());
        assert!(live.server_config("api.example.com").is_err());
        let mk = |ttl| {
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let csr = rcgen::CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
            let c = root.issue_node_ca(&csr, "n1", &["api.example.com".into()], ttl).unwrap();
            Arc::new(NodeCa::load(&c.pem, &key.serialize_pem()).unwrap())
        };
        // A CA that has ended: nothing minted.
        live.set(Some(mk(time::Duration::seconds(-1))));
        let user: Arc<dyn Minter> = live.clone();
        assert!(user.server_config("api.example.com").is_err());
        live.set(Some(mk(time::Duration::minutes(10))));
        assert!(user.server_config("api.example.com").is_ok(), "the same handle mints from the new CA");
    }

    #[test]
    fn an_expired_ca_refuses_boxes_that_need_it() {
        let root = InstallationCa::generate().unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let csr = rcgen::CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
        let c = root.issue_node_ca(&csr, "n1", &["api.example.com".into(), "*.example.org".into()], time::Duration::minutes(10)).unwrap();
        let ca = NodeCa::load(&c.pem, &key.serialize_pem()).unwrap();
        let zone = |y: &str| {
            wicket_core::Manifest::from_yaml(&format!("task: t\nprogram: {{ name: p, command: [x] }}\nzone:\n  name: z\n{y}")).unwrap().zone
        };
        let reach = zone("  reach:\n    - { host: api.example.com }\n");
        let wild = zone("  reach:\n    - { host: \"*.example.org\" }\n");
        let other = zone("  reach:\n    - { host: elsewhere.example.net }\n");
        assert_eq!(expired_for(Some(&ca), &reach, "n1", c.not_after - 1), None, "not expired");
        assert_eq!(expired_for(None, &reach, "n1", c.not_after), None, "no CA: nothing to expire");
        let e = expired_for(Some(&ca), &reach, "n1", c.not_after).unwrap();
        assert!(e.contains("CA expired") && e.contains("wicket node renew-ca n1"), "{e}");
        assert!(expired_for(Some(&ca), &wild, "n1", c.not_after).is_some());
        assert_eq!(expired_for(Some(&ca), &other, "n1", c.not_after), None, "spliced or refused either way");
    }
}
