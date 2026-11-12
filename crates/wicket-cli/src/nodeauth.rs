//! Mutual authentication on the node control channel (#16), on top of the transport-independent
//! handshake in `wicket_identity::node`.
//!
//! Over the channel (`chan.rs`), before anything else:
//!
//! | # | from | message | carries |
//! |---|---|---|---|
//! | 1 | control host | [`Msg::Hello`] | node name, build, a fresh nonce |
//! | 2 | node | [`Msg::Challenge`] | its nonce, its node certificate, a proof signed with its node key |
//! | 3 | control host | [`Msg::Prove`] | a proof signed with the installation's issuer key |
//! | 4 | node | [`Msg::Welcome`] (or [`Msg::Refused`]) | its runs and feed position |
//!
//! - **The control host refuses the node** unless its certificate is signed by this installation's
//!   issuer, names it (`spiffe://<trust domain>/node/<name>`), is unexpired by the control host's clock,
//!   binds the node key recorded at enrolment, is recorded in the ledger and not revoked, the node
//!   itself is active, and its proof verifies for this connection. Then nothing is sent to the node
//!   (no feed, no box, no files) before step 3.
//! - **The node refuses the control host** unless its proof verifies against the issuer public key
//!   installed at enrolment (`issuer.pub.json`). Before that, nothing changes on the node: the
//!   current control connection keeps the link, and no run or feed state is sent.
//! - **Renewal.** At half its lifetime the control host issues the node a new certificate for the same
//!   key over the channel ([`Msg::NodeCert`]); the node checks it and swaps it in atomically. Earlier
//!   certificates stay valid until they expire, so a lost renewal doesn't lock the node out. A node
//!   that was unreachable until its certificate expired is renewed out of band, over its pinned ssh:
//!   `wicket node renew-ca <name>`.
//! - **Revocation.** `wicket node revoke` marks the node and its certificates revoked. A run connected
//!   to it notices within a second, stops its box and drops the channel; nothing reconnects to it.
//! - **Observers** (`wicket dev node-feed-probe`, run on the node itself) skip the handshake: they
//!   can only send feed frames, which the node checks against the feed root's signatures anyway, and
//!   they never take over the control connection.

use crate::chan::{self, Frame, Msg};
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use wicket_identity::node::{ControlHandshake, NodeCertClaims, NodeHandshake};
use wicket_identity::{Issuer, SigningKey, VerifyingKey};
use wicket_store::{Ledger, NodeCertRow};

/// The node's identity certificate, beside its key in the node's directory.
pub const CERT_FILE: &str = "node-cert.jwt";

/// Lifetimes allowed for node certificates.
pub fn cert_ttl(d: std::time::Duration) -> Result<i64> {
    let s = d.as_secs() as i64;
    if !(300..=30 * 86_400).contains(&s) {
        anyhow::bail!("node certificate lifetime must be between 5 minutes and 30 days");
    }
    Ok(s)
}

/// Issues node `name` a certificate for `key` and records it. Returns the certificate.
pub fn issue(ledger: &Ledger, issuer: &Issuer, name: &str, key: &VerifyingKey, now: i64, ttl: i64) -> Result<(String, NodeCertClaims)> {
    let (jws, c) = issuer.issue_node_cert(name, key, now, ttl);
    ledger.record_node_cert(&NodeCertRow {
        serial: c.jti.clone(),
        node: name.into(),
        node_key: hex::encode(key.to_bytes()),
        issued_at: c.iat,
        not_after: c.exp,
        status: "active".into(),
    })?;
    Ok((jws, c))
}

/// The enrolled node key, from the ledger's hex.
pub fn enrolled_key(hex_key: &str) -> Result<VerifyingKey> {
    let b: [u8; 32] = hex::decode(hex_key).ok().and_then(|b| b.try_into().ok()).context("the ledger's node key is not 32 bytes of hex")?;
    VerifyingKey::from_bytes(&b).context("the ledger's node key is not an Ed25519 key")
}

/// Why the control host stopped talking to a node.
#[derive(Debug, thiserror::Error)]
pub enum HsError {
    /// The channel ended, or sent something other than a message, before the handshake finished.
    #[error("no answer")]
    NoAnswer,
    #[error("node {0} did not answer within 30 s")]
    Timeout(String),
    /// One side refused the other: not worth retrying.
    #[error("{0}")]
    Refused(String),
}

/// What the node said once both ends were authenticated.
pub struct Authenticated {
    pub welcome: Msg,
    pub cert: NodeCertClaims,
    /// The protocol version the connection talks (#162).
    pub proto: u32,
}

async fn next_msg<R: AsyncRead + Unpin>(rd: &mut R, node: &str) -> Result<Msg, HsError> {
    match tokio::time::timeout(std::time::Duration::from_secs(30), chan::read_frame(rd)).await {
        Ok(Ok(Some(Frame::Msg(m)))) => Ok(m),
        Ok(_) => Err(HsError::NoAnswer),
        Err(_) => Err(HsError::Timeout(node.into())),
    }
}

/// The control host's side: authenticates node `node` and proves this installation to it.
/// `hello` makes the hello from the nonce.
pub async fn control<R, W>(
    rd: &mut R,
    wr: &mut W,
    node: &str,
    ledger: &Mutex<Ledger>,
    issuer: &Issuer,
    hello: impl FnOnce(String) -> Msg,
) -> Result<Authenticated, HsError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let refused = |why: String| HsError::Refused(why);
    let mut hs = ControlHandshake::new(node, b"");
    // A failed write shows up as no answer, with the channel's own error.
    let _ = wr.write_all(&Frame::Msg(hello(hs.nonce().to_string())).encode()).await;
    let proof = match next_msg(rd, node).await? {
        Msg::Challenge { proof } => proof,
        Msg::Refused { why } => return Err(refused(format!("node {node} refused this control host: {why}"))),
        other => return Err(refused(format!("unexpected first message from node {node}: {}", short(&other)))),
    };
    let now = wicket_store::now();
    let cert = {
        let l = ledger.lock().expect("ledger");
        let row = l.node(node).map_err(|e| refused(e.to_string()))?.ok_or_else(|| refused(format!("node {node} is not enrolled")))?;
        if row.status != "active" {
            return Err(refused(format!("node {node} is {}", row.status)));
        }
        let key = enrolled_key(&row.node_key).map_err(|e| refused(format!("{e:#}")))?;
        let c = hs.verify_node(&proof, &issuer.verifying_key(), &key, now).map_err(|e| {
            refused(format!("node {node} failed authentication: {e} (renew it with `wicket node renew-ca {node}`, or revoke it)"))
        })?;
        match l.node_cert(&c.jti).map_err(|e| refused(e.to_string()))? {
            Some(r) if r.node == node && r.status == "active" => {}
            Some(r) => return Err(refused(format!("node {node} presented certificate {} which is {}", c.jti, r.status))),
            None => return Err(refused(format!("node {node} presented certificate {}, which this installation never recorded", c.jti))),
        }
        c
    };
    let cp = hs.prove(issuer).map_err(|e| refused(e.to_string()))?;
    let _ = wr.write_all(&Frame::Msg(Msg::Prove { proof: cp }).encode()).await;
    match next_msg(rd, node).await? {
        m @ Msg::Welcome { proto, .. } => match chan::negotiate(chan::PROTOCOL, proto) {
            Ok(proto) => Ok(Authenticated { welcome: m, cert, proto }),
            Err(e) => Err(refused(format!(
                "node {node} can't talk to this control host: {e}; update the older of the two (`wicket self update --nodes {node}`)"
            ))),
        },
        Msg::Refused { why } => Err(refused(format!("node {node} refused this control host: {why}"))),
        other => Err(refused(format!("unexpected answer from node {node}: {}", short(&other)))),
    }
}

fn short(m: &Msg) -> String {
    let s = format!("{m:?}");
    s.chars().take(120).collect()
}

/// What a node proves itself with: its key and the issuer it trusts, loaded once at `serve`.
pub struct NodeIdentity {
    pub key: SigningKey,
    pub issuer: VerifyingKey,
}

impl NodeIdentity {
    /// Loads `node.key` and `issuer.pub.json` from the node's directory, and warns if the certificate
    /// held there is missing, expired or for another key.
    pub fn load(root: &Path, name: &str, now: i64) -> Result<NodeIdentity> {
        let pem = std::fs::read_to_string(root.join("node.key"))
            .with_context(|| format!("{} (is this node enrolled?)", root.join("node.key").display()))?;
        let key = wicket_identity::node::signing_key_from_pkcs8_pem(&pem).context("node.key")?;
        let jwk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("issuer.pub.json")).context("issuer.pub.json (is this node enrolled?)")?)?;
        let issuer = wicket_identity::verifying_key_from_jwk(&jwk).context("issuer.pub.json")?;
        let id = NodeIdentity { key, issuer };
        match std::fs::read_to_string(root.join(CERT_FILE)) {
            Err(_) => eprintln!(
                "[node] no identity certificate ({CERT_FILE}): control hosts will refuse this node until `wicket node renew-ca {name}`"
            ),
            Ok(c) => match id.check_cert(c.trim(), name, now) {
                Ok(c) => eprintln!("[node] identity {} (certificate {}…, expires in {} s)", c.sub, &c.jti[..12], c.exp - now),
                Err(e) => eprintln!("[node] the identity certificate is unusable ({e:#}): renew it with `wicket node renew-ca {name}`"),
            },
        }
        Ok(id)
    }

    /// A certificate is this node's: from the issuer it trusts, for its name and its own key, valid now.
    pub fn check_cert(&self, cert: &str, name: &str, now: i64) -> Result<NodeCertClaims> {
        let c = wicket_identity::node::verify_node_cert(cert, &self.issuer, name, now)?;
        if c.key()? != self.key.verifying_key() {
            anyhow::bail!("the certificate is for another key");
        }
        Ok(c)
    }

    /// Checks a renewed certificate and swaps it in (written aside, then renamed).
    pub fn install_cert(&self, root: &Path, cert: &str, name: &str, now: i64) -> Result<NodeCertClaims> {
        use std::os::unix::fs::OpenOptionsExt;
        let c = self.check_cert(cert, name, now)?;
        let tmp = root.join(format!("{CERT_FILE}.new"));
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        std::io::Write::write_all(&mut f, format!("{cert}\n").as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, root.join(CERT_FILE))?;
        Ok(c)
    }
}

/// The node's side, after the hello's name and build have been checked: answers with its certificate
/// and proof, then checks the control host's. `Err` is the reason to refuse it.
pub async fn node<R, W>(rd: &mut R, wr: &mut W, id: &NodeIdentity, root: &Path, name: &str, nonce: &str) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let cert = std::fs::read_to_string(root.join(CERT_FILE))
        .map(|s| s.trim().to_string())
        .map_err(|_| anyhow::anyhow!("this node has no identity certificate: run `wicket node renew-ca {name}` from the control host"))?;
    let (hs, proof) = NodeHandshake::answer(name, &id.key, &cert, nonce, b"")?;
    wr.write_all(&Frame::Msg(Msg::Challenge { proof }).encode()).await?;
    let answer = tokio::time::timeout(std::time::Duration::from_secs(15), chan::read_frame(rd))
        .await
        .context("no proof from the control host")??;
    match answer {
        Some(Frame::Msg(Msg::Prove { proof })) => Ok(hs.verify_control(&proof, &id.issuer)?),
        _ => anyhow::bail!("the control host sent no proof"),
    }
}

/// Renewal, on the control host: when a certificate is past half its life.
pub fn due(c: &NodeCertClaims, now: i64) -> bool {
    now >= c.iat + (c.exp - c.iat) / 2
}

/// A renewed certificate for the node's key (with the same lifetime as `current`), if `current` is due.
pub fn renew_if_due(
    ledger: &Ledger,
    issuer: &Issuer,
    node: &str,
    current: &NodeCertClaims,
    now: i64,
) -> Option<Result<(String, NodeCertClaims)>> {
    if !due(current, now) {
        return None;
    }
    Some(current.key().map_err(anyhow::Error::from).and_then(|k| issue(ledger, issuer, node, &k, now, current.exp - current.iat)))
}

/// Checked every second on a live connection: why the control host must drop the node now, if it
/// must. The node (or the certificate it authenticated with) was revoked, by this process or another,
/// or the certificate expired without a renewal.
pub fn untrusted(ledger: &Ledger, node: &str, cert: Option<&NodeCertClaims>, now: i64) -> Option<String> {
    match ledger.node(node) {
        Ok(Some(n)) if n.status == "active" => {}
        Ok(Some(n)) => return Some(format!("node {node} is {}", n.status)),
        Ok(None) => return Some(format!("node {node} is no longer enrolled")),
        Err(e) => {
            eprintln!("[wicket] could not check node {node}'s status: {e}");
            return None;
        }
    }
    let c = cert?;
    if let Ok(Some(r)) = ledger.node_cert(&c.jti) {
        if r.status != "active" {
            return Some(format!("node {node}'s certificate {} is {}", c.jti, r.status));
        }
    }
    (c.exp <= now).then(|| format!("node {node}'s certificate expired"))
}

/// A test installation: an issuer, a ledger with node `n1` enrolled, and the node's key and
/// certificate in a directory, as enrolment leaves them.
#[cfg(test)]
pub mod testkit {
    use super::*;

    pub struct Install {
        pub issuer: Issuer,
        pub ledger: Mutex<Ledger>,
        pub key: SigningKey,
        pub dir: std::path::PathBuf,
        pub cert: NodeCertClaims,
    }

    impl Install {
        pub fn new(tag: &str) -> Install {
            let dir = std::env::temp_dir().join(format!("wicket-nodeauth-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let issuer = Issuer::generate("test.wicket.example");
            let key = SigningKey::generate(&mut rand_core::OsRng);
            let mut l = Ledger::open_in_memory().unwrap();
            let t = l.create_node_token(&wicket_core::TenantId::single(), "n1", 600).unwrap();
            let row = wicket_store::NodeRow {
                name: "n1".into(),
                tenant: wicket_core::TenantId::single().0,
                target: "wicket@n1.example.com".into(),
                host_key: "ssh-ed25519 AAAA".into(),
                host_key_fp: "SHA256:x".into(),
                node_key: hex::encode(key.verifying_key().to_bytes()),
                ssh_key: None,
                hosts: vec![],
                enrolled_at: wicket_store::now(),
                status: "active".into(),
                revoked_at: None,
            };
            let ca = wicket_store::NodeCaRow {
                serial: "ca1".into(),
                node: "n1".into(),
                issued_at: wicket_store::now(),
                not_after: wicket_store::now() + 3600,
                hosts: vec![],
                status: "active".into(),
            };
            l.enrol_node(&t, &row, &ca).unwrap();
            let (jws, cert) = issue(&l, &issuer, "n1", &key.verifying_key(), wicket_store::now(), 3600).unwrap();
            std::fs::write(dir.join(CERT_FILE), format!("{jws}\n")).unwrap();
            Install { issuer, ledger: Mutex::new(l), key, dir, cert }
        }

        /// What the node loads at `serve`.
        pub fn identity(&self) -> NodeIdentity {
            NodeIdentity { key: SigningKey::from_bytes(&self.key.to_bytes()), issuer: self.issuer.verifying_key() }
        }
    }

    impl Drop for Install {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::Install;
    use super::*;

    #[test]
    fn renewal_is_due_at_half_life_and_keeps_the_key_and_lifetime() {
        let i = Install::new("renew");
        let c = i.cert.clone();
        let l = i.ledger.lock().unwrap();
        assert!(renew_if_due(&l, &i.issuer, "n1", &c, c.iat + 1799).is_none());
        let (jws, n) = renew_if_due(&l, &i.issuer, "n1", &c, c.iat + 1800).unwrap().unwrap();
        assert_eq!((n.exp - n.iat, n.key().unwrap()), (3600, i.key.verifying_key()));
        assert_ne!(n.jti, c.jti);
        assert_eq!(l.node_cert(&n.jti).unwrap().unwrap().status, "active", "recorded");
        // The node takes it (and refuses one that isn't its own), atomically replacing the file.
        let id = i.identity();
        id.install_cert(&i.dir, &jws, "n1", n.iat).unwrap();
        assert_eq!(std::fs::read_to_string(i.dir.join(CERT_FILE)).unwrap().trim(), jws);
        let other = SigningKey::generate(&mut rand_core::OsRng);
        let (foreign_key, _) = i.issuer.issue_node_cert("n1", &other.verifying_key(), n.iat, 3600);
        assert!(id.install_cert(&i.dir, &foreign_key, "n1", n.iat).unwrap_err().to_string().contains("another key"));
        let (foreign_issuer, _) = Issuer::generate("test.wicket.example").issue_node_cert("n1", &i.key.verifying_key(), n.iat, 3600);
        assert!(id.install_cert(&i.dir, &foreign_issuer, "n1", n.iat).is_err());
        assert!(id.install_cert(&i.dir, &jws, "n1", n.exp).is_err(), "expired by the node's clock");
        assert_eq!(std::fs::read_to_string(i.dir.join(CERT_FILE)).unwrap().trim(), jws, "untouched by the refusals");
        // Not for a revoked node.
        drop(l);
        i.ledger.lock().unwrap().revoke_node("n1").unwrap();
        assert!(renew_if_due(&i.ledger.lock().unwrap(), &i.issuer, "n1", &c, c.exp).unwrap().is_err());
    }

    #[test]
    fn a_live_connection_stops_trusting_a_revoked_or_expired_node() {
        let i = Install::new("untrusted");
        let c = i.cert.clone();
        let now = c.iat + 10;
        assert_eq!(untrusted(&i.ledger.lock().unwrap(), "n1", Some(&c), now), None);
        let e = untrusted(&i.ledger.lock().unwrap(), "n1", Some(&c), c.exp).unwrap();
        assert!(e.contains("expired"), "{e}");
        // Revoked from another handle on the same ledger, as `wicket node revoke` does from its own process.
        i.ledger.lock().unwrap().revoke_node("n1").unwrap();
        let e = untrusted(&i.ledger.lock().unwrap(), "n1", Some(&c), now).unwrap();
        assert!(e.contains("revoked"), "{e}");
        assert!(untrusted(&i.ledger.lock().unwrap(), "n2", None, now).unwrap().contains("no longer enrolled"));
    }

    #[test]
    fn revocation_seen_through_another_ledger_connection() {
        // The file-backed case: the run's ledger handle sees a revocation made by another process.
        let i = Install::new("file");
        let path = i.dir.join("ledger.db");
        let mut a = Ledger::open(&path).unwrap();
        let t = a.create_node_token(&wicket_core::TenantId::single(), "n1", 600).unwrap();
        let row = i.ledger.lock().unwrap().node("n1").unwrap().unwrap();
        let ca = wicket_store::NodeCaRow {
            serial: "ca1".into(),
            node: "n1".into(),
            issued_at: 0,
            not_after: wicket_store::now() + 60,
            hosts: vec![],
            status: "active".into(),
        };
        a.enrol_node(&t, &row, &ca).unwrap();
        let (_, c) = issue(&a, &i.issuer, "n1", &i.key.verifying_key(), wicket_store::now(), 3600).unwrap();
        let run_side = Ledger::open(&path).unwrap();
        assert_eq!(untrusted(&run_side, "n1", Some(&c), c.iat), None);
        a.revoke_node("n1").unwrap();
        assert!(untrusted(&run_side, "n1", Some(&c), c.iat).unwrap().contains("revoked"));
    }

    #[test]
    fn node_keys_from_openssl_load_and_match_what_enrolment_parses() {
        if std::process::Command::new("openssl").arg("version").output().is_err() {
            eprintln!("openssl not found: skipping");
            return;
        }
        let i = Install::new("openssl");
        let out =
            std::process::Command::new("sh").arg("-c").arg(crate::enrol::keygen_script("n1", true)).env("HOME", &i.dir).output().unwrap();
        assert!(out.status.success());
        let g = crate::enrol::parse_generated(&String::from_utf8_lossy(&out.stdout), true).unwrap();
        let pem = std::fs::read_to_string(i.dir.join(crate::enrol::NODE_DIR).join("node.key.new")).unwrap();
        let k = wicket_identity::node::signing_key_from_pkcs8_pem(&pem).unwrap();
        assert_eq!(k.verifying_key().to_bytes(), g.node_key.unwrap().0);
    }
}
