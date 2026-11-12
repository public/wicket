//! Node enrolment (#16; step 2 of #57's plan): `wicket node token | enrol | list | revoke | renew-ca`.
//!
//! **Trust model (kept deliberately small).**
//! - The operator runs everything on the control host. Enrolment drives the node over ssh, using
//!   `openssl` there; afterwards `wicket node install` puts wicket itself on the node, to run
//!   `wicket node serve` (`nodesrv.rs`).
//! - **Join token.** `wicket node token` mints a one-time, short-lived token for an intended node name
//!   (the ledger keeps its hash). `enrol` checks it before any remote work and redeems it atomically
//!   with recording the node. It proves the person who minted it meant *this* name to join; it is not
//!   a credential the node holds, and it never leaves the control host.
//! - **Host key.** The node's ssh host key is pinned from `--host-key` (a key line, or a `SHA256:`
//!   fingerprint matched against what the node offers), taken from somewhere other than the network
//!   path: the provider's console or API, cloud-init output, or the image. Without one, `enrol`
//!   refuses unless `--trust-first-use` is given, and then prints the fingerprint it pinned. From then
//!   on every ssh call to the node uses a wicket-managed known_hosts file with
//!   `StrictHostKeyChecking=yes` (`Node::pinned`), so a node with any other key is refused.
//! - **Node key.** An Ed25519 key generated on the node; the private half never leaves it (mode 0600
//!   under `~/.local/share/wicket-node`). The control host records the public half.
//! - **Node identity certificate.** The issuer certifies the node key (`node-cert.jwt`, 24 h by
//!   default, `spiffe://<trust domain>/node/<name>`; `wicket_identity::node`), and the ledger records
//!   its serial. The node proves itself with it at the start of every control connection, and the
//!   control host proves the issuer key back (`nodeauth.rs`). It is renewed over the channel at
//!   half-life; `renew-ca` also issues a fresh one over ssh, for a node whose certificate expired
//!   while it was unreachable (or that was enrolled before certificates existed).
//! - **Node CA.** The node generates a P-256 key and a certificate signing request; the control host
//!   signs a short-lived (24 h by default) intermediate under wicket's installation CA, path length 0
//!   and **name-constrained** to `--hosts` (see `wicket_proxy::ca::permitted_dns_subtrees`). This is
//!   the one secret a dedicated node holds (design §8, #57): stolen, it can only mint certificates for
//!   the hosts that node's boxes could reach anyway, until it expires.
//! - **Feed and issuer keys.** The node gets the feed root's public key (created on the control host,
//!   next to the issuer key, on first use) and the issuer's public JWK, to verify the feed and agent
//!   identities offline.
//! - **Revocation** marks the node and its identity certificates revoked in the ledger, deletes its
//!   pinned key (so ssh refuses it) and records its CA serials for the feed's revocation list. Runs
//!   naming a revoked node are refused, and runs connected to it drop it within a second.

use crate::node::{Node, Pin};
use anyhow::{bail, Context, Result};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use wicket_core::TenantId;
use wicket_proxy::ca::{InstallationCa, NodeCaCert};
use wicket_store::{Ledger, NodeCaRow, NodeRow};

/// Where wicket keeps its files on a node, relative to the login's home directory.
pub const NODE_DIR: &str = ".local/share/wicket-node";

/// The control host's files for nodes.
pub struct Paths {
    /// `<data dir>/nodes/<name>/known_hosts`: each enrolled node's pinned host key.
    pub nodes_dir: PathBuf,
    /// The installation CA's key (its certificate is beside it, `.pem`).
    pub ca_key: PathBuf,
    /// The approval service's key: signs grant blocks. Tokens name it; nodes needn't know it.
    pub approver_key: PathBuf,
}

impl Paths {
    pub fn installation() -> Paths {
        let id = crate::issuer_key_path();
        Paths {
            nodes_dir: crate::data_dir().join("nodes"),
            ca_key: id.with_file_name("ca.key"),
            approver_key: id.with_file_name("approver.key"),
        }
    }
}

/// A token signing key (the authority root or the approver), created on first use like the feed
/// root (hex seed, mode 0600, public half in `<path>.pub`). Separate from the feed root, so feed
/// signing and authority can be rotated apart.
pub fn token_key(path: &std::path::Path) -> Result<wicket_authz::SigningKey> {
    let k = wicket_identity::load_or_create_feed_root_signing(path)?;
    Ok(wicket_authz::SigningKey::from_bytes(&k.to_bytes())?)
}

/// Node names: what ledgers, aliases, certificate subjects and directories are keyed by.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-');
    if !ok {
        bail!("{name:?} is not a node name: use 1-63 lowercase letters, digits and '-'");
    }
    if name == crate::localnode::NAME {
        bail!("{name:?} is this host's own built-in node: choose another name");
    }
    Ok(())
}

// ---- host keys ----

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// An ssh host public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKey {
    pub kind: String,
    pub b64: String,
}

impl HostKey {
    /// Parses `<type> <base64> [comment]`, or a known_hosts line `<host> <type> <base64>`. The blob
    /// must decode and name the same type.
    pub fn parse(s: &str) -> Result<HostKey> {
        let t: Vec<&str> = s.split_whitespace().collect();
        let i = t.iter().position(|w| KEY_TYPES.contains(w)).with_context(|| format!("no ssh public key in {s:?}"))?;
        let b64 = t.get(i + 1).with_context(|| format!("no key data after {}", t[i]))?;
        let blob = base64::engine::general_purpose::STANDARD.decode(b64).context("host key is not base64")?;
        let n = blob.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize).unwrap_or(usize::MAX);
        if blob.get(4..4usize.saturating_add(n)) != Some(t[i].as_bytes()) {
            bail!("host key data is not a {} key", t[i]);
        }
        Ok(HostKey { kind: t[i].to_string(), b64: b64.to_string() })
    }

    /// `SHA256:…`, as `ssh-keygen -l` and ssh's own prompts print it.
    pub fn fingerprint(&self) -> String {
        let blob = base64::engine::general_purpose::STANDARD.decode(&self.b64).unwrap_or_default();
        format!("SHA256:{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(blob)))
    }

    pub fn line(&self) -> String {
        format!("{} {}", self.kind, self.b64)
    }
}

/// What the operator said the node's host key is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeySpec {
    Key(HostKey),
    Fingerprint(String),
}

impl HostKeySpec {
    pub fn parse(s: &str) -> Result<HostKeySpec> {
        let s = s.trim();
        match s.strip_prefix("SHA256:") {
            Some(fp) if !fp.is_empty() => Ok(HostKeySpec::Fingerprint(format!("SHA256:{}", fp.trim_end_matches('=')))),
            Some(_) => bail!("empty fingerprint"),
            None => Ok(HostKeySpec::Key(HostKey::parse(s)?)),
        }
    }
}

/// Picks the key to pin from the keys the node offered (`scanned`, possibly over an untrusted path).
pub fn choose_host_key(scanned: &[HostKey], spec: Option<&HostKeySpec>, trust_first_use: bool) -> Result<HostKey> {
    match spec {
        Some(HostKeySpec::Key(k)) => Ok(k.clone()),
        Some(HostKeySpec::Fingerprint(fp)) => match scanned.iter().find(|k| &k.fingerprint() == fp) {
            Some(k) => Ok(k.clone()),
            None => bail!(
                "the node offered no host key with fingerprint {fp} (it offered: {}): refusing to enrol it",
                if scanned.is_empty() {
                    "none".to_string()
                } else {
                    scanned.iter().map(|k| k.fingerprint()).collect::<Vec<_>>().join(", ")
                }
            ),
        },
        None if trust_first_use => {
            scanned.iter().find(|k| k.kind == "ssh-ed25519").or_else(|| scanned.first()).cloned().context("the node offered no host key")
        }
        None => bail!(
            "no host key to pin: pass --host-key with the node's key or its SHA256 fingerprint (from the provider's console, \
             cloud-init output or /etc/ssh/ssh_host_ed25519_key.pub), or --trust-first-use to accept what the network delivers"
        ),
    }
}

/// The keys `target` offers, fetched with ssh-keyscan from the host and port ssh would use for it.
async fn scan(target: &str) -> Result<Vec<HostKey>> {
    let g = tokio::process::Command::new("ssh").arg("-G").arg(target).output().await.context("ssh -G")?;
    if !g.status.success() {
        bail!("ssh -G {target}: {}", String::from_utf8_lossy(&g.stderr).trim());
    }
    let cfg = String::from_utf8_lossy(&g.stdout);
    let get = |k: &str| cfg.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string()));
    let host = get("hostname ").context("ssh -G printed no hostname")?;
    let port = get("port ").unwrap_or_else(|| "22".into());
    let out = tokio::process::Command::new("ssh-keyscan")
        .args(["-T", "10", "-p", &port, "-t", "ed25519,ecdsa,rsa", "--", &host])
        .output()
        .await
        .context("ssh-keyscan")?;
    Ok(String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.starts_with('#')).filter_map(|l| HostKey::parse(l).ok()).collect())
}

/// Writes the node's pinned key: a known_hosts file holding only it, under the alias.
pub fn write_pin(pin: &Pin, key: &HostKey) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = pin.known_hosts.parent().context("pin path")?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&pin.known_hosts)?;
    std::io::Write::write_all(&mut f, format!("{} {}\n", pin.alias, key.line()).as_bytes())?;
    Ok(())
}

// ---- what runs on the node ----

/// A shell script, run on the node, that makes the new keys (as `*.new`, private, never printed) and
/// prints the node key's public half (if `node_key`) and a CSR for the node CA key.
pub fn keygen_script(name: &str, node_key: bool) -> String {
    let mut s = format!(
        "set -eu\numask 077\nd=\"$HOME/{NODE_DIR}\"\nmkdir -p \"$d\"\ncd \"$d\"\n\
         command -v openssl >/dev/null || {{ echo 'openssl is not installed on the node' >&2; exit 1; }}\n\
         rm -f node.key.new ca.key.new\n"
    );
    if node_key {
        s += "openssl genpkey -algorithm ed25519 -out node.key.new\nopenssl pkey -in node.key.new -pubout\n";
    }
    s += &format!(
        "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key.new\n\
         openssl req -new -key ca.key.new -subj '/O=wicket/CN=wicket node CA {name}'\n"
    );
    s
}

/// What `keygen_script` printed.
#[derive(Debug)]
pub struct Generated {
    /// The node's Ed25519 public key, and its PEM.
    pub node_key: Option<([u8; 32], String)>,
    pub csr_pem: String,
}

fn pem_block<'a>(out: &'a str, label: &str) -> Option<&'a str> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let i = out.find(&begin)?;
    let j = out[i..].find(&end)? + i + end.len();
    Some(&out[i..j])
}

pub fn parse_generated(out: &str, node_key: bool) -> Result<Generated> {
    let csr_pem = pem_block(out, "CERTIFICATE REQUEST").context("the node printed no certificate signing request")?.to_string() + "\n";
    let node_key = match node_key {
        false => None,
        true => {
            let pem = pem_block(out, "PUBLIC KEY").context("the node printed no public key")?;
            let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = base64::engine::general_purpose::STANDARD.decode(body.trim()).context("node public key")?;
            // SubjectPublicKeyInfo for Ed25519 (RFC 8410): a fixed 12-byte prefix, then the key.
            const PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
            if der.len() != 44 || der[..12] != PREFIX {
                bail!("the node key is not an Ed25519 public key");
            }
            Some((der[12..].try_into().expect("32 bytes"), format!("{pem}\n")))
        }
    };
    Ok(Generated { node_key, csr_pem })
}

const EOF_MARK: &str = "WICKET_NODE_FILE_EOF";

/// A shell script, run on the node, that writes `files` and then moves the new keys and files into
/// place together.
pub fn install_script(files: &[(&str, String)], node_key: bool) -> Result<String> {
    let mut s = format!("set -eu\numask 077\ncd \"$HOME/{NODE_DIR}\"\n");
    let mut moves = vec!["ca.key"];
    if node_key {
        moves.push("node.key");
    }
    for (name, body) in files {
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') || body.lines().any(|l| l == EOF_MARK) {
            bail!("refusing to write {name:?}");
        }
        let nl = if body.ends_with('\n') { "" } else { "\n" };
        s += &format!("cat > {name}.new <<'{EOF_MARK}'\n{body}{nl}{EOF_MARK}\n");
        moves.push(name);
    }
    for m in moves {
        s += &format!("mv -f {m}.new {m}\n");
    }
    Ok(s)
}

/// The public files a node gets.
fn node_files(
    ca: &InstallationCa,
    cert: &NodeCaCert,
    feed_root: &wicket_identity::VerifyingKey,
    authz_root: &wicket_authz::PublicKey,
    info: serde_json::Value,
    node_pub: Option<&str>,
    node_cert: &str,
) -> Result<Vec<(&'static str, String)>> {
    let issuer = crate::issuer()?;
    let mut f = vec![
        (crate::nodeauth::CERT_FILE, format!("{node_cert}\n")),
        ("ca.pem", cert.pem.clone()),
        ("ca-chain.pem", format!("{}{}", cert.pem, ca.cert_pem())),
        ("root.pem", ca.cert_pem().to_string()),
        ("feed-root.pub", hex::encode(feed_root.to_bytes())),
        ("authz-root.pub", authz_root.to_hex()),
        ("issuer.pub.json", serde_json::to_string_pretty(&issuer.public_jwk())?),
        ("node.json", serde_json::to_string_pretty(&info)?),
    ];
    if let Some(p) = node_pub {
        f.push(("node.pub", p.to_string()));
    }
    Ok(f)
}

fn ca_row(name: &str, cert: &NodeCaCert) -> NodeCaRow {
    NodeCaRow {
        serial: cert.serial.clone(),
        node: name.into(),
        issued_at: wicket_store::now(),
        not_after: cert.not_after,
        hosts: cert.permitted.clone(),
        status: "active".into(),
    }
}

fn to_time(d: Duration) -> Result<time::Duration> {
    let d = time::Duration::try_from(d).context("duration")?;
    if d < time::Duration::minutes(5) || d > time::Duration::days(30) {
        bail!("node CA lifetime must be between 5 minutes and 30 days");
    }
    Ok(d)
}

// ---- commands ----

pub fn token(name: Option<String>, ttl: Duration) -> Result<()> {
    let name = match name {
        Some(n) => n,
        None => {
            let mut b = [0u8; 3];
            getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("random: {e}"))?;
            format!("node-{}", hex::encode(b))
        }
    };
    validate_name(&name)?;
    let l = Ledger::open(&crate::ledger_path())?;
    let t = l.create_node_token(&TenantId::single(), &name, ttl.as_secs() as i64)?;
    l.audit(&TenantId::single(), None, "node.token", &serde_json::json!({ "name": name, "ttl_secs": ttl.as_secs() }))?;
    println!("{t}");
    eprintln!(
        "one-time join token for node {name}, valid for {}: wicket node enrol <ssh-target> --token <token> --hosts …",
        humantime::format_duration(ttl)
    );
    Ok(())
}

pub struct EnrolOpts {
    pub target: String,
    pub token: String,
    pub name: Option<String>,
    pub ssh_key: Option<PathBuf>,
    pub host_key: Option<String>,
    pub trust_first_use: bool,
    pub hosts: Vec<String>,
    pub ca_ttl: Duration,
    pub cert_ttl: Duration,
}

pub async fn enrol(o: EnrolOpts) -> Result<()> {
    let paths = Paths::installation();
    let ttl = to_time(o.ca_ttl)?;
    let cert_ttl = crate::nodeauth::cert_ttl(o.cert_ttl)?;
    wicket_proxy::ca::permitted_dns_subtrees(&o.hosts)?;
    let spec = o.host_key.as_deref().map(HostKeySpec::parse).transpose()?;
    let mut ledger = Ledger::open(&crate::ledger_path())?;
    let name = ledger.check_node_token(&o.token, wicket_store::now())?;
    if let Some(n) = &o.name {
        if n != &name {
            bail!("this token is for node {name}, not {n}");
        }
    }
    validate_name(&name)?;
    if ledger.node(&name)?.is_some_and(|n| n.status != "revoked") {
        bail!("node {name} is already enrolled (wicket node revoke {name} first, or renew its CA with wicket node renew-ca)");
    }
    // Everything the control host needs, before touching the node.
    let ca = InstallationCa::load_or_create(&paths.ca_key)?;
    let feed_root = crate::roots::feed_root_public()?;
    let authz_root = crate::roots::authz_root_public()?;
    let issuer = crate::issuer()?;

    let scanned = match &spec {
        Some(HostKeySpec::Key(_)) => vec![],
        _ => scan(&o.target).await?,
    };
    let key = choose_host_key(&scanned, spec.as_ref(), o.trust_first_use)?;
    let pin = Pin::for_node(&paths.nodes_dir, &name);
    write_pin(&pin, &key)?;
    let pin_dir = paths.nodes_dir.join(&name);
    // Until the ledger records the node, a failure leaves no pin behind.
    let forget = || {
        let _ = std::fs::remove_dir_all(&pin_dir);
    };
    if spec.is_none() {
        println!("pinned host key {} {} (trust on first use: check it against the node's console)", key.kind, key.fingerprint());
    }
    let node = Node::pinned(&o.target, o.ssh_key.as_deref(), &pin, &name);
    let generated = match node
        .script("generating the node key and CA key", &keygen_script(&name, true))
        .await
        .and_then(|out| parse_generated(&out, true))
    {
        Ok(g) => g,
        Err(e) => {
            forget();
            return Err(e.context(format!("generating keys on {}", o.target)));
        }
    };
    let (node_key, node_pub_pem) = generated.node_key.clone().expect("asked for a node key");
    let cert = match ca.issue_node_ca(&generated.csr_pem, &name, &o.hosts, ttl) {
        Ok(c) => c,
        Err(e) => {
            forget();
            return Err(e);
        }
    };
    let now = wicket_store::now();
    let row = NodeRow {
        name: name.clone(),
        tenant: TenantId::single().0,
        target: o.target.clone(),
        host_key: key.line(),
        host_key_fp: key.fingerprint(),
        node_key: hex::encode(node_key),
        ssh_key: o.ssh_key.as_ref().map(|k| k.display().to_string()),
        hosts: cert.permitted.clone(),
        enrolled_at: now,
        status: "active".into(),
        revoked_at: None,
    };
    if let Err(e) = ledger.enrol_node(&o.token, &row, &ca_row(&name, &cert)) {
        forget();
        return Err(e.into());
    }
    let vk = crate::nodeauth::enrolled_key(&row.node_key)?;
    let (node_cert, nc) = crate::nodeauth::issue(&ledger, &issuer, &name, &vk, now, cert_ttl)?;
    ledger.audit(
        &TenantId::single(),
        None,
        "node.enrolled",
        &serde_json::json!({
            "name": name, "target": o.target, "host_key_fp": row.host_key_fp, "trust_first_use": spec.is_none(),
            "node_key": row.node_key, "ca_serial": cert.serial, "ca_not_after": cert.not_after, "hosts": cert.permitted,
            "identity": nc.sub, "cert_serial": nc.jti, "cert_not_after": nc.exp,
        }),
    )?;
    let info = serde_json::json!({ "name": name, "node_key": row.node_key, "hosts": cert.permitted, "ca_serial": cert.serial,
                                   "ca_not_after": cert.not_after, "enrolled_at": now });
    let script = install_script(&node_files(&ca, &cert, &feed_root, &authz_root, info, Some(&node_pub_pem), &node_cert)?, true)?;
    node.script("installing the node files", &script).await.with_context(|| {
        format!("node {name} is recorded and its CA (serial {}) issued, but installing it on the node failed: fix that and run `wicket node renew-ca {name}`, or `wicket node revoke {name}`", cert.serial)
    })?;
    println!(
        "enrolled node {name} ({}): host key {} pinned, node key {}, identity {} until {}, CA serial {} for {} until {}",
        o.target,
        row.host_key_fp,
        &row.node_key[..16],
        nc.sub,
        fmt_time(nc.exp),
        cert.serial,
        cert.permitted.join(", "),
        fmt_time(cert.not_after)
    );
    Ok(())
}

pub async fn renew_ca(name: &str, hosts: Vec<String>, ca_ttl: Duration, cert_ttl: Duration) -> Result<()> {
    let paths = Paths::installation();
    let ttl = to_time(ca_ttl)?;
    let cert_ttl = crate::nodeauth::cert_ttl(cert_ttl)?;
    let mut ledger = Ledger::open(&crate::ledger_path())?;
    let row = ledger.node(name)?.with_context(|| format!("node {name} is not enrolled"))?;
    if row.status != "active" {
        bail!("node {name} is {}", row.status);
    }
    // Default: the hosts it was constrained to (stored as subtrees; turn `.d` back into `*.d`).
    let hosts = if hosts.is_empty() {
        row.hosts.iter().map(|h| h.strip_prefix('.').map(|d| format!("*.{d}")).unwrap_or_else(|| h.clone())).collect()
    } else {
        hosts
    };
    let ca = InstallationCa::load_or_create(&paths.ca_key)?;
    let feed_root = crate::roots::feed_root_public()?;
    let authz_root = crate::roots::authz_root_public()?;
    let node = pinned_node(&paths.nodes_dir, &row, None)?;
    let generated = parse_generated(&node.script("generating a new CA key", &keygen_script(name, false)).await?, false)?;
    let cert = ca.issue_node_ca(&generated.csr_pem, name, &hosts, ttl)?;
    ledger.renew_node_ca(&ca_row(name, &cert))?;
    let vk = crate::nodeauth::enrolled_key(&row.node_key)?;
    let (node_cert, nc) = crate::nodeauth::issue(&ledger, &crate::issuer()?, name, &vk, wicket_store::now(), cert_ttl)?;
    ledger.audit(
        &TenantId::single(),
        None,
        "node.ca_renewed",
        &serde_json::json!({ "name": name, "ca_serial": cert.serial, "ca_not_after": cert.not_after, "hosts": cert.permitted,
                             "cert_serial": nc.jti, "cert_not_after": nc.exp }),
    )?;
    let info = serde_json::json!({ "name": name, "node_key": row.node_key, "hosts": cert.permitted, "ca_serial": cert.serial,
                                   "ca_not_after": cert.not_after, "enrolled_at": row.enrolled_at });
    node.script(
        "installing the node files",
        &install_script(&node_files(&ca, &cert, &feed_root, &authz_root, info, None, &node_cert)?, false)?,
    )
    .await
    .with_context(|| {
        format!(
            "CA serial {} is recorded for node {name}, but installing it failed (the node keeps its old CA): run renew-ca again",
            cert.serial
        )
    })?;
    println!(
        "renewed node {name}'s CA: serial {} for {} until {}; identity certificate until {}",
        cert.serial,
        cert.permitted.join(", "),
        fmt_time(cert.not_after),
        fmt_time(nc.exp)
    );
    Ok(())
}

/// The systemd user unit `wicket node install` writes. Lingering (`loginctl enable-linger`, done by
/// `deploy/vultr/node-setup.sh`) keeps it running without a login session.
pub const NODE_UNIT: &str = "[Unit]
Description=wicket node: runs this node's boxes and decides their egress locally
After=docker.service

[Service]
ExecStart=%h/.local/bin/wicket node serve
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
";

/// `wicket node install <name>`: copies this control host's current wicket binary to the node over
/// the pinned ssh connection (as a version: see `update.rs`), checks its sha256 there, and (unless `no_service`)
/// installs and restarts the `wicket-node` systemd user service that runs `wicket node serve`. The
/// node's `serve` refuses a control host more than one protocol version away (`chan.rs`); `wicket self
/// update --nodes` keeps nodes current.
pub async fn install(name: &str, ssh_key: Option<&Path>, no_service: bool) -> Result<()> {
    use sha2::Digest;
    let ledger = Ledger::open(&crate::ledger_path())?;
    let row = ledger.node(name)?.with_context(|| format!("node {name} is not enrolled"))?;
    if row.status != "active" {
        bail!("node {name} is {}", row.status);
    }
    let node = pinned_node(&Paths::installation().nodes_dir, &row, ssh_key)?;
    let arch = node.sh("uname -m").await?;
    if arch != std::env::consts::ARCH {
        bail!("node {name} is {arch}, this control host's wicket is {}: install a {arch} build there yourself", std::env::consts::ARCH);
    }
    // The control host's current version, staged on the node as a version of its own
    // (`<node dir>/versions/<id>/wicket`, `~/.local/bin/wicket` a link to its `current`).
    let exe = crate::update::self_exe()?;
    let bytes = std::fs::read(&exe)?;
    let sha = hex::encode(Sha256::digest(&bytes));
    let prev = crate::update::push_version(&node, &bytes, &sha).await?;
    println!(
        "installed wicket on node {name} ({} MB, version {}{}, sha256 {}…)",
        bytes.len() >> 20,
        &sha[..12],
        prev.filter(|p| p.as_str() != &sha[..12]).map(|p| format!(", was {p}")).unwrap_or_default(),
        &sha[..16]
    );
    if no_service {
        println!("no service installed: run `~/.local/bin/wicket node serve` on the node yourself");
        return Ok(());
    }
    let home = node.sh("echo $HOME").await?;
    let unit_dir = format!("{home}/.config/systemd/user");
    let script = format!(
        "set -eu\nexport XDG_RUNTIME_DIR=/run/user/$(id -u)\nmkdir -p {d}\ncat > {d}/wicket-node.service <<'WICKET_UNIT_EOF'\n{NODE_UNIT}WICKET_UNIT_EOF\n\
         systemctl --user daemon-reload\nsystemctl --user enable wicket-node >/dev/null 2>&1\nsystemctl --user restart wicket-node\n\
         sleep 1\nsystemctl --user is-active wicket-node\n",
        d = wicket_sandbox::shell_quote(&unit_dir)
    );
    let state = node.script("installing the wicket-node service (is lingering enabled for this user?)", &script).await?;
    println!("wicket-node service on {name}: {state}");
    Ok(())
}

/// Revokes a node: the ledger marks it (and its CA certificates) revoked, and its pinned host key is
/// deleted, so ssh to it fails host key verification. Returns the revoked CA serials.
pub fn revoke(ledger: &mut Ledger, nodes_dir: &Path, name: &str) -> Result<Vec<String>> {
    let serials = ledger.revoke_node(name)?;
    let pin = Pin::for_node(nodes_dir, name);
    match std::fs::remove_file(&pin.known_hosts) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("removing the pinned host key"),
    }
    ledger.audit(&TenantId::single(), None, "node.revoked", &serde_json::json!({ "name": name, "ca_serials": serials }))?;
    Ok(serials)
}

pub fn list() -> Result<()> {
    let l = Ledger::open(&crate::ledger_path())?;
    let nodes = l.nodes()?;
    if nodes.is_empty() {
        println!("no enrolled nodes (wicket node token, then wicket node enrol)");
    }
    for n in nodes {
        let ca = l.node_cas(&n.name)?.into_iter().find(|c| c.status == "active");
        let ca = match ca {
            Some(c) if c.not_after > wicket_store::now() => {
                format!("CA {} until {}", &c.serial[..12.min(c.serial.len())], fmt_time(c.not_after))
            }
            Some(c) => {
                format!("CA {} EXPIRED {} (wicket node renew-ca {})", &c.serial[..12.min(c.serial.len())], fmt_time(c.not_after), n.name)
            }
            None => "no CA".into(),
        };
        let now = wicket_store::now();
        let id = match l.node_certs(&n.name)?.into_iter().find(|c| c.status == "active") {
            Some(c) if c.not_after > now => format!("identity until {}", fmt_time(c.not_after)),
            Some(c) => format!("identity EXPIRED {} (wicket node renew-ca {})", fmt_time(c.not_after), n.name),
            None if n.status == "active" => format!("no identity certificate (wicket node renew-ca {})", n.name),
            None => "no identity certificate".into(),
        };
        println!("{}  {}  {}  host key {}  hosts {}  {}  {}", n.name, n.status, n.target, n.host_key_fp, n.hosts.join(","), ca, id);
    }
    Ok(())
}

fn pinned_node(nodes_dir: &Path, row: &NodeRow, ssh_key: Option<&Path>) -> Result<Node> {
    let pin = Pin::for_node(nodes_dir, &row.name);
    if !pin.known_hosts.exists() {
        bail!("node {} is enrolled but its pinned host key ({}) is missing: refusing to connect", row.name, pin.known_hosts.display());
    }
    let key = ssh_key.map(Path::to_path_buf).or_else(|| row.ssh_key.as_ref().map(PathBuf::from));
    Ok(Node::pinned(&row.target, key.as_deref(), &pin, &row.name))
}

/// The node for `--node <arg>`: an enrolled node by name or ssh target, with its host key pinned. A
/// revoked node is refused, and so is the built-in local node (it has no ssh). Anything else is an
/// unenrolled target, reached by trust on first use with a warning (only enrolment uses that).
pub fn resolve(ledger: &Ledger, nodes_dir: &Path, arg: &str, ssh_key: Option<&Path>) -> Result<Node> {
    let row = match ledger.node(arg)? {
        Some(r) => Some(r),
        None => ledger.node_by_target(arg)?,
    };
    match row {
        Some(r) if r.target.starts_with("unix:") => {
            bail!("{} is this host's own built-in node: wicket reaches it itself (run without --node)", r.name)
        }
        Some(r) if r.status == "active" => pinned_node(nodes_dir, &r, ssh_key),
        Some(r) => bail!("node {} ({}) is {}: refusing to use it", r.name, r.target, r.status),
        None => {
            eprintln!(
                "[wicket] warning: {arg} is not an enrolled node, so its ssh host key is not pinned (trusted on first use). \
                 Enrol it: wicket node token --name <name>, then wicket node enrol {arg} --token … --host-key …"
            );
            Ok(Node::new(arg, ssh_key))
        }
    }
}

/// `resolve` against this installation's ledger.
pub fn resolve_installed(arg: &str, ssh_key: Option<&Path>) -> Result<Node> {
    let l = Ledger::open(&crate::ledger_path())?;
    resolve(&l, &Paths::installation().nodes_dir, arg, ssh_key)
}

fn fmt_time(t: i64) -> String {
    humantime::format_rfc3339_seconds(std::time::UNIX_EPOCH + Duration::from_secs(t.max(0) as u64)).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway key made for this test, and its fingerprint as `ssh-keygen -lf` printed it.
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEggj6FyU//JJDZKykzPImKRPFveTcOK9nWc/L0oCx+k";
    const FP: &str = "SHA256:pYdl51baaCJaZ0bIjf3261Vm2L+uckq/QqvzTRuPpbo";

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-enrol-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn host_keys_parse_from_key_lines_and_known_hosts_lines_and_fingerprint_like_ssh_keygen() {
        let k = HostKey::parse(KEY).unwrap();
        assert_eq!(k.fingerprint(), FP);
        assert_eq!(HostKey::parse(&format!("{KEY} root@node")).unwrap(), k);
        assert_eq!(HostKey::parse(&format!("203.0.113.7 {KEY}")).unwrap(), k);
        assert!(HostKey::parse("ssh-ed25519 notbase64!").is_err());
        assert!(HostKey::parse("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIEggj6FyU//JJDZKykzPImKRPFveTcOK9nWc/L0oCx+k").is_err(), "type mismatch");
        assert!(HostKey::parse("hello").is_err());
        assert_eq!(HostKeySpec::parse(&format!("{FP}=")).unwrap(), HostKeySpec::Fingerprint(FP.into()));
        assert_eq!(HostKeySpec::parse(KEY).unwrap(), HostKeySpec::Key(k));
    }

    #[test]
    fn the_pinned_key_comes_from_the_operator_not_the_network() {
        let good = HostKey::parse(KEY).unwrap();
        let other =
            HostKey { kind: "ssh-ed25519".into(), b64: "AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into() };
        // A key given outright is pinned as given, whatever the network says.
        assert_eq!(choose_host_key(std::slice::from_ref(&other), Some(&HostKeySpec::Key(good.clone())), false).unwrap(), good);
        // A fingerprint must match one of the offered keys.
        let fp = HostKeySpec::Fingerprint(FP.into());
        assert_eq!(choose_host_key(&[other.clone(), good.clone()], Some(&fp), false).unwrap(), good);
        let e = choose_host_key(std::slice::from_ref(&other), Some(&fp), true).unwrap_err().to_string();
        assert!(e.contains("refusing"), "{e}");
        // Nothing given: refused, unless trust on first use is asked for (ed25519 preferred).
        assert!(choose_host_key(std::slice::from_ref(&good), None, false).is_err());
        let rsa = HostKey { kind: "ssh-rsa".into(), b64: "x".into() };
        assert_eq!(choose_host_key(&[rsa, good.clone()], None, true).unwrap(), good);
        assert!(choose_host_key(&[], None, true).is_err());
    }

    #[test]
    fn enrolled_nodes_are_reached_with_strict_host_key_checking_and_only_the_pinned_file() {
        let pin = Pin::for_node(Path::new("/var/lib/wicket test/nodes"), "n1");
        let p = Node::pinned("wicket@203.0.113.7", None, &pin, "n1").ssh_prefix();
        let opts: Vec<&str> = p.windows(2).filter(|w| w[0] == "-o").map(|w| w[1].as_str()).collect();
        for want in [
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=\"/var/lib/wicket test/nodes/n1/known_hosts\"",
            "GlobalKnownHostsFile=/dev/null",
            "HostKeyAlias=wicket-node-n1",
            "UpdateHostKeys=no",
        ] {
            assert!(opts.contains(&want), "{want} missing from {opts:?}");
        }
        assert!(!opts.iter().any(|o| o.contains("accept-new")));
        assert_eq!(p.last().unwrap(), "wicket@203.0.113.7");
        let tofu = Node::new("wicket@203.0.113.7", None).ssh_prefix();
        assert!(tofu.iter().any(|o| o == "StrictHostKeyChecking=accept-new"));
    }

    fn enrol_row(l: &mut Ledger, nodes: &Path, name: &str) {
        let t = l.create_node_token(&TenantId::single(), name, 600).unwrap();
        let key = HostKey::parse(KEY).unwrap();
        write_pin(&Pin::for_node(nodes, name), &key).unwrap();
        let row = NodeRow {
            name: name.into(),
            tenant: TenantId::single().0,
            target: format!("wicket@{name}.example.com"),
            host_key: key.line(),
            host_key_fp: key.fingerprint(),
            node_key: "00".repeat(32),
            ssh_key: None,
            hosts: vec!["api.example.com".into()],
            enrolled_at: wicket_store::now(),
            status: "active".into(),
            revoked_at: None,
        };
        let ca = NodeCaRow {
            serial: format!("{name}-serial"),
            node: name.into(),
            issued_at: wicket_store::now(),
            not_after: wicket_store::now() + 3600,
            hosts: row.hosts.clone(),
            status: "active".into(),
        };
        l.enrol_node(&t, &row, &ca).unwrap();
    }

    #[test]
    fn runs_resolve_enrolled_nodes_pinned_and_refuse_revoked_ones() {
        let dir = tmp("resolve");
        let mut l = Ledger::open_in_memory().unwrap();
        enrol_row(&mut l, &dir, "n1");
        let pin = Pin::for_node(&dir, "n1");
        assert_eq!(std::fs::read_to_string(&pin.known_hosts).unwrap(), format!("wicket-node-n1 {KEY}\n"));
        for arg in ["n1", "wicket@n1.example.com"] {
            let n = resolve(&l, &dir, arg, None).unwrap();
            assert_eq!(n.name.as_deref(), Some("n1"));
            assert!(n.ssh_prefix().iter().any(|o| o == "StrictHostKeyChecking=yes"));
            assert_eq!(n.target, "wicket@n1.example.com");
        }
        let n = resolve(&l, &dir, "wicket@203.0.113.9", None).unwrap();
        assert!(n.name.is_none() && n.ssh_prefix().iter().any(|o| o == "StrictHostKeyChecking=accept-new"), "unenrolled: as before");

        let serials = revoke(&mut l, &dir, "n1").unwrap();
        assert_eq!(serials, vec!["n1-serial"]);
        assert!(!pin.known_hosts.exists(), "the pinned key is gone, so ssh refuses the host");
        for arg in ["n1", "wicket@n1.example.com"] {
            let e = resolve(&l, &dir, arg, None).err().expect("revoked").to_string();
            assert!(e.contains("revoked"), "{e}");
        }
        assert_eq!(l.revoked_node_cas(wicket_store::now()).unwrap()[0].serial, "n1-serial");
        assert!(revoke(&mut l, &dir, "n1").is_err());
        // An enrolled node whose pin file has gone missing is refused, not silently trusted.
        enrol_row(&mut l, &dir, "n2");
        std::fs::remove_file(Pin::for_node(&dir, "n2").known_hosts).unwrap();
        assert!(resolve(&l, &dir, "n2", None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_names_are_safe_everywhere_they_are_used() {
        for ok in ["n1", "gpu-node-3"] {
            validate_name(ok).unwrap();
        }
        for bad in ["", "N1", "-x", "a/b", "a b", "a.b", "x'y", &"a".repeat(64)] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    fn sh(home: &Path, script: &str) -> String {
        let out = std::process::Command::new("sh").arg("-c").arg(script).env("HOME", home).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// The node-side scripts, run locally against a fake home: keys made "on the node", a CSR the
    /// installation CA signs, and the files moved into place privately.
    #[test]
    fn the_node_scripts_make_private_keys_and_a_csr_the_control_host_signs() {
        use std::os::unix::fs::PermissionsExt;
        if std::process::Command::new("openssl").arg("version").output().is_err() {
            eprintln!("openssl not found: skipping");
            return;
        }
        let home = tmp("node-home");
        let g = parse_generated(&sh(&home, &keygen_script("n1", true)), true).unwrap();
        let d = home.join(NODE_DIR);
        for f in ["node.key.new", "ca.key.new"] {
            assert_eq!(std::fs::metadata(d.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
        }
        let root = InstallationCa::generate().unwrap();
        let cert = root.issue_node_ca(&g.csr_pem, "n1", &["api.example.com".into()], time::Duration::hours(24)).unwrap();
        let feed = wicket_identity::Issuer::generate("wicket.example.com").verifying_key();
        let files = vec![
            ("ca.pem", cert.pem.clone()),
            ("root.pem", root.cert_pem().to_string()),
            ("feed-root.pub", hex::encode(feed.to_bytes())),
            ("node.pub", g.node_key.as_ref().unwrap().1.clone()),
        ];
        sh(&home, &install_script(&files, true).unwrap());
        for f in ["node.key", "ca.key", "ca.pem", "root.pem", "feed-root.pub", "node.pub"] {
            assert_eq!(std::fs::metadata(d.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
        }
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(!d.join("ca.key.new").exists() && !d.join("node.key.new").exists());
        // The installed certificate is for the key that stayed on the node, and chains to the root.
        let check =
            std::process::Command::new("openssl").current_dir(&d).args(["verify", "-CAfile", "root.pem", "ca.pem"]).output().unwrap();
        assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stdout));
        let pubkey = |args: &[&str]| std::process::Command::new("openssl").current_dir(&d).args(args).output().unwrap().stdout;
        assert_eq!(pubkey(&["x509", "-in", "ca.pem", "-noout", "-pubkey"]), pubkey(&["pkey", "-in", "ca.key", "-pubout"]));
        // The node key printed is the one kept.
        assert_eq!(String::from_utf8(pubkey(&["pkey", "-in", "node.key", "-pubout"])).unwrap(), g.node_key.unwrap().1);
        // Renewal: a new CA key and CSR, the node key untouched.
        let before = std::fs::read(d.join("node.key")).unwrap();
        let g2 = parse_generated(&sh(&home, &keygen_script("n1", false)), false).unwrap();
        assert!(g2.node_key.is_none());
        let cert2 = root.issue_node_ca(&g2.csr_pem, "n1", &["api.example.com".into()], time::Duration::hours(24)).unwrap();
        sh(&home, &install_script(&[("ca.pem", cert2.pem.clone())], false).unwrap());
        assert_eq!(std::fs::read(d.join("node.key")).unwrap(), before);
        assert_eq!(pubkey(&["x509", "-in", "ca.pem", "-noout", "-pubkey"]), pubkey(&["pkey", "-in", "ca.key", "-pubout"]));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn install_scripts_refuse_odd_file_names_and_heredoc_breakouts() {
        assert!(install_script(&[("../x", "a".into())], false).is_err());
        assert!(install_script(&[("ca.pem", format!("a\n{EOF_MARK}\nrm -rf /\n"))], false).is_err());
    }
}
