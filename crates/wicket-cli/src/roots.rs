//! The installation's roots, offline (#154): the feed root (certifies each node feed's key) and
//! the authority root (mints block 0 of every box's token) can leave the control host.
//!
//! - **`wicket keys roots-offline --to DIR`** makes an online authority *issuing* key with a
//!   certificate from the authority root, re-certifies every node feed's key for `--days`, copies
//!   both roots' private keys to DIR (removable media, say), checks the copies, and removes them
//!   here. `<identity dir>/roots-offline` records it. Nodes pin the same public keys as before.
//! - **While they are offline** boxes' tokens are minted by the issuing key and carry its
//!   certificate (`BoxAuthority::issuer_cert`), which nodes check against the authority root.
//!   Nothing makes a root again: anything that needs one (enrolling a node, a feed's new
//!   generation, a certificate past its end) fails with a message naming `WICKET_ROOTS`.
//! - **`WICKET_ROOTS=DIR wicket keys certify`** renews the issuing key's certificate and every node
//!   feed's for another `--days`, and starts the new generation of any feed that needs one (after a
//!   restore). `WICKET_ROOTS=DIR` works for any other command too.
//! - **`wicket keys roots-online --from DIR`** puts them back.

use crate::data_dir;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use wicket_feed::KeyCert;

const MARKER: &str = "roots-offline";
pub const FEED_ROOT: &str = "feed-root.key";
pub const AUTHZ_ROOT: &str = "authz-root.key";
const ISSUING_KEY: &str = "authz-issuing.key";
const ISSUING_CERT: &str = "authz-issuing.cert";

pub fn identity_dir() -> PathBuf {
    crate::issuer_key_path().parent().expect("the identity dir").to_path_buf()
}

/// What `roots-offline` recorded.
#[derive(serde::Serialize, serde::Deserialize)]
struct Offline {
    at: i64,
    /// How long certificates issued with the roots last.
    days: i64,
}

fn marker() -> Option<Offline> {
    serde_json::from_slice(&std::fs::read(identity_dir().join(MARKER)).ok()?).ok()
}

/// Whether the roots were moved off this host.
pub fn offline() -> bool {
    identity_dir().join(MARKER).exists()
}

/// Where the roots' private keys are read from: `WICKET_ROOTS` if set, else the identity dir.
fn roots_dir() -> PathBuf {
    std::env::var_os("WICKET_ROOTS").map(PathBuf::from).unwrap_or_else(identity_dir)
}

/// How long a certificate the roots issue lasts (ms): a week while they are online (renewed
/// automatically), the `--days` chosen when they went offline.
pub fn cert_ms() -> i64 {
    marker().map(|m| m.days).unwrap_or(7) * 86_400_000
}

fn offline_error(which: &str) -> anyhow::Error {
    anyhow::anyhow!("the {which} is offline (`wicket keys roots-offline`): run this with WICKET_ROOTS set to the directory that holds it")
}

fn read_seed(path: &Path) -> Option<[u8; 32]> {
    hex::decode(std::fs::read_to_string(path).ok()?.trim()).ok()?.try_into().ok()
}

/// The public half the installation pinned for a root, if it has one (`<identity dir>/<root>.pub`).
fn pinned(file: &str) -> Option<[u8; 32]> {
    hex::decode(std::fs::read_to_string(identity_dir().join(file).with_extension("pub")).ok()?.trim()).ok()?.try_into().ok()
}

/// A root's seed. Made here only by an installation that never had it (no pinned public half): a
/// missing root is never made again, and one read from elsewhere must be the pinned one.
fn root_seed(file: &str, which: &str) -> Result<[u8; 32]> {
    let p = roots_dir().join(file);
    if let Some(s) = read_seed(&p) {
        let public = wicket_identity::SigningKey::from_bytes(&s).verifying_key().to_bytes();
        if pinned(file).is_some_and(|pk| pk != public) {
            bail!("{} is not this installation's {which} (its public half differs from the pinned one)", p.display());
        }
        return Ok(s);
    }
    if offline() {
        return Err(offline_error(which));
    }
    if pinned(file).is_some() {
        bail!(
            "the {which}'s private key is missing ({}) but its public half is pinned: put the key back (or run with WICKET_ROOTS set to the directory that holds it)",
            p.display()
        );
    }
    // A new installation: made here, as before.
    Ok(wicket_identity::load_or_create_feed_root_signing(&p)?.to_bytes())
}

pub fn feed_root_signing() -> Result<wicket_identity::SigningKey> {
    Ok(wicket_identity::SigningKey::from_bytes(&root_seed(FEED_ROOT, "feed root")?))
}

pub fn authz_root_signing() -> Result<wicket_authz::SigningKey> {
    Ok(wicket_authz::SigningKey::from_bytes(&root_seed(AUTHZ_ROOT, "authority root")?)?)
}

fn public(file: &str, which: &str) -> Result<[u8; 32]> {
    if let Some(b) = pinned(file) {
        return Ok(b);
    }
    Ok(wicket_identity::SigningKey::from_bytes(&root_seed(file, which)?).verifying_key().to_bytes())
}

/// The feed root's public key (what nodes pin).
pub fn feed_root_public() -> Result<wicket_identity::VerifyingKey> {
    Ok(wicket_identity::VerifyingKey::from_bytes(&public(FEED_ROOT, "feed root")?)?)
}

/// The authority root's public key (what nodes pin).
pub fn authz_root_public() -> Result<wicket_authz::PublicKey> {
    Ok(wicket_authz::PublicKey(public(AUTHZ_ROOT, "authority root")?))
}

/// The key boxes' block 0 is minted with, and its certificate: the issuing key while the roots are
/// offline, else the authority root itself. A token that would outlive the certificate (`until`,
/// Unix ms) isn't minted: its box would be refused mid-run.
pub fn minting_key(until: i64) -> Result<(wicket_authz::SigningKey, Option<String>)> {
    if !offline() {
        return Ok((authz_root_signing()?, None));
    }
    let d = identity_dir();
    let seed = read_seed(&d.join(ISSUING_KEY)).context("the authority issuing key (authz-issuing.key) is missing")?;
    let cert = std::fs::read_to_string(d.join(ISSUING_CERT)).context("the authority issuing key's certificate")?;
    let key = wicket_authz::SigningKey::from_bytes(&seed)?;
    let (certified, ends) = wicket_feed::AuthzKeyCert::open(&cert, &authz_root_public()?).map_err(|e| anyhow::anyhow!("{e}"))?;
    if certified != key.public() {
        bail!("the authority issuing key's certificate is for another key");
    }
    let now = wicket_feed::now_ms();
    if ends < until {
        bail!(
            "the authority issuing key's certificate ends before this box's token would ({} s left, {} s needed): renew it with `WICKET_ROOTS=<dir> wicket keys certify`",
            ((ends - now) / 1000).max(0),
            (until - now) / 1000
        );
    }
    if ends - now < 7 * 86_400_000 {
        eprintln!(
            "[wicket] the authority issuing key's certificate ends in under a week: renew it with `WICKET_ROOTS=<dir> wicket keys certify`"
        );
    }
    Ok((key, Some(cert)))
}

fn write_new(p: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(p).with_context(|| p.display().to_string())?;
    f.write_all(body)?;
    f.sync_all()?;
    Ok(())
}

fn write_replace(p: &Path, body: &[u8]) -> Result<()> {
    let tmp = p.with_extension("new");
    let _ = std::fs::remove_file(&tmp);
    write_new(&tmp, body)?;
    std::fs::rename(&tmp, p)?;
    Ok(())
}

/// Every node with a feed on this host.
fn feed_nodes() -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(data_dir().join("nodes"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join("feed/feed.key").exists())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    out.sort();
    out
}

/// Re-signs node `name`'s feed key certificate with the feed root: same key and version, until
/// `ms` from now.
fn recertify_feed(name: &str, root: &wicket_identity::SigningKey, ms: i64) -> Result<()> {
    let p = data_dir().join("nodes").join(name).join("feed/cert.jws");
    let Some(c) = std::fs::read_to_string(&p).ok().and_then(|j| wicket_feed::jws::payload_unverified::<KeyCert>(&j)) else {
        return Ok(()); // never opened: its first run makes one
    };
    let key: [u8; 32] = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &c.x)
        .ok()
        .and_then(|b| b.try_into().ok())
        .context("cert.jws key")?;
    let vk = wicket_identity::VerifyingKey::from_bytes(&key)?;
    let n = KeyCert::new(&vk, c.version, wicket_feed::now_ms() + ms, c.max_ttl_ms, c.max_narrow_ms);
    write_replace(&p, wicket_feed::sign(root, wicket_feed::TYP_KEY, &n).as_bytes())
}

/// Makes (or renews) the issuing key's certificate.
fn certify_issuing(root_seed: &[u8; 32], ms: i64) -> Result<i64> {
    let d = identity_dir();
    let kp = d.join(ISSUING_KEY);
    let seed = match read_seed(&kp) {
        Some(s) => s,
        None => {
            let mut s = [0u8; 32];
            getrandom::getrandom(&mut s).map_err(|e| anyhow::anyhow!("random: {e}"))?;
            write_new(&kp, hex::encode(s).as_bytes())?;
            s
        }
    };
    let key = wicket_authz::SigningKey::from_bytes(&seed)?;
    let until = wicket_feed::now_ms() + ms;
    write_replace(&d.join(ISSUING_CERT), wicket_feed::AuthzKeyCert::sign(root_seed, &key.public(), until).as_bytes())?;
    Ok(until)
}

fn audit(kind: &str, body: serde_json::Value) -> Result<()> {
    wicket_store::Ledger::open(&crate::ledger_path())?.audit(&wicket_core::TenantId::single(), None, kind, &body)?;
    Ok(())
}

/// Active nodes that can't be shown to talk protocol `proto` or later (unreachable, or older), each
/// with why. This host's own node is started if it isn't serving.
async fn nodes_below(proto: u32) -> Result<Vec<(String, String)>> {
    let ledger = std::sync::Arc::new(std::sync::Mutex::new(wicket_store::Ledger::open(&crate::ledger_path())?));
    let nodes: Vec<String> = ledger.lock().expect("ledger").nodes()?.into_iter().filter(|n| n.status == "active").map(|n| n.name).collect();
    let mut out = vec![];
    for n in nodes {
        if n == crate::localnode::NAME {
            if let Err(e) = crate::localnode::ensure(&ledger).await {
                out.push((n, format!("this host's node did not start: {e:#}")));
                continue;
            }
        }
        let scope = format!("keys:{}", std::process::id());
        match tokio::time::timeout(std::time::Duration::from_secs(10), crate::nodecall::Link::connect(&n, &scope, &ledger)).await {
            Ok(Ok(l)) if l.proto >= proto => {}
            Ok(Ok(l)) => out.push((
                n,
                format!("it talks protocol {}, and issuing-key tokens need {proto}: update it (`wicket node install`)", l.proto),
            )),
            Ok(Err(e)) => out.push((n, format!("can't be asked: {e:#}"))),
            Err(_) => out.push((n, "can't be asked: no answer in 10 s".into())),
        }
    }
    Ok(out)
}

/// `wicket keys roots-offline --to DIR --days N`.
pub async fn roots_offline(to: &Path, days: i64) -> Result<()> {
    if offline() {
        bail!("the roots are already offline");
    }
    if !(1..=365).contains(&days) {
        bail!("--days: 1 to 365");
    }
    // Tokens are then minted by the issuing key and carry its certificate: every active node must
    // understand that, or it would refuse every box (a node's build is checked, not assumed).
    let lacking = nodes_below(crate::chan::ISSUER_CERT).await?;
    if !lacking.is_empty() {
        bail!(
            "not every node can take tokens minted by an issuing key; nothing changed:\n{}\n(update them, or revoke the ones you no longer use)",
            lacking.iter().map(|(n, why)| format!("  - node {n}: {why}")).collect::<Vec<_>>().join("\n")
        );
    }
    let d = identity_dir();
    let (feed_seed, authz_seed) = (root_seed(FEED_ROOT, "feed root")?, root_seed(AUTHZ_ROOT, "authority root")?);
    // Their public halves stay (nodes pin them; enrolment hands them out).
    feed_root_public()?;
    authz_root_public()?;
    let ms = days * 86_400_000;
    let until = certify_issuing(&authz_seed, ms)?;
    let froot = wicket_identity::SigningKey::from_bytes(&feed_seed);
    let nodes = feed_nodes();
    for n in &nodes {
        recertify_feed(n, &froot, ms)?;
    }
    std::fs::create_dir_all(to)?;
    for (file, seed) in [(FEED_ROOT, feed_seed), (AUTHZ_ROOT, authz_seed)] {
        let dest = to.join(file);
        write_new(&dest, hex::encode(seed).as_bytes())?;
        if read_seed(&dest) != Some(seed) {
            bail!("{} doesn't read back as written: nothing removed here", dest.display());
        }
    }
    write_new(&d.join(MARKER), &serde_json::to_vec(&Offline { at: wicket_store::now(), days })?)?;
    for file in [FEED_ROOT, AUTHZ_ROOT] {
        std::fs::remove_file(d.join(file))?;
    }
    audit("keys.roots_offline", serde_json::json!({ "days": days, "issuing_until": until, "feeds": nodes }))?;
    println!("the feed root and the authority root are in {} and no longer on this host", to.display());
    println!("certificates issued with them (the authority issuing key's, {} node feed(s)) last {days} days:", nodes.len());
    println!("  renew them before then with `WICKET_ROOTS={} wicket keys certify`", to.display());
    Ok(())
}

/// `WICKET_ROOTS=DIR wicket keys certify`.
pub fn certify() -> Result<()> {
    if !offline() {
        bail!("the roots are on this host: their certificates are renewed as they are used");
    }
    let ms = cert_ms();
    let authz_seed = root_seed(AUTHZ_ROOT, "authority root")?;
    let froot = feed_root_signing()?;
    // The keys given must be the pinned ones.
    if wicket_authz::SigningKey::from_bytes(&authz_seed)?.public() != authz_root_public()? || froot.verifying_key() != feed_root_public()? {
        bail!("the keys in WICKET_ROOTS are not this installation's roots");
    }
    let until = certify_issuing(&authz_seed, ms)?;
    let nodes = feed_nodes();
    let mut regen = vec![];
    for n in &nodes {
        if data_dir().join("nodes").join(n).join("feed").join(crate::noderun::REGENESIS).exists() {
            // A new generation (after a restore): opened here, with the roots at hand.
            crate::noderun::open_feed(n, crate::noderun::feed_config())?;
            regen.push(n.clone());
        } else {
            recertify_feed(n, &froot, ms)?;
        }
    }
    audit("keys.certified", serde_json::json!({ "issuing_until": until, "feeds": nodes, "new_generation": regen }))?;
    println!(
        "renewed for {} days: the authority issuing key and {} node feed(s){}",
        ms / 86_400_000,
        nodes.len(),
        if regen.is_empty() { String::new() } else { format!(" ({} started a new generation)", regen.join(", ")) }
    );
    Ok(())
}

/// `wicket keys roots-online --from DIR`.
pub fn roots_online(from: &Path) -> Result<()> {
    if !offline() {
        bail!("the roots are on this host already");
    }
    let d = identity_dir();
    for file in [FEED_ROOT, AUTHZ_ROOT] {
        let seed = read_seed(&from.join(file)).with_context(|| format!("{}", from.join(file).display()))?;
        let pk = wicket_identity::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        if pk != public(file, "root")? {
            bail!("{} is not this installation's root", from.join(file).display());
        }
        write_new(&d.join(file), hex::encode(seed).as_bytes())?;
    }
    std::fs::remove_file(d.join(MARKER))?;
    audit("keys.roots_online", serde_json::json!({}))?;
    println!("the roots are back on this host; tokens are minted by the authority root again");
    Ok(())
}
