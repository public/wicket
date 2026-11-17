//! Root's copy of a build an operator approved in the console (#465's follow-up, #261).
//!
//! An update the console applies (`wicket self apply-update`) runs as the `wicket` user and moves
//! the versions root only, so root's link (`/usr/local/bin/wicket`) would be left on the old
//! build. Root never runs bytes the `wicket` user could have written ([`crate::rootcopy`]), and the
//! artifact came through the `wicket` user. Root may still make its own copy of it, because what
//! root trusts here is not the bytes or the ledger but an operator's passkey:
//!
//! - **Who root trusts to approve an update** is root's own list, `/etc/wicket/update-approvers/`
//!   (root-owned, refused if the `wicket` user could write it): an operator's passkey public key,
//!   added by root (`sudo wicket self trust-operator <name>`).
//! - **What is queued** (`<data dir>/self-admit/<sha256>.json` and `.artifact`, written by
//!   `apply-update` once an update is done) is untrusted: the artifact, and the passkey-signed
//!   decision as the console recorded it.
//! - **What root checks** ([`check_entry`]): the signature verifies, by a key in root's list, over a
//!   challenge that is the hash of the decision JSON; the decision approves exactly `UPDATE
//!   wicket.internal/self/<sha256>`; and root's own copy of the artifact has that sha256. Only
//!   then does root make its copy ([`crate::rootcopy::Layout::admit_file`]), and its link moves
//!   only as it always does ([`crate::rootcopy::Layout::relink`]): to root's copy of the versions
//!   root's `current`, if it has one.
//!
//! So the `wicket` user can't make root run anything an operator's passkey didn't approve: it can
//! queue only builds an operator approved, and choose only among root's copies of them. Run by the
//! root unit `wicket-admit.service`, which `wicket-admit.path` starts when an entry is queued.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Root's list of operators whose passkeys may approve an update root copies.
pub const APPROVERS: &str = "/etc/wicket/update-approvers";
/// The largest queued decision root reads.
const MAX_ENTRY: u64 = 64 * 1024;

/// The queue, under the data dir: the `wicket` user's.
pub fn spool(data: &Path) -> PathBuf {
    data.join("self-admit")
}

/// An operator root trusts, by its passkey's public key.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approver {
    /// The credential id (base64url), as the console records it.
    pub id: String,
    pub name: String,
    /// The P-256 public key's coordinates (base64url).
    pub x: String,
    pub y: String,
}

/// What `apply-update` queues for root: the request, the artifact's sha256 and the signed decision.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub v: u32,
    pub request: String,
    pub sha256: String,
    /// The console's `signed` triple (credential, rp_id, origin, nonce, client_data_json,
    /// authenticator_data, signature, decision_json).
    pub signed: serde_json::Value,
}

fn plain_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 128 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) && !n.starts_with('.')
}

fn is_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Queues an applied update for root (as the `wicket` user): moves `artifact` to the queue and
/// writes the entry last, by rename, so root sees it whole.
pub fn queue(data: &Path, entry: &Entry, artifact: &Path) -> Result<PathBuf> {
    if !is_sha(&entry.sha256) {
        bail!("not a sha256: {}", entry.sha256);
    }
    let dir = spool(data);
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
    let art = dir.join(format!("{}.artifact", entry.sha256));
    let _ = std::fs::remove_file(&art);
    if std::fs::rename(artifact, &art).is_err() {
        std::fs::copy(artifact, &art)?;
    }
    std::fs::set_permissions(&art, std::fs::Permissions::from_mode(0o644))?;
    let tmp = dir.join(format!(".{}.json.new", entry.sha256));
    let _ = std::fs::remove_file(&tmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &serde_json::to_vec(entry)?))?;
    let json = dir.join(format!("{}.json", entry.sha256));
    std::fs::rename(&tmp, &json)?;
    Ok(json)
}

/// Opens `name` in `dir` without following a link, as a regular file of at most `max` bytes (a
/// FIFO can't block: O_NONBLOCK, then refused as not a regular file).
fn open_plain(dir: &Path, name: &str, max: u64) -> Result<std::fs::File> {
    let p = dir.join(name);
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&p)
        .with_context(|| format!("opening {}", p.display()))?;
    let m = f.metadata()?;
    if !m.is_file() || m.len() > max {
        bail!("{} is not a regular file of at most {max} bytes", p.display());
    }
    Ok(f)
}

/// Root's list, refused if the `wicket` user could change it.
pub fn approvers(dir: &Path, untrusted: Option<&crate::rootcopy::Account>) -> Result<Vec<Approver>> {
    if !dir.is_dir() {
        return Ok(vec![]);
    }
    if let Some(why) = untrusted.and_then(|a| crate::rootcopy::writable_by(dir, a)) {
        bail!("refused: root's list of update approvers must be root's alone, and {why}");
    }
    let mut out = vec![];
    for e in std::fs::read_dir(dir)?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".json").filter(|s| plain_name(s)) else { continue };
        let f = open_plain(dir, &name, MAX_ENTRY)?;
        let a: Approver = serde_json::from_reader(f).with_context(|| format!("reading {}", dir.join(&name).display()))?;
        if a.name != stem {
            bail!("{} names {}", dir.join(&name).display(), a.name);
        }
        out.push(a);
    }
    Ok(out)
}

/// Checks a queued entry's signed decision against root's approvers: returns the approver's name.
pub fn check_entry(e: &Entry, approvers: &[Approver]) -> Result<String> {
    use wicket_auth::{decision_challenge, unb64u, Credential, RelyingParty};
    if e.v != 1 || !is_sha(&e.sha256) {
        bail!("not an entry this build reads");
    }
    let get = |k: &str| e.signed.get(k).and_then(|x| x.as_str()).unwrap_or("");
    let a = approvers
        .iter()
        .find(|a| a.id == get("credential"))
        .with_context(|| format!("signed by a passkey root doesn't trust to approve updates (credential {:?})", get("credential")))?;
    let decision_json = get("decision_json");
    let d: serde_json::Value = serde_json::from_str(decision_json).context("the signed decision")?;
    let s = |k: &str| d.get(k).and_then(|x| x.as_str()).unwrap_or("");
    let path = format!("/self/{}", e.sha256);
    if (s("action"), s("decision"), s("method"), s("host"), s("path")) != ("decide", "approve", "UPDATE", "wicket.internal", path.as_str())
    {
        bail!("the signed decision isn't an approval of UPDATE wicket.internal{path}");
    }
    if d.get("prefix").and_then(|p| p.as_bool()) == Some(true) || d.get("path_prefix").is_some_and(|p| !p.is_null()) {
        bail!("the signed decision approves a prefix, not one build");
    }
    // The signature: the operator's passkey over this decision, for the relying party it names.
    // (Only the operator's key can make one: the relying party is the one the passkey was made for.)
    let rp = RelyingParty { rp_id: get("rp_id").into(), origin: get("origin").into() };
    let cred = Credential {
        id: unb64u(&a.id)?,
        x: unb64u(&a.x)?.try_into().map_err(|_| anyhow::anyhow!("approver {}: a bad key", a.name))?,
        y: unb64u(&a.y)?.try_into().map_err(|_| anyhow::anyhow!("approver {}: a bad key", a.name))?,
        sign_count: 0,
    };
    rp.verify_assertion(
        &decision_challenge(&unb64u(get("nonce"))?, decision_json),
        &cred,
        &unb64u(get("client_data_json"))?,
        &unb64u(get("authenticator_data"))?,
        &unb64u(get("signature"))?,
    )
    .context("the passkey signature")?;
    Ok(a.name.clone())
}

/// One queued entry, as root: checked, then root's copy of its artifact. Returns the build id.
fn admit_one(layout: &crate::rootcopy::Layout, dir: &Path, sha: &str, approvers: &[Approver]) -> Result<String> {
    let e: Entry = serde_json::from_reader(open_plain(dir, &format!("{sha}.json"), MAX_ENTRY)?).context("reading the entry")?;
    if e.sha256 != sha {
        bail!("the entry for {sha} names {}", e.sha256);
    }
    let by = check_entry(&e, approvers)?;
    let name = format!("{sha}.artifact");
    let f = open_plain(dir, &name, crate::apply_update::MAX_ARTIFACT)?;
    let id = layout.admit_file(&f, &dir.join(&name), Some(sha))?;
    println!("[self] root's copy of {id}, from request {} approved by {by}: {}", e.request, layout.copy(&id).display());
    Ok(id)
}

/// Every queued entry (root's side): admitted or refused, and removed either way; then root's link
/// moves to root's copy of `current`, if it has one.
pub fn admit_queued(layout: &crate::rootcopy::Layout, dir: &Path, approvers_dir: &Path) -> Result<(usize, usize)> {
    let list = approvers(approvers_dir, layout.untrusted.as_ref())?;
    let (mut ok, mut refused) = (0, 0);
    let Ok(rd) = std::fs::read_dir(dir) else { return Ok((0, 0)) };
    let mut shas: Vec<String> =
        rd.flatten().filter_map(|e| e.file_name().to_str()?.strip_suffix(".json").filter(|s| is_sha(s)).map(String::from)).collect();
    shas.sort();
    for sha in shas {
        match admit_one(layout, dir, &sha, &list) {
            Ok(_) => ok += 1,
            Err(e) => {
                println!("[self] queued update {sha} refused: {e:#}");
                refused += 1;
            }
        }
        let _ = std::fs::remove_file(dir.join(format!("{sha}.json")));
        let _ = std::fs::remove_file(dir.join(format!("{sha}.artifact")));
    }
    if ok > 0 {
        layout.relink()?;
    }
    Ok((ok, refused))
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// `wicket self admit-approved` (root, `wicket-admit.service`).
pub fn admit_approved_cmd() -> Result<()> {
    if !is_root() {
        bail!("root's copies of wicket are root's to make: sudo wicket self admit-approved");
    }
    let layout = crate::rootcopy::Layout::installed();
    let (ok, refused) = admit_queued(&layout, &spool(&crate::data_dir()), Path::new(APPROVERS))?;
    println!("[self] {ok} queued update(s) admitted, {refused} refused");
    Ok(())
}

/// `wicket self trust-operator <name>` (root): adds an enrolled operator's passkey to root's list.
/// The key is read from the ledger once, by root, as `trust-key` reads a key file: run it when you
/// enrol the passkey, and check the fingerprint it prints is the one `wicket operator list` shows.
pub fn trust_operator_cmd(name: &str) -> Result<()> {
    use sha2::Digest;
    if !is_root() {
        bail!("root's list of update approvers is root's: sudo wicket self trust-operator {name}");
    }
    if !plain_name(name) {
        bail!("{name:?} is not a passkey name this list can hold (letters, digits, `_`, `.`, `-`)");
    }
    let l = wicket_store::Ledger::open(&crate::ledger_path())?;
    let found: Vec<_> = l.operator_credentials_all(&wicket_core::TenantId::single())?.into_iter().filter(|c| c.name == name).collect();
    let [c] = &found[..] else { bail!("{} enrolled passkeys are named {name}; there must be one", found.len()) };
    let a = Approver { id: c.id.clone(), name: name.into(), x: wicket_auth::b64u(&c.x), y: wicket_auth::b64u(&c.y) };
    write_approver(Path::new(APPROVERS), &a)?;
    let fp = hex::encode(sha2::Sha256::digest([c.x, c.y].concat()));
    println!("[self] root trusts passkey {name} (key sha256 {}) to approve the updates root copies", &fp[..16]);
    Ok(())
}

fn write_approver(dir: &Path, a: &Approver) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let p = dir.join(format!("{}.json", a.name));
    let tmp = dir.join(format!(".{}.json.new", a.name));
    let _ = std::fs::remove_file(&tmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &serde_json::to_vec_pretty(a)?))?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use sha2::Digest;
    use wicket_auth::b64u;

    const ORIGIN: &str = "https://console.example";

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-rootadmit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// An operator's passkey, and what it signs as the console's `signed` triple.
    struct Passkey(SigningKey);
    impl Passkey {
        fn approver(&self, name: &str) -> Approver {
            let p = self.0.verifying_key().to_sec1_point(false);
            Approver { id: b64u(b"cred-1"), name: name.into(), x: b64u(p.x().unwrap()), y: b64u(p.y().unwrap()) }
        }
        fn sign(&self, decision: &serde_json::Value) -> serde_json::Value {
            let decision_json = decision.to_string();
            let nonce = b"0123456789abcdef";
            let ch = wicket_auth::decision_challenge(nonce, &decision_json);
            let cdj =
                serde_json::json!({ "type": "webauthn.get", "challenge": b64u(&ch), "origin": ORIGIN, "crossOrigin": false }).to_string();
            let mut ad = sha2::Sha256::digest(b"console.example").to_vec();
            ad.push(0x05);
            ad.extend_from_slice(&1u32.to_be_bytes());
            let mut msg = ad.clone();
            msg.extend_from_slice(&sha2::Sha256::digest(cdj.as_bytes()));
            let sig: Signature = self.0.sign(&msg);
            serde_json::json!({ "credential": b64u(b"cred-1"), "rp_id": "console.example", "origin": ORIGIN, "nonce": b64u(nonce),
                "client_data_json": b64u(cdj.as_bytes()), "authenticator_data": b64u(&ad), "signature": b64u(sig.to_der().as_bytes()),
                "decision_json": decision_json })
        }
    }

    fn approval(sha: &str) -> serde_json::Value {
        serde_json::json!({ "v": 1, "action": "decide", "request": "req_1", "method": "UPDATE", "host": "wicket.internal",
            "path": format!("/self/{sha}"), "prefix": false, "path_prefix": null, "decision": "approve" })
    }

    #[test]
    fn only_an_approval_of_that_sha256_by_a_trusted_passkey_checks() {
        let key = Passkey(SigningKey::from_slice(&[7u8; 32]).unwrap());
        let list = [key.approver("laptop")];
        let sha = "ab".repeat(32);
        let entry = |signed| Entry { v: 1, request: "req_1".into(), sha256: sha.clone(), signed };
        assert_eq!(check_entry(&entry(key.sign(&approval(&sha))), &list).unwrap(), "laptop");
        // Another build's approval, a denial, a prefix, or tampered JSON: refused.
        let other = "cd".repeat(32);
        assert!(check_entry(&entry(key.sign(&approval(&other))), &list).is_err());
        let mut deny = approval(&sha);
        deny["decision"] = "deny".into();
        assert!(check_entry(&entry(key.sign(&deny)), &list).is_err());
        let mut prefix = approval(&sha);
        prefix["prefix"] = true.into();
        assert!(check_entry(&entry(key.sign(&prefix)), &list).is_err());
        let mut forged = key.sign(&approval(&other));
        forged["decision_json"] = approval(&sha).to_string().into();
        assert!(check_entry(&entry(forged), &list).unwrap_err().to_string().contains("signature"));
        // A passkey root doesn't trust (the wicket user's own, say): refused.
        let stranger = Passkey(SigningKey::from_slice(&[9u8; 32]).unwrap());
        let err = check_entry(&entry(stranger.sign(&approval(&sha))), &list).unwrap_err();
        assert!(format!("{err:#}").contains("signature"), "{err:#}");
        assert!(check_entry(&entry(key.sign(&approval(&sha))), &[]).unwrap_err().to_string().contains("doesn't trust"));
    }

    /// The whole queue, as root runs it: an approved artifact becomes root's copy, and root's link
    /// moves to it once it is the versions root's current; a tampered one is refused; both go.
    #[test]
    fn a_queued_approved_build_becomes_roots_copy_and_its_link() {
        let d = tmp("queue");
        let layout =
            crate::rootcopy::Layout { copies: d.join("copies"), link: d.join("bin/wicket"), versions: d.join("versions"), untrusted: None };
        std::fs::create_dir_all(d.join("bin")).unwrap();
        let key = Passkey(SigningKey::from_slice(&[7u8; 32]).unwrap());
        let approvers_dir = d.join("approvers");
        write_approver(&approvers_dir, &key.approver("laptop")).unwrap();
        // A "build": an ELF header is all binary_in looks for.
        let mut bin = b"\x7fELF".to_vec();
        bin.extend_from_slice(b" a build");
        let art_sha = hex::encode(sha2::Sha256::digest(&bin));
        let id = art_sha[..12].to_string();
        let data = d.join("data");
        std::fs::create_dir_all(&data).unwrap();
        let staged = d.join("staged");
        std::fs::write(&staged, &bin).unwrap();
        let e = Entry { v: 1, request: "req_1".into(), sha256: art_sha.clone(), signed: key.sign(&approval(&art_sha)) };
        queue(&data, &e, &staged).unwrap();
        // The versions root's current is the build (the update moved it).
        std::fs::create_dir_all(d.join("versions").join(&id)).unwrap();
        std::os::unix::fs::symlink(d.join("versions").join(&id), d.join("versions/current")).unwrap();
        // And a tampered one: its artifact isn't what was approved.
        let bad_sha = "ef".repeat(32);
        std::fs::write(&staged, b"\x7fELF other").unwrap();
        queue(&data, &Entry { v: 1, request: "req_2".into(), sha256: bad_sha.clone(), signed: key.sign(&approval(&bad_sha)) }, &staged)
            .unwrap();
        assert_eq!(admit_queued(&layout, &spool(&data), &approvers_dir).unwrap(), (1, 1));
        assert_eq!(std::fs::read(layout.copy(&id)).unwrap(), bin);
        assert_eq!(layout.linked().as_deref(), Some(id.as_str()));
        assert_eq!(std::fs::read_dir(spool(&data)).unwrap().count(), 0, "the queue is emptied");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn roots_list_must_be_roots_alone() {
        let d = tmp("list");
        let key = Passkey(SigningKey::from_slice(&[7u8; 32]).unwrap());
        write_approver(&d, &key.approver("laptop")).unwrap();
        assert_eq!(approvers(&d, None).unwrap(), [key.approver("laptop")]);
        // SAFETY: plain getters.
        let me = crate::rootcopy::Account { uid: unsafe { libc::geteuid() }, groups: vec![] };
        assert!(approvers(&d, Some(&me)).unwrap_err().to_string().contains("root's alone"));
        assert!(approvers(&d.join("none"), Some(&me)).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
