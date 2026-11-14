//! `wicket self` (#162): updates an installation to another wicket build, blue/green, with health
//! gates and rollback, on the control host and then on its nodes. The design is in
//! docs/explanation/updates.md ("Updating wicket"); in short:
//!
//! - **Versions side by side.** Each build is a directory named by its build id (the first 12 hex
//!   digits of the binary's sha256) under a versions root, holding `wicket` and `manifest.json` (its
//!   version, protocol and schema, and what accepted it). `current` and `previous` are symlinks to
//!   two of them. An installed control host's `/usr/local/bin/wicket` is a link to
//!   `<root>/current/wicket`; a node's `~/.local/bin/wicket` likewise. A process running from a
//!   staged version starts its children from `current` ([`self_exe`]), so after a switch everything
//!   new is green.
//! - **Only signed or approved artifacts** ([`accept`]): signed by one of the installation's release
//!   keys (`<data dir>/release-keys/`), or with a sha256 a human approved for one update (an
//!   agent's `request_update`, approved like any R4 request). The artifact is copied to a private
//!   staging file first, and only that copy is hashed, verified and unpacked.
//! - **Switch, hand over, gate.** A switch moves `current` (and `previous`); then the control host's
//!   processes hand over to the new build: this host's own node's `serve` re-executes itself from
//!   it (and adopts its boxes), runs' supervisors are stopped without stopping their boxes and the
//!   new build's reconciler adopts the runs (#151's path), and long-running services re-execute
//!   themselves on SIGHUP. Then the health gate runs the new build's `wicket self health` (and the
//!   operator's checks) over a window; any failure switches back the same way. Every step is an
//!   audit record (`self.*`).
//! - **Nodes after the control host**, a canary first: the binary is pushed over the node's pinned
//!   ssh, checked against its sha256 there, switched, and the node's `serve` re-executes itself;
//!   the gate then checks the node answers as the new build, still has its boxes, and passes the
//!   operator's checks.

use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wicket_core::TenantId;
use wicket_store::Ledger;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// What a release signature signs, before the artifact's sha256 (hex).
const SIG_DOMAIN: &[u8] = b"wicket-release-v1\0";

/// What a CI signature signs, before its claims ([`CiClaims`], the payload's bytes as shipped, #190).
pub const CI_DOMAIN: &[u8] = b"wicket-ci-release-v1\0";

/// What CI states about a build it signed (#190): the artifact, the commit and ref it was built
/// from, where (repository, workflow, run) and that it was signed in the `release` environment,
/// after a reviewer approved it. Verified as the bytes CI signed, never re-serialised.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CiClaims {
    pub v: u32,
    pub artifact: String,
    pub sha256: String,
    pub repo: String,
    pub commit: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub workflow: String,
    pub run_id: u64,
    pub run_attempt: u32,
    pub environment: String,
    /// Unix seconds, CI's clock.
    pub signed_at: i64,
}

/// What a CI build must be to be taken (`self update --from-ci`, `self follow`): from this
/// installation's configured repository and workflow, of this commit, on `main`, signed in the
/// `release` environment. The repository comes from the installation, never from the build.
#[derive(Clone, Debug)]
pub struct CiExpect {
    pub repo: String,
    pub workflow: String,
    pub commit: String,
}

/// The only ref CI builds are taken from.
pub const CI_REF: &str = "refs/heads/main";
/// The environment CI signs in, behind its required reviewers.
pub const CI_ENVIRONMENT: &str = "release";

/// Whether `c` is a build `e` asks for, at `now` (Unix seconds).
pub fn check_claims(c: &CiClaims, e: &CiExpect, now: i64) -> Result<()> {
    if c.v != 1 {
        bail!("CI claims version {} (this build reads 1)", c.v);
    }
    if !c.repo.eq_ignore_ascii_case(&e.repo) {
        bail!("built from repository {}, not {}", c.repo, e.repo);
    }
    if c.workflow != e.workflow {
        bail!("signed by workflow {}, not {}", c.workflow, e.workflow);
    }
    if c.commit != e.commit {
        bail!("built from commit {}, not {}", c.commit, e.commit);
    }
    if c.git_ref != CI_REF {
        bail!("built from {}, not {CI_REF}", c.git_ref);
    }
    if c.environment != CI_ENVIRONMENT {
        bail!("signed in environment {:?}, not {CI_ENVIRONMENT}", c.environment);
    }
    if c.signed_at > now + 300 {
        bail!("signed at {} (Unix), in the future", c.signed_at);
    }
    Ok(())
}

/// A build's compatibility facts (`wicket self describe`), recorded in its version's manifest.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Describe {
    pub version: String,
    /// The binary's sha256.
    pub build: String,
    pub protocol: u32,
    pub protocol_skew: u32,
    pub schema: u32,
    pub schema_floor: u32,
}

pub fn describe() -> Result<Describe> {
    Ok(Describe {
        version: env!("CARGO_PKG_VERSION").into(),
        build: crate::nodesrv::build_id()?,
        protocol: crate::chan::PROTOCOL,
        protocol_skew: crate::chan::PROTOCOL_SKEW,
        schema: wicket_store::SCHEMA_VERSION,
        schema_floor: wicket_store::SCHEMA_FLOOR,
    })
}

/// A staged version's `manifest.json`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    #[serde(flatten)]
    pub describe: Describe,
    /// The sha256 of the artifact it came from (the archive, or the binary itself).
    pub artifact_sha256: String,
    /// What accepted it: `{"signed": key id}`, `{"approved": {"request", "grant"}}`, or
    /// `{"running": true}` for the build that ran before the first update.
    pub source: serde_json::Value,
    pub staged_at: i64,
}

/// A versions root.
pub struct Versions {
    pub root: PathBuf,
}

fn valid_id(id: &str) -> bool {
    id.len() == 12 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The versions root the running binary is in, if it is a staged version.
fn running_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let root = dir.parent()?;
    let staged = exe.file_name()? == "wicket" && valid_id(dir.file_name()?.to_str()?) && root.join("current").exists();
    staged.then(|| root.to_path_buf())
}

impl Versions {
    /// The control host's: the root the running binary is in (an installed host's
    /// `/usr/local/bin/wicket` links into it), else `$WICKET_VERSIONS`, else `<data dir>/versions`.
    pub fn control() -> Versions {
        if let Some(root) = running_root() {
            return Versions { root };
        }
        if let Some(v) = std::env::var_os("WICKET_VERSIONS").filter(|v| !v.is_empty()) {
            return Versions { root: PathBuf::from(v) };
        }
        Versions { root: crate::data_dir().join("versions") }
    }

    pub fn pointer(&self, name: &str) -> Option<String> {
        let t = std::fs::read_link(self.root.join(name)).ok()?;
        let id = t.file_name()?.to_str()?.to_string();
        valid_id(&id).then_some(id)
    }

    pub fn binary(&self, id: &str) -> PathBuf {
        self.root.join(id).join("wicket")
    }

    pub fn manifest(&self, id: &str) -> Result<Manifest> {
        let p = self.root.join(id).join("manifest.json");
        serde_json::from_slice(&std::fs::read(&p).with_context(|| p.display().to_string())?).with_context(|| p.display().to_string())
    }

    fn set_pointer(&self, name: &str, id: &str) -> Result<()> {
        let tmp = self.root.join(format!(".{name}.{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(id, &tmp)?;
        std::fs::rename(&tmp, self.root.join(name)).with_context(|| format!("switching {name}"))?;
        Ok(())
    }

    /// Makes `to` current, and what was current previous. Returns what was current.
    pub fn switch(&self, to: &str) -> Result<Option<String>> {
        if !self.binary(to).is_file() {
            bail!("version {to} is not staged in {}", self.root.display());
        }
        let cur = self.pointer("current");
        if cur.as_deref() == Some(to) {
            return Ok(cur);
        }
        if let Some(c) = &cur {
            self.set_pointer("previous", c)?;
        }
        self.set_pointer("current", to)?;
        Ok(cur)
    }

    /// Stages the binary at `bin` (already verified) as a version, with its manifest. Returns its id.
    fn stage(&self, bin: &Path, artifact_sha256: &str, source: serde_json::Value) -> Result<(String, Manifest)> {
        let sha = sha256_file(bin)?;
        let id = sha[..12].to_string();
        std::fs::create_dir_all(&self.root)?;
        std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o755))?;
        let dir = self.root.join(&id);
        if !dir.join("manifest.json").is_file() {
            let tmp = self.root.join(format!(".stage-{id}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(&tmp)?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
            std::fs::copy(bin, tmp.join("wicket"))?;
            std::fs::set_permissions(tmp.join("wicket"), std::fs::Permissions::from_mode(0o755))?;
            if sha256_file(&tmp.join("wicket"))? != sha {
                bail!("the staged copy of {} changed while it was copied", bin.display());
            }
            // Ask the build itself what it is (it is verified by now).
            let out = std::process::Command::new(tmp.join("wicket"))
                .args(["self", "describe"])
                .env("WICKET_HOME", tmp.join("probe"))
                .env_remove("WICKET_DAEMON_SOCKET")
                .output()
                .context("running the new build")?;
            let _ = std::fs::remove_dir_all(tmp.join("probe"));
            if !out.status.success() {
                let _ = std::fs::remove_dir_all(&tmp);
                bail!("the new build doesn't run here: {}", String::from_utf8_lossy(&out.stderr).trim());
            }
            let describe: Describe = serde_json::from_slice(&out.stdout).context("the new build's `self describe`")?;
            if describe.build != sha {
                let _ = std::fs::remove_dir_all(&tmp);
                bail!("the new build says it is {}, but its sha256 is {sha}", describe.build);
            }
            let m = Manifest { describe, artifact_sha256: artifact_sha256.into(), source, staged_at: wicket_store::now() };
            std::fs::write(tmp.join("manifest.json"), serde_json::to_vec_pretty(&m)?)?;
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::rename(&tmp, &dir)?;
        } else if sha256_file(&self.binary(&id))? != sha {
            bail!("{} exists with another binary: remove it", dir.display());
        }
        Ok((id.clone(), self.manifest(&id)?))
    }

    /// Imports the running binary as a version, for an installation updated for the first time.
    fn import_running(&self) -> Result<String> {
        let exe = std::env::current_exe().context("finding this binary")?;
        let (id, _) = self.stage(&exe, &sha256_file(&exe)?, serde_json::json!({ "running": true }))?;
        Ok(id)
    }
}

/// Whether this process runs a staged version.
pub fn is_staged() -> bool {
    running_root().is_some()
}

/// The binary a wicket process starts its children from: the versions root's `current` when this
/// process runs a staged version (so after a switch every new process is the new build), else this
/// binary.
pub fn self_exe() -> Result<PathBuf> {
    if let Some(root) = running_root() {
        let b = root.join("current").join("wicket");
        if b.is_file() {
            return Ok(b);
        }
    }
    std::env::current_exe().context("finding this binary")
}

/// Replaces this process with the current version in `versions` (else [`self_exe`]), same
/// arguments, same pid (only returns on failure).
pub fn reexec(versions: &Path) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let cur = versions.join("current").join("wicket");
    let exe = match cur.is_file() {
        true => cur,
        false => match self_exe() {
            Ok(e) => e,
            Err(e) => return e,
        },
    };
    let err = std::process::Command::new(&exe).args(std::env::args_os().skip(1)).exec();
    anyhow::anyhow!("re-executing {}: {err}", exe.display())
}

/// Writes this process's pid to `pidfile`, and on SIGHUP runs `before` and then re-executes from
/// the current version in `versions` ([`reexec`]): how a long-running wicket process moves to a new
/// build without a service manager. Must be called inside a tokio runtime.
pub fn reexec_on_hangup(pidfile: PathBuf, versions: PathBuf, before: impl FnOnce() + Send + 'static) {
    use tokio::signal::unix::{signal, SignalKind};
    if let Some(d) = pidfile.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = pidfile.with_extension(format!("{}.new", std::process::id()));
    if std::fs::write(&tmp, format!("{}\n", std::process::id())).is_ok() {
        let _ = std::fs::rename(&tmp, &pidfile);
    }
    // What this process runs, for checks that can't read `/proc/<pid>/exe`: a `node serve` makes
    // itself non-dumpable (it holds secrets in memory, #152), which hides that from its own user.
    if let Ok(exe) = std::env::current_exe().and_then(std::fs::canonicalize) {
        let tmp = pidfile.with_extension(format!("{}.exe-new", std::process::id()));
        if std::fs::write(&tmp, format!("{}\n{}\n", std::process::id(), exe.display())).is_ok() {
            let _ = std::fs::rename(&tmp, pidfile.with_extension("exe"));
        }
    }
    let Ok(mut hup) = signal(SignalKind::hangup()) else { return };
    tokio::spawn(async move {
        hup.recv().await;
        eprintln!("wicket: SIGHUP: re-executing from the current version");
        let _ = tokio::task::spawn_blocking(move || {
            before();
            eprintln!("wicket: {:#}", reexec(&versions));
        })
        .await;
    });
}

/// The pid files of the control host's long-running processes.
pub fn pidfile(role: &str) -> PathBuf {
    crate::data_dir().join("pids").join(format!("{role}.pid"))
}

/// Sends SIGHUP to the process a pid file names, if it is still a wicket process whose command line
/// has `expect` in it. Returns its pid.
fn hangup(pidfile: &Path, expect: &str) -> Option<u32> {
    let pid: u32 = std::fs::read_to_string(pidfile).ok()?.trim().parse().ok()?;
    let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let cmd = String::from_utf8_lossy(&cmd).replace('\0', " ");
    if !cmd.contains("wicket") || !cmd.contains(expect) || pid == std::process::id() {
        return None;
    }
    // SAFETY: a plain syscall.
    (unsafe { libc::kill(pid as i32, libc::SIGHUP) } == 0).then_some(pid)
}

/// Whether process `pid` now runs `bin`.
fn runs(pid: u32, bin: &Path, pidfile: &Path) -> bool {
    let want = std::fs::canonicalize(bin).ok();
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok().or_else(|| {
        // A non-dumpable process: what it wrote beside its pid file, if it is this pid's.
        let s = std::fs::read_to_string(pidfile.with_extension("exe")).ok()?;
        let mut l = s.lines();
        (l.next()?.trim().parse::<u32>().ok()? == pid).then(|| PathBuf::from(l.next().unwrap_or_default()))
    });
    exe.is_some_and(|e| Some(e) == want)
}

fn sha256_file(p: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(p).with_context(|| p.display().to_string())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

// ---- release keys and signatures ----

/// A detached signature (`<artifact>.sig`).
#[derive(Serialize, Deserialize, Clone)]
struct Signature {
    alg: String,
    /// The signing key's public half (base64url).
    key: String,
    sha256: String,
    sig: String,
    /// A CI signature's claims ([`CiClaims`]), base64url: what it signs, after [`CI_DOMAIN`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
}

fn key_id(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public))[..16].to_string()
}

fn release_keys_dir() -> PathBuf {
    crate::data_dir().join("release-keys")
}

/// `wicket self keygen`: a release key pair, the private half in `out` (0600), the public in `out.pub`.
pub fn keygen(out: &Path) -> Result<()> {
    if out.exists() {
        bail!("{} exists", out.display());
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    let key = wicket_identity::SigningKey::from_bytes(&seed);
    let public = key.verifying_key().to_bytes();
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode_0600().open(out)?;
    use std::io::Write;
    writeln!(f, "{}", serde_json::json!({ "alg": "ed25519", "secret": B64.encode(seed) }))?;
    let pubpath = PathBuf::from(format!("{}.pub", out.display()));
    std::fs::write(&pubpath, format!("{}\n", serde_json::json!({ "alg": "ed25519", "key": B64.encode(public) })))?;
    println!(
        "release key {} (keep {} offline; give {} to each installation: wicket self trust-key)",
        key_id(&public),
        out.display(),
        pubpath.display()
    );
    Ok(())
}

trait Mode0600 {
    fn mode_0600(&mut self) -> &mut Self;
}
impl Mode0600 for std::fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600)
    }
}

fn read_secret(key: &Path) -> Result<wicket_identity::SigningKey> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(key).with_context(|| key.display().to_string())?)?;
    let seed: [u8; 32] = B64
        .decode(v["secret"].as_str().context("not a release key (wicket self keygen)")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("not a release key"))?;
    Ok(wicket_identity::SigningKey::from_bytes(&seed))
}

fn read_public(p: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(p).with_context(|| p.display().to_string())?;
    // An Ed25519 public key in PEM (`openssl pkey -pubout`): CI's release key (#190).
    if let Some(body) = std::str::from_utf8(&bytes).ok().and_then(|t| {
        t.trim().strip_prefix("-----BEGIN PUBLIC KEY-----").and_then(|r| r.trim_end().strip_suffix("-----END PUBLIC KEY-----"))
    }) {
        let der = base64::engine::general_purpose::STANDARD.decode(body.split_whitespace().collect::<String>())?;
        const SPKI: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        return match der.strip_prefix(&SPKI[..]) {
            Some(k) => k.try_into().map_err(|_| anyhow::anyhow!("not an Ed25519 public key")),
            None => bail!("not an Ed25519 public key"),
        };
    }
    let v: serde_json::Value = serde_json::from_slice(&bytes)?;
    B64.decode(v["key"].as_str().context("not a release public key")?)?.try_into().map_err(|_| anyhow::anyhow!("not a release public key"))
}

/// `wicket self sign`: writes `<artifact>.sig`.
pub fn sign(key: &Path, artifact: &Path) -> Result<()> {
    use wicket_identity::SigningKey;
    let k: SigningKey = read_secret(key)?;
    let sha = sha256_file(artifact)?;
    let sig = ed25519_sign(&k, &sha);
    let s = Signature { alg: "ed25519".into(), key: B64.encode(k.verifying_key().to_bytes()), sha256: sha.clone(), sig, payload: None };
    let out = PathBuf::from(format!("{}.sig", artifact.display()));
    std::fs::write(&out, format!("{}\n", serde_json::to_string(&s)?))?;
    println!("{}: sha256 {sha}, signed by {}", out.display(), key_id(&k.verifying_key().to_bytes()));
    Ok(())
}

fn ed25519_sign(k: &wicket_identity::SigningKey, sha: &str) -> String {
    use ed25519_dalek::Signer;
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(sha.as_bytes());
    B64.encode(k.sign(&msg).to_bytes())
}

/// Whether `sig` is a valid signature of the artifact with `sha` by one of `trusted`. Returns the
/// key's id.
fn verify_sig(sig: &Signature, sha: &str, trusted: &[[u8; 32]]) -> Result<String> {
    use ed25519_dalek::Verifier;
    if sig.payload.is_some() {
        return verify_ci_sig(sig, sha, trusted).map(|(k, _)| k);
    }
    if sig.alg != "ed25519" {
        bail!("an {} signature (only ed25519)", sig.alg);
    }
    if sig.sha256 != sha {
        bail!("the signature is for another artifact (sha256 {})", sig.sha256);
    }
    let public: [u8; 32] = B64.decode(&sig.key)?.try_into().map_err(|_| anyhow::anyhow!("a malformed key"))?;
    if !trusted.contains(&public) {
        bail!("signed by key {}, which this installation doesn't trust", key_id(&public));
    }
    let vk = wicket_identity::VerifyingKey::from_bytes(&public)?;
    let s = ed25519_dalek::Signature::from_slice(&B64.decode(&sig.sig)?)?;
    let mut msg = SIG_DOMAIN.to_vec();
    msg.extend_from_slice(sha.as_bytes());
    vk.verify(&msg, &s).map_err(|_| anyhow::anyhow!("the signature doesn't verify"))?;
    Ok(key_id(&public))
}

/// Whether `sig` is a valid CI signature (#190) of the artifact with `sha` by one of `trusted`: the
/// key's id and the claims, read from the bytes it signed.
fn verify_ci_sig(sig: &Signature, sha: &str, trusted: &[[u8; 32]]) -> Result<(String, CiClaims)> {
    use ed25519_dalek::Verifier;
    if sig.alg != "ed25519" {
        bail!("an {} signature (only ed25519)", sig.alg);
    }
    let payload = B64.decode(sig.payload.as_deref().context("not a CI signature (no claims)")?)?;
    let public: [u8; 32] = B64.decode(&sig.key)?.try_into().map_err(|_| anyhow::anyhow!("a malformed key"))?;
    if !trusted.contains(&public) {
        bail!("signed by key {}, which this installation doesn't trust", key_id(&public));
    }
    let vk = wicket_identity::VerifyingKey::from_bytes(&public)?;
    let s = ed25519_dalek::Signature::from_slice(&B64.decode(&sig.sig)?)?;
    let mut msg = CI_DOMAIN.to_vec();
    msg.extend_from_slice(&payload);
    vk.verify(&msg, &s).map_err(|_| anyhow::anyhow!("the signature doesn't verify"))?;
    let claims: CiClaims = serde_json::from_slice(&payload).context("the signed claims")?;
    if claims.sha256 != sha || sig.sha256 != sha {
        bail!("the signature is for another artifact (sha256 {})", claims.sha256);
    }
    Ok((key_id(&public), claims))
}

fn trusted_keys() -> Result<Vec<[u8; 32]>> {
    let mut v = vec![];
    if let Ok(rd) = std::fs::read_dir(release_keys_dir()) {
        for e in rd.flatten() {
            if e.path().extension().is_some_and(|x| x == "pub") {
                v.push(read_public(&e.path())?);
            }
        }
    }
    Ok(v)
}

/// `wicket self trust-key`: adds a release public key.
pub fn trust_key(public: &Path) -> Result<()> {
    let k = read_public(public)?;
    wicket_identity::VerifyingKey::from_bytes(&k).context("not an Ed25519 key")?;
    let dir = release_keys_dir();
    std::fs::create_dir_all(&dir)?;
    let id = key_id(&k);
    std::fs::write(dir.join(format!("{id}.pub")), format!("{}\n", serde_json::json!({ "alg": "ed25519", "key": B64.encode(k) })))?;
    Ledger::open(&crate::ledger_path())?.audit(&TenantId::single(), None, "self.key_trusted", &serde_json::json!({ "key": id }))?;
    println!("trusting release key {id}");
    Ok(())
}

// ---- accepting an artifact ----

/// A verified artifact: the private copy, its sha256, and what accepted it.
struct Accepted {
    copy: PathBuf,
    sha256: String,
    source: serde_json::Value,
}

/// Copies the artifact into `stage` (private), then accepts that copy if it is signed by a trusted
/// release key or its sha256 was approved for an update (used up here). Refusals are audited.
fn accept(ledger: &Mutex<Ledger>, artifact: &Path, sig: Option<&Path>, stage: &Path, ci: Option<&CiExpect>) -> Result<Accepted> {
    std::fs::create_dir_all(stage)?;
    std::fs::set_permissions(stage, std::fs::Permissions::from_mode(0o700))?;
    let copy = stage.join("artifact");
    std::fs::copy(artifact, &copy).with_context(|| format!("reading {}", artifact.display()))?;
    let sha = sha256_file(&copy)?;
    let refuse = |why: String| -> anyhow::Error {
        let _ = ledger.lock().expect("ledger").audit(
            &TenantId::single(),
            None,
            "self.update_refused",
            &serde_json::json!({ "artifact_sha256": sha, "why": why, "by": crate::operator() }),
        );
        anyhow::anyhow!("refused: {why}")
    };
    let sig_path = sig.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(format!("{}.sig", artifact.display())));
    // A CI build (#190): only a CI signature whose claims are what was asked for. No other
    // signature, and no human approval of its sha256, stands in for it.
    if let Some(e) = ci {
        let checked = std::fs::read(&sig_path)
            .with_context(|| format!("no signature ({})", sig_path.display()))
            .and_then(|b| Ok(serde_json::from_slice::<Signature>(&b)?))
            .and_then(|s| verify_ci_sig(&s, &sha, &trusted_keys()?))
            .and_then(|(key, c)| check_claims(&c, e, wicket_store::now()).map(|_| (key, c)));
        return match checked {
            Ok((key, c)) => Ok(Accepted { copy, sha256: sha, source: ci_source(&key, &c) }),
            Err(e) => Err(refuse(format!("the CI build isn't signed as asked: {e:#}"))),
        };
    }
    let mut why_not_signed = format!("no signature ({} doesn't exist)", sig_path.display());
    if let Ok(bytes) = std::fs::read(&sig_path) {
        match serde_json::from_slice::<Signature>(&bytes).map_err(anyhow::Error::from).and_then(|s| verify_sig(&s, &sha, &trusted_keys()?))
        {
            Ok(key) => {
                // A CI signature given by hand: its claims are recorded too.
                let claims = serde_json::from_slice::<Signature>(&bytes)
                    .ok()
                    .and_then(|s| s.payload)
                    .and_then(|p| B64.decode(p).ok())
                    .and_then(|p| serde_json::from_slice::<CiClaims>(&p).ok());
                let source = match claims {
                    Some(c) => ci_source(&key, &c),
                    None => serde_json::json!({ "signed": key }),
                };
                return Ok(Accepted { copy, sha256: sha, source });
            }
            Err(e) => why_not_signed = format!("{} ({e:#})", sig_path.display()),
        }
    }
    // Bound first: the ledger's lock must be released before `refuse` takes it again.
    let approval = ledger.lock().expect("ledger").use_update_approval(&sha)?;
    match approval {
        Some((request, grant)) => Ok(Accepted { copy, sha256: sha, source: serde_json::json!({ "approved": { "request": request, "grant": grant } }) }),
        None => Err(refuse(format!(
            "the artifact (sha256 {sha}) is not signed by a release key this installation trusts: {why_not_signed}; and no human has approved an update to it (an agent's request_update, approved with `wicket approve`)"
        ))),
    }
}

/// Verifies a downloaded CI build without staging it (#190, `self follow`'s soak and contract-step
/// checks, before an update verifies it again from its private copy): the signing key's id and
/// the claims.
pub fn verify_ci_files(archive: &Path, sig: &Path, e: &CiExpect) -> Result<(String, CiClaims)> {
    let sha = sha256_file(archive)?;
    let s: Signature = serde_json::from_slice(&std::fs::read(sig)?)?;
    let (key, c) = verify_ci_sig(&s, &sha, &trusted_keys()?)?;
    check_claims(&c, e, wicket_store::now())?;
    Ok((key, c))
}

/// What a verified archive's build is (`self describe`, run from a private copy).
pub fn describe_archive(archive: &Path, stage: &Path) -> Result<Describe> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(stage)?;
    std::fs::set_permissions(stage, std::fs::Permissions::from_mode(0o700))?;
    let bin = binary_in(archive, stage)?;
    let out = std::process::Command::new(&bin).args(["self", "describe"]).output().context("running the build's describe")?;
    if !out.status.success() {
        bail!("the build's describe failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    serde_json::from_slice(&out.stdout).context("the build's describe")
}

/// What accepted a CI build, as its version's manifest and the audit record it.
fn ci_source(key: &str, c: &CiClaims) -> serde_json::Value {
    serde_json::json!({
        "signed": key,
        "ci": { "repo": c.repo, "commit": c.commit, "ref": c.git_ref, "workflow": c.workflow, "run_id": c.run_id,
                "run_attempt": c.run_attempt, "environment": c.environment, "signed_at": c.signed_at },
    })
}

/// The wicket binary in an accepted artifact: the artifact itself (an executable), or the
/// `<dir>/wicket` of a release archive (`ci/package.sh`), read without unpacking anything else.
fn binary_of(a: &Accepted, stage: &Path) -> Result<PathBuf> {
    binary_in(&a.copy, stage)
}

fn binary_in(artifact: &Path, stage: &Path) -> Result<PathBuf> {
    let mut magic = [0u8; 4];
    {
        use std::io::Read;
        std::fs::File::open(artifact)?.read_exact(&mut magic).context("an empty artifact")?;
    }
    if magic == *b"\x7fELF" {
        return Ok(artifact.to_path_buf());
    }
    if magic[..2] != [0x1f, 0x8b] {
        bail!("the artifact is neither a wicket binary nor a release archive (.tar.gz)");
    }
    let list = std::process::Command::new("tar").arg("-tzf").arg(artifact).output().context("running tar")?;
    if !list.status.success() {
        bail!("not a readable archive: {}", String::from_utf8_lossy(&list.stderr).trim());
    }
    let names = String::from_utf8_lossy(&list.stdout);
    let member = names
        .lines()
        .find(|n| matches!(n.split('/').collect::<Vec<_>>()[..], [d, "wicket"] if d.starts_with("wicket-") && !d.contains("..")))
        .context("the archive has no <wicket-…>/wicket")?
        .to_string();
    std::fs::create_dir_all(stage)?;
    let out = stage.join("wicket");
    let f = std::fs::File::create(&out)?;
    let st = std::process::Command::new("tar").arg("-xzOf").arg(artifact).arg("--").arg(&member).stdout(f).status()?;
    if !st.success() {
        bail!("extracting {member} from the archive failed");
    }
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755))?;
    Ok(out)
}

// ---- the update ----

pub struct UpdateOpts {
    pub artifact: PathBuf,
    pub sig: Option<PathBuf>,
    /// `all`, or node names (comma-separated); None: the control host only.
    pub nodes: Option<String>,
    /// The control host is already on this build: only the nodes.
    pub only_nodes: bool,
    pub gate: Gate,
    /// Prune afterwards, where it updated (`wicket self prune`).
    pub prune: bool,
    /// A CI build (#190): taken only with a CI signature whose claims match.
    pub ci: Option<CiExpect>,
}

/// The health gate's settings.
#[derive(Clone)]
pub struct Gate {
    /// How long a new build is watched after a switch.
    pub window: Duration,
    /// How often within the window.
    pub interval: Duration,
    /// Commands (`sh -c`) that must succeed each time, with `WICKET` (the new build's binary) and
    /// `WICKET_UPDATE_TARGET` (`control`, or `node:<name>`) set.
    pub checks: Vec<String>,
    /// A manifest the new build runs once on the control host, which must succeed.
    pub canary: Option<PathBuf>,
    /// The canary's image (default: the new build's own, `wicket/claude-code:<build id>`).
    pub image: Option<String>,
}

/// Makes sure version `id`'s own agent image (`wicket/claude-code:<id>`) is in this host's Docker:
/// built by that version's binary from the image sources embedded in it, so it matches it.
async fn ensure_image(v: &Versions, id: &str) -> Result<String> {
    let tag = crate::image::tag_for(id);
    if wicket_sandbox::Docker::from_env().image_exists(&tag).await? {
        return Ok(tag);
    }
    say(format!("building {tag} with {id}"));
    let out = tokio::process::Command::new(v.binary(id))
        .args(["image", "--tag", &tag])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .context("running `wicket image`")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("building {tag}: {}", err.lines().rev().take(5).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n"));
    }
    Ok(tag)
}

/// Makes sure a node's Docker has `tag`: if not, `docker save` here piped into `docker load` over
/// the node's pinned ssh.
async fn ensure_image_on_node(node: &crate::node::Node, tag: &str) -> Result<()> {
    let remote = wicket_sandbox::Docker::over_ssh(node.ssh_prefix());
    if remote.image_exists(tag).await? {
        return Ok(());
    }
    say(format!("node {}: loading {tag}", node.name.as_deref().unwrap_or(&node.target)));
    let here: Vec<String> =
        std::env::var("WICKET_DOCKER").unwrap_or_else(|_| "docker".into()).split_whitespace().map(String::from).collect();
    let mut save = tokio::process::Command::new(&here[0]);
    save.args(&here[1..]).args(["save", tag]).stdout(std::process::Stdio::piped());
    let mut save = save.spawn().context("docker save")?;
    let mut ssh = node.ssh_prefix();
    ssh.push("docker load".into());
    let mut load = tokio::process::Command::new(&ssh[0]);
    let stdout: std::process::Stdio = save.stdout.take().context("docker save's output")?.try_into()?;
    load.args(&ssh[1..]).stdin(stdout).stdout(std::process::Stdio::null());
    let (s, l) = (save.wait(), load.status());
    let (s, l) = tokio::join!(s, l);
    if !s?.success() || !l?.success() {
        bail!("loading {tag} onto node {} failed", node.target);
    }
    Ok(())
}

fn audit(ledger: &Mutex<Ledger>, kind: &str, body: serde_json::Value) {
    if let Err(e) = ledger.lock().expect("ledger").audit(&TenantId::single(), None, kind, &body) {
        eprintln!("[self] recording {kind}: {e}");
    }
}

fn say(s: impl AsRef<str>) {
    println!("[self] {}", s.as_ref());
}

/// Every node `--nodes` names, canary first.
fn node_list(ledger: &Ledger, spec: &str) -> Result<Vec<String>> {
    let active: Vec<String> =
        ledger.nodes()?.into_iter().filter(|n| n.status == "active" && !n.target.starts_with("unix:")).map(|n| n.name).collect();
    if spec == "all" {
        return Ok(active);
    }
    let mut v = vec![];
    for n in spec.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if !active.iter().any(|a| a == n) {
            bail!("{n} is not an active enrolled node");
        }
        v.push(n.to_string());
    }
    Ok(v)
}

/// `wicket self update`.
pub async fn update(o: UpdateOpts) -> Result<()> {
    let ledger = Arc::new(Mutex::new(Ledger::open(&crate::ledger_path())?));
    let nodes = match &o.nodes {
        Some(s) => node_list(&ledger.lock().expect("ledger"), s)?,
        None => vec![],
    };
    if o.only_nodes && nodes.is_empty() {
        bail!("--only-nodes needs --nodes");
    }
    let v = Versions::control();
    let stage = crate::data_dir().join(format!("self-stage-{}", std::process::id()));
    let _clean = RemoveOnDrop(stage.clone());
    let _one = update_lock()?;
    let accepted = accept(&ledger, &o.artifact, o.sig.as_deref(), &stage, o.ci.as_ref())?;
    let bin = binary_of(&accepted, &stage)?;
    if v.pointer("current").is_none() {
        let id = v.import_running()?;
        v.switch(&id)?;
        say(format!("first update here: the running build is version {id} in {}", v.root.display()));
    }
    let blue = v.pointer("current").context("no current version")?;
    let (green, m) = v.stage(&bin, &accepted.sha256, accepted.source.clone())?;
    // Each version's own agent image: the new one's for its boxes and its canary, the old one's for
    // a rollback (running boxes keep whatever they started with).
    let image = ensure_image(&v, &green).await?;
    if let Err(e) = ensure_image(&v, &blue).await {
        say(format!("warning: no image of the running version {blue} for a rollback's new boxes: {e:#}"));
    }
    audit(
        &ledger,
        "self.staged",
        serde_json::json!({ "version": green, "build": m.describe.build, "wicket": m.describe.version, "protocol": m.describe.protocol,
            "schema": m.describe.schema, "artifact_sha256": accepted.sha256, "source": accepted.source, "image": image, "by": crate::operator() }),
    );
    say(format!(
        "staged {green} (wicket {}, protocol {}, schema {}), accepted as {}",
        m.describe.version, m.describe.protocol, m.describe.schema, accepted.source
    ));
    let here = describe()?;
    if here.protocol.abs_diff(m.describe.protocol) > crate::chan::PROTOCOL_SKEW {
        bail!("{green} speaks protocol {}, this build {}: update one protocol version at a time", m.describe.protocol, here.protocol);
    }
    if !o.only_nodes {
        if blue == green {
            say(format!("the control host already runs {green}"));
        } else {
            control_switch(&ledger, &v, &blue, &green, &nodes, &o.gate, false).await?;
        }
    } else if v.pointer("current").as_deref() != Some(green.as_str()) {
        bail!("--only-nodes: the control host runs {blue}, not {green}; update it first");
    }
    for (i, n) in nodes.iter().enumerate() {
        node_update(&ledger, &v, n, &green, &o.gate, i == 0).await?;
    }
    // wicketd re-executes itself last, once the commands it is running (this one) have ended.
    if let Some(pid) = hangup(&pidfile("daemon"), "daemon") {
        say(format!("wicketd (pid {pid}) moves to {green} when its running commands end"));
    }
    say(format!(
        "done: the control host{} run {green}; `wicket self rollback` goes back to {blue}",
        if nodes.is_empty() { "" } else { " and the nodes" }
    ));
    if o.prune {
        // Committed: what neither this version nor a rollback to the last one needs can go.
        let names = (!nodes.is_empty()).then(|| nodes.join(","));
        if let Err(e) = prune(names, o.only_nodes, KEEP_SNAPSHOTS, false).await {
            say(format!("pruning old versions failed (the update stands): {e:#}"));
        }
    }
    Ok(())
}

/// One update or rollback at a time on a control host, whoever starts it (an operator, `self
/// follow`): held until dropped.
pub fn update_lock() -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    let p = crate::data_dir().join("self-update.lock");
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&p).with_context(|| p.display().to_string())?;
    // SAFETY: flock on a file this process holds open.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another update or rollback is running on this control host");
    }
    Ok(f)
}

struct RemoveOnDrop(PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Switches the control host from `from` to `to`, hands over, and gates; on a failed gate, switches
/// back (automatically) and fails. `rollback`: this is `wicket self rollback` (no gate of its own
/// beyond one health check, and no switching back).
async fn control_switch(
    ledger: &Mutex<Ledger>,
    v: &Versions,
    from: &str,
    to: &str,
    nodes: &[String],
    gate: &Gate,
    rollback: bool,
) -> Result<()> {
    let target = v.manifest(to)?;
    let schema = Ledger::schema_of(&crate::ledger_path())?;
    if target.describe.schema < schema.floor {
        bail!(
            "{to} has schema {}, but the ledger has been through a contract step to schema {} (floor {}): it can't go back past it. Roll forward, or restore the snapshot taken before that update (see docs/explanation/updates.md)",
            target.describe.schema,
            schema.version,
            schema.floor
        );
    }
    // A snapshot of the ledger before the new build migrates anything.
    let snaps = crate::data_dir().join("snapshots");
    std::fs::create_dir_all(&snaps)?;
    std::fs::set_permissions(&snaps, std::fs::Permissions::from_mode(0o700))?;
    let snap = snaps.join(format!("{}-{from}.db", wicket_store::now()));
    ledger.lock().expect("ledger").snapshot(&snap)?;
    let protect: Vec<String> = [Some(from.to_string()), v.pointer("previous")].into_iter().flatten().collect();
    prune_snapshots(&snaps, KEEP_SNAPSHOTS, &protect, false);
    // And off the host, with a state store (#167): an update doesn't switch without it there (the
    // way back past a contract step must survive losing this host); a rollback only warns.
    let stored = match push_snapshot(snap.clone(), KEEP_SNAPSHOTS, protect.clone()).await {
        Ok(k) => k,
        Err(e) if rollback => {
            say(format!("warning: the ledger snapshot isn't in the state store: {e:#}"));
            None
        }
        Err(e) => {
            audit(
                ledger,
                "self.snapshot",
                serde_json::json!({ "path": snap.display().to_string(), "version": from, "schema": schema, "store_error": format!("{e:#}") }),
            );
            bail!("not switching: the ledger snapshot couldn't be pushed to the state store: {e:#}");
        }
    };
    audit(
        ledger,
        "self.snapshot",
        serde_json::json!({ "path": snap.display().to_string(), "version": from, "schema": schema, "store_key": stored }),
    );
    if let Some(k) = &stored {
        say(format!("ledger snapshot {} (and in the state store as {k})", snap.display()));
    }
    v.switch(to)?;
    let kind = if rollback { "self.rolled_back" } else { "self.switched" };
    audit(ledger, kind, serde_json::json!({ "target": "control", "from": from, "to": to, "automatic": false, "by": crate::operator() }));
    say(format!("control host: switched {from} → {to}"));
    let bin = v.binary(to);
    handover(&bin).await?;
    let gate = if rollback { Gate { window: Duration::ZERO, canary: None, ..gate.clone() } } else { gate.clone() };
    match run_gate(ledger, &bin, "control", nodes, &gate).await {
        Ok(()) => {
            audit(ledger, "self.committed", serde_json::json!({ "target": "control", "version": to }));
            say(format!("control host: {to} is healthy"));
            Ok(())
        }
        Err(why) if rollback => bail!("control host: rolled back to {to}, but it isn't healthy: {why}"),
        Err(why) => {
            say(format!("control host: {to} failed its health gate ({why}); rolling back to {from}"));
            v.switch(from)?;
            audit(
                ledger,
                "self.rolled_back",
                serde_json::json!({ "target": "control", "from": to, "to": from, "automatic": true, "why": why }),
            );
            handover(&v.binary(from)).await?;
            match run_gate(
                ledger,
                &v.binary(from),
                "control",
                nodes,
                &Gate { window: Duration::ZERO, canary: None, checks: vec![], ..gate.clone() },
            )
            .await
            {
                Ok(()) => say(format!("control host: back on {from}, healthy")),
                Err(e) => say(format!("control host: back on {from}, but it isn't healthy either: {e}")),
            }
            bail!("the update to {to} failed its health gate on the control host and was rolled back to {from}: {why}")
        }
    }
}

/// How many ledger snapshots are kept (besides those a rollback needs).
pub const KEEP_SNAPSHOTS: usize = 5;

/// The snapshots (`<time>-<version>.db`, the ledger before switching away from that version) to
/// delete: all but the newest `keep`, and never the newest of a version in `protect` (the current
/// and previous versions': a way back past a contract step).
fn snapshots_to_prune(mut names: Vec<String>, keep: usize, protect: &[String]) -> Vec<String> {
    names.retain(|n| n.ends_with(".db"));
    // `<seconds>-<id>.db`: numeric order is time order.
    names.sort_by_key(|n| (n.split('-').next().and_then(|t| t.parse::<i64>().ok()).unwrap_or(0), n.clone()));
    let mut kept_for: Vec<&str> = vec![];
    let mut out = vec![];
    let total = names.len();
    for (i, n) in names.iter().enumerate().rev() {
        let version = n.trim_end_matches(".db").split_once('-').map(|(_, v)| v).unwrap_or("");
        let newest_of_protected = protect.iter().any(|p| p == version) && !kept_for.contains(&version);
        if newest_of_protected {
            kept_for.push(version);
        }
        if total - i > keep && !newest_of_protected {
            out.push(n.clone());
        }
    }
    out.reverse();
    out
}

/// Pushes a snapshot to the state store, if there is one, then prunes the store's copies as the
/// local ones are; returns its key (None: no state store).
async fn push_snapshot(snap: PathBuf, keep: usize, protect: Vec<String>) -> Result<Option<String>> {
    tokio::task::spawn_blocking(move || -> Result<Option<String>> {
        let Some(st) = crate::snapstore::store()? else { return Ok(None) };
        let key = crate::snapstore::push(&st, &snap)?;
        if let Err(e) = prune_store_snapshots(&st, keep, &protect, false) {
            say(format!("warning: pruning the state store's snapshots: {e:#}"));
        }
        Ok(Some(key))
    })
    .await?
}

/// Deletes the store's snapshots `snapshots_to_prune` picks; returns their names.
fn prune_store_snapshots(
    st: &dyn wicket_store::objects::ObjectStore,
    keep: usize,
    protect: &[String],
    dry_run: bool,
) -> Result<Vec<String>> {
    let gone = snapshots_to_prune(crate::snapstore::list(st)?, keep, protect);
    if !dry_run {
        for n in &gone {
            st.delete(&format!("{}{n}", crate::snapstore::PREFIX))?;
        }
    }
    Ok(gone)
}

/// Deletes the snapshots `snapshots_to_prune` picks; returns their names.
fn prune_snapshots(dir: &Path, keep: usize, protect: &[String], dry_run: bool) -> Vec<String> {
    let names = std::fs::read_dir(dir).into_iter().flatten().flatten().filter_map(|e| e.file_name().to_str().map(String::from)).collect();
    let gone = snapshots_to_prune(names, keep, protect);
    if !dry_run {
        for n in &gone {
            let _ = std::fs::remove_file(dir.join(n));
        }
    }
    gone
}

/// Shell (with `$vr`, the versions root, and `$D`, the docker command, set) that removes the
/// versions that are neither `current` nor `previous` nor run by any process here (`/proc/*/exe`),
/// and each one's agent image unless a container (running or not) was made from it. Prints
/// `version <id>`, `image <tag>` and `kept <tag> (…)` lines; with `dry` set, removes nothing.
fn prune_sh(dry: bool) -> String {
    PRUNE_SH.replace("@DRY@", if dry { "true" } else { "false" }).replace("@REPO@", crate::image::REPO)
}

const PRUNE_SH: &str = r#"dry=@DRY@
[ -d "$vr" ] || exit 0
real=$(cd "$vr" && pwd -P)
cur=$(readlink "$vr/current" 2>/dev/null || true)
prev=$(readlink "$vr/previous" 2>/dev/null || true)
used=$(for p in /proc/[0-9]*; do readlink "$p/exe" 2>/dev/null; done | sed -n "s|^$real/\([0-9a-f]\{12\}\)/wicket.*|\1|p" | sort -u)
for d in "$real"/*/; do
  id=$(basename "$d")
  case "$id" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;; *) continue ;; esac
  if [ "$id" = "$cur" ] || [ "$id" = "$prev" ]; then continue; fi
  if printf '%s\n' "$used" | grep -qx "$id"; then echo "kept-version $id (a process runs it)"; continue; fi
  echo "version $id"
  [ "$dry" = true ] || rm -rf "${real:?}/$id"
  tag=@REPO@:$id
  $D image inspect "$tag" >/dev/null 2>&1 || continue
  if [ -n "$($D ps -aq --filter "ancestor=$tag" 2>/dev/null)" ]; then echo "kept $tag (a container uses it)"; continue; fi
  echo "image $tag"
  [ "$dry" = true ] || $D rmi "$tag" >/dev/null
done
"#;

/// What one prune removed (or would): `version <id>`, `image <tag>` and `kept …` lines.
fn prune_report(out: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let pick = |p: &str| out.lines().filter_map(|l| l.strip_prefix(p)).map(String::from).collect::<Vec<_>>();
    let kept = out.lines().filter(|l| l.starts_with("kept")).map(|l| l.split_once(' ').map(|x| x.1).unwrap_or("").to_string()).collect();
    (pick("version "), pick("image "), kept)
}

/// `wicket self prune`: on the control host (unless `only_nodes`) and the nodes named, removes the
/// versions, and their agent images, that nothing needs: neither current nor previous, run by no
/// process, and (for an image) used by no container; and ledger snapshots beyond the newest
/// `keep`, except the newest of the current and previous versions. Each target is audited.
pub async fn prune(nodes: Option<String>, only_nodes: bool, keep: usize, dry_run: bool) -> Result<()> {
    let ledger = Arc::new(Mutex::new(Ledger::open(&crate::ledger_path())?));
    let nodes = match &nodes {
        Some(s) => node_list(&ledger.lock().expect("ledger"), s)?,
        None => vec![],
    };
    let verb = if dry_run { "would remove" } else { "removed" };
    let report = |target: &str, out: &str, snapshots: Vec<String>| {
        let (versions, images, kept) = prune_report(out);
        say(format!(
            "{target}: {verb} {} version(s) [{}], {} image(s) [{}], {} snapshot(s){}",
            versions.len(),
            versions.join(", "),
            images.len(),
            images.join(", "),
            snapshots.len(),
            if kept.is_empty() { String::new() } else { format!("; kept {}", kept.join(", ")) }
        ));
        if !dry_run && (!versions.is_empty() || !images.is_empty() || !snapshots.is_empty()) {
            audit(
                &ledger,
                "self.pruned",
                serde_json::json!({ "target": target, "versions": versions, "images": images, "snapshots": snapshots, "kept": kept, "by": crate::operator() }),
            );
        }
    };
    if !only_nodes {
        let v = Versions::control();
        let docker = std::env::var("WICKET_DOCKER").unwrap_or_else(|_| "docker".into());
        let out = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(prune_sh(dry_run))
            .env("vr", &v.root)
            .env("D", &docker)
            .output()
            .await
            .context("pruning versions")?;
        if !out.status.success() {
            bail!("pruning versions: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        let protect: Vec<String> = [v.pointer("current"), v.pointer("previous")].into_iter().flatten().collect();
        let snapshots = prune_snapshots(&crate::data_dir().join("snapshots"), keep, &protect, dry_run);
        report("control", &String::from_utf8_lossy(&out.stdout), snapshots);
        // The state store's copies (#167), by the same rule.
        let stored = tokio::task::spawn_blocking(move || -> Result<Option<Vec<String>>> {
            match crate::snapstore::store()? {
                Some(st) => Ok(Some(prune_store_snapshots(&st, keep, &protect, dry_run)?)),
                None => Ok(None),
            }
        })
        .await?;
        match stored {
            Ok(Some(gone)) => {
                say(format!("state store: {verb} {} snapshot(s)", gone.len()));
                if !dry_run && !gone.is_empty() {
                    audit(&ledger, "self.pruned", serde_json::json!({ "target": "store", "snapshots": gone, "by": crate::operator() }));
                }
            }
            Ok(None) => {}
            Err(e) => say(format!("warning: pruning the state store's snapshots: {e:#}")),
        }
    }
    for n in &nodes {
        let row = ledger.lock().expect("ledger").node(n)?.with_context(|| format!("node {n} is not enrolled"))?;
        let node = crate::enrol::resolve_installed(&row.name, None)?;
        let out = node.script("pruning versions", &format!("set -u\n{NODE_ROOT}\nD=docker\n{}", prune_sh(dry_run))).await?;
        report(&format!("node:{n}"), &out, vec![]);
    }
    Ok(())
}

/// Moves the control host's processes to `bin` (the version just made current): this host's own
/// node's `serve` re-executes itself (adopting its boxes), runs' supervisors here are stopped
/// without stopping their boxes and `bin`'s reconciler adopts their runs, and the console and the
/// reconciler service re-execute themselves.
async fn handover(bin: &Path) -> Result<()> {
    // Supervisors: a SIGKILL ends one without its box (a SIGTERM would stop the box).
    let mut killed = vec![];
    {
        let l = Ledger::open(&crate::ledger_path())?;
        for (run, owner) in l.running_runs()? {
            let Some(o) = owner else { continue };
            if crate::reap::owner_alive(&o) != Some(true) {
                continue;
            }
            let Some(pid) = o.split(':').nth(1).and_then(|p| p.parse::<i32>().ok()) else { continue };
            if pid as u32 == std::process::id() {
                continue;
            }
            // SAFETY: a plain syscall.
            if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                killed.push(run);
            }
        }
    }
    // This host's own node.
    let local = crate::localnode::pidfile()?;
    if let Some(pid) = hangup(&local, "node serve") {
        for _ in 0..200 {
            if runs(pid, bin, &local) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        say(format!("this host's node: serve (pid {pid}) re-executed as {}", if runs(pid, bin, &local) { "the new build" } else { "?" }));
    }
    for role in ["console", "reconcile"] {
        if let Some(pid) = hangup(&pidfile(role), role) {
            say(format!("{role} (pid {pid}): re-executing"));
        }
    }
    if !killed.is_empty() {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let out = tokio::process::Command::new(bin).arg("reconcile").output().await.context("running the new build's reconcile")?;
        let text = String::from_utf8_lossy(&out.stdout);
        let adopted: Vec<&String> =
            killed.iter().filter(|r| text.lines().any(|l| l.starts_with("run_adopted") && l.contains(r.as_str()))).collect();
        say(format!("runs: {} handed over, {} adopted by the new build", killed.len(), adopted.len()));
        if adopted.len() != killed.len() {
            eprintln!("{text}{}", String::from_utf8_lossy(&out.stderr));
        }
    }
    Ok(())
}

/// Runs the health gate for `target` (`control`, or `node:<name>`) over its window: `bin`'s
/// `wicket self health` (control) and the operator's checks. Each round is audited.
async fn run_gate(ledger: &Mutex<Ledger>, bin: &Path, target: &str, nodes: &[String], g: &Gate) -> std::result::Result<(), String> {
    let deadline = std::time::Instant::now() + g.window;
    let mut round = 0;
    loop {
        round += 1;
        let r = gate_round(bin, target, nodes, g, round == 1).await;
        audit(ledger, "self.health", serde_json::json!({ "target": target, "round": round, "ok": r.is_ok(), "detail": r.as_ref().err() }));
        r?;
        if std::time::Instant::now() + g.interval > deadline {
            return Ok(());
        }
        tokio::time::sleep(g.interval).await;
    }
}

async fn gate_round(bin: &Path, target: &str, nodes: &[String], g: &Gate, first: bool) -> std::result::Result<(), String> {
    if target == "control" {
        let mut c = tokio::process::Command::new(bin);
        c.args(["self", "health", "--node", crate::localnode::NAME]);
        for n in nodes {
            c.args(["--node", n]);
        }
        if let (true, Some(m)) = (first, &g.canary) {
            // `bin` is `<root>/<id>/wicket`.
            let id = bin.parent().and_then(|d| d.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let image = g.image.clone().unwrap_or_else(|| crate::image::tag_for(&id));
            c.arg("--canary").arg(m).args(["--image", &image]);
        }
        let out = tokio::time::timeout(Duration::from_secs(600), c.output())
            .await
            .map_err(|_| "self health timed out".to_string())?
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let o = String::from_utf8_lossy(&out.stdout);
            return Err(format!(
                "self health: {}",
                o.lines().chain(err.lines()).rfind(|l| !l.trim().is_empty()).unwrap_or("failed").trim()
            ));
        }
    }
    for check in &g.checks {
        let st = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(check)
            .env("WICKET", bin)
            .env("WICKET_UPDATE_TARGET", target)
            .stdin(std::process::Stdio::null())
            .status()
            .await
            .map_err(|e| e.to_string())?;
        if !st.success() {
            return Err(format!("check `{check}` failed ({st})"));
        }
    }
    Ok(())
}

// ---- `wicket self health` (run by the new build) ----

/// `wicket self health`: this build opens the ledger (migrating it) and verifies its audit chain,
/// reaches Docker, talks to each node named (this host's own included), and runs the canary.
pub async fn health(nodes: Vec<String>, canary: Option<PathBuf>, image: String) -> Result<()> {
    let d = describe()?;
    println!("build {} (wicket {}, protocol {}, schema {})", &d.build[..12], d.version, d.protocol, d.schema);
    let ledger = Arc::new(Mutex::new(Ledger::open(&crate::ledger_path())?));
    let n = ledger.lock().expect("ledger").verify_audit().context("the audit chain")?;
    println!("ledger: ok ({n} audit records verify)");
    let rt = wicket_sandbox::Docker::from_env().runtimes().await.context("docker")?;
    println!("docker: ok ({})", rt.join(", "));
    for n in &nodes {
        if n == crate::localnode::NAME {
            crate::localnode::ensure(&ledger).await.context("this host's node")?;
        }
        let link = crate::nodecall::Link::connect(n, "self-health", &ledger).await.with_context(|| format!("node {n}"))?;
        println!("node {n}: ok (build {}, protocol {}, {} runs)", &link.build[..12.min(link.build.len())], link.proto, link.runs.len());
    }
    if let Some(m) = canary {
        let out = tokio::time::timeout(
            Duration::from_secs(300),
            tokio::process::Command::new(self_exe()?)
                .arg("run")
                .arg(&m)
                .args(["--image", &image])
                .stdin(std::process::Stdio::null())
                .output(),
        )
        .await
        .context("the canary timed out")??;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("the canary ({}) failed: {}", m.display(), err.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("no output"));
        }
        println!("canary {}: ok", m.display());
    }
    println!("health: ok");
    Ok(())
}

// ---- nodes ----

/// The node's versions root and binary link, in shell (on the node).
const NODE_ROOT: &str = "root=\"${WICKET_NODE_HOME:-$HOME/.local/share/wicket-node}\"; vr=\"$root/versions\"";

/// Pushes a binary to a node as version `id` (checked against `sha` there), makes it current there
/// and links `~/.local/bin/wicket` to it. Returns what was current on the node.
pub async fn push_version(node: &crate::node::Node, bytes: &[u8], sha: &str) -> Result<Option<String>> {
    let id = &sha[..12];
    node.sh(&format!("{NODE_ROOT}; mkdir -p \"$vr\" && chmod 755 \"$vr\"")).await?;
    let vr = node.sh(&format!("{NODE_ROOT}; echo \"$vr\"")).await?;
    let incoming = format!("{vr}/.incoming-{id}");
    node.put(&incoming, bytes).await?;
    let script = format!(
        "set -eu\n{NODE_ROOT}\ncd \"$vr\"\n\
         echo '{sha}  .incoming-{id}' | sha256sum -c --quiet\n\
         if [ -f {id}/wicket ] && echo '{sha}  {id}/wicket' | sha256sum -c --quiet 2>/dev/null; then rm -f .incoming-{id}; else\n\
           rm -rf {id}.new && mkdir -m 755 {id}.new && chmod 755 .incoming-{id} && mv -f .incoming-{id} {id}.new/wicket && rm -rf {id} && mv {id}.new {id}\nfi\n\
         {SWITCH}\n",
        SWITCH = node_switch_sh(id)
    );
    let prev = node.script("staging and switching the new version", &script).await?;
    Ok(prev.lines().last().filter(|p| valid_id(p)).map(String::from))
}

/// Shell (in `$vr`, `$root` set) that makes `id` current, the old current previous, links the
/// binary, and prints what was current (or `none`).
fn node_switch_sh(id: &str) -> String {
    format!(
        "cd \"$vr\"\ncur=$(readlink current 2>/dev/null || true)\n\
         if [ \"$cur\" != {id} ]; then\n  if [ -n \"$cur\" ]; then ln -sfn \"$cur\" .previous.tmp && mv -Tf .previous.tmp previous; fi\n  ln -sfn {id} .current.tmp && mv -Tf .current.tmp current\nfi\n\
         mkdir -p \"$HOME/.local/bin\"\nln -sfn \"$vr/current/wicket\" \"$HOME/.local/bin/.wicket.tmp\" && mv -Tf \"$HOME/.local/bin/.wicket.tmp\" \"$HOME/.local/bin/wicket\"\n\
         echo \"${{cur:-none}}\""
    )
}

/// Restarts a node's `serve` on the current version: SIGHUP (it re-executes itself and adopts its
/// boxes), or its systemd user service. Returns how.
pub async fn restart_node_serve(node: &crate::node::Node) -> Result<String> {
    node.script(
        "restarting wicket node serve",
        &format!(
            "set -eu\n{NODE_ROOT}\npid=$(cat \"$root/serve.pid\" 2>/dev/null || true)\n\
             if [ -n \"$pid\" ] && tr '\\0' ' ' </proc/$pid/cmdline 2>/dev/null | grep -q 'node serve'; then kill -HUP \"$pid\"; echo \"re-executed (pid $pid)\"\n\
             elif [ -f \"$HOME/.config/systemd/user/wicket-node.service\" ]; then export XDG_RUNTIME_DIR=/run/user/$(id -u); systemctl --user restart wicket-node; echo restarted the wicket-node service\n\
             else echo 'not running (it starts on the new version)'; fi\n"
        ),
    )
    .await
}

/// The node's control connection, as the control host sees it: (build, run ids), or why not.
async fn node_state(ledger: &Arc<Mutex<Ledger>>, name: &str) -> Result<(String, Vec<String>)> {
    let link = crate::nodecall::Link::connect(name, "self-update", ledger).await?;
    Ok((link.build.clone(), link.runs.iter().filter(|r| r.exited.is_none()).map(|r| r.run.clone()).collect()))
}

/// Waits until the node answers as build `sha`; returns its live runs.
async fn wait_node(ledger: &Arc<Mutex<Ledger>>, name: &str, sha: &str) -> std::result::Result<Vec<String>, String> {
    let mut last = String::new();
    for _ in 0..60 {
        match node_state(ledger, name).await {
            Ok((b, runs)) if b == sha => return Ok(runs),
            Ok((b, _)) => last = format!("it answers as build {}", &b[..12.min(b.len())]),
            Err(e) => last = format!("{e:#}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!("node {name} did not come back as {}: {last}", &sha[..12]))
}

/// Updates one node to `green`, gated; on failure, switches it back and fails.
async fn node_update(ledger: &Arc<Mutex<Ledger>>, v: &Versions, name: &str, green: &str, g: &Gate, canary: bool) -> Result<()> {
    let row = ledger.lock().expect("ledger").node(name)?.with_context(|| format!("node {name} is not enrolled"))?;
    let node = crate::enrol::resolve_installed(&row.name, None)?;
    let bin = v.binary(green);
    let sha = v.manifest(green)?.describe.build;
    let before = match node_state(ledger, name).await {
        Ok((b, _)) if b == sha => {
            say(format!("node {name}: already runs {green}"));
            return Ok(());
        }
        Ok((_, runs)) => runs,
        Err(e) => bail!("node {name}: can't reach it before updating it ({e:#}); nothing changed there"),
    };
    // The version's image first, so the node's new boxes have it the moment it switches.
    ensure_image_on_node(&node, &crate::image::tag_for(green)).await.with_context(|| format!("node {name}: nothing changed there"))?;
    let bytes = std::fs::read(&bin)?;
    let prev = push_version(&node, &bytes, &sha).await?;
    audit(
        ledger,
        "self.switched",
        serde_json::json!({ "target": format!("node:{name}"), "from": prev, "to": green, "canary": canary, "by": crate::operator() }),
    );
    let how = restart_node_serve(&node).await?;
    say(format!(
        "node {name}{}: switched {} → {green}; serve {how}",
        if canary { " (canary)" } else { "" },
        prev.as_deref().unwrap_or("?")
    ));
    let target = format!("node:{name}");
    let r = match wait_node(ledger, name, &sha).await {
        Ok(after) => match before.iter().find(|r| !after.contains(r)) {
            Some(lost) => Err(format!("run {lost}'s box was running before the update and isn't now")),
            None => run_gate(ledger, &bin, &target, &[], &Gate { canary: None, ..g.clone() }).await,
        },
        Err(e) => Err(e),
    };
    match r {
        Ok(()) => {
            audit(ledger, "self.committed", serde_json::json!({ "target": target, "version": green }));
            say(format!("node {name}: {green} is healthy ({} runs kept)", before.len()));
            Ok(())
        }
        Err(why) => {
            say(format!("node {name}: {green} failed its health gate ({why}); rolling it back"));
            let back = node_rollback(ledger, &node, name).await;
            audit(
                ledger,
                "self.rolled_back",
                serde_json::json!({ "target": target, "from": green, "to": back.as_ref().ok(), "automatic": true, "why": why }),
            );
            let back = back?;
            bail!("the update of node {name} to {green} failed its health gate and was rolled back to {back}: {why}; the rollout stopped")
        }
    }
}

/// Switches a node back to its previous version and restarts its serve. Returns that version.
async fn node_rollback(ledger: &Arc<Mutex<Ledger>>, node: &crate::node::Node, name: &str) -> Result<String> {
    let prev = node.sh(&format!("{NODE_ROOT}; readlink \"$vr/previous\" 2>/dev/null || true")).await?;
    if !valid_id(&prev) {
        bail!("node {name} has no previous version");
    }
    node.script("switching back", &format!("set -eu\n{NODE_ROOT}\n{}\n", node_switch_sh(&prev))).await?;
    restart_node_serve(node).await?;
    let sha = node.sh(&format!("{NODE_ROOT}; sha256sum \"$vr/{prev}/wicket\" | cut -d' ' -f1")).await?;
    wait_node(ledger, name, &sha).await.map_err(|e| anyhow::anyhow!(e))?;
    Ok(prev)
}

/// `wicket self rollback`: the control host (unless `only_nodes`) and the nodes named, back to
/// their previous versions.
pub async fn rollback(nodes: Option<String>, only_nodes: bool) -> Result<()> {
    let _one = update_lock()?;
    let ledger = Arc::new(Mutex::new(Ledger::open(&crate::ledger_path())?));
    let nodes = match &nodes {
        Some(s) => node_list(&ledger.lock().expect("ledger"), s)?,
        None => vec![],
    };
    let gate = Gate { window: Duration::ZERO, interval: Duration::from_secs(1), checks: vec![], canary: None, image: None };
    if !only_nodes {
        let v = Versions::control();
        let cur = v.pointer("current").context("nothing to roll back: no versions here (wicket self status)")?;
        let prev = v.pointer("previous").context("no previous version to roll back to")?;
        control_switch(&ledger, &v, &cur, &prev, &nodes, &gate, true).await?;
    }
    for n in &nodes {
        let row = ledger.lock().expect("ledger").node(n)?.with_context(|| format!("node {n} is not enrolled"))?;
        let node = crate::enrol::resolve_installed(&row.name, None)?;
        let cur = node.sh(&format!("{NODE_ROOT}; readlink \"$vr/current\" 2>/dev/null || true")).await?;
        let to = node_rollback(&ledger, &node, n).await?;
        audit(
            &ledger,
            "self.rolled_back",
            serde_json::json!({ "target": format!("node:{n}"), "from": cur, "to": to, "automatic": false, "by": crate::operator() }),
        );
        say(format!("node {n}: rolled back {cur} → {to}"));
    }
    if !only_nodes {
        if let Some(pid) = hangup(&pidfile("daemon"), "daemon") {
            say(format!("wicketd (pid {pid}) moves back when its running commands end"));
        }
    }
    Ok(())
}

/// `wicket self status`.
pub fn status() -> Result<()> {
    let v = Versions::control();
    println!("versions: {}", v.root.display());
    let (cur, prev) = (v.pointer("current"), v.pointer("previous"));
    let mut ids: Vec<String> = std::fs::read_dir(&v.root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| valid_id(n))
        .collect();
    ids.sort();
    if ids.is_empty() {
        println!("  none: this installation hasn't been updated with `wicket self update` (running {})", &describe()?.build[..12]);
    }
    for id in ids {
        let mark = if cur.as_deref() == Some(&id) {
            "current "
        } else if prev.as_deref() == Some(&id) {
            "previous"
        } else {
            "        "
        };
        match v.manifest(&id) {
            Ok(m) => println!(
                "  {mark} {id}  wicket {}  protocol {}  schema {}  {}",
                m.describe.version, m.describe.protocol, m.describe.schema, m.source
            ),
            Err(e) => println!("  {mark} {id}  ({e:#})"),
        }
    }
    let s = Ledger::schema_of(&crate::ledger_path()).ok();
    if let Some(s) = s {
        println!("ledger: schema {}, floor {} (versions below the floor can't open it)", s.version, s.floor);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-self-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A CI signature (#190) as the `sign` job makes one: the claims' bytes as given, signed after
    /// [`CI_DOMAIN`].
    fn ci_sign(k: &wicket_identity::SigningKey, payload: &[u8], sha: &str) -> Signature {
        use ed25519_dalek::Signer;
        let mut msg = CI_DOMAIN.to_vec();
        msg.extend_from_slice(payload);
        Signature {
            alg: "ed25519".into(),
            key: B64.encode(k.verifying_key().to_bytes()),
            sha256: sha.into(),
            sig: B64.encode(k.sign(&msg).to_bytes()),
            payload: Some(B64.encode(payload)),
        }
    }

    fn claims_json(sha: &str, commit: &str, git_ref: &str, environment: &str, signed_at: i64) -> String {
        // Keys in another order than the struct's, and spaced: what is verified is these bytes.
        format!(
            r#"{{"signed_at": {signed_at}, "v": 1, "sha256": "{sha}", "artifact": "wicket-0.0.1-{c}-x86_64-linux.tar.gz", "repo": "acme/wicket", "commit": "{commit}", "ref": "{git_ref}", "workflow": ".github/workflows/build.yml", "run_id": 42, "run_attempt": 1, "environment": "{environment}"}}"#,
            c = &commit[..12]
        )
    }

    /// #190: a CI signature verifies only for its artifact and a trusted key, over the claims' bytes
    /// as signed; `--from-ci` takes it only for this repository, workflow, commit, main and the
    /// release environment, signed in the past; a plain (sha-only) signature from the same key
    /// isn't one.
    #[test]
    fn a_ci_signature_binds_the_commit_main_and_the_release_environment() {
        let k = wicket_identity::SigningKey::from_bytes(&[7; 32]);
        let trusted = [k.verifying_key().to_bytes()];
        let sha = "ab".repeat(32);
        let commit = "c0ffee".repeat(6) + "c0ff";
        let now = 1_800_000_000;
        let e = CiExpect { repo: "acme/wicket".into(), workflow: ".github/workflows/build.yml".into(), commit: commit.clone() };
        let ok = ci_sign(&k, claims_json(&sha, &commit, CI_REF, CI_ENVIRONMENT, now - 60).as_bytes(), &sha);
        let (_, c) = verify_ci_sig(&ok, &sha, &trusted).unwrap();
        check_claims(&c, &e, now).unwrap();
        assert!(verify_sig(&ok, &sha, &trusted).is_ok(), "a plain update takes it too");
        assert!(verify_ci_sig(&ok, &sha, &[]).unwrap_err().to_string().contains("doesn't trust"));
        assert!(verify_ci_sig(&ok, &"cd".repeat(32), &trusted).unwrap_err().to_string().contains("another artifact"));
        // The claims edited after signing (their bytes changed): refused.
        let mut edited = ok.clone();
        edited.payload = Some(B64.encode(claims_json(&sha, &commit, CI_REF, CI_ENVIRONMENT, now - 60).replace("acme", "evil")));
        assert!(verify_ci_sig(&edited, &sha, &trusted).unwrap_err().to_string().contains("doesn't verify"));
        // A sha-only signature from the same key isn't a CI signature.
        let plain =
            Signature { alg: "ed25519".into(), key: ok.key.clone(), sha256: sha.clone(), sig: ed25519_sign(&k, &sha), payload: None };
        assert!(verify_sig(&plain, &sha, &trusted).is_ok());
        assert!(verify_ci_sig(&plain, &sha, &trusted).unwrap_err().to_string().contains("no claims"));
        // Each claim must be what was asked for.
        let refused = |payload: String, e: &CiExpect| {
            let s = ci_sign(&k, payload.as_bytes(), &sha);
            let (_, c) = verify_ci_sig(&s, &sha, &trusted).unwrap();
            check_claims(&c, e, now).unwrap_err().to_string()
        };
        assert!(refused(claims_json(&sha, &commit, "refs/heads/feature", CI_ENVIRONMENT, now), &e).contains("not refs/heads/main"));
        assert!(refused(claims_json(&sha, &commit, CI_REF, "staging", now), &e).contains("not release"));
        assert!(refused(claims_json(&sha, &commit, CI_REF, CI_ENVIRONMENT, now + 3600), &e).contains("future"));
        let other = CiExpect { commit: "d".repeat(40), ..e.clone() };
        assert!(refused(claims_json(&sha, &commit, CI_REF, CI_ENVIRONMENT, now), &other).contains("not dddd"));
        let fork = CiExpect { repo: "someone/wicket".into(), ..e.clone() };
        assert!(refused(claims_json(&sha, &commit, CI_REF, CI_ENVIRONMENT, now), &fork).contains("not someone/wicket"));
    }

    /// #190: the `sign` job signs with openssl (no build output touches the key), and its public
    /// key is PEM: both read here as the workflow makes them.
    #[test]
    fn an_openssl_signature_and_pem_key_verify() {
        let d = tmp("openssl");
        let run = |args: &[&str]| std::process::Command::new("openssl").args(args).current_dir(&d).output();
        if !run(&["version"]).is_ok_and(|o| o.status.success()) {
            eprintln!("skipped: no openssl");
            return;
        }
        assert!(run(&["genpkey", "-algorithm", "ed25519", "-out", "k.pem"]).unwrap().status.success());
        assert!(run(&["pkey", "-in", "k.pem", "-pubout", "-out", "k.pub.pem"]).unwrap().status.success());
        let sha = "ef".repeat(32);
        let commit = "1".repeat(40);
        let payload = claims_json(&sha, &commit, CI_REF, CI_ENVIRONMENT, 1_700_000_000);
        let mut msg = CI_DOMAIN.to_vec();
        msg.extend_from_slice(payload.as_bytes());
        std::fs::write(d.join("msg"), &msg).unwrap();
        let o = run(&["pkeyutl", "-sign", "-rawin", "-inkey", "k.pem", "-in", "msg", "-out", "sig.bin"]).unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let public = read_public(&d.join("k.pub.pem")).unwrap();
        let s = Signature {
            alg: "ed25519".into(),
            key: B64.encode(public),
            sha256: sha.clone(),
            sig: B64.encode(std::fs::read(d.join("sig.bin")).unwrap()),
            payload: Some(B64.encode(&payload)),
        };
        let (_, c) = verify_ci_sig(&s, &sha, &[public]).unwrap();
        assert_eq!((c.commit.as_str(), c.run_id), (commit.as_str(), 42));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_release_signature_verifies_only_for_its_artifact_and_a_trusted_key() {
        let d = tmp("sig");
        keygen(&d.join("k")).unwrap();
        let art = d.join("a.bin");
        std::fs::write(&art, b"build A").unwrap();
        sign(&d.join("k"), &art).unwrap();
        let s: Signature = serde_json::from_slice(&std::fs::read(d.join("a.bin.sig")).unwrap()).unwrap();
        let sha = sha256_file(&art).unwrap();
        let k = read_public(&d.join("k.pub")).unwrap();
        assert!(verify_sig(&s, &sha, &[k]).is_ok());
        assert!(verify_sig(&s, &sha, &[]).unwrap_err().to_string().contains("doesn't trust"));
        assert!(verify_sig(&s, &"00".repeat(32), &[k]).unwrap_err().to_string().contains("another artifact"));
        // A signature over another hash, relabelled: doesn't verify.
        let mut forged = serde_json::from_slice::<Signature>(&std::fs::read(d.join("a.bin.sig")).unwrap()).unwrap();
        forged.sha256 = "11".repeat(32);
        assert!(verify_sig(&forged, &"11".repeat(32), &[k]).unwrap_err().to_string().contains("doesn't verify"));
        // The key file is private.
        assert_eq!(std::fs::metadata(d.join("k")).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn switching_keeps_current_and_previous() {
        let d = tmp("switch");
        let v = Versions { root: d.clone() };
        for id in ["aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"] {
            std::fs::create_dir_all(d.join(id)).unwrap();
            std::fs::write(d.join(id).join("wicket"), id).unwrap();
        }
        assert_eq!(v.switch("aaaaaaaaaaaa").unwrap(), None);
        assert_eq!(v.switch("bbbbbbbbbbbb").unwrap().as_deref(), Some("aaaaaaaaaaaa"));
        assert_eq!((v.pointer("current").unwrap().as_str(), v.pointer("previous").unwrap().as_str()), ("bbbbbbbbbbbb", "aaaaaaaaaaaa"));
        // Rolling back is a switch to previous: they trade places.
        v.switch("aaaaaaaaaaaa").unwrap();
        assert_eq!((v.pointer("current").unwrap().as_str(), v.pointer("previous").unwrap().as_str()), ("aaaaaaaaaaaa", "bbbbbbbbbbbb"));
        assert_eq!(std::fs::read_to_string(d.join("current/wicket")).unwrap(), "aaaaaaaaaaaa");
        assert!(v.switch("dddddddddddd").is_err(), "not staged");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_node_switch_script_moves_current_previous_and_the_binary_link() {
        let d = tmp("nodesh");
        let vr = d.join("versions");
        for id in ["aaaaaaaaaaaa", "bbbbbbbbbbbb"] {
            std::fs::create_dir_all(vr.join(id)).unwrap();
        }
        let run = |id: &str| {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("set -eu\n{NODE_ROOT}\n{}", node_switch_sh(id)))
                .env("HOME", &d)
                .env("WICKET_NODE_HOME", &d)
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        assert_eq!(run("aaaaaaaaaaaa"), "none");
        assert_eq!(run("bbbbbbbbbbbb"), "aaaaaaaaaaaa");
        let v = Versions { root: vr.clone() };
        assert_eq!((v.pointer("current").as_deref(), v.pointer("previous").as_deref()), (Some("bbbbbbbbbbbb"), Some("aaaaaaaaaaaa")));
        assert_eq!(std::fs::read_link(d.join(".local/bin/wicket")).unwrap(), vr.join("current/wicket"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn snapshots_keep_the_newest_and_whatever_a_rollback_needs() {
        let names: Vec<String> = [
            "100-aaaaaaaaaaaa.db",
            "200-bbbbbbbbbbbb.db",
            "300-cccccccccccc.db",
            "400-dddddddddddd.db",
            "1000-eeeeeeeeeeee.db",
            "notes.txt",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Numeric, not lexical, order: 1000 is the newest.
        assert_eq!(snapshots_to_prune(names.clone(), 2, &[]), ["100-aaaaaaaaaaaa.db", "200-bbbbbbbbbbbb.db", "300-cccccccccccc.db"]);
        // The previous version's snapshot stays, however old.
        assert_eq!(snapshots_to_prune(names.clone(), 2, &["aaaaaaaaaaaa".into()]), ["200-bbbbbbbbbbbb.db", "300-cccccccccccc.db"]);
        assert!(snapshots_to_prune(names, 10, &[]).is_empty());
        // Only the newest of a protected version is protected.
        let two = vec!["1-aaaaaaaaaaaa.db".to_string(), "2-aaaaaaaaaaaa.db".to_string()];
        assert_eq!(snapshots_to_prune(two, 0, &["aaaaaaaaaaaa".into()]), ["1-aaaaaaaaaaaa.db"]);
    }

    #[test]
    fn prune_keeps_current_previous_running_versions_and_used_images() {
        let d = tmp("prune");
        let vr = d.join("versions");
        let ids = ["aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc", "dddddddddddd", "eeeeeeeeeeee"];
        for id in ids {
            std::fs::create_dir_all(vr.join(id)).unwrap();
            std::fs::copy("/bin/sleep", vr.join(id).join("wicket")).unwrap();
        }
        std::fs::create_dir_all(vr.join("not-a-version")).unwrap();
        let v = Versions { root: vr.clone() };
        v.switch("aaaaaaaaaaaa").unwrap();
        v.switch("bbbbbbbbbbbb").unwrap();
        // A process runs dddddddddddd.
        let mut running = std::process::Command::new(vr.join("dddddddddddd/wicket")).arg("30").spawn().unwrap();
        // A docker stand-in: every version has an image, and a container uses eeeeeeeeeeee's.
        let fake = d.join("docker");
        let log = d.join("rmi.log");
        std::fs::write(
            &fake,
            format!(
                "case \"$1 $2\" in\n  'image inspect') exit 0 ;;\n  'ps -aq') case \"$4\" in *eeeeeeeeeeee) echo c1 ;; esac ;;\n  'rmi '*) echo \"$2\" >> {} ;;\nesac\n",
                log.display()
            ),
        )
        .unwrap();
        let run = |dry: bool| {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(prune_sh(dry))
                .env("vr", &vr)
                .env("D", format!("sh {}", fake.display()))
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            prune_report(&String::from_utf8_lossy(&out.stdout))
        };
        let (versions, images, kept) = run(true);
        assert_eq!(versions, ["cccccccccccc", "eeeeeeeeeeee"]);
        assert_eq!(images, ["wicket/claude-code:cccccccccccc"]);
        assert!(kept.iter().any(|k| k.starts_with("dddddddddddd")) && kept.iter().any(|k| k.contains("eeeeeeeeeeee")), "{kept:?}");
        assert!(vr.join("cccccccccccc").exists() && !log.exists(), "a dry run removes nothing");
        let (versions, _, _) = run(false);
        assert_eq!(versions, ["cccccccccccc", "eeeeeeeeeeee"]);
        for (id, there) in
            [("aaaaaaaaaaaa", true), ("bbbbbbbbbbbb", true), ("cccccccccccc", false), ("dddddddddddd", true), ("eeeeeeeeeeee", false)]
        {
            assert_eq!(vr.join(id).exists(), there, "{id}");
        }
        assert!(vr.join("not-a-version").exists());
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "wicket/claude-code:cccccccccccc\n");
        let _ = running.kill();
        let _ = running.wait();
        std::fs::remove_dir_all(&d).unwrap();
    }
}
