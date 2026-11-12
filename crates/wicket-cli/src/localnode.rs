//! The built-in local node (#146): the control host runs its own boxes as a node like any other.
//!
//! `wicket run` without `--node` places the box on node [`NAME`], served by the same `wicket node
//! serve` runtime as a remote node and reached over its unix socket instead of ssh. The control
//! host makes and enrols it itself, the first time a run needs it:
//!
//! - **Its directory** is `<data dir>/local-node/`: a node key (made here with `openssl`, as on a
//!   remote node), the installation's public keys, and `node.json` with `"shares_host": true`. It
//!   gets no node CA: every host it would decide is forwarded to the run's own proxies.
//! - **Enrolment** records it in the ledger like any node (target `unix:<socket>`, no ssh host key)
//!   and issues its identity certificate; the control host renews the certificate itself when a run
//!   finds it past half its life, so an installation idle for days still starts boxes.
//! - **One `serve` per build.** The node refuses a control host with another build, so each build
//!   has its own subdirectory (`<build id prefix>/`) and its own `serve`, started on demand (detached,
//!   its log in `serve.log` there) and exiting once it has had no boxes and no connections for a while
//!   (10 minutes; `WICKET_LOCAL_NODE_IDLE_SECS`). A `serve` from before an upgrade keeps the boxes
//!   it runs until they end.
//! - **What sharing the filesystem means.** The control host lays out the box itself, in the run's own
//!   directory ([`crate::chan::HostBox`]): its sockets are the run's proxies, its workspace, state,
//!   `/tmp` and volumes are where they always were. That is how hibernation, wrapped sessions and
//!   in-place workspaces keep working; a node that doesn't share the filesystem refuses such a box.

use anyhow::{bail, Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use wicket_store::Ledger;

/// The built-in node's name (reserved: `wicket node enrol` refuses it).
pub const NAME: &str = "local";

/// How long the local node's identity certificate lasts.
const CERT_TTL: i64 = 86_400;

fn root() -> PathBuf {
    crate::data_dir().join("local-node")
}

/// This build's serving directory.
fn build_dir() -> Result<PathBuf> {
    Ok(root().join(&crate::nodesrv::build_id()?[..12]))
}

/// This build's control socket.
pub fn socket() -> Result<PathBuf> {
    Ok(crate::nodesrv::NodePaths::new(Some(build_dir()?)).socket())
}

/// The files every build's directory gets (copied from the node's own).
const SHARED: &[&str] = &["node.key", "node.pub", "root.pem", "feed-root.pub", "authz-root.pub", "issuer.pub.json", "node.json"];

/// Makes, enrols and starts the local node as needed; returns once its `serve` answers.
pub async fn ensure(ledger: &std::sync::Mutex<Ledger>) -> Result<()> {
    let dir = build_dir()?;
    {
        let _lock = lock(&root().join("enrol.lock"))?;
        enrol(ledger)?;
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        for f in SHARED {
            let (from, to) = (root().join(f), dir.join(f));
            if from.exists() && std::fs::read(&from).ok() != std::fs::read(&to).ok() {
                std::fs::copy(&from, &to).with_context(|| format!("copying {f} for the local node"))?;
            }
        }
        renew_cert(ledger, &dir)?;
    }
    let sock = socket()?;
    if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
        return Ok(());
    }
    start_serve(&dir)?;
    for _ in 0..200 {
        if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let log = std::fs::read_to_string(dir.join("serve.log")).unwrap_or_default();
    bail!("the local node did not start: {}", log.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no output"))
}

fn lock(path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
    }
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(path)?;
    // SAFETY: flock on a file descriptor this function owns.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error()).context("locking the local node");
    }
    Ok(f)
}

/// Makes the node's key and files, and records it, if that isn't done yet.
fn enrol(ledger: &std::sync::Mutex<Ledger>) -> Result<()> {
    let dir = root();
    let row = ledger.lock().expect("ledger").node(NAME)?;
    match &row {
        Some(r) if !r.target.starts_with("unix:") => {
            bail!("an enrolled node is named {NAME:?}, which is now the built-in local node's name: revoke it (wicket node revoke {NAME}) and enrol it under another name")
        }
        Some(r) if r.status != "active" => bail!("the local node was revoked: boxes can't run on this host until its directory {} is removed", dir.display()),
        Some(_) if dir.join("node.key").exists() => return Ok(()),
        _ => {}
    }
    // The node's own key, made as a remote node makes it.
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg("set -eu; umask 077; rm -f node.key.new; openssl genpkey -algorithm ed25519 -out node.key.new && openssl pkey -in node.key.new -pubout && mv -f node.key.new node.key")
        .current_dir(&dir)
        .output()
        .context("running openssl")?;
    if !out.status.success() {
        bail!("making the local node's key: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let pem = std::fs::read_to_string(dir.join("node.key"))?;
    let key = wicket_identity::node::signing_key_from_pkcs8_pem(&pem).context("node.key")?;
    let node_key = hex::encode(key.verifying_key().to_bytes());
    let paths = crate::enrol::Paths::installation();
    let ca = wicket_proxy::ca::InstallationCa::load_or_create(&paths.ca_key)?;
    let feed_root = wicket_identity::load_or_create_feed_root(&paths.feed_root_key)?;
    let authz_root = crate::enrol::token_key(&paths.authz_root_key)?.public();
    let issuer = crate::issuer()?;
    let now = wicket_store::now();
    let files: [(&str, String); 6] = [
        ("node.pub", String::from_utf8_lossy(&out.stdout).to_string()),
        ("root.pem", ca.cert_pem().to_string()),
        ("feed-root.pub", hex::encode(feed_root.to_bytes())),
        ("authz-root.pub", authz_root.to_hex()),
        ("issuer.pub.json", serde_json::to_string_pretty(&issuer.public_jwk())?),
        ("node.json", serde_json::to_string_pretty(&serde_json::json!({ "name": NAME, "node_key": node_key, "shares_host": true, "enrolled_at": now }))?),
    ];
    for (f, body) in files {
        std::fs::write(dir.join(f), body)?;
        std::fs::set_permissions(dir.join(f), std::fs::Permissions::from_mode(0o600))?;
    }
    let row = wicket_store::NodeRow {
        name: NAME.into(),
        tenant: wicket_core::TenantId::single().0,
        target: format!("unix:{}", dir.display()),
        host_key: String::new(),
        host_key_fp: String::new(),
        node_key: node_key.clone(),
        ssh_key: None,
        hosts: vec![],
        enrolled_at: now,
        status: "active".into(),
        revoked_at: None,
    };
    let l = ledger.lock().expect("ledger");
    l.enrol_builtin_node(&row)?;
    l.audit(
        &wicket_core::TenantId::single(),
        None,
        "node.enrolled",
        &serde_json::json!({ "name": NAME, "target": row.target, "node_key": node_key, "builtin": true }),
    )?;
    println!("[wicket] made this host's built-in node {NAME:?} ({})", dir.display());
    Ok(())
}

/// A fresh identity certificate for this build's directory, if it has none or it is past half its life.
fn renew_cert(ledger: &std::sync::Mutex<Ledger>, dir: &std::path::Path) -> Result<()> {
    let issuer = crate::issuer()?;
    let now = wicket_store::now();
    let held = std::fs::read_to_string(dir.join(crate::nodeauth::CERT_FILE)).ok();
    let current = held.and_then(|c| wicket_identity::node::verify_node_cert(c.trim(), &issuer.verifying_key(), NAME, now).ok());
    if current.is_some_and(|c| !crate::nodeauth::due(&c, now)) {
        return Ok(());
    }
    let l = ledger.lock().expect("ledger");
    let row = l.node(NAME)?.context("the local node is not enrolled")?;
    let key = crate::nodeauth::enrolled_key(&row.node_key)?;
    let (jws, _) = crate::nodeauth::issue(&l, &issuer, NAME, &key, now, CERT_TTL)?;
    let tmp = dir.join(format!("{}.new", crate::nodeauth::CERT_FILE));
    std::fs::write(&tmp, format!("{jws}\n"))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, dir.join(crate::nodeauth::CERT_FILE))?;
    Ok(())
}

/// Starts this build's `serve`, detached from this run (it outlives it, and serves the next).
fn start_serve(dir: &std::path::Path) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().context("finding this binary")?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("serve.log"))?;
    let idle = std::env::var("WICKET_LOCAL_NODE_IDLE_SECS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(600);
    let mut c = std::process::Command::new(exe);
    c.args(["node", "serve", "--idle-exit", &idle.to_string(), "--dir"])
        .arg(dir)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    // SAFETY: setsid in the child before exec: its own session, so a ^C or SIGHUP to this run's
    // terminal doesn't reach it.
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    c.spawn().context("starting the local node")?;
    Ok(())
}
