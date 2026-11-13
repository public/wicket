//! `wicket state` (#154): control-plane state off the host, and a restore onto a standby.
//!
//! What a control host holds, and where it goes:
//!
//! | What | Where |
//! |---|---|
//! | The ledger (runs, agents, grants, nodes, passkeys, the audit chain) | Streamed to the state store by Litestream (`wicket state replicate`), seconds behind |
//! | Hibernated agents' bundles | The state store (`bundles: s3`), sealed under `state.key` |
//! | Audit records and signed checkpoints | The state store, by an audit sink of type `store` |
//! | Keys that rarely change: the identity issuer, the installation CA, the approver, `state.key`, nodes' feed keys and pinned host keys, the vault, the config files | The recovery kit (`wicket state kit`), kept offline by the operator |
//! | The feed root and the authority root | Offline (`wicket keys roots-offline`), or in the kit |
//! | Run directories (transcripts, workspaces), this host's own node, feed delta logs | Not kept: runs that were running end as lost, the node is made again, each feed starts a new generation |
//!
//! `wicket state restore` puts a kit and the streamed ledger back on a fresh host. See
//! docs/how-to/state-off-host-and-restore.md for the procedure.

use crate::statestore::{LedgerStream, StateStore};
use crate::{data_dir, ledger_path};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// How far a restore moves every agent's generation (see [`wicket_store::Ledger::bump_agent_generations`]).
const GENERATION_BUMP: i64 = 1000;

fn identity_dir() -> PathBuf {
    crate::issuer_key_path().parent().expect("the identity dir").to_path_buf()
}

fn vault_dir() -> PathBuf {
    wicket_proxy::vault::Vault::default_dir()
}

// ---- the ledger's lineages ----
//
// Each control host streams the ledger to a path of its own, `ledger/<lineage>/`: a restored
// standby must not continue the lost host's stream (Litestream would see a database behind its
// replica), and a restore to a point in time must find the stream that was current then. The store
// keeps the list, `ledger/lineages.json`; this host's own lineage is `<data dir>/ledger-lineage`.

const LINEAGES: &str = "ledger/lineages.json";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Lineage {
    id: String,
    /// When it started (Unix ms).
    since: i64,
}

fn lineage_file() -> PathBuf {
    data_dir().join("ledger-lineage")
}

fn lineages(st: &crate::s3::S3Store) -> Result<Vec<Lineage>> {
    use wicket_store::objects::ObjectStore;
    let Some(mut r) = st.get(LINEAGES)? else { return Ok(vec![]) };
    let mut b = vec![];
    std::io::Read::read_to_end(&mut r, &mut b)?;
    serde_json::from_slice(&b).context("ledger/lineages.json")
}

/// Starts a new lineage for this host: recorded here and appended to the store's list.
fn new_lineage(st: &crate::s3::S3Store, mut list: Vec<Lineage>) -> Result<String> {
    let id = ulid::Ulid::new().to_string().to_lowercase();
    list.push(Lineage { id: id.clone(), since: wicket_feed::now_ms() });
    st.put_overwrite(LINEAGES, serde_json::to_vec(&list)?)?;
    std::fs::write(lineage_file(), &id)?;
    Ok(id)
}

/// This host's lineage, if it may stream: started here on first use, refused if another host has
/// taken over the store (restored from it) since.
fn my_lineage(st: &crate::s3::S3Store) -> Result<String> {
    let list = lineages(st)?;
    let mine = std::fs::read_to_string(lineage_file()).ok().map(|s| s.trim().to_string());
    match (mine, list.last()) {
        (Some(m), Some(last)) if last.id == m => Ok(m),
        (Some(m), Some(last)) => bail!(
            "another control host restored from this state store and streams to it now (lineage {}, this host's {m}): this host must not; restore it from the store if it is to take over again",
            last.id
        ),
        (Some(m), None) => bail!("the state store has no ledger lineages, but this host streamed as {m}: is state-store.yaml pointing at another store?"),
        (None, Some(last)) => bail!(
            "the state store already holds another installation's ledger (lineage {}): restore from it (`wicket state restore`), or use another prefix",
            last.id
        ),
        (None, None) => new_lineage(st, list),
    }
}

/// `wicket state check`: where each kind of state goes, and whether the store takes writes.
pub fn check(probe: bool) -> Result<()> {
    let Some(s) = StateStore::load()? else {
        println!("no {}: everything stays on this host", crate::statestore::path().display());
        return Ok(());
    };
    if let Some(c) = &s.s3 {
        println!("state store: {} bucket {} prefix {:?}", c.endpoint, c.bucket, c.prefix);
        if probe {
            s.open_s3()?.probe().context("writing to the state store")?;
            println!("  it takes writes (a probe object written, read back and deleted)");
        }
    }
    println!("bundles: {}", if s.bundles == crate::statestore::Where::S3 { "the state store" } else { "this host" });
    match &s.ledger {
        Some(l) => println!("ledger: streamed every {} (kept {}), by Litestream ({})", l.sync_interval, l.retention, litestream_desc(l)),
        None => println!("ledger: this host only"),
    }
    let stores: Vec<String> = crate::audit_export::SinksConfig::load()?
        .map(|c| c.sinks.into_iter().filter(|k| matches!(k.kind, crate::audit_export::SinkKind::Store {})).map(|k| k.name).collect())
        .unwrap_or_default();
    match stores.is_empty() {
        true => println!("audit: no sink of type store"),
        false => println!("audit: to the state store by sink(s) {}", stores.join(", ")),
    }
    println!("roots: {}", if crate::roots::offline() { "offline" } else { "on this host" });
    Ok(())
}

fn litestream_desc(l: &LedgerStream) -> String {
    l.litestream.binary.clone().or(l.litestream.image.clone()).unwrap_or_else(|| crate::statestore::LITESTREAM_IMAGE.into())
}

/// Litestream's configuration for the ledger, with the store's credentials if given.
fn litestream_config(s: &StateStore, l: &LedgerStream, db: &Path, lineage: &str, creds: Option<&crate::s3::Creds>) -> Result<String> {
    let c = s.s3()?;
    let mut cfg = serde_json::json!({
        "snapshot": { "interval": "1h", "retention": l.retention },
        "dbs": [{
            "path": db.to_string_lossy(),
            "replica": {
                "type": "s3", "bucket": c.bucket, "path": format!("{}ledger/{lineage}", c.prefix), "endpoint": c.endpoint,
                "region": c.region, "force-path-style": c.path_style, "sync-interval": l.sync_interval,
            },
        }],
    });
    if let Some(k) = creds {
        cfg["dbs"][0]["replica"]["access-key-id"] = k.access_key_id.clone().into();
        cfg["dbs"][0]["replica"]["secret-access-key"] = k.secret_access_key.clone().into();
    }
    Ok(serde_yaml::to_string(&cfg)?)
}

/// A Litestream command (`replicate` or `restore …`), with its config written beside the ledger,
/// credentials included, 0600 (as the vault holds them): the caller removes it when the command ends.
/// (Not in its environment: `sudo docker` drops that, and Litestream's restore reads only the config.)
fn litestream(s: &StateStore, args: &[&str], db: &Path, lineage: &str) -> Result<(std::process::Command, PathBuf)> {
    use std::os::unix::fs::OpenOptionsExt;
    let l = s.ledger.as_ref().context("state-store.yaml has no ledger: section")?;
    let dir = db.parent().context("the ledger's directory")?.to_path_buf();
    let creds = s.creds()?;
    let cfg_path = dir.join(format!("litestream-{}.yml", args[0]));
    let _ = std::fs::remove_file(&cfg_path);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&cfg_path)?;
    std::io::Write::write_all(&mut f, litestream_config(s, l, db, lineage, Some(&creds))?.as_bytes())?;
    let default_image = Some(crate::statestore::LITESTREAM_IMAGE.to_string());
    let image = l.litestream.image.as_ref().or(default_image.as_ref());
    let mut cmd = match (&l.litestream.binary, image) {
        (Some(b), _) => std::process::Command::new(b),
        (None, Some(image)) => {
            // Run as this user, with host networking and the data directory at the same path.
            let docker = std::env::var("WICKET_DOCKER").unwrap_or_else(|_| "docker".into());
            let mut parts = docker.split_whitespace();
            let mut c = std::process::Command::new(parts.next().context("WICKET_DOCKER is empty")?);
            c.args(parts);
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            // Named after the data directory: one per installation, and findable to stop.
            let name = {
                use sha2::Digest;
                format!("wicket-litestream-{}", &hex::encode(sha2::Sha256::digest(dir.to_string_lossy().as_bytes()))[..12])
            };
            // One left by a supervisor killed hard (the client died, the container didn't) goes first.
            let mut rm = std::process::Command::new(c.get_program());
            rm.args(c.get_args()).args(["rm", "-f", &name]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
            let _ = rm.status();
            c.args(["run", "--rm", "-i", "--name", &name, "--network", "host", "--user", &format!("{uid}:{gid}")])
                .arg("-v")
                .arg(format!("{0}:{0}", dir.display()))
                .arg(image);
            c
        }
        (None, None) => bail!("ledger.litestream: one of binary or image"),
    };
    let sub = args[0];
    cmd.arg(sub).arg("-config").arg(&cfg_path).args(&args[1..]);
    Ok((cmd, cfg_path))
}

/// `wicket state replicate`: streams the ledger to the state store until stopped.
pub fn replicate() -> Result<()> {
    let s = StateStore::load()?.context("no state-store.yaml")?;
    let Some(l) = &s.ledger else {
        // Not an error (the service would restart for ever): nothing to stream.
        println!("[wicket] state-store.yaml has no ledger: section: the ledger isn't streamed");
        return Ok(());
    };
    let db = ledger_path();
    // Litestream needs the database in WAL mode, which the ledger is; make sure it exists.
    drop(wicket_store::Ledger::open(&db)?);
    let lineage = my_lineage(&s.open_s3()?)?;
    let (mut cmd, cfg) = litestream(&s, &["replicate"], &db, &lineage)?;
    println!("[wicket] streaming {} to the state store as lineage {lineage} ({})", db.display(), litestream_desc(l));
    let status = cmd.status();
    let _ = std::fs::remove_file(&cfg);
    let status = status.context("starting Litestream")?;
    if !status.success() {
        bail!("Litestream exited: {status}");
    }
    Ok(())
}

/// The files a recovery kit holds: (path in the kit, path on this host).
fn kit_files(with_secrets: bool, with_roots: bool) -> Result<Vec<(String, PathBuf)>> {
    let mut out = vec![];
    let mut add_dir = |prefix: &str, dir: &Path, filter: &dyn Fn(&str) -> bool| -> Result<()> {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if e.file_type()?.is_file() && filter(&name) {
                    out.push((format!("{prefix}/{name}"), e.path()));
                }
            }
        }
        Ok(())
    };
    let roots = ["feed-root.key", "authz-root.key"];
    add_dir("identity", &identity_dir(), &|n| with_roots || !roots.contains(&n))?;
    let d = data_dir();
    let data =
        ["state.key", "state-store.yaml", "audit-sinks.yaml", "placement.yaml", "placement-static.json", "images.yaml", "ci-builds.yaml"];
    add_dir("data", &d, &|n| data.contains(&n))?;
    if let Ok(rd) = std::fs::read_dir(d.join("nodes")) {
        for e in rd.flatten() {
            let node = e.file_name().to_string_lossy().to_string();
            add_dir(&format!("data/nodes/{node}"), &e.path(), &|_| true)?;
            add_dir(&format!("data/nodes/{node}/feed"), &e.path().join("feed"), &|n| n == "feed.key" || n == "cert.jws")?;
        }
    }
    // The org policy (#51), and every version runs were minted under: a standby mints as this host did.
    add_dir("data/policy", &d.join("policy"), &|_| true)?;
    add_dir("data/policy/versions", &d.join("policy/versions"), &|_| true)?;
    if with_secrets {
        add_dir("secrets", &vault_dir(), &|_| true)?;
    }
    Ok(out)
}

/// `wicket state kit`: the recovery kit, a tar of what a standby needs besides the state store.
pub fn kit(out: &Path, with_secrets: bool, with_roots: bool) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let files = kit_files(with_secrets, with_roots)?;
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .with_context(|| format!("{} (it must not exist yet)", out.display()))?;
    let mut t = tar::Builder::new(f);
    for (name, path) in &files {
        let mut h = tar::Header::new_gnu();
        let body = std::fs::read(path).with_context(|| path.display().to_string())?;
        h.set_size(body.len() as u64);
        h.set_mode(0o600);
        h.set_cksum();
        t.append_data(&mut h, name, body.as_slice())?;
    }
    t.into_inner()?.sync_all()?;
    let roots = files.iter().any(|(n, _)| n.ends_with("-root.key"));
    println!(
        "wrote {} ({} files), unencrypted: the installation's keys and state.key{}{}. Whoever has it owns the installation: encrypt it and keep it offline",
        out.display(),
        files.len(),
        if with_secrets { ", the vault's secrets" } else { "" },
        if roots { ", and the roots" } else { "" }
    );
    if !with_secrets {
        println!("  without the vault: set the secrets again on the standby before `wicket state restore`'s first use of the store");
    }
    let l = wicket_store::Ledger::open(&ledger_path())?;
    l.audit(
        &wicket_core::TenantId::single(),
        None,
        "state.kit",
        &serde_json::json!({ "files": files.iter().map(|(n, _)| n).collect::<Vec<_>>(), "secrets": with_secrets, "roots": with_roots }),
    )?;
    Ok(())
}

/// Unpacks a kit onto this host. Returns the files written.
fn unpack_kit(kit: &Path) -> Result<Vec<String>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut a = tar::Archive::new(std::fs::File::open(kit).with_context(|| kit.display().to_string())?);
    let mut written = vec![];
    for e in a.entries()? {
        let mut e = e?;
        let name = e.path()?.to_string_lossy().to_string();
        let (top, rest) = name.split_once('/').context("a kit entry outside identity/, data/ and secrets/")?;
        if rest.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
            bail!("a kit entry with an unsafe path: {name}");
        }
        let dest = match top {
            "identity" => identity_dir().join(rest),
            "data" => data_dir().join(rest),
            "secrets" => vault_dir().join(rest),
            _ => bail!("a kit entry outside identity/, data/ and secrets/: {name}"),
        };
        std::fs::create_dir_all(dest.parent().expect("a parent"))?;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&dest)?;
        std::io::copy(&mut e, &mut f)?;
        written.push(name);
    }
    Ok(written)
}

/// `wicket state restore`: a fresh host becomes the control host, from a kit and the state store.
pub fn restore(kit: &Path, at: Option<&str>, force: bool) -> Result<()> {
    let db = ledger_path();
    if db.exists() && !force {
        bail!("{} exists: this host already has a ledger (--force replaces it)", db.display());
    }
    let files = unpack_kit(kit)?;
    println!("[wicket] the kit's {} files are in place", files.len());
    let s = StateStore::load()?.context("the kit has no state-store.yaml")?;
    // The ledger, as the store last had it (or as it was at `at`), from the lineage current then.
    let st = s.open_s3()?;
    let list = lineages(&st)?;
    let at_ms = match at {
        Some(t) => Some(
            humantime::parse_rfc3339_weak(t)
                .with_context(|| format!("--at {t}: a time like 2026-11-12T19:05:05Z"))?
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as i64,
        ),
        None => None,
    };
    let from = match at_ms {
        None => list.last(),
        Some(t) => list.iter().rev().find(|l| l.since <= t).or(list.first()),
    }
    .context("the state store has no streamed ledger (ledger/lineages.json)")?
    .clone();
    let tmp = db.with_extension("restoring");
    let _ = std::fs::remove_file(&tmp);
    std::fs::create_dir_all(db.parent().expect("a parent"))?;
    let mut args = vec!["restore".to_string()];
    if let Some(t) = at {
        let t = humantime::parse_rfc3339_weak(t).with_context(|| format!("--at {t}: a time like 2026-11-12T19:05:05Z"))?;
        args.push("-timestamp".into());
        args.push(humantime::format_rfc3339_seconds(t).to_string());
    }
    args.extend(["-o".to_string(), tmp.to_string_lossy().to_string(), db.to_string_lossy().to_string()]);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (mut cmd, cfg) = litestream(&s, &argv, &db, &from.id)?;
    let out = cmd.output();
    let _ = std::fs::remove_file(&cfg);
    let out = out.context("starting Litestream")?;
    if !out.status.success() || !tmp.exists() {
        bail!("Litestream could not restore the ledger: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", db.display()));
    }
    std::fs::rename(&tmp, &db)?;
    let l = wicket_store::Ledger::open(&db)?;
    l.verify_audit().context("the restored ledger's audit chain")?;
    let (head, _) = l.audit_head()?.unwrap_or((0, String::new()));
    println!("[wicket] the ledger is restored from lineage {}: its audit chain verifies, up to record {head}", from.id);
    // This host streams as a lineage of its own from now on; the one it came from is superseded.
    let lineage = new_lineage(&st, list)?;

    // Audit records a store sink exported after the restore point continue the chain: back in, up to
    // the newest checkpoint signed by this installation's issuer (anyone who can write the bucket
    // could make records that chain; not ones a checkpoint signs).
    let mut imported = 0;
    let mut exported_beyond = 0i64;
    if let Some(cfg) = crate::audit_export::SinksConfig::load()? {
        let issuer = crate::issuer()?.verifying_key();
        for sink in cfg.sinks.iter().filter(|k| matches!(k.kind, crate::audit_export::SinkKind::Store {})) {
            let objs = crate::audit_export::stored_objects(&sink.name)?;
            let mut recs: Vec<wicket_store::AuditRecord> =
                objs.iter().filter(|o| o["type"] == "wicket.audit.record").filter_map(exported_record).collect();
            recs.sort_by_key(|r| r.seq);
            recs.dedup_by_key(|r| r.seq);
            exported_beyond = exported_beyond.max(recs.last().map(|r| r.seq).unwrap_or(0));
            if at.is_some() {
                continue;
            }
            let signed = signed_up_to(&objs, &recs, &issuer);
            let trusted: Vec<_> = recs.into_iter().filter(|r| r.seq <= signed).collect();
            imported += l.import_exported_audit(&trusted)?;
        }
    }
    let (new_head, _) = l.audit_head()?.unwrap_or((0, String::new()));
    l.rewind_exports(new_head)?;
    let bumped = l.bump_agent_generations(GENERATION_BUMP)?;
    l.audit(
        &wicket_core::TenantId::single(),
        None,
        "state.restored",
        &serde_json::json!({
            "kit_files": files.len(), "at": at, "ledger_head": head, "from_lineage": from.id, "lineage": lineage, "imported_from_export": imported,
            "agents_fenced": bumped, "generation_bump": GENERATION_BUMP,
            // What was recorded after this point and exported (a restore to an earlier point, or
            // records no signed checkpoint covered) is discarded: `audit --verify --against` then
            // doesn't compare those copies.
            "rolled_back_after": (at.is_some() || exported_beyond > new_head).then_some(new_head),
        }),
    )?;
    if imported > 0 {
        println!("[wicket] {imported} audit record(s) the store had beyond the ledger's copy are back in the chain");
    }
    println!("[wicket] {bumped} agent(s) fenced: their generation moved by {GENERATION_BUMP}");
    // Each node's feed starts a new generation (its delta log stayed behind): the next run that
    // reaches a node publishes a fresh snapshot under a new certificate version.
    let mut regen = vec![];
    if let Ok(rd) = std::fs::read_dir(data_dir().join("nodes")) {
        for e in rd.flatten() {
            let feed = e.path().join("feed");
            if feed.join("feed.key").exists() {
                std::fs::write(feed.join(crate::noderun::REGENESIS), b"")?;
                regen.push(e.file_name().to_string_lossy().to_string());
            }
        }
    }
    if !regen.is_empty() {
        println!("[wicket] node feeds start a new generation on first use: {}", regen.join(", "));
    }
    println!("[wicket] next: start wicket's services, then `wicket reconcile` (runs that were running end as lost)");
    Ok(())
}

/// The newest seq a checkpoint signed by `issuer` covers whose head is the exported record's hash
/// at that seq (0: none).
fn signed_up_to(objs: &[serde_json::Value], recs: &[wicket_store::AuditRecord], issuer: &wicket_identity::VerifyingKey) -> i64 {
    objs.iter()
        .filter(|o| o["type"] == "wicket.audit.checkpoint")
        .filter_map(|o| wicket_identity::verify_checkpoint(o["jws"].as_str()?, issuer).ok())
        .filter_map(|p| {
            let seq = p["seq"].as_i64()?;
            let head = p["head"].as_str()?;
            recs.iter().any(|r| r.seq == seq && r.hash == head).then_some(seq)
        })
        .max()
        .unwrap_or(0)
}

/// An exported record, as the ledger stores it (its body back to the string that was hashed).
fn exported_record(o: &serde_json::Value) -> Option<wicket_store::AuditRecord> {
    Some(wicket_store::AuditRecord {
        seq: o["seq"].as_i64()?,
        ts: o["ts"].as_i64()?,
        tenant: o["tenant"].as_str()?.to_string(),
        run: o["run"].as_str().map(String::from),
        kind: o["kind"].as_str()?.to_string(),
        body: match &o["body"] {
            serde_json::Value::String(s) => s.clone(),
            v => serde_json::to_string(v).ok()?,
        },
        prev: o["prev"].as_str()?.to_string(),
        hash: o["hash"].as_str()?.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An exported record's body goes back to the exact string that was hashed.
    #[test]
    fn an_exported_record_comes_back_as_it_was_hashed() {
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        l.audit(&wicket_core::TenantId::single(), None, "op", &serde_json::json!({ "z": 1, "a": [1, "x"], "m": { "k": null } })).unwrap();
        let r = l.audit_record_at(1).unwrap().unwrap();
        let o = crate::audit_export::record_json(&r);
        assert_eq!(exported_record(&o).unwrap(), r);
        // And it continues another ledger's chain exactly.
        let l2 = wicket_store::Ledger::open_in_memory().unwrap();
        assert_eq!(l2.import_exported_audit(std::slice::from_ref(&r)).unwrap(), 1);
        l2.verify_audit().unwrap();
        let mut bad = r;
        bad.seq = 3;
        assert_eq!(l2.import_exported_audit(&[bad]).unwrap(), 0);
    }
}
