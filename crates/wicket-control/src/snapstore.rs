//! Pre-update ledger snapshots in the state store (#167). Before every switch, `wicket self update`
//! takes a snapshot of the ledger (`<data dir>/snapshots/<time>-<build id>.db`, VACUUM INTO); with a
//! state store (`state-store.yaml`'s `s3:`) it is also pushed there, into the content-addressed store
//! (#258, docs/explanation/store.md) sealed under `state.key`: the file as a blob, and a ref
//! `ledger-snapshots/<time>-<build id>.db` naming its digest. A rollback past a contract step then
//! survives losing the control host: a standby restored from the recovery kit (which holds
//! `state.key`) and the store fetches it with `wicket state snapshot`, verified by its digest.
//!
//! Snapshots that builds before #258 pushed (sealed objects `ledger-snapshots/<name>`, no digest) are
//! still listed, fetched and pruned.
//!
//! Pruning (`wicket self prune`, and after each update) applies the local rule to the store's copies
//! too: the newest few, and always the newest of the current and previous versions'.

use anyhow::{bail, Context, Result};
use std::path::Path;
use wicket_store::cas::{Cas, Digest};
use wicket_store::sealed::SealedStore;

/// The refs' prefix in the store (and the objects' prefix before #258).
pub const PREFIX: &str = "ledger-snapshots/";

/// The installation's store for snapshots, sealed; None without a state store.
pub fn store() -> Result<Option<Cas>> {
    let Some(s) = crate::statestore::StateStore::load()? else { return Ok(None) };
    if s.s3.is_none() {
        return Ok(None);
    }
    Ok(Some(Cas::new(SealedStore::new(s.open_s3()?, &crate::hibernate::state_key()?))))
}

fn valid_name(name: &str) -> bool {
    name.ends_with(".db") && !name.contains('/') && wicket_store::objects::valid_key(name)
}

/// Pushes the snapshot file `snap` (named `<time>-<id>.db`); returns its ref and digest. A ref
/// already there under that name is left as it is (a snapshot is never rewritten).
pub fn push(st: &Cas, snap: &Path) -> Result<(String, Digest)> {
    let name = snap.file_name().and_then(|n| n.to_str()).context("a snapshot's name")?;
    if !valid_name(name) {
        bail!("not a snapshot's name: {name}");
    }
    let key = format!("{PREFIX}{name}");
    if let Some(d) = st.get_ref(&key)? {
        return Ok((key, d));
    }
    // Held until the ref names the blob: no collection deletes it meanwhile (#258).
    let _held = st.writing(&format!("the push of {key}"))?;
    let d = st.put_file(snap).with_context(|| format!("pushing {key} to the state store"))?;
    if !st.set_ref(&key, &d).with_context(|| format!("naming {key} in the state store"))? {
        // Pushed by another update in the meantime: that one stands.
        let d = st.get_ref(&key)?.with_context(|| format!("{key} in the state store"))?;
        return Ok((key, d));
    }
    Ok((key, d))
}

/// The snapshots in the store, oldest first (by name: `<seconds>-<id>.db`).
pub fn list(st: &Cas) -> Result<Vec<String>> {
    let refs = st.refs(PREFIX)?;
    let legacy = st.backend().list_prefix(PREFIX)?;
    let mut names: Vec<String> =
        refs.into_iter().chain(legacy).filter_map(|k| k.strip_prefix(PREFIX).map(String::from)).filter(|n| valid_name(n)).collect();
    names.sort_by_key(|n| (n.split('-').next().and_then(|t| t.parse::<i64>().ok()).unwrap_or(0), n.clone()));
    names.dedup();
    Ok(names)
}

/// Deletes snapshot `name` from the store: its ref, and a copy pushed before #258. Its blob goes
/// with the store's next collection (`crate::storegc`), unless something else still names it.
pub fn remove(st: &Cas, name: &str) -> Result<()> {
    if !valid_name(name) {
        bail!("not a snapshot's name: {name}");
    }
    let key = format!("{PREFIX}{name}");
    st.delete_ref(&key)?;
    st.backend().delete(&key)?;
    Ok(())
}

/// Fetches snapshot `name` into `out` (which must not exist; 0600), unsealed and verified, and checks
/// it is a SQLite database.
pub fn fetch(st: &Cas, name: &str, out: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if !valid_name(name) {
        bail!("not a snapshot's name: {name} (`wicket state snapshots` lists them)");
    }
    let key = format!("{PREFIX}{name}");
    let mut r = match st.get_ref(&key)? {
        Some(d) => st.get(&d)?.with_context(|| format!("snapshot {name} names {d}, which isn't in the state store"))?,
        None => st.backend().get(&key)?.with_context(|| format!("no snapshot {name} in the state store"))?,
    };
    let tmp = out.with_file_name(format!(".{}.part", out.file_name().and_then(|n| n.to_str()).unwrap_or("snapshot")));
    let _ = std::fs::remove_file(&tmp);
    let mut f =
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).with_context(|| tmp.display().to_string())?;
    let copied = std::io::copy(&mut r, &mut f).and_then(|_| f.sync_all());
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).context(format!("reading {name} from the state store (sealed under another state.key, or altered?)"));
    }
    let mut head = [0u8; 16];
    let ok =
        std::fs::File::open(&tmp).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head)).is_ok() && &head == b"SQLite format 3\0";
    if !ok {
        let _ = std::fs::remove_file(&tmp);
        bail!("{name} from the state store isn't a SQLite database");
    }
    // Not over an existing file; the unsealed copy never stays behind.
    let linked = std::fs::hard_link(&tmp, out);
    let _ = std::fs::remove_file(&tmp);
    linked.with_context(|| format!("{} (it must not exist yet)", out.display()))?;
    Ok(())
}

/// `wicket state snapshots`.
pub fn print_list() -> Result<()> {
    let st = store()?.context("no state store (state-store.yaml with an s3: store): snapshots are only local")?;
    let names = list(&st)?;
    if names.is_empty() {
        println!("no ledger snapshots in the state store");
    }
    for n in names {
        let (t, id) = n.trim_end_matches(".db").split_once('-').unwrap_or(("?", "?"));
        let when = t
            .parse::<u64>()
            .ok()
            .map(|s| wicket_core::time::format_rfc3339_seconds(std::time::UNIX_EPOCH + std::time::Duration::from_secs(s)));
        println!("{n}  (the ledger before switching away from {id}, {})", when.map(|w| w.to_string()).unwrap_or_else(|| "?".into()));
    }
    Ok(())
}

/// `wicket state snapshot`.
pub fn get(name: &str, out: &Path) -> Result<()> {
    let st = store()?.context("no state store (state-store.yaml with an s3: store)")?;
    fetch(&st, name, out)?;
    println!("wrote {} (snapshot {name} from the state store)", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_store::objects::{DirStore, ObjectStore};

    fn files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                files(&e.path(), out);
            } else {
                out.push(e.path());
            }
        }
    }

    #[test]
    fn a_snapshot_goes_to_the_store_sealed_and_comes_back() {
        let d = std::env::temp_dir().join(format!("wicket-snapstore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("local")).unwrap();
        let st = Cas::new(SealedStore::new(DirStore::new(d.join("store")), &[7u8; 32]));
        let snap = d.join("local/1700000000-aaaaaaaaaaaa.db");
        let ledger = wicket_store::Ledger::open(&d.join("local/ledger.db")).unwrap();
        ledger.snapshot(&snap).unwrap();
        let (key, digest) = push(&st, &snap).unwrap();
        assert_eq!(key, "ledger-snapshots/1700000000-aaaaaaaaaaaa.db");
        assert_eq!(digest, Digest::of(&std::fs::read(&snap).unwrap()));
        assert_eq!(st.get_ref(&key).unwrap(), Some(digest));
        // Sealed: none of the store's files is the database.
        let mut all = vec![];
        files(&d.join("store"), &mut all);
        assert!(!all.is_empty());
        for f in &all {
            assert!(!std::fs::read(f).unwrap().starts_with(b"SQLite format 3"), "{}", f.display());
        }
        // Never rewritten.
        let later = d.join("local/1800000000-bbbbbbbbbbbb.db");
        std::fs::copy(&snap, &later).unwrap();
        std::fs::write(&snap, b"something else").unwrap();
        assert_eq!(push(&st, &snap).unwrap().1, digest);
        push(&st, &later).unwrap();
        assert_eq!(list(&st).unwrap(), ["1700000000-aaaaaaaaaaaa.db", "1800000000-bbbbbbbbbbbb.db"]);
        let out = d.join("back.db");
        fetch(&st, "1700000000-aaaaaaaaaaaa.db", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&later).unwrap());
        assert!(fetch(&st, "1700000000-aaaaaaaaaaaa.db", &out).is_err(), "never over an existing file");
        assert!(!d.join(".back.db.part").exists(), "and no unsealed copy left beside it");
        assert!(fetch(&st, "1-cccccccccccc.db", &d.join("none.db")).is_err());
        assert!(fetch(&st, "../x.db", &d.join("bad.db")).is_err());
        // Another state.key can't read it, and leaves nothing behind.
        let other = Cas::new(SealedStore::new(DirStore::new(d.join("store")), &[8u8; 32]));
        assert!(fetch(&other, "1700000000-aaaaaaaaaaaa.db", &d.join("other.db")).is_err());
        assert!(!d.join("other.db").exists() && !d.join(".other.db.part").exists());
        // The two share one blob: removing one keeps it for the other.
        remove(&st, "1700000000-aaaaaaaaaaaa.db").unwrap();
        assert!(st.has(&digest).unwrap());
        assert_eq!(list(&st).unwrap(), ["1800000000-bbbbbbbbbbbb.db"]);
        remove(&st, "1800000000-bbbbbbbbbbbb.db").unwrap();
        assert!(list(&st).unwrap().is_empty());
        // The blob, now named by nothing, goes with the store's next collection (#258).
        let plan = wicket_store::cas::GcPlan {
            roots: &|| Ok(vec![]),
            drop_ref: &|_, _| false,
            dry_run: false,
            by: "test",
            cap: None,
            now: &wicket_store::now,
        };
        assert_eq!(st.collect(&plan).unwrap().deleted, vec![digest]);
        assert!(!st.has(&digest).unwrap());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_snapshot_pushed_before_the_store_is_still_read_and_pruned() {
        let d = std::env::temp_dir().join(format!("wicket-snapstore-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let snap = d.join("ledger.db");
        wicket_store::Ledger::open(&d.join("l.db")).unwrap().snapshot(&snap).unwrap();
        // As #167 pushed it: the file sealed as an object of its own name.
        let old = SealedStore::new(DirStore::new(d.join("store")), &[7u8; 32]);
        let name = "1600000000-cccccccccccc.db";
        old.put_if_absent(&format!("{PREFIX}{name}"), &mut std::fs::File::open(&snap).unwrap()).unwrap();
        let st = Cas::new(SealedStore::new(DirStore::new(d.join("store")), &[7u8; 32]));
        assert_eq!(list(&st).unwrap(), [name]);
        fetch(&st, name, &d.join("back.db")).unwrap();
        assert_eq!(std::fs::read(d.join("back.db")).unwrap(), std::fs::read(&snap).unwrap());
        remove(&st, name).unwrap();
        assert!(list(&st).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
