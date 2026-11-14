//! Pre-update ledger snapshots in the state store (#167). Before every switch, `wicket self update`
//! takes a snapshot of the ledger (`<data dir>/snapshots/<time>-<build id>.db`, VACUUM INTO); with a
//! state store (`state-store.yaml`'s `s3:`) it is also pushed there, sealed under `state.key` as
//! hibernated agents' bundles are, as `ledger-snapshots/<time>-<build id>.db`. A rollback past a
//! contract step then survives losing the control host: a standby restored from the recovery kit
//! (which holds `state.key`) and the store fetches it with `wicket state snapshot`.
//!
//! Pruning (`wicket self prune`, and after each update) applies the local rule to the store's copies
//! too: the newest few, and always the newest of the current and previous versions'.

use anyhow::{bail, Context, Result};
use std::path::Path;
use wicket_store::objects::ObjectStore;
use wicket_store::sealed::SealedStore;

/// Where in the store.
pub const PREFIX: &str = "ledger-snapshots/";

/// The installation's store for snapshots, sealed; None without a state store.
pub fn store() -> Result<Option<SealedStore<crate::s3::S3Store>>> {
    let Some(s) = crate::statestore::StateStore::load()? else { return Ok(None) };
    if s.s3.is_none() {
        return Ok(None);
    }
    Ok(Some(SealedStore::new(s.open_s3()?, &crate::hibernate::state_key()?)))
}

fn valid_name(name: &str) -> bool {
    name.ends_with(".db") && !name.contains('/') && wicket_store::objects::valid_key(name)
}

/// Pushes the snapshot file `snap` (named `<time>-<id>.db`); returns its key. An object already
/// there under that name is left as it is (a snapshot is never rewritten).
pub fn push(st: &dyn ObjectStore, snap: &Path) -> Result<String> {
    let name = snap.file_name().and_then(|n| n.to_str()).context("a snapshot's name")?;
    if !valid_name(name) {
        bail!("not a snapshot's name: {name}");
    }
    let key = format!("{PREFIX}{name}");
    let mut f = std::fs::File::open(snap).with_context(|| snap.display().to_string())?;
    st.put_if_absent(&key, &mut f).with_context(|| format!("pushing {key} to the state store"))?;
    Ok(key)
}

/// The snapshots in the store, oldest first (by name: `<seconds>-<id>.db`).
pub fn list(st: &dyn ObjectStore) -> Result<Vec<String>> {
    let mut names: Vec<String> =
        st.list_prefix(PREFIX)?.into_iter().filter_map(|k| k.strip_prefix(PREFIX).map(String::from)).filter(|n| valid_name(n)).collect();
    names.sort_by_key(|n| (n.split('-').next().and_then(|t| t.parse::<i64>().ok()).unwrap_or(0), n.clone()));
    Ok(names)
}

/// Fetches snapshot `name` into `out` (which must not exist; 0600), unsealed, and checks it is a
/// SQLite database.
pub fn fetch(st: &dyn ObjectStore, name: &str, out: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if !valid_name(name) {
        bail!("not a snapshot's name: {name} (`wicket state snapshots` lists them)");
    }
    let mut r = st.get(&format!("{PREFIX}{name}"))?.with_context(|| format!("no snapshot {name} in the state store"))?;
    let tmp = out.with_file_name(format!(".{}.part", out.file_name().and_then(|n| n.to_str()).unwrap_or("snapshot")));
    let _ = std::fs::remove_file(&tmp);
    let mut f =
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).with_context(|| tmp.display().to_string())?;
    let copied = std::io::copy(&mut r, &mut f).and_then(|_| f.sync_all());
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).context(format!("reading {name} from the state store (sealed under another state.key?)"));
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
        let when =
            t.parse::<u64>().ok().map(|s| humantime::format_rfc3339_seconds(std::time::UNIX_EPOCH + std::time::Duration::from_secs(s)));
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
    use wicket_store::objects::DirStore;

    #[test]
    fn a_snapshot_goes_to_the_store_sealed_and_comes_back() {
        let d = std::env::temp_dir().join(format!("wicket-snapstore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("local")).unwrap();
        let st = SealedStore::new(DirStore::new(d.join("store")), &[7u8; 32]);
        let snap = d.join("local/1700000000-aaaaaaaaaaaa.db");
        let ledger = wicket_store::Ledger::open(&d.join("local/ledger.db")).unwrap();
        ledger.snapshot(&snap).unwrap();
        let key = push(&st, &snap).unwrap();
        assert_eq!(key, "ledger-snapshots/1700000000-aaaaaaaaaaaa.db");
        // Sealed: the store's bytes aren't the database.
        let raw = std::fs::read(d.join("store/sealed").join(&key)).unwrap();
        assert!(!raw.starts_with(b"SQLite format 3"));
        let later = d.join("local/1800000000-bbbbbbbbbbbb.db");
        std::fs::copy(&snap, &later).unwrap();
        push(&st, &later).unwrap();
        assert_eq!(list(&st).unwrap(), ["1700000000-aaaaaaaaaaaa.db", "1800000000-bbbbbbbbbbbb.db"]);
        let out = d.join("back.db");
        fetch(&st, "1700000000-aaaaaaaaaaaa.db", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&snap).unwrap());
        assert!(fetch(&st, "1700000000-aaaaaaaaaaaa.db", &out).is_err(), "never over an existing file");
        assert!(!d.join(".back.db.part").exists(), "and no unsealed copy left beside it");
        assert!(fetch(&st, "1-cccccccccccc.db", &d.join("none.db")).is_err());
        assert!(fetch(&st, "../x.db", &d.join("bad.db")).is_err());
        // Another state.key can't read it, and leaves nothing behind.
        let other = SealedStore::new(DirStore::new(d.join("store")), &[8u8; 32]);
        assert!(fetch(&other, "1700000000-aaaaaaaaaaaa.db", &d.join("other.db")).is_err());
        assert!(!d.join("other.db").exists() && !d.join(".other.db.part").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
