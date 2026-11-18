//! Writing a whole file so a reader sees the old contents or the new, never a part (moved from
//! `nodesecrets`, where `write_atomic` was, though it writes much more than secrets).
//!
//! Two ways, for two needs. [`write_atomic`] is private (0600) and durable (synced before the
//! rename): state that must survive a crash and isn't anyone else's to read. [`replace`] is
//! neither: state rewritten often (a box's status, a node's spend) where the sync would cost more
//! than a lost last write. Neither suits a file several processes write at once: those name their
//! temporary file by process (`reexec`'s pidfile), so they keep their own.

use anyhow::Result;
use std::path::Path;

/// Writes `bytes` to `path` (0600), synced, through `<path>.tmp` and a rename.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Writes `bytes` to `path` (the process's default mode), not synced, through `<path>.<tmp_ext>`
/// and a rename.
pub fn replace(path: &Path, tmp_ext: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(tmp_ext);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}
