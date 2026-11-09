//! Program source digests (design §17): the identity a program run pins.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// sha256 over every regular file's relative path, executable bit and content, in sorted order.
/// Symlinks and other special files are refused: a program is plain files.
pub fn digest_dir(root: &Path) -> Result<String> {
    let mut files: Vec<PathBuf> = Vec::new();
    walk(root, root, &mut files)?;
    files.sort();
    let mut h = Sha256::new();
    h.update(b"wicket-program-v1\0");
    for rel in &files {
        let full = root.join(rel);
        let meta = std::fs::metadata(&full)?;
        let exec = meta.permissions().mode() & 0o111 != 0;
        h.update(rel.to_string_lossy().as_bytes());
        h.update([0u8, exec as u8, 0u8]);
        h.update(Sha256::digest(std::fs::read(&full)?));
    }
    Ok(format!("sha256:{}", hex(&h.finalize())))
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let ft = e.file_type()?;
        let p = e.path();
        if ft.is_symlink() {
            bail!("{} is a symlink: programs are plain files", p.display());
        } else if ft.is_dir() {
            walk(root, &p, out)?;
        } else if ft.is_file() {
            out.push(p.strip_prefix(root)?.to_path_buf());
        } else {
            bail!("{} is not a regular file", p.display());
        }
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
