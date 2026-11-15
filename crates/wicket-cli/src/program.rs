//! Program source digests (design §17): the identity a program run pins.
//!
//! A program's digest is the digest of its source as a plain tree in wicket's content-addressed
//! store (#258, docs/explanation/store.md): plain files only, named by content and executable bit.
//! Pins made before it (`wicket-program-v1`) are still accepted, with a warning, until `wicket zone
//! pin` rewrites them.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use wicket_store::cas::{dir_digest, DirOpts};

/// The digest of `root` as a plain tree: `sha256:` of its tree, with every file `0644` or `0755`
/// by its executable bit, every directory `0755` and every time 0. Symlinks and other special
/// files are refused: a program is plain files.
pub fn digest_dir(root: &Path) -> Result<String> {
    Ok(dir_digest(root, &DirOpts { plain: true, ..DirOpts::default() })?.to_string())
}

/// What a pin says of `root`'s source.
#[derive(Debug, PartialEq, Eq)]
pub enum Pinned {
    /// The pin is the source's digest.
    Yes,
    /// The pin is the source's `wicket-program-v1` digest, from before #258: the same source,
    /// to be re-pinned.
    Legacy,
    No,
}

/// Whether `pin` is `root`'s digest (`digest`, as [`digest_dir`] made it), or its old one.
pub fn check_pin(root: &Path, digest: &str, pin: &str) -> Result<Pinned> {
    Ok(if pin == digest {
        Pinned::Yes
    } else if pin == legacy_digest_dir(root)? {
        Pinned::Legacy
    } else {
        Pinned::No
    })
}

/// `wicket-program-v1`: sha256 over every regular file's relative path, executable bit and
/// content, in sorted order. Only to recognise pins made before #258.
pub fn legacy_digest_dir(root: &Path) -> Result<String> {
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
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_is_named_by_its_plain_tree_and_old_pins_are_recognised() {
        let d = std::env::temp_dir().join(format!("wicket-program-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("lib")).unwrap();
        std::fs::write(d.join("run.sh"), b"echo hi\n").unwrap();
        std::fs::set_permissions(d.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(d.join("lib/x"), b"x").unwrap();
        let digest = digest_dir(&d).unwrap();
        // The tree is the one the store would hold.
        let cas = wicket_store::cas::Cas::new(wicket_store::objects::DirStore::new(d.with_extension("store")));
        let t = cas.put_dir(&d, &DirOpts { plain: true, ..DirOpts::default() }).unwrap();
        assert_eq!(t.to_string(), digest);
        let legacy = legacy_digest_dir(&d).unwrap();
        assert_ne!(legacy, digest);
        assert_eq!(check_pin(&d, &digest, &digest).unwrap(), Pinned::Yes);
        assert_eq!(check_pin(&d, &digest, &legacy).unwrap(), Pinned::Legacy);
        assert_eq!(check_pin(&d, &digest, &format!("sha256:{}", "0".repeat(64))).unwrap(), Pinned::No);
        std::os::unix::fs::symlink("run.sh", d.join("l")).unwrap();
        assert!(digest_dir(&d).is_err());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(d.with_extension("store"));
    }

    #[test]
    fn the_pinned_example_pins_its_source() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let text = std::fs::read_to_string(root.join("examples/program-repo-stats.pinned.yaml")).unwrap();
        let m = wicket_core::Manifest::from_yaml(&text).unwrap();
        let p = m.program.unwrap();
        let src = root.join("examples").join(p.source.unwrap());
        assert_eq!(p.digest.unwrap(), digest_dir(&src).unwrap());
    }
}
