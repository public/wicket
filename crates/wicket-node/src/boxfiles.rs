//! Files wicket reads and writes in a box's tree, which the box may have written: never following
//! what it put there (moved from wicket-cli's `hibernate`, which re-exports them).

use anyhow::Result;
use std::path::{Path, PathBuf};
use wicket_store::bundle;

/// Reads a box's typed output file, `<root>/workspace/out/result.json`, without trusting the box:
/// no component under `root` is followed if it is a symlink, the file must be a regular file of
/// at most `max` bytes, and at most `max + 1` bytes are read. Anything else is "no result".
pub fn read_outbox(root: &Path, max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let open_at = |dir: libc::c_int, name: &str, flags: libc::c_int| -> Option<OwnedFd> {
        let c = std::ffi::CString::new(name).ok()?;
        let fd = unsafe { libc::openat(dir, c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
    };
    let c = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()).ok()?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return None;
    }
    let mut dir = unsafe { OwnedFd::from_raw_fd(fd) };
    for d in ["workspace", "out"] {
        dir = open_at(dir.as_raw_fd(), d, libc::O_RDONLY | libc::O_DIRECTORY)?;
    }
    // O_NONBLOCK so a FIFO can't block the open; it is then refused as not a regular file.
    let f = open_at(dir.as_raw_fd(), "result.json", libc::O_RDONLY | libc::O_NONBLOCK)?;
    let f = std::fs::File::from(f);
    let m = f.metadata().ok()?;
    if !m.file_type().is_file() || m.len() > max as u64 {
        return None;
    }
    let mut b = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut b).ok()?;
    (b.len() <= max).then_some(b)
}

/// Writes a file wicket owns at `root/rel`, where the tree under `root` may be agent-written:
/// every directory on the way is made a real directory (a symlink there is replaced), and the
/// file itself is created new with `write_new`, mode 0600.
pub fn write_owned(root: &Path, rel: &str, body: &[u8]) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let rel = Path::new(rel);
    anyhow::ensure!(
        rel.components().all(|c| matches!(c, std::path::Component::Normal(_))),
        "{} is not a plain relative path",
        rel.display()
    );
    let mut d = root.to_path_buf();
    real_dirs(std::slice::from_ref(&d))?;
    if let Some(parent) = rel.parent() {
        for c in parent.components() {
            d.push(c);
            real_dirs(std::slice::from_ref(&d))?;
        }
    }
    let p = root.join(rel);
    write_new(&p, &[])?;
    let mut f = std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW).open(&p)?;
    std::fs::File::set_permissions(&f, std::fs::Permissions::from_mode(0o600))?;
    std::io::Write::write_all(&mut f, body)?;
    Ok(())
}

/// Writes a file wicket owns into an agent-written tree: whatever is at `p` (a symlink, say) is
/// removed first, and the file is created new, never followed.
pub fn write_new(p: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            bundle::make_writable(p)?;
            std::fs::remove_dir_all(p)?;
        }
        Ok(_) => std::fs::remove_file(p)?,
        Err(_) => {}
    }
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(p)?;
    f.write_all(body)?;
    Ok(())
}

/// The bytes `dir` takes on disk (allocated blocks, so a sparse file counts as what it uses).
/// Symlinks aren't followed. What a node measures a box's /tmp with, against its cap.
pub fn used_bytes(dir: &Path) -> u64 {
    fn walk(d: &Path, total: &mut u64) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                walk(&e.path(), total);
            } else {
                use std::os::unix::fs::MetadataExt;
                *total += m.blocks() * 512;
            }
        }
    }
    let mut total = 0;
    walk(dir, &mut total);
    total
}

#[cfg(test)]
mod outbox_tests {
    use super::{read_outbox, write_owned};
    use std::os::unix::fs::symlink;

    fn root(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-outbox-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("workspace/out")).unwrap();
        d
    }

    #[test]
    fn a_plain_result_is_read() {
        let d = root("plain");
        std::fs::write(d.join("workspace/out/result.json"), b"{\"ok\":1}").unwrap();
        assert_eq!(read_outbox(&d, 64).as_deref(), Some(&b"{\"ok\":1}"[..]));
        std::fs::write(d.join("workspace/out/result.json"), vec![b' '; 65]).unwrap();
        assert_eq!(read_outbox(&d, 64), None, "too big");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A box can't make the host read some other file through its outbox.
    #[test]
    fn links_and_special_files_are_not_followed() {
        let d = root("links");
        let secret = d.join("secret.json");
        std::fs::write(&secret, b"{\"token\":\"x\"}").unwrap();
        symlink("../../secret.json", d.join("workspace/out/result.json")).unwrap();
        assert_eq!(read_outbox(&d, 64), None, "file link");
        std::fs::remove_file(d.join("workspace/out/result.json")).unwrap();
        std::fs::create_dir_all(d.join("elsewhere")).unwrap();
        std::fs::copy(&secret, d.join("elsewhere/result.json")).unwrap();
        std::fs::remove_dir(d.join("workspace/out")).unwrap();
        symlink("../elsewhere", d.join("workspace/out")).unwrap();
        assert_eq!(read_outbox(&d, 64), None, "directory link");
        std::fs::remove_file(d.join("workspace/out")).unwrap();
        std::fs::create_dir(d.join("workspace/out")).unwrap();
        symlink("/dev/zero", d.join("workspace/out/result.json")).unwrap();
        assert_eq!(read_outbox(&d, 64), None, "device link");
        std::fs::remove_file(d.join("workspace/out/result.json")).unwrap();
        let fifo = std::ffi::CString::new(d.join("workspace/out/result.json").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(read_outbox(&d, 64), None, "fifo");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Restored state can't redirect wicket's own writes onto a host file.
    #[test]
    fn owned_writes_replace_links() {
        let d = root("owned");
        let victim = d.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let st = d.join("state");
        std::fs::create_dir_all(st.join("claude")).unwrap();
        symlink(&victim, st.join("claude/.credentials.json")).unwrap();
        std::fs::create_dir_all(d.join("vdir")).unwrap();
        symlink(d.join("vdir"), st.join("launcher")).unwrap();
        write_owned(&st, "claude/.credentials.json", b"placeholder").unwrap();
        write_owned(&st, "launcher/file0", b"prompt").unwrap();
        // A link deeper in a harness's config (its skills directory, say), as its node writes them.
        std::fs::create_dir_all(d.join("sdir")).unwrap();
        symlink(d.join("sdir"), st.join("claude/skills")).unwrap();
        write_owned(&st, wicket_agent::claude::BOX_SKILL_FILE, wicket_agent::BOX_SKILL.as_bytes()).unwrap();
        assert!(std::fs::read_dir(d.join("sdir")).unwrap().next().is_none());
        assert_eq!(std::fs::read(st.join(wicket_agent::claude::BOX_SKILL_FILE)).unwrap(), wicket_agent::BOX_SKILL.as_bytes());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(std::fs::read_dir(d.join("vdir")).unwrap().next().is_none());
        assert_eq!(std::fs::read(st.join("claude/.credentials.json")).unwrap(), b"placeholder");
        assert!(std::fs::symlink_metadata(st.join("launcher")).unwrap().is_dir());
        assert!(write_owned(&st, "../x", b"").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
/// Makes sure each of `dirs` is a real directory, not a symlink or a file: they come from a bundle the
/// agent wrote, and wicket mounts them and writes into them on the host.
pub fn real_dirs(dirs: &[PathBuf]) -> Result<()> {
    for d in dirs {
        match std::fs::symlink_metadata(d) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                std::fs::remove_file(d)?;
                std::fs::create_dir_all(d)?;
            }
            Err(_) => std::fs::create_dir_all(d)?,
        }
    }
    Ok(())
}
