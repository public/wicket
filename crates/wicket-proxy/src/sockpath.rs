//! Unix socket paths are limited to `sun_path` (108 bytes, including the terminating NUL), which a
//! long data dir, a long tenant or zone name or nested child runs can exceed (#105).
//!
//! [`resolve`] returns a path that can be bound: the path itself when it fits, else the same file
//! reached through a short per-directory symlink (`$XDG_RUNTIME_DIR/wicket/<hash>` or
//! `/tmp/wicket-<uid>/<hash>`, pointing at the socket's directory). The kernel follows the symlink, so
//! the socket lands in its real directory (and is still found there by bind mounts and peers). When
//! even that is too long, it fails with an error naming the path and the limit.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

/// `sizeof(sockaddr_un.sun_path)`.
pub const SUN_PATH_LIMIT: usize = 108;

/// The longest bindable path: the limit less the terminating NUL.
pub const MAX_PATH_BYTES: usize = SUN_PATH_LIMIT - 1;

/// Fails with a clear error unless `path` fits in `sun_path`.
pub fn check(path: &Path) -> io::Result<()> {
    let n = path.as_os_str().as_bytes().len();
    if n > MAX_PATH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "unix socket path {} is {n} bytes, over the {SUN_PATH_LIMIT}-byte limit (sun_path, with its NUL); use a shorter data dir or tenant/zone name",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// A path to bind for `path`: itself if it fits, else through a short symlink to its directory.
pub fn resolve(path: &Path) -> io::Result<PathBuf> {
    let too_long = match check(path) {
        Ok(()) => return Ok(path.to_path_buf()),
        Err(e) => e,
    };
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(too_long);
    };
    // Only a directory that exists can be linked to; make it absolute so the link is valid anywhere.
    let dir = std::fs::canonicalize(dir)?;
    let short = short_link(&dir)?.join(name);
    // The backstop: still too long (the file's own name is), so say so, naming the real path.
    if check(&short).is_err() {
        return Err(too_long);
    }
    Ok(short)
}

fn short_base() -> io::Result<PathBuf> {
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let base = match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|p| p.is_absolute() && p.is_dir()) {
        Some(x) => x.join("wicket"),
        None => std::env::temp_dir().join(format!("wicket-{uid}")),
    };
    match std::fs::DirBuilder::new().mode(0o700).create(&base) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    // Never trust a directory someone else made in a shared temp dir.
    let m = std::fs::symlink_metadata(&base)?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o022 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is not a private directory of ours", base.display())));
    }
    Ok(base)
}

fn short_link(dir: &Path) -> io::Result<PathBuf> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    dir.hash(&mut h);
    let link = short_base()?.join(format!("{:016x}", h.finish()));
    for _ in 0..3 {
        match std::fs::read_link(&link) {
            Ok(t) if t == dir => return Ok(link),
            Ok(_) => {
                let _ = std::fs::remove_file(&link);
            }
            Err(_) => {}
        }
        match std::os::unix::fs::symlink(dir, &link) {
            Ok(()) => return Ok(link),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other(format!("could not link {} for {}", link.display(), dir.display())))
}

/// Binds a unix listener at `path`, replacing a stale socket there; see [`resolve`].
pub fn bind(path: &Path) -> io::Result<tokio::net::UnixListener> {
    let p = resolve(path)?;
    let _ = std::fs::remove_file(&p);
    tokio::net::UnixListener::bind(&p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileTypeExt;

    fn long_dir(tag: &str, pad: usize) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-sockpath-{tag}-{}", std::process::id())).join("x".repeat(pad));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_short_path_is_used_as_it_is() {
        let p = Path::new("/tmp/a/egress.sock");
        assert_eq!(resolve(p).unwrap(), p);
    }

    #[tokio::test]
    async fn a_long_data_dir_binds_through_a_short_link() {
        let d = long_dir("long", 120);
        let sock = d.join("egress.sock");
        assert!(sock.as_os_str().len() > MAX_PATH_BYTES);
        assert!(tokio::net::UnixListener::bind(&sock).is_err(), "the plain bind should hit the limit");
        let l = bind(&sock).unwrap();
        // The socket is in the real directory, and reachable by its short path.
        assert!(std::fs::symlink_metadata(&sock).unwrap().file_type().is_socket());
        let short = resolve(&sock).unwrap();
        assert!(short.as_os_str().len() <= MAX_PATH_BYTES);
        let c = tokio::spawn(async move { tokio::net::UnixStream::connect(short).await });
        let (_s, _) = l.accept().await.unwrap();
        c.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }

    #[test]
    fn a_name_too_long_even_for_the_short_link_fails_clearly() {
        let d = long_dir("name", 10);
        let sock = d.join(format!("{}.sock", "n".repeat(120)));
        let e = resolve(&sock).unwrap_err().to_string();
        assert!(e.contains(&sock.display().to_string()) && e.contains("108-byte limit"), "{e}");
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }

    #[tokio::test]
    async fn deeply_nested_child_runs_bind_their_link_sockets() {
        let mut d = std::env::temp_dir().join(format!("wicket-sockpath-nest-{}", std::process::id()));
        let top = d.clone();
        for i in 0..6 {
            d = d.join(format!("runs/run_01JABCDEFGHJKMNPQRSTVWXY{i:02}/children"));
        }
        let d = d.join("sock");
        std::fs::create_dir_all(&d).unwrap();
        let sock = d.join("link-01JABCDEFGHJKMNPQRSTVWXYZ0.sock");
        assert!(sock.as_os_str().len() > MAX_PATH_BYTES);
        let l = bind(&sock).unwrap();
        let short = resolve(&sock).unwrap();
        let c = tokio::spawn(async move { tokio::net::UnixStream::connect(short).await });
        let (_s, _) = l.accept().await.unwrap();
        c.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(top);
    }
}
