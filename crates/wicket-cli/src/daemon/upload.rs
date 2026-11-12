//! Files the caller names (a manifest, its program's source, a `--workdir`), sent as content: the
//! `wicket` user can't read the caller's files, and must not read files the caller merely names
//! (`--workdir /var/lib/wicket` would copy the vault into a box).
//!
//! The daemon writes them into a fresh staging directory it owns. Paths are relative, plain names
//! only; files are created new, never through a link; symlinks (copied into the box as they are,
//! like `cp -a` does) are made last, and only inside directories made here.

use super::proto::{self, Entry};
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// The most an upload may carry in all.
pub const MAX_TOTAL: u64 = 2 << 30;

/// Sends `root` (a file or a directory tree) as `role`.
pub fn send(w: &mut impl Write, role: &str, root: &Path) -> Result<()> {
    let meta = std::fs::metadata(root).with_context(|| root.display().to_string())?;
    if meta.is_file() {
        return send_file(w, role, "", root, meta.permissions().mode());
    }
    if !meta.is_dir() {
        bail!("{} is neither a file nor a directory", root.display());
    }
    entry(w, role, "", "dir", 0o700, None, b"", false)?;
    walk(w, role, root, Path::new(""))
}

fn walk(w: &mut impl Write, role: &str, dir: &Path, rel: &Path) -> Result<()> {
    let mut names: Vec<_> = std::fs::read_dir(dir).with_context(|| dir.display().to_string())?.collect::<Result<_, _>>()?;
    names.sort_by_key(|e| e.file_name());
    for e in names {
        let full = e.path();
        let r = rel.join(e.file_name());
        let rs = r.to_str().with_context(|| format!("{} is not UTF-8", full.display()))?.to_string();
        let ty = e.file_type()?;
        if ty.is_symlink() {
            let t = std::fs::read_link(&full)?;
            let t = t.to_str().with_context(|| format!("{}'s target is not UTF-8", full.display()))?.to_string();
            entry(w, role, &rs, "symlink", 0, Some(t), b"", false)?;
        } else if ty.is_dir() {
            entry(w, role, &rs, "dir", 0o700, None, b"", false)?;
            walk(w, role, &full, &r)?;
        } else if ty.is_file() {
            send_file(w, role, &rs, &full, e.metadata()?.permissions().mode())?;
        }
        // Sockets, fifos and devices are skipped, as copying a project would.
    }
    Ok(())
}

fn send_file(w: &mut impl Write, role: &str, rel: &str, path: &Path, mode: u32) -> Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).with_context(|| path.display().to_string())?;
    let mut buf = vec![0u8; proto::MAX_FRAME];
    let mut first = true;
    loop {
        let n = read_full(&mut f, &mut buf)?;
        if n > 0 || first {
            entry(w, role, rel, "file", mode & 0o755, None, &buf[..n], !first)?;
        }
        first = false;
        if n < buf.len() {
            return Ok(());
        }
    }
    fn read_full(f: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            match f.read(&mut buf[n..])? {
                0 => break,
                k => n += k,
            }
        }
        Ok(n)
    }
}

#[allow(clippy::too_many_arguments)]
fn entry(
    w: &mut impl Write,
    role: &str,
    path: &str,
    kind: &str,
    mode: u32,
    target: Option<String>,
    data: &[u8],
    append: bool,
) -> Result<()> {
    let e = Entry { role: role.into(), path: path.into(), kind: kind.into(), mode, target, append };
    proto::write_frame(w, proto::kind::UPLOAD, &proto::upload_frame(&e, data)?)
}

/// A relative path of plain names, or an error.
pub fn plain(rel: &str) -> Result<PathBuf> {
    let p = Path::new(rel);
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            _ => bail!("upload path {rel:?} is not a plain relative path"),
        }
    }
    Ok(out)
}

/// Where uploads are written, by role.
pub struct Stage {
    pub dir: PathBuf,
    roots: Vec<(String, PathBuf)>,
    total: u64,
    links: Vec<(PathBuf, String)>,
}

impl Stage {
    /// A fresh staging directory under `parent` (mode 0700). `roots` maps each role to where its
    /// root goes, relative to the staging directory.
    pub fn new(parent: &Path, roots: Vec<(String, PathBuf)>) -> Result<Stage> {
        std::fs::create_dir_all(parent)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("random: {e}"))?;
        let dir = parent.join(hex::encode(nonce));
        std::fs::create_dir(&dir).with_context(|| dir.display().to_string())?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(Stage { dir, roots, total: 0, links: vec![] })
    }

    /// Where `role`'s root is.
    pub fn root(&self, role: &str) -> Option<PathBuf> {
        self.roots.iter().find(|(r, _)| r == role).map(|(_, p)| self.dir.join(p))
    }

    /// Writes one entry.
    pub fn add(&mut self, e: &Entry, data: &[u8]) -> Result<()> {
        let root = self.root(&e.role).with_context(|| format!("unexpected upload role {:?}", e.role))?;
        let rel = plain(&e.path)?;
        // (join("") would add a trailing slash, which a file's path can't have.)
        let path = if rel.as_os_str().is_empty() { root.clone() } else { root.join(&rel) };
        self.total += data.len() as u64;
        if self.total > MAX_TOTAL {
            bail!("uploads are limited to {} GiB", MAX_TOTAL >> 30);
        }
        match e.kind.as_str() {
            "dir" => {
                // A role's root (and the directories above it) are made here; anything else must
                // be new, inside a directory made here.
                if rel.as_os_str().is_empty() {
                    std::fs::create_dir_all(&path)?;
                } else {
                    self.check_parent(&path)?;
                    std::fs::create_dir(&path).with_context(|| e.path.clone())?;
                }
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
            }
            "file" => {
                if rel.as_os_str().is_empty() {
                    std::fs::create_dir_all(path.parent().expect("a role root has a parent"))?;
                } else {
                    self.check_parent(&path)?;
                }
                let mut o = std::fs::OpenOptions::new();
                o.write(true).custom_flags(libc::O_NOFOLLOW);
                if e.append {
                    o.append(true);
                } else {
                    o.create_new(true).mode(0o600 | (e.mode & 0o700));
                }
                o.open(&path).with_context(|| format!("upload {}", e.path))?.write_all(data)?;
            }
            "symlink" => {
                let t = e.target.clone().with_context(|| "a symlink without a target".to_string())?;
                if rel.as_os_str().is_empty() {
                    bail!("an upload's root can't be a symlink");
                }
                self.links.push((path, t));
            }
            k => bail!("unknown upload kind {k:?}"),
        }
        Ok(())
    }

    /// Every directory between the staging directory and `path`'s parent must be a real directory
    /// (no symlinks exist until [`Stage::finish`], but a file might stand where a directory is
    /// claimed).
    fn check_parent(&self, path: &Path) -> Result<()> {
        let parent = path.parent().context("no parent")?;
        let rel = parent.strip_prefix(&self.dir).context("outside the staging directory")?;
        let mut p = self.dir.clone();
        for c in rel.components() {
            p.push(c);
            let m = std::fs::symlink_metadata(&p).with_context(|| format!("{} is not an uploaded directory", p.display()))?;
            if !m.file_type().is_dir() {
                bail!("{} is not an uploaded directory", p.display());
            }
        }
        Ok(())
    }

    /// Makes the symlinks, after every file and directory.
    pub fn finish(&mut self) -> Result<()> {
        for (path, target) in std::mem::take(&mut self.links) {
            self.check_parent(&path)?;
            std::os::unix::fs::symlink(&target, &path).with_context(|| format!("symlink {}", path.display()))?;
        }
        Ok(())
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Where a manifest goes in the staging directory so that its program `source` (relative to the
/// manifest, possibly with leading `..`) lands inside the staging directory too: the manifest's
/// directory, and the source's directory, both relative to the staging directory.
pub fn manifest_layout(file_name: &str, source: Option<&str>) -> Result<(PathBuf, Option<PathBuf>)> {
    let name = plain(file_name)?;
    if name.components().count() != 1 {
        bail!("bad manifest name {file_name:?}");
    }
    let Some(src) = source else {
        return Ok((PathBuf::from("m").join(name), None));
    };
    let sp = Path::new(src);
    if sp.is_absolute() {
        bail!("program source {src:?} is absolute: with wicketd, a program's source must be relative to its manifest");
    }
    // Resolve the source lexically against a manifest directory deep enough for its `..`s.
    let mut depth = 0usize;
    let mut stack: Vec<std::ffi::OsString> = vec![];
    for c in sp.components() {
        match c {
            Component::ParentDir => {
                if stack.pop().is_none() {
                    depth += 1;
                }
            }
            Component::Normal(n) => stack.push(n.to_os_string()),
            Component::CurDir => {}
            _ => bail!("bad program source {src:?}"),
        }
    }
    let mut mdir = PathBuf::from("m");
    for i in 0..depth {
        mdir.push(format!("d{i}"));
    }
    // The source, from "m": the manifest directory's path with `depth` levels removed, then the rest.
    let mut sdir = PathBuf::from("m");
    for n in stack {
        sdir.push(n);
    }
    if sdir == mdir || mdir.starts_with(&sdir) {
        bail!("program source {src:?} contains its own manifest");
    }
    Ok((mdir.join(name), Some(sdir)))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp(tag: &str) -> Tmp {
        let mut n = [0u8; 6];
        getrandom::getrandom(&mut n).unwrap();
        let d = std::env::temp_dir().join(format!("wicket-upload-{tag}-{}", hex::encode(n)));
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }

    fn replay(stage: &mut Stage, wire: &[u8]) -> Result<()> {
        let mut r = wire;
        while let Some((k, p)) = proto::read_frame(&mut r)? {
            assert_eq!(k, proto::kind::UPLOAD);
            let (e, d) = proto::parse_upload(&p)?;
            stage.add(&e, d)?;
        }
        stage.finish()
    }

    #[test]
    fn a_tree_arrives_whole_with_exec_bits_and_links() {
        let src = tmp("src");
        let s = &src.0;
        std::fs::create_dir_all(s.join("a/b")).unwrap();
        std::fs::write(s.join("a/b/run.sh"), "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(s.join("a/b/run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(s.join("top.txt"), vec![7u8; proto::MAX_FRAME + 10]).unwrap();
        std::fs::write(s.join("empty"), "").unwrap();
        std::os::unix::fs::symlink("a/b/run.sh", s.join("link")).unwrap();
        let mut wire = Vec::new();
        send(&mut wire, "workdir", s).unwrap();
        let parent = tmp("stage");
        let mut st = Stage::new(&parent.0, vec![("workdir".into(), "w".into())]).unwrap();
        replay(&mut st, &wire).unwrap();
        let w = st.root("workdir").unwrap();
        assert_eq!(std::fs::read_to_string(w.join("a/b/run.sh")).unwrap(), "#!/bin/sh\necho hi\n");
        assert!(std::fs::metadata(w.join("a/b/run.sh")).unwrap().permissions().mode() & 0o100 != 0);
        assert_eq!(std::fs::read(w.join("top.txt")).unwrap().len(), proto::MAX_FRAME + 10);
        assert_eq!(std::fs::read(w.join("empty")).unwrap().len(), 0);
        assert_eq!(std::fs::read_link(w.join("link")).unwrap(), Path::new("a/b/run.sh"));
        assert_eq!(crate::program::digest_dir(&s.join("a")).unwrap(), crate::program::digest_dir(&w.join("a")).unwrap());
        let dir = st.dir.clone();
        drop(st);
        assert!(!dir.exists(), "the stage is removed with it");
    }

    #[test]
    fn hostile_uploads_are_refused() {
        let parent = tmp("hostile");
        let outside = parent.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let mk = |path: &str, kind: &str, target: Option<&str>| Entry {
            role: "workdir".into(),
            path: path.into(),
            kind: kind.into(),
            mode: 0o644,
            target: target.map(String::from),
            append: false,
        };
        let mut st = Stage::new(&parent.0.join("s"), vec![("workdir".into(), "w".into())]).unwrap();
        st.add(&mk("", "dir", None), b"").unwrap();
        for bad in ["../x", "/etc/x", "a/../../x"] {
            assert!(st.add(&mk(bad, "file", None), b"x").is_err(), "{bad}");
        }
        assert!(st.add(&mk("x", "fifo", None), b"").is_err());
        assert!(Stage::new(&parent.0.join("s"), vec![]).unwrap().add(&mk("x", "file", None), b"").is_err(), "unknown role");
        // A link to a directory outside, then a file "through" it: the link isn't there yet when
        // files are written, and the parent check refuses to write through a non-directory.
        st.add(&mk("esc", "symlink", Some(outside.to_str().unwrap())), b"").unwrap();
        assert!(st.add(&mk("esc/pwned", "file", None), b"x").is_err());
        // A link inside a link is refused when links are made.
        st.add(&mk("esc/deeper", "symlink", Some("/")), b"").unwrap();
        assert!(st.finish().is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "nothing was written outside");
        // A second file of the same name doesn't replace the first.
        st.add(&mk("f", "file", None), b"one").unwrap();
        assert!(st.add(&mk("f", "file", None), b"two").is_err());
        // Appending can't go through a symlink either.
        std::os::unix::fs::symlink(outside.join("t"), st.root("workdir").unwrap().join("l")).unwrap();
        let mut ap = mk("l", "file", None);
        ap.append = true;
        assert!(st.add(&ap, b"x").is_err());
        assert!(!outside.join("t").exists());
    }

    #[test]
    fn a_manifest_keeps_its_program_beside_it() {
        assert_eq!(manifest_layout("task.yaml", None).unwrap(), (PathBuf::from("m/task.yaml"), None));
        assert_eq!(manifest_layout("task.yaml", Some("src")).unwrap(), (PathBuf::from("m/task.yaml"), Some(PathBuf::from("m/src"))));
        assert_eq!(
            manifest_layout("p.yaml", Some("../../programs/x")).unwrap(),
            (PathBuf::from("m/d0/d1/p.yaml"), Some(PathBuf::from("m/programs/x")))
        );
        // The source must resolve, from the staged manifest's directory, to where it is staged.
        let (m, s) = manifest_layout("p.yaml", Some("../../programs/x")).unwrap();
        let resolved = m.parent().unwrap().join("../../programs/x");
        let norm: PathBuf = resolved.components().fold(PathBuf::new(), |mut acc, c| {
            match c {
                Component::ParentDir => {
                    acc.pop();
                }
                c => acc.push(c),
            }
            acc
        });
        assert_eq!(norm, s.unwrap());
        assert!(manifest_layout("p.yaml", Some("/abs")).is_err());
        assert!(manifest_layout("p.yaml", Some(".")).is_err());
        assert!(manifest_layout("p.yaml", Some("..")).is_err());
        assert!(manifest_layout("../p.yaml", None).is_err());
    }
}
