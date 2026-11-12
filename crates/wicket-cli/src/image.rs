//! `wicket image`: the agent image's build context is the image directory plus the in-box
//! forwarder's source, which the Dockerfile compiles in a builder stage.
//!
//! The forwarder's source is embedded in this binary, so `wicket image` builds the forwarder that
//! matches the wicket that runs the box, from any working directory that has the image directory.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// The wicket-fwd crate, path relative to the crate root and contents. It has no dependencies and
/// no workspace inheritance, so these files alone build it. A test checks the list is complete.
const FWD_SOURCES: &[(&str, &str)] = &[
    ("Cargo.toml", include_str!("../../wicket-fwd/Cargo.toml")),
    ("src/main.rs", include_str!("../../wicket-fwd/src/main.rs")),
    ("src/lib.rs", include_str!("../../wicket-fwd/src/lib.rs")),
    ("src/copy.rs", include_str!("../../wicket-fwd/src/copy.rs")),
    ("src/spec.rs", include_str!("../../wicket-fwd/src/spec.rs")),
    ("src/sys.rs", include_str!("../../wicket-fwd/src/sys.rs")),
    ("src/frame.rs", include_str!("../../wicket-fwd/src/frame.rs")),
    ("src/udp.rs", include_str!("../../wicket-fwd/src/udp.rs")),
    ("src/stdin.rs", include_str!("../../wicket-fwd/src/stdin.rs")),
];

/// A temporary build context, removed on drop.
pub struct BuildContext {
    pub dir: PathBuf,
}

impl Drop for BuildContext {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Copies `image_dir` into a fresh temporary directory and adds the forwarder's source under
/// `wicket-fwd/`.
pub fn context(image_dir: &Path) -> Result<BuildContext> {
    if !image_dir.join("Dockerfile").is_file() {
        bail!("{}: no Dockerfile (is --dir the image directory?)", image_dir.display());
    }
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let ctx = BuildContext { dir: std::env::temp_dir().join(format!("wicket-image-{}-{nonce}", std::process::id())) };
    std::fs::create_dir(&ctx.dir).with_context(|| format!("creating {}", ctx.dir.display()))?;
    copy_tree(image_dir, &ctx.dir)?;
    let fwd = ctx.dir.join("wicket-fwd");
    for (rel, text) in FWD_SOURCES {
        let p = fwd.join(rel);
        std::fs::create_dir_all(p.parent().expect("a relative file path has a parent"))?;
        std::fs::write(&p, text).with_context(|| format!("writing {}", p.display()))?;
    }
    Ok(ctx)
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    for e in std::fs::read_dir(from).with_context(|| format!("reading {}", from.display()))? {
        let e = e?;
        let (src, dst) = (e.path(), to.join(e.file_name()));
        let ty = e.file_type()?;
        if ty.is_dir() {
            std::fs::create_dir_all(&dst)?;
            copy_tree(&src, &dst)?;
        } else if ty.is_file() {
            // fs::copy keeps the permission bits (wicket-entry's executable bit).
            std::fs::copy(&src, &dst).with_context(|| format!("copying {}", src.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(root: &Path, dir: &Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                files(root, &p, out);
            } else {
                out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
            }
        }
    }

    #[test]
    fn the_embedded_forwarder_is_the_whole_crate() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../wicket-fwd");
        let mut on_disk = vec!["Cargo.toml".to_string()];
        files(&root, &root.join("src"), &mut on_disk);
        on_disk.sort();
        let mut embedded: Vec<String> = FWD_SOURCES.iter().map(|(p, _)| p.to_string()).collect();
        embedded.sort();
        assert_eq!(embedded, on_disk, "add new wicket-fwd source files to FWD_SOURCES");
        // Standalone: nothing inherited from the workspace, no dependencies to fetch.
        let manifest = FWD_SOURCES[0].1;
        assert!(!manifest.contains(".workspace"), "wicket-fwd must not inherit from the workspace");
        let deps = manifest.split("[dependencies]").nth(1).unwrap_or("");
        assert!(deps.lines().all(|l| l.trim().is_empty() || l.trim_start().starts_with('#')), "wicket-fwd must have no dependencies");
    }

    #[test]
    fn the_context_holds_the_image_dir_and_the_forwarder() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../images/claude-code");
        let ctx = context(&dir).unwrap();
        assert!(ctx.dir.join("Dockerfile").is_file());
        assert!(ctx.dir.join("wicket-entry").is_file());
        assert!(ctx.dir.join("wicket-fwd/src/main.rs").is_file());
        let df = std::fs::read_to_string(ctx.dir.join("Dockerfile")).unwrap();
        assert!(df.contains("COPY wicket-fwd "), "the Dockerfile builds the forwarder from the context");
        assert!(!df.contains("socat"), "socat is gone from the image");
        let d = ctx.dir.clone();
        drop(ctx);
        assert!(!d.exists());
        assert!(context(Path::new("/nonexistent")).is_err());
    }
}
