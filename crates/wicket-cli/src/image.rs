//! `wicket image`: the agent image's build context is the image directory plus the in-box
//! forwarder's source, which the Dockerfile compiles in a builder stage.
//!
//! The forwarder's source and the image directory are embedded in this binary, so `wicket image`
//! builds the image that matches the wicket that runs the box, from anywhere (#162). Each build's
//! image is tagged with its build id ([`tag_for`]): `wicket self update` builds the new version's
//! before switching to it, new boxes of a staged version use it ([`effective`]), and a rollback finds
//! the old one still there. Running boxes keep the image they started with.

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

/// The image directory (`images/claude-code`), path relative to it and contents. A test checks the
/// list is complete.
const IMAGE_SOURCES: &[(&str, &str)] = &[
    ("Dockerfile", include_str!("../../../images/claude-code/Dockerfile")),
    ("wicket-entry", include_str!("../../../images/claude-code/wicket-entry")),
];

/// The agent image's repository, and the tag a box gets when nothing names another.
pub const REPO: &str = "wicket/claude-code";
pub const DEFAULT: &str = "wicket/claude-code:poc";

/// A build's own image: `wicket/claude-code:<build id>`.
pub fn tag_for(build_id: &str) -> String {
    format!("{REPO}:{}", &build_id[..12.min(build_id.len())])
}

/// The image a new box gets for `image`: the default, from a staged version (`wicket self`), is
/// that version's own image; anything else is what it says.
pub fn effective(image: &str) -> String {
    if image == DEFAULT && crate::update::is_staged() {
        if let Ok(b) = crate::nodesrv::build_id() {
            return tag_for(&b);
        }
    }
    image.to_string()
}

/// The tag `wicket image` builds: an explicit `--tag` exactly as given, else `own`, the
/// installation's own image ([`effective`] of [`DEFAULT`]).
pub fn build_tag(explicit: Option<String>, own: &str) -> String {
    explicit.unwrap_or_else(|| own.to_string())
}

/// Whether a Dockerfile declares the build argument `name` (`ARG NAME` or `ARG NAME=default`).
pub fn declares_arg(dockerfile: &str, name: &str) -> bool {
    dockerfile.lines().any(|l| {
        let mut w = l.split_whitespace();
        w.next().is_some_and(|k| k.eq_ignore_ascii_case("ARG")) && w.next().is_some_and(|a| a.split('=').next() == Some(name))
    })
}

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

/// The build context from this binary alone: the embedded image directory and forwarder.
pub fn embedded_context() -> Result<BuildContext> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let src = std::env::temp_dir().join(format!("wicket-image-src-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&src).with_context(|| format!("creating {}", src.display()))?;
    let _clean = BuildContext { dir: src.clone() };
    for (rel, text) in IMAGE_SOURCES {
        std::fs::write(src.join(rel), text)?;
    }
    context(&src)
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
    fn the_embedded_image_dir_is_the_whole_directory() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../images/claude-code");
        let mut on_disk = vec![];
        files(&root, &root, &mut on_disk);
        on_disk.sort();
        let mut embedded: Vec<String> = IMAGE_SOURCES.iter().map(|(p, _)| p.to_string()).collect();
        embedded.sort();
        assert_eq!(embedded, on_disk, "add new images/claude-code files to IMAGE_SOURCES");
        let ctx = embedded_context().unwrap();
        assert!(ctx.dir.join("Dockerfile").is_file() && ctx.dir.join("wicket-fwd/src/main.rs").is_file());
        assert_eq!(tag_for(&"ab".repeat(32)), "wicket/claude-code:abababababab");
    }

    #[test]
    fn an_explicit_tag_is_kept_and_the_default_is_the_own_image() {
        // On an installed version the own image is the build-id tag (#277).
        let own = tag_for(&"cd".repeat(32));
        assert_eq!(build_tag(Some(DEFAULT.to_string()), &own), DEFAULT);
        assert_eq!(build_tag(Some("wicket-self:dev".to_string()), &own), "wicket-self:dev");
        assert_eq!(build_tag(None, &own), "wicket/claude-code:cdcdcdcdcdcd");
        // Not installed: the default is the default.
        assert_eq!(build_tag(None, DEFAULT), DEFAULT);
    }

    #[test]
    fn the_self_hosting_dockerfile_declares_base() {
        let df = include_str!("../../../examples/self-hosting/Dockerfile");
        assert!(declares_arg(df, "BASE"));
        assert!(df.contains("FROM ${BASE}"));
        assert!(!declares_arg(df, "BAS"));
        assert!(declares_arg("arg BASE\nFROM $BASE", "BASE"));
        assert!(!declares_arg(IMAGE_SOURCES[0].1, "BASE"));
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
