//! The installation's image policy (`<data dir>/images.yaml`, #192): whether every image a run may
//! start must be pinned by digest.
//!
//! ```yaml
//! require_digests: true
//! ```
//!
//! With it, a run is refused unless its own image and every entry of its zone's `images` are pinned
//! (`name@sha256:…`; `wicket zone pin MANIFEST` rewrites tags to their current digests). The
//! installation's own agent image (built by this wicket from the sources it embeds) is exempt: it
//! is resolved and recorded like any other when its box starts. Spawns then can only start pinned
//! images, or the parent's own image pinned to the digest it started as, wherever they are decided.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagesPolicy {
    #[serde(default)]
    pub require_digests: bool,
}

pub fn path() -> std::path::PathBuf {
    crate::data_dir().join("images.yaml")
}

pub fn load() -> Result<ImagesPolicy> {
    match std::fs::read_to_string(path()) {
        Ok(t) => serde_yaml::from_str(&t).with_context(|| path().display().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ImagesPolicy::default()),
        Err(e) => Err(e).with_context(|| path().display().to_string()),
    }
}

/// Whether a run of `m` starting `image` may start under the installation's policy.
pub fn check(m: &wicket_core::Manifest, image: &str, default_image: &str) -> Result<()> {
    check_with(&load()?, m, image, default_image)
}

pub fn check_with(p: &ImagesPolicy, m: &wicket_core::Manifest, image: &str, default_image: &str) -> Result<()> {
    if !p.require_digests {
        return Ok(());
    }
    let mut tags: Vec<&str> = m.zone.images.iter().map(String::as_str).filter(|i| !wicket_core::image::is_pinned(i)).collect();
    if image != default_image && !wicket_core::image::is_pinned(image) {
        tags.insert(0, image);
    }
    if !tags.is_empty() {
        bail!(
            "this installation requires images pinned by digest ({}), and these are tags: {}. Pin them: wicket zone pin <manifest>",
            path().display(),
            tags.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_digests_refuse_tags_but_not_the_installation_s_own_image() {
        let pin = format!("img@sha256:{}", "a".repeat(64));
        let m = |images: &str| {
            wicket_core::Manifest::from_yaml(&format!(
                "task: t\nagent: {{name: a}}\nzone: {{name: z, llm: {{secret: m}}, images: [{images}]}}"
            ))
            .unwrap()
        };
        let on = ImagesPolicy { require_digests: true };
        assert!(check_with(&ImagesPolicy::default(), &m("img:tag"), "img:tag", "dflt").is_ok(), "off by default");
        assert!(check_with(&on, &m(&pin), &pin, "dflt").is_ok());
        assert!(check_with(&on, &m(&pin), "dflt", "dflt").is_ok(), "the installation's own image");
        let e = check_with(&on, &m(&format!("{pin}, img:tag")), &pin, "dflt").unwrap_err().to_string();
        assert!(e.contains("img:tag") && e.contains("wicket zone pin"), "{e}");
        assert!(check_with(&on, &m(&pin), "img:tag", "dflt").is_err(), "its own image a tag");
    }
}
