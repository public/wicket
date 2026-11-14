//! The installation's image policy (`<data dir>/images.yaml`, #192, #191): whether every image a run
//! may start must be pinned by digest, and the registries its nodes may pull images from.
//!
//! ```yaml
//! require_digests: true
//! registries:
//!   - host: registry.example.com      # host[:port], as image names give it
//!     secret: registry-login          # optional: a vault secret bound to the host, `user:password` or a token
//!     auth_hosts: [auth.example.com]  # where its token service is, if elsewhere
//!     blob_hosts: [cdn.example.com]   # where it redirects blob downloads, if elsewhere
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
    /// Registries a node may pull a pinned image from, host-side (#191). None: images reach nodes
    /// from the control host only.
    #[serde(default)]
    pub registries: Vec<Registry>,
}

/// A registry nodes may pull from (#191): its host, and the only other hosts the pull may reach.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub host: String,
    /// A vault secret (`wicket secret set NAME --host <host>`): `user:password`, or a bearer token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_hosts: Vec<String>,
}

/// The registry host of an image name and the repository in it, as the distribution API names
/// them (`registry.example.com:5000/team/agent:1` → (`registry.example.com:5000`, `team/agent`)). A
/// name without a registry host is Docker Hub's (`registry-1.docker.io`, `library/` for one part).
pub fn registry_of(image: &str) -> Option<(String, String)> {
    let r = wicket_core::image::parse(image).ok()?;
    if r.name.is_empty() {
        return None;
    }
    let repo = wicket_core::image::repository(&r.name);
    let (first, rest) = repo.split_once('/').unwrap_or(("", repo));
    if first.contains('.') || first.contains(':') || first == "localhost" {
        return Some((first.to_string(), rest.to_string()));
    }
    let rest = if repo.contains('/') { repo.to_string() } else { format!("library/{repo}") };
    Some(("registry-1.docker.io".into(), rest))
}

impl ImagesPolicy {
    /// The registry entry `image` may be pulled from, and its repository there, if any.
    pub fn registry_for(&self, image: &str) -> Option<(Registry, String)> {
        let (host, repo) = registry_of(image)?;
        let host_of = |h: &str| if h == "docker.io" || h == "index.docker.io" { "registry-1.docker.io".to_string() } else { h.to_string() };
        self.registries.iter().find(|r| host_of(&r.host) == host).map(|r| (Registry { host: host.clone(), ..r.clone() }, repo))
    }
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
        let on = ImagesPolicy { require_digests: true, ..Default::default() };
        assert!(check_with(&ImagesPolicy::default(), &m("img:tag"), "img:tag", "dflt").is_ok(), "off by default");
        assert!(check_with(&on, &m(&pin), &pin, "dflt").is_ok());
        assert!(check_with(&on, &m(&pin), "dflt", "dflt").is_ok(), "the installation's own image");
        let e = check_with(&on, &m(&format!("{pin}, img:tag")), &pin, "dflt").unwrap_err().to_string();
        assert!(e.contains("img:tag") && e.contains("wicket zone pin"), "{e}");
        assert!(check_with(&on, &m(&pin), "img:tag", "dflt").is_err(), "its own image a tag");
    }

    #[test]
    fn images_name_their_registry_and_only_listed_ones_are_pulled_from() {
        assert_eq!(registry_of("registry.example.com:5000/team/agent:1"), Some(("registry.example.com:5000".into(), "team/agent".into())));
        assert_eq!(registry_of("ubuntu:24.04"), Some(("registry-1.docker.io".into(), "library/ubuntu".into())));
        assert_eq!(registry_of("wicket/claude-code:abc"), Some(("registry-1.docker.io".into(), "wicket/claude-code".into())));
        assert_eq!(registry_of(&format!("localhost/x@sha256:{}", "a".repeat(64))), Some(("localhost".into(), "x".into())));
        assert_eq!(registry_of(&format!("sha256:{}", "a".repeat(64))), None);
        let p: ImagesPolicy =
            serde_yaml::from_str("registries:\n  - host: registry.example.com\n    secret: reg\n  - host: docker.io\n").unwrap();
        let (r, repo) = p.registry_for("registry.example.com/team/agent:1").unwrap();
        assert_eq!((r.host.as_str(), r.secret.as_deref(), repo.as_str()), ("registry.example.com", Some("reg"), "team/agent"));
        assert_eq!(p.registry_for("ubuntu:24.04").unwrap().0.host, "registry-1.docker.io");
        assert!(p.registry_for("other.example.com/x:1").is_none());
        assert!(serde_yaml::from_str::<ImagesPolicy>("registries: [{host: a, typo: 1}]").is_err());
    }
}
