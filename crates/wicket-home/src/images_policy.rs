//! The installation's image registries (`<data dir>/images.yaml`, #191): the registries its nodes
//! may pull images from.
//!
//! ```yaml
//! registries:
//!   - host: registry.example.com      # host[:port], as image names give it
//!     secret: registry-login          # optional: a vault secret bound to the host, `user:password` or a token
//!     auth_hosts: [auth.example.com]  # where its token service is, if elsewhere
//!     blob_hosts: [cdn.example.com]   # where it redirects blob downloads, if elsewhere
//! ```
//!
//! Whether an image may run is no longer this file's (#258): a pinned image is accepted by a grant
//! on its digest, the one "may this digest run" check (`wicket_control::digest`). The old
//! `require_digests` is still read, so a file that sets it opens, and ignored.

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagesPolicy {
    /// Ignored since #258 (a pinned image is accepted by a grant on its digest); read so an older
    /// file still opens.
    #[serde(default)]
    pub require_digests: bool,
    /// Registries a node may pull a pinned image from, host-side (#191). None: images reach nodes
    /// from the control host only.
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
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
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default", skip_serializing_if = "Vec::is_empty")]
    pub auth_hosts: Vec<String>,
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default", skip_serializing_if = "Vec::is_empty")]
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
    if first == "docker.io" || first == "index.docker.io" {
        let rest = if rest.contains('/') { rest.to_string() } else { format!("library/{rest}") };
        return Some(("registry-1.docker.io".into(), rest));
    }
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
        Ok(t) => wicket_core::yaml::from_str(&t).with_context(|| path().display().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ImagesPolicy::default()),
        Err(e) => Err(e).with_context(|| path().display().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #258: a file from before still opens; `require_digests` is read and ignored.
    #[test]
    fn an_older_file_with_require_digests_still_opens() {
        let p: ImagesPolicy = wicket_core::yaml::from_str("require_digests: true\nregistries: []\n").unwrap();
        assert!(p.require_digests && p.registries.is_empty());
    }

    #[test]
    fn images_name_their_registry_and_only_listed_ones_are_pulled_from() {
        assert_eq!(registry_of("registry.example.com:5000/team/agent:1"), Some(("registry.example.com:5000".into(), "team/agent".into())));
        assert_eq!(registry_of("ubuntu:24.04"), Some(("registry-1.docker.io".into(), "library/ubuntu".into())));
        assert_eq!(registry_of("docker.io/ubuntu:24.04"), Some(("registry-1.docker.io".into(), "library/ubuntu".into())));
        assert_eq!(registry_of("docker.io/wicket/x:1"), Some(("registry-1.docker.io".into(), "wicket/x".into())));
        assert_eq!(registry_of("wicket/claude-code:abc"), Some(("registry-1.docker.io".into(), "wicket/claude-code".into())));
        assert_eq!(registry_of(&format!("localhost/x@sha256:{}", "a".repeat(64))), Some(("localhost".into(), "x".into())));
        assert_eq!(registry_of(&format!("sha256:{}", "a".repeat(64))), None);
        let p: ImagesPolicy =
            wicket_core::yaml::from_str("registries:\n  - host: registry.example.com\n    secret: reg\n  - host: docker.io\n").unwrap();
        let (r, repo) = p.registry_for("registry.example.com/team/agent:1").unwrap();
        assert_eq!((r.host.as_str(), r.secret.as_deref(), repo.as_str()), ("registry.example.com", Some("reg"), "team/agent"));
        assert_eq!(p.registry_for("ubuntu:24.04").unwrap().0.host, "registry-1.docker.io");
        assert_eq!(p.registry_for("docker.io/library/ubuntu:24.04").unwrap().0.host, "registry-1.docker.io");
        assert!(p.registry_for("other.example.com/x:1").is_none());
        assert!(wicket_core::yaml::from_str::<ImagesPolicy>("registries: [{host: a, typo: 1}]").is_err());
        // An empty key, as serde_yaml read it: no registries, not an error (#326).
        assert!(wicket_core::yaml::from_str::<ImagesPolicy>("registries:\n").unwrap().registries.is_empty());
    }
}
