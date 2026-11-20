//! The installation's image policy (`<data dir>/images.yaml`, #192, #191): whether a run may
//! start a tag image, and the registries its nodes may pull images from.
//!
//! ```yaml
//! require_digests: true
//! registries:
//!   - host: registry.example.com      # host[:port], as image names give it
//!     secret: registry-login          # optional: a vault secret bound to the host, `user:password` or a token
//!     auth_hosts: [auth.example.com]  # where its token service is, if elsewhere
//!     blob_hosts: [cdn.example.com]   # where it redirects blob downloads, if elsewhere

//! trust:                              # image signatures (#191): which keys must have signed what
//!   default: allow-unsigned           # or require-signed: for images no rule matches
//!   rules:                            # the first that matches an image (and its zone) decides
//!     - repositories: ["registry.example.com/team/*"]   # host/repository; `*` matches anything
//!       zones: ["prod-*"]             # optional: only for these zones
//!       keys: [keys/team.pub]         # PEM public keys, relative to the data dir
//!       require: signed               # the default; or allow-unsigned (checked if signed)
//! ```
//!
//! `trust` is checked on the control host before a box starts (`wicket_control::imagetrust`), never
//! in the box: the signature is fetched from the image's registry (one of `registries`) and must be by one
//! of the rule's keys over exactly the image's digest ([`wicket_chan::signature`]). The image's node
//! checks its bytes against that digest. Unsigned, signed by another key or over another digest,
//! an image a rule requires signed is refused, and so is a tag (a signature names a digest).
//!
//! `require_digests` is the operator's policy, not a trust path: with it, a run is refused unless
//! its own image and every entry of its zone's `images` are pinned (`name@sha256:…`; `wicket zone
//! pin MANIFEST` rewrites tags to their current digests), checked just before a pinned image is
//! accepted by a grant on its digest, the one "may this digest run" check (#258,
//! `wicket_control::digest`). The installation's own agent image (built by this wicket from the
//! sources it embeds) is exempt.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagesPolicy {
    /// Refuse a run whose image, or any of its zone's `images`, is a tag ([`require_pinned`]).
    #[serde(default)]
    pub require_digests: bool,
    /// Registries a node may pull a pinned image from, host-side (#191). None: images reach nodes
    /// from the control host only.
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
    pub registries: Vec<Registry>,
    /// Which keys must have signed which images (#191).
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
    pub trust: Trust,
}

/// The installation's signature policy (#191).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    /// For an image no rule matches.
    #[serde(default)]
    pub default: Require,
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
    pub rules: Vec<TrustRule>,
}

/// Whether an image must be signed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Require {
    /// Run unsigned; a rule's keys are still checked, and recorded, if it is signed.
    #[default]
    AllowUnsigned,
    /// Run only if one of the rule's keys signed exactly its digest.
    #[serde(alias = "signed")]
    RequireSigned,
}

/// A rule of [`Trust`].
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRule {
    /// `host/repository` patterns (`docker.io/` names Docker Hub); `*` matches any run of characters.
    pub repositories: Vec<String>,
    /// Zone name patterns it is for; none: every zone.
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
    pub zones: Vec<String>,
    /// PEM public keys, relative to the data dir unless absolute.
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
    pub keys: Vec<String>,
    #[serde(default = "require_signed")]
    pub require: Require,
}

fn require_signed() -> Require {
    Require::RequireSigned
}

/// `*` matches any run of characters (`/` included); everything else itself. In time linear in
/// the product of their lengths, whatever the pattern: the name may be an agent's.
fn glob(pat: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    let (mut i, mut j) = (0, 0);
    // The last `*` seen, and where in `s` it was tried up to.
    let mut star: Option<(usize, usize)> = None;
    while j < s.len() {
        if i < p.len() && p[i] == '*' {
            star = Some((i, j));
            i += 1;
        } else if i < p.len() && p[i] == s[j] {
            i += 1;
            j += 1;
        } else if let Some((si, sj)) = star {
            i = si + 1;
            j = sj + 1;
            star = Some((si, sj + 1));
        } else {
            return false;
        }
    }
    p[i..].iter().all(|&c| c == '*')
}

/// `host/repository` as [`registry_of`] names it, with Docker Hub's other names folded in.
fn qualified(pat: &str) -> String {
    for hub in ["docker.io/", "index.docker.io/"] {
        if let Some(rest) = pat.strip_prefix(hub) {
            return format!("registry-1.docker.io/{rest}");
        }
    }
    pat.to_string()
}

/// What [`Trust`] asks of one image.
#[derive(Debug, PartialEq, Eq)]
pub struct Wanted {
    /// The matching rule's index, if one matched.
    pub rule: Option<usize>,
    pub require: Require,
    /// Its keys' paths, as resolved.
    pub keys: Vec<std::path::PathBuf>,
    /// `host/repository`, if the image names one.
    pub repository: Option<String>,
}

impl Trust {
    /// Whether this policy asks anything at all: if not, nothing is fetched.
    pub fn is_empty(&self) -> bool {
        self.default == Require::AllowUnsigned && self.rules.is_empty()
    }

    /// What it asks of `image` started in zone `zone`.
    pub fn wanted(&self, image: &str, zone: &str) -> Wanted {
        let repository = registry_of(image).map(|(h, r)| format!("{h}/{r}"));
        let hit = repository.as_deref().and_then(|repo| {
            self.rules.iter().position(|r| {
                r.repositories.iter().any(|p| glob(&qualified(p), repo)) && (r.zones.is_empty() || r.zones.iter().any(|z| glob(z, zone)))
            })
        });
        match hit {
            Some(i) => {
                let r = &self.rules[i];
                let keys = r.keys.iter().map(|k| crate::data_dir().join(k)).collect();
                Wanted { rule: Some(i), require: r.require, keys, repository }
            }
            None => Wanted { rule: None, require: self.default, keys: vec![], repository },
        }
    }

    fn check(&self) -> Result<()> {
        for (i, r) in self.rules.iter().enumerate() {
            if r.repositories.is_empty() {
                bail!("trust rule {} names no repositories", i + 1);
            }
            if r.keys.is_empty() {
                bail!("trust rule {} ({}) names no keys", i + 1, r.repositories.join(", "));
            }
        }
        Ok(())
    }
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
        Ok(t) => {
            let p: ImagesPolicy = wicket_core::yaml::from_str(&t).with_context(|| path().display().to_string())?;
            p.trust.check().with_context(|| path().display().to_string())?;
            Ok(p)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ImagesPolicy::default()),
        Err(e) => Err(e).with_context(|| path().display().to_string()),
    }
}

/// The operator's `require_digests` policy, for a run of `m` starting `image`: refused, naming the
/// tags, if the installation requires pins and the run's image (other than `default_image`, the
/// installation's own) or any of its zone's `images` is a tag.
pub fn require_pinned(m: &wicket_core::Manifest, image: &str, default_image: &str) -> Result<()> {
    require_pinned_with(&load()?, m, image, default_image)
}

pub fn require_pinned_with(p: &ImagesPolicy, m: &wicket_core::Manifest, image: &str, default_image: &str) -> Result<()> {
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
            wicket_agent::load(&format!("task: t\nagent: {{name: a}}\nzone: {{name: z, llm: {{secret: m}}, images: [{images}]}}")).unwrap()
        };
        let on = ImagesPolicy { require_digests: true, ..Default::default() };
        assert!(require_pinned_with(&ImagesPolicy::default(), &m("img:tag"), "img:tag", "dflt").is_ok(), "off by default");
        assert!(require_pinned_with(&on, &m(&pin), &pin, "dflt").is_ok());
        assert!(require_pinned_with(&on, &m(&pin), "dflt", "dflt").is_ok(), "the installation's own image");
        let e = require_pinned_with(&on, &m(&format!("{pin}, img:tag")), &pin, "dflt").unwrap_err().to_string();
        assert!(
            e.starts_with("this installation requires images pinned by digest") && e.contains("img:tag") && e.contains("wicket zone pin"),
            "{e}"
        );
        assert!(require_pinned_with(&on, &m(&pin), "img:tag", "dflt").is_err(), "its own image a tag");
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
        assert!(p.trust.is_empty(), "no trust section: nothing asked");
        // An empty key, as serde_yaml read it: no registries, not an error (#326).
        assert!(wicket_core::yaml::from_str::<ImagesPolicy>("registries:\n").unwrap().registries.is_empty());
    }

    #[test]
    fn globs_match_any_run_of_characters() {
        assert!(glob("registry.example.com/team/*", "registry.example.com/team/agent"));
        assert!(glob("registry.example.com/team/*", "registry.example.com/team/a/b"));
        assert!(!glob("registry.example.com/team/*", "registry.example.com/teamx"));
        assert!(glob("*", "") && glob("a*b*c", "abc") && glob("a*b*c", "axxbyyc") && !glob("a*b*c", "acb"));
        assert!(glob("exact", "exact") && !glob("exact", "exactly") && !glob("", "x") && glob("**", "x"));
        assert!(glob("*b", "aab") && !glob("*b", "aba") && glob("a*", "a") && glob("é*", "éx"));
        // A pattern made to backtrack, against a long name: quick.
        let t = std::time::Instant::now();
        assert!(!glob(&format!("{}b", "a*".repeat(20)), &"a".repeat(4000)));
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn the_first_matching_trust_rule_decides() {
        let p: ImagesPolicy = wicket_core::yaml::from_str(
            "trust:\n  default: require-signed\n  rules:\n    - repositories: [registry.example.com/team/*]\n      zones: [prod-*]\n      keys: [keys/prod.pub]\n    - repositories: [registry.example.com/team/*, docker.io/library/*]\n      keys: [keys/team.pub, /etc/k.pub]\n      require: allow-unsigned\n",
        )
        .unwrap();
        p.trust.check().unwrap();
        assert!(!p.trust.is_empty());
        let w = p.trust.wanted(&format!("registry.example.com/team/agent@sha256:{}", "a".repeat(64)), "prod-eu");
        assert_eq!((w.rule, w.require, w.keys.len()), (Some(0), Require::RequireSigned, 1));
        assert!(w.keys[0].ends_with("keys/prod.pub"));
        assert_eq!(w.repository.as_deref(), Some("registry.example.com/team/agent"));
        let w = p.trust.wanted("registry.example.com/team/agent:1", "dev");
        assert_eq!((w.rule, w.require), (Some(1), Require::AllowUnsigned));
        assert_eq!(w.keys[1], std::path::PathBuf::from("/etc/k.pub"), "absolute paths stay");
        assert_eq!(p.trust.wanted("ubuntu:24.04", "dev").rule, Some(1), "Docker Hub by its other name");
        let w = p.trust.wanted("other.example.com/x:1", "prod-eu");
        assert_eq!((w.rule, w.require, w.keys.len()), (None, Require::RequireSigned, 0), "the default");
        assert_eq!(p.trust.wanted("sha256:aa", "z").repository, None);

        // `require: signed`, as #191's proposal spells it; a rule needs keys and repositories.
        let p: ImagesPolicy =
            wicket_core::yaml::from_str("trust:\n  rules: [{repositories: [a/*], keys: [k], require: signed}]\n").unwrap();
        assert_eq!(p.trust.rules[0].require, Require::RequireSigned);
        let p: ImagesPolicy = wicket_core::yaml::from_str("trust:\n  rules: [{repositories: [a/*]}]\n").unwrap();
        assert!(p.trust.check().unwrap_err().to_string().contains("names no keys"));
        let p: ImagesPolicy = wicket_core::yaml::from_str("trust:\n  rules: [{repositories: [], keys: [k]}]\n").unwrap();
        assert!(p.trust.check().is_err());
        assert!(wicket_core::yaml::from_str::<ImagesPolicy>("trust: {default: maybe}").is_err());
        assert!(wicket_core::yaml::from_str::<ImagesPolicy>("trust: {rules: [{repositories: [a], keys: [k], typo: 1}]}").is_err());
        assert!(wicket_core::yaml::from_str::<ImagesPolicy>("trust:\n").unwrap().trust.is_empty());
    }
}
