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
//!   rules:                            # the first that matches an image decides
//!     - repositories: ["registry.example.com/team/*"]   # host/repository; `*` matches anything
//!       keys: [keys/team.pub]         # PEM public keys, relative to the data dir
//!       require: signed               # the default; or allow-unsigned (checked if signed)
//! ```
//!
//! `trust` is checked on the control host before a box starts (`wicket_control::imagetrust`), never
//! in the box: the signature is fetched from the image's registry (one of `registries`) and must be
//! by one of the rule's keys over exactly the image's digest ([`wicket_chan::signature`]). The
//! image's node checks its bytes against that digest. Unsigned, signed by another key or over
//! another digest, an image a rule requires signed is refused, and so is a tag (a signature names a
//! digest). No `trust` section asks nothing: no signature is fetched or checked.
//!
//! Rules match an image's name as written, so names are normalised first (the host lowercased, its
//! `:443` dropped, Docker Hub's names folded together), and, once any rule requires signatures, a
//! pinned image whose name maps to no listed registry (a bare digest included) is refused: it
//! could otherwise dodge every rule by how it is spelled. Even so, only `default: require-signed`
//! holds every image to a signature; under `allow-unsigned`, rules cover the repositories they name.
//! Rules don't match zones: a zone's name is the manifest's own choice, so it is no boundary.
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
    /// PEM public keys, relative to the data dir unless absolute.
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
    pub keys: Vec<String>,
    #[serde(default = "require_signed")]
    pub require: Require,
    /// The keys, as read and parsed when the policy is loaded ([`load`]).
    #[serde(skip)]
    pub parsed: Vec<wicket_chan::signature::Key>,
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

/// A registry host as wicket compares them: lowercased, without HTTPS's own port, and Docker
/// Hub's names as one.
pub fn host_key(h: &str) -> String {
    let h = h.to_ascii_lowercase();
    let h = h.strip_suffix(":443").map(String::from).unwrap_or(h);
    match h.as_str() {
        "docker.io" | "index.docker.io" => "registry-1.docker.io".into(),
        _ => h,
    }
}

/// A `host/repository` pattern with its host as [`host_key`] has it.
fn qualified(pat: &str) -> String {
    match pat.split_once('/') {
        Some((h, rest)) => format!("{}/{rest}", host_key(h)),
        None => pat.to_string(),
    }
}

/// What [`Trust`] asks of one image.
#[derive(Debug)]
pub struct Wanted {
    /// Why the image is refused before any signature is looked at, if it is.
    pub refused: Option<String>,
    /// The matching rule's index, if one matched.
    pub rule: Option<usize>,
    pub require: Require,
    /// Its keys, as loaded.
    pub keys: Vec<wicket_chan::signature::Key>,
    /// `host/repository`, if the image names one.
    pub repository: Option<String>,
}

impl Trust {
    /// Whether this policy asks anything at all: if not, nothing is fetched.
    pub fn is_empty(&self) -> bool {
        self.default == Require::AllowUnsigned && self.rules.is_empty()
    }

    /// Whether any image may need a signature.
    pub fn requires_any(&self) -> bool {
        self.default == Require::RequireSigned || self.rules.iter().any(|r| r.require == Require::RequireSigned)
    }

    /// What it asks of `image`, given the registries `p` lists.
    pub fn wanted(&self, p: &ImagesPolicy, image: &str) -> Wanted {
        let repository = registry_of(image).map(|(h, r)| format!("{h}/{r}"));
        let pinned = wicket_core::image::parse(image).is_ok_and(|r| r.pin.is_some());
        let refused = (self.requires_any() && pinned && p.registry_for(image).is_none()).then(|| {
            "its name maps to no registry in images.yaml's registries, and a rule here requires signatures: name it by its registry"
                .to_string()
        });
        let hit =
            repository.as_deref().and_then(|repo| self.rules.iter().position(|r| r.repositories.iter().any(|p| glob(&qualified(p), repo))));
        match hit {
            Some(i) => Wanted { refused, rule: Some(i), require: self.rules[i].require, keys: self.rules[i].parsed.clone(), repository },
            None => Wanted { refused, rule: None, require: self.default, keys: vec![], repository },
        }
    }

    /// Checks the rules and reads their keys (relative to `dir` unless absolute).
    pub fn load_keys(&mut self, dir: &std::path::Path) -> Result<()> {
        for (i, r) in self.rules.iter_mut().enumerate() {
            if r.repositories.is_empty() {
                bail!("trust rule {} names no repositories", i + 1);
            }
            if r.keys.is_empty() {
                bail!("trust rule {} ({}) names no keys", i + 1, r.repositories.join(", "));
            }
            r.parsed.clear();
            for k in &r.keys {
                let path = dir.join(k);
                let pem = std::fs::read_to_string(&path).with_context(|| format!("trust rule {}'s key {}", i + 1, path.display()))?;
                let key = wicket_chan::signature::Key::from_pem(&pem)
                    .with_context(|| format!("trust rule {}'s key {}", i + 1, path.display()))?;
                r.parsed.push(key);
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
    let host = host_key(first);
    if host == "registry-1.docker.io" {
        let rest = if rest.contains('/') { rest.to_string() } else { format!("library/{rest}") };
        return Some((host, rest));
    }
    if first.contains('.') || first.contains(':') || host == "localhost" {
        return Some((host, rest.to_string()));
    }
    let rest = if repo.contains('/') { repo.to_string() } else { format!("library/{repo}") };
    Some(("registry-1.docker.io".into(), rest))
}

impl ImagesPolicy {
    /// The registry entry `image` may be pulled from, and its repository there, if any.
    pub fn registry_for(&self, image: &str) -> Option<(Registry, String)> {
        let (host, repo) = registry_of(image)?;
        self.registries.iter().find(|r| host_key(&r.host) == host).map(|r| (Registry { host: host.clone(), ..r.clone() }, repo))
    }
}

pub fn path() -> std::path::PathBuf {
    crate::data_dir().join("images.yaml")
}

pub fn load() -> Result<ImagesPolicy> {
    match std::fs::read_to_string(path()) {
        Ok(t) => {
            let mut p: ImagesPolicy = wicket_core::yaml::from_str(&t).with_context(|| path().display().to_string())?;
            p.trust.load_keys(&crate::data_dir()).with_context(|| path().display().to_string())?;
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

    /// A data dir with `keys/a.pub` (a P-256 key) in it.
    fn key_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-trust-{}-{}", std::process::id(), wicket_core::new_ulid()));
        std::fs::create_dir_all(d.join("keys")).unwrap();
        let k = wicket_chan::signature::testkit::p256_key(7);
        std::fs::write(d.join("keys/a.pub"), wicket_chan::signature::testkit::pem_of_p256(&k)).unwrap();
        d
    }

    fn trust(y: &str, dir: &std::path::Path) -> ImagesPolicy {
        let mut p: ImagesPolicy = wicket_core::yaml::from_str(y).unwrap();
        p.trust.load_keys(dir).unwrap();
        p
    }

    #[test]
    fn the_first_matching_trust_rule_decides() {
        let dir = key_dir();
        let pin = format!("sha256:{}", "a".repeat(64));
        let p = trust(
            "registries: [{host: registry.example.com}, {host: docker.io}]\ntrust:\n  default: require-signed\n  rules:\n    - repositories: [registry.example.com/team/*]\n      keys: [keys/a.pub]\n    - repositories: [registry.example.com/*, docker.io/library/*]\n      keys: [keys/a.pub, keys/a.pub]\n      require: allow-unsigned\n",
            &dir,
        );
        assert!(!p.trust.is_empty() && p.trust.requires_any());
        let w = p.trust.wanted(&p, &format!("registry.example.com/team/agent@{pin}"));
        assert_eq!((w.rule, w.require, w.keys.len(), w.refused.as_deref()), (Some(0), Require::RequireSigned, 1, None));
        assert_eq!(w.repository.as_deref(), Some("registry.example.com/team/agent"));
        let w = p.trust.wanted(&p, "registry.example.com/other/x:1");
        assert_eq!((w.rule, w.require, w.keys.len()), (Some(1), Require::AllowUnsigned, 2));
        assert_eq!(p.trust.wanted(&p, "ubuntu:24.04").rule, Some(1), "Docker Hub by its other name");
        let w = p.trust.wanted(&p, &format!("other.example.com/x@{pin}"));
        assert_eq!((w.rule, w.require, w.keys.len()), (None, Require::RequireSigned, 0), "the default");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn how_an_image_is_spelled_doesnt_dodge_a_rule() {
        let dir = key_dir();
        let pin = format!("sha256:{}", "a".repeat(64));
        // Under allow-unsigned, a rule requiring signatures for one registry.
        let p = trust(
            "registries: [{host: Registry.Example.com}]\ntrust:\n  rules: [{repositories: ['REGISTRY.example.com:443/team/*'], keys: [keys/a.pub]}]\n",
            &dir,
        );
        assert_eq!(host_key("Registry.Example.COM:443"), "registry.example.com");
        assert_eq!(host_key("registry.example.com:5000"), "registry.example.com:5000");
        let mut tried = vec![];
        for spelled in ["registry.example.com", "REGISTRY.EXAMPLE.COM", "registry.example.com:443", "Registry.Example.Com:443"] {
            let img = format!("{spelled}/team/agent@{pin}");
            if wicket_core::image::parse(&img).is_err() {
                continue; // not a name wicket would run
            }
            tried.push(spelled);
            let w = p.trust.wanted(&p, &img);
            assert_eq!((w.rule, w.require, w.refused.as_deref()), (Some(0), Require::RequireSigned, None), "{img}");
            assert!(p.registry_for(&img).is_some(), "{img}");
        }
        println!("spellings wicket runs: {tried:?}");
        assert!(tried.len() >= 2, "{tried:?}");
        // A bare digest, or a name on no listed registry, names no repository a rule could match.
        for img in [pin.clone(), format!("elsewhere.example.com/team/agent@{pin}")] {
            let w = p.trust.wanted(&p, &img);
            assert!(w.refused.as_deref().is_some_and(|r| r.contains("maps to no registry")), "{img}: {w:?}");
        }
        // A tag there is the default's to decide (it can't be signed-checked anyway).
        assert!(p.trust.wanted(&p, "elsewhere.example.com/x:1").refused.is_none());
        // With nothing required, nothing is refused for its spelling.
        let lax = trust("trust:\n  rules: [{repositories: [a/*], keys: [keys/a.pub], require: allow-unsigned}]\n", &dir);
        assert!(!lax.trust.requires_any() && lax.trust.wanted(&lax, &pin).refused.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn trust_rules_are_checked_and_their_keys_read_when_loaded() {
        let dir = key_dir();
        let load = |y: &str| -> Result<ImagesPolicy> {
            let mut p: ImagesPolicy = wicket_core::yaml::from_str(y)?;
            p.trust.load_keys(&dir)?;
            Ok(p)
        };
        // `require: signed`, as #191's proposal spells it.
        let p = load("trust:\n  rules: [{repositories: [a/*], keys: [keys/a.pub], require: signed}]\n").unwrap();
        assert_eq!((p.trust.rules[0].require, p.trust.rules[0].parsed.len()), (Require::RequireSigned, 1));
        assert!(format!("{:#}", load("trust:\n  rules: [{repositories: [a/*]}]\n").unwrap_err()).contains("names no keys"));
        assert!(load("trust:\n  rules: [{repositories: [], keys: [keys/a.pub]}]\n").is_err());
        assert!(format!("{:#}", load("trust:\n  rules: [{repositories: [a/*], keys: [keys/none.pub]}]\n").unwrap_err())
            .contains("keys/none.pub"));
        std::fs::write(dir.join("keys/bad.pub"), "not a key").unwrap();
        assert!(load("trust:\n  rules: [{repositories: [a/*], keys: [keys/bad.pub]}]\n").is_err());
        assert!(load("trust: {default: maybe}").is_err());
        assert!(load("trust: {rules: [{repositories: [a], keys: [k], zones: [z]}]}").is_err(), "no zone filters");
        assert!(load("trust:\n").unwrap().trust.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
