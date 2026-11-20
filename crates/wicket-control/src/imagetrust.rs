//! Image signatures, checked on the control host before a box starts (#191): the installation's
//! `trust` policy (`images.yaml`, [`crate::images_policy::Trust`]) names which keys must have
//! signed an image. Never in the box, and before its node is asked for anything.
//!
//! Why here rather than on the node: a signature binds a key to a digest, and the node already
//! checks the image's bytes against that digest when it imports or starts it (#192, #273, #289).
//! The control host holds the policy and is the authority a node trusts anyway (it issues its feed
//! and tokens), so a check on the node would add no protection against it, and checking here covers
//! every node alike (the control host's own, images already on a node) with no change to the
//! channel.
//!
//! The signature is fetched from the image's registry, one of `registries` in the same file, with
//! its credential (bound to the registry's hosts, #152), within [`FETCH_DEADLINE`]. Each
//! [`wicket_chan::signature::Scheme`] is tried in turn; the first that verifies is what the audit
//! records. A verified (digest, keys) pair is cached under the data dir, so the next run of the
//! same image with the same keys isn't fetched again; changing a rule's keys changes the key.

use crate::images_policy::{ImagesPolicy, Require};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use wicket_chan::signature::{self, Key, Subject, Verified};
use wicket_core::RunId;
use wicket_store::Ledger;

/// The most the fetches for one image's signatures may take, altogether.
pub const FETCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// What checking one image found, as its `image.signature` audit records it.
#[derive(Debug, Default, serde::Serialize)]
pub struct Outcome {
    /// The trust rule that decided (1-based, as messages name it), or none: the default.
    pub rule: Option<usize>,
    /// Whether that rule (or the default) requires a signature.
    pub required: bool,
    pub verified: Option<Verified>,
    /// Whether `verified` came from the cache.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub cached: bool,
    /// Why no signature verified, if none did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// The registry credential asked for, and why it wasn't released, if it wasn't.
    #[serde(skip)]
    pub credential: Option<(String, Option<String>)>,
}

impl Outcome {
    /// Refused: a signature was required and none verified.
    pub fn refused(&self) -> bool {
        self.required && self.verified.is_none()
    }
}

/// Where verified signatures are cached, by (digest, keys).
pub fn cache_dir() -> std::path::PathBuf {
    crate::data_dir().join("cache/signatures")
}

fn cache_key(digest: &str, keys: &[Key]) -> String {
    let mut fps: Vec<String> = keys.iter().map(Key::fingerprint).collect();
    fps.sort();
    fps.dedup();
    hex::encode(Sha256::digest(format!("{digest}\n{}", fps.join("\n"))))
}

/// Checks `image` (pinned to `pin`, if it is) against `p`'s trust policy. `cred(name, hosts)` is
/// the registry's secret, if it may go to all of `hosts`. `cache`, if given, is where verified
/// signatures are kept.
pub async fn check(
    p: &ImagesPolicy,
    image: &str,
    pin: Option<&str>,
    cache: Option<&Path>,
    mut cred: impl FnMut(&str, &[String]) -> Result<String>,
) -> Outcome {
    let mut out = Outcome::default();
    if p.trust.is_empty() {
        return out;
    }
    let w = p.trust.wanted(p, image);
    out.rule = w.rule.map(|i| i + 1);
    out.required = w.require == Require::RequireSigned || w.refused.is_some();
    let done = |mut out: Outcome, why: String| {
        out.why = Some(why);
        out
    };
    if let Some(r) = w.refused {
        return done(out, r);
    }
    let Some(pin) = pin else {
        return done(out, "it is a tag: a signature is checked against a digest. Pin it: wicket zone pin <manifest>".into());
    };
    if w.keys.is_empty() {
        return done(out, "no trust rule names keys for it".into());
    }
    let cached = cache.map(|d| d.join(format!("{}.json", cache_key(pin, &w.keys))));
    if let Some(v) = cached.as_ref().and_then(|f| std::fs::read(f).ok()).and_then(|b| serde_json::from_slice::<Verified>(&b).ok()) {
        if w.keys.iter().any(|k| k.fingerprint() == v.key) {
            out.verified = Some(v);
            out.cached = true;
            return out;
        }
    }
    let Some((reg, repository)) = p.registry_for(image) else {
        return done(out, "its registry isn't one of images.yaml's registries, so its signature can't be fetched".into());
    };
    let src = wicket_chan::registry::Source {
        host: reg.host.clone(),
        repository,
        auth_hosts: reg.auth_hosts.clone(),
        blob_hosts: reg.blob_hosts.clone(),
        secret: reg.secret.clone(),
    };
    let secret = match &reg.secret {
        Some(s) => {
            let hosts: Vec<String> = std::iter::once(reg.host.clone()).chain(reg.auth_hosts.iter().cloned()).collect();
            match cred(s, &hosts) {
                Ok(v) => {
                    out.credential = Some((s.clone(), None));
                    Some(zeroize::Zeroizing::new(v))
                }
                Err(e) => {
                    out.credential = Some((s.clone(), Some(format!("{e:#}"))));
                    return done(out, format!("the registry's credential {s} is not released for it: {e:#}"));
                }
            }
        }
        None => None,
    };
    let subject = Subject { digest: pin, repository: w.repository.as_deref().unwrap_or_default() };
    let found = tokio::time::timeout(FETCH_DEADLINE, async {
        let mut why = vec![];
        for scheme in signature::schemes() {
            let Some(tag) = scheme.tag(pin) else { continue };
            match wicket_chan::registry::signature(&src, &tag, secret.as_deref().map(String::as_str)).await {
                Ok(None) => why.push(format!("{}: no signature ({tag})", scheme.name())),
                Ok(Some(a)) => match scheme.verify(subject, &a, &w.keys) {
                    Ok(v) => return Ok(v),
                    Err(e) => why.push(format!("{}: {e:#}", scheme.name())),
                },
                Err(e) => why.push(format!("{}: fetching {tag}: {e:#}", scheme.name())),
            }
        }
        Err(why.join("; "))
    })
    .await;
    match found {
        Ok(Ok(v)) => {
            if let Some(f) = &cached {
                if let Some(d) = f.parent() {
                    let _ = std::fs::create_dir_all(d);
                }
                let _ = std::fs::write(f, serde_json::to_vec(&v).unwrap_or_default());
            }
            out.verified = Some(v);
            out
        }
        Ok(Err(why)) => done(out, format!("no signature verified ({why})")),
        Err(_) => done(out, format!("its signatures weren't fetched within {} s", FETCH_DEADLINE.as_secs())),
    }
}

/// The images a run of `m` starting `image` is checked for: its own, then its zone's `images` (a
/// node may start children from them itself, #164), each once, without the installation's own.
pub fn images_to_check<'a>(m: &'a wicket_core::Manifest, image: &'a str, default_image: &str) -> Vec<&'a str> {
    let mut seen = std::collections::BTreeSet::new();
    std::iter::once(image).chain(m.zone.images.iter().map(String::as_str)).filter(|i| *i != default_image && seen.insert(*i)).collect()
}

/// What admitting a run's image needs from its caller.
pub struct Admit<'a> {
    pub policy: &'a ImagesPolicy,
    pub ledger: &'a Ledger,
    pub manifest: &'a wicket_core::Manifest,
    pub run: &'a RunId,
    pub image: &'a str,
    /// The installation's own agent image, exempt from pins and signatures.
    pub default_image: &'a str,
    /// The run's parent, for a child: its image is pinned to its parent's, not regranted.
    pub parent: Option<&'a str>,
    /// Who accepts a pinned image's digest by running the manifest.
    pub by: &'a str,
    pub cache: Option<&'a Path>,
}

/// Admits a new run's image, in order: the operator's `require_digests`, then the `trust`
/// policy's signatures for every image it may start (each audited as `image.signature`, its
/// registry credential as `image.secret_fetch`), and only then the grant on its digest (#258). A
/// refusal at any step stops the run before anything later, and before any node is asked. The
/// signature that verified the run's own image, if any, is what `run.image` records.
pub async fn admit(a: Admit<'_>, mut cred: impl FnMut(&str, &[String]) -> Result<String>) -> Result<Option<Verified>> {
    let m = a.manifest;
    crate::images_policy::require_pinned_with(a.policy, m, a.image, a.default_image)?;
    let mut signed = None;
    if !a.policy.trust.is_empty() {
        for img in images_to_check(m, a.image, a.default_image) {
            let pin = wicket_core::image::parse(img).map_err(anyhow::Error::msg)?.pin;
            let out = check(a.policy, img, pin.as_deref(), a.cache, &mut cred).await;
            if let Some((secret, why)) = &out.credential {
                a.ledger.audit(
                    &m.tenant,
                    Some(a.run),
                    "image.secret_fetch",
                    &serde_json::json!({ "secret": secret, "released": why.is_none(), "why": why, "image": img, "for": "signature" }),
                )?;
            }
            let mut body = serde_json::json!({ "image": img, "digest": pin, "zone": m.zone.name });
            body.as_object_mut().expect("an object").extend(serde_json::to_value(&out)?.as_object().cloned().unwrap_or_default());
            body["refused"] = out.refused().into();
            a.ledger.audit(&m.tenant, Some(a.run), "image.signature", &body)?;
            let rule = out.rule.map_or("the trust policy's default".to_string(), |r| format!("trust rule {r}"));
            match (&out.verified, &out.why) {
                (Some(v), _) => say!("[wicket] image {img} signed by key {} ({} {})", v.key, v.scheme, v.signature),
                (None, Some(why)) if out.required => {
                    bail!("image {img} must be signed ({rule} in {}), and {why}", crate::images_policy::path().display())
                }
                (None, Some(why)) => say!("[wicket] image {img}: {why}; {rule} allows it unsigned"),
                (None, None) => {}
            }
            if img == a.image {
                signed = out.verified;
            }
        }
    }
    // The one "may this digest run" check (#258): a pinned image is accepted by a grant on its
    // digest, which the operator running the manifest records. A child's image is pinned to its
    // parent's, as its parent's zone allows (decided where it is spawned): not regranted.
    let pin = wicket_core::image::parse(a.image).map_err(anyhow::Error::msg)?.pin;
    if let (Some(pin), None) = (&pin, a.parent) {
        let u = crate::digest::accept_image(a.ledger, &m.tenant, &m.zone.name, a.image, pin, a.by)?;
        say!("[wicket] image {} accepted by grant {} from {}", a.image, u.grant, u.decided_by);
    }
    Ok(signed)
}

/// `run.image`'s body: the image, the digest it started as, its pin, and the signature that
/// verified it.
pub fn run_image_body(image: &str, digest: &str, pinned: Option<&str>, signed: Option<&Verified>) -> serde_json::Value {
    serde_json::json!({ "image": image, "digest": digest, "pinned": pinned, "signature": signed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wicket_chan::oci::testkit::sha;
    use wicket_chan::signature::testkit::*;

    struct Setup {
        fake: wicket_chan::registry::testkit::Fake,
        dir: std::path::PathBuf,
        host: String,
        pin: String,
    }

    /// A registry holding `team/agent`'s signature for `pin` by `signer`, and a data dir with
    /// `trusted`'s public key at `keys/team.pub`.
    async fn setup(signer: &P256Key, trusted: &P256Key, signed: &str) -> Setup {
        let pin = sha(b"the image's index");
        let pl = payload(signed, "x");
        let (_, m, layers) = artifact(&pl, &sign_p256(signer, &pl));
        let mut blobs: HashMap<String, Vec<u8>> = layers.into_iter().collect();
        blobs.insert(format!("sha256-{}.sig", &pin[7..]), m);
        let fake = wicket_chan::registry::testkit::serve("team/agent", blobs, None).await;
        let dir = std::env::temp_dir().join(format!("wicket-imagetrust-{}-{}", std::process::id(), wicket_core::new_ulid()));
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        std::fs::write(dir.join("keys/team.pub"), pem_of_p256(trusted)).unwrap();
        Setup { host: fake.addr.to_string(), fake, dir, pin }
    }

    impl Setup {
        fn hits(&self) -> usize {
            self.fake.hits.lock().unwrap().len()
        }
    }

    fn policy(s: &Setup, default: &str, require: &str) -> ImagesPolicy {
        let y = format!(
            "registries: [{{host: '{h}'}}]\ntrust:\n  default: {default}\n  rules:\n    - repositories: ['{h}/team/*']\n      keys: [keys/team.pub]\n      require: {require}\n",
            h = s.host
        );
        let mut p: ImagesPolicy = wicket_core::yaml::from_str(&y).unwrap();
        p.trust.load_keys(&s.dir).unwrap();
        p
    }

    fn no_cred(_: &str, _: &[String]) -> Result<String> {
        bail!("no credential asked for")
    }

    fn why(o: &Outcome) -> &str {
        o.why.as_deref().unwrap_or_default()
    }

    #[tokio::test]
    async fn a_signed_image_runs_and_its_key_and_signature_are_named() {
        let k = p256_key(7);
        let s = setup(&k, &k, &sha(b"the image's index")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let o = check(&policy(&s, "require-signed", "signed"), &image, Some(&s.pin), None, no_cred).await;
        let v = o.verified.clone().unwrap();
        assert_eq!((o.rule, o.required, o.refused(), o.cached), (Some(1), true, false, false));
        assert_eq!(v.scheme, "cosign");
        assert_eq!(v.key, Key::from_pem(&pem_of_p256(&k)).unwrap().fingerprint());
        assert!(v.signature.starts_with("sha256:"));
        // No trust section: nothing is fetched or asked.
        let before = s.hits();
        let o = check(&ImagesPolicy::default(), &image, Some(&s.pin), None, no_cred).await;
        assert!(o.verified.is_none() && !o.required && o.why.is_none() && s.hits() == before);
        std::fs::remove_dir_all(&s.dir).unwrap();
    }

    #[tokio::test]
    async fn another_key_another_digest_unsigned_or_a_tag_is_refused_when_required() {
        let (k, stranger) = (p256_key(7), p256_key(8));
        // Signed by a key the rule doesn't name.
        let s = setup(&stranger, &k, &sha(b"the image's index")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let o = check(&policy(&s, "require-signed", "signed"), &image, Some(&s.pin), None, no_cred).await;
        assert!(o.refused() && why(&o).contains("none of the policy's keys"), "{o:?}");
        // The same, allowed unsigned: runs, and why it is unsigned is recorded.
        let o = check(&policy(&s, "allow-unsigned", "allow-unsigned"), &image, Some(&s.pin), None, no_cred).await;
        assert!(!o.refused() && o.verified.is_none() && why(&o).contains("none of the policy's keys"), "{o:?}");
        // A tag can't be checked.
        let o = check(&policy(&s, "require-signed", "signed"), &format!("{}/team/agent:1", s.host), None, None, no_cred).await;
        assert!(o.refused() && why(&o).contains("it is a tag"), "{o:?}");
        // Another repository: the default, which requires a signature and names no keys.
        let other = format!("{}/elsewhere/x@{}", s.host, s.pin);
        let o = check(&policy(&s, "require-signed", "signed"), &other, Some(&s.pin), None, no_cred).await;
        assert!(o.refused() && o.rule.is_none() && why(&o).contains("no trust rule names keys"), "{o:?}");
        // Under allow-unsigned with a rule requiring signatures, a bare digest or another
        // registry's name is refused rather than slipping past the rule.
        for img in [s.pin.clone(), format!("unlisted.example.com/team/agent@{}", s.pin)] {
            let o = check(&policy(&s, "allow-unsigned", "signed"), &img, Some(&s.pin), None, no_cred).await;
            assert!(o.refused() && why(&o).contains("maps to no registry"), "{img}: {o:?}");
        }
        std::fs::remove_dir_all(&s.dir).unwrap();

        // A good signature over another digest.
        let s = setup(&k, &k, &sha(b"another image")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let o = check(&policy(&s, "require-signed", "signed"), &image, Some(&s.pin), None, no_cred).await;
        assert!(o.refused() && why(&o).contains("a signature for"), "{o:?}");
        // Unsigned: the registry has no signature for this digest.
        let unsigned = sha(b"unsigned");
        let o =
            check(&policy(&s, "require-signed", "signed"), &format!("{}/team/agent@{unsigned}", s.host), Some(&unsigned), None, no_cred)
                .await;
        assert!(o.refused() && why(&o).contains("cosign: no signature (sha256-"), "{o:?}");
        std::fs::remove_dir_all(&s.dir).unwrap();
    }

    #[tokio::test]
    async fn the_registry_s_credential_must_be_bound_to_its_hosts() {
        let k = p256_key(7);
        let s = setup(&k, &k, &sha(b"the image's index")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let mut p = policy(&s, "require-signed", "signed");
        p.registries[0].secret = Some("reg".into());
        p.registries[0].auth_hosts = vec!["auth.example.com".into()];
        let mut asked = vec![];
        let o = check(&p, &image, Some(&s.pin), None, |n, h| {
            asked.push((n.to_string(), h.to_vec()));
            Ok("u:p".into())
        })
        .await;
        assert!(o.verified.is_some());
        assert_eq!(o.credential, Some(("reg".to_string(), None)));
        assert_eq!(asked, vec![("reg".to_string(), vec![s.host.clone(), "auth.example.com".to_string()])]);
        let o = check(&p, &image, Some(&s.pin), None, |_, _| bail!("not bound")).await;
        assert!(o.refused() && why(&o).contains("the registry's credential reg"), "{o:?}");
        assert_eq!(o.credential, Some(("reg".to_string(), Some("not bound".to_string()))));
        std::fs::remove_dir_all(&s.dir).unwrap();
    }

    #[tokio::test]
    async fn a_verified_signature_is_cached_by_digest_and_keys() {
        let k = p256_key(7);
        let s = setup(&k, &k, &sha(b"the image's index")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let cache = s.dir.join("cache");
        let p = policy(&s, "require-signed", "signed");
        let first = check(&p, &image, Some(&s.pin), Some(&cache), no_cred).await;
        assert!(first.verified.is_some() && !first.cached);
        let hits = s.hits();
        let again = check(&p, &image, Some(&s.pin), Some(&cache), no_cred).await;
        assert!(again.cached && again.verified == first.verified && s.hits() == hits, "no fetch the second time");
        // Other keys: another cache entry, fetched and checked afresh.
        std::fs::write(s.dir.join("keys/team.pub"), pem_of_p256(&p256_key(9))).unwrap();
        let p = policy(&s, "require-signed", "signed");
        let o = check(&p, &image, Some(&s.pin), Some(&cache), no_cred).await;
        assert!(o.refused() && !o.cached && s.hits() > hits, "{o:?}");
        std::fs::remove_dir_all(&s.dir).unwrap();
    }

    fn manifest(zone_images: &str) -> wicket_core::Manifest {
        wicket_agent::load(&format!("task: t\nagent: {{name: a}}\nzone: {{name: z, llm: {{secret: m}}, images: [{zone_images}]}}")).unwrap()
    }

    fn rows(l: &Ledger, kind: &str) -> Vec<(Option<String>, serde_json::Value)> {
        l.audit_of_kind(kind).unwrap().into_iter().map(|r| (r.run, serde_json::from_str(&r.body).unwrap())).collect()
    }

    fn granted(l: &Ledger, m: &wicket_core::Manifest, pin: &str) -> bool {
        l.digest_granted(&m.tenant, pin, wicket_store::DigestAction::Run, &wicket_store::DigestScope::Zone(m.zone.name.clone())).unwrap()
    }

    #[tokio::test]
    async fn admitting_a_run_checks_every_image_before_the_grant_and_audits_each() {
        let k = p256_key(7);
        let s = setup(&k, &k, &sha(b"the image's index")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let p = policy(&s, "require-signed", "signed");
        let run = RunId::new();
        let admit_with = |l, m, img, parent| Admit {
            policy: &p,
            ledger: l,
            manifest: m,
            run: &run,
            image: img,
            default_image: "wicket/agent:own",
            parent,
            by: "op",
            cache: None,
        };

        // Signed, with the installation's own image among the zone's: admitted, granted, and the
        // run's image's signature is what run.image will record.
        let l = Ledger::open_in_memory().unwrap();
        let m = manifest(&format!("'{image}', 'wicket/agent:own'"));
        let v = admit(admit_with(&l, &m, &image, None), no_cred).await.unwrap().unwrap();
        assert!(granted(&l, &m, &s.pin), "the grant follows the check");
        let r = rows(&l, "image.signature");
        assert_eq!(r.len(), 1, "the run's image once, the installation's own not at all: {r:?}");
        assert_eq!(r[0].0.as_deref(), Some(run.0.as_str()), "tied to the run");
        assert_eq!(
            (r[0].1["verified"]["key"].as_str(), r[0].1["rule"].as_u64(), r[0].1["refused"].as_bool()),
            (Some(v.key.as_str()), Some(1), Some(false))
        );
        let b = run_image_body(&image, &s.pin, Some(&s.pin), Some(&v));
        assert_eq!(b["signature"]["key"], v.key.as_str());

        // An unsigned image among the zone's `images`: the whole run is refused, before its own
        // image's grant, and the refusal is audited with why.
        let l = Ledger::open_in_memory().unwrap();
        let unsigned = format!("{}/team/other@{}", s.host, sha(b"unsigned"));
        let m = manifest(&format!("'{unsigned}'"));
        let e = admit(admit_with(&l, &m, &image, None), no_cred).await.unwrap_err().to_string();
        assert!(e.contains(&format!("image {unsigned} must be signed (trust rule 1")), "{e}");
        assert!(!granted(&l, &m, &s.pin), "refused before the grant");
        let r = rows(&l, "image.signature");
        assert_eq!(r.len(), 2, "{r:?}");
        assert_eq!((r[1].1["image"].as_str(), r[1].1["refused"].as_bool()), (Some(unsigned.as_str()), Some(true)));
        assert!(r[1].1["why"].as_str().unwrap().contains("no signature"), "{r:?}");

        // The installation's own image as the run's: exempt, nothing fetched or audited.
        let l = Ledger::open_in_memory().unwrap();
        let m = manifest("");
        assert!(admit(admit_with(&l, &m, "wicket/agent:own", None), no_cred).await.unwrap().is_none());
        assert!(rows(&l, "image.signature").is_empty());

        // `require_digests` still comes first.
        let mut strict = policy(&s, "require-signed", "signed");
        strict.require_digests = true;
        let l = Ledger::open_in_memory().unwrap();
        let m = manifest("'x:tag'");
        let a = Admit { policy: &strict, ..admit_with(&l, &m, &image, None) };
        assert!(admit(a, no_cred).await.unwrap_err().to_string().contains("pinned by digest"));
        assert!(rows(&l, "image.signature").is_empty());
        std::fs::remove_dir_all(&s.dir).unwrap();
    }

    #[tokio::test]
    async fn a_credential_read_for_a_signature_is_audited() {
        let k = p256_key(7);
        let s = setup(&k, &k, &sha(b"the image's index")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let mut p = policy(&s, "require-signed", "signed");
        p.registries[0].secret = Some("reg".into());
        let (l, m, run) = (Ledger::open_in_memory().unwrap(), manifest(""), RunId::new());
        let a = Admit {
            policy: &p,
            ledger: &l,
            manifest: &m,
            run: &run,
            image: &image,
            default_image: "own",
            parent: Some("run_parent"),
            by: "op",
            cache: None,
        };
        admit(a, |_, _| Ok("u:p".into())).await.unwrap();
        let r = rows(&l, "image.secret_fetch");
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].1["secret"].as_str(), r[0].1["released"].as_bool()), (Some("reg"), Some(true)));
        assert!(!granted(&l, &m, &s.pin), "a child's image is its parent's: not regranted");
        std::fs::remove_dir_all(&s.dir).unwrap();
    }
}
