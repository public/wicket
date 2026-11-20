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
//! its credential (bound to the registry's hosts, #152). Each [`wicket_chan::signature::Scheme`] is
//! tried in turn; the first that verifies is what the audit records.

use crate::images_policy::{ImagesPolicy, Require};
use anyhow::{bail, Context, Result};
use wicket_chan::signature::{self, Key, Subject, Verified};

/// Checks `image` (pinned to `pin`, if it is) for zone `zone` against `p`'s trust policy: the
/// signature that verified, if one was asked for and found; an error if the policy requires one and
/// none verified. `cred(name, hosts)` is the registry's secret, if it may go to all of `hosts`.
pub async fn check(
    p: &ImagesPolicy,
    image: &str,
    pin: Option<&str>,
    zone: &str,
    cred: impl Fn(&str, &[String]) -> Result<String>,
) -> Result<Option<Verified>> {
    if p.trust.is_empty() {
        return Ok(None);
    }
    let w = p.trust.wanted(image, zone);
    let required = w.require == Require::RequireSigned;
    let rule = w.rule.map_or("the trust policy's default".to_string(), |i| format!("trust rule {}", i + 1));
    let refuse = |why: String| -> Result<Option<Verified>> {
        if required {
            bail!("image {image} must be signed ({rule} in {}), and {why}", crate::images_policy::path().display())
        }
        say!("[wicket] image {image}: {why}; {rule} allows it unsigned");
        Ok(None)
    };
    let Some(pin) = pin else {
        return refuse("it is a tag: a signature is checked against a digest. Pin it: wicket zone pin <manifest>".into());
    };
    if w.keys.is_empty() {
        return refuse("no trust rule names keys for it".into());
    }
    let mut keys = vec![];
    for k in &w.keys {
        let pem = std::fs::read_to_string(k).with_context(|| format!("{rule}'s key {}", k.display()))?;
        keys.push(Key::from_pem(&pem).with_context(|| format!("{rule}'s key {}", k.display()))?);
    }
    let Some((reg, repository)) = p.registry_for(image) else {
        return refuse("its registry isn't one of images.yaml's registries, so its signature can't be fetched".into());
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
            Some(cred(s, &hosts).with_context(|| format!("the registry's credential {s}"))?)
        }
        None => None,
    };
    let subject = Subject { digest: pin, repository: w.repository.as_deref().unwrap_or_default() };
    let mut why = vec![];
    for scheme in signature::schemes() {
        let Some(tag) = scheme.tag(pin) else { continue };
        match wicket_chan::registry::signature(&src, &tag, secret.as_deref()).await {
            Ok(None) => why.push(format!("{}: no signature ({tag})", scheme.name())),
            Ok(Some(a)) => match scheme.verify(subject, &a, &keys) {
                Ok(v) => return Ok(Some(v)),
                Err(e) => why.push(format!("{}: {e:#}", scheme.name())),
            },
            Err(e) => why.push(format!("{}: fetching {tag}: {e:#}", scheme.name())),
        }
    }
    refuse(format!("no signature verified ({})", why.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wicket_chan::oci::testkit::sha;
    use wicket_chan::signature::testkit::*;

    struct Setup {
        _fake: wicket_chan::registry::testkit::Fake,
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
        Setup { host: fake.addr.to_string(), _fake: fake, dir, pin }
    }

    fn policy(s: &Setup, require: &str) -> ImagesPolicy {
        let y = format!(
            "registries: [{{host: '{h}'}}]\ntrust:\n  default: require-signed\n  rules:\n    - repositories: ['{h}/team/*']\n      keys: ['{k}']\n      require: {require}\n",
            h = s.host,
            k = s.dir.join("keys/team.pub").display()
        );
        wicket_core::yaml::from_str(&y).unwrap()
    }

    fn no_cred(_: &str, _: &[String]) -> Result<String> {
        bail!("no credential asked for")
    }

    #[tokio::test]
    async fn a_signed_image_runs_and_its_key_and_signature_are_named() {
        let k = p256_key(7);
        let s = setup(&k, &k, &sha(b"the image's index")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let v = check(&policy(&s, "signed"), &image, Some(&s.pin), "z", no_cred).await.unwrap().unwrap();
        assert_eq!(v.scheme, "cosign");
        assert_eq!(v.key, Key::from_pem(&pem_of_p256(&k)).unwrap().fingerprint());
        assert!(v.signature.starts_with("sha256:"));
        // No trust section: nothing is fetched or asked.
        assert!(check(&ImagesPolicy::default(), &image, Some(&s.pin), "z", no_cred).await.unwrap().is_none());
        std::fs::remove_dir_all(&s.dir).unwrap();
    }

    #[tokio::test]
    async fn another_key_another_digest_unsigned_or_a_tag_is_refused_when_required() {
        let (k, stranger) = (p256_key(7), p256_key(8));
        // Signed by a key the rule doesn't name.
        let s = setup(&stranger, &k, &sha(b"the image's index")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let e = check(&policy(&s, "signed"), &image, Some(&s.pin), "z", no_cred).await.unwrap_err().to_string();
        assert!(e.contains("must be signed (trust rule 1") && e.contains("none of the policy's keys"), "{e}");
        // The same, allowed unsigned: runs, unrecorded.
        assert!(check(&policy(&s, "allow-unsigned"), &image, Some(&s.pin), "z", no_cred).await.unwrap().is_none());
        // A tag can't be checked.
        let e = check(&policy(&s, "signed"), &format!("{}/team/agent:1", s.host), None, "z", no_cred).await.unwrap_err().to_string();
        assert!(e.contains("it is a tag"), "{e}");
        // Another repository: the default, which requires a signature and names no keys.
        let other = format!("{}/elsewhere/x@{}", s.host, s.pin);
        let e = check(&policy(&s, "signed"), &other, Some(&s.pin), "z", no_cred).await.unwrap_err().to_string();
        assert!(e.contains("the trust policy's default") && e.contains("no trust rule names keys"), "{e}");
        std::fs::remove_dir_all(&s.dir).unwrap();

        // A good signature over another digest.
        let s = setup(&k, &k, &sha(b"another image")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let e = check(&policy(&s, "signed"), &image, Some(&s.pin), "z", no_cred).await.unwrap_err().to_string();
        assert!(e.contains("a signature for"), "{e}");
        // Unsigned: the registry has no signature for this digest.
        let unsigned = sha(b"unsigned");
        let e = check(&policy(&s, "signed"), &format!("{}/team/agent@{unsigned}", s.host), Some(&unsigned), "z", no_cred)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("cosign: no signature (sha256-"), "{e}");
        std::fs::remove_dir_all(&s.dir).unwrap();
    }

    #[tokio::test]
    async fn the_registry_s_credential_must_be_bound_to_its_hosts() {
        let k = p256_key(7);
        let s = setup(&k, &k, &sha(b"the image's index")).await;
        let image = format!("{}/team/agent@{}", s.host, s.pin);
        let mut p = policy(&s, "signed");
        p.registries[0].secret = Some("reg".into());
        p.registries[0].auth_hosts = vec!["auth.example.com".into()];
        let asked = std::sync::Mutex::new(vec![]);
        let v = check(&p, &image, Some(&s.pin), "z", |n, h| {
            asked.lock().unwrap().push((n.to_string(), h.to_vec()));
            Ok("u:p".into())
        })
        .await
        .unwrap();
        assert!(v.is_some());
        assert_eq!(asked.into_inner().unwrap(), vec![("reg".to_string(), vec![s.host.clone(), "auth.example.com".to_string()])]);
        let e = check(&p, &image, Some(&s.pin), "z", |_, _| bail!("not bound")).await.unwrap_err();
        assert!(format!("{e:#}").contains("the registry's credential reg"), "{e:#}");
        std::fs::remove_dir_all(&s.dir).unwrap();
    }
}
