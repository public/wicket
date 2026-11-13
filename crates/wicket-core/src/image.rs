//! Image references and pins (#192): what a zone may start, named exactly.
//!
//! An image is named by a tag (`wicket-self:dev`) or pinned by digest (`wicket-self@sha256:<64 hex>`,
//! or `sha256:<64 hex>` alone). A pin names exactly one image: the one whose digest (its id, or one
//! of its repository digests, as its node's Docker reports them) is that. A tag names whatever it
//! points to now, and is resolved to a digest when a box starts and recorded.
//!
//! [`matching`] is the one place a requested image is checked against a list of allowed ones (a
//! zone's `images`, a box's own image): the manifest, `spawn` on the control host and on a node, and
//! a node-started child's takeover all use it, so they agree.

/// The digest algorithm pins use.
pub const DIGEST_PREFIX: &str = "sha256:";

/// A parsed image reference: its name (repository and tag, or empty for a bare digest) and its pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRef {
    pub name: String,
    pub pin: Option<String>,
}

fn digest_ok(d: &str) -> bool {
    d.strip_prefix(DIGEST_PREFIX).is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)))
}

fn name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 255
        && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-/:".contains(c))
        && !n.starts_with(['-', '.', '/', ':'])
        && !n.contains("..")
}

/// Parses `name`, `name@sha256:<64 hex>` or `sha256:<64 hex>`. Anything with `@` must be a strict
/// pin: it is never read as a tag.
pub fn parse(s: &str) -> Result<ImageRef, String> {
    if let Some((name, digest)) = s.split_once('@') {
        if !digest_ok(digest) {
            return Err(format!("image {s:?}: a pin is @sha256: and 64 lowercase hex digits"));
        }
        if !name_ok(name) || name.contains('@') {
            return Err(format!("image {s:?}: not an image name"));
        }
        return Ok(ImageRef { name: name.into(), pin: Some(digest.into()) });
    }
    if s.starts_with(DIGEST_PREFIX) {
        if !digest_ok(s) {
            return Err(format!("image {s:?}: a digest is sha256: and 64 lowercase hex digits"));
        }
        return Ok(ImageRef { name: String::new(), pin: Some(s.into()) });
    }
    if !name_ok(s) {
        return Err(format!("image {s:?}: not an image name"));
    }
    Ok(ImageRef { name: s.into(), pin: None })
}

/// Whether `s` is pinned by digest.
pub fn is_pinned(s: &str) -> bool {
    parse(s).is_ok_and(|r| r.pin.is_some())
}

/// The repository of a name: without its tag (`wicket-self:dev` → `wicket-self`;
/// `registry:5000/x:1` → `registry:5000/x`).
pub fn repository(name: &str) -> &str {
    match name.rfind(':') {
        Some(i) if !name[i + 1..].contains('/') => &name[..i],
        _ => name,
    }
}

/// `name@digest`: what a box pinned to `digest` is started as (the digest alone if there's no name).
pub fn pinned(name: &str, digest: &str) -> String {
    match parse(name) {
        Ok(ImageRef { name, .. }) if !name.is_empty() => format!("{}@{digest}", repository(&name)),
        _ => digest.to_string(),
    }
}

/// Which of `allowed` lets a box start `wanted`, and the digest the box must then have:
/// - a tag is allowed by the same tag (no pin: it is resolved when the box starts);
/// - a pin is allowed by an entry pinned to the same digest (with no name, or the same repository);
/// - a tag is allowed by an entry pinned for its repository: the box must be that digest, so a
///   retagged image is refused where it starts.
///
/// A pin is never allowed by a tag entry (what a tag points to is no one's choice to narrow). Exact
/// equality wins over the rest. None if nothing allows it (or `wanted` doesn't parse).
pub fn matching(wanted: &str, allowed: &[String]) -> Option<(String, Option<String>)> {
    let w = parse(wanted).ok()?;
    if let Some(e) = allowed.iter().find(|e| *e == wanted) {
        return Some((e.clone(), w.pin));
    }
    for e in allowed {
        let Ok(a) = parse(e) else { continue };
        match (&w.pin, &a.pin) {
            (Some(wp), Some(ap)) if wp == ap && (w.name.is_empty() || a.name.is_empty() || repository(&w.name) == repository(&a.name)) => {
                return Some((e.clone(), Some(ap.clone())));
            }
            (None, Some(ap)) if !a.name.is_empty() && repository(&w.name) == repository(&a.name) => {
                return Some((e.clone(), Some(ap.clone())))
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(c: char) -> String {
        format!("sha256:{}", std::iter::repeat_n(c, 64).collect::<String>())
    }

    #[test]
    fn pins_parse_strictly() {
        assert_eq!(parse("wicket-self:dev").unwrap(), ImageRef { name: "wicket-self:dev".into(), pin: None });
        let p = format!("wicket-self@{}", d('a'));
        assert_eq!(parse(&p).unwrap().pin, Some(d('a')));
        assert_eq!(parse(&d('b')).unwrap(), ImageRef { name: String::new(), pin: Some(d('b')) });
        for bad in [
            "x@sha256:abc".to_string(),
            format!("x@{}", d('A')),
            format!("x@sha512:{}", "a".repeat(128)),
            "x@".into(),
            format!("@{}", d('a')),
            "sha256:zz".into(),
            "../x".into(),
            "a b".into(),
            format!("x@y@{}", d('a')),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
        assert!(is_pinned(&p) && !is_pinned("x:1"));
        assert_eq!(repository("registry:5000/team/x:1"), "registry:5000/team/x");
        assert_eq!(repository("registry:5000/team/x"), "registry:5000/team/x");
        assert_eq!(pinned("wicket-self:dev", &d('c')), format!("wicket-self@{}", d('c')));
    }

    #[test]
    fn a_pinned_entry_pins_what_it_allows() {
        let pin = format!("wicket-self@{}", d('a'));
        let allowed = vec!["img:tag".to_string(), pin.clone()];
        // A tag allowed as a tag: no pin.
        assert_eq!(matching("img:tag", &allowed), Some(("img:tag".into(), None)));
        // The pinned entry itself, its digest alone, or the same repository's digest.
        assert_eq!(matching(&pin, &allowed), Some((pin.clone(), Some(d('a')))));
        assert_eq!(matching(&d('a'), &allowed), Some((pin.clone(), Some(d('a')))));
        // A tag of the pinned repository: allowed, pinned to that digest (a retag is refused where it starts).
        assert_eq!(matching("wicket-self:dev", &allowed), Some((pin.clone(), Some(d('a')))));
        // Another digest of the same repository, another repository's digest, or a pin a tag entry
        // would have to vouch for: refused.
        assert_eq!(matching(&format!("wicket-self@{}", d('b')), &allowed), None);
        assert_eq!(matching(&format!("other@{}", d('a')), &allowed), None);
        assert_eq!(matching(&format!("img@{}", d('c')), &allowed), None);
        assert_eq!(matching("img:other", &allowed), None);
        assert_eq!(matching("bad image", &allowed), None);
    }
}
