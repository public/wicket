//! Target 9: canonicalize-or-reject (`wicket_core::canonical_host` and `canonical_path`, #361), the
//! one spelling every decision, audit record and upstream request agrees on. The input is tried as
//! a host and as a path (with any query), whole; `#361`'s conformance pack pins known bypasses, this
//! looks for unknown ones.
//!
//! The oracle, besides panics:
//! - a host taken is lowercase, has no trailing dot and no empty label, is taken again unchanged
//!   (with or without a trailing dot), and is what a URL parser makes of it: the same domain, never
//!   an IP address. Whatever a URL parser reads as an IP address is refused.
//! - a path taken starts with `/`, has no empty, `.` or `..` segment, no `;`, backslash, control
//!   character or encoded separator or dot, and is taken again unchanged; it is exactly the path as
//!   written, and what a URL parser sends upstream.
//! - a path taken with an encoded slash decided decoded (`canonical_path_decoding`, a reach rule's
//!   `decode_slash`, #664) holds to the same rules, and differs from the path as written only by
//!   encoded slashes that became `/`.

use wicket_core::{canonical_host, canonical_path, canonical_path_decoding};

pub fn run(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else { return };
    host(s);
    path(s);
}

fn host(raw: &str) {
    let parsed =
        url::Url::parse(&format!("https://{raw}/")).ok().filter(|u| u.path() == "/" && u.query().is_none() && u.fragment().is_none());
    if let Some(u) = &parsed {
        if matches!(u.host(), Some(url_host) if !matches!(url_host, url::Host::Domain(_))) {
            assert!(canonical_host(raw).is_err(), "{raw:?} is an IP address to a URL parser, and was taken as a host");
        }
    }
    let Ok(h) = canonical_host(raw) else { return };
    assert!(!h.is_empty() && !h.ends_with('.') && !h.split('.').any(str::is_empty), "{raw:?} -> {h:?}");
    assert!(!h.bytes().any(|b| b.is_ascii_uppercase()), "{raw:?} -> {h:?} isn't lowercase");
    assert_eq!(canonical_host(&h).as_deref(), Ok(h.as_str()), "{raw:?} -> {h:?} isn't taken again unchanged");
    assert_eq!(canonical_host(&format!("{h}.")).as_deref(), Ok(h.as_str()), "{h:?} with a trailing dot");
    let u = url::Url::parse(&format!("https://{h}/")).unwrap_or_else(|e| panic!("{raw:?} -> {h:?} isn't a URL's host: {e}"));
    assert!(matches!(u.host(), Some(url::Host::Domain(d)) if d == h), "{raw:?} -> {h:?}, but a URL parser reads {:?}", u.host());
}

fn path(pq: &str) {
    if let Ok(c) = canonical_path(pq) {
        plain(pq, c.as_ref());
        assert_eq!(c.as_ref(), pq.split('?').next().unwrap_or(""), "{pq:?}: nothing is decoded unless asked");
        let u = url::Url::parse(&format!("https://h.example{pq}")).unwrap_or_else(|e| panic!("{pq:?} isn't a URL's path: {e}"));
        assert_eq!(u.path(), c.as_ref(), "{pq:?} is decided as {c:?} but sent as {:?}", u.path());
    }
    if let Ok(d) = canonical_path_decoding(pq, &[1, 2, 3]) {
        plain(pq, d.as_ref());
        let as_written = pq.split('?').next().unwrap_or("");
        assert_eq!(as_written.replace("%2F", "/").replace("%2f", "/"), d.as_ref(), "{pq:?} -> {d:?}: only encoded slashes decoded");
    }
}

/// What every decided path holds to.
fn plain(pq: &str, p: &str) {
    assert!(p.starts_with('/'), "{pq:?} -> {p:?}");
    let lower = p.to_ascii_lowercase();
    for bad in ["%2f", "%5c", "%2e", "%00", ";", "\\"] {
        assert!(!lower.contains(bad), "{pq:?} -> {p:?} contains {bad}");
    }
    assert!(!p.bytes().any(|b| b < 0x20 || b == 0x7f), "{pq:?} -> {p:?} has a control character");
    for seg in p[1..].split('/') {
        assert!(seg != "." && seg != "..", "{pq:?} -> {p:?} has a dot segment");
    }
    // An empty segment only as the trailing one (`/a/`), or the root.
    assert!(!p[1..].split('/').rev().skip(1).any(str::is_empty), "{pq:?} -> {p:?} has an empty segment");
    assert_eq!(canonical_path(p).as_deref(), Ok(p), "{pq:?} -> {p:?} isn't taken again unchanged");
}
