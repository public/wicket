//! Canonicalize-or-reject for request paths (design §9.1). Anything ambiguous is rejected rather
//! than normalised, so wicket and the upstream can never disagree about which resource a request
//! names.

use std::borrow::Cow;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CanonError {
    #[error("path must start with '/'")]
    NotAbsolute,
    #[error("path contains a dot segment")]
    DotSegment,
    #[error("path contains an empty segment ('//')")]
    EmptySegment,
    #[error("path contains an encoded separator or dot ({0})")]
    EncodedSeparator(String),
    #[error("path contains a backslash, control character or NUL")]
    BadCharacter,
    #[error("path is longer than {0} bytes")]
    TooLong(usize),
    #[error("path contains a percent-escape that isn't canonical ({0}): unreserved characters must not be escaped, and escapes are two upper-case hex digits")]
    NonCanonicalEscape(String),
    #[error("path contains ';' (matrix parameters are not accepted)")]
    Parameter,
    #[error("{0} is an IP address; use a host name")]
    IpLiteral(String),
    #[error("host {0:?} is not a canonical host name")]
    BadHost(String),
}

/// A path prefix as a grant holds it: ending in `/`, so it covers whole segments (#119). A prefix of
/// `/repos/acme/app` is `/repos/acme/app/`, which covers `/repos/acme/app` itself and every path
/// under it, but not `/repos/acme/app-secrets`.
pub fn prefix_dir(prefix: &str) -> String {
    if prefix.ends_with('/') {
        prefix.to_string()
    } else {
        format!("{prefix}/")
    }
}

/// Whether a path-prefix grant for `prefix` covers `path` (see [`prefix_dir`]).
pub fn prefix_covers(prefix: &str, path: &str) -> bool {
    let dir = prefix_dir(prefix);
    path.starts_with(&dir) || format!("{path}/") == dir
}

/// The host a request names, lowercased and without a trailing dot, if that is how a URL parser
/// would spell it too (WHATWG host parsing). IP addresses in any spelling (`[::1]`, `2852039166`,
/// `0x7f.1`) are refused, as are hosts with escapes or characters a parser would rewrite: the
/// decision, the audit record and the upstream connection then all name the same host.
pub fn canonical_host(raw: &str) -> Result<String, CanonError> {
    let lower = raw.to_ascii_lowercase();
    let host = lower.strip_suffix('.').unwrap_or(&lower);
    match url::Host::parse(host) {
        Ok(url::Host::Domain(d)) if d == host && !host.split('.').any(str::is_empty) => Ok(d),
        Ok(url::Host::Ipv4(_)) | Ok(url::Host::Ipv6(_)) => Err(CanonError::IpLiteral(raw.to_string())),
        _ => Err(CanonError::BadHost(raw.to_string())),
    }
}

const MAX_PATH: usize = 4096;

/// The path a request is decided on, if it is canonical, else an error. Usually the path part of
/// `path_and_query` as written (borrowed); the one exception is npm's scoped-package form (#143),
/// whose first segment `@scope%2fname` is decided as `/@scope/name` (see [`npm_scoped`]). The
/// request still goes upstream as the client wrote it: only the decision uses the decoded form.
pub fn canonical_path(path_and_query: &str) -> Result<Cow<'_, str>, CanonError> {
    let path = path_and_query.split('?').next().unwrap_or("");
    if path.len() > MAX_PATH {
        return Err(CanonError::TooLong(MAX_PATH));
    }
    if !path.starts_with('/') {
        return Err(CanonError::NotAbsolute);
    }
    let path = match npm_scoped(path) {
        Some(decoded) => Cow::Owned(decoded),
        None => Cow::Borrowed(path),
    };
    check_plain(&path)?;
    Ok(path)
}

/// The checks every decided path passes: no odd characters, parameters, escapes or segments.
fn check_plain(path: &str) -> Result<(), CanonError> {
    if path.bytes().any(|b| b == b'\\' || b < 0x20 || b == 0x7f) {
        return Err(CanonError::BadCharacter);
    }
    // `;` starts a path parameter for some servers (`/a;x/b`, `/..;/`): not one spelling per resource.
    if path.contains(';') {
        return Err(CanonError::Parameter);
    }
    check_escapes(path)?;
    // Skip the leading empty segment; a single trailing slash is allowed.
    let body = &path[1..];
    if body.starts_with('/') {
        return Err(CanonError::EmptySegment); // "//", which the trailing-slash rule below would accept
    }
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() {
        return Ok(());
    }
    for seg in body.split('/') {
        match seg {
            "" => return Err(CanonError::EmptySegment),
            "." | ".." => return Err(CanonError::DotSegment),
            _ => {}
        }
    }
    Ok(())
}

/// npm asks a registry for a scoped package as `GET /@scope%2fname` (#143). If `path`'s first
/// segment is exactly that shape, the path with that one `%2f` (or `%2F`) decoded to `/`, so a rule
/// on `/@scope/name` or `/@scope/**` decides it as it would the unencoded spelling. Scope and name
/// are npm's lower-case URL-safe characters and don't start with `.` (so neither can be a dot
/// segment); anything else in the segment (another escape, a second `%2f`, `%252f`) is not this
/// shape and is left for `check_escapes` to refuse.
fn npm_scoped(path: &str) -> Option<String> {
    let first = path[1..].split('/').next().unwrap_or("");
    let rest = &path[1 + first.len()..];
    let scoped = first.strip_prefix('@')?;
    let at = scoped.find('%')?;
    let (scope, name) = (&scoped[..at], &scoped[at..]);
    let name = name.strip_prefix("%2f").or_else(|| name.strip_prefix("%2F"))?;
    let part = |s: &str| {
        let b = s.as_bytes();
        !b.is_empty()
            && b.len() <= 214
            && b[0] != b'.'
            && b.iter().all(|&c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'))
    };
    (part(scope) && part(name)).then(|| format!("/@{scope}/{name}{rest}"))
}

/// Every `%` must start an escape of two upper-case hex digits, for a byte that has to be escaped:
/// not an unreserved character (`/pro%64` is `/prod` to most servers, so a forbid on `/prod/**`
/// would miss it), and not a separator, dot, NUL or `%` itself.
fn check_escapes(path: &str) -> Result<(), CanonError> {
    let b = path.as_bytes();
    let mut i = 0;
    while let Some(off) = b[i..].iter().position(|&c| c == b'%') {
        let at = i + off;
        let esc = path.get(at..at + 3).unwrap_or(&path[at..]);
        let hex = |c: u8| matches!(c, b'0'..=b'9' | b'A'..=b'F');
        if esc.len() < 3 || !hex(esc.as_bytes()[1]) || !hex(esc.as_bytes()[2]) {
            let lower = esc.to_ascii_lowercase();
            if ["%2f", "%5c", "%2e", "%00", "%25"].contains(&lower.as_str()) {
                return Err(CanonError::EncodedSeparator(lower));
            }
            return Err(CanonError::NonCanonicalEscape(esc.to_string()));
        }
        let byte = u8::from_str_radix(&esc[1..], 16).expect("two hex digits");
        if matches!(byte, b'/' | b'\\' | b'.' | 0 | b'%') {
            return Err(CanonError::EncodedSeparator(esc.to_ascii_lowercase()));
        }
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') {
            return Err(CanonError::NonCanonicalEscape(esc.to_string()));
        }
        i = at + 3;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_paths() {
        assert_eq!(canonical_path("/repos/a/b/contents/x.md?ref=main").as_deref(), Ok("/repos/a/b/contents/x.md"));
        assert_eq!(canonical_path("/").as_deref(), Ok("/"));
        assert_eq!(canonical_path("/a/b/").as_deref(), Ok("/a/b/"));
    }

    #[test]
    fn rejects_ambiguous_paths() {
        assert_eq!(canonical_path("/a/../b"), Err(CanonError::DotSegment));
        assert_eq!(canonical_path("/a/./b"), Err(CanonError::DotSegment));
        assert_eq!(canonical_path("/a//b"), Err(CanonError::EmptySegment));
        assert_eq!(canonical_path("//"), Err(CanonError::EmptySegment));
        assert_eq!(canonical_path("//a"), Err(CanonError::EmptySegment));
        assert_eq!(canonical_path("/a//"), Err(CanonError::EmptySegment));
        assert!(matches!(canonical_path("/a/%2e%2e/b"), Err(CanonError::EncodedSeparator(_))));
        assert!(matches!(canonical_path("/a%2Fb"), Err(CanonError::EncodedSeparator(_))));
        assert_eq!(canonical_path("/a\\b"), Err(CanonError::BadCharacter));
        assert_eq!(canonical_path("a/b"), Err(CanonError::NotAbsolute));
    }

    /// #119: a prefix covers whole segments only.
    #[test]
    fn prefixes_cover_whole_segments() {
        assert_eq!(prefix_dir("/repos/acme/app"), "/repos/acme/app/");
        assert_eq!(prefix_dir("/"), "/");
        for p in ["/repos/acme/app", "/repos/acme/app/"] {
            assert!(prefix_covers(p, "/repos/acme/app"));
            assert!(prefix_covers(p, "/repos/acme/app/"));
            assert!(prefix_covers(p, "/repos/acme/app/contents/x"));
            assert!(!prefix_covers(p, "/repos/acme/app-secrets/contents/x"));
            assert!(!prefix_covers(p, "/repos/acme/ap"));
        }
        assert!(prefix_covers("/", "/anything/at/all"));
    }

    /// #116: hosts are decided in one spelling, and IP addresses in none.
    #[test]
    fn hosts_are_canonical_or_refused() {
        assert_eq!(canonical_host("API.GitHub.com."), Ok("api.github.com".into()));
        for h in ["[::1]", "2852039166", "0x7f.1", "127.0.0.1", "1.1.1.1"] {
            assert!(matches!(canonical_host(h), Err(CanonError::IpLiteral(_))), "{h}");
        }
        for h in ["", ".", "ex%61mple.com", "a b", "foo.123", "a..b"] {
            assert!(matches!(canonical_host(h), Err(CanonError::BadHost(_))), "{h}");
        }
    }

    /// #115: spellings most servers read as another, canonical path are refused, so a forbid glob
    /// can't be dodged by them.
    #[test]
    fn rejects_other_spellings_of_a_path() {
        for p in ["/repos/acme/pro%64/x", "/m%65rge", "/a%2Db", "/a%5Fb", "/a%7Eb", "/a%41"] {
            assert!(matches!(canonical_path(p), Err(CanonError::NonCanonicalEscape(_))), "{p}");
        }
        for p in ["/repos/acme/prod;x/y", "/a/..;/b", "/a;"] {
            assert_eq!(canonical_path(p), Err(CanonError::Parameter), "{p}");
        }
        for p in ["/a%2", "/a%", "/a%zz", "/a%c3%a9"] {
            assert!(matches!(canonical_path(p), Err(CanonError::NonCanonicalEscape(_))), "{p}");
        }
        assert!(matches!(canonical_path("/a%2e%2E"), Err(CanonError::EncodedSeparator(_))));
        assert!(matches!(canonical_path("/a%2E"), Err(CanonError::EncodedSeparator(_))));
        // Escapes of bytes that must be escaped are fine.
        assert_eq!(canonical_path("/a%20b/caf%C3%A9?q=%41").as_deref(), Ok("/a%20b/caf%C3%A9"));
    }

    /// #143: npm's scoped-package form is decided with its one `%2f` decoded; nothing else is.
    #[test]
    fn npm_scoped_packages_decode_one_separator() {
        for (raw, want) in [
            ("/@types%2fnode", "/@types/node"),
            ("/@types%2Fnode", "/@types/node"),
            ("/@eslint-community%2feslint-utils", "/@eslint-community/eslint-utils"),
            ("/@babel%2fcore?write=true", "/@babel/core"),
            ("/@scope%2fname/1.2.3", "/@scope/name/1.2.3"),
            ("/@scope%2fname/", "/@scope/name/"),
            ("/@0x%2fa.b_c~d", "/@0x/a.b_c~d"),
            ("/@_x%2f_y", "/@_x/_y"),
        ] {
            let got = canonical_path(raw);
            assert_eq!(got.as_deref(), Ok(want), "{raw}");
            assert!(matches!(got, Ok(Cow::Owned(_))), "{raw}");
        }
        // The unencoded spelling decides the same and is borrowed as written.
        assert!(matches!(canonical_path("/@types/node"), Ok(Cow::Borrowed("/@types/node"))));
        for p in [
            "/x/@scope%2fname",          // not the first segment
            "/-/package/@scope%2fname/dist-tags",
            "/@scope%2fname%2fmore",     // double
            "/@sc%2fope%2fname",         // in the scope
            "/@scope%2f%2fname",
            "/%40scope%2fname",          // `@` escaped
            "/scope%2fname",             // no `@`
            "/@%2fname",                 // empty scope
            "/@scope%2f",                // empty name
            "/@scope%2f..",              // dot segment once decoded
            "/@..%2fname",
            "/@scope%2f.name",
            "/@.scope%2fname",
            "/@Scope%2fname",            // upper case
            "/@scope%2fna%20me",         // another escape in the segment
            "/@scope%5cname",
            "/@scope%2Ename",
        ] {
            assert!(matches!(canonical_path(p), Err(CanonError::EncodedSeparator(_))), "{p}: {:?}", canonical_path(p));
        }
        assert!(matches!(canonical_path("/@scope%252fname"), Err(CanonError::EncodedSeparator(_))));
        assert!(matches!(canonical_path("/@scope%2fname%41"), Err(_)));
        assert_eq!(canonical_path("/@scope%2fname/../x"), Err(CanonError::DotSegment));
        assert_eq!(canonical_path("/@scope%2fname//x"), Err(CanonError::EmptySegment));
        assert_eq!(canonical_path("/@scope%2fname;x"), Err(CanonError::Parameter));
        assert_eq!(canonical_path("/@scope%2fname/a\\b"), Err(CanonError::BadCharacter));
    }
}
