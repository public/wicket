//! Canonicalize-or-reject for request paths (design §9.1). Anything ambiguous is rejected rather
//! than normalised, so wicket and the upstream can never disagree about which resource a request
//! names.

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
}

const MAX_PATH: usize = 4096;

/// Returns the path part (without query) if it is canonical, else an error.
pub fn canonical_path(path_and_query: &str) -> Result<&str, CanonError> {
    let path = path_and_query.split('?').next().unwrap_or("");
    if path.len() > MAX_PATH {
        return Err(CanonError::TooLong(MAX_PATH));
    }
    if !path.starts_with('/') {
        return Err(CanonError::NotAbsolute);
    }
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
        return Ok(path);
    }
    for seg in body.split('/') {
        match seg {
            "" => return Err(CanonError::EmptySegment),
            "." | ".." => return Err(CanonError::DotSegment),
            _ => {}
        }
    }
    Ok(path)
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
        assert_eq!(canonical_path("/repos/a/b/contents/x.md?ref=main"), Ok("/repos/a/b/contents/x.md"));
        assert_eq!(canonical_path("/"), Ok("/"));
        assert_eq!(canonical_path("/a/b/"), Ok("/a/b/"));
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
        assert_eq!(canonical_path("/a%20b/caf%C3%A9?q=%41"), Ok("/a%20b/caf%C3%A9"));
    }
}
