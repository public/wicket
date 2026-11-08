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
    let lower = path.to_ascii_lowercase();
    for enc in ["%2f", "%5c", "%2e", "%00", "%25"] {
        if lower.contains(enc) {
            return Err(CanonError::EncodedSeparator(enc.to_string()));
        }
    }
    // Skip the leading empty segment; a single trailing slash is allowed.
    let body = &path[1..];
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
        assert!(matches!(canonical_path("/a/%2e%2e/b"), Err(CanonError::EncodedSeparator(_))));
        assert!(matches!(canonical_path("/a%2Fb"), Err(CanonError::EncodedSeparator(_))));
        assert_eq!(canonical_path("/a\\b"), Err(CanonError::BadCharacter));
        assert_eq!(canonical_path("a/b"), Err(CanonError::NotAbsolute));
    }
}
