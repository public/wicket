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
    #[error("path contains {0:?} unescaped, which a URL parser would percent-encode on the way upstream; send it percent-encoded")]
    Unescaped(char),
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

/// Whether a path-prefix grant for `prefix` covers `path` (see [`prefix_dir`]): the directory itself,
/// or a path under it. Without allocating (a node decides it per request, and Kani checks it).
pub fn prefix_covers(prefix: &str, path: &str) -> bool {
    let dir = prefix.strip_suffix('/').unwrap_or(prefix);
    path == dir || path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('/'))
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

/// The path a request is decided on, if it is canonical, else an error: the path part of
/// `path_and_query` exactly as written. Nothing is decoded: an encoded slash is refused, unless a
/// zone's rule for the host asks for it to be decided decoded ([`canonical_path_decoding`]).
pub fn canonical_path(path_and_query: &str) -> Result<Cow<'_, str>, CanonError> {
    canonical_path_decoding(path_and_query, &[])
}

/// [`canonical_path`], with one encoded slash (`%2F` or `%2f`) decided as `/` in each of
/// `segments` (1 for the first) that holds exactly one, between two non-empty parts (#664, a reach
/// rule's `decode_slash`, for an API that names one resource `/@scope%2fname`). The decoded path must pass
/// every check a path passes (no dot or empty segment, no other escape of a separator, no double
/// escape), and the request still goes upstream as the client wrote it: only the decision reads
/// the decoded form.
pub fn canonical_path_decoding<'a>(path_and_query: &'a str, segments: &[u8]) -> Result<Cow<'a, str>, CanonError> {
    let path = path_and_query.split('?').next().unwrap_or("");
    if path.len() > MAX_PATH {
        return Err(CanonError::TooLong(MAX_PATH));
    }
    if !path.starts_with('/') {
        return Err(CanonError::NotAbsolute);
    }
    let path = match decode_slash(path, segments) {
        Some(decoded) => Cow::Owned(decoded),
        None => Cow::Borrowed(path),
    };
    check_plain(&path)?;
    Ok(path)
}

/// Where a segment's only encoded slash starts, if it has exactly one and it is between two
/// non-empty parts: what [`decode_slash`] decodes. On bytes and allocation-free, for the Kani
/// harness (proofs/canon.rs).
fn slash_escape(seg: &[u8]) -> Option<usize> {
    let is_esc = |i: usize| seg.get(i) == Some(&b'%') && seg.get(i + 1) == Some(&b'2') && matches!(seg.get(i + 2), Some(b'f' | b'F'));
    let mut found = None;
    let mut i = 0;
    while i < seg.len() {
        if is_esc(i) {
            if found.is_some() {
                return None;
            }
            found = Some(i);
            i += 3;
        } else {
            i += 1;
        }
    }
    found.filter(|&at| at > 0 && at + 3 < seg.len())
}

/// `path` (starting with `/`) with each of `segments` (1 for the first) that has one encoded
/// slash ([`slash_escape`]) decoded; None if nothing was decoded.
fn decode_slash(path: &str, segments: &[u8]) -> Option<String> {
    if segments.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(path.len());
    let mut changed = false;
    for (k, seg) in path[1..].split('/').enumerate() {
        out.push('/');
        let at = if segments.iter().any(|&n| usize::from(n) == k + 1) { slash_escape(seg.as_bytes()) } else { None };
        match at {
            Some(at) => {
                out.push_str(&seg[..at]);
                out.push('/');
                out.push_str(&seg[at + 3..]);
                changed = true;
            }
            None => out.push_str(seg),
        }
    }
    changed.then_some(out)
}

/// The checks every decided path passes: no odd characters, parameters, escapes or segments.
fn check_plain(path: &str) -> Result<(), CanonError> {
    plain_fault(path.as_bytes()).map_or(Ok(()), |f| Err(f.error(path)))
}

/// What is wrong with a path, without the error's text: [`check_plain`]'s and [`escape_fault`]'s
/// decisions, on bytes and allocation-free, so the Kani harnesses (#325, proofs/canon.rs) check
/// them themselves. Escapes carry where they start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    BadCharacter,
    Unescaped(usize),
    Parameter,
    EncodedSeparator(usize),
    NonCanonicalEscape(usize),
    EmptySegment,
    DotSegment,
}

impl Fault {
    fn error(self, path: &str) -> CanonError {
        // The escape as written (all of the rest if it isn't three characters).
        let esc = |at: usize| path.get(at..at + 3).unwrap_or(&path[at..]);
        match self {
            Fault::BadCharacter => CanonError::BadCharacter,
            Fault::Unescaped(at) => CanonError::Unescaped(path[at..].chars().next().unwrap_or(char::REPLACEMENT_CHARACTER)),
            Fault::Parameter => CanonError::Parameter,
            Fault::EncodedSeparator(at) => CanonError::EncodedSeparator(esc(at).to_ascii_lowercase()),
            Fault::NonCanonicalEscape(at) => CanonError::NonCanonicalEscape(esc(at).to_string()),
            Fault::EmptySegment => CanonError::EmptySegment,
            Fault::DotSegment => CanonError::DotSegment,
        }
    }
}

/// [`check_plain`]'s decision (`b` starts with `/`).
fn plain_fault(b: &[u8]) -> Option<Fault> {
    if b.iter().any(|&c| c == b'\\' || c < 0x20 || c == 0x7f) {
        return Some(Fault::BadCharacter);
    }
    // The request goes upstream through a URL parser, which percent-encodes these (WHATWG's path
    // percent-encode set, and every non-ASCII character): `/a{b` would be decided as itself and sent
    // as `/a%7Bb`. Refused, so the decided path is the one sent.
    // The first such byte is where its character starts: one of these, or a non-ASCII lead byte.
    if let Some(at) = b.iter().position(|&c| matches!(c, b' ' | b'"' | b'#' | b'<' | b'>' | b'?' | b'`' | b'{' | b'}') || c >= 0x80) {
        return Some(Fault::Unescaped(at));
    }
    // `;` starts a path parameter for some servers (`/a;x/b`, `/..;/`): not one spelling per resource.
    if b.contains(&b';') {
        return Some(Fault::Parameter);
    }
    if let Some(f) = escape_fault(b) {
        return Some(f);
    }
    // Skip the leading empty segment; a single trailing slash is allowed.
    let body = &b[1..];
    if body.first() == Some(&b'/') {
        return Some(Fault::EmptySegment); // "//", which the trailing-slash rule below would accept
    }
    let body = body.strip_suffix(b"/").unwrap_or(body);
    if body.is_empty() {
        return None;
    }
    for seg in body.split(|&c| c == b'/') {
        match seg {
            b"" => return Some(Fault::EmptySegment),
            b"." | b".." => return Some(Fault::DotSegment),
            _ => {}
        }
    }
    None
}

/// Every `%` must start an escape of two upper-case hex digits, for a byte that has to be escaped:
/// not an unreserved character (`/pro%64` is `/prod` to most servers, so a forbid on `/prod/**`
/// would miss it), and not a separator, dot, NUL or `%` itself. The first that isn't, if any.
fn escape_fault(b: &[u8]) -> Option<Fault> {
    let hex = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            i += 1;
            continue;
        }
        let byte = match (b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
            (Some(h), Some(l)) => 16 * h + l,
            _ => {
                // Not canonical; a lower-case spelling of an encoded separator or dot says so.
                let lower = |j: usize| b.get(i + j).map(u8::to_ascii_lowercase);
                let sep = matches!(
                    (lower(1), lower(2)),
                    (Some(b'2'), Some(b'f' | b'e' | b'5')) | (Some(b'5'), Some(b'c')) | (Some(b'0'), Some(b'0'))
                );
                return Some(if sep { Fault::EncodedSeparator(i) } else { Fault::NonCanonicalEscape(i) });
            }
        };
        if matches!(byte, b'/' | b'\\' | b'.' | 0 | b'%') {
            return Some(Fault::EncodedSeparator(i));
        }
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') {
            return Some(Fault::NonCanonicalEscape(i));
        }
        i += 3;
    }
    None
}

#[cfg(test)]
mod tests {

    /// #326: the length cap is inclusive, and each byte the matcher can't see as written (a
    /// backslash, a control character, DEL) is refused on its own.
    #[test]
    fn the_length_cap_is_inclusive_and_each_bad_byte_is_refused() {
        let at = format!("/{}", "a".repeat(MAX_PATH - 1));
        assert!(canonical_path(&at).is_ok());
        assert!(matches!(canonical_path(&format!("{at}a")), Err(CanonError::TooLong(_))));
        assert!(canonical_path(&format!("{at}?q=1")).is_ok(), "the query isn't counted");
        for bad in ["/a\\b", "/a\u{1}b", "/a\u{1f}b", "/a\u{7f}b"] {
            assert!(canonical_path(bad).is_err(), "{bad:?}");
        }
        assert!(canonical_path("/a b").is_err() && canonical_path("/a~b").is_ok());
    }
    use super::*;

    /// #325 rewrote `check_plain` and `check_escapes` on bytes for Kani: they decide, and report,
    /// exactly as the previous spellings did, on every path of up to 6 bytes over two alphabets that
    /// spell every escape case.
    #[test]
    fn byte_wise_checks_agree_with_the_old_spelling() {
        fn plain_was(path: &str) -> Result<(), CanonError> {
            if path.bytes().any(|b| b == b'\\' || b < 0x20 || b == 0x7f) {
                return Err(CanonError::BadCharacter);
            }
            if let Some(c) = path.chars().find(|c| matches!(c, ' ' | '"' | '#' | '<' | '>' | '?' | '`' | '{' | '}') || !c.is_ascii()) {
                return Err(CanonError::Unescaped(c));
            }
            if path.contains(';') {
                return Err(CanonError::Parameter);
            }
            escapes_was(path)?;
            let body = &path[1..];
            if body.starts_with('/') {
                return Err(CanonError::EmptySegment);
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
        fn escapes_was(path: &str) -> Result<(), CanonError> {
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
        for alphabet in [&b"/.%2EFf;{"[..], b"%05cC4a/", b"%2eAD\\/"] {
            for tail in crate::subset::tests::strings(alphabet, 5) {
                for p in [format!("/{tail}"), format!("/{tail}\u{e9}"), format!("/%{tail}\u{e9}")] {
                    assert_eq!(check_plain(&p), plain_was(&p), "{p:?}");
                }
            }
        }
    }

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
        // What a URL parser would escape on the way upstream (found by fuzzing, #323).
        for (p, c) in
            [("/up{oad", '{'), ("/a}", '}'), ("/a b", ' '), ("/a\"b", '"'), ("/a<b>", '<'), ("/a`b", '`'), ("/caf\u{e9}", '\u{e9}')]
        {
            assert_eq!(canonical_path(p), Err(CanonError::Unescaped(c)), "{p}");
        }
        // Their escapes are canonical, and go upstream as they are.
        assert!(canonical_path("/up%7Boad").is_ok());
        assert!(canonical_path("/caf%C3%A9").is_ok());
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
        // As prefix_dir has it: with or without the trailing `/`, and `/` (or nothing) is everything.
        for (pre, path) in [("/a", "/a"), ("/a/", "/a"), ("/a", "/a/"), ("/a/", "/a/b"), ("", "/x"), ("/", "/")] {
            assert!(
                prefix_covers(pre, path) && (path.starts_with(&prefix_dir(pre)) || format!("{path}/") == prefix_dir(pre)),
                "{pre} {path}"
            );
        }
        for (pre, path) in [("/a", "/ab"), ("/a/", "/"), ("/a/b", "/a"), ("/a", "")] {
            assert!(!prefix_covers(pre, path), "{pre} {path}");
        }
    }

    /// #257 4a: a prefix grant, now also honoured on nodes, never covers a path outside it. Every
    /// path of up to 6 bytes over `/`, two letters, `.`, `%2E` and `%2e` (dot segments, encoded
    /// dots, doubled `/`, case) that `canonical_path` accepts is checked against every other as a
    /// prefix: if the grant covers it, its segments begin with all of the prefix's. (The Kani
    /// harness `a_prefix_grant_covers_only_paths_under_it` proves it for its alphabet too.)
    #[test]
    fn a_prefix_grant_covers_only_paths_under_it() {
        let alphabet = ["/", "a", "b", ".", "%2E", "%2e"];
        let mut raw = vec![String::new()];
        let mut all = vec![];
        for _ in 0..6 {
            raw = raw.iter().flat_map(|s| alphabet.iter().map(move |a| format!("{s}{a}"))).filter(|s| s.len() <= 6).collect();
            all.extend(raw.iter().cloned());
        }
        all.sort();
        all.dedup();
        // The allocation-free form means what `prefix_dir`'s did, on every pair, canonical or not.
        let old = |pre: &str, path: &str| path.starts_with(&prefix_dir(pre)) || format!("{path}/") == prefix_dir(pre);
        for pre in all.iter().take(400) {
            for path in &all {
                assert_eq!(prefix_covers(pre, path), old(pre, path), "{pre} {path}");
            }
        }
        let canonical: Vec<String> = all.iter().filter_map(|s| canonical_path(s).ok().map(|p| p.into_owned())).collect();
        let segs = |p: &str| -> Vec<String> {
            p.trim_start_matches('/').trim_end_matches('/').split('/').filter(|s| !s.is_empty()).map(String::from).collect()
        };
        // What a canonical path can't hold: a doubled `/`, an encoded dot, a `.` or `..` segment.
        assert!(canonical.len() > 20);
        assert!(
            canonical.iter().all(|p| !p.contains("//") && !p.contains("%2") && segs(p).iter().all(|s| s != "." && s != "..")),
            "{canonical:?}"
        );
        let mut covered = 0;
        for pre in &canonical {
            for path in &canonical {
                if prefix_covers(pre, path) {
                    covered += 1;
                    let (ps, qs) = (segs(pre), segs(path));
                    assert!(qs.len() >= ps.len() && qs[..ps.len()] == ps[..], "{pre} covers {path}");
                }
            }
        }
        assert!(covered > canonical.len(), "the check saw prefixes that cover other paths");
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

    /// #664 (#143's guarantees, kept): nothing is decoded unless asked; asked, one encoded slash
    /// in a named segment is decided as `/`, between two non-empty parts, and the result passes
    /// every check a path does: no dot or empty segment, no double escape, no other separator.
    #[test]
    fn an_encoded_slash_is_decoded_only_where_asked() {
        // Not asked: refused, as every encoded separator is.
        for p in ["/@scope%2fname", "/a%2Fb", "/x/a%2fb"] {
            assert!(matches!(canonical_path(p), Err(CanonError::EncodedSeparator(_))), "{p}");
        }
        let first = |p| canonical_path_decoding(p, &[1]);
        for (raw, want) in [
            ("/@types%2fnode", "/@types/node"),
            ("/@types%2Fnode", "/@types/node"),
            ("/@babel%2fcore?write=true", "/@babel/core"),
            ("/@scope%2fname/1.2.3", "/@scope/name/1.2.3"),
            ("/@scope%2fname/", "/@scope/name/"),
            ("/Org%2FRepo", "/Org/Repo"),
            ("/a%2fb", "/a/b"),
        ] {
            let got = first(raw);
            assert_eq!(got.as_deref(), Ok(want), "{raw}");
            assert!(matches!(got, Ok(Cow::Owned(_))), "{raw}");
        }
        // The unencoded spelling decides the same and is borrowed as written.
        assert!(matches!(first("/@types/node"), Ok(Cow::Borrowed("/@types/node"))));
        // Only the segments named: the second segment here.
        assert_eq!(canonical_path_decoding("/x/a%2fb", &[2]).as_deref(), Ok("/x/a/b"));
        assert!(first("/x/a%2fb").is_err(), "the second segment wasn't named");
        assert_eq!(canonical_path_decoding("/a%2fb/c%2fd", &[1, 2]).as_deref(), Ok("/a/b/c/d"));
        for p in [
            "/a%2fb%2fc", // two in one segment
            "/a%2f%2fb",
            "/%2fname", // an empty part
            "/name%2f",
            "/%40scope%2f", // and another escape
            "/a%5cb",       // not a slash
            "/a%2Eb",
        ] {
            assert!(matches!(first(p), Err(CanonError::EncodedSeparator(_))), "{p}: {:?}", first(p));
        }
        assert!(matches!(first("/a%252fb"), Err(CanonError::EncodedSeparator(_))), "a double escape isn't decoded");
        assert_eq!(first("/a%2f.."), Err(CanonError::DotSegment), "a dot segment once decoded");
        assert_eq!(first("/..%2fa"), Err(CanonError::DotSegment));
        assert!(first("/a%2fb%41").is_err());
        assert_eq!(first("/a%2fb/../x"), Err(CanonError::DotSegment));
        assert_eq!(first("/a%2fb//x"), Err(CanonError::EmptySegment));
        assert_eq!(first("/a%2fb;x"), Err(CanonError::Parameter));
        assert_eq!(first("/a%2fb/c\\d"), Err(CanonError::BadCharacter));
        assert_eq!(slash_escape(b"a%2fb"), Some(1));
        assert_eq!(slash_escape(b"a%2fb%2Fc"), None);
        assert_eq!(slash_escape(b"%2fb"), None);
    }
}

#[cfg(kani)]
#[path = "proofs/canon.rs"]
mod proofs;
