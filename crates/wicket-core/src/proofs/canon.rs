//! Canonical paths (`canon::canonical_path`: `plain_fault`, `escape_fault`, `npm_scoped`):
//! Wicket/Canon.lean.
//!
//! Lean's `canonicalPath_plain` holds of the Rust by construction: `canonical_path` returns a path
//! only once `check_plain` (whose decision is `plain_fault`, proved here to be `plainOk`) accepted
//! exactly that path. Not harnessed: `npm_scoped` (#143), whose `str` splitting and searching took
//! CBMC past 4 GiB at 7 bytes; its unit tests cover it.
//! The Lean definitions are restated here over bytes, as Rust checks them, and Kani checks the Rust
//! against them.

use super::{escape_fault, plain_fault, prefix_covers};
use crate::proofs::AnyStr;

/// Segments: `/`, `.`, a letter, `;`, `\`, `{` (which a URL parser would escape), and the escape
/// `%2E` (an encoded dot) and `%22` (a byte that may be escaped). Paths of up to [`N`] bytes:
/// `/a/./`, `/../a`, `//`, `/%2E/a`, `/a;\`, `/a{`.
const PATH: &[u8] = b"/.%2Ea;\\{";

/// Longest path checked.
const N: usize = 6;

/// The prefix harness's alphabet: what canonical paths' segments are made of. Escapes and dot
/// segments are `check_plain`'s to refuse (`check_plain_is_plain_ok`), and no escape makes a `/` or a
/// dot segment (`upstream_reads_the_same_segments`), so here `/`, a letter and `.` (in `.a`, `a.`).
const SEGS: &[u8] = b"/a.";

/// Escapes: hex digits of both cases, so `%2E` (a dot), `%2f` (lower case), `%4A` (unreserved
/// `J`), `%24` (`$`, which may be escaped) and `%AA` (a non-ASCII byte) are all spelled; and a
/// letter and `/` around them. Up to [`E`] bytes: two escapes, or one cut short.
const ESC: &[u8] = b"%24AEFa/";
const E: usize = 6;

fn is_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'A'..=b'F').contains(&c)
}

fn hex_val(c: u8) -> u8 {
    if c <= b'9' {
        c - b'0'
    } else {
        c - b'A' + 10
    }
}

/// `unreservedNat`: RFC 3986's unreserved bytes.
fn unreserved(v: u8) -> bool {
    v.is_ascii_alphanumeric() || matches!(v, b'-' | b'.' | b'_' | b'~')
}

/// `escByteOk`: a byte an escape may stand for.
fn esc_byte_ok(v: u8) -> bool {
    !matches!(v, b'/' | b'\\' | 0 | b'%') && !unreserved(v)
}

/// `escapesOk`.
fn escapes_ok(p: &[u8]) -> bool {
    let mut i = 0;
    while i < p.len() {
        if p[i] == b'%' {
            if !(i + 2 < p.len() && is_hex(p[i + 1]) && is_hex(p[i + 2]) && esc_byte_ok(16 * hex_val(p[i + 1]) + hex_val(p[i + 2]))) {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

/// `segsOk`: `/`, then no empty, `.` or `..` segment (one trailing `/` allowed).
fn segs_ok(p: &[u8]) -> bool {
    let Some((b'/', body)) = p.split_first().map(|(c, b)| (*c, b)) else { return false };
    if body.first() == Some(&b'/') {
        return false;
    }
    let b = body.strip_suffix(b"/").unwrap_or(body);
    if b.is_empty() {
        return true;
    }
    let (mut start, mut i) = (0, 0);
    while i <= b.len() {
        if i == b.len() || b[i] == b'/' {
            let s = &b[start..i];
            if s.is_empty() || s == b"." || s == b".." {
                return false;
            }
            start = i + 1;
        }
        i += 1;
    }
    true
}

/// `unescapedChar`: what a URL parser would percent-encode on the way upstream (a symbol is a UTF-8 byte).
fn unescaped_char(c: u8) -> bool {
    [b' ', b'"', b'#', b'<', b'>', b'?', b'`', b'{', b'}'].contains(&c) || 0x80 <= c
}

/// `plainOk`.
fn plain_ok(p: &[u8]) -> bool {
    !p.iter().any(|&c| c == b'\\' || c < 0x20 || c == 0x7f)
        && !p.iter().any(|&c| unescaped_char(c))
        && !p.contains(&b';')
        && escapes_ok(p)
        && segs_ok(p)
}

/// `check_escapes` is exactly Lean's `escapesOk`, on the escapes' own alphabet (the segment
/// checks below then need only one escape spelling).
#[kani::proof]
#[kani::unwind(10)]
fn check_escapes_is_escapes_ok() {
    let p = AnyStr::<E>::new(ESC);
    assert_eq!(escape_fault(p.bytes()).is_none(), escapes_ok(p.bytes()));
}

/// `check_plain` is exactly Lean's `plainOk` (on paths starting with `/`, as `canonical_path` passes
/// it): the definitions the Lean theorems are about are the Rust's.
#[kani::proof]
#[kani::unwind(10)]
fn check_plain_is_plain_ok() {
    let p = AnyStr::<N>::new(PATH);
    kani::assume(p.bytes().first() == Some(&b'/'));
    assert_eq!(plain_fault(p.bytes()).is_none(), plain_ok(p.bytes()));
}

/// `upstream_eq`: an upstream that percent-decodes a canonical path and resolves its dot segments
/// (RFC 3986 §5.2.4), in either order, names the same segments as wicket decided on, each decoded:
/// decoding makes no new `/` and no `.` or `..` segment, so resolving changes nothing. With
/// Wicket/Subset.lean's matching this gives `reach_no_escape` and `forbid_no_escape`: no escape or
/// dot segment takes a path out from under (or into) a rule `Q/**`.
#[kani::proof]
#[kani::unwind(10)]
fn upstream_reads_the_same_segments() {
    let p = AnyStr::<N>::new(PATH);
    kani::assume(p.bytes().first() == Some(&b'/'));
    if plain_fault(p.bytes()).is_some() {
        return;
    }
    let b = p.bytes();
    // Decode, noting where each decoded segment starts and ends.
    let mut out = [0u8; N];
    let mut n = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out[n] = 16 * hex_val(b[i + 1]) + hex_val(b[i + 2]);
            i += 3;
        } else {
            out[n] = b[i];
            i += 1;
        }
        n += 1;
    }
    let decoded = &out[..n];
    // As many separators as the path wicket decided on: no segment was split or joined.
    let slashes = |s: &[u8]| s.iter().filter(|&&c| c == b'/').count();
    assert_eq!(slashes(decoded), slashes(b));
    // And no decoded segment is a dot segment, so dot-segment resolution is the identity.
    let mut start = 1;
    let mut j = 1;
    while j <= n {
        if j == n || decoded[j] == b'/' {
            let s = &decoded[start..j];
            assert!(s != b"." && s != b"..");
            start = j + 1;
        }
        j += 1;
    }
}

/// The segments of a canonical path: between its `/`s, a trailing `/` making no empty segment.
fn segments_end(b: &[u8], seg: usize) -> Option<(usize, usize)> {
    // The `seg`th segment's bounds in `b` (starting after the leading `/`), if there is one.
    let body_end = if b.len() > 1 && b[b.len() - 1] == b'/' { b.len() - 1 } else { b.len() };
    let (mut k, mut start, mut i) = (0, 1, 1);
    if body_end <= 1 {
        return None;
    }
    while i <= body_end {
        if i == body_end || b[i] == b'/' {
            if k == seg {
                return Some((start, i));
            }
            k += 1;
            start = i + 1;
        }
        i += 1;
    }
    None
}

/// A path-prefix grant (#257 4a: honoured on nodes too) covers only paths under it: for two
/// canonical paths, if the grant for `P` covers `Q` then `Q`'s segments begin with all of `P`'s.
/// No escape, dot segment, doubled `/` or separator in a segment takes a covered path outside its
/// prefix, since `canonical_path` admits none of them. With `upstream_reads_the_same_segments`, an
/// upstream that decodes and resolves the path names the same segments. Lean:
/// `prefix_covers_segments` and `prefix_no_escape` (`Wicket/Canon.lean`).
#[kani::proof]
#[kani::unwind(10)]
fn a_prefix_grant_covers_only_paths_under_it() {
    // Two paths over [`SEGS`], one byte shorter than the single-path harnesses (531 s over a
    // six-symbol alphabet): `/../`, `//` and `/.a/` still fit.
    let pre = AnyStr::<{ N - 1 }>::new(SEGS);
    let path = AnyStr::<{ N - 1 }>::new(SEGS);
    let (p, q) = (pre.bytes(), path.bytes());
    kani::assume(p.first() == Some(&b'/') && q.first() == Some(&b'/'));
    // Canonical, over [`SEGS`]: `check_plain_is_plain_ok` proves `plain_fault` is Lean's `plainOk`, which
    // on these bytes (no escape, no `;`, `\\` or byte a parser would encode) is `segs_ok` alone. Using
    // that here keeps CBMC off `plain_fault` for two symbolic paths (401 s with it).
    kani::assume(segs_ok(p) && segs_ok(q));
    let (Ok(ps), Ok(qs)) = (std::str::from_utf8(p), std::str::from_utf8(q)) else { return };
    if !prefix_covers(ps, qs) {
        return;
    }
    let mut seg = 0;
    while let Some((a, b)) = segments_end(p, seg) {
        let Some((c, d)) = segments_end(q, seg) else { panic!("the path has fewer segments than its prefix") };
        assert!(p[a..b] == q[c..d], "segment {seg} differs");
        seg += 1;
    }
}
