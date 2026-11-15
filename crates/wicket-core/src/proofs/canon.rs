//! Canonical paths (`canon::canonical_path`, `check_plain`, `check_escapes`): Wicket/Canon.lean.
//! The Lean definitions are restated here over bytes, as Rust checks them, and Kani checks the Rust
//! against them.

use super::{canonical_path, check_plain};
use crate::proofs::AnyStr;

/// Enough to spell every rule: `/`, `.`, an escape's `%` and hex digits of both cases (`%2E`,
/// `%2f`, `%4A` is unreserved `J`, `%24` is `$`, `%AA` a non-ASCII byte), `;`, `\` and a letter.
const PATH: &[u8] = b"/.%24AEFa;\\";

/// Longest path checked: room for `/a/%2E/` and `/%2E%2E`.
const N: usize = 7;

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

/// `plainOk`.
fn plain_ok(p: &[u8]) -> bool {
    !p.iter().any(|&c| c == b'\\' || c < 0x20 || c == 0x7f) && !p.contains(&b';') && escapes_ok(p) && segs_ok(p)
}

/// `check_plain` is exactly Lean's `plainOk` (on paths starting with `/`, as `canonical_path` passes
/// it): the definitions the Lean theorems are about are the Rust's.
#[kani::proof]
#[kani::unwind(9)]
fn check_plain_is_plain_ok() {
    let p = AnyStr::<N>::new(PATH);
    kani::assume(p.bytes().first() == Some(&b'/'));
    assert_eq!(check_plain(p.as_str()).is_ok(), plain_ok(p.bytes()));
}

/// `canonicalPath_plain`: a path `canonical_path` accepts is plain, with or without a query and
/// npm's scoped form (`@` is in the alphabet, so `/@a%2Fa` is decided as `/@a/a`).
#[kani::proof]
#[kani::unwind(9)]
fn canonical_path_plain() {
    let pq = AnyStr::<N>::new(b"/.%2Fa@?;");
    if let Ok(p) = canonical_path(pq.as_str()) {
        assert!(plain_ok(p.as_bytes()));
    }
}

/// `upstream_eq`: an upstream that percent-decodes a canonical path and resolves its dot segments
/// (RFC 3986 §5.2.4), in either order, names the same segments as wicket decided on, each decoded:
/// decoding makes no new `/` and no `.` or `..` segment, so resolving changes nothing. With
/// Wicket/Subset.lean's matching this gives `reach_no_escape` and `forbid_no_escape`: no escape or
/// dot segment takes a path out from under (or into) a rule `Q/**`.
#[kani::proof]
#[kani::unwind(9)]
fn upstream_reads_the_same_segments() {
    let p = AnyStr::<N>::new(PATH);
    kani::assume(p.bytes().first() == Some(&b'/'));
    if check_plain(p.as_str()).is_err() {
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
