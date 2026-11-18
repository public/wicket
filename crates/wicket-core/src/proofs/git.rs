//! A git push's grant (`git`): the terms every grant is made with (#26). #322's Lean spec has no
//! counterpart. Short strings over the letters of `/git-receive-pack` in both cases, so every
//! branch is reached: a push needs 19 bytes (a repository's one byte and `/` before it).

use super::{grant_terms, is_push, PUSH_WINDOW_SECS, RECEIVE_PACK};
use crate::proofs::AnyStr;

const METHOD: &[u8] = b"POSTpostG";
const PATH: &[u8] = b"/-gitrecvpakGITRECVPAKx";

/// `grant_terms`, for any method, path, uses and lifetime picked: a grant is never made to last
/// longer than the approver picked; one that isn't a push's is made exactly as picked; and a push's
/// is uncounted only for its window, at most [`PUSH_WINDOW_SECS`].
#[kani::proof]
#[kani::unwind(21)]
fn a_grant_is_made_as_picked_or_as_a_push_window() {
    let (m, p) = (AnyStr::<4>::new(METHOD), AnyStr::<19>::new(PATH));
    let (uses, ttl): (Option<u32>, u64) = kani::any();
    let (u, t) = grant_terms(m.as_str(), p.as_str(), uses, ttl);
    assert!(t <= ttl);
    if is_push(m.as_str(), p.as_str()) {
        assert!(u.is_none() && t <= PUSH_WINDOW_SECS && t == ttl.min(PUSH_WINDOW_SECS));
    } else {
        assert!(u == uses && t == ttl);
    }
}

/// `is_push` is exactly a POST (any case) to `<repo>/git-receive-pack` (any case) with a
/// repository of at least one byte before its `/`.
#[kani::proof]
#[kani::unwind(21)]
fn a_push_is_a_post_to_a_repositorys_receive_pack() {
    let (m, p) = (AnyStr::<4>::new(METHOD), AnyStr::<19>::new(PATH));
    let (mb, pb) = (m.bytes(), p.bytes());
    let post = mb.len() == 4 && mb.eq_ignore_ascii_case(b"POST");
    let rp = RECEIVE_PACK.as_bytes();
    let mut tail = pb.len() >= rp.len() + 2;
    let mut i = 0;
    while tail && i < rp.len() {
        tail = pb[pb.len() - rp.len() + i].to_ascii_lowercase() == rp[i];
        i += 1;
    }
    assert_eq!(is_push(m.as_str(), p.as_str()), post && tail);
}
