//! Kani proof harnesses (#325), built only by `cargo kani` (`cfg(kani)`; ci/kani.sh). Each states,
//! on bounded inputs, a property #322's Lean spec (verification/lean, PR #340) proves of its model
//! of the same function, and names that theorem: Kani checks it of the Rust itself. Where the Lean
//! spec has no counterpart (protocol skew, budget arithmetic) the harness says so.
//!
//! The harnesses live next to the code they check (`#[path]` child modules of `manifest`,
//! `subset`, `canon`, `op`, `git`, `effect`, `version`, `budget`, `authority` and `quota`, so they
//! reach private functions); this module holds what they share.
//!
//! Bounds. CBMC unrolls every loop, so inputs are short strings over a few characters chosen to
//! reach every branch, and the checked functions avoid `format!` and allocation on the paths the
//! harnesses take (formatting alone exhausts a 6 GiB box). Each harness's bound is in its
//! `#[kani::unwind]`; ci/kani.sh runs them one at a time.

/// A string of at most `N` bytes, each one of `alphabet` (ASCII, so every choice is valid UTF-8),
/// held in a fixed array: no allocation, so no heap model for CBMC to track.
pub(crate) struct AnyStr<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> AnyStr<N> {
    pub(crate) fn new(alphabet: &[u8]) -> Self {
        let buf: [u8; N] = kani::any();
        let mut i = 0;
        while i < N {
            kani::assume(buf[i].is_ascii() && alphabet.contains(&buf[i]));
            i += 1;
        }
        let len: usize = kani::any_where(|&l| l <= N);
        AnyStr { buf, len }
    }

    pub(crate) fn as_str(&self) -> &str {
        // SAFETY: every byte is ASCII (assumed in `new`), so any prefix of `buf` is valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}
