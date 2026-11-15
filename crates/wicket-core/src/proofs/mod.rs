//! Kani proof harnesses (#325), built only by `cargo kani` (`cfg(kani)`; ci/kani.sh). Each states,
//! on bounded inputs, a property #322's Lean spec (verification/lean) proves of its model of the
//! same function, and names that theorem: Kani checks it of the Rust itself.
//!
//! The harnesses live next to the code they check (`#[path]` child modules of `manifest`,
//! `subset`, `canon` and `op`, so they reach private functions); this module holds what they share.

/// A string of at most `N` bytes, each one of `alphabet` (ASCII, so every choice is valid UTF-8).
/// Bounded strings over a few interesting characters are what makes the search finite.
pub(crate) fn any_str<const N: usize>(alphabet: &[u8]) -> String {
    let len: usize = kani::any_where(|&l| l <= N);
    let mut s = String::with_capacity(N);
    for i in 0..N {
        let k: usize = kani::any_where(|&k| k < alphabet.len());
        if i < len {
            s.push(char::from(alphabet[k]));
        }
    }
    s
}
