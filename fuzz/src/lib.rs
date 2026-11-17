//! wicket's fuzz harnesses (#323): one module per target, each a `run(&[u8])` that panics on a
//! finding. The `fuzz_targets/` binaries are one line each; `tests/corpus.rs` replays the seed
//! corpora and every past finding (`regressions/<target>/`) through the same functions on stable.
#![allow(clippy::new_without_default)]

pub mod canon;
pub mod egress;
pub mod feed;
pub mod gateway;
pub mod git;
pub mod manifest;
pub mod node_chan;
pub mod store;
pub mod token;

pub(crate) mod util;

// The control/node channel, as the CLI uses it (#219): its own crate.
pub use wicket_chan::chan;
