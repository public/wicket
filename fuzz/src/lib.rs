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

// The control/node channel lives in the CLI binary (no library target): its protocol module and the
// modules its messages carry are compiled in here as they are, so the target fuzzes the real code.
#[path = "../../crates/wicket-cli/src/chan.rs"]
#[allow(dead_code, unused_imports)]
pub mod chan;
#[path = "../../crates/wicket-cli/src/health.rs"]
#[allow(dead_code, unused_imports)]
mod health;
#[path = "../../crates/wicket-cli/src/nodesecrets.rs"]
#[allow(dead_code, unused_imports)]
mod nodesecrets;
#[path = "../../crates/wicket-cli/src/oci.rs"]
#[allow(dead_code, unused_imports)]
mod oci;
#[path = "../../crates/wicket-cli/src/registry.rs"]
#[allow(dead_code, unused_imports)]
mod registry;
/// The one function of the CLI's `run` module the channel's modules call.
mod run {
    pub fn check_run_id(id: &str) -> anyhow::Result<()> {
        if id.len() == 30 && id.starts_with("run_") && id[4..].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
            Ok(())
        } else {
            anyhow::bail!("bad run id {id:?}")
        }
    }
}
