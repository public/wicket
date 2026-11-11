//! Experiment #60: a signed snapshot-and-delta policy feed with a TUF-style freshness statement,
//! and a node that fails narrow when the control plane goes away.

pub mod cp;
pub mod feed;
pub mod node;

/// `--key value` arguments.
pub fn arg(args: &[String], k: &str, default: &str) -> String {
    args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| default.to_string())
}
