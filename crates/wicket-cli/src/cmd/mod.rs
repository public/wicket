//! `wicket`'s commands, one module per group (#220); `main.rs` parses and dispatches.

pub mod approve;
pub mod audit;
pub mod dev;
pub mod identity;
pub mod image;
pub mod itself;
pub mod node;
pub mod operator;
pub mod policy;
pub mod run;
pub mod secret;
pub mod service;
pub mod standing;
pub mod trigger;
pub mod zone;

/// What `--json` prints: one pretty-printed document on stdout, and nothing else there. A list is
/// an array (`[]` when empty); its objects' fields are those docs/reference/cli.md lists, and a new
/// field may be added but none is renamed or removed (#574).
pub fn print_json(v: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

/// The fields of `v`'s objects (an array's first, or `v` itself), sorted: what the shape tests
/// compare with the documented list.
#[cfg(test)]
pub fn keys(v: &serde_json::Value) -> Vec<String> {
    let o = v.as_array().and_then(|a| a.first()).unwrap_or(v);
    let mut k: Vec<String> = o.as_object().expect("an object").keys().cloned().collect();
    k.sort();
    k
}

/// A ledger in a directory of its own, for the `--json` tests.
#[cfg(test)]
pub fn test_ledger(tag: &str) -> (std::path::PathBuf, wicket_store::Ledger) {
    let d = std::env::temp_dir().join(format!("wicket-json-{tag}-{}", wicket_core::new_ulid()));
    std::fs::create_dir_all(&d).unwrap();
    let l = wicket_store::Ledger::open(&d.join("ledger.db")).unwrap();
    (d, l)
}

#[cfg(test)]
mod json_tests;
