//! YAML for every file and manifest wicket reads and writes, through one parser configured for
//! untrusted input (#326: serde_yaml's unsafe-libyaml is unmaintained, RUSTSEC-2024-0449).
//!
//! The control host parses YAML that agents influence (a spawned child's manifest, written from
//! the zone its parent asked for and re-read at start or adoption), so the parser is attack
//! surface. This is serde-saphyr: pure safe Rust (`forbid(unsafe_code)`), panic-free by design,
//! with an explicit budget. What it allows here, beyond the library's defaults:
//!
//! - at most [`MAX_INPUT`] bytes (a manifest or config file is a few KiB);
//! - one document, at most 64 levels deep, [`MAX_NODES`] nodes and [`MAX_EVENTS`] parser events;
//! - few anchors and aliases ([`MAX_ALIASES`]), so a billion-laughs expansion fails fast;
//! - a duplicate key is an error, as it was; no includes, no property interpolation (those features
//!   aren't compiled in).
//!
//! Untyped YAML (`serde_json::Value`) is read the same way; there is no YAML value type of its own.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// The most bytes of YAML read at once.
pub const MAX_INPUT: usize = 4 << 20;
/// The most parser events (every scalar, mapping and sequence start and end).
pub const MAX_EVENTS: usize = 200_000;
/// The most nodes (scalars, mappings and sequences).
pub const MAX_NODES: usize = 100_000;
/// The most anchors, and the most aliases.
pub const MAX_ALIASES: usize = 1_000;

/// Why YAML couldn't be read or written. Its message names the line and column, as the parser
/// gives them.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Parse(String),
    #[error("YAML input is {0} bytes; at most {MAX_INPUT} are read")]
    TooLarge(usize),
    #[error("{0}")]
    Write(String),
}

fn options() -> serde_saphyr::Options {
    let mut b = serde_saphyr::Budget::default();
    b.max_events = MAX_EVENTS;
    b.max_nodes = MAX_NODES;
    b.max_aliases = MAX_ALIASES;
    b.max_anchors = MAX_ALIASES;
    b.max_documents = 1;
    b.max_depth = 64;
    b.max_total_scalar_bytes = MAX_INPUT;
    b.max_merge_keys = 100;
    let mut o = serde_saphyr::Options::default();
    o.budget = Some(b);
    o.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::Error;
    o
}

/// Reads `s` as a `T`, within the limits above.
pub fn from_str<T: DeserializeOwned>(s: &str) -> Result<T, Error> {
    if s.len() > MAX_INPUT {
        return Err(Error::TooLarge(s.len()));
    }
    serde_saphyr::from_str_with_options(s, options()).map_err(|e| Error::Parse(e.to_string()))
}

/// Writes `v` as YAML.
pub fn to_string<T: Serialize>(v: &T) -> Result<String, Error> {
    serde_saphyr::to_string(v).map_err(|e| Error::Write(e.to_string()))
}

/// For a defaulted list or map field: an empty YAML key (`reach:` with nothing after it, or only
/// commented-out entries) is the field's default, as serde_yaml read it, not an error.
pub fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_shapes_are_refused_quickly() {
        // A billion laughs: nested aliases.
        let mut lol = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            lol.push_str(&format!(
                "{c}: &{c} [*{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}, *{p}]\n",
                c = (b'a' + i) as char,
                p = (b'a' + i - 1) as char
            ));
        }
        let t = std::time::Instant::now();
        assert!(from_str::<serde_json::Value>(&lol).is_err());
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "refused quickly: {:?}", t.elapsed());
        // Deep nesting, a second document, a duplicate key, too much input.
        assert!(from_str::<serde_json::Value>(&format!("{}x{}", "[".repeat(200), "]".repeat(200))).is_err());
        assert!(from_str::<serde_json::Value>("a: 1\n---\nb: 2\n").is_err());
        assert!(from_str::<serde_json::Value>("a: 1\na: 2\n").is_err());
        assert!(matches!(from_str::<serde_json::Value>(&"a".repeat(MAX_INPUT + 1)), Err(Error::TooLarge(_))));
        // Ordinary YAML reads, and writes back.
        let v: serde_json::Value = from_str("name: z\nreach: [{host: a.example, paths: [\"/x\"]}]\n").unwrap();
        assert_eq!(v["reach"][0]["host"], "a.example");
        assert_eq!(from_str::<serde_json::Value>(&to_string(&v).unwrap()).unwrap(), v);
        // An empty list key is the empty list (serde_yaml's reading, kept).
        let z: crate::ZoneSpec = from_str("name: z\nreach:\nforbid:\n  # none yet\n").unwrap();
        assert!(z.reach.is_empty() && z.forbid.is_empty());
    }
}
