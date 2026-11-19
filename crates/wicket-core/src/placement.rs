//! What a box asks of the node it goes on (#579): node labels it must match, and the node taints it
//! tolerates. The scheduler that uses them is `wicket-placement::schedule`.
//!
//! A node's operator labels it (`wicket node set <node> --label gpu=a100`) and taints it
//! (`--taint dedicated=ci`). A box goes on a node only if the node has every label its
//! `placement.node_selector` names, with the value named, and the box tolerates every taint the node
//! has. A taint keeps off every box that doesn't say otherwise: a node kept for one kind of work.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The longest label key or value.
pub const MAX_LEN: usize = 63;

/// A manifest's `placement:`. Written out only when it says something, so a manifest that doesn't
/// use it reads the same to a node that doesn't know it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementSpec {
    /// Labels the node must have, with these values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", deserialize_with = "crate::yaml::null_as_default")]
    pub node_selector: BTreeMap<String, String>,
    /// Node taints the box may go on despite: `key` (any value) or `key=value`.
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "crate::yaml::null_as_default")]
    pub tolerations: Vec<String>,
}

impl PlacementSpec {
    pub fn is_default(&self) -> bool {
        self == &PlacementSpec::default()
    }

    /// Every key and value well-formed.
    pub fn check(&self) -> Result<(), String> {
        for (k, v) in &self.node_selector {
            check_key(k).map_err(|e| format!("placement.node_selector: {e}"))?;
            check_value(v).map_err(|e| format!("placement.node_selector.{k}: {e}"))?;
        }
        for t in &self.tolerations {
            Taint::parse(t).map_err(|e| format!("placement.tolerations: {e}"))?;
        }
        Ok(())
    }

    /// The tolerations, parsed (those that don't parse are left out: [`Self::check`] refuses them).
    pub fn tolerations(&self) -> Vec<Taint> {
        self.tolerations.iter().filter_map(|t| Taint::parse(t).ok()).collect()
    }
}

/// A node taint, or a box's toleration of one: a key, and a value or none. A toleration without a
/// value tolerates the key's taints whatever their value; one with a value only that value's.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Taint {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl Taint {
    /// `key` or `key=value`.
    pub fn parse(s: &str) -> Result<Taint, String> {
        let (k, v) = match s.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (s, None),
        };
        check_key(k)?;
        if let Some(v) = v {
            check_value(v)?;
        }
        Ok(Taint { key: k.to_string(), value: v.map(str::to_string) })
    }

    /// Whether this toleration lets a box onto a node with `taint`.
    pub fn tolerates(&self, taint: &Taint) -> bool {
        self.key == taint.key && (self.value.is_none() || self.value == taint.value)
    }
}

impl fmt::Display for Taint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(v) => write!(f, "{}={v}", self.key),
            None => f.write_str(&self.key),
        }
    }
}

/// A label or taint key: lowercase letters, digits, and `.`, `_`, `-`, `/` inside, at most 63.
pub fn check_key(k: &str) -> Result<(), String> {
    let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let ok = !k.is_empty()
        && k.len() <= MAX_LEN
        && k.starts_with(edge)
        && k.ends_with(edge)
        && k.chars().all(|c| edge(c) || matches!(c, '.' | '_' | '-' | '/'));
    if ok {
        Ok(())
    } else {
        Err(format!("{k:?} is not a key: lowercase letters and digits, with . _ - / inside, at most {MAX_LEN}"))
    }
}

/// A label or taint value: letters, digits, `.`, `_`, `-`, at most 63 (empty allowed).
pub fn check_value(v: &str) -> Result<(), String> {
    if v.len() <= MAX_LEN && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        Ok(())
    } else {
        Err(format!("{v:?} is not a value: letters, digits, . _ -, at most {MAX_LEN}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taints_and_tolerations() {
        let any = Taint::parse("dedicated").unwrap();
        let ci = Taint::parse("dedicated=ci").unwrap();
        let gpu = Taint::parse("dedicated=gpu").unwrap();
        assert!(any.tolerates(&ci) && any.tolerates(&gpu) && any.tolerates(&any), "no value: any value");
        assert!(ci.tolerates(&ci) && !ci.tolerates(&gpu), "a value: only that one");
        assert!(!ci.tolerates(&any), "a valued toleration doesn't tolerate a bare taint");
        assert!(!Taint::parse("other").unwrap().tolerates(&ci));
        assert_eq!(ci.to_string(), "dedicated=ci");
        assert_eq!(Taint::parse("k=").unwrap(), Taint { key: "k".into(), value: Some(String::new()) });
        for bad in ["", "=v", "Key", "-k", "k-", "k=a b", "k=a=b", &"k".repeat(64)] {
            assert!(Taint::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Taint::parse("wicket.dev/pool").is_ok());
    }

    #[test]
    fn a_placement_spec_is_checked() {
        let mut p = PlacementSpec::default();
        assert!(p.is_default() && p.check().is_ok());
        p.node_selector.insert("gpu".into(), "a100".into());
        p.tolerations.push("dedicated=ci".into());
        assert!(p.check().is_ok());
        assert_eq!(p.tolerations(), vec![Taint { key: "dedicated".into(), value: Some("ci".into()) }]);
        p.node_selector.insert("Bad".into(), "x".into());
        assert!(p.check().unwrap_err().contains("node_selector"));
    }
}
