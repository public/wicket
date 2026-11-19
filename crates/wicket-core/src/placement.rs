//! What a box asks of the node it goes on (#579): node labels it must match, the node taints it
//! tolerates, what it wants near it or away from it (affinity), and how it ranks against other boxes
//! for room (priority, and whether it may be stopped for a higher one). The scheduler that uses them
//! is `wicket-placement::schedule`.
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
    /// Where it waits for a node, and which boxes it may displace: higher first. A child's is at
    /// most its parent's ([`within`]).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub priority: i32,
    /// It may be stopped to make room for a box of higher priority.
    #[serde(default, skip_serializing_if = "is_false")]
    pub preemptible: bool,
    /// What it wants on its node: a service its zone uses, or a volume it holds.
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "crate::yaml::null_as_default")]
    pub affinity: Vec<Affinity>,
    /// What it wants off its node: another zone's boxes, or one principal's.
    #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "crate::yaml::null_as_default")]
    pub anti_affinity: Vec<AntiAffinity>,
}

fn is_zero(n: &i32) -> bool {
    *n == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// The highest priority, and minus it the lowest.
pub const MAX_PRIORITY: i32 = 1000;

/// One thing a box wants on its node: `{service: npm-cache}` or `{volume: data}`. Preferred (a node
/// with it ranks first) unless `required` (a node without it is out).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Affinity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
}

/// What an affinity term names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Near {
    /// A per-node service whose instance runs on the node.
    Service(String),
    /// A volume the node holds.
    Volume(String),
}

impl Affinity {
    /// What it names (None: not exactly one of `service` and `volume`; [`PlacementSpec::check`]
    /// refuses it).
    pub fn near(&self) -> Option<Near> {
        match (&self.service, &self.volume) {
            (Some(s), None) => Some(Near::Service(s.clone())),
            (None, Some(v)) => Some(Near::Volume(v.clone())),
            _ => None,
        }
    }
}

impl fmt::Display for Near {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Near::Service(s) => write!(f, "service {s}"),
            Near::Volume(v) => write!(f, "volume {v}"),
        }
    }
}

/// One thing a box wants off its node: `{zone: research}` (any box of that zone) or `{principal:
/// spiffe://…/a/<agent>}` (that agent's boxes). Preferred unless `required`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntiAffinity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
}

/// What an anti-affinity term names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Away {
    Zone(String),
    Principal(String),
}

impl AntiAffinity {
    /// What it names (None: not exactly one of `zone` and `principal`).
    pub fn away(&self) -> Option<Away> {
        match (&self.zone, &self.principal) {
            (Some(z), None) => Some(Away::Zone(z.clone())),
            (None, Some(p)) => Some(Away::Principal(p.clone())),
            _ => None,
        }
    }
}

impl fmt::Display for Away {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Away::Zone(z) => write!(f, "zone {z}"),
            Away::Principal(p) => write!(f, "principal {p}"),
        }
    }
}

/// Where a child's placement asks for more than its parent's may (#579 step 4): a higher priority,
/// or not preemptible when its parent is. Each is a reason; none: it's within.
pub fn within(child: &PlacementSpec, parent: &PlacementSpec) -> Vec<String> {
    let mut v = vec![];
    if child.priority > parent.priority {
        v.push(format!("placement.priority {}: above this zone's {}", child.priority, parent.priority));
    }
    if parent.preemptible && !child.preemptible {
        v.push("placement.preemptible false: this zone's boxes may be stopped for higher priorities, so its children's may".into());
    }
    v
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
        if !(-MAX_PRIORITY..=MAX_PRIORITY).contains(&self.priority) {
            return Err(format!("placement.priority {}: from -{MAX_PRIORITY} to {MAX_PRIORITY}", self.priority));
        }
        for a in &self.affinity {
            match a.near() {
                None => return Err("placement.affinity: each names one service or one volume".into()),
                Some(Near::Service(s)) => crate::service::check_name(&s).map_err(|e| format!("placement.affinity: {e}"))?,
                Some(Near::Volume(v)) => check_volume(&v).map_err(|e| format!("placement.affinity: {e}"))?,
            }
        }
        for a in &self.anti_affinity {
            match a.away() {
                None => return Err("placement.anti_affinity: each names one zone or one principal".into()),
                Some(Away::Zone(z)) => {
                    if z.is_empty() || z.len() > 128 || crate::manifest::is_principal_entry(&z) || z.chars().any(char::is_whitespace) {
                        return Err(format!("placement.anti_affinity: {z:?} is not a zone name"));
                    }
                }
                Some(Away::Principal(p)) => {
                    if !p.starts_with("spiffe://") || p.len() > 512 || p.chars().any(char::is_whitespace) {
                        return Err(format!("placement.anti_affinity: {p:?} is not a principal id (spiffe://…)"));
                    }
                }
            }
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

/// A volume's name, as `zone.volumes` names it: `[a-z0-9-]+`.
fn check_volume(v: &str) -> Result<(), String> {
    if !v.is_empty() && v.len() <= 63 && v.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        Ok(())
    } else {
        Err(format!("{v:?} is not a volume name: [a-z0-9-]+"))
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

    #[test]
    fn priorities_and_affinity_are_checked() {
        let y = |s: &str| crate::yaml::from_str::<PlacementSpec>(s);
        let p = y("priority: 10\npreemptible: true\naffinity: [{service: npm-cache}, {volume: data, required: true}]\n\
                   anti_affinity: [{zone: research}, {principal: 'spiffe://w.test/t/t0/z/x/a/b', required: true}]")
        .unwrap();
        assert!(p.check().is_ok(), "{:?}", p.check());
        assert_eq!(p.affinity[0].near(), Some(Near::Service("npm-cache".into())));
        assert_eq!(p.affinity[1].near(), Some(Near::Volume("data".into())));
        assert!(p.affinity[1].required && !p.affinity[0].required);
        assert_eq!(p.anti_affinity[1].away(), Some(Away::Principal("spiffe://w.test/t/t0/z/x/a/b".into())));
        // Unset, they aren't written: a manifest that doesn't use them reads the same as before.
        assert!(PlacementSpec::default().is_default());
        assert_eq!(crate::yaml::to_string(&PlacementSpec { priority: 0, ..Default::default() }).unwrap().trim(), "{}");

        for bad in [
            "priority: 1001",
            "priority: -1001",
            "affinity: [{}]",
            "affinity: [{service: a, volume: b}]",
            "affinity: [{service: Bad}]",
            "affinity: [{volume: 'a b'}]",
            "anti_affinity: [{}]",
            "anti_affinity: [{zone: z, principal: 'spiffe://x'}]",
            "anti_affinity: [{principal: research}]",
            "anti_affinity: [{zone: 'spiffe://x/y'}]",
        ] {
            assert!(y(bad).map_err(|e| e.to_string()).and_then(|p| p.check()).is_err(), "{bad}");
        }
        assert!(y("affinity: [{node: x}]").is_err(), "unknown fields are refused");
    }

    #[test]
    fn a_child_never_ranks_above_its_parent() {
        let spec = |priority, preemptible| PlacementSpec { priority, preemptible, ..Default::default() };
        assert!(within(&spec(5, false), &spec(5, false)).is_empty());
        assert!(within(&spec(-3, true), &spec(5, false)).is_empty(), "lower, and preemptible: narrower");
        assert_eq!(within(&spec(6, false), &spec(5, false)), ["placement.priority 6: above this zone's 5"]);
        assert_eq!(within(&spec(5, false), &spec(5, true)).len(), 1, "not preemptible under a preemptible parent");
        assert_eq!(within(&spec(9, false), &spec(5, true)).len(), 2, "every reason");
        // Exhaustively over a small range: within() holds exactly when both hold.
        for (cp, pp) in (-3..=3).flat_map(|a| (-3..=3).map(move |b| (a, b))) {
            for (ce, pe) in [(false, false), (false, true), (true, false), (true, true)] {
                let ok = within(&spec(cp, ce), &spec(pp, pe)).is_empty();
                assert_eq!(ok, cp <= pp && (ce || !pe), "{cp} {ce} under {pp} {pe}");
            }
        }
    }
}
