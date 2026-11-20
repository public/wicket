//! The installation's `names:` settings (`wicket.yaml`, #575 design: "What the operator sets
//! once"): installation decisions, not a manifest's. Read when a run starts and when a human
//! decides, and checked as a whole ([`NamesConfig::check`]) so a setting that can't work stops the
//! run instead of being ignored.

use crate::label::{check_shape, Rules};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::ops::RangeInclusive;

/// The lowest and highest record TTL an operator may set (seconds).
pub const TTL_RANGE: RangeInclusive<u32> = 30..=3600;
/// The longest DNS name.
const MAX_NAME: usize = 253;

/// `names:` in `wicket.yaml`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamesConfig {
    #[serde(default)]
    pub internal: InternalConfig,
    /// Public names. Absent: this installation publishes none, and asks for them are refused.
    #[serde(default)]
    pub public: Option<PublicConfig>,
}

/// `names.internal`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalConfig {
    /// The most live internal names one workload (an agent's principal) holds at once.
    #[serde(default = "three")]
    pub per_workload: usize,
}

impl Default for InternalConfig {
    fn default() -> Self {
        InternalConfig { per_workload: three() }
    }
}

fn three() -> usize {
    3
}
fn one() -> usize {
    1
}
fn sixty() -> u32 {
    60
}
fn default_ports() -> PortRange {
    PortRange(20000, 20999)
}

/// Which DNS provider publishes the boxes zone's records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    /// Publishes nothing: each reconcile's plan is only recorded (`name.plan`, `applied: false`).
    Noop,
}

impl ProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Noop => "noop",
        }
    }
}

/// `names.public`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicConfig {
    /// `noop` for now; `vultr` and `rfc2136` come with #575 step 5.
    pub provider: ProviderKind,
    /// The boxes domain: public names are `<label>.<zone>`. A delegated subzone is recommended, so
    /// the provider's credential touches nothing else.
    pub zone: String,
    /// The vault secret holding the provider's credential: its name, never its value. The `noop`
    /// provider needs none.
    #[serde(default)]
    pub credential: Option<String>,
    /// This installation's owner id, written in its owner records (`_wicket.<name>` TXT): random,
    /// made once (for example `openssl rand -hex 8`), with no host name or other detail in it.
    pub owner: String,
    /// The records' TTL, seconds ([`TTL_RANGE`]).
    #[serde(default = "sixty")]
    pub ttl: u32,
    /// The most live public names one workload holds at once.
    #[serde(default = "one")]
    pub per_workload: usize,
    /// Labels reserved besides wicket's own (`wicket_names::label::RESERVED`).
    #[serde(default)]
    pub reserved: Vec<String>,
    /// The console's host name: its first label is reserved too, so no box gets a lookalike of it.
    #[serde(default)]
    pub console_host: Option<String>,
    /// Whether `xn--` labels are allowed.
    #[serde(default)]
    pub allow_idn: bool,
    /// The node labels a node needs to publish public ports.
    #[serde(default)]
    pub nodes: BTreeMap<String, String>,
    /// The host ports wicket allocates on each node, `low-high`.
    #[serde(default = "default_ports")]
    pub ports: PortRange,
}

/// An inclusive range of host ports, written `low-high`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange(pub u16, pub u16);

impl PortRange {
    pub fn range(self) -> RangeInclusive<u16> {
        self.0..=self.1
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bad = || serde::de::Error::custom(format!("ports: {s:?} is not low-high (for example 20000-20999)"));
        let (a, b) = s.split_once('-').ok_or_else(bad)?;
        let (a, b) = (a.trim().parse::<u16>().map_err(|_| bad())?, b.trim().parse::<u16>().map_err(|_| bad())?);
        Ok(PortRange(a, b))
    }
}

impl NamesConfig {
    /// Every setting that can't work, as one message: a run doesn't start on them.
    pub fn check(&self) -> Result<(), String> {
        let mut bad = vec![];
        if self.internal.per_workload == 0 {
            bad.push("names.internal.per_workload must be at least 1".to_string());
        }
        if let Some(p) = &self.public {
            bad.extend(p.problems());
        }
        match bad.is_empty() {
            true => Ok(()),
            false => Err(bad.join("; ")),
        }
    }

    /// The rules a public label meets here, or None if this installation publishes no names.
    pub fn public_rules(&self) -> Option<Rules> {
        self.public.as_ref().map(PublicConfig::rules)
    }
}

impl PublicConfig {
    /// The rules a label meets: wicket's reserved labels, the operator's, and the console's first
    /// label.
    pub fn rules(&self) -> Rules {
        let mut reserved = self.reserved.clone();
        if let Some(host) = self.console_host.as_deref().map(|h| h.trim_end_matches('.').to_ascii_lowercase()) {
            if let Some(first) = host.split('.').next() {
                reserved.push(first.to_string());
            }
            // A console host under the boxes zone (`console.ops.<zone>`): the label directly under
            // the zone too, or a box could take `ops.<zone>` (#716 review, F9).
            if let Some(under) = host.strip_suffix(&format!(".{}", self.domain())).and_then(|rest| rest.rsplit('.').next()) {
                reserved.push(under.to_string());
            }
        }
        Rules { reserved, allow_idn: self.allow_idn }
    }

    /// The zone as names are written under it: lower case, no trailing dot.
    pub fn domain(&self) -> String {
        self.zone.trim_end_matches('.').to_ascii_lowercase()
    }

    /// `label`'s public name here.
    pub fn fqdn(&self, label: &str) -> String {
        format!("{label}.{}", self.domain())
    }

    fn problems(&self) -> Vec<String> {
        let mut bad = vec![];
        let d = self.domain();
        if d.is_empty() || d.split('.').count() < 2 || d.split('.').any(|p| check_shape(p, true).is_err()) {
            bad.push(format!("names.public.zone {:?} is not a DNS domain of two or more labels", self.zone));
        } else if d.len() + 1 + crate::label::MAX_LABEL > MAX_NAME {
            bad.push(format!("names.public.zone {:?} is too long: a 63-character label under it would pass 253", self.zone));
        }
        if d == crate::label::INTERNAL_DOMAIN || d.ends_with(&format!(".{}", crate::label::INTERNAL_DOMAIN)) {
            bad.push(format!("names.public.zone can't be under {}", crate::label::INTERNAL_DOMAIN));
        }
        if !(8..=32).contains(&self.owner.len()) || !self.owner.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
            bad.push("names.public.owner must be 8 to 32 lower-case hex characters (random, made once: openssl rand -hex 8)".into());
        }
        if !TTL_RANGE.contains(&self.ttl) {
            bad.push(format!("names.public.ttl must be {}-{} seconds, not {}", TTL_RANGE.start(), TTL_RANGE.end(), self.ttl));
        }
        if self.per_workload == 0 {
            bad.push("names.public.per_workload must be at least 1".into());
        }
        for r in &self.reserved {
            if check_shape(&r.to_ascii_lowercase(), true).is_err() {
                bad.push(format!("names.public.reserved: {r:?} is not a DNS label"));
            }
        }
        if let Some(h) = &self.console_host {
            let h = h.trim_end_matches('.');
            if h.is_empty() || h.split('.').any(|p| check_shape(&p.to_ascii_lowercase(), true).is_err()) {
                bad.push(format!("names.public.console_host {h:?} is not a host name"));
            }
        }
        let PortRange(lo, hi) = self.ports;
        if lo < 1024 || lo > hi {
            bad.push(format!("names.public.ports {lo}-{hi}: a range of ports from 1024 up, low first"));
        }
        if let (ProviderKind::Noop, Some(_)) = (self.provider, &self.credential) {
            bad.push("names.public.credential: the noop provider takes none".into());
        }
        bad
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The section as JSON, which the YAML it is written in maps to one to one (this crate has no
    /// YAML parser).
    fn parse(json: &str) -> NamesConfig {
        serde_json::from_str(json).unwrap()
    }

    const OK: &str = r#"{ "public": { "provider": "noop", "zone": "boxes.example.com", "owner": "a1b2c3d4" } }"#;

    #[test]
    fn defaults_and_a_minimal_public_section() {
        let c = NamesConfig::default();
        assert_eq!((c.internal.per_workload, c.public.is_none()), (3, true));
        assert_eq!(c.check(), Ok(()));
        assert!(c.public_rules().is_none());
        let c = parse(OK);
        assert_eq!(c.check(), Ok(()));
        let p = c.public.as_ref().unwrap();
        assert_eq!((p.ttl, p.per_workload, p.ports, p.provider.as_str()), (60, 1, PortRange(20000, 20999), "noop"));
        assert_eq!(p.fqdn("demo"), "demo.boxes.example.com");
    }

    #[test]
    fn the_console_label_and_the_operators_list_are_reserved() {
        let c = parse(
            r#"{ "public": { "provider": "noop", "zone": "Boxes.Example.com.", "owner": "a1b2c3d4",
                 "reserved": ["status"], "console_host": "Ops.example.com" } }"#,
        );
        assert_eq!(c.check(), Ok(()));
        let r = c.public_rules().unwrap();
        assert!(crate::check_label("status", &r).is_err());
        assert!(crate::check_label("ops", &r).is_err());
        assert!(crate::check_label("0ps", &r).is_err(), "a lookalike of the console's label");
        assert!(crate::check_label("demo", &r).is_ok());
        assert_eq!(c.public.unwrap().domain(), "boxes.example.com");
        // A console deep under the boxes zone: the label under the zone is the console's too.
        let c = parse(
            r#"{ "public": { "provider": "noop", "zone": "boxes.example.com", "owner": "a1b2c3d4",
                 "console_host": "console.ops.boxes.example.com" } }"#,
        );
        let r = c.public_rules().unwrap();
        assert!(crate::check_label("ops", &r).is_err());
        assert!(crate::check_label("0ps", &r).is_err());
        assert!(crate::check_label("demo", &r).is_ok());
    }

    #[test]
    fn settings_that_cant_work_are_refused() {
        for (field, value, says) in [
            ("zone", r#""com""#, "two or more labels"),
            ("zone", r#""a..b""#, "not a DNS domain"),
            ("zone", r#""x.wicket.internal""#, "wicket.internal"),
            ("owner", r#""web-01.example""#, "hex"),
            ("owner", r#""abc""#, "hex"),
            ("ttl", "5", "30-3600"),
            ("per_workload", "0", "at least 1"),
            ("reserved", r#"["a.b"]"#, "not a DNS label"),
            ("console_host", r#""bad host""#, "not a host name"),
            ("ports", r#""80-443""#, "from 1024"),
            ("ports", r#""30000-20000""#, "low first"),
            ("credential", r#""dns-boxes""#, "takes none"),
        ] {
            let mut v: serde_json::Value = serde_json::from_str(OK).unwrap();
            v["public"][field] = serde_json::from_str(value).unwrap();
            let c: NamesConfig = serde_json::from_value(v).unwrap();
            let e = c.check().unwrap_err();
            assert!(e.contains(says), "{field}={value}: {e}");
        }
        assert!(serde_json::from_str::<NamesConfig>(
            r#"{ "public": { "provider": "noop", "zone": "b.example", "owner": "a1b2c3d4", "ports": "x" } }"#
        )
        .is_err());
        assert!(serde_json::from_str::<NamesConfig>(
            r#"{ "public": { "provider": "route53", "zone": "b.example", "owner": "a1b2c3d4" } }"#
        )
        .is_err());
        assert!(serde_json::from_str::<NamesConfig>(r#"{ "internal": { "per_workloads": 3 } }"#).is_err(), "unknown keys");
        let zero: NamesConfig = serde_json::from_str(r#"{ "internal": { "per_workload": 0 } }"#).unwrap();
        assert!(zero.check().is_err());
    }
}
