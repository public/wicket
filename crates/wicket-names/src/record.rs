//! DNS records as wicket reconciles them.
//!
//! Names are absolute, lower case, without the trailing dot. A record's identity is its name, type
//! and value ([`Record::key`]); its TTL is not part of it, so a TTL change is an update.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The label of a name's owner record: `_wicket.<name>`.
pub const OWNER_LABEL: &str = "_wicket";

/// The record types wicket writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
    Srv,
    Txt,
    /// Any type wicket doesn't write (CNAME, MX, CAA, …), as a zone lists it. wicket never plans
    /// one, and one at a box name makes the name a conflict.
    Other,
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Srv => "SRV",
            RecordType::Txt => "TXT",
            RecordType::Other => "OTHER",
        })
    }
}

/// One record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Record {
    pub name: String,
    pub rtype: RecordType,
    /// A and AAAA: the address, in its canonical text. SRV: `<priority> <weight> <port> <target>`.
    /// TXT: the text, unquoted. Other: whatever the provider shows.
    pub value: String,
    pub ttl: u32,
}

impl Record {
    pub fn a(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
        Record { name: norm_name(name), rtype: RecordType::A, value: ip.to_string(), ttl }
    }

    pub fn aaaa(name: &str, ip: Ipv6Addr, ttl: u32) -> Record {
        Record { name: norm_name(name), rtype: RecordType::Aaaa, value: ip.to_string(), ttl }
    }

    /// `_<service>._tcp.<name>`, priority 0, weight 0, pointing at `<name>` itself.
    pub fn srv(name: &str, service: &str, port: u16, ttl: u32) -> Record {
        let name = norm_name(name);
        Record { name: format!("_{service}._tcp.{name}"), rtype: RecordType::Srv, value: format!("0 0 {port} {name}"), ttl }
    }

    pub fn txt(name: &str, text: &str, ttl: u32) -> Record {
        Record { name: norm_name(name), rtype: RecordType::Txt, value: text.to_string(), ttl }
    }

    /// The record with its name lower-cased and without a trailing dot, and an address in its
    /// canonical text, as a provider's listing may not have them.
    pub fn normalized(&self) -> Record {
        let value = match self.rtype {
            RecordType::A => self.value.trim().parse::<Ipv4Addr>().map(|i| i.to_string()).unwrap_or_else(|_| self.value.clone()),
            RecordType::Aaaa => self.value.trim().parse::<Ipv6Addr>().map(|i| i.to_string()).unwrap_or_else(|_| self.value.clone()),
            _ => self.value.clone(),
        };
        Record { name: norm_name(&self.name), rtype: self.rtype, value, ttl: self.ttl }
    }

    /// Its identity: name, type and value.
    pub fn key(&self) -> (String, RecordType, String) {
        (self.name.clone(), self.rtype, self.value.clone())
    }

    /// The box name the record belongs to: its name with leading `_` labels removed, so
    /// `_wicket.demo.boxes.example.com` (the owner record), `_http._tcp.demo.boxes.example.com` and
    /// `demo.boxes.example.com` all belong to `demo.boxes.example.com`.
    pub fn base(&self) -> &str {
        base_of(&self.name)
    }

    /// Whether this is an owner record (a TXT at `_wicket.<name>`).
    pub fn is_owner_record(&self) -> bool {
        self.rtype == RecordType::Txt && self.name.strip_prefix(OWNER_LABEL).is_some_and(|r| r.starts_with('.'))
    }
}

/// `name` lower-cased, without a trailing dot.
pub fn norm_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// `name` with its leading `_` labels removed.
pub fn base_of(name: &str) -> &str {
    let mut n = name;
    while n.starts_with('_') {
        match n.split_once('.') {
            Some((_, rest)) => n = rest,
            None => break,
        }
    }
    n
}

/// A DNS zone wicket was given (its apex), such as `boxes.example.com`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Zone(String);

impl Zone {
    pub fn new(apex: &str) -> Zone {
        Zone(norm_name(apex))
    }

    pub fn apex(&self) -> &str {
        &self.0
    }

    /// `<label>.<apex>`.
    pub fn name(&self, label: &str) -> String {
        format!("{label}.{}", self.0)
    }

    /// Whether `name` is exactly one label under the apex: the only names wicket publishes.
    pub fn holds_box_name(&self, name: &str) -> bool {
        name.strip_suffix(self.0.as_str()).and_then(|l| l.strip_suffix('.')).is_some_and(|l| !l.is_empty() && !l.contains('.'))
    }
}

/// This installation's owner id: random, made at install, 8–32 characters of `a-z0-9`. It is all
/// an owner record says of the installation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OwnerId(String);

impl OwnerId {
    pub fn parse(s: &str) -> Option<OwnerId> {
        let ok = (8..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        ok.then(|| OwnerId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The owner record for box name `name`, held by grant `grant`.
    pub fn owner_record(&self, name: &str, grant: &str, ttl: u32) -> Record {
        Record::txt(&format!("{OWNER_LABEL}.{name}"), &format!("wicket-owner={};name={grant}", self.0), ttl)
    }

    /// Whether an owner record's text names this installation.
    pub fn is_owner_of(&self, text: &str) -> bool {
        text.split(';').next().and_then(|f| f.strip_prefix("wicket-owner=")).is_some_and(|id| id == self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bases_and_owner_records() {
        let o = OwnerId::parse("a1b2c3d4").unwrap();
        let r = o.owner_record("demo.boxes.example.com", "g1", 60);
        assert_eq!(r.name, "_wicket.demo.boxes.example.com");
        assert_eq!(r.base(), "demo.boxes.example.com");
        assert!(r.is_owner_record());
        assert!(o.is_owner_of(&r.value));
        assert!(!OwnerId::parse("zzzzzzzz").unwrap().is_owner_of(&r.value));
        assert!(!o.is_owner_of("wicket-owner=a1b2c3d4x;name=g1"));
        let s = Record::srv("demo.boxes.example.com", "http", 20001, 60);
        assert_eq!(s.name, "_http._tcp.demo.boxes.example.com");
        assert_eq!(s.base(), "demo.boxes.example.com");
        assert!(!s.is_owner_record());
        assert_eq!(base_of("_x"), "_x");
    }

    #[test]
    fn normalizes_what_providers_list() {
        let r = Record { name: "Demo.Boxes.Example.com.".into(), rtype: RecordType::Aaaa, value: "2001:DB8:0::1".into(), ttl: 60 };
        let n = r.normalized();
        assert_eq!(n.name, "demo.boxes.example.com");
        assert_eq!(n.value, "2001:db8::1");
    }

    #[test]
    fn zones_hold_one_label() {
        let z = Zone::new("Boxes.Example.com.");
        assert!(z.holds_box_name("demo.boxes.example.com"));
        assert!(!z.holds_box_name("boxes.example.com"));
        assert!(!z.holds_box_name("a.demo.boxes.example.com"));
        assert!(!z.holds_box_name("demoboxes.example.com"));
        assert!(!z.holds_box_name("demo.other.com"));
    }

    #[test]
    fn owner_ids() {
        assert!(OwnerId::parse("a1b2c3d4").is_some());
        assert!(OwnerId::parse("short").is_none());
        assert!(OwnerId::parse("UPPERCASE1").is_none());
        assert!(OwnerId::parse("has;semi1").is_none());
    }
}
