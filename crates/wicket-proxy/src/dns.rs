//! wicket DNS for a box (#92). The box's resolver is wicket.internal:53, relayed by `wicket-fwd`
//! to the run's [`crate::h3`] socket; wicket answers every query itself and never asks anyone else,
//! so a lookup can't carry data out of the box.
//!
//! - A host the zone can reach resolves to a **synthetic address** in 198.19.0.0/16, one per host,
//!   stable for the run. [`Names`] maps it back: QUIC to that address is terminated as that host.
//! - A host the zone hides or forbids is **NXDOMAIN**, so it doesn't exist as far as the box can tell.
//! - AAAA for a reachable host is NOERROR with no answer (NODATA): NXDOMAIN there would make
//!   resolvers drop the A answer too. Other types are NODATA as well.
//! - HTTPS (type 65) answers `1 . alpn="h3" ipv4hint=<address>`, so clients that read it (browsers)
//!   go straight to HTTP/3.
//!
//! TCP (the CONNECT proxy) doesn't use these addresses: proxied clients send the host name.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// The first address handed out; 198.19.0.0/24 is kept for wicket (198.19.0.1 is the address that
/// makes the whole /16 local on `lo`).
const FIRST: u32 = u32::from_be_bytes([198, 19, 1, 0]);
const LAST: u32 = u32::from_be_bytes([198, 19, 255, 254]);
/// Answers' TTL. Mappings never change within a run, so this only bounds a client's cache.
pub const TTL: u32 = 300;

/// Is `ip` in the synthetic range (whether or not it has been handed out)?
pub fn is_synthetic(ip: Ipv4Addr) -> bool {
    (FIRST..=LAST).contains(&u32::from(ip))
}

/// The run's host ↔ synthetic address map.
#[derive(Default)]
pub struct Names {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    by_name: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
    next: u32,
    /// Hidden names already reported (each is audited once).
    refused: HashSet<String>,
}

/// What an answer did, for the audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answered {
    /// A reachable host; `fresh` when its address was handed out by this query.
    Resolved { name: String, ip: Ipv4Addr, fresh: bool },
    /// NXDOMAIN; `first` the first time this name was refused.
    Refused { name: String, first: bool },
}

impl Names {
    pub fn new() -> Names {
        Names::default()
    }

    /// The address for `name` (lowercase, no trailing dot), handing one out if needed. None once
    /// the range is exhausted (65,000 hosts in one run): refuse rather than reuse a live mapping.
    pub fn mint(&self, name: &str) -> Option<(Ipv4Addr, bool)> {
        let mut g = self.inner.lock().expect("names");
        if let Some(ip) = g.by_name.get(name) {
            return Some((*ip, false));
        }
        if g.next == 0 {
            g.next = FIRST;
        }
        if g.next > LAST {
            return None;
        }
        let ip = Ipv4Addr::from(g.next);
        g.next += 1;
        g.by_name.insert(name.to_string(), ip);
        g.by_ip.insert(ip, name.to_string());
        Some((ip, true))
    }

    /// The host a synthetic address was handed out for.
    pub fn name_of(&self, ip: Ipv4Addr) -> Option<String> {
        self.inner.lock().expect("names").by_ip.get(&ip).cloned()
    }

    fn refused_first(&self, name: &str) -> bool {
        self.inner.lock().expect("names").refused.insert(name.to_string())
    }
}

const T_A: u16 = 1;
const T_AAAA: u16 = 28;
const T_HTTPS: u16 = 65;

/// A normalised query name: lowercase, no trailing dot, and only what a host name can be.
fn host_name(labels: &[String]) -> Option<String> {
    let name = labels.join(".").to_ascii_lowercase();
    let ok = !name.is_empty()
        && name.len() <= 253
        && labels.iter().all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    ok.then_some(name)
}

/// Answers one DNS query (`reachable` says whether the zone can reach a host). None for anything
/// that isn't a well-formed single-question query: it is dropped.
pub fn answer(names: &Names, q: &[u8], https_records: bool, reachable: impl Fn(&str) -> bool) -> Option<(Vec<u8>, Answered)> {
    if q.len() < 12 || q[2] & 0x80 != 0 || q[2] & 0x78 != 0 {
        return None; // a response, or not a standard query
    }
    if u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let l = *q.get(i)? as usize;
        i += 1;
        if l == 0 {
            break;
        }
        if l > 63 || labels.len() > 127 {
            return None;
        }
        labels.push(String::from_utf8(q.get(i..i + l)?.to_vec()).ok()?);
        i += l;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    let qend = i + 4;
    q.get(..qend)?;
    let name = host_name(&labels);
    let resolved = name.as_deref().filter(|n| reachable(n)).and_then(|n| names.mint(n));
    let display = name.clone().unwrap_or_else(|| labels.join("."));
    let mut r = Vec::with_capacity(qend + 64);
    r.extend_from_slice(&q[0..2]); // id
    r.push(0x84 | (q[2] & 0x01)); // QR, AA; RD copied
    r.push(0x80 | if resolved.is_none() { 3 } else { 0 }); // RA; NXDOMAIN or NOERROR
    r.extend_from_slice(&[0, 1]); // QDCOUNT
    let mut ans: Vec<Vec<u8>> = Vec::new();
    if let Some((ip, _)) = resolved {
        match qtype {
            T_A => ans.push(rr(T_A, &ip.octets())),
            T_HTTPS if https_records => {
                let mut d = vec![0, 1, 0]; // SvcPriority 1, TargetName "." (this name)
                d.extend_from_slice(&[0, 1, 0, 3, 2, b'h', b'3']); // alpn="h3"
                d.extend_from_slice(&[0, 4, 0, 4]); // ipv4hint
                d.extend_from_slice(&ip.octets());
                ans.push(rr(T_HTTPS, &d));
            }
            T_AAAA => {} // NODATA: the box is IPv4 only
            _ => {}      // NODATA
        }
    }
    r.extend_from_slice(&(ans.len() as u16).to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
    r.extend_from_slice(&q[12..qend]);
    for a in ans {
        r.extend_from_slice(&a);
    }
    let what = match resolved {
        Some((ip, fresh)) => Answered::Resolved { name: display, ip, fresh },
        None => {
            let first = names.refused_first(&display);
            Answered::Refused { name: display, first }
        }
    };
    Some((r, what))
}

fn rr(t: u16, data: &[u8]) -> Vec<u8> {
    let mut v = vec![0xC0, 0x0C]; // the question's name
    v.extend_from_slice(&t.to_be_bytes());
    v.extend_from_slice(&[0, 1]); // IN
    v.extend_from_slice(&TTL.to_be_bytes());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn query(name: &str, t: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&t.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    fn reach(h: &str) -> bool {
        h.ends_with(".test") && h != "hidden.test"
    }

    #[test]
    fn reachable_hosts_get_stable_synthetic_addresses() {
        let n = Names::new();
        let (a, what) = answer(&n, &query("H3.Test", T_A), true, reach).unwrap();
        assert_eq!(&a[..2], &[0x12, 0x34]);
        assert_eq!(a[3] & 0x0f, 0, "NOERROR");
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1, "one answer");
        assert_eq!(&a[a.len() - 4..], &[198, 19, 1, 0]);
        assert_eq!(what, Answered::Resolved { name: "h3.test".into(), ip: Ipv4Addr::new(198, 19, 1, 0), fresh: true });
        let (_, again) = answer(&n, &query("h3.test", T_A), true, reach).unwrap();
        assert!(matches!(again, Answered::Resolved { fresh: false, .. }));
        let (b, _) = answer(&n, &query("other.test", T_A), true, reach).unwrap();
        assert_eq!(&b[b.len() - 4..], &[198, 19, 1, 1]);
        assert_eq!(n.name_of(Ipv4Addr::new(198, 19, 1, 0)).as_deref(), Some("h3.test"));
        assert!(is_synthetic(Ipv4Addr::new(198, 19, 1, 0)) && !is_synthetic(Ipv4Addr::new(198, 19, 0, 1)));
    }

    #[test]
    fn hidden_hosts_are_nxdomain_and_aaaa_is_nodata() {
        let n = Names::new();
        let (b, what) = answer(&n, &query("hidden.test", T_A), true, reach).unwrap();
        assert_eq!(b[3] & 0x0f, 3, "NXDOMAIN");
        assert_eq!(what, Answered::Refused { name: "hidden.test".into(), first: true });
        assert!(matches!(answer(&n, &query("hidden.test", T_AAAA), true, reach).unwrap().1, Answered::Refused { first: false, .. }));
        assert!(n.name_of(Ipv4Addr::new(198, 19, 1, 0)).is_none(), "nothing was handed out");
        let (c, _) = answer(&n, &query("h3.test", T_AAAA), true, reach).unwrap();
        assert_eq!((c[3] & 0x0f, c[7]), (0, 0), "NOERROR, no answers");
        // Not a host name at all: refused too.
        assert_eq!(answer(&n, &query("a b.test", T_A), true, reach).unwrap().0[3] & 0x0f, 3);
    }

    #[test]
    fn https_records_carry_alpn_h3_and_the_address() {
        let n = Names::new();
        let (r, _) = answer(&n, &query("h3.test", T_HTTPS), true, reach).unwrap();
        let q = query("h3.test", T_HTTPS);
        let rd = &r[q.len()..];
        assert_eq!(u16::from_be_bytes([rd[2], rd[3]]), T_HTTPS);
        let data = &rd[12..];
        assert_eq!(&data[..3], &[0, 1, 0]);
        assert_eq!(&data[7..10], &[2, b'h', b'3']);
        assert_eq!(&data[data.len() - 4..], &[198, 19, 1, 0]);
        let (off, _) = answer(&n, &query("h3.test", T_HTTPS), false, reach).unwrap();
        assert_eq!(off[7], 0, "no HTTPS answer when they're off");
    }

    #[test]
    fn garbage_is_dropped() {
        let n = Names::new();
        assert!(answer(&n, &[0; 5], true, reach).is_none());
        let mut resp = query("h3.test", T_A);
        resp[2] |= 0x80;
        assert!(answer(&n, &resp, true, reach).is_none());
        let mut two = query("h3.test", T_A);
        two[5] = 2;
        assert!(answer(&n, &two, true, reach).is_none());
        let q = query("h3.test", T_A);
        assert!(answer(&n, &q[..q.len() - 1], true, reach).is_none());
    }
}
