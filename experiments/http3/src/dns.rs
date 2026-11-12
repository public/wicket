//! wicket DNS for the box: an allowed name gets one synthetic address in 198.19.0.0/16 (stable for
//! the run, mapped back by the terminator); a name the zone hides or forbids is NXDOMAIN. AAAA for an
//! allowed name is NOERROR with no answer (NODATA): NXDOMAIN there would make resolvers drop the A
//! answer too. HTTPS (type 65) answers `1 . alpn=h3 ipv4hint=<synthetic>`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

pub struct Names {
    inner: Mutex<Inner>,
    allow: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

struct Inner {
    by_name: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
    next: u32,
}

/// First synthetic address handed out; 198.19.0.0/24 is kept for wicket's own use (198.19.0.1 is
/// the address that makes the whole /16 local on `lo`).
const FIRST: u32 = u32::from_be_bytes([198, 19, 1, 0]);
const LAST: u32 = u32::from_be_bytes([198, 19, 255, 254]);
pub const TTL: u32 = 300;

impl Names {
    pub fn new(allow: Box<dyn Fn(&str) -> bool + Send + Sync>) -> Names {
        Names { inner: Mutex::new(Inner { by_name: HashMap::new(), by_ip: HashMap::new(), next: FIRST }), allow }
    }

    pub fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if !(self.allow)(&name) {
            return None;
        }
        let mut g = self.inner.lock().unwrap();
        if let Some(ip) = g.by_name.get(&name) {
            return Some(*ip);
        }
        if g.next > LAST {
            return None; // 65k names in one run: refuse rather than reuse a live mapping
        }
        let ip = Ipv4Addr::from(g.next);
        g.next += 1;
        g.by_name.insert(name.clone(), ip);
        g.by_ip.insert(ip, name);
        Some(ip)
    }

    pub fn name_of(&self, ip: Ipv4Addr) -> Option<String> {
        self.inner.lock().unwrap().by_ip.get(&ip).cloned()
    }
}

const T_A: u16 = 1;
const T_AAAA: u16 = 28;
const T_HTTPS: u16 = 65;

/// Answers one query. Returns None for garbage (dropped, like a real server under attack would).
pub fn answer(names: &Names, q: &[u8], https_records: bool) -> Option<(Vec<u8>, String)> {
    if q.len() < 12 || q[2] & 0x80 != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([q[4], q[5]]);
    if qd != 1 {
        return None;
    }
    // QNAME (no compression in a question).
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let l = *q.get(i)? as usize;
        i += 1;
        if l == 0 {
            break;
        }
        if l > 63 {
            return None;
        }
        labels.push(std::str::from_utf8(q.get(i..i + l)?).ok()?.to_string());
        i += l;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    let qend = i + 4;
    q.get(..qend)?;
    let name = labels.join(".");
    let ip = names.resolve(&name);
    let mut r = Vec::with_capacity(qend + 64);
    r.extend_from_slice(&q[0..2]); // id
    let rd = q[2] & 0x01;
    r.push(0x84 | rd); // QR, AA, RD copied
    r.push(0x80 | if ip.is_none() { 3 } else { 0 }); // RA, NXDOMAIN or NOERROR
    r.extend_from_slice(&[0, 1]); // QDCOUNT
    let mut ans: Vec<Vec<u8>> = Vec::new();
    if let Some(ip) = ip {
        match qtype {
            T_A => ans.push(rr(T_A, &ip.octets())),
            T_HTTPS if https_records => {
                let mut d = vec![0, 1, 0]; // priority 1, target "."
                d.extend_from_slice(&[0, 1, 0, 3, 2, b'h', b'3']); // alpn=h3
                d.extend_from_slice(&[0, 4, 0, 4]); // ipv4hint
                d.extend_from_slice(&ip.octets());
                ans.push(rr(T_HTTPS, &d));
            }
            _ => {} // AAAA and the rest: NODATA
        }
    }
    r.extend_from_slice(&(ans.len() as u16).to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
    r.extend_from_slice(&q[12..qend]);
    for a in ans {
        r.extend_from_slice(&a);
    }
    let what = match (qtype, ip) {
        (_, None) => "NXDOMAIN".to_string(),
        (T_A, Some(ip)) => format!("A {ip}"),
        (T_HTTPS, Some(ip)) if https_records => format!("HTTPS alpn=h3 ipv4hint={ip}"),
        (T_AAAA, Some(_)) => "AAAA NODATA".into(),
        (t, Some(_)) => format!("type {t} NODATA"),
    };
    Some((r, format!("{name} {what}")))
}

fn rr(t: u16, data: &[u8]) -> Vec<u8> {
    let mut v = vec![0xC0, 0x0C]; // pointer to the question name
    v.extend_from_slice(&t.to_be_bytes());
    v.extend_from_slice(&[0, 1]);
    v.extend_from_slice(&TTL.to_be_bytes());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, t: u16) -> Vec<u8> {
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

    #[test]
    fn allowed_hidden_and_nodata() {
        let n = Names::new(Box::new(|h| h.ends_with(".test") && h != "hidden.test"));
        let (a, _) = answer(&n, &query("h3.test", T_A), true).unwrap();
        assert_eq!(a[3] & 0x0f, 0);
        assert_eq!(&a[a.len() - 4..], &[198, 19, 1, 0]);
        let (b, _) = answer(&n, &query("hidden.test", T_A), true).unwrap();
        assert_eq!(b[3] & 0x0f, 3);
        let (c, _) = answer(&n, &query("h3.test", T_AAAA), true).unwrap();
        assert_eq!((c[3] & 0x0f, c[7]), (0, 0));
        assert_eq!(n.name_of(Ipv4Addr::new(198, 19, 1, 0)).as_deref(), Some("h3.test"));
    }
}
