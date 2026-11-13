//! "No such domain" in `escalate` zones (#19, design §9.1 DNS). A request to a host the zone doesn't
//! name would become a pending request for a human, even for a domain that doesn't exist. Before that,
//! wicket asks one question: does the host's *registered* domain (per the public suffix list) exist?
//!
//! - Only the registered domain is ever queried (`example.com` for `a.b.example.com`), never the name
//!   the agent chose: the labels below it, the part an agent could fill with data, stay on the node.
//! - The answer is read from the response code alone: NXDOMAIN means it doesn't exist and the agent
//!   is told "unknown host"; NOERROR means it does and the request escalates as before. Anything
//!   else (no resolver, a timeout, SERVFAIL, offline) is "can't tell", and the request escalates as
//!   before: a human still decides, nothing gets through unasked.
//! - The public suffix list is compiled in (the `psl` crate), so deciding what to ask needs no
//!   network.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// What a registered-domain check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exists {
    Yes,
    No,
    /// No answer that says either way.
    Unknown,
}

/// How long one resolver gets to answer.
const TIMEOUT: Duration = Duration::from_secs(2);
/// How many of the system's resolvers are tried.
const MAX_SERVERS: usize = 3;
const T_SOA: u16 = 6;

/// The registered domain of `host` (lowercase, no trailing dot): the public suffix plus one label.
/// None for a host that is itself a public suffix (`co.uk`), or isn't a DNS name.
pub fn registered_domain(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() || !host.contains('.') {
        return None;
    }
    let d = psl::domain_str(&host)?;
    // A name that is all suffix (or whose suffix is an unlisted TLD with nothing before it) has none.
    (d.contains('.') && d.len() <= 253).then(|| d.to_string())
}

/// The system's resolvers, from /etc/resolv.conf (the node's own, never the box's).
fn nameservers() -> Vec<SocketAddr> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    conf.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|a| a.trim().split('%').next()?.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .take(MAX_SERVERS)
        .collect()
}

/// Top-level domains reserved never to exist on the public DNS (RFC 2606, RFC 6761): answered
/// here, with no query.
const RESERVED_TLDS: &[&str] = &["test", "example", "invalid"];

/// Whether `domain` exists, asked of the system's resolvers (a reserved TLD isn't asked about).
pub async fn check(domain: &str) -> Exists {
    if RESERVED_TLDS.iter().any(|t| domain.rsplit('.').next() == Some(t)) {
        return Exists::No;
    }
    for server in nameservers() {
        match ask(server, domain).await {
            Exists::Unknown => continue,
            answer => return answer,
        }
    }
    Exists::Unknown
}

/// One SOA query for `domain` to `server`; the response code is the answer.
async fn ask(server: SocketAddr, domain: &str) -> Exists {
    let mut id = [0u8; 2];
    if getrandom::getrandom(&mut id).is_err() {
        return Exists::Unknown;
    }
    let Some(q) = query(u16::from_be_bytes(id), domain) else { return Exists::Unknown };
    let bind: SocketAddr = if server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
    let Ok(sock) = tokio::net::UdpSocket::bind(bind).await else { return Exists::Unknown };
    if sock.connect(server).await.is_err() || sock.send(&q).await.is_err() {
        return Exists::Unknown;
    }
    let read = async {
        let mut buf = [0u8; 1500];
        loop {
            let n = sock.recv(&mut buf).await.ok()?;
            if let Some(e) = rcode(&q, &buf[..n]) {
                return Some(e);
            }
        }
    };
    tokio::time::timeout(TIMEOUT, read).await.ok().flatten().unwrap_or(Exists::Unknown)
}

/// A recursive SOA query for `domain`. None if it isn't a plain DNS name.
pub(crate) fn query(id: u16, domain: &str) -> Option<Vec<u8>> {
    let mut q = Vec::with_capacity(18 + domain.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD; one question
    for l in domain.split('.') {
        let ok = !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return None;
        }
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&T_SOA.to_be_bytes());
    q.extend_from_slice(&[0, 1]); // IN
    Some(q)
}

/// What a response to `q` says: None if it isn't one (another id, not a response, another question).
pub(crate) fn rcode(q: &[u8], r: &[u8]) -> Option<Exists> {
    if r.len() < q.len() || r[..2] != q[..2] || r[2] & 0x80 == 0 || r[2] & 0x78 != 0 || r[4..6] != [0, 1] {
        return None;
    }
    if !r[12..q.len()].eq_ignore_ascii_case(&q[12..]) {
        return None;
    }
    Some(match r[3] & 0x0f {
        0 => Exists::Yes,
        3 => Exists::No,
        _ => Exists::Unknown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_registered_domain_is_asked_about() {
        assert_eq!(registered_domain("a.b.example.com").as_deref(), Some("example.com"));
        assert_eq!(registered_domain("Secret-Data.Exfil.Example.CO.UK.").as_deref(), Some("example.co.uk"));
        assert_eq!(registered_domain("x.y.github.io").as_deref(), Some("y.github.io"), "private suffixes count");
        assert_eq!(registered_domain("co.uk"), None);
        assert_eq!(registered_domain("localhost"), None);
        assert_eq!(registered_domain("10.0.0.1"), None);
    }

    #[tokio::test]
    async fn reserved_top_level_domains_never_exist_and_are_not_asked_about() {
        for d in ["nope.test", "a.example", "x.invalid"] {
            assert_eq!(check(d).await, Exists::No, "{d}");
        }
    }

    #[test]
    fn the_response_code_is_the_answer() {
        let q = query(0x1234, "example.com").unwrap();
        let reply = |rc: u8, id: u8, qname: &[u8]| {
            let mut r = q.clone();
            r[1] = id;
            r[2] = 0x81;
            r[3] = 0x80 | rc;
            r[12..12 + qname.len()].copy_from_slice(qname);
            r
        };
        assert_eq!(rcode(&q, &reply(0, 0x34, b"\x07EXAMPLE")), Some(Exists::Yes));
        assert_eq!(rcode(&q, &reply(3, 0x34, b"\x07example")), Some(Exists::No));
        assert_eq!(rcode(&q, &reply(2, 0x34, b"\x07example")), Some(Exists::Unknown), "SERVFAIL can't tell");
        assert_eq!(rcode(&q, &reply(3, 0x35, b"\x07example")), None, "another id");
        assert_eq!(rcode(&q, &reply(3, 0x34, b"\x07exbmple")), None, "another question");
        assert_eq!(rcode(&q, &q), None, "not a response");
        assert!(query(1, "a b.com").is_none());
    }
}
