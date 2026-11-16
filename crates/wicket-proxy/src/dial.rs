//! Dial-time address checks (design §9.1, #116). wicket resolves every upstream name itself and
//! connects only to addresses it has checked: none private, loopback, link-local, metadata or
//! otherwise non-public ([`wicket_core::is_public_ip`]), and none of the node's own (an address of
//! one of its interfaces, public or not: its own services are not the internet, #366). If any
//! address a name resolves to is
//! non-public, the name is refused outright rather than filtered, so a DNS answer that mixes a
//! public address with an internal one can't be used to reach the internal one.
//!
//! The checked addresses are the ones dialled: reqwest connects to what [`PublicResolver`] returns,
//! and the HTTP/3 dialler to what [`resolve_public`] returns, so a second (rebinding) answer is
//! never consulted for that connection.
//!
//! Addresses pinned by whoever configures the proxy ([`crate::egress::Upstream::resolve`]: tests,
//! pointing hosts at local origins) are the operator's choice and aren't checked.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Where names are looked up: the system resolver, or (tests) fixed answers, which are checked
/// just like real ones.
#[derive(Clone, Default)]
pub(crate) struct Lookup {
    pub fixed: Arc<HashMap<String, Vec<IpAddr>>>,
    /// (Tests) the node's own addresses, instead of its interfaces'.
    pub own: Option<Arc<Vec<IpAddr>>>,
}

impl Lookup {
    async fn addrs(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Some(ips) = self.fixed.get(host) {
            return Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
        }
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
}

/// The addresses `host` resolves to, if every one of them is public. An error otherwise, saying
/// which address was refused.
pub(crate) async fn resolve_public(lookup: &Lookup, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let addrs = lookup.addrs(host, port).await?;
    let own = match &lookup.own {
        Some(own) => own.to_vec(),
        None => own_addresses()?,
    };
    check(host, addrs, &own)
}

/// The addresses of this node's interfaces, as they are now (an interface may come up, or get a
/// new address, at any time: read at every dial).
fn own_addresses() -> io::Result<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free below, once.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::other(format!("reading this node's interface addresses: {}", io::Error::last_os_error())));
    }
    let mut out = vec![];
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned, not yet freed.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` points at a sockaddr of the family it says.
            match i32::from(unsafe { (*ifa.ifa_addr).sa_family }) {
                libc::AF_INET => {
                    // SAFETY: an AF_INET address is a sockaddr_in.
                    let a = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    out.push(IpAddr::from(u32::from_be(a.sin_addr.s_addr).to_be_bytes()));
                }
                libc::AF_INET6 => {
                    // SAFETY: an AF_INET6 address is a sockaddr_in6.
                    let a = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    out.push(IpAddr::from(a.sin6_addr.s6_addr));
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

fn check(host: &str, addrs: Vec<SocketAddr>, own: &[IpAddr]) -> io::Result<Vec<SocketAddr>> {
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{host}: no address")));
    }
    if let Some(bad) = addrs.iter().find(|a| !wicket_core::is_public_ip(&a.ip())) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{host} resolves to the non-public address {}, which is never reachable from a box", bad.ip()),
        ));
    }
    if let Some(bad) = addrs.iter().find(|a| own.contains(&a.ip())) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{host} resolves to {}, an address of this node itself, which is never reachable from a box", bad.ip()),
        ));
    }
    Ok(addrs)
}

/// reqwest's resolver for the egress proxy: [`resolve_public`].
pub(crate) struct PublicResolver(pub Lookup);

impl reqwest::dns::Resolve for PublicResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let lookup = self.0.clone();
        Box::pin(async move {
            let addrs = resolve_public(&lookup, name.as_str(), 0).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_name_with_any_non_public_address_is_refused() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let fixed = HashMap::from([
            ("public.example".to_string(), vec![ip("8.8.8.8"), ip("2606:4700::1111")]),
            ("meta.example".to_string(), vec![ip("169.254.169.254")]),
            ("mixed.example".to_string(), vec![ip("8.8.8.8"), ip("10.0.0.7")]),
            ("loop6.example".to_string(), vec![ip("::1")]),
            ("nat64.example".to_string(), vec![ip("64:ff9b::a9fe:a9fe")]),
            ("none.example".to_string(), vec![]),
        ]);
        let l = Lookup { fixed: Arc::new(fixed), own: Some(Arc::new(vec![])) };
        assert_eq!(resolve_public(&l, "public.example", 443).await.unwrap().len(), 2);
        for h in ["meta.example", "mixed.example", "loop6.example", "nat64.example"] {
            let e = resolve_public(&l, h, 443).await.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{h}");
            assert!(e.to_string().contains("non-public"), "{e}");
        }
        assert!(resolve_public(&l, "none.example", 443).await.is_err());
    }

    /// #366: a name that resolves to one of the node's own addresses is refused, public or not; the
    /// node's interfaces are read as they are.
    #[tokio::test]
    async fn the_nodes_own_addresses_are_refused() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let fixed = HashMap::from([
            ("node.example".to_string(), vec![ip("8.8.8.8"), ip("203.0.114.9")]),
            ("public.example".to_string(), vec![ip("8.8.4.4")]),
        ]);
        let l = Lookup { fixed: Arc::new(fixed), own: Some(Arc::new(vec![ip("203.0.114.9"), ip("2001:4860::9")])) };
        let e = resolve_public(&l, "node.example", 443).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("an address of this node itself"), "{e}");
        assert!(resolve_public(&l, "public.example", 443).await.is_ok());
        let own = own_addresses().unwrap();
        assert!(own.iter().any(|a| a.is_loopback()), "the interfaces are read: {own:?}");
    }

    /// #366: cloud metadata services at addresses outside the special-purpose ranges.
    #[test]
    fn metadata_addresses_are_not_public() {
        for a in ["168.63.129.16", "169.254.169.254", "fd00:ec2::254", "100.100.100.200", "192.0.0.192"] {
            assert!(!wicket_core::is_public_ip(&a.parse().unwrap()), "{a}");
        }
        assert!(wicket_core::is_public_ip(&"168.63.129.17".parse().unwrap()));
    }
}
