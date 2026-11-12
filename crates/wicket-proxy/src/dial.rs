//! Dial-time address checks (design §9.1, #116). wicket resolves every upstream name itself and
//! connects only to addresses it has checked: none private, loopback, link-local, metadata or
//! otherwise non-public ([`wicket_core::is_public_ip`]). If any address a name resolves to is
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
    check(host, addrs)
}

fn check(host: &str, addrs: Vec<SocketAddr>) -> io::Result<Vec<SocketAddr>> {
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{host}: no address")));
    }
    if let Some(bad) = addrs.iter().find(|a| !wicket_core::is_public_ip(&a.ip())) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{host} resolves to the non-public address {}, which is never reachable from a sandbox", bad.ip()),
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
            ("public.example".to_string(), vec![ip("93.184.215.14"), ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c")]),
            ("meta.example".to_string(), vec![ip("169.254.169.254")]),
            ("mixed.example".to_string(), vec![ip("93.184.215.14"), ip("10.0.0.7")]),
            ("loop6.example".to_string(), vec![ip("::1")]),
            ("nat64.example".to_string(), vec![ip("64:ff9b::a9fe:a9fe")]),
            ("none.example".to_string(), vec![]),
        ]);
        let l = Lookup { fixed: Arc::new(fixed) };
        assert_eq!(resolve_public(&l, "public.example", 443).await.unwrap().len(), 2);
        for h in ["meta.example", "mixed.example", "loop6.example", "nat64.example"] {
            let e = resolve_public(&l, h, 443).await.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{h}");
            assert!(e.to_string().contains("non-public"), "{e}");
        }
        assert!(resolve_public(&l, "none.example", 443).await.is_err());
    }
}
