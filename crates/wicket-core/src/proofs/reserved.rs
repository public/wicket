//! wicket's own approval namespace (`op::agent_op_refusal`, #117): what an agent or a node may
//! never ask a human for. #322's Lean spec has no counterpart. In two harnesses, so each stays
//! small: the method side, over every reserved and HTTP method in other cases and near misses
//! (with hosts in and out of the namespace); and the host side, over every host of up to 17 bytes
//! of the letters of `wicket.internal` (some in upper case) and dots, which reaches the domain,
//! a name under it, trailing dots and look-alikes. (One harness over both took 139 s.)

use super::{agent_op_refusal, AgentOpRefusal, HTTP_METHODS, RESERVED_METHODS};
use crate::link::DOMAIN;
use crate::proofs::AnyStr;

const METHODS: [&str; 12] = ["GET", "get", "POST", "DELETE", "SPAWN", "spawn", "Link", "DIGEST", "tool", "TOOLS", "CONNECT", ""];
const HOSTS: [&str; 4] = ["wicket.internal", "A.WICKET.INTERNAL.", "example.com", "xwicket.internal"];
const HOST: &[u8] = b"wicketnral.WI";

/// Whether `host` is `wicket.internal` or a name under it, in any case, with trailing dots: read
/// byte by byte here, apart from `is_wicket_host`'s slices.
fn under_domain(host: &[u8]) -> bool {
    let d = DOMAIN.as_bytes();
    let mut end = host.len();
    while end > 0 && host[end - 1] == b'.' {
        end -= 1;
    }
    if end < d.len() {
        return false;
    }
    let start = end - d.len();
    let mut i = 0;
    let mut same = true;
    while i < d.len() {
        same &= host[start + i].to_ascii_lowercase() == d[i];
        i += 1;
    }
    same && (start == 0 || host[start - 1] == b'.')
}

/// The decision, given whether the op is in the namespace by its host: refused as reserved if it
/// is, or if its method is reserved in any case; else let through only for an HTTP method as
/// written.
fn expect(method: &str, host_reserved: bool) -> Option<AgentOpRefusal> {
    if host_reserved || RESERVED_METHODS.iter().any(|m| m.eq_ignore_ascii_case(method)) {
        Some(AgentOpRefusal::Reserved)
    } else if HTTP_METHODS.contains(&method) {
        None
    } else {
        Some(AgentOpRefusal::NotHttp)
    }
}

/// The method side: every reserved method in any case is refused, on any host; past that only
/// the HTTP methods themselves, in upper case, are let through.
#[kani::proof]
#[kani::unwind(20)]
fn a_reserved_method_is_refused_to_agents() {
    let method = METHODS[kani::any_where(|&i: &usize| i < METHODS.len())];
    let host = HOSTS[kani::any_where(|&i: &usize| i < HOSTS.len())];
    assert_eq!(agent_op_refusal(method, host), expect(method, under_domain(host.as_bytes())));
}

/// The host side: every name under `wicket.internal`, in any case, with trailing dots, is
/// refused, whatever the method; other hosts are decided by the method alone.
#[kani::proof]
#[kani::unwind(19)]
fn a_wicket_host_is_refused_to_agents() {
    let method = if kani::any() { "GET" } else { "CONNECT" };
    let host = AnyStr::<17>::new(HOST);
    assert_eq!(agent_op_refusal(method, host.as_str()), expect(method, under_domain(host.bytes())));
}
