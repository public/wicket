//! wicket's own approval namespace (`op::agent_op_refusal`, #117): what an agent or a node may
//! never ask a human for. #322's Lean spec has no counterpart. Methods: every reserved and HTTP
//! method, in other cases and near misses; hosts: up to 18 bytes over the letters of
//! `wicket.internal` in both cases, so the domain, names under it and look-alikes are all reached.

use super::{agent_op_refusal, AgentOpRefusal, HTTP_METHODS, RESERVED_METHODS};
use crate::link::DOMAIN;
use crate::proofs::AnyStr;

const METHODS: [&str; 12] = ["GET", "get", "POST", "DELETE", "SPAWN", "spawn", "Link", "DIGEST", "tool", "TOOLS", "CONNECT", ""];
const HOST: &[u8] = b"wicketnral.WICKETNRAL";

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

/// An agent or a node is refused every op in wicket's namespace, whatever the method: every name
/// under `wicket.internal` (any case, trailing dots), and every reserved method in any case. Past
/// that, only the HTTP methods themselves, in upper case, are let through.
#[kani::proof]
#[kani::unwind(20)]
fn wickets_own_namespace_is_refused_to_agents() {
    let method = METHODS[kani::any_where(|&i: &usize| i < METHODS.len())];
    let host = AnyStr::<18>::new(HOST);
    let reserved = under_domain(host.bytes()) || RESERVED_METHODS.iter().any(|m| m.eq_ignore_ascii_case(method));
    let got = agent_op_refusal(method, host.as_str());
    if reserved {
        assert_eq!(got, Some(AgentOpRefusal::Reserved));
    } else if HTTP_METHODS.contains(&method) {
        assert_eq!(got, None);
    } else {
        assert_eq!(got, Some(AgentOpRefusal::NotHttp));
    }
}
