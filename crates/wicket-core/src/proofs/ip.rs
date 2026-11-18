//! The SSRF guard (`op::is_public_ip`): which addresses a box's egress may dial (`wicket-proxy`'s
//! dialer, and `never_reachable` before a decision). #322's Lean spec has no counterpart. Over
//! every IPv4 and every IPv6 address: the function is checked against the special-purpose blocks
//! written as a table of prefixes (`ip_blocks.rs`), apart from how it tests them (std's
//! predicates, octets, masks).

use super::ip_blocks::{in_v4, in_v6, V4_BLOCKS, V6_BLOCKS};
use super::is_public_ip;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IPv4 address is public exactly when no never-public block holds it.
#[kani::proof]
#[kani::unwind(17)]
fn an_ipv4_address_is_public_exactly_outside_the_special_blocks() {
    let a: u32 = kani::any();
    let special = V4_BLOCKS.iter().any(|b| in_v4(a, *b));
    assert_eq!(is_public_ip(&IpAddr::V4(Ipv4Addr::from(a))), !special);
}

/// An IPv6 address is public exactly when no never-public block holds it: so no form that carries
/// or translates to an IPv4 address is, whatever that address.
// 17: the table's 11 blocks, and the 12-byte compare of `is_public_ip`'s `s[..6] == [0; 6]`.
#[kani::proof]
#[kani::unwind(17)]
fn an_ipv6_address_is_public_exactly_outside_the_special_blocks() {
    let a: u128 = kani::any();
    let special = V6_BLOCKS.iter().any(|b| in_v6(a, *b));
    assert_eq!(is_public_ip(&IpAddr::V6(Ipv6Addr::from(a))), !special);
}
