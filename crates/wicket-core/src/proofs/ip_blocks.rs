//! The never-public address blocks, as a table of prefixes: what the Kani harnesses (`ip.rs`)
//! check `op::is_public_ip` against over every address, and a unit test samples (`op.rs`), so a
//! typo in a table is caught without Kani too.

/// IPv4 blocks that are never public (IANA's special-purpose registry, multicast and the reserved
/// 240/4 with the broadcast address, and Azure's WireServer, #366), as (network, prefix length).
pub(crate) const V4_BLOCKS: &[(u32, u32)] = &[
    (0x0000_0000, 8),  // 0/8, "this network"
    (0x0a00_0000, 8),  // 10/8, private
    (0x6440_0000, 10), // 100.64/10, CGNAT
    (0x7f00_0000, 8),  // 127/8, loopback
    (0xa9fe_0000, 16), // 169.254/16, link-local (cloud metadata)
    (0xac10_0000, 12), // 172.16/12, private
    (0xc000_0000, 24), // 192.0.0/24, IETF protocol assignments
    (0xc000_0200, 24), // 192.0.2/24, documentation
    (0xc058_6300, 24), // 192.88.99/24, 6to4 relay anycast
    (0xc0a8_0000, 16), // 192.168/16, private
    (0xc612_0000, 15), // 198.18/15, benchmarking
    (0xc633_6400, 24), // 198.51.100/24, documentation
    (0xcb00_7100, 24), // 203.0.113/24, documentation
    (0xe000_0000, 4),  // 224/4, multicast
    (0xf000_0000, 4),  // 240/4, reserved, and 255.255.255.255
    (0xa83f_8110, 32), // 168.63.129.16, Azure's WireServer
];

/// IPv6 blocks that are never public: loopback and unspecified (in ::/96), the forms that carry an
/// IPv4 address (compatible ::/96, mapped, NAT64 and its local-use range, 6to4, Teredo and the
/// rest of 2001::/23), unique-local, link-local, site-local, multicast, documentation, discard.
pub(crate) const V6_BLOCKS: &[(u128, u32)] = &[
    (0, 96),                                         // ::/96: ::, ::1, IPv4-compatible
    (0x0000_0000_0000_0000_0000_ffff_0000_0000, 96), // ::ffff:0:0/96, IPv4-mapped
    (0x0064_ff9b_0000_0000_0000_0000_0000_0000, 32), // 64:ff9b::/32, NAT64 (and 64:ff9b:1::/48)
    (0x0100_0000_0000_0000_0000_0000_0000_0000, 64), // 100::/64, discard
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 23), // 2001::/23, IETF (Teredo among them)
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // 2001:db8::/32, documentation
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16), // 2002::/16, 6to4
    (0xfc00_0000_0000_0000_0000_0000_0000_0000, 7),  // fc00::/7, unique-local
    (0xfe80_0000_0000_0000_0000_0000_0000_0000, 10), // fe80::/10, link-local
    (0xfec0_0000_0000_0000_0000_0000_0000_0000, 10), // fec0::/10, site-local
    (0xff00_0000_0000_0000_0000_0000_0000_0000, 8),  // ff00::/8, multicast
];

pub(crate) fn in_v4(a: u32, (net, len): (u32, u32)) -> bool {
    (a ^ net) >> (32 - len) == 0
}

pub(crate) fn in_v6(a: u128, (net, len): (u128, u32)) -> bool {
    (a ^ net) >> (128 - len) == 0
}
