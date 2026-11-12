//! The datagram relay frame between the in-box forwarder and the host (#92).
//!
//! One frame per `SOCK_SEQPACKET` message (or, over a stream socket, each frame after a 4-byte
//! big-endian length). A 16-byte header in network byte order, then the payload:
//!
//! ```text
//! version u8 (1) | flags u8 (0) | seg u16 | src port u16 | dst port u16 | src IPv4 | dst IPv4
//! ```
//!
//! `src` is the box client's address and `dst` the address it sent to (a synthetic address, or
//! wicket.internal:53), in **both** directions: a reply is sent from `dst` to `src`. So the forwarder
//! keeps no flow table and no idle timers; QUIC's own idle timeout and migration work end to end (a
//! client that changes port is just a new `src`).
//!
//! `seg` is 0 for one datagram. Otherwise the payload is several datagrams of `seg` bytes each (the
//! last may be shorter), all between the same `src` and `dst`: GSO/GRO over the relay, so a batch
//! costs one unix message. A payload is at most [`MAX_PAYLOAD`] bytes either way.
//!
//! IPv4 only: the box resolves names to IPv4 synthetic addresses. IPv6 would be version 2.

use std::net::{Ipv4Addr, SocketAddrV4};

pub const VERSION: u8 = 1;
pub const HDR: usize = 16;
/// The largest payload of one frame (all its segments together).
pub const MAX_PAYLOAD: usize = 65_535;
/// The largest frame.
pub const MAX_FRAME: usize = HDR + MAX_PAYLOAD;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Head {
    /// 0: one datagram; else the size of each datagram in the payload (the last may be shorter).
    pub seg: u16,
    /// The box client.
    pub src: SocketAddrV4,
    /// The address in the box the client sent to.
    pub dst: SocketAddrV4,
}

impl Head {
    pub fn encode(&self) -> [u8; HDR] {
        let mut b = [0u8; HDR];
        b[0] = VERSION;
        b[2..4].copy_from_slice(&self.seg.to_be_bytes());
        b[4..6].copy_from_slice(&self.src.port().to_be_bytes());
        b[6..8].copy_from_slice(&self.dst.port().to_be_bytes());
        b[8..12].copy_from_slice(&self.src.ip().octets());
        b[12..16].copy_from_slice(&self.dst.ip().octets());
        b
    }

    /// The header of a frame, or None if it is short or another version.
    pub fn decode(b: &[u8]) -> Option<Head> {
        if b.len() < HDR || b[0] != VERSION {
            return None;
        }
        let u16_at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        let ip_at = |i: usize| Ipv4Addr::new(b[i], b[i + 1], b[i + 2], b[i + 3]);
        Some(Head { seg: u16_at(2), src: SocketAddrV4::new(ip_at(8), u16_at(4)), dst: SocketAddrV4::new(ip_at(12), u16_at(6)) })
    }
}

/// The datagrams in a frame's payload: one, or `seg`-sized pieces.
pub fn segments(seg: u16, payload: &[u8]) -> impl Iterator<Item = &[u8]> {
    let size = if seg == 0 { payload.len().max(1) } else { seg as usize };
    payload.chunks(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_garbage() {
        let h = Head { seg: 1452, src: "198.19.0.1:40000".parse().unwrap(), dst: "198.19.1.7:443".parse().unwrap() };
        let b = h.encode();
        assert_eq!(b.len(), HDR);
        assert_eq!(Head::decode(&b), Some(h));
        assert_eq!(&b[..4], &[1, 0, 0x05, 0xac]);
        assert!(Head::decode(&b[..15]).is_none());
        let mut v2 = b;
        v2[0] = 2;
        assert!(Head::decode(&v2).is_none());
    }

    #[test]
    fn splits_segments() {
        let p: Vec<u8> = (0..10).collect();
        assert_eq!(segments(0, &p).count(), 1);
        let s: Vec<&[u8]> = segments(4, &p).collect();
        assert_eq!(s, vec![&p[0..4], &p[4..8], &p[8..10]]);
        assert_eq!(segments(0, &[]).count(), 0);
    }
}
