//! The relay frame between the in-box forwarder and the host, one per SOCK_SEQPACKET message:
//! `kind u8 | seg u16 | src ip4 | src port u16 | dst ip4 | dst port u16 | payload`. `seg` is 0 for
//! one datagram; otherwise the payload is several datagrams of `seg` bytes each (the last may be
//! shorter), all of one flow: GSO/GRO over the relay, so a batch costs one unix message. `src` is the box client's
//! address, `dst` the address it sent to (a synthetic address, or wicket.internal:53), in both
//! directions, so the forwarder keeps no state: a reply goes from `dst` to `src`.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub const HDR: usize = 15;
pub const KIND_QUIC: u8 = 0;
pub const KIND_DNS: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Head {
    pub kind: u8,
    pub seg: u16,
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
}

pub fn put_head(buf: &mut [u8], h: &Head) {
    buf[0] = h.kind;
    buf[1..3].copy_from_slice(&h.seg.to_be_bytes());
    buf[3..7].copy_from_slice(&h.src.ip().octets());
    buf[7..9].copy_from_slice(&h.src.port().to_be_bytes());
    buf[9..13].copy_from_slice(&h.dst.ip().octets());
    buf[13..15].copy_from_slice(&h.dst.port().to_be_bytes());
}

pub fn get_head(buf: &[u8]) -> Option<Head> {
    if buf.len() < HDR {
        return None;
    }
    let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    Some(Head {
        kind: buf[0],
        seg: port(&buf[1..3]),
        src: SocketAddrV4::new(ip(&buf[3..7]), port(&buf[7..9])),
        dst: SocketAddrV4::new(ip(&buf[9..13]), port(&buf[13..15])),
    })
}

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn sockaddr_un(path: &str) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as _;
    let b = path.as_bytes();
    if b.len() >= a.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long"));
    }
    for (i, c) in b.iter().enumerate() {
        a.sun_path[i] = *c as _;
    }
    Ok((a, (std::mem::size_of::<libc::sa_family_t>() + b.len() + 1) as _))
}

pub fn seqpacket(nonblocking: bool) -> io::Result<OwnedFd> {
    let mut t = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
    if nonblocking {
        t |= libc::SOCK_NONBLOCK;
    }
    let fd = cvt(unsafe { libc::socket(libc::AF_UNIX, t, 0) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn connect(path: &str) -> io::Result<OwnedFd> {
    let fd = seqpacket(false)?;
    let (a, len) = sockaddr_un(path)?;
    cvt(unsafe { libc::connect(fd.as_raw_fd(), &a as *const _ as *const libc::sockaddr, len) })?;
    set_bufs(fd.as_raw_fd(), 4 << 20);
    Ok(fd)
}

pub fn listen(path: &str) -> io::Result<OwnedFd> {
    let _ = std::fs::remove_file(path);
    let fd = seqpacket(true)?;
    let (a, len) = sockaddr_un(path)?;
    cvt(unsafe { libc::bind(fd.as_raw_fd(), &a as *const _ as *const libc::sockaddr, len) })?;
    cvt(unsafe { libc::listen(fd.as_raw_fd(), 16) })?;
    Ok(fd)
}

pub fn accept(fd: RawFd) -> io::Result<OwnedFd> {
    let c = cvt(unsafe { libc::accept4(fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) })?;
    set_bufs(c, 4 << 20);
    Ok(unsafe { OwnedFd::from_raw_fd(c) })
}

pub fn set_bufs(fd: RawFd, n: libc::c_int) {
    for o in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, o, &n as *const _ as *const libc::c_void, 4);
        }
    }
}

pub fn send(fd: RawFd, parts: &[&[u8]]) -> io::Result<usize> {
    let iov: Vec<libc::iovec> = parts.iter().map(|p| libc::iovec { iov_base: p.as_ptr() as *mut _, iov_len: p.len() }).collect();
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = iov.as_ptr() as *mut _;
    m.msg_iovlen = iov.len() as _;
    let n = unsafe { libc::sendmsg(fd, &m, libc::MSG_NOSIGNAL) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

pub fn recv(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
