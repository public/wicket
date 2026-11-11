//! The in-box UDP forwarder (what `wicket-fwd` would grow): a wildcard UDP socket on port 443 that
//! learns each datagram's original (synthetic) destination with IP_PKTINFO, and a DNS socket on
//! wicket.internal:53. Every datagram goes to the host as one SOCK_SEQPACKET message with a
//! `wire::Head`; replies come back the same way and are sent from the address the client used.
//! Stateless; runs as the box user with no capabilities. Blocking std threads.

use crate::wire::{self, Head, HDR, KIND_DNS, KIND_QUIC};
use anyhow::{Context, Result};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct Opts {
    pub sock: String,
    pub quic_port: u16,
    pub dns: SocketAddrV4,
    /// Synthetic range: datagrams to anything else on the wildcard socket are dropped.
    pub net: Ipv4Addr,
    pub prefix: u8,
    /// recvmmsg batch size (1 = plain recvmsg).
    pub batch: usize,
    /// SO_SNDBUF/SO_RCVBUF for the relay and UDP sockets.
    pub sockbuf: i32,
}

static UP: AtomicU64 = AtomicU64::new(0);
static DOWN: AtomicU64 = AtomicU64::new(0);

pub fn run(o: Opts) -> Result<()> {
    let host = Arc::new(wire::connect(&o.sock).with_context(|| format!("connecting {}", o.sock))?);
    wire::set_bufs(host.as_raw_fd(), o.sockbuf);
    let quic = UdpSocket::bind(("0.0.0.0", o.quic_port)).context("binding UDP 443")?;
    let on: libc::c_int = 1;
    unsafe {
        libc::setsockopt(quic.as_raw_fd(), libc::IPPROTO_IP, libc::IP_PKTINFO, &on as *const _ as *const _, 4);
    }
    wire::set_bufs(quic.as_raw_fd(), o.sockbuf);
    let dns = UdpSocket::bind(o.dns).context("binding DNS")?;
    eprintln!("fwd: udp :{} (synthetic {}/{}) and dns {} -> {}", o.quic_port, o.net, o.prefix, o.dns, o.sock);
    let mask = if o.prefix == 0 { 0 } else { u32::MAX << (32 - o.prefix) };
    let net = u32::from(o.net) & mask;

    let (q, h) = (quic.try_clone()?, host.clone());
    let batch = o.batch;
    let port = o.quic_port;
    std::thread::spawn(move || {
        if let Err(e) = up_quic(&q, h.as_raw_fd(), port, net, mask, batch) {
            eprintln!("fwd: quic up: {e}");
            std::process::exit(1);
        }
    });
    let (d, h) = (dns.try_clone()?, host.clone());
    let dns_addr = o.dns;
    std::thread::spawn(move || {
        let mut buf = vec![0u8; HDR + 4096];
        loop {
            let Ok((n, peer)) = d.recv_from(&mut buf[HDR..]) else { continue };
            let std::net::SocketAddr::V4(peer) = peer else { continue };
            wire::put_head(&mut buf, &Head { kind: KIND_DNS, src: peer, dst: dns_addr });
            let _ = wire::send(h.as_raw_fd(), &[&buf[..HDR + n]]);
        }
    });
    if std::env::var_os("FWD_STATS").is_some() {
        std::thread::spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            eprintln!("fwd: up {} down {} datagrams", UP.load(Ordering::Relaxed), DOWN.load(Ordering::Relaxed));
        });
    }
    // Host -> box.
    let mut buf = vec![0u8; 70000];
    loop {
        let n = match wire::recv(host.as_raw_fd(), &mut buf) {
            Ok(0) => anyhow::bail!("host closed the relay socket"),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        let Some(h) = wire::get_head(&buf[..n]) else { continue };
        let payload = &buf[HDR..n];
        match h.kind {
            KIND_QUIC => {
                DOWN.fetch_add(1, Ordering::Relaxed);
                let _ = send_from(quic.as_raw_fd(), payload, *h.dst.ip(), h.src);
            }
            KIND_DNS => {
                let _ = dns.send_to(payload, h.src);
            }
            _ => {}
        }
    }
}

fn up_quic(sock: &UdpSocket, host: RawFd, port: u16, net: u32, mask: u32, batch: usize) -> io::Result<()> {
    const CMSG: usize = 64;
    const MAXB: usize = 64;
    let batch = batch.clamp(1, MAXB);
    let mut bufs = vec![[0u8; HDR + 65536]; batch];
    let mut names: Vec<libc::sockaddr_in> = vec![unsafe { std::mem::zeroed() }; batch];
    let mut ctrl = vec![[0u8; CMSG]; batch];
    let mut iovs: Vec<libc::iovec> = Vec::with_capacity(batch);
    for b in bufs.iter_mut() {
        iovs.push(libc::iovec { iov_base: b[HDR..].as_mut_ptr() as *mut _, iov_len: 65536 });
    }
    let mut msgs: Vec<libc::mmsghdr> = vec![unsafe { std::mem::zeroed() }; batch];
    loop {
        for i in 0..batch {
            let m = &mut msgs[i].msg_hdr;
            m.msg_name = &mut names[i] as *mut _ as *mut _;
            m.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as _;
            m.msg_iov = &mut iovs[i];
            m.msg_iovlen = 1;
            m.msg_control = ctrl[i].as_mut_ptr() as *mut _;
            m.msg_controllen = CMSG as _;
            m.msg_flags = 0;
        }
        // gVisor refuses MSG_WAITFORONE (EINVAL): block for one with recvmsg, then take whatever
        // else is queued with recvmmsg(MSG_DONTWAIT).
        let r = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msgs[0].msg_hdr, 0) };
        let n = if r < 0 {
            -1
        } else {
            msgs[0].msg_len = r as _;
            let more = if batch > 1 {
                unsafe { libc::recvmmsg(sock.as_raw_fd(), msgs[1..].as_mut_ptr(), (batch - 1) as _, libc::MSG_DONTWAIT as _, std::ptr::null_mut()) }
            } else {
                0
            };
            1 + more.max(0)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        for i in 0..n as usize {
            let len = msgs[i].msg_len as usize;
            let Some(dst) = pktinfo_dst(&msgs[i].msg_hdr) else { continue };
            if u32::from(dst) & mask != net {
                continue;
            }
            let sa = &names[i];
            let src = SocketAddrV4::new(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)), u16::from_be(sa.sin_port));
            wire::put_head(&mut bufs[i], &Head { kind: KIND_QUIC, src, dst: SocketAddrV4::new(dst, port) });
            UP.fetch_add(1, Ordering::Relaxed);
            // Blocking send: the host's receive buffer is the flow control.
            wire::send(host, &[&bufs[i][..HDR + len]])?;
        }
    }
}

fn pktinfo_dst(m: &libc::msghdr) -> Option<Ipv4Addr> {
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(m);
        while !c.is_null() {
            if (*c).cmsg_level == libc::IPPROTO_IP && (*c).cmsg_type == libc::IP_PKTINFO {
                let pi = &*(libc::CMSG_DATA(c) as *const libc::in_pktinfo);
                return Some(Ipv4Addr::from(u32::from_be(pi.ipi_addr.s_addr)));
            }
            c = libc::CMSG_NXTHDR(m, c);
        }
    }
    None
}

/// sendmsg with IP_PKTINFO's ipi_spec_dst set, so the reply leaves from the synthetic address.
fn send_from(fd: RawFd, payload: &[u8], from: Ipv4Addr, to: SocketAddrV4) -> io::Result<()> {
    let mut name: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    name.sin_family = libc::AF_INET as _;
    name.sin_port = to.port().to_be();
    name.sin_addr.s_addr = u32::from(*to.ip()).to_be();
    let mut iov = libc::iovec { iov_base: payload.as_ptr() as *mut _, iov_len: payload.len() };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) } as usize;
    let mut ctrl = [0u8; 64];
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_name = &mut name as *mut _ as *mut _;
    m.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as _;
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = ctrl.as_mut_ptr() as *mut _;
    m.msg_controllen = space as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&m);
        (*c).cmsg_level = libc::IPPROTO_IP;
        (*c).cmsg_type = libc::IP_PKTINFO;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as _;
        let pi = libc::CMSG_DATA(c) as *mut libc::in_pktinfo;
        (*pi).ipi_ifindex = 0;
        (*pi).ipi_spec_dst.s_addr = u32::from(from).to_be();
        (*pi).ipi_addr.s_addr = 0;
        if libc::sendmsg(fd, &m, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
