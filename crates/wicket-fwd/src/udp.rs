//! `--udp` listeners (#92): datagrams in the box relayed to a host unix socket, one
//! [`frame`](crate::frame) per datagram or batch.
//!
//! - **In the box**, one UDP socket per listener, with `IP_PKTINFO` so each datagram's original
//!   destination is known even on a wildcard socket (`0.0.0.0:443` catches every synthetic address
//!   on `lo`). Replies leave from that same address (`IP_PKTINFO`'s `ipi_spec_dst` on send).
//! - **To the host**, one connection per listener: `SOCK_SEQPACKET` (boundaries kept, one message
//!   per frame), or, if that connect fails, a stream socket (an SSH-forwarded socket
//!   on a remote node), the same frames each after a 4-byte big-endian length. Unix `SOCK_DGRAM` is
//!   not used: under gVisor the host can't answer a box's datagram socket (experiment #92).
//! - **Stateless.** Every frame names the client and the address it used, both ways, so there is no
//!   flow table and no idle timeout here; the host's QUIC (or DNS) state is the only state.
//! - **Batches.** Received datagrams are taken in batches (`recvmsg`, then `recvmmsg` of whatever
//!   else is queued); consecutive datagrams of one flow, all but the last of one size, go as one
//!   frame (GRO), up to [`frame::MAX_PAYLOAD`] bytes. A frame from the host with `seg` set is split
//!   and sent with one `sendmmsg`. Under gVisor every trapped syscall costs, so this halves the
//!   relay's syscalls; the per-datagram cost of gVisor's own UDP stack remains (#92's results).
//! - **The host going away** (wicket restarting the run's proxy) drops datagrams until it is back;
//!   the forwarder reconnects at most twice a second, on demand. QUIC retransmits.
//!
//! The forwarder decides nothing: the host drops datagrams to addresses it didn't mint.

use crate::frame::{self, Head, HDR, MAX_FRAME, MAX_PAYLOAD};
use crate::sys::net;
use crate::{log, Quiet};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Datagrams taken per receive batch.
const BATCH: usize = 32;
/// Socket buffers asked for, each way.
const SOCK_BUF: i32 = 4 << 20;

/// How the forwarder reaches the host.
pub enum Link {
    Seqpacket(OwnedFd),
    Stream(UnixStream),
}

impl Link {
    /// SEQPACKET first; a stream socket if that's what the host listens on.
    pub fn connect(path: &Path) -> io::Result<Link> {
        match net::connect_seqpacket(path) {
            Ok(fd) => {
                net::set_bufs(fd.as_raw_fd(), SOCK_BUF);
                Ok(Link::Seqpacket(fd))
            }
            // EPROTOTYPE on Linux; whatever a sandbox's kernel says, a stream socket gets a try.
            Err(e) => UnixStream::connect(path).map(Link::Stream).map_err(|_| e),
        }
    }

    pub fn try_clone(&self) -> io::Result<Link> {
        Ok(match self {
            Link::Seqpacket(fd) => Link::Seqpacket(fd.try_clone()?),
            Link::Stream(s) => Link::Stream(s.try_clone()?),
        })
    }

    /// Sends one frame: `head`, then the concatenation of `parts`.
    pub fn send(&mut self, head: &Head, parts: &[&[u8]]) -> io::Result<()> {
        let h = head.encode();
        match self {
            Link::Seqpacket(fd) => {
                let mut all: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
                all.push(&h);
                all.extend_from_slice(parts);
                net::send_parts(fd.as_raw_fd(), &all)?;
            }
            Link::Stream(s) => {
                let len: usize = HDR + parts.iter().map(|p| p.len()).sum::<usize>();
                let mut buf = Vec::with_capacity(4 + len);
                buf.extend_from_slice(&(len as u32).to_be_bytes());
                buf.extend_from_slice(&h);
                for p in parts {
                    buf.extend_from_slice(p);
                }
                s.write_all(&buf)?;
            }
        }
        Ok(())
    }

    /// Receives one frame into `buf` (at least [`MAX_FRAME`] bytes); returns its length, 0 at end.
    pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Link::Seqpacket(fd) => net::recv_one(fd.as_raw_fd(), buf),
            Link::Stream(s) => {
                let mut len = [0u8; 4];
                match s.read_exact(&mut len) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                    Err(e) => return Err(e),
                }
                let n = u32::from_be_bytes(len) as usize;
                if !(HDR..=MAX_FRAME).contains(&n) || n > buf.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("frame of {n} bytes")));
                }
                s.read_exact(&mut buf[..n])?;
                Ok(n)
            }
        }
    }
}

/// Binds a UDP listener (waiting up to `timeout` for its address to appear), with `IP_PKTINFO`.
pub fn bind(addr: SocketAddr, timeout: Duration) -> io::Result<UdpSocket> {
    let SocketAddr::V4(_) = addr else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "UDP listeners are IPv4 only"));
    };
    let start = Instant::now();
    let mut said = false;
    let sock = loop {
        match UdpSocket::bind(addr) {
            Ok(s) => break s,
            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable && start.elapsed() < timeout => {
                if !said {
                    log(format_args!("waiting for address {} to appear", addr.ip()));
                    said = true;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    };
    net::enable_pktinfo(sock.as_raw_fd())?;
    net::set_bufs(sock.as_raw_fd(), SOCK_BUF);
    Ok(sock)
}

/// Runs one listener for good: datagrams on `sock` up to the host at `path`, replies back.
pub fn serve(sock: UdpSocket, path: PathBuf, verbose: bool) {
    let sock = Arc::new(sock);
    let quiet = Arc::new(Mutex::new(Quiet { last: None, dropped: 0 }));
    let local = sock.local_addr().ok();
    let mut link: Option<Link> = None;
    let mut last_try: Option<Instant> = None;
    let mut batch = net::RecvBatch::new(BATCH, MAX_PAYLOAD);
    loop {
        let n = match batch.recv(sock.as_raw_fd()) {
            Ok(n) => n,
            Err(e) => {
                Quiet::say(&quiet, format_args!("udp {}: receive: {e}", local.map_or("?".into(), |a| a.to_string())));
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        if link.is_none() && last_try.is_none_or(|t| t.elapsed() >= Duration::from_millis(500)) {
            last_try = Some(Instant::now());
            match Link::connect(&path).and_then(|l| Ok((l.try_clone()?, l))) {
                Ok((down, up)) => {
                    if verbose {
                        log(format_args!("udp {} -> {}: connected", local.map_or("?".into(), |a| a.to_string()), path.display()));
                    }
                    let s = sock.clone();
                    let q = quiet.clone();
                    let spawned = thread::Builder::new().name("udp down".into()).spawn(move || down_loop(down, s, q));
                    if spawned.is_ok() {
                        link = Some(up);
                    }
                }
                Err(e) => Quiet::say(&quiet, format_args!("connect {}: {e} (dropping datagrams until it is back)", path.display())),
            }
        }
        let Some(l) = link.as_mut() else { continue };
        if let Err(e) = send_batch(l, &batch, n, local) {
            Quiet::say(&quiet, format_args!("relay to {}: {e}; reconnecting", path.display()));
            link = None;
        }
    }
}

/// Groups the batch into frames: runs of one flow, all but the last datagram of one size.
fn send_batch(link: &mut Link, batch: &net::RecvBatch, n: usize, local: Option<SocketAddr>) -> io::Result<()> {
    let fallback_dst = match local {
        Some(SocketAddr::V4(a)) => Some(a),
        _ => None,
    };
    let mut run: Option<(Head, Vec<usize>, usize)> = None; // head, members, payload bytes
    let flush = |link: &mut Link, run: &mut Option<(Head, Vec<usize>, usize)>| -> io::Result<()> {
        let Some((mut head, idx, _)) = run.take() else { return Ok(()) };
        let parts: Vec<&[u8]> = idx.iter().map(|&i| batch.get(i).0).collect();
        head.seg = if parts.len() > 1 { parts[0].len() as u16 } else { 0 };
        link.send(&head, &parts)
    };
    for i in 0..n {
        let (data, src, dst) = batch.get(i);
        let Some(dst) = dst.or(fallback_dst.map(|a| *a.ip())) else { continue };
        let port = fallback_dst.map_or(0, |a| a.port());
        let head = Head { seg: 0, src, dst: SocketAddrV4::new(dst, port) };
        let joins = run.as_ref().is_some_and(|(h, idx, bytes)| {
            let first = batch.get(idx[0]).0.len();
            let last = batch.get(*idx.last().expect("non-empty")).0.len();
            h.src == head.src
                && h.dst == head.dst
                && last == first
                && data.len() <= first
                && !data.is_empty()
                && bytes + data.len() <= MAX_PAYLOAD
        });
        if joins {
            let (_, idx, bytes) = run.as_mut().expect("run");
            idx.push(i);
            *bytes += data.len();
        } else {
            flush(link, &mut run)?;
            run = Some((head, vec![i], data.len()));
        }
    }
    flush(link, &mut run)
}

/// Host to box: frames from the host, sent as datagrams from the address each names.
fn down_loop(mut link: Link, sock: Arc<UdpSocket>, quiet: Arc<Mutex<Quiet>>) {
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        let n = match link.recv(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let Some(head) = Head::decode(&buf[..n]) else {
            Quiet::say(&quiet, format_args!("a malformed frame from the host ({n} bytes)"));
            continue;
        };
        let parts: Vec<&[u8]> = frame::segments(head.seg, &buf[HDR..n]).collect();
        if let Err(e) = net::send_from(sock.as_raw_fd(), &parts, *head.dst.ip(), head.src) {
            Quiet::say(&quiet, format_args!("udp send to {}: {e}", head.src));
        }
    }
}
