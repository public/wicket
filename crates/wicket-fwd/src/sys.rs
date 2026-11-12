//! The few libc calls std doesn't wrap. std already links the C library, so these need no crate.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::raw::{c_int, c_uint};

const O_CLOEXEC: c_int = 0o2_000_000;
const F_SETPIPE_SZ: c_int = 1031;
pub const SPLICE_F_MOVE: c_uint = 1;

extern "C" {
    fn splice(fd_in: c_int, off_in: *mut i64, fd_out: c_int, off_out: *mut i64, len: usize, flags: c_uint) -> isize;
    fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

/// A pipe (read end, write end), close-on-exec. Asks for `size` bytes of pipe buffer; the kernel
/// may give less (or, unprivileged, cap it at `/proc/sys/fs/pipe-max-size`), which is fine.
pub fn pipe(size: usize) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: `fds` is a valid array of two ints for pipe2 to fill.
    if unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 succeeded, so both are fresh descriptors that nothing else owns.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let size = c_int::try_from(size).unwrap_or(c_int::MAX);
    // SAFETY: F_SETPIPE_SZ takes one int argument; failure leaves the default size.
    let _ = unsafe { fcntl(fds[1], F_SETPIPE_SZ, size) };
    Ok((r, w))
}

/// One splice(2) call without offsets (both ends are sockets or pipes). Retries EINTR.
pub fn splice_once(from: RawFd, to: RawFd, len: usize, flags: c_uint) -> io::Result<usize> {
    loop {
        // SAFETY: null offsets are valid for non-seekable descriptors; the fds are borrowed for the call.
        let n = unsafe { splice(from, std::ptr::null_mut(), to, std::ptr::null_mut(), len, flags) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

// Datagram sockets (`--udp`, #92): the kernel's ABI on 64-bit Linux. musl and glibc declare
// `msghdr` differently (int + padding vs size_t), but on a little-endian 64-bit target both match
// these layouts byte for byte.

pub mod net {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    use std::os::raw::{c_int, c_uint, c_void};

    pub const AF_UNIX: c_int = 1;
    pub const AF_INET: u16 = 2;
    pub const SOCK_SEQPACKET: c_int = 5;
    pub const SOCK_CLOEXEC: c_int = 0o2_000_000;
    const SOL_SOCKET: c_int = 1;
    const SO_SNDBUF: c_int = 7;
    const SO_RCVBUF: c_int = 8;
    const IPPROTO_IP: c_int = 0;
    const IP_PKTINFO: c_int = 8;
    pub const MSG_DONTWAIT: c_int = 0x40;
    pub const MSG_NOSIGNAL: c_int = 0x4000;

    #[repr(C)]
    pub struct IoVec {
        pub base: *mut c_void,
        pub len: usize,
    }

    #[repr(C)]
    pub struct MsgHdr {
        pub name: *mut c_void,
        pub namelen: u32,
        pub iov: *mut IoVec,
        pub iovlen: usize,
        pub control: *mut c_void,
        pub controllen: usize,
        pub flags: c_int,
    }

    #[repr(C)]
    pub struct MMsgHdr {
        pub hdr: MsgHdr,
        pub len: c_uint,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SockAddrIn {
        pub family: u16,
        pub port: u16,
        pub addr: u32,
        pub zero: [u8; 8],
    }

    #[repr(C)]
    struct SockAddrUn {
        family: u16,
        path: [u8; 108],
    }

    #[repr(C)]
    struct CMsgHdr {
        len: usize,
        level: c_int,
        kind: c_int,
    }

    #[repr(C)]
    struct InPktInfo {
        ifindex: c_int,
        spec_dst: u32,
        addr: u32,
    }

    /// Room for one `IP_PKTINFO` control message (CMSG_SPACE(12)).
    pub const PKTINFO_SPACE: usize = 32;
    const PKTINFO_LEN: usize = 16 + 12;

    extern "C" {
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, len: u32) -> c_int;
        fn sendmsg(fd: c_int, msg: *const MsgHdr, flags: c_int) -> isize;
        fn recvmsg(fd: c_int, msg: *mut MsgHdr, flags: c_int) -> isize;
        fn recvmmsg(fd: c_int, msgs: *mut MMsgHdr, n: c_uint, flags: c_int, timeout: *mut c_void) -> c_int;
        fn sendmmsg(fd: c_int, msgs: *mut MMsgHdr, n: c_uint, flags: c_int) -> c_int;
    }

    fn cvt(r: isize) -> io::Result<usize> {
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r as usize)
        }
    }

    pub fn set_int(fd: RawFd, level: c_int, name: c_int, v: c_int) -> io::Result<()> {
        // SAFETY: the value is a live c_int of the length given.
        cvt(unsafe { setsockopt(fd, level, name, &v as *const c_int as *const c_void, 4) } as isize).map(|_| ())
    }

    /// Asks for `n` bytes of socket buffer each way (the kernel may cap it).
    pub fn set_bufs(fd: RawFd, n: c_int) {
        let _ = set_int(fd, SOL_SOCKET, SO_SNDBUF, n);
        let _ = set_int(fd, SOL_SOCKET, SO_RCVBUF, n);
    }

    pub fn enable_pktinfo(fd: RawFd) -> io::Result<()> {
        set_int(fd, IPPROTO_IP, IP_PKTINFO, 1)
    }

    /// A `SOCK_SEQPACKET` connection to the unix socket at `path`.
    pub fn connect_seqpacket(path: &std::path::Path) -> io::Result<OwnedFd> {
        use std::os::unix::ffi::OsStrExt;
        let b = path.as_os_str().as_bytes();
        let mut a = SockAddrUn { family: AF_UNIX as u16, path: [0; 108] };
        if b.len() >= a.path.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long"));
        }
        a.path[..b.len()].copy_from_slice(b);
        // SAFETY: plain socket(2); the result is checked before use.
        let fd = cvt(unsafe { socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0) } as isize)? as RawFd;
        // SAFETY: socket succeeded, so fd is fresh and owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        use std::os::fd::AsRawFd;
        // SAFETY: `a` is a valid sockaddr_un and the length covers the path and its NUL.
        cvt(unsafe { connect(fd.as_raw_fd(), &a as *const SockAddrUn as *const c_void, (2 + b.len() + 1) as u32) } as isize)?;
        Ok(fd)
    }

    /// sendmsg of the concatenation of `parts`, as one message.
    pub fn send_parts(fd: RawFd, parts: &[&[u8]]) -> io::Result<usize> {
        let mut iov: Vec<IoVec> = parts.iter().map(|p| IoVec { base: p.as_ptr() as *mut c_void, len: p.len() }).collect();
        let m = MsgHdr {
            name: std::ptr::null_mut(),
            namelen: 0,
            iov: iov.as_mut_ptr(),
            iovlen: iov.len(),
            control: std::ptr::null_mut(),
            controllen: 0,
            flags: 0,
        };
        loop {
            // SAFETY: every iovec points into a live slice for the duration of the call.
            match cvt(unsafe { sendmsg(fd, &m, MSG_NOSIGNAL) }) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                r => return r,
            }
        }
    }

    /// recv(2) of one message into `buf`; 0 means the peer closed.
    pub fn recv_one(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        let mut iov = IoVec { base: buf.as_mut_ptr() as *mut c_void, len: buf.len() };
        let mut m = MsgHdr {
            name: std::ptr::null_mut(),
            namelen: 0,
            iov: &mut iov,
            iovlen: 1,
            control: std::ptr::null_mut(),
            controllen: 0,
            flags: 0,
        };
        loop {
            // SAFETY: the iovec points into `buf`, which outlives the call.
            match cvt(unsafe { recvmsg(fd, &mut m, 0) }) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                r => return r,
            }
        }
    }

    pub fn sockaddr(a: SocketAddrV4) -> SockAddrIn {
        SockAddrIn { family: AF_INET, port: a.port().to_be(), addr: u32::from(*a.ip()).to_be(), zero: [0; 8] }
    }

    pub fn from_sockaddr(a: &SockAddrIn) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(u32::from_be(a.addr)), u16::from_be(a.port))
    }

    /// A batch of datagrams received on a UDP socket with `IP_PKTINFO`: buffers, peers and each
    /// datagram's original destination address.
    pub struct RecvBatch {
        bufs: Vec<Vec<u8>>,
        names: Vec<SockAddrIn>,
        ctrl: Vec<[u64; PKTINFO_SPACE / 8 * 2]>,
        iovs: Vec<IoVec>,
        msgs: Vec<MMsgHdr>,
    }

    // SAFETY: the raw pointers only ever point into the batch's own vectors.
    unsafe impl Send for RecvBatch {}

    impl RecvBatch {
        pub fn new(n: usize, size: usize) -> RecvBatch {
            let mut b = RecvBatch {
                bufs: (0..n).map(|_| vec![0u8; size]).collect(),
                names: vec![SockAddrIn { family: 0, port: 0, addr: 0, zero: [0; 8] }; n],
                ctrl: vec![[0u64; PKTINFO_SPACE / 8 * 2]; n],
                iovs: Vec::with_capacity(n),
                msgs: Vec::with_capacity(n),
            };
            for i in 0..n {
                b.iovs.push(IoVec { base: b.bufs[i].as_mut_ptr() as *mut c_void, len: size });
            }
            for i in 0..n {
                b.msgs.push(MMsgHdr {
                    hdr: MsgHdr {
                        name: &mut b.names[i] as *mut SockAddrIn as *mut c_void,
                        namelen: 16,
                        iov: &mut b.iovs[i],
                        iovlen: 1,
                        control: b.ctrl[i].as_mut_ptr() as *mut c_void,
                        controllen: PKTINFO_SPACE * 2,
                        flags: 0,
                    },
                    len: 0,
                });
            }
            b
        }

        fn reset(&mut self, i: usize) {
            let m = &mut self.msgs[i].hdr;
            m.namelen = 16;
            m.controllen = PKTINFO_SPACE * 2;
            m.flags = 0;
        }

        /// Blocks for one datagram, then takes whatever else is queued, up to the batch size (gVisor
        /// refuses `MSG_WAITFORONE`). Returns how many arrived.
        pub fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
            for i in 0..self.msgs.len() {
                self.reset(i);
            }
            let n = loop {
                // SAFETY: msgs[0] points into this batch's buffers.
                match cvt(unsafe { recvmsg(fd, &mut self.msgs[0].hdr, 0) }) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    r => break r?,
                }
            };
            self.msgs[0].len = n as c_uint;
            if self.msgs.len() == 1 {
                return Ok(1);
            }
            // SAFETY: as above, for the rest of the batch.
            let more =
                unsafe { recvmmsg(fd, self.msgs[1..].as_mut_ptr(), (self.msgs.len() - 1) as c_uint, MSG_DONTWAIT, std::ptr::null_mut()) };
            Ok(1 + more.max(0) as usize)
        }

        /// Datagram `i`: its bytes, its sender, and the address it was sent to (None without
        /// `IP_PKTINFO`, or for a truncated control message).
        pub fn get(&self, i: usize) -> (&[u8], SocketAddrV4, Option<Ipv4Addr>) {
            let len = (self.msgs[i].len as usize).min(self.bufs[i].len());
            (&self.bufs[i][..len], from_sockaddr(&self.names[i]), pktinfo_dst(&self.msgs[i].hdr))
        }
    }

    fn pktinfo_dst(m: &MsgHdr) -> Option<Ipv4Addr> {
        let mut off = 0usize;
        while off + 16 <= m.controllen {
            // SAFETY: the control buffer holds `controllen` bytes, aligned for cmsghdr.
            let c = unsafe { &*((m.control as *const u8).add(off) as *const CMsgHdr) };
            if c.len < 16 {
                return None;
            }
            if c.level == IPPROTO_IP && c.kind == IP_PKTINFO && c.len >= PKTINFO_LEN {
                // SAFETY: the data of an IP_PKTINFO message is one in_pktinfo, right after the header.
                let pi = unsafe { &*((m.control as *const u8).add(off + 16) as *const InPktInfo) };
                return Some(Ipv4Addr::from(u32::from_be(pi.addr)));
            }
            off += (c.len + 7) & !7;
        }
        None
    }

    /// Sends each of `parts` as one datagram from `from` (via `IP_PKTINFO`) to `to`, in as few
    /// sendmmsg calls as the kernel allows.
    pub fn send_from(fd: RawFd, parts: &[&[u8]], from: Ipv4Addr, to: SocketAddrV4) -> io::Result<()> {
        let n = parts.len();
        if n == 0 {
            return Ok(());
        }
        let mut name = sockaddr(to);
        let mut ctrl = vec![[0u64; PKTINFO_SPACE / 8]; n];
        let mut iovs: Vec<IoVec> = parts.iter().map(|p| IoVec { base: p.as_ptr() as *mut c_void, len: p.len() }).collect();
        let mut msgs: Vec<MMsgHdr> = Vec::with_capacity(n);
        for i in 0..n {
            let base = ctrl[i].as_mut_ptr() as *mut u8;
            // SAFETY: each control buffer is PKTINFO_SPACE bytes, aligned to 8: room for one cmsghdr
            // and one in_pktinfo.
            unsafe {
                *(base as *mut CMsgHdr) = CMsgHdr { len: PKTINFO_LEN, level: IPPROTO_IP, kind: IP_PKTINFO };
                *(base.add(16) as *mut InPktInfo) = InPktInfo { ifindex: 0, spec_dst: u32::from(from).to_be(), addr: 0 };
            }
            msgs.push(MMsgHdr {
                hdr: MsgHdr {
                    name: &mut name as *mut SockAddrIn as *mut c_void,
                    namelen: 16,
                    iov: &mut iovs[i],
                    iovlen: 1,
                    control: base as *mut c_void,
                    controllen: PKTINFO_SPACE,
                    flags: 0,
                },
                len: 0,
            });
        }
        let mut off = 0;
        while off < n {
            // SAFETY: every pointer in msgs[off..] points into the vectors above, alive for the call.
            let r = unsafe { sendmmsg(fd, msgs[off..].as_mut_ptr(), (n - off) as c_uint, 0) };
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            off += (r as usize).max(1);
        }
        Ok(())
    }
}
