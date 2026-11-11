//! Moving bytes between two sockets: tokio's userspace copy, or `splice(2)` through a pipe so the bytes
//! never enter user space. The splice path uses two blocking threads per connection: enough for a
//! prototype; a real proxy would drive it from its event loop (or io_uring).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// Copy everything from `from` to `to` with splice(2), then half-close `to`.
pub fn pump(from: RawFd, to: RawFd) -> io::Result<u64> {
    let mut p = [0i32; 2];
    if unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::fcntl(p[1], libc::F_SETPIPE_SZ, 1 << 20) };
    // No SPLICE_F_MORE: on a socket it sets MSG_MORE, which corks a small TLS record for up to 200 ms.
    let flags = libc::SPLICE_F_MOVE;
    let mut total = 0u64;
    let res = loop {
        let n = unsafe { libc::splice(from, std::ptr::null_mut(), p[1], std::ptr::null_mut(), 1 << 20, flags) };
        if n == 0 {
            break Ok(total);
        }
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break Err(e);
        }
        let mut left = n as usize;
        let mut err = None;
        while left > 0 {
            let m = unsafe { libc::splice(p[0], std::ptr::null_mut(), to, std::ptr::null_mut(), left, flags) };
            if m <= 0 {
                let e = io::Error::last_os_error();
                if m < 0 && e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                err = Some(e);
                break;
            }
            left -= m as usize;
        }
        if let Some(e) = err {
            break Err(e);
        }
        total += n as u64;
    };
    unsafe {
        libc::shutdown(to, libc::SHUT_WR);
        libc::close(p[0]);
        libc::close(p[1]);
    }
    res
}

/// Splice both directions between two blocking sockets until both sides are done.
pub fn bidirectional(a: OwnedFd, b: OwnedFd) {
    let (ar, br) = (a.as_raw_fd(), b.as_raw_fd());
    let t = std::thread::spawn(move || pump(ar, br));
    let _ = pump(br, ar);
    let _ = t.join();
    drop((a, b));
}

/// A tokio stream as a blocking file descriptor for the splice threads.
pub trait IntoStd {
    fn into_blocking_fd(self) -> io::Result<OwnedFd>;
}

impl IntoStd for tokio::net::TcpStream {
    fn into_blocking_fd(self) -> io::Result<OwnedFd> {
        let s = self.into_std()?;
        s.set_nonblocking(false)?;
        Ok(s.into())
    }
}

impl IntoStd for tokio::net::UnixStream {
    fn into_blocking_fd(self) -> io::Result<OwnedFd> {
        let s = self.into_std()?;
        s.set_nonblocking(false)?;
        Ok(s.into())
    }
}
