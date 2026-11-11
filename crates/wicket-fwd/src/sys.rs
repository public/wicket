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
