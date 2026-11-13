//! Moving one direction of a connection: read/write through a buffer, or splice(2) through a pipe.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};

use crate::sys;

/// How bytes move from one socket to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMode {
    /// read(2) into a userspace buffer, write(2) it out.
    ReadWrite,
    /// splice(2) through a pipe, never through userspace. Falls back to read/write per direction
    /// when the first splice is refused (a kernel, or a gVisor, that can't splice these sockets).
    Splice,
}

impl std::str::FromStr for CopyMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "rw" => Ok(CopyMode::ReadWrite),
            "splice" => Ok(CopyMode::Splice),
            _ => Err(format!("--copy {s:?}: expected rw or splice")),
        }
    }
}

/// Copies `from` to `to` until `from` reaches end of file; returns the bytes moved. An error means
/// the connection is broken, in either direction.
pub fn copy<R, W>(mode: CopyMode, from: &mut R, to: &mut W, buf_size: usize) -> io::Result<u64>
where
    R: Read + AsFd,
    W: Write + AsFd,
{
    if mode == CopyMode::Splice {
        return match splice(from, to, buf_size) {
            Splice::Done(r) => r,
            // splice can't serve these sockets: read/write the rest (all of it, normally).
            Splice::Refused(moved) => {
                static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                if !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    crate::log(format_args!("splice(2) refused here; copying with read/write instead"));
                }
                Ok(moved + read_write(from, to, buf_size)?)
            }
        };
    }
    read_write(from, to, buf_size)
}

fn read_write<R: Read, W: Write>(from: &mut R, to: &mut W, buf_size: usize) -> io::Result<u64> {
    let mut buf = vec![0u8; buf_size];
    let mut total = 0u64;
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        to.write_all(&buf[..n])?;
        total += n as u64;
    }
}

enum Splice {
    /// Finished: end of file (bytes moved) or a broken connection.
    Done(io::Result<u64>),
    /// splice(2) refused these sockets (EINVAL, ENOSYS, EOPNOTSUPP) after moving this many bytes,
    /// none of them left in the pipe. Support doesn't change mid-stream, so in practice this is
    /// the first call, but whatever already sits in the pipe is written out first either way.
    Refused(u64),
}

fn refused(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(22 | 38 | 95))
}

fn splice<R: AsFd, W: Write + AsFd>(from: &R, to: &mut W, buf_size: usize) -> Splice {
    let Ok((pr, pw)) = sys::pipe(buf_size) else { return Splice::Refused(0) };
    let src = from.as_fd().as_raw_fd();
    let mut total = 0u64;
    loop {
        let n = match sys::splice_once(src, pw.as_raw_fd(), buf_size, sys::SPLICE_F_MOVE) {
            Ok(0) => return Splice::Done(Ok(total)),
            Ok(n) => n,
            Err(e) if refused(&e) => return Splice::Refused(total),
            Err(e) => return Splice::Done(Err(e)),
        };
        let mut left = n;
        while left > 0 {
            match sys::splice_once(pr.as_raw_fd(), to.as_fd().as_raw_fd(), left, sys::SPLICE_F_MOVE) {
                Ok(0) => return Splice::Done(Err(io::ErrorKind::WriteZero.into())),
                Ok(m) => left -= m,
                Err(e) if refused(&e) => {
                    // The bytes are in the pipe: write them out the ordinary way, then give up on splice.
                    let mut rest = vec![0u8; left];
                    let mut pipe = std::fs::File::from(pr);
                    if let Err(e) = pipe.read_exact(&mut rest).and_then(|()| to.write_all(&rest)) {
                        return Splice::Done(Err(e));
                    }
                    return Splice::Refused(total + n as u64);
                }
                Err(e) => return Splice::Done(Err(e)),
            }
        }
        total += n as u64;
    }
}
// #218 measurement only
