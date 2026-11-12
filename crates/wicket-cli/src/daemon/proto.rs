//! The wire between the CLI and `wicketd`, over one unix stream socket per command.
//!
//! 1. The client sends one byte with its stdin, stdout and stderr (and, for commands that mount a
//!    directory in place, that directory) attached as `SCM_RIGHTS`, so the command the daemon runs
//!    reads and writes the caller's own terminal or pipes.
//! 2. Then frames: `[kind: u8][len: u32 big-endian][payload]`. The client sends a [`Hello`], any
//!    uploads, and `Go`; the daemon answers `Welcome` (or `Error` and closes), runs the command, and
//!    sends its exit status. While it runs, the client may send signals; closing the connection
//!    stops the command (SIGTERM).
//!
//! Who the caller is comes from the kernel ([`peer`]: `SO_PEERCRED`, `SO_PEERGROUPS`), never from
//! the frames.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Frames are at most this long (uploads are split into frames of this size).
pub const MAX_FRAME: usize = 4 << 20;
/// At most this many fds come with the first byte.
pub const MAX_FDS: usize = 4;

pub mod kind {
    // client → daemon
    pub const HELLO: u8 = b'H';
    pub const UPLOAD: u8 = b'U';
    pub const GO: u8 = b'G';
    pub const SIGNAL: u8 = b'S';
    // daemon → client
    pub const WELCOME: u8 = b'W';
    pub const ERROR: u8 = b'E';
    pub const EXIT: u8 = b'X';
}

/// What the client asks for.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub version: String,
    /// The command line, without the program name.
    pub argv: Vec<String>,
    /// The caller's working directory (informational, and a wrapped agent's directory).
    pub cwd: String,
    /// The caller's WICKET_LOG, passed on if well-formed.
    #[serde(default)]
    pub log: Option<String>,
    /// Whether a directory fd came after the three stdio fds.
    #[serde(default)]
    pub dir_fd: bool,
    /// For `run` and `wrap`: the manifest's file name, and its program's source as written in it
    /// (checked against the manifest that arrives).
    #[serde(default)]
    pub manifest_name: Option<String>,
    #[serde(default)]
    pub program_source: Option<String>,
}

/// The daemon's answer once it has let the caller in.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Welcome {
    pub version: String,
    pub data_dir: String,
    pub daemon_user: String,
    /// The caller as the daemon sees it.
    pub you: String,
    /// How the caller was let in: "root", "daemon" or "policy".
    pub basis: String,
}

/// One upload entry; a file's bytes follow its header in the same frame.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// "manifest", "program" or "workdir".
    pub role: String,
    /// Relative to the role's root ("" for the root itself).
    pub path: String,
    /// "file", "dir" or "symlink".
    pub kind: String,
    #[serde(default)]
    pub mode: u32,
    #[serde(default)]
    pub target: Option<String>,
    /// More bytes for a file already started.
    #[serde(default)]
    pub append: bool,
}

pub fn write_frame(w: &mut impl Write, kind: u8, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_FRAME + 64 * 1024 {
        bail!("frame too long");
    }
    let mut head = [0u8; 5];
    head[0] = kind;
    head[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&head)?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// The next frame, or None at a clean end of stream.
pub fn read_frame(r: &mut impl Read) -> Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(head[1..].try_into().expect("4 bytes")) as usize;
    if len > MAX_FRAME + 64 * 1024 {
        bail!("frame too long ({len} bytes)");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some((head[0], buf)))
}

pub fn write_json(w: &mut impl Write, kind: u8, v: &impl Serialize) -> Result<()> {
    write_frame(w, kind, &serde_json::to_vec(v)?)
}

/// An upload frame: header length, header, bytes.
pub fn upload_frame(e: &Entry, data: &[u8]) -> Result<Vec<u8>> {
    let h = serde_json::to_vec(e)?;
    let mut out = Vec::with_capacity(4 + h.len() + data.len());
    out.extend_from_slice(&(h.len() as u32).to_be_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(data);
    Ok(out)
}

pub fn parse_upload(p: &[u8]) -> Result<(Entry, &[u8])> {
    if p.len() < 4 {
        bail!("short upload frame");
    }
    let n = u32::from_be_bytes(p[..4].try_into().expect("4 bytes")) as usize;
    if p.len() < 4 + n {
        bail!("short upload frame");
    }
    Ok((serde_json::from_slice(&p[4..4 + n])?, &p[4 + n..]))
}

/// Sends one byte with `fds` attached.
pub fn send_fds(s: &UnixStream, fds: &[RawFd]) -> Result<()> {
    let byte = b"F";
    let mut iov = libc::iovec { iov_base: byte.as_ptr() as *mut libc::c_void, iov_len: 1 };
    let fd_bytes = std::mem::size_of_val(fds);
    // SAFETY: CMSG_SPACE is a pure computation.
    let space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: msghdr is plain data; every pointer set below outlives the sendmsg call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    // SAFETY: the control buffer is CMSG_SPACE bytes for this many fds, so the first header and its
    // data fit.
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, libc::CMSG_DATA(c), fd_bytes);
    }
    // SAFETY: a valid socket and a fully initialised msghdr.
    let n = unsafe { libc::sendmsg(s.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if n != 1 {
        return Err(std::io::Error::last_os_error()).context("sending the caller's file descriptors");
    }
    Ok(())
}

/// Receives the one byte [`send_fds`] sent and the fds with it (at most [`MAX_FDS`]).
pub fn recv_fds(s: &UnixStream) -> Result<Vec<OwnedFd>> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut libc::c_void, iov_len: 1 };
    // SAFETY: a pure computation.
    let space = unsafe { libc::CMSG_SPACE((MAX_FDS * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: plain data; the pointers outlive the call.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    // SAFETY: as above; MSG_CMSG_CLOEXEC so received fds don't leak into other children.
    let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("receiving the caller's file descriptors");
    }
    let mut out = Vec::new();
    // SAFETY: walking the control messages recvmsg filled in, within msg_controllen.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c);
                let len = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for i in 0..len / std::mem::size_of::<RawFd>() {
                    let fd = std::ptr::read_unaligned((data as *const RawFd).add(i));
                    out.push(OwnedFd::from_raw_fd(fd));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if n != 1 || byte[0] != b'F' {
        bail!("the caller did not start with its file descriptors");
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        bail!("too many file descriptors");
    }
    Ok(out)
}

/// The process at the other end of a unix socket, as the kernel reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pub user: String,
    /// Its groups (primary and supplementary): gid and name ("" when the gid has no name).
    pub groups: Vec<(u32, String)>,
}

pub fn peer(s: &UnixStream) -> Result<Peer> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`.
    let r =
        unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    if r != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_PEERCRED");
    }
    let mut gids = vec![cred.gid];
    let mut buf = vec![0 as libc::gid_t; 256];
    let mut glen = std::mem::size_of_val(buf.as_slice()) as libc::socklen_t;
    // SAFETY: as above, into a gid_t buffer of `glen` bytes.
    let r =
        unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERGROUPS, buf.as_mut_ptr() as *mut libc::c_void, &mut glen) };
    if r == 0 {
        buf.truncate(glen as usize / std::mem::size_of::<libc::gid_t>());
        gids.extend(buf);
    }
    gids.sort_unstable();
    gids.dedup();
    let groups = gids.into_iter().map(|g| (g, group_name(g).unwrap_or_default())).collect();
    Ok(Peer { pid: cred.pid, uid: cred.uid, gid: cred.gid, user: user_name(cred.uid).unwrap_or_else(|| cred.uid.to_string()), groups })
}

/// The name of `uid` in the user database.
pub fn user_name(uid: u32) -> Option<String> {
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r fills `pw` with pointers into `buf`, which outlives their use here.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    // SAFETY: pw_name is a NUL-terminated string in `buf`.
    Some(unsafe { std::ffi::CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned())
}

/// The name of `gid` in the group database.
pub fn group_name(gid: u32) -> Option<String> {
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 65536];
    let mut out: *mut libc::group = std::ptr::null_mut();
    // SAFETY: as user_name.
    let r = unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    // SAFETY: gr_name is a NUL-terminated string in `buf`.
    Some(unsafe { std::ffi::CStr::from_ptr(gr.gr_name) }.to_string_lossy().into_owned())
}

/// The gid of the group called `name`.
pub fn group_id(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 65536];
    let mut out: *mut libc::group = std::ptr::null_mut();
    // SAFETY: as user_name.
    let r = unsafe { libc::getgrnam_r(c.as_ptr(), &mut gr, buf.as_mut_ptr(), buf.len(), &mut out) };
    (r == 0 && !out.is_null()).then_some(gr.gr_gid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn frames_round_trip_and_end_cleanly() {
        let mut buf = Vec::new();
        write_frame(&mut buf, kind::HELLO, b"{}").unwrap();
        write_frame(&mut buf, kind::GO, b"").unwrap();
        let mut r = buf.as_slice();
        assert_eq!(read_frame(&mut r).unwrap(), Some((kind::HELLO, b"{}".to_vec())));
        assert_eq!(read_frame(&mut r).unwrap(), Some((kind::GO, vec![])));
        assert_eq!(read_frame(&mut r).unwrap(), None);
        // A length beyond the limit is refused before anything is allocated.
        let mut bad = vec![kind::UPLOAD];
        bad.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(read_frame(&mut bad.as_slice()).is_err());
        let e = Entry { role: "workdir".into(), path: "a/b".into(), kind: "file".into(), mode: 0o644, target: None, append: false };
        let f = upload_frame(&e, b"data").unwrap();
        let (e2, d) = parse_upload(&f).unwrap();
        assert_eq!((e2, d), (e, &b"data"[..]));
        assert!(parse_upload(&[0, 0, 0, 9, b'{']).is_err());
    }

    #[test]
    fn fds_and_credentials_cross_the_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, mut w) = std::io::pipe().unwrap();
        send_fds(&a, &[r.as_fd().as_raw_fd()]).unwrap();
        drop(r);
        let fds = recv_fds(&b).unwrap();
        assert_eq!(fds.len(), 1);
        w.write_all(b"through the passed fd").unwrap();
        drop(w);
        let mut got = String::new();
        std::fs::File::from(fds.into_iter().next().unwrap()).read_to_string(&mut got).unwrap();
        assert_eq!(got, "through the passed fd");
        let p = peer(&b).unwrap();
        // SAFETY: plain getters.
        assert_eq!((p.uid, p.gid), unsafe { (libc::geteuid(), libc::getegid()) });
        assert_eq!(p.pid as u32, std::process::id());
        assert!(p.groups.iter().any(|(g, _)| *g == p.gid));
        assert_eq!(Some(p.user.clone()), user_name(p.uid));
    }

    #[test]
    fn a_caller_without_fds_is_refused() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"H").unwrap();
        assert!(recv_fds(&b).unwrap_err().to_string().contains("did not start"));
    }
}
