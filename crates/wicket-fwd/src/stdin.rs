//! `wicket-fwd --stdin-from SOCK -- CMD...` (#151): runs CMD with its stdin fed from wicket's node
//! over a unix socket in the box's socket directory, so the box's stdin outlives the node process
//! that writes it (a restarted `wicket node serve` takes over where the last one stopped).
//!
//! On each connection this side first sends how many bytes it has received (u64, big-endian); the
//! node then sends frames of a u32 big-endian length and that many bytes, from that offset on. A
//! frame of length 0 is the end of stdin: CMD's stdin is closed. A connection that drops without one
//! is reconnected (every 200 ms), never taken as the end. Exits with CMD's exit code.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Relays one connection into `to` until it ends: Ok(true) at the end-of-stdin frame, Ok(false) if
/// the connection dropped first.
fn relay(s: &mut UnixStream, to: &mut impl Write, received: &mut u64) -> io::Result<bool> {
    s.write_all(&received.to_be_bytes())?;
    let mut len = [0u8; 4];
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if s.read_exact(&mut len).is_err() {
            return Ok(false);
        }
        let mut n = u32::from_be_bytes(len) as usize;
        if n == 0 {
            return Ok(true);
        }
        while n > 0 {
            let want = n.min(buf.len());
            let k = s.read(&mut buf[..want])?;
            if k == 0 {
                return Ok(false);
            }
            to.write_all(&buf[..k])?;
            to.flush()?;
            *received += k as u64;
            n -= k;
        }
    }
}

/// Runs `argv` with its stdin fed from `sock`; its exit code.
pub fn run(sock: &Path, argv: &[String]) -> io::Result<i32> {
    let (cmd, args) = argv.split_first().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no command"))?;
    let mut child = Command::new(cmd).args(args).stdin(Stdio::piped()).spawn()?;
    let mut to = child.stdin.take().expect("stdin");
    let sock = sock.to_path_buf();
    std::thread::spawn(move || {
        let mut received = 0u64;
        loop {
            if let Ok(mut s) = UnixStream::connect(&sock) {
                match relay(&mut s, &mut to, &mut received) {
                    Ok(true) => return, // drops `to`: the command's stdin closes
                    Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return, // the command closed its stdin
                    _ => {}
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    let st = child.wait()?;
    Ok(st.code().unwrap_or(128))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn frame(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }

    /// Stdin survives the node going away (a dropped connection is reconnected, resuming where it
    /// left off), and only the end frame closes it.
    #[test]
    fn stdin_survives_a_reconnect_and_ends_only_when_told() {
        let dir = std::env::temp_dir().join(format!("wicket-fwd-stdin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("stdin.sock");
        let out = dir.join("out");
        let l = UnixListener::bind(&sock).unwrap();
        let (s2, o2) = (sock.clone(), out.clone());
        let t = std::thread::spawn(move || run(&s2, &["sh".into(), "-c".into(), format!("cat > {}", o2.display())]).unwrap());
        // First node: sends "hello ", then goes away mid-stream.
        let (mut c, _) = l.accept().unwrap();
        let mut off = [0u8; 8];
        c.read_exact(&mut off).unwrap();
        assert_eq!(u64::from_be_bytes(off), 0);
        c.write_all(&frame(b"hello ")).unwrap();
        drop(c);
        // The next one is told how far the box got, and sends the rest and the end.
        let (mut c, _) = l.accept().unwrap();
        c.read_exact(&mut off).unwrap();
        assert_eq!(u64::from_be_bytes(off), 6);
        c.write_all(&frame(b"world")).unwrap();
        c.write_all(&frame(b"")).unwrap();
        assert_eq!(t.join().unwrap(), 0);
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "hello world");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
