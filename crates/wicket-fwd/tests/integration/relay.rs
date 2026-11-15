//! The forwarder on the host: a TCP client, wicket-fwd on 127.0.0.1, and a unix-socket server.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use wicket_fwd::{spec, Config, CopyMode, Forwarder, Kind};

/// A fresh directory for one test's sockets (under target/, so nothing is left in /tmp).
fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("wfwd-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Starts a unix-socket server that runs `handle` on each connection, and a forwarder to it.
fn setup(mode: CopyMode, max_conns: usize, handle: impl Fn(UnixStream) + Send + Sync + 'static) -> SocketAddr {
    let sock = tmpdir().join("s.sock");
    let server = UnixListener::bind(&sock).unwrap();
    let handle = Arc::new(handle);
    thread::spawn(move || {
        for c in server.incoming() {
            let h = handle.clone();
            thread::spawn(move || h(c.unwrap()));
        }
    });
    let cfg = Config {
        listens: vec![spec::parse(Kind::Tcp, &format!("127.0.0.1:0={}", sock.display())).unwrap()],
        copy: mode,
        max_conns,
        ..Config::default()
    };
    Forwarder::start(cfg).unwrap().addrs[0]
}

fn connect(addr: SocketAddr) -> TcpStream {
    let c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    c
}

/// Echoes until end of file, then closes.
fn echo(mut c: UnixStream) {
    let mut buf = [0u8; 65536];
    loop {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if c.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

const MODES: [CopyMode; 2] = [CopyMode::ReadWrite, CopyMode::Splice];

#[test]
fn relays_bytes_both_ways() {
    for mode in MODES {
        let addr = setup(mode, 16, |mut c| {
            let mut b = [0u8; 5];
            c.read_exact(&mut b).unwrap();
            assert_eq!(&b, b"hello");
            c.write_all(b"world").unwrap();
        });
        let mut c = connect(addr);
        c.write_all(b"hello").unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"world", "{mode:?}");
    }
}

#[test]
fn half_close_from_the_client() {
    // The client sends a request and shuts down writing; the server reads to end of file, then
    // answers. The answer must still reach the client.
    for mode in MODES {
        let addr = setup(mode, 16, |mut c| {
            let mut req = Vec::new();
            c.read_to_end(&mut req).unwrap();
            thread::sleep(Duration::from_millis(50));
            c.write_all(format!("got {} bytes", req.len()).as_bytes()).unwrap();
        });
        let mut c = connect(addr);
        c.write_all(&[7u8; 100_000]).unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut got = String::new();
        c.read_to_string(&mut got).unwrap();
        assert_eq!(got, "got 100000 bytes", "{mode:?}");
    }
}

#[test]
fn half_close_from_the_server() {
    // The server says something and shuts down writing, but keeps reading: the client sees end of
    // file and can still send.
    for mode in MODES {
        let addr = setup(mode, 16, |mut c| {
            c.write_all(b"banner").unwrap();
            c.shutdown(Shutdown::Write).unwrap();
            let mut rest = Vec::new();
            c.read_to_end(&mut rest).unwrap();
            assert_eq!(rest, b"after eof");
        });
        let mut c = connect(addr);
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"banner", "{mode:?}");
        c.write_all(b"after eof").unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        // The connection ends once the server has read it all and closed.
        let mut tail = Vec::new();
        assert_eq!(c.read_to_end(&mut tail).unwrap(), 0);
    }
}

#[test]
fn many_concurrent_connections() {
    for mode in MODES {
        let addr = setup(mode, 256, echo);
        let clients: Vec<_> = (0..100u8)
            .map(|i| {
                thread::spawn(move || {
                    let mut c = connect(addr);
                    let data: Vec<u8> = (0..64 * 1024).map(|j| (j as u8).wrapping_mul(i)).collect();
                    let mut w = c.try_clone().unwrap();
                    let d = data.clone();
                    let writer = thread::spawn(move || {
                        w.write_all(&d).unwrap();
                        w.shutdown(Shutdown::Write).unwrap();
                    });
                    let mut got = Vec::new();
                    c.read_to_end(&mut got).unwrap();
                    writer.join().unwrap();
                    assert_eq!(got, data);
                })
            })
            .collect();
        for c in clients {
            c.join().unwrap();
        }
    }
}

#[test]
fn a_large_transfer() {
    const SIZE: usize = 256 << 20;
    for mode in MODES {
        // Download: the server streams SIZE bytes of a known pattern.
        let addr = setup(mode, 16, |mut c| {
            let chunk: Vec<u8> = (0..1 << 20).map(|i| (i % 251) as u8).collect();
            for _ in 0..SIZE >> 20 {
                c.write_all(&chunk).unwrap();
            }
        });
        let start = Instant::now();
        let mut c = connect(addr);
        let mut buf = vec![0u8; 1 << 20];
        let (mut total, mut pos) = (0usize, 0usize);
        loop {
            let n = c.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            for &b in &buf[..n] {
                assert_eq!(b, (pos % (1 << 20) % 251) as u8, "byte {pos}");
                pos += 1;
            }
            total += n;
        }
        assert_eq!(total, SIZE);
        eprintln!("{mode:?}: {} MB in {:?}", SIZE >> 20, start.elapsed());

        // Upload through echo, both directions at once.
        let addr = setup(mode, 16, echo);
        let mut c = connect(addr);
        let mut w = c.try_clone().unwrap();
        let writer = thread::spawn(move || {
            let chunk = vec![0x5au8; 1 << 20];
            for _ in 0..64 {
                w.write_all(&chunk).unwrap();
            }
            w.shutdown(Shutdown::Write).unwrap();
        });
        let mut total = 0;
        loop {
            let n = c.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            assert!(buf[..n].iter().all(|&b| b == 0x5a));
            total += n;
        }
        writer.join().unwrap();
        assert_eq!(total, 64 << 20);
    }
}

#[test]
fn the_connection_limit_holds_new_connections() {
    let addr = setup(CopyMode::ReadWrite, 2, echo);
    let mut a = connect(addr);
    let mut b = connect(addr);
    for c in [&mut a, &mut b] {
        c.write_all(b"x").unwrap();
        let mut one = [0u8; 1];
        c.read_exact(&mut one).unwrap();
    }
    // A third connection is accepted by the kernel but not relayed while two are open.
    let mut c = connect(addr);
    c.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    c.write_all(b"y").unwrap();
    let mut one = [0u8; 1];
    assert!(c.read_exact(&mut one).is_err(), "relayed past the limit");
    // Closing one lets it through.
    a.shutdown(Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    a.read_to_end(&mut rest).unwrap();
    drop(a);
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.read_exact(&mut one).unwrap();
    assert_eq!(&one, b"y");
}

#[test]
fn a_missing_socket_closes_the_connection() {
    let dir = tmpdir();
    let cfg = Config {
        listens: vec![spec::parse(Kind::Tcp, &format!("127.0.0.1:0={}", dir.join("absent.sock").display())).unwrap()],
        ..Config::default()
    };
    let addr = Forwarder::start(cfg).unwrap().addrs[0];
    let mut c = connect(addr);
    let mut got = Vec::new();
    // Closed, or reset: either way, nothing arrives and the read ends.
    let _ = c.read_to_end(&mut got);
    assert!(got.is_empty());
}

#[test]
fn an_address_that_never_appears_fails_after_the_timeout() {
    // 198.18.0.1 is wicket.internal in a box, never an address of the host running the tests.
    if wicket_fwd::is_local("198.18.0.1".parse().unwrap()) {
        eprintln!("skipped: this machine has 198.18.0.1");
        return;
    }
    let cfg = Config {
        listens: vec![spec::parse(Kind::Tcp, "198.18.0.1:3128=/wicket/sock/egress.sock").unwrap()],
        bind_timeout: Duration::from_millis(300),
        ..Config::default()
    };
    let start = Instant::now();
    let err = Forwarder::start(cfg).err().expect("bound an address that isn't there");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
    assert!(start.elapsed() >= Duration::from_millis(300));
}

#[test]
fn the_binary_refuses_bad_specs_and_serves_good_ones() {
    let bin = env!("CARGO_BIN_EXE_wicket-fwd");
    for bad in [vec!["--listen", "198.18.0.1:3128"], vec!["--listen", "wicket.internal:3128=/s"], vec![]] {
        let out = Command::new(bin).args(&bad).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
    }
    // A listener already in use is a fatal error at start, not a retry.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let out = Command::new(bin).args(["--listen", &format!("{}=/s", taken.local_addr().unwrap())]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("listen 127.0.0.1:"));
}

#[test]
fn dial_relays_stdin_and_stdout_with_half_close() {
    let bin = env!("CARGO_BIN_EXE_wicket-fwd");
    // A server that reads the whole request (to the client's half-close), then answers and closes.
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = server.local_addr().unwrap();
    thread::spawn(move || {
        for c in server.incoming().take(2) {
            let mut c = c.unwrap();
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            c.write_all(format!("got {} bytes", got.len()).as_bytes()).unwrap();
        }
    });
    for mode in ["splice", "rw"] {
        let mut child = Command::new(bin)
            .args(["--dial", &addr.to_string(), "--copy", mode])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&vec![7u8; 300_000]).unwrap();
        drop(stdin);
        let mut out = String::new();
        child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
        assert_eq!(out, "got 300000 bytes", "{mode}");
        assert!(child.wait().unwrap().success());
    }
    // Nothing listening: a failure, said on stderr.
    let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let out = Command::new(bin).args(["--dial", &gone.to_string()]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("dial 127.0.0.1:"));
}
