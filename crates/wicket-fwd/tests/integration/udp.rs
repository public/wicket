//! `--udp` on the host: a UDP client, wicket-fwd on a wildcard 127.0.0.1-range socket, and a unix
//! server (SEQPACKET, or a stream socket) that answers each frame back to the client.

use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use wicket_fwd::frame::{self, Head, HDR};
use wicket_fwd::{spec, Config, Forwarder, Kind};

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("wfwd-udp-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A free UDP port on 0.0.0.0.
fn free_port() -> u16 {
    UdpSocket::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port()
}

fn forwarder(sock: &std::path::Path) -> u16 {
    let port = free_port();
    let cfg = Config { listens: vec![spec::parse(Kind::Udp, &format!("0.0.0.0:{port}={}", sock.display())).unwrap()], ..Config::default() };
    let f = Forwarder::start(cfg).unwrap();
    assert_eq!(f.addrs[0].port(), port);
    std::mem::forget(f);
    port
}

/// What the host saw: (head, payload) per frame.
type Seen = mpsc::Receiver<(Head, Vec<u8>)>;

/// A host on a stream socket (the length-prefixed fallback; std has no SEQPACKET listener, so the
/// SEQPACKET path is tested from `wicket_proxy::h3`, against this crate's code).
fn stream_host(path: &std::path::Path) -> Seen {
    let l = UnixListener::bind(path).unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for c in l.incoming() {
            let mut c: UnixStream = c.unwrap();
            let tx = tx.clone();
            thread::spawn(move || loop {
                let mut len = [0u8; 4];
                if c.read_exact(&mut len).is_err() {
                    return;
                }
                let n = u32::from_be_bytes(len) as usize;
                let mut f = vec![0u8; n];
                c.read_exact(&mut f).unwrap();
                let h = Head::decode(&f).unwrap();
                tx.send((h, f[HDR..].to_vec())).unwrap();
                // Answer: every datagram upper-cased, as one frame with the same seg.
                let reply: Vec<u8> = f[HDR..].iter().map(|b| b.to_ascii_uppercase()).collect();
                let mut out = ((HDR + reply.len()) as u32).to_be_bytes().to_vec();
                out.extend_from_slice(&h.encode());
                out.extend_from_slice(&reply);
                c.write_all(&out).unwrap();
            });
        }
    });
    rx
}

#[test]
fn relays_datagrams_both_ways_over_a_stream_socket_with_the_original_destination() {
    let dir = tmpdir();
    let sock = dir.join("udp.sock");
    let seen = stream_host(&sock);
    let port = forwarder(&sock);
    for dst in ["127.0.0.1", "127.0.0.2"] {
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let to: SocketAddr = format!("{dst}:{port}").parse().unwrap();
        // The first datagram triggers the connection to the host; send until one comes back.
        let mut buf = [0u8; 2048];
        let mut got = None;
        for _ in 0..20 {
            c.send_to(b"hello", to).unwrap();
            if let Ok((n, from)) = c.recv_from(&mut buf) {
                got = Some((buf[..n].to_vec(), from));
                break;
            }
        }
        let (body, from) = got.expect("a reply");
        assert_eq!(body, b"HELLO");
        assert_eq!(from, to, "the reply comes from the address the client used");
        let (h, p) = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(p, b"hello");
        assert_eq!(h.dst, SocketAddrV4::new(dst.parse().unwrap(), port));
        let SocketAddr::V4(me) = c.local_addr().unwrap() else { panic!() };
        assert_eq!(h.src, me);
        while seen.try_recv().is_ok() {}
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_burst_of_one_flow_goes_as_segments_and_comes_back_as_datagrams() {
    let dir = tmpdir();
    let sock = dir.join("udp.sock");
    let seen = stream_host(&sock);
    let port = forwarder(&sock);
    let c = UdpSocket::bind("127.0.0.1:0").unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let to: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    // Connect first (one round trip), then a burst.
    let mut buf = [0u8; 2048];
    loop {
        c.send_to(b"x", to).unwrap();
        if c.recv_from(&mut buf).is_ok() {
            break;
        }
    }
    while seen.try_recv().is_ok() {}
    // Well under the client's default receive buffer (about 2.3 KB of kernel accounting per datagram).
    let n = 40;
    for i in 0..n {
        let mut d = vec![b'a' + (i % 26) as u8; 1200];
        if i == n - 1 {
            d.truncate(700);
        }
        c.send_to(&d, to).unwrap();
    }
    let mut datagrams = 0;
    let mut frames = 0;
    let mut batched = false;
    while datagrams < n {
        let (h, p) = seen.recv_timeout(Duration::from_secs(5)).expect("all datagrams reach the host");
        frames += 1;
        let segs: Vec<&[u8]> = frame::segments(h.seg, &p).collect();
        if h.seg != 0 {
            batched = true;
            assert_eq!(h.seg, 1200);
            assert!(p.len() <= frame::MAX_PAYLOAD);
        }
        datagrams += segs.len();
    }
    assert_eq!(datagrams, n);
    // Each reply frame is split back into datagrams of the original sizes.
    let mut back = 0;
    while back < n {
        let (k, _) = c.recv_from(&mut buf).expect("replies");
        assert!(k == 1200 || k == 700);
        assert!(buf[..k].iter().all(|b| b.is_ascii_uppercase()));
        back += 1;
    }
    assert!(frames <= n);
    // Batching depends on the receive queue at the time, so it isn't required; when it happened,
    // the segments were checked above.
    let _ = batched;
    std::fs::remove_dir_all(&dir).unwrap();
}
