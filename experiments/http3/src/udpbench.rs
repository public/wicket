//! `udpbench`: what one UDP datagram costs on the box's loopback (question 5's attribution). A
//! receiver thread and a sender in one process; reports wall time and process CPU per datagram.
//! `--send sendto|mmsg` `--recv one|mmsg` `--n N` `--size BYTES` `--to IP:PORT`.

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Instant;

fn cpu_s() -> f64 {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    let t = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1e6;
    t(u.ru_utime) + t(u.ru_stime)
}

pub fn run(send: &str, recv: &str, n: usize, size: usize, to: SocketAddr) -> anyhow::Result<()> {
    let rx = UdpSocket::bind(to)?;
    let big: libc::c_int = 8 << 20;
    unsafe { libc::setsockopt(rx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, &big as *const _ as *const _, 4) };
    rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    let to = rx.local_addr()?;
    let recv_mmsg = recv == "mmsg";
    let r = std::thread::spawn(move || {
        let mut got = 0usize;
        let mut calls = 0usize;
        let mut bufs = vec![[0u8; 2048]; 32];
        let mut iovs: Vec<libc::iovec> =
            bufs.iter_mut().map(|b| libc::iovec { iov_base: b.as_mut_ptr() as *mut _, iov_len: 2048 }).collect();
        let mut msgs: Vec<libc::mmsghdr> = vec![unsafe { std::mem::zeroed() }; 32];
        for (m, iov) in msgs.iter_mut().zip(iovs.iter_mut()) {
            m.msg_hdr.msg_iov = iov;
            m.msg_hdr.msg_iovlen = 1;
        }
        let t0 = Instant::now();
        let mut last = t0;
        while got < n {
            let k = if recv_mmsg {
                // Block for the first (recvmsg), then take what's queued: gVisor refuses MSG_WAITFORONE.
                let a = unsafe { libc::recvmsg(rx.as_raw_fd(), &mut msgs[0].msg_hdr, 0) };
                if a < 0 {
                    break;
                }
                let b =
                    unsafe { libc::recvmmsg(rx.as_raw_fd(), msgs[1..].as_mut_ptr(), 31, libc::MSG_DONTWAIT as _, std::ptr::null_mut()) };
                calls += 2;
                1 + b.max(0) as usize
            } else {
                let a = unsafe { libc::recv(rx.as_raw_fd(), bufs[0].as_mut_ptr() as *mut _, 2048, 0) };
                calls += 1;
                if a < 0 {
                    break;
                }
                1
            };
            got += k;
            last = Instant::now();
        }
        (got, calls, last.duration_since(t0))
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    let tx = UdpSocket::bind((to.ip(), 0))?;
    tx.connect(to)?;
    let payload = vec![7u8; size];
    let (c0, t0) = (cpu_s(), Instant::now());
    let mut sent = 0;
    let mut send_calls = 0;
    while sent < n {
        if send == "mmsg" {
            let k = (n - sent).min(32);
            let mut iovs: Vec<libc::iovec> = (0..k).map(|_| libc::iovec { iov_base: payload.as_ptr() as *mut _, iov_len: size }).collect();
            let mut msgs: Vec<libc::mmsghdr> = vec![unsafe { std::mem::zeroed() }; k];
            for (m, iov) in msgs.iter_mut().zip(iovs.iter_mut()) {
                m.msg_hdr.msg_iov = iov;
                m.msg_hdr.msg_iovlen = 1;
            }
            let r = unsafe { libc::sendmmsg(tx.as_raw_fd(), msgs.as_mut_ptr(), k as _, 0) };
            if r > 0 {
                sent += r as usize;
            }
        } else {
            if tx.send(&payload).is_ok() {
                sent += 1;
            }
        }
        send_calls += 1;
        // Don't outrun the receiver by more than its buffer: pace every 512 datagrams.
        if sent % 512 == 0 {
            std::thread::yield_now();
        }
    }
    let send_wall = t0.elapsed();
    let (got, recv_calls, recv_wall) = r.join().unwrap();
    let cpu = cpu_s() - c0;
    println!(
        "{}",
        serde_json::json!({"event": "udpbench", "send": send, "recv": recv, "n": n, "size": size, "got": got, "lost": n - got,
            "send_calls": send_calls, "recv_calls": recv_calls, "send_us_per_dgram": send_wall.as_secs_f64() * 1e6 / n as f64,
            "recv_wall_s": recv_wall.as_secs_f64(), "cpu_us_per_dgram": cpu * 1e6 / got.max(1) as f64,
            "mb_s": (got * size) as f64 / recv_wall.as_secs_f64() / 1e6})
    );
    Ok(())
}
