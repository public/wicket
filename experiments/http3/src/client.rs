//! A small HTTP/3 client (quinn + h3) for inside the box, and for the direct baseline on the host.
//! Names resolve through the platform resolver (getaddrinfo: musl in this static build), unless
//! `--connect host=ip:port` pins them. Prints one JSON line per request and one per connection.

use crate::certs;
use anyhow::{anyhow, Context, Result};
use bytes::{Buf, Bytes};
use serde_json::json;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Opts {
    pub ca: String,
    pub connect: HashMap<String, SocketAddr>,
    pub urls: Vec<String>,
    pub n: usize,
    pub conns: usize,
    pub zero_rtt: bool,
    pub rebind_after: Option<usize>,
    pub pause_secs: u64,
    pub mtu_upper: Option<u16>,
    pub gso: bool,
    pub idle_secs: u64,
    pub method: String,
    pub body_bytes: usize,
    pub quiet: bool,
    pub rcvbuf: Option<i32>,
}

fn now_ms(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 1e6).round() / 1e3
}

pub async fn run(o: Opts) -> Result<()> {
    let roots = std::fs::read_to_string(&o.ca).with_context(|| format!("reading {}", o.ca))?;
    let mut tls = certs::client_config(&roots, &[b"h3"])?;
    tls.enable_early_data = true;
    let mut cc = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(o.idle_secs).try_into()?));
    t.enable_segmentation_offload(o.gso);
    t.stream_receive_window((8u32 << 20).into());
    t.receive_window((16u32 << 20).into());
    if let Some(up) = o.mtu_upper {
        let mut m = quinn::MtuDiscoveryConfig::default();
        m.upper_bound(up);
        t.mtu_discovery_config(Some(m));
    }
    cc.transport_config(Arc::new(t));
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    if let Some(n) = o.rcvbuf {
        crate::wire::set_bufs(std::os::fd::AsRawFd::as_raw_fd(&sock), n);
    }
    let rcvbuf = getsockopt_int(std::os::fd::AsRawFd::as_raw_fd(&sock), libc::SO_RCVBUF);
    let gso = quinn::udp::UdpSocketState::new((&sock).into()).map(|s| s.max_gso_segments()).unwrap_or(0);
    let gro = quinn::udp::UdpSocketState::new((&sock).into()).map(|s| s.gro_segments()).unwrap_or(0);
    println!("{}", json!({"event": "socket", "so_rcvbuf": rcvbuf, "max_gso_segments": gso, "gro_segments": gro, "gso_enabled": o.gso}));
    let mut ep = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, sock, Arc::new(quinn::TokioRuntime))?;
    ep.set_default_client_config(cc);

    let first = o.urls.first().ok_or_else(|| anyhow!("no URL"))?;
    let host = first.parse::<http::Uri>()?.host().ok_or_else(|| anyhow!("URL without host"))?.to_string();
    let mut done = 0usize;
    for ci in 0..o.conns {
        let t0 = Instant::now();
        let addr = match o.connect.get(&host) {
            Some(a) => *a,
            None => (host.as_str(), 443).to_socket_addrs().with_context(|| format!("resolving {host}"))?.next().ok_or_else(|| anyhow!("{host}: no address"))?,
        };
        let dns_ms = now_ms(t0);
        let connecting = ep.connect(addr, &host)?;
        let (conn, early_send) = if o.zero_rtt && ci > 0 {
            match connecting.into_0rtt() {
                Ok((c, accepted)) => {
                    let early = Instant::now();
                    // The 0-RTT request goes before the handshake completes.
                    let (mut drv, mut send) = h3::client::new(h3_quinn::Connection::new(c.clone())).await?;
                    tokio::spawn(async move {
                        let _ = std::future::poll_fn(|cx| drv.poll_close(cx)).await;
                    });
                    let r = one(&mut send, first, &o.method, o.body_bytes).await;
                    let acc = accepted.await;
                    println!("{}", json!({"event": "zero-rtt", "offered": true, "accepted": acc, "request": r.as_ref().map(|r| r.status).ok(), "error": r.err().map(|e| format!("{e:#}")), "ms": now_ms(early)}));
                    (c, Some(send))
                }
                Err(connecting) => {
                    println!("{}", json!({"event": "zero-rtt", "offered": false, "why": "no 0-RTT-capable session ticket (server allows no early data)"}));
                    (connecting.await?, None)
                }
            }
        } else {
            (connecting.await?, None)
        };
        let hs_ms = now_ms(t0);
        let mut send = match early_send {
            Some(s) => s,
            None => {
                let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await?;
                tokio::spawn(async move {
                    let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                });
                send
            }
        };
        let ready_ms = now_ms(t0);
        println!("{}", json!({"event": "connected", "conn": ci, "addr": addr.to_string(), "dns_ms": dns_ms, "handshake_ms": hs_ms, "h3_ready_ms": ready_ms}));
        for url in &o.urls {
            for i in 0..o.n {
                if o.rebind_after == Some(done) {
                    let s = std::net::UdpSocket::bind("0.0.0.0:0")?;
                    let new = s.local_addr()?;
                    ep.rebind(s)?;
                    println!("{}", json!({"event": "rebind", "new_local_port": new.port()}));
                }
                if o.pause_secs > 0 && done == 1 {
                    println!("{}", json!({"event": "pause", "secs": o.pause_secs}));
                    tokio::time::sleep(Duration::from_secs(o.pause_secs)).await;
                }
                let r = one(&mut send, url, &o.method, o.body_bytes).await;
                done += 1;
                match r {
                    Ok(r) => {
                        let mut line = json!({"event": "response", "conn": ci, "i": i, "url": url, "status": r.status, "bytes": r.bytes,
                            "ttfb_ms": r.ttfb_ms, "total_ms": r.total_ms, "mbit_s": (r.bytes as f64 * 8.0 / 1e6) / (r.total_ms / 1e3)});
                        if !o.quiet && r.bytes < 2000 {
                            line["body"] = String::from_utf8_lossy(&r.body).into();
                            line["x_wicket"] = r.x_wicket.into();
                        }
                        println!("{line}");
                    }
                    Err(e) => println!("{}", json!({"event": "error", "conn": ci, "url": url, "error": format!("{e:#}")})),
                }
            }
        }
        let s = conn.stats();
        println!("{}", json!({"event": "conn-stats", "conn": ci, "rtt_us": s.path.rtt.as_micros() as u64, "mtu": s.path.current_mtu,
            "lost_packets": s.path.lost_packets, "sent_packets": s.path.sent_packets, "udp_tx": s.udp_tx.datagrams, "udp_rx": s.udp_rx.datagrams,
            "udp_tx_ios": s.udp_tx.ios, "udp_rx_ios": s.udp_rx.ios, "udp_rx_bytes": s.udp_rx.bytes, "congestion_events": s.path.congestion_events}));
        conn.close(0u32.into(), b"done");
        // Let the server's session ticket arrive for the next (resumed / 0-RTT) connection.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ep.wait_idle().await;
    Ok(())
}

struct Resp {
    status: u16,
    bytes: u64,
    ttfb_ms: f64,
    total_ms: f64,
    body: Vec<u8>,
    x_wicket: Option<String>,
}

async fn one(send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, url: &str, method: &str, body_bytes: usize) -> Result<Resp> {
    let t = Instant::now();
    let req = http::Request::builder().method(method).uri(url).body(())?;
    let mut s = send.send_request(req).await?;
    if body_bytes > 0 {
        s.send_data(Bytes::from(vec![b'b'; body_bytes])).await?;
    }
    s.finish().await?;
    let resp = s.recv_response().await?;
    let ttfb = now_ms(t);
    let x_wicket = resp.headers().get("x-wicket").and_then(|v| v.to_str().ok()).map(String::from);
    let mut bytes = 0u64;
    let mut body = Vec::new();
    while let Some(mut c) = s.recv_data().await? {
        bytes += c.remaining() as u64;
        if body.len() < 2000 {
            body.extend_from_slice(&c.copy_to_bytes(c.remaining().min(2000)));
        } else {
            c.advance(c.remaining());
        }
    }
    Ok(Resp { status: resp.status().as_u16(), bytes, ttfb_ms: ttfb, total_ms: now_ms(t), body, x_wicket })
}

/// getaddrinfo for each name, as the box's programs see it.
pub fn resolve(names: &[String]) {
    for n in names {
        let t = Instant::now();
        let r: Result<Vec<String>, _> = (n.as_str(), 443).to_socket_addrs().map(|i| i.map(|a| a.ip().to_string()).collect());
        match r {
            Ok(v) => println!("{}", json!({"name": n, "addrs": v, "ms": now_ms(t)})),
            Err(e) => println!("{}", json!({"name": n, "error": e.to_string(), "ms": now_ms(t)})),
        }
    }
}

fn getsockopt_int(fd: i32, opt: libc::c_int) -> i32 {
    let mut v: libc::c_int = 0;
    let mut l: libc::socklen_t = 4;
    unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, opt, &mut v as *mut _ as *mut _, &mut l) };
    v
}
