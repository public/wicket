//! HTTP/3 egress (#92): wicket's DNS and QUIC termination for a box, over the box's UDP forwarder.
//!
//! HTTP/3 can't go through a CONNECT proxy: a client sends QUIC straight to the origin's address. So
//! the box resolves names through wicket ([`crate::dns`]): a host the zone can reach gets a synthetic
//! address in 198.19.0.0/16, which `wicket-entry` makes local on the box's `lo`, and `wicket-fwd`
//! relays every datagram to it (and every DNS query to wicket.internal:53) over the run's
//! `udp.sock`, in `wicket_fwd::frame`s. Here, on the host:
//!
//! - **DNS** queries are answered from the zone (NXDOMAIN for hidden and forbidden hosts).
//! - **QUIC** is terminated by quinn, as the host the destination address was minted for, with a
//!   leaf from the same [`Minter`](crate::ca::Minter) as the CONNECT proxy (the run's CA, or a node's
//!   CA). The ClientHello must name that host, and every request's `:authority` must be it (421
//!   otherwise): one connection serves one host.
//! - **Each request** goes through the egress proxy's own path, [`Egress::handle`]: the same
//!   canonical paths, decisions (reach, forbid, risk, grants, pending requests, node policy),
//!   credential injection and audit as HTTP/1.1 through CONNECT. Upstream it is re-originated over
//!   HTTP/3 when the origin offers it, raced against HTTP/2 ([`Up`]), else HTTP/2 or HTTP/1.1.
//! - **A superseded activation** (#70: its agent was woken again) is refused like everywhere else:
//!   no DNS answers, no QUIC connections, and every request on an open one gets the egress proxy's 403.
//! - **0-RTT is refused** (no early data is ever accepted: a replayed request would replay a request
//!   that was already decided and audited). **Migration** is on: only the client's port inside the
//!   box can change, and the frame carries it. The **idle timeout** is 30 s.
//! - **MTU**: the box leg is loopback plus a unix socket. Under gVisor each UDP datagram costs about
//!   110 µs of CPU in the box, so throughput is bound by datagrams, not bytes (#92's measurements:
//!   40–100 Mbit/s at the usual 1452-byte MTU, 430–460 Mbit/s with path MTU discovery allowed up to
//!   16000, for clients that advertise large datagrams). The default stays conservative (quinn's
//!   1452 bound); [`Options::box_mtu`] (`WICKET_H3_BOX_MTU=16000`) raises it. Bounds of 32000 and
//!   up measured faster still (545–573 Mbit/s at 60000) but added ~60 ms to the first request on a
//!   new connection, unexplained; 16000 is the value to use.
//!
//! On a remote node, hosts the node forwards to the control host (`decide::route`: credentials to
//! inject, or outside what the node's CA may mint) aren't served over HTTP/3: the QUIC handshake is
//! refused (audited once, with the reason), so clients fall back to TCP through the proxy, which
//! forwards them. Should a host's route change mid-connection, its requests get a 403 that says so.

use crate::dns::{self, Answered, Names};
use crate::egress::{Egress, Outgoing, Upstream, Via};
use crate::{problem, BoxBody, Event};
use anyhow::{anyhow, Context as _, Result};
use bytes::{Buf, Bytes};
use http::{Request, Response};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use wicket_core::HostVerdict;
use wicket_fwd::frame::{self, Head, HDR, MAX_FRAME, MAX_PAYLOAD};

/// QUIC's port in the box; DNS is the other.
const QUIC_PORT: u16 = 443;
const DNS_PORT: u16 = 53;
/// Datagrams from the box waiting for quinn, per relay connection; more are dropped (UDP).
const INBOUND_QUEUE: usize = 4096;
/// Frames waiting to go to the box, per relay connection; more are dropped (UDP), so a box that
/// stops reading its socket can't grow the host's memory.
const OUTBOUND_QUEUE: usize = 4096;
/// Unknown addresses whose refusal is audited (once each); beyond that, refusals aren't logged.
const MAX_REFUSAL_NOTES: usize = 1024;
/// How long a request waits for a new HTTP/3 upstream connection before going over HTTP/2.
const RACE: Duration = Duration::from_millis(250);
/// How long an origin that didn't answer HTTP/3 is left on HTTP/2 before trying again.
const NO_H3_FOR: Duration = Duration::from_secs(600);

/// HTTP/3 settings for a run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Answer HTTPS (type 65) queries with `alpn="h3"` (default on).
    pub https_records: bool,
    /// The largest datagram on the box leg (path MTU discovery's upper bound, and the largest UDP
    /// payload advertised to the client). None: quinn's default (1452).
    pub box_mtu: Option<u16>,
    /// QUIC idle timeout towards the box (at least 30 s).
    pub idle: Duration,
}

impl Options {
    /// The defaults, with `WICKET_H3_BOX_MTU` (1200–65535; e.g. 16000) raising the box leg's MTU and
    /// `WICKET_H3_HTTPS_RECORDS=0` turning HTTPS records off.
    pub fn from_env() -> Options {
        let mut o = Options::default();
        if let Some(m) = std::env::var("WICKET_H3_BOX_MTU").ok().and_then(|v| v.parse::<u16>().ok()).filter(|m| *m >= 1200) {
            o.box_mtu = Some(m);
        }
        if std::env::var("WICKET_H3_HTTPS_RECORDS").is_ok_and(|v| v == "0") {
            o.https_records = false;
        }
        o
    }
}

impl Default for Options {
    fn default() -> Self {
        Options { https_records: true, box_mtu: None, idle: Duration::from_secs(30) }
    }
}

/// A run's DNS and HTTP/3 server, in front of its egress proxy.
pub struct H3 {
    egress: Arc<Egress>,
    names: Arc<Names>,
    opts: Options,
    transport: Arc<quinn::TransportConfig>,
    per_host: Mutex<HashMap<String, quinn::ServerConfig>>,
    /// What has been refused and audited already (each once, up to [`MAX_REFUSAL_NOTES`]).
    noted: Mutex<std::collections::HashSet<String>>,
}

impl H3 {
    pub fn new(egress: Arc<Egress>, opts: Options) -> Result<Arc<H3>> {
        let mut t = quinn::TransportConfig::default();
        t.max_idle_timeout(Some(opts.idle.max(Duration::from_secs(30)).try_into()?));
        if let Some(m) = opts.box_mtu {
            let mut d = quinn::MtuDiscoveryConfig::default();
            d.upper_bound(m.clamp(1200, MAX_PAYLOAD as u16));
            t.mtu_discovery_config(Some(d));
        }
        // Room for a fast box to download without waiting on flow control (quinn's defaults are
        // sized for long, lossy paths' memory use; this path is local).
        t.stream_receive_window((8u32 << 20).into());
        t.receive_window((16u32 << 20).into());
        t.send_window(16 << 20);
        Ok(Arc::new(H3 {
            egress,
            names: Arc::new(Names::new()),
            opts,
            transport: Arc::new(t),
            per_host: Default::default(),
            noted: Default::default(),
        }))
    }

    /// The run's host <-> synthetic address map.
    pub fn names(&self) -> &Arc<Names> {
        &self.names
    }

    /// Serves the box's forwarder on a `SOCK_SEQPACKET` unix socket at `socket`, until dropped.
    pub async fn serve(self: Arc<Self>, socket: &Path) -> Result<()> {
        let listener = seqpacket_listen(socket)?;
        loop {
            let mut g = listener.readable().await?;
            let fd = match g.try_io(|l| seqpacket_accept(l.as_raw_fd())) {
                Ok(Ok(fd)) => fd,
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "udp relay accept");
                    continue;
                }
                Err(_would_block) => continue,
            };
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.relay(Link::Seqpacket(register(fd)?)).await {
                    tracing::debug!(error = %e, "udp relay ended");
                }
                Ok::<_, io::Error>(())
            });
        }
    }

    /// As [`H3::serve`], on a stream socket (frames after a 4-byte length): for a box on a remote
    /// node whose sockets are forwarded over SSH, which carries only streams.
    pub async fn serve_stream(self: Arc<Self>, socket: &Path) -> Result<()> {
        let _ = std::fs::remove_file(socket);
        let listener = tokio::net::UnixListener::bind(socket)?;
        loop {
            let (s, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.relay(Link::Stream(s)).await {
                    tracing::debug!(error = %e, "udp relay ended");
                }
            });
        }
    }

    /// One forwarder connection: DNS answered here, QUIC handed to a quinn endpoint of its own.
    async fn relay(self: Arc<Self>, link: Link) -> Result<()> {
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_QUEUE);
        let (in_tx, in_rx) = mpsc::channel::<Datagram>(INBOUND_QUEUE);
        let socket = Arc::new(RelaySocket {
            inbound: Mutex::new((in_rx, VecDeque::new())),
            out: out_tx.clone(),
            gso: (MAX_PAYLOAD / self.opts.box_mtu.unwrap_or(1452).max(1200) as usize).clamp(1, 32),
        });
        let mut ep_cfg = quinn::EndpointConfig::default();
        if let Some(m) = self.opts.box_mtu {
            ep_cfg.max_udp_payload_size(m.clamp(1200, MAX_PAYLOAD as u16))?;
        }
        // quinn surfaces incoming connections only to an endpoint with a server config; each is then
        // accepted with its own host's config, so this one never serves a handshake.
        let ep = quinn::Endpoint::new_with_abstract_socket(ep_cfg, Some(self.placeholder()?), socket, Arc::new(quinn::TokioRuntime))?;
        let me = self.clone();
        let accept = tokio::spawn(async move {
            while let Some(inc) = ep.accept().await {
                let me = me.clone();
                tokio::spawn(async move { me.connection(inc).await });
            }
        });
        let (reader, writer) = link.split()?;
        let w = tokio::spawn(write_frames(writer, out_rx));
        let r = self.read_frames(reader, in_tx, out_tx).await;
        accept.abort();
        w.abort();
        r
    }

    /// Box -> host: DNS answered at once, QUIC datagrams queued for quinn.
    async fn read_frames(&self, mut reader: Reader, in_tx: mpsc::Sender<Datagram>, out: mpsc::Sender<Vec<u8>>) -> Result<()> {
        let mut buf = vec![0u8; MAX_FRAME + 4];
        loop {
            let n = reader.recv(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            let Some(head) = Head::decode(&buf[..n]) else { continue };
            let payload = &buf[HDR..n];
            match head.dst.port() {
                DNS_PORT => {
                    if let Some(reply) = self.dns(payload) {
                        let mut f = Vec::with_capacity(HDR + reply.len());
                        f.extend_from_slice(&Head { seg: 0, ..head }.encode());
                        f.extend_from_slice(&reply);
                        let _ = out.try_send(f);
                    }
                }
                QUIC_PORT => {
                    for d in frame::segments(head.seg, payload) {
                        // A full queue drops, as a full socket buffer would; QUIC retransmits.
                        let _ = in_tx.try_send(Datagram { src: head.src, dst: *head.dst.ip(), data: Bytes::copy_from_slice(d) });
                    }
                }
                _ => {}
            }
        }
    }

    /// Answers one DNS query from the zone, auditing each host the first time it resolves (or is
    /// refused).
    fn dns(&self, q: &[u8]) -> Option<Vec<u8>> {
        let e = &self.egress;
        // A superseded activation (#70) resolves nothing, unaudited (it is refused everywhere).
        let stale = e.ctx.superseded().is_some();
        let reachable = |h: &str| !stale && e.decider.host_verdict(&e.ctx, h) == HostVerdict::Open;
        let (reply, what) = dns::answer(&self.names, q, self.opts.https_records, reachable)?;
        if stale {
            return Some(reply);
        }
        let emit = |host: &str, outcome: &str, detail: String| {
            e.ctx.emit(Event::Egress {
                method: "DNS".into(),
                host: host.into(),
                path: String::new(),
                risk: "-".into(),
                outcome: outcome.into(),
                detail,
            })
        };
        match what {
            Answered::Resolved { name, ip, fresh: true } => emit(&name, "allow", format!("resolved to {ip} (wicket DNS, for HTTP/3)")),
            Answered::Refused { name, first: true } => emit(&name, "hidden", "NXDOMAIN: not a host this zone can reach".into()),
            _ => {}
        }
        Some(reply)
    }

    /// A server config that only lets quinn surface incoming connections (see [`H3::relay`]):
    /// a throwaway self-signed certificate, never presented.
    fn placeholder(&self) -> Result<quinn::ServerConfig> {
        let ck = rcgen::generate_simple_self_signed(vec!["placeholder.invalid".to_string()])?;
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![ck.cert.der().clone()], key)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let qc = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| anyhow!("QUIC TLS config: {e}"))?;
        Ok(quinn::ServerConfig::with_crypto(Arc::new(qc)))
    }

    /// The QUIC server config for `host`: a leaf from the run's minter, HTTP/3 only, no early data.
    fn server_config(&self, host: &str) -> Result<quinn::ServerConfig> {
        if let Some(c) = self.per_host.lock().expect("per_host").get(host) {
            return Ok(c.clone());
        }
        let mut tls = (*self.egress.ca.server_config(host)?).clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.max_early_data_size = 0;
        tls.send_half_rtt_data = false;
        let qc = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| anyhow!("QUIC TLS config: {e}"))?;
        let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qc));
        sc.transport_config(self.transport.clone());
        sc.migration(true);
        self.per_host.lock().expect("per_host").insert(host.to_string(), sc.clone());
        Ok(sc)
    }

    /// Audits a refused connection, once per host and reason: a box retrying (or flooding) gets
    /// no more log lines than it has distinct targets, up to a cap.
    fn refused(&self, host: &str, why: String) {
        {
            let mut n = self.noted.lock().expect("noted");
            if n.len() >= MAX_REFUSAL_NOTES || !n.insert(format!("{host} {why}")) {
                return;
            }
        }
        self.egress.ctx.emit(Event::Egress {
            method: "QUIC".into(),
            host: host.into(),
            path: String::new(),
            risk: "-".into(),
            outcome: "forbidden".into(),
            detail: why,
        });
    }

    async fn connection(self: Arc<Self>, inc: quinn::Incoming) {
        // The connection is the host its destination address was minted for, nothing else.
        let host = match inc.local_ip() {
            Some(IpAddr::V4(ip)) => self.names.name_of(ip),
            _ => None,
        };
        let Some(host) = host else {
            self.refused(&format!("{:?}", inc.local_ip()), "QUIC to an address wicket's DNS didn't hand out".into());
            inc.refuse();
            return;
        };
        // A superseded activation (#70) gets no connection at all, as it gets no CONNECT tunnel.
        if let Some(why) = self.egress.ctx.superseded() {
            self.refused(&host, why);
            inc.refuse();
            return;
        }
        if self.egress.decider.host_verdict(&self.egress.ctx, &host) != HostVerdict::Open {
            inc.refuse();
            return;
        }
        // On a node, a host it forwards to the control host isn't served over HTTP/3 (the node
        // usually can't mint a leaf for it, and the control host isn't reached over UDP): the
        // handshake is refused, and HTTP/3 clients fall back to TCP through the proxy, which forwards it.
        if let Some(relay) = &self.egress.relay {
            if let crate::decide::Route::Forward(why) = relay.route(&host) {
                self.refused(&host, format!("HTTP/3 to {host} isn't served on this node ({why}); HTTPS through the proxy reaches it"));
                inc.refuse();
                return;
            }
        }
        let cfg = match self.server_config(&host) {
            Ok(c) => c,
            Err(e) => {
                self.refused(&host, format!("no certificate for {host}: {e:#}"));
                inc.refuse();
                return;
            }
        };
        let conn = match inc.accept_with(Arc::new(cfg)) {
            Ok(c) => match c.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(%host, error = %e, "QUIC handshake failed");
                    return;
                }
            },
            Err(e) => {
                tracing::debug!(%host, error = %e, "QUIC accept failed");
                return;
            }
        };
        let sni = conn.handshake_data().and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok()).and_then(|h| h.server_name);
        if !sni.as_deref().is_some_and(|s| s.trim_end_matches('.').eq_ignore_ascii_case(&host)) {
            self.refused(
                &host,
                format!("the TLS server name ({}) is not the host this address stands for", sni.as_deref().unwrap_or("none")),
            );
            conn.close(0x0101u32.into(), b"wicket: the server name does not match the address");
            return;
        }
        let mut h3c: h3::server::Connection<h3_quinn::Connection, Bytes> =
            match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(%host, error = %e, "HTTP/3 setup failed");
                    return;
                }
            };
        loop {
            match h3c.accept().await {
                Ok(Some(resolver)) => {
                    let (me, host) = (self.clone(), host.clone());
                    tokio::spawn(async move {
                        match resolver.resolve_request().await {
                            Ok((req, stream)) => me.request(host, req, stream).await,
                            Err(e) => tracing::debug!(error = %e, "HTTP/3 request head"),
                        }
                    });
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(%host, error = %e, "HTTP/3 connection ended");
                    break;
                }
            }
        }
    }

    async fn request(
        self: Arc<Self>,
        host: String,
        req: Request<()>,
        stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) {
        let (mut send, recv) = stream.split();
        let resp = self.decide(&host, req, recv).await;
        if let Err(e) = send_response(&mut send, resp).await {
            tracing::debug!(%host, error = %e, "HTTP/3 response");
        }
    }

    async fn decide(
        self: &Arc<Self>,
        host: &str,
        req: Request<()>,
        recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
    ) -> Response<BoxBody> {
        let method = req.method().to_string();
        let authority = req.uri().host().map(|h| h.trim_end_matches('.').to_ascii_lowercase());
        if authority.as_deref() != Some(host) {
            let asked = authority.unwrap_or_default();
            self.egress.ctx.emit(Event::Egress {
                method: method.clone(),
                host: host.into(),
                path: "/".into(),
                risk: "-".into(),
                outcome: "forbidden".into(),
                detail: format!("HTTP/3 request for {asked} on {host}'s connection"),
            });
            return problem(
                421,
                "misdirected",
                "Blocked by wicket sandbox: wrong host for this connection",
                &format!("This HTTP/3 connection serves {host} only; connect to {asked} separately. {}", crate::SANDBOX_FACT),
                None,
            );
        }
        if let Some(relay) = &self.egress.relay {
            if let crate::decide::Route::Forward(why) = relay.route(host) {
                return self.egress.refuse(
                    host,
                    &method,
                    "/",
                    &format!(
                        "HTTP/3 to {host} isn't served on this node ({why}); use HTTPS through the proxy (HTTPS_PROXY), which reaches it"
                    ),
                );
            }
        }
        let body = StreamBody::new(futures_util::stream::unfold(recv, |mut r| async move {
            match r.recv_data().await {
                Ok(Some(mut b)) => Some((Ok(Frame::data(b.copy_to_bytes(b.remaining()))), r)),
                Ok(None) => None,
                Err(e) => Some((Err(io::Error::other(e.to_string())), r)),
            }
        }));
        let (parts, ()) = req.into_parts();
        self.egress.clone().handle(Request::from_parts(parts, body), host.to_string(), "https", Via::H3).await
    }
}

/// Sends a response (head, then its body as it arrives) on an HTTP/3 request stream.
async fn send_response(send: &mut h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>, resp: Response<BoxBody>) -> Result<()> {
    let (parts, mut body) = resp.into_parts();
    send.send_response(Response::from_parts(parts, ())).await?;
    while let Some(f) = body.frame().await {
        match f {
            Ok(f) => {
                if let Ok(d) = f.into_data() {
                    if !d.is_empty() {
                        send.send_data(d).await?;
                    }
                }
            }
            Err(e) => {
                send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                return Err(anyhow!("upstream body: {e}"));
            }
        }
    }
    send.finish().await?;
    Ok(())
}

/// A datagram from the box, for quinn.
struct Datagram {
    src: SocketAddrV4,
    dst: Ipv4Addr,
    data: Bytes,
}

/// quinn's socket: datagrams to and from the box, through the relay connection's tasks.
struct RelaySocket {
    inbound: Mutex<(mpsc::Receiver<Datagram>, VecDeque<Datagram>)>,
    out: mpsc::Sender<Vec<u8>>,
    /// Datagrams per frame towards the box (quinn's GSO batches).
    gso: usize,
}

impl fmt::Debug for RelaySocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelaySocket")
    }
}

impl AsyncUdpSocket for RelaySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        // Nothing but the box is on the other side: anything else is dropped.
        let (SocketAddr::V4(to), Some(IpAddr::V4(from))) = (t.destination, t.src_ip) else { return Ok(()) };
        let seg = t.segment_size.filter(|&s| s < t.contents.len()).unwrap_or(0) as u16;
        let mut f = Vec::with_capacity(HDR + t.contents.len());
        f.extend_from_slice(&Head { seg, src: to, dst: SocketAddrV4::new(from, QUIC_PORT) }.encode());
        f.extend_from_slice(t.contents);
        match self.out.try_send(f) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()), // full: dropped, as UDP would
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "box relay closed")),
        }
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let mut g = self.inbound.lock().expect("inbound");
        let (rx, queued) = &mut *g;
        if queued.is_empty() {
            match ready!(rx.poll_recv(cx)) {
                Some(d) => queued.push_back(d),
                None => return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "box relay closed"))),
            }
        }
        while queued.len() < bufs.len() {
            match rx.try_recv() {
                Ok(d) => queued.push_back(d),
                Err(_) => break,
            }
        }
        let mut n = 0;
        while n < bufs.len() {
            let Some(d) = queued.pop_front() else { break };
            if d.data.len() > bufs[n].len() {
                continue; // larger than quinn takes: dropped, as the kernel would truncate it
            }
            bufs[n][..d.data.len()].copy_from_slice(&d.data);
            meta[n] = RecvMeta {
                addr: SocketAddr::V4(d.src),
                len: d.data.len(),
                stride: d.data.len(),
                ecn: None,
                dst_ip: Some(IpAddr::V4(d.dst)),
            };
            n += 1;
        }
        if n == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), QUIC_PORT))
    }

    fn max_transmit_segments(&self) -> usize {
        self.gso
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    /// Unix sockets never fragment.
    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// One forwarder connection, before it's split into its two directions.
enum Link {
    Seqpacket(AsyncFd<OwnedFd>),
    Stream(tokio::net::UnixStream),
}

enum Reader {
    Seqpacket(Arc<AsyncFd<OwnedFd>>),
    Stream(tokio::net::unix::OwnedReadHalf),
}

enum Writer {
    Seqpacket(Arc<AsyncFd<OwnedFd>>),
    Stream(tokio::net::unix::OwnedWriteHalf),
}

impl Link {
    fn split(self) -> io::Result<(Reader, Writer)> {
        Ok(match self {
            Link::Seqpacket(fd) => {
                let fd = Arc::new(fd);
                (Reader::Seqpacket(fd.clone()), Writer::Seqpacket(fd))
            }
            Link::Stream(s) => {
                let (r, w) = s.into_split();
                (Reader::Stream(r), Writer::Stream(w))
            }
        })
    }
}

impl Reader {
    /// One frame into `buf`; 0 at end.
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Reader::Seqpacket(fd) => loop {
                let mut g = fd.readable().await?;
                match g.try_io(|f| sys_recv(f.as_raw_fd(), buf)) {
                    Ok(r) => return r,
                    Err(_would_block) => continue,
                }
            },
            Reader::Stream(s) => {
                let mut len = [0u8; 4];
                match s.read_exact(&mut len).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                    Err(e) => return Err(e),
                }
                let n = u32::from_be_bytes(len) as usize;
                if !(HDR..=MAX_FRAME).contains(&n) || n > buf.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("frame of {n} bytes")));
                }
                s.read_exact(&mut buf[..n]).await?;
                Ok(n)
            }
        }
    }
}

/// Host -> box: frames written as they come.
async fn write_frames(mut w: Writer, mut rx: mpsc::Receiver<Vec<u8>>) -> io::Result<()> {
    while let Some(f) = rx.recv().await {
        match &mut w {
            Writer::Seqpacket(fd) => loop {
                let mut g = fd.writable().await?;
                match g.try_io(|s| sys_send(s.as_raw_fd(), &f)) {
                    Ok(Ok(_)) => break,
                    // The box is gone or the frame is refused: drop it, as UDP would.
                    Ok(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe || e.kind() == io::ErrorKind::ConnectionReset => return Err(e),
                    Ok(Err(_)) => break,
                    Err(_would_block) => continue,
                }
            },
            Writer::Stream(s) => {
                s.write_all(&(f.len() as u32).to_be_bytes()).await?;
                s.write_all(&f).await?;
            }
        }
    }
    Ok(())
}

fn cvt(r: isize) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

fn sys_recv(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buf` is valid for writes of its length for the duration of the call.
    cvt(unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) })
}

fn sys_send(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: `buf` is valid for reads of its length for the duration of the call.
    cvt(unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), libc::MSG_NOSIGNAL) })
}

fn sockaddr_un(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: sockaddr_un is plain data; all zeroes is a valid (empty) value.
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let b = path.as_os_str().as_bytes();
    if b.len() >= a.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long"));
    }
    for (d, s) in a.sun_path.iter_mut().zip(b) {
        *d = *s as libc::c_char;
    }
    Ok((a, (std::mem::size_of::<libc::sa_family_t>() + b.len() + 1) as libc::socklen_t))
}

fn set_bufs(fd: RawFd) {
    let n: libc::c_int = 4 << 20;
    for o in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: the option value is a live c_int.
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, o, &n as *const libc::c_int as *const libc::c_void, 4) };
    }
}

/// A nonblocking `SOCK_SEQPACKET` listener at `path` (replacing a stale socket), with the same mode
/// as the proxies' sockets beside it.
fn seqpacket_listen(path: &Path) -> Result<AsyncFd<OwnedFd>> {
    let _ = std::fs::remove_file(path);
    // SAFETY: plain socket(2); checked before use.
    let fd = cvt(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) } as isize)?;
    // SAFETY: socket succeeded: a fresh descriptor owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    let (a, len) = sockaddr_un(path)?;
    // SAFETY: `a` is a valid sockaddr_un of `len` bytes.
    cvt(unsafe { libc::bind(fd.as_raw_fd(), &a as *const libc::sockaddr_un as *const libc::sockaddr, len) } as isize)
        .with_context(|| format!("binding {}", path.display()))?;
    // SAFETY: listen on a bound socket.
    cvt(unsafe { libc::listen(fd.as_raw_fd(), 16) } as isize)?;
    Ok(register(fd)?)
}

fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: the descriptor is owned by the AsyncFd from here on, and closed only when it drops.
    unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)
}

fn seqpacket_accept(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: accept4 on a listening socket, without the peer's address.
    let c =
        cvt(unsafe { libc::accept4(fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) } as isize)?;
    set_bufs(c as RawFd);
    // SAFETY: accept4 succeeded: a fresh descriptor owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(c as RawFd) })
}

/// HTTP/3 to origins: one pooled QUIC connection per host, raced against HTTP/2.
///
/// A request that arrived over HTTP/3 goes over HTTP/3 if the origin's connection is up, or comes up
/// within [`RACE`]. Otherwise it goes over HTTP/2 (the egress proxy's ordinary client) while the
/// HTTP/3 attempt carries on for later requests; an origin that refuses HTTP/3 (or times out) is
/// left on HTTP/2 for [`NO_H3_FOR`].
pub(crate) struct Up {
    ep: quinn::Endpoint,
    resolve: HashMap<String, SocketAddr>,
    /// Names are resolved and checked as for HTTP/2 (`crate::dial`, #116).
    lookup: crate::dial::Lookup,
    state: Arc<Mutex<HashMap<String, State>>>,
}

#[derive(Clone)]
enum State {
    Ready(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>),
    /// Connecting since then: requests wait for it only within [`RACE`] of the start.
    Connecting(tokio::sync::watch::Receiver<bool>, Instant),
    NoH3(Instant),
}

impl Up {
    pub(crate) fn new(u: &Upstream) -> Result<Up> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = &u.roots_pem {
            for c in rustls::pki_types::pem::PemObject::pem_slice_iter(pem.as_bytes()) {
                let c: rustls::pki_types::CertificateDer<'static> = c.map_err(|e| anyhow!("upstream roots: {e:?}"))?;
                roots.add(c)?;
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let qc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| anyhow!("QUIC client TLS: {e}"))?;
        let mut cc = quinn::ClientConfig::new(Arc::new(qc));
        let mut t = quinn::TransportConfig::default();
        t.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
        t.keep_alive_interval(Some(Duration::from_secs(10)));
        cc.transport_config(Arc::new(t));
        let mut ep = quinn::Endpoint::client("[::]:0".parse()?).or_else(|_| quinn::Endpoint::client("0.0.0.0:0".parse().expect("addr")))?;
        ep.set_default_client_config(cc);
        Ok(Up { ep, resolve: u.resolve.clone(), lookup: u.lookup(), state: Default::default() })
    }

    /// Sends `out` over HTTP/3 if that's available now (see the type's docs). None: use HTTP/2.
    pub(crate) async fn try_send(&self, host: &str, out: &Outgoing) -> Option<Result<Response<BoxBody>>> {
        let mut send = self.ready(host).await?;
        let mut req = Request::builder().method(out.method.clone()).uri(&out.url);
        for (k, v) in out.headers.iter() {
            req = req.header(k, v);
        }
        let req = match req.body(()) {
            Ok(r) => r,
            Err(e) => return Some(Err(e.into())),
        };
        let mut s = match send.send_request(req).await {
            Ok(s) => s,
            Err(e) => {
                // The connection went away before this request was sent: HTTP/2 then.
                tracing::debug!(host, error = %e, "HTTP/3 upstream connection lost");
                self.state.lock().expect("state").remove(host);
                return None;
            }
        };
        Some(Self::exchange(&mut s, out.body.clone()).await.map(|head| {
            // The body streams through a channel (a body must be Sync; the stream isn't).
            let (mut tx, body) = http_body_util::channel::Channel::<Bytes, Box<dyn std::error::Error + Send + Sync>>::new(8);
            tokio::spawn(async move {
                loop {
                    match s.recv_data().await {
                        Ok(Some(mut b)) => {
                            if tx.send_data(b.copy_to_bytes(b.remaining())).await.is_err() {
                                s.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                                return;
                            }
                        }
                        Ok(None) => return,
                        Err(e) => return tx.abort(Box::new(io::Error::other(e.to_string()))),
                    }
                }
            });
            let (parts, ()) = head.into_parts();
            Response::from_parts(parts, BodyExt::boxed(body))
        }))
    }

    async fn exchange(s: &mut h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>, body: Bytes) -> Result<Response<()>> {
        if !body.is_empty() {
            s.send_data(body).await?;
        }
        s.finish().await?;
        Ok(s.recv_response().await?)
    }

    /// The host's HTTP/3 connection if it is up, or comes up within [`RACE`].
    async fn ready(&self, host: &str) -> Option<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>> {
        let st = self.state.lock().expect("state").get(host).cloned();
        let (mut watch, since) = match st {
            Some(State::Ready(s)) => return Some(s),
            Some(State::NoH3(since)) if since.elapsed() < NO_H3_FOR => return None,
            Some(State::Connecting(w, since)) => (w, since),
            _ => (self.connect(host), Instant::now()),
        };
        let left = RACE.saturating_sub(since.elapsed());
        if left.is_zero() {
            return None;
        }
        let _ = tokio::time::timeout(left, watch.wait_for(|done| *done)).await;
        match self.state.lock().expect("state").get(host) {
            Some(State::Ready(s)) => Some(s.clone()),
            _ => None,
        }
    }

    /// Starts connecting to `host` in the background; the watch turns true when it's settled.
    fn connect(&self, host: &str) -> tokio::sync::watch::Receiver<bool> {
        let (tx, rx) = tokio::sync::watch::channel(false);
        self.state.lock().expect("state").insert(host.to_string(), State::Connecting(rx.clone(), Instant::now()));
        let (ep, state, host, fixed) = (self.ep.clone(), self.state.clone(), host.to_string(), self.resolve.get(host).copied());
        let lookup = self.lookup.clone();
        tokio::spawn(async move {
            let r = tokio::time::timeout(Duration::from_secs(5), async {
                // The checked address is the one dialled, for the connection's whole life (#116).
                let addr = match fixed {
                    Some(a) => a,
                    None => crate::dial::resolve_public(&lookup, &host, 443).await?.into_iter().next().ok_or_else(|| anyhow!("{host}: no address"))?,
                };
                let conn = ep.connect(addr, &host)?.await?;
                let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
                let (state2, host2) = (state.clone(), host.clone());
                tokio::spawn(async move {
                    let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
                    // Closed (idle, or by the origin): the next request connects afresh.
                    let mut g = state2.lock().expect("state");
                    if matches!(g.get(&host2), Some(State::Ready(_))) {
                        g.remove(&host2);
                    }
                });
                Ok::<_, anyhow::Error>(send)
            })
            .await;
            let next = match r {
                Ok(Ok(send)) => State::Ready(send),
                Ok(Err(e)) => {
                    tracing::debug!(%host, error = %e, "no HTTP/3 upstream; HTTP/2 for now");
                    State::NoH3(Instant::now())
                }
                Err(_) => State::NoH3(Instant::now()),
            };
            state.lock().expect("state").insert(host, next);
            let _ = tx.send(true);
        });
        rx
    }
}
